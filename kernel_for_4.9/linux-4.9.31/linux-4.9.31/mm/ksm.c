/*
 * Memory merging support.
 *
 * This code enables dynamic sharing of identical pages found in different
 * memory areas, even if they are not shared by fork()
 *
 * Copyright (C) 2008-2009 Red Hat, Inc.
 * Authors:
 *	Izik Eidus
 *	Andrea Arcangeli
 *	Chris Wright
 *	Hugh Dickins
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 */

/* KSM全称Kernel SamePage Merging,用于合并内容相同的页面.
 * KSM的出现是为了优化虚拟化中产生的冗余页面,因为虚拟化的实际应用中在同一个宿主机上会有许多相同的操作系统和应用程序,
 * 那么许多内存页面的内容有可能是相同的,因此他们可以被合并,从而释放内存供其它应用程序使用.
 *
 * KSM允许合并同一个进程或不同进程之间内容相同的匿名页面,这对应用程序来说是不可见的.
 * 把这些相同的页面被合并成一个只读页面,从而释放出来物理页面,当应用程序需要改变页面冲突时,会发生写时复制(copy-on-write,COW).
 */

#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/mman.h>
#include <linux/sched.h>
#include <linux/rwsem.h>
#include <linux/pagemap.h>
#include <linux/rmap.h>
#include <linux/spinlock.h>
#include <linux/jhash.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/wait.h>
#include <linux/slab.h>
#include <linux/rbtree.h>
#include <linux/memory.h>
#include <linux/mmu_notifier.h>
#include <linux/swap.h>
#include <linux/ksm.h>
#include <linux/hashtable.h>
#include <linux/freezer.h>
#include <linux/oom.h>
#include <linux/numa.h>

#include <asm/tlbflush.h>
#include "internal.h"

#ifdef CONFIG_NUMA
#define NUMA(x)		(x)
#define DO_NUMA(x)	do { (x); } while (0)
#else
#define NUMA(x)		(0)
#define DO_NUMA(x)	do { } while (0)
#endif

/*
 * A few notes about the KSM scanning process,
 * to make it easier to understand the data structures below:
 *
 * In order to reduce excessive scanning, KSM sorts the memory pages by their
 * contents into a data structure that holds pointers to the pages' locations.
 *
 * Since the contents of the pages may change at any moment, KSM cannot just
 * insert the pages into a normal sorted tree and expect it to find anything.
 * Therefore KSM uses two data structures - the stable and the unstable tree.
 *
 * The stable tree holds pointers to all the merged pages (ksm pages), sorted
 * by their contents.  Because each such page is write-protected, searching on
 * this tree is fully assured to be working (except when pages are unmapped),
 * and therefore this tree is called the stable tree.
 *
 * In addition to the stable tree, KSM uses a second data structure called the
 * unstable tree: this tree holds pointers to pages which have been found to
 * be "unchanged for a period of time".  The unstable tree sorts these pages
 * by their contents, but since they are not write-protected, KSM cannot rely
 * upon the unstable tree to work correctly - the unstable tree is liable to
 * be corrupted as its contents are modified, and so it is called unstable.
 *
 * KSM solves this problem by several techniques:
 *
 * 1) The unstable tree is flushed every time KSM completes scanning all
 *    memory areas, and then the tree is rebuilt again from the beginning.
 * 2) KSM will only insert into the unstable tree, pages whose hash value
 *    has not changed since the previous scan of all memory areas.
 * 3) The unstable tree is a RedBlack Tree - so its balancing is based on the
 *    colors of the nodes and not on their contents, assuring that even when
 *    the tree gets "corrupted" it won't get out of balance, so scanning time
 *    remains the same (also, searching and inserting nodes in an rbtree uses
 *    the same algorithm, so we have no overhead when we flush and rebuild).
 * 4) KSM never flushes the stable tree, which means that even if it were to
 *    take 10 attempts to find a page in the unstable tree, once it is found,
 *    it is secured in the stable tree.  (When we scan a new page, we first
 *    compare it against the stable tree, and then against the unstable tree.)
 *
 * If the merge_across_nodes tunable is unset, then KSM maintains multiple
 * stable trees and multiple unstable trees: one of each for each NUMA node.
 */

/**
 * struct mm_slot - ksm information per mm that is being scanned
 * @link: link to the mm_slots hash list
 * @mm_list: link into the mm_slots list, rooted in ksm_mm_head
 * @rmap_list: head for this mm_slot's singly-linked list of rmap_items
 * @mm: the mm that this information is valid for
 */

/* mm_slot数据结构描述添加到ksm系统中将要被扫描的进程mm_struct数据结构 */
struct mm_slot {
	/* link: 用于添加到mm_slot哈希表中 */
	struct hlist_node link;
	/* 用于添加到mm_slot链表中,链表头在ksm_mm_head */
	struct list_head mm_list;
	/* mm_slot's ramp_items单链表的头 */
	struct rmap_item *rmap_list;
	/* 进程的mm数据结构 */
	struct mm_struct *mm;
};

/**
 * struct ksm_scan - cursor for scanning
 * @mm_slot: the current mm_slot we are scanning
 * @address: the next address inside that to be scanned
 * @rmap_list: link to the next rmap to be scanned in the rmap_list
 * @seqnr: count of completed full scans (needed when removing unstable node)
 *
 * There is only the one ksm_scan instance of this cursor structure.
 */
/* ksm_scan数据结构用于表示当前扫描的状态 */
struct ksm_scan {
	/* 当前正在扫描的mm_slot */
	struct mm_slot *mm_slot;
	/* 下一次扫描的地址 */
	unsigned long address;
	/* 指向rmap_list中要扫描的下一个rmap的链接 */
	struct rmap_item **rmap_list;
	/* 全部扫描完成后会计数一次,用于删除unstable节点 */
	unsigned long seqnr;
};

/**
 * struct stable_node - node of the stable rbtree
 * @node: rb node of this ksm page in the stable tree
 * @head: (overlaying parent) &migrate_nodes indicates temporarily on that list
 * @list: linked into migrate_nodes, pending placement in the proper node tree
 * @hlist: hlist head of rmap_items using this ksm page
 * @kpfn: page frame number of this ksm page (perhaps temporarily on wrong nid)
 * @nid: NUMA node id of stable tree in which linked (may not match kpfn)
 *
 * struct stable_node - stable rbtree的节点
 * @node: ksm page在stable tree里面的节点
 * @head: (覆盖父项) &migrate_nodes临时显示在该列表上
 * @list: 链接到migrate_nodes,在适当的节点树中挂起的位置
 * @hlist: 使用此ksm页面rmap_items的hlist的头
 * @kpfn: 此ksm页面的页面帧号(可能暂时位于错误的nid上)
 * @nid: 链接的稳定树的NUMA节点id(可能与kpfn不匹配)
 */
struct stable_node {
	union {
		struct rb_node node;	/* when node of stable tree
					 * 当节点在stable tree中时
					 */
		struct {		/* when listed for migration
					 * 但在迁移列表中时
					 */
			struct list_head *head;
			struct list_head list;
		};
	};
	struct hlist_head hlist;
	unsigned long kpfn;
#ifdef CONFIG_NUMA
	int nid;
#endif
};

/**
 * struct rmap_item - reverse mapping item for virtual addresses
 * @rmap_list: next rmap_item in mm_slot's singly-linked rmap_list
 * @anon_vma: pointer to anon_vma for this mm,address, when in stable tree
 * @nid: NUMA node id of unstable tree in which linked (may not match page)
 * @mm: the memory structure this rmap_item is pointing into
 * @address: the virtual address this rmap_item tracks (+ flags in low bits)
 * @oldchecksum: previous checksum of the page at that virtual address
 * @node: rb node of this rmap_item in the unstable tree
 * @head: pointer to stable_node heading this list in the stable tree
 * @hlist: link into hlist of rmap_items hanging off that stable_node
 *
 * struct rmap_item - 虚拟地址的反向映射项
 * @rmap_list: mm_slot的单链rmap_list中的下一个rmap_item
 * @anon_vm: 在stable tree时,指向此mm地址的anon_vm的指针
 * @nid: 链接的不稳定树的NUMA节点id(可能与页面不匹配)
 * @mm: 这个rmap_item指向的内存结构
 * @address: 此rmap_item跟踪的虚拟地址( +低位 flags)
 * @oldchecksum: 该虚拟地址的页面上一次的校验和
 * @node: unstable树中此rmap_item的rb节点
 * @head: 指向在stable tree中该链表头的stable_node
 * @hlist: 链接到挂在稳定节点上的rmap_items的hlist
 */

/* rmap_item数据结构描述一个虚拟地址反向映射的条目(item) */
struct rmap_item {
	/* 所有的rmap_item连接成一个链表,链表头在ksm_scan.rmap_list中 */
	struct rmap_item *rmap_list;
	union {
		/* 当rmap_item加入stable树时,指向vma的anon_vma数据结构 */
		struct anon_vma *anon_vma;	/* when stable */
#ifdef CONFIG_NUMA
		int nid;		/* when node of unstable tree */
#endif
	};
	/* 进程的struct mm_struct数据结构 */
	struct mm_struct *mm;
	/* rmap_item所跟踪的用户空间地址 */
	unsigned long address;		/* + low bits used for flags below */
	/* 虚拟地址对应的物理页面的旧效验值 */
	unsigned int oldchecksum;	/* when unstable */
	union {
		/* rmap_item加入unstable红黑树的节点 */
		struct rb_node node;	/* when node of unstable tree */
		struct {		/* when listed from stable tree */
			/* 加入stable红黑树的节点 */
			struct stable_node *head;
			/* stable链表 */
			struct hlist_node hlist;
		};
	};
};

#define SEQNR_MASK	0x0ff	/* low bits of unstable tree seqnr */
#define UNSTABLE_FLAG	0x100	/* is a node of the unstable tree */
#define STABLE_FLAG	0x200	/* is listed from the stable tree */

/* The stable and unstable tree heads */
static struct rb_root one_stable_tree[1] = { RB_ROOT };
static struct rb_root one_unstable_tree[1] = { RB_ROOT };
static struct rb_root *root_stable_tree = one_stable_tree;
static struct rb_root *root_unstable_tree = one_unstable_tree;

/* Recently migrated nodes of stable tree, pending proper placement */
static LIST_HEAD(migrate_nodes);

#define MM_SLOTS_HASH_BITS 10
static DEFINE_HASHTABLE(mm_slots_hash, MM_SLOTS_HASH_BITS);

static struct mm_slot ksm_mm_head = {
	.mm_list = LIST_HEAD_INIT(ksm_mm_head.mm_list),
};
static struct ksm_scan ksm_scan = {
	.mm_slot = &ksm_mm_head,
};

static struct kmem_cache *rmap_item_cache;
static struct kmem_cache *stable_node_cache;
static struct kmem_cache *mm_slot_cache;

/* The number of nodes in the stable tree
 * stable tree中nodes的数量
 */
static unsigned long ksm_pages_shared;

/* The number of page slots additionally sharing those nodes
 * ksm_pages_sharing计数表示合并到ksm节点中的页面的个数
 */
static unsigned long ksm_pages_sharing;

/* The number of nodes in the unstable tree
 * unstable tree中节点的数目
 */
static unsigned long ksm_pages_unshared;

/* The number of rmap_items in use: to calculate pages_volatile */
static unsigned long ksm_rmap_items;

/* Number of pages ksmd should scan in one batch */
static unsigned int ksm_thread_pages_to_scan = 100;

/* Milliseconds ksmd should sleep between batches */
static unsigned int ksm_thread_sleep_millisecs = 20;

#ifdef CONFIG_NUMA
/* Zeroed when merging across nodes is not allowed */
/* 指定是否可以合并来自不同NUMA节点的页面.
 * 当设置为0时,ksm仅合并物理上驻留在同一NUMA节点的内存区域中的页面.
 * 这为访问共享页面带来了更低的延迟.
 * 具有更多节点且NUMA距离较远的系统可能会受益于设置0的较低延迟.
 * 需要最小化内存使用量的较小系统可能会受益于设置1(默认值)的更大共享.
 *
 * 在决定使用哪种设置之前,您可能希望比较系统在每种设置下的性能.
 * merge_across_nodes只有在系统中没有ksm共享页面时才能更改设置:将run 2设置为先取消合并页面,更改后merge_across_nodes设置为1,
 * 根据新设置重新合并.
 * 默认值: 1(在早期版本中跨节点合并)
 */
static unsigned int ksm_merge_across_nodes = 1;
static int ksm_nr_node_ids = 1;
#else
#define ksm_merge_across_nodes	1U
#define ksm_nr_node_ids		1
#endif

#define KSM_RUN_STOP	0
#define KSM_RUN_MERGE	1
#define KSM_RUN_UNMERGE	2
#define KSM_RUN_OFFLINE	4
static unsigned long ksm_run = KSM_RUN_STOP;
static void wait_while_offlining(void);

static DECLARE_WAIT_QUEUE_HEAD(ksm_thread_wait);
static DEFINE_MUTEX(ksm_thread_mutex);
static DEFINE_SPINLOCK(ksm_mmlist_lock);

#define KSM_KMEM_CACHE(__struct, __flags) kmem_cache_create("ksm_"#__struct,\
		sizeof(struct __struct), __alignof__(struct __struct),\
		(__flags), NULL)

static int __init ksm_slab_init(void)
{
	rmap_item_cache = KSM_KMEM_CACHE(rmap_item, 0);
	if (!rmap_item_cache)
		goto out;

	stable_node_cache = KSM_KMEM_CACHE(stable_node, 0);
	if (!stable_node_cache)
		goto out_free1;

	mm_slot_cache = KSM_KMEM_CACHE(mm_slot, 0);
	if (!mm_slot_cache)
		goto out_free2;

	return 0;

out_free2:
	kmem_cache_destroy(stable_node_cache);
out_free1:
	kmem_cache_destroy(rmap_item_cache);
out:
	return -ENOMEM;
}

static void __init ksm_slab_free(void)
{
	kmem_cache_destroy(mm_slot_cache);
	kmem_cache_destroy(stable_node_cache);
	kmem_cache_destroy(rmap_item_cache);
	mm_slot_cache = NULL;
}

static inline struct rmap_item *alloc_rmap_item(void)
{
	struct rmap_item *rmap_item;

	rmap_item = kmem_cache_zalloc(rmap_item_cache, GFP_KERNEL |
						__GFP_NORETRY | __GFP_NOWARN);
	if (rmap_item)
		ksm_rmap_items++;
	return rmap_item;
}

static inline void free_rmap_item(struct rmap_item *rmap_item)
{
	ksm_rmap_items--;
	rmap_item->mm = NULL;	/* debug safety */
	kmem_cache_free(rmap_item_cache, rmap_item);
}

static inline struct stable_node *alloc_stable_node(void)
{
	/*
	 * The allocation can take too long with GFP_KERNEL when memory is under
	 * pressure, which may lead to hung task warnings.  Adding __GFP_HIGH
	 * grants access to memory reserves, helping to avoid this problem.
	 */
	return kmem_cache_alloc(stable_node_cache, GFP_KERNEL | __GFP_HIGH);
}

static inline void free_stable_node(struct stable_node *stable_node)
{
	kmem_cache_free(stable_node_cache, stable_node);
}

static inline struct mm_slot *alloc_mm_slot(void)
{
	if (!mm_slot_cache)	/* initialization failed */
		return NULL;
	return kmem_cache_zalloc(mm_slot_cache, GFP_KERNEL);
}

static inline void free_mm_slot(struct mm_slot *mm_slot)
{
	kmem_cache_free(mm_slot_cache, mm_slot);
}

static struct mm_slot *get_mm_slot(struct mm_struct *mm)
{
	struct mm_slot *slot;

	hash_for_each_possible(mm_slots_hash, slot, link, (unsigned long)mm)
		if (slot->mm == mm)
			return slot;

	return NULL;
}

static void insert_to_mm_slots_hash(struct mm_struct *mm,
				    struct mm_slot *mm_slot)
{
	mm_slot->mm = mm;
	hash_add(mm_slots_hash, &mm_slot->link, (unsigned long)mm);
}

/*
 * ksmd, and unmerge_and_remove_all_rmap_items(), must not touch an mm's
 * page tables after it has passed through ksm_exit() - which, if necessary,
 * takes mmap_sem briefly to serialize against them.  ksm_exit() does not set
 * a special flag: they can just back out as soon as mm_users goes to zero.
 * ksm_test_exit() is used throughout to make this test for exit: in some
 * places for correctness, in some places just to avoid unnecessary work.
 */
static inline bool ksm_test_exit(struct mm_struct *mm)
{
	return atomic_read(&mm->mm_users) == 0;
}

/*
 * We use break_ksm to break COW on a ksm page: it's a stripped down
 *
 *	if (get_user_pages(addr, 1, 1, 1, &page, NULL) == 1)
 *		put_page(page);
 *
 * but taking great care only to touch a ksm page, in a VM_MERGEABLE vma,
 * in case the application has unmapped and remapped mm,addr meanwhile.
 * Could a ksm page appear anywhere else?  Actually yes, in a VM_PFNMAP
 * mmap of /dev/mem or /dev/kmem, where we would not want to touch it.
 *
 * FAULT_FLAG/FOLL_REMOTE are because we do this outside the context
 * of the process that owns 'vma'.  We also do not want to enforce
 * protection keys here anyway.
 *
 * 我们使用break_ksm来打破ksm页面上的COW: 这是一个精简版
 *
 *	if（get_user_pages(addr, 1, 1, &page, NULL) == 1)
 *		put_page(page);
 *
 * 但在VM_MERGEABLE vma中,如果应用程序同时取消映射和重新映射了mm,addr,则只需非常小心地触摸ksm页.
 * ksm页面会出现在其他地方吗? 实际上是的,在/dev/mem或/dev/kmem的VM_PFNMAP mmap中,我们不想触摸它.
 *
 * FAULT_FLAG/FOLL_REMOTE是因为我们在拥有“vma”的进程的上下文之外执行此操作.
 * 无论如何,我们也不想在这里强制执行protection keys.
 */
static int break_ksm(struct vm_area_struct *vma, unsigned long addr)
{
	struct page *page;
	int ret = 0;

	do {
		cond_resched();
		/* follow_page函数由VMA和虚拟地址获取出normal mapping的页面数据结构,参数flags是FOLL_GET | FOLL_MIGRATION,
		 * FOLL_GET表示增加该页的_refcount计数,FOLL_MIGRATION表示如果该页在页迁移的过程中会等待页迁移完成.
		 * FOLL_REMOTE: we are working on non-current tsk/mm
		 */
		page = follow_page(vma, addr,
				FOLL_GET | FOLL_MIGRATION | FOLL_REMOTE);
		if (IS_ERR_OR_NULL(page))
			break;
		/* 对于KSM页面,这里直接调用handle_mm_fault()人为造一个写错误(FAULT_FLAG_WRITE)的
		 * 缺页中断,在缺页中断处理函数找那个处理写时复制COW,最终调用do_wp_page()重新分配一个页面来
		 * 和对应的虚拟地址建立映射关系.
		 */
		if (PageKsm(page))
			ret = handle_mm_fault(vma, addr,
					FAULT_FLAG_WRITE | FAULT_FLAG_REMOTE);
		else
			ret = VM_FAULT_WRITE;
		put_page(page);
	} while (!(ret & (VM_FAULT_WRITE | VM_FAULT_SIGBUS | VM_FAULT_SIGSEGV | VM_FAULT_OOM)));
	/*
	 * We must loop because handle_mm_fault() may back out if there's
	 * any difficulty e.g. if pte accessed bit gets updated concurrently.
	 *
	 * VM_FAULT_WRITE is what we have been hoping for: it indicates that
	 * COW has been broken, even if the vma does not permit VM_WRITE;
	 * but note that a concurrent fault might break PageKsm for us.
	 *
	 * VM_FAULT_SIGBUS could occur if we race with truncation of the
	 * backing file, which also invalidates anonymous pages: that's
	 * okay, that truncation will have unmapped the PageKsm for us.
	 *
	 * VM_FAULT_OOM: at the time of writing (late July 2009), setting
	 * aside mem_cgroup limits, VM_FAULT_OOM would only be set if the
	 * current task has TIF_MEMDIE set, and will be OOM killed on return
	 * to user; and ksmd, having no mm, would never be chosen for that.
	 *
	 * But if the mm is in a limited mem_cgroup, then the fault may fail
	 * with VM_FAULT_OOM even if the current task is not TIF_MEMDIE; and
	 * even ksmd can fail in this way - though it's usually breaking ksm
	 * just to undo a merge it made a moment before, so unlikely to oom.
	 *
	 * That's a pity: we might therefore have more kernel pages allocated
	 * than we're counting as nodes in the stable tree; but ksm_do_scan
	 * will retry to break_cow on each pass, so should recover the page
	 * in due course.  The important thing is to not let VM_MERGEABLE
	 * be cleared while any such pages might remain in the area.
	 *
	 * 我们必须循环,因为如果有任何困难,handle_mm_fault()可能会退出,例如,如果pte访问的位同时更新.
	 *
	 * VM_FAULT_WRITE是我们一直希望的: 它表明COW已经被破坏,即使vma不允许VM_WRITE;
	 * 但请注意,同时发生的故障可能会破坏我们的PageKsm.
	 *
	 * 如果我们与backing 文件的截断竞争,VM_FAULT_SIGBUS可能会发生,这也会使匿名页面无效:
	 * 没关系,截断会为我们取消PageKsm的映射.
	 *
	 * VM_FAULT_OOM: 在编写时(2009年7月下旬),抛开mem_cgroup限制,只有当当前任务设置了TIF_MEMDIE时,才会设置VM_FAULTE_OOM,并且在返回给用户时会被OOM杀死;
	 * 而没有mm的ksmd永远不会被选中.
	 *
	 * 但是,如果mm在有限的mem_cgroup中,则即使当前任务不是TIF_MEMDIE,故障也可能以VM_fault_OOM失败;
	 * 甚至ksmd也可能以这种方式失败 — 尽管它通常会破坏ksm,只是为了撤销之前进行的合并,所以不太可能oom.
	 *
	 * 这很遗憾: 因此,我们分配的内核页面可能比我们在稳定树中计算的节点还要多;但是ksm_do_scan在每次通过时都会重试breakcow,因此应该会在适当的时候恢复页面.
	 * 重要的是,当任何此类页面可能保留在该区域时,不要让VM_MERGEABLE被清除
	 */
	return (ret & VM_FAULT_OOM) ? -ENOMEM : 0;
}

static struct vm_area_struct *find_mergeable_vma(struct mm_struct *mm,
		unsigned long addr)
{
	struct vm_area_struct *vma;
	if (ksm_test_exit(mm))
		return NULL;
	vma = find_vma(mm, addr);
	if (!vma || vma->vm_start > addr)
		return NULL;
	if (!(vma->vm_flags & VM_MERGEABLE) || !vma->anon_vma)
		return NULL;
	return vma;
}
/* break_cow函数处理已经把页面设置成写保护的情况,并人为造一个写错误的缺页中断,即写时复制(COW)的场景.
 * 其中,参数rmap_item中保存了该页的虚拟地址和进程数据结构,由此可以找到对应的VMA
 */
static void break_cow(struct rmap_item *rmap_item)
{
	struct mm_struct *mm = rmap_item->mm;
	unsigned long addr = rmap_item->address;
	struct vm_area_struct *vma;

	/*
	 * It is not an accident that whenever we want to break COW
	 * to undo, we also need to drop a reference to the anon_vma.
	 *
	 * 每当我们想要中断COW以撤消时,我们还需要删除对anon_vm的引用,这并非偶然.
	 */
	/* 将对应的anon_vma引用计数 -1 */
	put_anon_vma(rmap_item->anon_vma);

	down_read(&mm->mmap_sem);
	/* 找到相关vma */
	vma = find_mergeable_vma(mm, addr);
	/* 触发写时复制 */
	if (vma)
		break_ksm(vma, addr);
	up_read(&mm->mmap_sem);
}

static struct page *get_mergeable_page(struct rmap_item *rmap_item)
{
	struct mm_struct *mm = rmap_item->mm;
	unsigned long addr = rmap_item->address;
	struct vm_area_struct *vma;
	struct page *page;

	down_read(&mm->mmap_sem);
	vma = find_mergeable_vma(mm, addr);
	if (!vma)
		goto out;

	page = follow_page(vma, addr, FOLL_GET);
	if (IS_ERR_OR_NULL(page))
		goto out;
	if (PageAnon(page)) {
		flush_anon_page(vma, page, addr);
		flush_dcache_page(page);
	} else {
		put_page(page);
out:
		page = NULL;
	}
	up_read(&mm->mmap_sem);
	return page;
}

/*
 * This helper is used for getting right index into array of tree roots.
 * When merge_across_nodes knob is set to 1, there are only two rb-trees for
 * stable and unstable pages from all nodes with roots in index 0. Otherwise,
 * every node has its own stable and unstable tree.
 *
 * 此辅助功能用于获取对tree roots的正确索引.
 * 当merge_across_nodes knob设置为1时,对于索引为0的所有节点中的稳定和不稳定页面,只有两个rb树.
 * 否则,每个节点都有自己的稳定和不稳定树.
 */

/* 所以这里就是看你设没设置ksm_merge_across_nodes
 * 如果设置了,那么系统中就只有两个rb树
 * 如果没设置,那么每个node都有自己的stable tree
 */
static inline int get_kpfn_nid(unsigned long kpfn)
{
	return ksm_merge_across_nodes ? 0 : NUMA(pfn_to_nid(kpfn));
}

static void remove_node_from_stable_tree(struct stable_node *stable_node)
{
	struct rmap_item *rmap_item;

	hlist_for_each_entry(rmap_item, &stable_node->hlist, hlist) {
		if (rmap_item->hlist.next)
			ksm_pages_sharing--;
		else
			ksm_pages_shared--;
		put_anon_vma(rmap_item->anon_vma);
		rmap_item->address &= PAGE_MASK;
		cond_resched();
	}

	if (stable_node->head == &migrate_nodes)
		list_del(&stable_node->list);
	else
		rb_erase(&stable_node->node,
			 root_stable_tree + NUMA(stable_node->nid));
	free_stable_node(stable_node);
}

/*
 * get_ksm_page: checks if the page indicated by the stable node
 * is still its ksm page, despite having held no reference to it.
 * In which case we can trust the content of the page, and it
 * returns the gotten page; but if the page has now been zapped,
 * remove the stale node from the stable tree and return NULL.
 * But beware, the stable node's page might be being migrated.
 *
 * You would expect the stable_node to hold a reference to the ksm page.
 * But if it increments the page's count, swapping out has to wait for
 * ksmd to come around again before it can free the page, which may take
 * seconds or even minutes: much too unresponsive.  So instead we use a
 * "keyhole reference": access to the ksm page from the stable node peeps
 * out through its keyhole to see if that page still holds the right key,
 * pointing back to this stable node.  This relies on freeing a PageAnon
 * page to reset its page->mapping to NULL, and relies on no other use of
 * a page to put something that might look like our key in page->mapping.
 * is on its way to being freed; but it is an anomaly to bear in mind.
 */
static struct page *get_ksm_page(struct stable_node *stable_node, bool lock_it)
{
	struct page *page;
	void *expected_mapping;
	unsigned long kpfn;

	expected_mapping = (void *)((unsigned long)stable_node |
					PAGE_MAPPING_KSM);
again:
	kpfn = READ_ONCE(stable_node->kpfn);
	page = pfn_to_page(kpfn);

	/*
	 * page is computed from kpfn, so on most architectures reading
	 * page->mapping is naturally ordered after reading node->kpfn,
	 * but on Alpha we need to be more careful.
	 */
	smp_read_barrier_depends();
	if (READ_ONCE(page->mapping) != expected_mapping)
		goto stale;

	/*
	 * We cannot do anything with the page while its refcount is 0.
	 * Usually 0 means free, or tail of a higher-order page: in which
	 * case this node is no longer referenced, and should be freed;
	 * however, it might mean that the page is under page_freeze_refs().
	 * The __remove_mapping() case is easy, again the node is now stale;
	 * but if page is swapcache in migrate_page_move_mapping(), it might
	 * still be our page, in which case it's essential to keep the node.
	 */
	while (!get_page_unless_zero(page)) {
		/*
		 * Another check for page->mapping != expected_mapping would
		 * work here too.  We have chosen the !PageSwapCache test to
		 * optimize the common case, when the page is or is about to
		 * be freed: PageSwapCache is cleared (under spin_lock_irq)
		 * in the freeze_refs section of __remove_mapping(); but Anon
		 * page->mapping reset to NULL later, in free_pages_prepare().
		 */
		if (!PageSwapCache(page))
			goto stale;
		cpu_relax();
	}

	if (READ_ONCE(page->mapping) != expected_mapping) {
		put_page(page);
		goto stale;
	}

	if (lock_it) {
		lock_page(page);
		if (READ_ONCE(page->mapping) != expected_mapping) {
			unlock_page(page);
			put_page(page);
			goto stale;
		}
	}
	return page;

stale:
	/*
	 * We come here from above when page->mapping or !PageSwapCache
	 * suggests that the node is stale; but it might be under migration.
	 * We need smp_rmb(), matching the smp_wmb() in ksm_migrate_page(),
	 * before checking whether node->kpfn has been changed.
	 */
	smp_rmb();
	if (READ_ONCE(stable_node->kpfn) != kpfn)
		goto again;
	remove_node_from_stable_tree(stable_node);
	return NULL;
}

/*
 * Removing rmap_item from stable or unstable tree.
 * This function will clean the information from the stable/unstable tree.
 *
 * 从stable或unstable tree中删除rmap_item.
 * 此函数将清除stable/unstable tree中的信息.
 */
static void remove_rmap_item_from_tree(struct rmap_item *rmap_item)
{
	/* 如果rmap_item在stable_tree上面 */
	if (rmap_item->address & STABLE_FLAG) {
		struct stable_node *stable_node;
		struct page *page;

		/* 拿到stable_node */
		stable_node = rmap_item->head;
		/* 拿到stable_node的page */
		page = get_ksm_page(stable_node, true);
		/* 如果没有page,那么goto out */
		if (!page)
			goto out;
		/* 把它从stable node的hlist中删除 */
		hlist_del(&rmap_item->hlist);
		unlock_page(page);
		/* page的_refcount -1 */
		put_page(page);

		/* 如果stable->hlist不是空的,那么说明它还是有rmap_item在里面的
		 * 也就是说还有page在里面共享着呢
		 * 那么ksm_pages_sharing--
		 * ksm_page_sharing计数表示合并到ksm节点中的页面的个数
		 */
		if (!hlist_empty(&stable_node->hlist))
			ksm_pages_sharing--;
		else	/* 如果是空的,那么ksm_pages_shared--
			 * ksm_pages_shared表示系统中有多少个stable节点
			 */
			ksm_pages_shared--;
		/* 将rmap_item->anon_vma计数 -1 */
		put_anon_vma(rmap_item->anon_vma);
		/* rmap_item->address清掉后面的flag(STABLE_FLAG) */
		rmap_item->address &= PAGE_MASK;
		/* 如果rmap_item在unstable tree里面 */
	} else if (rmap_item->address & UNSTABLE_FLAG) {
		unsigned char age;
		/*
		 * Usually ksmd can and must skip the rb_erase, because
		 * root_unstable_tree was already reset to RB_ROOT.
		 * But be careful when an mm is exiting: do the rb_erase
		 * if this rmap_item was inserted by this scan, rather
		 * than left over from before.
		 *
		 * 通常ksmd可以也必须跳过rb_erase,因为root_unstable_tree已经重置为RB_ROOT.
		 * 但当mm退出时要小心: 如果这个rmap_item是通过这次扫描插入的.而不是以前留下的,请执行rb_erase.
		 */

		/* ksm_scan.seqnr全部扫描完成后会计数一次,也就是全部扫描的周期数
		 * 当它插入到unstable tree中rmap_item会做这样一个操作
		 * rmap_item->address |= UNSTABLE_FLAG;
		 * rmap_item->address |= (ksm_scan.seqnr & SEQNR_MASK);
		 *
		 * 因为这里前面减法之后取了后八位
		 */
		age = (unsigned char)(ksm_scan.seqnr - rmap_item->address);
		/* 如果age > 1 报个bug吧 */
		BUG_ON(age > 1);
		/* 如果age等于0,说明这个rmap_item是通过这次扫描插入的.而不是以前留下的,请执行rb_erase. */
		if (!age)
			rb_erase(&rmap_item->node,
				 root_unstable_tree + NUMA(rmap_item->nid));
		/* unstable tree中节点的数目减1 */
		ksm_pages_unshared--;
		/* 清除UNSTABLE_FLAG和ksm_scan.seqnr & SEQNR_MASK */
		rmap_item->address &= PAGE_MASK;
	}
out:
	cond_resched();		/* we're called from many long loops */
}

static void remove_trailing_rmap_items(struct mm_slot *mm_slot,
				       struct rmap_item **rmap_list)
{
	while (*rmap_list) {
		struct rmap_item *rmap_item = *rmap_list;
		*rmap_list = rmap_item->rmap_list;
		remove_rmap_item_from_tree(rmap_item);
		free_rmap_item(rmap_item);
	}
}

/*
 * Though it's very tempting to unmerge rmap_items from stable tree rather
 * than check every pte of a given vma, the locking doesn't quite work for
 * that - an rmap_item is assigned to the stable tree after inserting ksm
 * page and upping mmap_sem.  Nor does it fit with the way we skip dup'ing
 * rmap_items from parent to child at fork time (so as not to waste time
 * if exit comes before the next scan reaches it).
 *
 * Similarly, although we'd like to remove rmap_items (so updating counts
 * and freeing memory) when unmerging an area, it's easier to leave that
 * to the next pass of ksmd - consider, for example, how ksmd might be
 * in cmp_and_merge_page on one of the rmap_items we would be removing.
 */
static int unmerge_ksm_pages(struct vm_area_struct *vma,
			     unsigned long start, unsigned long end)
{
	unsigned long addr;
	int err = 0;

	for (addr = start; addr < end && !err; addr += PAGE_SIZE) {
		if (ksm_test_exit(vma->vm_mm))
			break;
		if (signal_pending(current))
			err = -ERESTARTSYS;
		else
			err = break_ksm(vma, addr);
	}
	return err;
}

#ifdef CONFIG_SYSFS
/*
 * Only called through the sysfs control interface:
 */
static int remove_stable_node(struct stable_node *stable_node)
{
	struct page *page;
	int err;

	page = get_ksm_page(stable_node, true);
	if (!page) {
		/*
		 * get_ksm_page did remove_node_from_stable_tree itself.
		 */
		return 0;
	}

	if (WARN_ON_ONCE(page_mapped(page))) {
		/*
		 * This should not happen: but if it does, just refuse to let
		 * merge_across_nodes be switched - there is no need to panic.
		 */
		err = -EBUSY;
	} else {
		/*
		 * The stable node did not yet appear stale to get_ksm_page(),
		 * since that allows for an unmapped ksm page to be recognized
		 * right up until it is freed; but the node is safe to remove.
		 * This page might be in a pagevec waiting to be freed,
		 * or it might be PageSwapCache (perhaps under writeback),
		 * or it might have been removed from swapcache a moment ago.
		 */
		set_page_stable_node(page, NULL);
		remove_node_from_stable_tree(stable_node);
		err = 0;
	}

	unlock_page(page);
	put_page(page);
	return err;
}

static int remove_all_stable_nodes(void)
{
	struct stable_node *stable_node, *next;
	int nid;
	int err = 0;

	for (nid = 0; nid < ksm_nr_node_ids; nid++) {
		while (root_stable_tree[nid].rb_node) {
			stable_node = rb_entry(root_stable_tree[nid].rb_node,
						struct stable_node, node);
			if (remove_stable_node(stable_node)) {
				err = -EBUSY;
				break;	/* proceed to next nid */
			}
			cond_resched();
		}
	}
	list_for_each_entry_safe(stable_node, next, &migrate_nodes, list) {
		if (remove_stable_node(stable_node))
			err = -EBUSY;
		cond_resched();
	}
	return err;
}

static int unmerge_and_remove_all_rmap_items(void)
{
	struct mm_slot *mm_slot;
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	int err = 0;

	spin_lock(&ksm_mmlist_lock);
	ksm_scan.mm_slot = list_entry(ksm_mm_head.mm_list.next,
						struct mm_slot, mm_list);
	spin_unlock(&ksm_mmlist_lock);

	for (mm_slot = ksm_scan.mm_slot;
			mm_slot != &ksm_mm_head; mm_slot = ksm_scan.mm_slot) {
		mm = mm_slot->mm;
		down_read(&mm->mmap_sem);
		for (vma = mm->mmap; vma; vma = vma->vm_next) {
			if (ksm_test_exit(mm))
				break;
			if (!(vma->vm_flags & VM_MERGEABLE) || !vma->anon_vma)
				continue;
			err = unmerge_ksm_pages(vma,
						vma->vm_start, vma->vm_end);
			if (err)
				goto error;
		}

		remove_trailing_rmap_items(mm_slot, &mm_slot->rmap_list);
		up_read(&mm->mmap_sem);

		spin_lock(&ksm_mmlist_lock);
		ksm_scan.mm_slot = list_entry(mm_slot->mm_list.next,
						struct mm_slot, mm_list);
		if (ksm_test_exit(mm)) {
			hash_del(&mm_slot->link);
			list_del(&mm_slot->mm_list);
			spin_unlock(&ksm_mmlist_lock);

			free_mm_slot(mm_slot);
			clear_bit(MMF_VM_MERGEABLE, &mm->flags);
			mmdrop(mm);
		} else
			spin_unlock(&ksm_mmlist_lock);
	}

	/* Clean up stable nodes, but don't worry if some are still busy */
	remove_all_stable_nodes();
	ksm_scan.seqnr = 0;
	return 0;

error:
	up_read(&mm->mmap_sem);
	spin_lock(&ksm_mmlist_lock);
	ksm_scan.mm_slot = &ksm_mm_head;
	spin_unlock(&ksm_mmlist_lock);
	return err;
}
#endif /* CONFIG_SYSFS */

static u32 calc_checksum(struct page *page)
{
	u32 checksum;
	void *addr = kmap_atomic(page);
	checksum = jhash2(addr, PAGE_SIZE / 4, 17);
	kunmap_atomic(addr);
	return checksum;
}

static int memcmp_pages(struct page *page1, struct page *page2)
{
	char *addr1, *addr2;
	int ret;

	addr1 = kmap_atomic(page1);
	addr2 = kmap_atomic(page2);
	ret = memcmp(addr1, addr2, PAGE_SIZE);
	kunmap_atomic(addr2);
	kunmap_atomic(addr1);
	return ret;
}

static inline int pages_identical(struct page *page1, struct page *page2)
{
	return !memcmp_pages(page1, page2);
}

static int write_protect_page(struct vm_area_struct *vma, struct page *page,
			      pte_t *orig_pte)
{
	struct mm_struct *mm = vma->vm_mm;
	unsigned long addr;
	pte_t *ptep;
	spinlock_t *ptl;
	int swapped;
	int err = -EFAULT;
	unsigned long mmun_start;	/* For mmu_notifiers */
	unsigned long mmun_end;		/* For mmu_notifiers */

	/* 拿到page在vma中的地址 */
	addr = page_address_in_vma(page, vma);
	if (addr == -EFAULT)
		goto out;

	BUG_ON(PageTransCompound(page));

	/* 把他给mmun_start和mmun_end,然后invalidate_range这段区间 */
	mmun_start = addr;
	mmun_end   = addr + PAGE_SIZE;
	mmu_notifier_invalidate_range_start(mm, mmun_start, mmun_end);
	/* 由mm和虚拟地址address通过查询页表找到该地址对应的pte页表项 */
	ptep = page_check_address(page, mm, addr, &ptl, 0);
	if (!ptep)
		goto out_mn;

	/* 因为该函数的作用是设置pte为写保护,因此对应pte页表项的属性是可写或者脏页面需要设置pte为写保护(对ARM处理器设置页表项的L_PTE_RDONLY比特位,
	 * 对x86处理器清_PAGE_BIT_RW比特位),
	 * 脏页面通过set_page_drity函数来调用该页面的mapping->a_ops->set_page_drity函数并通知回写系统.
	 */
	if (pte_write(*ptep) || pte_dirty(*ptep)) {
		pte_t entry;

		swapped = PageSwapCache(page);
		/* 刷新这个page的cache */
		flush_cache_page(vma, addr, page_to_pfn(page));
		/*
		 * Ok this is tricky, when get_user_pages_fast() run it doesn't
		 * take any lock, therefore the check that we are going to make
		 * with the pagecount against the mapcount is racey and
		 * O_DIRECT can happen right after the check.
		 * So we clear the pte and flush the tlb before the check
		 * this assure us that no O_DIRECT can happen after the check
		 * or in the middle of the check.
		 *
		 * 好吧,这很棘手,当get_user_pages_fast()运行时,它不需要任何锁,
		 * 因此我们要对pagecount和mapcount进行的检查是竞态的
		 * O_DIRECT可以在检查后立即发生.
		 * 因此,我们在检查之前清除pte并刷新tlb,这确保了在检查之后或检查中间不会发生O_DIRECT.
		 */

		/* ptep_clear_flush_notify清空pte页表项内容并冲刷相应的TLB,保证没有DIRECT_IO发生,函数返回该pte原来的内容 */
		entry = ptep_clear_flush_notify(vma, addr, ptep);
		/*
		 * Check that no O_DIRECT or similar I/O is in progress on the
		 * page
		 */
		/* 这里为什么要有这样一个判断公式呢?
		 * page_mapcount(page) + 1 + swapped != page_count(page)
		 * 这是一个需要深入理解内存管理代码才能明确的问题,涉及到page的_refcount和_mapcount两个引用计数的巧妙运用.
		 * write_protect_page函数本身的目的是让页面变成只读,
		 * 后续就可以做比较和合并的工作了.
		 * 要把一个页面变成只读需要满足如下两个条件:
		 * 1、确认没有其他人获取了该页面.
		 * 2、将指向该页面的pte变成只读属性.
		 * 第二个条件容易处理,难点就在第一个条件.
		 * 一般来说,page的_refcount计数有如下四种来源
		 * 1、page cache在radix tree上,KSM不考虑page cache情况.
		 * 2、被用户态的pte引用,_refcount和_mapcount都会增加计数.
		 * 3、page->private私用数据也会增加_refcount计数,对于匿名页面,需要判断是否在swap cache中,例如add_to_swap函数.
		 * 4、内核中某些页面操作时会增加_refcount计数,例如follow_page、get_user_pages、fast等
		 *
		 * 假设没有其他内核路径操作该页面,并且该页面不在swap cache中,两个引用计数的关系为:
		 * page->_mapcount + 1 = page->_refcount
		 * 那么在write_protect_page场景中,swapped指的是页面是否为swapcache,在add_to_swap函数里增加_refcount计数,因此上面的公示可以变为:
		 * page->_mapcount + 1 + swapped == page_count(page)
		 *
		 * 但是上述公司也有例外,例如该页面发生DIRECT_IO读写的情况,调用关系如下:
		 * genneric_file_direct_write
		 *    mapping->a_ops->direct_IO
		 *       ext4_direct_IO()
		 *          __blockdev_direct_IO
		 *             do_blockdev_direct_IO
		 *                do_direct_IO
		 *                   dio_get_page
		 *                      dio_refill_pages
		 *                         iov_iter_get_pages
		 *                            get_user_page_fast
		 * 最后调用get_user_pages_fast函数来分配内存,它会让page->_refcount引用计数 + 1,因此在没有DIRECT_IO读写的情况下,上述公示变成:
		 * page_mapcount(page) + 1 + PageSwapCache == page_count(page)
		 * 那为什么这下面会有 +1 呢,因为该页面scan_get_next_rmap_item函数通过follow_page操作来获取struct page数据结构,
		 * 这个过程中会让page->_count引用计数+1,综上所述,在当前场景下判断没有DIRECT_IO的读写的情况下,公式变成
		 * page_mapcount(page) + 1 + swapped != page_count(page)
		 *
		 * 因此下面判断不相等,说明有内核代码路径(例如DIRECT_IO读写)正在操作该页面,
		 * 那么write_protect_page函数只能把entry设置回去之后返回错误
		 */
		if (page_mapcount(page) + 1 + swapped != page_count(page)) {
			set_pte_at(mm, addr, ptep, entry);
			goto out_unlock;
		}
		/* 如果entry是drity的,那么设置page的drity位 */
		if (pte_dirty(entry))
			set_page_dirty(page);
		/* 新生成一个具有只读属性的PTE entry,并设置到硬件页面表中 */
		entry = pte_mkclean(pte_wrprotect(entry));
		set_pte_at_notify(mm, addr, ptep, entry);
	}
	*orig_pte = *ptep;
	err = 0;

out_unlock:
	pte_unmap_unlock(ptep, ptl);
out_mn:
	mmu_notifier_invalidate_range_end(mm, mmun_start, mmun_end);
out:
	return err;
}

/**
 * replace_page - replace page in vma by new ksm page
 * @vma:      vma that holds the pte pointing to page
 * @page:     the page we are replacing by kpage
 * @kpage:    the ksm page we replace page by
 * @orig_pte: the original value of the pte
 *
 * Returns 0 on success, -EFAULT on failure.
 */
/* replace_pages函数中的参数,其中page是旧的page,
 * kpage是stable树种找到的KSM页面
 * orig_pte用于判断在这期间page是否被修改了.
 * 简单来说就是使用kpage的pfn加上原来pagea的一些属性构成一个新的pte页表项,
 * 然后写入到原来page的pte页表项中,这样原来的page项对应的VMA用户地址空间就和kpage建立了映射关系
 */
static int replace_page(struct vm_area_struct *vma, struct page *page,
			struct page *kpage, pte_t orig_pte)
{
	struct mm_struct *mm = vma->vm_mm;
	pmd_t *pmd;
	pte_t *ptep;
	spinlock_t *ptl;
	unsigned long addr;
	int err = -EFAULT;
	unsigned long mmun_start;	/* For mmu_notifiers */
	unsigned long mmun_end;		/* For mmu_notifiers */

	/* 找到该page在该vma里面的地址 */
	addr = page_address_in_vma(page, vma);
	if (addr == -EFAULT)
		goto out;

	/* 找到该地址的pmd */
	pmd = mm_find_pmd(mm, addr);
	if (!pmd)
		goto out;

	mmun_start = addr;
	mmun_end   = addr + PAGE_SIZE;
	mmu_notifier_invalidate_range_start(mm, mmun_start, mmun_end);

	/* 找到该地址的ptep */
	ptep = pte_offset_map_lock(mm, pmd, addr, &ptl);
	/* 如果这个pte和原来的pte不相同,也就是说orig_pte在这期间被修改了,那么解锁之后goto out_mn */
	if (!pte_same(*ptep, orig_pte)) {
		pte_unmap_unlock(ptep, ptl);
		goto out_mn;
	}

	/* 增加kpage的引用计数 */
	get_page(kpage);
	/* 将kpage添加到RMAP系统中,因为kpage早已经添加到RMAP系统中,所以这里只是增加mapcount计数 */
	page_add_anon_rmap(kpage, vma, addr, false);

	/* 冲刷addr和pte对应的cache,然后清空pte的内容和对应的TLB后,写入新的pte的内容 */
	flush_cache_page(vma, addr, pte_pfn(*ptep));
	ptep_clear_flush_notify(vma, addr, ptep);
	set_pte_at_notify(mm, addr, ptep, mk_pte(kpage, vma->vm_page_prot));

	/* 减少page的_mapcount和count计数,并且删除该page在swap分区的swap space */
	page_remove_rmap(page, false);
	if (!page_mapped(page))
		try_to_free_swap(page);
	put_page(page);

	pte_unmap_unlock(ptep, ptl);
	err = 0;
out_mn:
	mmu_notifier_invalidate_range_end(mm, mmun_start, mmun_end);
out:
	return err;
}

/*
 * try_to_merge_one_page - take two pages and merge them into one
 * @vma: the vma that holds the pte pointing to page
 * @page: the PageAnon page that we want to replace with kpage
 * @kpage: the PageKsm page that we want to map instead of page,
 *         or NULL the first time when we want to use page as kpage.
 *
 * This function returns 0 if the pages were merged, -EFAULT otherwise.
 *
 * try_to_merge_one_page- 将两页并合并为一页
 * @vma: 保存指向页面的pte的vma
 * @page: 我们要用kpage替换的PageAnon页面
 * @kpage: 我们要映射的PageKsm页面,而不是页面.或者当我们第一次想使用page作为kpage时为NULL.
 *
 * 如果页面已合并,此函数将返回0,否则返回-EFAULT.
 */

static int try_to_merge_one_page(struct vm_area_struct *vma,
				 struct page *page, struct page *kpage)
{
	pte_t orig_pte = __pte(0);
	int err = -EFAULT;

	/* 如果page和kpage是同一个page,那么直接返回0 */
	if (page == kpage)			/* ksm page forked */
		return 0;

	/* 如果它不是匿名页面,那么也直接goto out */
	if (!PageAnon(page))
		goto out;

	/*
	 * We need the page lock to read a stable PageSwapCache in
	 * write_protect_page().  We use trylock_page() instead of
	 * lock_page() because we don't want to wait here - we
	 * prefer to continue scanning and merging different pages,
	 * then come back to this page when it is unlocked.
	 *
	 * 我们需要页面锁来读取write_protect_page()中stable PageSwapCache.
	 * 我们使用trylock_page()而不是lock_page(),因为我们不想在这里等待 - 我们更喜欢继续扫描和合并不同的页面,然后在解锁后返回此页面
	 *
	 * 这里为什么要使用trylock_page,而不使用lock_page呢?
	 * 我们需要申请该页的页面锁以方便在稍后的write_protect_page中读取稳定的PageSwapCache状态,并且不需要在这里睡眠等待该页的页锁.
	 * 如果该页被其它人加锁了,我们可以掠过它,先处理其他页面
	 */
	if (!trylock_page(page))
		goto out;

	if (PageTransCompound(page)) {
		if (split_huge_page(page))
			goto out_unlock;
	}

	/*
	 * If this anonymous page is mapped only here, its pte may need
	 * to be write-protected.  If it's mapped elsewhere, all of its
	 * ptes are necessarily already write-protected.  But in either
	 * case, we need to lock and check page_count is not raised.
	 *
	 * 如果仅在此映射此匿名页面,则可能需要对其pte进行写保护.
	 * 如果它被映射到其他地方,那么它的所有pte必然都已被写保护.
	 * 但在任何一个在这种情况下,我们需要锁定并检查page_count是否被引发.
	 */
	if (write_protect_page(vma, page, &orig_pte) == 0) {
		/* 在与unstable树节点合并时,参数kpage有可能传过来是NULL的,这主要设置page为stable节点,并且设置该页的活动情况(mark_page_accessed())
		 */
		if (!kpage) {
			/*
			 * While we hold page lock, upgrade page from
			 * PageAnon+anon_vma to PageKsm+NULL stable_node:
			 * stable_tree_insert() will update stable_node.
			 *
			 * 当我们保持页面锁时,将页面从PageAnon+anon_vma升级到PageKsm+NULL stable_node:
			 * stable_tree_insert()将更新stable_node
			 */
			/*
			 * static inline void set_page_stable_node(struct page *page,
			 *		struct stable_node *stable_node)
			 * {
			 *	page->mapping = (void *)((unsigned long)stable_node | PAGE_MAPPING_KSM);
			 * }
			 */
			set_page_stable_node(page, NULL);
			/* 设置该页的活跃情况 */
			mark_page_accessed(page);
			/*
			 * Page reclaim just frees a clean page with no dirty
			 * ptes: make sure that the ksm page would be swapped.
			 *
			 * 页面回收只是释放一个没有drity的干净的页面
			 * ptes: 确保ksm页面将被交换.
			 */
			if (!PageDirty(page))
				SetPageDirty(page);
			err = 0;
			/* pages_identical再次比较page和kpage内容是否一致,如果一致调用replace_page,
			 * 使用kpage的pfn加上原来page的一些属性构成一个新的pte页表项,然后写入到原来的page的pte页表项中,
			 * 这样原来的page页对应的VMA用户地址空间就和kpage建立了映射关系.
			 */
		} else if (pages_identical(page, kpage))
			err = replace_page(vma, page, kpage, orig_pte);
	}

	if ((vma->vm_flags & VM_LOCKED) && kpage && !err) {
		munlock_vma_page(page);
		if (!PageMlocked(kpage)) {
			unlock_page(page);
			lock_page(kpage);
			mlock_vma_page(kpage);
			page = kpage;		/* for final unlock */
		}
	}

out_unlock:
	unlock_page(page);
out:
	return err;
}

/*
 * try_to_merge_with_ksm_page - like try_to_merge_two_pages,
 * but no new kernel page is allocated: kpage must already be a ksm page.
 *
 * This function returns 0 if the pages were merged, -EFAULT otherwise.
 *
 * try_to_merge_with_ksm_page - 类似于try_to_merge_two_pages,
 * 但没有分配新的内核页面: kpage必须已经是ksm页面.
 *
 * 如果页面已合并,此函数将返回0,否则返回-EFAULT。
 */

/* try_to_merge_with_ksm_page函数中参数page是候选页,rmap_item是候选页对应的rmap_item结构,
 * kpage是stable树中的KSM 页面,尝试把候选页page合并到kpage中
 */
static int try_to_merge_with_ksm_page(struct rmap_item *rmap_item,
				      struct page *page, struct page *kpage)
{
	struct mm_struct *mm = rmap_item->mm;
	struct vm_area_struct *vma;
	int err = -EFAULT;

	/* 接下来需要操作VMA,因此加上一个mm->mmap_sem读者锁 */
	down_read(&mm->mmap_sem);
	/* 这里是通过rmap_item->address 找到可merge的vma */
	vma = find_mergeable_vma(mm, rmap_item->address);
	if (!vma)
		goto out;
	/* try_to_merge_one_page尝试合并page到kpage */
	err = try_to_merge_one_page(vma, page, kpage);
	if (err)
		goto out;

	/* Unstable nid is in union with stable anon_vma: remove first
	 * 不稳定的nid和稳定的anon_vma结合,首先移除它
	 */
	/* 把它的rmap_item从相应的tree上拔掉(stable_tree or unstable_tree) */
	remove_rmap_item_from_tree(rmap_item);

	/* Must get reference to anon_vma while still holding mmap_sem
	 * 必须在保持mmap_sem的同时获取对anon_vm的引用
	 */
	/* 设置rmap_item->anon_vma设置为vma->anon_vma */
	rmap_item->anon_vma = vma->anon_vma;
	/* 让vma->anon_vma计数 +1 */
	get_anon_vma(vma->anon_vma);
out:
	up_read(&mm->mmap_sem);
	return err;
}

/*
 * try_to_merge_two_pages - take two identical pages and prepare them
 * to be merged into one page.
 *
 * This function returns the kpage if we successfully merged two identical
 * pages into one ksm page, NULL otherwise.
 *
 * Note that this function upgrades page to ksm page: if one of the pages
 * is already a ksm page, try_to_merge_with_ksm_page should be used.
 *
 * try_to_merge_two_pages - 取两个相同的页面,准备将它们合并为一个页面.
 *
 * 如果我们成功地将两个相同的页面合并为一个ksm页面,此函数将返回kpage,否则返回NULL.
 * 请注意,此功能将页面升级为ksm页面: 如果其中一个页面已经是ksm页面,则应使用try_to_merge_with_ksm_page.
 */
static struct page *try_to_merge_two_pages(struct rmap_item *rmap_item,
					   struct page *page,
					   struct rmap_item *tree_rmap_item,
					   struct page *tree_page)
{
	int err;
	/* 这里调用了两次try_to_merge_with_ksm_page(),注意这两次调用的参数不一样,实现的功能也不一样 */
	/* 第一次,参数是候选者page和对应的rmap_item,kpage为NULL,因此第一次调用主要是想把page的页表设置为写保护,并且把该页设置为KSM节点 */
	err = try_to_merge_with_ksm_page(rmap_item, page, NULL);
	if (!err) {
		/* 第二次,参数变成了tree_page和对应的tree_rmap_item,kpage为候选者page,
		 * 因此这里要实现的功能是把tree_page的页面设置为写保护,然后再比较tree_page和page之间的内容是否一致.
		 * 在查找unstable树时已经做过页面内容的比较,为什么这里还需要再比较一次呢?
		 * 因为在这个过程中,页面有可能被别的进程修改了内容.
		 * 当两个页面内容确保一致后,借用page的pfn来重新生成一个页表项并设置到tree_page的页表中,
		 * 也就是tree_page对应的进程虚拟地址和物理地址page重新建立了映射关系,
		 * tree_page和page合并成一个KSM页面,page作为KSM页面的联络点
		 */
		err = try_to_merge_with_ksm_page(tree_rmap_item,
							tree_page, page);
		/*
		 * If that fails, we have a ksm page with only one pte
		 * pointing to it: so break it.
		 *
		 * 如果失败,我们会得到一个只有一个pte指向它的ksm页面: 所以break它
		 */
		/* 处理已经把页面设置成写保护的情况,人为造一个写错误的缺页中断,即写时复制(COW)的场景 */
		if (err)
			break_cow(rmap_item);
	}
	return err ? NULL : page;
}

/*
 * stable_tree_search - search for page inside the stable tree
 *
 * This function checks if there is a page inside the stable tree
 * with identical content to the page that we are scanning right now.
 *
 * This function returns the stable tree node of identical content if found,
 * NULL otherwise.
 *
 * stable_tree_search - 在stable tree中搜索页面
 *
 * 此函数检查stable tree中是否有与我们现在扫描的页面内容相同的页面.
 *
 * 如果找到,此函数将返回内容相同的stable tree节点,否则返回NULL.
 */
static struct page *stable_tree_search(struct page *page)
{
	int nid;
	struct rb_root *root;
	struct rb_node **new;
	struct rb_node *parent;
	struct stable_node *stable_node;
	struct stable_node *page_node;

	/* 如果page已经是stable page,
	 * 如果不支持ksm迁移,且物理页做了numa node迁移.
	 * 则把stable node迁移至migrate_nodes上.
	 * 否则它已经在stable树上了,直接返回
	 */
	page_node = page_stable_node(page);
	if (page_node && page_node->head != &migrate_nodes) {
		/* ksm page forked */
		get_page(page);
		return page;
	}

	/* 这里找到node id */
	nid = get_kpfn_nid(page_to_pfn(page));
	/* 找到本地node的root_stable_tree */
	root = root_stable_tree + nid;
again:
	/* 拿到该红黑树的根的rb_node */
	new = &root->rb_node;
	/* 设置parent = NULL */
	parent = NULL;

	while (*new) {
		struct page *tree_page;
		int ret;

		cond_resched();
		/* 这边是去通过node拿到stable_node结构体 */
		stable_node = rb_entry(*new, struct stable_node, node);
		/* get_ksm_page函数把对应的stable节点转换为struct page数据结构.
		 * stable节点中有一个成员kpfn存放着页帧号,通过页帧号可以求出对应的page数据结构tree_page,注意这个函数会增加该节点的tree_page的_count引用计数
		 */
		tree_page = get_ksm_page(stable_node, false);
		if (!tree_page) {
			/*
			 * If we walked over a stale stable_node,
			 * get_ksm_page() will call rb_erase() and it
			 * may rebalance the tree from under us. So
			 * restart the search from scratch. Returning
			 * NULL would be safe too, but we'd generate
			 * false negative insertions just because some
			 * stable_node was stale.
			 *
			 * 如果我们遍历一个过时的stable_node,get_ksm_page()将调用rb_erase(),它
			 * 可能会重新平衡我们脚下的树.
			 * 所以从头开始搜索.返回NULL也是安全的,
			 * 但我们会生成假的负面的插入,因为有些stable_node已过时.
			 */
			goto again;
		}

		/* 通过memcmp_pages来对比page和tree_page内容不一样,这个是很常规的操作,可以看一下这个函数 */
		ret = memcmp_pages(page, tree_page);
		/* 调用put_page来减少tree_page的_refcount引用计数,
		 * 之前get_ksm_page对该页增加了引用计数.
		 */
		put_page(tree_page);

		/* 如果不一致,则继续搜索红黑树的叶节点 */
		/* 把new设置为parent */
		parent = *new;
		/* 小于0,就找rb_left */
		if (ret < 0)
			new = &parent->rb_left;
		else if (ret > 0)	/* 大于0就找rb_right */
			new = &parent->rb_right;
		else {
			/* 这里是page和tree_page内容一致的情况 */
			/*
			 * Lock and unlock the stable_node's page (which
			 * might already have been migrated) so that page
			 * migration is sure to notice its raised count.
			 * It would be more elegant to return stable_node
			 * than kpage, but that involves more changes.
			 *
			 * lock并unlock stable_node的页面(可能已经迁移)以便页面迁移一定会注意到其引发的计数.
			 * 返回stable_node比kpage更优雅,但这涉及到更多的更改.
			 */

			/* 这里重新用get_ksm_page增加tree_page的引用计数,其实就是让页面迁移模块(page migration)知道这里在使用这个页面,最后返回tree_page. */
			tree_page = get_ksm_page(stable_node, true);
			/* 如果找到这个page */
			if (tree_page) {
				/* 释放tree_page */
				unlock_page(tree_page);
				/* 这里判断stable_node->kpfn的node id是不是跟stable_node->nid一样的
				 * 也就是说页面和stable_node不在一个node上,注意结点的id和我们所在页面的id是一样的
				 */
				if (get_kpfn_nid(stable_node->kpfn) !=
						NUMA(stable_node->nid)) {
					/* 如果不一样,那么就put_page之后goto replace */
					put_page(tree_page);
					goto replace;
				}
				/* 如果一致,那么就返回tree_page */
				return tree_page;
			}
			/*
			 * There is now a place for page_node, but the tree may
			 * have been rebalanced, so re-evaluate parent and new.
			 *
			 * 现在有一个page_node的位置,但树可能已经被重新平衡,所以重新评估父节点和新节点
			 */
			/* 如果页面在做迁移,那么goto again */
			if (page_node)
				goto again;
			/* 如果没找到tree_page,page_node也没有,也就是啥都没有 */
			return NULL;
		}
	}

	/* 如果page_node为NULL,那么直接返回,说明在这stable tree里面没有页面和page内容一样,那么直接返回NULL */
	if (!page_node)
		return NULL;
	/* 到这里就是说你虽然没有找到相同内容的page,但是page_node是有的并且是在迁移的node */
	/* 把page_node从migrate_node链表里面删除 */
	list_del(&page_node->list);
	/* 把page_node->nid设置为nid */
	DO_NUMA(page_node->nid = nid);
	/* 插入到红黑树的位置 */
	rb_link_node(&page_node->node, parent, new);
	rb_insert_color(&page_node->node, root);
	/* 让page->_refcount + 1 */
	get_page(page);
	return page;

replace:
	/* 我来理一下进入这个条件的原因
	 * 1、有page_node,但是是在迁移的node里面
	 * 2、我先拿到我这个page所在的node的id
	 * 3、我在我这个node的root_stable中查找
	 * 4、找到了一样的页面的,很不辛,这个stable_node的页面又没有在这个node上
	 * 5、那对于我来说很爽了啊,这不就是给我找了个位置,我就把它替换进去
	 */
	/* 如果我是迁移中的page_node */
	if (page_node) {
		/* 那么把我从迁移列表中删除 */
		list_del(&page_node->list);
		/* page_node->nid = nid,这个id就是传进来的page的nid */
		DO_NUMA(page_node->nid = nid);
		/* 用page_node->node代替stable_node->node */
		rb_replace_node(&stable_node->node, &page_node->node, root);
		get_page(page);
	} else {
		/* 我的页面都已经不在你这个节点上了,那就把它从这上面擦除掉吧 */
		rb_erase(&stable_node->node, root);
		page = NULL;
	}
	/* 把它放到迁移node上 */
	stable_node->head = &migrate_nodes;
	list_add(&stable_node->list, stable_node->head);
	/* 返回这个page */
	return page;
}

/*
 * stable_tree_insert - insert stable tree node pointing to new ksm page
 * into the stable tree.
 *
 * This function returns the stable tree node just allocated on success,
 * NULL otherwise.
 *
 * stable_tree_insert - 将指向新ksm页面的稳定树节点插入到稳定树中.
 *
 * 此函数返回刚刚在成功时分配的稳定树节点,否则为NULL.
 */
static struct stable_node *stable_tree_insert(struct page *kpage)
{
	int nid;
	unsigned long kpfn;
	struct rb_root *root;
	struct rb_node **new;
	struct rb_node *parent;
	struct stable_node *stable_node;

	/* 拿到该page的pfn */
	kpfn = page_to_pfn(kpage);
	/* 拿到该pfn所在的node id */
	nid = get_kpfn_nid(kpfn);
	/* 这里就是找到本节点的root_stable_tree */
	root = root_stable_tree + nid;
again:
	parent = NULL;
	new = &root->rb_node;

	/* 轮询这棵树,找到我们kpage要插入的位置 */
	while (*new) {
		struct page *tree_page;
		int ret;

		cond_resched();
		/* 通过node拿到stable node */
		stable_node = rb_entry(*new, struct stable_node, node);
		/* 拿到stable_node所代表的ksm page */
		tree_page = get_ksm_page(stable_node, false);
		if (!tree_page) {
			/*
			 * If we walked over a stale stable_node,
			 * get_ksm_page() will call rb_erase() and it
			 * may rebalance the tree from under us. So
			 * restart the search from scratch. Returning
			 * NULL would be safe too, but we'd generate
			 * false negative insertions just because some
			 * stable_node was stale.
			 *
			 * 如果我们遍历一个过时的stable_node,get_ksm_page()将调用rb_erase(),它可能会重新平衡我们脚下的树.
			 * 所以从头开始搜索.
			 * 返回NULL也是安全的,但我们会生成假消极插入,因为有些stable_node已过时.
			 */
			goto again;
		}

		/* 通过memcmp_pages来对比page和tree_page内容不一样,这个是很常规的操作,可以看一下这个函数 */
		ret = memcmp_pages(kpage, tree_page);
		/* 调用put_page来减少tree_page的_refcount引用计数 */
		/* 之前get_ksm_page对该页增加了引用计数. */
		put_page(tree_page);

		/* 如果不一致,则继续搜索红黑树的叶节点 */
		/* 把new设置为parent */
		parent = *new;
		if (ret < 0)
			new = &parent->rb_left;
		else if (ret > 0)
			new = &parent->rb_right;
		else {
			/*
			 * It is not a bug that stable_tree_search() didn't
			 * find this node: because at that time our page was
			 * not yet write-protected, so may have changed since.
			 *
			 * stable_tree_search()没有找到这个节点并不是一个bug: 因为当时我们的页面还没有写保护,所以可能已经更改了.
			 */
			return NULL;
		}
	}

	/* 如果都没找到,那我们分配一个stable_node */
	stable_node = alloc_stable_node();
	if (!stable_node)
		return NULL;

	/* 初始化stable_node->hlist */
	INIT_HLIST_HEAD(&stable_node->hlist);
	/* 设置kpfn */
	stable_node->kpfn = kpfn;
	/*
	 * static inline void set_page_stable_node(struct page *page,
	 *				struct stable_node *stable_node)
	 * {
	 *	page->mapping = (void *)((unsigned long)stable_node | PAGE_MAPPING_KSM);
	 * }
	 */
	set_page_stable_node(kpage, stable_node);
	/* 设置stable_node->nid */
	DO_NUMA(stable_node->nid = nid);
	/* 插入到红黑树中 */
	rb_link_node(&stable_node->node, parent, new);
	rb_insert_color(&stable_node->node, root);
	/* 返回stable_node */
	return stable_node;
}

/*
 * unstable_tree_search_insert - search for identical page,
 * else insert rmap_item into the unstable tree.
 *
 * This function searches for a page in the unstable tree identical to the
 * page currently being scanned; and if no identical page is found in the
 * tree, we insert rmap_item as a new object into the unstable tree.
 *
 * This function returns pointer to rmap_item found to be identical
 * to the currently scanned page, NULL otherwise.
 *
 * This function does both searching and inserting, because they share
 * the same walking algorithm in an rbtree.
 *
 * unstatible_tree_search_insert - 搜索相同的页面,否则将rmap_item插入到不稳定的树中.
 *
 * 此功能在unstable tree 中搜索与当前正在扫描的页面相同的页面;
 * 如果在树中没有找到相同的页面,我们将rmap_item作为新对象插入到不稳定的树中.
 *
 * 此函数返回指向与当前扫描的页面相同的rmap_item的指针,否则为NULL.
 *
 * 这个函数同时执行搜索和插入,因为它们在rbtree中共享相同的遍历算法.
 */
static
struct rmap_item *unstable_tree_search_insert(struct rmap_item *rmap_item,
					      struct page *page,
					      struct page **tree_pagep)
{
	struct rb_node **new;
	struct rb_root *root;
	struct rb_node *parent = NULL;
	int nid;
	/* 找到这个页面的node id */
	nid = get_kpfn_nid(page_to_pfn(page));
	/* 拿到这个node id的root_unstable_tree */
	root = root_unstable_tree + nid;
	new = &root->rb_node;
	/* 轮询这棵树 */
	while (*new) {
		struct rmap_item *tree_rmap_item;
		struct page *tree_page;
		int ret;

		cond_resched();
		/* 通过node,拿到rmap_item */
		tree_rmap_item = rb_entry(*new, struct rmap_item, node);
		/* 拿到该tree_rmap_item相关的page */
		tree_page = get_mergeable_page(tree_rmap_item);
		/* 如果tree_page为NULL,那么直接返回NULL */
		if (!tree_page)
			return NULL;

		/*
		 * Don't substitute a ksm page for a forked page.
		 *
		 * 不要用ksm页面代替forked 页面
		 */
		/*
		 * 如果page和tree_page是同一个page
		 * get_mergeable_page会使计数 +1,所以这里-1之后返回NULL
		 */
		if (page == tree_page) {
			put_page(tree_page);
			return NULL;
		}

		/* 通过memcmp_pages来对比page和tree_page内容不一样,这个是很常规的操作,可以看一下这个函数 */
		ret = memcmp_pages(page, tree_page);

		/* 如果不一致,则继续搜索红黑树的叶节点 */
		/* 把new设置为parent */
		parent = *new;
		/* 小于0,就找rb_left */
		if (ret < 0) {
			put_page(tree_page);
			new = &parent->rb_left;
		/* 大于0就找rb_right */
		} else if (ret > 0) {
			put_page(tree_page);
			new = &parent->rb_right;
			/* 如果ksm_merge_across_nodes被设置了,并且tree_page的node id不等于这个page的node id,也就是tree page已经被迁移到别的node上面去了 */
		} else if (!ksm_merge_across_nodes &&
			   page_to_nid(tree_page) != nid) {
			/*
			 * If tree_page has been migrated to another NUMA node,
			 * it will be flushed out and put in the right unstable
			 * tree next time: only merge with it when across_nodes.
			 *
			 * 如果tree_page已经迁移到另一个NUMA节点,那么下次它将被清除并放在正确的unstable tree中:
			 * 只有当acoss_nodes才能合并.
			 */
			put_page(tree_page);
			return NULL;
		} else {
			/* 这说明找到了,那么就tree_page赋值给tree_pagep,方便带出去
			 * 然后返回tree_rmap_item
			 */
			*tree_pagep = tree_page;
			return tree_rmap_item;
		}
	}

	/* 如果在树种没有找到和候选页面相同的内容,那么会把候选页面也添加到该树中
	 * rmap_item->address的低12比特位用于存放一些标志位,例如UNSTABLE_FLAG(0x100)表示rmap_item在unstable树中,
	 * 另外低8位用于存放全盘扫描的次数seqnr.
	 * unstable树的节点会在一次全盘扫描后被删除,在下一次全盘扫描重新加入到unstable树中.
	 */
	rmap_item->address |= UNSTABLE_FLAG;
	rmap_item->address |= (ksm_scan.seqnr & SEQNR_MASK);
	/* 设置rmap_item->nid为nid */
	DO_NUMA(rmap_item->nid = nid);
	/* 插入到unstable树中 */
	rb_link_node(&rmap_item->node, parent, new);
	rb_insert_color(&rmap_item->node, root);
	/* ksm_pages_unshared表示在unstable树中的节点个数
	 * 所以这里得++
	 */
	ksm_pages_unshared++;
	return NULL;
}

/*
 * stable_tree_append - add another rmap_item to the linked list of
 * rmap_items hanging off a given node of the stable tree, all sharing
 * the same ksm page.
 *
 * stable_tree_append - 将另一个rmap_item添加到挂在稳定树的给定节点上的rmap_items的链接列表中,所有这些都共享同一个ksm页面.
 */
static void stable_tree_append(struct rmap_item *rmap_item,
			       struct stable_node *stable_node)
{
	/* 设置rmap_item的head为stable_node */
	rmap_item->head = stable_node;
	/* 把rmap_item->address带上STABLE_FLAG */
	rmap_item->address |= STABLE_FLAG;
	/* 把它添加到stable_node->hlist中 */
	hlist_add_head(&rmap_item->hlist, &stable_node->hlist);

	/* 如果说还有next,说明不止有我们一个
	 * ksm_pages_sharing计数表示合并到ksm节点中的页面的个数
	 * 那么让我们的ksm_pages_sharing++
	 */
	if (rmap_item->hlist.next)
		ksm_pages_sharing++;
	else	/* 如果只有我们一个,那么stable tree中nodes的数量 ++ */
		ksm_pages_shared++;
}

/*
 * cmp_and_merge_page - first see if page can be merged into the stable tree;
 * if not, compare checksum to previous and if it's the same, see if page can
 * be inserted into the unstable tree, or merged with a page already there and
 * both transferred to the stable tree.
 *
 * @page: the page that we are searching identical page to.
 * @rmap_item: the reverse mapping into the virtual address of this page
 *
 * cmp_and_merge_page - 首先看看页面是否可以合并到稳定的树中;
 * 如果不可以,请将校验和与以前的校验和进行比较,如果校验和相同,请查看页面是否可以插入到不稳定树中,
 * 或者与已经存在的页面合并,然后两者都传输到稳定树中.
 *
 * @page: 我们搜索相同页面的页面.
 * @rmap_item: 反向映射到此页面的虚拟地址
 */

/* page表示刚才扫描mm_slot时找到的一个合格的匿名页面,rmap_item表示该page对应的rmap_item数据结构 */
static void cmp_and_merge_page(struct page *page, struct rmap_item *rmap_item)
{
	struct rmap_item *tree_rmap_item;
	struct page *tree_page = NULL;
	struct stable_node *stable_node;
	struct page *kpage;
	unsigned int checksum;
	int err;

	/* 如果这个页面是stable_node,则page_stable_node返回这个page对应的stable_node,否则返回NULL */
	stable_node = page_stable_node(page);
	/* 如果该page是ksm里面的page */
	if (stable_node) {
		/* 如果stable_node->head不等于migrate_nodes,说明他没有在迁移node里面
		 * 并且kpfn的node id不等于stable_node->nid
		 * 那么就要把它从当前NUMA的stable_node里面的红黑树中给擦除掉,把它加入到migrate_nodes里面
		 * 因为他要迁移到他page所在的那个node
		 */
		if (stable_node->head != &migrate_nodes &&
		    get_kpfn_nid(stable_node->kpfn) != NUMA(stable_node->nid)) {
			rb_erase(&stable_node->node,
				 root_stable_tree + NUMA(stable_node->nid));
			stable_node->head = &migrate_nodes;
			list_add(&stable_node->list, stable_node->head);
		}
		/* 如果stable_node->head不是migrate_nodes,也就是说它没有在migrate_nodes里面
		 * 并且rmap_item->head == stable_node,那可以直接返回了,啥事也不用干
		 */
		if (stable_node->head != &migrate_nodes &&
		    rmap_item->head == stable_node)
			return;
	}

	/* We first start with searching the page inside the stable tree
	 * 我们首先从stable tree中搜索这个页面
	 */
	kpage = stable_tree_search(page);
	/* 如果找到的stable页kpage和page是同一个页面,说明该页已经是KSM页面,不需要继续处理,直接返回.
	 * put_page减少page->_refcount引用计数,注意page在scan_get_next_rmap_item()->follow_page()时给该页增加了_count引用计数
	 * rmap_item->head表示加入stable红黑树的节点,如果和stable_node相同,那就什么都不用做了
	 */
	if (kpage == page && rmap_item->head == stable_node) {
		put_page(kpage);
		return;
	}

	/* 你都准备合并了,那么不把你从相应的树摘下来
	 * 这里主要说的是unstable tree中的node把
	 */
	remove_rmap_item_from_tree(rmap_item);

	/* 如果在stable红黑树中找到了一个页面相同的节点,那么调用try_to_merge_with_ksm_page来尝试合并这个页面到节点上 */
	if (kpage) {
		err = try_to_merge_with_ksm_page(rmap_item, page, kpage);
		if (!err) {
			/*
			 * The page was successfully merged:
			 * add its rmap_item to the stable tree.
			 */
			/* 合并成功后,stable_tree_append会把rmap_item添加到stable_node->hlist哈希链表上 */
			lock_page(kpage);
			stable_tree_append(rmap_item, page_stable_node(kpage));
			unlock_page(kpage);
		}
		/* 将kpage计数-1 */
		put_page(kpage);
		return;
	}

	/*
	 * If the hash value of the page has changed from the last time
	 * we calculated it, this page is changing frequently: therefore we
	 * don't want to insert it in the unstable tree, and we don't want
	 * to waste our time searching for something identical to it there.
	 *
	 * 如果页面的哈希值与上次计算时相比发生了变化,则该页面会频繁变化:
	 * 因此,我们不想将其插入不稳定的树中,也不想浪费时间在那里搜索与之相同的内容.
	 */

	/* 如果在stable红黑树中没能找到和page内容相同的节点 */
	/* 重新计算该页的效验值.
	 * 如果效验值发生变化,说明该页面的内容被频繁修改,这种页面不适合添加到unstable红黑树中
	 */
	checksum = calc_checksum(page);
	if (rmap_item->oldchecksum != checksum) {
		rmap_item->oldchecksum = checksum;
		return;
	}

	/* unstable_tree_search_insert搜索unstable红黑树中是否有和该页内容相同的节点
	 * 如果没有,就把它插入到unstable的红黑树中
	 */
	tree_rmap_item =
		unstable_tree_search_insert(rmap_item, page, &tree_page);
	/* 如果没有返回NULL,那么说明在unstable里面找到了和该页内容相同的节点 */
	if (tree_rmap_item) {
		kpage = try_to_merge_two_pages(rmap_item, page,
						tree_rmap_item, tree_page);
		put_page(tree_page);
		if (kpage) {
			/*
			 * The pages were successfully merged: insert new
			 * node in the stable tree and add both rmap_items.
			 *
			 * 页面已成功合并: 在稳定树中插入新节点并添加两个rmap_items.
			 */
			lock_page(kpage);
			/* 把这个kpage插入到stable tree中 */
			stable_node = stable_tree_insert(kpage);
			/* 如果分配好了stable_node */
			if (stable_node) {
				/* 将tree_rmap_item和rmap_item都链接到这个stable_node上来 */
				stable_tree_append(tree_rmap_item, stable_node);
				stable_tree_append(rmap_item, stable_node);
			}
			unlock_page(kpage);

			/*
			 * If we fail to insert the page into the stable tree,
			 * we will have 2 virtual addresses that are pointing
			 * to a ksm page left outside the stable tree,
			 * in which case we need to break_cow on both.
			 *
			 * 如果我们未能将页面插入到stable tree中,我们将有两个虚拟地址指向稳定树外的ksm页面,在这种情况下,我们需要对这两个地址进行break_cow.
			 */
			/* 如果没能够插入到stable_tree中,因为已经把页面设置成写保护的情况了,那么人造一个写错误的缺页中断出来,把它分离 */
			if (!stable_node) {
				break_cow(tree_rmap_item);
				break_cow(rmap_item);
			}
		}
	}
}

static struct rmap_item *get_next_rmap_item(struct mm_slot *mm_slot,
					    struct rmap_item **rmap_list,
					    unsigned long addr)
{
	struct rmap_item *rmap_item;

	/* 如果*rmap_list不是空 */
	while (*rmap_list) {
		/* 取他的值 */
		rmap_item = *rmap_list;
		/* 如果地址能对得上,那么就直接返回 rmap_item */
		if ((rmap_item->address & PAGE_MASK) == addr)
			return rmap_item;
		/* 如果说rmap_item->address > addr,那么break */
		if (rmap_item->address > addr)
			break;
		/* 所有的rmap_item连接成一个链表,链表头在ksm_scan.rmap_list中
		 * 这里就是指向下一个rmap_item
		 *
		 * 所以这里就是起到一个循环作用
		 */
		*rmap_list = rmap_item->rmap_list;
		remove_rmap_item_from_tree(rmap_item);
		free_rmap_item(rmap_item);
	}

	/* 这里就是分配rmap_item */
	rmap_item = alloc_rmap_item();
	if (rmap_item) {
		/* It has already been zeroed */
		/* 设置rmap_item->mm = mm_slot->mm */
		rmap_item->mm = mm_slot->mm;
		/* 设置rmap_item->rmap_list 指向*rmap_list */
		rmap_item->address = addr;
		/* 把它指向*rmap_list,实际上就是指向了它后面那个rmap_list
		 * 譬如上面rmap_item->address > addr,
		 * 那么你的rmap_item就指向了它
		 */
		rmap_item->rmap_list = *rmap_list;
		/* 把rmap_list赋值了rmap_item */
		*rmap_list = rmap_item;
	}
	/* 返回rmap_item */
	return rmap_item;
}

static struct rmap_item *scan_get_next_rmap_item(struct page **page)
{
	struct mm_struct *mm;
	struct mm_slot *slot;
	struct vm_area_struct *vma;
	struct rmap_item *rmap_item;
	int nid;

	/* 如果ksm_mm_head.mm_list链表为空,则不进行扫描 */
	if (list_empty(&ksm_mm_head.mm_list))
		return NULL;

	slot = ksm_scan.mm_slot;
	/* ksmd第一次跑的情况,初始化ksm_scan数据结构中的成员ksm_scan.mm_slot、ksm_scan.address和ksm_scan.rmap_list */
	if (slot == &ksm_mm_head) {
		/*
		 * A number of pages can hang around indefinitely on per-cpu
		 * pagevecs, raised page count preventing write_protect_page
		 * from merging them.  Though it doesn't really matter much,
		 * it is puzzling to see some stuck in pages_volatile until
		 * other activity jostles them out, and they also prevented
		 * LTP's KSM test from succeeding deterministically; so drain
		 * them here (here rather than on entry to ksm_do_scan(),
		 * so we don't IPI too often when pages_to_scan is set low).
		 *
		 * 许多页面可以无限期地挂在每cpu页面向量上,增加的页面计数会阻止write_protect_page合并它们.
		 * 虽然这并不重要,令人费解的是,看到一些页面被困在pages_volatile中,直到其他活动将它们挤出,它们也阻止了LTP的KSM测试决定性地成功;
		 * 所以在这里排出它们(在这里而不是在进入ksm_do_scan()时,所以当pages_to_scan设置为低时,我们不会经常使用IPI.
		 */
		lru_add_drain_all();

		/*
		 * Whereas stale stable_nodes on the stable_tree itself
		 * get pruned in the regular course of stable_tree_search(),
		 * those moved out to the migrate_nodes list can accumulate:
		 * so prune them once before each full scan.
		 *
		 * 在stable_tree_search()的常规过程中,stable_tree上过时的stable_node本身会被修剪,而那些被移到migrate_nodes列表中的节点可能会累积:
		 * 所以在每次完全扫描之前修剪一次.
		 */
		if (!ksm_merge_across_nodes) {
			struct stable_node *stable_node, *next;
			struct page *page;

			list_for_each_entry_safe(stable_node, next,
						 &migrate_nodes, list) {
				page = get_ksm_page(stable_node, false);
				if (page)
					put_page(page);
				cond_resched();
			}
		}

		for (nid = 0; nid < ksm_nr_node_ids; nid++)
			root_unstable_tree[nid] = RB_ROOT;

		spin_lock(&ksm_mmlist_lock);
		/* 这里就是把slot->mm_list.next的mm_slot赋值给slot,实际上第一次进来应该是没变的 */
		slot = list_entry(slot->mm_list.next, struct mm_slot, mm_list);
		/* 把ksm_scan.mm_slot赋值为slot */
		ksm_scan.mm_slot = slot;
		spin_unlock(&ksm_mmlist_lock);
		/*
		 * Although we tested list_empty() above, a racing __ksm_exit
		 * of the last mm on the list may have removed it since then.
		 *
		 * 尽管我们在上面测试了list_empty(),但从那时起,列表上最后一个mm的竞态__ksm_exit可能已经将其删除.
		 */
		if (slot == &ksm_mm_head)
			return NULL;
next_mm:
		/* 设置ksm_scan.address = 0 */
		ksm_scan.address = 0;
		/* 设置ksm_scan.rmap_list为slot->rmap_list */
		ksm_scan.rmap_list = &slot->rmap_list;
	}

	/* 拿到slot->mm */
	mm = slot->mm;
	down_read(&mm->mmap_sem);
	/* 如果mm已经没有人用了,那么直接退出 */
	if (ksm_test_exit(mm))
		vma = NULL;
	else	/* 这里回去找ksm_scan.address中的vma,如果是刚初始化完之后进来,那么这里找的就是这个用户进程的第一个vma */
		vma = find_vma(mm, ksm_scan.address);
	/* for循环遍历所有的VMA */
	for (; vma; vma = vma->vm_next) {
		/* 如果vma->vm_flags不带VM_MERGEABLE,那么continue */
		if (!(vma->vm_flags & VM_MERGEABLE))
			continue;
		/* 如果ksm_scan.address比vma->vm_start小,那么设置ksm_scan.address = vma->vm_start */
		if (ksm_scan.address < vma->vm_start)
			ksm_scan.address = vma->vm_start;
		/* 如果vma没有anon_vma,那么设置ksm_scan.address = vma->vm_end */
		if (!vma->anon_vma)
			ksm_scan.address = vma->vm_end;

		while (ksm_scan.address < vma->vm_end) {
			if (ksm_test_exit(mm))
				break;
			/* 扫描vma中所有的虚拟页面,follow_page函数从虚拟地址开始找回normal mapping页面的struct page数据结构,KSM只会处理匿名的情况 */
			*page = follow_page(vma, ksm_scan.address, FOLL_GET);
			/* 如果是空的,那么设置ksm_scan.address += PAGE_SIZE,然后continue */
			if (IS_ERR_OR_NULL(*page)) {
				ksm_scan.address += PAGE_SIZE;
				cond_resched();
				continue;
			}
			/* 用PageAnon来判断该页是否为匿名页面 */
			if (PageAnon(*page)) {
				/* 冲刷该页对应的cache */
				flush_anon_page(vma, *page, ksm_scan.address);
				flush_dcache_page(*page);
				/* get_next_rmap_item去找mm_slot->rmap_list链表上是否有该虚拟地址对应的ramp_item,没有就新建一个
				 *
				 * 遍历一个进程所有mergeable anon vma中的有物理页的page，跳过device页,
				 * 找到对应address的rmap_item,或为它新创建一个rmap_item,
				 * 上一次扫描到的ksm_scan.rmap_list 到它之间的所有item都
				 * 不再mergable或没有物理页了,需要删除 rmap_item.
				 * (这样一轮下来,整个进程的全部mergable的物理页的rmap,
				 * 就全放在mm_struct->rmap_list上了)
				 */
				rmap_item = get_next_rmap_item(slot,
					ksm_scan.rmap_list, ksm_scan.address);
				/* 如果分配或者找到rmap_item了,那么设置下一次要扫描的人rmap_list和address */
				if (rmap_item) {
					ksm_scan.rmap_list =
							&rmap_item->rmap_list;
					ksm_scan.address += PAGE_SIZE;
				} else	/* 如果没有找到又没有分配,那么就put_page */
					put_page(*page);
				up_read(&mm->mmap_sem);
				return rmap_item;
			}
			/* put_page */
			put_page(*page);
			/* 让ksm_scan.address += PAGE_SIZE 之后接着循环 */
			/* ksm_scan.address += PAGE_SIZE */
			ksm_scan.address += PAGE_SIZE;
			cond_resched();
		}
	}

	/* 如果mm的mm_users等于0,那么这是ksm_scan.address = 0,
	 * ksm_scan.rmap_list为slot->rmap_list
	 *
	 * 运行到这里说明for循环里扫描该进程所有的VMA都没有找到合适的匿名页面,
	 * 因为如果找到一个合适的匿名页面会返回rmap_item的.
	 * 如果被扫描的进程已经被销毁了(mm->mm_users=0),那么设置ksm_scan.address = 0
	 */
	if (ksm_test_exit(mm)) {
		ksm_scan.address = 0;
		ksm_scan.rmap_list = &slot->rmap_list;
	}
	/*
	 * Nuke all the rmap_items that are above this current rmap:
	 * because there were no VM_MERGEABLE vmas with such addresses.
	 *
	 * Nuke所有高于此当前rmap的rmap_items: 因为没有具有此类地址的VM_MERGEABLE vma.
	 */

	/* 在该进程中没有找到合适的匿名页面时,那么对应的rmap_item已经没有用处,为了避免占用内存空间,直接删除掉 */
	/* 这里就是清除ksm_scan.rmap_list下所有的rmap_item */
	remove_trailing_rmap_items(slot, ksm_scan.rmap_list);

	spin_lock(&ksm_mmlist_lock);
	/* 这里就是拿到下一个mm_slot */
	ksm_scan.mm_slot = list_entry(slot->mm_list.next,
						struct mm_slot, mm_list);
	/* 处理该进程被销毁的情况,把mm_slot从ksm_mm_head链表删除,释放mm_slot数据结构,情况mm->flags中的MMF_VM_MERGEBLE标志位 */
	if (ksm_scan.address == 0) {
		/*
		 * We've completed a full scan of all vmas, holding mmap_sem
		 * throughout, and found no VM_MERGEABLE: so do the same as
		 * __ksm_exit does to remove this mm from all our lists now.
		 * This applies either when cleaning up after __ksm_exit
		 * (but beware: we can reach here even before __ksm_exit),
		 * or when all VM_MERGEABLE areas have been unmapped (and
		 * mmap_sem then protects against race with MADV_MERGEABLE).
		 *
		 * 我们已经完成了对所有vma的完整扫描,始终保持mmap_sem,但没有发现VM_MERGEABLE: 所以现在按照__ksm_exit的操作从我们的所有列表中删除此mm.
		 * 这适用于在__ksm_exit之后进行清理时(但请注意: 我们甚至可以在__ksm_exit之前到达这里),
		 * 或者当所有VM_MERGEABLE区域都已取消映射时(然后mmap_sem使用MADV_MERGEABLE防止种族).
		 */
		/* 把它从slot->link中删除 */
		hash_del(&slot->link);
		/* 把它从mm_list中删除 */
		list_del(&slot->mm_list);
		/* 解锁 */
		spin_unlock(&ksm_mmlist_lock);

		/* 释放mm_slot */
		free_mm_slot(slot);
		/* 清除mm->flags中的MMF_VM_MERGEABLE */
		clear_bit(MMF_VM_MERGEABLE, &mm->flags);
		up_read(&mm->mmap_sem);
		/* mm->mm_count 计数 -1 */
		mmdrop(mm);
	} else {
		up_read(&mm->mmap_sem);
		/*
		 * up_read(&mm->mmap_sem) first because after
		 * spin_unlock(&ksm_mmlist_lock) run, the "mm" may
		 * already have been freed under us by __ksm_exit()
		 * because the "mm_slot" is still hashed and
		 * ksm_scan.mm_slot doesn't point to it anymore.
		 *
		 * 首先up_read(&mm->mmap_sem)因为在spin_unlock(&ksm_mmlist_lock)运行后,
		 * __ksm_exit()可能已经释放了“mm”,因为“mm_slot”仍然是散列的,ksm_scan.mm_slot不再指向它.
		 */
		spin_unlock(&ksm_mmlist_lock);
	}

	/* Repeat until we've completed scanning the whole list
	 * 重复此步骤，直到我们完成对整个列表的扫描
	 */
	slot = ksm_scan.mm_slot;
	/* 如果没有扫描完一轮mm_slot,那么就继续扫描下一个mm_slot */
	if (slot != &ksm_mm_head)
		goto next_mm;

	/* 全部扫描完成后会计数一次 */
	ksm_scan.seqnr++;
	return NULL;
}

/**
 * ksm_do_scan  - the ksm scanner main worker function.
 * @scan_npages - number of pages we want to scan before we return.
 */

/* ksm_scan_thread是ksmd内核线程的主干,每次会执行ksm_do_scan函数去扫描和合并100个页面(见ksm_thread_pages_to_scan变量),
 * 然后睡眠等待20毫秒(见ksm_thread_sleep_millisecs变量),这两个参数可以在“/sys/kernel/mm/ksm”目录下的相关参数中设置和修改.
 */
static void ksm_do_scan(unsigned int scan_npages)
{
	struct rmap_item *rmap_item;
	struct page *uninitialized_var(page);

	while (scan_npages-- && likely(!freezing(current))) {
		cond_resched();
		/* scan_get_next_rmap_item获取一个合适的匿名页面page */
		rmap_item = scan_get_next_rmap_item(&page);
		if (!rmap_item)
			return;
		/* cmp_and_merge_page会让page在KSM中stable和unstable的两颗红黑树中查找是否有合适合并的对象,并且尝试去合并他们 */
		cmp_and_merge_page(page, rmap_item);
		put_page(page);
	}
}

static int ksmd_should_run(void)
{
	/* ksm运行有两个条件
	 *
	 * 1、ksm_run 状态是KSM_RUN_MERGE
	 * 2、ksm_mm_head.mm_list不是空的
	 */
	return (ksm_run & KSM_RUN_MERGE) && !list_empty(&ksm_mm_head.mm_list);
}

/* ksm_scan_thread是ksmd内核线程的主干,每次会执行ksm_do_scan函数去扫描和合并100个页面(见ksm_thread_pages_to_scan变量),
 * 然后睡眠等待20毫秒(见ksm_thread_sleep_millisecs变量),
 * 这两个参数可以在“/sys/kernel/mm/ksm”目录下的相关参数中去设置和修改
 */
static int ksm_scan_thread(void *nothing)
{
	set_freezable();
	/* 设置ksmd的nice值为5 */
	set_user_nice(current, 5);

	while (!kthread_should_stop()) {
		mutex_lock(&ksm_thread_mutex);
		/* 这里应该是当ksmd为offline的时候,在这里等着 */
		wait_while_offlining();
		if (ksmd_should_run())
			ksm_do_scan(ksm_thread_pages_to_scan);
		mutex_unlock(&ksm_thread_mutex);

		try_to_freeze();

		if (ksmd_should_run()) {
			schedule_timeout_interruptible(
				msecs_to_jiffies(ksm_thread_sleep_millisecs));
		} else {
			wait_event_freezable(ksm_thread_wait,
				ksmd_should_run() || kthread_should_stop());
		}
	}
	return 0;
}

/* KSM只会处理通过madvise系统调用显示指定的用户进程空间内存,
 * 因此用户程序想使用这个功能就必须在分配内存时显式地调用“madvise(addr,length,MADV_MERGEABLE)”,
 * 如果用户想在KSM中取消一个用户进程地址空间的合并功能,也需要显示地调用madvise(addr,length,MADV_UNMERGEABLE)".
 *
 * 调用链如下:
 * madvise->madvise_vma->madvise_behavior -> ksm_madvise
 */
int ksm_madvise(struct vm_area_struct *vma, unsigned long start,
		unsigned long end, int advice, unsigned long *vm_flags)
{
	struct mm_struct *mm = vma->vm_mm;
	int err;

	/* 这里主要是去处理MADV_MERGEABLE和MADV_UNMERGEABLE的操作 */
	switch (advice) {
	case MADV_MERGEABLE:
		/*
		 * Be somewhat over-protective for now!
		 *
		 * 现在要有点过度保护!
		 */
		/* 如果vm_flags中含有如下flags,那边直接返回0
		 * VM_MERGEABLE: KSM may merge identical pages
		 * VM_SHARED:	 页可以被多个进程共享
		 * VM_MAYSHARE:  VM_WRITE 标志可以被设置
		 * VM_PFNMAP:    VM_PFNMAP表示页帧号(Page Frame Number, PFN)映射,
		 *		 特殊映射不希望关联页描述符,直接使用页帧号,可能是因为页描述符不存在,也可能是因为不想使用页描述符.
		 * VM_IO:	 这个区间映射一个设备的I/O地址空间
		 * VM_DONTEXPAND: 不能用mremap 函数扩展映射区域
		 * VM_HUGETLB:	 HUGETLB
		 * VM_MIXEDMAP:  不能用mremap 函数扩展映射区域
		 */
		if (*vm_flags & (VM_MERGEABLE | VM_SHARED  | VM_MAYSHARE   |
				 VM_PFNMAP    | VM_IO      | VM_DONTEXPAND |
				 VM_HUGETLB | VM_MIXEDMAP))
			return 0;		/* just ignore the advice */

#ifdef VM_SAO
		if (*vm_flags & VM_SAO)
			return 0;
#endif
		/* #define MMF_VM_MERGEABLE	16	KSM may merge identical pages */
		/* 判断MMF_VM_MERGEABLE是否被设置为1,如果被设置了那么就啥也不做 */
		if (!test_bit(MMF_VM_MERGEABLE, &mm->flags)) {
			err = __ksm_enter(mm);
			if (err)
				return err;
		}

		/* 将vm_flags带上VM_MERGEABLE */
		*vm_flags |= VM_MERGEABLE;
		break;

	case MADV_UNMERGEABLE:
		if (!(*vm_flags & VM_MERGEABLE))
			return 0;		/* just ignore the advice */

		if (vma->anon_vma) {
			err = unmerge_ksm_pages(vma, start, end);
			if (err)
				return err;
		}

		*vm_flags &= ~VM_MERGEABLE;
		break;
	}

	return 0;
}

int __ksm_enter(struct mm_struct *mm)
{
	struct mm_slot *mm_slot;
	int needs_wakeup;

	/* 分配mm_sloct数据结构 */
	mm_slot = alloc_mm_slot();
	if (!mm_slot)
		return -ENOMEM;

	/* Check ksm_run too?  Would need tighter locking
	 * 是否也检查ksm_run？需要更紧的锁
	 */

	/* 这里判断ksm_mm_head.mm_list是否为空的 */
	needs_wakeup = list_empty(&ksm_mm_head.mm_list);

	spin_lock(&ksm_mmlist_lock);
	/* 把当前的mm数据结构添加到mm_slot_hash哈希表中 */
	insert_to_mm_slots_hash(mm, mm_slot);
	/*
	 * When KSM_RUN_MERGE (or KSM_RUN_STOP),
	 * insert just behind the scanning cursor, to let the area settle
	 * down a little; when fork is followed by immediate exec, we don't
	 * want ksmd to waste time setting up and tearing down an rmap_list.
	 *
	 * But when KSM_RUN_UNMERGE, it's important to insert ahead of its
	 * scanning cursor, otherwise KSM pages in newly forked mms will be
	 * missed: then we might as well insert at the end of the list.
	 *
	 * 当KSM_RUN_MERGE(或KSM_RUN_STOP)时,插入扫描位置的正后方,使区域稍微稳定下来;
	 * 当fork后面跟immediate exec(立即执行)时,我们不会希望ksmd浪费时间设置和删除rmap_list.
	 *
	 * 但当KSM_RUN_UNMERGE时,重要的是要在其扫描位置之前插入,否则将错过forked mms中的KSM页面: 那么我们不妨在列表的末尾插入.
	 */

	/* 如果ksm_run是KSM_RUN_UNMERGE,将它加入到ksm_mm_head.mm_list链表的尾部,也就是把它插入到ksm_mm_head.mm_list的后面 */
	if (ksm_run & KSM_RUN_UNMERGE)
		list_add_tail(&mm_slot->mm_list, &ksm_mm_head.mm_list);
	else	/* 否则把它加入到ksm_scan.mm_slot->mm_list的尾部,也就是插入到ksm_scan.mm_slot的前面
		 * 这里不能只看初始化的时候,这个ksm_scam.mm_slot一直在变
		 */
		list_add_tail(&mm_slot->mm_list, &ksm_scan.mm_slot->mm_list);
	spin_unlock(&ksm_mmlist_lock);

	/* 设置当前mm->flags为MMF_VM_MERGEABLE,表示该进程已经添加到KSM系统中了 */
	set_bit(MMF_VM_MERGEABLE, &mm->flags);
	/* 增加mm引用计数 */
	atomic_inc(&mm->mm_count);

	/* 如果ksm_mm_head.mm_list链表为空,则唤醒ksmd内核线程 */
	if (needs_wakeup)
		wake_up_interruptible(&ksm_thread_wait);

	return 0;
}

void __ksm_exit(struct mm_struct *mm)
{
	struct mm_slot *mm_slot;
	int easy_to_free = 0;

	/*
	 * This process is exiting: if it's straightforward (as is the
	 * case when ksmd was never running), free mm_slot immediately.
	 * But if it's at the cursor or has rmap_items linked to it, use
	 * mmap_sem to synchronize with any break_cows before pagetables
	 * are freed, and leave the mm_slot on the list for ksmd to free.
	 * Beware: ksm may already have noticed it exiting and freed the slot.
	 */

	spin_lock(&ksm_mmlist_lock);
	mm_slot = get_mm_slot(mm);
	if (mm_slot && ksm_scan.mm_slot != mm_slot) {
		if (!mm_slot->rmap_list) {
			hash_del(&mm_slot->link);
			list_del(&mm_slot->mm_list);
			easy_to_free = 1;
		} else {
			list_move(&mm_slot->mm_list,
				  &ksm_scan.mm_slot->mm_list);
		}
	}
	spin_unlock(&ksm_mmlist_lock);

	if (easy_to_free) {
		free_mm_slot(mm_slot);
		clear_bit(MMF_VM_MERGEABLE, &mm->flags);
		mmdrop(mm);
	} else if (mm_slot) {
		down_write(&mm->mmap_sem);
		up_write(&mm->mmap_sem);
	}
}

struct page *ksm_might_need_to_copy(struct page *page,
			struct vm_area_struct *vma, unsigned long address)
{
	struct anon_vma *anon_vma = page_anon_vma(page);
	struct page *new_page;

	if (PageKsm(page)) {
		if (page_stable_node(page) &&
		    !(ksm_run & KSM_RUN_UNMERGE))
			return page;	/* no need to copy it */
	} else if (!anon_vma) {
		return page;		/* no need to copy it */
	} else if (anon_vma->root == vma->anon_vma->root &&
		 page->index == linear_page_index(vma, address)) {
		return page;		/* still no need to copy it */
	}
	if (!PageUptodate(page))
		return page;		/* let do_swap_page report the error */

	new_page = alloc_page_vma(GFP_HIGHUSER_MOVABLE, vma, address);
	if (new_page) {
		copy_user_highpage(new_page, page, address, vma);

		SetPageDirty(new_page);
		__SetPageUptodate(new_page);
		__SetPageLocked(new_page);
	}

	return new_page;
}

int rmap_walk_ksm(struct page *page, struct rmap_walk_control *rwc)
{
	struct stable_node *stable_node;
	struct rmap_item *rmap_item;
	int ret = SWAP_AGAIN;
	int search_new_forks = 0;

	VM_BUG_ON_PAGE(!PageKsm(page), page);

	/*
	 * Rely on the page lock to protect against concurrent modifications
	 * to that page's node of the stable tree.
	 */
	VM_BUG_ON_PAGE(!PageLocked(page), page);

	stable_node = page_stable_node(page);
	if (!stable_node)
		return ret;
again:
	hlist_for_each_entry(rmap_item, &stable_node->hlist, hlist) {
		struct anon_vma *anon_vma = rmap_item->anon_vma;
		struct anon_vma_chain *vmac;
		struct vm_area_struct *vma;

		cond_resched();
		anon_vma_lock_read(anon_vma);
		anon_vma_interval_tree_foreach(vmac, &anon_vma->rb_root,
					       0, ULONG_MAX) {
			cond_resched();
			vma = vmac->vma;
			if (rmap_item->address < vma->vm_start ||
			    rmap_item->address >= vma->vm_end)
				continue;
			/*
			 * Initially we examine only the vma which covers this
			 * rmap_item; but later, if there is still work to do,
			 * we examine covering vmas in other mms: in case they
			 * were forked from the original since ksmd passed.
			 */
			if ((rmap_item->mm == vma->vm_mm) == search_new_forks)
				continue;

			if (rwc->invalid_vma && rwc->invalid_vma(vma, rwc->arg))
				continue;

			ret = rwc->rmap_one(page, vma,
					rmap_item->address, rwc->arg);
			if (ret != SWAP_AGAIN) {
				anon_vma_unlock_read(anon_vma);
				goto out;
			}
			if (rwc->done && rwc->done(page)) {
				anon_vma_unlock_read(anon_vma);
				goto out;
			}
		}
		anon_vma_unlock_read(anon_vma);
	}
	if (!search_new_forks++)
		goto again;
out:
	return ret;
}

#ifdef CONFIG_MIGRATION
void ksm_migrate_page(struct page *newpage, struct page *oldpage)
{
	struct stable_node *stable_node;

	VM_BUG_ON_PAGE(!PageLocked(oldpage), oldpage);
	VM_BUG_ON_PAGE(!PageLocked(newpage), newpage);
	VM_BUG_ON_PAGE(newpage->mapping != oldpage->mapping, newpage);

	stable_node = page_stable_node(newpage);
	if (stable_node) {
		VM_BUG_ON_PAGE(stable_node->kpfn != page_to_pfn(oldpage), oldpage);
		stable_node->kpfn = page_to_pfn(newpage);
		/*
		 * newpage->mapping was set in advance; now we need smp_wmb()
		 * to make sure that the new stable_node->kpfn is visible
		 * to get_ksm_page() before it can see that oldpage->mapping
		 * has gone stale (or that PageSwapCache has been cleared).
		 */
		smp_wmb();
		set_page_stable_node(oldpage, NULL);
	}
}
#endif /* CONFIG_MIGRATION */

#ifdef CONFIG_MEMORY_HOTREMOVE
static void wait_while_offlining(void)
{
	/* 如果ksm是KSM_RUN_OFFLINE的状态 */
	while (ksm_run & KSM_RUN_OFFLINE) {
		mutex_unlock(&ksm_thread_mutex);
		/* ilog2(KSM_RUN_OFFLINE),也就是ilog2(4)=2
		 */
		wait_on_bit(&ksm_run, ilog2(KSM_RUN_OFFLINE),
			    TASK_UNINTERRUPTIBLE);
		mutex_lock(&ksm_thread_mutex);
	}
}

static void ksm_check_stable_tree(unsigned long start_pfn,
				  unsigned long end_pfn)
{
	struct stable_node *stable_node, *next;
	struct rb_node *node;
	int nid;

	for (nid = 0; nid < ksm_nr_node_ids; nid++) {
		node = rb_first(root_stable_tree + nid);
		while (node) {
			stable_node = rb_entry(node, struct stable_node, node);
			if (stable_node->kpfn >= start_pfn &&
			    stable_node->kpfn < end_pfn) {
				/*
				 * Don't get_ksm_page, page has already gone:
				 * which is why we keep kpfn instead of page*
				 */
				remove_node_from_stable_tree(stable_node);
				node = rb_first(root_stable_tree + nid);
			} else
				node = rb_next(node);
			cond_resched();
		}
	}
	list_for_each_entry_safe(stable_node, next, &migrate_nodes, list) {
		if (stable_node->kpfn >= start_pfn &&
		    stable_node->kpfn < end_pfn)
			remove_node_from_stable_tree(stable_node);
		cond_resched();
	}
}

static int ksm_memory_callback(struct notifier_block *self,
			       unsigned long action, void *arg)
{
	struct memory_notify *mn = arg;

	switch (action) {
	case MEM_GOING_OFFLINE:
		/*
		 * Prevent ksm_do_scan(), unmerge_and_remove_all_rmap_items()
		 * and remove_all_stable_nodes() while memory is going offline:
		 * it is unsafe for them to touch the stable tree at this time.
		 * But unmerge_ksm_pages(), rmap lookups and other entry points
		 * which do not need the ksm_thread_mutex are all safe.
		 */
		mutex_lock(&ksm_thread_mutex);
		ksm_run |= KSM_RUN_OFFLINE;
		mutex_unlock(&ksm_thread_mutex);
		break;

	case MEM_OFFLINE:
		/*
		 * Most of the work is done by page migration; but there might
		 * be a few stable_nodes left over, still pointing to struct
		 * pages which have been offlined: prune those from the tree,
		 * otherwise get_ksm_page() might later try to access a
		 * non-existent struct page.
		 */
		ksm_check_stable_tree(mn->start_pfn,
				      mn->start_pfn + mn->nr_pages);
		/* fallthrough */

	case MEM_CANCEL_OFFLINE:
		mutex_lock(&ksm_thread_mutex);
		ksm_run &= ~KSM_RUN_OFFLINE;
		mutex_unlock(&ksm_thread_mutex);

		smp_mb();	/* wake_up_bit advises this */
		wake_up_bit(&ksm_run, ilog2(KSM_RUN_OFFLINE));
		break;
	}
	return NOTIFY_OK;
}
#else
static void wait_while_offlining(void)
{
}
#endif /* CONFIG_MEMORY_HOTREMOVE */

#ifdef CONFIG_SYSFS
/*
 * This all compiles without CONFIG_SYSFS, but is a waste of space.
 */

#define KSM_ATTR_RO(_name) \
	static struct kobj_attribute _name##_attr = __ATTR_RO(_name)
#define KSM_ATTR(_name) \
	static struct kobj_attribute _name##_attr = \
		__ATTR(_name, 0644, _name##_show, _name##_store)

static ssize_t sleep_millisecs_show(struct kobject *kobj,
				    struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%u\n", ksm_thread_sleep_millisecs);
}

static ssize_t sleep_millisecs_store(struct kobject *kobj,
				     struct kobj_attribute *attr,
				     const char *buf, size_t count)
{
	unsigned long msecs;
	int err;

	err = kstrtoul(buf, 10, &msecs);
	if (err || msecs > UINT_MAX)
		return -EINVAL;

	ksm_thread_sleep_millisecs = msecs;

	return count;
}
KSM_ATTR(sleep_millisecs);

static ssize_t pages_to_scan_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%u\n", ksm_thread_pages_to_scan);
}

static ssize_t pages_to_scan_store(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   const char *buf, size_t count)
{
	int err;
	unsigned long nr_pages;

	err = kstrtoul(buf, 10, &nr_pages);
	if (err || nr_pages > UINT_MAX)
		return -EINVAL;

	ksm_thread_pages_to_scan = nr_pages;

	return count;
}
KSM_ATTR(pages_to_scan);

static ssize_t run_show(struct kobject *kobj, struct kobj_attribute *attr,
			char *buf)
{
	return sprintf(buf, "%lu\n", ksm_run);
}

static ssize_t run_store(struct kobject *kobj, struct kobj_attribute *attr,
			 const char *buf, size_t count)
{
	int err;
	unsigned long flags;

	err = kstrtoul(buf, 10, &flags);
	if (err || flags > UINT_MAX)
		return -EINVAL;
	if (flags > KSM_RUN_UNMERGE)
		return -EINVAL;

	/*
	 * KSM_RUN_MERGE sets ksmd running, and 0 stops it running.
	 * KSM_RUN_UNMERGE stops it running and unmerges all rmap_items,
	 * breaking COW to free the pages_shared (but leaves mm_slots
	 * on the list for when ksmd may be set running again).
	 */

	mutex_lock(&ksm_thread_mutex);
	wait_while_offlining();
	if (ksm_run != flags) {
		ksm_run = flags;
		if (flags & KSM_RUN_UNMERGE) {
			set_current_oom_origin();
			err = unmerge_and_remove_all_rmap_items();
			clear_current_oom_origin();
			if (err) {
				ksm_run = KSM_RUN_STOP;
				count = err;
			}
		}
	}
	mutex_unlock(&ksm_thread_mutex);

	if (flags & KSM_RUN_MERGE)
		wake_up_interruptible(&ksm_thread_wait);

	return count;
}
KSM_ATTR(run);

#ifdef CONFIG_NUMA
static ssize_t merge_across_nodes_show(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%u\n", ksm_merge_across_nodes);
}

static ssize_t merge_across_nodes_store(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   const char *buf, size_t count)
{
	int err;
	unsigned long knob;

	err = kstrtoul(buf, 10, &knob);
	if (err)
		return err;
	if (knob > 1)
		return -EINVAL;

	mutex_lock(&ksm_thread_mutex);
	wait_while_offlining();
	if (ksm_merge_across_nodes != knob) {
		if (ksm_pages_shared || remove_all_stable_nodes())
			err = -EBUSY;
		else if (root_stable_tree == one_stable_tree) {
			struct rb_root *buf;
			/*
			 * This is the first time that we switch away from the
			 * default of merging across nodes: must now allocate
			 * a buffer to hold as many roots as may be needed.
			 * Allocate stable and unstable together:
			 * MAXSMP NODES_SHIFT 10 will use 16kB.
			 */
			buf = kcalloc(nr_node_ids + nr_node_ids, sizeof(*buf),
				      GFP_KERNEL);
			/* Let us assume that RB_ROOT is NULL is zero */
			if (!buf)
				err = -ENOMEM;
			else {
				root_stable_tree = buf;
				root_unstable_tree = buf + nr_node_ids;
				/* Stable tree is empty but not the unstable */
				root_unstable_tree[0] = one_unstable_tree[0];
			}
		}
		if (!err) {
			ksm_merge_across_nodes = knob;
			ksm_nr_node_ids = knob ? 1 : nr_node_ids;
		}
	}
	mutex_unlock(&ksm_thread_mutex);

	return err ? err : count;
}
KSM_ATTR(merge_across_nodes);
#endif

static ssize_t pages_shared_show(struct kobject *kobj,
				 struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%lu\n", ksm_pages_shared);
}
KSM_ATTR_RO(pages_shared);

static ssize_t pages_sharing_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%lu\n", ksm_pages_sharing);
}
KSM_ATTR_RO(pages_sharing);

static ssize_t pages_unshared_show(struct kobject *kobj,
				   struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%lu\n", ksm_pages_unshared);
}
KSM_ATTR_RO(pages_unshared);

static ssize_t pages_volatile_show(struct kobject *kobj,
				   struct kobj_attribute *attr, char *buf)
{
	long ksm_pages_volatile;

	ksm_pages_volatile = ksm_rmap_items - ksm_pages_shared
				- ksm_pages_sharing - ksm_pages_unshared;
	/*
	 * It was not worth any locking to calculate that statistic,
	 * but it might therefore sometimes be negative: conceal that.
	 */
	if (ksm_pages_volatile < 0)
		ksm_pages_volatile = 0;
	return sprintf(buf, "%ld\n", ksm_pages_volatile);
}
KSM_ATTR_RO(pages_volatile);

static ssize_t full_scans_show(struct kobject *kobj,
			       struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%lu\n", ksm_scan.seqnr);
}
KSM_ATTR_RO(full_scans);

static struct attribute *ksm_attrs[] = {
	&sleep_millisecs_attr.attr,
	&pages_to_scan_attr.attr,
	&run_attr.attr,
	&pages_shared_attr.attr,
	&pages_sharing_attr.attr,
	&pages_unshared_attr.attr,
	&pages_volatile_attr.attr,
	&full_scans_attr.attr,
#ifdef CONFIG_NUMA
	&merge_across_nodes_attr.attr,
#endif
	NULL,
};

static struct attribute_group ksm_attr_group = {
	.attrs = ksm_attrs,
	.name = "ksm",
};
#endif /* CONFIG_SYSFS */

static int __init ksm_init(void)
{
	struct task_struct *ksm_thread;
	int err;

	/* 这里只要是用来初始化ksm用到的slab */
	err = ksm_slab_init();
	if (err)
		goto out;

	/* 创建ksm线程 */
	ksm_thread = kthread_run(ksm_scan_thread, NULL, "ksmd");
	if (IS_ERR(ksm_thread)) {
		pr_err("ksm: creating kthread failed\n");
		err = PTR_ERR(ksm_thread);
		goto out_free;
	}

#ifdef CONFIG_SYSFS
	/* 这里就是在/sys/kernel/mm/ksm/下面创建相应的文件节点 */
	err = sysfs_create_group(mm_kobj, &ksm_attr_group);
	if (err) {
		pr_err("ksm: register sysfs failed\n");
		kthread_stop(ksm_thread);
		goto out_free;
	}
#else
	/* 如果没有配置CONFIG_SYSFS,那么设置ksm_run为KSM_RUN_MERGE,也就是默认启动
	 * 因为对外没有接口可以启动它,所以默认启动
	 */
	ksm_run = KSM_RUN_MERGE;	/*
					 * no way for user to start it
					 * 用户无法启动它
					 */

#endif /* CONFIG_SYSFS */

#ifdef CONFIG_MEMORY_HOTREMOVE
	/* There is no significance to this priority 100 */
	hotplug_memory_notifier(ksm_memory_callback, 100);
#endif
	return 0;

out_free:
	ksm_slab_free();
out:
	return err;
}
subsys_initcall(ksm_init);
