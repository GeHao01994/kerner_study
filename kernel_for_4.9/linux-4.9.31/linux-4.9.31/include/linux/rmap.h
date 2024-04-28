#ifndef _LINUX_RMAP_H
#define _LINUX_RMAP_H
/*
 * Declarations for Reverse Mapping functions in mm/rmap.c
 */

#include <linux/list.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/rwsem.h>
#include <linux/memcontrol.h>

/*
 * The anon_vma heads a list of private "related" vmas, to scan if
 * an anonymous page pointing to this anon_vma needs to be unmapped:
 * the vmas on the list will be related by forking, or by splitting.
 *
 * Since vmas come and go as they are split and merged (particularly
 * in mprotect), the mapping field of an anonymous page cannot point
 * directly to a vma: instead it points to an anon_vma, on whose list
 * the related vmas can be easily linked or unlinked.
 *
 * After unlinking the last vma on the list, we must garbage collect
 * the anon_vma object itself: we're guaranteed no page can be
 * pointing to this anon_vma once its vma list is empty.
 *
 * anon_vma是私有"related" vma列表的头,用于扫描是否需要取消映射指向该anon_vm的匿名页面:
 * 列表上的vma将依赖于forking或者拆分,
 *
 * 由于vma是在拆分和合并时出现和消失的(特别是在mprotect中),因此匿名页面的映射字段不能直接指向vma: 相反,它指向一个anon_vm,
 * 相关的vma可以很容易地在其列表上链接或取消链接。
 *
 * 在取消列表上最后一个vma的链接后,我们必须对anon_vm对象本身进行垃圾收集: 我们保证一旦其vma列表为空,就没有页面可以指向该anon_vm.
 *
 * 用户进程在使用虚拟内存过程中,从虚拟内存页面映射到物理内存页面,PTE页表项保留着这个记录,
 * page 数据结构中的_mapcount成员记录有多少个用户PTE页表项映射了物理页面.
 * 用户PTE页表项是指用户进程地址空间和物理页面建立映射的PTE页表项,不包括内核地址空间映射物理页面产生的PTE页表项.
 * 有的页面需要被迁移,有的页面长时间不适用需要被交换到磁盘.
 * 在交换之前,必须找出哪些进程使用这个页面,然后断开这些映射的PTE.
 * 一个物理页面可以同时被多个进程的虚拟内存映射,一个虚拟页面同时只有有一个物理页面与之映射.
 */

/* RMAP反向映射系统中有两个重要的数据结构,一个是anon_vma,简称AV;
 * 另一个是anon_vma_chain,简称AVC.
 */
struct anon_vma {
	/* 指向anon_vma数据结构中的根节点 */
	struct anon_vma *root;		/* Root of this anon_vma tree */
	/* 保护anon_vma中链表的读写信号量 */
	struct rw_semaphore rwsem;	/* W: modification, R: walking the list */
	/*
	 * The refcount is taken on an anon_vma when there is no
	 * guarantee that the vma of page tables will exist for
	 * the duration of the operation. A caller that takes
	 * the reference is responsible for clearing up the
	 * anon_vma if they are the last user on release
	 *
	 * 当不能保证页表的vma在操作期间存在时,refcount是在anon_vm上获取的.
	 * 如果调用方是release时的最后一个用户,则接受引用的调用方负责清除anon_vm.
	 */

	/* 引用计数 */
	atomic_t refcount;

	/*
	 * Count of child anon_vmas and VMAs which points to this anon_vma.
	 *
	 * This counter is used for making decision about reusing anon_vma
	 * instead of forking new one. See comments in function anon_vma_clone.
	 *
	 * 指向此anon_vm的子anon_vm和vma的计数.
	 *
	 * 此计数器用于决定是否重用anon_vm,而不是forking新的.
	 * 请参见函数anon_vma_clone中的注释.
	 */
	unsigned degree;
	/* 指向父anon_vma数据结构 */
	struct anon_vma *parent;	/* Parent of this anon_vma */

	/*
	 * NOTE: the LSB of the rb_root.rb_node is set by
	 * mm_take_all_locks() _after_ taking the above lock. So the
	 * rb_root must only be read/written after taking the above lock
	 * to be sure to see a valid next pointer. The LSB bit itself
	 * is serialized by a system wide lock only visible to
	 * mm_take_all_locks() (mm_all_locks_mutex).
	 *
	 * 注意: rb_root.rb_node的LSB是通过mm_take_all_locks()_after_ 获取上述锁来设置的.
	 * 因此,rb_root必须在获取上述锁之后才能进行读/写以确保看到有效的下一个指针.
	 * LSB位本身由仅对mm_take_all_locks()可见的系统范围锁(mm_all_lacks_mutex)序列化.
	 */

	/* 红黑树根节点. anon_vma内部有一课红黑树 */
	struct rb_root rb_root;	/* Interval tree of private "related" vmas */
};

/*
 * The copy-on-write semantics of fork mean that an anon_vma
 * can become associated with multiple processes. Furthermore,
 * each child process will have its own anon_vma, where new
 * pages for that process are instantiated.
 *
 * This structure allows us to find the anon_vmas associated
 * with a VMA, or the VMAs associated with an anon_vma.
 * The "same_vma" list contains the anon_vma_chains linking
 * all the anon_vmas associated with this VMA.
 * The "rb" field indexes on an interval tree the anon_vma_chains
 * which link all the VMAs associated with this anon_vma.
 *
 * fork的copy-on-write 语义意味着一个anon_vm可以与多个进程相关联.此外,每个子进程都将有自己的anon_vm,在其中实例化该进程的新页面.
 *
 * 该结构允许我们找到与VMA相关联的anon_vm,或与anon_vm相关联的VMA.
 * "same_vma" 列表包含链接与此vma关联的所有anon_vma的anon_vma_chains.
 * "rb"字段在区间树上索引anon_vma_chains,该链链接与该anon_vma相关联的所有vma.
 */

/* struct anon_vma_chain数据结构是连接父子进程中的枢纽,定义如下: */
struct anon_vma_chain {
	/* 指向VMA,可以指向父进程的VMA,也可以指向子进程的VMA,具体情况需要具体分析 */
	struct vm_area_struct *vma;
	/* anon_vma: 指向anon_vam数据结构,可以指向父进程的anon_vma数据结构,也可以指向子进程的anon_vma数据结构,具体问题需要具体分析 */
	struct anon_vma *anon_vma;
	/* 链表节点,通常把anon_vma_chain添加到anon_vma->rb_root的红黑树中 */
	struct list_head same_vma;   /* locked by mmap_sem & page_table_lock */
	struct rb_node rb;			/* locked by anon_vma->rwsem */
	unsigned long rb_subtree_last;
#ifdef CONFIG_DEBUG_VM_RB
	unsigned long cached_vma_start, cached_vma_last;
#endif
};

enum ttu_flags {
	TTU_UNMAP = 1,			/* unmap mode */
	TTU_MIGRATION = 2,		/* migration mode */
	TTU_MUNLOCK = 4,		/* munlock mode */
	TTU_LZFREE = 8,			/* lazy free mode */
	TTU_SPLIT_HUGE_PMD = 16,	/* split huge PMD if any */

	TTU_IGNORE_MLOCK = (1 << 8),	/* ignore mlock */
	TTU_IGNORE_ACCESS = (1 << 9),	/* don't age */
	TTU_IGNORE_HWPOISON = (1 << 10),/* corrupted page is recoverable */
	TTU_BATCH_FLUSH = (1 << 11),	/* Batch TLB flushes where possible
					 * and caller guarantees they will
					 * do a final flush if necessary */
	TTU_RMAP_LOCKED = (1 << 12)	/* do not grab rmap lock:
					 * caller holds it */
};

#ifdef CONFIG_MMU
static inline void get_anon_vma(struct anon_vma *anon_vma)
{
	atomic_inc(&anon_vma->refcount);
}

void __put_anon_vma(struct anon_vma *anon_vma);

static inline void put_anon_vma(struct anon_vma *anon_vma)
{
	/* 将anon_vma->refcount -1 之后判断是否等于0
	 * 如果等于就调用__put_anon_vma去释放anon_vma
	 */
	if (atomic_dec_and_test(&anon_vma->refcount))
		__put_anon_vma(anon_vma);
}

static inline void anon_vma_lock_write(struct anon_vma *anon_vma)
{
	down_write(&anon_vma->root->rwsem);
}

static inline void anon_vma_unlock_write(struct anon_vma *anon_vma)
{
	up_write(&anon_vma->root->rwsem);
}

static inline void anon_vma_lock_read(struct anon_vma *anon_vma)
{
	down_read(&anon_vma->root->rwsem);
}

static inline void anon_vma_unlock_read(struct anon_vma *anon_vma)
{
	up_read(&anon_vma->root->rwsem);
}


/*
 * anon_vma helper functions.
 */
void anon_vma_init(void);	/* create anon_vma_cachep */
int  anon_vma_prepare(struct vm_area_struct *);
void unlink_anon_vmas(struct vm_area_struct *);
int anon_vma_clone(struct vm_area_struct *, struct vm_area_struct *);
int anon_vma_fork(struct vm_area_struct *, struct vm_area_struct *);

static inline void anon_vma_merge(struct vm_area_struct *vma,
				  struct vm_area_struct *next)
{
	VM_BUG_ON_VMA(vma->anon_vma != next->anon_vma, vma);
	unlink_anon_vmas(next);
}

struct anon_vma *page_get_anon_vma(struct page *page);

/* bitflags for do_page_add_anon_rmap() */
#define RMAP_EXCLUSIVE 0x01
#define RMAP_COMPOUND 0x02

/*
 * rmap interfaces called when adding or removing pte of page
 */
void page_move_anon_rmap(struct page *, struct vm_area_struct *);
void page_add_anon_rmap(struct page *, struct vm_area_struct *,
		unsigned long, bool);
void do_page_add_anon_rmap(struct page *, struct vm_area_struct *,
			   unsigned long, int);
void page_add_new_anon_rmap(struct page *, struct vm_area_struct *,
		unsigned long, bool);
void page_add_file_rmap(struct page *, bool);
void page_remove_rmap(struct page *, bool);

void hugepage_add_anon_rmap(struct page *, struct vm_area_struct *,
			    unsigned long);
void hugepage_add_new_anon_rmap(struct page *, struct vm_area_struct *,
				unsigned long);

static inline void page_dup_rmap(struct page *page, bool compound)
{
	atomic_inc(compound ? compound_mapcount_ptr(page) : &page->_mapcount);
}

/*
 * Called from mm/vmscan.c to handle paging out
 */
int page_referenced(struct page *, int is_locked,
			struct mem_cgroup *memcg, unsigned long *vm_flags);

#define TTU_ACTION(x) ((x) & TTU_ACTION_MASK)

int try_to_unmap(struct page *, enum ttu_flags flags);

/*
 * Used by uprobes to replace a userspace page safely
 */
pte_t *__page_check_address(struct page *, struct mm_struct *,
				unsigned long, spinlock_t **, int);

static inline pte_t *page_check_address(struct page *page, struct mm_struct *mm,
					unsigned long address,
					spinlock_t **ptlp, int sync)
{
	pte_t *ptep;

	__cond_lock(*ptlp, ptep = __page_check_address(page, mm, address,
						       ptlp, sync));
	return ptep;
}

/*
 * Used by idle page tracking to check if a page was referenced via page
 * tables.
 */
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
bool page_check_address_transhuge(struct page *page, struct mm_struct *mm,
				  unsigned long address, pmd_t **pmdp,
				  pte_t **ptep, spinlock_t **ptlp);
#else
static inline bool page_check_address_transhuge(struct page *page,
				struct mm_struct *mm, unsigned long address,
				pmd_t **pmdp, pte_t **ptep, spinlock_t **ptlp)
{
	*ptep = page_check_address(page, mm, address, ptlp, 0);
	*pmdp = NULL;
	return !!*ptep;
}
#endif

/*
 * Used by swapoff to help locate where page is expected in vma.
 */
unsigned long page_address_in_vma(struct page *, struct vm_area_struct *);

/*
 * Cleans the PTEs of shared mappings.
 * (and since clean PTEs should also be readonly, write protects them too)
 *
 * returns the number of cleaned PTEs.
 */
int page_mkclean(struct page *);

/*
 * called in munlock()/munmap() path to check for other vmas holding
 * the page mlocked.
 */
int try_to_munlock(struct page *);

void remove_migration_ptes(struct page *old, struct page *new, bool locked);

/*
 * Called by memory-failure.c to kill processes.
 */
struct anon_vma *page_lock_anon_vma_read(struct page *page);
void page_unlock_anon_vma_read(struct anon_vma *anon_vma);
int page_mapped_in_vma(struct page *page, struct vm_area_struct *vma);

/*
 * rmap_walk_control: To control rmap traversing for specific needs
 *
 * arg: passed to rmap_one() and invalid_vma()
 * rmap_one: executed on each vma where page is mapped
 * done: for checking traversing termination condition
 * anon_lock: for getting anon_lock by optimized way rather than default
 * invalid_vma: for skipping uninterested vma
 */
struct rmap_walk_control {
	void *arg;
	int (*rmap_one)(struct page *page, struct vm_area_struct *vma,
					unsigned long addr, void *arg);
	int (*done)(struct page *page);
	struct anon_vma *(*anon_lock)(struct page *page);
	bool (*invalid_vma)(struct vm_area_struct *vma, void *arg);
};

int rmap_walk(struct page *page, struct rmap_walk_control *rwc);
int rmap_walk_locked(struct page *page, struct rmap_walk_control *rwc);

#else	/* !CONFIG_MMU */

#define anon_vma_init()		do {} while (0)
#define anon_vma_prepare(vma)	(0)
#define anon_vma_link(vma)	do {} while (0)

static inline int page_referenced(struct page *page, int is_locked,
				  struct mem_cgroup *memcg,
				  unsigned long *vm_flags)
{
	*vm_flags = 0;
	return 0;
}

#define try_to_unmap(page, refs) SWAP_FAIL

static inline int page_mkclean(struct page *page)
{
	return 0;
}


#endif	/* CONFIG_MMU */

/*
 * Return values of try_to_unmap
 */
#define SWAP_SUCCESS	0
#define SWAP_AGAIN	1
#define SWAP_FAIL	2
#define SWAP_MLOCK	3
#define SWAP_LZFREE	4

#endif	/* _LINUX_RMAP_H */
