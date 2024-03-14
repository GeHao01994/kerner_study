#ifndef _LINUX_MM_TYPES_H
#define _LINUX_MM_TYPES_H

#include <linux/auxvec.h>
#include <linux/types.h>
#include <linux/threads.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/rbtree.h>
#include <linux/rwsem.h>
#include <linux/completion.h>
#include <linux/cpumask.h>
#include <linux/uprobes.h>
#include <linux/page-flags-layout.h>
#include <linux/workqueue.h>
#include <asm/page.h>
#include <asm/mmu.h>

#ifndef AT_VECTOR_SIZE_ARCH
#define AT_VECTOR_SIZE_ARCH 0
#endif
#define AT_VECTOR_SIZE (2*(AT_VECTOR_SIZE_ARCH + AT_VECTOR_SIZE_BASE + 1))

struct address_space;
struct mem_cgroup;

#define USE_SPLIT_PTE_PTLOCKS	(NR_CPUS >= CONFIG_SPLIT_PTLOCK_CPUS)
#define USE_SPLIT_PMD_PTLOCKS	(USE_SPLIT_PTE_PTLOCKS && \
		IS_ENABLED(CONFIG_ARCH_ENABLE_SPLIT_PMD_PTLOCK))
#define ALLOC_SPLIT_PTLOCKS	(SPINLOCK_SIZE > BITS_PER_LONG/8)

/*
 * Each physical page in the system has a struct page associated with
 * it to keep track of whatever it is we are using the page for at the
 * moment. Note that we have no way to track which tasks are using
 * a page, though if it is a pagecache page, rmap structures can tell us
 * who is mapping it.
 *
 * The objects in struct page are organized in double word blocks in
 * order to allows us to use atomic double word operations on portions
 * of struct page. That is currently only used by slub but the arrangement
 * allows the use of atomic double word operations on the flags/mapping
 * and lru list pointers also.
 */
struct page {
	/* First double word block */
	unsigned long flags;		/* Atomic flags, some possibly
					 * updated asynchronously */
	union {
		struct address_space *mapping;	/* If low bit clear, points to
						 * inode address_space, or NULL.
						 * If page mapped as anonymous
						 * memory, low bit is set, and
						 * it points to anon_vma object:
						 * see PAGE_MAPPING_ANON below.
						 */
		void *s_mem;			/* slab first object */
		atomic_t compound_mapcount;	/* first tail page */
		/* page_deferred_list().next	 -- second tail page */
	};

	/* Second double word */
	union {
		pgoff_t index;		/* Our offset within mapping. */
		void *freelist;		/* sl[aou]b first free object */
		/* page_deferred_list().prev	-- second tail page */
	};

	union {
#if defined(CONFIG_HAVE_CMPXCHG_DOUBLE) && \
	defined(CONFIG_HAVE_ALIGNED_STRUCT_PAGE)
		/* Used for cmpxchg_double in slub */
		unsigned long counters;
#else
		/*
		 * Keep _refcount separate from slub cmpxchg_double data.
		 * As the rest of the double word is protected by slab_lock
		 * but _refcount is not.
		 */
		unsigned counters;
#endif
		struct {

			union {
				/*
				 * Count of ptes mapped in mms, to show when
				 * page is mapped & limit reverse map searches.
				 *
				 * Extra information about page type may be
				 * stored here for pages that are never mapped,
				 * in which case the value MUST BE <= -2.
				 * See page-flags.h for more details.
				 */
				atomic_t _mapcount;

				unsigned int active;		/* SLAB */
				struct {			/* SLUB */
					unsigned inuse:16;
					unsigned objects:15;
					unsigned frozen:1;
				};
				int units;			/* SLOB */
			};
			/*
			 * Usage count, *USE WRAPPER FUNCTION* when manual
			 * accounting. See page_ref.h
			 */
			atomic_t _refcount;
		};
	};

	/*
	 * Third double word block
	 *
	 * WARNING: bit 0 of the first word encode PageTail(). That means
	 * the rest users of the storage space MUST NOT use the bit to
	 * avoid collision and false-positive PageTail().
	 */
	union {
		struct list_head lru;	/* Pageout list, eg. active_list
					 * protected by zone_lru_lock !
					 * Can be used as a generic list
					 * by the page owner.
					 */
		struct dev_pagemap *pgmap; /* ZONE_DEVICE pages are never on an
					    * lru or handled by a slab
					    * allocator, this points to the
					    * hosting device page map.
					    */
		struct {		/* slub per cpu partial pages */
			struct page *next;	/* Next partial slab */
#ifdef CONFIG_64BIT
			int pages;	/* Nr of partial slabs left */
			int pobjects;	/* Approximate # of objects */
#else
			short int pages;
			short int pobjects;
#endif
		};

		struct rcu_head rcu_head;	/* Used by SLAB
						 * when destroying via RCU
						 */
		/* Tail pages of compound page */
		struct {
			/* 在由N个4KB组成的compound page的第1~N-1的page结构体(page[1] ~ Page[N-1],
			 * 即tail page)的compound_head上的最后一位设置1,逻辑如下:
			 * page->compound_head |=  1UL
			 */
			unsigned long compound_head; /* If bit zero is set */

			/* First tail page only */
#ifdef CONFIG_64BIT
			/*
			 * On 64 bit system we have enough space in struct page
			 * to encode compound_dtor and compound_order with
			 * unsigned int. It can help compiler generate better or
			 * smaller code on some archtectures.
			 */
			unsigned int compound_dtor;
			unsigned int compound_order;
#else
			unsigned short int compound_dtor;
			unsigned short int compound_order;
#endif
		};

#if defined(CONFIG_TRANSPARENT_HUGEPAGE) && USE_SPLIT_PMD_PTLOCKS
		struct {
			unsigned long __pad;	/* do not overlay pmd_huge_pte
						 * with compound_head to avoid
						 * possible bit 0 collision.
						 */
			/* 在创建大页表项的时候，与其他人不同，还预留了一张页表。分别对应两个函数。
			 * pgtable_trans_huge_deposit()
			 * pgtable_trans_huge_withdraw()
			 * 我们先来看第一个。这个函数的动作是预留了一个页表。那什么时候用呢？
			 * 就是在第二个函数发生的时候。那为什么要这么做呢？这个就牵扯到下一个不同点--拆分页表。
			 * 我们知道对于大页，页表一共有三级。而正常的4k页的页表是四级。所以当我们要拆分大页页表时，就需要补上这么一级.
			 * 为了保证拆分时，不会因为内存不够导致不能展开到四级页表，所以在分配时就多预留了一个页表。
			 */
			pgtable_t pmd_huge_pte; /* protected by page->ptl */
		};
#endif
	};

	/* Remainder is not double word aligned */
	union {
		unsigned long private;		/* Mapping-private opaque data:
					 	 * usually used for buffer_heads
						 * if PagePrivate set; used for
						 * swp_entry_t if PageSwapCache;
						 * indicates order in the buddy
						 * system if PG_buddy is set.
						 */
#if USE_SPLIT_PTE_PTLOCKS
#if ALLOC_SPLIT_PTLOCKS
		spinlock_t *ptl;
#else
		spinlock_t ptl;
#endif
#endif
		struct kmem_cache *slab_cache;	/* SL[AU]B: Pointer to slab */
	};

#ifdef CONFIG_MEMCG
	struct mem_cgroup *mem_cgroup;
#endif

	/*
	 * On machines where all RAM is mapped into kernel address space,
	 * we can simply calculate the virtual address. On machines with
	 * highmem some memory is mapped into kernel virtual memory
	 * dynamically, so we need a place to store that address.
	 * Note that this field could be 16 bits on x86 ... ;)
	 *
	 * Architectures with slow multiplication can define
	 * WANT_PAGE_VIRTUAL in asm/page.h
	 */
#if defined(WANT_PAGE_VIRTUAL)
	void *virtual;			/* Kernel virtual address (NULL if
					   not kmapped, ie. highmem) */
#endif /* WANT_PAGE_VIRTUAL */

#ifdef CONFIG_KMEMCHECK
	/*
	 * kmemcheck wants to track the status of each byte in a page; this
	 * is a pointer to such a status block. NULL if not tracked.
	 */
	void *shadow;
#endif

#ifdef LAST_CPUPID_NOT_IN_PAGE_FLAGS
	int _last_cpupid;
#endif
}
/*
 * The struct page can be forced to be double word aligned so that atomic ops
 * on double words work. The SLUB allocator can make use of such a feature.
 */
#ifdef CONFIG_HAVE_ALIGNED_STRUCT_PAGE
	__aligned(2 * sizeof(unsigned long))
#endif
;

struct page_frag {
	struct page *page;
#if (BITS_PER_LONG > 32) || (PAGE_SIZE >= 65536)
	__u32 offset;
	__u32 size;
#else
	__u16 offset;
	__u16 size;
#endif
};

#define PAGE_FRAG_CACHE_MAX_SIZE	__ALIGN_MASK(32768, ~PAGE_MASK)
#define PAGE_FRAG_CACHE_MAX_ORDER	get_order(PAGE_FRAG_CACHE_MAX_SIZE)

struct page_frag_cache {
	void * va;
#if (PAGE_SIZE < PAGE_FRAG_CACHE_MAX_SIZE)
	__u16 offset;
	__u16 size;
#else
	__u32 offset;
#endif
	/* we maintain a pagecount bias, so that we dont dirty cache line
	 * containing page->_refcount every time we allocate a fragment.
	 */
	unsigned int		pagecnt_bias;
	bool pfmemalloc;
};

typedef unsigned long vm_flags_t;

/*
 * A region containing a mapping of a non-memory backed file under NOMMU
 * conditions.  These are held in a global tree and are pinned by the VMAs that
 * map parts of them.
 */
struct vm_region {
	struct rb_node	vm_rb;		/* link in global region tree */
	vm_flags_t	vm_flags;	/* VMA vm_flags */
	unsigned long	vm_start;	/* start address of region */
	unsigned long	vm_end;		/* region initialised to here */
	unsigned long	vm_top;		/* region allocated to here */
	unsigned long	vm_pgoff;	/* the offset in vm_file corresponding to vm_start */
	struct file	*vm_file;	/* the backing file or NULL */

	int		vm_usage;	/* region usage count (access under nommu_region_sem) */
	bool		vm_icache_flushed : 1; /* true if the icache has been flushed for
						* this region */
};

#ifdef CONFIG_USERFAULTFD
#define NULL_VM_UFFD_CTX ((struct vm_userfaultfd_ctx) { NULL, })
struct vm_userfaultfd_ctx {
	struct userfaultfd_ctx *ctx;
};
#else /* CONFIG_USERFAULTFD */
#define NULL_VM_UFFD_CTX ((struct vm_userfaultfd_ctx) {})
struct vm_userfaultfd_ctx {};
#endif /* CONFIG_USERFAULTFD */

/*
 * This struct defines a memory VMM memory area. There is one of these
 * per VM-area/task.  A VM area is any part of the process virtual memory
 * space that has a special rule for the page-fault handlers (ie a shared
 * library, the executable area etc).
 */
/*
 * 对于文件页，vma->vm_start记录了vma的首虚拟地址，vma->vm_pgoff记录了该vma在对应的映射文件
 *（或共享内存）中的偏移，而page->index记录了页面在文件（或共享内存）中的偏移.
 * 通过vma->vm_pgoff和page->index能得到页面在vma中的偏移,加上vma->vm_start就能得到页面的虚拟地址;
 * 而通过page->index就能得到页面在文件磁盘高速缓存中的位置
 *
 * 下面的还是太理想了，但是不影响我们理解，可以想一下如果内存不联系的情况，其实是一样的
 *
 *  —————————————————————————————
 * ↓		page->index      ↓
 *  ———————————————————
 * ↓     vma->pgoff    ↓
 *  ———— ———— ———— ———— ———— ———— ———— ———— ———— ————
 * |    |    |    |    |    |    |    |    |    |    |
 * |    |    |    |    |    |    |PAGE|    |    |    |  File
 * |    |    |    |    |    |    |    |    |    |    |
 *  ———— ———— ———— ———— ———— ———— ———— ———— ———— ————
 *
 *                      ———— ———— ———— ————
 *                     |    |    |    |    |
 *                     |    |    |    |    |		VMA
 *                     |    |    |    |    |
 *                      ———— ———— ———— ————
 *
 *                     ↑         ↑
 *                  vm->start  page的虚拟地址
 */
struct vm_area_struct {
	/* The first cache line has the info for VMA tree walking. */
	/* 指定VMA在进程地址空间的起始地址 */
	unsigned long vm_start;		/* Our start address within vm_mm. */
	/* 指定VMA在进程地址空间的结束地址 */
	unsigned long vm_end;		/* The first byte after our end address
					   within vm_mm. */
	/* vm_next和vm_prev让进程的VMA都连接成一个链表 */
	/* linked list of VM areas per task, sorted by address */
	struct vm_area_struct *vm_next, *vm_prev;
	/* VMA作为一个节点加入红黑树中，
	 * 每个进程的struct mm_struct数据结构中都有这样一颗红黑树 mm->mm_rb
	 */
	struct rb_node vm_rb;

	/*
	 * Largest free memory gap in bytes to the left of this VMA.
	 * Either between this VMA and vma->vm_prev, or between one of the
	 * VMAs below us in the VMA rbtree and its ->vm_prev. This helps
	 * get_unmapped_area find a free area of the right size.
	 */
	unsigned long rb_subtree_gap;

	/* Second cache line starts here. */
	/* 指向该VMA所属进程的struct mm_struct数据结构 */
	struct mm_struct *vm_mm;	/* The address space we belong to. */
	/* VMA的访问权限 */
	pgprot_t vm_page_prot;		/* Access permissions of this VMA. */
	/* 描述该VMA的一组标志位 */
	unsigned long vm_flags;		/* Flags, see mm.h. */

	/*
	 * For areas with an address space and backing store,
	 * linkage into the address_space->i_mmap interval tree.
	 */
	struct {
		struct rb_node rb;
		unsigned long rb_subtree_last;
	} shared;

	/*
	 * A file's MAP_PRIVATE vma can be in both i_mmap tree and anon_vma
	 * list, after a COW of one of the file pages.	A MAP_SHARED vma
	 * can only be in the i_mmap tree.  An anonymous MAP_PRIVATE, stack
	 * or brk vma (with NULL file) can only be in an anon_vma list.
	 */
	/* 用于管理RMAP反向映射 */
	struct list_head anon_vma_chain; /* Serialized by mmap_sem &
					  * page_table_lock */
	struct anon_vma *anon_vma;	/* Serialized by page_table_lock */

	/* Function pointers to deal with this struct. */
	/* 指向许多方法的集合，这些方法用于在VMA中执行各种操作，通常用于文件映射 */
	const struct vm_operations_struct *vm_ops;

	/* Information about our backing store: */
	/* 指向文件映射的偏移量，这个变量的单位不是Byte,而是页面的大小（PAGE_SIZE）*/
	unsigned long vm_pgoff;		/* Offset (within vm_file) in PAGE_SIZE
					   units */
	/* 描述一个被映射的文件 */
	struct file * vm_file;		/* File we map to (can be NULL). */
	void * vm_private_data;		/* was vm_pte (shared mem) */

#ifndef CONFIG_MMU
	struct vm_region *vm_region;	/* NOMMU mapping region */
#endif
#ifdef CONFIG_NUMA
	struct mempolicy *vm_policy;	/* NUMA policy for the VMA */
#endif
	struct vm_userfaultfd_ctx vm_userfaultfd_ctx;
};

struct core_thread {
	struct task_struct *task;
	struct core_thread *next;
};

struct core_state {
	atomic_t nr_threads;
	struct core_thread dumper;
	struct completion startup;
};

enum {
	MM_FILEPAGES,	/* Resident file mapping pages */
	MM_ANONPAGES,	/* Resident anonymous pages */
	MM_SWAPENTS,	/* Anonymous swap entries */
	MM_SHMEMPAGES,	/* Resident shared memory pages */
	NR_MM_COUNTERS
};

#if USE_SPLIT_PTE_PTLOCKS && defined(CONFIG_MMU)
#define SPLIT_RSS_COUNTING
/* per-thread cached information, */
struct task_rss_stat {
	int events;	/* for synchronization threshold */
	int count[NR_MM_COUNTERS];
};
#endif /* USE_SPLIT_PTE_PTLOCKS */

struct mm_rss_stat {
	atomic_long_t count[NR_MM_COUNTERS];
};

struct kioctx_table;
struct mm_struct {
	struct vm_area_struct *mmap;		/* list of VMAs */
	struct rb_root mm_rb;
	u32 vmacache_seqnum;                   /* per-thread vmacache */
#ifdef CONFIG_MMU
	unsigned long (*get_unmapped_area) (struct file *filp,
				unsigned long addr, unsigned long len,
				unsigned long pgoff, unsigned long flags);
#endif
	unsigned long mmap_base;		/* base of mmap area */
	unsigned long mmap_legacy_base;         /* base of mmap area in bottom-up allocations */
	unsigned long task_size;		/* size of task vm space */
	unsigned long highest_vm_end;		/* highest vma end address */
	pgd_t * pgd;
	atomic_t mm_users;			/* How many users with user space? */
	atomic_t mm_count;			/* How many references to "struct mm_struct" (users count as 1) */
	atomic_long_t nr_ptes;			/* PTE page table pages */
#if CONFIG_PGTABLE_LEVELS > 2
	atomic_long_t nr_pmds;			/* PMD page table pages */
#endif
	int map_count;				/* number of VMAs */

	spinlock_t page_table_lock;		/* Protects page tables and some counters */
	struct rw_semaphore mmap_sem;

	struct list_head mmlist;		/* List of maybe swapped mm's.	These are globally strung
						 * together off init_mm.mmlist, and are protected
						 * by mmlist_lock
						 */

	/* 进程拥有的最大页表数目 */
	unsigned long hiwater_rss;	/* High-watermark of RSS usage */
	/* 表示进程的线程区最大页数(虚拟地址的最大页数？) */
	unsigned long hiwater_vm;	/* High-water virtual memory usage */
	/* 表示进程的虚拟地址空间的总页数 */
	unsigned long total_vm;		/* Total pages mapped */
	/* 表示内存页被锁住的个数 , 这些内存页不能被换出 */
	unsigned long locked_vm;	/* Pages that have PG_mlocked set */
	/* pinned_vm  表示既不能换出，也不能移动的内存页总数 */
	unsigned long pinned_vm;	/* Refcount permanently increased */
	/* 这些变量均是表示进程虚拟内存空间中的虚拟内存使用情况 */
	/* 表示数据段中映射的内存页数目 */
	unsigned long data_vm;		/* VM_WRITE & ~VM_SHARED & ~VM_STACK */
	/* exec_vm 是代码段中存放可执行文件的内存页数目 */
	unsigned long exec_vm;		/* VM_EXEC & ~VM_WRITE & ~VM_STACK */
	/* stack_vm 是栈中所映射的内存页数目 */
	unsigned long stack_vm;		/* VM_STACK */
	unsigned long def_flags;
	unsigned long start_code, end_code, start_data, end_data;
	unsigned long start_brk, brk, start_stack;
	unsigned long arg_start, arg_end, env_start, env_end;

	unsigned long saved_auxv[AT_VECTOR_SIZE]; /* for /proc/PID/auxv */

	/*
	 * Special counters, in some configurations protected by the
	 * page_table_lock, in other configurations by being atomic.
	 */
	struct mm_rss_stat rss_stat;

	struct linux_binfmt *binfmt;

	cpumask_var_t cpu_vm_mask_var;

	/* Architecture-specific MM context */
	mm_context_t context;

	unsigned long flags; /* Must use atomic bitops to access the bits */

	struct core_state *core_state; /* coredumping support */
#ifdef CONFIG_AIO
	spinlock_t			ioctx_lock;
	struct kioctx_table __rcu	*ioctx_table;
#endif
#ifdef CONFIG_MEMCG
	/*
	 * "owner" points to a task that is regarded as the canonical
	 * user/owner of this mm. All of the following must be true in
	 * order for it to be changed:
	 *
	 * current == mm->owner
	 * current->mm != mm
	 * new_owner->mm == mm
	 * new_owner->alloc_lock is held
	 */
	struct task_struct __rcu *owner;
#endif
	struct user_namespace *user_ns;

	/* store ref to file /proc/<pid>/exe symlink points to */
	struct file __rcu *exe_file;
#ifdef CONFIG_MMU_NOTIFIER
	struct mmu_notifier_mm *mmu_notifier_mm;
#endif
#if defined(CONFIG_TRANSPARENT_HUGEPAGE) && !USE_SPLIT_PMD_PTLOCKS
	pgtable_t pmd_huge_pte; /* protected by page_table_lock */
#endif
#ifdef CONFIG_CPUMASK_OFFSTACK
	struct cpumask cpumask_allocation;
#endif
#ifdef CONFIG_NUMA_BALANCING
	/*
	 * numa_next_scan is the next time that the PTEs will be marked
	 * pte_numa. NUMA hinting faults will gather statistics and migrate
	 * pages to new nodes if necessary.
	 */
	unsigned long numa_next_scan;

	/* Restart point for scanning and setting pte_numa */
	unsigned long numa_scan_offset;

	/* numa_scan_seq prevents two threads setting pte_numa */
	int numa_scan_seq;
#endif
#if defined(CONFIG_NUMA_BALANCING) || defined(CONFIG_COMPACTION)
	/*
	 * An operation with batched TLB flushing is going on. Anything that
	 * can move process memory needs to flush the TLB when moving a
	 * PROT_NONE or PROT_NUMA mapped page.
	 */
	bool tlb_flush_pending;
#endif
	struct uprobes_state uprobes_state;
#ifdef CONFIG_X86_INTEL_MPX
	/* address of the bounds directory */
	void __user *bd_addr;
#endif
#ifdef CONFIG_HUGETLB_PAGE
	atomic_long_t hugetlb_usage;
#endif
	struct work_struct async_put_work;
};

static inline void mm_init_cpumask(struct mm_struct *mm)
{
#ifdef CONFIG_CPUMASK_OFFSTACK
	mm->cpu_vm_mask_var = &mm->cpumask_allocation;
#endif
	cpumask_clear(mm->cpu_vm_mask_var);
}

/* Future-safe accessor for struct mm_struct's cpu_vm_mask. */
static inline cpumask_t *mm_cpumask(struct mm_struct *mm)
{
	return mm->cpu_vm_mask_var;
}

#if defined(CONFIG_NUMA_BALANCING) || defined(CONFIG_COMPACTION)
/*
 * Memory barriers to keep this state in sync are graciously provided by
 * the page table locks, outside of which no page table modifications happen.
 * The barriers below prevent the compiler from re-ordering the instructions
 * around the memory barriers that are already present in the code.
 */
static inline bool mm_tlb_flush_pending(struct mm_struct *mm)
{
	barrier();
	return mm->tlb_flush_pending;
}
static inline void set_tlb_flush_pending(struct mm_struct *mm)
{
	mm->tlb_flush_pending = true;

	/*
	 * Guarantee that the tlb_flush_pending store does not leak into the
	 * critical section updating the page tables
	 */
	smp_mb__before_spinlock();
}
/* Clearing is done after a TLB flush, which also provides a barrier. */
static inline void clear_tlb_flush_pending(struct mm_struct *mm)
{
	barrier();
	mm->tlb_flush_pending = false;
}
#else
static inline bool mm_tlb_flush_pending(struct mm_struct *mm)
{
	return false;
}
static inline void set_tlb_flush_pending(struct mm_struct *mm)
{
}
static inline void clear_tlb_flush_pending(struct mm_struct *mm)
{
}
#endif

struct vm_fault;

struct vm_special_mapping {
	const char *name;	/* The name, e.g. "[vdso]". */

	/*
	 * If .fault is not provided, this points to a
	 * NULL-terminated array of pages that back the special mapping.
	 *
	 * This must not be NULL unless .fault is provided.
	 */
	struct page **pages;

	/*
	 * If non-NULL, then this is called to resolve page faults
	 * on the special mapping.  If used, .pages is not checked.
	 */
	int (*fault)(const struct vm_special_mapping *sm,
		     struct vm_area_struct *vma,
		     struct vm_fault *vmf);

	int (*mremap)(const struct vm_special_mapping *sm,
		     struct vm_area_struct *new_vma);
};

enum tlb_flush_reason {
	TLB_FLUSH_ON_TASK_SWITCH,
	TLB_REMOTE_SHOOTDOWN,
	TLB_LOCAL_SHOOTDOWN,
	TLB_LOCAL_MM_SHOOTDOWN,
	TLB_REMOTE_SEND_IPI,
	NR_TLB_FLUSH_REASONS,
};

 /*
  * A swap entry has to fit into a "unsigned long", as the entry is hidden
  * in the "index" field of the swapper address space.
  */
typedef struct {
	unsigned long val;
} swp_entry_t;

#endif /* _LINUX_MM_TYPES_H */
