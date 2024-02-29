#ifndef _LINUX_MMZONE_H
#define _LINUX_MMZONE_H

#ifndef __ASSEMBLY__
#ifndef __GENERATING_BOUNDS_H

#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/wait.h>
#include <linux/bitops.h>
#include <linux/cache.h>
#include <linux/threads.h>
#include <linux/numa.h>
#include <linux/init.h>
#include <linux/seqlock.h>
#include <linux/nodemask.h>
#include <linux/pageblock-flags.h>
#include <linux/page-flags-layout.h>
#include <linux/atomic.h>
#include <asm/page.h>

/* Free memory management - zoned buddy allocator.  */
#ifndef CONFIG_FORCE_MAX_ZONEORDER
#define MAX_ORDER 11
#else
#define MAX_ORDER CONFIG_FORCE_MAX_ZONEORDER
#endif
#define MAX_ORDER_NR_PAGES (1 << (MAX_ORDER - 1))

/*
 * PAGE_ALLOC_COSTLY_ORDER is the order at which allocations are deemed
 * costly to service.  That is between allocation orders which should
 * coalesce naturally under reasonable reclaim pressure and those which
 * will not.
 *
 * PAGE_ALLOC_COSTLY_ORDER是分配器视为服务成本高昂的order.
 * 这是在合理的回收压力下应该自然结合的分配order和不会的分配order之间。
 */
#define PAGE_ALLOC_COSTLY_ORDER 3

enum {
	/* 页框中的内容不可移动.内核分配的大部分内存属于这种类型 */
	MIGRATE_UNMOVABLE,
	/* 页框中的内容可移动.用户空间分配的内存大部分属于这种类型.
	 * 移动页框的方法为将老页框中的内容拷贝到新页框中,然后将页表的pte entry指向新页框地址即可
	 */
	MIGRATE_MOVABLE,
	/* 这种页框一般用于文件缓存,它们虽然不能被移动,但可以被回收,当再次需要时可通过源文件重建 */
	MIGRATE_RECLAIMABLE,
	/* MIGRATE_PCPTYPES是per_cpu_pageset,即用来表示每CPU页框高速缓存的数据结构中的链表的迁移类型数目 */
	MIGRATE_PCPTYPES,	/* the number of types on the pcp lists */
	/* MIGRATE_HIGHATOMIC: 它是为那些不允许内存分配失败情形预留的紧急内存,只有当gfp_flags为__GFP_ATOMIC时,才可能会从该内存池中分配 */
	MIGRATE_HIGHATOMIC = MIGRATE_PCPTYPES,
#ifdef CONFIG_CMA
	/*
	 * MIGRATE_CMA migration type is designed to mimic the way
	 * ZONE_MOVABLE works.  Only movable pages can be allocated
	 * from MIGRATE_CMA pageblocks and page allocator never
	 * implicitly change migration type of MIGRATE_CMA pageblock.
	 *
	 * The way to use it is to change migratetype of a range of
	 * pageblocks to MIGRATE_CMA which can be done by
	 * __free_pageblock_cma() function.  What is important though
	 * is that a range of pageblocks must be aligned to
	 * MAX_ORDER_NR_PAGES should biggest page be bigger then
	 * a single pageblock.
	 */
	/* MIGRATE_CMA: 这种内存被预留给驱动使用,当驱动未使用时,伙伴系统可以将其分配给用户进程使用.
	 * 但驱动需要时,就需要用户进程通过回收或迁移的方式返还它们,以供驱动使用,因此它必须是可迁移或可回收的
	 */
	MIGRATE_CMA,
#endif
#ifdef CONFIG_MEMORY_ISOLATION
	/* MIGRATE_ISOLATE：它用于numa节点之间移动内存，从而将内存迁移到访问它最频繁cpu的node上 */
	/* 它用于numa节点之间移动内存,从而将内存迁移到访问它最频繁cpu的node上
	 * 内核将可移动和可回收的内存页块通过移动物理内存或者回收内存的方法将内存碎片合并成连续的大块内存以此来缓解内存碎片.
	 */
	MIGRATE_ISOLATE,	/* can't allocate from here */
#endif
	MIGRATE_TYPES
};

/* In mm/page_alloc.c; keep in sync also with show_migration_types() there */
extern char * const migratetype_names[MIGRATE_TYPES];

#ifdef CONFIG_CMA
#  define is_migrate_cma(migratetype) unlikely((migratetype) == MIGRATE_CMA)
#  define is_migrate_cma_page(_page) (get_pageblock_migratetype(_page) == MIGRATE_CMA)
#else
#  define is_migrate_cma(migratetype) false
#  define is_migrate_cma_page(_page) false
#endif

#define for_each_migratetype_order(order, type) \
	for (order = 0; order < MAX_ORDER; order++) \
		for (type = 0; type < MIGRATE_TYPES; type++)

extern int page_group_by_mobility_disabled;

#define NR_MIGRATETYPE_BITS (PB_migrate_end - PB_migrate + 1)
#define MIGRATETYPE_MASK ((1UL << NR_MIGRATETYPE_BITS) - 1)

#define get_pageblock_migratetype(page)					\
	get_pfnblock_flags_mask(page, page_to_pfn(page),		\
			PB_migrate_end, MIGRATETYPE_MASK)

struct free_area {
	struct list_head	free_list[MIGRATE_TYPES];
	unsigned long		nr_free;
};

struct pglist_data;

/*
 * zone->lock and the zone lru_lock are two of the hottest locks in the kernel.
 * So add a wild amount of padding here to ensure that they fall into separate
 * cachelines.  There are very few zone structures in the machine, so space
 * consumption is not a concern here.
 */
#if defined(CONFIG_SMP)
struct zone_padding {
	char x[0];
} ____cacheline_internodealigned_in_smp;
#define ZONE_PADDING(name)	struct zone_padding name;
#else
#define ZONE_PADDING(name)
#endif

enum zone_stat_item {
	/* First 128 byte cacheline (assuming 64 bit words) */
	NR_FREE_PAGES,
	NR_ZONE_LRU_BASE, /* Used only for compaction and reclaim retry */
	NR_ZONE_INACTIVE_ANON = NR_ZONE_LRU_BASE,
	NR_ZONE_ACTIVE_ANON,
	NR_ZONE_INACTIVE_FILE,
	NR_ZONE_ACTIVE_FILE,
	NR_ZONE_UNEVICTABLE,
	NR_ZONE_WRITE_PENDING,	/* Count of dirty, writeback and unstable pages */
	NR_MLOCK,		/* mlock()ed pages found and moved off LRU */
	NR_SLAB_RECLAIMABLE,
	NR_SLAB_UNRECLAIMABLE,
	NR_PAGETABLE,		/* used for pagetables */
	NR_KERNEL_STACK_KB,	/* measured in KiB */
	/* Second 128 byte cacheline */
	NR_BOUNCE,
#if IS_ENABLED(CONFIG_ZSMALLOC)
	NR_ZSPAGES,		/* allocated in zsmalloc */
#endif
#ifdef CONFIG_NUMA
	NUMA_HIT,		/* allocated in intended node */
	NUMA_MISS,		/* allocated in non intended node */
	NUMA_FOREIGN,		/* was intended here, hit elsewhere */
	NUMA_INTERLEAVE_HIT,	/* interleaver preferred this zone */
	NUMA_LOCAL,		/* allocation from local node */
	NUMA_OTHER,		/* allocation from other node */
#endif
	NR_FREE_CMA_PAGES,
	NR_VM_ZONE_STAT_ITEMS };

enum node_stat_item {
	NR_LRU_BASE,
	NR_INACTIVE_ANON = NR_LRU_BASE, /* must match order of LRU_[IN]ACTIVE */
	NR_ACTIVE_ANON,		/*  "     "     "   "       "         */
	NR_INACTIVE_FILE,	/*  "     "     "   "       "         */
	NR_ACTIVE_FILE,		/*  "     "     "   "       "         */
	NR_UNEVICTABLE,		/*  "     "     "   "       "         */
	NR_ISOLATED_ANON,	/* Temporary isolated pages from anon lru */
	NR_ISOLATED_FILE,	/* Temporary isolated pages from file lru */
	NR_PAGES_SCANNED,	/* pages scanned since last reclaim */
	WORKINGSET_REFAULT,
	WORKINGSET_ACTIVATE,
	WORKINGSET_NODERECLAIM,
	NR_ANON_MAPPED,	/* Mapped anonymous pages */
	NR_FILE_MAPPED,	/* pagecache pages mapped into pagetables.
			   only modified from process context */
	NR_FILE_PAGES,
	NR_FILE_DIRTY,
	NR_WRITEBACK,
	NR_WRITEBACK_TEMP,	/* Writeback using temporary buffers */
	NR_SHMEM,		/* shmem pages (included tmpfs/GEM pages) */
	NR_SHMEM_THPS,
	NR_SHMEM_PMDMAPPED,
	NR_ANON_THPS,
	NR_UNSTABLE_NFS,	/* NFS unstable pages */
	NR_VMSCAN_WRITE,
	NR_VMSCAN_IMMEDIATE,	/* Prioritise for reclaim when writeback ends */
	NR_DIRTIED,		/* page dirtyings since bootup */
	NR_WRITTEN,		/* page writings since bootup */
	NR_VM_NODE_STAT_ITEMS
};

/*
 * We do arithmetic on the LRU lists in various places in the code,
 * so it is important to keep the active lists LRU_ACTIVE higher in
 * the array than the corresponding inactive lists, and to keep
 * the *_FILE lists LRU_FILE higher than the corresponding _ANON lists.
 *
 * This has to be kept in sync with the statistics in zone_stat_item
 * above and the descriptions in vmstat_text in mm/vmstat.c
 */
#define LRU_BASE 0
#define LRU_ACTIVE 1
#define LRU_FILE 2

enum lru_list {
	LRU_INACTIVE_ANON = LRU_BASE,
	LRU_ACTIVE_ANON = LRU_BASE + LRU_ACTIVE,
	LRU_INACTIVE_FILE = LRU_BASE + LRU_FILE,
	LRU_ACTIVE_FILE = LRU_BASE + LRU_FILE + LRU_ACTIVE,
	LRU_UNEVICTABLE,
	NR_LRU_LISTS
};

#define for_each_lru(lru) for (lru = 0; lru < NR_LRU_LISTS; lru++)

#define for_each_evictable_lru(lru) for (lru = 0; lru <= LRU_ACTIVE_FILE; lru++)

static inline int is_file_lru(enum lru_list lru)
{
	return (lru == LRU_INACTIVE_FILE || lru == LRU_ACTIVE_FILE);
}

static inline int is_active_lru(enum lru_list lru)
{
	return (lru == LRU_ACTIVE_ANON || lru == LRU_ACTIVE_FILE);
}
/* 统计扫描页面和活跃页面的情况
 * 匿名页面存放在数组[0]中，文件缓存存放在数组[1]中.
 * recent_rotated / recent_scanned的比值比较大，说明这些被缓存起来的页面越有价值，
 * 它们更应该留下来.
 * 以匿名页面为例，recent_rotated值越小，说明LRU链表中匿名页面价值越小，
 * 那么就应该多扫描一些匿名页面，尽量把没有缓存价值的页面换出去
 */
struct zone_reclaim_stat {
	/*
	 * The pageout code in vmscan.c keeps track of how many of the
	 * mem/swap backed and file backed pages are referenced.
	 * The higher the rotated/scanned ratio, the more valuable
	 * that cache is.
	 *
	 * The anon LRU stats live in [0], file LRU stats in [1]
	 */
	/* 在扫描不活跃链表时，统计那些被踢回活跃链表的页面数量到recent_rotated变量中，
	 * 详见shrink_inactive_list()->putback_inactive_pages()函数。
	 * 在扫描活跃页面时，访问引用的页面数量也被加到recent_rotated变量。
	 * 总之，该变量反映了真实的活跃页面的数量.
	 */
	unsigned long		recent_rotated[2];
	/* recent_scanned:指最近扫描的页面的数量，在扫描活跃链表和不活跃链表时,
	 * 会统计到recent_scanned变量中
	 */
	unsigned long		recent_scanned[2];
};

struct lruvec {
	struct list_head		lists[NR_LRU_LISTS];
	struct zone_reclaim_stat	reclaim_stat;
	/* Evictions & activations on the inactive file list */
	atomic_long_t			inactive_age;
#ifdef CONFIG_MEMCG
	struct pglist_data *pgdat;
#endif
};

/* Mask used at gathering information at once (see memcontrol.c) */
#define LRU_ALL_FILE (BIT(LRU_INACTIVE_FILE) | BIT(LRU_ACTIVE_FILE))
#define LRU_ALL_ANON (BIT(LRU_INACTIVE_ANON) | BIT(LRU_ACTIVE_ANON))
#define LRU_ALL	     ((1 << NR_LRU_LISTS) - 1)

/* Isolate clean file */
#define ISOLATE_CLEAN		((__force isolate_mode_t)0x1)
/* Isolate unmapped file */
#define ISOLATE_UNMAPPED	((__force isolate_mode_t)0x2)
/* Isolate for asynchronous migration */
#define ISOLATE_ASYNC_MIGRATE	((__force isolate_mode_t)0x4)
/* Isolate unevictable pages */
#define ISOLATE_UNEVICTABLE	((__force isolate_mode_t)0x8)

/* LRU Isolation modes. */
typedef unsigned __bitwise__ isolate_mode_t;

enum zone_watermarks {
	WMARK_MIN,
	WMARK_LOW,
	WMARK_HIGH,
	NR_WMARK
};

#define min_wmark_pages(z) (z->watermark[WMARK_MIN])
#define low_wmark_pages(z) (z->watermark[WMARK_LOW])
#define high_wmark_pages(z) (z->watermark[WMARK_HIGH])

struct per_cpu_pages {
	/* 表示当前zone中的per_cpu_pages的页表 */
	int count;		/* number of pages in the list */
	/* 表示当缓存的页面高于这个水位时,会回收页面到伙伴系统 */
	int high;		/* high watermark, emptying needed */
	/* 表示一次回收页面到伙伴系统的页面数量 */
	int batch;		/* chunk size for buddy add/remove */

	/* Lists of pages, one per migrate type stored on the pcp-lists */
	struct list_head lists[MIGRATE_PCPTYPES];
};

struct per_cpu_pageset {
	struct per_cpu_pages pcp;
#ifdef CONFIG_NUMA
	s8 expire;
#endif
#ifdef CONFIG_SMP
	s8 stat_threshold;
	s8 vm_stat_diff[NR_VM_ZONE_STAT_ITEMS];
#endif
};

struct per_cpu_nodestat {
	s8 stat_threshold;
	s8 vm_node_stat_diff[NR_VM_NODE_STAT_ITEMS];
};

#endif /* !__GENERATING_BOUNDS.H */

/* 通常情况下，内核中的ZONE分为ZONE_DMA,ZONE_DMA32,
 * ZONE_NORMAL,ZONE_HIGHMEM
 * 但是有些也没有ZONE_DMA 和ZONE_DMA32
 */
enum zone_type {
#ifdef CONFIG_ZONE_DMA
	/*
	 * ZONE_DMA is used when there are devices that are not able
	 * to do DMA to all of addressable memory (ZONE_NORMAL). Then we
	 * carve out the portion of memory that is needed for these devices.
	 * The range is arch specific.
	 *
	 * Some examples
	 *
	 * Architecture		Limit
	 * ---------------------------
	 * parisc, ia64, sparc	<4G
	 * s390			<2G
	 * arm			Various
	 * alpha		Unlimited or 0-16MB.
	 *
	 * i386, x86_64 and multiple other arches
	 * 			<16M.
	 */
	ZONE_DMA,
#endif
#ifdef CONFIG_ZONE_DMA32
	/*
	 * x86_64 needs two ZONE_DMAs because it supports devices that are
	 * only able to do DMA to the lower 16M but also 32 bit devices that
	 * can only do DMA areas below 4G.
	 */
	ZONE_DMA32,
#endif
	/*
	 * Normal addressable memory is in ZONE_NORMAL. DMA operations can be
	 * performed on pages in ZONE_NORMAL if the DMA devices support
	 * transfers to all addressable memory.
	 */
	ZONE_NORMAL,
#ifdef CONFIG_HIGHMEM
	/*
	 * A memory area that is only addressable by the kernel through
	 * mapping portions into its own address space. This is for example
	 * used by i386 to allow the kernel to address the memory beyond
	 * 900MB. The kernel will set up special mappings (page
	 * table entries on i386) for each page that the kernel needs to
	 * access.
	 */
	ZONE_HIGHMEM,
#endif
	/* ZONE_MOVABLE: 网上看到一些文章经常会把它叫做虚拟内存区(pseudo zone),为什么说它是一个虚拟内存区呢?
	 * 实际上它是从平台中最高内存区中(比如ZONE_HIHGMEM)划出了一部分内存,作为ZONE_MOVABLE.
	 * 内核中有如下代码可以作为参考依据: find_usable_zone_for_movable
	 * 那么引入该内存区的目的是什么？
	 * 它存在的意义实际上是为了减少内存的碎片化,想象一下这个场景,当我们需要一块大的连续内存时向伙伴系统申请,虽然对应的内存区剩余内存还很多,
	 * 但是却发现对应的内存区并无法满足连续的内存申请需求,这就是由于内存碎片化导致的问题.
	 * 那么此时是可以通过内存迁移来完成连续内存的申请,但是这个过程并不一定能够成功,因为中间有一些页面可能是不允许迁移的.
	 * 引入ZONE_MOVABLE就是为了优化内存迁移场景的,主要目的是想要把Non-Movable和Movable的内存区分管理,当我们划分出该区域后,那么只有可迁移的页才能够从该区域申请,
	 * 这样当我们后面回收内存时,针对该区域就都可以执行迁移.从而保证能够获取到足够大的连续内存.
	 * 除了这个用途之外,该区域还有一种使用场景,那就是memory hotplug场景,内存热插拔场景,当我们对内存区执行remove时,
	 * 必须保证其中的内容都是可以被迁移走的,因此热插拔的内存区必须位于ZONE_MOVABLE区域.
	 *
	 * ZONE_MOVABLE的开启与是否指定了kernelcore有关,该参数指定了不可移动的内存数量,计算结果会存储在required_kernelcore.
	 * movablecore指定了可移动的内存数量.
	 * 如果同时指定kernelcore和movablecore此时会按照两种方式计算出较大的required_kernelcore,如果都未指定,则该区域范围为0,相当于未开启.
	 * 内核中find_zone_movable_pfns_for_nodes就是在做这个事情,该函数会按照上述的参数计算出ZONE_MOVABLE内存域的首个page的PFN(page frame number).
	 * 一直都说ZONE_MOVABLE是一个虚拟内存域,是因为ZONE_MOVABLE管理了NORMAL或者HIGHMEM的内存,看到这里之后我就产生了疑问.
	 * 管理的内存与其他zone是重叠的吗?难道同一个内存页会属于两个内存域吗?答案是ZONE_MOVABLE管理的内存与其他内存区域是不重叠的.
	 * 之前我们计算好了ZONE_MOVABLE的区域大小和在每个node上的起始pfn的时候就已经确定了ZONE_MOVABLE管理的内存区域,在做其他内存区域的初始化时就会对原本的内存区域进行调整,
	 * 如果别的内存区域计算出的范围和ZONE_MOVABLE内定的范围产生了重叠,adjust_zone_range_for_zone_movable这个函数就会对这些区域进行压缩.
	 * 比如某个情况下的HIGHMEM区域的内存都被包含在ZONE_MOBVABLE中了,经过调整后高端内存内存区域管理的内存就为0.
	 */
	ZONE_MOVABLE,
#ifdef CONFIG_ZONE_DEVICE
	ZONE_DEVICE,
#endif
	__MAX_NR_ZONES

};

#ifndef __GENERATING_BOUNDS_H

struct zone {
	/* Read-mostly fields */
	/* 每个zone在系统启动的时候会计算3个水位值，
	 * 分别是WMARK_MIN,WMARK_LOW和WMARK_HIGH水位
	 * 这在页面分配器和kswapd页面回收中会用到
	 */
	/* zone watermarks, access with *_wmark_pages(zone) macros */
	unsigned long watermark[NR_WMARK];
	/* 高阶原子分配：阶数大于0，并且调用者设置了分配标志位__GFP_ATOMIC，要求不能睡眠。
	 * 页分配器对高阶原子分配做了优化处理,增加了高阶原子类型（MIGRATE_HIGHATOMIC）,在内存区域的结构体中增加1个成员“nr_reserved_highatomic”,用来记录高阶原子类型的总页数,
	 * 并且限制其数量: zone->nr_reserved_highatomic < (zone->managed_pages / 100) + pageblock_nr_pages,即必须小于(伙伴分配器管理的总页数 / 100 + 分组阶数对应的页数).
	 */
	unsigned long nr_reserved_highatomic;

	/*
	 * We don't know if the memory that we're going to allocate will be
	 * freeable or/and it will be released eventually, so to avoid totally
	 * wasting several GB of ram we must reserve some of the lower zone
	 * memory (otherwise we risk to run OOM on the lower zones despite
	 * there being tons of freeable ram on the higher zones).  This array is
	 * recalculated at runtime if the sysctl_lowmem_reserve_ratio sysctl
	 * changes.
	 *
	 * 我们不知道我们将要分配的内存是否是freeable,或者/并且它最终会被释放,
	 * 所以为了避免完全浪费几个GB的内存,我们必须保留一些较低区域的内存(否则,尽管较高区域上有大量可自由用的内存,但我们仍有在较低区域上运行OOM的风险)
	 * 如果sysctl_lowmem_reserve_ratio sysctl发生更改，则会在运行时重新计算此数组.
	 */
	/* zone预留的内存 */
	/* 每个内存管理区(zone)都有一个lowmem_reserve字段,它代表本管理区预留的物理内存大小.
	 * 所谓预留,那就是说肯定还是有用的,只是用的时机不同.
	 * 系统中已经为每个管理区(zone)内存大小设定了三个水位值了,分别时WMARK_HIGH/WMARK_LOW/WMARK_MIN.怎么这里又多出来一个lowmem_reserve?
	 * 在内存分配时,分配器会根据不同的水位执行不同的动作,首先内存分配器会扫描所有zonelist中的管理区,按照zonelist中的分配顺序依次检查管理区中能否分配对应的内存.
	 * 这几个值都是用来确定最终要从哪个管理区来分配内存这个问题的.
	 * 内存申请时有一个fallback的过程，通过gfp flag得到zone并不一定是最终申请内存所在的zone，fallback的顺序如下:
	 * fallback list: MOVABLE=>HIGHMEM=>NORMAL=>DMA32=>DMA
	 * 通过fallback顺序依次检测具备合适空闲内存的zone用于本次申请,那么对于高位的zone过量申请可能导致低位的zone被用尽,从而影响低位的申请,比如DMA内存的申请失败可能引起系统异常,
	 * 那么lowmem_reserve就是为了防止高位zone在fallback时过度使用自己的内存.
	 * 低位zone会优先保证自己的内存分配,确实有一定的富余的情况下,才可以提供给更高位的zones.
	 * 通过系统文件/proc/zoneinfo中的"protection"可以看到各个zone的lowmem_reserve配置.
	 */
	long lowmem_reserve[MAX_NR_ZONES];

#ifdef CONFIG_NUMA
	int node;
#endif
	/* 指向内存的节点 */
	struct pglist_data	*zone_pgdat;
	/* 用于维护Per-CPU上一系列页面，以减少自旋锁的争用 */
	struct per_cpu_pageset __percpu *pageset;

#ifndef CONFIG_SPARSEMEM
	/*
	 * Flags for a pageblock_nr_pages block. See pageblock-flags.h.
	 * In SPARSEMEM, this map is stored in struct mem_section
	 */
	unsigned long		*pageblock_flags;
#endif /* CONFIG_SPARSEMEM */

	/* zone_start_pfn == zone_start_paddr >> PAGE_SHIFT */
	/* zone中开始页面的页帧号 */
	unsigned long		zone_start_pfn;

	/*
	 * spanned_pages is the total pages spanned by the zone, including
	 * holes, which is calculated as:
	 * 	spanned_pages = zone_end_pfn - zone_start_pfn;
	 *
	 * spanned_pages是zone 跨越的总页数,包括黑洞,计算如下:
	 * 	spanned_pages=zone_end_pfn-zone_start_pfn;
	 *
	 * present_pages is physical pages existing within the zone, which
	 * is calculated as:
	 *	present_pages = spanned_pages - absent_pages(pages in holes);
	 *
	 * present_pages是zone存在的物理页面，计算如下：
	 *	present_pages = spanned_pages- absent_pages(黑洞的页面);
	 *
	 * managed_pages is present pages managed by the buddy system, which
	 * is calculated as (reserved_pages includes pages allocated by the
	 * bootmem allocator):
	 *	managed_pages = present_pages - reserved_pages;
	 *
	 * managed_pages是由伙伴系统管理的当前页面,其计算为(reserved_pages包括由bootmem分配器分配的页面)
	 *	managed_pages=present_pages-reserved_pages;
	 *
	 * So present_pages may be used by memory hotplug or memory power
	 * management logic to figure out unmanaged pages by checking
	 * (present_pages - managed_pages). And managed_pages should be used
	 * by page allocator and vm scanner to calculate all kinds of watermarks
	 * and thresholds.
	 *
	 * 因此，内存热插拔或内存电源管理logic可以使用present_pages来通过检查(present_paages-managed_pages)找出未管理的页面.
	 * managed_pagesb被页面分配器使用和vm扫描器来计算各种水位和阈值。
	 *
	 * Locking rules:
	 *
	 * zone_start_pfn and spanned_pages are protected by span_seqlock.
	 * It is a seqlock because it has to be read outside of zone->lock,
	 * and it is done in the main allocator path.  But, it is written
	 * quite infrequently.
	 *
	 * zone_start_pfn和spanned_pages受span_seqlock保护,
	 * 它是一个seqlock,因为它必须在zone->lock之外读取,并且是在主分配器路径中完成的.但是,它很少被写.
	 *
	 * The span_seq lock is declared along with zone->lock because it is
	 * frequently read in proximity to zone->lock.  It's good to
	 * give them a chance of being in the same cacheline.
	 *
	 * span_seq lock 与zone->lock 一起声明,因为它经常在zone->lock 附近读取.
	 * 很高兴能给他们一个机会,让他们有相同的cacheline.
	 *
	 * Write access to present_pages at runtime should be protected by
	 * mem_hotplug_begin/end(). Any reader who can't tolerant drift of
	 * present_pages should get_online_mems() to get a stable value.
	 *
	 * 运行时对present_pages的写访问应该受到mem_hotplug_begin/end()的保护.
	 * 任何不能容忍present_pages变动的读者都应该通过get_online_mems()以获得一个稳定的值.
	 *
	 * Read access to managed_pages should be safe because it's unsigned
	 * long. Write access to zone->managed_pages and totalram_pages are
	 * protected by managed_page_count_lock at runtime. Idealy only
	 * adjust_managed_page_count() should be used instead of directly
	 * touching zone->managed_pages and totalram_pages.
	 *
	 * 对managed_pages的读取访问应该是安全的,因为它是unsigned long的.
	 * 在运行时,对zone->managed_pages和totalam_pages的写访问受managed_page_count_lock保护.
	 * 理想情况下,adjust_managed_page_count()应该取代直接接触zone->managed_pages和totalram_pages而被使用
	 *
	 */
	/* zone被伙伴系统管理的数量 */
	unsigned long		managed_pages;
	/* zone 包含的页面数量 */
	unsigned long		spanned_pages;
	/* zone 里实际管理的页面的数量。对一些体系结构来说，其值和spanned_pages相等 */
	unsigned long		present_pages;

	const char		*name;

#ifdef CONFIG_MEMORY_ISOLATION
	/*
	 * Number of isolated pageblock. It is used to solve incorrect
	 * freepage counting problem due to racy retrieving migratetype
	 * of pageblock. Protected by zone->lock.
	 */
	unsigned long		nr_isolate_pageblock;
#endif

#ifdef CONFIG_MEMORY_HOTPLUG
	/* see spanned/present_pages for more description */
	seqlock_t		span_seqlock;
#endif

	int initialized;

	/* Write-intensive fields used from the page allocator */
	ZONE_PADDING(_pad1_)
	/* free areas of different sizes */
	/* 管理空闲区域的数组，包含管理链表等 */
	struct free_area	free_area[MAX_ORDER];

	/* zone flags, see below */
	unsigned long		flags;
	/* Primarily protects free_area */
	/* 并行访问时用于对zone保护的自旋锁 */
	spinlock_t		lock;

	/* Write-intensive fields used by compaction and vmstats. */
	ZONE_PADDING(_pad2_)

	/*
	 * When free pages are below this point, additional steps are taken
	 * when reading the number of free pages to avoid per-cpu counter
	 * drift allowing watermarks to be breached
	 *
	 * 当free pages 低于这一点时,在读取free pages的数量时采取额外步骤,以避免per-cpu 计数滑动导致水位被破坏
	 */
	unsigned long percpu_drift_mark;

#if defined CONFIG_COMPACTION || defined CONFIG_CMA
	/* pfn where compaction free scanner should start */
	/* 用于记录从尾部开始扫描的空闲page的位置 */
	unsigned long		compact_cached_free_pfn;
	/* 该数组用于控制异步和同步两种memory compact场景所从头部开始扫描的页迁移位置 */
	/* pfn where async and sync compaction migration scanner should start */
	unsigned long		compact_cached_migrate_pfn[2];
#endif

#ifdef CONFIG_COMPACTION
	/*
	 * On compaction failure, 1<<compact_defer_shift compactions
	 * are skipped before trying again. The number attempted since
	 * last failure is tracked with compact_considered.
	 *
	 * 在规整失败时,在重试之前将跳过 1<<compact_defer_shift规整.
	 * 使用compact_conidered来跟踪自上次失败以来尝试的次数.
	 */

	/* 内存碎片整理成功的标准是: (空闲页数 − 申请页数)大于或等于水线,并且申请或备用的迁移类型至少有一个足够大的空闲页块.
	 * 执行完全同步模式或轻量级同步模式的内存碎片整理,当迁移扫描器和空闲扫描器相遇的时候,没有达到成功标准,以后试图执行轻量级同步或异步模式的内存碎片整理,
	 * 如果申请阶数大于或等于内存碎片整理失败时的申请阶数,需要推迟若干次.
	 * 内核在内存区域中增加了3个成员用来记录内存碎片整理推迟的信息:
	 *
	 * 成员compact_considered记录推迟的次数
	 * 成员compact_defer_shift是推迟的最大次数以2为底的对数,当推迟的次数达到(1 << compact_defer_shift)时,不能推迟
	 *
	 * 每次内存碎片整理执行失败,把成员compact_defer_shift加1,不允许超过COMPACT_MAX_DEFER_SHIFT(值为6),即把推迟的最大次数翻倍,但是不能超过64.
	 * 页分配器在执行内存碎片整理以后,如果分配页成功,那么把成员compact_defer_shift设置为0.
	 */
	unsigned int		compact_considered;
	unsigned int		compact_defer_shift;
	/* 成员compact_order_failed记录内存碎片整理失败时的申请阶数.
	 * 内存碎片整理执行成功的时候,如果申请阶数order大于或等于成员compact_order_failed,那么把成员compact_order_failed设置为(order + 1).
	 * 内存碎片整理执行失败的时候,如果申请阶数order小于成员compact_order_failed,那么把成员compact_order_failed设置为order.
	 */
	int			compact_order_failed;
#endif

#if defined CONFIG_COMPACTION || defined CONFIG_CMA
	/* Set to true when the PG_migrate_skip bits should be cleared */
	bool			compact_blockskip_flush;
#endif

	bool			contiguous;

	ZONE_PADDING(_pad3_)
	/* Zone statistics */
	/* zone 计数 */
	atomic_long_t		vm_stat[NR_VM_ZONE_STAT_ITEMS];
} ____cacheline_internodealigned_in_smp;

enum pgdat_flags {
	PGDAT_CONGESTED,		/* pgdat has many dirty pages backed by
					 * a congested BDI
					 */
	PGDAT_DIRTY,			/* reclaim scanning has recently found
					 * many dirty file pages at the tail
					 * of the LRU.
					 */
	PGDAT_WRITEBACK,		/* reclaim scanning has recently found
					 * many pages under writeback
					 */
	PGDAT_RECLAIM_LOCKED,		/* prevents concurrent reclaim */
};

static inline unsigned long zone_end_pfn(const struct zone *zone)
{
	return zone->zone_start_pfn + zone->spanned_pages;
}

static inline bool zone_spans_pfn(const struct zone *zone, unsigned long pfn)
{
	return zone->zone_start_pfn <= pfn && pfn < zone_end_pfn(zone);
}

static inline bool zone_is_initialized(struct zone *zone)
{
	return zone->initialized;
}

static inline bool zone_is_empty(struct zone *zone)
{
	return zone->spanned_pages == 0;
}

/*
 * The "priority" of VM scanning is how much of the queues we will scan in one
 * go. A value of 12 for DEF_PRIORITY implies that we will scan 1/4096th of the
 * queues ("queue_length >> 12") during an aging round.
 */
#define DEF_PRIORITY 12

/* Maximum number of zones on a zonelist */
#define MAX_ZONES_PER_ZONELIST (MAX_NUMNODES * MAX_NR_ZONES)

enum {
	ZONELIST_FALLBACK,	/* zonelist with fallback */
#ifdef CONFIG_NUMA
	/*
	 * The NUMA zonelists are doubled because we need zonelists that
	 * restrict the allocations to a single node for __GFP_THISNODE.
	 */
	ZONELIST_NOFALLBACK,	/* zonelist without fallback (__GFP_THISNODE) */
#endif
	MAX_ZONELISTS
};

/*
 * This struct contains information about a zone in a zonelist. It is stored
 * here to avoid dereferences into large structures and lookups of tables
 */
struct zoneref {
	struct zone *zone;	/* Pointer to actual zone */
	int zone_idx;		/* zone_idx(zoneref->zone) */
};

/*
 * One allocation request operates on a zonelist. A zonelist
 * is a list of zones, the first one is the 'goal' of the
 * allocation, the other zones are fallback zones, in decreasing
 * priority.
 *
 * To speed the reading of the zonelist, the zonerefs contain the zone index
 * of the entry being read. Helper functions to access information given
 * a struct zoneref are
 *
 * zonelist_zone()	- Return the struct zone * for an entry in _zonerefs
 * zonelist_zone_idx()	- Return the index of the zone for an entry
 * zonelist_node_idx()	- Return the index of the node for an entry
 */
struct zonelist {
	struct zoneref _zonerefs[MAX_ZONES_PER_ZONELIST + 1];
};

#ifndef CONFIG_DISCONTIGMEM
/* The array of struct pages - for discontigmem use pgdat->lmem_map */
extern struct page *mem_map;
#endif

/*
 * The pg_data_t structure is used in machines with CONFIG_DISCONTIGMEM
 * (mostly NUMA machines?) to denote a higher-level memory zone than the
 * zone denotes.
 *
 * On NUMA machines, each NUMA node would have a pg_data_t to describe
 * it's memory layout.
 *
 * Memory statistics and page replacement data structures are maintained on a
 * per-zone basis.
 */
struct bootmem_data;
typedef struct pglist_data {
	struct zone node_zones[MAX_NR_ZONES];
	struct zonelist node_zonelists[MAX_ZONELISTS];
	int nr_zones;
#ifdef CONFIG_FLAT_NODE_MEM_MAP	/* means !SPARSEMEM */
	struct page *node_mem_map;
#ifdef CONFIG_PAGE_EXTENSION
	struct page_ext *node_page_ext;
#endif
#endif
#ifndef CONFIG_NO_BOOTMEM
	struct bootmem_data *bdata;
#endif
#ifdef CONFIG_MEMORY_HOTPLUG
	/*
	 * Must be held any time you expect node_start_pfn, node_present_pages
	 * or node_spanned_pages stay constant.  Holding this will also
	 * guarantee that any pfn_valid() stays that way.
	 *
	 * pgdat_resize_lock() and pgdat_resize_unlock() are provided to
	 * manipulate node_size_lock without checking for CONFIG_MEMORY_HOTPLUG.
	 *
	 * Nests above zone->lock and zone->span_seqlock
	 */
	spinlock_t node_size_lock;
#endif
	unsigned long node_start_pfn;
	unsigned long node_present_pages; /* total number of physical pages */
	unsigned long node_spanned_pages; /* total size of physical page
					     range, including holes */
	int node_id;
	wait_queue_head_t kswapd_wait;
	wait_queue_head_t pfmemalloc_wait;
	struct task_struct *kswapd;	/* Protected by
					   mem_hotplug_begin/end() */
	int kswapd_order;
	enum zone_type kswapd_classzone_idx;

#ifdef CONFIG_COMPACTION
	int kcompactd_max_order;
	enum zone_type kcompactd_classzone_idx;
	wait_queue_head_t kcompactd_wait;
	struct task_struct *kcompactd;
#endif
#ifdef CONFIG_NUMA_BALANCING
	/* Lock serializing the migrate rate limiting window */
	spinlock_t numabalancing_migrate_lock;

	/* Rate limiting time interval */
	unsigned long numabalancing_migrate_next_window;

	/* Number of pages migrated during the rate limiting time interval */
	unsigned long numabalancing_migrate_nr_pages;
#endif
	/*
	 * This is a per-node reserve of pages that are not available
	 * to userspace allocations.
	 */
	unsigned long		totalreserve_pages;

#ifdef CONFIG_NUMA
	/*
	 * zone reclaim becomes active if more unmapped pages exist.
	 */
	/* pgdat->min_unmapped_pages 是“/proc/sys/vm/min_unmapped_ratio”乘上总的页数.
	 * 页缓存中潜在可回收页数如果大于pgdat->min_unmapped_pages才做页回收
	 */
	unsigned long		min_unmapped_pages;
	/* min_slab_pages:如果用于slab的页达到这个值就缓存收缩 */
	unsigned long		min_slab_pages;
#endif /* CONFIG_NUMA */

	/* Write-intensive fields used by page reclaim */
	ZONE_PADDING(_pad1_)
	spinlock_t		lru_lock;

#ifdef CONFIG_DEFERRED_STRUCT_PAGE_INIT
	/*
	 * If memory initialisation on large machines is deferred then this
	 * is the first PFN that needs to be initialised.
	 */
	/* 若在大机器上的内存初始化被推迟了，那么这是
	 * 第一个需要被初始化的 PFN
	 */
	unsigned long first_deferred_pfn;
	unsigned long static_init_size;
#endif /* CONFIG_DEFERRED_STRUCT_PAGE_INIT */

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	/* 这里实际上就是把THP切割成小page的队列
	 * 具体可以看一下deferred_split_huge_page函数
	 */
	spinlock_t split_queue_lock;
	struct list_head split_queue;
	unsigned long split_queue_len;
#endif

	/* Fields commonly accessed by the page reclaim scanner */
	struct lruvec		lruvec;

	/*
	 * The target ratio of ACTIVE_ANON to INACTIVE_ANON pages on
	 * this node's LRU.  Maintained by the pageout code.
	 */
	unsigned int inactive_ratio;

	unsigned long		flags;

	ZONE_PADDING(_pad2_)

	/* Per-node vmstats */
	struct per_cpu_nodestat __percpu *per_cpu_nodestats;
	atomic_long_t		vm_stat[NR_VM_NODE_STAT_ITEMS];
} pg_data_t;

#define node_present_pages(nid)	(NODE_DATA(nid)->node_present_pages)
#define node_spanned_pages(nid)	(NODE_DATA(nid)->node_spanned_pages)
#ifdef CONFIG_FLAT_NODE_MEM_MAP
#define pgdat_page_nr(pgdat, pagenr)	((pgdat)->node_mem_map + (pagenr))
#else
#define pgdat_page_nr(pgdat, pagenr)	pfn_to_page((pgdat)->node_start_pfn + (pagenr))
#endif
#define nid_page_nr(nid, pagenr) 	pgdat_page_nr(NODE_DATA(nid),(pagenr))

#define node_start_pfn(nid)	(NODE_DATA(nid)->node_start_pfn)
#define node_end_pfn(nid) pgdat_end_pfn(NODE_DATA(nid))
static inline spinlock_t *zone_lru_lock(struct zone *zone)
{
	return &zone->zone_pgdat->lru_lock;
}

static inline struct lruvec *node_lruvec(struct pglist_data *pgdat)
{
	return &pgdat->lruvec;
}

static inline unsigned long pgdat_end_pfn(pg_data_t *pgdat)
{
	return pgdat->node_start_pfn + pgdat->node_spanned_pages;
}

static inline bool pgdat_is_empty(pg_data_t *pgdat)
{
	return !pgdat->node_start_pfn && !pgdat->node_spanned_pages;
}

static inline int zone_id(const struct zone *zone)
{
	struct pglist_data *pgdat = zone->zone_pgdat;

	return zone - pgdat->node_zones;
}

#ifdef CONFIG_ZONE_DEVICE
static inline bool is_dev_zone(const struct zone *zone)
{
	return zone_id(zone) == ZONE_DEVICE;
}
#else
static inline bool is_dev_zone(const struct zone *zone)
{
	return false;
}
#endif

#include <linux/memory_hotplug.h>

extern struct mutex zonelists_mutex;
void build_all_zonelists(pg_data_t *pgdat, struct zone *zone);
void wakeup_kswapd(struct zone *zone, int order, enum zone_type classzone_idx);
bool __zone_watermark_ok(struct zone *z, unsigned int order, unsigned long mark,
			 int classzone_idx, unsigned int alloc_flags,
			 long free_pages);
bool zone_watermark_ok(struct zone *z, unsigned int order,
		unsigned long mark, int classzone_idx,
		unsigned int alloc_flags);
bool zone_watermark_ok_safe(struct zone *z, unsigned int order,
		unsigned long mark, int classzone_idx);
enum memmap_context {
	MEMMAP_EARLY,
	MEMMAP_HOTPLUG,
};
extern int init_currently_empty_zone(struct zone *zone, unsigned long start_pfn,
				     unsigned long size);

extern void lruvec_init(struct lruvec *lruvec);

static inline struct pglist_data *lruvec_pgdat(struct lruvec *lruvec)
{
#ifdef CONFIG_MEMCG
	return lruvec->pgdat;
#else
	return container_of(lruvec, struct pglist_data, lruvec);
#endif
}

extern unsigned long lruvec_lru_size(struct lruvec *lruvec, enum lru_list lru, int zone_idx);

#ifdef CONFIG_HAVE_MEMORY_PRESENT
void memory_present(int nid, unsigned long start, unsigned long end);
#else
static inline void memory_present(int nid, unsigned long start, unsigned long end) {}
#endif

#ifdef CONFIG_HAVE_MEMORYLESS_NODES
int local_memory_node(int node_id);
#else
static inline int local_memory_node(int node_id) { return node_id; };
#endif

#ifdef CONFIG_NEED_NODE_MEMMAP_SIZE
unsigned long __init node_memmap_size_bytes(int, unsigned long, unsigned long);
#endif

/*
 * zone_idx() returns 0 for the ZONE_DMA zone, 1 for the ZONE_NORMAL zone, etc.
 */
#define zone_idx(zone)		((zone) - (zone)->zone_pgdat->node_zones)

/*
 * Returns true if a zone has pages managed by the buddy allocator.
 * All the reclaim decisions have to use this function rather than
 * populated_zone(). If the whole zone is reserved then we can easily
 * end up with populated_zone() && !managed_zone().
 *
 * 如果zone内有由伙伴分配器管理的页面,则返回true.
 * 所有回收决策都必须使用此函数,而不是populated_zone().
 * 如果整个区域都是reserved,那么我们可以用 populated_zone() &&! managed_zone() 判断
 */
static inline bool managed_zone(struct zone *zone)
{
	return zone->managed_pages;
}

/* Returns true if a zone has memory */
static inline bool populated_zone(struct zone *zone)
{
	return zone->present_pages;
}

extern int movable_zone;

#ifdef CONFIG_HIGHMEM
static inline int zone_movable_is_highmem(void)
{
#ifdef CONFIG_HAVE_MEMBLOCK_NODE_MAP
	return movable_zone == ZONE_HIGHMEM;
#else
	return (ZONE_MOVABLE - 1) == ZONE_HIGHMEM;
#endif
}
#endif

static inline int is_highmem_idx(enum zone_type idx)
{
#ifdef CONFIG_HIGHMEM
	return (idx == ZONE_HIGHMEM ||
		(idx == ZONE_MOVABLE && zone_movable_is_highmem()));
#else
	return 0;
#endif
}

/**
 * is_highmem - helper function to quickly check if a struct zone is a 
 *              highmem zone or not.  This is an attempt to keep references
 *              to ZONE_{DMA/NORMAL/HIGHMEM/etc} in general code to a minimum.
 * @zone - pointer to struct zone variable
 */
static inline int is_highmem(struct zone *zone)
{
#ifdef CONFIG_HIGHMEM
	return is_highmem_idx(zone_idx(zone));
#else
	return 0;
#endif
}

/* These two functions are used to setup the per zone pages min values */
struct ctl_table;
int min_free_kbytes_sysctl_handler(struct ctl_table *, int,
					void __user *, size_t *, loff_t *);
int watermark_scale_factor_sysctl_handler(struct ctl_table *, int,
					void __user *, size_t *, loff_t *);
extern int sysctl_lowmem_reserve_ratio[MAX_NR_ZONES-1];
int lowmem_reserve_ratio_sysctl_handler(struct ctl_table *, int,
					void __user *, size_t *, loff_t *);
int percpu_pagelist_fraction_sysctl_handler(struct ctl_table *, int,
					void __user *, size_t *, loff_t *);
int sysctl_min_unmapped_ratio_sysctl_handler(struct ctl_table *, int,
			void __user *, size_t *, loff_t *);
int sysctl_min_slab_ratio_sysctl_handler(struct ctl_table *, int,
			void __user *, size_t *, loff_t *);

extern int numa_zonelist_order_handler(struct ctl_table *, int,
			void __user *, size_t *, loff_t *);
extern char numa_zonelist_order[];
#define NUMA_ZONELIST_ORDER_LEN 16	/* string buffer size */

#ifndef CONFIG_NEED_MULTIPLE_NODES

extern struct pglist_data contig_page_data;
#define NODE_DATA(nid)		(&contig_page_data)
#define NODE_MEM_MAP(nid)	mem_map

#else /* CONFIG_NEED_MULTIPLE_NODES */

#include <asm/mmzone.h>

#endif /* !CONFIG_NEED_MULTIPLE_NODES */

extern struct pglist_data *first_online_pgdat(void);
extern struct pglist_data *next_online_pgdat(struct pglist_data *pgdat);
extern struct zone *next_zone(struct zone *zone);

/**
 * for_each_online_pgdat - helper macro to iterate over all online nodes
 * @pgdat - pointer to a pg_data_t variable
 */
#define for_each_online_pgdat(pgdat)			\
	for (pgdat = first_online_pgdat();		\
	     pgdat;					\
	     pgdat = next_online_pgdat(pgdat))
/**
 * for_each_zone - helper macro to iterate over all memory zones
 * @zone - pointer to struct zone variable
 *
 * The user only needs to declare the zone variable, for_each_zone
 * fills it in.
 */
#define for_each_zone(zone)			        \
	for (zone = (first_online_pgdat())->node_zones; \
	     zone;					\
	     zone = next_zone(zone))

#define for_each_populated_zone(zone)		        \
	for (zone = (first_online_pgdat())->node_zones; \
	     zone;					\
	     zone = next_zone(zone))			\
		if (!populated_zone(zone))		\
			; /* do nothing */		\
		else

static inline struct zone *zonelist_zone(struct zoneref *zoneref)
{
	return zoneref->zone;
}

static inline int zonelist_zone_idx(struct zoneref *zoneref)
{
	return zoneref->zone_idx;
}

static inline int zonelist_node_idx(struct zoneref *zoneref)
{
#ifdef CONFIG_NUMA
	/* zone_to_nid not available in this context */
	return zoneref->zone->node;
#else
	return 0;
#endif /* CONFIG_NUMA */
}

struct zoneref *__next_zones_zonelist(struct zoneref *z,
					enum zone_type highest_zoneidx,
					nodemask_t *nodes);

/**
 * next_zones_zonelist - Returns the next zone at or below highest_zoneidx within the allowed nodemask using a cursor within a zonelist as a starting point
 * @z - The cursor used as a starting point for the search
 * @highest_zoneidx - The zone index of the highest zone to return
 * @nodes - An optional nodemask to filter the zonelist with
 *
 * This function returns the next zone at or below a given zone index that is
 * within the allowed nodemask using a cursor as the starting point for the
 * search. The zoneref returned is a cursor that represents the current zone
 * being examined. It should be advanced by one before calling
 * next_zones_zonelist again.
 */
static __always_inline struct zoneref *next_zones_zonelist(struct zoneref *z,
					enum zone_type highest_zoneidx,
					nodemask_t *nodes)
{
	/* 如果node不为空,并且zonelist_zone_idx(z) <= highest_zoneidx
	 * 那么返回zoneref
	 * 在build_zonelists_node中
	 * ZONE_HIGHMEM _zonerefs[0] -> zone_index = 1
	 * ZONE_NORMAL  _zonerefs[1] -> zone_index = 0
	 */
	if (likely(!nodes && zonelist_zone_idx(z) <= highest_zoneidx))
		return z;
	return __next_zones_zonelist(z, highest_zoneidx, nodes);
}

/**
 * first_zones_zonelist - Returns the first zone at or below highest_zoneidx within the allowed nodemask in a zonelist
 * @zonelist - The zonelist to search for a suitable zone
 * @highest_zoneidx - The zone index of the highest zone to return
 * @nodes - An optional nodemask to filter the zonelist with
 * @return - Zoneref pointer for the first suitable zone found (see below)
 *
 * This function returns the first zone at or below a given zone index that is
 * within the allowed nodemask. The zoneref returned is a cursor that can be
 * used to iterate the zonelist with next_zones_zonelist by advancing it by
 * one before calling.
 *
 * When no eligible zone is found, zoneref->zone is NULL (zoneref itself is
 * never NULL). This may happen either genuinely, or due to concurrent nodemask
 * update due to cpuset modification.
 *
 * first_zones_zonelist-返回在允许的nodemask的zonelist中第一个小于等于highest_zoneidx的zone
 * @zonelist-搜索合适zone的zonelist
 * @highest_zoneidx-要返回的最高区域的zone index
 * @nodes-一个可选的nodemask，用于过滤zonelist
 * @return-找到的第一个合适区域的Zoneref指针（见下文）
 *
 * 此函数返回在allowed nodemask 位于或低于给定zone inde的第一个区域,
 * 返回的zoneref是一个游标,可通过在调用前让其+1通过next_zones_zonelist去迭代zonelist
 *
 * 当找不到符合条件的zone时,zoneref->区域为NULL(zoneref本身从不为NULL).
 * 这可能是真实发生的，也可能是由于cpuset修改导致的并发nodemask更新.
 */
static inline struct zoneref *first_zones_zonelist(struct zonelist *zonelist,
					enum zone_type highest_zoneidx,
					nodemask_t *nodes)
{
	return next_zones_zonelist(zonelist->_zonerefs,
							highest_zoneidx, nodes);
}

/**
 * for_each_zone_zonelist_nodemask - helper macro to iterate over valid zones in a zonelist at or below a given zone index and within a nodemask
 * @zone - The current zone in the iterator
 * @z - The current pointer within zonelist->zones being iterated
 * @zlist - The zonelist being iterated
 * @highidx - The zone index of the highest zone to return
 * @nodemask - Nodemask allowed by the allocator
 *
 * This iterator iterates though all zones at or below a given zone index and
 * within a given nodemask
 */
#define for_each_zone_zonelist_nodemask(zone, z, zlist, highidx, nodemask) \
	for (z = first_zones_zonelist(zlist, highidx, nodemask), zone = zonelist_zone(z);	\
		zone;							\
		z = next_zones_zonelist(++z, highidx, nodemask),	\
			zone = zonelist_zone(z))

/* 首先通过first_zones_zonelist从给定的zoneidx开始查找,这个给定的zoneidx就是highidx,之前通过gfp_zone函数转换得来的 */
#define for_next_zone_zonelist_nodemask(zone, z, zlist, highidx, nodemask) \
	for (zone = z->zone;	\
		zone;							\
		z = next_zones_zonelist(++z, highidx, nodemask),	\
			zone = zonelist_zone(z))


/**
 * for_each_zone_zonelist - helper macro to iterate over valid zones in a zonelist at or below a given zone index
 * @zone - The current zone in the iterator
 * @z - The current pointer within zonelist->zones being iterated
 * @zlist - The zonelist being iterated
 * @highidx - The zone index of the highest zone to return
 *
 * This iterator iterates though all zones at or below a given zone index.
 */
#define for_each_zone_zonelist(zone, z, zlist, highidx) \
	for_each_zone_zonelist_nodemask(zone, z, zlist, highidx, NULL)

#ifdef CONFIG_SPARSEMEM
#include <asm/sparsemem.h>
#endif

#if !defined(CONFIG_HAVE_ARCH_EARLY_PFN_TO_NID) && \
	!defined(CONFIG_HAVE_MEMBLOCK_NODE_MAP)
static inline unsigned long early_pfn_to_nid(unsigned long pfn)
{
	return 0;
}
#endif

#ifdef CONFIG_FLATMEM
#define pfn_to_nid(pfn)		(0)
#endif

#ifdef CONFIG_SPARSEMEM

/*
 * SECTION_SHIFT    		#bits space required to store a section #
 *
 * PA_SECTION_SHIFT		physical address to/from section number
 * PFN_SECTION_SHIFT		pfn to/from section number
 */
#define PA_SECTION_SHIFT	(SECTION_SIZE_BITS)
#define PFN_SECTION_SHIFT	(SECTION_SIZE_BITS - PAGE_SHIFT)

#define NR_MEM_SECTIONS		(1UL << SECTIONS_SHIFT)

#define PAGES_PER_SECTION       (1UL << PFN_SECTION_SHIFT)
#define PAGE_SECTION_MASK	(~(PAGES_PER_SECTION-1))

#define SECTION_BLOCKFLAGS_BITS \
	((1UL << (PFN_SECTION_SHIFT - pageblock_order)) * NR_PAGEBLOCK_BITS)

#if (MAX_ORDER - 1 + PAGE_SHIFT) > SECTION_SIZE_BITS
#error Allocator MAX_ORDER exceeds SECTION_SIZE
#endif

#define pfn_to_section_nr(pfn) ((pfn) >> PFN_SECTION_SHIFT)
#define section_nr_to_pfn(sec) ((sec) << PFN_SECTION_SHIFT)

#define SECTION_ALIGN_UP(pfn)	(((pfn) + PAGES_PER_SECTION - 1) & PAGE_SECTION_MASK)
#define SECTION_ALIGN_DOWN(pfn)	((pfn) & PAGE_SECTION_MASK)

struct page;
struct page_ext;
struct mem_section {
	/*
	 * This is, logically, a pointer to an array of struct
	 * pages.  However, it is stored with some other magic.
	 * (see sparse.c::sparse_init_one_section())
	 *
	 * Additionally during early boot we encode node id of
	 * the location of the section here to guide allocation.
	 * (see sparse.c::memory_present())
	 *
	 * Making it a UL at least makes someone do a cast
	 * before using it wrong.
	 */
	unsigned long section_mem_map;

	/* See declaration of similar field in struct zone */
	unsigned long *pageblock_flags;
#ifdef CONFIG_PAGE_EXTENSION
	/*
	 * If SPARSEMEM, pgdat doesn't have page_ext pointer. We use
	 * section. (see page_ext.h about this.)
	 */
	struct page_ext *page_ext;
	unsigned long pad;
#endif
	/*
	 * WARNING: mem_section must be a power-of-2 in size for the
	 * calculation and use of SECTION_ROOT_MASK to make sense.
	 */
};

#ifdef CONFIG_SPARSEMEM_EXTREME
#define SECTIONS_PER_ROOT       (PAGE_SIZE / sizeof (struct mem_section))
#else
#define SECTIONS_PER_ROOT	1
#endif

#define SECTION_NR_TO_ROOT(sec)	((sec) / SECTIONS_PER_ROOT)
#define NR_SECTION_ROOTS	DIV_ROUND_UP(NR_MEM_SECTIONS, SECTIONS_PER_ROOT)
#define SECTION_ROOT_MASK	(SECTIONS_PER_ROOT - 1)

#ifdef CONFIG_SPARSEMEM_EXTREME
extern struct mem_section *mem_section[NR_SECTION_ROOTS];
#else
extern struct mem_section mem_section[NR_SECTION_ROOTS][SECTIONS_PER_ROOT];
#endif

static inline struct mem_section *__nr_to_section(unsigned long nr)
{
	if (!mem_section[SECTION_NR_TO_ROOT(nr)])
		return NULL;
	return &mem_section[SECTION_NR_TO_ROOT(nr)][nr & SECTION_ROOT_MASK];
}
extern int __section_nr(struct mem_section* ms);
extern unsigned long usemap_size(void);

/*
 * We use the lower bits of the mem_map pointer to store
 * a little bit of information.  There should be at least
 * 3 bits here due to 32-bit alignment.
 */
#define	SECTION_MARKED_PRESENT	(1UL<<0)
#define SECTION_HAS_MEM_MAP	(1UL<<1)
#define SECTION_MAP_LAST_BIT	(1UL<<2)
#define SECTION_MAP_MASK	(~(SECTION_MAP_LAST_BIT-1))
#define SECTION_NID_SHIFT	2

static inline struct page *__section_mem_map_addr(struct mem_section *section)
{
	unsigned long map = section->section_mem_map;
	map &= SECTION_MAP_MASK;
	return (struct page *)map;
}

static inline int present_section(struct mem_section *section)
{
	return (section && (section->section_mem_map & SECTION_MARKED_PRESENT));
}

static inline int present_section_nr(unsigned long nr)
{
	return present_section(__nr_to_section(nr));
}

static inline int valid_section(struct mem_section *section)
{
	return (section && (section->section_mem_map & SECTION_HAS_MEM_MAP));
}

static inline int valid_section_nr(unsigned long nr)
{
	return valid_section(__nr_to_section(nr));
}

static inline struct mem_section *__pfn_to_section(unsigned long pfn)
{
	return __nr_to_section(pfn_to_section_nr(pfn));
}

#ifndef CONFIG_HAVE_ARCH_PFN_VALID
static inline int pfn_valid(unsigned long pfn)
{
	if (pfn_to_section_nr(pfn) >= NR_MEM_SECTIONS)
		return 0;
	return valid_section(__nr_to_section(pfn_to_section_nr(pfn)));
}
#endif

static inline int pfn_present(unsigned long pfn)
{
	if (pfn_to_section_nr(pfn) >= NR_MEM_SECTIONS)
		return 0;
	return present_section(__nr_to_section(pfn_to_section_nr(pfn)));
}

/*
 * These are _only_ used during initialisation, therefore they
 * can use __initdata ...  They could have names to indicate
 * this restriction.
 */
#ifdef CONFIG_NUMA
#define pfn_to_nid(pfn)							\
({									\
	unsigned long __pfn_to_nid_pfn = (pfn);				\
	page_to_nid(pfn_to_page(__pfn_to_nid_pfn));			\
})
#else
#define pfn_to_nid(pfn)		(0)
#endif

#define early_pfn_valid(pfn)	pfn_valid(pfn)
void sparse_init(void);
#else
#define sparse_init()	do {} while (0)
#define sparse_index_init(_sec, _nid)  do {} while (0)
#endif /* CONFIG_SPARSEMEM */

/*
 * During memory init memblocks map pfns to nids. The search is expensive and
 * this caches recent lookups. The implementation of __early_pfn_to_nid
 * may treat start/end as pfns or sections.
 */
struct mminit_pfnnid_cache {
	unsigned long last_start;
	unsigned long last_end;
	int last_nid;
};

#ifndef early_pfn_valid
#define early_pfn_valid(pfn)	(1)
#endif

void memory_present(int nid, unsigned long start, unsigned long end);
unsigned long __init node_memmap_size_bytes(int, unsigned long, unsigned long);

/*
 * If it is possible to have holes within a MAX_ORDER_NR_PAGES, then we
 * need to check pfn validility within that MAX_ORDER_NR_PAGES block.
 * pfn_valid_within() should be used in this case; we optimise this away
 * when we have no holes within a MAX_ORDER_NR_PAGES block.
 */
#ifdef CONFIG_HOLES_IN_ZONE
#define pfn_valid_within(pfn) pfn_valid(pfn)
#else
#define pfn_valid_within(pfn) (1)
#endif

#ifdef CONFIG_ARCH_HAS_HOLES_MEMORYMODEL
/*
 * pfn_valid() is meant to be able to tell if a given PFN has valid memmap
 * associated with it or not. In FLATMEM, it is expected that holes always
 * have valid memmap as long as there is valid PFNs either side of the hole.
 * In SPARSEMEM, it is assumed that a valid section has a memmap for the
 * entire section.
 *
 * However, an ARM, and maybe other embedded architectures in the future
 * free memmap backing holes to save memory on the assumption the memmap is
 * never used. The page_zone linkages are then broken even though pfn_valid()
 * returns true. A walker of the full memmap must then do this additional
 * check to ensure the memmap they are looking at is sane by making sure
 * the zone and PFN linkages are still valid. This is expensive, but walkers
 * of the full memmap are extremely rare.
 */
bool memmap_valid_within(unsigned long pfn,
					struct page *page, struct zone *zone);
#else
static inline bool memmap_valid_within(unsigned long pfn,
					struct page *page, struct zone *zone)
{
	return true;
}
#endif /* CONFIG_ARCH_HAS_HOLES_MEMORYMODEL */

#endif /* !__GENERATING_BOUNDS.H */
#endif /* !__ASSEMBLY__ */
#endif /* _LINUX_MMZONE_H */
