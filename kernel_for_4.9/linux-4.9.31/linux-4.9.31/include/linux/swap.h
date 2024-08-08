#ifndef _LINUX_SWAP_H
#define _LINUX_SWAP_H

#include <linux/spinlock.h>
#include <linux/linkage.h>
#include <linux/mmzone.h>
#include <linux/list.h>
#include <linux/memcontrol.h>
#include <linux/sched.h>
#include <linux/node.h>
#include <linux/fs.h>
#include <linux/atomic.h>
#include <linux/page-flags.h>
#include <asm/page.h>

struct notifier_block;

struct bio;

#define SWAP_FLAG_PREFER	0x8000	/* set if swap priority specified */
#define SWAP_FLAG_PRIO_MASK	0x7fff
#define SWAP_FLAG_PRIO_SHIFT	0
#define SWAP_FLAG_DISCARD	0x10000 /* enable discard for swap */
#define SWAP_FLAG_DISCARD_ONCE	0x20000 /* discard swap area at swapon-time */
#define SWAP_FLAG_DISCARD_PAGES 0x40000 /* discard page-clusters after use */

#define SWAP_FLAGS_VALID	(SWAP_FLAG_PRIO_MASK | SWAP_FLAG_PREFER | \
				 SWAP_FLAG_DISCARD | SWAP_FLAG_DISCARD_ONCE | \
				 SWAP_FLAG_DISCARD_PAGES)

static inline int current_is_kswapd(void)
{
	return current->flags & PF_KSWAPD;
}

/*
 * MAX_SWAPFILES defines the maximum number of swaptypes: things which can
 * be swapped to.  The swap type and the offset into that swap type are
 * encoded into pte's and into pgoff_t's in the swapcache.  Using five bits
 * for the type means that the maximum number of swapcache pages is 27 bits
 * on 32-bit-pgoff_t architectures.  And that assumes that the architecture packs
 * the type/offset into the pte as 5/27 as well.
 */
#define MAX_SWAPFILES_SHIFT	5

/*
 * Use some of the swap files numbers for other purposes. This
 * is a convenient way to hook into the VM to trigger special
 * actions on faults.
 */

/*
 * NUMA node memory migration support
 */
#ifdef CONFIG_MIGRATION
#define SWP_MIGRATION_NUM 2
#define SWP_MIGRATION_READ	(MAX_SWAPFILES + SWP_HWPOISON_NUM)
#define SWP_MIGRATION_WRITE	(MAX_SWAPFILES + SWP_HWPOISON_NUM + 1)
#else
#define SWP_MIGRATION_NUM 0
#endif

/*
 * Handling of hardware poisoned pages with memory corruption.
 */
#ifdef CONFIG_MEMORY_FAILURE
#define SWP_HWPOISON_NUM 1
#define SWP_HWPOISON		MAX_SWAPFILES
#else
#define SWP_HWPOISON_NUM 0
#endif

#define MAX_SWAPFILES \
	((1 << MAX_SWAPFILES_SHIFT) - SWP_MIGRATION_NUM - SWP_HWPOISON_NUM)

/*
 * Magic header for a swap area. The first part of the union is
 * what the swap magic looks like for the old (limited to 128MB)
 * swap area format, the second part of the union adds - in the
 * old reserved area - some extra information. Note that the first
 * kilobyte is reserved for boot loader or disk label stuff...
 *
 * Having the magic at the end of the PAGE_SIZE makes detecting swap
 * areas somewhat tricky on machines that support multiple page sizes.
 * For 2.5 we'll probably want to move the magic to just beyond the
 * bootbits...
 *
 * 交换区的魔法头部(Magic Header).
 * 这个联合(union)的第一部分展示了旧版(限制在128MB)交换区格式的"交换魔法"看起来是什么样的.
 * 联合的第二部分在旧的保留区域中添加了一些额外的信息.
 * 请注意,第一个千字节(kilobyte)是保留给引导加载程序或磁盘标签信息的……
 *
 * 在PAGE_SIZE末尾放置魔法值使得在多页面大小支持的机器上检测交换区变得有些棘手.
 * 对于2.5版本,我们可能希望将魔法值移动到引导位(bootbits)之后的位置……
 */

/* 之所以使用两个数据结构来分析该信息,一方面是出于历史原因(新的信息只会出现在旧格式不
 * 使用的区域中,即分区起始处保留的1 024字节到swap_header尾部的特征信息之间的区域),另一方
 * 面在一定程度上也是因为内核必须处理不同的页长度,如果使用不同的结构来表示,处理会比较简单.
 * 由于信息位于第一个交换槽位的开始和结束之间,其中的空间必须填充一定数量的填充数据,至少从
 * 该数据结构的角度来看,应该如此处理.但如果从页长度(在所有体系结构上都通过 PAGE_SIZE 指定)
 */
union swap_header {
	struct {
		char reserved[PAGE_SIZE - 10];
		char magic[10];			/* SWAP-SPACE or SWAPSPACE2 */
	} magic;
	struct {
		/* 前1024字节是空闲的,为启动装载程序腾出空间,因为在某些体系结构上启动装载程序必须
		 * 位于硬盘上指定的位置.这种做法,使得交换区可以位于磁盘的起始处,尽管在这样的体系
		 * 结构上,启动装载程序代码也位于该处.
		 */
		char		bootbits[1024];	/* Space for disklabel etc. */
		/* 接下来是交换区版本号(version)、最后一页的编号(last_page)和不可用页的数目(nr_badpages) */
		__u32		version;
		__u32		last_page;
		__u32		nr_badpages;
		/* label和uuid用于将一个标签和UUID(Universally Unique Identifier,全局唯一标识符)
		 * 与一个交换分区关联起来.内核并不使用这些字段,但有些用户层工具需要使用(手册页 blkid(8)提供了这些标识符背后原理相关的更多信息).
		 */
		unsigned char	sws_uuid[16];
		unsigned char	sws_volume[16];
		/* 在117个整数填充项之后,info结构的末尾是坏块块号的列表,在交换区格式发
		 * 生变化时,填充项可用于表示附加信息.
		 * 尽管在上述数据结构中坏块列表只有一项,但实际的数组项数目是nr_badpages */
		__u32		padding[117];
		__u32		badpages[1];
	} info;
};

/*
 * current->reclaim_state points to one of these when a task is running
 * memory reclaim
 * 当一个进程运行内存回收的时候,current->reclaim_state就指向这个
 */
struct reclaim_state {
	unsigned long reclaimed_slab;
};

#ifdef __KERNEL__

struct address_space;
struct sysinfo;
struct writeback_control;
struct zone;

/*
 * A swap extent maps a range of a swapfile's PAGE_SIZE pages onto a range of
 * disk blocks.  A list of swap extents maps the entire swapfile.  (Where the
 * term `swapfile' refers to either a blockdevice or an IS_REG file.  Apart
 * from setup, they're handled identically.
 *
 * We always assume that blocks are of size PAGE_SIZE.
 *
 * 交换区段(swap extent)将交换文件(swapfile)的PAGE_SIZE页范围映射到磁盘块的一个范围上.
 * 一系列交换区段映射了整个交换文件.(这里的“交换文件”指的是块设备或IS_REG文件.除了设置之外,它们的处理方式完全相同.)
 *
 * 我们始终假设块的大小为PAGE_SIZE.
 */
struct swap_extent {
	/* list 是一个链表元素,用于将区间结构置于一个标准双链表上进行管理.其他成员描述了一个连续的块组 */
	struct list_head list;
	/* 块组中第一个槽位的编号保存在 start_page 中 */
	pgoff_t start_page;
	/* nr_pages 指定了块组中可容纳页的数目 */
	pgoff_t nr_pages;
	/* start_block 是块组的第一块在硬盘上的块号 */
	sector_t start_block;
};

/*
 * Max bad pages in the new format..
 */
#define __swapoffset(x) ((unsigned long)&((union swap_header *)0)->x)
#define MAX_SWAP_BADPAGES \
	((__swapoffset(magic.magic) - __swapoffset(info.badpages)) / sizeof(int))

enum {
	SWP_USED	= (1 << 0),	/* is slot in swap_info[] used? */
	SWP_WRITEOK	= (1 << 1),	/* ok to write to this swap?	*/
	SWP_DISCARDABLE = (1 << 2),	/* blkdev support discard */
	SWP_DISCARDING	= (1 << 3),	/* now discarding a free cluster */
	SWP_SOLIDSTATE	= (1 << 4),	/* blkdev seeks are cheap */
	SWP_CONTINUED	= (1 << 5),	/* swap_map has count continuation */
	SWP_BLKDEV	= (1 << 6),	/* its a block device */
	SWP_FILE	= (1 << 7),	/* set after swap_activate success */
	SWP_AREA_DISCARD = (1 << 8),	/* single-time swap area discards */
	SWP_PAGE_DISCARD = (1 << 9),	/* freed swap page-cluster discards */
	SWP_STABLE_WRITES = (1 << 10),	/* no overwrite PG_writeback pages */
					/* add others here before... */
	SWP_SCANNING	= (1 << 11),	/* refcount in scan_swap_map */
};

#define SWAP_CLUSTER_MAX 32UL
#define COMPACT_CLUSTER_MAX SWAP_CLUSTER_MAX

#define SWAP_MAP_MAX	0x3e	/* Max duplication count, in first swap_map */
#define SWAP_MAP_BAD	0x3f	/* Note pageblock is bad, in first swap_map */
#define SWAP_HAS_CACHE	0x40	/* Flag page is cached, in first swap_map */
#define SWAP_CONT_MAX	0x7f	/* Max count, in each swap_map continuation */
#define COUNT_CONTINUED	0x80	/* See swap_map continuation for full count */
#define SWAP_MAP_SHMEM	0xbf	/* Owned by shmem/tmpfs, in first swap_map */

/*
 * We use this to track usage of a cluster. A cluster is a block of swap disk
 * space with SWAPFILE_CLUSTER pages long and naturally aligns in disk. All
 * free clusters are organized into a list. We fetch an entry from the list to
 * get a free cluster.
 *
 * The data field stores next cluster if the cluster is free or cluster usage
 * counter otherwise. The flags field determines if a cluster is free. This is
 * protected by swap_info_struct.lock.
 *
 * 我们使用这个来跟踪集群的使用情况.
 * 一个集群是具有SWAPFILE_CLUSTER页长的交换磁盘空间块,并且自然地在磁盘上对齐.
 * 所有空闲的集群都被组织成一个列表.我们从列表中获取一个条目以获得一个空闲的集群.
 *
 * data域存储下一个集群(如果该集群是空闲的)或者存储集群使用计数器(否则).标志字段确定一个集群是否空闲.这是由swap_info_struct.lock保护的.
 */
struct swap_cluster_info {
	unsigned int data:24;
	unsigned int flags:8;
};
#define CLUSTER_FLAG_FREE 1 /* This cluster is free */
#define CLUSTER_FLAG_NEXT_NULL 2 /* This cluster has no next cluster */

/*
 * We assign a cluster to each CPU, so each CPU can allocate swap entry from
 * its own cluster and swapout sequentially. The purpose is to optimize swapout
 * throughput.
 *
 * 这种方法的目的是优化交换(swap)操作的吞吐量,特别是在多CPU系统中.
 * 通过将每个CPU分配给一个独立的集群(cluster),可以使每个CPU能够从其自己的集群中分配交换条目,并按顺序进行交换出操作.
 *
 * 具体来说，这种方法的优势在于：
 *
 * 并行性增加: 每个CPU都可以独立操作其分配的集群中的交换条目,避免了不同CPU之间的竞争和等待.
 * 减少竞争: 由于每个CPU只操作自己的集群,减少了对共享资源(如交换空间)的竞争,降低了因资源争夺而导致的性能下降.
 * 顺序化提升: 按照集群的分配,可以更有效地管理交换出操作的顺序，避免了随机访问导致的延迟和效率低下.
 * 总之,这种方法通过将系统资源(如交换空间)分割和分配给各个CPU的方式,有效地提升了交换操作的整体性能和吞吐量.
 */
struct percpu_cluster {
	struct swap_cluster_info index; /* Current cluster index */
	unsigned int next; /* Likely next allocation offset */
};

struct swap_cluster_list {
	struct swap_cluster_info head;
	struct swap_cluster_info tail;
};

/*
 * The in-memory structure used to track swap areas.
 */
struct swap_info_struct {
	/* 交换区的状态可用通过flags成员中存储的各个标志描述.
	 * SWP_USED 表明当前项在交换数组中处于使用状态.否则,相应的数组项会用字节0填充,使得很容易区分使用和未使用的数组项.
	 * SWP_WRITEOK 指定当前项对应的交换区可写.
	 * 在交换区插入到内核之后,这两个标志都会设置;二者合并后的缩写是SWP_ACTIVE.
	 */
	unsigned long	flags;		/* SWP_USED etc: see above */
	/* 交换区的相对优先级保存在 prio 成员中.
	 * 因为这是一个有符号数据类型,所以正负优先级都是可能的.
	 * 交换分区的优先级越高,表明该交换分区越重要
	 */
	signed short	prio;		/* swap priority of this type */
	/* 用于挂到全局链表swap_active_head中 */
	struct plist_node list;		/* entry in swap_active_head */
	/* 用于挂到全局链表swap_avail_head中 */
	struct plist_node avail_list;	/* entry in swap_avail_head */
	/* 交换分区在数组swap_info[type]中的位置 */
	signed char	type;		/* strange name for an index */
	/* max保存了交换区当前包含的页数.
	 * 不同于 pages,该成员不仅计算可用的槽位,而且包括那些(例如,因为块设备故障)损坏或用于管理目的的槽位.
	 * 因为在当今的硬盘上,坏块是极端罕见的(也没有必要在这样的区域上创建交换分区),max 通常等于 pages 加1
	 * 对上例给出的3个交换区来说,情况就是这样二者差一个槽位有两个原因.首先,交换区的第一个
	 * 槽位由内核用作标识(毕竟,不能将交换数据写出到硬盘上完全随机的某些部分).
	 * 其次,内核还使用第一个槽位来存储状态信息,例如交换区的长度和坏扇区的列表,该信息必须持久保留.
	 */
	unsigned int	max;		/* extent of the swap_map */
	/* swap_map 是一个指针,指向一个短整型数组(不出所料,该数组在下文称为交换映射),其中
	 * 包含的项数与交换区槽位数目相同.该数组用作一个访问计数器,每个数组项都表示共享对
	 * 应换出页的进程的数目.
	 */
	unsigned char *swap_map;	/* vmalloc'ed array of usage counts */
	struct swap_cluster_info *cluster_info; /* cluster info. Only for SSD */
	struct swap_cluster_list free_clusters; /* free clusters list */
	/* 为了减少扫描整个交换区查找空闲槽位的搜索时间,内核借助lowest_bit和highest_bit成员,
	 * 来管理搜索区域的下界和上界.在 lowest_bit 之下和 highest_bit 之上,是没有空闲槽
	 * 位的,因而搜索相关区域是无意义的.
	 * 尽管这两个成员的名称以_bit结尾,但二者不是位域,只是普通整数,解释为交换区
	 * 中线性排布的各槽位的索引
	 */
	unsigned int lowest_bit;	/* index of first free in swap_map */
	unsigned int highest_bit;	/* index of last free in swap_map */
	/* pages保存了交换区中可用槽位的总数,每个槽位可容纳一个内存页面 */
	unsigned int pages;		/* total of usable pages of swap */
	unsigned int inuse_pages;	/* number of those currently in use */
	/* 内核还提供了两个成员,分别是 cluster_next 和 cluster_nr ,以实现上文简要提到的聚集技
	 * 术.前者指定了在交换区中接下来使用的槽位(在某个现存聚集中)的索引,而cluster_nr
	 * 表示当前聚集中仍然可用的槽位数,在消耗了这些空闲槽位之后,则必须建立一个新的聚集,
	 * 否则(如果没有足够空闲槽位可用于建立新的聚集)就只能进行细粒度分配了(即不再按聚
	 * 集分配槽位).
	 */
	unsigned int cluster_next;	/* likely index for next allocation */
	unsigned int cluster_nr;	/* countdown to next cluster search */
	struct percpu_cluster __percpu *percpu_cluster; /* per cpu's swap location */
	/* 内核使用curr_swap_extent 成员来实现区间(extent),用于创建假定连续的交
	 * 换区槽位与交换文件的磁盘块之间的映射. 如果使用分区作为交换区,这是不必要的,因为内核可以
	 * 依赖于一个事实,即分区中的块在磁盘上是线性排列的.因而槽位与磁盘块之间的映射会非常简单.
	 * 从第一个磁盘块开始,加上所需的页数乘以一个常量得到的偏移量,即可获得所需地址.
	 *
	 * 在使用文件作为交换区时,情况会更复杂,因为无法保证文件的所有块在磁盘上是连续的.
	 * 因而,在槽位与磁盘块之间的映射更为复杂.
	 * 文件由多个部分组成,这些部分可能位于块设备的任意位置.(磁盘碎片的程度越轻,文件分成
	 * 的部分就越少。毕竟,如果文件的各部分数据尽可能接近,才是最好的
	 *
	 * curr_swap_extent将文件散布在块设备上各处的块,与线性排布的槽位关联起来.这样做
	 * 时,应该确保两个要点:使用的内存空间尽可能少,将消耗的搜索时间保持在最低限度.
	 * 没有必要将每个槽位都关联到块号.将一个连续块组的第一个块与对应槽位关联并标明块组中的
	 * 块数,就可以非常紧凑地将文件的结构刻画出来
	 *
	 * swap_info_struct 中一个额外的成员 curr_swap_extent 用于保存一个指针,指向区间链表中上一次访问的 swap_extent 实例.
	 * 每次新的搜索都从该实例开始.因为通常是对连续的槽位进行访问,所搜索的块通常会位于该区间或下一个区间.
	 * 如果内核的搜索不能立即成功,则必须逐元素扫描整个区间链表,直至所需块所在区间被找到
	 */
	/* 指向最近使用的子区描述符 */
	struct swap_extent *curr_swap_extent;
	/* 第一个交换子区. */
	struct swap_extent first_swap_extent;
	/* bdev 指向文件/分区所在底层块设备的 block_device 结构.
	 * 虽然在我们的例子中,所有交换区都位于同一块设备上( /dev/hda ),但3个数组
	 * 项中的bdev却指向该数据结构的不同实例.
	 * 这是因为两个文件是在硬盘的不同分区上,而交换分区本身是一个独立的分区.
	 * 因为从结构上来看,内核像独立块设备一样来管理分区,这导致尽管3个交换区都位于同一磁盘,但三者的 bdev 指针却指向3个不同的实例.
	 */
	struct block_device *bdev;	/* swap device or bdev of swap file */
	/* swap_file 指向与该交换区关联的file结构.
	 * 对于交换分区,这是一个指向块设备上分区的设备文件的指针(在我们的例子中, /dev/hda5的情形即如此).
	 * 对于交换文件,该指针指向相关文件的 file 实例,即例子中 /mnt/swap1 或/tmp/swap2 的情形.
	 */
	struct file *swap_file;		/* seldom referenced */
	unsigned int old_block_size;	/* seldom referenced */
#ifdef CONFIG_FRONTSWAP
	unsigned long *frontswap_map;	/* frontswap in-use, one bit per page */
	atomic_t frontswap_pages;	/* frontswap pages in-use counter */
#endif
	spinlock_t lock;		/*
					 * protect map scan related fields like
					 * swap_map, lowest_bit, highest_bit,
					 * inuse_pages, cluster_next,
					 * cluster_nr, lowest_alloc,
					 * highest_alloc, free/discard cluster
					 * list. other fields are only changed
					 * at swapon/swapoff, so are protected
					 * by swap_lock. changing flags need
					 * hold this lock and swap_lock. If
					 * both locks need hold, hold swap_lock
					 * first.
					 */
	struct work_struct discard_work; /* discard worker */
	struct swap_cluster_list discard_clusters; /* discard clusters list */
};

/* linux/mm/workingset.c */
void *workingset_eviction(struct address_space *mapping, struct page *page);
bool workingset_refault(void *shadow);
void workingset_activation(struct page *page);
extern struct list_lru workingset_shadow_nodes;

static inline unsigned int workingset_node_pages(struct radix_tree_node *node)
{
	return node->count & RADIX_TREE_COUNT_MASK;
}

static inline void workingset_node_pages_inc(struct radix_tree_node *node)
{
	node->count++;
}

static inline void workingset_node_pages_dec(struct radix_tree_node *node)
{
	VM_WARN_ON_ONCE(!workingset_node_pages(node));
	node->count--;
}

static inline unsigned int workingset_node_shadows(struct radix_tree_node *node)
{
	return node->count >> RADIX_TREE_COUNT_SHIFT;
}

static inline void workingset_node_shadows_inc(struct radix_tree_node *node)
{
	node->count += 1U << RADIX_TREE_COUNT_SHIFT;
}

static inline void workingset_node_shadows_dec(struct radix_tree_node *node)
{
	VM_WARN_ON_ONCE(!workingset_node_shadows(node));
	node->count -= 1U << RADIX_TREE_COUNT_SHIFT;
}

/* linux/mm/page_alloc.c */
extern unsigned long totalram_pages;
extern unsigned long totalreserve_pages;
extern unsigned long nr_free_buffer_pages(void);
extern unsigned long nr_free_pagecache_pages(void);

/* Definition of global_page_state not available yet */
#define nr_free_pages() global_page_state(NR_FREE_PAGES)


/* linux/mm/swap.c */
extern void lru_cache_add(struct page *);
extern void lru_cache_add_anon(struct page *page);
extern void lru_cache_add_file(struct page *page);
extern void lru_add_page_tail(struct page *page, struct page *page_tail,
			 struct lruvec *lruvec, struct list_head *head);
extern void activate_page(struct page *);
extern void mark_page_accessed(struct page *);
extern void lru_add_drain(void);
extern void lru_add_drain_cpu(int cpu);
extern void lru_add_drain_all(void);
extern void rotate_reclaimable_page(struct page *page);
extern void deactivate_file_page(struct page *page);
extern void deactivate_page(struct page *page);
extern void swap_setup(void);

extern void add_page_to_unevictable_list(struct page *page);

extern void lru_cache_add_active_or_unevictable(struct page *page,
						struct vm_area_struct *vma);

/* linux/mm/vmscan.c */
extern unsigned long zone_reclaimable_pages(struct zone *zone);
extern unsigned long pgdat_reclaimable_pages(struct pglist_data *pgdat);
extern unsigned long try_to_free_pages(struct zonelist *zonelist, int order,
					gfp_t gfp_mask, nodemask_t *mask);
extern int __isolate_lru_page(struct page *page, isolate_mode_t mode);
extern unsigned long try_to_free_mem_cgroup_pages(struct mem_cgroup *memcg,
						  unsigned long nr_pages,
						  gfp_t gfp_mask,
						  bool may_swap);
extern unsigned long mem_cgroup_shrink_node(struct mem_cgroup *mem,
						gfp_t gfp_mask, bool noswap,
						pg_data_t *pgdat,
						unsigned long *nr_scanned);
extern unsigned long shrink_all_memory(unsigned long nr_pages);
extern int vm_swappiness;
extern int remove_mapping(struct address_space *mapping, struct page *page);
extern unsigned long vm_total_pages;

#ifdef CONFIG_NUMA
extern int node_reclaim_mode;
extern int sysctl_min_unmapped_ratio;
extern int sysctl_min_slab_ratio;
extern int node_reclaim(struct pglist_data *, gfp_t, unsigned int);
#else
#define node_reclaim_mode 0
static inline int node_reclaim(struct pglist_data *pgdat, gfp_t mask,
				unsigned int order)
{
	return 0;
}
#endif

extern int page_evictable(struct page *page);
extern void check_move_unevictable_pages(struct page **, int nr_pages);

extern int kswapd_run(int nid);
extern void kswapd_stop(int nid);

#ifdef CONFIG_SWAP
/* linux/mm/page_io.c */
extern int swap_readpage(struct page *);
extern int swap_writepage(struct page *page, struct writeback_control *wbc);
extern void end_swap_bio_write(struct bio *bio);
extern int __swap_writepage(struct page *page, struct writeback_control *wbc,
	bio_end_io_t end_write_func);
extern int swap_set_page_dirty(struct page *page);

int add_swap_extent(struct swap_info_struct *sis, unsigned long start_page,
		unsigned long nr_pages, sector_t start_block);
int generic_swapfile_activate(struct swap_info_struct *, struct file *,
		sector_t *);

/* linux/mm/swap_state.c */
extern struct address_space swapper_spaces[];
#define swap_address_space(entry) (&swapper_spaces[swp_type(entry)])
extern unsigned long total_swapcache_pages(void);
extern void show_swap_cache_info(void);
extern int add_to_swap(struct page *, struct list_head *list);
extern int add_to_swap_cache(struct page *, swp_entry_t, gfp_t);
extern int __add_to_swap_cache(struct page *page, swp_entry_t entry);
extern void __delete_from_swap_cache(struct page *);
extern void delete_from_swap_cache(struct page *);
extern void free_page_and_swap_cache(struct page *);
extern void free_pages_and_swap_cache(struct page **, int);
extern struct page *lookup_swap_cache(swp_entry_t);
extern struct page *read_swap_cache_async(swp_entry_t, gfp_t,
			struct vm_area_struct *vma, unsigned long addr);
extern struct page *__read_swap_cache_async(swp_entry_t, gfp_t,
			struct vm_area_struct *vma, unsigned long addr,
			bool *new_page_allocated);
extern struct page *swapin_readahead(swp_entry_t, gfp_t,
			struct vm_area_struct *vma, unsigned long addr);

/* linux/mm/swapfile.c */
extern atomic_long_t nr_swap_pages;
extern long total_swap_pages;

/* Swap 50% full? Release swapcache more aggressively.. */
static inline bool vm_swap_full(void)
{
	return atomic_long_read(&nr_swap_pages) * 2 < total_swap_pages;
}

static inline long get_nr_swap_pages(void)
{
	return atomic_long_read(&nr_swap_pages);
}

extern void si_swapinfo(struct sysinfo *);
extern swp_entry_t get_swap_page(void);
extern swp_entry_t get_swap_page_of_type(int);
extern int add_swap_count_continuation(swp_entry_t, gfp_t);
extern void swap_shmem_alloc(swp_entry_t);
extern int swap_duplicate(swp_entry_t);
extern int swapcache_prepare(swp_entry_t);
extern void swap_free(swp_entry_t);
extern void swapcache_free(swp_entry_t);
extern int free_swap_and_cache(swp_entry_t);
extern int swap_type_of(dev_t, sector_t, struct block_device **);
extern unsigned int count_swap_pages(int, int);
extern sector_t map_swap_page(struct page *, struct block_device **);
extern sector_t swapdev_block(int, pgoff_t);
extern int page_swapcount(struct page *);
extern int swp_swapcount(swp_entry_t entry);
extern struct swap_info_struct *page_swap_info(struct page *);
extern bool reuse_swap_page(struct page *, int *);
extern int try_to_free_swap(struct page *);
struct backing_dev_info;

#else /* CONFIG_SWAP */

#define swap_address_space(entry)		(NULL)
#define get_nr_swap_pages()			0L
#define total_swap_pages			0L
#define total_swapcache_pages()			0UL
#define vm_swap_full()				0

#define si_swapinfo(val) \
	do { (val)->freeswap = (val)->totalswap = 0; } while (0)
/* only sparc can not include linux/pagemap.h in this file
 * so leave put_page and release_pages undeclared... */
#define free_page_and_swap_cache(page) \
	put_page(page)
#define free_pages_and_swap_cache(pages, nr) \
	release_pages((pages), (nr), false);

static inline void show_swap_cache_info(void)
{
}

#define free_swap_and_cache(swp)	is_migration_entry(swp)
#define swapcache_prepare(swp)		is_migration_entry(swp)

static inline int add_swap_count_continuation(swp_entry_t swp, gfp_t gfp_mask)
{
	return 0;
}

static inline void swap_shmem_alloc(swp_entry_t swp)
{
}

static inline int swap_duplicate(swp_entry_t swp)
{
	return 0;
}

static inline void swap_free(swp_entry_t swp)
{
}

static inline void swapcache_free(swp_entry_t swp)
{
}

static inline struct page *swapin_readahead(swp_entry_t swp, gfp_t gfp_mask,
			struct vm_area_struct *vma, unsigned long addr)
{
	return NULL;
}

static inline int swap_writepage(struct page *p, struct writeback_control *wbc)
{
	return 0;
}

static inline struct page *lookup_swap_cache(swp_entry_t swp)
{
	return NULL;
}

static inline int add_to_swap(struct page *page, struct list_head *list)
{
	return 0;
}

static inline int add_to_swap_cache(struct page *page, swp_entry_t entry,
							gfp_t gfp_mask)
{
	return -1;
}

static inline void __delete_from_swap_cache(struct page *page)
{
}

static inline void delete_from_swap_cache(struct page *page)
{
}

static inline int page_swapcount(struct page *page)
{
	return 0;
}

static inline int swp_swapcount(swp_entry_t entry)
{
	return 0;
}

#define reuse_swap_page(page, total_mapcount) \
	(page_trans_huge_mapcount(page, total_mapcount) == 1)

static inline int try_to_free_swap(struct page *page)
{
	return 0;
}

static inline swp_entry_t get_swap_page(void)
{
	swp_entry_t entry;
	entry.val = 0;
	return entry;
}

#endif /* CONFIG_SWAP */

#ifdef CONFIG_MEMCG
static inline int mem_cgroup_swappiness(struct mem_cgroup *memcg)
{
	/* Cgroup2 doesn't have per-cgroup swappiness */
	if (cgroup_subsys_on_dfl(memory_cgrp_subsys))
		return vm_swappiness;

	/* root ? */
	if (mem_cgroup_disabled() || !memcg->css.parent)
		return vm_swappiness;

	return memcg->swappiness;
}

#else
static inline int mem_cgroup_swappiness(struct mem_cgroup *mem)
{
	return vm_swappiness;
}
#endif

#ifdef CONFIG_MEMCG_SWAP
extern void mem_cgroup_swapout(struct page *page, swp_entry_t entry);
extern int mem_cgroup_try_charge_swap(struct page *page, swp_entry_t entry);
extern void mem_cgroup_uncharge_swap(swp_entry_t entry);
extern long mem_cgroup_get_nr_swap_pages(struct mem_cgroup *memcg);
extern bool mem_cgroup_swap_full(struct page *page);
#else
static inline void mem_cgroup_swapout(struct page *page, swp_entry_t entry)
{
}

static inline int mem_cgroup_try_charge_swap(struct page *page,
					     swp_entry_t entry)
{
	return 0;
}

static inline void mem_cgroup_uncharge_swap(swp_entry_t entry)
{
}

static inline long mem_cgroup_get_nr_swap_pages(struct mem_cgroup *memcg)
{
	return get_nr_swap_pages();
}

static inline bool mem_cgroup_swap_full(struct page *page)
{
	return vm_swap_full();
}
#endif

#endif /* __KERNEL__*/
#endif /* _LINUX_SWAP_H */
