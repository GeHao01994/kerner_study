/*
 *  linux/mm/swapfile.c
 *
 *  Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 *  Swap reorganised 29.12.95, Stephen Tweedie
 */

#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/kernel_stat.h>
#include <linux/swap.h>
#include <linux/vmalloc.h>
#include <linux/pagemap.h>
#include <linux/namei.h>
#include <linux/shmem_fs.h>
#include <linux/blkdev.h>
#include <linux/random.h>
#include <linux/writeback.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/init.h>
#include <linux/ksm.h>
#include <linux/rmap.h>
#include <linux/security.h>
#include <linux/backing-dev.h>
#include <linux/mutex.h>
#include <linux/capability.h>
#include <linux/syscalls.h>
#include <linux/memcontrol.h>
#include <linux/poll.h>
#include <linux/oom.h>
#include <linux/frontswap.h>
#include <linux/swapfile.h>
#include <linux/export.h>

#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include <linux/swapops.h>
#include <linux/swap_cgroup.h>

static bool swap_count_continued(struct swap_info_struct *, pgoff_t,
				 unsigned char);
static void free_swap_count_continuations(struct swap_info_struct *);
static sector_t map_swap_entry(swp_entry_t, struct block_device**);

DEFINE_SPINLOCK(swap_lock);
static unsigned int nr_swapfiles;
atomic_long_t nr_swap_pages;
/*
 * Some modules use swappable objects and may try to swap them out under
 * memory pressure (via the shrinker). Before doing so, they may wish to
 * check to see if any swap space is available.
 */
EXPORT_SYMBOL_GPL(nr_swap_pages);
/* protected with swap_lock. reading in vm_swap_full() doesn't need lock */
long total_swap_pages;
static int least_priority;

static const char Bad_file[] = "Bad swap file entry ";
static const char Unused_file[] = "Unused swap file entry ";
static const char Bad_offset[] = "Bad swap offset entry ";
static const char Unused_offset[] = "Unused swap offset entry ";

/*
 * all active swap_info_structs
 * protected with swap_lock, and ordered by priority.
 *
 * 所有活跃的swap_info_structs
 * 受swap_lock保护,并按优先级排序
 */
PLIST_HEAD(swap_active_head);

/*
 * all available (active, not full) swap_info_structs
 * protected with swap_avail_lock, ordered by priority.
 * This is used by get_swap_page() instead of swap_active_head
 * because swap_active_head includes all swap_info_structs,
 * but get_swap_page() doesn't need to look at full ones.
 * This uses its own lock instead of swap_lock because when a
 * swap_info_struct changes between not-full/full, it needs to
 * add/remove itself to/from this list, but the swap_info_struct->lock
 * is held and the locking order requires swap_lock to be taken
 * before any swap_info_struct->lock.
 *
 * 所有可用的(活跃的、未满的)swap_info_structs都受到swap_avail_lock锁的保护,
 * 并且它们根据优先级进行排序.
 * get_swap_page()函数使用这个排序的列表而不是swap_active_head,
 * 因为swap_active_head包含了所有的swap_info_structs,但get_swap_page()函数不需要查看那些已经满的交换空间信息.
 *
 * 此列表使用它自己的锁(swap_avail_lock)而不是swap_lock,原因在于当某个swap_info_struct的状态从非满变为满,或者从满变为非满时,它需要从这个列表中添加或移除自己.
 * 然而,在这个过程中,swap_info_struct的锁(swap_info_struct->lock)会被持有,且根据锁的顺序要求,
 * 必须先获取swap_lock才能获取任何swap_info_struct->lock.
 * 因此,为了保持锁的顺序并避免死锁,这个特定的列表操作使用了不同的锁(swap_avail_lock).
 */
static PLIST_HEAD(swap_avail_head);
static DEFINE_SPINLOCK(swap_avail_lock);

struct swap_info_struct *swap_info[MAX_SWAPFILES];

static DEFINE_MUTEX(swapon_mutex);

static DECLARE_WAIT_QUEUE_HEAD(proc_poll_wait);
/* Activity counter to indicate that a swapon or swapoff has occurred */
static atomic_t proc_poll_event = ATOMIC_INIT(0);

static inline unsigned char swap_count(unsigned char ent)
{
	return ent & ~SWAP_HAS_CACHE;	/* may include SWAP_HAS_CONT flag */
}

/* returns 1 if swap entry is freed */
/* 这个应该是回收这个swap cache */
static int
__try_to_reclaim_swap(struct swap_info_struct *si, unsigned long offset)
{
	/* 找到这个swp_entry_t */
	swp_entry_t entry = swp_entry(si->type, offset);
	struct page *page;
	int ret = 0;
	/* 通过entry找到对应的swap cache */
	page = find_get_page(swap_address_space(entry), swp_offset(entry));
	if (!page)
		return 0;
	/*
	 * This function is called from scan_swap_map() and it's called
	 * by vmscan.c at reclaiming pages. So, we hold a lock on a page, here.
	 * We have to use trylock for avoiding deadlock. This is a special
	 * case and you should use try_to_free_swap() with explicit lock_page()
	 * in usual operations.
	 *
	 * 这个函数是从scan_swap_map()中被调用的,并且在vmscan.c中用于回收页面时也会被调用.
	 * 因此,在这里我们需要对页面加锁.为了避免死锁,我们必须使用尝试锁(trylock).
	 * 这是一个特殊情况,在常规操作中,你应该结合显式的lock_page()调用try_to_free_swap()函数.
	 */
	if (trylock_page(page)) {
		ret = try_to_free_swap(page);
		unlock_page(page);
	}
	put_page(page);
	return ret;
}

/*
 * swapon tell device that all the old swap contents can be discarded,
 * to allow the swap device to optimize its wear-levelling.
 */
static int discard_swap(struct swap_info_struct *si)
{
	struct swap_extent *se;
	sector_t start_block;
	sector_t nr_blocks;
	int err = 0;

	/* Do not discard the swap header page! */
	se = &si->first_swap_extent;
	start_block = (se->start_block + 1) << (PAGE_SHIFT - 9);
	nr_blocks = ((sector_t)se->nr_pages - 1) << (PAGE_SHIFT - 9);
	if (nr_blocks) {
		err = blkdev_issue_discard(si->bdev, start_block,
				nr_blocks, GFP_KERNEL, 0);
		if (err)
			return err;
		cond_resched();
	}

	list_for_each_entry(se, &si->first_swap_extent.list, list) {
		start_block = se->start_block << (PAGE_SHIFT - 9);
		nr_blocks = (sector_t)se->nr_pages << (PAGE_SHIFT - 9);

		err = blkdev_issue_discard(si->bdev, start_block,
				nr_blocks, GFP_KERNEL, 0);
		if (err)
			break;

		cond_resched();
	}
	return err;		/* That will often be -EOPNOTSUPP */
}

/*
 * swap allocation tell device that a cluster of swap can now be discarded,
 * to allow the swap device to optimize its wear-levelling.
 */
static void discard_swap_cluster(struct swap_info_struct *si,
				 pgoff_t start_page, pgoff_t nr_pages)
{
	struct swap_extent *se = si->curr_swap_extent;
	int found_extent = 0;

	while (nr_pages) {
		if (se->start_page <= start_page &&
		    start_page < se->start_page + se->nr_pages) {
			pgoff_t offset = start_page - se->start_page;
			sector_t start_block = se->start_block + offset;
			sector_t nr_blocks = se->nr_pages - offset;

			if (nr_blocks > nr_pages)
				nr_blocks = nr_pages;
			start_page += nr_blocks;
			nr_pages -= nr_blocks;

			if (!found_extent++)
				si->curr_swap_extent = se;

			start_block <<= PAGE_SHIFT - 9;
			nr_blocks <<= PAGE_SHIFT - 9;
			if (blkdev_issue_discard(si->bdev, start_block,
				    nr_blocks, GFP_NOIO, 0))
				break;
		}

		se = list_next_entry(se, list);
	}
}

#define SWAPFILE_CLUSTER	256
#define LATENCY_LIMIT		256

static inline void cluster_set_flag(struct swap_cluster_info *info,
	unsigned int flag)
{
	info->flags = flag;
}

static inline unsigned int cluster_count(struct swap_cluster_info *info)
{
	return info->data;
}

static inline void cluster_set_count(struct swap_cluster_info *info,
				     unsigned int c)
{
	info->data = c;
}

static inline void cluster_set_count_flag(struct swap_cluster_info *info,
					 unsigned int c, unsigned int f)
{
	info->flags = f;
	info->data = c;
}

static inline unsigned int cluster_next(struct swap_cluster_info *info)
{
	return info->data;
}

static inline void cluster_set_next(struct swap_cluster_info *info,
				    unsigned int n)
{
	info->data = n;
}

static inline void cluster_set_next_flag(struct swap_cluster_info *info,
					 unsigned int n, unsigned int f)
{
	info->flags = f;
	info->data = n;
}

static inline bool cluster_is_free(struct swap_cluster_info *info)
{
	return info->flags & CLUSTER_FLAG_FREE;
}

static inline bool cluster_is_null(struct swap_cluster_info *info)
{
	return info->flags & CLUSTER_FLAG_NEXT_NULL;
}

static inline void cluster_set_null(struct swap_cluster_info *info)
{
	info->flags = CLUSTER_FLAG_NEXT_NULL;
	info->data = 0;
}

static inline bool cluster_list_empty(struct swap_cluster_list *list)
{
	return cluster_is_null(&list->head);
}

static inline unsigned int cluster_list_first(struct swap_cluster_list *list)
{
	return cluster_next(&list->head);
}

static void cluster_list_init(struct swap_cluster_list *list)
{
	cluster_set_null(&list->head);
	cluster_set_null(&list->tail);
}

static void cluster_list_add_tail(struct swap_cluster_list *list,
				  struct swap_cluster_info *ci,
				  unsigned int idx)
{
	if (cluster_list_empty(list)) {
		cluster_set_next_flag(&list->head, idx, 0);
		cluster_set_next_flag(&list->tail, idx, 0);
	} else {
		unsigned int tail = cluster_next(&list->tail);

		cluster_set_next(&ci[tail], idx);
		cluster_set_next_flag(&list->tail, idx, 0);
	}
}

static unsigned int cluster_list_del_first(struct swap_cluster_list *list,
					   struct swap_cluster_info *ci)
{
	unsigned int idx;

	idx = cluster_next(&list->head);
	if (cluster_next(&list->tail) == idx) {
		cluster_set_null(&list->head);
		cluster_set_null(&list->tail);
	} else
		cluster_set_next_flag(&list->head,
				      cluster_next(&ci[idx]), 0);

	return idx;
}

/* Add a cluster to discard list and schedule it to do discard */
static void swap_cluster_schedule_discard(struct swap_info_struct *si,
		unsigned int idx)
{
	/*
	 * If scan_swap_map() can't find a free cluster, it will check
	 * si->swap_map directly. To make sure the discarding cluster isn't
	 * taken by scan_swap_map(), mark the swap entries bad (occupied). It
	 * will be cleared after discard
	 */
	memset(si->swap_map + idx * SWAPFILE_CLUSTER,
			SWAP_MAP_BAD, SWAPFILE_CLUSTER);

	cluster_list_add_tail(&si->discard_clusters, si->cluster_info, idx);

	schedule_work(&si->discard_work);
}

/*
 * Doing discard actually. After a cluster discard is finished, the cluster
 * will be added to free cluster list. caller should hold si->lock.
*/
static void swap_do_scheduled_discard(struct swap_info_struct *si)
{
	struct swap_cluster_info *info;
	unsigned int idx;

	info = si->cluster_info;

	while (!cluster_list_empty(&si->discard_clusters)) {
		idx = cluster_list_del_first(&si->discard_clusters, info);
		spin_unlock(&si->lock);

		discard_swap_cluster(si, idx * SWAPFILE_CLUSTER,
				SWAPFILE_CLUSTER);

		spin_lock(&si->lock);
		cluster_set_flag(&info[idx], CLUSTER_FLAG_FREE);
		cluster_list_add_tail(&si->free_clusters, info, idx);
		memset(si->swap_map + idx * SWAPFILE_CLUSTER,
				0, SWAPFILE_CLUSTER);
	}
}

static void swap_discard_work(struct work_struct *work)
{
	struct swap_info_struct *si;

	si = container_of(work, struct swap_info_struct, discard_work);

	spin_lock(&si->lock);
	swap_do_scheduled_discard(si);
	spin_unlock(&si->lock);
}

/*
 * The cluster corresponding to page_nr will be used. The cluster will be
 * removed from free cluster list and its usage counter will be increased.
 *
 * 将使用与page_nr对应的集群.
 * 该群集将从空闲群集列表中删除,其使用计数器将增加。
 */
static void inc_cluster_info_page(struct swap_info_struct *p,
	struct swap_cluster_info *cluster_info, unsigned long page_nr)
{
	/* 拿到该page_nr集群的index */
	unsigned long idx = page_nr / SWAPFILE_CLUSTER;

	/* 如果cluster_info == NULL,那么直接返回 */
	if (!cluster_info)
		return;
	/* 如果该info->flags & CLUSTER_FLAG_FREE;是free的 */
	if (cluster_is_free(&cluster_info[idx])) {
		/* 如果p->free_cluster的第一个cluster_idx != 我们现在的这个idx,那么报个VM_BUG */
		VM_BUG_ON(cluster_list_first(&p->free_clusters) != idx);
		/* 那么把头从free_clusters里面拔掉 */
		cluster_list_del_first(&p->free_clusters, cluster_info);
		/* 设置当前的cluster_info的值全为0 */
		cluster_set_count_flag(&cluster_info[idx], 0, 0);
	}
	/* 这个就是看该cluster的用量是不是大于SWAPFILE_CLUSTER,如果大于了那么就报个BUG吧 */
	VM_BUG_ON(cluster_count(&cluster_info[idx]) >= SWAPFILE_CLUSTER);
	/* 否则就在原有的count上 + 1 */
	cluster_set_count(&cluster_info[idx],
		cluster_count(&cluster_info[idx]) + 1);
}

/*
 * The cluster corresponding to page_nr decreases one usage. If the usage
 * counter becomes 0, which means no page in the cluster is in using, we can
 * optionally discard the cluster and add it to free cluster list.
 */
static void dec_cluster_info_page(struct swap_info_struct *p,
	struct swap_cluster_info *cluster_info, unsigned long page_nr)
{
	unsigned long idx = page_nr / SWAPFILE_CLUSTER;

	if (!cluster_info)
		return;

	VM_BUG_ON(cluster_count(&cluster_info[idx]) == 0);
	cluster_set_count(&cluster_info[idx],
		cluster_count(&cluster_info[idx]) - 1);

	if (cluster_count(&cluster_info[idx]) == 0) {
		/*
		 * If the swap is discardable, prepare discard the cluster
		 * instead of free it immediately. The cluster will be freed
		 * after discard.
		 */
		if ((p->flags & (SWP_WRITEOK | SWP_PAGE_DISCARD)) ==
				 (SWP_WRITEOK | SWP_PAGE_DISCARD)) {
			swap_cluster_schedule_discard(p, idx);
			return;
		}

		cluster_set_flag(&cluster_info[idx], CLUSTER_FLAG_FREE);
		cluster_list_add_tail(&p->free_clusters, cluster_info, idx);
	}
}

/*
 * It's possible scan_swap_map() uses a free cluster in the middle of free
 * cluster list. Avoiding such abuse to avoid list corruption.
 */
static bool
scan_swap_map_ssd_cluster_conflict(struct swap_info_struct *si,
	unsigned long offset)
{
	struct percpu_cluster *percpu_cluster;
	bool conflict;

	offset /= SWAPFILE_CLUSTER;
	conflict = !cluster_list_empty(&si->free_clusters) &&
		offset != cluster_list_first(&si->free_clusters) &&
		cluster_is_free(&si->cluster_info[offset]);

	if (!conflict)
		return false;

	percpu_cluster = this_cpu_ptr(si->percpu_cluster);
	cluster_set_null(&percpu_cluster->index);
	return true;
}

/*
 * Try to get a swap entry from current cpu's swap entry pool (a cluster). This
 * might involve allocating a new cluster for current CPU too.
 */
static void scan_swap_map_try_ssd_cluster(struct swap_info_struct *si,
	unsigned long *offset, unsigned long *scan_base)
{
	struct percpu_cluster *cluster;
	bool found_free;
	unsigned long tmp;

new_cluster:
	cluster = this_cpu_ptr(si->percpu_cluster);
	if (cluster_is_null(&cluster->index)) {
		if (!cluster_list_empty(&si->free_clusters)) {
			cluster->index = si->free_clusters.head;
			cluster->next = cluster_next(&cluster->index) *
					SWAPFILE_CLUSTER;
		} else if (!cluster_list_empty(&si->discard_clusters)) {
			/*
			 * we don't have free cluster but have some clusters in
			 * discarding, do discard now and reclaim them
			 */
			swap_do_scheduled_discard(si);
			*scan_base = *offset = si->cluster_next;
			goto new_cluster;
		} else
			return;
	}

	found_free = false;

	/*
	 * Other CPUs can use our cluster if they can't find a free cluster,
	 * check if there is still free entry in the cluster
	 */
	tmp = cluster->next;
	while (tmp < si->max && tmp < (cluster_next(&cluster->index) + 1) *
	       SWAPFILE_CLUSTER) {
		if (!si->swap_map[tmp]) {
			found_free = true;
			break;
		}
		tmp++;
	}
	if (!found_free) {
		cluster_set_null(&cluster->index);
		goto new_cluster;
	}
	cluster->next = tmp + 1;
	*offset = tmp;
	*scan_base = tmp;
}

static unsigned long scan_swap_map(struct swap_info_struct *si,
				   unsigned char usage)
{
	unsigned long offset;
	unsigned long scan_base;
	unsigned long last_in_cluster = 0;
	int latency_ration = LATENCY_LIMIT;

	/*
	 * We try to cluster swap pages by allocating them sequentially
	 * in swap.  Once we've allocated SWAPFILE_CLUSTER pages this
	 * way, however, we resort to first-free allocation, starting
	 * a new cluster.  This prevents us from scattering swap pages
	 * all over the entire swap partition, so that we reduce
	 * overall disk seek times between swap pages.  -- sct
	 * But we do now try to find an empty cluster.  -Andrea
	 * And we let swap pages go all over an SSD partition.  Hugh
	 *
	 * 我们尝试通过在swap中顺序分配swap页面来将它们聚集在一起.
	 * 然而,一旦我们以这种方式分配了SWAPFILE_CLUSTER数量的页面后,我们就会转而采用“首次空闲分配”策略,开始一个新的聚集区.
	 * 这样做可以防止swap页面分散在整个swap分区中,从而减少swap页面之间的总体磁盘寻道时间. ——sct
	 * 但我们现在也尝试找到一个空的聚集区. ——Andrea
	 * 并且我们允许swap页面遍布SSD分区的各个位置. ——Hugh
	 *
	 * 这里的“聚集区”可以理解为在swap分区中连续分配的一系列swap页面,它们物理上相邻,可以减少磁盘的寻道次数,提高swap操作的效率.
	 * SWAPFILE_CLUSTER是一个定义好的页面数量,当达到这个数量后,系统会开始一个新的聚集区进行swap页面的分配.
	 *
	 * Andrea提到的“找到一个空的聚集区”可能是指系统尝试在分配新的swap页面时,优先检查是否有足够的连续空闲空间来形成一个新的聚集区,而不是简单地采用“首次空闲”策略.
	 *
	 * Hugh的评论则指出,在SSD分区上,由于SSD的随机读写性能远高于传统硬盘,因此允许swap页面遍布整个分区可能不会对性能造成太大影响.
	 * 然而,即使在SSD上,通过聚集swap页面来减少寻道次数(虽然SSD的寻道时间非常短)仍然是一个可以考虑的优化策略,特别是在高负载或需要频繁进行swap操作的情况下.
	 */

	/* SWP_SCANNING	= (1 << 11), refcount in scan_swap_map */
	/* 这里表示的是说引用计数 + 1 */
	si->flags += SWP_SCANNING;
	/* 这里就是拿到下一个cluster,基于这个我们去寻找 */
	scan_base = offset = si->cluster_next;

	/* SSD algorithm */
	if (si->cluster_info) {
		scan_swap_map_try_ssd_cluster(si, &offset, &scan_base);
		goto checks;
	}

	/* 这里是先判断si->cluster_nr是否等于0,在判断--
	 * 这里就是想分配一个聚集(cluster)
	 */
	if (unlikely(!si->cluster_nr--)) {
		/* 如果si->pages - si->inuser_pages(在使用的page) < SWAPFILE_CLUSTER
		 * 如果交换分区中剩余的槽位不足以分配一个聚集,就跳过直接扫描剩余的槽位
		 */
		if (si->pages - si->inuse_pages < SWAPFILE_CLUSTER) {
			/* 设置cluster_nr = SWAPFILE_CLUSTER - 1 */
			si->cluster_nr = SWAPFILE_CLUSTER - 1;
			goto checks;
		}

		spin_unlock(&si->lock);

		/*
		 * If seek is expensive, start searching for new cluster from
		 * start of partition, to minimize the span of allocated swap.
		 * If seek is cheap, that is the SWP_SOLIDSTATE si->cluster_info
		 * case, just handled by scan_swap_map_try_ssd_cluster() above.
		 *
		 * 如果查找成本很高,请从分区开始搜索新集群,以尽量减少分配的交换范围.
		 * 如果seek很便宜,那就是SWP_SOLIDSTATE si->cluster_info的情况,刚刚由上面的scan_swap_map_try_ssd_cluster()处理.
		 */
		/* lowest_bit指向第一个空闲的槽位 */
		scan_base = offset = si->lowest_bit;
		last_in_cluster = offset + SWAPFILE_CLUSTER - 1;

		/* Locate the first empty (unaligned) cluster */
		/* highest_bit保存的是最后一个槽位,下面循环尝试找到SWAPFILE_CLUSTER个连续槽位 */
		for (; last_in_cluster <= si->highest_bit; offset++) {
			if (si->swap_map[offset])	/* 不为0表示已经被占用,last_in_cluster后移 */
				last_in_cluster = offset + SWAPFILE_CLUSTER;
			else if (offset == last_in_cluster) {	/* 相等表示找到SWAPFILE_CLUSTER个连续槽位 */
				spin_lock(&si->lock);
				offset -= SWAPFILE_CLUSTER - 1;
				/* 设置聚集中第一个空闲槽位 */
				si->cluster_next = offset;
				/* cluster_nr表示当前聚集中仍然可用的槽位数,在消耗了这些空闲槽位之后,则必须建立一个新的聚集,
				 * 否则(如果没有足够空闲槽位可用于建立新的聚集)就只能进行细粒度分配了(即不再按聚
				 * 集分配槽位).
				 */
				si->cluster_nr = SWAPFILE_CLUSTER - 1;
				goto checks;
			}
			/* 这里应该说的是定时延迟,就如果循环了latency_ration就cond_resched出去 */
			if (unlikely(--latency_ration < 0)) {
				cond_resched();
				latency_ration = LATENCY_LIMIT;
			}
		}
		/* 如果没能成功分配一个聚集就重新扫描,希望分配一个单独的槽位 */
		offset = scan_base;
		spin_lock(&si->lock);
		si->cluster_nr = SWAPFILE_CLUSTER - 1;
	}

checks:
	/* ssd */
	if (si->cluster_info) {
		while (scan_swap_map_ssd_cluster_conflict(si, offset))
			scan_swap_map_try_ssd_cluster(si, &offset, &scan_base);
	}
	/* SWP_WRITEOK 指定当前项对应的交换区可写
	 * 如果该交换区不是可写的,那么goto no_page */
	if (!(si->flags & SWP_WRITEOK))
		goto no_page;
	/* 如果highest_bit = 0说明没有空闲的槽位了,那么goto no_page */
	if (!si->highest_bit)
		goto no_page;
	/* 如果offset > si->highest_bit,有可能是上面分配的聚集超过的原因,那么就只分配一个吧 */
	if (offset > si->highest_bit)
		scan_base = offset = si->lowest_bit;

	/* reuse swap entry of cache-only swap if not busy. */
	/* 如果可用槽位数不到总槽位数的一半,并且当前的槽位还有swap_cache时,那么回收该槽的swap cache */
	if (vm_swap_full() && si->swap_map[offset] == SWAP_HAS_CACHE) {
		int swap_was_freed;
		spin_unlock(&si->lock);
		swap_was_freed = __try_to_reclaim_swap(si, offset);
		spin_lock(&si->lock);
		/* entry was freed successfully, try to use this again */
		/* 如果回收成功了,那么再去check一下 */
		if (swap_was_freed)
			goto checks;
		goto scan; /* check next one */
	}

	/* 判断si->swap_map[offset]这个位置是否是空的槽位 */
	if (si->swap_map[offset])
		goto scan;

	/* 如果offset是si->lowest_bit或si->highest_bit,压缩lowest_bit ~ highest_bit的空间 */
	if (offset == si->lowest_bit)
		si->lowest_bit++;
	if (offset == si->highest_bit)
		si->highest_bit--;
	/* 设置si->inuse_pages++ */
	si->inuse_pages++;
	/* 如果已经想等了,说明已经满了,那么设置si->lowest_bit和si->highest_bit之后把它从swap_avail_head中拔掉 */
	if (si->inuse_pages == si->pages) {
		si->lowest_bit = si->max;
		si->highest_bit = 0;
		spin_lock(&swap_avail_lock);
		plist_del(&si->avail_list, &swap_avail_head);
		spin_unlock(&swap_avail_lock);
	}
	/* 设置相关标记,表示这个槽位已经在使用中 */
	si->swap_map[offset] = usage;
	/* 设置相关的cluster_info中的offset成员 */
	inc_cluster_info_page(si, si->cluster_info, offset);
	/* cluster_next表示在交换区中接下来使用的槽位(在某个现存聚集中)的索引,设置为offset + 1 */
	si->cluster_next = offset + 1;
	/* 前面引用计数 +1 了,这里-1 */
	si->flags -= SWP_SCANNING;

	return offset;
	/* 前面没有分配到空闲槽位,下面扩大扫描范围查找 */
scan:
	spin_unlock(&si->lock);
	/* 一个一个的找,从++offset到si->highest_bit范围开始找 */
	while (++offset <= si->highest_bit) {
		/* 如果找到一个空闲槽位就goto checks */
		if (!si->swap_map[offset]) {
			spin_lock(&si->lock);
			goto checks;
		}
		if (vm_swap_full() && si->swap_map[offset] == SWAP_HAS_CACHE) {
			spin_lock(&si->lock);
			goto checks;
		}
		if (unlikely(--latency_ration < 0)) {
			cond_resched();
			latency_ration = LATENCY_LIMIT;
		}
	}
	offset = si->lowest_bit;
	/* 既然上面没找到,那么就往前找,从si->lowest_bit到scan_base开始找 */
	while (offset < scan_base) {
		if (!si->swap_map[offset]) {
			spin_lock(&si->lock);
			goto checks;
		}
		if (vm_swap_full() && si->swap_map[offset] == SWAP_HAS_CACHE) {
			spin_lock(&si->lock);
			goto checks;
		}
		if (unlikely(--latency_ration < 0)) {
			cond_resched();
			latency_ration = LATENCY_LIMIT;
		}
		offset++;
	}
	spin_lock(&si->lock);

no_page:
	si->flags -= SWP_SCANNING;
	return 0;
}

swp_entry_t get_swap_page(void)
{
	struct swap_info_struct *si, *next;
	pgoff_t offset;

	/* 如果os中没有swap,那么直接返回noswap */
	if (atomic_long_read(&nr_swap_pages) <= 0)
		goto noswap;
	atomic_long_dec(&nr_swap_pages);

	spin_lock(&swap_avail_lock);

start_over:
	/* 这里就是轮询swap_avail_head链表 */
	plist_for_each_entry_safe(si, next, &swap_avail_head, avail_list) {
		/* requeue si to after same-priority siblings */
		/* 把它放到相同优先级的siblings的最后
		 * 实际上这里达到的效果就是相同优先级交换分区使用均衡
		 */
		plist_requeue(&si->avail_list, &swap_avail_head);
		spin_unlock(&swap_avail_lock);
		spin_lock(&si->lock);
		/* 为了减少扫描整个交换区查找空闲槽位的搜索时间,内核借助lowest_bit和highest_bit成员,
		 * 来管理搜索区域的下界和上界.在 lowest_bit 之下和 highest_bit 之上,是没有空闲槽
		 * 位的,因而搜索相关区域是无意义的.
		 * 尽管这两个成员的名称以_bit结尾,但二者不是位域,只是普通整数,解释为交换区
		 * 中线性排布的各槽位的索引
		 *
		 * SWP_WRITEOK 指定当前项对应的交换区可写.
		 *
		 * 如果si->highest_bit为0,或者说交换区不是可写的
		 */
		if (!si->highest_bit || !(si->flags & SWP_WRITEOK)) {
			spin_lock(&swap_avail_lock);
			/* 这里就是说如果该si已经从plist被拔掉了,那么解锁之后搜索下一个si */
			if (plist_node_empty(&si->avail_list)) {
				spin_unlock(&si->lock);
				goto nextsi;
			}

			/* 如果说还在swap_avail_head链表里面,那么看!si->highest_bit和!(si->flags & SWP_WRITEOK)
			 * 报警告
			 */
			WARN(!si->highest_bit,
			     "swap_info %d in list but !highest_bit\n",
			     si->type);
			WARN(!(si->flags & SWP_WRITEOK),
			     "swap_info %d in list but !SWP_WRITEOK\n",
			     si->type);
			/* 把它从swap_avail_head中删除 */
			plist_del(&si->avail_list, &swap_avail_head);
			/* 解锁之后去查询下一个si */
			spin_unlock(&si->lock);
			goto nextsi;
		}

		/* This is called for allocating swap entry for cache
		 * 这用于为缓存分配交换条目
		 */
		offset = scan_swap_map(si, SWAP_HAS_CACHE);
		spin_unlock(&si->lock);
		if (offset)
			return swp_entry(si->type, offset);
		pr_debug("scan_swap_map of si %d failed to find offset\n",
		       si->type);
		spin_lock(&swap_avail_lock);
nextsi:
		/*
		 * if we got here, it's likely that si was almost full before,
		 * and since scan_swap_map() can drop the si->lock, multiple
		 * callers probably all tried to get a page from the same si
		 * and it filled up before we could get one; or, the si filled
		 * up between us dropping swap_avail_lock and taking si->lock.
		 * Since we dropped the swap_avail_lock, the swap_avail_head
		 * list may have been modified; so if next is still in the
		 * swap_avail_head list then try it, otherwise start over.
		 *
		 * 如果我们到达这里,那么很可能之前si(swap info,即交换信息)几乎已经满了.
		 * 因为scan_swap_map()函数可能会释放si->lock,所以多个调用者可能都试图从同一个si中获取页面,
		 * 而在我们能够获取一个页面之前,它就已经被填满了;或者,在我们释放swap_avail_lock和重新获取si->lock之间，si被填满了.
		 * 由于我们释放了swap_avail_lock,swap_avail_head列表(交换可用头列表)可能已经被修改了.
		 * 因此，如果next仍然位于swap_avail_head列表中,则尝试获取它;否则,重新开始
		 */
		if (plist_node_empty(&next->avail_list))
			goto start_over;
	}

	spin_unlock(&swap_avail_lock);

	atomic_long_inc(&nr_swap_pages);
noswap:
	return (swp_entry_t) {0};
}

/* The only caller of this function is now suspend routine */
swp_entry_t get_swap_page_of_type(int type)
{
	struct swap_info_struct *si;
	pgoff_t offset;

	si = swap_info[type];
	spin_lock(&si->lock);
	if (si && (si->flags & SWP_WRITEOK)) {
		atomic_long_dec(&nr_swap_pages);
		/* This is called for allocating swap entry, not cache */
		offset = scan_swap_map(si, 1);
		if (offset) {
			spin_unlock(&si->lock);
			return swp_entry(type, offset);
		}
		atomic_long_inc(&nr_swap_pages);
	}
	spin_unlock(&si->lock);
	return (swp_entry_t) {0};
}

static struct swap_info_struct *swap_info_get(swp_entry_t entry)
{
	struct swap_info_struct *p;
	unsigned long offset, type;

	if (!entry.val)
		goto out;
	type = swp_type(entry);
	if (type >= nr_swapfiles)
		goto bad_nofile;
	p = swap_info[type];
	if (!(p->flags & SWP_USED))
		goto bad_device;
	offset = swp_offset(entry);
	if (offset >= p->max)
		goto bad_offset;
	if (!p->swap_map[offset])
		goto bad_free;
	spin_lock(&p->lock);
	return p;

bad_free:
	pr_err("swap_free: %s%08lx\n", Unused_offset, entry.val);
	goto out;
bad_offset:
	pr_err("swap_free: %s%08lx\n", Bad_offset, entry.val);
	goto out;
bad_device:
	pr_err("swap_free: %s%08lx\n", Unused_file, entry.val);
	goto out;
bad_nofile:
	pr_err("swap_free: %s%08lx\n", Bad_file, entry.val);
out:
	return NULL;
}

static unsigned char swap_entry_free(struct swap_info_struct *p,
				     swp_entry_t entry, unsigned char usage)
{
	unsigned long offset = swp_offset(entry);
	unsigned char count;
	unsigned char has_cache;

	count = p->swap_map[offset];
	has_cache = count & SWAP_HAS_CACHE;
	count &= ~SWAP_HAS_CACHE;

	if (usage == SWAP_HAS_CACHE) {
		VM_BUG_ON(!has_cache);
		has_cache = 0;
	} else if (count == SWAP_MAP_SHMEM) {
		/*
		 * Or we could insist on shmem.c using a special
		 * swap_shmem_free() and free_shmem_swap_and_cache()...
		 */
		count = 0;
	} else if ((count & ~COUNT_CONTINUED) <= SWAP_MAP_MAX) {
		if (count == COUNT_CONTINUED) {
			if (swap_count_continued(p, offset, count))
				count = SWAP_MAP_MAX | COUNT_CONTINUED;
			else
				count = SWAP_MAP_MAX;
		} else
			count--;
	}

	usage = count | has_cache;
	p->swap_map[offset] = usage;

	/* free if no reference */
	if (!usage) {
		mem_cgroup_uncharge_swap(entry);
		dec_cluster_info_page(p, p->cluster_info, offset);
		if (offset < p->lowest_bit)
			p->lowest_bit = offset;
		if (offset > p->highest_bit) {
			bool was_full = !p->highest_bit;
			p->highest_bit = offset;
			if (was_full && (p->flags & SWP_WRITEOK)) {
				spin_lock(&swap_avail_lock);
				WARN_ON(!plist_node_empty(&p->avail_list));
				if (plist_node_empty(&p->avail_list))
					plist_add(&p->avail_list,
						  &swap_avail_head);
				spin_unlock(&swap_avail_lock);
			}
		}
		atomic_long_inc(&nr_swap_pages);
		p->inuse_pages--;
		frontswap_invalidate_page(p->type, offset);
		if (p->flags & SWP_BLKDEV) {
			struct gendisk *disk = p->bdev->bd_disk;
			if (disk->fops->swap_slot_free_notify)
				disk->fops->swap_slot_free_notify(p->bdev,
								  offset);
		}
	}

	return usage;
}

/*
 * Caller has made sure that the swap device corresponding to entry
 * is still around or has not been recycled.
 */
void swap_free(swp_entry_t entry)
{
	struct swap_info_struct *p;

	p = swap_info_get(entry);
	if (p) {
		swap_entry_free(p, entry, 1);
		spin_unlock(&p->lock);
	}
}

/*
 * Called after dropping swapcache to decrease refcnt to swap entries.
 */
void swapcache_free(swp_entry_t entry)
{
	struct swap_info_struct *p;

	/* 拿到对应是swap_info_struct */
	p = swap_info_get(entry);
	if (p) {
		/* 把swap_entry_t也给释放掉 */
		swap_entry_free(p, entry, SWAP_HAS_CACHE);
		spin_unlock(&p->lock);
	}
}

/*
 * How many references to page are currently swapped out?
 * This does not give an exact answer when swap count is continued,
 * but does include the high COUNT_CONTINUED flag to allow for that.
 *
 * 当前有多少个对页面的引用是被交换出去的?
 * 当swap计数持续(即超过了一定阈值)时,这并不能给出一个确切的答案,但确实包括了高位的COUNT_CONTINUED标志来允许这种情况的发生.
 */
int page_swapcount(struct page *page)
{
	int count = 0;
	struct swap_info_struct *p;
	swp_entry_t entry;

	/* 拿到该page对应的swap_entry_t */
	entry.val = page_private(page);
	/* 拿到对应是swap_info_struct */
	p = swap_info_get(entry);
	if (p) {
		/* ent & ~SWAP_HAS_CACHE; may include SWAP_HAS_CONT flag */
		count = swap_count(p->swap_map[swp_offset(entry)]);
		spin_unlock(&p->lock);
	}
	return count;
}

/*
 * How many references to @entry are currently swapped out?
 * This considers COUNT_CONTINUED so it returns exact answer.
 */
int swp_swapcount(swp_entry_t entry)
{
	int count, tmp_count, n;
	struct swap_info_struct *p;
	struct page *page;
	pgoff_t offset;
	unsigned char *map;

	p = swap_info_get(entry);
	if (!p)
		return 0;

	count = swap_count(p->swap_map[swp_offset(entry)]);
	if (!(count & COUNT_CONTINUED))
		goto out;

	count &= ~COUNT_CONTINUED;
	n = SWAP_MAP_MAX + 1;

	offset = swp_offset(entry);
	page = vmalloc_to_page(p->swap_map + offset);
	offset &= ~PAGE_MASK;
	VM_BUG_ON(page_private(page) != SWP_CONTINUED);

	do {
		page = list_next_entry(page, lru);
		map = kmap_atomic(page);
		tmp_count = map[offset];
		kunmap_atomic(map);

		count += (tmp_count & ~COUNT_CONTINUED) * n;
		n *= (SWAP_CONT_MAX + 1);
	} while (tmp_count & COUNT_CONTINUED);
out:
	spin_unlock(&p->lock);
	return count;
}

/*
 * We can write to an anon page without COW if there are no other references
 * to it.  And as a side-effect, free up its swap: because the old content
 * on disk will never be read, and seeking back there to write new content
 * later would only waste time away from clustering.
 *
 * NOTE: total_mapcount should not be relied upon by the caller if
 * reuse_swap_page() returns false, but it may be always overwritten
 * (see the other implementation for CONFIG_SWAP=n).
 *
 * 如果没有其他引用,我们可以在没有COW的情况下写入一个匿名页面.
 * 副作用是,释放它的swap: 因为磁盘上的旧内容永远不会被读取,以后再找回来写新内容只会浪费集群时间.
 *
 * 注意: 如果reuse_swap_page()返回false,调用方不应依赖total_mapcount,但它可能总是被覆盖(请参阅CONFIG_SWAP=n的其他实现).
 *
 * reuse_swap_page函数通过page_trans_huge_mapcount计数到变量count中,
 * 并且返回“count是否小于等于1”. count为1,表示只有一个进程映射了找个页面
 */
bool reuse_swap_page(struct page *page, int *total_mapcount)
{
	int count;

	/* 如果page没有被lock住,那么报个BUG */
	VM_BUG_ON_PAGE(!PageLocked(page), page);
	/* 如果page是ksm page,那么直接返回false */
	if (unlikely(PageKsm(page)))
		return false;
	count = page_trans_huge_mapcount(page, total_mapcount);
	if (count <= 1 && PageSwapCache(page)) {
		count += page_swapcount(page);
		if (count != 1)
			goto out;
		if (!PageWriteback(page)) {
			delete_from_swap_cache(page);
			SetPageDirty(page);
		} else {
			swp_entry_t entry;
			struct swap_info_struct *p;

			entry.val = page_private(page);
			p = swap_info_get(entry);
			if (p->flags & SWP_STABLE_WRITES) {
				spin_unlock(&p->lock);
				return false;
			}
			spin_unlock(&p->lock);
		}
	}
out:
	return count <= 1;
}

/*
 * If swap is getting full, or if there are no more mappings of this page,
 * then try_to_free_swap is called to free its swap space.
 *
 * 如果swap空间即将满,或者这个页面已经没有更多的映射了,那么会调用try_to_free_swap函数来释放它所占用的swap空间.
 */
int try_to_free_swap(struct page *page)
{
	VM_BUG_ON_PAGE(!PageLocked(page), page);

	/* 如果不是SwapCache,那么return 0 */
	if (!PageSwapCache(page))
		return 0;
	/* 如果不能写回,那么返回0 */
	if (PageWriteback(page))
		return 0;
	/* 如果对应的swap被占用了,那么也返回0 */
	if (page_swapcount(page))
		return 0;

	/*
	 * Once hibernation has begun to create its image of memory,
	 * there's a danger that one of the calls to try_to_free_swap()
	 * - most probably a call from __try_to_reclaim_swap() while
	 * hibernation is allocating its own swap pages for the image,
	 * but conceivably even a call from memory reclaim - will free
	 * the swap from a page which has already been recorded in the
	 * image as a clean swapcache page, and then reuse its swap for
	 * another page of the image.  On waking from hibernation, the
	 * original page might be freed under memory pressure, then
	 * later read back in from swap, now with the wrong data.
	 *
	 * Hibernation suspends storage while it is writing the image
	 * to disk so check that here.
	 *
	 * 一旦休眠过程开始创建内存镜像,就存在一个风险,即try_to_free_swap()函数的调用之一
	 * - 最可能的是在休眠过程中分配用于镜像的swap页面时由__try_to_reclaim_swap()发起的调用,
	 * 但理论上甚至可能是由内存回收过程发起的调用 - 可能会释放那些已经被记录为干净swapcache页面的swap空间,
	 * 并随后将该swap空间重用于镜像中的另一个页面.
	 * 当从休眠中唤醒时,原始页面可能会因内存压力而被释放,然后稍后从swap中读取回来时,会包含错误的数据.
	 *
	 * 休眠在将镜像写入磁盘时会暂停存储操作,因此请在这里检查这一点.
	 */
	if (pm_suspended_storage())
		return 0;
	/* 从swap cache中删除该page */
	delete_from_swap_cache(page);
	SetPageDirty(page);
	return 1;
}

/*
 * Free the swap entry like above, but also try to
 * free the page cache entry if it is the last user.
 */
int free_swap_and_cache(swp_entry_t entry)
{
	struct swap_info_struct *p;
	struct page *page = NULL;

	if (non_swap_entry(entry))
		return 1;

	p = swap_info_get(entry);
	if (p) {
		if (swap_entry_free(p, entry, 1) == SWAP_HAS_CACHE) {
			page = find_get_page(swap_address_space(entry),
					     swp_offset(entry));
			if (page && !trylock_page(page)) {
				put_page(page);
				page = NULL;
			}
		}
		spin_unlock(&p->lock);
	}
	if (page) {
		/*
		 * Not mapped elsewhere, or swap space full? Free it!
		 * Also recheck PageSwapCache now page is locked (above).
		 */
		if (PageSwapCache(page) && !PageWriteback(page) &&
		    (!page_mapped(page) || mem_cgroup_swap_full(page))) {
			delete_from_swap_cache(page);
			SetPageDirty(page);
		}
		unlock_page(page);
		put_page(page);
	}
	return p != NULL;
}

#ifdef CONFIG_HIBERNATION
/*
 * Find the swap type that corresponds to given device (if any).
 *
 * @offset - number of the PAGE_SIZE-sized block of the device, starting
 * from 0, in which the swap header is expected to be located.
 *
 * This is needed for the suspend to disk (aka swsusp).
 */
int swap_type_of(dev_t device, sector_t offset, struct block_device **bdev_p)
{
	struct block_device *bdev = NULL;
	int type;

	if (device)
		bdev = bdget(device);

	spin_lock(&swap_lock);
	for (type = 0; type < nr_swapfiles; type++) {
		struct swap_info_struct *sis = swap_info[type];

		if (!(sis->flags & SWP_WRITEOK))
			continue;

		if (!bdev) {
			if (bdev_p)
				*bdev_p = bdgrab(sis->bdev);

			spin_unlock(&swap_lock);
			return type;
		}
		if (bdev == sis->bdev) {
			struct swap_extent *se = &sis->first_swap_extent;

			if (se->start_block == offset) {
				if (bdev_p)
					*bdev_p = bdgrab(sis->bdev);

				spin_unlock(&swap_lock);
				bdput(bdev);
				return type;
			}
		}
	}
	spin_unlock(&swap_lock);
	if (bdev)
		bdput(bdev);

	return -ENODEV;
}

/*
 * Get the (PAGE_SIZE) block corresponding to given offset on the swapdev
 * corresponding to given index in swap_info (swap type).
 */
sector_t swapdev_block(int type, pgoff_t offset)
{
	struct block_device *bdev;

	if ((unsigned int)type >= nr_swapfiles)
		return 0;
	if (!(swap_info[type]->flags & SWP_WRITEOK))
		return 0;
	return map_swap_entry(swp_entry(type, offset), &bdev);
}

/*
 * Return either the total number of swap pages of given type, or the number
 * of free pages of that type (depending on @free)
 *
 * This is needed for software suspend
 */
unsigned int count_swap_pages(int type, int free)
{
	unsigned int n = 0;

	spin_lock(&swap_lock);
	if ((unsigned int)type < nr_swapfiles) {
		struct swap_info_struct *sis = swap_info[type];

		spin_lock(&sis->lock);
		if (sis->flags & SWP_WRITEOK) {
			n = sis->pages;
			if (free)
				n -= sis->inuse_pages;
		}
		spin_unlock(&sis->lock);
	}
	spin_unlock(&swap_lock);
	return n;
}
#endif /* CONFIG_HIBERNATION */

static inline int pte_same_as_swp(pte_t pte, pte_t swp_pte)
{
	return pte_same(pte_swp_clear_soft_dirty(pte), swp_pte);
}

/*
 * No need to decide whether this PTE shares the swap entry with others,
 * just let do_wp_page work it out if a write is requested later - to
 * force COW, vm_page_prot omits write permission from any private vma.
 */
static int unuse_pte(struct vm_area_struct *vma, pmd_t *pmd,
		unsigned long addr, swp_entry_t entry, struct page *page)
{
	struct page *swapcache;
	struct mem_cgroup *memcg;
	spinlock_t *ptl;
	pte_t *pte;
	int ret = 1;

	swapcache = page;
	page = ksm_might_need_to_copy(page, vma, addr);
	if (unlikely(!page))
		return -ENOMEM;

	if (mem_cgroup_try_charge(page, vma->vm_mm, GFP_KERNEL,
				&memcg, false)) {
		ret = -ENOMEM;
		goto out_nolock;
	}

	pte = pte_offset_map_lock(vma->vm_mm, pmd, addr, &ptl);
	if (unlikely(!pte_same_as_swp(*pte, swp_entry_to_pte(entry)))) {
		mem_cgroup_cancel_charge(page, memcg, false);
		ret = 0;
		goto out;
	}

	dec_mm_counter(vma->vm_mm, MM_SWAPENTS);
	inc_mm_counter(vma->vm_mm, MM_ANONPAGES);
	get_page(page);
	set_pte_at(vma->vm_mm, addr, pte,
		   pte_mkold(mk_pte(page, vma->vm_page_prot)));
	if (page == swapcache) {
		page_add_anon_rmap(page, vma, addr, false);
		mem_cgroup_commit_charge(page, memcg, true, false);
	} else { /* ksm created a completely new copy */
		page_add_new_anon_rmap(page, vma, addr, false);
		mem_cgroup_commit_charge(page, memcg, false, false);
		lru_cache_add_active_or_unevictable(page, vma);
	}
	swap_free(entry);
	/*
	 * Move the page to the active list so it is not
	 * immediately swapped out again after swapon.
	 */
	activate_page(page);
out:
	pte_unmap_unlock(pte, ptl);
out_nolock:
	if (page != swapcache) {
		unlock_page(page);
		put_page(page);
	}
	return ret;
}

static int unuse_pte_range(struct vm_area_struct *vma, pmd_t *pmd,
				unsigned long addr, unsigned long end,
				swp_entry_t entry, struct page *page)
{
	pte_t swp_pte = swp_entry_to_pte(entry);
	pte_t *pte;
	int ret = 0;

	/*
	 * We don't actually need pte lock while scanning for swp_pte: since
	 * we hold page lock and mmap_sem, swp_pte cannot be inserted into the
	 * page table while we're scanning; though it could get zapped, and on
	 * some architectures (e.g. x86_32 with PAE) we might catch a glimpse
	 * of unmatched parts which look like swp_pte, so unuse_pte must
	 * recheck under pte lock.  Scanning without pte lock lets it be
	 * preemptable whenever CONFIG_PREEMPT but not CONFIG_HIGHPTE.
	 */
	pte = pte_offset_map(pmd, addr);
	do {
		/*
		 * swapoff spends a _lot_ of time in this loop!
		 * Test inline before going to call unuse_pte.
		 */
		if (unlikely(pte_same_as_swp(*pte, swp_pte))) {
			pte_unmap(pte);
			ret = unuse_pte(vma, pmd, addr, entry, page);
			if (ret)
				goto out;
			pte = pte_offset_map(pmd, addr);
		}
	} while (pte++, addr += PAGE_SIZE, addr != end);
	pte_unmap(pte - 1);
out:
	return ret;
}

static inline int unuse_pmd_range(struct vm_area_struct *vma, pud_t *pud,
				unsigned long addr, unsigned long end,
				swp_entry_t entry, struct page *page)
{
	pmd_t *pmd;
	unsigned long next;
	int ret;

	pmd = pmd_offset(pud, addr);
	do {
		next = pmd_addr_end(addr, end);
		if (pmd_none_or_trans_huge_or_clear_bad(pmd))
			continue;
		ret = unuse_pte_range(vma, pmd, addr, next, entry, page);
		if (ret)
			return ret;
	} while (pmd++, addr = next, addr != end);
	return 0;
}

static inline int unuse_pud_range(struct vm_area_struct *vma, pgd_t *pgd,
				unsigned long addr, unsigned long end,
				swp_entry_t entry, struct page *page)
{
	pud_t *pud;
	unsigned long next;
	int ret;

	pud = pud_offset(pgd, addr);
	do {
		next = pud_addr_end(addr, end);
		if (pud_none_or_clear_bad(pud))
			continue;
		ret = unuse_pmd_range(vma, pud, addr, next, entry, page);
		if (ret)
			return ret;
	} while (pud++, addr = next, addr != end);
	return 0;
}

static int unuse_vma(struct vm_area_struct *vma,
				swp_entry_t entry, struct page *page)
{
	pgd_t *pgd;
	unsigned long addr, end, next;
	int ret;

	if (page_anon_vma(page)) {
		addr = page_address_in_vma(page, vma);
		if (addr == -EFAULT)
			return 0;
		else
			end = addr + PAGE_SIZE;
	} else {
		addr = vma->vm_start;
		end = vma->vm_end;
	}

	pgd = pgd_offset(vma->vm_mm, addr);
	do {
		next = pgd_addr_end(addr, end);
		if (pgd_none_or_clear_bad(pgd))
			continue;
		ret = unuse_pud_range(vma, pgd, addr, next, entry, page);
		if (ret)
			return ret;
	} while (pgd++, addr = next, addr != end);
	return 0;
}

static int unuse_mm(struct mm_struct *mm,
				swp_entry_t entry, struct page *page)
{
	struct vm_area_struct *vma;
	int ret = 0;

	if (!down_read_trylock(&mm->mmap_sem)) {
		/*
		 * Activate page so shrink_inactive_list is unlikely to unmap
		 * its ptes while lock is dropped, so swapoff can make progress.
		 */
		activate_page(page);
		unlock_page(page);
		down_read(&mm->mmap_sem);
		lock_page(page);
	}
	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		if (vma->anon_vma && (ret = unuse_vma(vma, entry, page)))
			break;
	}
	up_read(&mm->mmap_sem);
	return (ret < 0)? ret: 0;
}

/*
 * Scan swap_map (or frontswap_map if frontswap parameter is true)
 * from current position to next entry still in use.
 * Recycle to start on reaching the end, returning 0 when empty.
 */
static unsigned int find_next_to_unuse(struct swap_info_struct *si,
					unsigned int prev, bool frontswap)
{
	unsigned int max = si->max;
	unsigned int i = prev;
	unsigned char count;

	/*
	 * No need for swap_lock here: we're just looking
	 * for whether an entry is in use, not modifying it; false
	 * hits are okay, and sys_swapoff() has already prevented new
	 * allocations from this area (while holding swap_lock).
	 */
	for (;;) {
		if (++i >= max) {
			if (!prev) {
				i = 0;
				break;
			}
			/*
			 * No entries in use at top of swap_map,
			 * loop back to start and recheck there.
			 */
			max = prev + 1;
			prev = 0;
			i = 1;
		}
		if (frontswap) {
			if (frontswap_test(si, i))
				break;
			else
				continue;
		}
		count = READ_ONCE(si->swap_map[i]);
		if (count && swap_count(count) != SWAP_MAP_BAD)
			break;
	}
	return i;
}

/*
 * We completely avoid races by reading each swap page in advance,
 * and then search for the process using it.  All the necessary
 * page table adjustments can then be made atomically.
 *
 * if the boolean frontswap is true, only unuse pages_to_unuse pages;
 * pages_to_unuse==0 means all pages; ignored if frontswap is false
 */
int try_to_unuse(unsigned int type, bool frontswap,
		 unsigned long pages_to_unuse)
{
	struct swap_info_struct *si = swap_info[type];
	struct mm_struct *start_mm;
	volatile unsigned char *swap_map; /* swap_map is accessed without
					   * locking. Mark it as volatile
					   * to prevent compiler doing
					   * something odd.
					   */
	unsigned char swcount;
	struct page *page;
	swp_entry_t entry;
	unsigned int i = 0;
	int retval = 0;

	/*
	 * When searching mms for an entry, a good strategy is to
	 * start at the first mm we freed the previous entry from
	 * (though actually we don't notice whether we or coincidence
	 * freed the entry).  Initialize this start_mm with a hold.
	 *
	 * A simpler strategy would be to start at the last mm we
	 * freed the previous entry from; but that would take less
	 * advantage of mmlist ordering, which clusters forked mms
	 * together, child after parent.  If we race with dup_mmap(), we
	 * prefer to resolve parent before child, lest we miss entries
	 * duplicated after we scanned child: using last mm would invert
	 * that.
	 */
	start_mm = &init_mm;
	atomic_inc(&init_mm.mm_users);

	/*
	 * Keep on scanning until all entries have gone.  Usually,
	 * one pass through swap_map is enough, but not necessarily:
	 * there are races when an instance of an entry might be missed.
	 */
	while ((i = find_next_to_unuse(si, i, frontswap)) != 0) {
		if (signal_pending(current)) {
			retval = -EINTR;
			break;
		}

		/*
		 * Get a page for the entry, using the existing swap
		 * cache page if there is one.  Otherwise, get a clean
		 * page and read the swap into it.
		 */
		swap_map = &si->swap_map[i];
		entry = swp_entry(type, i);
		page = read_swap_cache_async(entry,
					GFP_HIGHUSER_MOVABLE, NULL, 0);
		if (!page) {
			/*
			 * Either swap_duplicate() failed because entry
			 * has been freed independently, and will not be
			 * reused since sys_swapoff() already disabled
			 * allocation from here, or alloc_page() failed.
			 */
			swcount = *swap_map;
			/*
			 * We don't hold lock here, so the swap entry could be
			 * SWAP_MAP_BAD (when the cluster is discarding).
			 * Instead of fail out, We can just skip the swap
			 * entry because swapoff will wait for discarding
			 * finish anyway.
			 */
			if (!swcount || swcount == SWAP_MAP_BAD)
				continue;
			retval = -ENOMEM;
			break;
		}

		/*
		 * Don't hold on to start_mm if it looks like exiting.
		 */
		if (atomic_read(&start_mm->mm_users) == 1) {
			mmput(start_mm);
			start_mm = &init_mm;
			atomic_inc(&init_mm.mm_users);
		}

		/*
		 * Wait for and lock page.  When do_swap_page races with
		 * try_to_unuse, do_swap_page can handle the fault much
		 * faster than try_to_unuse can locate the entry.  This
		 * apparently redundant "wait_on_page_locked" lets try_to_unuse
		 * defer to do_swap_page in such a case - in some tests,
		 * do_swap_page and try_to_unuse repeatedly compete.
		 */
		wait_on_page_locked(page);
		wait_on_page_writeback(page);
		lock_page(page);
		wait_on_page_writeback(page);

		/*
		 * Remove all references to entry.
		 */
		swcount = *swap_map;
		if (swap_count(swcount) == SWAP_MAP_SHMEM) {
			retval = shmem_unuse(entry, page);
			/* page has already been unlocked and released */
			if (retval < 0)
				break;
			continue;
		}
		if (swap_count(swcount) && start_mm != &init_mm)
			retval = unuse_mm(start_mm, entry, page);

		if (swap_count(*swap_map)) {
			int set_start_mm = (*swap_map >= swcount);
			struct list_head *p = &start_mm->mmlist;
			struct mm_struct *new_start_mm = start_mm;
			struct mm_struct *prev_mm = start_mm;
			struct mm_struct *mm;

			atomic_inc(&new_start_mm->mm_users);
			atomic_inc(&prev_mm->mm_users);
			spin_lock(&mmlist_lock);
			while (swap_count(*swap_map) && !retval &&
					(p = p->next) != &start_mm->mmlist) {
				mm = list_entry(p, struct mm_struct, mmlist);
				if (!atomic_inc_not_zero(&mm->mm_users))
					continue;
				spin_unlock(&mmlist_lock);
				mmput(prev_mm);
				prev_mm = mm;

				cond_resched();

				swcount = *swap_map;
				if (!swap_count(swcount)) /* any usage ? */
					;
				else if (mm == &init_mm)
					set_start_mm = 1;
				else
					retval = unuse_mm(mm, entry, page);

				if (set_start_mm && *swap_map < swcount) {
					mmput(new_start_mm);
					atomic_inc(&mm->mm_users);
					new_start_mm = mm;
					set_start_mm = 0;
				}
				spin_lock(&mmlist_lock);
			}
			spin_unlock(&mmlist_lock);
			mmput(prev_mm);
			mmput(start_mm);
			start_mm = new_start_mm;
		}
		if (retval) {
			unlock_page(page);
			put_page(page);
			break;
		}

		/*
		 * If a reference remains (rare), we would like to leave
		 * the page in the swap cache; but try_to_unmap could
		 * then re-duplicate the entry once we drop page lock,
		 * so we might loop indefinitely; also, that page could
		 * not be swapped out to other storage meanwhile.  So:
		 * delete from cache even if there's another reference,
		 * after ensuring that the data has been saved to disk -
		 * since if the reference remains (rarer), it will be
		 * read from disk into another page.  Splitting into two
		 * pages would be incorrect if swap supported "shared
		 * private" pages, but they are handled by tmpfs files.
		 *
		 * Given how unuse_vma() targets one particular offset
		 * in an anon_vma, once the anon_vma has been determined,
		 * this splitting happens to be just what is needed to
		 * handle where KSM pages have been swapped out: re-reading
		 * is unnecessarily slow, but we can fix that later on.
		 */
		if (swap_count(*swap_map) &&
		     PageDirty(page) && PageSwapCache(page)) {
			struct writeback_control wbc = {
				.sync_mode = WB_SYNC_NONE,
			};

			swap_writepage(page, &wbc);
			lock_page(page);
			wait_on_page_writeback(page);
		}

		/*
		 * It is conceivable that a racing task removed this page from
		 * swap cache just before we acquired the page lock at the top,
		 * or while we dropped it in unuse_mm().  The page might even
		 * be back in swap cache on another swap area: that we must not
		 * delete, since it may not have been written out to swap yet.
		 */
		if (PageSwapCache(page) &&
		    likely(page_private(page) == entry.val))
			delete_from_swap_cache(page);

		/*
		 * So we could skip searching mms once swap count went
		 * to 1, we did not mark any present ptes as dirty: must
		 * mark page dirty so shrink_page_list will preserve it.
		 */
		SetPageDirty(page);
		unlock_page(page);
		put_page(page);

		/*
		 * Make sure that we aren't completely killing
		 * interactive performance.
		 */
		cond_resched();
		if (frontswap && pages_to_unuse > 0) {
			if (!--pages_to_unuse)
				break;
		}
	}

	mmput(start_mm);
	return retval;
}

/*
 * After a successful try_to_unuse, if no swap is now in use, we know
 * we can empty the mmlist.  swap_lock must be held on entry and exit.
 * Note that mmlist_lock nests inside swap_lock, and an mm must be
 * added to the mmlist just after page_duplicate - before would be racy.
 */
static void drain_mmlist(void)
{
	struct list_head *p, *next;
	unsigned int type;

	for (type = 0; type < nr_swapfiles; type++)
		if (swap_info[type]->inuse_pages)
			return;
	spin_lock(&mmlist_lock);
	list_for_each_safe(p, next, &init_mm.mmlist)
		list_del_init(p);
	spin_unlock(&mmlist_lock);
}

/*
 * Use this swapdev's extent info to locate the (PAGE_SIZE) block which
 * corresponds to page offset for the specified swap entry.
 * Note that the type of this function is sector_t, but it returns page offset
 * into the bdev, not sector offset.
 */
static sector_t map_swap_entry(swp_entry_t entry, struct block_device **bdev)
{
	struct swap_info_struct *sis;
	struct swap_extent *start_se;
	struct swap_extent *se;
	pgoff_t offset;

	sis = swap_info[swp_type(entry)];
	*bdev = sis->bdev;

	offset = swp_offset(entry);
	start_se = sis->curr_swap_extent;
	se = start_se;

	for ( ; ; ) {
		if (se->start_page <= offset &&
				offset < (se->start_page + se->nr_pages)) {
			return se->start_block + (offset - se->start_page);
		}
		se = list_next_entry(se, list);
		sis->curr_swap_extent = se;
		BUG_ON(se == start_se);		/* It *must* be present */
	}
}

/*
 * Returns the page offset into bdev for the specified page's swap entry.
 */
sector_t map_swap_page(struct page *page, struct block_device **bdev)
{
	swp_entry_t entry;
	entry.val = page_private(page);
	return map_swap_entry(entry, bdev);
}

/*
 * Free all of a swapdev's extent information
 */
static void destroy_swap_extents(struct swap_info_struct *sis)
{
	while (!list_empty(&sis->first_swap_extent.list)) {
		struct swap_extent *se;

		se = list_first_entry(&sis->first_swap_extent.list,
				struct swap_extent, list);
		list_del(&se->list);
		kfree(se);
	}

	if (sis->flags & SWP_FILE) {
		struct file *swap_file = sis->swap_file;
		struct address_space *mapping = swap_file->f_mapping;

		sis->flags &= ~SWP_FILE;
		mapping->a_ops->swap_deactivate(swap_file);
	}
}

/*
 * Add a block range (and the corresponding page range) into this swapdev's
 * extent list.  The extent list is kept sorted in page order.
 *
 * This function rather assumes that it is called in ascending page order.
 *
 * 将块范围(和相应的页面范围)添加到此swapdev的范围列表中.扩展列表按页面顺序排序.
 *
 * 此函数假定它是按页面升序调用的.
 */
int
add_swap_extent(struct swap_info_struct *sis, unsigned long start_page,
		unsigned long nr_pages, sector_t start_block)
{
	struct swap_extent *se;
	struct swap_extent *new_se;
	struct list_head *lh;
	/* 如果start_page == 0 */
	if (start_page == 0) {
		/* 拿到sis里面的first_swap_extent */
		se = &sis->first_swap_extent;
		/* 记录我们curr_swap_extent,便于查找 */
		sis->curr_swap_extent = se;
		/* 对first_swap_extent进行赋值 */
		se->start_page = 0;
		se->nr_pages = nr_pages;
		se->start_block = start_block;
		return 1;
	} else {
		/* 如果start_page != 0,说明它可能不是连续的,那么就去取最高的范围的 */
		lh = sis->first_swap_extent.list.prev;	/* Highest extent */
		/* 通过list_head拿到se */
		se = list_entry(lh, struct swap_extent, list);
		BUG_ON(se->start_page + se->nr_pages != start_page);
		/* 如果是连续的,那么就merge就好了 */
		if (se->start_block + se->nr_pages == start_block) {
			/* Merge it */
			se->nr_pages += nr_pages;
			return 0;
		}
	}

	/*
	 * No merge.  Insert a new extent, preserving ordering.
	 * 不能合并,插入一个新的extent,保持次序
	 */

	/* 如果不能merge,那么就插入一个新的extent */
	new_se = kmalloc(sizeof(*se), GFP_KERNEL);
	/* 如果new_se不能分配空间,那么直接返货-ENOMEM */
	if (new_se == NULL)
		return -ENOMEM;
	/* 设置new_se */
	new_se->start_page = start_page;
	new_se->nr_pages = nr_pages;
	new_se->start_block = start_block;

	/* 添加到链表里面去 */
	list_add_tail(&new_se->list, &sis->first_swap_extent.list);
	return 1;
}

/*
 * A `swap extent' is a simple thing which maps a contiguous range of pages
 * onto a contiguous range of disk blocks.  An ordered list of swap extents
 * is built at swapon time and is then used at swap_writepage/swap_readpage
 * time for locating where on disk a page belongs.
 *
 * If the swapfile is an S_ISBLK block device, a single extent is installed.
 * This is done so that the main operating code can treat S_ISBLK and S_ISREG
 * swap files identically.
 *
 * Whether the swapdev is an S_ISREG file or an S_ISBLK blockdev, the swap
 * extent list operates in PAGE_SIZE disk blocks.  Both S_ISREG and S_ISBLK
 * swapfiles are handled *identically* after swapon time.
 *
 * For S_ISREG swapfiles, setup_swap_extents() will walk all the file's blocks
 * and will parse them into an ordered extent list, in PAGE_SIZE chunks.  If
 * some stray blocks are found which do not fall within the PAGE_SIZE alignment
 * requirements, they are simply tossed out - we will never use those blocks
 * for swapping.
 *
 * For S_ISREG swapfiles we set S_SWAPFILE across the life of the swapon.  This
 * prevents root from shooting her foot off by ftruncating an in-use swapfile,
 * which will scribble on the fs.
 *
 * The amount of disk space which a single swap extent represents varies.
 * Typically it is in the 1-4 megabyte range.  So we can have hundreds of
 * extents in the list.  To avoid much list walking, we cache the previous
 * search location in `curr_swap_extent', and start new searches from there.
 * This is extremely effective.  The average number of iterations in
 * map_swap_page() has been measured at about 0.3 per page.  - akpm.
 *
 * 交换范围”(swap extent)是一个简单的概念,它将一段连续的页面映射到一段连续的磁盘块上.
 * 在交换启用时(swapon 时间),构建一个有序的交换范围列表,并在交换写页面(swap_writepage)和交换读页面(swap_readpage)时用于定位页面在磁盘上的位置.
 *
 * 如果交换文件是一个S_ISBLK块设备,则安装一个单一的交换范围.这是为了让主操作代码能够将S_ISBLK和S_ISREG 交换文件视为相同.
 *
 * 无论swapdev是S_ISREG文件还是S_ISBLK块设备,交换范围列表都以PAGE_SIZE大小的磁盘块操作. 在swapon时间后,S_ISREG和S_ISBLK交换文件的处理是相同的.
 *
 * 对于S_ISREG 交换文件,setup_swap_extents()会遍历该文件的所有块,并将其解析为按照PAGE_SIZE切分的有序范围列表.
 * 如果发现一些不符合PAGE_SIZE对齐要求的零散块,它们会被简单地丢弃 - 我们永远不会使用这些块进行交换.
 *
 * 对于S_ISREG交换文件,我们在整个交换启用期间设置S_SWAPFILE.这可以防止root用户通过ftruncate修改正在使用的交换文件,从而导致文件系统损坏.
 *
 * 单个交换范围表示的磁盘空间大小是可变的.
 * 通常,它在1到4兆字节范围内. 因此,我们可以在列表中拥有数百个交换范围.为了避免频繁遍历列表,我们将上一次搜索的位置缓存到curr_swap_extent中,
 * 并从那里开始新的搜索.这是非常有效的.测得在map_swap_page()中平均迭代次数约为每页0.3 次. - akpm
 */
static int setup_swap_extents(struct swap_info_struct *sis, sector_t *span)
{
	/* 拿到交换空间后备的文件 */
	struct file *swap_file = sis->swap_file;
	/* 拿到该文件的地址空间 */
	struct address_space *mapping = swap_file->f_mapping;
	/* 拿到该文件的inode */
	struct inode *inode = mapping->host;
	int ret;

	/* 在使用交换分区而不是交换文件时,该函数的任务很简单.
	 * 块设备可以确保所有扇区都包含在一个连续的列表中,因而,在区间链表中只需要一项.
	 * 该项是使用 add_swap_extent 创建的,包含了分区中所有的块
	 */
	if (S_ISBLK(inode->i_mode)) {
		/* 如果是块设备,那么在这里添加的时候吧所有的扇区都添加到一个连续的列表中 */
		ret = add_swap_extent(sis, 0, sis->max, 0);
		*span = sis->pages;
		return ret;
	}

	/* 如果交换区是文件,内核需要完成的工作会多一些,因为必须逐个扫描该文件的各个块,来确定
	 * 块是如何分配到扇区的.
	 * bmap 函数即用于该目的.它是虚拟文件系统的一部分,调用了特定文件系统的地址空间操作中的bmap方法.
	 * 这里不详细讲述各个特定文件系统的实现,因为它们都会得出同样的结果,即给定块号的硬盘扇区编号.
	 * 内核的其他部分可以认为在一个文件内,逻辑上的各个块是连续的.
	 * 但对与各个块对应的磁盘扇区来说,事实并非如此
	 */
	if (mapping->a_ops->swap_activate) {
		ret = mapping->a_ops->swap_activate(sis, swap_file, span);
		if (!ret) {
			sis->flags |= SWP_FILE;
			ret = add_swap_extent(sis, 0, sis->max, 0);
			*span = sis->pages;
		}
		return ret;
	}

	return generic_swapfile_activate(sis, swap_file, span);
}

static void _enable_swap_info(struct swap_info_struct *p, int prio,
				unsigned char *swap_map,
				struct swap_cluster_info *cluster_info)
{
	/* 如果prio >= 0,那么p->prio = prio
	 * 否则
	 * p->prio = --least_priority
	 */
	if (prio >= 0)
		p->prio = prio;
	else
		p->prio = --least_priority;
	/*
	 * the plist prio is negated because plist ordering is
	 * low-to-high, while swap ordering is high-to-low
	 *
	 * 由于plist(可能是指某种优先级列表或页面列表)的排序是从低到高,而交换(swap)的排序是从高到低,
	 * 因此plist中的优先级(prio)在用于交换排序时会被取反(或称为反转)
	 */
	p->list.prio = -p->prio;
	p->avail_list.prio = -p->prio;
	p->swap_map = swap_map;
	p->cluster_info = cluster_info;
	p->flags |= SWP_WRITEOK;
	atomic_long_add(p->pages, &nr_swap_pages);
	total_swap_pages += p->pages;

	assert_spin_locked(&swap_lock);
	/*
	 * both lists are plists, and thus priority ordered.
	 * swap_active_head needs to be priority ordered for swapoff(),
	 * which on removal of any swap_info_struct with an auto-assigned
	 * (i.e. negative) priority increments the auto-assigned priority
	 * of any lower-priority swap_info_structs.
	 * swap_avail_head needs to be priority ordered for get_swap_page(),
	 * which allocates swap pages from the highest available priority
	 * swap_info_struct.
	 *
	 * 这两份列表都是plist(可能指的是优先级列表),因此它们都是按照优先级排序的.
	 * swap_active_head需要按照优先级排序,这对于执行swapoff()操作是必要的.
	 * 当从系统中移除任何具有自动分配(即负值)优先级的swap_info_struct时,会递增任何具有较低优先级的swap_info_struct的自动分配优先级.
	 * 这是因为 swapoff() 需要确保在关闭交换分区时,系统能够按照一定顺序安全地释放或处理这些交换分区,避免数据丢失或不一致.
	 * swap_avail_head同样需要按照优先级排序,这对于 get_swap_page() 函数的操作是必要的.
	 * get_swap_page() 函数用于从具有最高可用优先级的 swap_info_struct 中分配交换页面.
	 * 这样做可以确保系统优先使用性能更好或更适合当前工作负载的交换空间.
	 * 简而言之,swap_active_head 和swap_avail_head这两份列表都按照优先级排序,但它们的用途不同:
	 * swap_active_head 用于 swapoff() 操作,确保在移除交换分区时能够正确管理优先级.
	 * swap_avail_head 用于 get_swap_page() 操作,确保系统能够优先从性能更优的交换分区中分配页面.
	 * 这种设计允许Linux内核更高效地管理交换空间，通过优先级排序来优化性能和数据一致性
	 */
	plist_add(&p->list, &swap_active_head);
	spin_lock(&swap_avail_lock);
	plist_add(&p->avail_list, &swap_avail_head);
	spin_unlock(&swap_avail_lock);
}

static void enable_swap_info(struct swap_info_struct *p, int prio,
				unsigned char *swap_map,
				struct swap_cluster_info *cluster_info,
				unsigned long *frontswap_map)
{
	frontswap_init(p->type, frontswap_map);
	spin_lock(&swap_lock);
	spin_lock(&p->lock);
	 _enable_swap_info(p, prio, swap_map, cluster_info);
	spin_unlock(&p->lock);
	spin_unlock(&swap_lock);
}

static void reinsert_swap_info(struct swap_info_struct *p)
{
	spin_lock(&swap_lock);
	spin_lock(&p->lock);
	_enable_swap_info(p, p->prio, p->swap_map, p->cluster_info);
	spin_unlock(&p->lock);
	spin_unlock(&swap_lock);
}

SYSCALL_DEFINE1(swapoff, const char __user *, specialfile)
{
	struct swap_info_struct *p = NULL;
	unsigned char *swap_map;
	struct swap_cluster_info *cluster_info;
	unsigned long *frontswap_map;
	struct file *swap_file, *victim;
	struct address_space *mapping;
	struct inode *inode;
	struct filename *pathname;
	int err, found = 0;
	unsigned int old_block_size;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	BUG_ON(!current->mm);

	pathname = getname(specialfile);
	if (IS_ERR(pathname))
		return PTR_ERR(pathname);

	victim = file_open_name(pathname, O_RDWR|O_LARGEFILE, 0);
	err = PTR_ERR(victim);
	if (IS_ERR(victim))
		goto out;

	mapping = victim->f_mapping;
	spin_lock(&swap_lock);
	plist_for_each_entry(p, &swap_active_head, list) {
		if (p->flags & SWP_WRITEOK) {
			if (p->swap_file->f_mapping == mapping) {
				found = 1;
				break;
			}
		}
	}
	if (!found) {
		err = -EINVAL;
		spin_unlock(&swap_lock);
		goto out_dput;
	}
	if (!security_vm_enough_memory_mm(current->mm, p->pages))
		vm_unacct_memory(p->pages);
	else {
		err = -ENOMEM;
		spin_unlock(&swap_lock);
		goto out_dput;
	}
	spin_lock(&swap_avail_lock);
	plist_del(&p->avail_list, &swap_avail_head);
	spin_unlock(&swap_avail_lock);
	spin_lock(&p->lock);
	if (p->prio < 0) {
		struct swap_info_struct *si = p;

		plist_for_each_entry_continue(si, &swap_active_head, list) {
			si->prio++;
			si->list.prio--;
			si->avail_list.prio--;
		}
		least_priority++;
	}
	plist_del(&p->list, &swap_active_head);
	atomic_long_sub(p->pages, &nr_swap_pages);
	total_swap_pages -= p->pages;
	p->flags &= ~SWP_WRITEOK;
	spin_unlock(&p->lock);
	spin_unlock(&swap_lock);

	set_current_oom_origin();
	err = try_to_unuse(p->type, false, 0); /* force unuse all pages */
	clear_current_oom_origin();

	if (err) {
		/* re-insert swap space back into swap_list */
		reinsert_swap_info(p);
		goto out_dput;
	}

	flush_work(&p->discard_work);

	destroy_swap_extents(p);
	if (p->flags & SWP_CONTINUED)
		free_swap_count_continuations(p);

	mutex_lock(&swapon_mutex);
	spin_lock(&swap_lock);
	spin_lock(&p->lock);
	drain_mmlist();

	/* wait for anyone still in scan_swap_map */
	p->highest_bit = 0;		/* cuts scans short */
	while (p->flags >= SWP_SCANNING) {
		spin_unlock(&p->lock);
		spin_unlock(&swap_lock);
		schedule_timeout_uninterruptible(1);
		spin_lock(&swap_lock);
		spin_lock(&p->lock);
	}

	swap_file = p->swap_file;
	old_block_size = p->old_block_size;
	p->swap_file = NULL;
	p->max = 0;
	swap_map = p->swap_map;
	p->swap_map = NULL;
	cluster_info = p->cluster_info;
	p->cluster_info = NULL;
	frontswap_map = frontswap_map_get(p);
	spin_unlock(&p->lock);
	spin_unlock(&swap_lock);
	frontswap_invalidate_area(p->type);
	frontswap_map_set(p, NULL);
	mutex_unlock(&swapon_mutex);
	free_percpu(p->percpu_cluster);
	p->percpu_cluster = NULL;
	vfree(swap_map);
	vfree(cluster_info);
	vfree(frontswap_map);
	/* Destroy swap account information */
	swap_cgroup_swapoff(p->type);

	inode = mapping->host;
	if (S_ISBLK(inode->i_mode)) {
		struct block_device *bdev = I_BDEV(inode);
		set_blocksize(bdev, old_block_size);
		blkdev_put(bdev, FMODE_READ | FMODE_WRITE | FMODE_EXCL);
	} else {
		inode_lock(inode);
		inode->i_flags &= ~S_SWAPFILE;
		inode_unlock(inode);
	}
	filp_close(swap_file, NULL);

	/*
	 * Clear the SWP_USED flag after all resources are freed so that swapon
	 * can reuse this swap_info in alloc_swap_info() safely.  It is ok to
	 * not hold p->lock after we cleared its SWP_WRITEOK.
	 */
	spin_lock(&swap_lock);
	p->flags = 0;
	spin_unlock(&swap_lock);

	err = 0;
	atomic_inc(&proc_poll_event);
	wake_up_interruptible(&proc_poll_wait);

out_dput:
	filp_close(victim, NULL);
out:
	putname(pathname);
	return err;
}

#ifdef CONFIG_PROC_FS
static unsigned swaps_poll(struct file *file, poll_table *wait)
{
	struct seq_file *seq = file->private_data;

	poll_wait(file, &proc_poll_wait, wait);

	if (seq->poll_event != atomic_read(&proc_poll_event)) {
		seq->poll_event = atomic_read(&proc_poll_event);
		return POLLIN | POLLRDNORM | POLLERR | POLLPRI;
	}

	return POLLIN | POLLRDNORM;
}

/* iterator */
static void *swap_start(struct seq_file *swap, loff_t *pos)
{
	struct swap_info_struct *si;
	int type;
	loff_t l = *pos;

	mutex_lock(&swapon_mutex);

	if (!l)
		return SEQ_START_TOKEN;

	for (type = 0; type < nr_swapfiles; type++) {
		smp_rmb();	/* read nr_swapfiles before swap_info[type] */
		si = swap_info[type];
		if (!(si->flags & SWP_USED) || !si->swap_map)
			continue;
		if (!--l)
			return si;
	}

	return NULL;
}

static void *swap_next(struct seq_file *swap, void *v, loff_t *pos)
{
	struct swap_info_struct *si = v;
	int type;

	if (v == SEQ_START_TOKEN)
		type = 0;
	else
		type = si->type + 1;

	for (; type < nr_swapfiles; type++) {
		smp_rmb();	/* read nr_swapfiles before swap_info[type] */
		si = swap_info[type];
		if (!(si->flags & SWP_USED) || !si->swap_map)
			continue;
		++*pos;
		return si;
	}

	return NULL;
}

static void swap_stop(struct seq_file *swap, void *v)
{
	mutex_unlock(&swapon_mutex);
}

static int swap_show(struct seq_file *swap, void *v)
{
	struct swap_info_struct *si = v;
	struct file *file;
	int len;

	if (si == SEQ_START_TOKEN) {
		seq_puts(swap,"Filename\t\t\t\tType\t\tSize\tUsed\tPriority\n");
		return 0;
	}

	file = si->swap_file;
	len = seq_file_path(swap, file, " \t\n\\");
	seq_printf(swap, "%*s%s\t%u\t%u\t%d\n",
			len < 40 ? 40 - len : 1, " ",
			S_ISBLK(file_inode(file)->i_mode) ?
				"partition" : "file\t",
			si->pages << (PAGE_SHIFT - 10),
			si->inuse_pages << (PAGE_SHIFT - 10),
			si->prio);
	return 0;
}

static const struct seq_operations swaps_op = {
	.start =	swap_start,
	.next =		swap_next,
	.stop =		swap_stop,
	.show =		swap_show
};

static int swaps_open(struct inode *inode, struct file *file)
{
	struct seq_file *seq;
	int ret;

	ret = seq_open(file, &swaps_op);
	if (ret)
		return ret;

	seq = file->private_data;
	seq->poll_event = atomic_read(&proc_poll_event);
	return 0;
}

static const struct file_operations proc_swaps_operations = {
	.open		= swaps_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
	.poll		= swaps_poll,
};

static int __init procswaps_init(void)
{
	proc_create("swaps", 0, NULL, &proc_swaps_operations);
	return 0;
}
__initcall(procswaps_init);
#endif /* CONFIG_PROC_FS */

#ifdef MAX_SWAPFILES_CHECK
static int __init max_swapfiles_check(void)
{
	MAX_SWAPFILES_CHECK();
	return 0;
}
late_initcall(max_swapfiles_check);
#endif

static struct swap_info_struct *alloc_swap_info(void)
{
	struct swap_info_struct *p;
	unsigned int type;

	/* 分配swap_info_struct的内存 */
	p = kzalloc(sizeof(*p), GFP_KERNEL);
	if (!p)
		return ERR_PTR(-ENOMEM);

	spin_lock(&swap_lock);
	/* 这里就是去找swap_info中空闲的项,并把它计入到type中 */
	for (type = 0; type < nr_swapfiles; type++) {
		if (!(swap_info[type]->flags & SWP_USED))
			break;
	}

	/* 如果说type大于等于MAX_SWAPFILES,也就是满了,那么free掉swap_info_struct,返回-EPERM */
	if (type >= MAX_SWAPFILES) {
		spin_unlock(&swap_lock);
		kfree(p);
		return ERR_PTR(-EPERM);
	}
	/* 如果大于等于nr_swapfiles,说明swap_info中没有空闲的项给你,那你就拿紧接着那个新的吧 */
	if (type >= nr_swapfiles) {
		p->type = type;
		swap_info[type] = p;
		/*
		 * Write swap_info[type] before nr_swapfiles, in case a
		 * racing procfs swap_start() or swap_next() is reading them.
		 * (We never shrink nr_swapfiles, we never free this entry.)
		 *
		 * 在nr_swapfiles之前写入swap_info[type],以防有并发运行的procfs swap_start()或swap_next()函数正在读取它们.
		 * (我们永远不会缩小nr_swapfiles,也永远不会释放这个条目.)
		 */
		smp_wmb();
		nr_swapfiles++;
	} else {
		/* 如果说type < nr_swapfiles,说明之前有人用过,但是退出了,所以这里我们就继承它的swap_info项吧 */
		kfree(p);
		p = swap_info[type];
		/*
		 * Do not memset this entry: a racing procfs swap_next()
		 * would be relying on p->type to remain valid.
		 *
		 * 不要对这个条目使用memset: 并发运行的procfs swap_next()函数会依赖于p->type保持有效.
		 */
	}
	/* 初始化 */
	INIT_LIST_HEAD(&p->first_swap_extent.list);
	plist_node_init(&p->list, 0);
	plist_node_init(&p->avail_list, 0);
	p->flags = SWP_USED;
	spin_unlock(&swap_lock);
	spin_lock_init(&p->lock);

	return p;
}

static int claim_swapfile(struct swap_info_struct *p, struct inode *inode)
{
	int error;

	/* 如果是块设备 */
	if (S_ISBLK(inode->i_mode)) {
		/* 拿到该块设备对应的block_device */
		p->bdev = bdgrab(I_BDEV(inode));
		/* blkdev_get()函数负责从gendisk中获取信息,并建立相关数据结构之间的联系 */
		error = blkdev_get(p->bdev,
				   FMODE_READ | FMODE_WRITE | FMODE_EXCL, p);
		if (error < 0) {
			p->bdev = NULL;
			return error;
		}
		/* 拿到块大小 */
		p->old_block_size = block_size(p->bdev);
		/* 设置块大小为PAGE_SIZE */
		error = set_blocksize(p->bdev, PAGE_SIZE);
		if (error < 0)
			return error;
		/* 带上SWP_BLKDEV的flag */
		p->flags |= SWP_BLKDEV;
		/* 如果是文件 */
	} else if (S_ISREG(inode->i_mode)) {
		/* 设置它为inode->i_sb->s_bdev */
		p->bdev = inode->i_sb->s_bdev;
		inode_lock(inode);
		/* (inode)->i_flags & S_SWAPFILE,如果它已经是swapfile了,那么返回-EBUSY */
		if (IS_SWAPFILE(inode))
			return -EBUSY;
	} else
		return -EINVAL;

	return 0;
}

static unsigned long read_swap_header(struct swap_info_struct *p,
					union swap_header *swap_header,
					struct inode *inode)
{
	int i;
	unsigned long maxpages;
	unsigned long swapfilepages;
	unsigned long last_page;

	/* 比较swap_header的魔数,如果不是SWAPSPACE2,那么直接return 0 */
	if (memcmp("SWAPSPACE2", swap_header->magic.magic, 10)) {
		pr_err("Unable to find swap-space signature\n");
		return 0;
	}

	/* swap partition endianess hack... */
	if (swab32(swap_header->info.version) == 1) {
		swab32s(&swap_header->info.version);
		swab32s(&swap_header->info.last_page);
		swab32s(&swap_header->info.nr_badpages);
		/* 如果坏页的数量大于MAX_SWAP_BADPAGES,那么直接返回0 */
		if (swap_header->info.nr_badpages > MAX_SWAP_BADPAGES)
			return 0;
		/* 初始化swap_header->info.badpages数组,大小为i */
		for (i = 0; i < swap_header->info.nr_badpages; i++)
			swab32s(&swap_header->info.badpages[i]);
	}
	/* Check the swap header's sub-version */
	if (swap_header->info.version != 1) {
		pr_warn("Unable to handle swap header version %d\n",
			swap_header->info.version);
		return 0;
	}

	/* 设置lowest_bit为1 */
	p->lowest_bit  = 1;
	p->cluster_next = 1;
	p->cluster_nr = 0;

	/*
	 * Find out how many pages are allowed for a single swap
	 * device. There are two limiting factors: 1) the number
	 * of bits for the swap offset in the swp_entry_t type, and
	 * 2) the number of bits in the swap pte as defined by the
	 * different architectures. In order to find the
	 * largest possible bit mask, a swap entry with swap type 0
	 * and swap offset ~0UL is created, encoded to a swap pte,
	 * decoded to a swp_entry_t again, and finally the swap
	 * offset is extracted. This will mask all the bits from
	 * the initial ~0UL mask that can't be encoded in either
	 * the swp_entry_t or the architecture definition of a
	 * swap pte.
	 *
	 * 了解单个交换设备能够支持的最大页面数时,需要考虑两个主要的限制因素:
	 * 1) 在swp_entry_t类型中用于表示交换偏移量的位数.
	 * 2) 不同体系结构(architecture)定义的交换页表项swap pte 中的位数.
	 * 为了确定可能的最大位掩码,我们可以创建一个交换条目,其交换类型设置为0,交换偏移量设置为~0UL(即无符号长整型能表示的最大值),
	 * 然后将这个交换条目编码为一个交换页表项,再将其解码回swp_entry_t类型,最后从解码后的结果中提取交换偏移量.
	 * 这个过程会屏蔽掉所有那些无法被编码到swp_entry_t或特定体系结构定义的交换页表项中的、来自初始~0UL掩码的位.
	 * 这样做的目的是找出单个交换设备能够支持的最大页面数.
	 */

	/* 这里真的非常之经典,值得阅读一下
	 * swp_entry(0, ~0UL),先用最大值,转换成common part的swp_entry_t
	 * 然后用swp_entry_to_pte转换成arch-independent的swp_entry_t,通过__swp_entry_to_pte转换成pte
	 * 然后pte_to_swp_entry把它转回来,最后拿到swp_offset就是我们arch-independent最大支持的maxpages了
	 */
	maxpages = swp_offset(pte_to_swp_entry(
			swp_entry_to_pte(swp_entry(0, ~0UL)))) + 1;
	/* 拿到swap分区的最后一页 */
	last_page = swap_header->info.last_page;
	/* 如果swap分区的最后一页大于maxpages,那么输出一行警告 */
	if (last_page > maxpages) {
		pr_warn("Truncating oversized swap area, only using %luk out of %luk\n",
			maxpages << (PAGE_SHIFT - 10),
			last_page << (PAGE_SHIFT - 10));
	}
	/* 如果maxpage > last_page,说明maxpage大于swap分区的最后一页,那总不可能超过它吧
	 * 所以就设置maxpages = last_page + 1
	 */
	if (maxpages > last_page) {
		maxpages = last_page + 1;
		/* p->max is an unsigned int: don't overflow it */
		if ((unsigned int)maxpages == 0)
			maxpages = UINT_MAX;
	}
	/* 设置swap_info_struct的highest_bit */
	p->highest_bit = maxpages - 1;

	if (!maxpages)
		return 0;
	/* 看看这个inode有多少个size 然后计算出swapfilepages */
	swapfilepages = i_size_read(inode) >> PAGE_SHIFT;
	/* 如果swapfilepages 但是maxpages > swapfilepages */
	if (swapfilepages && maxpages > swapfilepages) {
		pr_warn("Swap area shorter than signature indicates\n");
		return 0;
	}
	/* 如果有badpages 并且是原始文件,那么直接返回0 */
	if (swap_header->info.nr_badpages && S_ISREG(inode->i_mode))
		return 0;
	/* 如果坏页的数量大于MAX_SWAP_BADPAGES,那么直接返回0 */
	if (swap_header->info.nr_badpages > MAX_SWAP_BADPAGES)
		return 0;

	/* 返回最大的页数 */
	return maxpages;
}

static int setup_swap_map_and_extents(struct swap_info_struct *p,
					union swap_header *swap_header,
					unsigned char *swap_map,
					struct swap_cluster_info *cluster_info,
					unsigned long maxpages,
					sector_t *span)
{
	int i;
	unsigned int nr_good_pages;
	int nr_extents;
	/* cluster的数量 = maxpages / SWAPFILE_CLUSTER */
	unsigned long nr_clusters = DIV_ROUND_UP(maxpages, SWAPFILE_CLUSTER);
	/* 算出下一个用的cluster的index */
	unsigned long idx = p->cluster_next / SWAPFILE_CLUSTER;

	/* 设置nr_good_pages,这里排除了头页 */
	nr_good_pages = maxpages - 1;	/* omit header page */

	/* 初始化free_clusters和discard_clusters链表 */
	cluster_list_init(&p->free_clusters);
	cluster_list_init(&p->discard_clusters);

	/* 处理坏页,对每个坏页进行操作 */
	for (i = 0; i < swap_header->info.nr_badpages; i++) {
		/* 这里是拿到坏页的number号 */
		unsigned int page_nr = swap_header->info.badpages[i];
		/* 如果page_nr == 0 || 或者page_nr大于最后一页,那么就返回-EINVAL */
		if (page_nr == 0 || page_nr > swap_header->info.last_page)
			return -EINVAL;
		/* 如果page_nr < maxpages,那么设置其对应的swap_map数组项为SWAP_MAP_BAD */
		if (page_nr < maxpages) {
			swap_map[page_nr] = SWAP_MAP_BAD;
			/* nr_good_page -- */
			nr_good_pages--;
			/*
			 * Haven't marked the cluster free yet, no list
			 * operation involved
			 *
			 * 尚未将集群标记为空闲,不涉及列表操作
			 */
			/* 这里会让它的使用计数 + 1,毕竟是坏页不能用嘛 */
			inc_cluster_info_page(p, cluster_info, page_nr);
		}
	}

	/* Haven't marked the cluster free yet, no list operation involved */
	/* 这里就是填充maxpages ~ round_up(maxpages, SWAPFILE_CLUSTER)的范围里面的页相当于坏页的操作,因为这些页也不能用嘛 */
	for (i = maxpages; i < round_up(maxpages, SWAPFILE_CLUSTER); i++)
		inc_cluster_info_page(p, cluster_info, i);

	/* 如果nr_good_pages不等于0 */
	if (nr_good_pages) {
		/* 将头页设置为SWAP_MAP_BAD,因为他保存的是head的信息,也是不能用的 */
		swap_map[0] = SWAP_MAP_BAD;
		/*
		 * Not mark the cluster free yet, no list
		 * operation involved
		 */
		/* 对0 page对应的cluster_info进行操作 */
		inc_cluster_info_page(p, cluster_info, 0);
		/* 这是p->max = maxpages,这表示最大的页面数(中间包括坏页,去除了头页) */
		p->max = maxpages;
		/* 这里设置p->pages = nr_good_pages,表示出去坏页和头页,可用的页面 */
		p->pages = nr_good_pages;
		/* setup_swap_extents函数,为一段连续的pages映射到连续的磁盘快中,返回的是磁盘快的数量,
		 * 如果最先建立的是交换分区,则这里就仅仅需要一个块,
		 * 而如果对应的是磁盘文件,就需要对文件涉及的各个磁盘快分别建立结构,并关联起来.
		 */
		nr_extents = setup_swap_extents(p, span);
		if (nr_extents < 0)
			return nr_extents;
		nr_good_pages = p->pages;
	}
	/* 如果nr_good_pages为NULL,那么报一行警告之后返回-EINVAL */
	if (!nr_good_pages) {
		pr_warn("Empty swap-file\n");
		return -EINVAL;
	}

	/* 如果cluster_info = NULL,直接返回 */
	if (!cluster_info)
		return nr_extents;

	/* 否则对每个cluster进行轮询 */
	for (i = 0; i < nr_clusters; i++) {
		/* 如果里面没有坏块、或者有人用了,那么就把它放到free_clusters链表里面去 */
		if (!cluster_count(&cluster_info[idx])) {
			cluster_set_flag(&cluster_info[idx], CLUSTER_FLAG_FREE);
			cluster_list_add_tail(&p->free_clusters, cluster_info,
					      idx);
		}
		idx++;
		if (idx == nr_clusters)
			idx = 0;
	}

	return nr_extents;
}

/*
 * Helper to sys_swapon determining if a given swap
 * backing device queue supports DISCARD operations.
 */
static bool swap_discardable(struct swap_info_struct *si)
{
	struct request_queue *q = bdev_get_queue(si->bdev);

	if (!q || !blk_queue_discard(q))
		return false;

	return true;
}

SYSCALL_DEFINE2(swapon, const char __user *, specialfile, int, swap_flags)
{
	struct swap_info_struct *p;
	struct filename *name;
	struct file *swap_file = NULL;
	struct address_space *mapping;
	int prio;
	int error;
	union swap_header *swap_header;
	int nr_extents;
	sector_t span;
	unsigned long maxpages;
	unsigned char *swap_map = NULL;
	struct swap_cluster_info *cluster_info = NULL;
	unsigned long *frontswap_map = NULL;
	struct page *page = NULL;
	struct inode *inode = NULL;

	if (swap_flags & ~SWAP_FLAGS_VALID)
		return -EINVAL;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	/* 为swap_info_struct分配内存,并做局部初始化 */
	p = alloc_swap_info();
	if (IS_ERR(p))
		return PTR_ERR(p);

	/* 初始化discard_work */
	INIT_WORK(&p->discard_work, swap_discard_work);

	/* 这边将specialfile转换成filename */
	name = getname(specialfile);
	if (IS_ERR(name)) {
		error = PTR_ERR(name);
		name = NULL;
		goto bad_swap;
	}
	/* 打开文件 */
	swap_file = file_open_name(name, O_RDWR|O_LARGEFILE, 0);
	if (IS_ERR(swap_file)) {
		error = PTR_ERR(swap_file);
		swap_file = NULL;
		goto bad_swap;
	}

	/* 让p->swap_file指向该swap_file */
	p->swap_file = swap_file;
	mapping = swap_file->f_mapping;
	inode = mapping->host;

	/* If S_ISREG(inode->i_mode) will do inode_lock(inode); */
	/* 设置bdev等相关信息 */
	error = claim_swapfile(p, inode);
	if (unlikely(error))
		goto bad_swap;

	/*
	 * Read the swap header.
	 */
	/* 如果没有readpage函数,那么goto bad_swap */
	if (!mapping->a_ops->readpage) {
		error = -EINVAL;
		goto bad_swap;
	}
	/* 读第一页 */
	page = read_mapping_page(mapping, 0, swap_file);
	if (IS_ERR(page)) {
		error = PTR_ERR(page);
		goto bad_swap;
	}
	/* 映射该页 */
	swap_header = kmap(page);
	/* 这里是读取该swap分区能容纳的最大page数 */
	maxpages = read_swap_header(p, swap_header, inode);
	if (unlikely(!maxpages)) {
		error = -EINVAL;
		goto bad_swap;
	}

	/* OK, set up the swap map and apply the bad block list
	 * 好的,设置交换映射并应用坏块列表
	 */
	swap_map = vzalloc(maxpages);
	if (!swap_map) {
		error = -ENOMEM;
		goto bad_swap;
	}

	/* 如果backing_dev支持稳定的写操作,那么设置p->flags |= SWP_STABLE_WRITES */
	if (bdi_cap_stable_pages_required(inode_to_bdi(inode)))
		p->flags |= SWP_STABLE_WRITES;

	/* #define QUEUE_FLAG_NONROT      12 non-rotational device (SSD)
	 * 如果说这个blk队列是非旋转设备(SSD) */
	if (p->bdev && blk_queue_nonrot(bdev_get_queue(p->bdev))) {
		int cpu;

		/* 带上SWP_SOLIDSTATE 表示blkdev寻道是非常廉价的 */
		p->flags |= SWP_SOLIDSTATE;
		/*
		 * select a random position to start with to help wear leveling
		 * SSD
		 *
		 * 选择一个随机位置开始,以帮助平衡SSD的磨损
		 */

		/* 这边就是选一个随机位置 */
		p->cluster_next = 1 + (prandom_u32() % p->highest_bit);

		/* 这里分配cluster_info,大小为 maxpages / SWAPFILE_CLUSTER * sizeof(*cluster_info) */
		cluster_info = vzalloc(DIV_ROUND_UP(maxpages,
			SWAPFILE_CLUSTER) * sizeof(*cluster_info));
		/* 如果没有分配到内存,那么就返回-ENOMEM */
		if (!cluster_info) {
			error = -ENOMEM;
			goto bad_swap;
		}
		/* 为每个CPU分配给一个独立的集群(cluster),可以使每个CPU能够从其自己的集群中分配交换条目,并按顺序进行交换出操作. */
		p->percpu_cluster = alloc_percpu(struct percpu_cluster);
		if (!p->percpu_cluster) {
			error = -ENOMEM;
			goto bad_swap;
		}
		for_each_possible_cpu(cpu) {
			struct percpu_cluster *cluster;
			cluster = per_cpu_ptr(p->percpu_cluster, cpu);
			/* 这里就是初始化cluster
			 *
			 * info->flags = CLUSTER_FLAG_NEXT_NULL;
			 * info->data = 0;
			 */
			cluster_set_null(&cluster->index);
		}
	}

	error = swap_cgroup_swapon(p->type, maxpages);
	if (error)
		goto bad_swap;

	/* 初始化swap_info_struct结构和建立swap_extent链表 */
	nr_extents = setup_swap_map_and_extents(p, swap_header, swap_map,
		cluster_info, maxpages, &span);
	if (unlikely(nr_extents < 0)) {
		error = nr_extents;
		goto bad_swap;
	}
	/* frontswap enabled? set up bit-per-page map for frontswap */
	/*
	 * Frontswap之所以如此命名,是因为它可以被视为交换设备的“背后存储”的反义词.
	 * 数据被存储在“超越性内存”中,这是一种内存,内核无法直接访问或寻址,其大小可能是未知的,并且可能随时间变化.
	 * 当超越性内存中有空间可用时,可以显著减少交换I/O操作.
	 * 当没有可用空间时,所有的frontswap调用都会被简化为单个指针与NULL比较,这几乎不会对性能产生影响,并且交换数据会像通常一样存储在匹配的交换设备上.
	 */

	/* 分配位图 */
	if (IS_ENABLED(CONFIG_FRONTSWAP))
		frontswap_map = vzalloc(BITS_TO_LONGS(maxpages) * sizeof(long));

	/* 如果p->bdev有东西并且swap有discard(丢弃)并且block 队列也有丢弃的功能 */
	if (p->bdev &&(swap_flags & SWAP_FLAG_DISCARD) && swap_discardable(p)) {
		/*
		 * When discard is enabled for swap with no particular
		 * policy flagged, we set all swap discard flags here in
		 * order to sustain backward compatibility with older
		 * swapon(8) releases.
		 *
		 * 当为swap启用了丢弃(discard),且没有特定的策略标志时,我们在这里设置所有的交换丢弃标志,以保持与旧版swapon(8)的向后兼容性
		 */
		p->flags |= (SWP_DISCARDABLE | SWP_AREA_DISCARD |
			     SWP_PAGE_DISCARD);

		/*
		 * By flagging sys_swapon, a sysadmin can tell us to
		 * either do single-time area discards only, or to just
		 * perform discards for released swap page-clusters.
		 * Now it's time to adjust the p->flags accordingly.
		 *
		 * 通过标记sys_swapon,系统管理员可以指示我们仅执行单次区域丢弃操作,或者仅对已释放的交换页簇执行丢弃操作.
		 * 现在,是时候根据这些指示相应地调整p->flags了
		 */
		if (swap_flags & SWAP_FLAG_DISCARD_ONCE)
			p->flags &= ~SWP_PAGE_DISCARD;
		else if (swap_flags & SWAP_FLAG_DISCARD_PAGES)
			p->flags &= ~SWP_AREA_DISCARD;

		/* issue a swapon-time discard if it's still required */
		if (p->flags & SWP_AREA_DISCARD) {
			int err = discard_swap(p);
			if (unlikely(err))
				pr_err("swapon: discard_swap(%p): %d\n",
					p, err);
		}
	}

	mutex_lock(&swapon_mutex);
	/* 设置优先级为-1 */
	prio = -1;
	if (swap_flags & SWAP_FLAG_PREFER)
		prio =
		  (swap_flags & SWAP_FLAG_PRIO_MASK) >> SWAP_FLAG_PRIO_SHIFT;
	enable_swap_info(p, prio, swap_map, cluster_info, frontswap_map);

	pr_info("Adding %uk swap on %s.  Priority:%d extents:%d across:%lluk %s%s%s%s%s\n",
		p->pages<<(PAGE_SHIFT-10), name->name, p->prio,
		nr_extents, (unsigned long long)span<<(PAGE_SHIFT-10),
		(p->flags & SWP_SOLIDSTATE) ? "SS" : "",
		(p->flags & SWP_DISCARDABLE) ? "D" : "",
		(p->flags & SWP_AREA_DISCARD) ? "s" : "",
		(p->flags & SWP_PAGE_DISCARD) ? "c" : "",
		(frontswap_map) ? "FS" : "");

	mutex_unlock(&swapon_mutex);
	atomic_inc(&proc_poll_event);
	wake_up_interruptible(&proc_poll_wait);

	if (S_ISREG(inode->i_mode))
		inode->i_flags |= S_SWAPFILE;
	error = 0;
	goto out;
bad_swap:
	free_percpu(p->percpu_cluster);
	p->percpu_cluster = NULL;
	if (inode && S_ISBLK(inode->i_mode) && p->bdev) {
		set_blocksize(p->bdev, p->old_block_size);
		blkdev_put(p->bdev, FMODE_READ | FMODE_WRITE | FMODE_EXCL);
	}
	destroy_swap_extents(p);
	swap_cgroup_swapoff(p->type);
	spin_lock(&swap_lock);
	p->swap_file = NULL;
	p->flags = 0;
	spin_unlock(&swap_lock);
	vfree(swap_map);
	vfree(cluster_info);
	if (swap_file) {
		if (inode && S_ISREG(inode->i_mode)) {
			inode_unlock(inode);
			inode = NULL;
		}
		filp_close(swap_file, NULL);
	}
out:
	if (page && !IS_ERR(page)) {
		kunmap(page);
		put_page(page);
	}
	if (name)
		putname(name);
	if (inode && S_ISREG(inode->i_mode))
		inode_unlock(inode);
	return error;
}

void si_swapinfo(struct sysinfo *val)
{
	unsigned int type;
	unsigned long nr_to_be_unused = 0;

	spin_lock(&swap_lock);
	for (type = 0; type < nr_swapfiles; type++) {
		struct swap_info_struct *si = swap_info[type];

		if ((si->flags & SWP_USED) && !(si->flags & SWP_WRITEOK))
			nr_to_be_unused += si->inuse_pages;
	}
	val->freeswap = atomic_long_read(&nr_swap_pages) + nr_to_be_unused;
	val->totalswap = total_swap_pages + nr_to_be_unused;
	spin_unlock(&swap_lock);
}

/*
 * Verify that a swap entry is valid and increment its swap map count.
 *
 * Returns error code in following case.
 * - success -> 0
 * - swp_entry is invalid -> EINVAL
 * - swp_entry is migration entry -> EINVAL
 * - swap-cache reference is requested but there is already one. -> EEXIST
 * - swap-cache reference is requested but the entry is not used. -> ENOENT
 * - swap-mapped reference requested but needs continued swap count. -> ENOMEM
 */
static int __swap_duplicate(swp_entry_t entry, unsigned char usage)
{
	struct swap_info_struct *p;
	unsigned long offset, type;
	unsigned char count;
	unsigned char has_cache;
	int err = -EINVAL;

	if (non_swap_entry(entry))
		goto out;

	type = swp_type(entry);
	if (type >= nr_swapfiles)
		goto bad_file;
	p = swap_info[type];
	offset = swp_offset(entry);

	spin_lock(&p->lock);
	if (unlikely(offset >= p->max))
		goto unlock_out;

	count = p->swap_map[offset];

	/*
	 * swapin_readahead() doesn't check if a swap entry is valid, so the
	 * swap entry could be SWAP_MAP_BAD. Check here with lock held.
	 */
	if (unlikely(swap_count(count) == SWAP_MAP_BAD)) {
		err = -ENOENT;
		goto unlock_out;
	}

	has_cache = count & SWAP_HAS_CACHE;
	count &= ~SWAP_HAS_CACHE;
	err = 0;

	if (usage == SWAP_HAS_CACHE) {

		/* set SWAP_HAS_CACHE if there is no cache and entry is used */
		if (!has_cache && count)
			has_cache = SWAP_HAS_CACHE;
		else if (has_cache)		/* someone else added cache */
			err = -EEXIST;
		else				/* no users remaining */
			err = -ENOENT;

	} else if (count || has_cache) {

		if ((count & ~COUNT_CONTINUED) < SWAP_MAP_MAX)
			count += usage;
		else if ((count & ~COUNT_CONTINUED) > SWAP_MAP_MAX)
			err = -EINVAL;
		else if (swap_count_continued(p, offset, count))
			count = COUNT_CONTINUED;
		else
			err = -ENOMEM;
	} else
		err = -ENOENT;			/* unused swap entry */

	p->swap_map[offset] = count | has_cache;

unlock_out:
	spin_unlock(&p->lock);
out:
	return err;

bad_file:
	pr_err("swap_dup: %s%08lx\n", Bad_file, entry.val);
	goto out;
}

/*
 * Help swapoff by noting that swap entry belongs to shmem/tmpfs
 * (in which case its reference count is never incremented).
 */
void swap_shmem_alloc(swp_entry_t entry)
{
	__swap_duplicate(entry, SWAP_MAP_SHMEM);
}

/*
 * Increase reference count of swap entry by 1.
 * Returns 0 for success, or -ENOMEM if a swap_count_continuation is required
 * but could not be atomically allocated.  Returns 0, just as if it succeeded,
 * if __swap_duplicate() fails for another reason (-EINVAL or -ENOENT), which
 * might occur if a page table entry has got corrupted.
 */
int swap_duplicate(swp_entry_t entry)
{
	int err = 0;

	while (!err && __swap_duplicate(entry, 1) == -ENOMEM)
		err = add_swap_count_continuation(entry, GFP_ATOMIC);
	return err;
}

/*
 * @entry: swap entry for which we allocate swap cache.
 *
 * Called when allocating swap cache for existing swap entry,
 * This can return error codes. Returns 0 at success.
 * -EBUSY means there is a swap cache.
 * Note: return code is different from swap_duplicate().
 */
int swapcache_prepare(swp_entry_t entry)
{
	return __swap_duplicate(entry, SWAP_HAS_CACHE);
}

struct swap_info_struct *page_swap_info(struct page *page)
{
	swp_entry_t swap = { .val = page_private(page) };
	return swap_info[swp_type(swap)];
}

/*
 * out-of-line __page_file_ methods to avoid include hell.
 */
struct address_space *__page_file_mapping(struct page *page)
{
	VM_BUG_ON_PAGE(!PageSwapCache(page), page);
	return page_swap_info(page)->swap_file->f_mapping;
}
EXPORT_SYMBOL_GPL(__page_file_mapping);

pgoff_t __page_file_index(struct page *page)
{
	swp_entry_t swap = { .val = page_private(page) };
	VM_BUG_ON_PAGE(!PageSwapCache(page), page);
	return swp_offset(swap);
}
EXPORT_SYMBOL_GPL(__page_file_index);

/*
 * add_swap_count_continuation - called when a swap count is duplicated
 * beyond SWAP_MAP_MAX, it allocates a new page and links that to the entry's
 * page of the original vmalloc'ed swap_map, to hold the continuation count
 * (for that entry and for its neighbouring PAGE_SIZE swap entries).  Called
 * again when count is duplicated beyond SWAP_MAP_MAX * SWAP_CONT_MAX, etc.
 *
 * These continuation pages are seldom referenced: the common paths all work
 * on the original swap_map, only referring to a continuation page when the
 * low "digit" of a count is incremented or decremented through SWAP_MAP_MAX.
 *
 * add_swap_count_continuation(, GFP_ATOMIC) can be called while holding
 * page table locks; if it fails, add_swap_count_continuation(, GFP_KERNEL)
 * can be called after dropping locks.
 */
int add_swap_count_continuation(swp_entry_t entry, gfp_t gfp_mask)
{
	struct swap_info_struct *si;
	struct page *head;
	struct page *page;
	struct page *list_page;
	pgoff_t offset;
	unsigned char count;

	/*
	 * When debugging, it's easier to use __GFP_ZERO here; but it's better
	 * for latency not to zero a page while GFP_ATOMIC and holding locks.
	 */
	page = alloc_page(gfp_mask | __GFP_HIGHMEM);

	si = swap_info_get(entry);
	if (!si) {
		/*
		 * An acceptable race has occurred since the failing
		 * __swap_duplicate(): the swap entry has been freed,
		 * perhaps even the whole swap_map cleared for swapoff.
		 */
		goto outer;
	}

	offset = swp_offset(entry);
	count = si->swap_map[offset] & ~SWAP_HAS_CACHE;

	if ((count & ~COUNT_CONTINUED) != SWAP_MAP_MAX) {
		/*
		 * The higher the swap count, the more likely it is that tasks
		 * will race to add swap count continuation: we need to avoid
		 * over-provisioning.
		 */
		goto out;
	}

	if (!page) {
		spin_unlock(&si->lock);
		return -ENOMEM;
	}

	/*
	 * We are fortunate that although vmalloc_to_page uses pte_offset_map,
	 * no architecture is using highmem pages for kernel page tables: so it
	 * will not corrupt the GFP_ATOMIC caller's atomic page table kmaps.
	 */
	head = vmalloc_to_page(si->swap_map + offset);
	offset &= ~PAGE_MASK;

	/*
	 * Page allocation does not initialize the page's lru field,
	 * but it does always reset its private field.
	 */
	if (!page_private(head)) {
		BUG_ON(count & COUNT_CONTINUED);
		INIT_LIST_HEAD(&head->lru);
		set_page_private(head, SWP_CONTINUED);
		si->flags |= SWP_CONTINUED;
	}

	list_for_each_entry(list_page, &head->lru, lru) {
		unsigned char *map;

		/*
		 * If the previous map said no continuation, but we've found
		 * a continuation page, free our allocation and use this one.
		 */
		if (!(count & COUNT_CONTINUED))
			goto out;

		map = kmap_atomic(list_page) + offset;
		count = *map;
		kunmap_atomic(map);

		/*
		 * If this continuation count now has some space in it,
		 * free our allocation and use this one.
		 */
		if ((count & ~COUNT_CONTINUED) != SWAP_CONT_MAX)
			goto out;
	}

	list_add_tail(&page->lru, &head->lru);
	page = NULL;			/* now it's attached, don't free it */
out:
	spin_unlock(&si->lock);
outer:
	if (page)
		__free_page(page);
	return 0;
}

/*
 * swap_count_continued - when the original swap_map count is incremented
 * from SWAP_MAP_MAX, check if there is already a continuation page to carry
 * into, carry if so, or else fail until a new continuation page is allocated;
 * when the original swap_map count is decremented from 0 with continuation,
 * borrow from the continuation and report whether it still holds more.
 * Called while __swap_duplicate() or swap_entry_free() holds swap_lock.
 */
static bool swap_count_continued(struct swap_info_struct *si,
				 pgoff_t offset, unsigned char count)
{
	struct page *head;
	struct page *page;
	unsigned char *map;

	head = vmalloc_to_page(si->swap_map + offset);
	if (page_private(head) != SWP_CONTINUED) {
		BUG_ON(count & COUNT_CONTINUED);
		return false;		/* need to add count continuation */
	}

	offset &= ~PAGE_MASK;
	page = list_entry(head->lru.next, struct page, lru);
	map = kmap_atomic(page) + offset;

	if (count == SWAP_MAP_MAX)	/* initial increment from swap_map */
		goto init_map;		/* jump over SWAP_CONT_MAX checks */

	if (count == (SWAP_MAP_MAX | COUNT_CONTINUED)) { /* incrementing */
		/*
		 * Think of how you add 1 to 999
		 */
		while (*map == (SWAP_CONT_MAX | COUNT_CONTINUED)) {
			kunmap_atomic(map);
			page = list_entry(page->lru.next, struct page, lru);
			BUG_ON(page == head);
			map = kmap_atomic(page) + offset;
		}
		if (*map == SWAP_CONT_MAX) {
			kunmap_atomic(map);
			page = list_entry(page->lru.next, struct page, lru);
			if (page == head)
				return false;	/* add count continuation */
			map = kmap_atomic(page) + offset;
init_map:		*map = 0;		/* we didn't zero the page */
		}
		*map += 1;
		kunmap_atomic(map);
		page = list_entry(page->lru.prev, struct page, lru);
		while (page != head) {
			map = kmap_atomic(page) + offset;
			*map = COUNT_CONTINUED;
			kunmap_atomic(map);
			page = list_entry(page->lru.prev, struct page, lru);
		}
		return true;			/* incremented */

	} else {				/* decrementing */
		/*
		 * Think of how you subtract 1 from 1000
		 */
		BUG_ON(count != COUNT_CONTINUED);
		while (*map == COUNT_CONTINUED) {
			kunmap_atomic(map);
			page = list_entry(page->lru.next, struct page, lru);
			BUG_ON(page == head);
			map = kmap_atomic(page) + offset;
		}
		BUG_ON(*map == 0);
		*map -= 1;
		if (*map == 0)
			count = 0;
		kunmap_atomic(map);
		page = list_entry(page->lru.prev, struct page, lru);
		while (page != head) {
			map = kmap_atomic(page) + offset;
			*map = SWAP_CONT_MAX | count;
			count = COUNT_CONTINUED;
			kunmap_atomic(map);
			page = list_entry(page->lru.prev, struct page, lru);
		}
		return count == COUNT_CONTINUED;
	}
}

/*
 * free_swap_count_continuations - swapoff free all the continuation pages
 * appended to the swap_map, after swap_map is quiesced, before vfree'ing it.
 */
static void free_swap_count_continuations(struct swap_info_struct *si)
{
	pgoff_t offset;

	for (offset = 0; offset < si->max; offset += PAGE_SIZE) {
		struct page *head;
		head = vmalloc_to_page(si->swap_map + offset);
		if (page_private(head)) {
			struct page *page, *next;

			list_for_each_entry_safe(page, next, &head->lru, lru) {
				list_del(&page->lru);
				__free_page(page);
			}
		}
	}
}
