/*
 *  linux/mm/vmscan.c
 *
 *  Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 *
 *  Swap reorganised 29.12.95, Stephen Tweedie.
 *  kswapd added: 7.1.96  sct
 *  Removed kswapd_ctl limits, and swap out as many pages as needed
 *  to bring the system back to freepages.high: 2.4.97, Rik van Riel.
 *  Zone aware kswapd started 02/00, Kanoj Sarcar (kanoj@sgi.com).
 *  Multiqueue VM started 5.8.00, Rik van Riel.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/mm.h>
#include <linux/module.h>
#include <linux/gfp.h>
#include <linux/kernel_stat.h>
#include <linux/swap.h>
#include <linux/pagemap.h>
#include <linux/init.h>
#include <linux/highmem.h>
#include <linux/vmpressure.h>
#include <linux/vmstat.h>
#include <linux/file.h>
#include <linux/writeback.h>
#include <linux/blkdev.h>
#include <linux/buffer_head.h>	/* for try_to_release_page(),
					buffer_heads_over_limit */
#include <linux/mm_inline.h>
#include <linux/backing-dev.h>
#include <linux/rmap.h>
#include <linux/topology.h>
#include <linux/cpu.h>
#include <linux/cpuset.h>
#include <linux/compaction.h>
#include <linux/notifier.h>
#include <linux/rwsem.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/freezer.h>
#include <linux/memcontrol.h>
#include <linux/delayacct.h>
#include <linux/sysctl.h>
#include <linux/oom.h>
#include <linux/prefetch.h>
#include <linux/printk.h>
#include <linux/dax.h>

#include <asm/tlbflush.h>
#include <asm/div64.h>

#include <linux/swapops.h>
#include <linux/balloon_compaction.h>

#include "internal.h"

#define CREATE_TRACE_POINTS
#include <trace/events/vmscan.h>

struct scan_control {
	/* How many pages shrink_list() should reclaim */
	/* 要回收的页面数量 */
	unsigned long nr_to_reclaim;

	/* This context's GFP mask */
	/*  内存分配掩码 */
	gfp_t gfp_mask;

	/* Allocation order */
	/* 页面分配的数量 */
	int order;

	/*
	 * Nodemask of nodes allowed by the caller. If NULL, all nodes
	 * are scanned.
	 */
	/* 内存节点掩码 */
	nodemask_t	*nodemask;

	/*
	 * The memory cgroup that hit its limit and as a result is the
	 * primary target of this reclaim invocation.
	 */
	struct mem_cgroup *target_mem_cgroup;

	/* Scan (total_size >> priority) pages at once */
	/* 页面扫描粒度 */
	int priority;

	/* The highest zone to isolate pages for reclaim from */
	/* 最高允许页面回收的zone */
	enum zone_type reclaim_idx;

	/* 是否能够进行回写操作(与分配标志的__GFP_IO和__GFP_FS有关) */
	unsigned int may_writepage:1;

	/* Can mapped pages be reclaimed? */
	/* 能否进行unmap操作，就是将所有映射了此页的页表项清空 */
	unsigned int may_unmap:1;

	/* Can pages be swapped as part of reclaim? */
	/* 是否能够进行swap交换，如果不能，在内存回收时则不扫描匿名页lru链表 */
	unsigned int may_swap:1;

	/* Can cgroups be reclaimed below their normal consumption range? */
	/* cgroups是否可以在低于其正常消耗范围的情况下回收？*/
	unsigned int may_thrash:1;

	unsigned int hibernation_mode:1;

	/* One of the zones is ready for compaction */
	/* 扫描结束后会标记，用于内存回收判断是否需要进行内存压缩 */
	unsigned int compaction_ready:1;

	/* Incremented by the number of inactive pages that were scanned */
	/* 按扫描的非活动页面数递增 */
	unsigned long nr_scanned;

	/* Number of pages freed so far during a call to shrink_zones() */
	/* 调用shrink_zones()期间到目前为止释放的页数 */
	unsigned long nr_reclaimed;
};

#ifdef ARCH_HAS_PREFETCH
#define prefetch_prev_lru_page(_page, _base, _field)			\
	do {								\
		if ((_page)->lru.prev != _base) {			\
			struct page *prev;				\
									\
			prev = lru_to_page(&(_page->lru));		\
			prefetch(&prev->_field);			\
		}							\
	} while (0)
#else
#define prefetch_prev_lru_page(_page, _base, _field) do { } while (0)
#endif

#ifdef ARCH_HAS_PREFETCHW
#define prefetchw_prev_lru_page(_page, _base, _field)			\
	do {								\
		if ((_page)->lru.prev != _base) {			\
			struct page *prev;				\
									\
			prev = lru_to_page(&(_page->lru));		\
			prefetchw(&prev->_field);			\
		}							\
	} while (0)
#else
#define prefetchw_prev_lru_page(_page, _base, _field) do { } while (0)
#endif

/*
 * From 0 .. 100.  Higher means more swappy.
 */
int vm_swappiness = 60;
/*
 * The total number of pages which are beyond the high watermark within all
 * zones.
 */
unsigned long vm_total_pages;

static LIST_HEAD(shrinker_list);
static DECLARE_RWSEM(shrinker_rwsem);

#ifdef CONFIG_MEMCG
static bool global_reclaim(struct scan_control *sc)
{
	return !sc->target_mem_cgroup;
}

/**
 * sane_reclaim - is the usual dirty throttling mechanism operational?
 * @sc: scan_control in question
 *
 * The normal page dirty throttling mechanism in balance_dirty_pages() is
 * completely broken with the legacy memcg and direct stalling in
 * shrink_page_list() is used for throttling instead, which lacks all the
 * niceties such as fairness, adaptive pausing, bandwidth proportional
 * allocation and configurability.
 *
 * This function tests whether the vmscan currently in progress can assume
 * that the normal dirty throttling mechanism is operational.
 */
static bool sane_reclaim(struct scan_control *sc)
{
	struct mem_cgroup *memcg = sc->target_mem_cgroup;

	if (!memcg)
		return true;
#ifdef CONFIG_CGROUP_WRITEBACK
	if (cgroup_subsys_on_dfl(memory_cgrp_subsys))
		return true;
#endif
	return false;
}
#else
static bool global_reclaim(struct scan_control *sc)
{
	return true;
}

static bool sane_reclaim(struct scan_control *sc)
{
	return true;
}
#endif

/*
 * This misses isolated pages which are not accounted for to save counters.
 * As the data only determines if reclaim or compaction continues, it is
 * not expected that isolated pages will be a dominating factor.
 */
unsigned long zone_reclaimable_pages(struct zone *zone)
{
	unsigned long nr;

	nr = zone_page_state_snapshot(zone, NR_ZONE_INACTIVE_FILE) +
		zone_page_state_snapshot(zone, NR_ZONE_ACTIVE_FILE);
	if (get_nr_swap_pages() > 0)
		nr += zone_page_state_snapshot(zone, NR_ZONE_INACTIVE_ANON) +
			zone_page_state_snapshot(zone, NR_ZONE_ACTIVE_ANON);

	return nr;
}

unsigned long pgdat_reclaimable_pages(struct pglist_data *pgdat)
{
	unsigned long nr;

	nr = node_page_state_snapshot(pgdat, NR_ACTIVE_FILE) +
	     node_page_state_snapshot(pgdat, NR_INACTIVE_FILE) +
	     node_page_state_snapshot(pgdat, NR_ISOLATED_FILE);

	if (get_nr_swap_pages() > 0)
		nr += node_page_state_snapshot(pgdat, NR_ACTIVE_ANON) +
		      node_page_state_snapshot(pgdat, NR_INACTIVE_ANON) +
		      node_page_state_snapshot(pgdat, NR_ISOLATED_ANON);

	return nr;
}

bool pgdat_reclaimable(struct pglist_data *pgdat)
{
	/* 扫描的数量 < 可回收的六倍? */
	return node_page_state_snapshot(pgdat, NR_PAGES_SCANNED) <
		pgdat_reclaimable_pages(pgdat) * 6;
}

/**
 * lruvec_lru_size -  Returns the number of pages on the given LRU list.
 * @lruvec: lru vector
 * @lru: lru to use
 * @zone_idx: zones to consider (use MAX_NR_ZONES for the whole LRU list)
 */
unsigned long lruvec_lru_size(struct lruvec *lruvec, enum lru_list lru, int zone_idx)
{
	unsigned long lru_size;
	int zid;
	/* 获得整个node的lru的数量 */
	if (!mem_cgroup_disabled())
		lru_size = mem_cgroup_get_lru_size(lruvec, lru);
	else
		lru_size = node_page_state(lruvec_pgdat(lruvec), NR_LRU_BASE + lru);

	for (zid = zone_idx + 1; zid < MAX_NR_ZONES; zid++) {
		struct zone *zone = &lruvec_pgdat(lruvec)->node_zones[zid];
		unsigned long size;

		if (!managed_zone(zone))
			continue;
		/* 这里就是减去它上面的lru链表数量
		 * 比如你这里如果是normal的话就减去了high
		 * 但是你还包括了DMA这些的
		 */
		if (!mem_cgroup_disabled())
			size = mem_cgroup_get_zone_lru_size(lruvec, lru, zid);
		else
			size = zone_page_state(&lruvec_pgdat(lruvec)->node_zones[zid],
				       NR_ZONE_LRU_BASE + lru);
		lru_size -= min(size, lru_size);
	}

	return lru_size;

}

/*
 * Add a shrinker callback to be called from the vm.
 */
int register_shrinker(struct shrinker *shrinker)
{
	size_t size = sizeof(*shrinker->nr_deferred);

	if (shrinker->flags & SHRINKER_NUMA_AWARE)
		size *= nr_node_ids;

	shrinker->nr_deferred = kzalloc(size, GFP_KERNEL);
	if (!shrinker->nr_deferred)
		return -ENOMEM;

	down_write(&shrinker_rwsem);
	list_add_tail(&shrinker->list, &shrinker_list);
	up_write(&shrinker_rwsem);
	return 0;
}
EXPORT_SYMBOL(register_shrinker);

/*
 * Remove one
 */
void unregister_shrinker(struct shrinker *shrinker)
{
	down_write(&shrinker_rwsem);
	list_del(&shrinker->list);
	up_write(&shrinker_rwsem);
	kfree(shrinker->nr_deferred);
}
EXPORT_SYMBOL(unregister_shrinker);

#define SHRINK_BATCH 128

static unsigned long do_shrink_slab(struct shrink_control *shrinkctl,
				    struct shrinker *shrinker,
				    unsigned long nr_scanned,
				    unsigned long nr_eligible)
{
	unsigned long freed = 0;
	unsigned long long delta;
	long total_scan;
	long freeable;
	long nr;
	long new_nr;
	int nid = shrinkctl->nid;
	long batch_size = shrinker->batch ? shrinker->batch
					  : SHRINK_BATCH;
	long scanned = 0, next_deferred;

	freeable = shrinker->count_objects(shrinker, shrinkctl);
	if (freeable == 0)
		return 0;

	/*
	 * copy the current shrinker scan count into a local variable
	 * and zero it so that other concurrent shrinker invocations
	 * don't also do this scanning work.
	 */
	nr = atomic_long_xchg(&shrinker->nr_deferred[nid], 0);

	total_scan = nr;
	delta = (4 * nr_scanned) / shrinker->seeks;
	delta *= freeable;
	do_div(delta, nr_eligible + 1);
	total_scan += delta;
	if (total_scan < 0) {
		pr_err("shrink_slab: %pF negative objects to delete nr=%ld\n",
		       shrinker->scan_objects, total_scan);
		total_scan = freeable;
		next_deferred = nr;
	} else
		next_deferred = total_scan;

	/*
	 * We need to avoid excessive windup on filesystem shrinkers
	 * due to large numbers of GFP_NOFS allocations causing the
	 * shrinkers to return -1 all the time. This results in a large
	 * nr being built up so when a shrink that can do some work
	 * comes along it empties the entire cache due to nr >>>
	 * freeable. This is bad for sustaining a working set in
	 * memory.
	 *
	 * Hence only allow the shrinker to scan the entire cache when
	 * a large delta change is calculated directly.
	 */
	if (delta < freeable / 4)
		total_scan = min(total_scan, freeable / 2);

	/*
	 * Avoid risking looping forever due to too large nr value:
	 * never try to free more than twice the estimate number of
	 * freeable entries.
	 */
	if (total_scan > freeable * 2)
		total_scan = freeable * 2;

	trace_mm_shrink_slab_start(shrinker, shrinkctl, nr,
				   nr_scanned, nr_eligible,
				   freeable, delta, total_scan);

	/*
	 * Normally, we should not scan less than batch_size objects in one
	 * pass to avoid too frequent shrinker calls, but if the slab has less
	 * than batch_size objects in total and we are really tight on memory,
	 * we will try to reclaim all available objects, otherwise we can end
	 * up failing allocations although there are plenty of reclaimable
	 * objects spread over several slabs with usage less than the
	 * batch_size.
	 *
	 * We detect the "tight on memory" situations by looking at the total
	 * number of objects we want to scan (total_scan). If it is greater
	 * than the total number of objects on slab (freeable), we must be
	 * scanning at high prio and therefore should try to reclaim as much as
	 * possible.
	 */
	while (total_scan >= batch_size ||
	       total_scan >= freeable) {
		unsigned long ret;
		unsigned long nr_to_scan = min(batch_size, total_scan);

		shrinkctl->nr_to_scan = nr_to_scan;
		ret = shrinker->scan_objects(shrinker, shrinkctl);
		if (ret == SHRINK_STOP)
			break;
		freed += ret;

		count_vm_events(SLABS_SCANNED, nr_to_scan);
		total_scan -= nr_to_scan;
		scanned += nr_to_scan;

		cond_resched();
	}

	if (next_deferred >= scanned)
		next_deferred -= scanned;
	else
		next_deferred = 0;
	/*
	 * move the unused scan count back into the shrinker in a
	 * manner that handles concurrent updates. If we exhausted the
	 * scan, there is no need to do an update.
	 */
	if (next_deferred > 0)
		new_nr = atomic_long_add_return(next_deferred,
						&shrinker->nr_deferred[nid]);
	else
		new_nr = atomic_long_read(&shrinker->nr_deferred[nid]);

	trace_mm_shrink_slab_end(shrinker, nid, freed, nr, new_nr, total_scan);
	return freed;
}

/**
 * shrink_slab - shrink slab caches
 * @gfp_mask: allocation context
 * @nid: node whose slab caches to target
 * @memcg: memory cgroup whose slab caches to target
 * @nr_scanned: pressure numerator
 * @nr_eligible: pressure denominator
 *
 * Call the shrink functions to age shrinkable caches.
 *
 * @nid is passed along to shrinkers with SHRINKER_NUMA_AWARE set,
 * unaware shrinkers will receive a node id of 0 instead.
 *
 * @memcg specifies the memory cgroup to target. If it is not NULL,
 * only shrinkers with SHRINKER_MEMCG_AWARE set will be called to scan
 * objects from the memory cgroup specified. Otherwise, only unaware
 * shrinkers are called.
 *
 * @nr_scanned and @nr_eligible form a ratio that indicate how much of
 * the available objects should be scanned.  Page reclaim for example
 * passes the number of pages scanned and the number of pages on the
 * LRU lists that it considered on @nid, plus a bias in @nr_scanned
 * when it encountered mapped pages.  The ratio is further biased by
 * the ->seeks setting of the shrink function, which indicates the
 * cost to recreate an object relative to that of an LRU page.
 *
 * Returns the number of reclaimed slab objects.
 */
static unsigned long shrink_slab(gfp_t gfp_mask, int nid,
				 struct mem_cgroup *memcg,
				 unsigned long nr_scanned,
				 unsigned long nr_eligible)
{
	struct shrinker *shrinker;
	unsigned long freed = 0;

	if (memcg && (!memcg_kmem_enabled() || !mem_cgroup_online(memcg)))
		return 0;

	if (nr_scanned == 0)
		nr_scanned = SWAP_CLUSTER_MAX;

	if (!down_read_trylock(&shrinker_rwsem)) {
		/*
		 * If we would return 0, our callers would understand that we
		 * have nothing else to shrink and give up trying. By returning
		 * 1 we keep it going and assume we'll be able to shrink next
		 * time.
		 */
		freed = 1;
		goto out;
	}

	list_for_each_entry(shrinker, &shrinker_list, list) {
		struct shrink_control sc = {
			.gfp_mask = gfp_mask,
			.nid = nid,
			.memcg = memcg,
		};

		/*
		 * If kernel memory accounting is disabled, we ignore
		 * SHRINKER_MEMCG_AWARE flag and call all shrinkers
		 * passing NULL for memcg.
		 */
		if (memcg_kmem_enabled() &&
		    !!memcg != !!(shrinker->flags & SHRINKER_MEMCG_AWARE))
			continue;

		if (!(shrinker->flags & SHRINKER_NUMA_AWARE))
			sc.nid = 0;

		freed += do_shrink_slab(&sc, shrinker, nr_scanned, nr_eligible);
	}

	up_read(&shrinker_rwsem);
out:
	cond_resched();
	return freed;
}

void drop_slab_node(int nid)
{
	unsigned long freed;

	do {
		struct mem_cgroup *memcg = NULL;

		freed = 0;
		do {
			freed += shrink_slab(GFP_KERNEL, nid, memcg,
					     1000, 1000);
		} while ((memcg = mem_cgroup_iter(NULL, memcg, NULL)) != NULL);
	} while (freed > 10);
}

void drop_slab(void)
{
	int nid;

	for_each_online_node(nid)
		drop_slab_node(nid);
}

static inline int is_page_cache_freeable(struct page *page)
{
	/*
	 * A freeable page cache page is referenced only by the caller
	 * that isolated the page, the page cache radix tree and
	 * optional buffer heads at page->private.
	 */
	return page_count(page) - page_has_private(page) == 2;
}

static int may_write_to_inode(struct inode *inode, struct scan_control *sc)
{
	if (current->flags & PF_SWAPWRITE)
		return 1;
	if (!inode_write_congested(inode))
		return 1;
	if (inode_to_bdi(inode) == current->backing_dev_info)
		return 1;
	return 0;
}

/*
 * We detected a synchronous write error writing a page out.  Probably
 * -ENOSPC.  We need to propagate that into the address_space for a subsequent
 * fsync(), msync() or close().
 *
 * The tricky part is that after writepage we cannot touch the mapping: nothing
 * prevents it from being freed up.  But we have a ref on the page and once
 * that page is locked, the mapping is pinned.
 *
 * We're allowed to run sleeping lock_page() here because we know the caller has
 * __GFP_FS.
 */
static void handle_write_error(struct address_space *mapping,
				struct page *page, int error)
{
	lock_page(page);
	if (page_mapping(page) == mapping)
		mapping_set_error(mapping, error);
	unlock_page(page);
}

/* possible outcome of pageout() */
typedef enum {
	/* failed to write page out, page is locked */
	PAGE_KEEP,
	/* move page to the active list, page is locked */
	PAGE_ACTIVATE,
	/* page has been sent to the disk successfully, page is unlocked */
	PAGE_SUCCESS,
	/* page is clean and locked */
	PAGE_CLEAN,
} pageout_t;

/*
 * pageout is called by shrink_page_list() for each dirty page.
 * Calls ->writepage().
 */
static pageout_t pageout(struct page *page, struct address_space *mapping,
			 struct scan_control *sc)
{
	/*
	 * If the page is dirty, only perform writeback if that write
	 * will be non-blocking.  To prevent this allocation from being
	 * stalled by pagecache activity.  But note that there may be
	 * stalls if we need to run get_block().  We could test
	 * PagePrivate for that.
	 *
	 * If this process is currently in __generic_file_write_iter() against
	 * this page's queue, we can perform writeback even if that
	 * will block.
	 *
	 * If the page is swapcache, write it back even if that would
	 * block, for some throttling. This happens by accident, because
	 * swap_backing_dev_info is bust: it doesn't reflect the
	 * congestion state of the swapdevs.  Easy to fix, if needed.
	 */
	if (!is_page_cache_freeable(page))
		return PAGE_KEEP;
	if (!mapping) {
		/*
		 * Some data journaling orphaned pages can have
		 * page->mapping == NULL while being dirty with clean buffers.
		 */
		if (page_has_private(page)) {
			if (try_to_free_buffers(page)) {
				ClearPageDirty(page);
				pr_info("%s: orphaned page\n", __func__);
				return PAGE_CLEAN;
			}
		}
		return PAGE_KEEP;
	}
	if (mapping->a_ops->writepage == NULL)
		return PAGE_ACTIVATE;
	if (!may_write_to_inode(mapping->host, sc))
		return PAGE_KEEP;

	if (clear_page_dirty_for_io(page)) {
		int res;
		struct writeback_control wbc = {
			.sync_mode = WB_SYNC_NONE,
			.nr_to_write = SWAP_CLUSTER_MAX,
			.range_start = 0,
			.range_end = LLONG_MAX,
			.for_reclaim = 1,
		};

		SetPageReclaim(page);
		res = mapping->a_ops->writepage(page, &wbc);
		if (res < 0)
			handle_write_error(mapping, page, res);
		if (res == AOP_WRITEPAGE_ACTIVATE) {
			ClearPageReclaim(page);
			return PAGE_ACTIVATE;
		}

		if (!PageWriteback(page)) {
			/* synchronous write or broken a_ops? */
			ClearPageReclaim(page);
		}
		trace_mm_vmscan_writepage(page);
		inc_node_page_state(page, NR_VMSCAN_WRITE);
		return PAGE_SUCCESS;
	}

	return PAGE_CLEAN;
}

/*
 * Same as remove_mapping, but if the page is removed from the mapping, it
 * gets returned with a refcount of 0.
 */
static int __remove_mapping(struct address_space *mapping, struct page *page,
			    bool reclaimed)
{
	unsigned long flags;

	BUG_ON(!PageLocked(page));
	BUG_ON(mapping != page_mapping(page));

	spin_lock_irqsave(&mapping->tree_lock, flags);
	/*
	 * The non racy check for a busy page.
	 *
	 * Must be careful with the order of the tests. When someone has
	 * a ref to the page, it may be possible that they dirty it then
	 * drop the reference. So if PageDirty is tested before page_count
	 * here, then the following race may occur:
	 *
	 * get_user_pages(&page);
	 * [user mapping goes away]
	 * write_to(page);
	 *				!PageDirty(page)    [good]
	 * SetPageDirty(page);
	 * put_page(page);
	 *				!page_count(page)   [good, discard it]
	 *
	 * [oops, our write_to data is lost]
	 *
	 * Reversing the order of the tests ensures such a situation cannot
	 * escape unnoticed. The smp_rmb is needed to ensure the page->flags
	 * load is not satisfied before that of page->_refcount.
	 *
	 * Note that if SetPageDirty is always performed via set_page_dirty,
	 * and thus under tree_lock, then this ordering is not required.
	 */
	if (!page_ref_freeze(page, 2))
		goto cannot_free;
	/* note: atomic_cmpxchg in page_freeze_refs provides the smp_rmb */
	if (unlikely(PageDirty(page))) {
		page_ref_unfreeze(page, 2);
		goto cannot_free;
	}

	if (PageSwapCache(page)) {
		swp_entry_t swap = { .val = page_private(page) };
		mem_cgroup_swapout(page, swap);
		__delete_from_swap_cache(page);
		spin_unlock_irqrestore(&mapping->tree_lock, flags);
		swapcache_free(swap);
	} else {
		void (*freepage)(struct page *);
		void *shadow = NULL;

		freepage = mapping->a_ops->freepage;
		/*
		 * Remember a shadow entry for reclaimed file cache in
		 * order to detect refaults, thus thrashing, later on.
		 *
		 * But don't store shadows in an address space that is
		 * already exiting.  This is not just an optizimation,
		 * inode reclaim needs to empty out the radix tree or
		 * the nodes are lost.  Don't plant shadows behind its
		 * back.
		 *
		 * We also don't store shadows for DAX mappings because the
		 * only page cache pages found in these are zero pages
		 * covering holes, and because we don't want to mix DAX
		 * exceptional entries and shadow exceptional entries in the
		 * same page_tree.
		 */
		if (reclaimed && page_is_file_cache(page) &&
		    !mapping_exiting(mapping) && !dax_mapping(mapping))
			shadow = workingset_eviction(mapping, page);
		__delete_from_page_cache(page, shadow);
		spin_unlock_irqrestore(&mapping->tree_lock, flags);

		if (freepage != NULL)
			freepage(page);
	}

	return 1;

cannot_free:
	spin_unlock_irqrestore(&mapping->tree_lock, flags);
	return 0;
}

/*
 * Attempt to detach a locked page from its ->mapping.  If it is dirty or if
 * someone else has a ref on the page, abort and return 0.  If it was
 * successfully detached, return 1.  Assumes the caller has a single ref on
 * this page.
 */
int remove_mapping(struct address_space *mapping, struct page *page)
{
	if (__remove_mapping(mapping, page, false)) {
		/*
		 * Unfreezing the refcount with 1 rather than 2 effectively
		 * drops the pagecache ref for us without requiring another
		 * atomic operation.
		 */
		page_ref_unfreeze(page, 1);
		return 1;
	}
	return 0;
}

/**
 * putback_lru_page - put previously isolated page onto appropriate LRU list
 * @page: page to be put back to appropriate lru list
 *
 * Add previously isolated @page to appropriate LRU list.
 * Page may still be unevictable for other reasons.
 *
 * lru_lock must not be held, interrupts must be enabled.
 *
 * putback_lru_page-将先前隔离的页面放到适当的lru列表中
 * @page：要放回相应lru列表的页面
 *
 * 将先前隔离的@页面添加到适当的LRU列表中.
 * 由于其他原因，page可能仍然无法回收.
 *
 * lru_lock不能获得,必须启用中断.
 *
 */
void putback_lru_page(struct page *page)
{
	bool is_unevictable;
	/* 如果page是不可回收的 */
	int was_unevictable = PageUnevictable(page);
	/* 如果Page不在LRU链表里面,那么报个BUG吧 */
	VM_BUG_ON_PAGE(PageLRU(page), page);

redo:
	/* 清除PG_unevictable */
	ClearPageUnevictable(page);
	/* 注意这里不是测试page flag是不是PG_unevictable了
	 *
	 * int page_evictable(struct page *page)
	 * {
	 *	int ret;
	 *	Prevent address_space of inode and swap cache from being freed
	 *	rcu_read_lock();
	 *	ret = !mapping_unevictable(page_mapping(page)) && !PageMlocked(page);
	 *	rcu_read_unlock();
	 *	return ret;
	 * }
	 */
	if (page_evictable(page)) {
		/*
		 * For evictable pages, we can use the cache.
		 * In event of a race, worst case is we end up with an
		 * unevictable page on [in]active list.
		 * We know how to handle that.
		 *
		 * 对于可收回的页面,我们可以使用cache.
		 * 在发生竞争的情况下,最坏的情况是我们最终会在[in]active list中出现一个无法回收的页面.
		 * 我们知道如何处理它.
		 */
		is_unevictable = false;
		/* 把它加回到lru链表里面去 */
		lru_cache_add(page);
	} else {
		/*
		 * Put unevictable pages directly on zone's unevictable
		 * list.
		 *
		 * 将不可回收的页面直接放在zone的不可回收链表里面
		 */
		is_unevictable = true;
		/* 把页面添加到不可回收链表里面去 */
		add_page_to_unevictable_list(page);
		/*
		 * When racing with an mlock or AS_UNEVICTABLE clearing
		 * (page is unlocked) make sure that if the other thread
		 * does not observe our setting of PG_lru and fails
		 * isolation/check_move_unevictable_pages,
		 * we see PG_mlocked/AS_UNEVICTABLE cleared below and move
		 * the page back to the evictable list.
		 *
		 * The other side is TestClearPageMlocked() or shmem_lock().
		 *
		 * 当使用mlock或AS_UNEVICTABLE清除(页面已解锁)进行竞争时,确保如果另一个线程没有遵守我们的PG_lru设置
		 * 并且在isolation/check_move_unevictable_pages失败，
		 * 我们看到PG_mlocked/AS_UNIVICTABLE在下面被清除,并将页面移回可收回列表.
		 *
		 * 另一边是TestClearPageMlocked()或者shmem_lock().
		 */
		smp_mb();
	}

	/*
	 * page's status can change while we move it among lru. If an evictable
	 * page is on unevictable list, it never be freed. To avoid that,
	 * check after we added it to the list, again.
	 *
	 * 当我们在lru之间移动页面时,页面的状态可能会发生变化.
	 * 如果一个可收回的页面在不可收回的列表中,它将永远不会被释放.
	 * 为了避免这种情况,请在我们将其添加到列表后再次进行检查.
	 */

	/* 根据上下文,is_unevictable = true的时候已经添加到不可回收链表里面去了
	 * page_evictable说明页面可回收
	 * 所以把页面分离出来
	 */
	if (is_unevictable && page_evictable(page)) {
		/* 从lru中分离页面,返回0表示分离成功 */
		if (!isolate_lru_page(page)) {
			/* isolate_lru_page 会调用get_page,所以这里put_page
			 * 然后在重新试一下
			 */
			put_page(page);
			goto redo;
		}
		/* This means someone else dropped this page from LRU
		 * So, it will be freed or putback to LRU again. There is
		 * nothing to do here.
		 */
	}
	/* 如果之前page带有flag为PG_unevictable,但是经过转换变成了可回收的
	 * 那么UNEVICTABLE_PGRESCUED event++
	 */
	if (was_unevictable && !is_unevictable)
		count_vm_event(UNEVICTABLE_PGRESCUED);
	/* 如果之前page带有flag没有PG_unevictable,但是经过转换变成了不可回收的
	 * 那么UNEVICTABLE_PGCULLED event++
	 */
	else if (!was_unevictable && is_unevictable)
		count_vm_event(UNEVICTABLE_PGCULLED);
	/* 因为我们添加到list的时候会调用get_page,所以这里put_page把之前的refcout -1 */
	put_page(page);		/* drop ref from isolate */
}

enum page_references {
	PAGEREF_RECLAIM,
	PAGEREF_RECLAIM_CLEAN,
	PAGEREF_KEEP,
	PAGEREF_ACTIVATE,
};

static enum page_references page_check_references(struct page *page,
						  struct scan_control *sc)
{
	int referenced_ptes, referenced_page;
	unsigned long vm_flags;

	referenced_ptes = page_referenced(page, 1, sc->target_mem_cgroup,
					  &vm_flags);
	referenced_page = TestClearPageReferenced(page);

	/*
	 * Mlock lost the isolation race with us.  Let try_to_unmap()
	 * move the page to the unevictable list.
	 */
	if (vm_flags & VM_LOCKED)
		return PAGEREF_RECLAIM;

	if (referenced_ptes) {
		if (PageSwapBacked(page))
			return PAGEREF_ACTIVATE;
		/*
		 * All mapped pages start out with page table
		 * references from the instantiating fault, so we need
		 * to look twice if a mapped file page is used more
		 * than once.
		 *
		 * Mark it and spare it for another trip around the
		 * inactive list.  Another page table reference will
		 * lead to its activation.
		 *
		 * Note: the mark is set for activated pages as well
		 * so that recently deactivated but used pages are
		 * quickly recovered.
		 */
		SetPageReferenced(page);

		if (referenced_page || referenced_ptes > 1)
			return PAGEREF_ACTIVATE;

		/*
		 * Activate file-backed executable pages after first usage.
		 */
		if (vm_flags & VM_EXEC)
			return PAGEREF_ACTIVATE;

		return PAGEREF_KEEP;
	}

	/* Reclaim if clean, defer dirty pages to writeback */
	if (referenced_page && !PageSwapBacked(page))
		return PAGEREF_RECLAIM_CLEAN;

	return PAGEREF_RECLAIM;
}

/* Check if a page is dirty or under writeback */
static void page_check_dirty_writeback(struct page *page,
				       bool *dirty, bool *writeback)
{
	struct address_space *mapping;

	/*
	 * Anonymous pages are not handled by flushers and must be written
	 * from reclaim context. Do not stall reclaim based on them
	 *
	 * 匿名页面不需要有flushers处理,必须从回收上下文中写入.
	 * 不要基于它们拖延回收
	 */
	if (!page_is_file_cache(page)) {
		*dirty = false;
		*writeback = false;
		return;
	}

	/* By default assume that the page flags are accurate */
	/* 默认情况下，假设页面标志是准确的 */
	*dirty = PageDirty(page);
	*writeback = PageWriteback(page);

	/* Verify dirty/writeback state if the filesystem supports it */
	if (!page_has_private(page))
		return;

	mapping = page_mapping(page);
	if (mapping && mapping->a_ops->is_dirty_writeback)
		mapping->a_ops->is_dirty_writeback(page, dirty, writeback);
}

/*
 * shrink_page_list() returns the number of reclaimed pages
 */
static unsigned long shrink_page_list(struct list_head *page_list,
				      struct pglist_data *pgdat,
				      struct scan_control *sc,
				      enum ttu_flags ttu_flags,
				      unsigned long *ret_nr_dirty,
				      unsigned long *ret_nr_unqueued_dirty,
				      unsigned long *ret_nr_congested,
				      unsigned long *ret_nr_writeback,
				      unsigned long *ret_nr_immediate,
				      bool force_reclaim)
{
	/* 初始化临时页表 */
	LIST_HEAD(ret_pages);
	LIST_HEAD(free_pages);
	int pgactivate = 0;
	unsigned long nr_unqueued_dirty = 0;
	unsigned long nr_dirty = 0;
	unsigned long nr_congested = 0;
	unsigned long nr_reclaimed = 0;
	unsigned long nr_writeback = 0;
	unsigned long nr_immediate = 0;

	cond_resched();
	/* while循环扫描page_list链表,这个链表的成员都是不活跃页面 */
	while (!list_empty(page_list)) {
		struct address_space *mapping;
		struct page *page;
		int may_enter_fs;
		enum page_references references = PAGEREF_RECLAIM_CLEAN;
		bool dirty, writeback;
		bool lazyfree = false;
		int ret = SWAP_SUCCESS;

		cond_resched();
		/* 将该list里面最后一个page从lru里面删除 */
		page = lru_to_page(page_list);
		list_del(&page->lru);
		/* 尝试获取page的PG_lock锁,如果获取不成功,那么page将继续保留在不活跃LRU链表中 */
		if (!trylock_page(page))
			goto keep;
		/* 如果page是active的,那么报个BUG吧 */
		VM_BUG_ON_PAGE(PageActive(page), page);
		/* sc->nr_scanned++ */
		sc->nr_scanned++;

		/* 如果页面是不可回收的,再一次注意这里不是去看PG_evictable,而是
		 *  int page_evictable(struct page *page)
		 * {
		 *	int ret;
		 *	Prevent address_space of inode and swap cache from being freed
		 *	rcu_read_lock();
		 *	ret = !mapping_unevictable(page_mapping(page)) && !PageMlocked(page);
		 *	rcu_read_unlock();
		 *	return ret;
		 * }
		 *
		 * 如果你是不可回收的,那么就把你返回到非活跃链表里面
		 */
		if (unlikely(!page_evictable(page)))
			goto cull_mlocked;
		/* 判断是否运行回收映射的页面,sc->may_unmap表示是否能够进行unmap操作,
		 * 如果不能进行unmap操作,就只能对没有进程映射的页进行回收
		 */
		/* 如果不能进行unmap的操作,但是page是mapped,所以把它保留在不活跃LRU链表里面 */
		if (!sc->may_unmap && page_mapped(page))
			goto keep_locked;

		/* Double the slab pressure for mapped and swapcache pages */
		/* 将映射页和swapcache页的slab的压力增加一倍
		 * PG_swapcache表示分配了交换空间
		 */
		if (page_mapped(page) || PageSwapCache(page))
			sc->nr_scanned++;
		/* may_enter_fs 表示可能用到fs */
		may_enter_fs = (sc->gfp_mask & __GFP_FS) ||
			(PageSwapCache(page) && (sc->gfp_mask & __GFP_IO));

		/*
		 * The number of dirty pages determines if a zone is marked
		 * reclaim_congested which affects wait_iff_congested. kswapd
		 * will stall and start writing pages if the tail of the LRU
		 * is all dirty unqueued pages.
		 *
		 * 脏页面的数量决定了zone是否标记为reclaim_congested,这会影响wait_iff_congested.
		 * 如果LRU的尾部都是脏的未排队页面,kswapd将暂停并开始写入页面。
		 */
		page_check_dirty_writeback(page, &dirty, &writeback);
		/* 如果page是dirty或者正在回写,那么nr_dirty++ */
		if (dirty || writeback)
			nr_dirty++;
		/* 如果page是dirty的,但是还没有回写
		 * 那么就让nr_unqueued_dirty++
		 * unqueued_dirty: 统计没有在块设备I/O上排队等待回写的页面数量
		 */
		if (dirty && !writeback)
			nr_unqueued_dirty++;

		/*
		 * Treat this page as congested if the underlying BDI is or if
		 * pages are cycling through the LRU so quickly that the
		 * pages marked for immediate reclaim are making it to the
		 * end of the LRU a second time.
		 *
		 * 如果基础BDI堵塞,或者页面在LRU中循环过快以至于标记为立即回收的页面第二次到达LRU的末尾,则将此页面视为堵塞.
		 */
		mapping = page_mapping(page);
		if (((dirty || writeback) && mapping &&
		     inode_write_congested(mapping->host)) ||
		    (writeback && PageReclaim(page)))
			nr_congested++;

		/*
		 * If a page at the tail of the LRU is under writeback, there
		 * are three cases to consider.
		 *
		 * 1) If reclaim is encountering an excessive number of pages
		 *    under writeback and this page is both under writeback and
		 *    PageReclaim then it indicates that pages are being queued
		 *    for IO but are being recycled through the LRU before the
		 *    IO can complete. Waiting on the page itself risks an
		 *    indefinite stall if it is impossible to writeback the
		 *    page due to IO error or disconnected storage so instead
		 *    note that the LRU is being scanned too quickly and the
		 *    caller can stall after page list has been processed.
		 *
		 * 2) Global or new memcg reclaim encounters a page that is
		 *    not marked for immediate reclaim, or the caller does not
		 *    have __GFP_FS (or __GFP_IO if it's simply going to swap,
		 *    not to fs). In this case mark the page for immediate
		 *    reclaim and continue scanning.
		 *
		 *    Require may_enter_fs because we would wait on fs, which
		 *    may not have submitted IO yet. And the loop driver might
		 *    enter reclaim, and deadlock if it waits on a page for
		 *    which it is needed to do the write (loop masks off
		 *    __GFP_IO|__GFP_FS for this reason); but more thought
		 *    would probably show more reasons.
		 *
		 * 3) Legacy memcg encounters a page that is already marked
		 *    PageReclaim. memcg does not have any dirty pages
		 *    throttling so we could easily OOM just because too many
		 *    pages are in writeback and there is nothing else to
		 *    reclaim. Wait for the writeback to complete.
		 *
		 * 如果LRU尾部的页面处于写回状态,则有三种情况需要考虑.
		 * 1) 如果回收遇到过多的写回页面,并且此页面同时处于写回和PageReclaim,
		 * 则表示页面正在排队等待IO,但在IO完成之前通过LRU进行回收.
		 * 如果由于IO错误或存储断开连接而无法写回页面,则等待页面本身有无限期暂停的风险,
		 * 因此请注意LRU扫描过快,调用方可能会在处理页面列表后暂停.
		 *
		 * 2) 全局或新的memcg回收遇到未标记为立即回收的页面,或者调用方没有__GFP_FS(或者__GFP_IO,如果只是交换,而不是FS).
		 * 在这种情况下，将页面标记为立即收回并继续扫描.
		 *
		 * 需要may_enter_fs,因为我们将等待fs,后者可能尚未提交IO.
		 * 如果循环驱动程序在需要写入的页面上等待,则循环驱动程序可能会进入回收和死锁(因此,循环屏蔽__GFP_IO|__GFP_FS);
		 * 但更多的思考可能会显示出更多的理由。
		 *
		 *
		 * 3) 旧版memcg遇到一个已标记为PageReclaim的页面.
		 *    memcg没有任何脏页节流,所以我们可以很容易地OOM,因为写回中有太多的页,没有其他东西可以取回等待写回完成.
		 */
		if (PageWriteback(page)) {
			/* Case 1 above */
			if (current_is_kswapd() &&
			    PageReclaim(page) &&
			    test_bit(PGDAT_WRITEBACK, &pgdat->flags)) {
				nr_immediate++;
				goto keep_locked;

			/* Case 2 above */
			} else if (sane_reclaim(sc) ||
			    !PageReclaim(page) || !may_enter_fs) {
				/*
				 * This is slightly racy - end_page_writeback()
				 * might have just cleared PageReclaim, then
				 * setting PageReclaim here end up interpreted
				 * as PageReadahead - but that does not matter
				 * enough to care.  What we do want is for this
				 * page to have PageReclaim set next time memcg
				 * reclaim reaches the tests above, so it will
				 * then wait_on_page_writeback() to avoid OOM;
				 * and it's also appropriate in global reclaim.
				 */
				SetPageReclaim(page);
				nr_writeback++;
				goto keep_locked;

			/* Case 3 above */
			} else {
				unlock_page(page);
				wait_on_page_writeback(page);
				/* then go back and try same page again */
				list_add_tail(&page->lru, page_list);
				continue;
			}
		}

		/* page_check_references函数计算该页访问引用pte的用户数,并返回page_references的状态 */
		/* 简单归纳如下:
		 * 1、如果有访问引用pte
		 *    该页是匿名页面(PageSpwaBacked(page)),则加入活跃链表
		 *    最近第二次访问的page cache或者共享的page cache,则加入活跃链表
		 *    可执行文件的page cache,则加入活跃链表.
		 *    除了上述三种情况,其余情况继续保留在不活跃链表
		 * 2、如果没有访问引用pte,则表示可以尝试回收
		 */
		if (!force_reclaim)
			references = page_check_references(page, sc);

		switch (references) {
		case PAGEREF_ACTIVATE:
			goto activate_locked;
		case PAGEREF_KEEP:
			goto keep_locked;
		case PAGEREF_RECLAIM:
		case PAGEREF_RECLAIM_CLEAN:
			; /* try to reclaim the page below */
		}

		/*
		 * Anonymous process memory has backing store?
		 * Try to allocate it some swap space here.
		 *
		 * 匿名内存有后备存储吗?
		 * 试着在这里给它分配一些交换空间。
		 */

		/* 如果page是匿名页面,!PageSwapCache说明page还没有分配交换空间(swap space),
		 * 那么调用add_to_swap函数为其分配交换空间,
		 * 并且设置该页的标志位PG_swapcache(add_to_swap里面会去设置)
		 */
		if (PageAnon(page) && !PageSwapCache(page)) {
			if (!(sc->gfp_mask & __GFP_IO))
				goto keep_locked;
			if (!add_to_swap(page, page_list))
				goto activate_locked;
			lazyfree = true;
			may_enter_fs = 1;

			/* Adding to swap updated mapping */
			/* page分配了交换空间后,page->mapping指向发生了变化,由原来指向匿名页面的anon_vma数据结构变成了交换分配的swapper_space */
			mapping = page_mapping(page);/* 如果是THP,那么分割THP */
		} else if (unlikely(PageTransHuge(page))) {
			/* Split file THP */
			if (split_huge_page_to_list(page, page_list))
				goto keep_locked;
		}
		/* 如果PAGE还是透明大页,那么直接报BUG吧 */
		VM_BUG_ON_PAGE(PageTransHuge(page), page);

		/*
		 * The page is mapped into the page tables of one or more
		 * processes. Try to unmap it here.
		 */
		/* page有多个用户映射(page->_mapcount >=0)且mapping指向address_space,那么调用try_to_unmap来解除这些用户映射的PTEs.
		 * 函数返回SWAP_FAIL,说明解除pte失败,该页将迁移到活跃LRU中.
		 * 返回SWAP_AGAIN,说明有的pte被漏掉了,保留在不活跃LRU链表中,下一次继续扫描.
		 * 返回SWAP_SUCCESS,说明已经成功解除了所有PTEs映射了.
		 */
		if (page_mapped(page) && mapping) {
			switch (ret = try_to_unmap(page, lazyfree ?
				(ttu_flags | TTU_BATCH_FLUSH | TTU_LZFREE) :
				(ttu_flags | TTU_BATCH_FLUSH))) {
			case SWAP_FAIL:
				goto activate_locked;
			case SWAP_AGAIN:
				goto keep_locked;
			case SWAP_MLOCK:
				goto cull_mlocked;
			case SWAP_LZFREE:
				goto lazyfree;
			case SWAP_SUCCESS:
				; /* try to free the page below */
			}
		}
		/* 如果page是dirty的 */
		if (PageDirty(page)) {
			/*
			 * Only kswapd can writeback filesystem pages to
			 * avoid risk of stack overflow but only writeback
			 * if many dirty pages have been encountered.
			 */
			/* 如果是文件映射页面,则设置page为PG_reclaim且继续保持在不活跃LRU中.
			 * 在kswapd内核线程中进行一个页面回收的做法可取,早前的linux这样做是因为向存储设备中写页面内容的速度比CPU慢很多个数量级.
			 * 目前的做法是kswapd内核线程不会对零星的几个page cache页面进行回写,除非遇到之前有很多还没有开始回写的脏页面.
			 * 当扫描完一轮后,发现有好多脏的page cache还没来得及加入回写子系统(writeback subsystem),那么设置ZONE_DRITY比特位,
			 * 表示kswapd可以回收脏页面,否则一般情况下kswapd不回写脏的page cache.
			 */
			if (page_is_file_cache(page) &&
					(!current_is_kswapd() ||
					 !test_bit(PGDAT_DIRTY, &pgdat->flags))) {
				/*
				 * Immediately reclaim when written back.
				 * Similar in principal to deactivate_page()
				 * except we already have the page isolated
				 * and know it's dirty
				 *
				 * 写回后立即收回.原则上类似于deactivate_page(),只是我们已经隔离了页面，并且知道它是脏的
				 */
				inc_node_page_state(page, NR_VMSCAN_IMMEDIATE);
				/* 设置page为PG_reclaim
				 * PG_reclaim: 表示该page要被回收.当PFRA决定要回收某个page后,需要设置该标志.
				 */
				SetPageReclaim(page);

				goto keep_locked;
			}

			if (references == PAGEREF_RECLAIM_CLEAN)
				goto keep_locked;
			if (!may_enter_fs)
				goto keep_locked;
			if (!sc->may_writepage)
				goto keep_locked;

			/*
			 * Page is dirty. Flush the TLB if a writable entry
			 * potentially exists to avoid CPU writes after IO
			 * starts and then write it out here.
			 */
			/* 如果是匿名页面,那么调用pageout函数进行写入交换分区.
			 * pageout函数有4个返回值,PAGE_KEEP表示回写失败,
			 * PAGE_ACTIVATE表示page需要迁移回到活跃LRU链表中,
			 * PAGE_SUCCESS表示page已经成功写入存储设备,
			 * PAGE_CLEAN表示page已经干净,可以被释放了
			 */
			try_to_unmap_flush_dirty();
			switch (pageout(page, mapping, sc)) {
			case PAGE_KEEP:
				goto keep_locked;
			case PAGE_ACTIVATE:
				goto activate_locked;
			case PAGE_SUCCESS:
				if (PageWriteback(page))
					goto keep;
				if (PageDirty(page))
					goto keep;

				/*
				 * A synchronous write - probably a ramdisk.  Go
				 * ahead and try to reclaim the page.
				 *
				 * 一个同步写入 - 可能是ramdisk.
				 * 继续并尝试收回页面。
				 */
				if (!trylock_page(page))
					goto keep;
				if (PageDirty(page) || PageWriteback(page))
					goto keep_locked;
				mapping = page_mapping(page);
			case PAGE_CLEAN:
				; /* try to free the page below */
			}
		}

		/*
		 * If the page has buffers, try to free the buffer mappings
		 * associated with this page. If we succeed we try to free
		 * the page as well.
		 *
		 * 如果页面有buffers,试图释放与此页面关联的buffer映射.
		 * 如果我们成功了，我们也会尝试释放页面。
		 *
		 * We do this even if the page is PageDirty().
		 * try_to_release_page() does not perform I/O, but it is
		 * possible for a page to have PageDirty set, but it is actually
		 * clean (all its buffers are clean).  This happens if the
		 * buffers were written out directly, with submit_bh(). ext3
		 * will do this, as well as the blockdev mapping.
		 * try_to_release_page() will discover that cleanness and will
		 * drop the buffers and mark the page clean - it can be freed.
		 *
		 * 即使页面是PageDirty(),我们也会这样做.
		 * try_to_release_page()不执行I/O,但页面可能设置了PageDirty,但它实际上是干净的(所有缓冲区都是干净的).
		 * 如果使用submit_bh()直接写出缓冲区,就会发生这种情况.
		 * ext3将执行此操作,以及blockdev映射.
		 * try_to_release_page()将发现该清洁,并将丢弃缓冲区并将页面标记为干净-它可以被释放.
		 *
		 * Rarely, pages can have buffers and no ->mapping.  These are
		 * the pages which were not successfully invalidated in
		 * truncate_complete_page().  We try to drop those buffers here
		 * and if that worked, and the page is no longer mapped into
		 * process address space (page_count == 1) it can be freed.
		 * Otherwise, leave the page on the LRU so it is swappable.
		 *
		 * 很少情况下，页面可以有缓冲区并且没有->mapping.
		 * 这些页面在truncate_complete_page()中未成功失效.
		 * 我们尝试在这里drop这些缓冲区,如果成功,页面不再映射到进程地址空间(page_count==1),则可以释放它。
		 * 否则，请将页面留在LRU上，以便进行swappable.
		 */

		/* 处理page用于块设备的buffer_head缓存,try_to_release_page释放buffer_head缓存 */
		if (page_has_private(page)) {
			if (!try_to_release_page(page, sc->gfp_mask))
				goto activate_locked;
			if (!mapping && page_count(page) == 1) {
				unlock_page(page);
				if (put_page_testzero(page))
					goto free_it;
				else {
					/*
					 * rare race with speculative reference.
					 * the speculative reference will free
					 * this page shortly, so we may
					 * increment nr_reclaimed here (and
					 * leave it off the LRU).
					 */
					nr_reclaimed++;
					continue;
				}
			}
		}

lazyfree:
		if (!mapping || !__remove_mapping(mapping, page, true))
			goto keep_locked;

		/*
		 * At this point, we have no other references and there is
		 * no way to pick any more up (removed from LRU, removed
		 * from pagecache). Can use non-atomic bitops now (and
		 * we obviously don't have to worry about waking up a process
		 * waiting on the page lock, because there are no references.
		 */
		__ClearPageLocked(page);
free_it:
		if (ret == SWAP_LZFREE)
			count_vm_event(PGLAZYFREED);

		nr_reclaimed++;

		/*
		 * Is there need to periodically free_page_list? It would
		 * appear not as the counts should be low
		 */
		/* 添加到free_pages的链表里面去 */
		list_add(&page->lru, &free_pages);
		continue;

cull_mlocked:
		/* 如果有给page在swap空间上分配空间,那么释放这块空间 */
		if (PageSwapCache(page))
			try_to_free_swap(page);
		/* 解锁页面 */
		unlock_page(page);
		/* 把page添加到ret_pages的链表里面去,这个链表主要是用来返回到不可活跃链表里面的 */
		list_add(&page->lru, &ret_pages);
		continue;

activate_locked:
		/* Not a candidate for swapping, so reclaim swap space.
		 * 不是交换的候选者,所以回收交换空间.
		 */
		if (PageSwapCache(page) && mem_cgroup_swap_full(page))
			try_to_free_swap(page);
		VM_BUG_ON_PAGE(PageActive(page), page);
		/* 将该page设置为Active */
		SetPageActive(page);
		pgactivate++;
keep_locked:
		unlock_page(page);
		/* 把该page添加到ret_pages里面去,主要是返回到inactive链表里面去 */
keep:
		list_add(&page->lru, &ret_pages);
		VM_BUG_ON_PAGE(PageLRU(page) || PageUnevictable(page), page);
	}
	/* mem uncharge计数 */
	mem_cgroup_uncharge_list(&free_pages);
	try_to_unmap_flush();
	/* 释放free_pages里面的页面 */
	free_hot_cold_page_list(&free_pages, true);
	/* 将ret_pages接到page_list里面去 */
	list_splice(&ret_pages, page_list);
	/* 计数PGACTIVATE */
	count_vm_events(PGACTIVATE, pgactivate);

	*ret_nr_dirty += nr_dirty;
	*ret_nr_congested += nr_congested;
	*ret_nr_unqueued_dirty += nr_unqueued_dirty;
	*ret_nr_writeback += nr_writeback;
	*ret_nr_immediate += nr_immediate;
	return nr_reclaimed;
}

unsigned long reclaim_clean_pages_from_list(struct zone *zone,
					    struct list_head *page_list)
{
	struct scan_control sc = {
		.gfp_mask = GFP_KERNEL,
		.priority = DEF_PRIORITY,
		.may_unmap = 1,
	};
	unsigned long ret, dummy1, dummy2, dummy3, dummy4, dummy5;
	struct page *page, *next;
	LIST_HEAD(clean_pages);

	list_for_each_entry_safe(page, next, page_list, lru) {
		if (page_is_file_cache(page) && !PageDirty(page) &&
		    !__PageMovable(page)) {
			ClearPageActive(page);
			list_move(&page->lru, &clean_pages);
		}
	}

	ret = shrink_page_list(&clean_pages, zone->zone_pgdat, &sc,
			TTU_UNMAP|TTU_IGNORE_ACCESS,
			&dummy1, &dummy2, &dummy3, &dummy4, &dummy5, true);
	list_splice(&clean_pages, page_list);
	mod_node_page_state(zone->zone_pgdat, NR_ISOLATED_FILE, -ret);
	return ret;
}

/*
 * Attempt to remove the specified page from its LRU.  Only take this page
 * if it is of the appropriate PageActive status.  Pages which are being
 * freed elsewhere are also ignored.
 *
 * page:	page to consider
 * mode:	one of the LRU isolation modes defined above
 *
 * 尝试从LRU中删除指定的页面.
 * 只有当此页面处于适当的PageActive状态时,才可使用此页面.
 * 其他地方正在释放的页面也会被忽略.
 *
 * returns 0 on success, -ve errno on failure.
 */
int __isolate_lru_page(struct page *page, isolate_mode_t mode)
{
	int ret = -EINVAL;

	/* Only take pages on the LRU. */
	/* 如果page已经不在LRU链表里面了,那么直接返回 */
	if (!PageLRU(page))
		return ret;

	/* Compaction should not handle unevictable pages but CMA can do so
	 * 内存压缩不应处理不可回收的页面,但CMA可以这样做
	 */

	/* 如果页面是LRU_UNEVICTABLE,但是mode是ISOLATE_UNEVICTABLE
	 * 那么就直接返回了
	 */
	if (PageUnevictable(page) && !(mode & ISOLATE_UNEVICTABLE))
		return ret;

	ret = -EBUSY;

	/*
	 * To minimise LRU disruption, the caller can indicate that it only
	 * wants to isolate pages it will be able to operate on without
	 * blocking - clean pages for the most part.
	 *
	 * ISOLATE_CLEAN means that only clean pages should be isolated. This
	 * is used by reclaim when it is cannot write to backing storage
	 *
	 * ISOLATE_ASYNC_MIGRATE is used to indicate that it only wants to pages
	 * that it is possible to migrate without blocking
	 *
	 * 为了最大限度地减少LRU中断,调用方可以指示它只想隔离它将能够在不阻塞的情况下操作的页面--大多数情况下是clean
	 *
	 * ISOLATE_CLEAN意味着只应隔离干净的页面.
	 * 当回收无法写入后备存储时,它会被回收使用
	 *
	 * ISOLATE_ASYNC_MIGRATE用于指示它只想对可以在不阻塞的情况下进行migrate的页面
	 */

	/* ISOLATE_CLEAN: 分离干净的页面
	 * ISOLATE_ASYNC_MIGRATE：分离异步迁移的页面
	 */
	if (mode & (ISOLATE_CLEAN|ISOLATE_ASYNC_MIGRATE)) {
		/* All the caller can do on PageWriteback is block */
		/* 如果page正在写回,那么直接返回 */
		if (PageWriteback(page))
			return ret;
		/* 如果page是dirty的 */
		if (PageDirty(page)) {
			struct address_space *mapping;
			/* ISOLATE_CLEAN 意味这只有干净的页面 */
			/* ISOLATE_CLEAN means only clean pages */
			if (mode & ISOLATE_CLEAN)
				return ret;

			/*
			 * Only pages without mappings or that have a
			 * ->migratepage callback are possible to migrate
			 * without blocking
			 *
			 */
			/* 如果page有映射且有migratepage函数,那么也直接返回 */
			mapping = page_mapping(page);
			if (mapping && !mapping->a_ops->migratepage)
				return ret;
		}
	}

	/* ISOLATE_UNMAPPED: 分离没有映射的页面
	 * page_mapped 表示page已经被映射了
	 */
	if ((mode & ISOLATE_UNMAPPED) && page_mapped(page))
		return ret;

	/* 如果page的引用计数为0则退出,否则增加其引用计数
	 * 也就是说，这个page不能是空闲页面，否则返回-EBUSY
	 */
	if (likely(get_page_unless_zero(page))) {
		/*
		 * Be careful not to clear PageLRU until after we're
		 * sure the page is not being freed elsewhere -- the
		 * page release code relies on it.
		 *
		 * 请注意,在我们确定页面没有在其他地方释放之前,不要清除PageLRU -- page release代码依赖它
		 */
		ClearPageLRU(page);
		ret = 0;
	}

	return ret;
}


/*
 * Update LRU sizes after isolating pages. The LRU size updates must
 * be complete before mem_cgroup_update_lru_size due to a santity check.
 */
static __always_inline void update_lru_sizes(struct lruvec *lruvec,
			enum lru_list lru, unsigned long *nr_zone_taken)
{
	int zid;

	for (zid = 0; zid < MAX_NR_ZONES; zid++) {
		if (!nr_zone_taken[zid])
			continue;

		__update_lru_size(lruvec, lru, zid, -nr_zone_taken[zid]);
#ifdef CONFIG_MEMCG
		mem_cgroup_update_lru_size(lruvec, lru, zid, -nr_zone_taken[zid]);
#endif
	}

}

/*
 * zone_lru_lock is heavily contended.  Some of the functions that
 * shrink the lists perform better by taking out a batch of pages
 * and working on them outside the LRU lock.
 *
 * zone_lru_lock受到严重竞争.
 * 通过取出一批页面并在LRU锁定之外对其进行处理，一些回收链表的功能执行得更好.
 *
 * For pagecache intensive workloads, this function is the hottest
 * spot in the kernel (apart from copy_*_user functions).
 *
 * 对于pagecheck密集型工作负载,此函数是内核中最热门的部分(除了copy_*_user函数)
 *
 * Appropriate locks must be held before calling this function.
 *
 * 调用此函数之前，必须持有适当的锁.
 *
 * @nr_to_scan:	The number of pages to look through on the list.
 * @lruvec:	The LRU vector to pull pages from.
 * @dst:	The temp list to put pages on to.
 * @nr_scanned:	The number of pages that were scanned.
 * @sc:		The scan_control struct for this reclaim session
 * @mode:	One of the LRU isolation modes
 * @lru:	LRU list id for isolating
 *
 * returns how many pages were moved onto *@dst.
 */
static unsigned long isolate_lru_pages(unsigned long nr_to_scan,
		struct lruvec *lruvec, struct list_head *dst,
		unsigned long *nr_scanned, struct scan_control *sc,
		isolate_mode_t mode, enum lru_list lru)
{
	struct list_head *src = &lruvec->lists[lru];
	unsigned long nr_taken = 0;
	unsigned long nr_zone_taken[MAX_NR_ZONES] = { 0 };
	unsigned long nr_skipped[MAX_NR_ZONES] = { 0, };
	unsigned long scan, nr_pages;
	LIST_HEAD(pages_skipped);

	for (scan = 0; scan < nr_to_scan && nr_taken < nr_to_scan &&
					!list_empty(src);) {
		struct page *page;
		/* #define lru_to_page(head) (list_entry((head)->prev, struct page, lru))
		 * 拿到这个链表的最后一个page
		 */
		page = lru_to_page(src);
		prefetchw_prev_lru_page(page, src, flags);
		/* 如果page的LRU没有,说明page已经不在LRU链表里面了
		 * 那么就直接报个BUG吧
		 */
		VM_BUG_ON_PAGE(!PageLRU(page), page);
		/* 如果pagg的zonenum要 > sc->reclaim_idx
		 * 那么就skip掉这个page
		 * 具体是把这个page移动到pages_skipped链表里面去
		 * 然后对应的nr_skipped ++
		 */
		if (page_zonenum(page) > sc->reclaim_idx) {
			list_move(&page->lru, &pages_skipped);
			nr_skipped[page_zonenum(page)]++;
			continue;
		}

		/*
		 * Account for scanned and skipped separetly to avoid the pgdat
		 * being prematurely marked unreclaimable by pgdat_reclaimable.
		 *
		 * 扫描和skip分别计数,以避免pgdat_reclaimable过早地将pgdat标记为不可回收.
		 */
		scan++;

		switch (__isolate_lru_page(page, mode)) {
		case 0: /* static inline int hpage_nr_pages(struct page *page)
			 * {
			 *   if (unlikely(PageTransHuge(page)))
			 *	return HPAGE_PMD_NR;
			 * return 1;
			 * }
			 */
			nr_pages = hpage_nr_pages(page);
			/* 然后nr_taken加上我们刚刚可以隔离的page */
			nr_taken += nr_pages;
			/* 然后nr_zone_taken[zone]加上刚刚隔离出来的nr_pages */
			nr_zone_taken[page_zonenum(page)] += nr_pages;
			list_move(&page->lru, dst);
			break;

		case -EBUSY: /* 如果是EBUSY,把page移动到lruvec->lists的头部,这样避免下次scan扫到这样的页面 */
			/* else it is being freed elsewhere */
			list_move(&page->lru, src);
			continue;

		default:
			BUG();
		}
	}

	/*
	 * Splice any skipped pages to the start of the LRU list. Note that
	 * this disrupts the LRU order when reclaiming for lower zones but
	 * we cannot splice to the tail. If we did then the SWAP_CLUSTER_MAX
	 * scanning would soon rescan the same pages to skip and put the
	 * system at risk of premature OOM.
	 *
	 * 将任何skipped的页面拼接到LRU列表的开头.
	 *
	 * 请注意，当回收较低zone时,这会扰乱LRU顺序,但我们无法拼接到尾部.
	 * 如果我们这样做了，那么SWAP_CLUSTER_MAX扫描将很快重新扫描相同的页面以跳过,并使系统面临过早OOM的风险.
	 */
	if (!list_empty(&pages_skipped)) {
		int zid;
		unsigned long total_skipped = 0;

		for (zid = 0; zid < MAX_NR_ZONES; zid++) {
			/* 如果该zone的nr_skipped为0,那么continue */
			if (!nr_skipped[zid])
				continue;
			/* total_skipped 加上nr_skipped[zid]的值
			 * 然后zone的PGSCAN_SKIP + 上nr_skipped[zid]的值
			 */
			__count_zid_vm_events(PGSCAN_SKIP, zid, nr_skipped[zid]);
			total_skipped += nr_skipped[zid];
		}

		/*
		 * Account skipped pages as a partial scan as the pgdat may be
		 * close to unreclaimable. If the LRU list is empty, account
		 * skipped pages as a full scan.
		 *
		 * 将skipped pages视为部分扫描,因为pgdat可能接近不可回收.
		 * 如果LRU列表为空,视skipped pages为完全扫描
		 */

		/* 如果src为空,那么scan + total_skipped
		 * 否则scan + total_skipped >> 2
		 */
		scan += list_empty(src) ? total_skipped : total_skipped >> 2;
		/* 将两个链表拼接在一起 */
		list_splice(&pages_skipped, src);
	}
	/* 把scan赋值给nr_scanned */
	*nr_scanned = scan;
	trace_mm_vmscan_lru_isolate(sc->reclaim_idx, sc->order, nr_to_scan, scan,
				    nr_taken, mode, is_file_lru(lru));
	/* 更新zone的lru的size
	 *
	 * static __always_inline void update_lru_sizes(struct lruvec *lruvec,
	 *		enum lru_list lru, unsigned long *nr_zone_taken){
	 *		int zid;
	 *		for (zid = 0; zid < MAX_NR_ZONES; zid++) {
	 *			if (!nr_zone_taken[zid])
	 *				continue;
	 *
	 *			__update_lru_size(lruvec, lru, zid, -nr_zone_taken[zid]);
	 *		#ifdef CONFIG_MEMCG
	 *		mem_cgroup_update_lru_size(lruvec, lru, zid, -nr_zone_taken[zid]);
	 *		#endif
	 *			}
	 *
	 *	}
	 */
	update_lru_sizes(lruvec, lru, nr_zone_taken);
	return nr_taken;
}

/**
 * isolate_lru_page - tries to isolate a page from its LRU list
 * @page: page to isolate from its LRU list
 *
 * Isolates a @page from an LRU list, clears PageLRU and adjusts the
 * vmstat statistic corresponding to whatever LRU list the page was on.
 *
 * Returns 0 if the page was removed from an LRU list.
 * Returns -EBUSY if the page was not on an LRU list.
 *
 * The returned page will have PageLRU() cleared.  If it was found on
 * the active list, it will have PageActive set.  If it was found on
 * the unevictable list, it will have the PageUnevictable bit set. That flag
 * may need to be cleared by the caller before letting the page go.
 *
 * The vmstat statistic corresponding to the list on which the page was
 * found will be decremented.
 *
 * Restrictions:
 * (1) Must be called with an elevated refcount on the page. This is a
 *     fundamentnal difference from isolate_lru_pages (which is called
 *     without a stable reference).
 * (2) the lru_lock must not be held.
 * (3) interrupts must be enabled.
 */
int isolate_lru_page(struct page *page)
{
	int ret = -EBUSY;
	/*  static inline int page_count(struct page *page)
	 * {
	 *	return atomic_read(&compound_head(page)->_refcount);
	 * }
	 *
	 * 如果page的_refcount为0,那么就报个BUG吧
	 */
	VM_BUG_ON_PAGE(!page_count(page), page);
	WARN_RATELIMIT(PageTail(page), "trying to isolate tail page");

	/* 如果Page在LRU链表里面 */
	if (PageLRU(page)) {
		/* 拿到page所在的zone */
		struct zone *zone = page_zone(page);
		struct lruvec *lruvec;

		spin_lock_irq(zone_lru_lock(zone));
		/* 拿到对应pgdat里面的lruvec */
		lruvec = mem_cgroup_page_lruvec(page, zone->zone_pgdat);
		/* 如果Page还在LRU里面里面 */
		if (PageLRU(page)) {
			/* 拿到page所在的lru */
			int lru = page_lru(page);
			/* 将page的refcount + 1 */
			get_page(page);
			/* 清除Page的PG_lru */
			ClearPageLRU(page);
			/* 把页面从lruvce的相应的lru链表中删除 */
			del_page_from_lru_list(page, lruvec, lru);
			ret = 0;
		}
		spin_unlock_irq(zone_lru_lock(zone));
	}
	return ret;
}

/*
 * A direct reclaimer may isolate SWAP_CLUSTER_MAX pages from the LRU list and
 * then get resheduled. When there are massive number of tasks doing page
 * allocation, such sleeping direct reclaimers may keep piling up on each CPU,
 * the LRU list will go small and be scanned faster than necessary, leading to
 * unnecessary swapping, thrashing and OOM.
 *
 * 直接回收可以将SWAP_CLUSTER_MAX页面与LRU列表隔离,然后重新进行处理.
 * 当有大量任务进行页面分配时,这种休眠的直接回收可能会在每个CPU上不断堆积,LRU列表会变小,
 * 扫描速度会超过必要的速度,导致不必要的交换、颠簸和OOM.
 */
static int too_many_isolated(struct pglist_data *pgdat, int file,
		struct scan_control *sc)
{
	unsigned long inactive, isolated;

	/* 如果当前是kswapd,那么直接返回0 */
	if (current_is_kswapd())
		return 0;

	if (!sane_reclaim(sc))
		return 0;

	/* 如果是file,那么inactive和isolated 就取file的
	 * 如果是匿名页面,那么就取匿名页面的
	 */
	if (file) {
		inactive = node_page_state(pgdat, NR_INACTIVE_FILE);
		isolated = node_page_state(pgdat, NR_ISOLATED_FILE);
	} else {
		inactive = node_page_state(pgdat, NR_INACTIVE_ANON);
		isolated = node_page_state(pgdat, NR_ISOLATED_ANON);
	}

	/*
	 * GFP_NOIO/GFP_NOFS callers are allowed to isolate more pages, so they
	 * won't get blocked by normal direct-reclaimers, forming a circular
	 * deadlock.
	 *
	 * 允许GFP_NOIO/GFP_NOFS调用方隔离更多页面,因此它们不会被普通的直接回收阻塞,形成循环死锁.
	 */
	if ((sc->gfp_mask & (__GFP_IO | __GFP_FS)) == (__GFP_IO | __GFP_FS))
		inactive >>= 3;

	return isolated > inactive;
}

static noinline_for_stack void
putback_inactive_pages(struct lruvec *lruvec, struct list_head *page_list)
{
	/* 拿到zone_reclaim_stat */
	struct zone_reclaim_stat *reclaim_stat = &lruvec->reclaim_stat;
	/* 获得pglist_data */
	struct pglist_data *pgdat = lruvec_pgdat(lruvec);
	LIST_HEAD(pages_to_free);

	/*
	 * Put back any unfreeable pages.
	 */
	/* while循环扫描page_list链表 */
	while (!list_empty(page_list)) {
		/* 拿到该list里面最后一个page */
		struct page *page = lru_to_page(page_list);
		int lru;
		/* 如果Page在LRU链表里面,那么报个BUG吧 */
		VM_BUG_ON_PAGE(PageLRU(page), page);
		/* 将这么page从lru里面删除 */
		list_del(&page->lru);

		/* 如果页面是不可回收的,再一次注意这里不是去看PG_evictable,而是
		 *  int page_evictable(struct page *page)
		 * {
		 *	int ret;
		 *	Prevent address_space of inode and swap cache from being freed
		 *	rcu_read_lock();
		 *	ret = !mapping_unevictable(page_mapping(page)) && !PageMlocked(page);
		 *	rcu_read_unlock();
		 *	return ret;
		 * }
		 *
		 * 如果你是不可回收的,那么就把你返回到相关的lru链表里面去
		 */
		if (unlikely(!page_evictable(page))) {
			spin_unlock_irq(&pgdat->lru_lock);
			/* 将它添加到相关的lru链表里面去 */
			putback_lru_page(page);
			spin_lock_irq(&pgdat->lru_lock);
			continue;
		}

		lruvec = mem_cgroup_page_lruvec(page, pgdat);
		/* 设置page的PG_lru flag */
		SetPageLRU(page);
		/* 获取page是属于哪个LRU链表里的 */
		lru = page_lru(page);
		/* 将其添加到相关的lru链表里面去 */
		add_page_to_lru_list(page, lruvec, lru);
		/* 如果page在活跃的lru链表 */
		if (is_active_lru(lru)) {
			/* 将相应的recent_rotated加上其page数量 */
			int file = is_file_lru(lru);
			int numpages = hpage_nr_pages(page);
			reclaim_stat->recent_rotated[file] += numpages;
		}

		/* 将page的_refcount减去1,判断它是否等于0 */
		if (put_page_testzero(page)) {
			/* 如果等于0,那么清除page的PG_lru */
			__ClearPageLRU(page);
			/* 清除PG_active */
			__ClearPageActive(page);
			/* 将其从相关的LRU链表里面删除 */
			del_page_from_lru_list(page, lruvec, lru);

			/* 如果page是组合页面,调用相关的get_compound_page_dtor函数 */
			if (unlikely(PageCompound(page))) {
				spin_unlock_irq(&pgdat->lru_lock);
				mem_cgroup_uncharge(page);
				(*get_compound_page_dtor(page))(page);
				spin_lock_irq(&pgdat->lru_lock);
			} else /* 添加到pages_to_free链表里面 */
				list_add(&page->lru, &pages_to_free);
		}
	}

	/*
	 * To save our caller's stack, now use input list for pages to free.
	 */
	/* 将pages_to_free 拼接到page_list里面去 */
	list_splice(&pages_to_free, page_list);
}

/*
 * If a kernel thread (such as nfsd for loop-back mounts) services
 * a backing device by writing to the page cache it sets PF_LESS_THROTTLE.
 * In that case we should only throttle if the backing device it is
 * writing to is congested.  In other cases it is safe to throttle.
 *
 * 如果内核线程(如用于环回装载的nfsd)服务一个后备设备通过写page cache,则它会设置PF_LESS_THROTLE.
 * 在这种情况下,只有当它正在写入的备份设备拥塞时,我们才应该进行节流.
 * 在其他情况下,节流是安全的.
 */
static int current_may_throttle(void)
{
	return !(current->flags & PF_LESS_THROTTLE) ||
		current->backing_dev_info == NULL ||
		bdi_write_congested(current->backing_dev_info);
}

static bool inactive_reclaimable_pages(struct lruvec *lruvec,
				struct scan_control *sc, enum lru_list lru)
{
	int zid;
	struct zone *zone;
	/* 判断是不是page cache */
	int file = is_file_lru(lru);
	/* 拿到pglist_data */
	struct pglist_data *pgdat = lruvec_pgdat(lruvec);
	/* 如果不是全局回收,那么返回true */
	if (!global_reclaim(sc))
		return true;
	/* 从reclaim_idx 到0 结束 */
	for (zid = await高,%uilt高sc->reclaim_idx; zid >= 0; zid--) {
		zone = &pgdat->node_zones[zid];
		/* 如果zone里面没有page,那么直接continue */
		if (!managed_zone(zone))
			continue;
		/* static inline unsigned long zone_page_state_snapshot(struct zone *zone,
		 *		enum zone_stat_item item)
		 * {
		 *	long x = atomic_long_read(&zone->vm_stat[item]);
		 *
		 * #ifdef CONFIG_SMP
		 *	int cpu;
		 *	for_each_online_cpu(cpu)
		 *		x += per_cpu_ptr(zone->pageset, cpu)->vm_stat_diff[item];
		 *
		 *	if (x < 0)
		 *	x = 0;
		 * #endif
		 * 	return x;
		 * }
		 */

		/* 如果其中的一个zone的NR_ZONE_LRU_BASE +  LRU_FILE * file的vm_state >= SWAP_CLUSTER_MAX
		 * 那么就返回true
		 */
		if (zone_page_state_snapshot(zone, NR_ZONE_LRU_BASE +
				LRU_FILE * file) >= SWAP_CLUSTER_MAX)
			return true;
	}

	return false;
}

/*
 * shrink_inactive_list() is a helper for shrink_node().  It returns the number
 * of reclaimed pages
 */
static noinline_for_stack unsigned long
shrink_inactive_list(unsigned long nr_to_scan, struct lruvec *lruvec,
		     struct scan_control *sc, enum lru_list lru)
{
	LIST_HEAD(page_list);
	unsigned long nr_scanned;
	unsigned long nr_reclaimed = 0;
	unsigned long nr_taken;
	unsigned long nr_dirty = 0;
	unsigned long nr_congested = 0;
	unsigned long nr_unqueued_dirty = 0;
	unsigned long nr_writeback = 0;
	unsigned long nr_immediate = 0;
	isolate_mode_t isolate_mode = 0;
	int file = is_file_lru(lru);
	/* 拿到当前的pgdat */
	struct pglist_data *pgdat = lruvec_pgdat(lruvec);
	struct zone_reclaim_stat *reclaim_stat = &lruvec->reclaim_stat;

	if (!inactive_reclaimable_pages(lruvec, sc, lru))
		return 0;

	while (unlikely(too_many_isolated(pgdat, file, sc))) {
	/* 内存管理在很多方面都是在追求平衡.例如,内核必须要对当前用户对内存的需求以及预期未来的需求之间进行一下权衡.
	 * 内核还必须权衡是否要为其他用途而回收内存,因为这可能涉及到需要将数据写入永久存储(permanent storage)以及底层的存储设备进行数据写入时的速度等等.
	 * 多年来,内存管理子系统一直把存储设备操作的拥塞作为一个信号,告诉它自己应该要放慢回收速度了.
	 * 不幸的是,这个机制从一开始就有点问题,在很长一段时间内其实并没有效果.
	 * Mel Gorman 现在正试图提供一个patch set来解决这个问题,不过这样一来内核就不应该再等待拥塞出现了.
	 * The congestion_wait() surprise
	 * 当内存变得紧张时,内存管理子系统必须得回收当前正在使用的page用于其他用途.
	 * 这反过来又先需要把所有被修改过的 page 的内容写出去.如果要写入这个 page 内容的块设备已经被繁重的写入任务所占用了,那么这里就算让 I/O 请求堆积得更高,也没有什么效果了.
	 * 早在黑暗和遥远的时代,Git 出现之前(2002 年),Andrew Morton就提议为块设备增加一个拥塞追踪(congestion-tracking)机制:
	 * 如果某个设备已经拥塞住了,那么内存管理子系统就会暂时不再发起新的I/O请求(并控制(也就是放慢)那些在申请更多内存的进程的运行),直到拥塞缓解.
	 * 这一机制在2002年9月的2.5.39 开发版内核中就位了.
	 * 在那以后的几年里,拥塞等待机制以各种方式演进.即将发布的5.15内核中仍然包含有一个叫做congestion_wait()的函数,
	 * 它可以暂停当前的task,直到拥挤的设备变得不那么拥挤(也就是通过clear_bdi_congested()调用来通知这个状态)或者出现timeout从而结束.
	 * 或者,至少这曾是它想象中的行为.
	 * 碰巧,clear_bdi_congested(()的主要调用位置是一个叫做blk_clear_congested()的函数,该函数在2018年的5.0内核版本中被移除了.
	 * 从那时起,除了少数文件系统(Ceph、FUSE和NFS)之外,没有任何东西调用clear_bdi_congested()了,这意味着对congestion_wait()的调用几乎总是会坐等到timeout 结束,这并不是开发者的本意.
	 */
		congestion_wait(BLK_RW_ASYNC, HZ/10);

		/* We are about to die and free our memory. Return now. */
		if (fatal_signal_pending(current))
			return SWAP_CLUSTER_MAX;
	}

	lru_add_drain();
	/* 如果sc->may_unmap没有设置,那么设置isolate_mode的ISOLATE_UNMAPPED位 */
	if (!sc->may_unmap)
		isolate_mode |= ISOLATE_UNMAPPED;
	/* 如果sc->may_writepage没有设置,那么设置isolate_mode的ISOLATE_CLEAN位 */
	if (!sc->may_writepage)
		isolate_mode |= ISOLATE_CLEAN;

	spin_lock_irq(&pgdat->lru_lock);

	/* 分离了nr_taken个页面出来,存放在page_list链表里面 scan了nr_scanned个page */
	nr_taken = isolate_lru_pages(nr_to_scan, lruvec, &page_list,
				     &nr_scanned, sc, isolate_mode, lru);
	/* void __mod_node_page_state(struct pglist_data *pgdat, enum node_stat_item item,
	 *		long delta)
	 * {
	 *	struct per_cpu_nodestat __percpu *pcp = pgdat->per_cpu_nodestats;
	 *	s8 __percpu *p = pcp->vm_node_stat_diff + item;
	 *	long x;
	 *	long t;
	 *
	 *	x = delta + __this_cpu_read(*p);
	 *
	 *	t = __this_cpu_read(pcp->stat_threshold);
	 *
	 *	if (unlikely(x > t || x < -t)) {
	 *		node_page_state_add(x, pgdat, item);
	 *		x = 0;
	 *	}
	 *	__this_cpu_write(*p, x);
	 * }
	 */
	__mod_node_page_state(pgdat, NR_ISOLATED_ANON + file, nr_taken);
	/* recent_scanned加上我们刚刚分离出来的页面数 */
	reclaim_stat->recent_scanned[file] += nr_taken;
	/* 如果是global_reclaim */
	if (global_reclaim(sc)) {
		/* 增加NR_PAGES_SCANNED的数量nr_scanned */
		__mod_node_page_state(pgdat, NR_PAGES_SCANNED, nr_scanned);
		/*  static inline void __count_vm_events(enum vm_event_item item, long delta)
		 * {
		 *	raw_cpu_add(vm_event_states.event[item], delta);
		 * }
		 */

		/* 如果当前进程是kswapd,那么就vm_event_states.event[PGSCAN_KSWAPD] + nr_scanned
		 * 否则vm_event_states.event[PGSCAN_DIRECT] + nr_scanned
		 */
		if (current_is_kswapd())
			__count_vm_events(PGSCAN_KSWAPD, nr_scanned);
		else
			__count_vm_events(PGSCAN_DIRECT, nr_scanned);
	}
	spin_unlock_irq(&pgdat->lru_lock);
	/* 如果分离出的页面是0,那么直接返回0 */
	if (nr_taken == 0)
		return 0;
	/* nr_reclaimed 表示回收的页面数量 */
	nr_reclaimed = shrink_page_list(&page_list, pgdat, sc, TTU_UNMAP,
				&nr_dirty, &nr_unqueued_dirty, &nr_congested,
				&nr_writeback, &nr_immediate,
				false);

	spin_lock_irq(&pgdat->lru_lock);
	/* 这里就是计数,如果是全局回收
	 * 如果是kswapd,那么就让PGSTEAL_KSWAPD增加nr_reclaimed
	 * 否则就是直接回收,那么就让PGSTEAL_DIRECT增加nr_reclaimed
	 */
	if (global_reclaim(sc)) {
		if (current_is_kswapd())
			__count_vm_events(PGSTEAL_KSWAPD, nr_reclaimed);
		else
			__count_vm_events(PGSTEAL_DIRECT, nr_reclaimed);
	}

	/* page_list是shrink_page_list处理之后的,也就是说其中有些页面没有回收,还存放在这里面的链表 */
	putback_inactive_pages(lruvec, &page_list);
	/* 将NR_ISOLATED_ANON + file 计数减去nr_taken */
	__mod_node_page_state(pgdat, NR_ISOLATED_ANON + file, -nr_taken);

	spin_unlock_irq(&pgdat->lru_lock);

	mem_cgroup_uncharge_list(&page_list);
	/* free掉page_list中的页面,这里面的页面已经全部属于可以释放的页面了 */
	free_hot_cold_page_list(&page_list, true);

	/*
	 * If reclaim is isolating dirty pages under writeback, it implies
	 * that the long-lived page allocation rate is exceeding the page
	 * laundering rate. Either the global limits are not being effective
	 * at throttling processes due to the page distribution throughout
	 * zones or there is heavy usage of a slow backing device. The
	 * only option is to throttle from reclaim context which is not ideal
	 * as there is no guarantee the dirtying process is throttled in the
	 * same way balance_dirty_pages() manages.
	 *
	 * Once a zone is flagged ZONE_WRITEBACK, kswapd will count the number
	 * of pages under pages flagged for immediate reclaim and stall if any
	 * are encountered in the nr_immediate check below.
	 *
	 * 如果回收是在写回下隔离脏页,则意味着长期页面分配率超过了页面清洗率.
	 * 由于页面分布在各个zone中全局限制无法有效地限制进程,或者大量使用慢速备份设备.
	 * 唯一的选择是从回收上下文中进行节流,这并不理想,因为无法保证以balance_dirty_pages管理的方式来节流清理过程。
	 *
	 * 一旦zone被标记为ZONE_WRITEBACK,kswapd将计算标记为立即回收的页面下的页面数量,如果在下面的nr_immediate检查中遇到任何页面,则会暂停。
	 */
	if (nr_writeback && nr_writeback == nr_taken)
		set_bit(PGDAT_WRITEBACK, &pgdat->flags);

	/*
	 * Legacy memcg will stall in page writeback so avoid forcibly
	 * stalling here.
	 */
	if (sane_reclaim(sc)) {
		/*
		 * Tag a zone as congested if all the dirty pages scanned were
		 * backed by a congested BDI and wait_iff_congested will stall.
		 */
		if (nr_dirty && nr_dirty == nr_congested)
			set_bit(PGDAT_CONGESTED, &pgdat->flags);

		/*
		 * If dirty pages are scanned that are not queued for IO, it
		 * implies that flushers are not keeping up. In this case, flag
		 * the pgdat PGDAT_DIRTY and kswapd will start writing pages from
		 * reclaim context.
		 */
		if (nr_unqueued_dirty == nr_taken)
			set_bit(PGDAT_DIRTY, &pgdat->flags);

		/*
		 * If kswapd scans pages marked marked for immediate
		 * reclaim and under writeback (nr_immediate), it implies
		 * that pages are cycling through the LRU faster than
		 * they are written so also forcibly stall.
		 */
		if (nr_immediate && current_may_throttle())
			congestion_wait(BLK_RW_ASYNC, HZ/10);
	}

	/*
	 * Stall direct reclaim for IO completions if underlying BDIs or zone
	 * is congested. Allow kswapd to continue until it starts encountering
	 * unqueued dirty pages or cycling through the LRU too quickly.
	 *
	 * 如果基础BDI或zone拥塞,则暂停IO完成的直接回收.
	 * 允许kswapd继续,直到它开始遇到为排队的脏页面或者过快地循环通过LRU.
	 */
	/* 在linux 3.11之前的内核,很多用户抱怨大文件复制或备份操作会导致系统宕机或应用被swap出去.
	 * 有时内存短缺的情况下,突然有大量的内存要被回收,而有时应用程序或kswapd线程的CPU占用率长时间为100%.
	 * 因此,linux 3.11以后的内核对此进行了优化,对于处于回写状态的页面会做统计,如果shrink_page_list扫描一轮之后发现有大量处于回写状态的页面,
	 * 则设置zone_flag中的ZONE_WRITEBACK标志位.在下一轮扫描时,如果kswapd内核线程还遇到回写页面,
	 * 那么认为LRU扫描的速度比页面IO回写的速度块,这是强制让kswapd睡眠等待100毫秒
	 * congestion_wait(BLK_RW_ASYNC,HZ/10)
	 */
	if (!sc->hibernation_mode && !current_is_kswapd() &&
	    current_may_throttle())
		wait_iff_congested(pgdat, BLK_RW_ASYNC, HZ/10);

	trace_mm_vmscan_lru_shrink_inactive(pgdat->node_id,
			nr_scanned, nr_reclaimed,
			sc->priority, file);
	/* 返回已经回收的页面数量 */
	return nr_reclaimed;
}

/*
 * This moves pages from the active list to the inactive list.
 *
 * We move them the other way if the page is referenced by one or more
 * processes, from rmap.
 *
 * If the pages are mostly unmapped, the processing is fast and it is
 * appropriate to hold zone_lru_lock across the whole operation.  But if
 * the pages are mapped, the processing is slow (page_referenced()) so we
 * should drop zone_lru_lock around each page.  It's impossible to balance
 * this, so instead we remove the pages from the LRU while processing them.
 * It is safe to rely on PG_active against the non-LRU pages in here because
 * nobody will play with that bit on a non-LRU page.
 *
 * The downside is that we have to touch page->_refcount against each page.
 * But we had to alter page->flags anyway.
 *
 * 这会将页面从活动列表移动到非活动列表.
 *
 * 如果页面被来自rmap的一个或多个进程引用,我们会将它们移到另一种方式。
 *
 * 如果页面大多未映射,则处理速度很快,并且在整个操作中在zone_lru_lock保护下是合适的.
 * 但是,如果页面被映射,处理速度会很慢(page_referenced()),所以我们应该在每个页面dropzone_lru_lock.
 * 这是不可能平衡的,所以我们在处理页面时从LRU中删除页面。
 * 对此处的非LRU页面使用PG_active是安全的，因为没有人会在非LRU页面上玩该位.
 *
 * 不利的一面是,我们必须针对每一页touch page->_refcount.
 * 但我们还是不得不更改page->flags
 */

static void move_active_pages_to_lru(struct lruvec *lruvec,
				     struct list_head *list,
				     struct list_head *pages_to_free,
				     enum lru_list lru)
{
	struct pglist_data *pgdat = lruvec_pgdat(lruvec);
	unsigned long pgmoved = 0;
	struct page *page;
	int nr_pages;

	/* 如果list不为空 */
	while (!list_empty(list)) {
		/* 拿到这个链表的最后一个page */
		page = lru_to_page(list);
		/* 拿到相关的lruvec */
		lruvec = mem_cgroup_page_lruvec(page, pgdat);
		/* 如果该page不在LRU链表里面
		 * 那么就报个BUG吧
		 */
		VM_BUG_ON_PAGE(PageLRU(page), page);
		/* 设置Page的PG_lru */
		SetPageLRU(page);

		/* 获得该page的page数量 */
		nr_pages = hpage_nr_pages(page);
		/* update lru size
		 * static __always_inline void __update_lru_size(struct lruvec *lruvec,
		 *	enum lru_list lru, enum zone_type zid,int nr_pages)
		 * {
		 *	struct pglist_data *pgdat = lruvec_pgdat(lruvec);
		 *	__mod_node_page_state(pgdat, NR_LRU_BASE + lru, nr_pages);
		 *	__mod_zone_page_state(&pgdat->node_zones[zid],
		 *	NR_ZONE_LRU_BASE + lru, nr_pages);
		 * }
		 * static __always_inline void update_lru_size(struct lruvec *lruvec,
		 *	enum lru_list lru, enum zone_type zid,int nr_pages)
		 * {
		 *	__update_lru_size(lruvec, lru, zid, nr_pages);
		 * #ifdef CONFIG_MEMCG
		 * mem_cgroup_update_lru_size(lruvec, lru, zid, nr_pages);
		 * #endif
		 * }
		 */
		update_lru_size(lruvec, lru, page_zonenum(page), nr_pages);

		/* 将page移动到相关的链表里面去 */
		list_move(&page->lru, &lruvec->lists[lru]);
		/* 算移动的pages的个数 */
		pgmoved += nr_pages;

		/* 因为我们在isolate_lru_pages中对page的_refcount进行了+1
		 * 所以这里需要将_refcount -1,然后判断是否等于0 */
		if (put_page_testzero(page)) {
			/* 清除PG_lru标志 */
			__ClearPageLRU(page);
			/* 清除PageActive标志 */
			__ClearPageActive(page);
			/* 从lru链表里面删除这个page */
			del_page_from_lru_list(page, lruvec, lru);

			if (unlikely(PageCompound(page))) {
				spin_unlock_irq(&pgdat->lru_lock);
				mem_cgroup_uncharge(page);
				(*get_compound_page_dtor(page))(page);
				spin_lock_irq(&pgdat->lru_lock);
			} else	/* 添加到pages_to_free链表里面 */
				list_add(&page->lru, pages_to_free);
		}
	}
	/* 如果是非活跃链表,把PGDEACTIVATE + pgmoved */
	if (!is_active_lru(lru))
		__count_vm_events(PGDEACTIVATE, pgmoved);
}

static void shrink_active_list(unsigned long nr_to_scan,
			       struct lruvec *lruvec,
			       struct scan_control *sc,
			       enum lru_list lru)
{
	unsigned long nr_taken;
	unsigned long nr_scanned;
	unsigned long vm_flags;
	/* 定义3个临时链表l_hold、l_active和l_inactive.
	 * 在操作LRU链表时,有一把保护LRU的spinlock锁zone->lru_lock.
	 * isolate_lru_pages批量地把LRU链表的部分页面先迁移到临时链表中,从而减少加锁的时间
	 */
	LIST_HEAD(l_hold);	/* The pages which were snipped off */
	LIST_HEAD(l_active);
	LIST_HEAD(l_inactive);
	struct page *page;
	struct zone_reclaim_stat *reclaim_stat = &lruvec->reclaim_stat;
	unsigned long nr_rotated = 0;
	isolate_mode_t isolate_mode = 0;
	int file = is_file_lru(lru);
	/* 拿到我们的pgdat数据结构 */
	struct pglist_data *pgdat = lruvec_pgdat(lruvec);

	lru_add_drain();

	if (!sc->may_unmap)
		isolate_mode |= ISOLATE_UNMAPPED;
	if (!sc->may_writepage)
		isolate_mode |= ISOLATE_CLEAN;

	spin_lock_irq(&pgdat->lru_lock);
	/* isolate_lru_pages批量从LRU链表中分离nr_to_scan个页面到l_hold链表里,这里会根据isolate_mode
	 * 来考虑一些特殊情况,基本上就是把LRU链表的页面迁移到临时l_hold链表中
	 */
	nr_taken = isolate_lru_pages(nr_to_scan, lruvec, &l_hold,
				     &nr_scanned, sc, isolate_mode, lru);
	/* void __mod_node_page_state(struct pglist_data *pgdat, enum node_stat_item item,
	 * long delta)
	 * {
	 *	struct per_cpu_nodestat __percpu *pcp = pgdat->per_cpu_nodestats;
	 *	s8 __percpu *p = pcp->vm_node_stat_diff + item;
	 *	long x;
	 *	long t;
	 *
	 *	x = delta + __this_cpu_read(*p);
	 *	t = __this_cpu_read(pcp->stat_threshold);
	 *
	 *	if (unlikely(x > t || x < -t)) {
	 *		node_page_state_add(x, pgdat, item);
	 *		x = 0;
	 *	}
	 *	__this_cpu_write(*p, x);
	 * }
	 */
	__mod_node_page_state(pgdat, NR_ISOLATED_ANON + file, nr_taken);
	/* reclaim_stat->recent_scanned[file] + 上我们scan的页面 */
	reclaim_stat->recent_scanned[file] += nr_taken;
	/* 如果是global_reclaim,那么
	 * 那么
	 * void __mod_node_page_state(struct pglist_data *pgdat, enum node_stat_item item,
	 *	long delta)
	 * {
	 *	struct per_cpu_nodestat __percpu *pcp = pgdat->per_cpu_nodestats;
	 *	s8 __percpu *p = pcp->vm_node_stat_diff + item;
	 *	long x;
	 *	long t;
	 *	x = delta + __this_cpu_read(*p);
	 *
	 *	t = __this_cpu_read(pcp->stat_threshold);
	 *
	 *	if (unlikely(x > t || x < -t)) {
	 *		node_page_state_add(x, pgdat, item);
	 *		x = 0;
	 *	}
	 *	__this_cpu_write(*p, x);
	 * }
	 */
	if (global_reclaim(sc))
		__mod_node_page_state(pgdat, NR_PAGES_SCANNED, nr_scanned);
	/* 将vm_event_states的PGREFILL + nr_scanned
	 *
	 * static inline void __count_vm_events(enum vm_event_item item, long delta)
	 * {
	 * 	raw_cpu_add(vm_event_states.event[item], delta);
	 * }
	 */
	__count_vm_events(PGREFILL, nr_scanned);
	spin_unlock_irq(&pgdat->lru_lock);

	while (!list_empty(&l_hold)) {
		cond_resched();
		/* #define lru_to_page(head) (list_entry((head)->prev, struct page, lru)) */
		/* 这里进行一个page 一个page的处理
		 * 从这个链表的最后一个page开始处理
		 */
		page = lru_to_page(&l_hold);
		/* 把page从lru的链表中删除 */
		list_del(&page->lru);
		/* 如果page是不可回收的,注意这里不是测试flag
		 *
		 * int page_evictable(struct page *page)
		 * {
		 *	int ret;
		 * 	Prevent address_space of inode and swap cache from being freed
		 *	rcu_read_lock();
		 *	ret = !mapping_unevictable(page_mapping(page)) && !PageMlocked(page);
		 *	rcu_read_unlock();
		 *	return ret;
		 * }
		 */
		if (unlikely(!page_evictable(page))) {
			/* 把页面放回到相关的链表里面去 */
			putback_lru_page(page);
			continue;
		}
		/* 如果buffer_heads已经超过了limit,那么尝试释放该page */
		if (unlikely(buffer_heads_over_limit)) {
			/* 这个private是只有buffer_heads的时候才有
			 * 也就是说缓冲读的时候才有
			 */
			if (page_has_private(page) && trylock_page(page)) {
				if (page_has_private(page))
					try_to_release_page(page, 0);
				unlock_page(page);
			}
		}

		/* 这里是看这个page有没有访问引用(实际上就是看有多少个进程映射了它) */
		if (page_referenced(page, 0, sc->target_mem_cgroup,
				    &vm_flags)) {
			/* 这里是个BUG,因为nr_rotated反应的是活跃页面的数量
			 * 这里应该要放到list_add(&page->lru, &l_active)
			 * 而不是这里,因为在这里加实际上还是有可能把这个页面添加到inactive里面去
			 * 这里将nr_rotated加上该pages数量
			 */
			nr_rotated += hpage_nr_pages(page);
			/*
			 * Identify referenced, file-backed active pages and
			 * give them one more trip around the active list. So
			 * that executable code get better chances to stay in
			 * memory under moderate memory pressure.  Anon pages
			 * are not likely to be evicted by use-once streaming
			 * IO, plus JVM can create lots of anon VM_EXEC pages,
			 * so we ignore them here.
			 *
			 * 识别被refrenced,后备文件的活跃页面,让它们在活动列表中再循环一次
			 * 这样可执行代码就有更好的机会在内存压力下留在内存中.
			 * 一旦使用流式IO,Anon页面不太可能被回收,加上JVM可以创建许多Anon VM_EXEC页面,所以我们在这里忽略它们.
			 */

			/* 如果vm有可执行权限并且是page cache的
			 * 那么把它添加到活跃链表里面去
			 */
			if ((vm_flags & VM_EXEC) && page_is_file_cache(page)) {
				list_add(&page->lru, &l_active);
				continue;
			}
		}
		/* 清除PG_active标志位 */
		ClearPageActive(page);	/* we are de-activating */
		/* 把它添加到非活跃链表里面去 */
		list_add(&page->lru, &l_inactive);
	}

	/*
	 * Move pages back to the lru list.
	 */
	spin_lock_irq(&pgdat->lru_lock);
	/*
	 * Count referenced pages from currently used mappings as rotated,
	 * even though only some of them are actually re-activated.  This
	 * helps balance scan pressure between file and anonymous pages in
	 * get_scan_count.
	 *
	 * 将当前使用的映射中的引用页计数为rotated,即使实际上只有其中一些被重新激活.
	 * 这有助于在get_scan_count中平衡文件页和匿名页之间的扫描压力。
	 */
	reclaim_stat->recent_rotated[file] += nr_rotated;

	/* 把 l_active和 l_inactive 链表的页迁移到LRU相应的链表中 */
	move_active_pages_to_lru(lruvec, &l_active, &l_hold, lru);
	move_active_pages_to_lru(lruvec, &l_inactive, &l_hold, lru - LRU_ACTIVE);
	__mod_node_page_state(pgdat, NR_ISOLATED_ANON + file, -nr_taken);
	spin_unlock_irq(&pgdat->lru_lock);

	mem_cgroup_uncharge_list(&l_hold);
	/* l_hold是剩下的页面,可以释放 */
	free_hot_cold_page_list(&l_hold, true);
}

/*
 * The inactive anon list should be small enough that the VM never has
 * to do too much work.
 *
 * The inactive file list should be small enough to leave most memory
 * to the established workingset on the scan-resistant active list,
 * but large enough to avoid thrashing the aggregate readahead window.
 *
 * Both inactive lists should also be large enough that each inactive
 * page has a chance to be referenced again before it is reclaimed.
 *
 * The inactive_ratio is the target ratio of ACTIVE to INACTIVE pages
 * on this LRU, maintained by the pageout code. A zone->inactive_ratio
 * of 3 means 3:1 or 25% of the pages are kept on the inactive list.
 *
 * total     target    max
 * memory    ratio     inactive
 * -------------------------------------
 *   10MB       1         5MB
 *  100MB       1        50MB
 *    1GB       3       250MB
 *   10GB      10       0.9GB
 *  100GB      31         3GB
 *    1TB     101        10GB
 *   10TB     320        32GB
 *
 * 非活动的匿名页面列表应该足够小，这样VM就不必做太多的工作。
 *
 * 非活动文件列表应足够小,以将大部分内存留给抵制-扫描的活动列表上已建立的工作集
 * 但应足够大,以避免破坏聚合预读窗口.
 *
 * 两个非活动列表也应该足够大，以便每个非活动页面在回收之前都有机会再次被引用。
 *
 * inactive_ratio是该LRU上ACTIVE与inactive页面的目标比率,由pageout代码维护.
 * zone->inactive_ratio为3意味着3:1或25%的页面保留在非活动列表中.
 *
 * total     target    max
 * memory    ratio     inactive
 * -------------------------------------
 *   10MB       1         5MB
 *  100MB       1        50MB
 *    1GB       3       250MB
 *   10GB      10       0.9GB
 * 100GB      31         3GB
 *    1TB     101        10GB
 *   10TB     320        32GB
 */

static bool inactive_list_is_low(struct lruvec *lruvec, bool file,
						struct scan_control *sc)
{
	unsigned long inactive_ratio;
	unsigned long inactive, active;
	enum lru_list inactive_lru = file * LRU_FILE;
	enum lru_list active_lru = file * LRU_FILE + LRU_ACTIVE;
	unsigned long gb;

	/*
	 * If we don't have swap space, anonymous page deactivation
	 * is pointless.
	 *
	 * 如果我们没有交换空间，匿名页面停用是毫无意义的.
	 */
	if (!file && !total_swap_pages)
		return false;

	inactive = lruvec_lru_size(lruvec, inactive_lru, sc->reclaim_idx);
	active = lruvec_lru_size(lruvec, active_lru, sc->reclaim_idx);

	gb = (inactive + active) >> (30 - PAGE_SHIFT);
	if (gb)
		inactive_ratio = int_sqrt(10 * gb);
	else
		inactive_ratio = 1;

	return inactive * inactive_ratio < active;
}

static unsigned long shrink_list(enum lru_list lru, unsigned long nr_to_scan,
				 struct lruvec *lruvec, struct scan_control *sc)
{
	/* 处理活跃的LRU链表,包括匿名页面和文件映射页面,如果不活跃页面少于活跃页面,
	 * 那么需要调用shrink_active_list函数来看哪些活跃页面可以迁移到不活跃页面链表中
	 * 为什么活跃LRU链表页面的数量少于不活跃LRU时,不去扫描活跃LRU呢?
	 * 系统常常会有只使用一次的文件访问的情况,不活跃LRU链表增长速度变快,不活跃LRU页面数量
	 * 大于活跃页面数量,这时不会去扫描活跃LRU
	 */
	if (is_active_lru(lru)) {
		if (inactive_list_is_low(lruvec, is_file_lru(lru), sc))
			shrink_active_list(nr_to_scan, lruvec, sc, lru);
		return 0;
	}

	return shrink_inactive_list(nr_to_scan, lruvec, sc, lru);
}

enum scan_balance {
	SCAN_EQUAL,
	SCAN_FRACT,
	SCAN_ANON,
	SCAN_FILE,
};

/*
 * Determine how aggressively the anon and file LRU lists should be
 * scanned.  The relative value of each set of LRU lists is determined
 * by looking at the fraction of the pages scanned we did rotate back
 * onto the active list instead of evict.
 *
 * nr[0] = anon inactive pages to scan; nr[1] = anon active pages to scan
 * nr[2] = file inactive pages to scan; nr[3] = file active pages to scan
 */

/* 根据swappiness参数和sc->priority优先级去计算4个LRU链表中应该扫描的页面页数,
 * 结果存放在nr[]数组中,扫描规则总结如下
 * 1、如果系统没有swap交换分区或者SWAP空间,则不用扫描匿名页面.
 * 2、如果zone_free + zone_lru_file <= watermark[WMARK_HIGH],那么只扫描匿名页面
 * 3、如果LRU_INACTIVE_FILE > LRU_ACTIVE_FILE,那么只扫描文件映射页面
 * 4、除此之外,两种页面都要扫描
 *
 * 扫描页面计算公式如下
 * 1、扫描一种页面(如果我没有swap空间,那就是说得这种情况)
 *    scan = LRU上总页面数 >> sc->priority
 * 2、同时扫描两种页面
 *    scan = LRU上总页面数 >> sc->priority
 *    ap = (swappniess * (recent_scanned[0] + 1)) / ( recent_rotated[0] + 1)
 *    fp = ((200 - swappniess)) * (recent_scanned[1] + 1) / ( recent_rotated[1] + 1)
 *    scan_anon = (scan * ap) / (ap + fp +1)
 *    scan_file = (scan * fp) / (ap + fp +1)
 * recent_scanned: 指最近扫描页面的数量,在扫描活跃链表和不活跃链表时,会统计到recent_scanned变量中.
 *		   详见shrink_inactive_list()函数和shrink_active_list()函数.
 * recent_rotated: 1、在扫描不活跃链表时,统计那些被踢回活跃链表的页面数量到recent_rotated变量中,
 *                 详见shrink_inactive_list -> putback_inactive_pages
 *		   2、在扫描活跃页面时,访问引用的页面也被加入到recent_rotated变量.
 *		   3、总之,该变量反映了真实的活跃页面的数量
 */

static void get_scan_count(struct lruvec *lruvec, struct mem_cgroup *memcg,
			   struct scan_control *sc, unsigned long *nr,
			   unsigned long *lru_pages)
{
	/* 拿到swappiness */
	int swappiness = mem_cgroup_swappiness(memcg);
	struct zone_reclaim_stat *reclaim_stat = &lruvec->reclaim_stat;
	u64 fraction[2];
	u64 denominator = 0;	/* gcc */
	/* 拿到pgdat */
	struct pglist_data *pgdat = lruvec_pgdat(lruvec);
	unsigned long anon_prio, file_prio;
	enum scan_balance scan_balance;
	unsigned long anon, file;
	bool force_scan = false;
	unsigned long ap, fp;
	enum lru_list lru;
	bool some_scanned;
	int pass;

	/*
	 * If the zone or memcg is small, nr[l] can be 0.  This
	 * results in no scanning on this priority and a potential
	 * priority drop.  Global direct reclaim can go to the next
	 * zone and tends to have no problems. Global kswapd is for
	 * zone balancing and it needs to scan a minimum amount. When
	 * reclaiming for a memcg, a priority drop can cause high
	 * latencies, so it's better to scan a minimum amount there as
	 * well.
	 *
	 * 如果zone或memcg较小,则nr[l]可以为0.
	 * 这导致没有对此优先级进行扫描,并且可能导致优先级下降.
	 * 全局的直接回收可以进入下一个zone,而且往往没有问题.
	 * 全局kswapd用于zone平衡,它需要扫描最小的数量.
	 * 当回收memcg时,优先级下降可能会导致高延迟,因此最好也扫描最小的数量.
	 */

	/* 如果当前进程是kswapd的话 */
	if (current_is_kswapd()) {
		/*  bool pgdat_reclaimable(struct pglist_data *pgdat)
		 * {
		 *	return node_page_state_snapshot(pgdat, NR_PAGES_SCANNED) <
		 *		pgdat_reclaimable_pages(pgdat) * 6;
		 * }
		 */
		if (!pgdat_reclaimable(pgdat))
			force_scan = true;
		if (!mem_cgroup_online(memcg))
			force_scan = true;
	}
	if (!global_reclaim(sc))
		force_scan = true;

	/* If we have no swap space, do not bother scanning anon pages. */
	/* 如果我们没有swap空间或者说sc->may_swap 设置为0,那么不要扫描匿名页面 */
	if (!sc->may_swap || mem_cgroup_get_nr_swap_pages(memcg) <= 0) {
		scan_balance = SCAN_FILE;
		goto out;
	}

	/*
	 * Global reclaim will swap to prevent OOM even with no
	 * swappiness, but memcg users want to use this knob to
	 * disable swapping for individual groups completely when
	 * using the memory controller's swap limit feature would be
	 * too expensive.
	 *
	 * 全局回收将进行交换以防止OOM，即使没有swappiness
	 * 但memcg用户希望使用此旋钮去完全禁用单个groups的交换,因为使用内存控制器的swap limit功能会过于昂贵.
	 */
	if (!global_reclaim(sc) && !swappiness) {
		scan_balance = SCAN_FILE;
		goto out;
	}

	/*
	 * Do not apply any pressure balancing cleverness when the
	 * system is close to OOM, scan both anon and file equally
	 * (unless the swappiness setting disagrees with swapping).
	 *
	 * 当系统接近OOM时,不要应用任何压力平衡技巧,平均扫描anon和file(除非swappiness为0).
	 */
	if (!sc->priority && swappiness) {
		/* SCAN_EQUAL 计算出的扫描值按原样使用 */
		scan_balance = SCAN_EQUAL;
		goto out;
	}

	/*
	 * Prevent the reclaimer from falling into the cache trap: as
	 * cache pages start out inactive, every cache fault will tip
	 * the scan balance towards the file LRU.  And as the file LRU
	 * shrinks, so does the window for rotation from references.
	 * This means we have a runaway feedback loop where a tiny
	 * thrashing file LRU becomes infinitely more attractive than
	 * anon pages.  Try to detect this based on file LRU size.
	 *
	 * 防止回收器落入缓存陷阱:当cache 页面开始处于非活动状态时,每个cache fault都会使scan balance 向file LRU倾斜.
	 * 随着file LRU的缩小,从references rotation的窗口也会缩小。
	 * 这意味着我们有一个失控的反馈循环，在这个循环中,一个微小的颠簸file LRU变得比一个匿名页面更有吸引力.
	 * 尝试根据file LRU大小检测此问题。
	 */
	if (global_reclaim(sc)) {
		unsigned long pgdatfile;
		unsigned long pgdatfree;
		int z;
		unsigned long total_high_wmark = 0;
		/* 拿到这个node的FREE_PAGES */
		pgdatfree = sum_zone_node_page_state(pgdat->node_id, NR_FREE_PAGES);
		/* 拿到这个node的file pages数 */
		pgdatfile = node_page_state(pgdat, NR_ACTIVE_FILE) +
			   node_page_state(pgdat, NR_INACTIVE_FILE);

		for (z = 0; z < MAX_NR_ZONES; z++) {
			struct zone *zone = &pgdat->node_zones[z];
			if (!managed_zone(zone))
				continue;
			/* total_high_wmark 等于整个node的各个zone的高水位相加 */
			total_high_wmark += high_wmark_pages(zone);
		}

		/* 如果pgdatfile + pgdatfree(也就是这个node里面的FREE_PAGES + 这个node里面的page cache的和)
		 * 都比整个高水位之和小,那说明大部分的页面都被匿名页面用掉了
		 * 那么就扫描匿名页面
		 */
		if (unlikely(pgdatfile + pgdatfree <= total_high_wmark)) {
			scan_balance = SCAN_ANON;
			goto out;
		}
	}

	/*
	 * If there is enough inactive page cache, i.e. if the size of the
	 * inactive list is greater than that of the active list *and* the
	 * inactive list actually has some pages to scan on this priority, we
	 * do not reclaim anything from the anonymous working set right now.
	 * Without the second condition we could end up never scanning an
	 * lruvec even if it has plenty of old anonymous pages unless the
	 * system is under heavy pressure.
	 *
	 * 如果有足够的非活动页面缓存,如果非活动列表的大小大于活动列表的大小,并且非活动列表实际上有一些页面在此优先级上扫描,
	 * 我们现在不会从匿名页面工作集中回收任何内容.
	 * 如果没有第二个条件,我们可能永远不会扫描lruvec,即使它有很多旧的匿名页面，除非系统承受巨大压力。
	 */

	/* 如果page cache(第二个参数表示是不是page cache)的不活跃链表没有到low,且sc->reclaim_idx以及其以下的LRU_INACTIVE_FILE lru size还能在sc->priority粒度下分离出页面
	 * 那么就扫描文件页面
	 */
	if (!inactive_list_is_low(lruvec, true, sc) &&
	    lruvec_lru_size(lruvec, LRU_INACTIVE_FILE, sc->reclaim_idx) >> sc->priority) {
		scan_balance = SCAN_FILE;
		goto out;
	}
	/* SCAN_FRACT 将分数应用于计算的扫描值 */
	scan_balance = SCAN_FRACT;

	/*
	 * With swappiness at 100, anonymous and file have the same priority.
	 * This scanning priority is essentially the inverse of IO cost.
	 *
	 * 当swappiness为100时，匿名页面和文件页面具有相同的优先级.
	 * 该扫描优先级本质上是IO成本的倒数.
	 */

	anon_prio = swappiness;
	file_prio = 200 - anon_prio;

	/*
	 * OK, so we have swap space and a fair amount of page cache
	 * pages.  We use the recently rotated / recently scanned
	 * ratios to determine how valuable each cache is.
	 *
	 * Because workloads change over time (and to avoid overflow)
	 * we keep these statistics as a floating average, which ends
	 * up weighing recent references more than old ones.
	 *
	 * anon in [0], file in [1]
	 *
	 * OK,所以我们有交换空间和相当多的page cache的页面.
	 * 我们使用最近 rotated/最近scanned 的比率来确定每个缓存的价值.
	 *
	 * 因为工作负载会随着时间的推移而变化(并避免溢出)
	 * 我们将这些统计数据作为一个浮动平均值,它最终比旧的更能权衡最近的references
	 *
	 * anon在[0]中，file在[1]中
	 */

	/* 拿到这个node中所有的匿名页面 */
	anon  = lruvec_lru_size(lruvec, LRU_ACTIVE_ANON, MAX_NR_ZONES) +
		lruvec_lru_size(lruvec, LRU_INACTIVE_ANON, MAX_NR_ZONES);
	/* 拿到这个node中所有的page cache */
	file  = lruvec_lru_size(lruvec, LRU_ACTIVE_FILE, MAX_NR_ZONES) +
		lruvec_lru_size(lruvec, LRU_INACTIVE_FILE, MAX_NR_ZONES);

	spin_lock_irq(&pgdat->lru_lock);
	/* 如果最近扫描的匿名页面大于总的匿名页面的1/4
	 * 那么每个都减半
	 */
	if (unlikely(reclaim_stat->recent_scanned[0] > anon / 4)) {
		reclaim_stat->recent_scanned[0] /= 2;
		reclaim_stat->recent_rotated[0] /= 2;
	}

	/* 如果最近扫描的page cache 大于总的page cache的1/4
	 * 那么每个都减半
	 */
	if (unlikely(reclaim_stat->recent_scanned[1] > file / 4)) {
		reclaim_stat->recent_scanned[1] /= 2;
		reclaim_stat->recent_rotated[1] /= 2;
	}

	/*
	 * The amount of pressure on anon vs file pages is inversely
	 * proportional to the fraction of recently scanned pages on
	 * each list that were recently referenced and in active use.
	 */

	/* ap = anon_prio * (reclaim_stat->recent_scanned[0] + 1) / (reclaim_stat->recent_rotated[0] + 1 ) */
	ap = anon_prio * (reclaim_stat->recent_scanned[0] + 1);
	ap /= reclaim_stat->recent_rotated[0] + 1;

	/* fp = file_prio * (reclaim_stat->recent_scanned[1] + 1) / (reclaim_stat->recent_rotated[1] + 1) */
	fp = file_prio * (reclaim_stat->recent_scanned[1] + 1);
	fp /= reclaim_stat->recent_rotated[1] + 1;
	spin_unlock_irq(&pgdat->lru_lock);
	/* fraction 应该是分子的意思? */
	fraction[0] = ap;
	fraction[1] = fp;
	/* denominator 是说分母的意思 */
	denominator = ap + fp + 1;
out:
	some_scanned = false;
	/* Only use force_scan on second pass. */
	for (pass = 0; !some_scanned && pass < 2; pass++) {
		*lru_pages = 0;
		/* #define for_each_evictable_lru(lru) for (lru = 0; lru <= LRU_ACTIVE_FILE; lru++) */
		for_each_evictable_lru(lru) {
			/* file是判断是不是file lru */
			int file = is_file_lru(lru);
			unsigned long size;
			unsigned long scan;
			/* 拿到sc->reclaim_idx及其以下的lru的大小 */
			size = lruvec_lru_size(lruvec, lru, sc->reclaim_idx);
			scan = size >> sc->priority;

			if (!scan && pass && force_scan)
				scan = min(size, SWAP_CLUSTER_MAX);

			switch (scan_balance) {
			case SCAN_EQUAL:
				/* Scan lists relative to size */
				break;
			case SCAN_FRACT:
				/*
				 * Scan types proportional to swappiness and
				 * their relative recent reclaim efficiency.
				 */
				scan = div64_u64(scan * fraction[file],
							denominator);
				break;
			case SCAN_FILE:
			case SCAN_ANON:
				/* Scan one type exclusively */
				if ((scan_balance == SCAN_FILE) != file) {
					size = 0;
					scan = 0;
				}
				break;
			default:
				/* Look ma, no brain */
				BUG();
			}

			/* lru_pages + size */
			*lru_pages += size;
			/* 把它给到nr里面 */
			nr[lru] = scan;

			/*
			 * Skip the second pass and don't force_scan,
			 * if we found something to scan.
			 * 如果我们找到要扫描的东西，跳过第二次，不要强制扫描.
			 */
			some_scanned |= !!scan;
		}
	}
}

/*
 * This is a basic per-node page freer.  Used by both kswapd and direct reclaim.
 */
static void shrink_node_memcg(struct pglist_data *pgdat, struct mem_cgroup *memcg,
			      struct scan_control *sc, unsigned long *lru_pages)
{
	/* 获得目标lruvec，lruvec包含5个lru链表，分别是活跃/非活跃匿名页
	 * 活跃/非活跃文件页，不可回收链表
	 */
	struct lruvec *lruvec = mem_cgroup_lruvec(pgdat, memcg);
	unsigned long nr[NR_LRU_LISTS];
	unsigned long targets[NR_LRU_LISTS];
	unsigned long nr_to_scan;
	enum lru_list lru;
	unsigned long nr_reclaimed = 0;
	unsigned long nr_to_reclaim = sc->nr_to_reclaim;
	struct blk_plug plug;
	bool scan_adjusted;
	/* 根据swappiness参数和sc->priority优先级去计算4个LRU链表中应该扫描的页面页数,
	 * 结果存放在nr[]数组中,扫描规则总结如下
	 * 1、如果系统没有swap交换分区或者SWAP空间,则不用扫描匿名页面.
	 * 2、如果zone_free + zone_lru_file <= watermark[WMARK_HIGH],那么只扫描匿名页面
	 * 3、如果LRU_INACTIVE_FILE > LRU_ACTIVE_FILE,那么只扫描文件映射页面
	 * 4、除此之外,两种页面都要扫描
	 */
	get_scan_count(lruvec, memcg, sc, nr, lru_pages);

	/* Record the original scan target for proportional adjustments later */
	/* 记录原始扫描的目标为之后的比例调整 */
	memcpy(targets, nr, sizeof(nr));

	/*
	 * Global reclaiming within direct reclaim at DEF_PRIORITY is a normal
	 * event that can occur when there is little memory pressure e.g.
	 * multiple streaming readers/writers. Hence, we do not abort scanning
	 * when the requested number of pages are reclaimed when scanning at
	 * DEF_PRIORITY on the assumption that the fact we are direct
	 * reclaiming implies that kswapd is not keeping up and it is best to
	 * do a batch of work at once. For memcg reclaim one check is made to
	 * abort proportional reclaim if either the file or anon lru has already
	 * dropped to zero at the first pass.
	 *
	 * 当内存压力很小时DEF_PRIORITY处的直接回收内的全局回收可能会发生是一种正常的事情,
	 * 例如多个流式读者/写者.
	 * 因此,当在DEF_PRIORITY扫描时,请求的页面数被回收时,我们不会中止扫描.
	 * 因为我们直接回收的事实意味着kswapd没有跟上,最好一次做一批工作.
	 * 对于memcg回收，如果file或anon lru在第一次通过时已降至零，则进行一次检查以中止比例回收.
	 */
	scan_adjusted = (global_reclaim(sc) && !current_is_kswapd() &&
			 sc->priority == DEF_PRIORITY);

	blk_start_plug(&plug);
	/* 这里循环为什么会漏掉活跃的匿名页面呢(LRU_ACTIVE_ANON)呢?
	 * 因为活跃的匿名页面不能直接回收,根据局部原理,它有可能很快被访问了,匿名页面
	 * 需要经过时间的老化且加入不活跃匿名页面LRU链表后才能被回收
	 */
	while (nr[LRU_INACTIVE_ANON] || nr[LRU_ACTIVE_FILE] ||
					nr[LRU_INACTIVE_FILE]) {
		unsigned long nr_anon, nr_file, percentage;
		unsigned long nr_scanned;
		/* 依次扫描可回收的4种LRU链表,shrink_list函数会具体处理各种LRU链表的情况 */
		for_each_evictable_lru(lru) {
			if (nr[lru]) {
				/* 选nr[lru]和SWAP_CLUSTER_MAX的最小值 */
				nr_to_scan = min(nr[lru], SWAP_CLUSTER_MAX);
				/* nr[lru] -= nr_to_scan */
				nr[lru] -= nr_to_scan;
				/* 将nr_reclaimed 加上刚刚回收的页面数 */
				nr_reclaimed += shrink_list(lru, nr_to_scan,
							    lruvec, sc);
			}
		}

		cond_resched();
		/* 如果已经回收的页面数量(nr_reclaimed)没有达到预期值(nr_to_reclaim),那么继续扫描 */
		if (nr_reclaimed < nr_to_reclaim || scan_adjusted)
			continue;

		/*
		 * For kswapd and memcg, reclaim at least the number of pages
		 * requested. Ensure that the anon and file LRUs are scanned
		 * proportionally what was requested by get_scan_count(). We
		 * stop reclaiming one LRU and reduce the amount scanning
		 * proportional to the original scan target.
		 *
		 * 对于kswapd和memcg,至少回收请求的页数.确保按get_scan_count()请求的比例扫描anon和文件LRU.
		 * 我们停止回收一个LRU,减少与原始扫描目标成比例的扫描量.
		 */

		/* 算出当时需要扫描多少个nr_file以及nr_anon */
		nr_file = nr[LRU_INACTIVE_FILE] + nr[LRU_ACTIVE_FILE];
		nr_anon = nr[LRU_INACTIVE_ANON] + nr[LRU_ACTIVE_ANON];

		/*
		 * It's just vindictive to attack the larger once the smaller
		 * has gone to zero.  And given the way we stop scanning the
		 * smaller below, this makes sure that we only make one nudge
		 * towards proportionality once we've got nr_to_reclaim.
		 *
		 * 一旦较小的变成零,攻击较大的只是报复.
		 * 考虑到我们停止扫描下面较小的部分的方式,这确保了一旦我们得到nr_to_reclaim,我们只朝着比例方向推进一步。
		 */

		/* 如果nr_file或者nr_anon有一方等于0,那么break */
		if (!nr_file || !nr_anon)
			break;
		/* 如果nr_file还要比匿名页面大 */
		if (nr_file > nr_anon) {
			/* 拿到我们之前目标要scan匿名页面的数量 */
			unsigned long scan_target = targets[LRU_INACTIVE_ANON] +
						targets[LRU_ACTIVE_ANON] + 1;
			lru = LRU_BASE;
			/* 用scan的目标数量/目标的页面数量得到一个百分比 */
			percentage = nr_anon * 100 / scan_target;
		} else {
			/* 拿到我们之前目标要scan page cache 的数量 */
			unsigned long scan_target = targets[LRU_INACTIVE_FILE] +
						targets[LRU_ACTIVE_FILE] + 1;
			lru = LRU_FILE;
			/* 用scan的目标数量/目标的页面数量得到一个百分比 */
			percentage = nr_file * 100 / scan_target;
		}

		/* Stop scanning the smaller of the LRU
		 * 停止扫描较小的LRU
		 */
		nr[lru] = 0;
		nr[lru + LRU_ACTIVE] = 0;

		/*
		 * Recalculate the other LRU scan count based on its original
		 * scan target and the percentage scanning already complete
		 *
		 * 其他LRU基于他们原有的scan target和早就完成扫描的百分比来计算扫描的数量
		 */

		/* 判断lru是LRU_BASE还是LRU_FILE */
		lru = (lru == LRU_FILE) ? LRU_BASE : LRU_FILE;
		/* 得到已经扫描过的page数量 */
		nr_scanned = targets[lru] - nr[lru];
		/* 获得剩余的nr[lru]的数量 */
		nr[lru] = targets[lru] * (100 - percentage) / 100;
		/* 减去nr[lru]和nr_scanned中最小的值 */
		nr[lru] -= min(nr[lru], nr_scanned);
		/* 对相关的inactive也进行计算 */
		lru += LRU_ACTIVE;
		nr_scanned = targets[lru] - nr[lru];
		nr[lru] = targets[lru] * (100 - percentage) / 100;
		nr[lru] -= min(nr[lru], nr_scanned);

		scan_adjusted = true;
	}
	blk_finish_plug(&plug);
	/* 将sc->nr_reclaimed 加上我们刚刚回收的页面 */
	sc->nr_reclaimed += nr_reclaimed;

	/*
	 * Even if we did not try to evict anon pages at all, we want to
	 * rebalance the anon lru active/inactive ratio.
	 *
	 * 即使我们根本没有试图驱逐anon页面,我们也希望重新平衡anon lru active/inactive比率.
	 */
	if (inactive_list_is_low(lruvec, false, sc))
		shrink_active_list(SWAP_CLUSTER_MAX, lruvec,
				   sc, LRU_ACTIVE_ANON);
}

/* Use reclaim/compaction for costly allocs or under memory pressure */
static bool in_reclaim_compaction(struct scan_control *sc)
{
	if (IS_ENABLED(CONFIG_COMPACTION) && sc->order &&
			(sc->order > PAGE_ALLOC_COSTLY_ORDER ||
			 sc->priority < DEF_PRIORITY - 2))
		return true;

	return false;
}

/*
 * Reclaim/compaction is used for high-order allocation requests. It reclaims
 * order-0 pages before compacting the zone. should_continue_reclaim() returns
 * true if more pages should be reclaimed such that when the page allocator
 * calls try_to_compact_zone() that it will have enough free pages to succeed.
 * It will give up earlier than that if there is difficulty reclaiming pages.
 */
static inline bool should_continue_reclaim(struct pglist_data *pgdat,
					unsigned long nr_reclaimed,
					unsigned long nr_scanned,
					struct scan_control *sc)
{
	unsigned long pages_for_compaction;
	unsigned long inactive_lru_pages;
	int z;

	/* If not in reclaim/compaction mode, stop */
	if (!in_reclaim_compaction(sc))
		return false;

	/* Consider stopping depending on scan and reclaim activity */
	if (sc->gfp_mask & __GFP_REPEAT) {
		/*
		 * For __GFP_REPEAT allocations, stop reclaiming if the
		 * full LRU list has been scanned and we are still failing
		 * to reclaim pages. This full LRU scan is potentially
		 * expensive but a __GFP_REPEAT caller really wants to succeed
		 */
		if (!nr_reclaimed && !nr_scanned)
			return false;
	} else {
		/*
		 * For non-__GFP_REPEAT allocations which can presumably
		 * fail without consequence, stop if we failed to reclaim
		 * any pages from the last SWAP_CLUSTER_MAX number of
		 * pages that were scanned. This will return to the
		 * caller faster at the risk reclaim/compaction and
		 * the resulting allocation attempt fails
		 */
		if (!nr_reclaimed)
			return false;
	}

	/*
	 * If we have not reclaimed enough pages for compaction and the
	 * inactive lists are large enough, continue reclaiming
	 */
	pages_for_compaction = compact_gap(sc->order);
	inactive_lru_pages = node_page_state(pgdat, NR_INACTIVE_FILE);
	if (get_nr_swap_pages() > 0)
		inactive_lru_pages += node_page_state(pgdat, NR_INACTIVE_ANON);
	if (sc->nr_reclaimed < pages_for_compaction &&
			inactive_lru_pages > pages_for_compaction)
		return true;

	/* If compaction would go ahead or the allocation would succeed, stop */
	for (z = 0; z <= sc->reclaim_idx; z++) {
		struct zone *zone = &pgdat->node_zones[z];
		if (!managed_zone(zone))
			continue;

		switch (compaction_suitable(zone, sc->order, 0, sc->reclaim_idx)) {
		case COMPACT_SUCCESS:
		case COMPACT_CONTINUE:
			return false;
		default:
			/* check next zone */
			;
		}
	}
	return true;
}

static bool shrink_node(pg_data_t *pgdat, struct scan_control *sc)
{
	struct reclaim_state *reclaim_state = current->reclaim_state;
	/* nr_reclaimed: 已回收的页框数
	 * nr_scanned : 已扫描的页框数
	 */
	unsigned long nr_reclaimed, nr_scanned;
	/* 是否允许回收 */
	bool reclaimable = false;

	do {
		struct mem_cgroup *root = sc->target_mem_cgroup;
		struct mem_cgroup_reclaim_cookie reclaim = {
			.pgdat = pgdat,
			.priority = sc->priority,
		};
		unsigned long node_lru_pages = 0;
		struct mem_cgroup *memcg;

		nr_reclaimed = sc->nr_reclaimed;
		nr_scanned = sc->nr_scanned;

		memcg = mem_cgroup_iter(root, NULL, &reclaim);
		do {
			unsigned long lru_pages;
			unsigned long reclaimed;
			unsigned long scanned;

			if (mem_cgroup_low(root, memcg)) {
				if (!sc->may_thrash)
					continue;
				mem_cgroup_events(memcg, MEMCG_LOW, 1);
			}

			reclaimed = sc->nr_reclaimed;
			scanned = sc->nr_scanned;

			shrink_node_memcg(pgdat, memcg, sc, &lru_pages);
			node_lru_pages += lru_pages;

			if (memcg)
				shrink_slab(sc->gfp_mask, pgdat->node_id,
					    memcg, sc->nr_scanned - scanned,
					    lru_pages);

			/* Record the group's reclaim efficiency */
			vmpressure(sc->gfp_mask, memcg, false,
				   sc->nr_scanned - scanned,
				   sc->nr_reclaimed - reclaimed);

			/*
			 * Direct reclaim and kswapd have to scan all memory
			 * cgroups to fulfill the overall scan target for the
			 * node.
			 *
			 * Limit reclaim, on the other hand, only cares about
			 * nr_to_reclaim pages to be reclaimed and it will
			 * retry with decreasing priority if one round over the
			 * whole hierarchy is not sufficient.
			 */
			if (!global_reclaim(sc) &&
					sc->nr_reclaimed >= sc->nr_to_reclaim) {
				mem_cgroup_iter_break(root, memcg);
				break;
			}
		} while ((memcg = mem_cgroup_iter(root, memcg, &reclaim)));

		/*
		 * Shrink the slab caches in the same proportion that
		 * the eligible LRU pages were scanned.
		 */
		if (global_reclaim(sc))
			shrink_slab(sc->gfp_mask, pgdat->node_id, NULL,
				    sc->nr_scanned - nr_scanned,
				    node_lru_pages);

		if (reclaim_state) {
			sc->nr_reclaimed += reclaim_state->reclaimed_slab;
			reclaim_state->reclaimed_slab = 0;
		}

		/* Record the subtree's reclaim efficiency */
		vmpressure(sc->gfp_mask, sc->target_mem_cgroup, true,
			   sc->nr_scanned - nr_scanned,
			   sc->nr_reclaimed - nr_reclaimed);

		if (sc->nr_reclaimed - nr_reclaimed)
			reclaimable = true;

	} while (should_continue_reclaim(pgdat, sc->nr_reclaimed - nr_reclaimed,
					 sc->nr_scanned - nr_scanned, sc));

	return reclaimable;
}

/*
 * Returns true if compaction should go ahead for a costly-order request, or
 * the allocation would already succeed without compaction. Return false if we
 * should reclaim first.
 */
static inline bool compaction_ready(struct zone *zone, struct scan_control *sc)
{
	unsigned long watermark;
	enum compact_result suitable;

	suitable = compaction_suitable(zone, sc->order, 0, sc->reclaim_idx);
	if (suitable == COMPACT_SUCCESS)
		/* Allocation should succeed already. Don't reclaim. */
		return true;
	if (suitable == COMPACT_SKIPPED)
		/* Compaction cannot yet proceed. Do reclaim. */
		return false;

	/*
	 * Compaction is already possible, but it takes time to run and there
	 * are potentially other callers using the pages just freed. So proceed
	 * with reclaim to make a buffer of free pages available to give
	 * compaction a reasonable chance of completing and allocating the page.
	 * Note that we won't actually reclaim the whole buffer in one attempt
	 * as the target watermark in should_continue_reclaim() is lower. But if
	 * we are already above the high+gap watermark, don't reclaim at all.
	 */
	watermark = high_wmark_pages(zone) + compact_gap(sc->order);

	return zone_watermark_ok_safe(zone, 0, watermark, sc->reclaim_idx);
}

/*
 * This is the direct reclaim path, for page-allocating processes.  We only
 * try to reclaim pages from zones which will satisfy the caller's allocation
 * request.
 *
 * If a zone is deemed to be full of pinned pages then just give it a light
 * scan then give up on it.
 */
static void shrink_zones(struct zonelist *zonelist, struct scan_control *sc)
{
	struct zoneref *z;
	struct zone *zone;
	unsigned long nr_soft_reclaimed;
	unsigned long nr_soft_scanned;
	gfp_t orig_mask;
	pg_data_t *last_pgdat = NULL;

	/*
	 * If the number of buffer_heads in the machine exceeds the maximum
	 * allowed level, force direct reclaim to scan the highmem zone as
	 * highmem pages could be pinning lowmem pages storing buffer_heads
	 */
	orig_mask = sc->gfp_mask;
	if (buffer_heads_over_limit) {
		sc->gfp_mask |= __GFP_HIGHMEM;
		sc->reclaim_idx = gfp_zone(sc->gfp_mask);
	}

	for_each_zone_zonelist_nodemask(zone, z, zonelist,
					sc->reclaim_idx, sc->nodemask) {
		/*
		 * Take care memory controller reclaiming has small influence
		 * to global LRU.
		 */
		if (global_reclaim(sc)) {
			if (!cpuset_zone_allowed(zone,
						 GFP_KERNEL | __GFP_HARDWALL))
				continue;

			if (sc->priority != DEF_PRIORITY &&
			    !pgdat_reclaimable(zone->zone_pgdat))
				continue;	/* Let kswapd poll it */

			/*
			 * If we already have plenty of memory free for
			 * compaction in this zone, don't free any more.
			 * Even though compaction is invoked for any
			 * non-zero order, only frequent costly order
			 * reclamation is disruptive enough to become a
			 * noticeable problem, like transparent huge
			 * page allocations.
			 */
			if (IS_ENABLED(CONFIG_COMPACTION) &&
			    sc->order > PAGE_ALLOC_COSTLY_ORDER &&
			    compaction_ready(zone, sc)) {
				sc->compaction_ready = true;
				continue;
			}

			/*
			 * Shrink each node in the zonelist once. If the
			 * zonelist is ordered by zone (not the default) then a
			 * node may be shrunk multiple times but in that case
			 * the user prefers lower zones being preserved.
			 */
			if (zone->zone_pgdat == last_pgdat)
				continue;

			/*
			 * This steals pages from memory cgroups over softlimit
			 * and returns the number of reclaimed pages and
			 * scanned pages. This works for global memory pressure
			 * and balancing, not for a memcg's limit.
			 */
			nr_soft_scanned = 0;
			nr_soft_reclaimed = mem_cgroup_soft_limit_reclaim(zone->zone_pgdat,
						sc->order, sc->gfp_mask,
						&nr_soft_scanned);
			sc->nr_reclaimed += nr_soft_reclaimed;
			sc->nr_scanned += nr_soft_scanned;
			/* need some check for avoid more shrink_zone() */
		}

		/* See comment about same check for global reclaim above */
		if (zone->zone_pgdat == last_pgdat)
			continue;
		last_pgdat = zone->zone_pgdat;
		shrink_node(zone->zone_pgdat, sc);
	}

	/*
	 * Restore to original mask to avoid the impact on the caller if we
	 * promoted it to __GFP_HIGHMEM.
	 */
	sc->gfp_mask = orig_mask;
}

/*
 * This is the main entry point to direct page reclaim.
 *
 * If a full scan of the inactive list fails to free enough memory then we
 * are "out of memory" and something needs to be killed.
 *
 * If the caller is !__GFP_FS then the probability of a failure is reasonably
 * high - the zone may be full of dirty or under-writeback pages, which this
 * caller can't do much about.  We kick the writeback threads and take explicit
 * naps in the hope that some of these pages can be written.  But if the
 * allocating task holds filesystem locks which prevent writeout this might not
 * work, and the allocation attempt will fail.
 *
 * returns:	0, if no pages reclaimed
 * 		else, the number of pages reclaimed
 */
static unsigned long do_try_to_free_pages(struct zonelist *zonelist,
					  struct scan_control *sc)
{
	int initial_priority = sc->priority;
	unsigned long total_scanned = 0;
	unsigned long writeback_threshold;
retry:
	delayacct_freepages_start();

	if (global_reclaim(sc))
		__count_zid_vm_events(ALLOCSTALL, sc->reclaim_idx, 1);

	do {
		vmpressure_prio(sc->gfp_mask, sc->target_mem_cgroup,
				sc->priority);
		sc->nr_scanned = 0;
		shrink_zones(zonelist, sc);

		total_scanned += sc->nr_scanned;
		if (sc->nr_reclaimed >= sc->nr_to_reclaim)
			break;

		if (sc->compaction_ready)
			break;

		/*
		 * If we're getting trouble reclaiming, start doing
		 * writepage even in laptop mode.
		 */
		if (sc->priority < DEF_PRIORITY - 2)
			sc->may_writepage = 1;

		/*
		 * Try to write back as many pages as we just scanned.  This
		 * tends to cause slow streaming writers to write data to the
		 * disk smoothly, at the dirtying rate, which is nice.   But
		 * that's undesirable in laptop mode, where we *want* lumpy
		 * writeout.  So in laptop mode, write out the whole world.
		 */
		writeback_threshold = sc->nr_to_reclaim + sc->nr_to_reclaim / 2;
		if (total_scanned > writeback_threshold) {
			wakeup_flusher_threads(laptop_mode ? 0 : total_scanned,
						WB_REASON_TRY_TO_FREE_PAGES);
			sc->may_writepage = 1;
		}
	} while (--sc->priority >= 0);

	delayacct_freepages_end();

	if (sc->nr_reclaimed)
		return sc->nr_reclaimed;

	/* Aborted reclaim to try compaction? don't OOM, then */
	if (sc->compaction_ready)
		return 1;

	/* Untapped cgroup reserves?  Don't OOM, retry. */
	if (!sc->may_thrash) {
		sc->priority = initial_priority;
		sc->may_thrash = 1;
		goto retry;
	}

	return 0;
}

static bool pfmemalloc_watermark_ok(pg_data_t *pgdat)
{
	struct zone *zone;
	unsigned long pfmemalloc_reserve = 0;
	unsigned long free_pages = 0;
	int i;
	bool wmark_ok;

	for (i = 0; i <= ZONE_NORMAL; i++) {
		zone = &pgdat->node_zones[i];
		if (!managed_zone(zone) ||
		    pgdat_reclaimable_pages(pgdat) == 0)
			continue;

		pfmemalloc_reserve += min_wmark_pages(zone);
		free_pages += zone_page_state(zone, NR_FREE_PAGES);
	}

	/* If there are no reserves (unexpected config) then do not throttle */
	if (!pfmemalloc_reserve)
		return true;

	wmark_ok = free_pages > pfmemalloc_reserve / 2;

	/* kswapd must be awake if processes are being throttled */
	if (!wmark_ok && waitqueue_active(&pgdat->kswapd_wait)) {
		pgdat->kswapd_classzone_idx = min(pgdat->kswapd_classzone_idx,
						(enum zone_type)ZONE_NORMAL);
		wake_up_interruptible(&pgdat->kswapd_wait);
	}

	return wmark_ok;
}

/*
 * Throttle direct reclaimers if backing storage is backed by the network
 * and the PFMEMALLOC reserve for the preferred node is getting dangerously
 * depleted. kswapd will continue to make progress and wake the processes
 * when the low watermark is reached.
 *
 * Returns true if a fatal signal was delivered during throttling. If this
 * happens, the page allocator should not consider triggering the OOM killer.
 */
static bool throttle_direct_reclaim(gfp_t gfp_mask, struct zonelist *zonelist,
					nodemask_t *nodemask)
{
	struct zoneref *z;
	struct zone *zone;
	pg_data_t *pgdat = NULL;

	/*
	 * Kernel threads should not be throttled as they may be indirectly
	 * responsible for cleaning pages necessary for reclaim to make forward
	 * progress. kjournald for example may enter direct reclaim while
	 * committing a transaction where throttling it could forcing other
	 * processes to block on log_wait_commit().
	 */
	if (current->flags & PF_KTHREAD)
		goto out;

	/*
	 * If a fatal signal is pending, this process should not throttle.
	 * It should return quickly so it can exit and free its memory
	 */
	if (fatal_signal_pending(current))
		goto out;

	/*
	 * Check if the pfmemalloc reserves are ok by finding the first node
	 * with a usable ZONE_NORMAL or lower zone. The expectation is that
	 * GFP_KERNEL will be required for allocating network buffers when
	 * swapping over the network so ZONE_HIGHMEM is unusable.
	 *
	 * Throttling is based on the first usable node and throttled processes
	 * wait on a queue until kswapd makes progress and wakes them. There
	 * is an affinity then between processes waking up and where reclaim
	 * progress has been made assuming the process wakes on the same node.
	 * More importantly, processes running on remote nodes will not compete
	 * for remote pfmemalloc reserves and processes on different nodes
	 * should make reasonable progress.
	 */
	for_each_zone_zonelist_nodemask(zone, z, zonelist,
					gfp_zone(gfp_mask), nodemask) {
		if (zone_idx(zone) > ZONE_NORMAL)
			continue;

		/* Throttle based on the first usable node */
		pgdat = zone->zone_pgdat;
		if (pfmemalloc_watermark_ok(pgdat))
			goto out;
		break;
	}

	/* If no zone was usable by the allocation flags then do not throttle */
	if (!pgdat)
		goto out;

	/* Account for the throttling */
	count_vm_event(PGSCAN_DIRECT_THROTTLE);

	/*
	 * If the caller cannot enter the filesystem, it's possible that it
	 * is due to the caller holding an FS lock or performing a journal
	 * transaction in the case of a filesystem like ext[3|4]. In this case,
	 * it is not safe to block on pfmemalloc_wait as kswapd could be
	 * blocked waiting on the same lock. Instead, throttle for up to a
	 * second before continuing.
	 */
	if (!(gfp_mask & __GFP_FS)) {
		wait_event_interruptible_timeout(pgdat->pfmemalloc_wait,
			pfmemalloc_watermark_ok(pgdat), HZ);

		goto check_pending;
	}

	/* Throttle until kswapd wakes the process */
	wait_event_killable(zone->zone_pgdat->pfmemalloc_wait,
		pfmemalloc_watermark_ok(pgdat));

check_pending:
	if (fatal_signal_pending(current))
		return true;

out:
	return false;
}

unsigned long try_to_free_pages(struct zonelist *zonelist, int order,
				gfp_t gfp_mask, nodemask_t *nodemask)
{
	unsigned long nr_reclaimed;
	struct scan_control sc = {
		.nr_to_reclaim = SWAP_CLUSTER_MAX,
		.gfp_mask = (gfp_mask = memalloc_noio_flags(gfp_mask)),
		.reclaim_idx = gfp_zone(gfp_mask),
		.order = order,
		.nodemask = nodemask,
		.priority = DEF_PRIORITY,
		.may_writepage = !laptop_mode,
		.may_unmap = 1,
		.may_swap = 1,
	};

	/*
	 * Do not enter reclaim if fatal signal was delivered while throttled.
	 * 1 is returned so that the page allocator does not OOM kill at this
	 * point.
	 */
	if (throttle_direct_reclaim(gfp_mask, zonelist, nodemask))
		return 1;

	trace_mm_vmscan_direct_reclaim_begin(order,
				sc.may_writepage,
				gfp_mask,
				sc.reclaim_idx);

	nr_reclaimed = do_try_to_free_pages(zonelist, &sc);

	trace_mm_vmscan_direct_reclaim_end(nr_reclaimed);

	return nr_reclaimed;
}

#ifdef CONFIG_MEMCG

unsigned long mem_cgroup_shrink_node(struct mem_cgroup *memcg,
						gfp_t gfp_mask, bool noswap,
						pg_data_t *pgdat,
						unsigned long *nr_scanned)
{
	struct scan_control sc = {
		.nr_to_reclaim = SWAP_CLUSTER_MAX,
		.target_mem_cgroup = memcg,
		.may_writepage = !laptop_mode,
		.may_unmap = 1,
		.reclaim_idx = MAX_NR_ZONES - 1,
		.may_swap = !noswap,
	};
	unsigned long lru_pages;

	sc.gfp_mask = (gfp_mask & GFP_RECLAIM_MASK) |
			(GFP_HIGHUSER_MOVABLE & ~GFP_RECLAIM_MASK);

	trace_mm_vmscan_memcg_softlimit_reclaim_begin(sc.order,
						      sc.may_writepage,
						      sc.gfp_mask,
						      sc.reclaim_idx);

	/*
	 * NOTE: Although we can get the priority field, using it
	 * here is not a good idea, since it limits the pages we can scan.
	 * if we don't reclaim here, the shrink_node from balance_pgdat
	 * will pick up pages from other mem cgroup's as well. We hack
	 * the priority and make it zero.
	 */
	shrink_node_memcg(pgdat, memcg, &sc, &lru_pages);

	trace_mm_vmscan_memcg_softlimit_reclaim_end(sc.nr_reclaimed);

	*nr_scanned = sc.nr_scanned;
	return sc.nr_reclaimed;
}

unsigned long try_to_free_mem_cgroup_pages(struct mem_cgroup *memcg,
					   unsigned long nr_pages,
					   gfp_t gfp_mask,
					   bool may_swap)
{
	struct zonelist *zonelist;
	unsigned long nr_reclaimed;
	int nid;
	struct scan_control sc = {
		.nr_to_reclaim = max(nr_pages, SWAP_CLUSTER_MAX),
		.gfp_mask = (gfp_mask & GFP_RECLAIM_MASK) |
				(GFP_HIGHUSER_MOVABLE & ~GFP_RECLAIM_MASK),
		.reclaim_idx = MAX_NR_ZONES - 1,
		.target_mem_cgroup = memcg,
		.priority = DEF_PRIORITY,
		.may_writepage = !laptop_mode,
		.may_unmap = 1,
		.may_swap = may_swap,
	};

	/*
	 * Unlike direct reclaim via alloc_pages(), memcg's reclaim doesn't
	 * take care of from where we get pages. So the node where we start the
	 * scan does not need to be the current node.
	 */
	nid = mem_cgroup_select_victim_node(memcg);

	zonelist = &NODE_DATA(nid)->node_zonelists[ZONELIST_FALLBACK];

	trace_mm_vmscan_memcg_reclaim_begin(0,
					    sc.may_writepage,
					    sc.gfp_mask,
					    sc.reclaim_idx);

	current->flags |= PF_MEMALLOC;
	nr_reclaimed = do_try_to_free_pages(zonelist, &sc);
	current->flags &= ~PF_MEMALLOC;

	trace_mm_vmscan_memcg_reclaim_end(nr_reclaimed);

	return nr_reclaimed;
}
#endif

static void age_active_anon(struct pglist_data *pgdat,
				struct scan_control *sc)
{
	struct mem_cgroup *memcg;

	if (!total_swap_pages)
		return;

	memcg = mem_cgroup_iter(NULL, NULL, NULL);
	do {
		struct lruvec *lruvec = mem_cgroup_lruvec(pgdat, memcg);

		if (inactive_list_is_low(lruvec, false, sc))
			shrink_active_list(SWAP_CLUSTER_MAX, lruvec,
					   sc, LRU_ACTIVE_ANON);

		memcg = mem_cgroup_iter(NULL, memcg, NULL);
	} while (memcg);
}

static bool zone_balanced(struct zone *zone, int order, int classzone_idx)
{
	unsigned long mark = high_wmark_pages(zone);

	if (!zone_watermark_ok_safe(zone, order, mark, classzone_idx))
		return false;

	/*
	 * If any eligible zone is balanced then the node is not considered
	 * to be congested or dirty
	 */
	clear_bit(PGDAT_CONGESTED, &zone->zone_pgdat->flags);
	clear_bit(PGDAT_DIRTY, &zone->zone_pgdat->flags);

	return true;
}

/*
 * Prepare kswapd for sleeping. This verifies that there are no processes
 * waiting in throttle_direct_reclaim() and that watermarks have been met.
 *
 * Returns true if kswapd is ready to sleep
 */
static bool prepare_kswapd_sleep(pg_data_t *pgdat, int order, int classzone_idx)
{
	int i;

	/*
	 * The throttled processes are normally woken up in balance_pgdat() as
	 * soon as pfmemalloc_watermark_ok() is true. But there is a potential
	 * race between when kswapd checks the watermarks and a process gets
	 * throttled. There is also a potential race if processes get
	 * throttled, kswapd wakes, a large process exits thereby balancing the
	 * zones, which causes kswapd to exit balance_pgdat() before reaching
	 * the wake up checks. If kswapd is going to sleep, no process should
	 * be sleeping on pfmemalloc_wait, so wake them now if necessary. If
	 * the wake up is premature, processes will wake kswapd and get
	 * throttled again. The difference from wake ups in balance_pgdat() is
	 * that here we are under prepare_to_wait().
	 */
	if (waitqueue_active(&pgdat->pfmemalloc_wait))
		wake_up_all(&pgdat->pfmemalloc_wait);

	for (i = 0; i <= classzone_idx; i++) {
		struct zone *zone = pgdat->node_zones + i;

		if (!managed_zone(zone))
			continue;

		if (!zone_balanced(zone, order, classzone_idx))
			return false;
	}

	return true;
}

/*
 * kswapd shrinks a node of pages that are at or below the highest usable
 * zone that is currently unbalanced.
 *
 * Returns true if kswapd scanned at least the requested number of pages to
 * reclaim or if the lack of progress was due to pages under writeback.
 * This is used to determine if the scanning priority needs to be raised.
 */
static bool kswapd_shrink_node(pg_data_t *pgdat,
			       struct scan_control *sc)
{
	struct zone *zone;
	int z;

	/* Reclaim a number of pages proportional to the number of zones */
	sc->nr_to_reclaim = 0;
	for (z = 0; z <= sc->reclaim_idx; z++) {
		zone = pgdat->node_zones + z;
		if (!managed_zone(zone))
			continue;

		sc->nr_to_reclaim += max(high_wmark_pages(zone), SWAP_CLUSTER_MAX);
	}

	/*
	 * Historically care was taken to put equal pressure on all zones but
	 * now pressure is applied based on node LRU order.
	 */
	shrink_node(pgdat, sc);

	/*
	 * Fragmentation may mean that the system cannot be rebalanced for
	 * high-order allocations. If twice the allocation size has been
	 * reclaimed then recheck watermarks only at order-0 to prevent
	 * excessive reclaim. Assume that a process requested a high-order
	 * can direct reclaim/compact.
	 */
	if (sc->order && sc->nr_reclaimed >= compact_gap(sc->order))
		sc->order = 0;

	return sc->nr_scanned >= sc->nr_to_reclaim;
}

/*
 * For kswapd, balance_pgdat() will reclaim pages across a node from zones
 * that are eligible for use by the caller until at least one zone is
 * balanced.
 *
 * Returns the order kswapd finished reclaiming at.
 *
 * kswapd scans the zones in the highmem->normal->dma direction.  It skips
 * zones which have free_pages > high_wmark_pages(zone), but once a zone is
 * found to have free_pages <= high_wmark_pages(zone), any page is that zone
 * or lower is eligible for reclaim until at least one usable zone is
 * balanced.
 */
static int balance_pgdat(pg_data_t *pgdat, int order, int classzone_idx)
{
	int i;
	unsigned long nr_soft_reclaimed;
	unsigned long nr_soft_scanned;
	struct zone *zone;
	struct scan_control sc = {
		.gfp_mask = GFP_KERNEL,
		.order = order,
		.priority = DEF_PRIORITY,
		.may_writepage = !laptop_mode,
		.may_unmap = 1,
		.may_swap = 1,
	};
	count_vm_event(PAGEOUTRUN);

	do {
		bool raise_priority = true;

		sc.nr_reclaimed = 0;
		sc.reclaim_idx = classzone_idx;

		/*
		 * If the number of buffer_heads exceeds the maximum allowed
		 * then consider reclaiming from all zones. This has a dual
		 * purpose -- on 64-bit systems it is expected that
		 * buffer_heads are stripped during active rotation. On 32-bit
		 * systems, highmem pages can pin lowmem memory and shrinking
		 * buffers can relieve lowmem pressure. Reclaim may still not
		 * go ahead if all eligible zones for the original allocation
		 * request are balanced to avoid excessive reclaim from kswapd.
		 */
		if (buffer_heads_over_limit) {
			for (i = MAX_NR_ZONES - 1; i >= 0; i--) {
				zone = pgdat->node_zones + i;
				if (!managed_zone(zone))
					continue;

				sc.reclaim_idx = i;
				break;
			}
		}

		/*
		 * Only reclaim if there are no eligible zones. Check from
		 * high to low zone as allocations prefer higher zones.
		 * Scanning from low to high zone would allow congestion to be
		 * cleared during a very small window when a small low
		 * zone was balanced even under extreme pressure when the
		 * overall node may be congested. Note that sc.reclaim_idx
		 * is not used as buffer_heads_over_limit may have adjusted
		 * it.
		 */
		for (i = classzone_idx; i >= 0; i--) {
			zone = pgdat->node_zones + i;
			if (!managed_zone(zone))
				continue;

			if (zone_balanced(zone, sc.order, classzone_idx))
				goto out;
		}

		/*
		 * Do some background aging of the anon list, to give
		 * pages a chance to be referenced before reclaiming. All
		 * pages are rotated regardless of classzone as this is
		 * about consistent aging.
		 */
		age_active_anon(pgdat, &sc);

		/*
		 * If we're getting trouble reclaiming, start doing writepage
		 * even in laptop mode.
		 */
		if (sc.priority < DEF_PRIORITY - 2 || !pgdat_reclaimable(pgdat))
			sc.may_writepage = 1;

		/* Call soft limit reclaim before calling shrink_node. */
		sc.nr_scanned = 0;
		nr_soft_scanned = 0;
		nr_soft_reclaimed = mem_cgroup_soft_limit_reclaim(pgdat, sc.order,
						sc.gfp_mask, &nr_soft_scanned);
		sc.nr_reclaimed += nr_soft_reclaimed;

		/*
		 * There should be no need to raise the scanning priority if
		 * enough pages are already being scanned that that high
		 * watermark would be met at 100% efficiency.
		 */
		if (kswapd_shrink_node(pgdat, &sc))
			raise_priority = false;

		/*
		 * If the low watermark is met there is no need for processes
		 * to be throttled on pfmemalloc_wait as they should not be
		 * able to safely make forward progress. Wake them
		 */
		if (waitqueue_active(&pgdat->pfmemalloc_wait) &&
				pfmemalloc_watermark_ok(pgdat))
			wake_up_all(&pgdat->pfmemalloc_wait);

		/* Check if kswapd should be suspending */
		if (try_to_freeze() || kthread_should_stop())
			break;

		/*
		 * Raise priority if scanning rate is too low or there was no
		 * progress in reclaiming pages
		 */
		if (raise_priority || !sc.nr_reclaimed)
			sc.priority--;
	} while (sc.priority >= 1);

out:
	/*
	 * Return the order kswapd stopped reclaiming at as
	 * prepare_kswapd_sleep() takes it into account. If another caller
	 * entered the allocator slow path while kswapd was awake, order will
	 * remain at the higher level.
	 */
	return sc.order;
}

static void kswapd_try_to_sleep(pg_data_t *pgdat, int alloc_order, int reclaim_order,
				unsigned int classzone_idx)
{
	long remaining = 0;
	DEFINE_WAIT(wait);

	if (freezing(current) || kthread_should_stop())
		return;

	prepare_to_wait(&pgdat->kswapd_wait, &wait, TASK_INTERRUPTIBLE);

	/* Try to sleep for a short interval */
	if (prepare_kswapd_sleep(pgdat, reclaim_order, classzone_idx)) {
		/*
		 * Compaction records what page blocks it recently failed to
		 * isolate pages from and skips them in the future scanning.
		 * When kswapd is going to sleep, it is reasonable to assume
		 * that pages and compaction may succeed so reset the cache.
		 */
		reset_isolation_suitable(pgdat);

		/*
		 * We have freed the memory, now we should compact it to make
		 * allocation of the requested order possible.
		 */
		wakeup_kcompactd(pgdat, alloc_order, classzone_idx);

		remaining = schedule_timeout(HZ/10);

		/*
		 * If woken prematurely then reset kswapd_classzone_idx and
		 * order. The values will either be from a wakeup request or
		 * the previous request that slept prematurely.
		 */
		if (remaining) {
			pgdat->kswapd_classzone_idx = max(pgdat->kswapd_classzone_idx, classzone_idx);
			pgdat->kswapd_order = max(pgdat->kswapd_order, reclaim_order);
		}

		finish_wait(&pgdat->kswapd_wait, &wait);
		prepare_to_wait(&pgdat->kswapd_wait, &wait, TASK_INTERRUPTIBLE);
	}

	/*
	 * After a short sleep, check if it was a premature sleep. If not, then
	 * go fully to sleep until explicitly woken up.
	 */
	if (!remaining &&
	    prepare_kswapd_sleep(pgdat, reclaim_order, classzone_idx)) {
		trace_mm_vmscan_kswapd_sleep(pgdat->node_id);

		/*
		 * vmstat counters are not perfectly accurate and the estimated
		 * value for counters such as NR_FREE_PAGES can deviate from the
		 * true value by nr_online_cpus * threshold. To avoid the zone
		 * watermarks being breached while under pressure, we reduce the
		 * per-cpu vmstat threshold while kswapd is awake and restore
		 * them before going back to sleep.
		 */
		set_pgdat_percpu_threshold(pgdat, calculate_normal_threshold);

		if (!kthread_should_stop())
			schedule();

		set_pgdat_percpu_threshold(pgdat, calculate_pressure_threshold);
	} else {
		if (remaining)
			count_vm_event(KSWAPD_LOW_WMARK_HIT_QUICKLY);
		else
			count_vm_event(KSWAPD_HIGH_WMARK_HIT_QUICKLY);
	}
	finish_wait(&pgdat->kswapd_wait, &wait);
}

/*
 * The background pageout daemon, started as a kernel thread
 * from the init process.
 *
 * This basically trickles out pages so that we have _some_
 * free memory available even if there is no other activity
 * that frees anything up. This is needed for things like routing
 * etc, where we otherwise might have all activity going on in
 * asynchronous contexts that cannot page things out.
 *
 * If there are applications that are active memory-allocators
 * (most normal use), this basically shouldn't matter.
 */
static int kswapd(void *p)
{
	unsigned int alloc_order, reclaim_order, classzone_idx;
	pg_data_t *pgdat = (pg_data_t*)p;
	struct task_struct *tsk = current;

	struct reclaim_state reclaim_state = {
		.reclaimed_slab = 0,
	};
	const struct cpumask *cpumask = cpumask_of_node(pgdat->node_id);

	lockdep_set_current_reclaim_state(GFP_KERNEL);

	if (!cpumask_empty(cpumask))
		set_cpus_allowed_ptr(tsk, cpumask);
	current->reclaim_state = &reclaim_state;

	/*
	 * Tell the memory management that we're a "memory allocator",
	 * and that if we need more memory we should get access to it
	 * regardless (see "__alloc_pages()"). "kswapd" should
	 * never get caught in the normal page freeing logic.
	 *
	 * (Kswapd normally doesn't need memory anyway, but sometimes
	 * you need a small amount of memory in order to be able to
	 * page out something else, and this flag essentially protects
	 * us from recursively trying to free more memory as we're
	 * trying to free the first piece of memory in the first place).
	 */
	tsk->flags |= PF_MEMALLOC | PF_SWAPWRITE | PF_KSWAPD;
	set_freezable();

	pgdat->kswapd_order = alloc_order = reclaim_order = 0;
	pgdat->kswapd_classzone_idx = classzone_idx = 0;
	for ( ; ; ) {
		bool ret;

kswapd_try_sleep:
		kswapd_try_to_sleep(pgdat, alloc_order, reclaim_order,
					classzone_idx);

		/* Read the new order and classzone_idx */
		alloc_order = reclaim_order = pgdat->kswapd_order;
		classzone_idx = pgdat->kswapd_classzone_idx;
		pgdat->kswapd_order = 0;
		pgdat->kswapd_classzone_idx = 0;

		ret = try_to_freeze();
		if (kthread_should_stop())
			break;

		/*
		 * We can speed up thawing tasks if we don't call balance_pgdat
		 * after returning from the refrigerator
		 */
		if (ret)
			continue;

		/*
		 * Reclaim begins at the requested order but if a high-order
		 * reclaim fails then kswapd falls back to reclaiming for
		 * order-0. If that happens, kswapd will consider sleeping
		 * for the order it finished reclaiming at (reclaim_order)
		 * but kcompactd is woken to compact for the original
		 * request (alloc_order).
		 */
		trace_mm_vmscan_kswapd_wake(pgdat->node_id, classzone_idx,
						alloc_order);
		reclaim_order = balance_pgdat(pgdat, alloc_order, classzone_idx);
		if (reclaim_order < alloc_order)
			goto kswapd_try_sleep;

		alloc_order = reclaim_order = pgdat->kswapd_order;
		classzone_idx = pgdat->kswapd_classzone_idx;
	}

	tsk->flags &= ~(PF_MEMALLOC | PF_SWAPWRITE | PF_KSWAPD);
	current->reclaim_state = NULL;
	lockdep_clear_current_reclaim_state();

	return 0;
}

/*
 * A zone is low on free memory, so wake its kswapd task to service it.
 */
void wakeup_kswapd(struct zone *zone, int order, enum zone_type classzone_idx)
{
	pg_data_t *pgdat;
	int z;

	if (!managed_zone(zone))
		return;

	if (!cpuset_zone_allowed(zone, GFP_KERNEL | __GFP_HARDWALL))
		return;
	pgdat = zone->zone_pgdat;
	pgdat->kswapd_classzone_idx = max(pgdat->kswapd_classzone_idx, classzone_idx);
	pgdat->kswapd_order = max(pgdat->kswapd_order, order);
	if (!waitqueue_active(&pgdat->kswapd_wait))
		return;

	/* Only wake kswapd if all zones are unbalanced */
	for (z = 0; z <= classzone_idx; z++) {
		zone = pgdat->node_zones + z;
		if (!managed_zone(zone))
			continue;

		if (zone_balanced(zone, order, classzone_idx))
			return;
	}

	trace_mm_vmscan_wakeup_kswapd(pgdat->node_id, zone_idx(zone), order);
	wake_up_interruptible(&pgdat->kswapd_wait);
}

#ifdef CONFIG_HIBERNATION
/*
 * Try to free `nr_to_reclaim' of memory, system-wide, and return the number of
 * freed pages.
 *
 * Rather than trying to age LRUs the aim is to preserve the overall
 * LRU order by reclaiming preferentially
 * inactive > active > active referenced > active mapped
 */
unsigned long shrink_all_memory(unsigned long nr_to_reclaim)
{
	struct reclaim_state reclaim_state;
	struct scan_control sc = {
		.nr_to_reclaim = nr_to_reclaim,
		.gfp_mask = GFP_HIGHUSER_MOVABLE,
		.reclaim_idx = MAX_NR_ZONES - 1,
		.priority = DEF_PRIORITY,
		.may_writepage = 1,
		.may_unmap = 1,
		.may_swap = 1,
		.hibernation_mode = 1,
	};
	struct zonelist *zonelist = node_zonelist(numa_node_id(), sc.gfp_mask);
	struct task_struct *p = current;
	unsigned long nr_reclaimed;

	p->flags |= PF_MEMALLOC;
	lockdep_set_current_reclaim_state(sc.gfp_mask);
	reclaim_state.reclaimed_slab = 0;
	p->reclaim_state = &reclaim_state;

	nr_reclaimed = do_try_to_free_pages(zonelist, &sc);

	p->reclaim_state = NULL;
	lockdep_clear_current_reclaim_state();
	p->flags &= ~PF_MEMALLOC;

	return nr_reclaimed;
}
#endif /* CONFIG_HIBERNATION */

/* It's optimal to keep kswapds on the same CPUs as their memory, but
   not required for correctness.  So if the last cpu in a node goes
   away, we get changed to run anywhere: as the first one comes back,
   restore their cpu bindings. */
static int cpu_callback(struct notifier_block *nfb, unsigned long action,
			void *hcpu)
{
	int nid;

	if (action == CPU_ONLINE || action == CPU_ONLINE_FROZEN) {
		for_each_node_state(nid, N_MEMORY) {
			pg_data_t *pgdat = NODE_DATA(nid);
			const struct cpumask *mask;

			mask = cpumask_of_node(pgdat->node_id);

			if (cpumask_any_and(cpu_online_mask, mask) < nr_cpu_ids)
				/* One of our CPUs online: restore mask */
				set_cpus_allowed_ptr(pgdat->kswapd, mask);
		}
	}
	return NOTIFY_OK;
}

/*
 * This kswapd start function will be called by init and node-hot-add.
 * On node-hot-add, kswapd will moved to proper cpus if cpus are hot-added.
 */
int kswapd_run(int nid)
{
	pg_data_t *pgdat = NODE_DATA(nid);
	int ret = 0;

	if (pgdat->kswapd)
		return 0;

	pgdat->kswapd = kthread_run(kswapd, pgdat, "kswapd%d", nid);
	if (IS_ERR(pgdat->kswapd)) {
		/* failure at boot is fatal */
		BUG_ON(system_state == SYSTEM_BOOTING);
		pr_err("Failed to start kswapd on node %d\n", nid);
		ret = PTR_ERR(pgdat->kswapd);
		pgdat->kswapd = NULL;
	}
	return ret;
}

/*
 * Called by memory hotplug when all memory in a node is offlined.  Caller must
 * hold mem_hotplug_begin/end().
 */
void kswapd_stop(int nid)
{
	struct task_struct *kswapd = NODE_DATA(nid)->kswapd;

	if (kswapd) {
		kthread_stop(kswapd);
		NODE_DATA(nid)->kswapd = NULL;
	}
}

static int __init kswapd_init(void)
{
	int nid;

	swap_setup();
	for_each_node_state(nid, N_MEMORY)
 		kswapd_run(nid);
	hotcpu_notifier(cpu_callback, 0);
	return 0;
}

module_init(kswapd_init)

#ifdef CONFIG_NUMA
/*
 * Node reclaim mode
 *
 * If non-zero call node_reclaim when the number of free pages falls below
 * the watermarks.
 */
int node_reclaim_mode __read_mostly;

#define RECLAIM_OFF 0
#define RECLAIM_ZONE (1<<0)	/* Run shrink_inactive_list on the zone */
#define RECLAIM_WRITE (1<<1)	/* Writeout pages during reclaim */
#define RECLAIM_UNMAP (1<<2)	/* Unmap pages during reclaim */

/*
 * Priority for NODE_RECLAIM. This determines the fraction of pages
 * of a node considered for each zone_reclaim. 4 scans 1/16th of
 * a zone.
 */
#define NODE_RECLAIM_PRIORITY 4

/*
 * Percentage of pages in a zone that must be unmapped for node_reclaim to
 * occur.
 */
int sysctl_min_unmapped_ratio = 1;

/*
 * If the number of slab pages in a zone grows beyond this percentage then
 * slab reclaim needs to occur.
 */
int sysctl_min_slab_ratio = 5;

static inline unsigned long node_unmapped_file_pages(struct pglist_data *pgdat)
{
	/* NR_FILE_MAPPED,pagecache pages mapped into pagetables.only modified from process context
	 * 看解释应该是映射到页表里面的才属于NR_FILE_MAPPED
	 * 那些预读页的应该就不是的了
	 */
	unsigned long file_mapped = node_page_state(pgdat, NR_FILE_MAPPED);
	unsigned long file_lru = node_page_state(pgdat, NR_INACTIVE_FILE) +
		node_page_state(pgdat, NR_ACTIVE_FILE);

	/*
	 * It's possible for there to be more file mapped pages than
	 * accounted for by the pages on the file LRU lists because
	 * tmpfs pages accounted for as ANON can also be FILE_MAPPED
	 *
	 * 文件映射的页面可能比file LRU列表上的页面所占的多
	 * 因为tmpfs 页面有当做匿名页面又当做FILE_MAPPED
	 */
	return (file_lru > file_mapped) ? (file_lru - file_mapped) : 0;
}

/* Work out how many page cache pages we can reclaim in this reclaim_mode
 * 计算出在这个回收模式中可以回收多少页面缓存页面
 */
static unsigned long node_pagecache_reclaimable(struct pglist_data *pgdat)
{
	unsigned long nr_pagecache_reclaimable;
	unsigned long delta = 0;

	/*
	 * If RECLAIM_UNMAP is set, then all file pages are considered
	 * potentially reclaimable. Otherwise, we have to worry about
	 * pages like swapcache and node_unmapped_file_pages() provides
	 * a better estimate
	 *
	 * 如果设置了RECLAIM_UNMAP,则所有文件页都被认为是潜在的可回收页.
	 * 否则,我们必须担心swapcache和node_unmapped_file_pages()这样的页面提供了更好的估计
	 */
	if (node_reclaim_mode & RECLAIM_UNMAP)
		nr_pagecache_reclaimable = node_page_state(pgdat, NR_FILE_PAGES);
	else
		nr_pagecache_reclaimable = node_unmapped_file_pages(pgdat);

	/* If we can't clean pages, remove dirty pages from consideration */
	/* 如果我们不能清理页面，考虑删除脏页面 */
	if (!(node_reclaim_mode & RECLAIM_WRITE))
		delta += node_page_state(pgdat, NR_FILE_DIRTY);

	/* Watch for any possible underflows due to delta
	 * 注意delta引起的任何可能的下溢
	 */

	/* 如果delta > nr_pagecache_reclaimable,那么delta = nr_pagecache_reclaimable */
	if (unlikely(delta > nr_pagecache_reclaimable))
		delta = nr_pagecache_reclaimable;

	return nr_pagecache_reclaimable - delta;
}

/*
 * Try to free up some pages from this node through reclaim.
 */
static int __node_reclaim(struct pglist_data *pgdat, gfp_t gfp_mask, unsigned int order)
{
	/* Minimum pages needed in order to stay on node */
	/* 停留在这个节点上,本次最少需要的页面数 */
	const unsigned long nr_pages = 1 << order;
	struct task_struct *p = current;
	struct reclaim_state reclaim_state;
	int classzone_idx = gfp_zone(gfp_mask);
	struct scan_control sc = {
		/* 如果本次需要页面数不足32个，则回收32个页面 */
		.nr_to_reclaim = max(nr_pages, SWAP_CLUSTER_MAX),
		.gfp_mask = (gfp_mask = memalloc_noio_flags(gfp_mask)),
		.order = order,
		.priority = NODE_RECLAIM_PRIORITY,
		/* 是否允许页回写到磁盘 */
		.may_writepage = !!(node_reclaim_mode & RECLAIM_WRITE),
		/* 是否允许对page进行unmap */
		.may_unmap = !!(node_reclaim_mode & RECLAIM_UNMAP),
		/* 是否允许将匿名页写入到swap分区 */
		.may_swap = 1,
		.reclaim_idx = classzone_idx,
	};

	cond_resched();
	/*
	 * We need to be able to allocate from the reserves for RECLAIM_UNMAP
	 * and we also need to be able to write out pages for RECLAIM_WRITE
	 * and RECLAIM_UNMAP.
	 *
	 * 我们需要为了RECLAIM_UNMAP从reserves中分配,我们还需要能够为RECLAIM_WRITE和RECLAIM_UNMAP写回页面
	 */
	p->flags |= PF_MEMALLOC | PF_SWAPWRITE;
	lockdep_set_current_reclaim_state(gfp_mask);
	reclaim_state.reclaimed_slab = 0;
	p->reclaim_state = &reclaim_state;
	/* min_unmapped_pages: 内存回收的阀值，如果unmapped 页达到这个值
	 * node进行快速内存回收的条件是可回收的页框大于node预留的min_unmapped_pages个页框.
	 * 而min_unmapped_pages是由/proc/sys/vm/min_unmapped_ratio配置的,该值的含义是每个zone最小预留unmapped_pages的比率,其范围是0-100.
	 * 如果条件满足时,则会对node循环进行快速内存回收
	 * 结束条件是：1.已经回收到所需要的页框数.
	 *	       2.优先级已经小于0,这表示已经进行过一次全node内存碎片回收了,如果还是满足不了要求,也没有其他办法了
	 */
	if (node_pagecache_reclaimable(pgdat) > pgdat->min_unmapped_pages) {
		/*
		 * Free memory by calling shrink zone with increasing
		 * priorities until we have enough memory freed.
		 */

		/* 每一趟内存回收，对应优先级的值就会减一，当优先级小于0或者
		 * 回收到的页面数满足要求的时候，则停止内存回收
		 */
		do {
			shrink_node(pgdat, &sc);
		} while (sc.nr_reclaimed < nr_pages && --sc.priority >= 0);
	}

	p->reclaim_state = NULL;
	current->flags &= ~(PF_MEMALLOC | PF_SWAPWRITE);
	lockdep_clear_current_reclaim_state();
	return sc.nr_reclaimed >= nr_pages;
}

int node_reclaim(struct pglist_data *pgdat, gfp_t gfp_mask, unsigned int order)
{
	int ret;

	/*
	 * Node reclaim reclaims unmapped file backed pages and
	 * slab pages if we are over the defined limits.
	 *
	 * A small portion of unmapped file backed pages is needed for
	 * file I/O otherwise pages read by file I/O will be immediately
	 * thrown out if the node is overallocated. So we do not reclaim
	 * if less than a specified percentage of the node is used by
	 * unmapped file backed pages.
	 *
	 * 如果超过定义的限制,node回收将回收未映射的文件backed页和slab页.
	 * 
	 * 文件I/O需要一小部分未映射的文件备份页,否则如果节点过度分配,文件I/O读取的页将立即抛出.
	 * 因此，如果未映射的文件备份页使用的节点百分比低于指定百分比，则我们不会回收。
	 */

	/* pgdat->min_unmapped_pages 是“/proc/sys/vm/min_unmapped_ratio”乘上总的页数.
	 * 页缓存中潜在可回收页数如果大于pgdat->min_unmapped_pages才做页回收
	 *
	 * min_slab_pages:如果用于slab的页达到这个值就缓存收缩.
	 * 如果这个pgdat所有的NR_SLAB_RECLAIMABLE <= pgdat->min_slab_pages
	 * 那么也不用回收了
	 */
	if (node_pagecache_reclaimable(pgdat) <= pgdat->min_unmapped_pages &&
	    sum_zone_node_page_state(pgdat->node_id, NR_SLAB_RECLAIMABLE) <= pgdat->min_slab_pages)
		return NODE_RECLAIM_FULL;

	/* 扫描的数量 >= 可回收的六倍 */
	if (!pgdat_reclaimable(pgdat))
		return NODE_RECLAIM_FULL;

	/*
	 * Do not scan if the allocation should not be delayed.
	 */
	if (!gfpflags_allow_blocking(gfp_mask) || (current->flags & PF_MEMALLOC))
		return NODE_RECLAIM_NOSCAN;

	/*
	 * Only run node reclaim on the local node or on nodes that do not
	 * have associated processors. This will favor the local processor
	 * over remote processors and spread off node memory allocations
	 * as wide as possible.
	 *
	 * 仅在本地节点或没有关联处理器的节点上运行节点回收.
	 * 这将有利于本地处理器而不是远程处理器,并尽可能广泛地分配节点内存.
	 */

	/* numa_node_id是看你本地CPU属于哪个node
	 */
	if (node_state(pgdat->node_id, N_CPU) && pgdat->node_id != numa_node_id())
		return NODE_RECLAIM_NOSCAN;

	/* 如果原来就被PGDAT_RECLAIM_LOCKED住了,那么直接返回
	 * 否则设置PGDAT_RECLAIM_LOCKED
	 */
	if (test_and_set_bit(PGDAT_RECLAIM_LOCKED, &pgdat->flags))
		return NODE_RECLAIM_NOSCAN;

	ret = __node_reclaim(pgdat, gfp_mask, order);
	clear_bit(PGDAT_RECLAIM_LOCKED, &pgdat->flags);

	if (!ret)
		count_vm_event(PGSCAN_ZONE_RECLAIM_FAILED);

	return ret;
}
#endif

/*
 * page_evictable - test whether a page is evictable
 * @page: the page to test
 *
 * Test whether page is evictable--i.e., should be placed on active/inactive
 * lists vs unevictable list.
 *
 * Reasons page might not be evictable:
 * (1) page's mapping marked unevictable
 * (2) page is part of an mlocked VMA
 *
 */
int page_evictable(struct page *page)
{
	return !mapping_unevictable(page_mapping(page)) && !PageMlocked(page);
}

#ifdef CONFIG_SHMEM
/**
 * check_move_unevictable_pages - check pages for evictability and move to appropriate zone lru list
 * @pages:	array of pages to check
 * @nr_pages:	number of pages to check
 *
 * Checks pages for evictability and moves them to the appropriate lru list.
 *
 * This function is only used for SysV IPC SHM_UNLOCK.
 */
void check_move_unevictable_pages(struct page **pages, int nr_pages)
{
	struct lruvec *lruvec;
	struct pglist_data *pgdat = NULL;
	int pgscanned = 0;
	int pgrescued = 0;
	int i;

	for (i = 0; i < nr_pages; i++) {
		struct page *page = pages[i];
		struct pglist_data *pagepgdat = page_pgdat(page);

		pgscanned++;
		if (pagepgdat != pgdat) {
			if (pgdat)
				spin_unlock_irq(&pgdat->lru_lock);
			pgdat = pagepgdat;
			spin_lock_irq(&pgdat->lru_lock);
		}
		lruvec = mem_cgroup_page_lruvec(page, pgdat);

		if (!PageLRU(page) || !PageUnevictable(page))
			continue;

		if (page_evictable(page)) {
			enum lru_list lru = page_lru_base_type(page);

			VM_BUG_ON_PAGE(PageActive(page), page);
			ClearPageUnevictable(page);
			del_page_from_lru_list(page, lruvec, LRU_UNEVICTABLE);
			add_page_to_lru_list(page, lruvec, lru);
			pgrescued++;
		}
	}

	if (pgdat) {
		__count_vm_events(UNEVICTABLE_PGRESCUED, pgrescued);
		__count_vm_events(UNEVICTABLE_PGSCANNED, pgscanned);
		spin_unlock_irq(&pgdat->lru_lock);
	}
}
#endif /* CONFIG_SHMEM */
