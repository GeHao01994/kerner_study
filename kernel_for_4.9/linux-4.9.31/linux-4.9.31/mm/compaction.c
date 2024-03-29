/*
 * linux/mm/compaction.c
 *
 * Memory compaction for the reduction of external fragmentation. Note that
 * this heavily depends upon page migration to do all the real heavy
 * lifting
 *
 * Copyright IBM Corp. 2007-2010 Mel Gorman <mel@csn.ul.ie>
 */
#include <linux/cpu.h>
#include <linux/swap.h>
#include <linux/migrate.h>
#include <linux/compaction.h>
#include <linux/mm_inline.h>
#include <linux/backing-dev.h>
#include <linux/sysctl.h>
#include <linux/sysfs.h>
#include <linux/page-isolation.h>
#include <linux/kasan.h>
#include <linux/kthread.h>
#include <linux/freezer.h>
#include <linux/page_owner.h>
#include "internal.h"

#ifdef CONFIG_COMPACTION
static inline void count_compact_event(enum vm_event_item item)
{
	count_vm_event(item);
}

static inline void count_compact_events(enum vm_event_item item, long delta)
{
	count_vm_events(item, delta);
}
#else
#define count_compact_event(item) do { } while (0)
#define count_compact_events(item, delta) do { } while (0)
#endif

#if defined CONFIG_COMPACTION || defined CONFIG_CMA

#define CREATE_TRACE_POINTS
#include <trace/events/compaction.h>

#define block_start_pfn(pfn, order)	round_down(pfn, 1UL << (order))
#define block_end_pfn(pfn, order)	ALIGN((pfn) + 1, 1UL << (order))
#define pageblock_start_pfn(pfn)	block_start_pfn(pfn, pageblock_order)
#define pageblock_end_pfn(pfn)		block_end_pfn(pfn, pageblock_order)

static unsigned long release_freepages(struct list_head *freelist)
{
	struct page *page, *next;
	unsigned long high_pfn = 0;

	list_for_each_entry_safe(page, next, freelist, lru) {
		unsigned long pfn = page_to_pfn(page);
		list_del(&page->lru);
		__free_page(page);
		if (pfn > high_pfn)
			high_pfn = pfn;
	}

	return high_pfn;
}

static void map_pages(struct list_head *list)
{
	unsigned int i, order, nr_pages;
	struct page *page, *next;
	LIST_HEAD(tmp_list);
	/* 对list中的链表进行分割的操作 */
	list_for_each_entry_safe(page, next, list, lru) {
		/* 先把它从lru链表里面删除 */
		list_del(&page->lru);
		/* 拿到该page的order */
		order = page_private(page);
		/* 根据oder来算出它有多少个页面 */
		nr_pages = 1 << order;
		/* 页面进行分配之前会进行一些处理 */
		post_alloc_hook(page, order, __GFP_MOVABLE);
		/* 如果order大于0,那么分割页面 */
		if (order)
			split_page(page, order);
		/* 把每一页都添加到临时的链表里面去 */
		for (i = 0; i < nr_pages; i++) {
			list_add(&page->lru, &tmp_list);
			page++;
		}
	}
	/* 然后把该临时链表贴到原来的链表里面去 */
	list_splice(&tmp_list, list);
}

static inline bool migrate_async_suitable(int migratetype)
{
	return is_migrate_cma(migratetype) || migratetype == MIGRATE_MOVABLE;
}

#ifdef CONFIG_COMPACTION

int PageMovable(struct page *page)
{
	struct address_space *mapping;

	VM_BUG_ON_PAGE(!PageLocked(page), page);
	if (!__PageMovable(page))
		return 0;

	mapping = page_mapping(page);
	if (mapping && mapping->a_ops && mapping->a_ops->isolate_page)
		return 1;

	return 0;
}
EXPORT_SYMBOL(PageMovable);

void __SetPageMovable(struct page *page, struct address_space *mapping)
{
	VM_BUG_ON_PAGE(!PageLocked(page), page);
	VM_BUG_ON_PAGE((unsigned long)mapping & PAGE_MAPPING_MOVABLE, page);
	page->mapping = (void *)((unsigned long)mapping | PAGE_MAPPING_MOVABLE);
}
EXPORT_SYMBOL(__SetPageMovable);

void __ClearPageMovable(struct page *page)
{
	VM_BUG_ON_PAGE(!PageLocked(page), page);
	VM_BUG_ON_PAGE(!PageMovable(page), page);
	/*
	 * Clear registered address_space val with keeping PAGE_MAPPING_MOVABLE
	 * flag so that VM can catch up released page by driver after isolation.
	 * With it, VM migration doesn't try to put it back.
	 */
	page->mapping = (void *)((unsigned long)page->mapping &
				PAGE_MAPPING_MOVABLE);
}
EXPORT_SYMBOL(__ClearPageMovable);

/* Do not skip compaction more than 64 times */
#define COMPACT_MAX_DEFER_SHIFT 6

/*
 * Compaction is deferred when compaction fails to result in a page
 * allocation success. 1 << compact_defer_limit compactions are skipped up
 * to a limit of 1 << COMPACT_MAX_DEFER_SHIFT
 */
void defer_compaction(struct zone *zone, int order)
{
	zone->compact_considered = 0;
	zone->compact_defer_shift++;

	if (order < zone->compact_order_failed)
		zone->compact_order_failed = order;

	if (zone->compact_defer_shift > COMPACT_MAX_DEFER_SHIFT)
		zone->compact_defer_shift = COMPACT_MAX_DEFER_SHIFT;

	trace_mm_compaction_defer_compaction(zone, order);
}

/* Returns true if compaction should be skipped this time */
bool compaction_deferred(struct zone *zone, int order)
{
	/* 成员compact_defer_shift是推迟的最大次数以2为底的对数,当推迟的次数达到(1 << compact_defer_shift)时,不能推迟 */
	/* 拿到这个defer_limit */
	unsigned long defer_limit = 1UL << zone->compact_defer_shift;

	/* 成员compact_order_failed记录内存碎片整理失败时的申请阶数.
	 * 内存碎片整理执行成功的时候,如果申请阶数order大于或等于成员compact_order_failed,那么把成员compact_order_failed设置为(order+1).
	 * 内存碎片整理执行失败的时候,如果申请阶数order小于成员compact_order_failed,那么把成员compact_order_failed设置为order.
	 *
	 */

	/* 如果order小于zone->compact_order_failed,则返回false */
	if (order < zone->compact_order_failed)
		return false;

	/* Avoid possible overflow */

	/* 成员compact_considered记录推迟的次数
	 * 如果该zone的推迟次数+1之后比defer_limit还要大,
	 * 那么重新赋值回来
	 */
	if (++zone->compact_considered > defer_limit)
		zone->compact_considered = defer_limit;

	/* 如果大于等于了defer_limit,那么返回false,否则返回true */
	if (zone->compact_considered >= defer_limit)
		return false;

	trace_mm_compaction_deferred(zone, order);

	return true;
}

/*
 * Update defer tracking counters after successful compaction of given order,
 * which means an allocation either succeeded (alloc_success == true) or is
 * expected to succeed.
 */
void compaction_defer_reset(struct zone *zone, int order,
		bool alloc_success)
{
	if (alloc_success) {
		zone->compact_considered = 0;
		zone->compact_defer_shift = 0;
	}
	if (order >= zone->compact_order_failed)
		zone->compact_order_failed = order + 1;

	trace_mm_compaction_defer_reset(zone, order);
}

/* Returns true if restarting compaction after many failures */
bool compaction_restarting(struct zone *zone, int order)
{
	/* 成员compact_order_failed记录内存碎片整理失败时的申请阶数.
	 * 内存碎片整理执行成功的时候,如果申请阶数order大于或等于成员compact_order_failed,那么把成员compact_order_failed设置为(order + 1).
	 * 内存碎片整理执行失败的时候,如果申请阶数order小于成员compact_order_failed,那么把成员compact_order_failed设置为order.
	 *
	 * 如果现在的order比之前内存规整失败时的order要小,那么返回false
	 */
	if (order < zone->compact_order_failed)
		return false;

	/* 到这里说明现在的order比之前内存规整失败时的order要大
	 * 成员compact_considered记录推迟的次数
	 * 成员compact_defer_shift是推迟的最大次数以2为底的对数,当推迟的次数达到(1 << compact_defer_shift)时,不能推迟
	 *
	 * 每次内存碎片整理执行失败,把成员compact_defer_shift加1,不允许超过COMPACT_MAX_DEFER_SHIFT(值为6),即把推迟的最大次数翻倍,但是不能超过64.
	 * 如果已经等于最大的DEFER_SHIFT了
	 * 并且推迟次数已经大于了1UL << zone->compact_defer_shift
	 * 才返回true
	 */
	return zone->compact_defer_shift == COMPACT_MAX_DEFER_SHIFT &&
		zone->compact_considered >= 1UL << zone->compact_defer_shift;
}

/* Returns true if the pageblock should be scanned for pages to isolate. */
static inline bool isolation_suitable(struct compact_control *cc,
					struct page *page)
{
	/*ignore_skip_hint: 若为true,代表扫描器在扫描pageblock过程中,不再根据PG_migrate_sip来判断是否跳过处理 */
	bool ignore_skip_hint;
	if (cc->ignore_skip_hint)
		return true;

	/* 否则得到(1 << (PB_migrate_skip)位,如果为1,则表示需要跳过 */
	return !get_pageblock_skip(page);
}

static void reset_cached_positions(struct zone *zone)
{
	/* 该数组用于控制异步和同步两种memory compact场景所从头部开始扫描的页迁移位置 */
	zone->compact_cached_migrate_pfn[0] = zone->zone_start_pfn;
	zone->compact_cached_migrate_pfn[1] = zone->zone_start_pfn;
	/* compact_cached_free_pfn 用于记录从尾部开始扫描的空闲page的位置 */
	zone->compact_cached_free_pfn =
				pageblock_start_pfn(zone_end_pfn(zone) - 1);
}

/*
 * This function is called to clear all cached information on pageblocks that
 * should be skipped for page isolation when the migrate and free page scanner
 * meet.
 *
 * 调用此函数是为了清除页面块上的所有缓存信息,当migrate和free page扫描程序相遇时,
 * 这些信息应该被跳过以进行页面隔离。
 */
static void __reset_isolation_suitable(struct zone *zone)
{
	unsigned long start_pfn = zone->zone_start_pfn;
	unsigned long end_pfn = zone_end_pfn(zone);
	unsigned long pfn;

	/* compact_blockskip_flush: Set to true when the PG_migrate_skip bits should be cleared */
	zone->compact_blockskip_flush = false;

	/* 将zone中所有pageblock的PB_migrate_skip清空 */
	/* Walk the zone and mark every pageblock as suitable for isolation */
	for (pfn = start_pfn; pfn < end_pfn; pfn += pageblock_nr_pages) {
		struct page *page;

		cond_resched();
		/* 如果pfn不是valid,那么skip掉 */
		if (!pfn_valid(pfn))
			continue;

		/* 得到page结构体 */
		page = pfn_to_page(pfn);
		/* 如果page不在这个zone里面,那么也continue */
		if (zone != page_zone(page))
			continue;
		/* 清除该pageblock的PB_migrate_skip bit */
		clear_pageblock_skip(page);
	}

	reset_cached_positions(zone);
}

void reset_isolation_suitable(pg_data_t *pgdat)
{
	int zoneid;

	for (zoneid = 0; zoneid < MAX_NR_ZONES; zoneid++) {
		struct zone *zone = &pgdat->node_zones[zoneid];
		if (!populated_zone(zone))
			continue;

		/* Only flush if a full compaction finished recently */
		if (zone->compact_blockskip_flush)
			__reset_isolation_suitable(zone);
	}
}

/*
 * If no pages were isolated then mark this pageblock to be skipped in the
 * future. The information is later cleared by __reset_isolation_suitable().
 *
 * 如果没有隔离任何页面,则将此页面块标记为将来跳过.该信息稍后由__reset_isolation_suitable()清除.
 */
static void update_pageblock_skip(struct compact_control *cc,
			struct page *page, unsigned long nr_isolated,
			bool migrate_scanner)
{
	struct zone *zone = cc->zone;
	unsigned long pfn;

	/* ignore_skip_hint若为true,代表扫描器在扫描pageblock过程中,不再根据PG_migrate_sip来判断是否跳过处理 */
	if (cc->ignore_skip_hint)
		return;

	/* 如果page是NULL,那么直接返回 */
	if (!page)
		return;

	/* 如果有页面隔离,那么直接返回 */
	if (nr_isolated)
		return;

	/* 设置该pageblock的PB_migrate_skip */
	set_pageblock_skip(page);

	/* 通过该page找到pfn */
	pfn = page_to_pfn(page);

	/* Update where async and sync compaction should restart
	 * 更新异步和同步规整应该重新启动的位置
	 */

	/* 如果migrate_scanner设置为true,那么更新compact_cached_migrate_pfn为此pfn */
	if (migrate_scanner) {
		if (pfn > zone->compact_cached_migrate_pfn[0])
			zone->compact_cached_migrate_pfn[0] = pfn;
		if (cc->mode != MIGRATE_ASYNC &&
		    pfn > zone->compact_cached_migrate_pfn[1])
			zone->compact_cached_migrate_pfn[1] = pfn;
	} else {
		/* 否则就是free的,更新compact_cached_free_pfn */
		if (pfn < zone->compact_cached_free_pfn)
			zone->compact_cached_free_pfn = pfn;
	}
}
#else
static inline bool isolation_suitable(struct compact_control *cc,
					struct page *page)
{
	return true;
}

static void update_pageblock_skip(struct compact_control *cc,
			struct page *page, unsigned long nr_isolated,
			bool migrate_scanner)
{
}
#endif /* CONFIG_COMPACTION */

/*
 * Compaction requires the taking of some coarse locks that are potentially
 * very heavily contended. For async compaction, back out if the lock cannot
 * be taken immediately. For sync compaction, spin on the lock if needed.
 *
 * Returns true if the lock is held
 * Returns false if the lock is not held and compaction should abort
 */
static bool compact_trylock_irqsave(spinlock_t *lock, unsigned long *flags,
						struct compact_control *cc)
{
	if (cc->mode == MIGRATE_ASYNC) {
		if (!spin_trylock_irqsave(lock, *flags)) {
			cc->contended = true;
			return false;
		}
	} else {
		spin_lock_irqsave(lock, *flags);
	}

	return true;
}

/*
 * Compaction requires the taking of some coarse locks that are potentially
 * very heavily contended. The lock should be periodically unlocked to avoid
 * having disabled IRQs for a long time, even when there is nobody waiting on
 * the lock. It might also be that allowing the IRQs will result in
 * need_resched() becoming true. If scheduling is needed, async compaction
 * aborts. Sync compaction schedules.
 * Either compaction type will also abort if a fatal signal is pending.
 * In either case if the lock was locked, it is dropped and not regained.
 *
 * Returns true if compaction should abort due to fatal signal pending, or
 *		async compaction due to need_resched()
 * Returns false when compaction can continue (sync compaction might have
 *		scheduled)
 *
 * 压缩需要拿到一些粗鲁的潜在的非常激烈的竞争锁.这个锁应该定期去解锁以避免
 * 长时间禁用IRQ,即使没有人等待锁.
 * 也可能是因为允许IRQ会导致need_resched()变为true.
 * 如果需要调度,异步规整将中止。同步规整调度.
 * 如果挂起致命信号,则任一压缩类型也将中止.
 * 在任何一种情况下,如果锁被锁定,它都会被丢弃而无法重新获得.
 *
 * 如果规整因致命信号挂起而中止,或者异步规整因need_sched而中止,则返回true
 *
 * 当规整可以继续时返回false(同步规整可能会调度)
 *
 */
static bool compact_unlock_should_abort(spinlock_t *lock,
		unsigned long flags, bool *locked, struct compact_control *cc)
{
	/* 如果被lock了,那么解锁之后把lock设置为false */
	if (*locked) {
		spin_unlock_irqrestore(lock, flags);
		*locked = false;
	}

	/* 如果有致命的信号,那么cc->contended设置为true */
	if (fatal_signal_pending(current)) {
		cc->contended = true;
		return true;
	}

	if (need_resched()) {
		/* 如果是异步模式,那么cc->contended = true之后返回true */
		if (cc->mode == MIGRATE_ASYNC) {
			cc->contended = true;
			return true;
		}
		/* 如果是同步,那么调度出去之后返回false */
		cond_resched();
	}

	return false;
}

/*
 * Aside from avoiding lock contention, compaction also periodically checks
 * need_resched() and either schedules in sync compaction or aborts async
 * compaction. This is similar to what compact_unlock_should_abort() does, but
 * is used where no lock is concerned.
 *
 * Returns false when no scheduling was needed, or sync compaction scheduled.
 * Returns true when async compaction should abort.
 *
 * 除了避免锁争用之外,规整还定期进行检查need_sched()无论同步规整的调度还是终止异步规整.
 * 这与compact_unlock_should_abort()的操作类似，但是在不涉及锁的情况下使用。
 *
 * 当不需要调度或同步规整调度时,返回false.
 * 当异步规整应该中止时,返回true.
 */
static inline bool compact_should_abort(struct compact_control *cc)
{
	/* async compaction aborts if contended */
	/* 如果需要重新调度 */
	if (need_resched()) {
		/* 如果是异步模式,那么cc->contended = true之后返回true */
		if (cc->mode == MIGRATE_ASYNC) {
			cc->contended = true;
			return true;
		}
		/* 如果是同步,那么调度出去之后返回false */
		cond_resched();
	}

	return false;
}

/*
 * Isolate free pages onto a private freelist. If @strict is true, will abort
 * returning 0 on any invalid PFNs or non-free pages inside of the pageblock
 * (even though it may still end up isolating some pages).
 *
 * 将free页面隔离到私有freelist中.
 * 如果@strict为true,则将终止
 * 在页面块内的任何无效PFN或non-free页面上返回0(即使最终可能仍会隔离某些页面)
 *
 * 这里面需要关注一个strict参数,如果该参数为true,那么isolate_freepages_block函数将会以页为遍历单位进行遍历及隔离,
 * 并且不会再根据当前收集空闲页已经大于当前已经收集迁移页则退出循环条件提前退出,而是完整隔离整个pageblock中合适的空闲页。
 */
static unsigned long isolate_freepages_block(struct compact_control *cc,
				unsigned long *start_pfn,
				unsigned long end_pfn,
				struct list_head *freelist,
				bool strict)
{
	int nr_scanned = 0, total_isolated = 0;
	struct page *cursor, *valid_page = NULL;
	unsigned long flags = 0;
	bool locked = false;
	unsigned long blockpfn = *start_pfn;
	unsigned int order;
	/* 得到blockpfn对应的struct page */
	cursor = pfn_to_page(blockpfn);

	/* Isolate free pages. */
	/* 开始隔离空闲的页面了 */
	for (; blockpfn < end_pfn; blockpfn++, cursor++) {
		int isolated;
		struct page *page = cursor;

		/*
		 * Periodically drop the lock (if held) regardless of its
		 * contention, to give chance to IRQs. Abort if fatal signal
		 * pending or async compaction detects need_resched()
		 *
		 * 无论锁的争用如何,都要定期丢弃锁(如果已持有),以便为IRQs提供机会.
		 * 如果有争用,则中止异步规整
		 */

		/* 如果blockpfn / SWAP_CLUSTER_MAX (#define SWAP_CLUSTER_MAX 32UL)
		 * 余数为0,并且compact_unlock_should_abort
		 * 那么break出去
		 */
		if (!(blockpfn % SWAP_CLUSTER_MAX)
		    && compact_unlock_should_abort(&cc->zone->lock, flags,
								&locked, cc))
			break;
		/* nr_scanned ++ */
		nr_scanned++;
		/* 如果pfn不是valid的,那么goto isolate_fail */
		if (!pfn_valid_within(blockpfn))
			goto isolate_fail;

		/* 如果valid_page为NULL,那么把该page设置为valid_page */
		if (!valid_page)
			valid_page = page;

		/*
		 * For compound pages such as THP and hugetlbfs, we can save
		 * potentially a lot of iterations if we skip them at once.
		 * The check is racy, but we can consider only valid values
		 * and the only danger is skipping too much.
		 *
		 * 对于像THP和hugetlbfs的复合页面,如果我们一次跳过它们,我们可能会节省很多迭代.
		 * 这个检查是活泼的,但我们只能考虑有效的值,唯一的危险是跳过太多.
		 */

		/* 如果是复合页 */
		if (PageCompound(page)) {
			/* 得到复合页的order */
			unsigned int comp_order = compound_order(page);
			/* 如果复合页的order < MAX_ORDER
			 * 那么blockpfn = low_pfn + 1 << comp_order - 1
			 */
			if (likely(comp_order < MAX_ORDER)) {
				blockpfn += (1UL << comp_order) - 1;
				cursor += (1UL << comp_order) - 1;
			}

			goto isolate_fail;
		}

		/* 如果不在伙伴系统里面,说明已经被用掉了,那么直接返回fail */
		if (!PageBuddy(page))
			goto isolate_fail;

		/*
		 * If we already hold the lock, we can skip some rechecking.
		 * Note that if we hold the lock now, checked_pageblock was
		 * already set in some previous iteration (or strict is true),
		 * so it is correct to skip the suitable migration target
		 * recheck as well.
		 *
		 * 如果我们已经锁定了,我们可以跳过一些复查.
		 * 请注意,如果我们现在持有锁,checked_pageblock已经在之前的一些迭代中设置(或者strict为true),因此跳过适当的迁移目标复查也是正确的.
		 */
		if (!locked) {
			/*
			 * The zone lock must be held to isolate freepages.
			 * Unfortunately this is a very coarse lock and can be
			 * heavily contended if there are parallel allocations
			 * or parallel compactions. For async compaction do not
			 * spin on the lock and we acquire the lock as late as
			 * possible.
			 *
			 * 必须保持zone锁定才能隔离空闲页面。
			 * 不幸的是,这是一个非常粗糙的锁,如果存在并行分配或并行压缩,则可能会受到严重的争用.
			 * 对于异步压缩,不要自旋在锁上，我们会尽可能晚地获得锁。
			 */
			locked = compact_trylock_irqsave(&cc->zone->lock,
								&flags, cc);
			/* 如果获得锁失败,那么break出去 */
			if (!locked)
				break;

			/* Recheck this is a buddy page under lock
			 * 如果Page不在LRU链表里面,那么跳到isolate_fail
			 */
			if (!PageBuddy(page))
				goto isolate_fail;
		}

		/* Found a free page, will break it into order-0 pages
		 * 找到一个可用页面，将其分解为0个页面
		 */
		order = page_order(page);
		/* 隔离该freepage */
		isolated = __isolate_free_page(page, order);
		/* 如果为0,表示如果隔离了这些页面,水位不够了,那么就break吧 */
		if (!isolated)
			break;
		/* 设置该page的private为对应的order */
		/* static inline void set_page_private(struct page *page, unsigned long private)
		 * {
		 *	page->private = private;
		 * }
		 */
		set_page_private(page, order);
		/* total_isolated加上这次隔离的数量 */
		total_isolated += isolated;
		/* 对应的nr_freepages加上这次隔离的数量 */
		cc->nr_freepages += isolated;
		/* 把它添加到freelist的尾部 */
		list_add_tail(&page->lru, freelist);
		/* 如果strict为false,然后nr_migratepages和nr_freepages已经相等了,说明已经满足需求了 */
		if (!strict && cc->nr_migratepages <= cc->nr_freepages) {
			/* 那么blockpfn + isolated 之后break吧 */
			blockpfn += isolated;
			break;
		}
		/* Advance to the end of split page
		 * 前进到拆分页的末尾
		 */
		blockpfn += isolated - 1;
		cursor += isolated - 1;
		continue;

isolate_fail:
		/* 如果strict为true,那么break,否则continue */
		if (strict)
			break;
		else
			continue;

	}
	/* 如果是locked的,那么解锁 */
	if (locked)
		spin_unlock_irqrestore(&cc->zone->lock, flags);

	/*
	 * There is a tiny chance that we have read bogus compound_order(),
	 * so be careful to not go outside of the pageblock.
	 *
	 * 我们读到伪compound_order的可能性很小,所以要小心不要超出页面块.
	 */
	if (unlikely(blockpfn > end_pfn))
		blockpfn = end_pfn;

	trace_mm_compaction_isolate_freepages(*start_pfn, blockpfn,
					nr_scanned, total_isolated);

	/* Record how far we have got within the block
	 * 记录我们在块内的距离
	 */
	*start_pfn = blockpfn;

	/*
	 * If strict isolation is requested by CMA then check that all the
	 * pages requested were isolated. If there were any failures, 0 is
	 * returned and CMA will fail.
	 *
	 * 如果CMA要求严格隔离,则检查所请求的所有页面是否已隔离.
	 * 如果存在任何故障，则返回0，并且CMA将失败。
	 */

	/* 如果strict为true,但是没有到end_pfn,那说明中间出现了fail,那么把total_isolated设置为0 */
	if (strict && blockpfn < end_pfn)
		total_isolated = 0;

	/* Update the pageblock-skip if the whole pageblock was scanned
	 * 如果扫描了整个页面块都没有隔离出任何free page,那么更新pageblock-skip信息和compact_cached_free_pfn
	 */
	if (blockpfn == end_pfn)
		update_pageblock_skip(cc, valid_page, total_isolated, false);

	/* 更新COMPACTMIGRATE_SCANNED event */
	count_compact_events(COMPACTFREE_SCANNED, nr_scanned);
	/* 如果有nr_isolated,那么更新COMPACTISOLATED event */
	if (total_isolated)
		count_compact_events(COMPACTISOLATED, total_isolated);
	/* 返回隔离数 */
	return total_isolated;
}

/**
 * isolate_freepages_range() - isolate free pages.
 * @start_pfn: The first PFN to start isolating.
 * @end_pfn:   The one-past-last PFN.
 *
 * Non-free pages, invalid PFNs, or zone boundaries within the
 * [start_pfn, end_pfn) range are considered errors, cause function to
 * undo its actions and return zero.
 *
 * Otherwise, function returns one-past-the-last PFN of isolated page
 * (which may be greater then end_pfn if end fell in a middle of
 * a free page).
 */
unsigned long
isolate_freepages_range(struct compact_control *cc,
			unsigned long start_pfn, unsigned long end_pfn)
{
	unsigned long isolated, pfn, block_start_pfn, block_end_pfn;
	LIST_HEAD(freelist);

	pfn = start_pfn;
	block_start_pfn = pageblock_start_pfn(pfn);
	if (block_start_pfn < cc->zone->zone_start_pfn)
		block_start_pfn = cc->zone->zone_start_pfn;
	block_end_pfn = pageblock_end_pfn(pfn);

	for (; pfn < end_pfn; pfn += isolated,
				block_start_pfn = block_end_pfn,
				block_end_pfn += pageblock_nr_pages) {
		/* Protect pfn from changing by isolate_freepages_block */
		unsigned long isolate_start_pfn = pfn;

		block_end_pfn = min(block_end_pfn, end_pfn);

		/*
		 * pfn could pass the block_end_pfn if isolated freepage
		 * is more than pageblock order. In this case, we adjust
		 * scanning range to right one.
		 */
		if (pfn >= block_end_pfn) {
			block_start_pfn = pageblock_start_pfn(pfn);
			block_end_pfn = pageblock_end_pfn(pfn);
			block_end_pfn = min(block_end_pfn, end_pfn);
		}

		if (!pageblock_pfn_to_page(block_start_pfn,
					block_end_pfn, cc->zone))
			break;

		isolated = isolate_freepages_block(cc, &isolate_start_pfn,
						block_end_pfn, &freelist, true);

		/*
		 * In strict mode, isolate_freepages_block() returns 0 if
		 * there are any holes in the block (ie. invalid PFNs or
		 * non-free pages).
		 */
		if (!isolated)
			break;

		/*
		 * If we managed to isolate pages, it is always (1 << n) *
		 * pageblock_nr_pages for some non-negative n.  (Max order
		 * page may span two pageblocks).
		 */
	}

	/* __isolate_free_page() does not map the pages */
	map_pages(&freelist);

	if (pfn < end_pfn) {
		/* Loop terminated early, cleanup. */
		release_freepages(&freelist);
		return 0;
	}

	/* We don't use freelists for anything. */
	return pfn;
}

/* Similar to reclaim, but different enough that they don't share logic */
static bool too_many_isolated(struct zone *zone)
{
	unsigned long active, inactive, isolated;

	inactive = node_page_state(zone->zone_pgdat, NR_INACTIVE_FILE) +
			node_page_state(zone->zone_pgdat, NR_INACTIVE_ANON);
	active = node_page_state(zone->zone_pgdat, NR_ACTIVE_FILE) +
			node_page_state(zone->zone_pgdat, NR_ACTIVE_ANON);
	isolated = node_page_state(zone->zone_pgdat, NR_ISOLATED_FILE) +
			node_page_state(zone->zone_pgdat, NR_ISOLATED_ANON);

	/* 这里主要是判断隔离的页面是不是大于(inactive + active) / 2 */
	return isolated > (inactive + active) / 2;
}

/**
 * isolate_migratepages_block() - isolate all migrate-able pages within
 *				  a single pageblock
 * @cc:		Compaction control structure.
 * @low_pfn:	The first PFN to isolate
 * @end_pfn:	The one-past-the-last PFN to isolate, within same pageblock
 * @isolate_mode: Isolation mode to be used.
 *
 * Isolate all pages that can be migrated from the range specified by
 * [low_pfn, end_pfn). The range is expected to be within same pageblock.
 * Returns zero if there is a fatal signal pending, otherwise PFN of the
 * first page that was not scanned (which may be both less, equal to or more
 * than end_pfn).
 *
 * The pages are isolated on cc->migratepages list (not required to be empty),
 * and cc->nr_migratepages is updated accordingly. The cc->migrate_pfn field
 * is neither read nor updated.
 *
 * isolate_migratepages_block（）- 在单个页面块中隔离所有可迁移的页面
 * @cc: 规整控制结构体
 * @low_pfn: 隔离的第一个PFN
 * @end_pfn：在同一页面块内要隔离的倒数第一个的PFN
 * isolate_mode：要使用的隔离模式.
 *
 * 将指定的[low_pfn,end_pfn)范围内的所有能够迁移的页面隔离出来.
 * 该范围应在同一个页面块内.
 * 如果有致命信号挂起,则返回零,否则返回未扫描的第一个页面(可能小于、等于或大于end_pfn).
 *
 * 页面在cc->migratepages列表中被隔离(不要求为空),cc->nr_migratepages会相应更新.
 * cc->migrate_pfn字段既不读取也不更新。
 */
static unsigned long
isolate_migratepages_block(struct compact_control *cc, unsigned long low_pfn,
			unsigned long end_pfn, isolate_mode_t isolate_mode)
{
	struct zone *zone = cc->zone;
	unsigned long nr_scanned = 0, nr_isolated = 0;
	struct lruvec *lruvec;
	unsigned long flags = 0;
	bool locked = false;
	struct page *page = NULL, *valid_page = NULL;
	unsigned long start_pfn = low_pfn;
	bool skip_on_failure = false;
	unsigned long next_skip_pfn = 0;

	/*
	 * Ensure that there are not too many pages isolated from the LRU
	 * list by either parallel reclaimers or compaction. If there are,
	 * delay for some time until fewer pages are isolated
	 *
	 * 确保没有太多页面通过并行回收或规整从LRU列表中隔离出来.
	 * 如果有,请延迟一段时间,直到隔离出较少的页面
	 */

	/* too_many_isolated如果判断当前临时从LRU链表分离出来的页面比较多,
	 * 则最好睡眠等待100毫秒(congestion_wait).
	 * 如果迁移模式是异步(MIGRATE_ASYNC)的,则直接退出
	 */
	while (unlikely(too_many_isolated(zone))) {
		/* async migration should just abort */
		if (cc->mode == MIGRATE_ASYNC)
			return 0;

		congestion_wait(BLK_RW_ASYNC, HZ/10);

		if (fatal_signal_pending(current))
			return 0;
	}

	/* 判断规整是不是要终止 */
	if (compact_should_abort(cc))
		return 0;

	/* 如果是异步直接规整,设置skip_on_failure为true,next_skip_pfn为
	 * #define block_end_pfn(pfn, order)	ALIGN((pfn) + 1, 1UL << (order))
	 * 为该pfn的结束pfn,实际上这里的意思是你是想分离1 << order个page是吧
	 * 那么我们就拿你这个来作为这个pageblock的步长
	 */
	if (cc->direct_compaction && (cc->mode == MIGRATE_ASYNC)) {
		skip_on_failure = true;
		next_skip_pfn = block_end_pfn(low_pfn, cc->order);
	}

	/* 执行完隔离，将low_pfn到end_pfn中正在使用的页框从zone->lru中取出来,返回的是可移动页扫描扫描到的页框号
	 * 而UNMOVABLE类型的页框是不会处于lru链表中的，所以所有不在lru链表中的页都会被跳过
	 * 返回的是扫描到的最后的页
	 *
	 * for循环扫描pageblock去寻觅可以迁移的页
	 */
	/* Time to isolate some pages for migration */
	for (; low_pfn < end_pfn; low_pfn++) {
		/* 如果skip_on_failure等于true,并且low_pfn大于next_skip_pfn */
		if (skip_on_failure && low_pfn >= next_skip_pfn) {
			/*
			 * We have isolated all migration candidates in the
			 * previous order-aligned block, and did not skip it due
			 * to failure. We should migrate the pages now and
			 * hopefully succeed compaction.
			 *
			 * 我们已经在上一个order-aligned的块中隔离了所有候选迁移,
			 * 并且没有因为失败而跳过它.
			 * 我们现在应该迁移这些页面,希望规整成功。
			 */
			if (nr_isolated)
				break;

			/*
			 * We failed to isolate in the previous order-aligned
			 * block. Set the new boundary to the end of the
			 * current block. Note we can't simply increase
			 * next_skip_pfn by 1 << order, as low_pfn might have
			 * been incremented by a higher number due to skipping
			 * a compound or a high-order buddy page in the
			 * previous loop iteration.
			 */
			/*
			 * 我们未能在上一个order-aligned的块中进行隔离.
			 * 将新边界设置为当前块的结束.
			 * 注意,我们不能简单地通过1 << order增加next_skip_pfn,因为low_pfn可能由于在上一次循环迭代中
			 * 跳过复合或高阶伙伴页面而增加了更高的数字
			 */
			next_skip_pfn = block_end_pfn(low_pfn, cc->order);
		}

		/*
		 * Periodically drop the lock (if held) regardless of its
		 * contention, to give chance to IRQs. Abort async compaction
		 * if contended.
		 *
		 * 无论锁的争用如何,都要定期丢弃锁(如果已持有),以便为IRQs提供机会.
		 * 如果有争用，则中止异步规整
		 */

		/* 如果low_pfn / SWAP_CLUSTER_MAX (#define SWAP_CLUSTER_MAX 32UL)
		 * 余数为0,并且compact_unlock_should_abort
		 * 那么break出去
		 */
		if (!(low_pfn % SWAP_CLUSTER_MAX)
		    && compact_unlock_should_abort(zone_lru_lock(zone), flags,
								&locked, cc))
			break;

		/* 如果pfn不是valid的,那么goto isolate_fail */
		if (!pfn_valid_within(low_pfn))
			goto isolate_fail;
		/* nr_scanned ++ */
		nr_scanned++;

		page = pfn_to_page(low_pfn);

		/* 如果valid_page为NULL,那么把该page设置为valid_page */
		if (!valid_page)
			valid_page = page;

		/*
		 * Skip if free. We read page order here without zone lock
		 * which is generally unsafe, but the race window is small and
		 * the worst thing that can happen is that we skip some
		 * potential isolation targets.
		 *
		 * 如果是空闲的,那么skip掉.
		 * 我们在这里在没有zone lock下去读的page order,
		 * 这通常是不安全的,但竞争机会很小,最糟糕的情况是我们跳过了一些潜在的隔离目标
		 */

		/* 如果该页还在伙伴系统中,那么该页不适合迁移,略过该页. */
		if (PageBuddy(page)) {
			/* 通过page_order_unsafe读取该页的order值 */
			unsigned long freepage_order = page_order_unsafe(page);

			/*
			 * Without lock, we cannot be sure that what we got is
			 * a valid page order. Consider only values in the
			 * valid order range to prevent low_pfn overflow.
			 *
			 * 没有锁,我们无法确定我们得到的是有效的page order.
			 * 只考虑有效的order范围内的值,以防止低_pfn溢出.
			 */

			/* 如果0 < freepage_order < MAX_ORDER
			 * 那么low_pfn = low_pfn + 1 << order - 1
			 *
			 * 这里肯定会-1啦,因为你到下一个循环的时候会 + 1就是下一块的起始地址了
			 */
			if (freepage_order > 0 && freepage_order < MAX_ORDER)
				low_pfn += (1UL << freepage_order) - 1;
			continue;
		}

		/*
		 * Regardless of being on LRU, compound pages such as THP and
		 * hugetlbfs are not to be compacted. We can potentially save
		 * a lot of iterations if we skip them at once. The check is
		 * racy, but we can consider only valid values and the only
		 * danger is skipping too much.
		 *
		 * 无论是否在LRU上,都不会规整像THP和hugetlbfs等复合页.
		 * 如果我们一次跳过它们,我们可能会节省很多迭代.
		 * 这个检查是活泼的,但我们只能考虑有效的值,唯一的危险是跳过太多.
		 */

		/* 如果是复合页 */
		if (PageCompound(page)) {
			/* 得到复合页的order */
			unsigned int comp_order = compound_order(page);

			/* 如果复合页 < MAX_ORDER
			 * 那么low_pfn = low_pfn + 1 << comp_order - 1
			 */
			if (likely(comp_order < MAX_ORDER))
				low_pfn += (1UL << comp_order) - 1;

			goto isolate_fail;
		}

		/*
		 * Check may be lockless but that's ok as we recheck later.
		 * It's possible to migrate LRU and non-lru movable pages.
		 * Skip any other type of page
		 *
		 * 检查可能是无锁的,但我们稍后再检查时也可以.
		 * 迁移LRU和非LRU可移动页面是可能的.
		 * 跳过任何其他类型的页面
		 */

		/* 如果page不在LRU页面里面 */
		/* 这个很有意思,上文谈到大部分可移动页应该都是用户态的匿名页,这里怎么还会有不再LRU上的物理页呢,
		 * 实际这涉及到页迁移特性的一种功能,有兴趣的朋友可以阅读一下"Documentation/vm/page_migration.rst"文章中"Non-LRU page migration"这一小节.
		 * 内核中申请的内存通常都是non-LRU上并且不可移动,但是内核提供了定制能力,开发者可以在内核驱动中将自己申请的内存标记为可移动,
		 * 为此内核为page添加了两个新的flag即PG_movable和PG_isolated用于标识这种non-LRU并且可迁移的页.
		 * 开发者通常使用__SetPageMovable接口主动设置这些内存页PG_movable标记,而PG_isolated标识此页已经被隔离,开发者不需要主动设置此标记
		 * 现在我们应该可以理解上述代码中对于__PageMovable(page)判断,如果一个non-LRU页被设置了PG_movable并且PG_isolated还未被设置,
		 * 那么代表这个页也是可以进行迁移，随后将会调用isolate_movable_page函数进行隔离操作
		 */
		if (!PageLRU(page)) {
			/*
			 * __PageMovable can return false positive so we need
			 * to verify it under page_lock.
			 *
			 * __PageMovable可能返回false,所以我们需要在page_lock下进行验证.
			 */

			/* 对于非LRU可移动页面的测试,VM支持__PageMovable()函数.
			 * 然而,它并不能保证识别非LRU可移动页面,因为page->mapping字段与struct page中的其他变量是统一的.
			 */
			/* 如果page是movable并且是没有在隔离链表里面的 */
			if (unlikely(__PageMovable(page)) &&
					!PageIsolated(page)) {
				/* 如果有锁就解锁之后把locked设置为false */
				if (locked) {
					spin_unlock_irqrestore(zone_lru_lock(zone),
									flags);
					locked = false;
				}
				/* 问题还没有结束,实际想要让这些在内核中直接申请的页变为可迁移,光设置标记还不行,开发人员需要自定义这些页如何隔离以及如何迁移,
				 * 因此内核要求,开发者需要在address_space_operations结构体里面实现isolate_page、migratepage及putback_page函数.
				 * 现在回到isolate_movable_page函数,此函数将会调用开发人员注册的isolate_page函数完成这些页隔离操作
				 */
				if (isolate_movable_page(page, isolate_mode))
					goto isolate_success;
			}

			goto isolate_fail;
		}

		/*
		 * Migration will fail if an anonymous page is pinned in memory,
		 * so avoid taking lru_lock and isolating it unnecessarily in an
		 * admittedly racy check.
		 *
		 * 如果一个匿名页面被固定在内存中,迁移将失败,因此避免使用lru_lock,隔离它不必在公认的
		 * 活跃检查
		 */
		/* 如果匿名页已经被mlock等接口pin住,那么将会略过
		 * 一方面,通过page_mapping判断当前页是否为文件页;
		 * 另一方面,通过page_count(page) > page_mapcount(page)判断是否被pin住,
		 * 匿名页被pin住时会增加_refcount数值。
		 */
		if (!page_mapping(page) &&
		    page_count(page) > page_mapcount(page))
			goto isolate_fail;

		/* If we already hold the lock, we can skip some rechecking
		 * 如果我们已经拿到了锁,我们可以跳过一些复查
		 */
		if (!locked) {
			locked = compact_trylock_irqsave(zone_lru_lock(zone),
								&flags, cc);
			if (!locked)
				break;

			/* Recheck PageLRU and PageCompound under lock
			 * 在锁下重新检查PageLRU和PageCompound
			 */

			/* 如果Page不在LRU链表里面,那么跳到isolate_fail */
			if (!PageLRU(page))
				goto isolate_fail;

			/*
			 * Page become compound since the non-locked check,
			 * and it's on LRU. It can only be a THP so the order
			 * is safe to read and it's 0 for tail pages.
			 *
			 * 由于没有锁的检查,页面变得复杂,并且在LRU上.
			 * 它只能是THP，所以order是安全的,对于尾页它是0。
			 */
			if (unlikely(PageCompound(page))) {
				low_pfn += (1UL << compound_order(page)) - 1;
				goto isolate_fail;
			}
		}

		/* 拿到lruvec */
		lruvec = mem_cgroup_page_lruvec(page, zone->zone_pgdat);

		/* Try isolate the page */
		/* 隔离该页面前的一些检查,如果不等于0,说明不能隔离 */
		if (__isolate_lru_page(page, isolate_mode) != 0)
			goto isolate_fail;

		/* 如果page是复合页面,那么报个BUG吧 */
		VM_BUG_ON_PAGE(PageCompound(page), page);

		/* Successfully isolated */
		/* 把这个页面从lru链表里面删除 */
		del_page_from_lru_list(page, lruvec, page_lru(page));
		/* 增加该node的NR_ISOLATED_ANON + page_is_file_cache(page) 计数 */
		inc_node_page_state(page,
				NR_ISOLATED_ANON + page_is_file_cache(page));

isolate_success:
		/* 把它添加到cc->migratepages 链表里面去 */
		list_add(&page->lru, &cc->migratepages);
		/* cc的nr_migratepages计数增加 */
		cc->nr_migratepages++;
		/* nr_isolated计数增加 */
		nr_isolated++;

		/*
		 * Record where we could have freed pages by migration and not
		 * yet flushed them to buddy allocator.
		 * - this is the lowest page that was isolated and likely be
		 * then freed by migration.
		 *
		 * 记录我们本可以通过迁移释放页面而尚未将其刷新到伙伴分配器的位置.
		 * -这是被隔离的最低页面,然后可能通过迁移释放。
		 */

		/* 如果cc->last_migrated_pfn为空,那么设置为low_pfn */
		if (!cc->last_migrated_pfn)
			cc->last_migrated_pfn = low_pfn;

		/* Avoid isolating too much
		 * 避免隔离太多了
		 * 如果已经隔离了32页
		 * #define SWAP_CLUSTER_MAX 32UL
		 * #define COMPACT_CLUSTER_MAX SWAP_CLUSTER_MAX
		 * 那么退出吧
		 */
		if (cc->nr_migratepages == COMPACT_CLUSTER_MAX) {
			++low_pfn;
			break;
		}

		continue;
isolate_fail:
		/* 如果skip_on_failure = false,那么接着来 */
		if (!skip_on_failure)
			continue;

		/*
		 * We have isolated some pages, but then failed. Release them
		 * instead of migrating, as we cannot form the cc->order buddy
		 * page anyway.
		 *
		 * 我们已经隔离了一些页面,但后来失败了.释放它们而不是迁移,因为我们无论如何都无法形成cc->order伙伴系统
		 */

		/* 如果之前有隔离了一些页面,但是这里失败了 */
		if (nr_isolated) {
			/* 如果有锁,那么解锁之后,设置locked为false */
			if (locked) {
				spin_unlock_irqrestore(zone_lru_lock(zone), flags);
				locked = false;
			}
			/* 放回到原来的lru链表里面去 */
			putback_movable_pages(&cc->migratepages);
			/* 然后设置cc->nr_migratepages、last_migrated_pfn、nr_isolate都为0 */
			cc->nr_migratepages = 0;
			cc->last_migrated_pfn = 0;
			nr_isolated = 0;
		}

		/* 如果low_pfn小于next_skip_pfn
		 * 那么更新一下low_pfn和next_skip_pfn
		 * 其实这里就是看到你这块以 1UL << cc->order为单位的块没隔离成功,那么我就想着去下一块呗
		 */
		if (low_pfn < next_skip_pfn) {
			low_pfn = next_skip_pfn - 1;
			/*
			 * The check near the loop beginning would have updated
			 * next_skip_pfn too, but this is a bit simpler.
			 * 循环开始附近的检查也会更新next_skip_pfn,但这要简单一点。
			 */
			next_skip_pfn += 1UL << cc->order;
		}
	}

	/*
	 * The PageBuddy() check could have potentially brought us outside
	 * the range to be scanned.
	 *
	 * PageBuddy（）检查可能会将我们带到要扫描的范围之外
	 */
	/* 所以这里如果low_pfn大于了end_pfn,那么就把end_pfn给它 */
	if (unlikely(low_pfn > end_pfn))
		low_pfn = end_pfn;

	if (locked)
		spin_unlock_irqrestore(zone_lru_lock(zone), flags);

	/*
	 * Update the pageblock-skip information and cached scanner pfn,
	 * if the whole pageblock was scanned without isolating any page.
	 *
	 * 如果扫描了整个页面块都没有隔离出任何页面,那么更新pageblock-skip信息和compact_cached_migrate_pfn
	 */
	if (low_pfn == end_pfn)
		update_pageblock_skip(cc, valid_page, nr_isolated, true);

	trace_mm_compaction_isolate_migratepages(start_pfn, low_pfn,
						nr_scanned, nr_isolated);

	/* 更新COMPACTMIGRATE_SCANNED event */
	count_compact_events(COMPACTMIGRATE_SCANNED, nr_scanned);
	/* 如果有nr_isolated,那么更新COMPACTISOLATED event */
	if (nr_isolated)
		count_compact_events(COMPACTISOLATED, nr_isolated);

	return low_pfn;
}

/**
 * isolate_migratepages_range() - isolate migrate-able pages in a PFN range
 * @cc:        Compaction control structure.
 * @start_pfn: The first PFN to start isolating.
 * @end_pfn:   The one-past-last PFN.
 *
 * Returns zero if isolation fails fatally due to e.g. pending signal.
 * Otherwise, function returns one-past-the-last PFN of isolated page
 * (which may be greater than end_pfn if end fell in a middle of a THP page).
 *
 * isolate_migratepages_range（）- 隔离PFN范围内的可迁移页面
 * @cc：规整控制结构体
 * @start_pfn: 第一个开始隔离的pfn
 * @end_pfn：倒数第一个pfn
 *
 * 如果规整由于例如挂起的信号而不幸失败了则返回零.
 * 否则,函数返回隔离页的最后一页(如果end落在THP页的中间,则该值可能大于end_PFN).
 *
 */
unsigned long
isolate_migratepages_range(struct compact_control *cc, unsigned long start_pfn,
							unsigned long end_pfn)
{
	unsigned long pfn, block_start_pfn, block_end_pfn;

	/* Scan block by block. First and last block may be incomplete
	 * 一块一块的扫描.第一块或者最后一块可能不完整
	 */

	/* 拿到起始的pfn,拿到该起始pfn所在块的起始pfn */
	pfn = start_pfn;
	block_start_pfn = pageblock_start_pfn(pfn);
	/* 如果起始块pfn < zone的起始pfn
	 * 那么把zone的起始块pfn赋值给block_start_pfn
	 */
	if (block_start_pfn < cc->zone->zone_start_pfn)
		block_start_pfn = cc->zone->zone_start_pfn;
	/* 拿到页面块的结束pfn */
	block_end_pfn = pageblock_end_pfn(pfn);

	/* 一块一块去检查并做isolate_migratepages_block的操作 */
	for (; pfn < end_pfn; pfn = block_end_pfn,
				block_start_pfn = block_end_pfn,
				block_end_pfn += pageblock_nr_pages) {

		block_end_pfn = min(block_end_pfn, end_pfn);

		if (!pageblock_pfn_to_page(block_start_pfn,
					block_end_pfn, cc->zone))
			continue;

		pfn = isolate_migratepages_block(cc, pfn, block_end_pfn,
							ISOLATE_UNEVICTABLE);

		if (!pfn)
			break;

		if (cc->nr_migratepages == COMPACT_CLUSTER_MAX)
			break;
	}

	return pfn;
}

#endif /* CONFIG_COMPACTION || CONFIG_CMA */
#ifdef CONFIG_COMPACTION

/* Returns true if the page is within a block suitable for migration to
 * 如果页面位于适合迁移到的块内,则返回true
 */
static bool suitable_migration_target(struct compact_control *cc,
							struct page *page)
{
	/*
	 * ignore_block_suitable
	 * 若为true,空闲页扫描器将不会对空闲页pageblock的迁移类型进行判断;
	 * 若为false,代表扫描出来的空闲页必须是MIGRATE_MOVEABLE或MIGRATE_CMA可移动迁移类型
	 */

	/* 如果它的ignore_block_suitable被置上了,那么表示空闲页扫描器将不会对空闲页pageblock的迁移类型进行判断
	 * 那么直接返回true
	 */
	if (cc->ignore_block_suitable)
		return true;

	/* If the page is a large free page, then disallow migration
	 * 如果页面是一个大的空闲页面，则禁止迁移
	 */
	if (PageBuddy(page)) {
		/*
		 * We are checking page_order without zone->lock taken. But
		 * the only small danger is that we skip a potentially suitable
		 * pageblock, so it's not worth to check order for valid range.
		 *
		 * 我们正在没有zone->lock的情况下检查page_order.
		 * 但唯一的小危险是我们跳过了一个可能合适的页面块,所以不值得对于一个有效range检查order
		 */
		if (page_order_unsafe(page) >= pageblock_order)
			return false;
	}

	/* If the block is MIGRATE_MOVABLE or MIGRATE_CMA, allow migration
	 * 如果块是MIGRATE_MOVABLE或MIGRATE_CMA,则允许迁移
	 */
	if (migrate_async_suitable(get_pageblock_migratetype(page)))
		return true;

	/* Otherwise skip the block */
	return false;
}

/*
 * Test whether the free scanner has reached the same or lower pageblock than
 * the migration scanner, and compaction should thus terminate.
 */
static inline bool compact_scanners_met(struct compact_control *cc)
{
	return (cc->free_pfn >> pageblock_order)
		<= (cc->migrate_pfn >> pageblock_order);
}

/*
 * Based on information in the current compact_control, find blocks
 * suitable for isolating free pages from and then isolate them.
 *
 * 根据当前compact_control中的信息,找到适合隔离空闲页面的块,然后将其隔离。
 */
static void isolate_freepages(struct compact_control *cc)
{
	struct zone *zone = cc->zone;
	struct page *page;
	unsigned long block_start_pfn;	/* start of current pageblock */
	unsigned long isolate_start_pfn; /* exact pfn we start at */
	unsigned long block_end_pfn;	/* end of current pageblock */
	unsigned long low_pfn;	     /* lowest pfn scanner is able to scan */
	struct list_head *freelist = &cc->freepages;

	/*
	 * Initialise the free scanner. The starting point is where we last
	 * successfully isolated from, zone-cached value, or the end of the
	 * zone when isolating for the first time. For looping we also need
	 * this pfn aligned down to the pageblock boundary, because we do
	 * block_start_pfn -= pageblock_nr_pages in the for loop.
	 * For ending point, take care when isolating in last pageblock of a
	 * a zone which ends in the middle of a pageblock.
	 * The low boundary is the end of the pageblock the migration scanner
	 * is using.
	 *
	 * 初始化free扫描仪.起点是我们最后一次成功隔离的位置,zone-cached value,或者第一次隔离时zone的结束.
	 * 对于循环,我们还需要将这个pfn向下对齐到页面块边界,因为我们在for循环中执行block_start_pfn-=pageblock_nr_pages.
	 * 对于结束点,要小心当隔离zone的最后一个块在一个pageblock的中间结束.
	 * 低边界是迁移扫描程序正在使用的页面块的末尾.
	 */

	/* 从尾部开始扫描的空闲起始页帧号,即本次扫描zone,从尾部开始扫描寻找空闲页的起始位置 */
	isolate_start_pfn = cc->free_pfn;
	/* #define block_start_pfn(pfn, order)	round_down(pfn, 1UL << (order))
	 * 拿到该block的起始页帧 */
	block_start_pfn = pageblock_start_pfn(cc->free_pfn);
	/* 结束帧就是block_start_pfn + pageblock_nr_pages和zone_end_pfn的最小值 */
	block_end_pfn = min(block_start_pfn + pageblock_nr_pages,
						zone_end_pfn(zone));
	/* low_pfn表示的是cc->migrate_pfn的pageblock对齐的页帧 */
	low_pfn = pageblock_end_pfn(cc->migrate_pfn);

	/*
	 * Isolate free pages until enough are available to migrate the
	 * pages on cc->migratepages. We stop searching if the migrate
	 * and free page scanners meet or enough free pages are isolated.
	 *
	 * 隔离free页面直到有足够的可用于迁移cc->migratepage上的页面.
	 * 如果migrate和free页面扫描程序相遇,或者隔离了足够多的free页面,我们将停止搜索
	 */
	for (; block_start_pfn >= low_pfn;
				block_end_pfn = block_start_pfn,
				block_start_pfn -= pageblock_nr_pages,
				isolate_start_pfn = block_start_pfn) {
		/*
		 * This can iterate a massively long zone without finding any
		 * suitable migration targets, so periodically check if we need
		 * to schedule, or even abort async compaction.
		 *
		 * 这可以在没有找到任何合适的迁移目标的情况下迭代一个非常长的区域,
		 * 因此定期检查是否需要调度,甚至中止异步压缩。
		 */

		/* !(block_start_pfn % (SWAP_CLUSTER_MAX(#define SWAP_CLUSTER_MAX 32UL) * pageblock_nr_pages)
		 * 如果为0表示我scan到了32个pageblock块
		 * compact_should_abort用于判断compact是不是要终止
		 *
		 * 所以这里指的是如果我scan到了32个pageblock块处并且规整需要终止,那么退出
		 */
		if (!(block_start_pfn % (SWAP_CLUSTER_MAX * pageblock_nr_pages))
						&& compact_should_abort(cc))
			break;

		/* 获取第一个页框，需要检查是否属于此zone */
		page = pageblock_pfn_to_page(block_start_pfn, block_end_pfn,
									zone);
		if (!page)
			continue;

		/* Check the block is suitable for migration
		 * 检查块是否适合迁移
		 */

		/* 如果这个块不适合迁移,那么跳过 */
		if (!suitable_migration_target(cc, page))
			continue;

		/* If isolation recently failed, do not retry
		 * 如果设置了ignore_skip_hint,那么就不用理PB_migrate_skip了
		 * 否则获取页框的PB_migrate_skip标志，如果设置了则跳过这个pageblock
		 */
		if (!isolation_suitable(cc, page))
			continue;

		/* Found a block suitable for isolating free pages from. */
		/* 去扫描和分离pageblock中的页面是否适合迁移 */
		isolate_freepages_block(cc, &isolate_start_pfn, block_end_pfn,
					freelist, false);

		/*
		 * If we isolated enough freepages, or aborted due to lock
		 * contention, terminate.
		 *
		 * 如果我们隔离了足够多的空闲页面,或者由于锁争用而中止,则终止。
		 */

		/* 如果cc->nr_freepages >= cc->nr_migratepages说明我们隔离出来的nr_freepages已经满足nr_migratepages了
		 * 如果cc是锁争用了
		 */
		if ((cc->nr_freepages >= cc->nr_migratepages)
							|| cc->contended) {
			/* 如果isolate_start_pfn大于等于block_end_pfn,说明这块已经扫描完了 */
			if (isolate_start_pfn >= block_end_pfn) {
				/*
				 * Restart at previous pageblock if more
				 * freepages can be isolated next time.
				 *
				 * 如果下次可以隔离更多的空闲页面,请在上一个页面块重新启动。
				 */
				isolate_start_pfn =
					block_start_pfn - pageblock_nr_pages;
			}
			break; /* 如果小于,说明没有扫描完,那么中间出现了错误 */
		} else if (isolate_start_pfn < block_end_pfn) {
			/*
			 * If isolation failed early, do not continue
			 * needlessly.
			 *
			 * 如果隔离早期失败,不要不必要地继续.
			 */
			break;
		}
	}

	/* __isolate_free_page() does not map the pages
	 * __isolate_free_page()不映射页面
	 */

	/* 实际上这里就是把high-order的页面切割成单个单个的页面 */
	map_pages(freelist);

	/*
	 * Record where the free scanner will restart next time. Either we
	 * broke from the loop and set isolate_start_pfn based on the last
	 * call to isolate_freepages_block(), or we met the migration scanner
	 * and the loop terminated due to isolate_start_pfn < low_pfn
	 *
	 * 记录free scanner下次重新启动的位置.
	 * 要么我们中断了循环,并根据对isolate_freepages_block()的最后一次调用设置了isolate_start_pfn,
	 * 要么我们遇到了迁移扫描程序,由于isolate_start_pfn < low_pfn,循环终止
	 */
	cc->free_pfn = isolate_start_pfn;
}

/*
 * This is a migrate-callback that "allocates" freepages by taking pages
 * from the isolated freelists in the block we are migrating to.
 *
 * 这是一个迁移回调,通过从我们要迁移到的块中的隔离出来的freelists获取页面来“分配”freepages.
 */
static struct page *compaction_alloc(struct page *migratepage,
					unsigned long data,
					int **result)
{
	struct compact_control *cc = (struct compact_control *)data;
	struct page *freepage;

	/*
	 * Isolate free pages if necessary, and if we are not aborting due to
	 * contention.
	 *
	 * 如有必要,如果我们没有因争用而中止,隔离free pages
	 */

	/* 如果cc->freepages是空的 */
	if (list_empty(&cc->freepages)) {
		/* 如果compaction没有竞态,那么开始隔离freepages了 */
		if (!cc->contended)
			isolate_freepages(cc);
		/* 如果我们的freepages是空的,那么返回NULL */
		if (list_empty(&cc->freepages))
			return NULL;
	}

	/* 拿到第一个freepage */
	freepage = list_entry(cc->freepages.next, struct page, lru);
	/* 把它从这个链表里面删除 */
	list_del(&freepage->lru);
	/* 然后nr_freepages-- */
	cc->nr_freepages--;

	/* 返回这个页面 */
	return freepage;
}

/*
 * This is a migrate-callback that "frees" freepages back to the isolated
 * freelist.  All pages on the freelist are from the same zone, so there is no
 * special handling needed for NUMA.
 */
static void compaction_free(struct page *page, unsigned long data)
{
	struct compact_control *cc = (struct compact_control *)data;

	list_add(&page->lru, &cc->freepages);
	cc->nr_freepages++;
}

/* possible outcome of isolate_migratepages */
typedef enum {
	ISOLATE_ABORT,		/* Abort compaction now */
	ISOLATE_NONE,		/* No pages isolated, continue scanning */
	ISOLATE_SUCCESS,	/* Pages isolated, migrate */
} isolate_migrate_t;

/*
 * Allow userspace to control policy on scanning the unevictable LRU for
 * compactable pages.
 */
int sysctl_compact_unevictable_allowed __read_mostly = 1;

/*
 * Isolate all pages that can be migrated from the first suitable block,
 * starting at the block pointed to by the migrate scanner pfn within
 * compact_control.
 */

/* isolate_migratepages函数用于扫描和查找合适迁移的页,从zone的头部开始.
 * 查找的步长以pageblock_nr_pages为单位.
 * Linux内核以pageblock为单位来管理页的迁移属性.
 */
static isolate_migrate_t isolate_migratepages(struct zone *zone,
					struct compact_control *cc)
{
	unsigned long block_start_pfn;
	unsigned long block_end_pfn;
	unsigned long low_pfn;
	struct page *page;
	/* compact_unevictable_allowed
	 * 仅在设置了CONFIG_COMPACTION 时可用.
	 * 当设置为1时,允许规整检查不可回收的lru(锁定页面)以查找要规整的页面.
	 * 这应该在系统中使用,因为较小的页面错误的停顿对于大的连续空闲内存是可接受的交易.
	 * 设置为0以防止规整移动不可回收的页面,默认值为1.
	 * CONFIG_PREEMPT_RT上,默认值为0,以避免由于规整导致的页面错误,这将阻止任务变为活动状态,直到错误解决
	 */

	/* 确定分离类型 */
	const isolate_mode_t isolate_mode =
		(sysctl_compact_unevictable_allowed ? ISOLATE_UNEVICTABLE : 0) |
		(cc->mode != MIGRATE_SYNC ? ISOLATE_ASYNC_MIGRATE : 0);

	/*
	 * Start at where we last stopped, or beginning of the zone as
	 * initialized by compact_zone()
	 *
	 * 从上次停止的位置开始,或者因为compact_zone的初始化从zone的起始位置开始
	 */

	/* 将low_pfn设置为cc->migrate_pfn(表示从上次停止的位置开始) */
	low_pfn = cc->migrate_pfn;
	/* 得到你这个low_pfn的起始块 */
	block_start_pfn = pageblock_start_pfn(low_pfn);
	/* 如果起始block_start_pfn要小于zone->zone_start_pfn
	 * 那么赋值为起始块以保证在这个zone的区域里面
	 */
	if (block_start_pfn < zone->zone_start_pfn)
		block_start_pfn = zone->zone_start_pfn;

	/* Only scan within a pageblock boundary
	 * 仅在页面块边界内扫描
	 */
	/* 获得这个pageblock的结束pfn */
	block_end_pfn = pageblock_end_pfn(low_pfn);

	/*
	 * Iterate over whole pageblocks until we find the first suitable.
	 * Do not cross the free scanner.
	 *
	 * 在整个页面块上迭代,直到找到第一个合适的页面块.
	 * 不要超过free scanner
	 */

	/* 从zone的头部cc->migrate_pfn开始以pageblock_nr_pages为单位向zone尾部扫描
	 * 但是不能超过free->pfn
	 */
	for (; block_end_pfn <= cc->free_pfn;
			low_pfn = block_end_pfn,
			block_start_pfn = block_end_pfn,
			block_end_pfn += pageblock_nr_pages) {

		/*
		 * This can potentially iterate a massively long zone with
		 * many pageblocks unsuitable, so periodically check if we
		 * need to schedule, or even abort async compaction.
		 *
		 * 这可能会迭代一个非常长并且其中有许多页面块不合适的区域,所以定期检查是否需要调度,甚至中止异步规整
		 */

		/* !(low_pfn % (SWAP_CLUSTER_MAX(#define SWAP_CLUSTER_MAX 32UL) * pageblock_nr_pages)
		 * 如果为0表示我scan到了32个pageblock块
		 * compact_should_abort用于判断compact是不是要终止
		 *
		 * 所以这里指的是如果我scan到了32个pageblock块处并且规整需要终止,那么退出
		 */
		if (!(low_pfn % (SWAP_CLUSTER_MAX * pageblock_nr_pages))
						&& compact_should_abort(cc))
			break;

		/* 获取第一个页框，需要检查是否属于此zone */
		page = pageblock_pfn_to_page(block_start_pfn, block_end_pfn,
									zone);
		if (!page)
			continue;

		/* If isolation recently failed, do not retry */

		/*
		 * 如果设置了ignore_skip_hint,那么就不用理PB_migrate_skip了
		 * 否则获取页框的PB_migrate_skip标志，如果设置了则跳过这个pageblock
		 */
		if (!isolation_suitable(cc, page))
			continue;

		/*
		 * For async compaction, also only scan in MOVABLE blocks.
		 * Async compaction is optimistic to see if the minimum amount
		 * of work satisfies the allocation.
		 *
		 * 对于异步压缩,也只扫描MOVABLE块.
		 * 异步压缩是乐观地去查看最小工作量是否满足分配。
		 */

		/* 异步情况,如果不是MIGRATE_MOVABLE或MIGRATE_CMA类型则跳过这段页框块 */
		/* 异步不处理RECLAIMABLE的页 */
		if (cc->mode == MIGRATE_ASYNC &&
		    !migrate_async_suitable(get_pageblock_migratetype(page)))
			continue;

		/* Perform the isolation */

		/* 执行完隔离,将low_pfn到end_pfn中正在使用的页框从zone->lru中取出来,返回的是可移动页扫描扫描到的页框号
		 * 而UNMOVABLE类型的页框是不会处于lru链表中的,所以所有不在lru链表中的页都会被跳过
		 * 返回的是扫描到的最后的页
		 */
		low_pfn = isolate_migratepages_block(cc, low_pfn,
						block_end_pfn, isolate_mode);

		/* 如果low_pfn为NULL 或者cc->contended是true,也就是竞争,那么就返回abort */
		if (!low_pfn || cc->contended)
			return ISOLATE_ABORT;

		/*
		 * Either we isolated something and proceed with migration. Or
		 * we failed and compact_zone should decide if we should
		 * continue or not.
		 *
		 * 要么我们隔离了一些东西,然后继续迁移.
		 * 或者我们失败了,compact_zone应该决定我们是否应该继续。
		 */
		break;
	}

	/* Record where migration scanner will be restarted.
	 * 记录迁移扫描程序将重新启动的位置
	 */
	/* 记录一下下一次迁移我们应该从哪里开始 */
	cc->migrate_pfn = low_pfn;

	/* 如果有nr_migratepages,表明我们有这么多页面可用于迁移,那么就返回ISOLATE_SUCCESS,否则就返回ISOLATE_NONE */
	return cc->nr_migratepages ? ISOLATE_SUCCESS : ISOLATE_NONE;
}

/*
 * order == -1 is expected when compacting via
 * /proc/sys/vm/compact_memory
 *
 * 通过/proc/sys/vm/compact_memory进行压缩时,需要order==-1
 */
static inline bool is_via_compact_memory(int order)
{
	return order == -1;
}

/* 结束的条件有两个,一是cc->migrate_pfn和cc->free_pfn两个指针相遇,它们从
 * zone的一头一尾向中间运行.
 * 二是以order为条件判断当前zone的水位在低水位WMARK_LOW之上.
 * 如果当前zone在低水位WMARK_LOW之上,那么需要判断伙伴系统中order对应的free_area链表正好有空闲页面,
 * 或者大于order的空闲链表里有空闲页面,再或者大于pageblock_order的空闲链表有空闲页面.
 */
static enum compact_result __compact_finished(struct zone *zone, struct compact_control *cc,
			    const int migratetype)
{
	unsigned int order;
	unsigned long watermark;

	/* cc->contended表示被锁争用
	 * 如果被锁争用了或者说收到了一个致命的信号
	 * 那么返回COMPACT_CONTENDED
	 */
	if (cc->contended || fatal_signal_pending(current))
		return COMPACT_CONTENDED;

	/* Compaction run completes if the migrate and free scanner meet
	 * 如果migrate和free扫描者相遇了,那么规整运行完成了
	 */
	if (compact_scanners_met(cc)) {
		/* Let the next compaction start anew. */
		/* 如果这次规整完成了,那么重置zone里面的compact_cached_migrate_pfn和compact_cached_free_pfn */
		reset_cached_positions(zone);

		/*
		 * Mark that the PG_migrate_skip information should be cleared
		 * by kswapd when it goes to sleep. kcompactd does not set the
		 * flag itself as the decision to be clear should be directly
		 * based on an allocation request.
		 *
		 * 标记PG_migrate_skip信息应在kswapd进入睡眠状态时由其清除。
		 * kcompactd本身不设置标志,因为要清除的决定应该直接基于分配请求.
		 */
		if (cc->direct_compaction)
			zone->compact_blockskip_flush = true;

		/* 如果是整个zone就返回COMPACT_COMPLETE */
		if (cc->whole_zone)
			return COMPACT_COMPLETE;
		else	/* 否则返回COMPACT_PARTIAL_SKIPPED */
			return COMPACT_PARTIAL_SKIPPED;
	}

	/* 如果通过/proc/sys/vm/compact_memory进行压缩,那么返回COMPACT_CONTINUE */
	if (is_via_compact_memory(cc->order))
		return COMPACT_CONTINUE;

	/* Compaction run is not finished if the watermark is not met
	 * 如果水位还是不足,那么规整的运行还没完成
	 */
	watermark = zone->watermark[cc->alloc_flags & ALLOC_WMARK_MASK];

	if (!zone_watermark_ok(zone, cc->order, watermark, cc->classzone_idx,
							cc->alloc_flags))
		return COMPACT_CONTINUE;


	/* Direct compactor: Is a suitable page free?
	 * 直接规整: 有一个合适的页面空闲吗
	 */

	/* 这里就是从我们需要分配的order到MAX_ORDER去检查有没有一个可以满足我们分配的空闲页面 */
	for (order = cc->order; order < MAX_ORDER; order++) {
		/* 得到free_area */
		struct free_area *area = &zone->free_area[order];
		bool can_steal;

		/* Job done if page is free of the right migratetype
		 * 如果有正确的migratetype空闲,则完成作业
		 */
		if (!list_empty(&area->free_list[migratetype]))
			return COMPACT_SUCCESS;

#ifdef CONFIG_CMA
		/* 因为MIGRATE_CMA是MIGRATE_MOVABLE的fallback
		 * 所以如果MIGRATE_CMA里面有空闲的可以满足要求,那么也返回成功
		 */
		/* MIGRATE_MOVABLE can fallback on MIGRATE_CMA */
		if (migratetype == MIGRATE_MOVABLE &&
			!list_empty(&area->free_list[MIGRATE_CMA]))
			return COMPACT_SUCCESS;
#endif
		/*
		 * Job done if allocation would steal freepages from
		 * other migratetype buddy lists.
		 *
		 * 如果分配能从其他migrateype伙伴列表中窃取空闲页面,那么工作就完成了.
		 */
		if (find_suitable_fallback(area, order, migratetype,
						true, &can_steal) != -1)
			return COMPACT_SUCCESS;
	}

	return COMPACT_NO_SUITABLE_PAGE;
}

static enum compact_result compact_finished(struct zone *zone,
			struct compact_control *cc,
			const int migratetype)
{
	int ret;

	ret = __compact_finished(zone, cc, migratetype);
	trace_mm_compaction_finished(zone, cc->order, ret);
	/* 如果ret = COMPACT_NO_SUITABLE_PAGE,那么返回COMPACT_CONTINUE */
	if (ret == COMPACT_NO_SUITABLE_PAGE)
		ret = COMPACT_CONTINUE;

	return ret;
}

/*
 * compaction_suitable: Is this suitable to run compaction on this zone now?
 * Returns
 *   COMPACT_SKIPPED  - If there are too few free pages for compaction
 *   COMPACT_SUCCESS  - If the allocation would succeed without compaction
 *   COMPACT_CONTINUE - If compaction should run now
 *
 * compaction_suitable: 现在整个zone适合运行内存规整吗?
 * 返回
 *	COMPACT_SKIPPED - 如果可规整的free pages页面太少
 *	COMPACT_SUCCESS - 如果在没有规整的情况下分配可以成功
 *	COMPACT_CONTINUE - 如果规整现在可以运行
 */
static enum compact_result __compaction_suitable(struct zone *zone, int order,
					unsigned int alloc_flags,
					int classzone_idx,
					unsigned long wmark_target)
{
	unsigned long watermark;

	/* 如果是通过/proc/sys/vm/compact_memory,那么直接返回COMPACT_CONTINUE */
	if (is_via_compact_memory(order))
		return COMPACT_CONTINUE;

	/* 拿到zone对应我们alloc_flags的水位 */
	watermark = zone->watermark[alloc_flags & ALLOC_WMARK_MASK];
	/*
	 * If watermarks for high-order allocation are already met, there
	 * should be no need for compaction at all.
	 *
	 * 如果high-order 分配的水位已经满足,则根本不需要压缩.
	 */
	if (zone_watermark_ok(zone, order, watermark, classzone_idx,
								alloc_flags))
		return COMPACT_SUCCESS;

	/*
	 * Watermarks for order-0 must be met for compaction to be able to
	 * isolate free pages for migration targets. This means that the
	 * watermark and alloc_flags have to match, or be more pessimistic than
	 * the check in __isolate_free_page(). We don't use the direct
	 * compactor's alloc_flags, as they are not relevant for freepage
	 * isolation. We however do use the direct compactor's classzone_idx to
	 * skip over zones where lowmem reserves would prevent allocation even
	 * if compaction succeeds.
	 * For costly orders, we require low watermark instead of min for
	 * compaction to proceed to increase its chances.
	 * ALLOC_CMA is used, as pages in CMA pageblocks are considered
	 * suitable migration targets
	 *
	 * 为了能够隔离迁移目标的free pages页面,必须满足order-0 的水位才能进行规整.
	 * 这意味着水位和alloc_flags必须匹配,或者比__isolate_free_page()中的检查更悲观.
	 * 我们不使用直接规整程序的alloc_flags,因为它们与freepage页面隔离无关.
	 * 然而,我们确实使用直接规整的classzone_idx来跳过lowmem reserves会阻止分配的zone,即使规整成功
	 * 对于高昂的orders,我们需要低水位而不是min 水位来进行规整,以增加其机会.
	 * 使用ALLOC_CMA,因为CMA页面块中的页面被认为是合适的迁移目标
	 */
	/* 如果order > PAGE_ALLOC_COSTLY_ORDER,则用low水位来进行确认水位是否安全 */
	watermark = (order > PAGE_ALLOC_COSTLY_ORDER) ?
				low_wmark_pages(zone) : min_wmark_pages(zone);
	/* 接下来以oder为0来判断zone是否在上诉水位 + 2 << order之上,如果达不到这个条件,说明zone中只有很少的空闲页面,不适合做内存规整,返回COMPACT_SKIPPED表示跳过这个zone */
	watermark += compact_gap(order);
	if (!__zone_watermark_ok(zone, 0, watermark, classzone_idx,
						ALLOC_CMA, wmark_target))
		return COMPACT_SKIPPED;

	return COMPACT_CONTINUE;
}

enum compact_result compaction_suitable(struct zone *zone, int order,
					unsigned int alloc_flags,
					int classzone_idx)
{
	enum compact_result ret;
	int fragindex;
	/* 判断它适不适合做规整 */
	ret = __compaction_suitable(zone, order, alloc_flags, classzone_idx,
				    zone_page_state(zone, NR_FREE_PAGES));
	/*
	 * fragmentation index determines if allocation failures are due to
	 * low memory or external fragmentation
	 *
	 * index of -1000 would imply allocations might succeed depending on
	 * watermarks, but we already failed the high-order watermark check
	 * index towards 0 implies failure is due to lack of memory
	 * index towards 1000 implies failure is due to fragmentation
	 *
	 * Only compact if a failure would be due to fragmentation. Also
	 * ignore fragindex for non-costly orders where the alternative to
	 * a successful reclaim/compaction is OOM. Fragindex and the
	 * vm.extfrag_threshold sysctl is meant as a heuristic to prevent
	 * excessive compaction for costly orders, but it should not be at the
	 * expense of system stability.
	 *
	 * 碎片索引确定分配失败是由于内存不足,还是外部碎片索引
	 *
	 * index为-1000意味着分配可能会成功取决于水位，但我们已经失败了高阶水印检查.
	 * index接近0意味着失败是由于缺乏内存
	 * index接近1000意味着失败由于碎片
	 *
	 * 只有当failure是由于碎片造成时才进行规整.对于不是昂贵的orders替代成功回收和规整的是OOM.
	 * Fragindex和vm.extfrag_threshold sysctl旨在作为一种启发式方法,防止对昂贵的order进行过度压缩,但不应以牺牲系统稳定性为代价.
	 */
	if (ret == COMPACT_CONTINUE && (order > PAGE_ALLOC_COSTLY_ORDER)) {
	/* 通过fragmentation_index函数获取当前zone对于order阶内存块碎片程度评估,如果认为碎片程度不高则不进行规整 */
		fragindex = fragmentation_index(zone, order);
		/* fragmentation_index返回值需要和sysctl_extfrag_threshold阈值进行比较，如果小于阈值，则不进行规整，此值通过/proc/sys/vm/extfrag_threshold进行设置. */
		if (fragindex >= 0 && fragindex <= sysctl_extfrag_threshold)
			ret = COMPACT_NOT_SUITABLE_ZONE;
	}

	trace_mm_compaction_suitable(zone, order, ret);
	if (ret == COMPACT_NOT_SUITABLE_ZONE)
		ret = COMPACT_SKIPPED;

	return ret;
}

bool compaction_zonelist_suitable(struct alloc_context *ac, int order,
		int alloc_flags)
{
	struct zone *zone;
	struct zoneref *z;

	/*
	 * Make sure at least one zone would pass __compaction_suitable if we continue
	 * retrying the reclaim.
	 */
	for_each_zone_zonelist_nodemask(zone, z, ac->zonelist, ac->high_zoneidx,
					ac->nodemask) {
		unsigned long available;
		enum compact_result compact_result;

		/*
		 * Do not consider all the reclaimable memory because we do not
		 * want to trash just for a single high order allocation which
		 * is even not guaranteed to appear even if __compaction_suitable
		 * is happy about the watermark check.
		 */
		available = zone_reclaimable_pages(zone) / order;
		available += zone_page_state_snapshot(zone, NR_FREE_PAGES);
		compact_result = __compaction_suitable(zone, order, alloc_flags,
				ac_classzone_idx(ac), available);
		if (compact_result != COMPACT_SKIPPED)
			return true;
	}

	return false;
}

static enum compact_result compact_zone(struct zone *zone, struct compact_control *cc)
{
	enum compact_result ret;
	/* 拿到该zone的起始pfn */
	unsigned long start_pfn = zone->zone_start_pfn;
	/* 拿到该zone的结束pfn */
	unsigned long end_pfn = zone_end_pfn(zone);
	/* 拿到gfp_mask的migratetype部分 */
	const int migratetype = gfpflags_to_migratetype(cc->gfp_mask);
	/* sync表示是同步还是异步 */
	const bool sync = cc->mode != MIGRATE_ASYNC;

	/* 根据当前的zone水位来判断是否进行内存规整 */
	ret = compaction_suitable(zone, cc->order, cc->alloc_flags,
							cc->classzone_idx);
	/* Compaction is likely to fail */
	/* 如果说ret == COMPACT_SUCCESS,说明可以不用规整就可以分配到order的内存了
	 * 如果ret == COMPACT_SKIPPED,说明可规整的页面太少
	 * 这两种情况都直接返回算了
	 */
	if (ret == COMPACT_SUCCESS || ret == COMPACT_SKIPPED)
		return ret;

	/* huh, compaction_suitable is returning something unexpected
	 * compaction_suitable返回了一些意想不到的东西
	 */
	VM_BUG_ON(ret != COMPACT_CONTINUE);

	/*
	 * Clear pageblock skip if there were failures recently and compaction
	 * is about to be retried after being deferred.
	 *
	 * 如果最近有失败清除pageblock skip,在延迟后即将重试规整
	 */
	if (compaction_restarting(zone, cc->order))
		__reset_isolation_suitable(zone);

	/*
	 * Setup to move all movable pages to the end of the zone. Used cached
	 * information on where the scanners should start (unless we explicitly
	 * want to compact the whole zone), but check that it is initialised
	 * by ensuring the values are within zone boundaries.
	 *
	 * 设置将所有可移动页面移动到区域的末尾.使用了关于scanner应该从哪里开始的缓存信息(除非我们明确希望规整整个区域),但通过确保值在zone边界内来检查它是否已初始化
	 */

	/* 如果是整个zone */
	if (cc->whole_zone) {
		/* 那么迁移起始pfh就是该zone的startr_pfn */
		cc->migrate_pfn = start_pfn;
		/* free_pfn就是最后一块pageblock的起始pfn */
		cc->free_pfn = pageblock_start_pfn(end_pfn - 1);
	} else {
		/* 如果不是,那么起始迁移帧就是zone里面缓存的migrate pfn,就看是同步还是异步了 */
		cc->migrate_pfn = zone->compact_cached_migrate_pfn[sync];
		/* free_pfn就是zone里面缓存的free_pfn */
		cc->free_pfn = zone->compact_cached_free_pfn;
		/* 如果free_pfn比start还要小 或者说比end_pfn还要大,说明没有在这个zone的区域里面 */
		if (cc->free_pfn < start_pfn || cc->free_pfn >= end_pfn) {
			/* 那么还是把free_pfn设置为该zone的最后一个pageblock的pfn */
			cc->free_pfn = pageblock_start_pfn(end_pfn - 1);
			/* 然后把compact_cache_free_pfn给替换掉 */
			zone->compact_cached_free_pfn = cc->free_pfn;
		}
		/* 如果cc->migrate_pfn比start_pfn要小,大于等于end_pfn,也说明migrate_pfn也没有落在这个zone里面 */
		if (cc->migrate_pfn < start_pfn || cc->migrate_pfn >= end_pfn) {
			/* 把它重新赋值为start_pfn之后,更新compact_cached_migrate_pfn */
			cc->migrate_pfn = start_pfn;
			zone->compact_cached_migrate_pfn[0] = cc->migrate_pfn;
			zone->compact_cached_migrate_pfn[1] = cc->migrate_pfn;
		}
		/* 如果cc->migrate_pfn为起始,那么这是为whole_zone */
		if (cc->migrate_pfn == start_pfn)
			cc->whole_zone = true;
	}

	/* 设置last_migrate_pfn为0 */
	cc->last_migrated_pfn = 0;

	trace_mm_compaction_begin(start_pfn, cc->migrate_pfn,
				cc->free_pfn, end_pfn, sync);

	/* 清理cpu的pagevec的页面,后续我要占用 */
	migrate_prep_local();

	/* while循坏从zone的开头处去扫描和查找合适的迁移页面,然后尝试迁移到
	 * zone末端的空闲页面中,直到zone处于低水位WMARK_LOW之上
	 */
	/* compact_finished 判断compact过程是否可以结束 */
	while ((ret = compact_finished(zone, cc, migratetype)) ==
						COMPACT_CONTINUE) {
		int err;

		/* isolate_migratepages函数用于扫描和查找合适迁移的页,从zone的头部开始找起.
		 * 查找的步长以pageblock_nr_pages为单位.
		 * Linux内核以pageblock为单位来管理页的迁移属性.
		 * 页的迁移属性包括MIGRATE_UNMOVABLE、MIGRATE_RECLAIMABLE、MIGRATE_MOVABLE、MIGRATE_PCPTYPES和MIGRATE_CMA等.
		 */
		switch (isolate_migratepages(zone, cc)) {
		/* 如果返回的是ABORT,那么把migratepages给移动回去,设置 cc->nr_migratepages = 0
		 * 设置ret为COMPACT_CONTENDED
		 * goto out
		 */
		case ISOLATE_ABORT:
			ret = COMPACT_CONTENDED;
			putback_movable_pages(&cc->migratepages);
			cc->nr_migratepages = 0;
			goto out;
		/* 如果返回的是ISOLATE_NONE,那说明我们在本次迁移中未隔离出任何page,
		 * goto check_drain
		 */
		case ISOLATE_NONE:
			/*
			 * We haven't isolated and migrated anything, but
			 * there might still be unflushed migrations from
			 * previous cc->order aligned block.
			 *
			 * 我们还没有隔离和迁移任何东西,但可能仍然有来自以前的cc->order对齐块的未刷新迁移.
			 */
			goto check_drain;
		case ISOLATE_SUCCESS:
			;
		}
		/* migrate_pages是页面迁移的核心函数 */
		err = migrate_pages(&cc->migratepages, compaction_alloc,
				compaction_free, (unsigned long)cc, cc->mode,
				MR_COMPACTION);

		trace_mm_compaction_migratepages(cc->nr_migratepages, err,
							&cc->migratepages);

		/* All pages were either migrated or will be released
		 * 所有页面要么已迁移,要么将被释放
		 */
		/* 设置cc->nr_migratepages为0 */
		cc->nr_migratepages = 0;
		/* 如果有error */
		if (err) {
			/* 将这些个页面都还回去 */
			putback_movable_pages(&cc->migratepages);
			/*
			 * migrate_pages() may return -ENOMEM when scanners meet
			 * and we want compact_finished() to detect it
			 *
			 * migrate_pages()可能会在scanner相遇时返回-ENOMM,并且我们希望compact_finished()检测到它
			 */
			if (err == -ENOMEM && !compact_scanners_met(cc)) {
				ret = COMPACT_CONTENDED;
				goto out;
			}
			/*
			 * We failed to migrate at least one page in the current
			 * order-aligned block, so skip the rest of it.
			 *
			 * 我们在当前order-aligned块中迁移至少失败了一页,因此跳过其余部分
			 */

			/* 如果cc是直接规整并且mode是异步的 */
			if (cc->direct_compaction &&
						(cc->mode == MIGRATE_ASYNC)) {
				/* #define block_end_pfn(pfn, order)	ALIGN((pfn) + 1, 1UL << (order)) */
				/* 那么cc-migrate_pfn就变成了下一个cc->order对齐的pfn */
				cc->migrate_pfn = block_end_pfn(
						cc->migrate_pfn - 1, cc->order);
				/* Draining pcplists is useless in this case
				 *
				 * 在这种情况下，排空pcplists是无用的
				 */
				cc->last_migrated_pfn = 0;

			}
		}

check_drain:
		/*
		 * Has the migration scanner moved away from the previous
		 * cc->order aligned block where we migrated from? If yes,
		 * flush the pages that were freed, so that they can merge and
		 * compact_finished() can detect immediately if allocation
		 * would succeed.
		 *
		 * 迁移扫描程序是否已从我们迁移的前一个cc->order对齐块移开?
		 * 如果是,则刷新释放的页面,以便它们可以合并,compact_finished可以立即检测是否分配成功
		 */
		 /* 如果cc->order大于0,并且中间没有失败的块 */
		if (cc->order > 0 && cc->last_migrated_pfn) {
			int cpu;
			/* 拿到当前migrate按cc->order开始的起始块号 */
			unsigned long current_block_start =
				block_start_pfn(cc->migrate_pfn, cc->order);

			/* 如果last_migrated_pfn 比 current_block_start 小 */
			if (cc->last_migrated_pfn < current_block_start) {
				cpu = get_cpu();
				lru_add_drain_cpu(cpu);
				drain_local_pages(zone);
				put_cpu();
				/* No more flushing until we migrate again */
				cc->last_migrated_pfn = 0;
			}
		}

	}

out:
	/*
	 * Release free pages and update where the free scanner should restart,
	 * so we don't leave any returned pages behind in the next attempt.
	 *
	 * 释放freepages并更新free scanner应重新启动的位置,
	 * 所以我们在下次尝试时不会留下任何返回的页面。
	 */
	/* 如果cc->nr_freepages大于0,说明freepages里面还有东西 */
	if (cc->nr_freepages > 0) {
		/* 把这些页面给释放掉,这里返回的是这个链表最大的pfn的值 */
		unsigned long free_pfn = release_freepages(&cc->freepages);
		/* 然后设置nr_freepages为0 */
		cc->nr_freepages = 0;
		/* 如果free_pfn等于0,那么就报个BUG吧 */
		VM_BUG_ON(free_pfn == 0);
		/* The cached pfn is always the first in a pageblock
		 * 缓存的pfn总是页面块中的第一个
		 */
		/* block_start_pfn(pfn, pageblock_order) */
		free_pfn = pageblock_start_pfn(free_pfn);
		/*
		 * Only go back, not forward. The cached pfn might have been
		 * already reset to zone end in compact_finished()
		 *
		 * 只后退,不前进. cached的pfn可能已在compact_finished()中重置为区域结束
		 */

		/* 如果free_pfn大于compact_cached_free_pfn,那么设置compact_cached_free_pfn为free_pfn */
		if (free_pfn > zone->compact_cached_free_pfn)
			zone->compact_cached_free_pfn = free_pfn;
	}

	trace_mm_compaction_end(start_pfn, cc->migrate_pfn,
				cc->free_pfn, end_pfn, sync, ret);

	return ret;
}

static enum compact_result compact_zone_order(struct zone *zone, int order,
		gfp_t gfp_mask, enum compact_priority prio,
		unsigned int alloc_flags, int classzone_idx)
{
	enum compact_result ret;
	struct compact_control cc = {
		.nr_freepages = 0,
		.nr_migratepages = 0,
		.order = order,
		.gfp_mask = gfp_mask,
		.zone = zone,
		/* 看是同步模式还是异步模式 */
		.mode = (prio == COMPACT_PRIO_ASYNC) ?
					MIGRATE_ASYNC :	MIGRATE_SYNC_LIGHT,
		.alloc_flags = alloc_flags,
		.classzone_idx = classzone_idx,
		.direct_compaction = true,
		/* 看是不是规整整个zone */
		.whole_zone = (prio == MIN_COMPACT_PRIORITY),
		/* 若为true,代表扫描器在扫描pageblock过程中,不再根据PG_migrate_sip来判断是否跳过处理,这将会借助历史信息避免重复扫描处理过的pageblock块 */
		.ignore_skip_hint = (prio == MIN_COMPACT_PRIORITY),
		/* 若为true,空闲页扫描器将不会对空闲页pageblock的迁移类型进行判断;
		 * 若为false,代表扫描出来的空闲页必须是MIGRATE_MOVEABLE或MIGRATE_CMA可移动迁移类型
		 */
		.ignore_block_suitable = (prio == MIN_COMPACT_PRIORITY)
	};
	INIT_LIST_HEAD(&cc.freepages);
	INIT_LIST_HEAD(&cc.migratepages);

	ret = compact_zone(zone, &cc);

	VM_BUG_ON(!list_empty(&cc.freepages));
	VM_BUG_ON(!list_empty(&cc.migratepages));

	return ret;
}

int sysctl_extfrag_threshold = 500;

/**
 * try_to_compact_pages - Direct compact to satisfy a high-order allocation
 * @gfp_mask: The GFP mask of the current allocation
 * @order: The order of the current allocation
 * @alloc_flags: The allocation flags of the current allocation
 * @ac: The context of current allocation
 * @mode: The migration mode for async, sync light, or sync migration
 *
 * This is the main entry point for direct page compaction.
 *
 * try_to_compact_pages - 直接规整以满足高阶分配
 * @gfp_mask: 当前分配的gfp掩码
 * @order: 当前分配的order
 * @alloc_flags: 当前分配的分配标志
 * @ac: 当前分配的上下文
 * @mode: async、sync light或sync migration的迁移模式
 *
 * 这是直接页面规整的主要入口点
 */
enum compact_result try_to_compact_pages(gfp_t gfp_mask, unsigned int order,
		unsigned int alloc_flags, const struct alloc_context *ac,
		enum compact_priority prio)
{
	int may_enter_fs = gfp_mask & __GFP_FS;
	int may_perform_io = gfp_mask & __GFP_IO;
	struct zoneref *z;
	struct zone *zone;
	enum compact_result rc = COMPACT_SKIPPED;

	/* Check if the GFP flags allow compaction
	 *
	 * 如果gfp_mask没有__GFP_FS,或者没有__GFP_IO,那么返回COMPACT_SKIPPED
	 */
	if (!may_enter_fs || !may_perform_io)
		return COMPACT_SKIPPED;

	trace_mm_compaction_try_to_compact_pages(order, gfp_mask, prio);

	/* Compact each zone in the list */
	/* for_each_zone_zonelist_nodemask 会根据分配掩码来确定需要扫描和遍历哪些zone */
	for_each_zone_zonelist_nodemask(zone, z, ac->zonelist, ac->high_zoneidx,
								ac->nodemask) {
		enum compact_result status;

		/* 如果优先级大于MIN_COMPACT_PRIORITY,并且因为前面的失败规整需要延迟 */
		if (prio > MIN_COMPACT_PRIORITY
					&& compaction_deferred(zone, order)) {
			/* 取rc和COMPACT_DEFERRED的最大值,然后continue,进行下一个zone的处理 */
			rc = max_t(enum compact_result, COMPACT_DEFERRED, rc);
			continue;
		}
		/* 对特定的zone执行内存规整 */
		status = compact_zone_order(zone, order, gfp_mask, prio,
					alloc_flags, ac_classzone_idx(ac));
		rc = max(status, rc);

		/* The allocation should succeed, stop compacting */
		if (status == COMPACT_SUCCESS) {
			/*
			 * We think the allocation will succeed in this zone,
			 * but it is not certain, hence the false. The caller
			 * will repeat this with true if allocation indeed
			 * succeeds in this zone.
			 */
			compaction_defer_reset(zone, order, false);

			break;
		}

		if (prio != COMPACT_PRIO_ASYNC && (status == COMPACT_COMPLETE ||
					status == COMPACT_PARTIAL_SKIPPED))
			/*
			 * We think that allocation won't succeed in this zone
			 * so we defer compaction there. If it ends up
			 * succeeding after all, it will be reset.
			 */
			defer_compaction(zone, order);

		/*
		 * We might have stopped compacting due to need_resched() in
		 * async compaction, or due to a fatal signal detected. In that
		 * case do not try further zones
		 */
		if ((prio == COMPACT_PRIO_ASYNC && need_resched())
					|| fatal_signal_pending(current))
			break;
	}

	return rc;
}


/* Compact all zones within a node */
static void compact_node(int nid)
{
	pg_data_t *pgdat = NODE_DATA(nid);
	int zoneid;
	struct zone *zone;
	struct compact_control cc = {
		.order = -1,
		.mode = MIGRATE_SYNC,
		.ignore_skip_hint = true,
		.whole_zone = true,
	};


	for (zoneid = 0; zoneid < MAX_NR_ZONES; zoneid++) {

		zone = &pgdat->node_zones[zoneid];
		if (!populated_zone(zone))
			continue;

		cc.nr_freepages = 0;
		cc.nr_migratepages = 0;
		cc.zone = zone;
		INIT_LIST_HEAD(&cc.freepages);
		INIT_LIST_HEAD(&cc.migratepages);

		compact_zone(zone, &cc);

		VM_BUG_ON(!list_empty(&cc.freepages));
		VM_BUG_ON(!list_empty(&cc.migratepages));
	}
}

/* Compact all nodes in the system */
static void compact_nodes(void)
{
	int nid;

	/* Flush pending updates to the LRU lists */
	lru_add_drain_all();

	for_each_online_node(nid)
		compact_node(nid);
}

/* The written value is actually unused, all memory is compacted */
int sysctl_compact_memory;

/*
 * This is the entry point for compacting all nodes via
 * /proc/sys/vm/compact_memory
 */
int sysctl_compaction_handler(struct ctl_table *table, int write,
			void __user *buffer, size_t *length, loff_t *ppos)
{
	if (write)
		compact_nodes();

	return 0;
}

int sysctl_extfrag_handler(struct ctl_table *table, int write,
			void __user *buffer, size_t *length, loff_t *ppos)
{
	proc_dointvec_minmax(table, write, buffer, length, ppos);

	return 0;
}

#if defined(CONFIG_SYSFS) && defined(CONFIG_NUMA)
static ssize_t sysfs_compact_node(struct device *dev,
			struct device_attribute *attr,
			const char *buf, size_t count)
{
	int nid = dev->id;

	if (nid >= 0 && nid < nr_node_ids && node_online(nid)) {
		/* Flush pending updates to the LRU lists */
		lru_add_drain_all();

		compact_node(nid);
	}

	return count;
}
static DEVICE_ATTR(compact, S_IWUSR, NULL, sysfs_compact_node);

int compaction_register_node(struct node *node)
{
	return device_create_file(&node->dev, &dev_attr_compact);
}

void compaction_unregister_node(struct node *node)
{
	return device_remove_file(&node->dev, &dev_attr_compact);
}
#endif /* CONFIG_SYSFS && CONFIG_NUMA */

static inline bool kcompactd_work_requested(pg_data_t *pgdat)
{
	return pgdat->kcompactd_max_order > 0 || kthread_should_stop();
}

static bool kcompactd_node_suitable(pg_data_t *pgdat)
{
	int zoneid;
	struct zone *zone;
	enum zone_type classzone_idx = pgdat->kcompactd_classzone_idx;

	for (zoneid = 0; zoneid <= classzone_idx; zoneid++) {
		zone = &pgdat->node_zones[zoneid];

		if (!populated_zone(zone))
			continue;

		if (compaction_suitable(zone, pgdat->kcompactd_max_order, 0,
					classzone_idx) == COMPACT_CONTINUE)
			return true;
	}

	return false;
}

static void kcompactd_do_work(pg_data_t *pgdat)
{
	/*
	 * With no special task, compact all zones so that a page of requested
	 * order is allocatable.
	 */
	int zoneid;
	struct zone *zone;
	struct compact_control cc = {
		.order = pgdat->kcompactd_max_order,
		.classzone_idx = pgdat->kcompactd_classzone_idx,
		.mode = MIGRATE_SYNC_LIGHT,
		.ignore_skip_hint = true,

	};
	trace_mm_compaction_kcompactd_wake(pgdat->node_id, cc.order,
							cc.classzone_idx);
	count_vm_event(KCOMPACTD_WAKE);

	for (zoneid = 0; zoneid <= cc.classzone_idx; zoneid++) {
		int status;

		zone = &pgdat->node_zones[zoneid];
		if (!populated_zone(zone))
			continue;

		if (compaction_deferred(zone, cc.order))
			continue;

		if (compaction_suitable(zone, cc.order, 0, zoneid) !=
							COMPACT_CONTINUE)
			continue;

		cc.nr_freepages = 0;
		cc.nr_migratepages = 0;
		cc.zone = zone;
		INIT_LIST_HEAD(&cc.freepages);
		INIT_LIST_HEAD(&cc.migratepages);

		if (kthread_should_stop())
			return;
		status = compact_zone(zone, &cc);

		if (status == COMPACT_SUCCESS) {
			compaction_defer_reset(zone, cc.order, false);
		} else if (status == COMPACT_PARTIAL_SKIPPED || status == COMPACT_COMPLETE) {
			/*
			 * We use sync migration mode here, so we defer like
			 * sync direct compaction does.
			 */
			defer_compaction(zone, cc.order);
		}

		VM_BUG_ON(!list_empty(&cc.freepages));
		VM_BUG_ON(!list_empty(&cc.migratepages));
	}

	/*
	 * Regardless of success, we are done until woken up next. But remember
	 * the requested order/classzone_idx in case it was higher/tighter than
	 * our current ones
	 */
	if (pgdat->kcompactd_max_order <= cc.order)
		pgdat->kcompactd_max_order = 0;
	if (pgdat->kcompactd_classzone_idx >= cc.classzone_idx)
		pgdat->kcompactd_classzone_idx = pgdat->nr_zones - 1;
}

void wakeup_kcompactd(pg_data_t *pgdat, int order, int classzone_idx)
{
	if (!order)
		return;

	if (pgdat->kcompactd_max_order < order)
		pgdat->kcompactd_max_order = order;

	if (pgdat->kcompactd_classzone_idx > classzone_idx)
		pgdat->kcompactd_classzone_idx = classzone_idx;

	if (!waitqueue_active(&pgdat->kcompactd_wait))
		return;

	if (!kcompactd_node_suitable(pgdat))
		return;

	trace_mm_compaction_wakeup_kcompactd(pgdat->node_id, order,
							classzone_idx);
	wake_up_interruptible(&pgdat->kcompactd_wait);
}

/*
 * The background compaction daemon, started as a kernel thread
 * from the init process.
 */
static int kcompactd(void *p)
{
	pg_data_t *pgdat = (pg_data_t*)p;
	struct task_struct *tsk = current;

	const struct cpumask *cpumask = cpumask_of_node(pgdat->node_id);

	if (!cpumask_empty(cpumask))
		set_cpus_allowed_ptr(tsk, cpumask);

	set_freezable();

	pgdat->kcompactd_max_order = 0;
	pgdat->kcompactd_classzone_idx = pgdat->nr_zones - 1;

	while (!kthread_should_stop()) {
		trace_mm_compaction_kcompactd_sleep(pgdat->node_id);
		wait_event_freezable(pgdat->kcompactd_wait,
				kcompactd_work_requested(pgdat));

		kcompactd_do_work(pgdat);
	}

	return 0;
}

/*
 * This kcompactd start function will be called by init and node-hot-add.
 * On node-hot-add, kcompactd will moved to proper cpus if cpus are hot-added.
 */
int kcompactd_run(int nid)
{
	pg_data_t *pgdat = NODE_DATA(nid);
	int ret = 0;

	if (pgdat->kcompactd)
		return 0;

	pgdat->kcompactd = kthread_run(kcompactd, pgdat, "kcompactd%d", nid);
	if (IS_ERR(pgdat->kcompactd)) {
		pr_err("Failed to start kcompactd on node %d\n", nid);
		ret = PTR_ERR(pgdat->kcompactd);
		pgdat->kcompactd = NULL;
	}
	return ret;
}

/*
 * Called by memory hotplug when all memory in a node is offlined. Caller must
 * hold mem_hotplug_begin/end().
 */
void kcompactd_stop(int nid)
{
	struct task_struct *kcompactd = NODE_DATA(nid)->kcompactd;

	if (kcompactd) {
		kthread_stop(kcompactd);
		NODE_DATA(nid)->kcompactd = NULL;
	}
}

/*
 * It's optimal to keep kcompactd on the same CPUs as their memory, but
 * not required for correctness. So if the last cpu in a node goes
 * away, we get changed to run anywhere: as the first one comes back,
 * restore their cpu bindings.
 */
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
				set_cpus_allowed_ptr(pgdat->kcompactd, mask);
		}
	}
	return NOTIFY_OK;
}

static int __init kcompactd_init(void)
{
	int nid;

	for_each_node_state(nid, N_MEMORY)
		kcompactd_run(nid);
	hotcpu_notifier(cpu_callback, 0);
	return 0;
}
subsys_initcall(kcompactd_init)

#endif /* CONFIG_COMPACTION */
