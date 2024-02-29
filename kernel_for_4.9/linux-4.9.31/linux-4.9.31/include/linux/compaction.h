#ifndef _LINUX_COMPACTION_H
#define _LINUX_COMPACTION_H

/*
 * Determines how hard direct compaction should try to succeed.
 * Lower value means higher priority, analogically to reclaim priority.
 */
enum compact_priority {
	/* 完全同步模式,允许阻塞,允许将脏页写回到存储设备上,直到等待完成 */
	COMPACT_PRIO_SYNC_FULL,
	MIN_COMPACT_PRIORITY = COMPACT_PRIO_SYNC_FULL,
	/* 轻量级同步模式,允许绝大多数阻塞,但是不允许将脏页写回到存储设备上,因为等待时间比较长 */
	COMPACT_PRIO_SYNC_LIGHT,
	MIN_COMPACT_COSTLY_PRIORITY = COMPACT_PRIO_SYNC_LIGHT,
	DEF_COMPACT_PRIORITY = COMPACT_PRIO_SYNC_LIGHT,
	/* 异步模式,不允许阻塞 */
	COMPACT_PRIO_ASYNC,
	INIT_COMPACT_PRIORITY = COMPACT_PRIO_ASYNC
};

/* Return values for compact_zone() and try_to_compact_pages() */
/* When adding new states, please adjust include/trace/events/compaction.h */
enum compact_result {
	/* For more detailed tracepoint output - internal to compaction
	 * 对于更详细的跟踪点输出 - 内部规整
	 */
	COMPACT_NOT_SUITABLE_ZONE,
	/*
	 * compaction didn't start as it was not possible or direct reclaim
	 * was more suitable
	 *
	 * 规整没有开始,因为它不能或者直接回收更合适
	 */
	COMPACT_SKIPPED,
	/* compaction didn't start as it was deferred due to past failures
	 * 规整没有开始因为它由过去的失败导致了延迟 */
	 /
	COMPACT_DEFERRED,

	/* compaction not active last round
	 * 上一轮压缩未激活
	 */
	COMPACT_INACTIVE = COMPACT_DEFERRED,

	/* For more detailed tracepoint output - internal to compaction
	 * 对于更详细的tracepoint输出 - 内部规整
	 */
	COMPACT_NO_SUITABLE_PAGE,
	/* compaction should continue to another pageblock
	 * 规整应该继续到另一个页面块
	 */
	COMPACT_CONTINUE,

	/*
	 * The full zone was compacted scanned but wasn't successfull to compact
	 * suitable pages.
	 *
	 * 对整个zone都进行了规整扫描,但未能成功规整合适的页面.
	 */
	COMPACT_COMPLETE,
	/*
	 * direct compaction has scanned part of the zone but wasn't successfull
	 * to compact suitable pages.
	 *
	 * 直接规整扫描了zone的一部分,但没有成功规整合适的页面。
	 */
	COMPACT_PARTIAL_SKIPPED,

	/* compaction terminated prematurely due to lock contentions
	 * 由于锁争用，压缩提前终止
	 */
	COMPACT_CONTENDED,

	/*
	 * direct compaction terminated after concluding that the allocation
	 * should now succeed
	 *
	 * 在分配应该的成功的结论之后直接规整终止
	 */
	COMPACT_SUCCESS,
};

struct alloc_context; /* in mm/internal.h */

/*
 * Number of free order-0 pages that should be available above given watermark
 * to make sure compaction has reasonable chance of not running out of free
 * pages that it needs to isolate as migration target during its work.
 *
 * 在给定的水印之上,空闲的order-0的页面的数量应该是可用的,以确保规整有合理的机会不会耗尽它在工作过程中需要隔离为迁移目标的可用页面
 */
static inline unsigned long compact_gap(unsigned int order)
{
	/*
	 * Although all the isolations for migration are temporary, compaction
	 * free scanner may have up to 1 << order pages on its list and then
	 * try to split an (order - 1) free page. At that point, a gap of
	 * 1 << order might not be enough, so it's safer to require twice that
	 * amount. Note that the number of pages on the list is also
	 * effectively limited by COMPACT_CLUSTER_MAX, as that's the maximum
	 * that the migrate scanner can have isolated on migrate list, and free
	 * scanner is only invoked when the number of isolated free pages is
	 * lower than that. But it's not worth to complicate the formula here
	 * as a bigger gap for higher orders than strictly necessary can also
	 * improve chances of compaction success.
	 *
	 * 尽管迁移的所有隔离都是临时的,规整扫描程序的列表中可能最多有1个<<order,然后尝试拆分一个(order-1)空闲页.
	 * 在这一点上,1个<<order可能不够,所以需要两倍的数量更安全.
	 * 请注意,列表上的页数也受到COMPACT_CLUSTER_MAX的有效限制,因为这是迁移扫描程序在迁移列表上可以隔离的最大值,
	 * 并且只有当隔离的可用页数低于此值时,才会调用空闲扫描程序.
	 * 但不值得在这里将公式复杂化,因为对于更高阶数比严格必要的gap更大也可以提高压实成功的机会
	 */
	return 2UL << order;
}

#ifdef CONFIG_COMPACTION
extern int sysctl_compact_memory;
extern int sysctl_compaction_handler(struct ctl_table *table, int write,
			void __user *buffer, size_t *length, loff_t *ppos);
extern int sysctl_extfrag_threshold;
extern int sysctl_extfrag_handler(struct ctl_table *table, int write,
			void __user *buffer, size_t *length, loff_t *ppos);
extern int sysctl_compact_unevictable_allowed;

extern int fragmentation_index(struct zone *zone, unsigned int order);
extern enum compact_result try_to_compact_pages(gfp_t gfp_mask,
		unsigned int order, unsigned int alloc_flags,
		const struct alloc_context *ac, enum compact_priority prio);
extern void reset_isolation_suitable(pg_data_t *pgdat);
extern enum compact_result compaction_suitable(struct zone *zone, int order,
		unsigned int alloc_flags, int classzone_idx);

extern void defer_compaction(struct zone *zone, int order);
extern bool compaction_deferred(struct zone *zone, int order);
extern void compaction_defer_reset(struct zone *zone, int order,
				bool alloc_success);
extern bool compaction_restarting(struct zone *zone, int order);

/* Compaction has made some progress and retrying makes sense */
static inline bool compaction_made_progress(enum compact_result result)
{
	/*
	 * Even though this might sound confusing this in fact tells us
	 * that the compaction successfully isolated and migrated some
	 * pageblocks.
	 */
	if (result == COMPACT_SUCCESS)
		return true;

	return false;
}

/* Compaction has failed and it doesn't make much sense to keep retrying. */
static inline bool compaction_failed(enum compact_result result)
{
	/* All zones were scanned completely and still not result. */
	if (result == COMPACT_COMPLETE)
		return true;

	return false;
}

/*
 * Compaction  has backed off for some reason. It might be throttling or
 * lock contention. Retrying is still worthwhile.
 */
static inline bool compaction_withdrawn(enum compact_result result)
{
	/*
	 * Compaction backed off due to watermark checks for order-0
	 * so the regular reclaim has to try harder and reclaim something.
	 */
	if (result == COMPACT_SKIPPED)
		return true;

	/*
	 * If compaction is deferred for high-order allocations, it is
	 * because sync compaction recently failed. If this is the case
	 * and the caller requested a THP allocation, we do not want
	 * to heavily disrupt the system, so we fail the allocation
	 * instead of entering direct reclaim.
	 */
	if (result == COMPACT_DEFERRED)
		return true;

	/*
	 * If compaction in async mode encounters contention or blocks higher
	 * priority task we back off early rather than cause stalls.
	 */
	if (result == COMPACT_CONTENDED)
		return true;

	/*
	 * Page scanners have met but we haven't scanned full zones so this
	 * is a back off in fact.
	 */
	if (result == COMPACT_PARTIAL_SKIPPED)
		return true;

	return false;
}


bool compaction_zonelist_suitable(struct alloc_context *ac, int order,
					int alloc_flags);

extern int kcompactd_run(int nid);
extern void kcompactd_stop(int nid);
extern void wakeup_kcompactd(pg_data_t *pgdat, int order, int classzone_idx);

#else
static inline void reset_isolation_suitable(pg_data_t *pgdat)
{
}

static inline enum compact_result compaction_suitable(struct zone *zone, int order,
					int alloc_flags, int classzone_idx)
{
	return COMPACT_SKIPPED;
}

static inline void defer_compaction(struct zone *zone, int order)
{
}

static inline bool compaction_deferred(struct zone *zone, int order)
{
	return true;
}

static inline bool compaction_made_progress(enum compact_result result)
{
	return false;
}

static inline bool compaction_failed(enum compact_result result)
{
	return false;
}

static inline bool compaction_withdrawn(enum compact_result result)
{
	return true;
}

static inline int kcompactd_run(int nid)
{
	return 0;
}
static inline void kcompactd_stop(int nid)
{
}

static inline void wakeup_kcompactd(pg_data_t *pgdat, int order, int classzone_idx)
{
}

#endif /* CONFIG_COMPACTION */

#if defined(CONFIG_COMPACTION) && defined(CONFIG_SYSFS) && defined(CONFIG_NUMA)
struct node;
extern int compaction_register_node(struct node *node);
extern void compaction_unregister_node(struct node *node);

#else

static inline int compaction_register_node(struct node *node)
{
	return 0;
}

static inline void compaction_unregister_node(struct node *node)
{
}
#endif /* CONFIG_COMPACTION && CONFIG_SYSFS && CONFIG_NUMA */

#endif /* _LINUX_COMPACTION_H */
