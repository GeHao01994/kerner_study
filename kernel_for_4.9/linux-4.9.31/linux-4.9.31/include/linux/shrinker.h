#ifndef _LINUX_SHRINKER_H
#define _LINUX_SHRINKER_H

/*
 * This struct is used to pass information from page reclaim to the shrinkers.
 * We consolidate the values for easier extention later.
 *
 * The 'gfpmask' refers to the allocation we are currently trying to
 * fulfil.
 */
struct shrink_control {
	gfp_t gfp_mask;

	/*
	 * How many objects scan_objects should scan and try to reclaim.
	 * This is reset before every call, so it is safe for callees
	 * to modify.
	 */
	unsigned long nr_to_scan;

	/* current node being shrunk (for NUMA aware shrinkers) */
	int nid;

	/* current memcg being shrunk (for memcg aware shrinkers) */
	struct mem_cgroup *memcg;
};

#define SHRINK_STOP (~0UL)
/*
 * A callback you can register to apply pressure to ageable caches.
 *
 * @count_objects should return the number of freeable items in the cache. If
 * there are no objects to free or the number of freeable items cannot be
 * determined, it should return 0. No deadlock checks should be done during the
 * count callback - the shrinker relies on aggregating scan counts that couldn't
 * be executed due to potential deadlocks to be run at a later call when the
 * deadlock condition is no longer pending.
 *
 * @scan_objects will only be called if @count_objects returned a non-zero
 * value for the number of freeable objects. The callout should scan the cache
 * and attempt to free items from the cache. It should then return the number
 * of objects freed during the scan, or SHRINK_STOP if progress cannot be made
 * due to potential deadlocks. If SHRINK_STOP is returned, then no further
 * attempts to call the @scan_objects will be made from the current reclaim
 * context.
 *
 * @flags determine the shrinker abilities, like numa awareness
 *
 * 一个回调,您可以注册以向可老化缓存施加压力。
 *
 * @count_objects应该返回缓存中可释放对象的数量.
 * 如果没有可释放的对象,或者无法确定可释放项目的数量,则应返回0.
 * 在计数回调期间不应进行死锁检查 - shrink 依赖于由于潜在死锁而无法执行的总的扫描计数,
 * 以便在死锁条件不再挂起时在以后的调用中运行。
 *
 * @scan_objects 只有当@count_objects返回可释放对象数的非零值时,才会调用scan_objects.
 * 调出应扫描缓存并尝试从缓存中释放cache,然后它应该返回扫描期间释放的对象数,
 * 如果由于潜在的死锁而无法进行,则为SHRINK_STOP.
 * 如果返回SHRINK_STOP,则不会从当前回收上下文中进一步尝试调用@scan_objects。
 *
 * flags 决定了shrinker的能力,比如numa awareness.
 */
struct shrinker {
	unsigned long (*count_objects)(struct shrinker *,
				       struct shrink_control *sc);
	unsigned long (*scan_objects)(struct shrinker *,
				      struct shrink_control *sc);

	int seeks;	/* seeks to recreate an obj */ /* 在高速缓存中的元素一旦被删除后重建一个所需的代价 */
	long batch;	/* reclaim batch size, 0 = default */ /* 批量释放的数量，如果为0，使用默认值128 */
	unsigned long flags; /* 标志位，目前定义了两个标志位，SHRINKER_NUMA_AWARE表示感知NUMA内存节点，SHRINKER_MEMCG_AWARE表示感知内存控制组 */

	/* These are for internal use */
	struct list_head list; /* 内部使用的成员，用来把收缩器添加到收缩器链表中 */
	/* objs pending delete, per node */
	/* 内部使用的成员，记录每个内存节点延迟到下一次扫描的对象数量 */
	atomic_long_t *nr_deferred;
};
#define DEFAULT_SEEKS 2 /* A good number if you don't know better. */

/* Flags */
#define SHRINKER_NUMA_AWARE	(1 << 0)
#define SHRINKER_MEMCG_AWARE	(1 << 1)

extern int register_shrinker(struct shrinker *);
extern void unregister_shrinker(struct shrinker *);
#endif
