#ifndef MIGRATE_MODE_H_INCLUDED
#define MIGRATE_MODE_H_INCLUDED
/*
 * MIGRATE_ASYNC means never block
 * MIGRATE_SYNC_LIGHT in the current implementation means to allow blocking
 *	on most operations but not ->writepage as the potential stall time
 *	is too significant
 * MIGRATE_SYNC will block when migrating pages
 */
/* MIGRATE_ASYNC 表示从不阻塞
 * MIGRATE_SYNC_LIGHT在当前实现中意味在大多数操作上允许阻塞,
 * 但不是->writepage因为潜在的停滞时间太长
 * 迁移页面时，MIGRATE_SYNC将阻止
 */
enum migrate_mode {
	/*
	 * 异步模式:
	 * 内存碎片整理最常用的模式(默认初始是异步模式),
	 * 在此模式中不会进行阻塞(但是时间片到了可以进行主动调度),也就是此种模式不会对文件页进行处理,
	 * 文件页用于映射文件数据使用,这种模式也是对整体系统压力较小的模式(尝试移动的页都是MIGRATE_MOVABLE和MIGRATE_CMA类型的页框)
	 */
	MIGRATE_ASYNC,
	/*
	 * 轻同步模式:
	 * 当异步模式整理不了更多内存时,有两种情况下会使用轻同步模式再次整理内存:
	 * 1.明确表示分配的不是透明大页的情况下;
	 * 2.当前进程是内核线程的情况下.
	 * 这个模式中允许大多数操作进行阻塞(比如隔离了太多页,需要阻塞等待一段时间,设备繁忙,会等待一小会,锁繁忙,会阻塞直到拿到锁为止).
	 * 这种模式会处理匿名页和文件页,但是不会对脏文件页执行回写操作,而当处理的页正在回写时,也不会等待其回写结束.
	 */
	MIGRATE_SYNC_LIGHT,
	/*
	 * 同步模式:
	 * 所有操作都可以进行阻塞,并且会等待处理的页回写结束,并会对文件页、匿名页进行回写到磁盘,
	 * 所以导致最耗费系统资源,对系统造成的压力最大.
	 * 它会在三种情况下发生:
	 * 1.从cma中分配内存时;
	 * 2.调用alloc_contig_range()尝试分配一段指定了开始页框号和结束页框号的连续页框时;
	 * 3.通过写入1到sysfs中的/vm/compact_memory文件手动实现同步内存碎片整理.
	 * 同步模式会增加推迟计数器阀值,并且在同步模式下,会设置好compact_control,让同步模式时忽略pageblock的PB_migrate_skip标记
	 */
	MIGRATE_SYNC,
};

#endif		/* MIGRATE_MODE_H_INCLUDED */
