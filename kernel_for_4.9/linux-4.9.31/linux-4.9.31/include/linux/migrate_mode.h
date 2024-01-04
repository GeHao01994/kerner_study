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
	MIGRATE_ASYNC,
	MIGRATE_SYNC_LIGHT,
	MIGRATE_SYNC,
};

#endif		/* MIGRATE_MODE_H_INCLUDED */
