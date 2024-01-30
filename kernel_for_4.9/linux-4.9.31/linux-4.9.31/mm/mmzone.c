/*
 * linux/mm/mmzone.c
 *
 * management codes for pgdats, zones and page flags
 */


#include <linux/stddef.h>
#include <linux/mm.h>
#include <linux/mmzone.h>

struct pglist_data *first_online_pgdat(void)
{
	return NODE_DATA(first_online_node);
}

struct pglist_data *next_online_pgdat(struct pglist_data *pgdat)
{
	int nid = next_online_node(pgdat->node_id);

	if (nid == MAX_NUMNODES)
		return NULL;
	return NODE_DATA(nid);
}

/*
 * next_zone - helper magic for for_each_zone()
 */
struct zone *next_zone(struct zone *zone)
{
	pg_data_t *pgdat = zone->zone_pgdat;

	if (zone < pgdat->node_zones + MAX_NR_ZONES - 1)
		zone++;
	else {
		pgdat = next_online_pgdat(pgdat);
		if (pgdat)
			zone = pgdat->node_zones;
		else
			zone = NULL;
	}
	return zone;
}

static inline int zref_in_nodemask(struct zoneref *zref, nodemask_t *nodes)
{
#ifdef CONFIG_NUMA
	return node_isset(zonelist_node_idx(zref), *nodes);
#else
	return 1;
#endif /* CONFIG_NUMA */
}

/* 计算zone的核心函数在next_zones_zonelist函数中,这里highest_zoneindex是gfp_zone()函数计算分配掩码得来.
 * zonelist有一个zoneref数组,zoneref数据结构里有一个成员zone指针会指向zone数据结构,还有 一个zone_index
 * 成员指向zone的编号.
 * zone在系统处理时会初始化这个数组,具体函数在build_zonelists_node中.
 * 如
 * ZONE_HIGHMEN _zonerefs[0] -> zone_index = 1
 * ZONE_NORMAL  _zonerefs[1] -> zone_index = 0
 * zonerefs[0] 表示ZONE_HIGHMEM,其zone的编号就是zone_index值为1；
 * zonerefs[1] 表示ZONE_NORMAL,其 zone的编号zone_index为0.
 * 也就是说,基于zone的设计思想是:分配物理页面时会优先考虑ZONE_HIGHMEN,
 * 因为ZONE_HIGHMEN在zonelist中排在ZONE_NORMAL前面
 */
/* Returns the next zone at or below highest_zoneidx in a zonelist */
struct zoneref *__next_zones_zonelist(struct zoneref *z,
					enum zone_type highest_zoneidx,
					nodemask_t *nodes)
{
	/*
	 * Find the next suitable zone to use for the allocation.
	 * Only filter based on nodemask if it's set
	 */
	/* 如果node为空 */
	if (likely(nodes == NULL))/* 如果zonelist_zone_idx(z) > highest_zoneidx,那么z++ */
		while (zonelist_zone_idx(z) > highest_zoneidx)
			z++;
	else /* 如果nodes不为空,那么zonelist_zone_idx(z) > highest_zoneidx 或者z->zone不为空,zoneref->zone->node在nodes这个位图里面,那么z++ */
		while (zonelist_zone_idx(z) > highest_zoneidx ||
				(z->zone && !zref_in_nodemask(z, nodes)))
			z++;

	return z;
}

#ifdef CONFIG_ARCH_HAS_HOLES_MEMORYMODEL
bool memmap_valid_within(unsigned long pfn,
					struct page *page, struct zone *zone)
{
	if (page_to_pfn(page) != pfn)
		return false;

	if (page_zone(page) != zone)
		return false;

	return true;
}
#endif /* CONFIG_ARCH_HAS_HOLES_MEMORYMODEL */

void lruvec_init(struct lruvec *lruvec)
{
	enum lru_list lru;

	memset(lruvec, 0, sizeof(struct lruvec));

	for_each_lru(lru)
		INIT_LIST_HEAD(&lruvec->lists[lru]);
}

#if defined(CONFIG_NUMA_BALANCING) && !defined(LAST_CPUPID_NOT_IN_PAGE_FLAGS)
int page_cpupid_xchg_last(struct page *page, int cpupid)
{
	unsigned long old_flags, flags;
	int last_cpupid;

	do {
		old_flags = flags = page->flags;
		last_cpupid = page_cpupid_last(page);

		flags &= ~(LAST_CPUPID_MASK << LAST_CPUPID_PGSHIFT);
		flags |= (cpupid & LAST_CPUPID_MASK) << LAST_CPUPID_PGSHIFT;
	} while (unlikely(cmpxchg(&page->flags, old_flags, flags) != old_flags));

	return last_cpupid;
}
#endif
