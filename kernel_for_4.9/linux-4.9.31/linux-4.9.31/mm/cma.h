#ifndef __MM_CMA_H__
#define __MM_CMA_H__

/* cma模块使用bitmap来管理其内存的分配,0表示free,1表示已经分配.
 *
 * 具体内存管理的单位和struct cma中的order_per_bit成员相关,如果order_per_bit等于0,表示按照一个一个page来分配和释放,
 * 如果order_per_bit等于1,表示按照2个page组成的block来分配和释放,以此类推.
 * struct cma中的bitmap成员就是管理该cma area内存的bit map.
 *
 * count成员说明了该cma area内存有多少个page.它和order_per_bit一起决定了bitmap指针指向内存的大小.
 *
 * base_pfn定义了该CMA area的起始page frame number,base_pfn和count一起定义了该CMA area在内存在的位置.
 */
struct cma {
	/* CMA区域物理地址的起始页帧号 */
	unsigned long   base_pfn;
	/* CMA区域总体的页数 */
	unsigned long   count;
	/* 位图中每个bit描述的物理页面的order值,其中页面数为2^order值; */
	unsigned long   *bitmap;
	/* 指明该CMA区域的bitmap中,每个bit代表的page数量 */
	unsigned int order_per_bit; /* Order of pages represented by one bit */
	struct mutex    lock;
#ifdef CONFIG_CMA_DEBUGFS
	struct hlist_head mem_head;
	spinlock_t mem_head_lock;
#endif
};

extern struct cma cma_areas[MAX_CMA_AREAS];
extern unsigned cma_area_count;

static inline unsigned long cma_bitmap_maxno(struct cma *cma)
{
	return cma->count >> cma->order_per_bit;
}

#endif
