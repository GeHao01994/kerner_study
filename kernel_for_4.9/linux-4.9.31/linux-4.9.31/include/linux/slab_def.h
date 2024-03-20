#ifndef _LINUX_SLAB_DEF_H
#define	_LINUX_SLAB_DEF_H

#include <linux/reciprocal_div.h>

/*
 * Definitions unique to the original Linux SLAB allocator.
 * 原始Linux SLAB分配器的唯一定义
 */

struct kmem_cache {
	/* cpu_cache: 一个per-cpu的struct array_cache数据结构,每个CPU一个,表示本地CPU的对象缓冲池 */
	struct array_cache __percpu *cpu_cache;

/* 1) Cache tunables. Protected by slab_mutex */
	/* 表示当前CPU的本地对象缓冲池array_cache为空时,从共享的缓冲池或者slabs_partial/slabs_free列表中获取对象的数目 */
	unsigned int batchcount;
	/* 当本地对象缓冲池的空闲对象数目大于limit时就会主动释放batchcount个对象,便于内核回收和销毁slab */
	unsigned int limit;
	/* 用于多核系统 */
	unsigned int shared;
	/* 对象的长度,这个长度要加上align对齐字节 */
	unsigned int size;
	struct reciprocal_value reciprocal_buffer_size;
/* 2) touched by every alloc & free from the backend */
	/* 对象的分配掩码 */
	unsigned int flags;		/* constant flags */
	/* 一个slab中最多可以有多少个对象 */
	unsigned int num;		/* # of objs per slab */

/* 3) cache_grow/shrink */
	/* order of pgs per slab (2^n)
	 * 一个slab中占用2 ^ gfporder 个对象
	 */
	unsigned int gfporder;

	/* force GFP flags, e.g. GFP_DMA */
	gfp_t allocflags;
	/* 一个slab中有几个不同的cache line */
	size_t colour;			/* cache colouring range */
	/* 一个cache colour的长度,和L1 cache line大小相同 */
	unsigned int colour_off;	/* colour offset */
	/*
	 * 空闲对象链表放在slab外部时使用,管理用于slab对象管理结构中freelist成员的缓存,也就是又一个新缓存
	 *
	 * 如果是off-slab的场景,freelist_cache指向一个通用slab cache，用来分配page->freelist的空间
	 * 如果是on-slab的场景,freelist_cache是空，page->freelist指向slab的尾部
	 */
	struct kmem_cache *freelist_cache;
	/* 每个对象要占用1 Byte来存放freelist */
	unsigned int freelist_size;

	/* constructor func */
	void (*ctor)(void *obj);

/* 4) cache creation/removal */
	/* slab描述符的名称 */
	const char *name;
	/* slab缓存描述符双向链表指针 */
	struct list_head list;
	int refcount;
	/* slab中每个obj的大小 */
	int object_size;
	/* obj对齐字节 */
	int align;

/* 5) statistics */
#ifdef CONFIG_DEBUG_SLAB
	unsigned long num_active;
	unsigned long num_allocations;
	unsigned long high_mark;
	unsigned long grown;
	unsigned long reaped;
	unsigned long errors;
	unsigned long max_freeable;
	unsigned long node_allocs;
	unsigned long node_frees;
	unsigned long node_overflow;
	atomic_t allochit;
	atomic_t allocmiss;
	atomic_t freehit;
	atomic_t freemiss;
#ifdef CONFIG_DEBUG_SLAB_LEAK
	atomic_t store_user_clean;
#endif

	/*
	 * If debugging is enabled, then the allocator can add additional
	 * fields and/or padding to every object. size contains the total
	 * object size including these internal fields, the following two
	 * variables contain the offset to the user object and its size.
	 */
	int obj_offset;
#endif /* CONFIG_DEBUG_SLAB */

#ifdef CONFIG_MEMCG
	struct memcg_cache_params memcg_params;
#endif
#ifdef CONFIG_KASAN
	struct kasan_cache kasan_info;
#endif

#ifdef CONFIG_SLAB_FREELIST_RANDOM
	unsigned int *random_seq;
#endif
	/* slab节点链表组,对于NUMA系统中每个节点都会有一个struct kmem_cache_node数据结构 */
	struct kmem_cache_node *node[MAX_NUMNODES];
};

static inline void *nearest_obj(struct kmem_cache *cache, struct page *page,
				void *x)
{
	void *object = x - (x - page->s_mem) % cache->size;
	void *last_object = page->s_mem + (cache->num - 1) * cache->size;

	if (unlikely(object > last_object))
		return last_object;
	else
		return object;
}

#endif	/* _LINUX_SLAB_DEF_H */
