/*
 * linux/mm/slab.c
 * Written by Mark Hemment, 1996/97.
 * (markhe@nextd.demon.co.uk)
 *
 * kmem_cache_destroy() + some cleanup - 1999 Andrea Arcangeli
 *
 * Major cleanup, different bufctl logic, per-cpu arrays
 *	(c) 2000 Manfred Spraul
 *
 * Cleanup, make the head arrays unconditional, preparation for NUMA
 * 	(c) 2002 Manfred Spraul
 *
 * An implementation of the Slab Allocator as described in outline in;
 *	UNIX Internals: The New Frontiers by Uresh Vahalia
 *	Pub: Prentice Hall	ISBN 0-13-101908-2
 * or with a little more detail in;
 *	The Slab Allocator: An Object-Caching Kernel Memory Allocator
 *	Jeff Bonwick (Sun Microsystems).
 *	Presented at: USENIX Summer 1994 Technical Conference
 *
 * The memory is organized in caches, one cache for each object type.
 * (e.g. inode_cache, dentry_cache, buffer_head, vm_area_struct)
 * Each cache consists out of many slabs (they are small (usually one
 * page long) and always contiguous), and each slab contains multiple
 * initialized objects.
 *
 * This means, that your constructor is used only for newly allocated
 * slabs and you must pass objects with the same initializations to
 * kmem_cache_free.
 *
 * Each cache can only support one memory type (GFP_DMA, GFP_HIGHMEM,
 * normal). If you need a special memory type, then must create a new
 * cache for that memory type.
 *
 * In order to reduce fragmentation, the slabs are sorted in 3 groups:
 *   full slabs with 0 free objects
 *   partial slabs
 *   empty slabs with no allocated objects
 *
 * If partial slabs exist, then new allocations come from these slabs,
 * otherwise from empty slabs or new slabs are allocated.
 *
 * kmem_cache_destroy() CAN CRASH if you try to allocate from the cache
 * during kmem_cache_destroy(). The caller must prevent concurrent allocs.
 *
 * Each cache has a short per-cpu head array, most allocs
 * and frees go into that array, and if that array overflows, then 1/2
 * of the entries in the array are given back into the global cache.
 * The head array is strictly LIFO and should improve the cache hit rates.
 * On SMP, it additionally reduces the spinlock operations.
 *
 * The c_cpuarray may not be read with enabled local interrupts -
 * it's changed with a smp_call_function().
 *
 * SMP synchronization:
 *  constructors and destructors are called without any locking.
 *  Several members in struct kmem_cache and struct slab never change, they
 *	are accessed without any locking.
 *  The per-cpu arrays are never accessed from the wrong cpu, no locking,
 *  	and local interrupts are disabled so slab code is preempt-safe.
 *  The non-constant members are protected with a per-cache irq spinlock.
 *
 * Many thanks to Mark Hemment, who wrote another per-cpu slab patch
 * in 2000 - many ideas in the current implementation are derived from
 * his patch.
 *
 * Further notes from the original documentation:
 *
 * 11 April '97.  Started multi-threading - markhe
 *	The global cache-chain is protected by the mutex 'slab_mutex'.
 *	The sem is only needed when accessing/extending the cache-chain, which
 *	can never happen inside an interrupt (kmem_cache_create(),
 *	kmem_cache_shrink() and kmem_cache_reap()).
 *
 *	At present, each engine can be growing a cache.  This should be blocked.
 *
 * 15 March 2005. NUMA slab allocator.
 *	Shai Fultheim <shai@scalex86.org>.
 *	Shobhit Dayal <shobhit@calsoftinc.com>
 *	Alok N Kataria <alokk@calsoftinc.com>
 *	Christoph Lameter <christoph@lameter.com>
 *
 *	Modified the slab allocator to be node aware on NUMA systems.
 *	Each node has its own list of partial, free and full slabs.
 *	All object allocations for a node occur from node specific slab lists.
 */

#include	<linux/slab.h>
#include	<linux/mm.h>
#include	<linux/poison.h>
#include	<linux/swap.h>
#include	<linux/cache.h>
#include	<linux/interrupt.h>
#include	<linux/init.h>
#include	<linux/compiler.h>
#include	<linux/cpuset.h>
#include	<linux/proc_fs.h>
#include	<linux/seq_file.h>
#include	<linux/notifier.h>
#include	<linux/kallsyms.h>
#include	<linux/cpu.h>
#include	<linux/sysctl.h>
#include	<linux/module.h>
#include	<linux/rcupdate.h>
#include	<linux/string.h>
#include	<linux/uaccess.h>
#include	<linux/nodemask.h>
#include	<linux/kmemleak.h>
#include	<linux/mempolicy.h>
#include	<linux/mutex.h>
#include	<linux/fault-inject.h>
#include	<linux/rtmutex.h>
#include	<linux/reciprocal_div.h>
#include	<linux/debugobjects.h>
#include	<linux/kmemcheck.h>
#include	<linux/memory.h>
#include	<linux/prefetch.h>

#include	<net/sock.h>

#include	<asm/cacheflush.h>
#include	<asm/tlbflush.h>
#include	<asm/page.h>

#include <trace/events/kmem.h>

#include	"internal.h"

#include	"slab.h"

/*
 * DEBUG	- 1 for kmem_cache_create() to honour; SLAB_RED_ZONE & SLAB_POISON.
 *		  0 for faster, smaller code (especially in the critical paths).
 *
 * STATS	- 1 to collect stats for /proc/slabinfo.
 *		  0 for faster, smaller code (especially in the critical paths).
 *
 * FORCED_DEBUG	- 1 enables SLAB_RED_ZONE and SLAB_POISON (if possible)
 */

#ifdef CONFIG_DEBUG_SLAB
#define	DEBUG		1
#define	STATS		1
#define	FORCED_DEBUG	1
#else
#define	DEBUG		0
#define	STATS		0
#define	FORCED_DEBUG	0
#endif

/* Shouldn't this be in a header file somewhere? */
#define	BYTES_PER_WORD		sizeof(void *)
#define	REDZONE_ALIGN		max(BYTES_PER_WORD, __alignof__(unsigned long long))

#ifndef ARCH_KMALLOC_FLAGS
#define ARCH_KMALLOC_FLAGS SLAB_HWCACHE_ALIGN
#endif

#define FREELIST_BYTE_INDEX (((PAGE_SIZE >> BITS_PER_BYTE) \
				<= SLAB_OBJ_MIN_SIZE) ? 1 : 0)

#if FREELIST_BYTE_INDEX
typedef unsigned char freelist_idx_t;
#else
typedef unsigned short freelist_idx_t;
#endif

#define SLAB_OBJ_MAX_NUM ((1 << sizeof(freelist_idx_t) * BITS_PER_BYTE) - 1)

/*
 * struct array_cache
 *
 * Purpose:
 * - LIFO ordering, to hand out cache-warm objects from _alloc
 * - reduce the number of linked list operations
 * - reduce spinlock operations
 *
 * The limit is stored in the per-cpu structure to reduce the data cache
 * footprint.
 *
 */

/* slab描述符给每个CPU都提供一个对象缓存池(array_cache) */
struct array_cache {
	/* 对象缓存池中可用的对象数目 */
	unsigned int avail;
	/* 当本地对象缓冲池的空闲对象数目大于limit时就会主动释放batchcount个对象,便于内核回收和销毁slab */
	unsigned int limit;
	unsigned int batchcount;
	/* 在从缓存移除一个对象时,将touched设置为1,而缓存收缩时,则将touched设置为0.这使得内核能够确认在缓存上一次收缩之后是否被访问过,也是缓存重要性的一个标志. */
	unsigned int touched;
	/* 保存对象的实体 */
	void *entry[];	/*
			 * Must have this definition in here for the proper
			 * alignment of array_cache. Also simplifies accessing
			 * the entries.
			 *
			 * 这里必须有这个定义才能正确对齐array_cache.还简化了对entries的访问.
			 */
};

struct alien_cache {
	spinlock_t lock;
	struct array_cache ac;
};

/*
 * Need this for bootstrapping a per node allocator.
 */
#define NUM_INIT_LISTS (2 * MAX_NUMNODES)
static struct kmem_cache_node __initdata init_kmem_cache_node[NUM_INIT_LISTS];
#define	CACHE_CACHE 0
#define	SIZE_NODE (MAX_NUMNODES)

static int drain_freelist(struct kmem_cache *cache,
			struct kmem_cache_node *n, int tofree);
static void free_block(struct kmem_cache *cachep, void **objpp, int len,
			int node, struct list_head *list);
static void slabs_destroy(struct kmem_cache *cachep, struct list_head *list);
static int enable_cpucache(struct kmem_cache *cachep, gfp_t gfp);
static void cache_reap(struct work_struct *unused);

static inline void fixup_objfreelist_debug(struct kmem_cache *cachep,
						void **list);
static inline void fixup_slab_list(struct kmem_cache *cachep,
				struct kmem_cache_node *n, struct page *page,
				void **list);
static int slab_early_init = 1;

#define INDEX_NODE kmalloc_index(sizeof(struct kmem_cache_node))

static void kmem_cache_node_init(struct kmem_cache_node *parent)
{
	INIT_LIST_HEAD(&parent->slabs_full);
	INIT_LIST_HEAD(&parent->slabs_partial);
	INIT_LIST_HEAD(&parent->slabs_free);
	parent->shared = NULL;
	parent->alien = NULL;
	parent->colour_next = 0;
	spin_lock_init(&parent->list_lock);
	parent->free_objects = 0;
	parent->free_touched = 0;
	parent->num_slabs = 0;
}

#define MAKE_LIST(cachep, listp, slab, nodeid)				\
	do {								\
		INIT_LIST_HEAD(listp);					\
		list_splice(&get_node(cachep, nodeid)->slab, listp);	\
	} while (0)

#define	MAKE_ALL_LISTS(cachep, ptr, nodeid)				\
	do {								\
	MAKE_LIST((cachep), (&(ptr)->slabs_full), slabs_full, nodeid);	\
	MAKE_LIST((cachep), (&(ptr)->slabs_partial), slabs_partial, nodeid); \
	MAKE_LIST((cachep), (&(ptr)->slabs_free), slabs_free, nodeid);	\
	} while (0)

#define CFLGS_OBJFREELIST_SLAB	(0x40000000UL)
#define CFLGS_OFF_SLAB		(0x80000000UL)
#define	OBJFREELIST_SLAB(x)	((x)->flags & CFLGS_OBJFREELIST_SLAB)
#define	OFF_SLAB(x)	((x)->flags & CFLGS_OFF_SLAB)

#define BATCHREFILL_LIMIT	16
/*
 * Optimization question: fewer reaps means less probability for unnessary
 * cpucache drain/refill cycles.
 *
 * OTOH the cpuarrays can contain lots of objects,
 * which could lock up otherwise freeable slabs.
 */
#define REAPTIMEOUT_AC		(2*HZ)
#define REAPTIMEOUT_NODE	(4*HZ)

#if STATS
#define	STATS_INC_ACTIVE(x)	((x)->num_active++)
#define	STATS_DEC_ACTIVE(x)	((x)->num_active--)
#define	STATS_INC_ALLOCED(x)	((x)->num_allocations++)
#define	STATS_INC_GROWN(x)	((x)->grown++)
#define	STATS_ADD_REAPED(x,y)	((x)->reaped += (y))
#define	STATS_SET_HIGH(x)						\
	do {								\
		if ((x)->num_active > (x)->high_mark)			\
			(x)->high_mark = (x)->num_active;		\
	} while (0)
#define	STATS_INC_ERR(x)	((x)->errors++)
#define	STATS_INC_NODEALLOCS(x)	((x)->node_allocs++)
#define	STATS_INC_NODEFREES(x)	((x)->node_frees++)
#define STATS_INC_ACOVERFLOW(x)   ((x)->node_overflow++)
#define	STATS_SET_FREEABLE(x, i)					\
	do {								\
		if ((x)->max_freeable < i)				\
			(x)->max_freeable = i;				\
	} while (0)
#define STATS_INC_ALLOCHIT(x)	atomic_inc(&(x)->allochit)
#define STATS_INC_ALLOCMISS(x)	atomic_inc(&(x)->allocmiss)
#define STATS_INC_FREEHIT(x)	atomic_inc(&(x)->freehit)
#define STATS_INC_FREEMISS(x)	atomic_inc(&(x)->freemiss)
#else
#define	STATS_INC_ACTIVE(x)	do { } while (0)
#define	STATS_DEC_ACTIVE(x)	do { } while (0)
#define	STATS_INC_ALLOCED(x)	do { } while (0)
#define	STATS_INC_GROWN(x)	do { } while (0)
#define	STATS_ADD_REAPED(x,y)	do { (void)(y); } while (0)
#define	STATS_SET_HIGH(x)	do { } while (0)
#define	STATS_INC_ERR(x)	do { } while (0)
#define	STATS_INC_NODEALLOCS(x)	do { } while (0)
#define	STATS_INC_NODEFREES(x)	do { } while (0)
#define STATS_INC_ACOVERFLOW(x)   do { } while (0)
#define	STATS_SET_FREEABLE(x, i) do { } while (0)
#define STATS_INC_ALLOCHIT(x)	do { } while (0)
#define STATS_INC_ALLOCMISS(x)	do { } while (0)
#define STATS_INC_FREEHIT(x)	do { } while (0)
#define STATS_INC_FREEMISS(x)	do { } while (0)
#endif

#if DEBUG

/*
 * memory layout of objects:
 * 0		: objp
 * 0 .. cachep->obj_offset - BYTES_PER_WORD - 1: padding. This ensures that
 * 		the end of an object is aligned with the end of the real
 * 		allocation. Catches writes behind the end of the allocation.
 * cachep->obj_offset - BYTES_PER_WORD .. cachep->obj_offset - 1:
 * 		redzone word.
 * cachep->obj_offset: The real object.
 * cachep->size - 2* BYTES_PER_WORD: redzone word [BYTES_PER_WORD long]
 * cachep->size - 1* BYTES_PER_WORD: last caller address
 *					[BYTES_PER_WORD long]
 */
static int obj_offset(struct kmem_cache *cachep)
{
	return cachep->obj_offset;
}

static unsigned long long *dbg_redzone1(struct kmem_cache *cachep, void *objp)
{
	BUG_ON(!(cachep->flags & SLAB_RED_ZONE));
	return (unsigned long long*) (objp + obj_offset(cachep) -
				      sizeof(unsigned long long));
}

static unsigned long long *dbg_redzone2(struct kmem_cache *cachep, void *objp)
{
	BUG_ON(!(cachep->flags & SLAB_RED_ZONE));
	if (cachep->flags & SLAB_STORE_USER)
		return (unsigned long long *)(objp + cachep->size -
					      sizeof(unsigned long long) -
					      REDZONE_ALIGN);
	return (unsigned long long *) (objp + cachep->size -
				       sizeof(unsigned long long));
}

static void **dbg_userword(struct kmem_cache *cachep, void *objp)
{
	/* 如果cachep->flags没有带SLAB_STORE_USER,那么报个BUG */
	BUG_ON(!(cachep->flags & SLAB_STORE_USER));
	/* 否则,返回userword的最后一个BYTES_PER_WORD的地址 */
	return (void **)(objp + cachep->size - BYTES_PER_WORD);
}

#else

#define obj_offset(x)			0
#define dbg_redzone1(cachep, objp)	({BUG(); (unsigned long long *)NULL;})
#define dbg_redzone2(cachep, objp)	({BUG(); (unsigned long long *)NULL;})
#define dbg_userword(cachep, objp)	({BUG(); (void **)NULL;})

#endif

#ifdef CONFIG_DEBUG_SLAB_LEAK

static inline bool is_store_user_clean(struct kmem_cache *cachep)
{
	return atomic_read(&cachep->store_user_clean) == 1;
}

static inline void set_store_user_clean(struct kmem_cache *cachep)
{
	atomic_set(&cachep->store_user_clean, 1);
}

static inline void set_store_user_dirty(struct kmem_cache *cachep)
{
	if (is_store_user_clean(cachep))
		atomic_set(&cachep->store_user_clean, 0);
}

#else
static inline void set_store_user_dirty(struct kmem_cache *cachep) {}

#endif

/*
 * Do not go above this order unless 0 objects fit into the slab or
 * overridden on the command line.
 */
#define	SLAB_MAX_ORDER_HI	1
#define	SLAB_MAX_ORDER_LO	0
static int slab_max_order = SLAB_MAX_ORDER_LO;
static bool slab_max_order_set __initdata;

static inline struct kmem_cache *virt_to_cache(const void *obj)
{
	struct page *page = virt_to_head_page(obj);
	return page->slab_cache;
}

static inline void *index_to_obj(struct kmem_cache *cache, struct page *page,
				 unsigned int idx)
{
	return page->s_mem + cache->size * idx;
}

/*
 * We want to avoid an expensive divide : (offset / cache->size)
 *   Using the fact that size is a constant for a particular cache,
 *   we can replace (offset / cache->size) by
 *   reciprocal_divide(offset, cache->reciprocal_buffer_size)
 */
static inline unsigned int obj_to_index(const struct kmem_cache *cache,
					const struct page *page, void *obj)
{
	u32 offset = (obj - page->s_mem);
	return reciprocal_divide(offset, cache->reciprocal_buffer_size);
}

#define BOOT_CPUCACHE_ENTRIES	1
/* internal cache of cache description objs */
static struct kmem_cache kmem_cache_boot = {
	.batchcount = 1,
	.limit = BOOT_CPUCACHE_ENTRIES,
	.shared = 1,
	.size = sizeof(struct kmem_cache),
	.name = "kmem_cache",
};

static DEFINE_PER_CPU(struct delayed_work, slab_reap_work);

static inline struct array_cache *cpu_cache_get(struct kmem_cache *cachep)
{
	return this_cpu_ptr(cachep->cpu_cache);
}

/*
 * Calculate the number of objects and left-over bytes for a given buffer size.
 *
 * 计算给定缓冲区大小的对象数和剩余字节数
 */
static unsigned int cache_estimate(unsigned long gfporder, size_t buffer_size,
		unsigned long flags, size_t *left_over)
{
	unsigned int num;
	size_t slab_size = PAGE_SIZE << gfporder;

	/*
	 * The slab management structure can be either off the slab or
	 * on it. For the latter case, the memory allocated for a
	 * slab is used for:
	 *
	 * - @buffer_size bytes for each object
	 * - One freelist_idx_t for each object
	 *
	 * We don't need to consider alignment of freelist because
	 * freelist will be at the end of slab page. The objects will be
	 * at the correct alignment.
	 *
	 * If the slab management structure is off the slab, then the
	 * alignment will already be calculated into the size. Because
	 * the slabs are all pages aligned, the objects will be at the
	 * correct alignment when allocated.
	 *
	 * slab管理结构可以在slab外,也可以在slabh内.
	 * 对于后一种情况,为slab分配的内存用于:
	 *
	 * - 每个对象的@buffer_size字节
	 * - 每个对象一个freelist_idx_t
	 *
	 * 我们不需要考虑freelist的对齐,因为freelist将在slab页面的末尾.
	 * 这些对象将处于正确的对齐.
	 *
	 * 如果slab管理结构体不在slab上,则对齐将已计算到size中.
	 * 因为slab是所有页面对齐的,所以分配时对象将处于正确的对齐方式.
	 */

	/* 如果CFLGS_OFF_SLAB或者CFLGS_OBJFREELIST_SLAB 被设置了
	 * 那么num = slab_size / buffer_size
	 * *left_over = slab_size % buffer_size
'	 */
	if (flags & (CFLGS_OBJFREELIST_SLAB | CFLGS_OFF_SLAB)) {
		num = slab_size / buffer_size;
		*left_over = slab_size % buffer_size;
	} else {
		num = slab_size / (buffer_size + sizeof(freelist_idx_t));
		*left_over = slab_size %
			(buffer_size + sizeof(freelist_idx_t));
	}

	return num;
}

#if DEBUG
#define slab_error(cachep, msg) __slab_error(__func__, cachep, msg)

static void __slab_error(const char *function, struct kmem_cache *cachep,
			char *msg)
{
	pr_err("slab error in %s(): cache `%s': %s\n",
	       function, cachep->name, msg);
	dump_stack();
	add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
}
#endif

/*
 * By default on NUMA we use alien caches to stage the freeing of
 * objects allocated from other nodes. This causes massive memory
 * inefficiencies when using fake NUMA setup to split memory into a
 * large number of small nodes, so it can be disabled on the command
 * line
 *
 * 默认情况下,在NUMA上,我们使用外部缓存来释放从其他节点分配的对象.
 * 当使用伪NUMA设置将内存拆分为大量小节点时,这会导致大量内存效率低下,因此可以在命令行中禁用它
 */

static int use_alien_caches __read_mostly = 1;
static int __init noaliencache_setup(char *s)
{
	use_alien_caches = 0;
	return 1;
}
__setup("noaliencache", noaliencache_setup);

static int __init slab_max_order_setup(char *str)
{
	get_option(&str, &slab_max_order);
	slab_max_order = slab_max_order < 0 ? 0 :
				min(slab_max_order, MAX_ORDER - 1);
	slab_max_order_set = true;

	return 1;
}
__setup("slab_max_order=", slab_max_order_setup);

#ifdef CONFIG_NUMA
/*
 * Special reaping functions for NUMA systems called from cache_reap().
 * These take care of doing round robin flushing of alien caches (containing
 * objects freed on different nodes from which they were allocated) and the
 * flushing of remote pcps by calling drain_node_pages.
 */
static DEFINE_PER_CPU(unsigned long, slab_reap_node);

static void init_reap_node(int cpu)
{
	per_cpu(slab_reap_node, cpu) = next_node_in(cpu_to_mem(cpu),
						    node_online_map);
}

static void next_reap_node(void)
{
	int node = __this_cpu_read(slab_reap_node);

	node = next_node_in(node, node_online_map);
	__this_cpu_write(slab_reap_node, node);
}

#else
#define init_reap_node(cpu) do { } while (0)
#define next_reap_node(void) do { } while (0)
#endif

/*
 * Initiate the reap timer running on the target CPU.  We run at around 1 to 2Hz
 * via the workqueue/eventd.
 * Add the CPU number into the expiration time to minimize the possibility of
 * the CPUs getting into lockstep and contending for the global cache chain
 * lock.
 */
static void start_cpu_timer(int cpu)
{
	struct delayed_work *reap_work = &per_cpu(slab_reap_work, cpu);

	/*
	 * When this gets called from do_initcalls via cpucache_init(),
	 * init_workqueues() has already run, so keventd will be setup
	 * at that time.
	 */
	if (keventd_up() && reap_work->work.func == NULL) {
		init_reap_node(cpu);
		INIT_DEFERRABLE_WORK(reap_work, cache_reap);
		schedule_delayed_work_on(cpu, reap_work,
					__round_jiffies_relative(HZ, cpu));
	}
}

static void init_arraycache(struct array_cache *ac, int limit, int batch)
{
	/*
	 * The array_cache structures contain pointers to free object.
	 * However, when such objects are allocated or transferred to another
	 * cache the pointers are not cleared and they could be counted as
	 * valid references during a kmemleak scan. Therefore, kmemleak must
	 * not scan such objects.
	 *
	 * array_cache结构包含指向空闲对象的指针.
	 * 然而,当这些对象被分配或传输到另一个缓存时,指针不会被清除,
	 * 并且在kmemleak扫描期间,它们可能被视为有效引用.
	 * 因此,kmemleak不得扫描此类对象
	 */
	kmemleak_no_scan(ac);
	if (ac) {
		ac->avail = 0;
		ac->limit = limit;
		ac->batchcount = batch;
		ac->touched = 0;
	}
}

static struct array_cache *alloc_arraycache(int node, int entries,
					    int batchcount, gfp_t gfp)
{
	size_t memsize = sizeof(void *) * entries + sizeof(struct array_cache);
	struct array_cache *ac = NULL;

	ac = kmalloc_node(memsize, gfp, node);
	init_arraycache(ac, entries, batchcount);
	return ac;
}

static noinline void cache_free_pfmemalloc(struct kmem_cache *cachep,
					struct page *page, void *objp)
{
	struct kmem_cache_node *n;
	int page_node;
	LIST_HEAD(list);

	page_node = page_to_nid(page);
	n = get_node(cachep, page_node);

	spin_lock(&n->list_lock);
	free_block(cachep, &objp, 1, page_node, &list);
	spin_unlock(&n->list_lock);

	slabs_destroy(cachep, &list);
}

/*
 * Transfer objects in one arraycache to another.
 * Locking must be handled by the caller.
 *
 * Return the number of entries transferred.
 *
 * From: transfer_objects(ac, shared, batchcount)
 */
static int transfer_objects(struct array_cache *to,
		struct array_cache *from, unsigned int max)
{
	/* Figure out how many entries to transfer
	 * 计算要转移多少个entries
	 */

	/* 从from->avvail、max、limit-avail中取最小的 */
	int nr = min3(from->avail, max, to->limit - to->avail);

	/* 如果nr = NULL,那么返回0 */
	if (!nr)
		return 0;

	/* avail表示对象缓冲池里面的可用数目
	 * 所以这里把from->entry + from->avail -nr 拷贝nr个指针到to->entry + to->avail
	 * 这里都是存放着指针
	 */
	memcpy(to->entry + to->avail, from->entry + from->avail -nr,
			sizeof(void *) *nr);

	/* 然后from->avail -=nr, to->avail += nr */
	from->avail -= nr;
	to->avail += nr;
	return nr;
}

#ifndef CONFIG_NUMA

#define drain_alien_cache(cachep, alien) do { } while (0)
#define reap_alien(cachep, n) do { } while (0)

static inline struct alien_cache **alloc_alien_cache(int node,
						int limit, gfp_t gfp)
{
	return NULL;
}

static inline void free_alien_cache(struct alien_cache **ac_ptr)
{
}

static inline int cache_free_alien(struct kmem_cache *cachep, void *objp)
{
	return 0;
}

static inline void *alternate_node_alloc(struct kmem_cache *cachep,
		gfp_t flags)
{
	return NULL;
}

static inline void *____cache_alloc_node(struct kmem_cache *cachep,
		 gfp_t flags, int nodeid)
{
	return NULL;
}

static inline gfp_t gfp_exact_node(gfp_t flags)
{
	return flags & ~__GFP_NOFAIL;
}

#else	/* CONFIG_NUMA */

static void *____cache_alloc_node(struct kmem_cache *, gfp_t, int);
static void *alternate_node_alloc(struct kmem_cache *, gfp_t);

static struct alien_cache *__alloc_alien_cache(int node, int entries,
						int batch, gfp_t gfp)
{
	size_t memsize = sizeof(void *) * entries + sizeof(struct alien_cache);
	struct alien_cache *alc = NULL;
	/* 根据node来调用kmalloc分配空间 */
	alc = kmalloc_node(memsize, gfp, node);
	/* 初始化alien_cache */
	init_arraycache(&alc->ac, entries, batch);
	spin_lock_init(&alc->lock);
	return alc;
}

static struct alien_cache **alloc_alien_cache(int node, int limit, gfp_t gfp)
{
	struct alien_cache **alc_ptr;
	/* 算出nr_node_ids个指针的大小 */
	size_t memsize = sizeof(void *) * nr_node_ids;
	int i;

	/* 如果limit大于1,那么把limit赋值为12 */
	if (limit > 1)
		limit = 12;
	/* 分配nr_node_ids个指针 */
	alc_ptr = kzalloc_node(memsize, gfp, node);
	/* 如果为NULL,则返回 */
	if (!alc_ptr)
		return NULL;

	/* 不然对于每个系统中的每个node都来个循环 */
	for_each_node(i) {
		/* 如果遇到了本node或者说node不是online的,那么continue */
		if (i == node || !node_online(i))
			continue;
		/* 在本节点中分配arraycache结构体 */
		alc_ptr[i] = __alloc_alien_cache(node, limit, 0xbaadf00d, gfp);
		/* 如果是空的,把之前分配的释放掉 */
		if (!alc_ptr[i]) {
			for (i--; i >= 0; i--)
				kfree(alc_ptr[i]);
			kfree(alc_ptr);
			return NULL;
		}
	}
	return alc_ptr;
}

static void free_alien_cache(struct alien_cache **alc_ptr)
{
	int i;

	if (!alc_ptr)
		return;
	for_each_node(i)
	    kfree(alc_ptr[i]);
	kfree(alc_ptr);
}

static void __drain_alien_cache(struct kmem_cache *cachep,
				struct array_cache *ac, int node,
				struct list_head *list)
{
	/* 拿到该node的kmem_cache_node */
	struct kmem_cache_node *n = get_node(cachep, node);

	/* 如果array_cache里面有可用对象 */
	if (ac->avail) {
		spin_lock(&n->list_lock);
		/*
		 * Stuff objects into the remote nodes shared array first.
		 * That way we could avoid the overhead of putting the objects
		 * into the free lists and getting them back later.
		 *
		 * 首先将对象填充到远程节点共享数组中.这样我们就可以避免将对象放入空闲列表并稍后将其取回的开销.
		 */

		/* 如果有共享array_cache,就把它扔过去 */
		if (n->shared)
			transfer_objects(n->shared, ac, ac->limit);
		/* 把多余的释放掉 */
		free_block(cachep, ac->entry, ac->avail, node, list);
		/* 设置ac->avail为0 */
		ac->avail = 0;
		spin_unlock(&n->list_lock);
	}
}

/*
 * Called from cache_reap() to regularly drain alien caches round robin.
 */
static void reap_alien(struct kmem_cache *cachep, struct kmem_cache_node *n)
{
	int node = __this_cpu_read(slab_reap_node);

	if (n->alien) {
		struct alien_cache *alc = n->alien[node];
		struct array_cache *ac;

		if (alc) {
			ac = &alc->ac;
			if (ac->avail && spin_trylock_irq(&alc->lock)) {
				LIST_HEAD(list);

				__drain_alien_cache(cachep, ac, node, &list);
				spin_unlock_irq(&alc->lock);
				slabs_destroy(cachep, &list);
			}
		}
	}
}

static void drain_alien_cache(struct kmem_cache *cachep,
				struct alien_cache **alien)
{
	int i = 0;
	struct alien_cache *alc;
	struct array_cache *ac;
	unsigned long flags;

	for_each_online_node(i) {
		alc = alien[i];
		if (alc) {
			LIST_HEAD(list);

			ac = &alc->ac;
			spin_lock_irqsave(&alc->lock, flags);
			__drain_alien_cache(cachep, ac, i, &list);
			spin_unlock_irqrestore(&alc->lock, flags);
			slabs_destroy(cachep, &list);
		}
	}
}

static int __cache_free_alien(struct kmem_cache *cachep, void *objp,
				int node, int page_node)
{
	struct kmem_cache_node *n;
	struct alien_cache *alien = NULL;
	struct array_cache *ac;
	LIST_HEAD(list);

	/* 拿到该节点的kmem_cache_node */
	n = get_node(cachep, node);
	/* (cachep)->node_frees++ */
	STATS_INC_NODEFREES(cachep);
	/* 如果n->alien不为空,且还有该node的alien_cache */
	if (n->alien && n->alien[page_node]) {
		/* 拿到该node的alien_cache */
		alien = n->alien[page_node];
		/* 拿到该alien_cache的array_cache */
		ac = &alien->ac;
		spin_lock(&alien->lock);
		/* 如果avail等于limit */
		if (unlikely(ac->avail == ac->limit)) {
			STATS_INC_ACOVERFLOW(cachep);
			/* 那么就想把这里面的对象放到shared arrya_cache里面去
			 * 如果放不下去了就把它给释放掉
			 */
			__drain_alien_cache(cachep, ac, page_node, &list);
		}
		/* 然后把这个free的对象给到它 */
		ac->entry[ac->avail++] = objp;
		spin_unlock(&alien->lock);
		/* 该destroy的就destroy */
		slabs_destroy(cachep, &list);
	} else {
		/* 如果没有alien,那么就拿到本node的kmem_cache_node */
		n = get_node(cachep, page_node);
		spin_lock(&n->list_lock);
		/* 调用free_block函数主动去释放1个空闲对象,如果slab没有了活跃对象(即page->active == 0),
		 * 并且slab节点中所有空闲对象数目n->free_objects超过了n->free_limit阀值,
		 * 那么调用slab_destroy函数来销毁这个slab.
		 */
		free_block(cachep, &objp, 1, page_node, &list);
		spin_unlock(&n->list_lock);
		slabs_destroy(cachep, &list);
	}
	return 1;
}

static inline int cache_free_alien(struct kmem_cache *cachep, void *objp)
{
	int page_node = page_to_nid(virt_to_page(objp));
	int node = numa_mem_id();
	/*
	 * Make sure we are not freeing a object from another node to the array
	 * cache on this cpu.
	 */
	if (likely(node == page_node))
		return 0;

	return __cache_free_alien(cachep, objp, node, page_node);
}

/*
 * Construct gfp mask to allocate from a specific node but do not reclaim or
 * warn about failures.
 */
static inline gfp_t gfp_exact_node(gfp_t flags)
{
	return (flags | __GFP_THISNODE | __GFP_NOWARN) & ~(__GFP_RECLAIM|__GFP_NOFAIL);
}
#endif

static int init_cache_node(struct kmem_cache *cachep, int node, gfp_t gfp)
{
	struct kmem_cache_node *n;

	/*
	 * Set up the kmem_cache_node for cpu before we can
	 * begin anything. Make sure some other cpu on this
	 * node has not already allocated this
	 *
	 * 在我们可以开始任何操作之前,先为cpu设置kmem_cache_node.
	 * 请确保此节点上的其他cpu尚未分配此
	 */

	/* 如果已经有这个kmem_cache_node了 */
	n = get_node(cachep, node);
	if (n) {
		spin_lock_irq(&n->list_lock);
		/* 那么这个kmem_cache_node的free_limit(表示该slab上容许空闲对象的最大数目)
		 * 等于(1 + nr_cpus_node(node)) * cachep->batchcount + cachep->num;
		 * 然后返回
		 */
		n->free_limit = (1 + nr_cpus_node(node)) * cachep->batchcount +
				cachep->num;
		spin_unlock_irq(&n->list_lock);

		return 0;
	}

	/* 分配一个kmem_cache_node */
	n = kmalloc_node(sizeof(struct kmem_cache_node), gfp, node);
	if (!n)
		return -ENOMEM;

	/* 初始化kmem_cache_node */
	kmem_cache_node_init(n);
	/* 设置回收间隔 */
	n->next_reap = jiffies + REAPTIMEOUT_NODE +
		    ((unsigned long)cachep) % REAPTIMEOUT_NODE;

	/* 设置free_limit */
	n->free_limit =
		(1 + nr_cpus_node(node)) * cachep->batchcount + cachep->num;

	/*
	 * The kmem_cache_nodes don't come and go as CPUs
	 * come and go.  slab_mutex is sufficient
	 * protection here.
	 *
	 * kmem_cache_node不会随着CPU去留,slab_mutex在这里是足够的保护.
	 */
	cachep->node[node] = n;

	return 0;
}

#if (defined(CONFIG_NUMA) && defined(CONFIG_MEMORY_HOTPLUG)) || defined(CONFIG_SMP)
/*
 * Allocates and initializes node for a node on each slab cache, used for
 * either memory or cpu hotplug.  If memory is being hot-added, the kmem_cache_node
 * will be allocated off-node since memory is not yet online for the new node.
 * When hotplugging memory or a cpu, existing node are not replaced if
 * already in use.
 *
 * Must hold slab_mutex.
 */
static int init_cache_node_node(int node)
{
	int ret;
	struct kmem_cache *cachep;

	list_for_each_entry(cachep, &slab_caches, list) {
		ret = init_cache_node(cachep, node, GFP_KERNEL);
		if (ret)
			return ret;
	}

	return 0;
}
#endif

static int setup_kmem_cache_node(struct kmem_cache *cachep,
				int node, gfp_t gfp, bool force_change)
{
	int ret = -ENOMEM;
	struct kmem_cache_node *n;
	struct array_cache *old_shared = NULL;
	struct array_cache *new_shared = NULL;
	struct alien_cache **new_alien = NULL;
	LIST_HEAD(list);
	/* use_alien_caches 将定义处的注释 */
	if (use_alien_caches) {
		new_alien = alloc_alien_cache(node, cachep->limit, gfp);
		/* 如果new_alien为NULL,那么goto fail */
		if (!new_alien)
			goto fail;
	}

	/* 如果cachep->shared不为0 */
	if (cachep->shared) {
		/* 分配一个arraycache,limit为cachep->shared * cachep->batchcount */
		new_shared = alloc_arraycache(node,
			cachep->shared * cachep->batchcount, 0xbaadf00d, gfp);
		if (!new_shared)
			goto fail;
	}

	/* 分配并初始化kmem_cache_node */
	ret = init_cache_node(cachep, node, gfp);
	if (ret)
		goto fail;

	/* 拿到这个kmem_cache_node */
	n = get_node(cachep, node);
	spin_lock_irq(&n->list_lock);
	/* 如果n->shared不为NULL(初始化一般为NULL),那么把n->shared给释放掉 */
	if (n->shared && force_change) {
		free_block(cachep, n->shared->entry,
				n->shared->avail, node, &list);
		n->shared->avail = 0;
	}

	/* 如果为NULL,或者要强行修改 */
	if (!n->shared || force_change) {
		/* 把n->shared给old_shared */
		old_shared = n->shared;
		/* 把新分配的给你 */
		n->shared = new_shared;
		new_shared = NULL;
	}

	/* 如果n->alien = NULL,那么把new_alien设置给你 */
	if (!n->alien) {
		n->alien = new_alien;
		new_alien = NULL;
	}

	spin_unlock_irq(&n->list_lock);
	/* 销毁slab */
	slabs_destroy(cachep, &list);

	/*
	 * To protect lockless access to n->shared during irq disabled context.
	 * If n->shared isn't NULL in irq disabled context, accessing to it is
	 * guaranteed to be valid until irq is re-enabled, because it will be
	 * freed after synchronize_sched().
	 *
	 * 在禁用irq的上下文中保护对n->shared的无锁访问.
	 * 如果n->shared在禁用irq的上下文中不为NULL,则在重新启用irq之前,对它的访问保证是有效的,
	 * 因为它将在synchronize_sched()之后释放.
	 */
	if (old_shared && force_change)
		synchronize_sched();

fail:
	kfree(old_shared);
	kfree(new_shared);
	free_alien_cache(new_alien);

	return ret;
}

#ifdef CONFIG_SMP

static void cpuup_canceled(long cpu)
{
	struct kmem_cache *cachep;
	struct kmem_cache_node *n = NULL;
	int node = cpu_to_mem(cpu);
	const struct cpumask *mask = cpumask_of_node(node);

	list_for_each_entry(cachep, &slab_caches, list) {
		struct array_cache *nc;
		struct array_cache *shared;
		struct alien_cache **alien;
		LIST_HEAD(list);

		n = get_node(cachep, node);
		if (!n)
			continue;

		spin_lock_irq(&n->list_lock);

		/* Free limit for this kmem_cache_node */
		n->free_limit -= cachep->batchcount;

		/* cpu is dead; no one can alloc from it. */
		nc = per_cpu_ptr(cachep->cpu_cache, cpu);
		if (nc) {
			free_block(cachep, nc->entry, nc->avail, node, &list);
			nc->avail = 0;
		}

		if (!cpumask_empty(mask)) {
			spin_unlock_irq(&n->list_lock);
			goto free_slab;
		}

		shared = n->shared;
		if (shared) {
			free_block(cachep, shared->entry,
				   shared->avail, node, &list);
			n->shared = NULL;
		}

		alien = n->alien;
		n->alien = NULL;

		spin_unlock_irq(&n->list_lock);

		kfree(shared);
		if (alien) {
			drain_alien_cache(cachep, alien);
			free_alien_cache(alien);
		}

free_slab:
		slabs_destroy(cachep, &list);
	}
	/*
	 * In the previous loop, all the objects were freed to
	 * the respective cache's slabs,  now we can go ahead and
	 * shrink each nodelist to its limit.
	 */
	list_for_each_entry(cachep, &slab_caches, list) {
		n = get_node(cachep, node);
		if (!n)
			continue;
		drain_freelist(cachep, n, INT_MAX);
	}
}

static int cpuup_prepare(long cpu)
{
	struct kmem_cache *cachep;
	int node = cpu_to_mem(cpu);
	int err;

	/*
	 * We need to do this right in the beginning since
	 * alloc_arraycache's are going to use this list.
	 * kmalloc_node allows us to add the slab to the right
	 * kmem_cache_node and not this cpu's kmem_cache_node
	 */
	err = init_cache_node_node(node);
	if (err < 0)
		goto bad;

	/*
	 * Now we can go ahead with allocating the shared arrays and
	 * array caches
	 */
	list_for_each_entry(cachep, &slab_caches, list) {
		err = setup_kmem_cache_node(cachep, node, GFP_KERNEL, false);
		if (err)
			goto bad;
	}

	return 0;
bad:
	cpuup_canceled(cpu);
	return -ENOMEM;
}

int slab_prepare_cpu(unsigned int cpu)
{
	int err;

	mutex_lock(&slab_mutex);
	err = cpuup_prepare(cpu);
	mutex_unlock(&slab_mutex);
	return err;
}

/*
 * This is called for a failed online attempt and for a successful
 * offline.
 *
 * Even if all the cpus of a node are down, we don't free the
 * kmem_list3 of any cache. This to avoid a race between cpu_down, and
 * a kmalloc allocation from another cpu for memory from the node of
 * the cpu going down.  The list3 structure is usually allocated from
 * kmem_cache_create() and gets destroyed at kmem_cache_destroy().
 */
int slab_dead_cpu(unsigned int cpu)
{
	mutex_lock(&slab_mutex);
	cpuup_canceled(cpu);
	mutex_unlock(&slab_mutex);
	return 0;
}
#endif

static int slab_online_cpu(unsigned int cpu)
{
	start_cpu_timer(cpu);
	return 0;
}

static int slab_offline_cpu(unsigned int cpu)
{
	/*
	 * Shutdown cache reaper. Note that the slab_mutex is held so
	 * that if cache_reap() is invoked it cannot do anything
	 * expensive but will only modify reap_work and reschedule the
	 * timer.
	 */
	cancel_delayed_work_sync(&per_cpu(slab_reap_work, cpu));
	/* Now the cache_reaper is guaranteed to be not running. */
	per_cpu(slab_reap_work, cpu).work.func = NULL;
	return 0;
}

#if defined(CONFIG_NUMA) && defined(CONFIG_MEMORY_HOTPLUG)
/*
 * Drains freelist for a node on each slab cache, used for memory hot-remove.
 * Returns -EBUSY if all objects cannot be drained so that the node is not
 * removed.
 *
 * Must hold slab_mutex.
 */
static int __meminit drain_cache_node_node(int node)
{
	struct kmem_cache *cachep;
	int ret = 0;

	list_for_each_entry(cachep, &slab_caches, list) {
		struct kmem_cache_node *n;

		n = get_node(cachep, node);
		if (!n)
			continue;

		drain_freelist(cachep, n, INT_MAX);

		if (!list_empty(&n->slabs_full) ||
		    !list_empty(&n->slabs_partial)) {
			ret = -EBUSY;
			break;
		}
	}
	return ret;
}

static int __meminit slab_memory_callback(struct notifier_block *self,
					unsigned long action, void *arg)
{
	struct memory_notify *mnb = arg;
	int ret = 0;
	int nid;

	nid = mnb->status_change_nid;
	if (nid < 0)
		goto out;

	switch (action) {
	case MEM_GOING_ONLINE:
		mutex_lock(&slab_mutex);
		ret = init_cache_node_node(nid);
		mutex_unlock(&slab_mutex);
		break;
	case MEM_GOING_OFFLINE:
		mutex_lock(&slab_mutex);
		ret = drain_cache_node_node(nid);
		mutex_unlock(&slab_mutex);
		break;
	case MEM_ONLINE:
	case MEM_OFFLINE:
	case MEM_CANCEL_ONLINE:
	case MEM_CANCEL_OFFLINE:
		break;
	}
out:
	return notifier_from_errno(ret);
}
#endif /* CONFIG_NUMA && CONFIG_MEMORY_HOTPLUG */

/*
 * swap the static kmem_cache_node with kmalloced memory
 */
static void __init init_list(struct kmem_cache *cachep, struct kmem_cache_node *list,
				int nodeid)
{
	struct kmem_cache_node *ptr;

	ptr = kmalloc_node(sizeof(struct kmem_cache_node), GFP_NOWAIT, nodeid);
	BUG_ON(!ptr);

	memcpy(ptr, list, sizeof(struct kmem_cache_node));
	/*
	 * Do not assume that spinlocks can be initialized via memcpy:
	 */
	spin_lock_init(&ptr->list_lock);

	MAKE_ALL_LISTS(cachep, ptr, nodeid);
	cachep->node[nodeid] = ptr;
}

/*
 * For setting up all the kmem_cache_node for cache whose buffer_size is same as
 * size of kmem_cache_node.
 */
static void __init set_up_node(struct kmem_cache *cachep, int index)
{
	int node;

	for_each_online_node(node) {
		cachep->node[node] = &init_kmem_cache_node[index + node];
		cachep->node[node]->next_reap = jiffies +
		    REAPTIMEOUT_NODE +
		    ((unsigned long)cachep) % REAPTIMEOUT_NODE;
	}
}

/*
 * Initialisation.  Called after the page allocator have been initialised and
 * before smp_init().
 */
void __init kmem_cache_init(void)
{
	int i;

	BUILD_BUG_ON(sizeof(((struct page *)NULL)->lru) <
					sizeof(struct rcu_head));
	kmem_cache = &kmem_cache_boot;

	if (!IS_ENABLED(CONFIG_NUMA) || num_possible_nodes() == 1)
		use_alien_caches = 0;

	for (i = 0; i < NUM_INIT_LISTS; i++)
		kmem_cache_node_init(&init_kmem_cache_node[i]);

	/*
	 * Fragmentation resistance on low memory - only use bigger
	 * page orders on machines with more than 32MB of memory if
	 * not overridden on the command line.
	 */
	if (!slab_max_order_set && totalram_pages > (32 << 20) >> PAGE_SHIFT)
		slab_max_order = SLAB_MAX_ORDER_HI;

	/* Bootstrap is tricky, because several objects are allocated
	 * from caches that do not exist yet:
	 * 1) initialize the kmem_cache cache: it contains the struct
	 *    kmem_cache structures of all caches, except kmem_cache itself:
	 *    kmem_cache is statically allocated.
	 *    Initially an __init data area is used for the head array and the
	 *    kmem_cache_node structures, it's replaced with a kmalloc allocated
	 *    array at the end of the bootstrap.
	 * 2) Create the first kmalloc cache.
	 *    The struct kmem_cache for the new cache is allocated normally.
	 *    An __init data area is used for the head array.
	 * 3) Create the remaining kmalloc caches, with minimally sized
	 *    head arrays.
	 * 4) Replace the __init data head arrays for kmem_cache and the first
	 *    kmalloc cache with kmalloc allocated arrays.
	 * 5) Replace the __init data for kmem_cache_node for kmem_cache and
	 *    the other cache's with kmalloc allocated memory.
	 * 6) Resize the head arrays of the kmalloc caches to their final sizes.
	 */

	/* 1) create the kmem_cache */

	/*
	 * struct kmem_cache size depends on nr_node_ids & nr_cpu_ids
	 */
	create_boot_cache(kmem_cache, "kmem_cache",
		offsetof(struct kmem_cache, node) +
				  nr_node_ids * sizeof(struct kmem_cache_node *),
				  SLAB_HWCACHE_ALIGN);
	list_add(&kmem_cache->list, &slab_caches);
	slab_state = PARTIAL;

	/*
	 * Initialize the caches that provide memory for the  kmem_cache_node
	 * structures first.  Without this, further allocations will bug.
	 */
	kmalloc_caches[INDEX_NODE] = create_kmalloc_cache("kmalloc-node",
				kmalloc_size(INDEX_NODE), ARCH_KMALLOC_FLAGS);
	slab_state = PARTIAL_NODE;
	setup_kmalloc_cache_index_table();

	slab_early_init = 0;

	/* 5) Replace the bootstrap kmem_cache_node */
	{
		int nid;

		for_each_online_node(nid) {
			init_list(kmem_cache, &init_kmem_cache_node[CACHE_CACHE + nid], nid);

			init_list(kmalloc_caches[INDEX_NODE],
					  &init_kmem_cache_node[SIZE_NODE + nid], nid);
		}
	}

	create_kmalloc_caches(ARCH_KMALLOC_FLAGS);
}

void __init kmem_cache_init_late(void)
{
	struct kmem_cache *cachep;

	slab_state = UP;

	/* 6) resize the head arrays to their final sizes */
	mutex_lock(&slab_mutex);
	list_for_each_entry(cachep, &slab_caches, list)
		if (enable_cpucache(cachep, GFP_NOWAIT))
			BUG();
	mutex_unlock(&slab_mutex);

	/* Done! */
	slab_state = FULL;

#ifdef CONFIG_NUMA
	/*
	 * Register a memory hotplug callback that initializes and frees
	 * node.
	 */
	hotplug_memory_notifier(slab_memory_callback, SLAB_CALLBACK_PRI);
#endif

	/*
	 * The reap timers are started later, with a module init call: That part
	 * of the kernel is not yet operational.
	 */
}

static int __init cpucache_init(void)
{
	int ret;

	/*
	 * Register the timers that return unneeded pages to the page allocator
	 */
	ret = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "SLAB online",
				slab_online_cpu, slab_offline_cpu);
	WARN_ON(ret < 0);

	/* Done! */
	slab_state = FULL;
	return 0;
}
__initcall(cpucache_init);

static noinline void
slab_out_of_memory(struct kmem_cache *cachep, gfp_t gfpflags, int nodeid)
{
#if DEBUG
	struct kmem_cache_node *n;
	struct page *page;
	unsigned long flags;
	int node;
	static DEFINE_RATELIMIT_STATE(slab_oom_rs, DEFAULT_RATELIMIT_INTERVAL,
				      DEFAULT_RATELIMIT_BURST);

	if ((gfpflags & __GFP_NOWARN) || !__ratelimit(&slab_oom_rs))
		return;

	pr_warn("SLAB: Unable to allocate memory on node %d, gfp=%#x(%pGg)\n",
		nodeid, gfpflags, &gfpflags);
	pr_warn("  cache: %s, object size: %d, order: %d\n",
		cachep->name, cachep->size, cachep->gfporder);

	/*
	 *
	 * #define for_each_kmem_cache_node(__s, __node, __n) \
	 *	for (__node = 0; __node < nr_node_ids; __node++) \
	 *		if ((__n = get_node(__s, __node)))
	 */
	for_each_kmem_cache_node(cachep, node, n) {
		unsigned long active_objs = 0, num_objs = 0, free_objects = 0;
		unsigned long active_slabs = 0, num_slabs = 0;
		unsigned long num_slabs_partial = 0, num_slabs_free = 0;
		unsigned long num_slabs_full;

		spin_lock_irqsave(&n->list_lock, flags);
		num_slabs = n->num_slabs;
		/* 对于每个部分free的slabs链表
		 * active_objs加上活跃的链表数目
		 * 所以active_objs表示所有slabs_partial上面的所有活跃链表的数目
		 */
		list_for_each_entry(page, &n->slabs_partial, lru) {
			active_objs += page->active;
			num_slabs_partial++;
		}
		/* 算出有多少个slabs_free */
		list_for_each_entry(page, &n->slabs_free, lru)
			num_slabs_free++;
		/* 拿到空闲对象 */
		free_objects += n->free_objects;
		spin_unlock_irqrestore(&n->list_lock, flags);

		/* num_slabs * cachep->num 获得所有的对象 */
		num_objs = num_slabs * cachep->num;
		/* 获得活跃的slab 但是这里没有算num_slabs_full * cachep->num */
		active_slabs = num_slabs - num_slabs_free;
		/* 获得slab_full的数量 */
		num_slabs_full = num_slabs -
			(num_slabs_partial + num_slabs_free);
		/* 真正获得活跃的slab数量 */
		active_objs += (num_slabs_full * cachep->num);
		/* 打印警告 */
		pr_warn("  node %d: slabs: %ld/%ld, objs: %ld/%ld, free: %ld\n",
			node, active_slabs, num_slabs, active_objs, num_objs,
			free_objects);
	}
#endif
}

/*
 * Interface to system's page allocator. No need to hold the
 * kmem_cache_node ->list_lock.
 *
 * If we requested dmaable memory, we will get it. Even if we
 * did not request dmaable memory, we might get it, but that
 * would be relatively rare and ignorable.
 *
 * 系统页面分配器的接口.无需获得kmem_cache_node->list_lock
 * 如果我们请求了dmable内存,我们就会得到它.
 * 即使我们没有请求dmaable内存,我们也可能得到它,但这是相对罕见和可忽略的
 */
static struct page *kmem_getpages(struct kmem_cache *cachep, gfp_t flags,
								int nodeid)
{
	struct page *page;
	int nr_pages;

	flags |= cachep->allocflags;
	/* 如果对象是可回收的,那么我们分配页面时候的flags就带上__GFP_RECLAIMABLE */
	if (cachep->flags & SLAB_RECLAIM_ACCOUNT)
		flags |= __GFP_RECLAIMABLE;

	/* 分配cachep->gfporder个页面 */
	page = __alloc_pages_node(nodeid, flags | __GFP_NOTRACK, cachep->gfporder);
	/* 如果分不出页面,那么就报一些警告给你 */
	if (!page) {
		slab_out_of_memory(cachep, flags, nodeid);
		return NULL;
	}

	if (memcg_charge_slab(page, flags, cachep->gfporder, cachep)) {
		__free_pages(page, cachep->gfporder);
		return NULL;
	}

	/* 拿到pages数量 */
	nr_pages = (1 << cachep->gfporder);
	/* 如果分配的flags是可回收的,那么对此node的NR_SLAB_RECLAIMABLE加上nr_pages
	 * 否则对此node的NR_SLAB_UNRECLAIMABLE进行加上nr_pages
	 */
	if (cachep->flags & SLAB_RECLAIM_ACCOUNT)
		add_zone_page_state(page_zone(page),
			NR_SLAB_RECLAIMABLE, nr_pages);
	else
		add_zone_page_state(page_zone(page),
			NR_SLAB_UNRECLAIMABLE, nr_pages);

	/* 设置该page的PG_slab */
	__SetPageSlab(page);
	/* Record if ALLOC_NO_WATERMARKS was set when allocating the slab */
	if (sk_memalloc_socks() && page_is_pfmemalloc(page))
		SetPageSlabPfmemalloc(page);

	if (kmemcheck_enabled && !(cachep->flags & SLAB_NOTRACK)) {
		kmemcheck_alloc_shadow(page, cachep->gfporder, flags, nodeid);

		if (cachep->ctor)
			kmemcheck_mark_uninitialized_pages(page, nr_pages);
		else
			kmemcheck_mark_unallocated_pages(page, nr_pages);
	}

	return page;
}

/*
 * Interface to system's page release.
 *
 * 系统页面release的接口
 */
static void kmem_freepages(struct kmem_cache *cachep, struct page *page)
{
	/* 拿到cachep的gfporder */
	int order = cachep->gfporder;
	/* 算出要释放多少个page */
	unsigned long nr_freed = (1 << order);

	kmemcheck_free_shadow(page, order);

	/* 如果cachep是可回收的,那么zone的NR_SLAB_RECLAIMABLE - nr_freed
	 * 否则NR_SLAB_UNRECLAIMABLE - nr_freed
	 */
	if (cachep->flags & SLAB_RECLAIM_ACCOUNT)
		sub_zone_page_state(page_zone(page),
				NR_SLAB_RECLAIMABLE, nr_freed);
	else
		sub_zone_page_state(page_zone(page),
				NR_SLAB_UNRECLAIMABLE, nr_freed);

	/* 如果page没有PG_slab,那么报个BUG */
	BUG_ON(!PageSlab(page));
	/*  static inline void __ClearPageSlabPfmemalloc(struct page *page)
	 * {
	 *	VM_BUG_ON_PAGE(!PageSlab(page), page);
	 *	__ClearPageActive(page);
	 * }
	 */
	__ClearPageSlabPfmemalloc(page);
	/* clear PG_slab */
	__ClearPageSlab(page);
	/* atomic_set(&(page)->_mapcount, -1); */
	page_mapcount_reset(page);
	/* 设置page->mapping为NULL */
	page->mapping = NULL;

	if (current->reclaim_state)
		current->reclaim_state->reclaimed_slab += nr_freed;
	memcg_uncharge_slab(page, order, cachep);
	/* 释放page */
	__free_pages(page, order);
}

static void kmem_rcu_free(struct rcu_head *head)
{
	struct kmem_cache *cachep;
	struct page *page;

	page = container_of(head, struct page, rcu_head);
	cachep = page->slab_cache;

	kmem_freepages(cachep, page);
}

#if DEBUG
static bool is_debug_pagealloc_cache(struct kmem_cache *cachep)
{
	if (debug_pagealloc_enabled() && OFF_SLAB(cachep) &&
		(cachep->size % PAGE_SIZE) == 0)
		return true;

	return false;
}

#ifdef CONFIG_DEBUG_PAGEALLOC
static void store_stackinfo(struct kmem_cache *cachep, unsigned long *addr,
			    unsigned long caller)
{
	/* 拿到对象的大小 */
	int size = cachep->object_size;

	/* 拿到对象的起始位置 */
	addr = (unsigned long *)&((char *)addr)[obj_offset(cachep)];

	/* 如果对象大小小于5个sizeof(unsigned long),那么返回 */
	if (size < 5 * sizeof(unsigned long))
		return;

	/* 把第一个long填充为0x12345678 */
	*addr++ = 0x12345678;
	/* 把第二个填充为 caller */
	*addr++ = caller;
	/* 把第三个填充为 cpu id */
	*addr++ = smp_processor_id();
	/* 然后把size减去3 * sizeof(unsigned long),预留三个sizeof(unsigned long)位置 */
	size -= 3 * sizeof(unsigned long);
	{
		/* 拿到caller的地址 */
		unsigned long *sptr = &caller;
		unsigned long svalue;

		while (!kstack_end(sptr)) {
			svalue = *sptr++;
			if (kernel_text_address(svalue)) {
				*addr++ = svalue;
				size -= sizeof(unsigned long);
				if (size <= sizeof(unsigned long))
					break;
			}
		}

	}
	*addr++ = 0x87654321;
}

static void slab_kernel_map(struct kmem_cache *cachep, void *objp,
				int map, unsigned long caller)
{
	if (!is_debug_pagealloc_cache(cachep))
		return;

	/* 如果有caller */
	if (caller)
		store_stackinfo(cachep, objp, caller);

	kernel_map_pages(virt_to_page(objp), cachep->size / PAGE_SIZE, map);
}

#else
static inline void slab_kernel_map(struct kmem_cache *cachep, void *objp,
				int map, unsigned long caller) {}

#endif

static void poison_obj(struct kmem_cache *cachep, void *addr, unsigned char val)
{
	/* 先拿到对象的大小 */
	int size = cachep->object_size;
	/* 拿到对象的起始地址 */
	addr = &((char *)addr)[obj_offset(cachep)];

	/* 然后填充val */
	memset(addr, val, size);
	/* 最后一个字节填充POISON_END即0xa5 */
	*(unsigned char *)(addr + size - 1) = POISON_END;
}

static void dump_line(char *data, int offset, int limit)
{
	int i;
	unsigned char error = 0;
	int bad_count = 0;

	/* 输出slab的行数的起始偏移量 */
	pr_err("%03x: ", offset);
	/* 算出哪一个字节坏了,然后计数到bad_count中 */
	for (i = 0; i < limit; i++) {
		if (data[offset + i] != POISON_FREE) {
			error = data[offset + i];
			bad_count++;
		}
	}
	/* 打印出这一行 */
	print_hex_dump(KERN_CONT, "", 0, 16, 1,
			&data[offset], limit, 1);


	/* 如果bad_count == 1 */
	if (bad_count == 1) {
		/* 如果error等于和POISON_FREE的异或的值 */
		error ^= POISON_FREE;
		/* 如果error & (error -1)等于0,那么就报如下错误 */
		if (!(error & (error - 1))) {
			pr_err("Single bit error detected. Probably bad RAM.\n");
#ifdef CONFIG_X86
			pr_err("Run memtest86+ or a similar memory test tool.\n");
#else
			pr_err("Run a memory test tool.\n");
#endif
		}
	}
}
#endif

#if DEBUG

static void print_objinfo(struct kmem_cache *cachep, void *objp, int lines)
{
	int i, size;
	char *realobj;

	/* 这里就是输出你的redzone的值 */
	if (cachep->flags & SLAB_RED_ZONE) {
		pr_err("Redzone: 0x%llx/0x%llx\n",
		       *dbg_redzone1(cachep, objp),
		       *dbg_redzone2(cachep, objp));
	}

	/* 输出你的user的值 */
	if (cachep->flags & SLAB_STORE_USER) {
		pr_err("Last user: [<%p>](%pSR)\n",
		       *dbg_userword(cachep, objp),
		       *dbg_userword(cachep, objp));
	}
	/* 拿到你真实的对象 */
	realobj = (char *)objp + obj_offset(cachep);
	/* 拿到你对象的大小 */
	size = cachep->object_size;
	for (i = 0; i < size && lines; i += 16, lines--) {
		int limit;
		limit = 16;
		if (i + limit > size)
			limit = size - i;
		dump_line(realobj, i, limit);
	}
}

static void check_poison_obj(struct kmem_cache *cachep, void *objp)
{
	char *realobj;
	int size, i;
	int lines = 0;

	if (is_debug_pagealloc_cache(cachep))
		return;

	/* 找到对象真正的地址 */
	realobj = (char *)objp + obj_offset(cachep);
	/* 找到对象的大小 */
	size = cachep->object_size;

	for (i = 0; i < size; i++) {
		char exp = POISON_FREE;
		/* 对象的最后一个字节是POISON_END */
		if (i == size - 1)
			exp = POISON_END;
		/* 判断他有没有被踩 */
		if (realobj[i] != exp) {
			int limit;

			/* 下面是一个输出的例子
			 *
			 * Slab corruption (Not tainted): kmalloc-2k start=ffff9504c58ab800, len=2048
			 * 420: 6b 6b 6b 6b 64 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b  kkkkdkkkkkkkkkkk
			 * Prev obj: start=ffff9504c58ab000, len=2048
			 * 000: 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b  kkkkkkkkkkkkkkkk
			 * 010: 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b  kkkkkkkkkkkkkkkk
			 */
			/* Mismatch ! */
			/* Print header */
			/* 这里说的第一行,输出头 */
			if (lines == 0) {
				pr_err("Slab corruption (%s): %s start=%p, len=%d\n",
				       print_tainted(), cachep->name,
				       realobj, size);
				print_objinfo(cachep, objp, 0);
			}
			/* Hexdump the affected line
			 * Hexdump 被污染的行
			 */
			/* 这里实际上是获取它的行数,你看前面的输出就知道了,一行16个字节 */
			i = (i / 16) * 16;
			limit = 16;
			/* 如果 i + limit 大于对象的大小,那就说明它最后不足一行,那么limit就设置为你最后一行的大小 */
			if (i + limit > size)
				limit = size - i;
			dump_line(realobj, i, limit);
			i += 16;
			lines++;
			/* Limit to 5 lines */
			/* 最多输出5行 */
			if (lines > 5)
				break;
		}
	}

	/* 如果lines != 0 说明有些数据烂了 */
	if (lines != 0) {
		/* Print some data about the neighboring objects, if they
		 * exist:
		 *
		 * 打印有关相邻对象的一些数据(如果存在):
		 */

		/* 拿到这个page */
		struct page *page = virt_to_head_page(objp);
		unsigned int objnr;

		/* 算出这个对象的index */
		objnr = obj_to_index(cachep, page, objp);
		/* 如果为0,那就没有Prev obj,否则就打印前置对象的2行 */
		if (objnr) {
			objp = index_to_obj(cachep, page, objnr - 1);
			realobj = (char *)objp + obj_offset(cachep);
			pr_err("Prev obj: start=%p, len=%d\n", realobj, size);
			print_objinfo(cachep, objp, 2);
		}
		/* 如果有 打印出后置对象 */
		if (objnr + 1 < cachep->num) {
			objp = index_to_obj(cachep, page, objnr + 1);
			realobj = (char *)objp + obj_offset(cachep);
			pr_err("Next obj: start=%p, len=%d\n", realobj, size);
			print_objinfo(cachep, objp, 2);
		}
	}
}
#endif

#if DEBUG
static void slab_destroy_debugcheck(struct kmem_cache *cachep,
						struct page *page)
{
	int i;
	/* #define	OBJFREELIST_SLAB(x)	((x)->flags & CFLGS_OBJFREELIST_SLAB)
	 * 对于OBJFREELIST_SLAB的SLAB,freelist是用了最后一个对象来存储的
	 *
	 * 如果freelist不是随机化的,并且是OBJFREELIST_SLAB
	 *	if (!shuffled && OBJFREELIST_SLAB(cachep)) {
	 *		page->freelist就是最后一个对象的起始地址,obj_offset是说的对象的偏移,因为对象前后还有redzone这些
	 *			page->freelist = index_to_obj(cachep, page, cachep->num - 1) + obj_offset(cachep);
	 * }
	 *
	 * 所以page->freelist - obj_offset(cachep),即把最后一个对象的内容填充为POISON_FREE
	 * #define POISON_FREE	0x6b	for use-after-free poisoning
	 */
	if (OBJFREELIST_SLAB(cachep) && cachep->flags & SLAB_POISON) {
		poison_obj(cachep, page->freelist - obj_offset(cachep),
			POISON_FREE);
	}

	/* 然后对这个cachep里面所有的对象进行检查 */
	for (i = 0; i < cachep->num; i++) {
		/* 找到该对象的地址 */
		void *objp = index_to_obj(cachep, page, i);

		/* 如果有SLAB_POISON,那么就开始检查 */
		if (cachep->flags & SLAB_POISON) {
			check_poison_obj(cachep, objp);
			slab_kernel_map(cachep, objp, 1, 0);
		}
		if (cachep->flags & SLAB_RED_ZONE) {
			if (*dbg_redzone1(cachep, objp) != RED_INACTIVE)
				slab_error(cachep, "start of a freed object was overwritten");
			if (*dbg_redzone2(cachep, objp) != RED_INACTIVE)
				slab_error(cachep, "end of a freed object was overwritten");
		}
	}
}
#else
static void slab_destroy_debugcheck(struct kmem_cache *cachep,
						struct page *page)
{
}
#endif

/**
 * slab_destroy - destroy and release all objects in a slab
 * @cachep: cache pointer being destroyed
 * @page: page pointer being destroyed
 *
 * Destroy all the objs in a slab page, and release the mem back to the system.
 * Before calling the slab page must have been unlinked from the cache. The
 * kmem_cache_node ->list_lock is not held/needed.
 *
 * slab_destroy-销毁并释放slab中的所有对象
 * @cachep: 将要销毁的cache指针
 * @page: 将要销毁的page指针
 *
 * 销毁slab页面中的所有obj,然后将mem释放回系统.
 * 在调用slab之前,页面必须从cache中取消link.
 * kmem_cache_node->list_lock未保存/不需要。
 */
static void slab_destroy(struct kmem_cache *cachep, struct page *page)
{
	void *freelist;

	freelist = page->freelist;
	slab_destroy_debugcheck(cachep, page);
	/* 如果flags没有带SSLAB_DESTROY_BY_RCULAB_DESTROY_BY_RCU
	 *
	 * #define SLAB_DESTROY_BY_RCU  0x00080000UL Defer freeing slabs to RCU(将释放slab推迟到RCU)
	 *
	 * 或者cachep有构造函数,那么返回false
	 */
	if (unlikely(cachep->flags & SLAB_DESTROY_BY_RCU))
		call_rcu(&page->rcu_head, kmem_rcu_free);
	else
		kmem_freepages(cachep, page);

	/*
	 * From now on, we don't use freelist
	 * although actual page can be freed in rcu context
	 */

	/* #define	OFF_SLAB(x)	((x)->flags & CFLGS_OFF_SLAB)
	 * 如果freelist在外面,那么释放它
	 */
	if (OFF_SLAB(cachep))
		kmem_cache_free(cachep->freelist_cache, freelist);
}

static void slabs_destroy(struct kmem_cache *cachep, struct list_head *list)
{
	struct page *page, *n;
	/* 对于这个链表里面的每个成员,首先把该page从该lru里面删除,然后销毁这个slab */
	list_for_each_entry_safe(page, n, list, lru) {
		list_del(&page->lru);
		slab_destroy(cachep, page);
	}
}

/**
 * calculate_slab_order - calculate size (page order) of slabs
 * @cachep: pointer to the cache that is being created
 * @size: size of objects to be created in this cache.
 * @flags: slab allocation flags
 *
 * Also calculates the number of objects per slab.
 *
 * This could be made much more intelligent.  For now, try to avoid using
 * high order pages for slabs.  When the gfp() functions are more friendly
 * towards high-order requests, this should be changed.
 *
 * calculate_slab_order - 计算slab的大小(page order)
 * @cachep: 指向正在创建的缓存的指针
 * @size: 要在此缓存中创建的对象的大小。
 * @标志: slab分配标志
 *
 * 也计算每个slab的对象数.
 *
 * 这可以变得更加智能.
 * 目前,请尽量避免对slab使用高阶页面.
 * 当gfp()函数对高阶请求更友好时,才对此进行更改。
 */
static size_t calculate_slab_order(struct kmem_cache *cachep,
				size_t size, unsigned long flags)
{
	size_t left_over = 0;
	int gfporder;

	for (gfporder = 0; gfporder <= KMALLOC_MAX_ORDER; gfporder++) {
		unsigned int num;
		size_t remainder;

		/* cache_estimate计算在 2 ^ gfporder个页面大小的情况下,可以容纳多少个obj对象,然后剩下的空间用于cache colour着色 */
		num = cache_estimate(gfporder, size, flags, &remainder);
		/* 如果一个都分配不出来,那么continue */
		if (!num)
			continue;

		/* Can't handle number of objects more than SLAB_OBJ_MAX_NUM
		 * 无法处理超过SLAB_OBJ_MAX_NUM的对象数
		 *
		 * #define SLAB_OBJ_MAX_NUM ((1 << sizeof(freelist_idx_t) * BITS_PER_BYTE) - 1)
		 */
		if (num > SLAB_OBJ_MAX_NUM)
			break;

		/* 如果flags设置了CFLGS_OFF_SLAB,也就是说freelist_idx_t在slab的外面 */
		if (flags & CFLGS_OFF_SLAB) {
			struct kmem_cache *freelist_cache;
			size_t freelist_size;

			/* 算出freelist_size的大小 */
			freelist_size = num * sizeof(freelist_idx_t);
			freelist_cache = kmalloc_slab(freelist_size, 0u);
			if (!freelist_cache)
				continue;

			/*
			 * Needed to avoid possible looping condition
			 * in cache_grow_begin()
			 */

			/* #define	OFF_SLAB(x)	((x)->flags & CFLGS_OFF_SLAB) */
			if (OFF_SLAB(freelist_cache))
				continue;

			/* check if off slab has enough benefit
			 * 检查off slab是否有足够的好处
			 */
			if (freelist_cache->size > cachep->size / 2)
				continue;
		}

		/* Found something acceptable - save it away
		 * 找到可以接受的东西 - 保存起来
		 */
		cachep->num = num;
		cachep->gfporder = gfporder;
		left_over = remainder;

		/*
		 * A VFS-reclaimable slab tends to have most allocations
		 * as GFP_NOFS and we really don't want to have to be allocating
		 * higher-order pages when we are unable to shrink dcache.
		 *
		 * A VFS-reclaimable slab往往大多数分配都具有GFP_NOFS,并且当我们无法回收dcache时,我们真的不希望必须分配更高阶的页面
		 */

		/* 使用SLAB_RECLAIM_ACCOUNT标志创建的内存缓存,宣称可回收,dentry和inode缓存应该属于这种情况 */
		if (flags & SLAB_RECLAIM_ACCOUNT)
			break;

		/*
		 * Large number of objects is good, but very large slabs are
		 * currently bad for the gfp()s.
		 *
		 * 大量的对象是好的,但是非常大的slabs对gfp()s当前是坏的
		 */

		/* 如果gfporder 大于等于slab_max_order,那么退出 */
		if (gfporder >= slab_max_order)
			break;

		/*
		 * Acceptable internal fragmentation?
		 *
		 * 可接受的内部碎片?
		 */

		/* 如果left_over * 8 <= PAGE_SIZE << gfporder,那么也break */
		if (left_over * 8 <= (PAGE_SIZE << gfporder))
			break;
	}
	return left_over;
}

static struct array_cache __percpu *alloc_kmem_cache_cpus(
		struct kmem_cache *cachep, int entries, int batchcount)
{
	int cpu;
	size_t size;
	struct array_cache __percpu *cpu_cache;

	size = sizeof(void *) * entries + sizeof(struct array_cache);
	/* 分配percpu内存,大小为size,align为sizeof(void *) */
	cpu_cache = __alloc_percpu(size, sizeof(void *));
	/* 如果cpu_cache为NULL,那么返回NULL */
	if (!cpu_cache)
		return NULL;

	/* 对每个CPU,初始化array_cache */
	for_each_possible_cpu(cpu) {
		init_arraycache(per_cpu_ptr(cpu_cache, cpu),
				entries, batchcount);
	}

	/* 返回cpu_cache */
	return cpu_cache;
}

static int __ref setup_cpu_cache(struct kmem_cache *cachep, gfp_t gfp)
{
	/* 如果slab_state是FULL,那么slab机制已经初始化完成 */
	if (slab_state >= FULL)
		return enable_cpucache(cachep, gfp);

	cachep->cpu_cache = alloc_kmem_cache_cpus(cachep, 1, 1);
	if (!cachep->cpu_cache)
		return 1;

	if (slab_state == DOWN) {
		/* Creation of first cache (kmem_cache). */
		set_up_node(kmem_cache, CACHE_CACHE);
	} else if (slab_state == PARTIAL) {
		/* For kmem_cache_node */
		set_up_node(cachep, SIZE_NODE);
	} else {
		int node;

		for_each_online_node(node) {
			cachep->node[node] = kmalloc_node(
				sizeof(struct kmem_cache_node), gfp, node);
			BUG_ON(!cachep->node[node]);
			kmem_cache_node_init(cachep->node[node]);
		}
	}

	cachep->node[numa_mem_id()]->next_reap =
			jiffies + REAPTIMEOUT_NODE +
			((unsigned long)cachep) % REAPTIMEOUT_NODE;

	cpu_cache_get(cachep)->avail = 0;
	cpu_cache_get(cachep)->limit = BOOT_CPUCACHE_ENTRIES;
	cpu_cache_get(cachep)->batchcount = 1;
	cpu_cache_get(cachep)->touched = 0;
	cachep->batchcount = 1;
	cachep->limit = BOOT_CPUCACHE_ENTRIES;
	return 0;
}

unsigned long kmem_cache_flags(unsigned long object_size,
	unsigned long flags, const char *name,
	void (*ctor)(void *))
{
	return flags;
}

struct kmem_cache *
__kmem_cache_alias(const char *name, size_t size, size_t align,
		   unsigned long flags, void (*ctor)(void *))
{
	struct kmem_cache *cachep;
	/* 在全局 slab cache 链表中查找与当前创建参数相匹配的 slab cache
	 * 如果在全局查找到一个  slab cache，它的核心参数和我们指定的创建参数很贴近
	 * 那么就没必要再创建新的 slab cache了，复用已有的slab cache
	 */
	cachep = find_mergeable(size, align, flags, name, ctor);
	if (cachep) {
		/* 如果存在可复用的 kmem_cache，则将它的引用计数 + 1 */
		cachep->refcount++;

		/*
		 * Adjust the object sizes so that we clear
		 * the complete object on kzalloc.
		 *
		 * 调整对象大小,以便清除kzalloc上的完整对象.
		 */

		/* cachep->object_size是cachep->object_size和size的最大值 */
		cachep->object_size = max_t(int, cachep->object_size, size);
	}
	return cachep;
}

static bool set_objfreelist_slab_cache(struct kmem_cache *cachep,
			size_t size, unsigned long flags)
{
	size_t left;

	cachep->num = 0;

	/* 如果flags没有带SSLAB_DESTROY_BY_RCULAB_DESTROY_BY_RCU
	 *
	 * #define SLAB_DESTROY_BY_RCU  0x00080000UL Defer freeing slabs to RCU(将释放slab推迟到RCU)
	 *
	 * 或者cachep有构造函数,那么返回false
	 */
	if (cachep->ctor || flags & SLAB_DESTROY_BY_RCU)
		return false;

	/* 带着CFLGS_OBJFREELIST_SLAB标志去计算看看需要多少个page,以及有多少个colour */
	left = calculate_slab_order(cachep, size,
			flags | CFLGS_OBJFREELIST_SLAB);
	if (!cachep->num)
		return false;

	/* 如果cachep->num * sizeof(freelist_idx_t) > 对象的实际大小,那么返回false */
	if (cachep->num * sizeof(freelist_idx_t) > cachep->object_size)
		return false;

	/* 算出有多少个colour */
	cachep->colour = left / cachep->colour_off;

	return true;
}

static bool set_off_slab_cache(struct kmem_cache *cachep,
			size_t size, unsigned long flags)
{
	size_t left;

	/* 设置cachep->num(num表示slab的数量)为0 */
	cachep->num = 0;

	/*
	 * Always use on-slab management when SLAB_NOLEAKTRACE
	 * to avoid recursive calls into kmemleak.
	 *
	 * 当SLAB_NOLEAKTRACE,始终使用on-slab 管理,以避免对kmemleak的递归调用.
	 */
	if (flags & SLAB_NOLEAKTRACE)
		return false;

	/*
	 * Size is large, assume best to place the slab management obj
	 * off-slab (should allow better packing of objs).
	 *
	 * size比较大,假设最好将slab management 对象放置在off-slab(应允许更好地包装对象).
	 */

	/* 把flags带着CFLGS_OFF_SLAB去算一下,看看有多少个colour区域 */
	left = calculate_slab_order(cachep, size, flags | CFLGS_OFF_SLAB);
	/* 如果cachep->num等于0,那么直接返回false */
	if (!cachep->num)
		return false;

	/*
	 * If the slab has been placed off-slab, and we have enough space then
	 * move it on-slab. This is at the expense of any extra colouring.
	 *
	 * 如果slab已放置在off-slab,并且我们有足够的空间,移动它到on-slab.这是以牺牲任何额外的colouring为代价的.
	 */
	if (left >= cachep->num * sizeof(freelist_idx_t))
		return false;

	/* cachep->colour(表示一个slab有多少个不同的cache line)
	 * cachep->colour_off表示一个cache colour的长度,和L1 cache line大小相同
	 */
	cachep->colour = left / cachep->colour_off;

	return true;
}

static bool set_on_slab_cache(struct kmem_cache *cachep,
			size_t size, unsigned long flags)
{
	size_t left;

	cachep->num = 0;

	left = calculate_slab_order(cachep, size, flags);
	if (!cachep->num)
		return false;

	cachep->colour = left / cachep->colour_off;

	return true;
}

/**
 * __kmem_cache_create - Create a cache.
 * @cachep: cache management descriptor
 * @flags: SLAB flags
 *
 * Returns a ptr to the cache on success, NULL on failure.
 * Cannot be called within a int, but can be interrupted.
 * The @ctor is run when new pages are allocated by the cache.
 *
 * The flags are
 *
 * %SLAB_POISON - Poison the slab with a known test pattern (a5a5a5a5)
 * to catch references to uninitialised memory.
 *
 * %SLAB_RED_ZONE - Insert `Red' zones around the allocated memory to check
 * for buffer overruns.
 *
 * %SLAB_HWCACHE_ALIGN - Align the objects in this cache to a hardware
 * cacheline.  This can be beneficial if you're counting cycles as closely
 * as davem.
 *
 * __kmem_cache_create - 创建缓存.
 * @cachep:缓存管理描述符
 * @标志：SLAB标志
 *
 * 成功时返回一个指向cache的指针,失败时返回NULL.
 * 不能在int(中断?)中调用,但可以被中断.
 * 当cache分配新页面时,@ctor将运行.
 *
 * 标志是
 *
 * %SLAB_POISON - 用已知的测试pattern(a5a5a5a5)污染slab,以捕获对未初始化内存的引用.
 *
 * %SLAB_RED_ZONE - 在分配的内存周围插入“Red”区域,以检查缓冲区是否溢出.
 *
 * %SLAB_HWCACHE_ALIGN - 将此缓存中的对象与硬件cacheline对齐.如果你像davem一样仔细地计算周期,这可能是有益的.
 */
int
__kmem_cache_create (struct kmem_cache *cachep, unsigned long flags)
{
	size_t ralign = BYTES_PER_WORD;
	gfp_t gfp;
	int err;
	size_t size = cachep->size;

#if DEBUG
#if FORCED_DEBUG
	/*
	 * Enable redzoning and last user accounting, except for caches with
	 * large objects, if the increased size would increase the object size
	 * above the next power of two: caches with object sizes just above a
	 * power of two have a significant amount of internal fragmentation.
	 *
	 * 使能redzoning和最后用户计数,除了大对象的cahce之外,如果增加大小将增加
	 * 对象大小得到2次幂以上.
	 * 对象大小略高于二次幂的缓存具有大量内部碎片.
	 */

	/*
	 * fls - find last (most-significant) bit set
	 * @x: the word to search
	 *
	 * This is defined the same way as ffs.
	 * Note fls(0) = 0, fls(1) = 1, fls(0x80000000) = 32.
	 */

	/* 如果size < 4096 或者说size - 1的最后一个被设置的bit = size - 1 + REDZONE_ALIGN + 2*sizeof(unsigned long long)
	 * #define	REDZONE_ALIGN	max(BYTES_PER_WORD, __alignof__(unsigned long long))
	 */
	if (size < 4096 || fls(size - 1) == fls(size-1 + REDZONE_ALIGN +
						2 * sizeof(unsigned long long)))
		flags |= SLAB_RED_ZONE | SLAB_STORE_USER;
	/* 如果flags没有带SLAB_DESTROY_BY_RCU
	 *
	 * #define SLAB_DESTROY_BY_RCU	0x00080000UL Defer freeing slabs to RCU(将释放slab推迟到RCU)
	 * 那么将flags带上SLAB_POISON
	 * #define SLAB_POISON		0x00000800UL	DEBUG: Poison objects
	 */
	if (!(flags & SLAB_DESTROY_BY_RCU))
		flags |= SLAB_POISON;
#endif
#endif

	/*
	 * Check that size is in terms of words.  This is needed to avoid
	 * unaligned accesses for some archs when redzoning is used, and makes
	 * sure any on-slab bufctl's are also correctly aligned.
	 *
	 * 检查大小是否和系统中的word长度对齐.
	 * 当使用redzoning时,这是为了避免某些arch的未对齐访问,并确保on-slab bufctl's 也正确对齐.
	 */

	/* 检查size是否和系统的word字节对齐(BYTES_PER_WORD).
	 * 如果size & (BYTES_PER_WORD - 1 ) 不为0,说明没有对齐 */
	if (size & (BYTES_PER_WORD - 1)) {
		/* 那么让size += (BYTES_PER_WORD -1) */
		size += (BYTES_PER_WORD - 1);
		/* 然后再让它与BYTES_PER_WORD对齐,实际上就是让他与BYTES_PER_WORD,没对齐那么就向上
		 * 加一个BYTES_PER_WORD - 1 之后对齐 */
		size &= ~(BYTES_PER_WORD - 1);
	}

	/* 如果flags里面有SLAB_RED_ZONE,那么就让size和REDZONE对齐 */
	if (flags & SLAB_RED_ZONE) {
		/* #define	REDZONE_ALIGN	max(BYTES_PER_WORD, __alignof__(unsigned long long)) */
		ralign = REDZONE_ALIGN;
		/* If redzoning, ensure that the second redzone is suitably
		 * aligned, by adjusting the object size accordingly.
		 *
		 * 如果是redzoning,通过相应地调整对象大小,确保第二个红色区域适当对齐
		 */
		size += REDZONE_ALIGN - 1;
		size &= ~(REDZONE_ALIGN - 1);
	}

	/* 3) caller mandated alignment
	 * 调用者强制对齐
	 */

	/* 如果ralign比cachep->align要小,那么ralign = cachep->align */
	if (ralign < cachep->align) {
		ralign = cachep->align;
	}
	/* disable debug if necessary
	 * 如果需要屏蔽debug
	 */

	/* 如果对齐大于8字节就关闭SLAB_RED_ZONE | SLAB_STORE_USER ? */
	if (ralign > __alignof__(unsigned long long))
		flags &= ~(SLAB_RED_ZONE | SLAB_STORE_USER);
	/*
	 * 4) Store it.
	 */
	/* 设置cachep->aligh为我们算出来的ralign */
	cachep->align = ralign;
	/* 将colour_off赋值为L1 cache line的大小 */
	cachep->colour_off = cache_line_size();
	/* Offset must be a multiple of the alignment.
	 * 偏移必须是对齐的倍数
	 */

	/* 如果colour_off比cachep->align还小,那么把cachep->align赋值给cachep->colour_off */
	if (cachep->colour_off < cachep->align)
		cachep->colour_off = cachep->align;

	/* 枚举类型slab_state用来表示slab系统中的状态,例如DOWN、PARTIAL、PARTIAL_NODE、UP、FULL等
	 * 当slab机制完全初始化完成后状态变成FULL.
	 * slab_is_available表示slab状态在UP或者FULL时,分配掩码可以使用GFP_KERNEL,否则只能使用GFP_NOWAIT
	 */
	if (slab_is_available())
		gfp = GFP_KERNEL;
	else
		gfp = GFP_NOWAIT;

#if DEBUG

	/*
	 * Both debugging options require word-alignment which is calculated
	 * into align above.
	 *
	 * 这两个debugging选项都需要word-alignment,这在上面计算为对齐。
	 */

	/* 如果flags带有SLAB_RED_ZONE
	 *  _____________________________________________
	 * |  red zone |     object size      |	red zone |
	 * |__0xbb_____|______________________|__________|
	 *
	 */

	/* 内核为了应对内存读写越界的场景,于是在对象内存的周围插入了一段不可访问的内存区域,
	 * 这些内存区域用特定的字节0xbb填充,当进程访问的到内存是 0xbb 时,表示已经越界访问了.
	 * 这段内存区域在 slab 中的术语为 red zone,大家可以理解为红色警戒区域.
	 */
	if (flags & SLAB_RED_ZONE) {
		/* add space for red zone words
		 * 为red zone words 添加空间
		 *
		 * 所以这里是为前后都添加red zone,大小都为sizeof(unsigned long long)
		 */
		cachep->obj_offset += sizeof(unsigned long long);
		size += 2 * sizeof(unsigned long long);
	}

	/* 当flags设置了SLAB_STORE_USER时,表示需要追踪对象的分配和释放相关信息,
	 * 这样会在slab对象内存区域中额外增加两个sizeof(struct track)大小的区域出来,
	 * 用于存储 slab 对象的分配和释放信息.
	 *
	 *  _____________________________________________________________________
	 * |    red zone |      object size    |    red zone  |  track  | track  |
	 * |_____________|_____________________|______________|_________|________|
	 *
	 */
	if (flags & SLAB_STORE_USER) {
		/* user store requires one word storage behind the end of
		 * the real object. But if the second red zone needs to be
		 * aligned to 64 bits, we must allow that much space.
		 *
		 * 用户存储需要在真实对象的末尾后面存储一个word.
		 * 但是如果第二个红色区域需要对齐到64位,我们必须允许那么多空间.
		 */

		/* 如果flag里面有SLAB_RED_ZONE,那么size还需要加上REDZONE_ALIGN
		 *
		 * 否则 size += BYTES_PER_WORD
		 */
		if (flags & SLAB_RED_ZONE)
			size += REDZONE_ALIGN;
		else
			size += BYTES_PER_WORD;
	}
#endif

	kasan_cache_create(cachep, &size, &flags);

	/* 前面给size加了东西,这里重新对齐一下 */
	size = ALIGN(size, cachep->align);
	/*
	 * We should restrict the number of objects in a slab to implement
	 * byte sized index. Refer comment on SLAB_OBJ_MIN_SIZE definition.
	 *
	 * 我们应该限制slab中对象的数量,以实现字节大小的索引.请参阅SLAB_OBJ_MIN_SIZE定义的注释
	 */
	if (FREELIST_BYTE_INDEX && size < SLAB_OBJ_MIN_SIZE)
		size = ALIGN(SLAB_OBJ_MIN_SIZE, cachep->align);

#if DEBUG
	/*
	 * To activate debug pagealloc, off-slab management is necessary
	 * requirement. In early phase of initialization, small sized slab
	 * doesn't get initialized so it would not be possible. So, we need
	 * to check size >= 256. It guarantees that all necessary small
	 * sized slab is initialized in current slab initialization sequence.
	 *
	 * 为了激活debug pagealloc,off-slab 管理是必要的要求.
	 * 在初始化的早期阶段,小型的slab不会被初始化,所以这是不可能的.
	 * 因此,我们需要检查大小>=256.它保证所有必要的小尺寸slab在当前slab初始化序列中初始化.
	 */

	/* 如果_debug_pagealloc_enabled被设置,并且flags里面有SLAB_POISON
	 * 或者size >=256,并且cachep->object_size > cache_line_size()
	 */
	if (debug_pagealloc_enabled() && (flags & SLAB_POISON) &&
		size >= 256 && cachep->object_size > cache_line_size()) {
		/* 如果size < PAGE_SIZE或者是PAGE_SIZE的倍数 */
		if (size < PAGE_SIZE || size % PAGE_SIZE == 0) {
			/* 将size和PAGE_SIZE 对齐 */
			size_t tmp_size = ALIGN(size, PAGE_SIZE);
			/* 这里看看要不要把freelist_idx_t设置到slab cache的外面,返回true表示需要 */
			if (set_off_slab_cache(cachep, tmp_size, flags)) {
				/* 把flags带上CFLGS_OFF_SLAB */
				flags |= CFLGS_OFF_SLAB;
				/* 算出对象的偏移 */
				cachep->obj_offset += tmp_size - size;
				/* size = tmp_size */
				size = tmp_size;
				goto done;
			}
		}
	}
#endif

	/* OBJFREELIST_SLAB模式.
	 * 这是Linux 4.6内核新增的—个优化,其目的是高效利用slab分配器中的内存.
	 * 使用slab分配器中最后一个slab对象的空间作为管理区，如下图所示
	 *
	 *  ______________________________________________________________________________________
	 * |    colour 	 |     colour   | ...... | obj  | obj  | obj |...... | obj      |剩余空间 |
	 * |_____________|______________|________|______|______|_____|_______|__________|_________|
	 * ↑                                     ↑                           ↑          ↑         ↑
	 * |                                     |                           |          |         |
	 * |---------------管理区----------------|--------num个对象----------|-freelist-|         |
	 * |                                                                                      |
	 * |-------------------------------2的gfporder个对象--------------------------------------|
	 *
	 *
	 * off_slab模式
	 *  ______________________________________________________________________________________
	 * |    colour 	 |     colour   | ...... | obj  | obj  | obj |...... | obj      |剩余空间 |
	 * |_____________|______________|________|______|______|_____|_______|__________|_________|
	 * ↑                                     ↑                                      ↑         ↑
	 * |                                     |                                      |         |
	 * |---------------管理区----------------|--------num个对象---------------------|         |
	 * |                                                                                      |
	 * |-------------------------------2的gfporder个对象--------------------------------------|
	 *
	 *			 ________________
	 *                      |		 |
	 *			|    freelist	 |
	 *			|________________|
	 *			额外分配的空间作为管理区
	 *
	 *
	 *
	 *
	 * 正常模式.传统的布局模式，如下图所示:
	 *  ____________________________________________________________________________
	 * |    colour 	 |     colour   | ...... | obj  | obj  | obj |...... | obj      |
	 * |_____________|______________|________|______|______|_____|_______|__________|
	 * ↑                                     ↑                           ↑          ↑
	 * |                                     |                           |          |
	 * |---------------管理区----------------|--------num个对象----------|----------|
	 * |                                                                            |
	 * |-------------------------------2的gfporder个对象----------------------------|
	 *
	 */


	/* 这里需要注意,freelist用于管理对应order的page中分出来的大小为size的每个片段索引号,
	 * objfreelist,off slab,on slab三者只用其中一个,优先考虑objfreelist,然后是off slab,最后是on slab
	 */
	/* 如果set_objfreelist_slab_cache返回true,那么就带上CFLGS_OBJFREELIST_SLAB */
	if (set_objfreelist_slab_cache(cachep, size, flags)) {
		flags |= CFLGS_OBJFREELIST_SLAB;
		goto done;
	}

	/* 这里看看要不要把freelist_idx_t设置到slab cache的外面,返回true表示需要 */
	if (set_off_slab_cache(cachep, size, flags)) {
		flags |= CFLGS_OFF_SLAB;
		goto done;
	}
	/* 这里就是把freelist_idx_t放到slab里面 */
	if (set_on_slab_cache(cachep, size, flags))
		goto done;

	return -E2BIG;

done:
	/* 每个对象需要一个字节来存放freelist_idx_t,这里算出freelist_size */
	cachep->freelist_size = cachep->num * sizeof(freelist_idx_t);
	/* 将flag设置进cachep->flags */
	cachep->flags = flags;
	cachep->allocflags = __GFP_COMP;
	if (flags & SLAB_CACHE_DMA)
		cachep->allocflags |= GFP_DMA;
	cachep->size = size;
	/* slab对象的大小的倒数，计算对象在slab中索引时用，参见obj_to_index函数 */
	cachep->reciprocal_buffer_size = reciprocal_value(size);

#if DEBUG
	/*
	 * If we're going to use the generic kernel_map_pages()
	 * poisoning, then it's going to smash the contents of
	 * the redzone and userword anyhow, so switch them off.
	 *
	 * 如果我们要使用通用的kernel_map_pages的poisoning,那么它无论如何都会破坏redzone和userword的内容,所以请关闭它们。
	 */

	/* 如果开了CONFIG_PAGE_POISONING并且cachep->flags & SLAB_POISON
	 * 并且is_debug_pagealloc_cache
	 * 那么把SLAB_RED_ZONE和SLAB_STORE_USER都关闭
	 */
	if (IS_ENABLED(CONFIG_PAGE_POISONING) &&
		(cachep->flags & SLAB_POISON) &&
		is_debug_pagealloc_cache(cachep))
		cachep->flags &= ~(SLAB_RED_ZONE | SLAB_STORE_USER);
#endif

	/* 如果OFF_SLAB,那么算出freelist_size需要哪个kmalloc_slab */
	if (OFF_SLAB(cachep)) {
		cachep->freelist_cache =
			kmalloc_slab(cachep->freelist_size, 0u);
	}

	/* 调用setup_cpu_cache函数来继续配置slab描述符 */
	err = setup_cpu_cache(cachep, gfp);
	if (err) {
		__kmem_cache_release(cachep);
		return err;
	}

	return 0;
}

#if DEBUG
static void check_irq_off(void)
{
	BUG_ON(!irqs_disabled());
}

static void check_irq_on(void)
{
	BUG_ON(irqs_disabled());
}

static void check_mutex_acquired(void)
{
	BUG_ON(!mutex_is_locked(&slab_mutex));
}

static void check_spinlock_acquired(struct kmem_cache *cachep)
{
#ifdef CONFIG_SMP
	check_irq_off();
	assert_spin_locked(&get_node(cachep, numa_mem_id())->list_lock);
#endif
}

static void check_spinlock_acquired_node(struct kmem_cache *cachep, int node)
{
#ifdef CONFIG_SMP
	check_irq_off();
	assert_spin_locked(&get_node(cachep, node)->list_lock);
#endif
}

#else
#define check_irq_off()	do { } while(0)
#define check_irq_on()	do { } while(0)
#define check_mutex_acquired()	do { } while(0)
#define check_spinlock_acquired(x) do { } while(0)
#define check_spinlock_acquired_node(x, y) do { } while(0)
#endif

static void drain_array_locked(struct kmem_cache *cachep, struct array_cache *ac,
				int node, bool free_all, struct list_head *list)
{
	int tofree;

	if (!ac || !ac->avail)
		return;

	tofree = free_all ? ac->avail : (ac->limit + 4) / 5;
	if (tofree > ac->avail)
		tofree = (ac->avail + 1) / 2;

	free_block(cachep, ac->entry, tofree, node, list);
	ac->avail -= tofree;
	memmove(ac->entry, &(ac->entry[tofree]), sizeof(void *) * ac->avail);
}

static void do_drain(void *arg)
{
	struct kmem_cache *cachep = arg;
	struct array_cache *ac;
	int node = numa_mem_id();
	struct kmem_cache_node *n;
	LIST_HEAD(list);

	check_irq_off();
	ac = cpu_cache_get(cachep);
	n = get_node(cachep, node);
	spin_lock(&n->list_lock);
	free_block(cachep, ac->entry, ac->avail, node, &list);
	spin_unlock(&n->list_lock);
	slabs_destroy(cachep, &list);
	ac->avail = 0;
}

static void drain_cpu_caches(struct kmem_cache *cachep)
{
	struct kmem_cache_node *n;
	int node;
	LIST_HEAD(list);

	on_each_cpu(do_drain, cachep, 1);
	check_irq_on();
	for_each_kmem_cache_node(cachep, node, n)
		if (n->alien)
			drain_alien_cache(cachep, n->alien);

	for_each_kmem_cache_node(cachep, node, n) {
		spin_lock_irq(&n->list_lock);
		drain_array_locked(cachep, n->shared, node, true, &list);
		spin_unlock_irq(&n->list_lock);

		slabs_destroy(cachep, &list);
	}
}

/*
 * Remove slabs from the list of free slabs.
 * Specify the number of slabs to drain in tofree.
 *
 * Returns the actual number of slabs released.
 */
static int drain_freelist(struct kmem_cache *cache,
			struct kmem_cache_node *n, int tofree)
{
	struct list_head *p;
	int nr_freed;
	struct page *page;

	nr_freed = 0;
	while (nr_freed < tofree && !list_empty(&n->slabs_free)) {

		spin_lock_irq(&n->list_lock);
		p = n->slabs_free.prev;
		if (p == &n->slabs_free) {
			spin_unlock_irq(&n->list_lock);
			goto out;
		}

		page = list_entry(p, struct page, lru);
		list_del(&page->lru);
		n->num_slabs--;
		/*
		 * Safe to drop the lock. The slab is no longer linked
		 * to the cache.
		 */
		n->free_objects -= cache->num;
		spin_unlock_irq(&n->list_lock);
		slab_destroy(cache, page);
		nr_freed++;
	}
out:
	return nr_freed;
}

int __kmem_cache_shrink(struct kmem_cache *cachep)
{
	int ret = 0;
	int node;
	struct kmem_cache_node *n;

	drain_cpu_caches(cachep);

	check_irq_on();
	for_each_kmem_cache_node(cachep, node, n) {
		drain_freelist(cachep, n, INT_MAX);

		ret += !list_empty(&n->slabs_full) ||
			!list_empty(&n->slabs_partial);
	}
	return (ret ? 1 : 0);
}

int __kmem_cache_shutdown(struct kmem_cache *cachep)
{
	return __kmem_cache_shrink(cachep);
}

void __kmem_cache_release(struct kmem_cache *cachep)
{
	int i;
	struct kmem_cache_node *n;

	cache_random_seq_destroy(cachep);

	free_percpu(cachep->cpu_cache);

	/* NUMA: free the node structures */
	for_each_kmem_cache_node(cachep, i, n) {
		kfree(n->shared);
		free_alien_cache(n->alien);
		kfree(n);
		cachep->node[i] = NULL;
	}
}

/*
 * Get the memory for a slab management obj.
 *
 * For a slab cache when the slab descriptor is off-slab, the
 * slab descriptor can't come from the same cache which is being created,
 * Because if it is the case, that means we defer the creation of
 * the kmalloc_{dma,}_cache of size sizeof(slab descriptor) to this point.
 * And we eventually call down to __kmem_cache_create(), which
 * in turn looks up in the kmalloc_{dma,}_caches for the disired-size one.
 * This is a "chicken-and-egg" problem.
 *
 * So the off-slab slab descriptor shall come from the kmalloc_{dma,}_caches,
 * which are all initialized during kmem_cache_init().
 *
 * 获取slab管理对象的内存.
 *
 * 对于slab缓存,当slab描述符是off-slab时,slab描述符不能来自正在创建的同一个cache,
 * 因为如果是这样,那就意味着在在此时我们推迟了kmalloc_{dma,}_cache的大小为sizeof(slab描述符)的创建
 * 我们最终调用__kmem_cache_create(),它反过来在kmalloc中查找_{dma,}_caches对于size不匹配的一个.
 * 这是一个“鸡和蛋”的问题.
 *
 * 因此，off-slab描述符应来自kmalloc_{dma,}_caches,它们都是在kmem_cache_init（）期间初始化的.
 */
static void *alloc_slabmgmt(struct kmem_cache *cachep,
				   struct page *page, int colour_off,
				   gfp_t local_flags, int nodeid)
{
	void *freelist;
	/* 拿到该page的虚拟地址 */
	void *addr = page_address(page);

	/* 让page->s_mem指向第一个对象的起始地址 */
	page->s_mem = addr + colour_off;
	page->active = 0;

	/* 如果是OBJFREELIST_SLAB(cachep),那么让freelist指向空 */
	if (OBJFREELIST_SLAB(cachep))
		freelist = NULL;	/* 如果是OFF_SLAB,那么就让他在外面分配一个freelist */
	else if (OFF_SLAB(cachep)) {
		/* Slab management obj is off-slab. */
		freelist = kmem_cache_alloc_node(cachep->freelist_cache,
					      local_flags, nodeid);
		if (!freelist)
			return NULL;
	} else {
		/* We will use last bytes at the slab for freelist
		 * 我们将使用slab的最后一个字节作为自由列表
		 */
		/* 这里就是用最后一个字节来做freelist */
		freelist = addr + (PAGE_SIZE << cachep->gfporder) -
				cachep->freelist_size;
	}

	return freelist;
}

static inline freelist_idx_t get_free_obj(struct page *page, unsigned int idx)
{
	/* 获得free的obj */
	return ((freelist_idx_t *)page->freelist)[idx];
}

static inline void set_free_obj(struct page *page,
					unsigned int idx, freelist_idx_t val)
{
	((freelist_idx_t *)(page->freelist))[idx] = val;
}

static void cache_init_objs_debug(struct kmem_cache *cachep, struct page *page)
{
#if DEBUG
	int i;

	/* 通过下面这个代码的分析,我们能够得到的obj的布局如下
	 *
	 *
	 *  _____________________________________________________________________
	 * |    red zone |      object size    |    red zone  |  track  | track  |
	 * |_____________|_____________________|______________|_________|________|
	 *
	 */
	/* 对该page的每个对象进行做debug的初始化 */
	for (i = 0; i < cachep->num; i++) {

		/* page->s_mem + cache->size * idx; */
		/* 也就是说拿到这块对象的内存 */
		void *objp = index_to_obj(cachep, page, i);
		/* 如果cachep->flags带了SLAB_STORE_USER
		 * 那么把这块内存的最后一个 BYTES_PER_WORD设置为NULL
		 *
		 * (void **)(objp + cachep->size - BYTES_PER_WORD);
		 */
		if (cachep->flags & SLAB_STORE_USER)
			*dbg_userword(cachep, objp) = NULL;

		/* 如果带了SLAB_RED_ZONE */
		if (cachep->flags & SLAB_RED_ZONE) {
			/* objp + obj_offset(cachep) - sizeof(unsigned long long)
			 * 也就是把对象前面的那个unsigned long long那一块赋值为0x09F911029D74E35BULL
			 */
			*dbg_redzone1(cachep, objp) = RED_INACTIVE;
			/* 所以说redzone是放到首位两边的
			 * if (cachep->flags & SLAB_STORE_USER)
			 *	return (unsigned long long *)(objp + cachep->size - sizeof(unsigned long long) - REDZONE_ALIGN);
			 *
			 *	return (unsigned long long *) (objp + cachep->size - sizeof(unsigned long long));
			 */
			*dbg_redzone2(cachep, objp) = RED_INACTIVE;
		}
		/*
		 * Constructors are not allowed to allocate memory from the same
		 * cache which they are a constructor for.  Otherwise, deadlock.
		 * They must also be threaded.
		 */
		if (cachep->ctor && !(cachep->flags & SLAB_POISON)) {
			kasan_unpoison_object_data(cachep,
						   objp + obj_offset(cachep));
			cachep->ctor(objp + obj_offset(cachep));
			kasan_poison_object_data(
				cachep, objp + obj_offset(cachep));
		}
		/* 如果cachep->flags & SLAB_RED_ZONE,那么去检查REDZONE有没有被人修改,也就是有没有被object越界 */
		if (cachep->flags & SLAB_RED_ZONE) {
			if (*dbg_redzone2(cachep, objp) != RED_INACTIVE)
				slab_error(cachep, "constructor overwrote the end of an object");
			if (*dbg_redzone1(cachep, objp) != RED_INACTIVE)
				slab_error(cachep, "constructor overwrote the start of an object");
		}
		/* need to poison the objs?
		 * 需要去填充对象
		 */
		if (cachep->flags & SLAB_POISON) {
			/* 这里就是给对象全部填充为POISON_FREE(0x6b),但是最后一个字节将会是0xa5 */
			poison_obj(cachep, objp, POISON_FREE);
			slab_kernel_map(cachep, objp, 0, 0);
		}
	}
#endif
}

#ifdef CONFIG_SLAB_FREELIST_RANDOM
/* Hold information during a freelist initialization */
union freelist_init_state {
	struct {
		unsigned int pos;
		unsigned int *list;
		unsigned int count;
	};
	struct rnd_state rnd_state;
};

/*
 * Initialize the state based on the randomization methode available.
 * return true if the pre-computed list is available, false otherwize.
 */
static bool freelist_state_initialize(union freelist_init_state *state,
				struct kmem_cache *cachep,
				unsigned int count)
{
	bool ret;
	unsigned int rand;

	/* Use best entropy available to define a random shift */
	rand = get_random_int();

	/* Use a random state if the pre-computed list is not available */
	if (!cachep->random_seq) {
		prandom_seed_state(&state->rnd_state, rand);
		ret = false;
	} else {
		state->list = cachep->random_seq;
		state->count = count;
		state->pos = rand % count;
		ret = true;
	}
	return ret;
}

/* Get the next entry on the list and randomize it using a random shift */
static freelist_idx_t next_random_slot(union freelist_init_state *state)
{
	if (state->pos >= state->count)
		state->pos = 0;
	return state->list[state->pos++];
}

/* Swap two freelist entries */
static void swap_free_obj(struct page *page, unsigned int a, unsigned int b)
{
	swap(((freelist_idx_t *)page->freelist)[a],
		((freelist_idx_t *)page->freelist)[b]);
}

/*
 * Shuffle the freelist initialization state based on pre-computed lists.
 * return true if the list was successfully shuffled, false otherwise.
 */
static bool shuffle_freelist(struct kmem_cache *cachep, struct page *page)
{
	unsigned int objfreelist = 0, i, rand, count = cachep->num;
	union freelist_init_state state;
	bool precomputed;

	if (count < 2)
		return false;

	precomputed = freelist_state_initialize(&state, cachep, count);

	/* Take a random entry as the objfreelist */
	if (OBJFREELIST_SLAB(cachep)) {
		if (!precomputed)
			objfreelist = count - 1;
		else
			objfreelist = next_random_slot(&state);
		page->freelist = index_to_obj(cachep, page, objfreelist) +
						obj_offset(cachep);
		count--;
	}

	/*
	 * On early boot, generate the list dynamically.
	 * Later use a pre-computed list for speed.
	 */
	if (!precomputed) {
		for (i = 0; i < count; i++)
			set_free_obj(page, i, i);

		/* Fisher-Yates shuffle */
		for (i = count - 1; i > 0; i--) {
			rand = prandom_u32_state(&state.rnd_state);
			rand %= (i + 1);
			swap_free_obj(page, i, rand);
		}
	} else {
		for (i = 0; i < count; i++)
			set_free_obj(page, i, next_random_slot(&state));
	}

	if (OBJFREELIST_SLAB(cachep))
		set_free_obj(page, cachep->num - 1, objfreelist);

	return true;
}
#else
static inline bool shuffle_freelist(struct kmem_cache *cachep,
				struct page *page)
{
	return false;
}
#endif /* CONFIG_SLAB_FREELIST_RANDOM */

static void cache_init_objs(struct kmem_cache *cachep,
			    struct page *page)
{
	int i;
	void *objp;
	bool shuffled;

	/* 这里主要是初始化obj的一些东西,譬如redzone、posion等 */
	cache_init_objs_debug(cachep, page);

	/* Try to randomize the freelist if enabled */
	shuffled = shuffle_freelist(cachep, page);

	/* 如果freelist不是随机化的,并且是OBJFREELIST_SLAB */
	if (!shuffled && OBJFREELIST_SLAB(cachep)) {
		/* page->freelist就是最后一个对象的起始地址 */
		page->freelist = index_to_obj(cachep, page, cachep->num - 1) +
						obj_offset(cachep);
	}

	for (i = 0; i < cachep->num; i++) {
		objp = index_to_obj(cachep, page, i);
		kasan_init_slab_obj(cachep, objp);

		/* constructor could break poison info */
		if (DEBUG == 0 && cachep->ctor) {
			kasan_unpoison_object_data(cachep, objp);
			cachep->ctor(objp);
			kasan_poison_object_data(cachep, objp);
		}

		if (!shuffled)
			set_free_obj(page, i, i);
	}
}

static void *slab_get_obj(struct kmem_cache *cachep, struct page *page)
{
	void *objp;

	/* 找到空闲的对象,objp指向这块内存的起始地址 */
	objp = index_to_obj(cachep, page, get_free_obj(page, page->active));
	/* 然后page->active++ */
	page->active++;

#if DEBUG
	if (cachep->flags & SLAB_STORE_USER)
		set_store_user_dirty(cachep);
#endif

	return objp;
}

static void slab_put_obj(struct kmem_cache *cachep,
			struct page *page, void *objp)
{
	/* objnr就是把对象转换成index后的值 */
	unsigned int objnr = obj_to_index(cachep, page, objp);
#if DEBUG
	unsigned int i;

	/* Verify double free bug */
	/* page->active表示用于SLAB时描述当前SLAB已经使用的对象数 */
	for (i = page->active; i < cachep->num; i++) {
		/* 如果page中的freelist(用于SLAB描述符，指向空闲对象链表)中index有你,说明你是空闲的
		 * 那么就是double free
		 */
		if (get_free_obj(page, i) == objnr) {
			pr_err("slab: double free detected in cache '%s', objp %p\n",
			       cachep->name, objp);
			BUG();
		}
	}
#endif
	/* page->active -- */
	page->active--;
	/* 如果page->freelist为NULL,那么page->freelist就等于objp + obj_offset(cachep),是因为他被释放了所以要用这篇内存吗? */
	if (!page->freelist)
		page->freelist = objp + obj_offset(cachep);
	/* ((freelist_idx_t *)(page->freelist))[idx] = val; */
	set_free_obj(page, page->active, objnr);
}

/*
 * Map pages beginning at addr to the given cache and slab. This is required
 * for the slab allocator to be able to lookup the cache and slab of a
 * virtual address for kfree, ksize, and slab debugging.
 *
 * 映射页面起始地址到给定的cache和slab.这对slab分配器是必须的,为了能够找到cache和slab
 * 的虚拟地址for kfree、ksize、slab_debugging
 */
static void slab_map_pages(struct kmem_cache *cache, struct page *page,
			   void *freelist)
{
	page->slab_cache = cache;
	page->freelist = freelist;
}

/*
 * Grow (by 1) the number of slabs within a cache.  This is called by
 * kmem_cache_alloc() when there are no active objs left in a cache.
 *
 * 将cache中的slab数量增加(增加1).
 * 当缓存中没有活动的对象时,kmem_cache_alloc()会调用此函数.
 */
static struct page *cache_grow_begin(struct kmem_cache *cachep,
				gfp_t flags, int nodeid)
{
	void *freelist;
	size_t offset;
	gfp_t local_flags;
	int page_node;
	struct kmem_cache_node *n;
	struct page *page;

	/*
	 * Be lazy and only check for valid flags here,  keeping it out of the
	 * critical path in kmem_cache_alloc().
	 *
	 * 懒惰一点,在这里只检查有效的标志,使其远离kmem_cache_alloc()中的关键路径.
	 */
	if (unlikely(flags & GFP_SLAB_BUG_MASK)) {
		gfp_t invalid_mask = flags & GFP_SLAB_BUG_MASK;
		flags &= ~GFP_SLAB_BUG_MASK;
		pr_warn("Unexpected gfp: %#x (%pGg). Fixing up to gfp: %#x (%pGg). Fix your code!\n",
				invalid_mask, &invalid_mask, flags, &flags);
		dump_stack();
	}

	/*
	 * Control allocation cpuset and node placement constraints
	 * #define GFP_CONSTRAINT_MASK (__GFP_HARDWALL|__GFP_THISNODE)
	 *
	 * GFP_RECLAIM_MASK是内存回收的MASK
	 */
	local_flags = flags & (GFP_CONSTRAINT_MASK|GFP_RECLAIM_MASK);

	check_irq_off();
	if (gfpflags_allow_blocking(local_flags))
		local_irq_enable();

	/*
	 * Get mem for the objs.  Attempt to allocate a physical page from
	 * 'nodeid'.
	 */

	/* 分配一个slab所需的页面 */
	page = kmem_getpages(cachep, local_flags, nodeid);
	if (!page)
		goto failed;

	/* 得到该page的node id */
	page_node = page_to_nid(page);
	/* 拿到该slab的kmem_cache_node 结构体 */
	n = get_node(cachep, page_node);

	/* Get colour for the slab, and cal the next value. */
	/* n->colour_next表示slab节点中下一个slab应该包括的colour数目,
	 * 然后又冲0开始计算. colour的大小为cache line大小,即cachep->colour_off,
	 * 这样布局有利于提高硬件cache效率
	 */
	n->colour_next++;
	/* 如果colour_next >= cachep->colour,那么设置 n->colour_next = 0 */
	if (n->colour_next >= cachep->colour)
		n->colour_next = 0;
	/* 将offset设置为n->colour_next,为了方便它乘以cachep->colour_off
	 */
	offset = n->colour_next;
	if (offset >= cachep->colour)
		offset = 0;


	/* colour_off: 一个cache colour的长度,和L1 cache line大小相同
	 * 所以这里算出要为colour偏移多少个字节为着色区让步
	 */
	offset *= cachep->colour_off;

	/* Get slab management. */
	/* 这里就是获取freelist的内存 */
	freelist = alloc_slabmgmt(cachep, page, offset,
			local_flags & ~GFP_CONSTRAINT_MASK, page_node);
	/* 如果是off_slab但是freelist又是空的,
	 * 因为本来你就是off_slab了,freelist是从外面分的
	 * 但是你又是空的,说明没有kmalloc没有初始化
	 * 那就直接把内存释放了算了
	 */
	if (OFF_SLAB(cachep) && !freelist)
		goto opps1;
	/*
	 * static void slab_map_pages(struct kmem_cache *cache, struct page *page,
	 *				void *freelist)
	 * {
	 *	page->slab_cache = cache;
	 *	page->freelist = freelist;
	 * }
	 */
	slab_map_pages(cachep, page, freelist);

	kasan_poison_slab(page);
	cache_init_objs(cachep, page);

	if (gfpflags_allow_blocking(local_flags))
		local_irq_disable();

	return page;

opps1:
	kmem_freepages(cachep, page);
failed:
	if (gfpflags_allow_blocking(local_flags))
		local_irq_disable();
	return NULL;
}

static void cache_grow_end(struct kmem_cache *cachep, struct page *page)
{
	struct kmem_cache_node *n;
	void *list = NULL;

	check_irq_off();

	/* 如果page为NULL,那么直接返回了 */
	if (!page)
		return;

	/* 初始化page的lru成员 */
	INIT_LIST_HEAD(&page->lru);
	/* 拿到该node的kmem_cache_node */
	n = get_node(cachep, page_to_nid(page));

	spin_lock(&n->list_lock);
	/* 如果page里面没有活跃的slab 对象,那么把它添加到尾部 */
	if (!page->active)
		list_add_tail(&page->lru, &(n->slabs_free));
	else
		fixup_slab_list(cachep, n, page, &list);

	/* 该kmem_cache_node的num_slabs++ */
	n->num_slabs++;
	/* cachep->grown++ 表示cachep增长的次数 */
	STATS_INC_GROWN(cachep);
	/* 让该node的kmem_cache_node的free_objects技术增加对应的数值 */
	n->free_objects += cachep->num - page->active;
	spin_unlock(&n->list_lock);

	fixup_objfreelist_debug(cachep, &list);
}

#if DEBUG

/*
 * Perform extra freeing checks:
 * - detect bad pointers.
 * - POISON/RED_ZONE checking
 */
static void kfree_debugcheck(const void *objp)
{
	if (!virt_addr_valid(objp)) {
		pr_err("kfree_debugcheck: out of range ptr %lxh\n",
		       (unsigned long)objp);
		BUG();
	}
}

static inline void verify_redzone_free(struct kmem_cache *cache, void *obj)
{
	unsigned long long redzone1, redzone2;

	/* 拿到该对象的redzone1和redzone2的值 */
	redzone1 = *dbg_redzone1(cache, obj);
	redzone2 = *dbg_redzone2(cache, obj);

	/*
	 * Redzone is ok.
	 */
	/* 如果都是RED_ACTIVE,那么才是正常的 */
	if (redzone1 == RED_ACTIVE && redzone2 == RED_ACTIVE)
		return;

	/* 如果都是RED_INACTIVE说明是double free */
	if (redzone1 == RED_INACTIVE && redzone2 == RED_INACTIVE)
		slab_error(cache, "double free detected");
	else	/* 如果是其他,那么就是被overwritten了 */
		slab_error(cache, "memory outside object was overwritten");

	/* 打印相关的信息 */
	pr_err("%p: redzone 1:0x%llx, redzone 2:0x%llx\n",
	       obj, redzone1, redzone2);
}

static void *cache_free_debugcheck(struct kmem_cache *cachep, void *objp,
				   unsigned long caller)
{
	unsigned int objnr;
	struct page *page;

	/* 通过虚拟地址得到cachep,如果和我们传进来的不一样,那么就报个BUG */
	BUG_ON(virt_to_cache(objp) != cachep);

	/* 这里就得到对象的包括redzone的起始地址 */
	objp -= obj_offset(cachep);
	kfree_debugcheck(objp);
	/* 通过起始地址得到page结构体 */
	page = virt_to_head_page(objp);

	/* 如果有redzone */
	if (cachep->flags & SLAB_RED_ZONE) {
		/* 去验证一下是否redzone是free的 */
		verify_redzone_free(cachep, objp);
		/* 将redzone设置为RED_INACTIVE */
		*dbg_redzone1(cachep, objp) = RED_INACTIVE;
		*dbg_redzone2(cachep, objp) = RED_INACTIVE;
	}
	if (cachep->flags & SLAB_STORE_USER) {
		/* 将cachep->store_user_clean保持为0 */
		set_store_user_dirty(cachep);
		/* 将调用者的返回地址填充到user段里面去 */
		*dbg_userword(cachep, objp) = (void *)caller;
	}

	/* 得到对象的index */
	objnr = obj_to_index(cachep, page, objp);

	/* 安全检查 */
	BUG_ON(objnr >= cachep->num);
	BUG_ON(objp != index_to_obj(cachep, page, objnr));


	/* 如果cachep->flags & SLAB_POISON */
	if (cachep->flags & SLAB_POISON) {
		/* 那么把该对象填充为POISON_FREE,最后一个字节填充为POISON_END */
		poison_obj(cachep, objp, POISON_FREE);
		slab_kernel_map(cachep, objp, 0, caller);
	}
	return objp;
}

#else
#define kfree_debugcheck(x) do { } while(0)
#define cache_free_debugcheck(x,objp,z) (objp)
#endif

static inline void fixup_objfreelist_debug(struct kmem_cache *cachep,
						void **list)
{
#if DEBUG
	void *next = *list;
	void *objp;

	while (next) {
		objp = next - obj_offset(cachep);
		next = *(void **)next;
		poison_obj(cachep, objp, POISON_FREE);
	}
#endif
}

static inline void fixup_slab_list(struct kmem_cache *cachep,
				struct kmem_cache_node *n, struct page *page,
				void **list)
{
	/* move slabp to correct slabp list:
	 * 将slabp 移动到正确的slabp列表里面去
	 */

	/* 把page从它所在的lru里面删除掉 */
	list_del(&page->lru);
	/* 如果page->active也就是说活跃的对象数已经对应于cachep->num,那么就说明他已经完全被使用了
	 * 那么把它置入到slabs_full链表里面去
	 */
	if (page->active == cachep->num) {
		/* 置入到slabs_full的链表里面去 */
		list_add(&page->lru, &n->slabs_full);
		if (OBJFREELIST_SLAB(cachep)) {
#if DEBUG
			/* Poisoning will be done without holding the lock */
			if (cachep->flags & SLAB_POISON) {
				void **objp = page->freelist;

				*objp = *list;
				*list = objp;
			}
#endif
			page->freelist = NULL;
		}
	} else	/* 否则把它添加到slabs_partial链表里面去 */
		list_add(&page->lru, &n->slabs_partial);
}

/* Try to find non-pfmemalloc slab if needed */
static noinline struct page *get_valid_first_slab(struct kmem_cache_node *n,
					struct page *page, bool pfmemalloc)
{
	if (!page)
		return NULL;

	if (pfmemalloc)
		return page;

	if (!PageSlabPfmemalloc(page))
		return page;

	/* No need to keep pfmemalloc slab if we have enough free objects */
	if (n->free_objects > n->free_limit) {
		ClearPageSlabPfmemalloc(page);
		return page;
	}

	/* Move pfmemalloc slab to the end of list to speed up next search */
	list_del(&page->lru);
	if (!page->active)
		list_add_tail(&page->lru, &n->slabs_free);
	else
		list_add_tail(&page->lru, &n->slabs_partial);

	list_for_each_entry(page, &n->slabs_partial, lru) {
		if (!PageSlabPfmemalloc(page))
			return page;
	}

	list_for_each_entry(page, &n->slabs_free, lru) {
		if (!PageSlabPfmemalloc(page))
			return page;
	}

	return NULL;
}

static struct page *get_first_slab(struct kmem_cache_node *n, bool pfmemalloc)
{
	struct page *page;

	/* 找到kmem_cache_node的slabs_partial的第一个page,可能为NULL,这里面的page都是有部分free的对象的 */
	page = list_first_entry_or_null(&n->slabs_partial,
			struct page, lru);
	/* 如果没有这种,那么就去找那么完全free的 */
	if (!page) {
		/* 把free_touched设置为1,说明再分配一个对象(后面再详细了解一下) */
		n->free_touched = 1;
		/* 如果全free的链表里面去找,看能不能得到相关的page */
		page = list_first_entry_or_null(&n->slabs_free,
				struct page, lru);
	}

	if (sk_memalloc_socks())
		return get_valid_first_slab(n, page, pfmemalloc);

	return page;
}

static noinline void *cache_alloc_pfmemalloc(struct kmem_cache *cachep,
				struct kmem_cache_node *n, gfp_t flags)
{
	struct page *page;
	void *obj;
	void *list = NULL;

	if (!gfp_pfmemalloc_allowed(flags))
		return NULL;

	spin_lock(&n->list_lock);
	page = get_first_slab(n, true);
	if (!page) {
		spin_unlock(&n->list_lock);
		return NULL;
	}

	obj = slab_get_obj(cachep, page);
	n->free_objects--;

	fixup_slab_list(cachep, n, page, &list);

	spin_unlock(&n->list_lock);
	fixup_objfreelist_debug(cachep, &list);

	return obj;
}

/*
 * Slab list should be fixed up by fixup_slab_list() for existing slab
 * or cache_grow_end() for new slab
 *
 * slab 列表对现有的slab应通过fixup_slab_list()为处理,新lab通过cache_grow_end处理
 */
static __always_inline int alloc_block(struct kmem_cache *cachep,
		struct array_cache *ac, struct page *page, int batchcount)
{
	/*
	 * There must be at least one object available for
	 * allocation.
	 *
	 * 必须至少有一个对象可供分配
	 */

	/* page->active表示当前SLAB已经使用的对象
	 *
	 * 如果大于cachep->num,那么报个BUG吧
	 */
	BUG_ON(page->active >= cachep->num);

	/* 如果高速缓存还存在空闲对象，就用batchcount个对象进行填充 */
	while (page->active < cachep->num && batchcount--) {
		/* 将cachep的num_allocations++ 说明分配对象 */
		STATS_INC_ALLOCED(cachep);
		/* 将cachep的num_active++ 说明这个对象要变成活跃对象了 */
		STATS_INC_ACTIVE(cachep);
		/* 更新high_mark */
		STATS_SET_HIGH(cachep);
		/* 让ac->entry的ac->avail++指向这块内存 */
		ac->entry[ac->avail++] = slab_get_obj(cachep, page);
	}

	/* 返回batchcount */
	return batchcount;
}

static void *cache_alloc_refill(struct kmem_cache *cachep, gfp_t flags)
{
	int batchcount;
	struct kmem_cache_node *n;
	struct array_cache *ac, *shared;
	int node;
	void *list = NULL;
	struct page *page;
	/* 检测IRQ中断是否关闭了 */
	check_irq_off();
	/* 拿到当前的node id */
	node = numa_mem_id();

	/*
	 *  static inline struct array_cache *cpu_cache_get(struct kmem_cache *cachep)
	 * {
	 *	return this_cpu_ptr(cachep->cpu_cache);
	 * }
	 */
	/* 拿到本地CPU的array_cache */
	ac = cpu_cache_get(cachep);
	/* 拿到batchcount batchcount是每次批处理变量. */
	batchcount = ac->batchcount;
	/* 如果本缓存是没有使用过的,同时批处理还大于最大的限制
	 * #define BATCHREFILL_LIMIT	16
	 */
	if (!ac->touched && batchcount > BATCHREFILL_LIMIT) {
		/*
		 * If there was little recent activity on this cache, then
		 * perform only a partial refill.  Otherwise we could generate
		 * refill bouncing.
		 *
		 * 如果在这个cache中有少量的最近活动的缓存,则只执行部分重新填充.
		 * 否则我们可能会产生重新填充
		 */
		/* 把batchcount设置为BATCHREFILL_LIMIT */
		batchcount = BATCHREFILL_LIMIT;
	}
	/* 拿到该node里面的kmem_cache_node结构体 */
	n = get_node(cachep, node);

	/* 如果本地CPU的arryr_cache里面还有可用的对象,或者说该node的kmem_cache_node为NULL
	 * 那么报个BUG吧
	 */
	BUG_ON(ac->avail > 0 || !n);
	/* 读该node的kmem_cache_node中shared array_cache */
	shared = READ_ONCE(n->shared);
	/* 如果该node中没有空闲对象,并且没有共享的array_cache或者共享的里面也没有对象,那么直接填充 */
	if (!n->free_objects && (!shared || !shared->avail))
		goto direct_grow;

	spin_lock(&n->list_lock);
	/* 拿到该kmem_cache_node的shared array_cache */
	shared = READ_ONCE(n->shared);

	/* See if we can refill from the shared array
	 * 如果能够冲共享array_cache里面拿到对象,那么最好
	 */
	if (shared && transfer_objects(ac, shared, batchcount)) {
		/* 因为是分配,所以把shared->touched设置为1 */
		shared->touched = 1;
		goto alloc_done;
	}
	/* 如果是单节点,或者共享节点的对象已经分配完,则从slab缓存中进行分配 */
	while (batchcount > 0) {
		/* Get slab alloc is to come from. */
		/* 分配规则:
		 *	1. 先从半满的缓存中进行分配
		 *	2. 如果半满缓存分配完.再从全部空闲的缓存中进行对象分配
		 */
		page = get_first_slab(n, false);
		/* 如果没有page,那么进入到goto must_grow */
		if (!page)
			goto must_grow;

		check_spinlock_acquired(cachep);

		batchcount = alloc_block(cachep, ac, page, batchcount);
		fixup_slab_list(cachep, n, page, &list);
	}

must_grow:
	/* free_objects: 高速缓存中空闲对象个数(包括slabs_partial链表中和slabs_free链表中所有的空闲对象)
	 * ac->avail: 对象缓存池中可用的对象数目
	 *
	 * 让free_objects减去ac->avail
	 */
	n->free_objects -= ac->avail;
alloc_done:
	spin_unlock(&n->list_lock);
	fixup_objfreelist_debug(cachep, &list);

direct_grow:
	/* 如果ac->avail等于0 */
	if (unlikely(!ac->avail)) {
		/* Check if we can use obj in pfmemalloc slab */
		if (sk_memalloc_socks()) {
			void *obj = cache_alloc_pfmemalloc(cachep, n, flags);

			if (obj)
				return obj;
		}

		/* 这里主要是去分配页面,顺便填充一下对象 */
		page = cache_grow_begin(cachep, gfp_exact_node(flags), node);

		/*
		 * cache_grow_begin() can reenable interrupts,
		 * then ac could change.
		 *
		 * cache_grow_begin可以再使能中断,然后ac可以更改
		 */

		/* 拿到本CPU的array_cache */
		ac = cpu_cache_get(cachep);
		/* 如果ac的可用对象里面没有空闲但是有page
		 * 那么去该page里面去分
		 */
		if (!ac->avail && page)
			alloc_block(cachep, ac, page, batchcount);
		/* 主要是看把这个页面分到那个链表里面去,slabs_free、slabs_partial、slabs_full */
		cache_grow_end(cachep, page);

		/* 如果ac->avail还为空,那么返回NULL */
		if (!ac->avail)
			return NULL;
	}
	/* 因为在分配对象,所以设置为1 */
	ac->touched = 1;

	/* 把最新的那个对象返回出去 */
	return ac->entry[--ac->avail];
}

static inline void cache_alloc_debugcheck_before(struct kmem_cache *cachep,
						gfp_t flags)
{
	might_sleep_if(gfpflags_allow_blocking(flags));
}

#if DEBUG
static void *cache_alloc_debugcheck_after(struct kmem_cache *cachep,
				gfp_t flags, void *objp, unsigned long caller)
{
	/* 如果对象为NULL,那么返回对象(即NULL) */
	if (!objp)
		return objp;
	/* 如果cachep->flags带了SLAB_POISON */
	if (cachep->flags & SLAB_POISON) {
		/* 安全检查 */
		check_poison_obj(cachep, objp);
		slab_kernel_map(cachep, objp, 1, 0);
		/* #define	POISON_INUSE	0x5a for use-uninitialised poisoning
		 * 将该对象都填充为POISON_INUSE
		 */
		poison_obj(cachep, objp, POISON_INUSE);
	}

	/* 如果带了SLAB_STORE_USER,那么就把caller也填充进去 */
	if (cachep->flags & SLAB_STORE_USER)
		*dbg_userword(cachep, objp) = (void *)caller;

	/* 如果有RED_ZONE */
	if (cachep->flags & SLAB_RED_ZONE) {
		/* 先检查redzone两边是不是都是RED_INACTIVE,如果不是那么可能是double free或者内存被overwritten了
		 * 然后输出错误的日志
		 */
		if (*dbg_redzone1(cachep, objp) != RED_INACTIVE ||
				*dbg_redzone2(cachep, objp) != RED_INACTIVE) {
			slab_error(cachep, "double free, or memory outside object was overwritten");
			pr_err("%p: redzone 1:0x%llx, redzone 2:0x%llx\n",
				objp, *dbg_redzone1(cachep, objp),
				*dbg_redzone2(cachep, objp));
		}

		/* 然后把RED_ACTIVE填充到RED_ZONE中,
		 * #define	RED_ACTIVE	0xD84156C5635688C0ULL  when obj is active
		 */
		*dbg_redzone1(cachep, objp) = RED_ACTIVE;
		*dbg_redzone2(cachep, objp) = RED_ACTIVE;
	}

	objp += obj_offset(cachep);
	if (cachep->ctor && cachep->flags & SLAB_POISON)
		cachep->ctor(objp);
	if (ARCH_SLAB_MINALIGN &&
	    ((unsigned long)objp & (ARCH_SLAB_MINALIGN-1))) {
		pr_err("0x%p: not aligned to ARCH_SLAB_MINALIGN=%d\n",
		       objp, (int)ARCH_SLAB_MINALIGN);
	}
	return objp;
}
#else
#define cache_alloc_debugcheck_after(a,b,objp,d) (objp)
#endif

static inline void *____cache_alloc(struct kmem_cache *cachep, gfp_t flags)
{
	void *objp;
	struct array_cache *ac;

	check_irq_off();
	/* 通过slab描述符cachep获取本地对象缓冲池ac */
	ac = cpu_cache_get(cachep);
	/* ac->avail表示对象缓冲池中可用的对象数目 */
	if (likely(ac->avail)) {
		/* 因为是要分配,所以将ac->touched为1 */
		ac->touched = 1;
		/* 然后拿entry数组里面最后一个元素的指针,并将--ac->avail */
		objp = ac->entry[--ac->avail];
		/* #define STATS_INC_ALLOCHIT(x)	atomic_inc(&(x)->allochit)
		 * cachep的allochit成员加1,说明分配命中.
		 */
		STATS_INC_ALLOCHIT(cachep);
		goto out;
	}

	/* 将cachep->allocmiss加1,表示分配失败计数 */
	STATS_INC_ALLOCMISS(cachep);

	/* 为高速缓存内存空间增加新的内存对象 */
	objp = cache_alloc_refill(cachep, flags);
	/*
	 * the 'ac' may be updated by cache_alloc_refill(),
	 * and kmemleak_erase() requires its correct value.
	 */
	ac = cpu_cache_get(cachep);

out:
	/*
	 * To avoid a false negative, if an object that is in one of the
	 * per-CPU caches is leaked, we need to make sure kmemleak doesn't
	 * treat the array pointers as a reference to the object.
	 */
	if (objp)
		kmemleak_erase(&ac->entry[ac->avail]);
	return objp;
}

#ifdef CONFIG_NUMA
/*
 * Try allocating on another node if PFA_SPREAD_SLAB is a mempolicy is set.
 *
 * If we are in_interrupt, then process context, including cpusets and
 * mempolicy, may not apply and should not be used for allocation policy.
 */
static void *alternate_node_alloc(struct kmem_cache *cachep, gfp_t flags)
{
	int nid_alloc, nid_here;

	if (in_interrupt() || (flags & __GFP_THISNODE))
		return NULL;
	nid_alloc = nid_here = numa_mem_id();
	if (cpuset_do_slab_mem_spread() && (cachep->flags & SLAB_MEM_SPREAD))
		nid_alloc = cpuset_slab_spread_node();
	else if (current->mempolicy)
		nid_alloc = mempolicy_slab_node();
	if (nid_alloc != nid_here)
		return ____cache_alloc_node(cachep, flags, nid_alloc);
	return NULL;
}

/*
 * Fallback function if there was no memory available and no objects on a
 * certain node and fall back is permitted. First we scan all the
 * available node for available objects. If that fails then we
 * perform an allocation without specifying a node. This allows the page
 * allocator to do its reclaim / fallback magic. We then insert the
 * slab into the proper nodelist and then allocate from it.
 */
static void *fallback_alloc(struct kmem_cache *cache, gfp_t flags)
{
	struct zonelist *zonelist;
	struct zoneref *z;
	struct zone *zone;
	enum zone_type high_zoneidx = gfp_zone(flags);
	void *obj = NULL;
	struct page *page;
	int nid;
	unsigned int cpuset_mems_cookie;

	if (flags & __GFP_THISNODE)
		return NULL;

retry_cpuset:
	cpuset_mems_cookie = read_mems_allowed_begin();
	zonelist = node_zonelist(mempolicy_slab_node(), flags);

retry:
	/*
	 * Look through allowed nodes for objects available
	 * from existing per node queues.
	 */
	for_each_zone_zonelist(zone, z, zonelist, high_zoneidx) {
		nid = zone_to_nid(zone);

		if (cpuset_zone_allowed(zone, flags) &&
			get_node(cache, nid) &&
			get_node(cache, nid)->free_objects) {
				obj = ____cache_alloc_node(cache,
					gfp_exact_node(flags), nid);
				if (obj)
					break;
		}
	}

	if (!obj) {
		/*
		 * This allocation will be performed within the constraints
		 * of the current cpuset / memory policy requirements.
		 * We may trigger various forms of reclaim on the allowed
		 * set and go into memory reserves if necessary.
		 */
		page = cache_grow_begin(cache, flags, numa_mem_id());
		cache_grow_end(cache, page);
		if (page) {
			nid = page_to_nid(page);
			obj = ____cache_alloc_node(cache,
				gfp_exact_node(flags), nid);

			/*
			 * Another processor may allocate the objects in
			 * the slab since we are not holding any locks.
			 */
			if (!obj)
				goto retry;
		}
	}

	if (unlikely(!obj && read_mems_allowed_retry(cpuset_mems_cookie)))
		goto retry_cpuset;
	return obj;
}

/*
 * A interface to enable slab creation on nodeid
 */
static void *____cache_alloc_node(struct kmem_cache *cachep, gfp_t flags,
				int nodeid)
{
	struct page *page;
	struct kmem_cache_node *n;
	void *obj = NULL;
	void *list = NULL;

	VM_BUG_ON(nodeid < 0 || nodeid >= MAX_NUMNODES);
	n = get_node(cachep, nodeid);
	BUG_ON(!n);

	check_irq_off();
	spin_lock(&n->list_lock);
	page = get_first_slab(n, false);
	if (!page)
		goto must_grow;

	check_spinlock_acquired_node(cachep, nodeid);

	STATS_INC_NODEALLOCS(cachep);
	STATS_INC_ACTIVE(cachep);
	STATS_SET_HIGH(cachep);

	BUG_ON(page->active == cachep->num);

	obj = slab_get_obj(cachep, page);
	n->free_objects--;

	fixup_slab_list(cachep, n, page, &list);

	spin_unlock(&n->list_lock);
	fixup_objfreelist_debug(cachep, &list);
	return obj;

must_grow:
	spin_unlock(&n->list_lock);
	page = cache_grow_begin(cachep, gfp_exact_node(flags), nodeid);
	if (page) {
		/* This slab isn't counted yet so don't update free_objects */
		obj = slab_get_obj(cachep, page);
	}
	cache_grow_end(cachep, page);

	return obj ? obj : fallback_alloc(cachep, flags);
}

static __always_inline void *
slab_alloc_node(struct kmem_cache *cachep, gfp_t flags, int nodeid,
		   unsigned long caller)
{
	unsigned long save_flags;
	void *ptr;
	int slab_node = numa_mem_id();

	flags &= gfp_allowed_mask;
	cachep = slab_pre_alloc_hook(cachep, flags);
	if (unlikely(!cachep))
		return NULL;

	cache_alloc_debugcheck_before(cachep, flags);
	local_irq_save(save_flags);

	if (nodeid == NUMA_NO_NODE)
		nodeid = slab_node;

	if (unlikely(!get_node(cachep, nodeid))) {
		/* Node not bootstrapped yet */
		ptr = fallback_alloc(cachep, flags);
		goto out;
	}

	if (nodeid == slab_node) {
		/*
		 * Use the locally cached objects if possible.
		 * However ____cache_alloc does not allow fallback
		 * to other nodes. It may fail while we still have
		 * objects on other nodes available.
		 */
		ptr = ____cache_alloc(cachep, flags);
		if (ptr)
			goto out;
	}
	/* ___cache_alloc_node can fall back to other nodes */
	ptr = ____cache_alloc_node(cachep, flags, nodeid);
  out:
	local_irq_restore(save_flags);
	ptr = cache_alloc_debugcheck_after(cachep, flags, ptr, caller);

	if (unlikely(flags & __GFP_ZERO) && ptr)
		memset(ptr, 0, cachep->object_size);

	slab_post_alloc_hook(cachep, flags, 1, &ptr);
	return ptr;
}

static __always_inline void *
__do_cache_alloc(struct kmem_cache *cache, gfp_t flags)
{
	void *objp;

	if (current->mempolicy || cpuset_do_slab_mem_spread()) {
		objp = alternate_node_alloc(cache, flags);
		if (objp)
			goto out;
	}
	objp = ____cache_alloc(cache, flags);

	/*
	 * We may just have run out of memory on the local node.
	 * ____cache_alloc_node() knows how to locate memory on other nodes
	 */
	if (!objp)
		objp = ____cache_alloc_node(cache, flags, numa_mem_id());

  out:
	return objp;
}
#else

static __always_inline void *
__do_cache_alloc(struct kmem_cache *cachep, gfp_t flags)
{
	return ____cache_alloc(cachep, flags);
}

#endif /* CONFIG_NUMA */

static __always_inline void *
slab_alloc(struct kmem_cache *cachep, gfp_t flags, unsigned long caller)
{
	unsigned long save_flags;
	void *objp;

	flags &= gfp_allowed_mask;
	cachep = slab_pre_alloc_hook(cachep, flags);
	if (unlikely(!cachep))
		return NULL;

	cache_alloc_debugcheck_before(cachep, flags);
	local_irq_save(save_flags);
	objp = __do_cache_alloc(cachep, flags);
	local_irq_restore(save_flags);
	objp = cache_alloc_debugcheck_after(cachep, flags, objp, caller);
	prefetchw(objp);

	if (unlikely(flags & __GFP_ZERO) && objp)
		memset(objp, 0, cachep->object_size);

	slab_post_alloc_hook(cachep, flags, 1, &objp);
	return objp;
}

/*
 * Caller needs to acquire correct kmem_cache_node's list_lock
 * @list: List of detached free slabs should be freed by caller
 *
 * 调用方需要获取正确的kmem_cache_node的list_lock
 * @list: 应该被调用者释放的独立的free slabs链表
 */
static void free_block(struct kmem_cache *cachep, void **objpp,
			int nr_objects, int node, struct list_head *list)
{
	int i;
	/* 拿到kmem_cache_node */
	struct kmem_cache_node *n = get_node(cachep, node);
	struct page *page;

	/* 让kmem_cache_node加上我们要free的对象数 */
	n->free_objects += nr_objects;

	/* 对于每个对象进行循环 */
	for (i = 0; i < nr_objects; i++) {
		void *objp;
		struct page *page;
		/* 获得对象的地址 */
		objp = objpp[i];
		/* 将虚拟地址转换成page */
		page = virt_to_head_page(objp);
		/* 把page从lru链表里面删除 */
		list_del(&page->lru);
		check_spinlock_acquired_node(cachep, node);
		/* 释放这个对象 */
		slab_put_obj(cachep, page, objp);
		/* (x)->num_active-- */
		STATS_DEC_ACTIVE(cachep);

		/* fixup slab chains */
		/* 如果该page的active为0,那么把它添加到kmem_cache_node的slabs_free链表里面去 */
		if (page->active == 0)
			list_add(&page->lru, &n->slabs_free);
		else {
			/* Unconditionally move a slab to the end of the
			 * partial list on free - maximum time for the
			 * other objects to be freed, too.
			 *
			 * 把空闲slab 链表无条件地将slab移动到partial list的末尾 - 这也是其他对象被释放的最长时间.
			 */
			/* 如果page里面还有对象,那么把它移动到slabs_partial的末尾 */
			list_add_tail(&page->lru, &n->slabs_partial);
		}
	}

	/* 如果free_objects大于free_limit,并且slabs_free里面不是空的 */
	while (n->free_objects > n->free_limit && !list_empty(&n->slabs_free)) {
		/* n->free_objects - cachep->num */
		n->free_objects -= cachep->num;
		/* 拿到slabs_free里面最后一个对象 */
		page = list_last_entry(&n->slabs_free, struct page, lru);
		/* 把它放到我们的list链表里面去 */
		list_move(&page->lru, list);
		/* num_slabs则是分配的slab个数,每个slab占用一页 */
		n->num_slabs--;
	}
}

static void cache_flusharray(struct kmem_cache *cachep, struct array_cache *ac)
{
	int batchcount;
	struct kmem_cache_node *n;
	int node = numa_mem_id();
	LIST_HEAD(list);

	/* 拿到batchcount */
	batchcount = ac->batchcount;

	check_irq_off();
	/* 得到该node的kmem_cache_node */
	n = get_node(cachep, node);
	spin_lock(&n->list_lock);
	/* 首先判断是否有共享对象缓冲池,如果有,那么就会把本地对象缓冲池中的空闲对象复制到共享对象缓冲池,这里复制batchcount个空闲对象. */
	if (n->shared) {
		struct array_cache *shared_array = n->shared;
		/* 这里算一下,看一下shared_array可以收多少个对象 */
		int max = shared_array->limit - shared_array->avail;
		/* 如果还有的话,就把它复制到共享对象缓冲池中去 */
		if (max) {
			if (batchcount > max)
				batchcount = max;
			memcpy(&(shared_array->entry[shared_array->avail]),
			       ac->entry, sizeof(void *) * batchcount);
			/* shared_array->avail + 上batchcount */
			shared_array->avail += batchcount;
			goto free_done;
		}
	}
	/* 主动释放batchcount个空闲对象 */
	free_block(cachep, ac->entry, batchcount, node, &list);
free_done:
#if STATS
	{
		int i = 0;
		struct page *page;

		/* 这里算出有多少个slabs_free page */
		list_for_each_entry(page, &n->slabs_free, lru) {
			BUG_ON(page->active);

			i++;
		}
		/*
		 *
		 * #define	STATS_SET_FREEABLE(x, i)	\
		 * do {						\
		 *	if ((x)->max_freeable < i)			\
		 *	(x)->max_freeable = i;			\
		 * } while (0)
		 */
		STATS_SET_FREEABLE(cachep, i);
	}
#endif
	/* 解锁 */
	spin_unlock(&n->list_lock);
	/* 销毁slab */
	slabs_destroy(cachep, &list);
	/* 然后减去batchcount */
	ac->avail -= batchcount;
	/* 把本地对象缓存池剩余的空闲对象迁移到buffer的头部 */
	memmove(ac->entry, &(ac->entry[batchcount]), sizeof(void *)*ac->avail);
}

/*
 * Release an obj back to its cache. If the obj has a constructed state, it must
 * be in this state _before_ it is released.  Called with disabled ints.
 */
static inline void __cache_free(struct kmem_cache *cachep, void *objp,
				unsigned long caller)
{
	/* Put the object into the quarantine, don't touch it for now. */
	if (kasan_slab_free(cachep, objp))
		return;

	___cache_free(cachep, objp, caller);
}

void ___cache_free(struct kmem_cache *cachep, void *objp,
		unsigned long caller)
{
	/* 得到本地CPU的arrya_cache结构体指针 */
	struct array_cache *ac = cpu_cache_get(cachep);

	check_irq_off();
	kmemleak_free_recursive(objp, cachep->flags);
	/* 先把对象给填充为free的状态 */
	objp = cache_free_debugcheck(cachep, objp, caller);

	kmemcheck_slab_free(cachep, objp, cachep->object_size);

	/*
	 * Skip calling cache_free_alien() when the platform is not numa.
	 * This will avoid cache misses that happen while accessing slabp (which
	 * is per page memory  reference) to get nodeid. Instead use a global
	 * variable to skip the call, which is mostly likely to be present in
	 * the cache.
	 *
	 * 当平台不是numa时,跳过调用cache_free_alien().
	 * 这将避免在访问slabp(每页内存引用)以获取nodeid时发生cache miss.
	 * 使用全局变量去替代可跳过调用,全局变量很可能存在于缓存中.
	 */

	/* 如果nr_online_nodes大于1就调用cache_free_alien处理
	 * 主要是考虑到NUMA的情况,这里面有个shared
	 */
	if (nr_online_nodes > 1 && cache_free_alien(cachep, objp))
		return;
	/* 如果ac->avail < ac->limit */
	if (ac->avail < ac->limit) {
		/* (cachep)->freehit ++ */
		STATS_INC_FREEHIT(cachep);
	} else {
		/* (cachep)->freemiss ++ */
		STATS_INC_FREEMISS(cachep);
		cache_flusharray(cachep, ac);
	}

	if (sk_memalloc_socks()) {
		struct page *page = virt_to_head_page(objp);

		if (unlikely(PageSlabPfmemalloc(page))) {
			cache_free_pfmemalloc(cachep, page, objp);
			return;
		}
	}

	/* 让本地可用对象指向刚刚释放的这个对象 */
	ac->entry[ac->avail++] = objp;
}

/**
 * kmem_cache_alloc - Allocate an object
 * @cachep: The cache to allocate from.
 * @flags: See kmalloc().
 *
 * Allocate an object from this cache.  The flags are only relevant
 * if the cache has no available objects.
 *
 * kmem_cache_alloc-分配一个对象
 * @cachep：要从中分配的cache
 * @flags：请参见kmalloc（）。
 * 从该cache中分配一个对象.只有当缓存没有可用对象时,这些标志才相关.
 */
void *kmem_cache_alloc(struct kmem_cache *cachep, gfp_t flags)
{
	void *ret = slab_alloc(cachep, flags, _RET_IP_);

	kasan_slab_alloc(cachep, ret, flags);
	trace_kmem_cache_alloc(_RET_IP_, ret,
			       cachep->object_size, cachep->size, flags);

	return ret;
}
EXPORT_SYMBOL(kmem_cache_alloc);

static __always_inline void
cache_alloc_debugcheck_after_bulk(struct kmem_cache *s, gfp_t flags,
				  size_t size, void **p, unsigned long caller)
{
	size_t i;

	for (i = 0; i < size; i++)
		p[i] = cache_alloc_debugcheck_after(s, flags, p[i], caller);
}

int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
			  void **p)
{
	size_t i;

	s = slab_pre_alloc_hook(s, flags);
	if (!s)
		return 0;

	cache_alloc_debugcheck_before(s, flags);

	local_irq_disable();
	for (i = 0; i < size; i++) {
		void *objp = __do_cache_alloc(s, flags);

		if (unlikely(!objp))
			goto error;
		p[i] = objp;
	}
	local_irq_enable();

	cache_alloc_debugcheck_after_bulk(s, flags, size, p, _RET_IP_);

	/* Clear memory outside IRQ disabled section */
	if (unlikely(flags & __GFP_ZERO))
		for (i = 0; i < size; i++)
			memset(p[i], 0, s->object_size);

	slab_post_alloc_hook(s, flags, size, p);
	/* FIXME: Trace call missing. Christoph would like a bulk variant */
	return size;
error:
	local_irq_enable();
	cache_alloc_debugcheck_after_bulk(s, flags, i, p, _RET_IP_);
	slab_post_alloc_hook(s, flags, i, p);
	__kmem_cache_free_bulk(s, i, p);
	return 0;
}
EXPORT_SYMBOL(kmem_cache_alloc_bulk);

#ifdef CONFIG_TRACING
void *
kmem_cache_alloc_trace(struct kmem_cache *cachep, gfp_t flags, size_t size)
{
	void *ret;

	ret = slab_alloc(cachep, flags, _RET_IP_);

	kasan_kmalloc(cachep, ret, size, flags);
	trace_kmalloc(_RET_IP_, ret,
		      size, cachep->size, flags);
	return ret;
}
EXPORT_SYMBOL(kmem_cache_alloc_trace);
#endif

#ifdef CONFIG_NUMA
/**
 * kmem_cache_alloc_node - Allocate an object on the specified node
 * @cachep: The cache to allocate from.
 * @flags: See kmalloc().
 * @nodeid: node number of the target node.
 *
 * Identical to kmem_cache_alloc but it will allocate memory on the given
 * node, which can improve the performance for cpu bound structures.
 *
 * Fallback to other node is possible if __GFP_THISNODE is not set.
 */
void *kmem_cache_alloc_node(struct kmem_cache *cachep, gfp_t flags, int nodeid)
{
	void *ret = slab_alloc_node(cachep, flags, nodeid, _RET_IP_);

	kasan_slab_alloc(cachep, ret, flags);
	trace_kmem_cache_alloc_node(_RET_IP_, ret,
				    cachep->object_size, cachep->size,
				    flags, nodeid);

	return ret;
}
EXPORT_SYMBOL(kmem_cache_alloc_node);

#ifdef CONFIG_TRACING
void *kmem_cache_alloc_node_trace(struct kmem_cache *cachep,
				  gfp_t flags,
				  int nodeid,
				  size_t size)
{
	void *ret;

	ret = slab_alloc_node(cachep, flags, nodeid, _RET_IP_);

	kasan_kmalloc(cachep, ret, size, flags);
	trace_kmalloc_node(_RET_IP_, ret,
			   size, cachep->size,
			   flags, nodeid);
	return ret;
}
EXPORT_SYMBOL(kmem_cache_alloc_node_trace);
#endif

static __always_inline void *
__do_kmalloc_node(size_t size, gfp_t flags, int node, unsigned long caller)
{
	struct kmem_cache *cachep;
	void *ret;

	cachep = kmalloc_slab(size, flags);
	if (unlikely(ZERO_OR_NULL_PTR(cachep)))
		return cachep;
	ret = kmem_cache_alloc_node_trace(cachep, flags, node, size);
	kasan_kmalloc(cachep, ret, size, flags);

	return ret;
}

void *__kmalloc_node(size_t size, gfp_t flags, int node)
{
	return __do_kmalloc_node(size, flags, node, _RET_IP_);
}
EXPORT_SYMBOL(__kmalloc_node);

void *__kmalloc_node_track_caller(size_t size, gfp_t flags,
		int node, unsigned long caller)
{
	return __do_kmalloc_node(size, flags, node, caller);
}
EXPORT_SYMBOL(__kmalloc_node_track_caller);
#endif /* CONFIG_NUMA */

/**
 * __do_kmalloc - allocate memory
 * @size: how many bytes of memory are required.
 * @flags: the type of memory to allocate (see kmalloc).
 * @caller: function caller for debug tracking of the caller
 */
static __always_inline void *__do_kmalloc(size_t size, gfp_t flags,
					  unsigned long caller)
{
	struct kmem_cache *cachep;
	void *ret;

	cachep = kmalloc_slab(size, flags);
	if (unlikely(ZERO_OR_NULL_PTR(cachep)))
		return cachep;
	ret = slab_alloc(cachep, flags, caller);

	kasan_kmalloc(cachep, ret, size, flags);
	trace_kmalloc(caller, ret,
		      size, cachep->size, flags);

	return ret;
}

void *__kmalloc(size_t size, gfp_t flags)
{
	return __do_kmalloc(size, flags, _RET_IP_);
}
EXPORT_SYMBOL(__kmalloc);

void *__kmalloc_track_caller(size_t size, gfp_t flags, unsigned long caller)
{
	return __do_kmalloc(size, flags, caller);
}
EXPORT_SYMBOL(__kmalloc_track_caller);

/**
 * kmem_cache_free - Deallocate an object
 * @cachep: The cache the allocation was from.
 * @objp: The previously allocated object.
 *
 * Free an object which was previously allocated from this
 * cache.
 *
 * kmem_cache_free - 释放一个对象
 * @cachep: 分配的时候的cache
 * @objp: 之前分配的对象
 *
 * 释放之前从此缓存分配的对象.
 */
void kmem_cache_free(struct kmem_cache *cachep, void *objp)
{
	unsigned long flags;
	/* 通过要释放对象obj的虚拟地址找到对应的struct kmem_cache数据结构 */
	cachep = cache_from_obj(cachep, objp);
	if (!cachep)
		return;
	/* local_irq_save 函数用于禁止中断,并且将中断状态保存在 flags 中.local_irq_restore 用于恢复中断,将中断到 flags 状态 */
	local_irq_save(flags);
	debug_check_no_locks_freed(objp, cachep->object_size);
	if (!(cachep->flags & SLAB_DEBUG_OBJECTS))
		debug_check_no_obj_freed(objp, cachep->object_size);
	/* 释放该对象 */
	__cache_free(cachep, objp, _RET_IP_);
	local_irq_restore(flags);

	trace_kmem_cache_free(_RET_IP_, objp);
}
EXPORT_SYMBOL(kmem_cache_free);

void kmem_cache_free_bulk(struct kmem_cache *orig_s, size_t size, void **p)
{
	struct kmem_cache *s;
	size_t i;

	local_irq_disable();
	for (i = 0; i < size; i++) {
		void *objp = p[i];

		if (!orig_s) /* called via kfree_bulk */
			s = virt_to_cache(objp);
		else
			s = cache_from_obj(orig_s, objp);

		debug_check_no_locks_freed(objp, s->object_size);
		if (!(s->flags & SLAB_DEBUG_OBJECTS))
			debug_check_no_obj_freed(objp, s->object_size);

		__cache_free(s, objp, _RET_IP_);
	}
	local_irq_enable();

	/* FIXME: add tracing */
}
EXPORT_SYMBOL(kmem_cache_free_bulk);

/**
 * kfree - free previously allocated memory
 * @objp: pointer returned by kmalloc.
 *
 * If @objp is NULL, no operation is performed.
 *
 * Don't free memory not originally allocated by kmalloc()
 * or you will run into trouble.
 */
void kfree(const void *objp)
{
	struct kmem_cache *c;
	unsigned long flags;

	trace_kfree(_RET_IP_, objp);

	if (unlikely(ZERO_OR_NULL_PTR(objp)))
		return;
	local_irq_save(flags);
	kfree_debugcheck(objp);
	c = virt_to_cache(objp);
	debug_check_no_locks_freed(objp, c->object_size);

	debug_check_no_obj_freed(objp, c->object_size);
	__cache_free(c, (void *)objp, _RET_IP_);
	local_irq_restore(flags);
}
EXPORT_SYMBOL(kfree);

/*
 * This initializes kmem_cache_node or resizes various caches for all nodes.
 *
 * 这将初始化kmem_cache_node或调整所有node的各种缓存的大小
 */
static int setup_kmem_cache_nodes(struct kmem_cache *cachep, gfp_t gfp)
{
	int ret;
	int node;
	struct kmem_cache_node *n;

	/* 对每个node都调用setup_kmem_cache_node */
	for_each_online_node(node) {
		ret = setup_kmem_cache_node(cachep, node, gfp, true);
		if (ret)
			goto fail;

	}

	return 0;

fail:
	if (!cachep->list.next) {
		/* Cache is not active yet. Roll back what we did */
		node--;
		while (node >= 0) {
			n = get_node(cachep, node);
			if (n) {
				kfree(n->shared);
				free_alien_cache(n->alien);
				kfree(n);
				cachep->node[node] = NULL;
			}
			node--;
		}
	}
	return -ENOMEM;
}

/* Always called with the slab_mutex held */
static int __do_tune_cpucache(struct kmem_cache *cachep, int limit,
				int batchcount, int shared, gfp_t gfp)
{
	struct array_cache __percpu *cpu_cache, *prev;
	int cpu;

	/* 首先通过alloc_kmem_cache_cpus函数来分配Per-CPU类型的 struct array_cache数据结构
	 * 我们称之为对象缓冲池.对象缓冲吃中包含了一个Per-CPU类型的struct array_cache指针,
	 * 即系统每个CPU有一个struct array_cache指针
	 */
	cpu_cache = alloc_kmem_cache_cpus(cachep, limit, batchcount);
	if (!cpu_cache)
		return -ENOMEM;

	/* 拿到之前的cpu_cache */
	prev = cachep->cpu_cache;
	/* 把我们刚刚分配好的cpu_cache赋值给这个cachep的cpu_cache */
	cachep->cpu_cache = cpu_cache;
	kick_all_cpus_sync();

	check_irq_on();
	/* 把batchcount、limit、shared都赋值给cachep */
	cachep->batchcount = batchcount;
	cachep->limit = limit;
	cachep->shared = shared;

	/* 如果原来cachep->cpu_cache没有值,那么进入setup_node */
	if (!prev)
		goto setup_node;

	for_each_online_cpu(cpu) {
		/* 初始化list */
		LIST_HEAD(list);
		int node;
		struct kmem_cache_node *n;
		/* 拿到cpu的array_cache */
		struct array_cache *ac = per_cpu_ptr(prev, cpu);
		/* 拿到node_id */
		node = cpu_to_mem(cpu);
		/* 拿到kmem_cache_node结构体 */
		n = get_node(cachep, node);
		spin_lock_irq(&n->list_lock);
		/* 把slab给清除掉 */
		free_block(cachep, ac->entry, ac->avail, node, &list);
		spin_unlock_irq(&n->list_lock);
		/* 然后再把它给销毁 */
		slabs_destroy(cachep, &list);
	}
	/* 释放percpu区域 */
	free_percpu(prev);

setup_node:
	return setup_kmem_cache_nodes(cachep, gfp);
}

static int do_tune_cpucache(struct kmem_cache *cachep, int limit,
				int batchcount, int shared, gfp_t gfp)
{
	int ret;
	struct kmem_cache *c;

	ret = __do_tune_cpucache(cachep, limit, batchcount, shared, gfp);

	if (slab_state < FULL)
		return ret;

	if ((ret < 0) || !is_root_cache(cachep))
		return ret;

	lockdep_assert_held(&slab_mutex);
	for_each_memcg_cache(c, cachep) {
		/* return value determined by the root cache only */
		__do_tune_cpucache(c, limit, batchcount, shared, gfp);
	}

	return ret;
}

/* Called with slab_mutex held always */
static int enable_cpucache(struct kmem_cache *cachep, gfp_t gfp)
{
	int err;
	int limit = 0;
	int shared = 0;
	int batchcount = 0;

	/* cache_random_seq_create会根据object的数量给random_seq数组分配内存,初始化为random_seq[index]=index,然后把顺序打乱再乘object的大小
	 * 然后在每次申请新的slab的时候,会调用shuffle_freelist函数,根据random_seq来把freelist链表的顺序打乱,
	 * 这样内存申请的object 后,下一个可以申请的object的地址也就变的不可预测
	 */
	err = cache_random_seq_create(cachep, cachep->num, gfp);
	if (err)
		goto end;

	if (!is_root_cache(cachep)) {
		struct kmem_cache *root = memcg_root_cache(cachep);
		limit = root->limit;
		shared = root->shared;
		batchcount = root->batchcount;
	}

	if (limit && shared && batchcount)
		goto skip_setup;
	/*
	 * The head array serves three purposes:
	 * - create a LIFO ordering, i.e. return objects that are cache-warm
	 * - reduce the number of spinlock operations.
	 * - reduce the number of linked list operations on the slab and
	 *   bufctl chains: array operations are cheaper.
	 * The numbers are guessed, we should auto-tune as described by
	 * Bonwick.
	 *
	 * 头阵列有三个用途:
	 * - 创建后进先出法排序,即返回cache-warm(热缓存)的对象
	 * - 减少自旋锁操作的次数.
	 * - 减少slab链接链表的操作.
	 *   bufctl chains: 数组操作更廉价.
	 * 这个数量已经猜到了,我们应该像Bonwick描述的那样自动调整
	 */

	/* 根据对象的大小来计算空闲对象的最大阈值limit,这里limit默认选择120 */
	/* 如果大于128K,那么limit等于1 */
	if (cachep->size > 131072)
		limit = 1;	/* 如果大于一个PAGE_SIZE,那么limit = 8 */
	else if (cachep->size > PAGE_SIZE)
		limit = 8;	/* 如果大于1024,那么limit = 24 */
	else if (cachep->size > 1024)
		limit = 24;	/* 如果大于256,那么limit = 54 */
	else if (cachep->size > 256)
		limit = 54;
	else			/* 默认为120 */
		limit = 120;

	/*
	 * CPU bound tasks (e.g. network routing) can exhibit cpu bound
	 * allocation behaviour: Most allocs on one cpu, most free operations
	 * on another cpu. For these cases, an efficient object passing between
	 * cpus is necessary. This is provided by a shared array. The array
	 * replaces Bonwick's magazine layer.
	 * On uniprocessor, it's functionally equivalent (but less efficient)
	 * to a larger limit. Thus disabled by default.
	 *
	 * CPU绑定的任务(例如网络路由)可以表现出CPU绑定的分配行为:
	 * 大多数分配在一个CPU上,大多数free操作在另一个CPU上.
	 * 对于这些情况,需要在cpu之间进行有效的对象传递.
	 * 这是由共享数组提供的.该阵列取代了Bonwick的弹药库层.
	 *
	 * 在单处理器上,它在功能上相当于(但效率较低)一个大的limit.因此在默认情况下被禁用.
	 */
	shared = 0;

	/* 如果cachep->size比PAGE_SIZE小,且CPU的数量大于1
	 * 那么设置shared为8
	 */
	if (cachep->size <= PAGE_SIZE && num_possible_cpus() > 1)
		shared = 8;

#if DEBUG
	/*
	 * With debugging enabled, large batchcount lead to excessively long
	 * periods with disabled local interrupts. Limit the batchcount
	 *
	 * 在debugging enabled的情况下,大的batchcount 会导致禁用本地中断的时间过长.
	 * 限制batchcount
	 */

	/* 如果limit大于32,那么把limit设置为32 */
	if (limit > 32)
		limit = 32;
#endif
	/* batchcount为limit的一半 */
	batchcount = (limit + 1) / 2;
skip_setup:
	err = do_tune_cpucache(cachep, limit, batchcount, shared, gfp);
end:
	if (err)
		pr_err("enable_cpucache failed for %s, error %d\n",
		       cachep->name, -err);
	return err;
}

/*
 * Drain an array if it contains any elements taking the node lock only if
 * necessary. Note that the node listlock also protects the array_cache
 * if drain_array() is used on the shared array.
 */
static void drain_array(struct kmem_cache *cachep, struct kmem_cache_node *n,
			 struct array_cache *ac, int node)
{
	LIST_HEAD(list);

	/* ac from n->shared can be freed if we don't hold the slab_mutex. */
	check_mutex_acquired();

	if (!ac || !ac->avail)
		return;

	if (ac->touched) {
		ac->touched = 0;
		return;
	}

	spin_lock_irq(&n->list_lock);
	drain_array_locked(cachep, ac, node, false, &list);
	spin_unlock_irq(&n->list_lock);

	slabs_destroy(cachep, &list);
}

/**
 * cache_reap - Reclaim memory from caches.
 * @w: work descriptor
 *
 * Called from workqueue/eventd every few seconds.
 * Purpose:
 * - clear the per-cpu caches for this CPU.
 * - return freeable pages to the main free memory pool.
 *
 * If we cannot acquire the cache chain mutex then just give up - we'll try
 * again on the next iteration.
 */
static void cache_reap(struct work_struct *w)
{
	struct kmem_cache *searchp;
	struct kmem_cache_node *n;
	int node = numa_mem_id();
	struct delayed_work *work = to_delayed_work(w);

	if (!mutex_trylock(&slab_mutex))
		/* Give up. Setup the next iteration. */
		goto out;

	list_for_each_entry(searchp, &slab_caches, list) {
		check_irq_on();

		/*
		 * We only take the node lock if absolutely necessary and we
		 * have established with reasonable certainty that
		 * we can do some work if the lock was obtained.
		 */
		n = get_node(searchp, node);

		reap_alien(searchp, n);

		drain_array(searchp, n, cpu_cache_get(searchp), node);

		/*
		 * These are racy checks but it does not matter
		 * if we skip one check or scan twice.
		 */
		if (time_after(n->next_reap, jiffies))
			goto next;

		n->next_reap = jiffies + REAPTIMEOUT_NODE;

		drain_array(searchp, n, n->shared, node);

		if (n->free_touched)
			n->free_touched = 0;
		else {
			int freed;

			freed = drain_freelist(searchp, n, (n->free_limit +
				5 * searchp->num - 1) / (5 * searchp->num));
			STATS_ADD_REAPED(searchp, freed);
		}
next:
		cond_resched();
	}
	check_irq_on();
	mutex_unlock(&slab_mutex);
	next_reap_node();
out:
	/* Set up the next iteration */
	schedule_delayed_work(work, round_jiffies_relative(REAPTIMEOUT_AC));
}

#ifdef CONFIG_SLABINFO
void get_slabinfo(struct kmem_cache *cachep, struct slabinfo *sinfo)
{
	struct page *page;
	unsigned long active_objs;
	unsigned long num_objs;
	unsigned long active_slabs = 0;
	unsigned long num_slabs, free_objects = 0, shared_avail = 0;
	unsigned long num_slabs_partial = 0, num_slabs_free = 0;
	unsigned long num_slabs_full = 0;
	const char *name;
	char *error = NULL;
	int node;
	struct kmem_cache_node *n;

	active_objs = 0;
	num_slabs = 0;
	for_each_kmem_cache_node(cachep, node, n) {

		check_irq_on();
		spin_lock_irq(&n->list_lock);

		num_slabs += n->num_slabs;

		list_for_each_entry(page, &n->slabs_partial, lru) {
			if (page->active == cachep->num && !error)
				error = "slabs_partial accounting error";
			if (!page->active && !error)
				error = "slabs_partial accounting error";
			active_objs += page->active;
			num_slabs_partial++;
		}

		list_for_each_entry(page, &n->slabs_free, lru) {
			if (page->active && !error)
				error = "slabs_free accounting error";
			num_slabs_free++;
		}

		free_objects += n->free_objects;
		if (n->shared)
			shared_avail += n->shared->avail;

		spin_unlock_irq(&n->list_lock);
	}
	num_objs = num_slabs * cachep->num;
	active_slabs = num_slabs - num_slabs_free;
	num_slabs_full = num_slabs - (num_slabs_partial + num_slabs_free);
	active_objs += (num_slabs_full * cachep->num);

	if (num_objs - active_objs != free_objects && !error)
		error = "free_objects accounting error";

	name = cachep->name;
	if (error)
		pr_err("slab: cache %s error: %s\n", name, error);

	sinfo->active_objs = active_objs;
	sinfo->num_objs = num_objs;
	sinfo->active_slabs = active_slabs;
	sinfo->num_slabs = num_slabs;
	sinfo->shared_avail = shared_avail;
	sinfo->limit = cachep->limit;
	sinfo->batchcount = cachep->batchcount;
	sinfo->shared = cachep->shared;
	sinfo->objects_per_slab = cachep->num;
	sinfo->cache_order = cachep->gfporder;
}

void slabinfo_show_stats(struct seq_file *m, struct kmem_cache *cachep)
{
#if STATS
	{			/* node stats */
		unsigned long high = cachep->high_mark;
		unsigned long allocs = cachep->num_allocations;
		unsigned long grown = cachep->grown;
		unsigned long reaped = cachep->reaped;
		unsigned long errors = cachep->errors;
		unsigned long max_freeable = cachep->max_freeable;
		unsigned long node_allocs = cachep->node_allocs;
		unsigned long node_frees = cachep->node_frees;
		unsigned long overflows = cachep->node_overflow;

		seq_printf(m, " : globalstat %7lu %6lu %5lu %4lu %4lu %4lu %4lu %4lu %4lu",
			   allocs, high, grown,
			   reaped, errors, max_freeable, node_allocs,
			   node_frees, overflows);
	}
	/* cpu stats */
	{
		unsigned long allochit = atomic_read(&cachep->allochit);
		unsigned long allocmiss = atomic_read(&cachep->allocmiss);
		unsigned long freehit = atomic_read(&cachep->freehit);
		unsigned long freemiss = atomic_read(&cachep->freemiss);

		seq_printf(m, " : cpustat %6lu %6lu %6lu %6lu",
			   allochit, allocmiss, freehit, freemiss);
	}
#endif
}

#define MAX_SLABINFO_WRITE 128
/**
 * slabinfo_write - Tuning for the slab allocator
 * @file: unused
 * @buffer: user buffer
 * @count: data length
 * @ppos: unused
 */
ssize_t slabinfo_write(struct file *file, const char __user *buffer,
		       size_t count, loff_t *ppos)
{
	char kbuf[MAX_SLABINFO_WRITE + 1], *tmp;
	int limit, batchcount, shared, res;
	struct kmem_cache *cachep;

	if (count > MAX_SLABINFO_WRITE)
		return -EINVAL;
	if (copy_from_user(&kbuf, buffer, count))
		return -EFAULT;
	kbuf[MAX_SLABINFO_WRITE] = '\0';

	tmp = strchr(kbuf, ' ');
	if (!tmp)
		return -EINVAL;
	*tmp = '\0';
	tmp++;
	if (sscanf(tmp, " %d %d %d", &limit, &batchcount, &shared) != 3)
		return -EINVAL;

	/* Find the cache in the chain of caches. */
	mutex_lock(&slab_mutex);
	res = -EINVAL;
	list_for_each_entry(cachep, &slab_caches, list) {
		if (!strcmp(cachep->name, kbuf)) {
			if (limit < 1 || batchcount < 1 ||
					batchcount > limit || shared < 0) {
				res = 0;
			} else {
				res = do_tune_cpucache(cachep, limit,
						       batchcount, shared,
						       GFP_KERNEL);
			}
			break;
		}
	}
	mutex_unlock(&slab_mutex);
	if (res >= 0)
		res = count;
	return res;
}

#ifdef CONFIG_DEBUG_SLAB_LEAK

static inline int add_caller(unsigned long *n, unsigned long v)
{
	unsigned long *p;
	int l;
	if (!v)
		return 1;
	l = n[1];
	p = n + 2;
	while (l) {
		int i = l/2;
		unsigned long *q = p + 2 * i;
		if (*q == v) {
			q[1]++;
			return 1;
		}
		if (*q > v) {
			l = i;
		} else {
			p = q + 2;
			l -= i + 1;
		}
	}
	if (++n[1] == n[0])
		return 0;
	memmove(p + 2, p, n[1] * 2 * sizeof(unsigned long) - ((void *)p - (void *)n));
	p[0] = v;
	p[1] = 1;
	return 1;
}

static void handle_slab(unsigned long *n, struct kmem_cache *c,
						struct page *page)
{
	void *p;
	int i, j;
	unsigned long v;

	if (n[0] == n[1])
		return;
	for (i = 0, p = page->s_mem; i < c->num; i++, p += c->size) {
		bool active = true;

		for (j = page->active; j < c->num; j++) {
			if (get_free_obj(page, j) == i) {
				active = false;
				break;
			}
		}

		if (!active)
			continue;

		/*
		 * probe_kernel_read() is used for DEBUG_PAGEALLOC. page table
		 * mapping is established when actual object allocation and
		 * we could mistakenly access the unmapped object in the cpu
		 * cache.
		 */
		if (probe_kernel_read(&v, dbg_userword(c, p), sizeof(v)))
			continue;

		if (!add_caller(n, v))
			return;
	}
}

static void show_symbol(struct seq_file *m, unsigned long address)
{
#ifdef CONFIG_KALLSYMS
	unsigned long offset, size;
	char modname[MODULE_NAME_LEN], name[KSYM_NAME_LEN];

	if (lookup_symbol_attrs(address, &size, &offset, modname, name) == 0) {
		seq_printf(m, "%s+%#lx/%#lx", name, offset, size);
		if (modname[0])
			seq_printf(m, " [%s]", modname);
		return;
	}
#endif
	seq_printf(m, "%p", (void *)address);
}

static int leaks_show(struct seq_file *m, void *p)
{
	struct kmem_cache *cachep = list_entry(p, struct kmem_cache, list);
	struct page *page;
	struct kmem_cache_node *n;
	const char *name;
	unsigned long *x = m->private;
	int node;
	int i;

	if (!(cachep->flags & SLAB_STORE_USER))
		return 0;
	if (!(cachep->flags & SLAB_RED_ZONE))
		return 0;

	/*
	 * Set store_user_clean and start to grab stored user information
	 * for all objects on this cache. If some alloc/free requests comes
	 * during the processing, information would be wrong so restart
	 * whole processing.
	 */
	do {
		set_store_user_clean(cachep);
		drain_cpu_caches(cachep);

		x[1] = 0;

		for_each_kmem_cache_node(cachep, node, n) {

			check_irq_on();
			spin_lock_irq(&n->list_lock);

			list_for_each_entry(page, &n->slabs_full, lru)
				handle_slab(x, cachep, page);
			list_for_each_entry(page, &n->slabs_partial, lru)
				handle_slab(x, cachep, page);
			spin_unlock_irq(&n->list_lock);
		}
	} while (!is_store_user_clean(cachep));

	name = cachep->name;
	if (x[0] == x[1]) {
		/* Increase the buffer size */
		mutex_unlock(&slab_mutex);
		m->private = kzalloc(x[0] * 4 * sizeof(unsigned long), GFP_KERNEL);
		if (!m->private) {
			/* Too bad, we are really out */
			m->private = x;
			mutex_lock(&slab_mutex);
			return -ENOMEM;
		}
		*(unsigned long *)m->private = x[0] * 2;
		kfree(x);
		mutex_lock(&slab_mutex);
		/* Now make sure this entry will be retried */
		m->count = m->size;
		return 0;
	}
	for (i = 0; i < x[1]; i++) {
		seq_printf(m, "%s: %lu ", name, x[2*i+3]);
		show_symbol(m, x[2*i+2]);
		seq_putc(m, '\n');
	}

	return 0;
}

static const struct seq_operations slabstats_op = {
	.start = slab_start,
	.next = slab_next,
	.stop = slab_stop,
	.show = leaks_show,
};

static int slabstats_open(struct inode *inode, struct file *file)
{
	unsigned long *n;

	n = __seq_open_private(file, &slabstats_op, PAGE_SIZE);
	if (!n)
		return -ENOMEM;

	*n = PAGE_SIZE / (2 * sizeof(unsigned long));

	return 0;
}

static const struct file_operations proc_slabstats_operations = {
	.open		= slabstats_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release_private,
};
#endif

static int __init slab_proc_init(void)
{
#ifdef CONFIG_DEBUG_SLAB_LEAK
	proc_create("slab_allocators", 0, NULL, &proc_slabstats_operations);
#endif
	return 0;
}
module_init(slab_proc_init);
#endif

#ifdef CONFIG_HARDENED_USERCOPY
/*
 * Rejects objects that are incorrectly sized.
 *
 * Returns NULL if check passes, otherwise const char * to name of cache
 * to indicate an error.
 */
const char *__check_heap_object(const void *ptr, unsigned long n,
				struct page *page)
{
	struct kmem_cache *cachep;
	unsigned int objnr;
	unsigned long offset;

	/* Find and validate object. */
	cachep = page->slab_cache;
	objnr = obj_to_index(cachep, page, (void *)ptr);
	BUG_ON(objnr >= cachep->num);

	/* Find offset within object. */
	offset = ptr - index_to_obj(cachep, page, objnr) - obj_offset(cachep);

	/* Allow address range falling entirely within object size. */
	if (offset <= cachep->object_size && n <= cachep->object_size - offset)
		return NULL;

	return cachep->name;
}
#endif /* CONFIG_HARDENED_USERCOPY */

/**
 * ksize - get the actual amount of memory allocated for a given object
 * @objp: Pointer to the object
 *
 * kmalloc may internally round up allocations and return more memory
 * than requested. ksize() can be used to determine the actual amount of
 * memory allocated. The caller may use this additional memory, even though
 * a smaller amount of memory was initially specified with the kmalloc call.
 * The caller must guarantee that objp points to a valid object previously
 * allocated with either kmalloc() or kmem_cache_alloc(). The object
 * must not be freed during the duration of the call.
 */
size_t ksize(const void *objp)
{
	size_t size;

	BUG_ON(!objp);
	if (unlikely(objp == ZERO_SIZE_PTR))
		return 0;

	size = virt_to_cache(objp)->object_size;
	/* We assume that ksize callers could use the whole allocated area,
	 * so we need to unpoison this area.
	 */
	kasan_unpoison_shadow(objp, size);

	return size;
}
EXPORT_SYMBOL(ksize);
