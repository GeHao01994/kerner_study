/*
 * Workingset detection
 *
 * Copyright (C) 2013 Red Hat, Inc., Johannes Weiner
 */

#include <linux/memcontrol.h>
#include <linux/writeback.h>
#include <linux/pagemap.h>
#include <linux/atomic.h>
#include <linux/module.h>
#include <linux/swap.h>
#include <linux/fs.h>
#include <linux/mm.h>

/*
 *		Double CLOCK lists
 *
 * Per node, two clock lists are maintained for file pages: the
 * inactive and the active list.  Freshly faulted pages start out at
 * the head of the inactive list and page reclaim scans pages from the
 * tail.  Pages that are accessed multiple times on the inactive list
 * are promoted to the active list, to protect them from reclaim,
 * whereas active pages are demoted to the inactive list when the
 * active list grows too big.
 *
 *
 * 双时钟列表
 *
 * 每个节点为文件页维护两个时钟列表: 不活动和活动列表。
 * 出现新故障的页面(新的文件页)放到不活跃链表的头
 * 页面回收从尾部开始扫描.
 * 在非活跃列表中多次访问的页面将移动到活跃列表,以保护它们不被回收，
 * 而当atcive列表增长过大，那么活跃链表会被降级到非活跃链表
 *
 *   fault ------------------------+
 *                                 |
 *              +--------------+   |            +-------------+
 *   reclaim <- |   inactive   | <-+-- demotion |    active   | <--+
 *              +--------------+       （降级） +-------------+    |
 *                     |                                           |
 *                     +-------------- promotion ------------------+
 *					（升级）
 *
 *		Access frequency and refault distance
 *
 * A workload is thrashing when its pages are frequently used but they
 * are evicted from the inactive list every time before another access
 * would have promoted them to the active list.
 *
 * 当它的页面频繁使用，但是在其他人访问访问让他们升级到活跃链表之前它们从不活跃链表逐出
 * 该工作负载就会剧烈波动.
 *
 * In cases where the average access distance between thrashing pages
 * is bigger than the size of memory there is nothing that can be
 * done - the thrashing set could never fit into memory under any
 * circumstance.
 *
 *
 * 在颠簸页面之间的平均访问距离大于内存大小的情况下，无法采取任何措施
 * - 在任何情况下，颠簸集都无法放入内存.
 *
 * However, the average access distance could be bigger than the
 * inactive list, yet smaller than the size of memory.  In this case,
 * the set could fit into memory if it weren't for the currently
 * active pages - which may be used more, hopefully less frequently:
 *
 * 然而，平均访问距离可能大于非活动列表，但小于内存大小.
 * 在这种情况下，如果不是针对当前活动的页面，该集可能会被放入内存中
 * - 这些页面可能会被更多地使用，希望不那么频繁:
 *
 *      +-memory available to cache-+
 *      |                           |
 *      +-inactive------+-active----+
 *  a b | c d e f g h i | J K L M N |
 *      +---------------+-----------+
 *
 * It is prohibitively expensive to accurately track access frequency
 * of pages.  But a reasonable approximation can be made to measure
 * thrashing on the inactive list, after which refaulting pages can be
 * activated optimistically to compete with the existing active pages.
 *
 * 准确跟踪页面的访问频率是非常昂贵的.
 * 但是，可以进行合理的近似来测量非活动列表上的颠簸,
 * 之后可以乐观地激活重新检查页面，以与现有的活动页面竞争.
 *
 * Approximating inactive page access frequency - Observations:
 *
 * 1. When a page is accessed for the first time, it is added to the
 *    head of the inactive list, slides every existing inactive page
 *    towards the tail by one slot, and pushes the current tail page
 *    out of memory.
 *
 * 1.当一个页面第一次被访问时，它被添加到非活动列表的头部，将每个现有的非活动页面向尾部滑动一个插槽，并将当前的尾部页面挤出内存.
 *
 * 2. When a page is accessed for the second time, it is promoted to
 *    the active list, shrinking the inactive list by one slot.  This
 *    also slides all inactive pages that were faulted into the cache
 *    more recently than the activated page towards the tail of the
 *    inactive list.
 *
 * 2.当第二次访问页面时，它将被提升到活动列表，将非活动列表缩小一个插槽.
 * 这还会将最近出现故障的所有非活动页面滑入缓存这是活跃页面划入非活跃页面的尾部
 *
 * Thus:
 *
 * 1. The sum of evictions and activations between any two points in
 *    time indicate the minimum number of inactive pages accessed in
 *    between.
 *
 * 因此：
 * 1. 任意两个时间点之间的驱逐(换出)和激活(变成active)的总和为其间访问的最小非活动页面数.
 *
 * 2. Moving one inactive page N page slots towards the tail of the
 *    list requires at least N inactive page accesses.
 *
 * 2. 向列表尾部移动一个非活跃page N page的槽 至少需要N次非活跃链表的访问
 *
 * Combining these:
 * 结合这些
 * 1. When a page is finally evicted from memory, the number of
 *    inactive pages accessed while the page was in cache is at least
 *    the number of page slots on the inactive list.
 *
 * 1. 当一个页面最终从内存中移出时，该页面在cache中非活跃页面访问的数量
 *    至少非活跃链表的页面槽的数量
 *
 * 2. In addition, measuring the sum of evictions and activations (E)
 *    at the time of a page's eviction, and comparing it to another
 *    reading (R) at the time the page faults back into memory tells
 *    the minimum number of accesses while the page was not cached.
 *    This is called the refault distance.
 *
 * 2. 额外的，一个页面被换出的时间估量为被驱逐(换出)和激活(E)的总和
 *    比较它和另外一个读者此时page faults 返回进内存 告诉这个最小访问数量
 *    当一个页面没有缓存，这个成为refault 距离
 *
 * Because the first access of the page was the fault and the second
 * access the refault, we combine the in-cache distance with the
 * out-of-cache distance to get the complete minimum access distance
 * of this page:
 *
 * 由于页面的第一次访问是fault，第二次访问是refault,
 * 我们将缓存内距离与缓存外距离相结合，得出该页面的完整最小访问距离：
 * R表示another reading (R)
 * E表示the sum of evictions and activations
 *      NR_inactive + (R - E)
 *
 * And knowing the minimum access distance of a page, we can easily
 * tell if the page would be able to stay in cache assuming all page
 * slots in the cache were available:
 *
 *   NR_inactive + (R - E) <= NR_inactive + NR_active
 *
 * which can be further simplified to
 *
 *   (R - E) <= NR_active
 *
 * Put into words, the refault distance (out-of-cache) can be seen as
 * a deficit in inactive list space (in-cache).  If the inactive list
 * had (R - E) more page slots, the page would not have been evicted
 * in between accesses, but activated instead.  And on a full system,
 * the only thing eating into inactive list space is active pages.
 *
 *
 *		Activating refaulting pages
 *
 * All that is known about the active list is that the pages have been
 * accessed more than once in the past.  This means that at any given
 * time there is actually a good chance that pages on the active list
 * are no longer in active use.
 *
 * So when a refault distance of (R - E) is observed and there are at
 * least (R - E) active pages, the refaulting page is activated
 * optimistically in the hope that (R - E) active pages are actually
 * used less frequently than the refaulting page - or even not used at
 * all anymore.
 *
 * If this is wrong and demotion kicks in, the pages which are truly
 * used more frequently will be reactivated while the less frequently
 * used once will be evicted from memory.
 *
 * But if this is right, the stale pages will be pushed out of memory
 * and the used pages get to stay in cache.
 *
 *
 *		Implementation
 *
 * For each node's file LRU lists, a counter for inactive evictions
 * and activations is maintained (node->inactive_age).
 *
 * On eviction, a snapshot of this counter (along with some bits to
 * identify the node) is stored in the now empty page cache radix tree
 * slot of the evicted page.  This is called a shadow entry.
 *
 * On cache misses for which there are shadow entries, an eligible
 * refault distance will immediately activate the refaulting page.
 */

/* 在学术界和linux内核社区，页面回收算法的优化一直没有停止过，其中Refault Distance算法在Linux 3.15版本中被加入，作为是社区专家johannes Weiner，该算法目前只针对page cache类型的页面.
 * 对于page cache类型的LRU链表来说，有两个链表值得关注，分别是活跃链表和不活跃链表.
 * 新产生的page总是加入到不活跃链表的头部，页面回收也总是从不活跃链表的尾部开始回收.
 * 不活跃链表的页面第二次访问时会升级(promote)到活跃链表，防止被回收;
 * 另一方面如果活跃链表增长太快，那么活跃的页面会被降级(demote)到不活跃链表中.
 *
 * 实际上有一些场景，某些页面经常被访问，但是它们在下一次被访问之前就在不活跃链表中被回收并释放了，
 * 那么又必须从存储系统中读取这些page cache页面，这些场景下产生颠簸现象(thrashing).
 *
 * 当我们观察文件缓存不活跃链表的行为特征时，会发现如下有趣特征。
 * 1.有一个page cache页面第一次访问时，它加入到不活跃链表头，然后慢慢从链表头向链表尾移动，链表尾的page cache 会被踢出LRU链表并且释放页面，这个过程叫做eviction(移出)。
 * 2.当第二次访问时，page cache被升级到活跃LRU链表，这样不活跃链表也空出一个位置，这个过程叫作activation(激活).
 * 3.从宏观时间轴来看，eviction过程处理的页面数量与activation过程处理的页数量的和等于不活跃链表的长度NR_inactive。
 * 4.要从不活跃链表中释放一个页面，需要移动N个页面(N = 不活跃链表长度).
 *
 * 综合上面的一些行为特征，定义了Refault Distance的概念.
 * 第一次访问page cache称为fault，第二次访问该页面称为refault.
 * page cache页面第一次被踢出LRU链表并回收(eviction)的时刻称为E，第二次再访问该页的时刻称为R，那么R-E的时间里需要移动的页面个数称为Refault Distance.
 *
 * 把Refault Distance概念再加上第一次读的时刻，可以用一个公式来概括第一次和第二次读之间的距离(read_distance).
 * 	read_distance = nr_inactive + (R-E)
 *
 * 如果page想一直保持在LRU链表中，那么read_distance不应该比内存的大小还长，否则该page永远都会被踢出LRU链表，因此公式可以推导为:
 *
 *  NR_inactive+（R-E） <= NR_inactive+NR_active
 *  (R-E) <= NR_active
 *
 * 换句话说，Refault Distance 可以理解为不活跃链表的"财政赤字"，
 * 如果不活跃链表常熟至少再延长Refault Distance，那么就可以保证该page cache在第二次读之前不会被踢出LRU链表并释放内存，
 * 否则就要把该page cache重新加入活跃链表加以保护，以防内存颠簸.
 * 在理想情况下，page cache的平均访问距离要大于不活跃链表，小于总的内存大小。
 * 上述内容讨论了两次读的距离小于等于内存大小的情况，即NR_inactive+(R-E)<= NR_inactive+NR_active,如果两次读的距离大于内存大小呢？
 * 这种特殊情况不是Refault Distance算法能解决的问题，因为它在第二次读时永远已经被踢出LRU链表，因为可以假设第二次读发生在遥远的未来，但谁都无法保证它在LRU链表中.
 * 其实Refault Distance算法是为了解决前者，在第二次读时，
 * 人为地把page cache添加到活跃链表从而防止该page cache被踢出LRU链表而带来的内存颠簸.
 *
 *  不活跃LRU长度              活跃LRU长度
 *  ________________ ___________________________
 * |________________|___________________________|
 *
 * | 不活跃LRU长度  | Refault_distance |
 *————————————————————————————————————————————→ 时间轴
 * T0               T1		       T2
 * 第一次读         第一次被          第二次读
 * add_to_page_     踢出LRU           workingset_refault
 * cache_lru        把当期zone->      1、Refault_distance=T2-T1
 * 分配shadow       inactive_age      2、如果Refault_distance <= ACTIVE_LIST
 *                  的值的编码存放       说明该page的平均访问时间隙会导致page被提出LRU,
 *                  在shadow中           所以就actived该页面并且加入活跃链表
 *
 * 如上图，T0时刻表示一个page cache第一次访问，
 * 这时会调用 add_to_page_cache_lru()函数来分配一个shadow用来存储zone->inactive_age值，
 * 每当有页面被promote到活跃链表时，zone->inactive_age值会加1，每当有页面被踢出不活跃链表时,zone->inactive_age也会加1.
 * T1时刻表示该页被踢出LRU链表并从LRU链表中回收释放，
 * 这时把当前T1时刻的zone->inactive_age的值编码存放到shadow中.
 * T2时刻是该页第二次读，这时要计算Refault Distance，Refault Distance = T2 - T1,
 * 如果Refault Distance <= NR_active，
 * 说明该page cache极有可能在下一次读时已经被踢出LRU链表，
 * 因此要人为地actived该页面并且加入活跃链表中
 */
#define EVICTION_SHIFT	(RADIX_TREE_EXCEPTIONAL_ENTRY + \
			 NODES_SHIFT +	\
			 MEM_CGROUP_ID_SHIFT)
#define EVICTION_MASK	(~0UL >> EVICTION_SHIFT)

/*
 * Eviction timestamps need to be able to cover the full range of
 * actionable refaults. However, bits are tight in the radix tree
 * entry, and after storing the identifier for the lruvec there might
 * not be enough left to represent every single actionable refault. In
 * that case, we have to sacrifice granularity for distance, and group
 * evictions into coarser buckets by shaving off lower timestamp bits.
 */
static unsigned int bucket_order __read_mostly;

static void *pack_shadow(int memcgid, pg_data_t *pgdat, unsigned long eviction)
{
	eviction >>= bucket_order;
	eviction = (eviction << MEM_CGROUP_ID_SHIFT) | memcgid;
	eviction = (eviction << NODES_SHIFT) | pgdat->node_id;
	eviction = (eviction << RADIX_TREE_EXCEPTIONAL_SHIFT);

	return (void *)(eviction | RADIX_TREE_EXCEPTIONAL_ENTRY);
}

static void unpack_shadow(void *shadow, int *memcgidp, pg_data_t **pgdat,
			  unsigned long *evictionp)
{
	unsigned long entry = (unsigned long)shadow;
	int memcgid, nid;

	entry >>= RADIX_TREE_EXCEPTIONAL_SHIFT;
	nid = entry & ((1UL << NODES_SHIFT) - 1);
	entry >>= NODES_SHIFT;
	memcgid = entry & ((1UL << MEM_CGROUP_ID_SHIFT) - 1);
	entry >>= MEM_CGROUP_ID_SHIFT;

	*memcgidp = memcgid;
	*pgdat = NODE_DATA(nid);
	*evictionp = entry << bucket_order;
}

/**
 * workingset_eviction - note the eviction of a page from memory
 * @mapping: address space the page was backing
 * @page: the page being evicted
 *
 * Returns a shadow entry to be stored in @mapping->page_tree in place
 * of the evicted @page so that a later refault can be detected.
 */
void *workingset_eviction(struct address_space *mapping, struct page *page)
{
	struct mem_cgroup *memcg = page_memcg(page);
	struct pglist_data *pgdat = page_pgdat(page);
	int memcgid = mem_cgroup_id(memcg);
	unsigned long eviction;
	struct lruvec *lruvec;

	/* Page is fully exclusive and pins page->mem_cgroup */
	VM_BUG_ON_PAGE(PageLRU(page), page);
	VM_BUG_ON_PAGE(page_count(page), page);
	VM_BUG_ON_PAGE(!PageLocked(page), page);

	lruvec = mem_cgroup_lruvec(pgdat, memcg);
	eviction = atomic_long_inc_return(&lruvec->inactive_age);
	return pack_shadow(memcgid, pgdat, eviction);
}

/**
 * workingset_refault - evaluate the refault of a previously evicted page
 * @shadow: shadow entry of the evicted page
 *
 * Calculates and evaluates the refault distance of the previously
 * evicted page in the context of the node it was allocated in.
 *
 * Returns %true if the page should be activated, %false otherwise.
 */
bool workingset_refault(void *shadow)
{
	unsigned long refault_distance;
	unsigned long active_file;
	struct mem_cgroup *memcg;
	unsigned long eviction;
	struct lruvec *lruvec;
	unsigned long refault;
	struct pglist_data *pgdat;
	int memcgid;

	unpack_shadow(shadow, &memcgid, &pgdat, &eviction);

	rcu_read_lock();
	/*
	 * Look up the memcg associated with the stored ID. It might
	 * have been deleted since the page's eviction.
	 *
	 * Note that in rare events the ID could have been recycled
	 * for a new cgroup that refaults a shared page. This is
	 * impossible to tell from the available data. However, this
	 * should be a rare and limited disturbance, and activations
	 * are always speculative anyway. Ultimately, it's the aging
	 * algorithm's job to shake out the minimum access frequency
	 * for the active cache.
	 *
	 * XXX: On !CONFIG_MEMCG, this will always return NULL; it
	 * would be better if the root_mem_cgroup existed in all
	 * configurations instead.
	 */
	memcg = mem_cgroup_from_id(memcgid);
	if (!mem_cgroup_disabled() && !memcg) {
		rcu_read_unlock();
		return false;
	}
	lruvec = mem_cgroup_lruvec(pgdat, memcg);
	refault = atomic_long_read(&lruvec->inactive_age);
	active_file = lruvec_lru_size(lruvec, LRU_ACTIVE_FILE, MAX_NR_ZONES);
	rcu_read_unlock();

	/*
	 * The unsigned subtraction here gives an accurate distance
	 * across inactive_age overflows in most cases.
	 *
	 * There is a special case: usually, shadow entries have a
	 * short lifetime and are either refaulted or reclaimed along
	 * with the inode before they get too old.  But it is not
	 * impossible for the inactive_age to lap a shadow entry in
	 * the field, which can then can result in a false small
	 * refault distance, leading to a false activation should this
	 * old entry actually refault again.  However, earlier kernels
	 * used to deactivate unconditionally with *every* reclaim
	 * invocation for the longest time, so the occasional
	 * inappropriate activation leading to pressure on the active
	 * list is not a problem.
	 */
	refault_distance = (refault - eviction) & EVICTION_MASK;

	inc_node_state(pgdat, WORKINGSET_REFAULT);

	if (refault_distance <= active_file) {
		inc_node_state(pgdat, WORKINGSET_ACTIVATE);
		return true;
	}
	return false;
}

/**
 * workingset_activation - note a page activation
 * @page: page that is being activated
 */
void workingset_activation(struct page *page)
{
	struct mem_cgroup *memcg;
	struct lruvec *lruvec;

	rcu_read_lock();
	/*
	 * Filter non-memcg pages here, e.g. unmap can call
	 * mark_page_accessed() on VDSO pages.
	 *
	 * XXX: See workingset_refault() - this should return
	 * root_mem_cgroup even for !CONFIG_MEMCG.
	 */
	memcg = page_memcg_rcu(page);
	if (!mem_cgroup_disabled() && !memcg)
		goto out;
	lruvec = mem_cgroup_lruvec(page_pgdat(page), memcg);
	atomic_long_inc(&lruvec->inactive_age);
out:
	rcu_read_unlock();
}

/*
 * Shadow entries reflect the share of the working set that does not
 * fit into memory, so their number depends on the access pattern of
 * the workload.  In most cases, they will refault or get reclaimed
 * along with the inode, but a (malicious) workload that streams
 * through files with a total size several times that of available
 * memory, while preventing the inodes from being reclaimed, can
 * create excessive amounts of shadow nodes.  To keep a lid on this,
 * track shadow nodes and reclaim them when they grow way past the
 * point where they would still be useful.
 */

struct list_lru workingset_shadow_nodes;

static unsigned long count_shadow_nodes(struct shrinker *shrinker,
					struct shrink_control *sc)
{
	unsigned long shadow_nodes;
	unsigned long max_nodes;
	unsigned long pages;

	/* list_lru lock nests inside IRQ-safe mapping->tree_lock */
	local_irq_disable();
	shadow_nodes = list_lru_shrink_count(&workingset_shadow_nodes, sc);
	local_irq_enable();

	if (sc->memcg) {
		pages = mem_cgroup_node_nr_lru_pages(sc->memcg, sc->nid,
						     LRU_ALL_FILE);
	} else {
		pages = node_page_state(NODE_DATA(sc->nid), NR_ACTIVE_FILE) +
			node_page_state(NODE_DATA(sc->nid), NR_INACTIVE_FILE);
	}

	/*
	 * Active cache pages are limited to 50% of memory, and shadow
	 * entries that represent a refault distance bigger than that
	 * do not have any effect.  Limit the number of shadow nodes
	 * such that shadow entries do not exceed the number of active
	 * cache pages, assuming a worst-case node population density
	 * of 1/8th on average.
	 *
	 * On 64-bit with 7 radix_tree_nodes per page and 64 slots
	 * each, this will reclaim shadow entries when they consume
	 * ~2% of available memory:
	 *
	 * PAGE_SIZE / radix_tree_nodes / node_entries / PAGE_SIZE
	 */
	max_nodes = pages >> (1 + RADIX_TREE_MAP_SHIFT - 3);

	if (shadow_nodes <= max_nodes)
		return 0;

	return shadow_nodes - max_nodes;
}

static enum lru_status shadow_lru_isolate(struct list_head *item,
					  struct list_lru_one *lru,
					  spinlock_t *lru_lock,
					  void *arg)
{
	struct address_space *mapping;
	struct radix_tree_node *node;
	unsigned int i;
	int ret;

	/*
	 * Page cache insertions and deletions synchroneously maintain
	 * the shadow node LRU under the mapping->tree_lock and the
	 * lru_lock.  Because the page cache tree is emptied before
	 * the inode can be destroyed, holding the lru_lock pins any
	 * address_space that has radix tree nodes on the LRU.
	 *
	 * We can then safely transition to the mapping->tree_lock to
	 * pin only the address_space of the particular node we want
	 * to reclaim, take the node off-LRU, and drop the lru_lock.
	 */

	node = container_of(item, struct radix_tree_node, private_list);
	mapping = node->private_data;

	/* Coming from the list, invert the lock order */
	if (!spin_trylock(&mapping->tree_lock)) {
		spin_unlock(lru_lock);
		ret = LRU_RETRY;
		goto out;
	}

	list_lru_isolate(lru, item);
	spin_unlock(lru_lock);

	/*
	 * The nodes should only contain one or more shadow entries,
	 * no pages, so we expect to be able to remove them all and
	 * delete and free the empty node afterwards.
	 */
	BUG_ON(!workingset_node_shadows(node));
	BUG_ON(workingset_node_pages(node));

	for (i = 0; i < RADIX_TREE_MAP_SIZE; i++) {
		if (node->slots[i]) {
			BUG_ON(!radix_tree_exceptional_entry(node->slots[i]));
			node->slots[i] = NULL;
			workingset_node_shadows_dec(node);
			BUG_ON(!mapping->nrexceptional);
			mapping->nrexceptional--;
		}
	}
	BUG_ON(workingset_node_shadows(node));
	inc_node_state(page_pgdat(virt_to_page(node)), WORKINGSET_NODERECLAIM);
	if (!__radix_tree_delete_node(&mapping->page_tree, node))
		BUG();

	spin_unlock(&mapping->tree_lock);
	ret = LRU_REMOVED_RETRY;
out:
	local_irq_enable();
	cond_resched();
	local_irq_disable();
	spin_lock(lru_lock);
	return ret;
}

static unsigned long scan_shadow_nodes(struct shrinker *shrinker,
				       struct shrink_control *sc)
{
	unsigned long ret;

	/* list_lru lock nests inside IRQ-safe mapping->tree_lock */
	local_irq_disable();
	ret =  list_lru_shrink_walk(&workingset_shadow_nodes, sc,
				    shadow_lru_isolate, NULL);
	local_irq_enable();
	return ret;
}

static struct shrinker workingset_shadow_shrinker = {
	.count_objects = count_shadow_nodes,
	.scan_objects = scan_shadow_nodes,
	.seeks = DEFAULT_SEEKS,
	.flags = SHRINKER_NUMA_AWARE | SHRINKER_MEMCG_AWARE,
};

/*
 * Our list_lru->lock is IRQ-safe as it nests inside the IRQ-safe
 * mapping->tree_lock.
 */
static struct lock_class_key shadow_nodes_key;

static int __init workingset_init(void)
{
	unsigned int timestamp_bits;
	unsigned int max_order;
	int ret;

	BUILD_BUG_ON(BITS_PER_LONG < EVICTION_SHIFT);
	/*
	 * Calculate the eviction bucket size to cover the longest
	 * actionable refault distance, which is currently half of
	 * memory (totalram_pages/2). However, memory hotplug may add
	 * some more pages at runtime, so keep working with up to
	 * double the initial memory by using totalram_pages as-is.
	 */
	timestamp_bits = BITS_PER_LONG - EVICTION_SHIFT;
	max_order = fls_long(totalram_pages - 1);
	if (max_order > timestamp_bits)
		bucket_order = max_order - timestamp_bits;
	pr_info("workingset: timestamp_bits=%d max_order=%d bucket_order=%u\n",
	       timestamp_bits, max_order, bucket_order);

	ret = __list_lru_init(&workingset_shadow_nodes, true, &shadow_nodes_key);
	if (ret)
		goto err;
	ret = register_shrinker(&workingset_shadow_shrinker);
	if (ret)
		goto err_list_lru;
	return 0;
err_list_lru:
	list_lru_destroy(&workingset_shadow_nodes);
err:
	return ret;
}
module_init(workingset_init);
