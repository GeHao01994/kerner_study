/*
 *  linux/mm/swap.c
 *
 *  Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 */

/*
 * This file contains the default values for the operation of the
 * Linux VM subsystem. Fine-tuning documentation can be found in
 * Documentation/sysctl/vm.txt.
 * Started 18.12.91
 * Swap aging added 23.2.95, Stephen Tweedie.
 * Buffermem limits added 12.3.98, Rik van Riel.
 */

#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/kernel_stat.h>
#include <linux/swap.h>
#include <linux/mman.h>
#include <linux/pagemap.h>
#include <linux/pagevec.h>
#include <linux/init.h>
#include <linux/export.h>
#include <linux/mm_inline.h>
#include <linux/percpu_counter.h>
#include <linux/memremap.h>
#include <linux/percpu.h>
#include <linux/cpu.h>
#include <linux/notifier.h>
#include <linux/backing-dev.h>
#include <linux/memcontrol.h>
#include <linux/gfp.h>
#include <linux/uio.h>
#include <linux/hugetlb.h>
#include <linux/page_idle.h>

#include "internal.h"

#define CREATE_TRACE_POINTS
#include <trace/events/pagemap.h>

/* How many pages do we try to swap or page in/out together? */
int page_cluster;
/* lru_add_pvec 将不处于lru链表的新页放入到lru链表中 */
static DEFINE_PER_CPU(struct pagevec, lru_add_pvec);
/* lru_rotate_pvecs INACTIVE 缓存已经在INACTIVE LRU链表中的非活动页，将这些页添加到INACTIVE LRU链表的尾部*/
static DEFINE_PER_CPU(struct pagevec, lru_rotate_pvecs);
/* 将一个page cache移到inactive lru里（比如手工触发drop cache释放pagecache) */
static DEFINE_PER_CPU(struct pagevec, lru_deactivate_file_pvecs);
/* 缓存已经在ACTIVE LRU链表中的页，清除掉PG_activate, PG_referenced标志后，将这些页加入到INACTIVE LRU链表中 */
static DEFINE_PER_CPU(struct pagevec, lru_deactivate_pvecs);
#ifdef CONFIG_SMP
/* 将非活跃lru链表的页移动到活跃lru链表 */
static DEFINE_PER_CPU(struct pagevec, activate_page_pvecs);
#endif

/*
 * This path almost never happens for VM activity - pages are normally
 * freed via pagevecs.  But it gets used by networking.
 */
/* 这个path几乎重来不会发生在VM的活动-pages通常通过pagevec释放
 * 但是他被networking使用
 */
static void __page_cache_release(struct page *page)
{
	/* 如果Page在LRU里面 */
	if (PageLRU(page)) {
		/* 获得page所在的zone */
		struct zone *zone = page_zone(page);
		struct lruvec *lruvec;
		unsigned long flags;

		spin_lock_irqsave(zone_lru_lock(zone), flags);
		lruvec = mem_cgroup_page_lruvec(page, zone->zone_pgdat);
		VM_BUG_ON_PAGE(!PageLRU(page), page);
		/* 清掉Page的LRU flag */
		__ClearPageLRU(page);
		/* 从lru链表里面拔掉这个page */
		del_page_from_lru_list(page, lruvec, page_off_lru(page));
		spin_unlock_irqrestore(zone_lru_lock(zone), flags);
	}
	mem_cgroup_uncharge(page);
}

static void __put_single_page(struct page *page)
{
	__page_cache_release(page);
	free_hot_cold_page(page, false);
}

static void __put_compound_page(struct page *page)
{
	compound_page_dtor *dtor;

	/*
	 * __page_cache_release() is supposed to be called for thp, not for
	 * hugetlb. This is because hugetlb page does never have PageLRU set
	 * (it's never listed to any LRU lists) and no memcg routines should
	 * be called for hugetlb (it has a separate hugetlb_cgroup.)
	 *
	 * __page_cache_release()应该被用于THP(透明大页)而不是用于hugetlb(巨大页).
	 * 这是因为hugetlb页面永远不会设置PageLRU(它从未被加入到任何LRU列表中),
	 * 并且对于hugetlb来说,不应该调用任何memcg(内存控制组)例程(因为它有一个独立的hugetlb_cgroup来处理).
	 */

	/* 如果不是HUGETLB,那么就调用__page_cache_release */
	if (!PageHuge(page))
		__page_cache_release(page);
	/* 去拿到复合页面的析构函数
	 *
	 * static inline compound_page_dtor *get_compound_page_dtor(struct page *page)
	 * {
	 *	VM_BUG_ON_PAGE(page[1].compound_dtor >= NR_COMPOUND_DTORS, page);
	 *	return compound_page_dtors[page[1].compound_dtor];
	 * }
	 */
	dtor = get_compound_page_dtor(page);
	/* 调用这析构函数 */
	(*dtor)(page);
}

void __put_page(struct page *page)
{
	/* 如果该page是复合页面 */
	if (unlikely(PageCompound(page)))
		__put_compound_page(page);
	else
		__put_single_page(page);
}
EXPORT_SYMBOL(__put_page);

/**
 * put_pages_list() - release a list of pages
 * @pages: list of pages threaded on page->lru
 *
 * Release a list of pages which are strung together on page.lru.  Currently
 * used by read_cache_pages() and related error recovery code.
 */
void put_pages_list(struct list_head *pages)
{
	while (!list_empty(pages)) {
		struct page *victim;

		victim = list_entry(pages->prev, struct page, lru);
		list_del(&victim->lru);
		put_page(victim);
	}
}
EXPORT_SYMBOL(put_pages_list);

/*
 * get_kernel_pages() - pin kernel pages in memory
 * @kiov:	An array of struct kvec structures
 * @nr_segs:	number of segments to pin
 * @write:	pinning for read/write, currently ignored
 * @pages:	array that receives pointers to the pages pinned.
 *		Should be at least nr_segs long.
 *
 * Returns number of pages pinned. This may be fewer than the number
 * requested. If nr_pages is 0 or negative, returns 0. If no pages
 * were pinned, returns -errno. Each page returned must be released
 * with a put_page() call when it is finished with.
 */
int get_kernel_pages(const struct kvec *kiov, int nr_segs, int write,
		struct page **pages)
{
	int seg;

	for (seg = 0; seg < nr_segs; seg++) {
		if (WARN_ON(kiov[seg].iov_len != PAGE_SIZE))
			return seg;

		pages[seg] = kmap_to_page(kiov[seg].iov_base);
		get_page(pages[seg]);
	}

	return seg;
}
EXPORT_SYMBOL_GPL(get_kernel_pages);

/*
 * get_kernel_page() - pin a kernel page in memory
 * @start:	starting kernel address
 * @write:	pinning for read/write, currently ignored
 * @pages:	array that receives pointer to the page pinned.
 *		Must be at least nr_segs long.
 *
 * Returns 1 if page is pinned. If the page was not pinned, returns
 * -errno. The page returned must be released with a put_page() call
 * when it is finished with.
 */
int get_kernel_page(unsigned long start, int write, struct page **pages)
{
	const struct kvec kiov = {
		.iov_base = (void *)start,
		.iov_len = PAGE_SIZE
	};

	return get_kernel_pages(&kiov, 1, write, pages);
}
EXPORT_SYMBOL_GPL(get_kernel_page);

static void pagevec_lru_move_fn(struct pagevec *pvec,
	void (*move_fn)(struct page *page, struct lruvec *lruvec, void *arg),
	void *arg)
{
	int i;
	struct pglist_data *pgdat = NULL;
	struct lruvec *lruvec;
	unsigned long flags = 0;
	/* 对pagevec里面的那个page进行处理 */
	for (i = 0; i < pagevec_count(pvec); i++) {
		/* 获取page */
		struct page *page = pvec->pages[i];
		/* 获得相应的pglist */
		struct pglist_data *pagepgdat = page_pgdat(page);
		/* 判断是否为同一个node，同一个node不需要加锁，否则需要加锁处理 */
		if (pagepgdat != pgdat) {
			if (pgdat)
				spin_unlock_irqrestore(&pgdat->lru_lock, flags);
			pgdat = pagepgdat;
			spin_lock_irqsave(&pgdat->lru_lock, flags);
		}

		lruvec = mem_cgroup_page_lruvec(page, pgdat);
		/* 调用我们传过来的move函数 */
		(*move_fn)(page, lruvec, arg);
	}
	if (pgdat)
		spin_unlock_irqrestore(&pgdat->lru_lock, flags);
	/* 减少page的引用值，当引用值为0时，从LRU链表中移除页表并释放掉 */
	release_pages(pvec->pages, pvec->nr, pvec->cold);
	/* 重置pvec->nr = 0 */
	pagevec_reinit(pvec);
}

static void pagevec_move_tail_fn(struct page *page, struct lruvec *lruvec,
				 void *arg)
{
	int *pgmoved = arg;
	/* 如果PAGE在LRU链表里面,且不是Active和不可回收的 */
	if (PageLRU(page) && !PageActive(page) && !PageUnevictable(page)) {
		/* static inline enum lru_list page_lru_base_type(struct page *page)
		 * {
		 *	if (page_is_file_cache(page))
		 *		return LRU_INACTIVE_FILE;
		 *	return LRU_INACTIVE_ANON;
		 * }
		 */
		enum lru_list lru = page_lru_base_type(page);
		/* 将其添加到相应链表的尾部 */
		list_move_tail(&page->lru, &lruvec->lists[lru]);
		/* pgrotated 被移动到lru链表末尾的page个数 +1 */
		(*pgmoved)++;
	}
}

/*
 * pagevec_move_tail() must be called with IRQ disabled.
 * Otherwise this may cause nasty races.
 */
static void pagevec_move_tail(struct pagevec *pvec)
{
	int pgmoved = 0;

	pagevec_lru_move_fn(pvec, pagevec_move_tail_fn, &pgmoved);
	/* pgrotated  被移动到lru链表末尾的page个数
	 * 这里就是将该CPU的vm_event_states.event[PGROTATED] + pgmoved */
	__count_vm_events(PGROTATED, pgmoved);
}

/*
 * Writeback is about to end against a page which has been marked for immediate
 * reclaim.  If it still appears to be reclaimable, move it to the tail of the
 * inactive list.
 */
void rotate_reclaimable_page(struct page *page)
{
	if (!PageLocked(page) && !PageDirty(page) && !PageActive(page) &&
	    !PageUnevictable(page) && PageLRU(page)) {
		struct pagevec *pvec;
		unsigned long flags;

		get_page(page);
		local_irq_save(flags);
		pvec = this_cpu_ptr(&lru_rotate_pvecs);
		if (!pagevec_add(pvec, page) || PageCompound(page))
			pagevec_move_tail(pvec);
		local_irq_restore(flags);
	}
}

static void update_page_reclaim_stat(struct lruvec *lruvec,
				     int file, int rotated)
{
	struct zone_reclaim_stat *reclaim_stat = &lruvec->reclaim_stat;

	reclaim_stat->recent_scanned[file]++;
	/* recent_rotated
	 * 在扫描不活跃链表时，统计那些被踢回活跃链表的页面数量到recent_rotated变量中，
	 * 详见shrink_inactive_list()->putback_inactive_pages()函数。
	 * 在扫描活跃页面时，访问引用的页面数量也被加到recent_rotated变量。
	 * 总之，该变量反映了真实的活跃页面的数量
	 */
	if (rotated)
		reclaim_stat->recent_rotated[file]++;
}

static void __activate_page(struct page *page, struct lruvec *lruvec,
			    void *arg)
{
	/* 如果page在LRU里面里面，且是不活跃的，并且不是不可回收的 */
	if (PageLRU(page) && !PageActive(page) && !PageUnevictable(page)) {
		int file = page_is_file_cache(page);
		int lru = page_lru_base_type(page);
		/* 从相关的lru链表里面拔掉 */
		del_page_from_lru_list(page, lruvec, lru);
		/* 设置为active的 */
		SetPageActive(page);
		lru += LRU_ACTIVE;
		/* 添加到ACTIVE链表中 */
		add_page_to_lru_list(page, lruvec, lru);
		trace_mm_lru_activate(page);
		/* vm_event_states.event[PGACTIVATE] + 1 */
		__count_vm_event(PGACTIVATE);
		/* 更新对应lruvec的reclaim_stat */
		update_page_reclaim_stat(lruvec, file, 1);
	}
}

#ifdef CONFIG_SMP
static void activate_page_drain(int cpu)
{
	/* 这里拿到本CPU的activate_page_pvecs向量,这里是将非活跃lru链表的页移动到活跃lru链表 */
	struct pagevec *pvec = &per_cpu(activate_page_pvecs, cpu);
	/*
	 * 如果里面有东西,也不管满不满,都给他移动到活跃链表里面去
	 *  static inline unsigned pagevec_count(struct pagevec *pvec)
	 * {
	 *	return pvec->nr;
	 * }
	 */
	if (pagevec_count(pvec))
		pagevec_lru_move_fn(pvec, __activate_page, NULL);
}

static bool need_activate_page_drain(int cpu)
{
	return pagevec_count(&per_cpu(activate_page_pvecs, cpu)) != 0;
}

void activate_page(struct page *page)
{
	page = compound_head(page);
	if (PageLRU(page) && !PageActive(page) && !PageUnevictable(page)) {
		struct pagevec *pvec = &get_cpu_var(activate_page_pvecs);

		get_page(page);
		if (!pagevec_add(pvec, page) || PageCompound(page))
			pagevec_lru_move_fn(pvec, __activate_page, NULL);
		put_cpu_var(activate_page_pvecs);
	}
}

#else
static inline void activate_page_drain(int cpu)
{
}

static bool need_activate_page_drain(int cpu)
{
	return false;
}

void activate_page(struct page *page)
{
	struct zone *zone = page_zone(page);

	page = compound_head(page);
	spin_lock_irq(zone_lru_lock(zone));
	__activate_page(page, mem_cgroup_page_lruvec(page, zone->zone_pgdat), NULL);
	spin_unlock_irq(zone_lru_lock(zone));
}
#endif

static void __lru_cache_activate_page(struct page *page)
{
	/* lru_add_pvec 将不处于lru链表的新页放入到lru链表中
	 * 所以这里拿到本都CPU的lru_add_pvec
	 */
	struct pagevec *pvec = &get_cpu_var(lru_add_pvec);
	int i;

	/*
	 * Search backwards on the optimistic assumption that the page being
	 * activated has just been added to this pagevec. Note that only
	 * the local pagevec is examined as a !PageLRU page could be in the
	 * process of being released, reclaimed, migrated or on a remote
	 * pagevec that is currently being drained. Furthermore, marking
	 * a remote pagevec's page PageActive potentially hits a race where
	 * a page is marked PageActive just after it is added to the inactive
	 * list causing accounting errors and BUG_ON checks to trigger.
	 *
	 * 在乐观的假设下向后搜索,即正在激活的页面刚刚添加到此页面vec.
	 * 请注意,只有本地pagevec被检查为!PageLRU页面可能正在被释放、回收、迁移或在远程当前正在drained的pagevec.
	 * 此外,标记一个远程的pagevec的页面PageActive可能会引发静态,即页面在添加到非活动列表后立即被标记为PageActive,从而引发计数错误和BUG_ON检查,
	 */

	/* 从pagevec的最后一个开始查询,看我们的目标page有没有在这里面
	 * 如果有把它设置为active
	 */
	for (i = pagevec_count(pvec) - 1; i >= 0; i--) {
		struct page *pagevec_page = pvec->pages[i];

		if (pagevec_page == page) {
			SetPageActive(page);
			break;
		}
	}

	put_cpu_var(lru_add_pvec);
}

/*
 * Mark a page as having seen activity.
 *
 * inactive,unreferenced	->	inactive,referenced
 * inactive,referenced		->	active,unreferenced
 * active,unreferenced		->	active,referenced
 *
 * When a newly allocated page is not yet visible, so safe for non-atomic ops,
 * __SetPageReferenced(page) may be substituted for mark_page_accessed(page).
 *
 * inactive,unreferenced	->	inactive,referenced
 * inactive,referenced		->	active,unreferenced
 * active,unreferenced		->	active,referenced
 *
 * 当新分配的页面还不可见(因此对于非原子操作是安全的)时,__SetPageReferenced(page)可以代替mark_page_accessed(page)
 */
void mark_page_accessed(struct page *page)
{
	/* 拿到复合页面的头 */
	page = compound_head(page);
	/* 如果这个page不是活跃的,不是不可回收的并且PG_referenced是被置位的 */
	if (!PageActive(page) && !PageUnevictable(page) &&
			PageReferenced(page)) {

		/*
		 * If the page is on the LRU, queue it for activation via
		 * activate_page_pvecs. Otherwise, assume the page is on a
		 * pagevec, mark it active and it'll be moved to the active
		 * LRU on the next drain.
		 *
		 * 如果页面在LRU上,则通过activate_page_pvecs将其排队进活跃链表里.
		 * 否则,假设页面在pagevec上,将其标记为活跃页面,并在下一个drain的时候将其移动到活跃LRU上
		 */
		if (PageLRU(page))
			activate_page(page);
		else
			__lru_cache_activate_page(page);
		/* 清除PG_referenced */
		ClearPageReferenced(page);
		/* 如果是pagecache,调用workingset_activation函数增加zone->inactive_page计数 */
		if (page_is_file_cache(page))
			workingset_activation(page);
	/* 如果没有PG_referenced,那么设置PG_referenced */
	} else if (!PageReferenced(page)) {
		SetPageReferenced(page);
	}
	if (page_is_idle(page))
		clear_page_idle(page);
}
EXPORT_SYMBOL(mark_page_accessed);

static void __lru_cache_add(struct page *page)
{
	/* 拿到本地CPU的lru_add_pvec */
	struct pagevec *pvec = &get_cpu_var(lru_add_pvec);

	/* 将该page的_refcount + 1 */
	get_page(page);
	/* pagevec_add就是把该page添加到向量pagevec中,如果没有空间了,那么就调用__pagevec_lru_add函数把原有的page加入到LRU链表中 */
	if (!pagevec_add(pvec, page) || PageCompound(page))
		__pagevec_lru_add(pvec);
	put_cpu_var(lru_add_pvec);
}

/**
 * lru_cache_add: add a page to the page lists
 * @page: the page to add
 */
void lru_cache_add_anon(struct page *page)
{
	if (PageActive(page))
		ClearPageActive(page);
	__lru_cache_add(page);
}

void lru_cache_add_file(struct page *page)
{
	if (PageActive(page))
		ClearPageActive(page);
	__lru_cache_add(page);
}
EXPORT_SYMBOL(lru_cache_add_file);

/**
 * lru_cache_add - add a page to a page list
 * @page: the page to be added to the LRU.
 *
 * Queue the page for addition to the LRU via pagevec. The decision on whether
 * to add the page to the [in]active [file|anon] list is deferred until the
 * pagevec is drained. This gives a chance for the caller of lru_cache_add()
 * have the page added to the active list using mark_page_accessed().
 */
void lru_cache_add(struct page *page)
{
	VM_BUG_ON_PAGE(PageActive(page) && PageUnevictable(page), page);
	VM_BUG_ON_PAGE(PageLRU(page), page);
	__lru_cache_add(page);
}

/**
 * add_page_to_unevictable_list - add a page to the unevictable list
 * @page:  the page to be added to the unevictable list
 *
 * Add page directly to its zone's unevictable list.  To avoid races with
 * tasks that might be making the page evictable, through eg. munlock,
 * munmap or exit, while it's not on the lru, we want to add the page
 * while it's locked or otherwise "invisible" to other tasks.  This is
 * difficult to do when using the pagevec cache, so bypass that.
 *
 * add_page_to_unevictable_list-将页面添加到不可回收链表
 * @page: 要添加到不可回收链表的页面
 *
 * 将页面直接添加到其zone的不可回收列表中.
 * 为了避免在页面不在lru上时,通过例如munlock、munmap或exit让页面变得可回收的tasks发生竞争,
 * 我们希望在页面被locked 或 其他tasks “不可见”的情况下添加页面.
 * 当使用pagevec缓存时,这很难做到,所以请绕过它.
 */
void add_page_to_unevictable_list(struct page *page)
{
	struct pglist_data *pgdat = page_pgdat(page);
	struct lruvec *lruvec;

	spin_lock_irq(&pgdat->lru_lock);
	/* 获得lruvec 变量 */
	lruvec = mem_cgroup_page_lruvec(page, pgdat);
	/* 清除该page的PG_active */
	ClearPageActive(page);
	/* 设置页面的PG_unevictable */
	SetPageUnevictable(page);
	/* 设置page的PG_lru flag */
	SetPageLRU(page);
	/* 把页面添加到不可回收链表里面去 */
	add_page_to_lru_list(page, lruvec, LRU_UNEVICTABLE);
	spin_unlock_irq(&pgdat->lru_lock);
}

/**
 * lru_cache_add_active_or_unevictable
 * @page:  the page to be added to LRU
 * @vma:   vma in which page is mapped for determining reclaimability
 *
 * Place @page on the active or unevictable LRU list, depending on its
 * evictability.  Note that if the page is not evictable, it goes
 * directly back onto it's zone's unevictable list, it does NOT use a
 * per cpu pagevec.
 */
void lru_cache_add_active_or_unevictable(struct page *page,
					 struct vm_area_struct *vma)
{
	VM_BUG_ON_PAGE(PageLRU(page), page);

	if (likely((vma->vm_flags & (VM_LOCKED | VM_SPECIAL)) != VM_LOCKED)) {
		SetPageActive(page);
		lru_cache_add(page);
		return;
	}

	if (!TestSetPageMlocked(page)) {
		/*
		 * We use the irq-unsafe __mod_zone_page_stat because this
		 * counter is not modified from interrupt context, and the pte
		 * lock is held(spinlock), which implies preemption disabled.
		 */
		__mod_zone_page_state(page_zone(page), NR_MLOCK,
				    hpage_nr_pages(page));
		count_vm_event(UNEVICTABLE_PGMLOCKED);
	}
	add_page_to_unevictable_list(page);
}

/*
 * If the page can not be invalidated, it is moved to the
 * inactive list to speed up its reclaim.  It is moved to the
 * head of the list, rather than the tail, to give the flusher
 * threads some time to write it out, as this is much more
 * effective than the single-page writeout from reclaim.
 *
 * If the page isn't page_mapped and dirty/writeback, the page
 * could reclaim asap using PG_reclaim.
 *
 * 1. active, mapped page -> none
 * 2. active, dirty/writeback page -> inactive, head, PG_reclaim
 * 3. inactive, mapped page -> none
 * 4. inactive, dirty/writeback page -> inactive, head, PG_reclaim
 * 5. inactive, clean -> inactive, tail
 * 6. Others -> none
 *
 * In 4, why it moves inactive's head, the VM expects the page would
 * be write it out by flusher threads as this is much more effective
 * than the single-page writeout from reclaim.
 */
/*
 * 如果页面不能invalidated，它移动到inactive list里面去加速它的回收.
 * 他被移动到链表的头部，而不是尾部，去给flusher线程一点时间把它写出
 * 因为这笔从回收中写出单个页面有效得多
 *
 * 如果页面不是page_mapped和dirty/writeback,这个页面能使用PG_reclaim尽快回收
 */
static void lru_deactivate_file_fn(struct page *page, struct lruvec *lruvec,
			      void *arg)
{
	int lru, file;
	bool active;
	/* 如果page没有在LRU链表里面，则返回 */
	if (!PageLRU(page))
		return;
	/* 如果page是不可回收的，那么也返回 */
	if (PageUnevictable(page))
		return;

	/* Some processes are using the page */
	/* 如果page还是mapped，也就是说还有进程在用它，那么也返回 */
	if (page_mapped(page))
		return;
	/* 判断该页是不是active的 */
	active = PageActive(page);
	/* 判断该页是不是Page cache */
	file = page_is_file_cache(page);
	/* static inline enum lru_list page_lru_base_type(struct page *page)
	 * {
	 *	if (page_is_file_cache(page))
	 *		return LRU_INACTIVE_FILE;
	 *	return LRU_INACTIVE_ANON;
	 * }
	 */
	lru = page_lru_base_type(page);
	/* 把这些页面从活跃链表里面移除 */
	del_page_from_lru_list(page, lruvec, lru + active);
	/* 清除active 位 */
	ClearPageActive(page);
	/* 清除PG_referenced 位 */
	ClearPageReferenced(page);
	/* 将它添加到不活跃链表里面 */
	add_page_to_lru_list(page, lruvec, lru);
	/* 如果page中的数据正在被回写到后备存储器，或者说Page是脏的 */
	if (PageWriteback(page) || PageDirty(page)) {
		/*
		 * PG_reclaim could be raced with end_page_writeback
		 * It can make readahead confusing.  But race window
		 * is _really_ small and  it's non-critical problem.
		 */
		/* 那么设置页面为正在进行回收，只有在内存回收时才会对需要回收的页进行此标记 */
		SetPageReclaim(page);
	} else {
		/*
		 * The page's writeback ends up during pagevec
		 * We moves tha page into tail of inactive.
		 */
		/* 页面的写回在pagevec期间结束。我们将页面移动到inactive的尾部 */
		list_move_tail(&page->lru, &lruvec->lists[lru]);
		/* 增加vmstate的被移动到lru链表末尾的page个数 */
		__count_vm_event(PGROTATED);
	}
	/* 增加vmstate的PGDEACTIVATE（被移入非活跃lru链表的page个数)计数 */
	if (active)
		__count_vm_event(PGDEACTIVATE);
	/* 将reclaim_stat中的recent_scanned + 1，但是recent_rotated不会+1，因为你不是active的 */
	update_page_reclaim_stat(lruvec, file, 0);
}


static void lru_deactivate_fn(struct page *page, struct lruvec *lruvec,
			    void *arg)
{
	/* 如果PAGE在LRU里面，然后又是active的且还是不是不可回收的 */
	if (PageLRU(page) && PageActive(page) && !PageUnevictable(page)) {
		int file = page_is_file_cache(page);
		int lru = page_lru_base_type(page);
		/* 从原来的lru链表里面删除 */
		del_page_from_lru_list(page, lruvec, lru + LRU_ACTIVE);
		/* 清除active和reference位 */
		ClearPageActive(page);
		ClearPageReferenced(page);
		/* 添加到inactive链表里面 */
		add_page_to_lru_list(page, lruvec, lru);
		/* 增加vmstate的PGDEACTIVATE（被移入非活跃lru链表的page个数)计数 */
		__count_vm_event(PGDEACTIVATE);
		/* 将reclaim_stat中的recent_scanned + 1，但是recent_rotated不会+1，因为你不是active的 */
		update_page_reclaim_stat(lruvec, file, 0);
	}
}

/*
 * Drain pages out of the cpu's pagevecs.
 * Either "cpu" is the current CPU, and preemption has already been
 * disabled; or "cpu" is being hot-unplugged, and is already dead.
 */
/* 排出cpu的pagevec的页面
 * “cpu”是当前的cpu，并且抢占已经被禁用；
 * 或者“cpu”正在被热插拔拔掉，并且已经死了
 */
void lru_add_drain_cpu(int cpu)
{
	/* lru_add_pvec 将不处于lru链表的新页放入到lru链表 */
	struct pagevec *pvec = &per_cpu(lru_add_pvec, cpu);
	/* 这里lru_add_pvec有东西，就开始__pagevec_lru_add
	 * 而不需要判断这个向量表是不是满了
	 */
	if (pagevec_count(pvec))
		__pagevec_lru_add(pvec);
	/* lru_rotate_pvecs INACTIVE 缓存已经在INACTIVE LRU链表中的非活动页，将这些页添加到INACTIVE LRU链表的尾部
	 * 这里就是开始处理这个pvec */
	pvec = &per_cpu(lru_rotate_pvecs, cpu);
	/* 这里lru_add_pvec有东西，就开始pagevec_move_tail
	 * 而不需要判断这个向量表是不是满了
	 */
	if (pagevec_count(pvec)) {
		unsigned long flags;

		/* No harm done if a racing interrupt already did this */
		local_irq_save(flags);
		pagevec_move_tail(pvec);
		local_irq_restore(flags);
	}
	/* 处理需要移入到非活跃文件lru链表的页面 */
	pvec = &per_cpu(lru_deactivate_file_pvecs, cpu);
	if (pagevec_count(pvec))
		pagevec_lru_move_fn(pvec, lru_deactivate_file_fn, NULL);
	/* 处理需要移入到非活跃匿名页面lru链表的页面 */
	pvec = &per_cpu(lru_deactivate_pvecs, cpu);
	if (pagevec_count(pvec))
		pagevec_lru_move_fn(pvec, lru_deactivate_fn, NULL);
	/* 处理将非活跃链表需要加入活跃链表的情况 */
	activate_page_drain(cpu);
}

/**
 * deactivate_file_page - forcefully deactivate a file page
 * @page: page to deactivate
 *
 * This function hints the VM that @page is a good reclaim candidate,
 * for example if its invalidation fails due to the page being dirty
 * or under writeback.
 */
void deactivate_file_page(struct page *page)
{
	/*
	 * In a workload with many unevictable page such as mprotect,
	 * unevictable page deactivation for accelerating reclaim is pointless.
	 */
	if (PageUnevictable(page))
		return;

	if (likely(get_page_unless_zero(page))) {
		struct pagevec *pvec = &get_cpu_var(lru_deactivate_file_pvecs);

		if (!pagevec_add(pvec, page) || PageCompound(page))
			pagevec_lru_move_fn(pvec, lru_deactivate_file_fn, NULL);
		put_cpu_var(lru_deactivate_file_pvecs);
	}
}

/**
 * deactivate_page - deactivate a page
 * @page: page to deactivate
 *
 * deactivate_page() moves @page to the inactive list if @page was on the active
 * list and was not an unevictable page.  This is done to accelerate the reclaim
 * of @page.
 */
void deactivate_page(struct page *page)
{
	if (PageLRU(page) && PageActive(page) && !PageUnevictable(page)) {
		struct pagevec *pvec = &get_cpu_var(lru_deactivate_pvecs);

		get_page(page);
		if (!pagevec_add(pvec, page) || PageCompound(page))
			pagevec_lru_move_fn(pvec, lru_deactivate_fn, NULL);
		put_cpu_var(lru_deactivate_pvecs);
	}
}

void lru_add_drain(void)
{
	lru_add_drain_cpu(get_cpu());
	put_cpu();
}

static void lru_add_drain_per_cpu(struct work_struct *dummy)
{
	lru_add_drain();
}

static DEFINE_PER_CPU(struct work_struct, lru_add_drain_work);

/*
 * lru_add_drain_wq is used to do lru_add_drain_all() from a WQ_MEM_RECLAIM
 * workqueue, aiding in getting memory freed.
 */
static struct workqueue_struct *lru_add_drain_wq;

static int __init lru_init(void)
{
	lru_add_drain_wq = alloc_workqueue("lru-add-drain", WQ_MEM_RECLAIM, 0);

	if (WARN(!lru_add_drain_wq,
		"Failed to create workqueue lru_add_drain_wq"))
		return -ENOMEM;

	return 0;
}
early_initcall(lru_init);

void lru_add_drain_all(void)
{
	static DEFINE_MUTEX(lock);
	static struct cpumask has_work;
	int cpu;

	mutex_lock(&lock);
	get_online_cpus();
	cpumask_clear(&has_work);

	for_each_online_cpu(cpu) {
		struct work_struct *work = &per_cpu(lru_add_drain_work, cpu);

		if (pagevec_count(&per_cpu(lru_add_pvec, cpu)) ||
		    pagevec_count(&per_cpu(lru_rotate_pvecs, cpu)) ||
		    pagevec_count(&per_cpu(lru_deactivate_file_pvecs, cpu)) ||
		    pagevec_count(&per_cpu(lru_deactivate_pvecs, cpu)) ||
		    need_activate_page_drain(cpu)) {
			INIT_WORK(work, lru_add_drain_per_cpu);
			queue_work_on(cpu, lru_add_drain_wq, work);
			cpumask_set_cpu(cpu, &has_work);
		}
	}

	for_each_cpu(cpu, &has_work)
		flush_work(&per_cpu(lru_add_drain_work, cpu));

	put_online_cpus();
	mutex_unlock(&lock);
}

/**
 * release_pages - batched put_page()
 * @pages: array of pages to release
 * @nr: number of pages
 * @cold: whether the pages are cache cold
 *
 * Decrement the reference count on all the pages in @pages.  If it
 * fell to zero, remove the page from the LRU and free it.
 */
/* 递减@pages中所有页面的引用计数。如果它降到零，从LRU中删除页面并释放它. */
void release_pages(struct page **pages, int nr, bool cold)
{
	int i;
	LIST_HEAD(pages_to_free);
	struct pglist_data *locked_pgdat = NULL;
	struct lruvec *lruvec;
	unsigned long uninitialized_var(flags);
	unsigned int uninitialized_var(lock_batch);

	for (i = 0; i < nr; i++) {
		struct page *page = pages[i];

		/*
		 * Make sure the IRQ-safe lock-holding time does not get
		 * excessive with a continuous string of pages from the
		 * same pgdat. The lock is held only if pgdat != NULL.
		 */
		/* 确保来自同一pgdat连续字符的页面不会使IRQ安全锁保持时间过长。只有当pgdat！=NULL才拿到锁 */
		/* 这里就是减少锁占用的时间，如果是同一个内存节点，就不要一直去切换解锁和上锁了 */
		if (locked_pgdat && ++lock_batch == SWAP_CLUSTER_MAX) {
			spin_unlock_irqrestore(&locked_pgdat->lru_lock, flags);
			locked_pgdat = NULL;
		}
		/* 如果page是huge zero page，那么就continue吧 */
		if (is_huge_zero_page(page))
			continue;
		/* 实际上就是这里去把它的引用计数-1了，如果-1之后不为0
		 * 那么说明还有人在用，不要release
		 */
		page = compound_head(page);
		if (!put_page_testzero(page))
			continue;
		/* 如果该页是个组合页,在这里进行处理 */
		if (PageCompound(page)) {
			if (locked_pgdat) {
				spin_unlock_irqrestore(&locked_pgdat->lru_lock, flags);
				locked_pgdat = NULL;
			}
			__put_compound_page(page);
			continue;
		}
		/* 如果Page在LRU里面 */
		if (PageLRU(page)) {
			/* 得到我们page所在的内存节点 */
			struct pglist_data *pgdat = page_pgdat(page);
			/* 如果locked_pgdat不等于现在的pgdat */
			if (pgdat != locked_pgdat) {
				/* 那就解锁，然后把自己锁上 */
				if (locked_pgdat)
					spin_unlock_irqrestore(&locked_pgdat->lru_lock,
									flags);
				lock_batch = 0;
				locked_pgdat = pgdat;
				spin_lock_irqsave(&locked_pgdat->lru_lock, flags);
			}

			lruvec = mem_cgroup_page_lruvec(page, locked_pgdat);
			VM_BUG_ON_PAGE(!PageLRU(page), page);
			/* 清除page的LRU flag */
			__ClearPageLRU(page);
			/* 从lru链表里面删除该page */
			del_page_from_lru_list(page, lruvec, page_off_lru(page));
		}

		/* Clear Active bit in case of parallel mark_page_accessed */
		/* 万一并行发生了mark_page_accessed，清除Active bit */
		__ClearPageActive(page);
		/* 把要free的page放到pages_to_free链表里面 */
		list_add(&page->lru, &pages_to_free);
	}
	/* 解锁 */
	if (locked_pgdat)
		spin_unlock_irqrestore(&locked_pgdat->lru_lock, flags);
	/* 把page给释放掉 */
	mem_cgroup_uncharge_list(&pages_to_free);
	free_hot_cold_page_list(&pages_to_free, cold);
}
EXPORT_SYMBOL(release_pages);

/*
 * The pages which we're about to release may be in the deferred lru-addition
 * queues.  That would prevent them from really being freed right now.  That's
 * OK from a correctness point of view but is inefficient - those pages may be
 * cache-warm and we want to give them back to the page allocator ASAP.
 *
 * So __pagevec_release() will drain those queues here.  __pagevec_lru_add()
 * and __pagevec_lru_add_active() call release_pages() directly to avoid
 * mutual recursion.
 */
void __pagevec_release(struct pagevec *pvec)
{
	lru_add_drain();
	release_pages(pvec->pages, pagevec_count(pvec), pvec->cold);
	pagevec_reinit(pvec);
}
EXPORT_SYMBOL(__pagevec_release);

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
/* used by __split_huge_page_refcount() */
void lru_add_page_tail(struct page *page, struct page *page_tail,
		       struct lruvec *lruvec, struct list_head *list)
{
	const int file = 0;

	VM_BUG_ON_PAGE(!PageHead(page), page);
	VM_BUG_ON_PAGE(PageCompound(page_tail), page);
	VM_BUG_ON_PAGE(PageLRU(page_tail), page);
	VM_BUG_ON(NR_CPUS != 1 &&
		  !spin_is_locked(&lruvec_pgdat(lruvec)->lru_lock));

	if (!list)
		SetPageLRU(page_tail);

	if (likely(PageLRU(page)))
		list_add_tail(&page_tail->lru, &page->lru);
	else if (list) {
		/* page reclaim is reclaiming a huge page */
		get_page(page_tail);
		list_add_tail(&page_tail->lru, list);
	} else {
		struct list_head *list_head;
		/*
		 * Head page has not yet been counted, as an hpage,
		 * so we must account for each subpage individually.
		 *
		 * Use the standard add function to put page_tail on the list,
		 * but then correct its position so they all end up in order.
		 */
		add_page_to_lru_list(page_tail, lruvec, page_lru(page_tail));
		list_head = page_tail->lru.prev;
		list_move_tail(&page_tail->lru, list_head);
	}

	if (!PageUnevictable(page))
		update_page_reclaim_stat(lruvec, file, PageActive(page_tail));
}
#endif /* CONFIG_TRANSPARENT_HUGEPAGE */

static void __pagevec_lru_add_fn(struct page *page, struct lruvec *lruvec,
				 void *arg)
{
	/* 判断它是不是pagecache */
	int file = page_is_file_cache(page);
	/* 判断该page是否为active page,用来判断它是否应该放到活跃链表 */
	int active = PageActive(page);
	/* 拿到你要放到那个lru链表的index */
	enum lru_list lru = page_lru(page);
	/* 如果你已经在LRU链表里面了，你还要加入，那就报个BUG吧 */
	VM_BUG_ON_PAGE(PageLRU(page), page);
	/* 设置PG_lru flag */
	SetPageLRU(page);
	/* 将页面添加到lru链表里面 */
	add_page_to_lru_list(page, lruvec, lru);
	/* 更新reclaim stat的计数 */
	update_page_reclaim_stat(lruvec, file, active);
	trace_mm_lru_insertion(page, lru);
}

/*
 * Add the passed pages to the LRU, then drop the caller's refcount
 * on them.  Reinitialises the caller's pagevec.
 *
 * 将传递的页面添加到LRU,然后将调用方的refcount丢弃在这.
 * 重新初始化调用者的pagevec。
 */
void __pagevec_lru_add(struct pagevec *pvec)
{
	pagevec_lru_move_fn(pvec, __pagevec_lru_add_fn, NULL);
}
EXPORT_SYMBOL(__pagevec_lru_add);

/**
 * pagevec_lookup_entries - gang pagecache lookup
 * @pvec:	Where the resulting entries are placed
 * @mapping:	The address_space to search
 * @start:	The starting entry index
 * @nr_entries:	The maximum number of entries
 * @indices:	The cache indices corresponding to the entries in @pvec
 *
 * pagevec_lookup_entries() will search for and return a group of up
 * to @nr_entries pages and shadow entries in the mapping.  All
 * entries are placed in @pvec.  pagevec_lookup_entries() takes a
 * reference against actual pages in @pvec.
 *
 * The search returns a group of mapping-contiguous entries with
 * ascending indexes.  There may be holes in the indices due to
 * not-present entries.
 *
 * pagevec_lookup_entries() returns the number of entries which were
 * found.
 */
unsigned pagevec_lookup_entries(struct pagevec *pvec,
				struct address_space *mapping,
				pgoff_t start, unsigned nr_pages,
				pgoff_t *indices)
{
	pvec->nr = find_get_entries(mapping, start, nr_pages,
				    pvec->pages, indices);
	return pagevec_count(pvec);
}

/**
 * pagevec_remove_exceptionals - pagevec exceptionals pruning
 * @pvec:	The pagevec to prune
 *
 * pagevec_lookup_entries() fills both pages and exceptional radix
 * tree entries into the pagevec.  This function prunes all
 * exceptionals from @pvec without leaving holes, so that it can be
 * passed on to page-only pagevec operations.
 */
void pagevec_remove_exceptionals(struct pagevec *pvec)
{
	int i, j;

	for (i = 0, j = 0; i < pagevec_count(pvec); i++) {
		struct page *page = pvec->pages[i];
		if (!radix_tree_exceptional_entry(page))
			pvec->pages[j++] = page;
	}
	pvec->nr = j;
}

/**
 * pagevec_lookup - gang pagecache lookup
 * @pvec:	Where the resulting pages are placed
 * @mapping:	The address_space to search
 * @start:	The starting page index
 * @nr_pages:	The maximum number of pages
 *
 * pagevec_lookup() will search for and return a group of up to @nr_pages pages
 * in the mapping.  The pages are placed in @pvec.  pagevec_lookup() takes a
 * reference against the pages in @pvec.
 *
 * The search returns a group of mapping-contiguous pages with ascending
 * indexes.  There may be holes in the indices due to not-present pages.
 *
 * pagevec_lookup() returns the number of pages which were found.
 */
unsigned pagevec_lookup(struct pagevec *pvec, struct address_space *mapping,
		pgoff_t start, unsigned nr_pages)
{
	pvec->nr = find_get_pages(mapping, start, nr_pages, pvec->pages);
	return pagevec_count(pvec);
}
EXPORT_SYMBOL(pagevec_lookup);

unsigned pagevec_lookup_tag(struct pagevec *pvec, struct address_space *mapping,
		pgoff_t *index, int tag, unsigned nr_pages)
{
	pvec->nr = find_get_pages_tag(mapping, index, tag,
					nr_pages, pvec->pages);
	return pagevec_count(pvec);
}
EXPORT_SYMBOL(pagevec_lookup_tag);

/*
 * Perform any setup for the swap system
 */
/* 根据物理内存大小设置全局变量page_cluster,磁盘读道是一个费时操作,
 * 每次读一个页面过于浪费,每次多读几个,这个量就要根据实际物理内存大小来确定
 * swap_setup函数根据物理内存大小设定全局变量page_cluster，当megs小于16时候，page_cluster为2，否则为3
 *
 * page_cluster为每次swap in或者swap out操作多少内存页
 * 为2的指数,当为0的时候为1页,为1的时候2页,2的时候4页,通过/proc/sys/vm/page-cluster查看
 */
void __init swap_setup(void)
{
	/* 拿总物理内存的pages数量 >> (20 - PAGE_SHIFT) */
	unsigned long megs = totalram_pages >> (20 - PAGE_SHIFT);
#ifdef CONFIG_SWAP
	int i;

	for (i = 0; i < MAX_SWAPFILES; i++)
		spin_lock_init(&swapper_spaces[i].tree_lock);
#endif

	/* Use a smaller cluster for small-memory machines
	 * 对小型内存机器使用较小的群集
	 */
	/* 如果小于16,那么page_cluster = 2,也就是4个page */
	if (megs < 16)
		page_cluster = 2;
	else	/* 否则就是3,那么就是8个page */
		page_cluster = 3;
	/*
	 * Right now other parts of the system means that we
	 * _really_ don't want to cluster much more
	 *
	 * 现在,系统的其他部分意味着我们不想再进行更多的集群
	 */
}
