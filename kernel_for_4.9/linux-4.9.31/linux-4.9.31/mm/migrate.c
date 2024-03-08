/*
 * Memory Migration functionality - linux/mm/migrate.c
 *
 * Copyright (C) 2006 Silicon Graphics, Inc., Christoph Lameter
 *
 * Page migration was first developed in the context of the memory hotplug
 * project. The main authors of the migration code are:
 *
 * IWAMOTO Toshihiro <iwamoto@valinux.co.jp>
 * Hirokazu Takahashi <taka@valinux.co.jp>
 * Dave Hansen <haveblue@us.ibm.com>
 * Christoph Lameter
 */

#include <linux/migrate.h>
#include <linux/export.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/pagemap.h>
#include <linux/buffer_head.h>
#include <linux/mm_inline.h>
#include <linux/nsproxy.h>
#include <linux/pagevec.h>
#include <linux/ksm.h>
#include <linux/rmap.h>
#include <linux/topology.h>
#include <linux/cpu.h>
#include <linux/cpuset.h>
#include <linux/writeback.h>
#include <linux/mempolicy.h>
#include <linux/vmalloc.h>
#include <linux/security.h>
#include <linux/backing-dev.h>
#include <linux/compaction.h>
#include <linux/syscalls.h>
#include <linux/hugetlb.h>
#include <linux/hugetlb_cgroup.h>
#include <linux/gfp.h>
#include <linux/balloon_compaction.h>
#include <linux/mmu_notifier.h>
#include <linux/page_idle.h>
#include <linux/page_owner.h>

#include <asm/tlbflush.h>

#define CREATE_TRACE_POINTS
#include <trace/events/migrate.h>

#include "internal.h"

/*
 * migrate_prep() needs to be called before we start compiling a list of pages
 * to be migrated using isolate_lru_page(). If scheduling work on other CPUs is
 * undesirable, use migrate_prep_local()
 */
int migrate_prep(void)
{
	/*
	 * Clear the LRU lists so pages can be isolated.
	 * Note that pages may be moved off the LRU after we have
	 * drained them. Those pages will fail to migrate like other
	 * pages that may be busy.
	 */
	lru_add_drain_all();

	return 0;
}

/* Do the necessary work of migrate_prep but not if it involves other CPUs */
int migrate_prep_local(void)
{
	lru_add_drain();

	return 0;
}

bool isolate_movable_page(struct page *page, isolate_mode_t mode)
{
	struct address_space *mapping;

	/*
	 * Avoid burning cycles with pages that are yet under __free_pages(),
	 * or just got freed under us.
	 *
	 * In case we 'win' a race for a movable page being freed under us and
	 * raise its refcount preventing __free_pages() from doing its job
	 * the put_page() at the end of this block will take care of
	 * release this page, thus avoiding a nasty leakage.
	 */
	if (unlikely(!get_page_unless_zero(page)))
		goto out;

	/*
	 * Check PageMovable before holding a PG_lock because page's owner
	 * assumes anybody doesn't touch PG_lock of newly allocated page
	 * so unconditionally grapping the lock ruins page's owner side.
	 */
	if (unlikely(!__PageMovable(page)))
		goto out_putpage;
	/*
	 * As movable pages are not isolated from LRU lists, concurrent
	 * compaction threads can race against page migration functions
	 * as well as race against the releasing a page.
	 *
	 * In order to avoid having an already isolated movable page
	 * being (wrongly) re-isolated while it is under migration,
	 * or to avoid attempting to isolate pages being released,
	 * lets be sure we have the page lock
	 * before proceeding with the movable page isolation steps.
	 */
	if (unlikely(!trylock_page(page)))
		goto out_putpage;

	if (!PageMovable(page) || PageIsolated(page))
		goto out_no_isolated;

	mapping = page_mapping(page);
	VM_BUG_ON_PAGE(!mapping, page);

	if (!mapping->a_ops->isolate_page(page, mode))
		goto out_no_isolated;

	/* Driver shouldn't use PG_isolated bit of page->flags */
	WARN_ON_ONCE(PageIsolated(page));
	__SetPageIsolated(page);
	unlock_page(page);

	return true;

out_no_isolated:
	unlock_page(page);
out_putpage:
	put_page(page);
out:
	return false;
}

/* It should be called on page which is PG_movable */
void putback_movable_page(struct page *page)
{
	struct address_space *mapping;

	VM_BUG_ON_PAGE(!PageLocked(page), page);
	VM_BUG_ON_PAGE(!PageMovable(page), page);
	VM_BUG_ON_PAGE(!PageIsolated(page), page);

	mapping = page_mapping(page);
	mapping->a_ops->putback_page(page);
	__ClearPageIsolated(page);
}

/*
 * Put previously isolated pages back onto the appropriate lists
 * from where they were once taken off for compaction/migration.
 *
 * This function shall be used whenever the isolated pageset has been
 * built from lru, balloon, hugetlbfs page. See isolate_migratepages_range()
 * and isolate_huge_page().
 */
void putback_movable_pages(struct list_head *l)
{
	struct page *page;
	struct page *page2;

	list_for_each_entry_safe(page, page2, l, lru) {
		if (unlikely(PageHuge(page))) {
			putback_active_hugepage(page);
			continue;
		}
		list_del(&page->lru);
		/*
		 * We isolated non-lru movable page so here we can use
		 * __PageMovable because LRU page's mapping cannot have
		 * PAGE_MAPPING_MOVABLE.
		 */
		if (unlikely(__PageMovable(page))) {
			VM_BUG_ON_PAGE(!PageIsolated(page), page);
			lock_page(page);
			if (PageMovable(page))
				putback_movable_page(page);
			else
				__ClearPageIsolated(page);
			unlock_page(page);
			put_page(page);
		} else {
			dec_node_page_state(page, NR_ISOLATED_ANON +
					page_is_file_cache(page));
			putback_lru_page(page);
		}
	}
}

/*
 * Restore a potential migration pte to a working pte entry
 */
static int remove_migration_pte(struct page *new, struct vm_area_struct *vma,
				 unsigned long addr, void *old)
{
	struct mm_struct *mm = vma->vm_mm;
	swp_entry_t entry;
 	pmd_t *pmd;
	pte_t *ptep, pte;
 	spinlock_t *ptl;

	if (unlikely(PageHuge(new))) {
		ptep = huge_pte_offset(mm, addr);
		if (!ptep)
			goto out;
		ptl = huge_pte_lockptr(hstate_vma(vma), mm, ptep);
	} else {
		pmd = mm_find_pmd(mm, addr);
		if (!pmd)
			goto out;

		ptep = pte_offset_map(pmd, addr);

		/*
		 * Peek to check is_swap_pte() before taking ptlock?  No, we
		 * can race mremap's move_ptes(), which skips anon_vma lock.
		 */

		ptl = pte_lockptr(mm, pmd);
	}

 	spin_lock(ptl);
	pte = *ptep;
	if (!is_swap_pte(pte))
		goto unlock;

	entry = pte_to_swp_entry(pte);

	if (!is_migration_entry(entry) ||
	    migration_entry_to_page(entry) != old)
		goto unlock;

	get_page(new);
	pte = pte_mkold(mk_pte(new, READ_ONCE(vma->vm_page_prot)));
	if (pte_swp_soft_dirty(*ptep))
		pte = pte_mksoft_dirty(pte);

	/* Recheck VMA as permissions can change since migration started  */
	if (is_write_migration_entry(entry))
		pte = maybe_mkwrite(pte, vma);

#ifdef CONFIG_HUGETLB_PAGE
	if (PageHuge(new)) {
		pte = pte_mkhuge(pte);
		pte = arch_make_huge_pte(pte, vma, new, 0);
	}
#endif
	flush_dcache_page(new);
	set_pte_at(mm, addr, ptep, pte);

	if (PageHuge(new)) {
		if (PageAnon(new))
			hugepage_add_anon_rmap(new, vma, addr);
		else
			page_dup_rmap(new, true);
	} else if (PageAnon(new))
		page_add_anon_rmap(new, vma, addr, false);
	else
		page_add_file_rmap(new, false);

	if (vma->vm_flags & VM_LOCKED && !PageTransCompound(new))
		mlock_vma_page(new);

	/* No need to invalidate - it was non-present before */
	update_mmu_cache(vma, addr, ptep);
unlock:
	pte_unmap_unlock(ptep, ptl);
out:
	return SWAP_AGAIN;
}

/*
 * Get rid of all migration entries and replace them by
 * references to the indicated page.
 */
void remove_migration_ptes(struct page *old, struct page *new, bool locked)
{
	struct rmap_walk_control rwc = {
		.rmap_one = remove_migration_pte,
		.arg = old,
	};

	if (locked)
		rmap_walk_locked(new, &rwc);
	else
		rmap_walk(new, &rwc);
}

/*
 * Something used the pte of a page under migration. We need to
 * get to the page and wait until migration is finished.
 * When we return from this function the fault will be retried.
 */
void __migration_entry_wait(struct mm_struct *mm, pte_t *ptep,
				spinlock_t *ptl)
{
	pte_t pte;
	swp_entry_t entry;
	struct page *page;

	spin_lock(ptl);
	pte = *ptep;
	if (!is_swap_pte(pte))
		goto out;

	entry = pte_to_swp_entry(pte);
	if (!is_migration_entry(entry))
		goto out;

	page = migration_entry_to_page(entry);

	/*
	 * Once radix-tree replacement of page migration started, page_count
	 * *must* be zero. And, we don't want to call wait_on_page_locked()
	 * against a page without get_page().
	 * So, we use get_page_unless_zero(), here. Even failed, page fault
	 * will occur again.
	 */
	if (!get_page_unless_zero(page))
		goto out;
	pte_unmap_unlock(ptep, ptl);
	wait_on_page_locked(page);
	put_page(page);
	return;
out:
	pte_unmap_unlock(ptep, ptl);
}

void migration_entry_wait(struct mm_struct *mm, pmd_t *pmd,
				unsigned long address)
{
	spinlock_t *ptl = pte_lockptr(mm, pmd);
	pte_t *ptep = pte_offset_map(pmd, address);
	__migration_entry_wait(mm, ptep, ptl);
}

void migration_entry_wait_huge(struct vm_area_struct *vma,
		struct mm_struct *mm, pte_t *pte)
{
	spinlock_t *ptl = huge_pte_lockptr(hstate_vma(vma), mm, pte);
	__migration_entry_wait(mm, pte, ptl);
}

#ifdef CONFIG_BLOCK
/* Returns true if all buffers are successfully locked */
static bool buffer_migrate_lock_buffers(struct buffer_head *head,
							enum migrate_mode mode)
{
	struct buffer_head *bh = head;

	/* Simple case, sync compaction */
	if (mode != MIGRATE_ASYNC) {
		do {
			get_bh(bh);
			lock_buffer(bh);
			bh = bh->b_this_page;

		} while (bh != head);

		return true;
	}

	/* async case, we cannot block on lock_buffer so use trylock_buffer */
	do {
		get_bh(bh);
		if (!trylock_buffer(bh)) {
			/*
			 * We failed to lock the buffer and cannot stall in
			 * async migration. Release the taken locks
			 */
			struct buffer_head *failed_bh = bh;
			put_bh(failed_bh);
			bh = head;
			while (bh != failed_bh) {
				unlock_buffer(bh);
				put_bh(bh);
				bh = bh->b_this_page;
			}
			return false;
		}

		bh = bh->b_this_page;
	} while (bh != head);
	return true;
}
#else
static inline bool buffer_migrate_lock_buffers(struct buffer_head *head,
							enum migrate_mode mode)
{
	return true;
}
#endif /* CONFIG_BLOCK */

/*
 * Replace the page in the mapping.
 *
 * The number of remaining references must be:
 * 1 for anonymous pages without a mapping
 * 2 for pages with a mapping
 * 3 for pages with a mapping and PagePrivate/PagePrivate2 set.
 *
 * 替换映射中的页面
 * 剩余引用数必须为：
 * 1 用于没有映射的匿名页面
 * 2 用于带有映射的页面
 * 3 用于具有映射和PagePrivate2/PagePrivate2集的页面
 */
int migrate_page_move_mapping(struct address_space *mapping,
		struct page *newpage, struct page *page,
		struct buffer_head *head, enum migrate_mode mode,
		int extra_count)
{
	struct zone *oldzone, *newzone;
	int dirty;
	int expected_count = 1 + extra_count;
	void **pslot;

	/* 对于mapping为NULL,也就是说匿名页面 */
	if (!mapping) {
		/* Anonymous page without mapping */
		/* 如果page的引用计数不符合预期(期望为0)时,这时系统认为有人在使用,不适用做迁移 */
		if (page_count(page) != expected_count)
			return -EAGAIN;

		/* No turning back from here
		 * 到了这里就不能回头了
		 */
		/* 那么就把老的page的index、mapping、PG_swapbacked(此页可写入swap分区，一般用于表示此页是非文件页)
		 * 都给新页面安排上
		 */
		newpage->index = page->index;
		newpage->mapping = page->mapping;
		if (PageSwapBacked(page))
			__SetPageSwapBacked(newpage);

		/* 然后返回MIGRATEPAGE_SUCCESS */
		return MIGRATEPAGE_SUCCESS;
	}

	/* 这里就是有mapping的情况,分别拿到老的page所在的zone和
	 * 新的page所在的zone
	 */
	oldzone = page_zone(page);
	newzone = page_zone(newpage);

	/* 对mapping中的基树上锁 */
	spin_lock_irq(&mapping->tree_lock);
	/* 找到该page所在的radix_tree的位置 */
	pslot = radix_tree_lookup_slot(&mapping->page_tree,
 					page_index(page));

	expected_count += 1 + page_has_private(page);
	/* page_count(page) != expected_count 说明有其他的进程又来把它映射了
	 * radix_tree_deref_slot_protected(pslot, &mapping->tree_lock) != page) 说明radix_tree里面对应的槽的页面不是这个页面
	 * 那么解锁之后返回
	 */
	if (page_count(page) != expected_count ||
		radix_tree_deref_slot_protected(pslot, &mapping->tree_lock) != page) {
		spin_unlock_irq(&mapping->tree_lock);
		return -EAGAIN;
	}

	/* 这里再次判断，这里就只判断page->_count是否为2 + page_has_private(page)了
	 * 是的话就继续往下走
	 * 如果不是，可能此旧页被某个进程映射了
	 */
	if (!page_ref_freeze(page, expected_count)) {
		spin_unlock_irq(&mapping->tree_lock);
		return -EAGAIN;
	}

	/*
	 * In the async migration case of moving a page with buffers, lock the
	 * buffers using trylock before the mapping is moved. If the mapping
	 * was moved, we later failed to lock the buffers and could not move
	 * the mapping back due to an elevated page count, we would have to
	 * block waiting on other references to be dropped.
	 *
	 * 在移动带有缓冲区的页面的异步迁移情况下,请在移动映射之前使用trylock锁定缓冲区.
	 * 如果映射被移动,我们后来无法锁定缓冲区,并且由于页面计数增加而无法将映射移回,我们将不得不阻塞等待其他引用被删除。
	 */
	if (mode == MIGRATE_ASYNC && head &&
			!buffer_migrate_lock_buffers(head, mode)) {
		/* 将expected_count设置到page的_refcount atomic_set(&page->_refcount, count) */
		page_ref_unfreeze(page, expected_count);
		spin_unlock_irq(&mapping->tree_lock);
		return -EAGAIN;
	}

	/*
	 * Now we know that no one else is looking at the page:
	 * no turning back from here.
	 */
	newpage->index = page->index;
	newpage->mapping = page->mapping;
	if (PageSwapBacked(page))
		__SetPageSwapBacked(newpage);

	/* 如果走到这，上面的代码得出一个结论，page是处于page->mapping指向的address_space的基树中的，并且没有进程映射此页
	 * 所以以下要做的，就是用新页(newpage)数据替换旧页(page)数据所在的slot
	 */

	/* 新的页的newpage->_refcount++，因为后面要把新页替换旧页所在的slot */
	get_page(newpage);	/* add cache reference */
	 /* 如果是匿名页,走到这,此匿名页必定已经加入了swapcache */
	if (PageSwapCache(page)) {
		/* 设置新页也在swapcache中,后面会替换旧页,新页就会加入到swapcache中 */
		SetPageSwapCache(newpage);
		/* 将旧页的private指向的地址复制到新页的private
		 * 对于加入了swapcache中的页，这项保存的都是以swap分区页槽为索引的swp_entry_t
		 * 这里注意与在内存压缩时unmap时写入进程页表项的swp_entry_t的区别，在内存压缩时，写入进程页表项的swp_entry_t是以旧页(page)为索引
		 */
		set_page_private(newpage, page_private(page));
	}

	/* Move dirty while page refs frozen and newpage not yet exposed
	 * 在页面引用冻结且新页面尚未公开的情况下移动脏标志位
	 */

	/* 如果oldpage的PG_drity被设置了,那么清除PG_drity之后把新页面的PG_drity给设置上 */
	dirty = PageDirty(page);
	if (dirty) {
		ClearPageDirty(page);
		SetPageDirty(newpage);
	}

	/* 用新页数据替换旧页的slot */
	radix_tree_replace_slot(pslot, newpage);

	/*
	 * Drop cache reference from old page by unfreezing
	 * to one less reference.
	 * We know this isn't the last reference.
	 *
	 * Drop到缓存的reference,通过unfreezing去减小一个引用
	 * 我们知道这不是最后一个refrence
	 */

	/* 设置旧页的page->_count为expected_count - 1
	 * 这个-1是因为此旧页已经算是从address_space的基树中拿出来了
	 */
	page_ref_unfreeze(page, expected_count - 1);
	/* 解锁 */
	spin_unlock(&mapping->tree_lock);
	/* Leave irq disabled to prevent preemption while updating stats
	 * 禁用irq以防止在更新统计信息时抢占
	 */

	/*
	 * If moved to a different zone then also account
	 * the page for that zone. Other VM counters will be
	 * taken care of when we establish references to the
	 * new page and drop references to the old page.
	 *
	 * Note that anonymous pages are accounted for
	 * via NR_FILE_PAGES and NR_ANON_MAPPED if they
	 * are mapped to swap space.
	 *
	 * 如果移动到另一个zone,则同时对该zone的这个页面进行计数
	 * 当我们建立新的页面进行引用和老的页面减少引用的时候,
	 * 其他VM的计数器应该小心
	 *
	 * 请注意,如果匿名页面映射到交换空间,则通过NR_FILE_PAGES和NR_ANON_MAPPED计数
	 */

	/* 如果zone不一致,说明跨zone了 */
	if (newzone != oldzone) {
		/* 将oldzone->zone_pgdat的NR_FILE_PAGES计数 -1
		 * 将newzone->zone_pgdat的NR_FILE_PAGES计数 +1
		 */
		__dec_node_state(oldzone->zone_pgdat, NR_FILE_PAGES);
		__inc_node_state(newzone->zone_pgdat, NR_FILE_PAGES);
		/* 如果有PG_swapbacked说明此页可写入swap分区，一般用于表示此页是非文件页
		 * 但是有PG_swapcache说明了分配了swap空间,如果没有设置
		 * 因为走到这里就表明不是匿名页面了,所以这里就是共享内存了
		 */
		/* Swap page: swp_entry_t in private */
		if (PageSwapBacked(page) && !PageSwapCache(page)) {
			/* 将oldzone->zone_pgdat的NR_SHMEM计数 -1
			 * 将newzone->zone_pgdat的NR_SHMEM计数 +1
			 */
			__dec_node_state(oldzone->zone_pgdat, NR_SHMEM);
			__inc_node_state(newzone->zone_pgdat, NR_SHMEM);
		}
		/* 如果page是dirty的,并且backing_dev能写回 */
		if (dirty && mapping_cap_account_dirty(mapping)) {
			/* 将oldzone->zone_pgdat的NR_FILE_DIRTY -1
			 * 将zone的NR_ZONE_WRITE_PENDING -1
			 *
			 * 将newzone->zone_pgdat的NR_FILE_DIRTY +1
			 * 将zone的NR_ZONE_WRITE_PENDING +1
			 */
			__dec_node_state(oldzone->zone_pgdat, NR_FILE_DIRTY);
			__dec_zone_state(oldzone, NR_ZONE_WRITE_PENDING);
			__inc_node_state(newzone->zone_pgdat, NR_FILE_DIRTY);
			__inc_zone_state(newzone, NR_ZONE_WRITE_PENDING);
		}
	}
	/* 使能中断 */
	local_irq_enable();

	/* 返回MIGRATEPAGE_SUCCESS */
	return MIGRATEPAGE_SUCCESS;
}
EXPORT_SYMBOL(migrate_page_move_mapping);

/*
 * The expected number of remaining references is the same as that
 * of migrate_page_move_mapping().
 */
int migrate_huge_page_move_mapping(struct address_space *mapping,
				   struct page *newpage, struct page *page)
{
	int expected_count;
	void **pslot;

	spin_lock_irq(&mapping->tree_lock);

	pslot = radix_tree_lookup_slot(&mapping->page_tree,
					page_index(page));

	expected_count = 2 + page_has_private(page);
	if (page_count(page) != expected_count ||
		radix_tree_deref_slot_protected(pslot, &mapping->tree_lock) != page) {
		spin_unlock_irq(&mapping->tree_lock);
		return -EAGAIN;
	}

	if (!page_ref_freeze(page, expected_count)) {
		spin_unlock_irq(&mapping->tree_lock);
		return -EAGAIN;
	}

	newpage->index = page->index;
	newpage->mapping = page->mapping;

	get_page(newpage);

	radix_tree_replace_slot(pslot, newpage);

	page_ref_unfreeze(page, expected_count - 1);

	spin_unlock_irq(&mapping->tree_lock);

	return MIGRATEPAGE_SUCCESS;
}

/*
 * Gigantic pages are so large that we do not guarantee that page++ pointer
 * arithmetic will work across the entire page.  We need something more
 * specialized.
 */
static void __copy_gigantic_page(struct page *dst, struct page *src,
				int nr_pages)
{
	int i;
	struct page *dst_base = dst;
	struct page *src_base = src;

	for (i = 0; i < nr_pages; ) {
		cond_resched();
		copy_highpage(dst, src);

		i++;
		dst = mem_map_next(dst, dst_base, i);
		src = mem_map_next(src, src_base, i);
	}
}

static void copy_huge_page(struct page *dst, struct page *src)
{
	int i;
	int nr_pages;

	if (PageHuge(src)) {
		/* hugetlbfs page */
		struct hstate *h = page_hstate(src);
		nr_pages = pages_per_huge_page(h);

		if (unlikely(nr_pages > MAX_ORDER_NR_PAGES)) {
			__copy_gigantic_page(dst, src, nr_pages);
			return;
		}
	} else {
		/* thp page */
		BUG_ON(!PageTransHuge(src));
		nr_pages = hpage_nr_pages(src);
	}

	for (i = 0; i < nr_pages; i++) {
		cond_resched();
		copy_highpage(dst + i, src + i);
	}
}

/*
 * Copy the page to its new location
 */
void migrate_page_copy(struct page *newpage, struct page *page)
{
	int cpupid;

	if (PageHuge(page) || PageTransHuge(page))
		copy_huge_page(newpage, page);
	else
		copy_highpage(newpage, page);

	if (PageError(page))
		SetPageError(newpage);
	if (PageReferenced(page))
		SetPageReferenced(newpage);
	if (PageUptodate(page))
		SetPageUptodate(newpage);
	if (TestClearPageActive(page)) {
		VM_BUG_ON_PAGE(PageUnevictable(page), page);
		SetPageActive(newpage);
	} else if (TestClearPageUnevictable(page))
		SetPageUnevictable(newpage);
	if (PageChecked(page))
		SetPageChecked(newpage);
	if (PageMappedToDisk(page))
		SetPageMappedToDisk(newpage);

	/* Move dirty on pages not done by migrate_page_move_mapping() */
	if (PageDirty(page))
		SetPageDirty(newpage);

	if (page_is_young(page))
		set_page_young(newpage);
	if (page_is_idle(page))
		set_page_idle(newpage);

	/*
	 * Copy NUMA information to the new page, to prevent over-eager
	 * future migrations of this same page.
	 */
	cpupid = page_cpupid_xchg_last(page, -1);
	page_cpupid_xchg_last(newpage, cpupid);

	ksm_migrate_page(newpage, page);
	/*
	 * Please do not reorder this without considering how mm/ksm.c's
	 * get_ksm_page() depends upon ksm_migrate_page() and PageSwapCache().
	 */
	if (PageSwapCache(page))
		ClearPageSwapCache(page);
	ClearPagePrivate(page);
	set_page_private(page, 0);

	/*
	 * If any waiters have accumulated on the new page then
	 * wake them up.
	 */
	if (PageWriteback(newpage))
		end_page_writeback(newpage);

	copy_page_owner(page, newpage);

	mem_cgroup_migrate(page, newpage);
}
EXPORT_SYMBOL(migrate_page_copy);

/************************************************************
 *                    Migration functions
 ***********************************************************/

/*
 * Common logic to directly migrate a single LRU page suitable for
 * pages that do not use PagePrivate/PagePrivate2.
 *
 * Pages are locked upon entry and exit.
 *
 * 用于直接迁移适用于没有使用PagePrivate/PagePrivate2的页面的单个LRU页面的通用逻辑.页面在进出时被锁定。
 */
int migrate_page(struct address_space *mapping,
		struct page *newpage, struct page *page,
		enum migrate_mode mode)
{
	int rc;
	/* 如果页面正在写回,那么报告BUG吧 */
	BUG_ON(PageWriteback(page));	/* Writeback must be complete */

	/* 这里只要是对oldpage的一些东西复制给newpage
	 * 然后把oldpage的这些东西清掉
	 * 可以进这个函数里面看看
	 */
	rc = migrate_page_move_mapping(mapping, newpage, page, NULL, mode, 0);

	if (rc != MIGRATEPAGE_SUCCESS)
		return rc;

	migrate_page_copy(newpage, page);
	return MIGRATEPAGE_SUCCESS;
}
EXPORT_SYMBOL(migrate_page);

#ifdef CONFIG_BLOCK
/*
 * Migration function for pages with buffers. This function can only be used
 * if the underlying filesystem guarantees that no other references to "page"
 * exist.
 */
int buffer_migrate_page(struct address_space *mapping,
		struct page *newpage, struct page *page, enum migrate_mode mode)
{
	struct buffer_head *bh, *head;
	int rc;

	if (!page_has_buffers(page))
		return migrate_page(mapping, newpage, page, mode);

	head = page_buffers(page);

	rc = migrate_page_move_mapping(mapping, newpage, page, head, mode, 0);

	if (rc != MIGRATEPAGE_SUCCESS)
		return rc;

	/*
	 * In the async case, migrate_page_move_mapping locked the buffers
	 * with an IRQ-safe spinlock held. In the sync case, the buffers
	 * need to be locked now
	 */
	if (mode != MIGRATE_ASYNC)
		BUG_ON(!buffer_migrate_lock_buffers(head, mode));

	ClearPagePrivate(page);
	set_page_private(newpage, page_private(page));
	set_page_private(page, 0);
	put_page(page);
	get_page(newpage);

	bh = head;
	do {
		set_bh_page(bh, newpage, bh_offset(bh));
		bh = bh->b_this_page;

	} while (bh != head);

	SetPagePrivate(newpage);

	migrate_page_copy(newpage, page);

	bh = head;
	do {
		unlock_buffer(bh);
 		put_bh(bh);
		bh = bh->b_this_page;

	} while (bh != head);

	return MIGRATEPAGE_SUCCESS;
}
EXPORT_SYMBOL(buffer_migrate_page);
#endif

/*
 * Writeback a page to clean the dirty state
 */
static int writeout(struct address_space *mapping, struct page *page)
{
	struct writeback_control wbc = {
		.sync_mode = WB_SYNC_NONE,
		.nr_to_write = 1,
		.range_start = 0,
		.range_end = LLONG_MAX,
		.for_reclaim = 1
	};
	int rc;

	if (!mapping->a_ops->writepage)
		/* No write method for the address space */
		return -EINVAL;

	if (!clear_page_dirty_for_io(page))
		/* Someone else already triggered a write */
		return -EAGAIN;

	/*
	 * A dirty page may imply that the underlying filesystem has
	 * the page on some queue. So the page must be clean for
	 * migration. Writeout may mean we loose the lock and the
	 * page state is no longer what we checked for earlier.
	 * At this point we know that the migration attempt cannot
	 * be successful.
	 */
	remove_migration_ptes(page, page, false);

	rc = mapping->a_ops->writepage(page, &wbc);

	if (rc != AOP_WRITEPAGE_ACTIVATE)
		/* unlocked. Relock */
		lock_page(page);

	return (rc < 0) ? -EIO : -EAGAIN;
}

/*
 * Default handling if a filesystem does not provide a migration function.
 */
static int fallback_migrate_page(struct address_space *mapping,
	struct page *newpage, struct page *page, enum migrate_mode mode)
{
	if (PageDirty(page)) {
		/* Only writeback pages in full synchronous migration */
		if (mode != MIGRATE_SYNC)
			return -EBUSY;
		return writeout(mapping, page);
	}

	/*
	 * Buffers may be managed in a filesystem specific way.
	 * We must have no buffers or drop them.
	 */
	if (page_has_private(page) &&
	    !try_to_release_page(page, GFP_KERNEL))
		return -EAGAIN;

	return migrate_page(mapping, newpage, page, mode);
}

/*
 * Move a page to a newly allocated page
 * The page is locked and all ptes have been successfully removed.
 *
 * The new page will have replaced the old page if this function
 * is successful.
 *
 * Return value:
 *   < 0 - error code
 *  MIGRATEPAGE_SUCCESS - success
 *
 * 页面是locked,所有的pte都成功被removed了
 *
 * 如果这个函数成功,新页面将替换旧页面
 *
 * 返回值：
 * < 0 - 错误代码
 * MIGRATEPAGE_SUCCESS - success
 */
static int move_to_new_page(struct page *newpage, struct page *page,
				enum migrate_mode mode)
{
	struct address_space *mapping;
	int rc = -EAGAIN;
	/* 判断这个页面在不在lru链表里面 */
	bool is_lru = !__PageMovable(page);

	/* 如果page或者newpage被加锁了,那么报个BUG */
	VM_BUG_ON_PAGE(!PageLocked(page), page);
	VM_BUG_ON_PAGE(!PageLocked(newpage), newpage);

	mapping = page_mapping(page);

	/* 如果在lru链表里面 */
	if (likely(is_lru)) {
		/* 如果mapping是空的,那么就是匿名页面的情况,那么调用migrate_page */
		if (!mapping)
			rc = migrate_page(mapping, newpage, page, mode);
		else if (mapping->a_ops->migratepage)/* 对于其他有mapping的页面,会调用mapping指向的migratepage()函数指针或fallabck_migrate_page函数,很多文件系统都提供了这样的函数接口 */
			/*
			 * Most pages have a mapping and most filesystems
			 * provide a migratepage callback. Anonymous pages
			 * are part of swap space which also has its own
			 * migratepage callback. This is the most common path
			 * for page migration.
			 */
			rc = mapping->a_ops->migratepage(mapping, newpage,
							page, mode);
		else
			rc = fallback_migrate_page(mapping, newpage,
							page, mode);
	} else {
		/*
		 * In case of non-lru page, it could be released after
		 * isolation step. In that case, we shouldn't try migration.
		 */
		VM_BUG_ON_PAGE(!PageIsolated(page), page);
		if (!PageMovable(page)) {
			rc = MIGRATEPAGE_SUCCESS;
			__ClearPageIsolated(page);
			goto out;
		}

		rc = mapping->a_ops->migratepage(mapping, newpage,
						page, mode);
		WARN_ON_ONCE(rc == MIGRATEPAGE_SUCCESS &&
			!PageIsolated(page));
	}

	/*
	 * When successful, old pagecache page->mapping must be cleared before
	 * page is freed; but stats require that PageAnon be left as PageAnon.
	 */
	if (rc == MIGRATEPAGE_SUCCESS) {
		if (__PageMovable(page)) {
			VM_BUG_ON_PAGE(!PageIsolated(page), page);

			/*
			 * We clear PG_movable under page_lock so any compactor
			 * cannot try to migrate this page.
			 */
			__ClearPageIsolated(page);
		}

		/*
		 * Anonymous and movable page->mapping will be cleard by
		 * free_pages_prepare so don't reset it here for keeping
		 * the type to work PageAnon, for example.
		 */
		if (!PageMappingFlags(page))
			page->mapping = NULL;
	}
out:
	return rc;
}

static int __unmap_and_move(struct page *page, struct page *newpage,
				int force, enum migrate_mode mode)
{
	int rc = -EAGAIN;
	int page_was_mapped = 0;
	struct anon_vma *anon_vma = NULL;
	/* 这里判断它是不是在lru里面的page,如果不是还一种可能就是它是驱动分配的页面
	 * 但是可以用来迁移
	 */
	bool is_lru = !__PageMovable(page);
	/* trylock_page尝试给page加锁,trylock_page返回false表示已经有别的进程给page加过锁,返回true表示当前进程可以成功获得锁 */
	if (!trylock_page(page)) {
		/* 如果尝试获取页面锁不成功,当前不是强制迁移(force=0)或迁移模式等于异步(mode == MIGRATE_ASYNC),会直接忽略这个page,因为这种情况下没有必要睡眠等待页面释放锁 */
		if (!force || mode == MIGRATE_ASYNC)
			goto out;

		/*
		 * It's not safe for direct compaction to call lock_page.
		 * For example, during page readahead pages are added locked
		 * to the LRU. Later, when the IO completes the pages are
		 * marked uptodate and unlocked. However, the queueing
		 * could be merging multiple pages for one bio (e.g.
		 * mpage_readpages). If an allocation happens for the
		 * second or third page, the process can end up locking
		 * the same page twice and deadlocking. Rather than
		 * trying to be clever about what pages can be locked,
		 * avoid the use of lock_page for direct compaction
		 * altogether.
		 *
		 * 直接压缩调用lock_page是不安全的.例如,在页面预读期间,页面被添加到LRU锁定.
		 * 稍后,当IO完成时,页面被标记为最新并解锁.
		 * 然而,queueing可能为一个bio合并多个页面(例如,mpage_readpages).
		 * 如果第二个或第三个页面发生分配,进程可能会锁定同一个页面两次并导致死锁.
		 * 与其试图巧妙地确定哪些页面可以被锁定,不如完全避免使用lock_page进行直接压缩.
		 */

		/* 如果当前进程设置了PF_MEMALLOC标志位,表示可能是在直接内存压缩(direct compatction)的内核路径上,睡眠等待页面锁是不安全的,所以直接忽略page.
		 * 举个例子,在文件预读中,预读的所有页面都会加页锁(PG_lock)并添加到LRU链表中,等到预读完成后,这些页面会标记PG_uptodate并释放锁,
		 * 这个过程中块设备层会把多个页面合并到一个BIO中(mpage_readpages).
		 * 如果在分配第2个或者第3个页面时发生内存短缺,内核会运行直接内存压缩(direct compatcion)内核路径上,
		 * 导致一个页面已经加锁了又去等待这个锁,产生死锁,因此在直接内存压缩(direct compaction)的内核路径会标记PF_MEMALLOC.
		 * PF_MEMALLOC标志位一般是在直接内存压缩、直接内存回收和kswapd中设置,这些场景下也可能会有少量的内存分配行为,
		 * 因此设置PF_MEMALLOC标志位,表示允许他们使用系统预留的内存,即不用考虑Water Mark水位.
		 * 可以参见__perform_reclaim()、__alloc_pages_direct_compact和kswapd等函数
		 */
		if (current->flags & PF_MEMALLOC)
			goto out;
		/* 除了上述情况,其余情况只能调用lock_page函数来等待页面锁被释放. */
		lock_page(page);
	}

	/* 处理正在回写的页面即PG_writeback标志位的页面.这里只有当
	 * 页面迁移模式为MIGRATE_SYNC且设置强制迁移force==1时才会去等待这个页面回写完成,否则直接忽略该页面.
	 */
	if (PageWriteback(page)) {
		/*
		 * Only in the case of a full synchronous migration is it
		 * necessary to wait for PageWriteback. In the async case,
		 * the retry loop is too short and in the sync-light case,
		 * the overhead of stalling is too much
		 *
		 * 只有在完全同步迁移的情况下,才需要等待PageWriteback.
		 * 在异步情况下,重试循环太短,而在sync-light情况下,停滞的开销太大
		 */
		if (mode != MIGRATE_SYNC) {
			rc = -EBUSY;
			goto out_unlock;
		}
		if (!force)
			goto out_unlock;

		/* 等待页面回写完成 */
		wait_on_page_writeback(page);
	}

	/*
	 * By try_to_unmap(), page->mapcount goes down to 0 here. In this case,
	 * we cannot notice that anon_vma is freed while we migrates a page.
	 * This get_anon_vma() delays freeing anon_vma pointer until the end
	 * of migration. File cache pages are no problem because of page_lock()
	 * File Caches may use write_page() or lock_page() in migration, then,
	 * just care Anon page here.
	 *
	 * Only page_get_anon_vma() understands the subtleties of
	 * getting a hold on an anon_vma from outside one of its mms.
	 * But if we cannot get anon_vma, then we won't need it anyway,
	 * because that implies that the anon page is no longer mapped
	 * (and cannot be remapped so long as we hold the page lock).
	 *
	 * 通过try_to_unmap(),page->mapcount在这里降到0.
	 * 在这种情况下,我们不会注意到在迁移页面时释放了anon_vma.
	 * get_anon_vma()将延迟释放anon_vma指针到迁移结束.
	 * 文件缓存页面没有问题,因为page_lock()
	 * 文件缓存在迁移中可能使用write_page()或lock_page(),这时这里只关系匿名页面
	 *
	 * 只有page_get_anon_vma才能理解从其mms外部获取anon_vm的微妙之处.
	 * 但是,如果我们不能获得anon_vma,那么我们无论如何都不需要它,
	 * 因为这意味着anon页面不再被映射(只要我们持有页面锁定,就不能重新映射).
	 */

	/* 如果是匿名页面然后还不是KSM页面
	 * 处理匿名页面的anon_vma可能被释放的特殊情况,因为接下来try_to_unmap的函数指向完成时,page->mapcout引用计数会变成0.
	 * 在页迁移的过程中,我们无法知道anon_vma数据结构是否被释放了.
	 * page_get_anon_vma会增加anon_vma->refcount引用计数防止它被其他进程释放,与之对应的是后面的put_anon_vma减少anon_vma->refcount引用计数,它们是成对出现的
	 */
	if (PageAnon(page) && !PageKsm(page))
		anon_vma = page_get_anon_vma(page);

	/*
	 * Block others from accessing the new page when we get around to
	 * establishing additional references. We are usually the only one
	 * holding a reference to newpage at this point. We used to have a BUG
	 * here if trylock_page(newpage) fails, but would like to allow for
	 * cases where there might be a race with the previous use of newpage.
	 * This is much like races on refcount of oldpage: just don't BUG().
	 *
	 * 当我们开始建立其他引用时,阻止其他人访问新页面.
	 * 通常只有我们一个此时持有对newpage的引用.
	 * 我们曾经有一个BUG,如果trylock_page（newpage）失败,但希望允许
	 * 在某些情况下,可能会与之前使用的newpage发生冲突。
	 * 这很像旧页面的refcount上的竞争,只是不要BUG();
	 */

	/* 如果newpage的锁拿不到,那就去解锁吧 */
	if (unlikely(!trylock_page(newpage)))
		goto out_unlock;

	/* 如果不是lru里面的page,那么就调用它们自己从迁移页面的函数 */
	if (unlikely(!is_lru)) {
		rc = move_to_new_page(newpage, page, mode);
		goto out_unlock_both;
	}

	/*
	 * Corner case handling:
	 * 1. When a new swap-cache page is read into, it is added to the LRU
	 * and treated as swapcache but it has no rmap yet.
	 * Calling try_to_unmap() against a page->mapping==NULL page will
	 * trigger a BUG.  So handle it here.
	 * 2. An orphaned page (see truncate_complete_page) might have
	 * fs-private metadata. The page can be picked up due to memory
	 * offlining.  Everywhere else except page reclaim, the page is
	 * invisible to the vm, so the page can not be migrated.  So try to
	 * free the metadata, so the page can be freedz.
	 */
	/* 这里是一种特殊情况,例如一个swap cache页面发生swap-in时,
	 * 在do_swap_page中分配一个新的页面,该页面添加到LRU链表中,
	 * 这个页面是swapcache页面,但是它还没有建立RMAP关系,
	 * 因此page->mapping = NULL,接下来要进行try_to_unmap函数处理这种页面会触发BUG
	 */
	if (!page->mapping) {
		VM_BUG_ON_PAGE(PageAnon(page), page);
		if (page_has_private(page)) {
			try_to_free_buffers(page);
			goto out_unlock_both;
		} /* 对于有pte映射的页面,调用try_to_unmap解除页面所有映射的pte. */
	} else if (page_mapped(page)) {
		/* Establish migration ptes */
		VM_BUG_ON_PAGE(PageAnon(page) && !PageKsm(page) && !anon_vma,
				page);
		try_to_unmap(page,
			TTU_MIGRATION|TTU_IGNORE_MLOCK|TTU_IGNORE_ACCESS);
		page_was_mapped = 1;
	}
	/* 对于已经解除完所有映射的页面,调用move_to_new_page迁移到新分配的页面new_page. */
	if (!page_mapped(page))
		rc = move_to_new_page(newpage, page, mode);

	/* 调用remove_migration_ptes删除掉迁移的pte */
	if (page_was_mapped)
		remove_migration_ptes(page,
			rc == MIGRATEPAGE_SUCCESS ? newpage : page, false);

out_unlock_both:
	unlock_page(newpage);
out_unlock:
	/* Drop an anon_vma reference if we took one */
	if (anon_vma)
		put_anon_vma(anon_vma);
	unlock_page(page);
out:
	/*
	 * If migration is successful, decrease refcount of the newpage
	 * which will not free the page because new page owner increased
	 * refcounter. As well, if it is LRU page, add the page to LRU
	 * list in here.
	 */
	if (rc == MIGRATEPAGE_SUCCESS) {
		if (unlikely(__PageMovable(newpage)))
			put_page(newpage);
		else
			putback_lru_page(newpage);
	}

	return rc;
}

/*
 * gcc 4.7 and 4.8 on arm get an ICEs when inlining unmap_and_move().  Work
 * around it.
 */
#if (GCC_VERSION >= 40700 && GCC_VERSION < 40900) && defined(CONFIG_ARM)
#define ICE_noinline noinline
#else
#define ICE_noinline
#endif

/*
 * Obtain the lock on page, remove all ptes and migrate the page
 * to the newly allocated page in newpage.
 *
 * 获取页面上的锁,删除所有pte,并将页面迁移到newpage中新分配的页面
 */
static ICE_noinline int unmap_and_move(new_page_t get_new_page,
				   free_page_t put_new_page,
				   unsigned long private, struct page *page,
				   int force, enum migrate_mode mode,
				   enum migrate_reason reason)
{
	int rc = MIGRATEPAGE_SUCCESS;
	int *result = NULL;
	struct page *newpage;

	/* 调用get_new_page获得新页面 */
	newpage = get_new_page(page, private, &result);
	/* 如果没有那就返回-ENOMEM */
	if (!newpage)
		return -ENOMEM;

	/* 如果该page的_refcount为1 */
	if (page_count(page) == 1) {
		/* page was freed from under us. So we are done.
		 * page从我们的脚下被释放了了.所以我们完了.
		 */

		/* 清除PG_active标记 */
		ClearPageActive(page);
		/* 清除PG_unevictable 标志 */
		ClearPageUnevictable(page);
		/* 如果__PageMovable,那么说明是内核用到的page,但是是可移动的 */
		if (unlikely(__PageMovable(page))) {
			/* 锁住page */
			lock_page(page);
			/* 如果PageMovable返回false,说明page里面没有迁移的一些功能函数
			 * 那么清除PG_isolated
			 */
			if (!PageMovable(page))
				__ClearPageIsolated(page);
			unlock_page(page);
		}
		/* 把page放回到原来的链表里面去  */
		if (put_new_page)
			put_new_page(newpage, private);
		else
			put_page(newpage);
		goto out;
	}

	if (unlikely(PageTransHuge(page))) {
		lock_page(page);
		rc = split_huge_page(page);
		unlock_page(page);
		if (rc)
			goto out;
	}
	/* 调用__unmap_and_move()去尝试迁移页面page到新分配的页面newpage中 */
	rc = __unmap_and_move(page, newpage, force, mode);
	if (rc == MIGRATEPAGE_SUCCESS)
		set_page_owner_migrate_reason(newpage, reason);

out:
	/* 迁移失败,会把这个页面重新返回LRU链表中.会把新分配的页面释放 */
	if (rc != -EAGAIN) {
		/*
		 * A page that has been migrated has all references
		 * removed and will be freed. A page that has not been
		 * migrated will have kepts its references and be
		 * restored.
		 */
		list_del(&page->lru);

		/*
		 * Compaction can migrate also non-LRU pages which are
		 * not accounted to NR_ISOLATED_*. They can be recognized
		 * as __PageMovable
		 */
		if (likely(!__PageMovable(page)))
			dec_node_page_state(page, NR_ISOLATED_ANON +
					page_is_file_cache(page));
	}

	/*
	 * If migration is successful, releases reference grabbed during
	 * isolation. Otherwise, restore the page to right list unless
	 * we want to retry.
	 */
	if (rc == MIGRATEPAGE_SUCCESS) {
		put_page(page);
		if (reason == MR_MEMORY_FAILURE) {
			/*
			 * Set PG_HWPoison on just freed page
			 * intentionally. Although it's rather weird,
			 * it's how HWPoison flag works at the moment.
			 */
			if (!test_set_page_hwpoison(page))
				num_poisoned_pages_inc();
		}
	} else {
		if (rc != -EAGAIN) {
			if (likely(!__PageMovable(page))) {
				putback_lru_page(page);
				goto put_new;
			}

			lock_page(page);
			if (PageMovable(page))
				putback_movable_page(page);
			else
				__ClearPageIsolated(page);
			unlock_page(page);
			put_page(page);
		}
put_new:
		if (put_new_page)
			put_new_page(newpage, private);
		else
			put_page(newpage);
	}

	if (result) {
		if (rc)
			*result = rc;
		else
			*result = page_to_nid(newpage);
	}
	return rc;
}

/*
 * Counterpart of unmap_and_move_page() for hugepage migration.
 *
 * This function doesn't wait the completion of hugepage I/O
 * because there is no race between I/O and migration for hugepage.
 * Note that currently hugepage I/O occurs only in direct I/O
 * where no lock is held and PG_writeback is irrelevant,
 * and writeback status of all subpages are counted in the reference
 * count of the head page (i.e. if all subpages of a 2MB hugepage are
 * under direct I/O, the reference of the head page is 512 and a bit more.)
 * This means that when we try to migrate hugepage whose subpages are
 * doing direct I/O, some references remain after try_to_unmap() and
 * hugepage migration fails without data corruption.
 *
 * There is also no race when direct I/O is issued on the page under migration,
 * because then pte is replaced with migration swap entry and direct I/O code
 * will wait in the page fault for migration to complete.
 */
static int unmap_and_move_huge_page(new_page_t get_new_page,
				free_page_t put_new_page, unsigned long private,
				struct page *hpage, int force,
				enum migrate_mode mode, int reason)
{
	int rc = -EAGAIN;
	int *result = NULL;
	int page_was_mapped = 0;
	struct page *new_hpage;
	struct anon_vma *anon_vma = NULL;

	/*
	 * Movability of hugepages depends on architectures and hugepage size.
	 * This check is necessary because some callers of hugepage migration
	 * like soft offline and memory hotremove don't walk through page
	 * tables or check whether the hugepage is pmd-based or not before
	 * kicking migration.
	 */
	if (!hugepage_migration_supported(page_hstate(hpage))) {
		putback_active_hugepage(hpage);
		return -ENOSYS;
	}

	new_hpage = get_new_page(hpage, private, &result);
	if (!new_hpage)
		return -ENOMEM;

	if (!trylock_page(hpage)) {
		if (!force || mode != MIGRATE_SYNC)
			goto out;
		lock_page(hpage);
	}

	if (PageAnon(hpage))
		anon_vma = page_get_anon_vma(hpage);

	if (unlikely(!trylock_page(new_hpage)))
		goto put_anon;

	if (page_mapped(hpage)) {
		try_to_unmap(hpage,
			TTU_MIGRATION|TTU_IGNORE_MLOCK|TTU_IGNORE_ACCESS);
		page_was_mapped = 1;
	}

	if (!page_mapped(hpage))
		rc = move_to_new_page(new_hpage, hpage, mode);

	if (page_was_mapped)
		remove_migration_ptes(hpage,
			rc == MIGRATEPAGE_SUCCESS ? new_hpage : hpage, false);

	unlock_page(new_hpage);

put_anon:
	if (anon_vma)
		put_anon_vma(anon_vma);

	if (rc == MIGRATEPAGE_SUCCESS) {
		hugetlb_cgroup_migrate(hpage, new_hpage);
		put_new_page = NULL;
		set_page_owner_migrate_reason(new_hpage, reason);
	}

	unlock_page(hpage);
out:
	if (rc != -EAGAIN)
		putback_active_hugepage(hpage);

	/*
	 * If migration was not successful and there's a freeing callback, use
	 * it.  Otherwise, put_page() will drop the reference grabbed during
	 * isolation.
	 */
	if (put_new_page)
		put_new_page(new_hpage, private);
	else
		putback_active_hugepage(new_hpage);

	if (result) {
		if (rc)
			*result = rc;
		else
			*result = page_to_nid(new_hpage);
	}
	return rc;
}

/*
 * migrate_pages - migrate the pages specified in a list, to the free pages
 *		   supplied as the target for the page migration
 *
 * @from:		The list of pages to be migrated.
 * @get_new_page:	The function used to allocate free pages to be used
 *			as the target of the page migration.
 * @put_new_page:	The function used to free target pages if migration
 *			fails, or NULL if no special handling is necessary.
 * @private:		Private data to be passed on to get_new_page()
 * @mode:		The migration mode that specifies the constraints for
 *			page migration, if any.
 * @reason:		The reason for page migration.
 *
 * The function returns after 10 attempts or if no pages are movable any more
 * because the list has become empty or no retryable pages exist any more.
 * The caller should call putback_movable_pages() to return pages to the LRU
 * or free list only if ret != 0.
 *
 * Returns the number of pages that were not migrated, or an error code.
 *
 * migrate_pages - 将列表中指定的页面迁移到作为页面迁移目标提供的free页面
 * @from：要迁移的页面列表。
 * @get_new_page：用于分配可用页面作为页面迁移目标的函数.
 * @put_new_page：如果迁移失败,用于释放目标页面的函数;如果不需要特殊处理,那么为NULL
 * @private：要传递到get_new_page的私有数据
 * @mode：指定页面迁移约束(如果有的话)的迁移模式。
 * @reaon：页面迁移的原因.
 *
 * 该功能在尝试10次后或者如果不再有页面可移动因为该列表已变为空或者不再存在可重试页面返回.
 * 调用方应调用putback_movable_pages（）将页面返回到LRU或仅当ret!=0时才返回可用列表.
 *
 * 返回未迁移的页数或错误代码。
 */

/* migrate_pages函数的参数from表示将要迁移的页面链表,get_new_page是内存函数指针,put_new_page是迁移失败时释放目标页面的函数指针,
 * private是传递给get_new_page的参数,mode是迁移模式,reason表示迁移的原因.
 */
int migrate_pages(struct list_head *from, new_page_t get_new_page,
		free_page_t put_new_page, unsigned long private,
		enum migrate_mode mode, int reason)
{
	int retry = 1;
	int nr_failed = 0;
	int nr_succeeded = 0;
	int pass = 0;
	struct page *page;
	struct page *page2;
	/* PF_SWAPWRITE: Allowed to write to swap */
	int swapwrite = current->flags & PF_SWAPWRITE;
	int rc;

	/* 如果当前进程的flag没有设置PF_SWAPWRITE,那么这里设置了
	 * 它代表该进程允许写到swap里面去
	 */
	if (!swapwrite)
		current->flags |= PF_SWAPWRITE;

	/* for循环表示这里会尝试10次,从from链表摘取一个页面,然后调用unmap_add_move()函数进行页面的迁移,
	 * 返回MIGRATEPAGE_SUCCESS表示迁移成功.
	 */
	for(pass = 0; pass < 10 && retry; pass++) {
		retry = 0;

		list_for_each_entry_safe(page, page2, from, lru) {
			cond_resched();

			if (PageHuge(page))
				rc = unmap_and_move_huge_page(get_new_page,
						put_new_page, private, page,
						pass > 2, mode, reason);
			else	/* 调用unmap_and_move进行页面迁移,返回MIGRATEPAGE_SUCCESS表示迁移成功 */
				rc = unmap_and_move(get_new_page, put_new_page,
						private, page, pass > 2, mode,
						reason);

			switch(rc) {
			case -ENOMEM:
				nr_failed++;
				goto out;
			case -EAGAIN:
				retry++;
				break;
			case MIGRATEPAGE_SUCCESS:
				nr_succeeded++;
				break;
			default:
				/*
				 * Permanent failure (-EBUSY, -ENOSYS, etc.):
				 * unlike -EAGAIN case, the failed page is
				 * removed from migration page list and not
				 * retried in the next outer loop.
				 */
				nr_failed++;
				break;
			}
		}
	}
	nr_failed += retry;
	rc = nr_failed;
out:
	if (nr_succeeded)
		count_vm_events(PGMIGRATE_SUCCESS, nr_succeeded);
	if (nr_failed)
		count_vm_events(PGMIGRATE_FAIL, nr_failed);
	trace_mm_migrate_pages(nr_succeeded, nr_failed, mode, reason);

	if (!swapwrite)
		current->flags &= ~PF_SWAPWRITE;

	return rc;
}

#ifdef CONFIG_NUMA
/*
 * Move a list of individual pages
 */
struct page_to_node {
	unsigned long addr;
	struct page *page;
	int node;
	int status;
};

static struct page *new_page_node(struct page *p, unsigned long private,
		int **result)
{
	struct page_to_node *pm = (struct page_to_node *)private;

	while (pm->node != MAX_NUMNODES && pm->page != p)
		pm++;

	if (pm->node == MAX_NUMNODES)
		return NULL;

	*result = &pm->status;

	if (PageHuge(p))
		return alloc_huge_page_node(page_hstate(compound_head(p)),
					pm->node);
	else
		return __alloc_pages_node(pm->node,
				GFP_HIGHUSER_MOVABLE | __GFP_THISNODE, 0);
}

/*
 * Move a set of pages as indicated in the pm array. The addr
 * field must be set to the virtual address of the page to be moved
 * and the node number must contain a valid target node.
 * The pm array ends with node = MAX_NUMNODES.
 */
static int do_move_page_to_node_array(struct mm_struct *mm,
				      struct page_to_node *pm,
				      int migrate_all)
{
	int err;
	struct page_to_node *pp;
	LIST_HEAD(pagelist);

	down_read(&mm->mmap_sem);

	/*
	 * Build a list of pages to migrate
	 */
	for (pp = pm; pp->node != MAX_NUMNODES; pp++) {
		struct vm_area_struct *vma;
		struct page *page;

		err = -EFAULT;
		vma = find_vma(mm, pp->addr);
		if (!vma || pp->addr < vma->vm_start || !vma_migratable(vma))
			goto set_status;

		/* FOLL_DUMP to ignore special (like zero) pages */
		page = follow_page(vma, pp->addr,
				FOLL_GET | FOLL_SPLIT | FOLL_DUMP);

		err = PTR_ERR(page);
		if (IS_ERR(page))
			goto set_status;

		err = -ENOENT;
		if (!page)
			goto set_status;

		pp->page = page;
		err = page_to_nid(page);

		if (err == pp->node)
			/*
			 * Node already in the right place
			 */
			goto put_and_set;

		err = -EACCES;
		if (page_mapcount(page) > 1 &&
				!migrate_all)
			goto put_and_set;

		if (PageHuge(page)) {
			if (PageHead(page))
				isolate_huge_page(page, &pagelist);
			goto put_and_set;
		}

		err = isolate_lru_page(page);
		if (!err) {
			list_add_tail(&page->lru, &pagelist);
			inc_node_page_state(page, NR_ISOLATED_ANON +
					    page_is_file_cache(page));
		}
put_and_set:
		/*
		 * Either remove the duplicate refcount from
		 * isolate_lru_page() or drop the page ref if it was
		 * not isolated.
		 */
		put_page(page);
set_status:
		pp->status = err;
	}

	err = 0;
	if (!list_empty(&pagelist)) {
		err = migrate_pages(&pagelist, new_page_node, NULL,
				(unsigned long)pm, MIGRATE_SYNC, MR_SYSCALL);
		if (err)
			putback_movable_pages(&pagelist);
	}

	up_read(&mm->mmap_sem);
	return err;
}

/*
 * Migrate an array of page address onto an array of nodes and fill
 * the corresponding array of status.
 */
static int do_pages_move(struct mm_struct *mm, nodemask_t task_nodes,
			 unsigned long nr_pages,
			 const void __user * __user *pages,
			 const int __user *nodes,
			 int __user *status, int flags)
{
	struct page_to_node *pm;
	unsigned long chunk_nr_pages;
	unsigned long chunk_start;
	int err;

	err = -ENOMEM;
	pm = (struct page_to_node *)__get_free_page(GFP_KERNEL);
	if (!pm)
		goto out;

	migrate_prep();

	/*
	 * Store a chunk of page_to_node array in a page,
	 * but keep the last one as a marker
	 */
	chunk_nr_pages = (PAGE_SIZE / sizeof(struct page_to_node)) - 1;

	for (chunk_start = 0;
	     chunk_start < nr_pages;
	     chunk_start += chunk_nr_pages) {
		int j;

		if (chunk_start + chunk_nr_pages > nr_pages)
			chunk_nr_pages = nr_pages - chunk_start;

		/* fill the chunk pm with addrs and nodes from user-space */
		for (j = 0; j < chunk_nr_pages; j++) {
			const void __user *p;
			int node;

			err = -EFAULT;
			if (get_user(p, pages + j + chunk_start))
				goto out_pm;
			pm[j].addr = (unsigned long) p;

			if (get_user(node, nodes + j + chunk_start))
				goto out_pm;

			err = -ENODEV;
			if (node < 0 || node >= MAX_NUMNODES)
				goto out_pm;

			if (!node_state(node, N_MEMORY))
				goto out_pm;

			err = -EACCES;
			if (!node_isset(node, task_nodes))
				goto out_pm;

			pm[j].node = node;
		}

		/* End marker for this chunk */
		pm[chunk_nr_pages].node = MAX_NUMNODES;

		/* Migrate this chunk */
		err = do_move_page_to_node_array(mm, pm,
						 flags & MPOL_MF_MOVE_ALL);
		if (err < 0)
			goto out_pm;

		/* Return status information */
		for (j = 0; j < chunk_nr_pages; j++)
			if (put_user(pm[j].status, status + j + chunk_start)) {
				err = -EFAULT;
				goto out_pm;
			}
	}
	err = 0;

out_pm:
	free_page((unsigned long)pm);
out:
	return err;
}

/*
 * Determine the nodes of an array of pages and store it in an array of status.
 */
static void do_pages_stat_array(struct mm_struct *mm, unsigned long nr_pages,
				const void __user **pages, int *status)
{
	unsigned long i;

	down_read(&mm->mmap_sem);

	for (i = 0; i < nr_pages; i++) {
		unsigned long addr = (unsigned long)(*pages);
		struct vm_area_struct *vma;
		struct page *page;
		int err = -EFAULT;

		vma = find_vma(mm, addr);
		if (!vma || addr < vma->vm_start)
			goto set_status;

		/* FOLL_DUMP to ignore special (like zero) pages */
		page = follow_page(vma, addr, FOLL_DUMP);

		err = PTR_ERR(page);
		if (IS_ERR(page))
			goto set_status;

		err = page ? page_to_nid(page) : -ENOENT;
set_status:
		*status = err;

		pages++;
		status++;
	}

	up_read(&mm->mmap_sem);
}

/*
 * Determine the nodes of a user array of pages and store it in
 * a user array of status.
 */
static int do_pages_stat(struct mm_struct *mm, unsigned long nr_pages,
			 const void __user * __user *pages,
			 int __user *status)
{
#define DO_PAGES_STAT_CHUNK_NR 16
	const void __user *chunk_pages[DO_PAGES_STAT_CHUNK_NR];
	int chunk_status[DO_PAGES_STAT_CHUNK_NR];

	while (nr_pages) {
		unsigned long chunk_nr;

		chunk_nr = nr_pages;
		if (chunk_nr > DO_PAGES_STAT_CHUNK_NR)
			chunk_nr = DO_PAGES_STAT_CHUNK_NR;

		if (copy_from_user(chunk_pages, pages, chunk_nr * sizeof(*chunk_pages)))
			break;

		do_pages_stat_array(mm, chunk_nr, chunk_pages, chunk_status);

		if (copy_to_user(status, chunk_status, chunk_nr * sizeof(*status)))
			break;

		pages += chunk_nr;
		status += chunk_nr;
		nr_pages -= chunk_nr;
	}
	return nr_pages ? -EFAULT : 0;
}

/*
 * Move a list of pages in the address space of the currently executing
 * process.
 */
SYSCALL_DEFINE6(move_pages, pid_t, pid, unsigned long, nr_pages,
		const void __user * __user *, pages,
		const int __user *, nodes,
		int __user *, status, int, flags)
{
	const struct cred *cred = current_cred(), *tcred;
	struct task_struct *task;
	struct mm_struct *mm;
	int err;
	nodemask_t task_nodes;

	/* Check flags */
	if (flags & ~(MPOL_MF_MOVE|MPOL_MF_MOVE_ALL))
		return -EINVAL;

	if ((flags & MPOL_MF_MOVE_ALL) && !capable(CAP_SYS_NICE))
		return -EPERM;

	/* Find the mm_struct */
	rcu_read_lock();
	task = pid ? find_task_by_vpid(pid) : current;
	if (!task) {
		rcu_read_unlock();
		return -ESRCH;
	}
	get_task_struct(task);

	/*
	 * Check if this process has the right to modify the specified
	 * process. The right exists if the process has administrative
	 * capabilities, superuser privileges or the same
	 * userid as the target process.
	 */
	tcred = __task_cred(task);
	if (!uid_eq(cred->euid, tcred->suid) && !uid_eq(cred->euid, tcred->uid) &&
	    !uid_eq(cred->uid,  tcred->suid) && !uid_eq(cred->uid,  tcred->uid) &&
	    !capable(CAP_SYS_NICE)) {
		rcu_read_unlock();
		err = -EPERM;
		goto out;
	}
	rcu_read_unlock();

 	err = security_task_movememory(task);
 	if (err)
		goto out;

	task_nodes = cpuset_mems_allowed(task);
	mm = get_task_mm(task);
	put_task_struct(task);

	if (!mm)
		return -EINVAL;

	if (nodes)
		err = do_pages_move(mm, task_nodes, nr_pages, pages,
				    nodes, status, flags);
	else
		err = do_pages_stat(mm, nr_pages, pages, status);

	mmput(mm);
	return err;

out:
	put_task_struct(task);
	return err;
}

#ifdef CONFIG_NUMA_BALANCING
/*
 * Returns true if this is a safe migration target node for misplaced NUMA
 * pages. Currently it only checks the watermarks which crude
 */
static bool migrate_balanced_pgdat(struct pglist_data *pgdat,
				   unsigned long nr_migrate_pages)
{
	int z;

	if (!pgdat_reclaimable(pgdat))
		return false;

	for (z = pgdat->nr_zones - 1; z >= 0; z--) {
		struct zone *zone = pgdat->node_zones + z;

		if (!populated_zone(zone))
			continue;

		/* Avoid waking kswapd by allocating pages_to_migrate pages. */
		if (!zone_watermark_ok(zone, 0,
				       high_wmark_pages(zone) +
				       nr_migrate_pages,
				       0, 0))
			continue;
		return true;
	}
	return false;
}

static struct page *alloc_misplaced_dst_page(struct page *page,
					   unsigned long data,
					   int **result)
{
	int nid = (int) data;
	struct page *newpage;

	newpage = __alloc_pages_node(nid,
					 (GFP_HIGHUSER_MOVABLE |
					  __GFP_THISNODE | __GFP_NOMEMALLOC |
					  __GFP_NORETRY | __GFP_NOWARN) &
					 ~__GFP_RECLAIM, 0);

	return newpage;
}

/*
 * page migration rate limiting control.
 * Do not migrate more than @pages_to_migrate in a @migrate_interval_millisecs
 * window of time. Default here says do not migrate more than 1280M per second.
 */
static unsigned int migrate_interval_millisecs __read_mostly = 100;
static unsigned int ratelimit_pages __read_mostly = 128 << (20 - PAGE_SHIFT);

/* Returns true if the node is migrate rate-limited after the update */
static bool numamigrate_update_ratelimit(pg_data_t *pgdat,
					unsigned long nr_pages)
{
	/*
	 * Rate-limit the amount of data that is being migrated to a node.
	 * Optimal placement is no good if the memory bus is saturated and
	 * all the time is being spent migrating!
	 */
	if (time_after(jiffies, pgdat->numabalancing_migrate_next_window)) {
		spin_lock(&pgdat->numabalancing_migrate_lock);
		pgdat->numabalancing_migrate_nr_pages = 0;
		pgdat->numabalancing_migrate_next_window = jiffies +
			msecs_to_jiffies(migrate_interval_millisecs);
		spin_unlock(&pgdat->numabalancing_migrate_lock);
	}
	if (pgdat->numabalancing_migrate_nr_pages > ratelimit_pages) {
		trace_mm_numa_migrate_ratelimit(current, pgdat->node_id,
								nr_pages);
		return true;
	}

	/*
	 * This is an unlocked non-atomic update so errors are possible.
	 * The consequences are failing to migrate when we potentiall should
	 * have which is not severe enough to warrant locking. If it is ever
	 * a problem, it can be converted to a per-cpu counter.
	 */
	pgdat->numabalancing_migrate_nr_pages += nr_pages;
	return false;
}

static int numamigrate_isolate_page(pg_data_t *pgdat, struct page *page)
{
	int page_lru;

	VM_BUG_ON_PAGE(compound_order(page) && !PageTransHuge(page), page);

	/* Avoid migrating to a node that is nearly full */
	if (!migrate_balanced_pgdat(pgdat, 1UL << compound_order(page)))
		return 0;

	if (isolate_lru_page(page))
		return 0;

	/*
	 * migrate_misplaced_transhuge_page() skips page migration's usual
	 * check on page_count(), so we must do it here, now that the page
	 * has been isolated: a GUP pin, or any other pin, prevents migration.
	 * The expected page count is 3: 1 for page's mapcount and 1 for the
	 * caller's pin and 1 for the reference taken by isolate_lru_page().
	 */
	if (PageTransHuge(page) && page_count(page) != 3) {
		putback_lru_page(page);
		return 0;
	}

	page_lru = page_is_file_cache(page);
	mod_node_page_state(page_pgdat(page), NR_ISOLATED_ANON + page_lru,
				hpage_nr_pages(page));

	/*
	 * Isolating the page has taken another reference, so the
	 * caller's reference can be safely dropped without the page
	 * disappearing underneath us during migration.
	 */
	put_page(page);
	return 1;
}

bool pmd_trans_migrating(pmd_t pmd)
{
	struct page *page = pmd_page(pmd);
	return PageLocked(page);
}

/*
 * Attempt to migrate a misplaced page to the specified destination
 * node. Caller is expected to have an elevated reference count on
 * the page that will be dropped by this function before returning.
 */
int migrate_misplaced_page(struct page *page, struct vm_area_struct *vma,
			   int node)
{
	pg_data_t *pgdat = NODE_DATA(node);
	int isolated;
	int nr_remaining;
	LIST_HEAD(migratepages);

	/*
	 * Don't migrate file pages that are mapped in multiple processes
	 * with execute permissions as they are probably shared libraries.
	 */
	if (page_mapcount(page) != 1 && page_is_file_cache(page) &&
	    (vma->vm_flags & VM_EXEC))
		goto out;

	/*
	 * Rate-limit the amount of data that is being migrated to a node.
	 * Optimal placement is no good if the memory bus is saturated and
	 * all the time is being spent migrating!
	 */
	if (numamigrate_update_ratelimit(pgdat, 1))
		goto out;

	isolated = numamigrate_isolate_page(pgdat, page);
	if (!isolated)
		goto out;

	list_add(&page->lru, &migratepages);
	nr_remaining = migrate_pages(&migratepages, alloc_misplaced_dst_page,
				     NULL, node, MIGRATE_ASYNC,
				     MR_NUMA_MISPLACED);
	if (nr_remaining) {
		if (!list_empty(&migratepages)) {
			list_del(&page->lru);
			dec_node_page_state(page, NR_ISOLATED_ANON +
					page_is_file_cache(page));
			putback_lru_page(page);
		}
		isolated = 0;
	} else
		count_vm_numa_event(NUMA_PAGE_MIGRATE);
	BUG_ON(!list_empty(&migratepages));
	return isolated;

out:
	put_page(page);
	return 0;
}
#endif /* CONFIG_NUMA_BALANCING */

#if defined(CONFIG_NUMA_BALANCING) && defined(CONFIG_TRANSPARENT_HUGEPAGE)
/*
 * Migrates a THP to a given target node. page must be locked and is unlocked
 * before returning.
 */
int migrate_misplaced_transhuge_page(struct mm_struct *mm,
				struct vm_area_struct *vma,
				pmd_t *pmd, pmd_t entry,
				unsigned long address,
				struct page *page, int node)
{
	spinlock_t *ptl;
	pg_data_t *pgdat = NODE_DATA(node);
	int isolated = 0;
	struct page *new_page = NULL;
	int page_lru = page_is_file_cache(page);
	unsigned long mmun_start = address & HPAGE_PMD_MASK;
	unsigned long mmun_end = mmun_start + HPAGE_PMD_SIZE;
	pmd_t orig_entry;

	/*
	 * Rate-limit the amount of data that is being migrated to a node.
	 * Optimal placement is no good if the memory bus is saturated and
	 * all the time is being spent migrating!
	 */
	if (numamigrate_update_ratelimit(pgdat, HPAGE_PMD_NR))
		goto out_dropref;

	new_page = alloc_pages_node(node,
		(GFP_TRANSHUGE_LIGHT | __GFP_THISNODE),
		HPAGE_PMD_ORDER);
	if (!new_page)
		goto out_fail;
	prep_transhuge_page(new_page);

	isolated = numamigrate_isolate_page(pgdat, page);
	if (!isolated) {
		put_page(new_page);
		goto out_fail;
	}
	/*
	 * We are not sure a pending tlb flush here is for a huge page
	 * mapping or not. Hence use the tlb range variant
	 */
	if (mm_tlb_flush_pending(mm))
		flush_tlb_range(vma, mmun_start, mmun_end);

	/* Prepare a page as a migration target */
	__SetPageLocked(new_page);
	__SetPageSwapBacked(new_page);

	/* anon mapping, we can simply copy page->mapping to the new page: */
	new_page->mapping = page->mapping;
	new_page->index = page->index;
	migrate_page_copy(new_page, page);
	WARN_ON(PageLRU(new_page));

	/* Recheck the target PMD */
	mmu_notifier_invalidate_range_start(mm, mmun_start, mmun_end);
	ptl = pmd_lock(mm, pmd);
	if (unlikely(!pmd_same(*pmd, entry) || page_count(page) != 2)) {
fail_putback:
		spin_unlock(ptl);
		mmu_notifier_invalidate_range_end(mm, mmun_start, mmun_end);

		/* Reverse changes made by migrate_page_copy() */
		if (TestClearPageActive(new_page))
			SetPageActive(page);
		if (TestClearPageUnevictable(new_page))
			SetPageUnevictable(page);

		unlock_page(new_page);
		put_page(new_page);		/* Free it */

		/* Retake the callers reference and putback on LRU */
		get_page(page);
		putback_lru_page(page);
		mod_node_page_state(page_pgdat(page),
			 NR_ISOLATED_ANON + page_lru, -HPAGE_PMD_NR);

		goto out_unlock;
	}

	orig_entry = *pmd;
	entry = mk_huge_pmd(new_page, vma->vm_page_prot);
	entry = maybe_pmd_mkwrite(pmd_mkdirty(entry), vma);

	/*
	 * Clear the old entry under pagetable lock and establish the new PTE.
	 * Any parallel GUP will either observe the old page blocking on the
	 * page lock, block on the page table lock or observe the new page.
	 * The SetPageUptodate on the new page and page_add_new_anon_rmap
	 * guarantee the copy is visible before the pagetable update.
	 */
	flush_cache_range(vma, mmun_start, mmun_end);
	page_add_anon_rmap(new_page, vma, mmun_start, true);
	pmdp_huge_clear_flush_notify(vma, mmun_start, pmd);
	set_pmd_at(mm, mmun_start, pmd, entry);
	update_mmu_cache_pmd(vma, address, &entry);

	if (page_count(page) != 2) {
		set_pmd_at(mm, mmun_start, pmd, orig_entry);
		flush_pmd_tlb_range(vma, mmun_start, mmun_end);
		mmu_notifier_invalidate_range(mm, mmun_start, mmun_end);
		update_mmu_cache_pmd(vma, address, &entry);
		page_remove_rmap(new_page, true);
		goto fail_putback;
	}

	mlock_migrate_page(new_page, page);
	page_remove_rmap(page, true);
	set_page_owner_migrate_reason(new_page, MR_NUMA_MISPLACED);

	spin_unlock(ptl);
	mmu_notifier_invalidate_range_end(mm, mmun_start, mmun_end);

	/* Take an "isolate" reference and put new page on the LRU. */
	get_page(new_page);
	putback_lru_page(new_page);

	unlock_page(new_page);
	unlock_page(page);
	put_page(page);			/* Drop the rmap reference */
	put_page(page);			/* Drop the LRU isolation reference */

	count_vm_events(PGMIGRATE_SUCCESS, HPAGE_PMD_NR);
	count_vm_numa_events(NUMA_PAGE_MIGRATE, HPAGE_PMD_NR);

	mod_node_page_state(page_pgdat(page),
			NR_ISOLATED_ANON + page_lru,
			-HPAGE_PMD_NR);
	return isolated;

out_fail:
	count_vm_events(PGMIGRATE_FAIL, HPAGE_PMD_NR);
out_dropref:
	ptl = pmd_lock(mm, pmd);
	if (pmd_same(*pmd, entry)) {
		entry = pmd_modify(entry, vma->vm_page_prot);
		set_pmd_at(mm, mmun_start, pmd, entry);
		update_mmu_cache_pmd(vma, address, &entry);
	}
	spin_unlock(ptl);

out_unlock:
	unlock_page(page);
	put_page(page);
	return 0;
}
#endif /* CONFIG_NUMA_BALANCING */

#endif /* CONFIG_NUMA */
