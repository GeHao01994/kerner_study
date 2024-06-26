/*
 *	linux/mm/filemap.c
 *
 * Copyright (C) 1994-1999  Linus Torvalds
 */

/*
 * This file handles the generic file mmap semantics used by
 * most "normal" filesystems (but you don't /have/ to use this:
 * the NFS filesystem used to do this differently, for example)
 */
#include <linux/export.h>
#include <linux/compiler.h>
#include <linux/dax.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/capability.h>
#include <linux/kernel_stat.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/mman.h>
#include <linux/pagemap.h>
#include <linux/file.h>
#include <linux/uio.h>
#include <linux/hash.h>
#include <linux/writeback.h>
#include <linux/backing-dev.h>
#include <linux/pagevec.h>
#include <linux/blkdev.h>
#include <linux/security.h>
#include <linux/cpuset.h>
#include <linux/hardirq.h> /* for BUG_ON(!in_atomic()) only */
#include <linux/hugetlb.h>
#include <linux/memcontrol.h>
#include <linux/cleancache.h>
#include <linux/rmap.h>
#include "internal.h"

#define CREATE_TRACE_POINTS
#include <trace/events/filemap.h>

/*
 * FIXME: remove all knowledge of the buffer layer from the core VM
 */
#include <linux/buffer_head.h> /* for try_to_free_buffers */

#include <asm/mman.h>

/*
 * Shared mappings implemented 30.11.1994. It's not fully working yet,
 * though.
 *
 * Shared mappings now work. 15.8.1995  Bruno.
 *
 * finished 'unifying' the page and buffer cache and SMP-threaded the
 * page-cache, 21.05.1999, Ingo Molnar <mingo@redhat.com>
 *
 * SMP-threaded pagemap-LRU 1999, Andrea Arcangeli <andrea@suse.de>
 */

/*
 * Lock ordering:
 *
 *  ->i_mmap_rwsem		(truncate_pagecache)
 *    ->private_lock		(__free_pte->__set_page_dirty_buffers)
 *      ->swap_lock		(exclusive_swap_page, others)
 *        ->mapping->tree_lock
 *
 *  ->i_mutex
 *    ->i_mmap_rwsem		(truncate->unmap_mapping_range)
 *
 *  ->mmap_sem
 *    ->i_mmap_rwsem
 *      ->page_table_lock or pte_lock	(various, mainly in memory.c)
 *        ->mapping->tree_lock	(arch-dependent flush_dcache_mmap_lock)
 *
 *  ->mmap_sem
 *    ->lock_page		(access_process_vm)
 *
 *  ->i_mutex			(generic_perform_write)
 *    ->mmap_sem		(fault_in_pages_readable->do_page_fault)
 *
 *  bdi->wb.list_lock
 *    sb_lock			(fs/fs-writeback.c)
 *    ->mapping->tree_lock	(__sync_single_inode)
 *
 *  ->i_mmap_rwsem
 *    ->anon_vma.lock		(vma_adjust)
 *
 *  ->anon_vma.lock
 *    ->page_table_lock or pte_lock	(anon_vma_prepare and various)
 *
 *  ->page_table_lock or pte_lock
 *    ->swap_lock		(try_to_unmap_one)
 *    ->private_lock		(try_to_unmap_one)
 *    ->tree_lock		(try_to_unmap_one)
 *    ->zone_lru_lock(zone)	(follow_page->mark_page_accessed)
 *    ->zone_lru_lock(zone)	(check_pte_range->isolate_lru_page)
 *    ->private_lock		(page_remove_rmap->set_page_dirty)
 *    ->tree_lock		(page_remove_rmap->set_page_dirty)
 *    bdi.wb->list_lock		(page_remove_rmap->set_page_dirty)
 *    ->inode->i_lock		(page_remove_rmap->set_page_dirty)
 *    ->memcg->move_lock	(page_remove_rmap->lock_page_memcg)
 *    bdi.wb->list_lock		(zap_pte_range->set_page_dirty)
 *    ->inode->i_lock		(zap_pte_range->set_page_dirty)
 *    ->private_lock		(zap_pte_range->__set_page_dirty_buffers)
 *
 * ->i_mmap_rwsem
 *   ->tasklist_lock            (memory_failure, collect_procs_ao)
 */

static int page_cache_tree_insert(struct address_space *mapping,
				  struct page *page, void **shadowp)
{
	struct radix_tree_node *node;
	void **slot;
	int error;

	error = __radix_tree_create(&mapping->page_tree, page->index, 0,
				    &node, &slot);
	if (error)
		return error;
	if (*slot) {
		void *p;

		p = radix_tree_deref_slot_protected(slot, &mapping->tree_lock);
		if (!radix_tree_exceptional_entry(p))
			return -EEXIST;

		mapping->nrexceptional--;
		if (!dax_mapping(mapping)) {
			if (shadowp)
				*shadowp = p;
			if (node)
				workingset_node_shadows_dec(node);
		} else {
			/* DAX can replace empty locked entry with a hole */
			WARN_ON_ONCE(p !=
				(void *)(RADIX_TREE_EXCEPTIONAL_ENTRY |
					 RADIX_DAX_ENTRY_LOCK));
			/* DAX accounts exceptional entries as normal pages */
			if (node)
				workingset_node_pages_dec(node);
			/* Wakeup waiters for exceptional entry lock */
			dax_wake_mapping_entry_waiter(mapping, page->index,
						      true);
		}
	}
	radix_tree_replace_slot(slot, page);
	mapping->nrpages++;
	if (node) {
		workingset_node_pages_inc(node);
		/*
		 * Don't track node that contains actual pages.
		 *
		 * Avoid acquiring the list_lru lock if already
		 * untracked.  The list_empty() test is safe as
		 * node->private_list is protected by
		 * mapping->tree_lock.
		 */
		if (!list_empty(&node->private_list))
			list_lru_del(&workingset_shadow_nodes,
				     &node->private_list);
	}
	return 0;
}

static void page_cache_tree_delete(struct address_space *mapping,
				   struct page *page, void *shadow)
{
	int i, nr = PageHuge(page) ? 1 : hpage_nr_pages(page);

	VM_BUG_ON_PAGE(!PageLocked(page), page);
	VM_BUG_ON_PAGE(PageTail(page), page);
	VM_BUG_ON_PAGE(nr != 1 && shadow, page);

	for (i = 0; i < nr; i++) {
		struct radix_tree_node *node;
		void **slot;

		__radix_tree_lookup(&mapping->page_tree, page->index + i,
				    &node, &slot);

		radix_tree_clear_tags(&mapping->page_tree, node, slot);

		if (!node) {
			VM_BUG_ON_PAGE(nr != 1, page);
			/*
			 * We need a node to properly account shadow
			 * entries. Don't plant any without. XXX
			 */
			shadow = NULL;
		}

		radix_tree_replace_slot(slot, shadow);

		if (!node)
			break;

		workingset_node_pages_dec(node);
		if (shadow)
			workingset_node_shadows_inc(node);
		else
			if (__radix_tree_delete_node(&mapping->page_tree, node))
				continue;

		/*
		 * Track node that only contains shadow entries. DAX mappings
		 * contain no shadow entries and may contain other exceptional
		 * entries so skip those.
		 *
		 * Avoid acquiring the list_lru lock if already tracked.
		 * The list_empty() test is safe as node->private_list is
		 * protected by mapping->tree_lock.
		 */
		if (!dax_mapping(mapping) && !workingset_node_pages(node) &&
				list_empty(&node->private_list)) {
			node->private_data = mapping;
			list_lru_add(&workingset_shadow_nodes,
					&node->private_list);
		}
	}

	if (shadow) {
		mapping->nrexceptional += nr;
		/*
		 * Make sure the nrexceptional update is committed before
		 * the nrpages update so that final truncate racing
		 * with reclaim does not see both counters 0 at the
		 * same time and miss a shadow entry.
		 */
		smp_wmb();
	}
	mapping->nrpages -= nr;
}

/*
 * Delete a page from the page cache and free it. Caller has to make
 * sure the page is locked and that nobody else uses it - or that usage
 * is safe.  The caller must hold the mapping's tree_lock.
 */
void __delete_from_page_cache(struct page *page, void *shadow)
{
	struct address_space *mapping = page->mapping;
	int nr = hpage_nr_pages(page);

	trace_mm_filemap_delete_from_page_cache(page);
	/*
	 * if we're uptodate, flush out into the cleancache, otherwise
	 * invalidate any existing cleancache entries.  We can't leave
	 * stale data around in the cleancache once our page is gone
	 */
	if (PageUptodate(page) && PageMappedToDisk(page))
		cleancache_put_page(page);
	else
		cleancache_invalidate_page(mapping, page);

	VM_BUG_ON_PAGE(PageTail(page), page);
	VM_BUG_ON_PAGE(page_mapped(page), page);
	if (!IS_ENABLED(CONFIG_DEBUG_VM) && unlikely(page_mapped(page))) {
		int mapcount;

		pr_alert("BUG: Bad page cache in process %s  pfn:%05lx\n",
			 current->comm, page_to_pfn(page));
		dump_page(page, "still mapped when deleted");
		dump_stack();
		add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);

		mapcount = page_mapcount(page);
		if (mapping_exiting(mapping) &&
		    page_count(page) >= mapcount + 2) {
			/*
			 * All vmas have already been torn down, so it's
			 * a good bet that actually the page is unmapped,
			 * and we'd prefer not to leak it: if we're wrong,
			 * some other bad page check should catch it later.
			 */
			page_mapcount_reset(page);
			page_ref_sub(page, mapcount);
		}
	}

	page_cache_tree_delete(mapping, page, shadow);

	page->mapping = NULL;
	/* Leave page->index set: truncation lookup relies upon it */

	/* hugetlb pages do not participate in page cache accounting. */
	if (!PageHuge(page))
		__mod_node_page_state(page_pgdat(page), NR_FILE_PAGES, -nr);
	if (PageSwapBacked(page)) {
		__mod_node_page_state(page_pgdat(page), NR_SHMEM, -nr);
		if (PageTransHuge(page))
			__dec_node_page_state(page, NR_SHMEM_THPS);
	} else {
		VM_BUG_ON_PAGE(PageTransHuge(page) && !PageHuge(page), page);
	}

	/*
	 * At this point page must be either written or cleaned by truncate.
	 * Dirty page here signals a bug and loss of unwritten data.
	 *
	 * This fixes dirty accounting after removing the page entirely but
	 * leaves PageDirty set: it has no effect for truncated page and
	 * anyway will be cleared before returning page into buddy allocator.
	 */
	if (WARN_ON_ONCE(PageDirty(page)))
		account_page_cleaned(page, mapping, inode_to_wb(mapping->host));
}

/**
 * delete_from_page_cache - delete page from page cache
 * @page: the page which the kernel is trying to remove from page cache
 *
 * This must be called only on pages that have been verified to be in the page
 * cache and locked.  It will never put the page into the free list, the caller
 * has a reference on the page.
 */
void delete_from_page_cache(struct page *page)
{
	struct address_space *mapping = page_mapping(page);
	unsigned long flags;
	void (*freepage)(struct page *);

	BUG_ON(!PageLocked(page));

	freepage = mapping->a_ops->freepage;

	spin_lock_irqsave(&mapping->tree_lock, flags);
	__delete_from_page_cache(page, NULL);
	spin_unlock_irqrestore(&mapping->tree_lock, flags);

	if (freepage)
		freepage(page);

	if (PageTransHuge(page) && !PageHuge(page)) {
		page_ref_sub(page, HPAGE_PMD_NR);
		VM_BUG_ON_PAGE(page_count(page) <= 0, page);
	} else {
		put_page(page);
	}
}
EXPORT_SYMBOL(delete_from_page_cache);

int filemap_check_errors(struct address_space *mapping)
{
	int ret = 0;
	/* Check for outstanding write errors */
	if (test_bit(AS_ENOSPC, &mapping->flags) &&
	    test_and_clear_bit(AS_ENOSPC, &mapping->flags))
		ret = -ENOSPC;
	if (test_bit(AS_EIO, &mapping->flags) &&
	    test_and_clear_bit(AS_EIO, &mapping->flags))
		ret = -EIO;
	return ret;
}
EXPORT_SYMBOL(filemap_check_errors);

/**
 * __filemap_fdatawrite_range - start writeback on mapping dirty pages in range
 * @mapping:	address space structure to write
 * @start:	offset in bytes where the range starts
 * @end:	offset in bytes where the range ends (inclusive)
 * @sync_mode:	enable synchronous operation
 *
 * Start writeback against all of a mapping's dirty pages that lie
 * within the byte offsets <start, end> inclusive.
 *
 * If sync_mode is WB_SYNC_ALL then this is a "data integrity" operation, as
 * opposed to a regular memory cleansing writeback.  The difference between
 * these two operations is that if a dirty page/buffer is encountered, it must
 * be waited upon, and not just skipped over.
 */
int __filemap_fdatawrite_range(struct address_space *mapping, loff_t start,
				loff_t end, int sync_mode)
{
	int ret;
	struct writeback_control wbc = {
		.sync_mode = sync_mode,
		.nr_to_write = LONG_MAX,
		.range_start = start,
		.range_end = end,
	};

	if (!mapping_cap_writeback_dirty(mapping))
		return 0;

	wbc_attach_fdatawrite_inode(&wbc, mapping->host);
	ret = do_writepages(mapping, &wbc);
	wbc_detach_inode(&wbc);
	return ret;
}

static inline int __filemap_fdatawrite(struct address_space *mapping,
	int sync_mode)
{
	return __filemap_fdatawrite_range(mapping, 0, LLONG_MAX, sync_mode);
}

int filemap_fdatawrite(struct address_space *mapping)
{
	return __filemap_fdatawrite(mapping, WB_SYNC_ALL);
}
EXPORT_SYMBOL(filemap_fdatawrite);

int filemap_fdatawrite_range(struct address_space *mapping, loff_t start,
				loff_t end)
{
	return __filemap_fdatawrite_range(mapping, start, end, WB_SYNC_ALL);
}
EXPORT_SYMBOL(filemap_fdatawrite_range);

/**
 * filemap_flush - mostly a non-blocking flush
 * @mapping:	target address_space
 *
 * This is a mostly non-blocking flush.  Not suitable for data-integrity
 * purposes - I/O may not be started against all dirty pages.
 */
int filemap_flush(struct address_space *mapping)
{
	return __filemap_fdatawrite(mapping, WB_SYNC_NONE);
}
EXPORT_SYMBOL(filemap_flush);

static int __filemap_fdatawait_range(struct address_space *mapping,
				     loff_t start_byte, loff_t end_byte)
{
	pgoff_t index = start_byte >> PAGE_SHIFT;
	pgoff_t end = end_byte >> PAGE_SHIFT;
	struct pagevec pvec;
	int nr_pages;
	int ret = 0;

	if (end_byte < start_byte)
		goto out;

	pagevec_init(&pvec, 0);
	while ((index <= end) &&
			(nr_pages = pagevec_lookup_tag(&pvec, mapping, &index,
			PAGECACHE_TAG_WRITEBACK,
			min(end - index, (pgoff_t)PAGEVEC_SIZE-1) + 1)) != 0) {
		unsigned i;

		for (i = 0; i < nr_pages; i++) {
			struct page *page = pvec.pages[i];

			/* until radix tree lookup accepts end_index */
			if (page->index > end)
				continue;

			wait_on_page_writeback(page);
			if (TestClearPageError(page))
				ret = -EIO;
		}
		pagevec_release(&pvec);
		cond_resched();
	}
out:
	return ret;
}

/**
 * filemap_fdatawait_range - wait for writeback to complete
 * @mapping:		address space structure to wait for
 * @start_byte:		offset in bytes where the range starts
 * @end_byte:		offset in bytes where the range ends (inclusive)
 *
 * Walk the list of under-writeback pages of the given address space
 * in the given range and wait for all of them.  Check error status of
 * the address space and return it.
 *
 * Since the error status of the address space is cleared by this function,
 * callers are responsible for checking the return value and handling and/or
 * reporting the error.
 */
int filemap_fdatawait_range(struct address_space *mapping, loff_t start_byte,
			    loff_t end_byte)
{
	int ret, ret2;

	ret = __filemap_fdatawait_range(mapping, start_byte, end_byte);
	ret2 = filemap_check_errors(mapping);
	if (!ret)
		ret = ret2;

	return ret;
}
EXPORT_SYMBOL(filemap_fdatawait_range);

/**
 * filemap_fdatawait_keep_errors - wait for writeback without clearing errors
 * @mapping: address space structure to wait for
 *
 * Walk the list of under-writeback pages of the given address space
 * and wait for all of them.  Unlike filemap_fdatawait(), this function
 * does not clear error status of the address space.
 *
 * Use this function if callers don't handle errors themselves.  Expected
 * call sites are system-wide / filesystem-wide data flushers: e.g. sync(2),
 * fsfreeze(8)
 */
void filemap_fdatawait_keep_errors(struct address_space *mapping)
{
	loff_t i_size = i_size_read(mapping->host);

	if (i_size == 0)
		return;

	__filemap_fdatawait_range(mapping, 0, i_size - 1);
}

/**
 * filemap_fdatawait - wait for all under-writeback pages to complete
 * @mapping: address space structure to wait for
 *
 * Walk the list of under-writeback pages of the given address space
 * and wait for all of them.  Check error status of the address space
 * and return it.
 *
 * Since the error status of the address space is cleared by this function,
 * callers are responsible for checking the return value and handling and/or
 * reporting the error.
 */
int filemap_fdatawait(struct address_space *mapping)
{
	loff_t i_size = i_size_read(mapping->host);

	if (i_size == 0)
		return 0;

	return filemap_fdatawait_range(mapping, 0, i_size - 1);
}
EXPORT_SYMBOL(filemap_fdatawait);

int filemap_write_and_wait(struct address_space *mapping)
{
	int err = 0;

	if ((!dax_mapping(mapping) && mapping->nrpages) ||
	    (dax_mapping(mapping) && mapping->nrexceptional)) {
		err = filemap_fdatawrite(mapping);
		/*
		 * Even if the above returned error, the pages may be
		 * written partially (e.g. -ENOSPC), so we wait for it.
		 * But the -EIO is special case, it may indicate the worst
		 * thing (e.g. bug) happened, so we avoid waiting for it.
		 */
		if (err != -EIO) {
			int err2 = filemap_fdatawait(mapping);
			if (!err)
				err = err2;
		}
	} else {
		err = filemap_check_errors(mapping);
	}
	return err;
}
EXPORT_SYMBOL(filemap_write_and_wait);

/**
 * filemap_write_and_wait_range - write out & wait on a file range
 * @mapping:	the address_space for the pages
 * @lstart:	offset in bytes where the range starts
 * @lend:	offset in bytes where the range ends (inclusive)
 *
 * Write out and wait upon file offsets lstart->lend, inclusive.
 *
 * Note that `lend' is inclusive (describes the last byte to be written) so
 * that this function can be used to write to the very end-of-file (end = -1).
 */
int filemap_write_and_wait_range(struct address_space *mapping,
				 loff_t lstart, loff_t lend)
{
	int err = 0;

	if ((!dax_mapping(mapping) && mapping->nrpages) ||
	    (dax_mapping(mapping) && mapping->nrexceptional)) {
		err = __filemap_fdatawrite_range(mapping, lstart, lend,
						 WB_SYNC_ALL);
		/* See comment of filemap_write_and_wait() */
		if (err != -EIO) {
			int err2 = filemap_fdatawait_range(mapping,
						lstart, lend);
			if (!err)
				err = err2;
		}
	} else {
		err = filemap_check_errors(mapping);
	}
	return err;
}
EXPORT_SYMBOL(filemap_write_and_wait_range);

/**
 * replace_page_cache_page - replace a pagecache page with a new one
 * @old:	page to be replaced
 * @new:	page to replace with
 * @gfp_mask:	allocation mode
 *
 * This function replaces a page in the pagecache with a new one.  On
 * success it acquires the pagecache reference for the new page and
 * drops it for the old page.  Both the old and new pages must be
 * locked.  This function does not add the new page to the LRU, the
 * caller must do that.
 *
 * The remove + add is atomic.  The only way this function can fail is
 * memory allocation failure.
 */
int replace_page_cache_page(struct page *old, struct page *new, gfp_t gfp_mask)
{
	int error;

	VM_BUG_ON_PAGE(!PageLocked(old), old);
	VM_BUG_ON_PAGE(!PageLocked(new), new);
	VM_BUG_ON_PAGE(new->mapping, new);

	error = radix_tree_preload(gfp_mask & ~__GFP_HIGHMEM);
	if (!error) {
		struct address_space *mapping = old->mapping;
		void (*freepage)(struct page *);
		unsigned long flags;

		pgoff_t offset = old->index;
		freepage = mapping->a_ops->freepage;

		get_page(new);
		new->mapping = mapping;
		new->index = offset;

		spin_lock_irqsave(&mapping->tree_lock, flags);
		__delete_from_page_cache(old, NULL);
		error = page_cache_tree_insert(mapping, new, NULL);
		BUG_ON(error);

		/*
		 * hugetlb pages do not participate in page cache accounting.
		 */
		if (!PageHuge(new))
			__inc_node_page_state(new, NR_FILE_PAGES);
		if (PageSwapBacked(new))
			__inc_node_page_state(new, NR_SHMEM);
		spin_unlock_irqrestore(&mapping->tree_lock, flags);
		mem_cgroup_migrate(old, new);
		radix_tree_preload_end();
		if (freepage)
			freepage(old);
		put_page(old);
	}

	return error;
}
EXPORT_SYMBOL_GPL(replace_page_cache_page);

static int __add_to_page_cache_locked(struct page *page,
				      struct address_space *mapping,
				      pgoff_t offset, gfp_t gfp_mask,
				      void **shadowp)
{
	/* hugetlb的page ? */
	int huge = PageHuge(page);
	struct mem_cgroup *memcg;
	int error;

	VM_BUG_ON_PAGE(!PageLocked(page), page);
	/* 此页可写入swap分区，一般用于表示此页是非文件页 */
	VM_BUG_ON_PAGE(PageSwapBacked(page), page);
	/* 如果不是hugetlb的page,让cgroup计数 */
	if (!huge) {
		error = mem_cgroup_try_charge(page, current->mm,
					      gfp_mask, &memcg, false);
		if (error)
			return error;
	}
	/* radix_tree_preload分配了足够的内存,以便后续插入树中不会失败 */
	error = radix_tree_maybe_preload(gfp_mask & ~__GFP_HIGHMEM);
	if (error) {
		if (!huge)
			mem_cgroup_cancel_charge(page, memcg, false);
		return error;
	}
	/* 增加page的引用计数 */
	get_page(page);
	/* 设置page的mappign为该mapping(地址空间) */
	page->mapping = mapping;
	/* 设置当前page的index */
	page->index = offset;

	spin_lock_irq(&mapping->tree_lock);
	/* 把page插入到radix_tree里面去 */
	error = page_cache_tree_insert(mapping, page, shadowp);
	/* 因为我们前面radix_tree_maybe_preload 关闭了抢占，所以这里打开抢占 */
	radix_tree_preload_end();
	if (unlikely(error))
		goto err_insert;

	/* hugetlb pages do not participate in page cache accounting. */
	/*  hugetlb页面不参与page cache 计数 */
	if (!huge)
		__inc_node_page_state(page, NR_FILE_PAGES);
	spin_unlock_irq(&mapping->tree_lock);
	if (!huge)
		mem_cgroup_commit_charge(page, memcg, false, false);
	trace_mm_filemap_add_to_page_cache(page);
	return 0;
err_insert:
	page->mapping = NULL;
	/* Leave page->index set: truncation relies upon it */
	spin_unlock_irq(&mapping->tree_lock);
	if (!huge)
		mem_cgroup_cancel_charge(page, memcg, false);
	put_page(page);
	return error;
}

/**
 * add_to_page_cache_locked - add a locked page to the pagecache
 * @page:	page to add
 * @mapping:	the page's address_space
 * @offset:	page index
 * @gfp_mask:	page allocation mode
 *
 * This function is used to add a page to the pagecache. It must be locked.
 * This function does not add the page to the LRU.  The caller must do that.
 */
int add_to_page_cache_locked(struct page *page, struct address_space *mapping,
		pgoff_t offset, gfp_t gfp_mask)
{
	return __add_to_page_cache_locked(page, mapping, offset,
					  gfp_mask, NULL);
}
EXPORT_SYMBOL(add_to_page_cache_locked);

int add_to_page_cache_lru(struct page *page, struct address_space *mapping,
				pgoff_t offset, gfp_t gfp_mask)
{
	void *shadow = NULL;
	int ret;
	/* 先把page给lock起来 */
	__SetPageLocked(page);
	ret = __add_to_page_cache_locked(page, mapping, offset,
					 gfp_mask, &shadow);
	if (unlikely(ret))
		__ClearPageLocked(page);
	else {
		/*
		 * The page might have been evicted from cache only
		 * recently, in which case it should be activated like
		 * any other repeatedly accessed page.
		 * The exception is pages getting rewritten; evicting other
		 * data from the working set, only to cache data that will
		 * get overwritten with something else, is a waste of memory.
		 */
		/* 该页面可能是最近才从缓存中逐出的，在这种情况下，它应该像任何其他重复访问的页面一样变成activated.
		 * 页面被重写是个例外;从working set 中驱逐其他数据，只是为了缓存将被其他数据覆盖的数据，这是对内存的浪费.
		 */
		if (!(gfp_mask & __GFP_WRITE) &&
		    shadow && workingset_refault(shadow)) {
			SetPageActive(page);
			workingset_activation(page);
			/* 加入不活跃链表 */
		} else
			ClearPageActive(page);
		lru_cache_add(page);
	}
	return ret;
}
EXPORT_SYMBOL_GPL(add_to_page_cache_lru);

#ifdef CONFIG_NUMA
struct page *__page_cache_alloc(gfp_t gfp)
{
	int n;
	struct page *page;

	if (cpuset_do_page_mem_spread()) {
		unsigned int cpuset_mems_cookie;
		do {
			cpuset_mems_cookie = read_mems_allowed_begin();
			n = cpuset_mem_spread_node();
			page = __alloc_pages_node(n, gfp, 0);
		} while (!page && read_mems_allowed_retry(cpuset_mems_cookie));

		return page;
	}
	return alloc_pages(gfp, 0);
}
EXPORT_SYMBOL(__page_cache_alloc);
#endif

/*
 * In order to wait for pages to become available there must be
 * waitqueues associated with pages. By using a hash table of
 * waitqueues where the bucket discipline is to maintain all
 * waiters on the same queue and wake all when any of the pages
 * become available, and for the woken contexts to check to be
 * sure the appropriate page became available, this saves space
 * at a cost of "thundering herd" phenomena during rare hash
 * collisions.
 */
wait_queue_head_t *page_waitqueue(struct page *page)
{
	return bit_waitqueue(page, 0);
}
EXPORT_SYMBOL(page_waitqueue);

void wait_on_page_bit(struct page *page, int bit_nr)
{
	DEFINE_WAIT_BIT(wait, &page->flags, bit_nr);

	if (test_bit(bit_nr, &page->flags))
		__wait_on_bit(page_waitqueue(page), &wait, bit_wait_io,
							TASK_UNINTERRUPTIBLE);
}
EXPORT_SYMBOL(wait_on_page_bit);

int wait_on_page_bit_killable(struct page *page, int bit_nr)
{
	DEFINE_WAIT_BIT(wait, &page->flags, bit_nr);

	if (!test_bit(bit_nr, &page->flags))
		return 0;

	return __wait_on_bit(page_waitqueue(page), &wait,
			     bit_wait_io, TASK_KILLABLE);
}

int wait_on_page_bit_killable_timeout(struct page *page,
				       int bit_nr, unsigned long timeout)
{
	DEFINE_WAIT_BIT(wait, &page->flags, bit_nr);

	wait.key.timeout = jiffies + timeout;
	if (!test_bit(bit_nr, &page->flags))
		return 0;
	return __wait_on_bit(page_waitqueue(page), &wait,
			     bit_wait_io_timeout, TASK_KILLABLE);
}
EXPORT_SYMBOL_GPL(wait_on_page_bit_killable_timeout);

/**
 * add_page_wait_queue - Add an arbitrary waiter to a page's wait queue
 * @page: Page defining the wait queue of interest
 * @waiter: Waiter to add to the queue
 *
 * Add an arbitrary @waiter to the wait queue for the nominated @page.
 */
void add_page_wait_queue(struct page *page, wait_queue_t *waiter)
{
	wait_queue_head_t *q = page_waitqueue(page);
	unsigned long flags;

	spin_lock_irqsave(&q->lock, flags);
	__add_wait_queue(q, waiter);
	spin_unlock_irqrestore(&q->lock, flags);
}
EXPORT_SYMBOL_GPL(add_page_wait_queue);

/**
 * unlock_page - unlock a locked page
 * @page: the page
 *
 * Unlocks the page and wakes up sleepers in ___wait_on_page_locked().
 * Also wakes sleepers in wait_on_page_writeback() because the wakeup
 * mechanism between PageLocked pages and PageWriteback pages is shared.
 * But that's OK - sleepers in wait_on_page_writeback() just go back to sleep.
 *
 * The mb is necessary to enforce ordering between the clear_bit and the read
 * of the waitqueue (to avoid SMP races with a parallel wait_on_page_locked()).
 */
void unlock_page(struct page *page)
{
	page = compound_head(page);
	VM_BUG_ON_PAGE(!PageLocked(page), page);
	clear_bit_unlock(PG_locked, &page->flags);
	smp_mb__after_atomic();
	wake_up_page(page, PG_locked);
}
EXPORT_SYMBOL(unlock_page);

/**
 * end_page_writeback - end writeback against a page
 * @page: the page
 */
void end_page_writeback(struct page *page)
{
	/*
	 * TestClearPageReclaim could be used here but it is an atomic
	 * operation and overkill in this particular case. Failing to
	 * shuffle a page marked for immediate reclaim is too mild to
	 * justify taking an atomic operation penalty at the end of
	 * ever page writeback.
	 */
	if (PageReclaim(page)) {
		ClearPageReclaim(page);
		rotate_reclaimable_page(page);
	}

	if (!test_clear_page_writeback(page))
		BUG();

	smp_mb__after_atomic();
	wake_up_page(page, PG_writeback);
}
EXPORT_SYMBOL(end_page_writeback);

/*
 * After completing I/O on a page, call this routine to update the page
 * flags appropriately
 */
void page_endio(struct page *page, bool is_write, int err)
{
	if (!is_write) {
		if (!err) {
			SetPageUptodate(page);
		} else {
			ClearPageUptodate(page);
			SetPageError(page);
		}
		unlock_page(page);
	} else {
		if (err) {
			struct address_space *mapping;

			SetPageError(page);
			mapping = page_mapping(page);
			if (mapping)
				mapping_set_error(mapping, err);
		}
		end_page_writeback(page);
	}
}
EXPORT_SYMBOL_GPL(page_endio);

/**
 * __lock_page - get a lock on the page, assuming we need to sleep to get it
 * @page: the page to lock
 */
void __lock_page(struct page *page)
{
	struct page *page_head = compound_head(page);
	DEFINE_WAIT_BIT(wait, &page_head->flags, PG_locked);

	__wait_on_bit_lock(page_waitqueue(page_head), &wait, bit_wait_io,
							TASK_UNINTERRUPTIBLE);
}
EXPORT_SYMBOL(__lock_page);

int __lock_page_killable(struct page *page)
{
	struct page *page_head = compound_head(page);
	DEFINE_WAIT_BIT(wait, &page_head->flags, PG_locked);

	return __wait_on_bit_lock(page_waitqueue(page_head), &wait,
					bit_wait_io, TASK_KILLABLE);
}
EXPORT_SYMBOL_GPL(__lock_page_killable);

/*
 * Return values:
 * 1 - page is locked; mmap_sem is still held.
 * 0 - page is not locked.
 *     mmap_sem has been released (up_read()), unless flags had both
 *     FAULT_FLAG_ALLOW_RETRY and FAULT_FLAG_RETRY_NOWAIT set, in
 *     which case mmap_sem is still held.
 *
 * If neither ALLOW_RETRY nor KILLABLE are set, will always return 1
 * with the page locked and the mmap_sem unperturbed.
 *
 *
 * 返回值：
 * 1 - 页面已锁定; mmap_sem仍然保持.
 * 0 - 页面未锁定.
 *
 * mmap_sem已经被释放(up_read()),除非标志同时设置了FAULT_FLAG_ALLOW_RETRY和FAULT_FlagG_RETRY_NOWAIT,
 * 在这种情况下，mmap_sem仍保持不变。
 * 如果既没有设置ALLOW_RETRY也没有设置KILLABLE,则在页面锁定且mmap_sem未受干扰的情况下,将始终返回1.
 */
int __lock_page_or_retry(struct page *page, struct mm_struct *mm,
			 unsigned int flags)
{
	/* 如果flag带了FAULT_FLAG_ALLOW_RETRY
	 * #define FAULT_FLAG_ALLOW_RETRY	0x04	Retry fault if blocking
	 */
	if (flags & FAULT_FLAG_ALLOW_RETRY) {
		/*
		 * CAUTION! In this case, mmap_sem is not released
		 * even though return 0.
		 *
		 * 小心! 在这种情况下,即使返回0,mmap_sem也不会被释放.
		 */
		if (flags & FAULT_FLAG_RETRY_NOWAIT)
			return 0;

		up_read(&mm->mmap_sem);
		/* #define FAULT_FLAG_KILLABLE	0x10	The fault task is in SIGKILL killable region
		 *
		 * 这下面就是一直阻塞直到PG_locked被清除
		 * 只是一个可被KILLABLE,另外一个不行
		 */
		if (flags & FAULT_FLAG_KILLABLE)
			wait_on_page_locked_killable(page);
		else
			wait_on_page_locked(page);
		return 0;
	} else {
		/* 这里就是要去阻塞直到拿到lock */
		if (flags & FAULT_FLAG_KILLABLE) {
			int ret;

			ret = __lock_page_killable(page);
			if (ret) {
				up_read(&mm->mmap_sem);
				return 0;
			}
		} else
			__lock_page(page);
		return 1;
	}
}

/**
 * page_cache_next_hole - find the next hole (not-present entry)
 * @mapping: mapping
 * @index: index
 * @max_scan: maximum range to search
 *
 * Search the set [index, min(index+max_scan-1, MAX_INDEX)] for the
 * lowest indexed hole.
 *
 * Returns: the index of the hole if found, otherwise returns an index
 * outside of the set specified (in which case 'return - index >=
 * max_scan' will be true). In rare cases of index wrap-around, 0 will
 * be returned.
 *
 * page_cache_next_hole may be called under rcu_read_lock. However,
 * like radix_tree_gang_lookup, this will not atomically search a
 * snapshot of the tree at a single point in time. For example, if a
 * hole is created at index 5, then subsequently a hole is created at
 * index 10, page_cache_next_hole covering both indexes may return 10
 * if called under rcu_read_lock.
 */
pgoff_t page_cache_next_hole(struct address_space *mapping,
			     pgoff_t index, unsigned long max_scan)
{
	unsigned long i;

	for (i = 0; i < max_scan; i++) {
		struct page *page;

		page = radix_tree_lookup(&mapping->page_tree, index);
		if (!page || radix_tree_exceptional_entry(page))
			break;
		index++;
		if (index == 0)
			break;
	}

	return index;
}
EXPORT_SYMBOL(page_cache_next_hole);

/**
 * page_cache_prev_hole - find the prev hole (not-present entry)
 * @mapping: mapping
 * @index: index
 * @max_scan: maximum range to search
 *
 * Search backwards in the range [max(index-max_scan+1, 0), index] for
 * the first hole.
 *
 * Returns: the index of the hole if found, otherwise returns an index
 * outside of the set specified (in which case 'index - return >=
 * max_scan' will be true). In rare cases of wrap-around, ULONG_MAX
 * will be returned.
 *
 * page_cache_prev_hole may be called under rcu_read_lock. However,
 * like radix_tree_gang_lookup, this will not atomically search a
 * snapshot of the tree at a single point in time. For example, if a
 * hole is created at index 10, then subsequently a hole is created at
 * index 5, page_cache_prev_hole covering both indexes may return 5 if
 * called under rcu_read_lock.
 */
pgoff_t page_cache_prev_hole(struct address_space *mapping,
			     pgoff_t index, unsigned long max_scan)
{
	unsigned long i;

	for (i = 0; i < max_scan; i++) {
		struct page *page;

		page = radix_tree_lookup(&mapping->page_tree, index);
		if (!page || radix_tree_exceptional_entry(page))
			break;
		index--;
		if (index == ULONG_MAX)
			break;
	}

	return index;
}
EXPORT_SYMBOL(page_cache_prev_hole);

/**
 * find_get_entry - find and get a page cache entry
 * @mapping: the address_space to search
 * @offset: the page cache index
 *
 * Looks up the page cache slot at @mapping & @offset.  If there is a
 * page cache page, it is returned with an increased refcount.
 *
 * If the slot holds a shadow entry of a previously evicted page, or a
 * swap entry from shmem/tmpfs, it is returned.
 *
 * Otherwise, %NULL is returned.
 */
struct page *find_get_entry(struct address_space *mapping, pgoff_t offset)
{
	void **pagep;
	struct page *head, *page;

	rcu_read_lock();
repeat:
	page = NULL;
	pagep = radix_tree_lookup_slot(&mapping->page_tree, offset);
	if (pagep) {
		page = radix_tree_deref_slot(pagep);
		if (unlikely(!page))
			goto out;
		if (radix_tree_exception(page)) {
			if (radix_tree_deref_retry(page))
				goto repeat;
			/*
			 * A shadow entry of a recently evicted page,
			 * or a swap entry from shmem/tmpfs.  Return
			 * it without attempting to raise page count.
			 */
			goto out;
		}

		head = compound_head(page);
		if (!page_cache_get_speculative(head))
			goto repeat;

		/* The page was split under us? */
		if (compound_head(page) != head) {
			put_page(head);
			goto repeat;
		}

		/*
		 * Has the page moved?
		 * This is part of the lockless pagecache protocol. See
		 * include/linux/pagemap.h for details.
		 */
		if (unlikely(page != *pagep)) {
			put_page(head);
			goto repeat;
		}
	}
out:
	rcu_read_unlock();

	return page;
}
EXPORT_SYMBOL(find_get_entry);

/**
 * find_lock_entry - locate, pin and lock a page cache entry
 * @mapping: the address_space to search
 * @offset: the page cache index
 *
 * Looks up the page cache slot at @mapping & @offset.  If there is a
 * page cache page, it is returned locked and with an increased
 * refcount.
 *
 * If the slot holds a shadow entry of a previously evicted page, or a
 * swap entry from shmem/tmpfs, it is returned.
 *
 * Otherwise, %NULL is returned.
 *
 * find_lock_entry() may sleep.
 */
struct page *find_lock_entry(struct address_space *mapping, pgoff_t offset)
{
	struct page *page;

repeat:
	page = find_get_entry(mapping, offset);
	if (page && !radix_tree_exception(page)) {
		lock_page(page);
		/* Has the page been truncated? */
		if (unlikely(page_mapping(page) != mapping)) {
			unlock_page(page);
			put_page(page);
			goto repeat;
		}
		VM_BUG_ON_PAGE(page_to_pgoff(page) != offset, page);
	}
	return page;
}
EXPORT_SYMBOL(find_lock_entry);

/**
 * pagecache_get_page - find and get a page reference
 * @mapping: the address_space to search
 * @offset: the page index
 * @fgp_flags: PCG flags
 * @gfp_mask: gfp mask to use for the page cache data page allocation
 *
 * Looks up the page cache slot at @mapping & @offset.
 *
 * PCG flags modify how the page is returned.
 *
 * FGP_ACCESSED: the page will be marked accessed
 * FGP_LOCK: Page is return locked
 * FGP_CREAT: If page is not present then a new page is allocated using
 *		@gfp_mask and added to the page cache and the VM's LRU
 *		list. The page is returned locked and with an increased
 *		refcount. Otherwise, %NULL is returned.
 *
 * If FGP_LOCK or FGP_CREAT are specified then the function may sleep even
 * if the GFP flags specified for FGP_CREAT are atomic.
 *
 * If there is a page cache page, it is returned with an increased refcount.
 *
 * pagecache_get_page-查找并获取页面引用
 * @映射：要搜索的地址空间
 * @偏移量：页面索引
 * @fgp_flags:PCG标志
 * @gfp_mask：用于页面缓存数据页面分配的gfp掩码
 *
 * 在@mapping和@offset 处查找页面缓存槽.
 *
 * PCG标志修改页面的返回方式.
 *
 * FGP_ACCESSED：页面将被标记为已访问
 * FGP_LOCK：页面返回locked
 * FGP_CREAT：如果页面不存在,则使用@gfp_mask分配一个新页面,并将其添加到页面缓存和VM的LRU列表中.
 * 页面返回时处于锁定状态，引用次数增加。否则，返回%NULL.
 *
 * 如果指定了FGP_LOCK或FGP_CREAT,则即使为FGP_CREAP指定的GFP标志是原子标志,该函数也可以休眠。
 * 如果存在页面缓存页面，则带着refcount增加而返回
 */
struct page *pagecache_get_page(struct address_space *mapping, pgoff_t offset,
	int fgp_flags, gfp_t gfp_mask)
{
	struct page *page;

repeat:
	/* 通过offset,找到page */
	page = find_get_entry(mapping, offset);
	/* 如果page为空或者异常,跳转到no_page去分配一个 */
	if (radix_tree_exceptional_entry(page))
		page = NULL;
	if (!page)
		goto no_page;
	/* 如果fgp_flags带有lock,那么就想获得锁
	 * 但是如果被锁了,你又是FGP_NOWAIT
	 * 也就是说又不想等待,那么就直接page的引用计数-1之后 返回NULL吧
	 * 因为find_get_entry -> page_cache_get_speculative -> page_ref_inc
	 * (get_page_unless_zero)也会去+1
	 * 所以这里要-1
	 */
	if (fgp_flags & FGP_LOCK) {
		if (fgp_flags & FGP_NOWAIT) {
			if (!trylock_page(page)) {
				put_page(page);
				return NULL;
			}
		} else {
			lock_page(page);
		}

		/* Has the page been truncated? */
		/* 这里可能发生的情况就是这个page被人解除了该文件的映射
		 * 然后unlock page, put_page之后重来一遍
		 */
		if (unlikely(page->mapping != mapping)) {
			unlock_page(page);
			put_page(page);
			goto repeat;
		}
		VM_BUG_ON_PAGE(page->index != offset, page);
	}
	/* 设置page的访问位 */
	if (page && (fgp_flags & FGP_ACCESSED))
		mark_page_accessed(page);

no_page:
	/* 如果没有page,且flag带了FGP_CREAT,那么就想去创建一个 */
	if (!page && (fgp_flags & FGP_CREAT)) {
		int err;
		/* 如果fgp_flags带了FGP_WRITE,并且!bdi->capabilities & BDI_CAP_NO_ACCT_DIRTY(Dirty pages shouldn't contribute to accounting) */
		if ((fgp_flags & FGP_WRITE) && mapping_cap_account_dirty(mapping))
			gfp_mask |= __GFP_WRITE;
		if (fgp_flags & FGP_NOFS)
			gfp_mask &= ~__GFP_FS;
		/* 分配一个page */
		page = __page_cache_alloc(gfp_mask);
		if (!page)
			return NULL;
		/* 如果fgp_flags没有带FGP_LOCK,我们给它带上 */
		if (WARN_ON_ONCE(!(fgp_flags & FGP_LOCK)))
			fgp_flags |= FGP_LOCK;

		/* Init accessed so avoid atomic mark_page_accessed later */
		if (fgp_flags & FGP_ACCESSED)
			__SetPageReferenced(page);

		err = add_to_page_cache_lru(page, mapping, offset,
				gfp_mask & GFP_RECLAIM_MASK);
		if (unlikely(err)) {
			put_page(page);
			page = NULL;
			if (err == -EEXIST)
				goto repeat;
		}
	}

	return page;
}
EXPORT_SYMBOL(pagecache_get_page);

/**
 * find_get_entries - gang pagecache lookup
 * @mapping:	The address_space to search
 * @start:	The starting page cache index
 * @nr_entries:	The maximum number of entries
 * @entries:	Where the resulting entries are placed
 * @indices:	The cache indices corresponding to the entries in @entries
 *
 * find_get_entries() will search for and return a group of up to
 * @nr_entries entries in the mapping.  The entries are placed at
 * @entries.  find_get_entries() takes a reference against any actual
 * pages it returns.
 *
 * The search returns a group of mapping-contiguous page cache entries
 * with ascending indexes.  There may be holes in the indices due to
 * not-present pages.
 *
 * Any shadow entries of evicted pages, or swap entries from
 * shmem/tmpfs, are included in the returned array.
 *
 * find_get_entries() returns the number of pages and shadow entries
 * which were found.
 */
unsigned find_get_entries(struct address_space *mapping,
			  pgoff_t start, unsigned int nr_entries,
			  struct page **entries, pgoff_t *indices)
{
	void **slot;
	unsigned int ret = 0;
	struct radix_tree_iter iter;

	if (!nr_entries)
		return 0;

	rcu_read_lock();
	radix_tree_for_each_slot(slot, &mapping->page_tree, &iter, start) {
		struct page *head, *page;
repeat:
		page = radix_tree_deref_slot(slot);
		if (unlikely(!page))
			continue;
		if (radix_tree_exception(page)) {
			if (radix_tree_deref_retry(page)) {
				slot = radix_tree_iter_retry(&iter);
				continue;
			}
			/*
			 * A shadow entry of a recently evicted page, a swap
			 * entry from shmem/tmpfs or a DAX entry.  Return it
			 * without attempting to raise page count.
			 */
			goto export;
		}

		head = compound_head(page);
		if (!page_cache_get_speculative(head))
			goto repeat;

		/* The page was split under us? */
		if (compound_head(page) != head) {
			put_page(head);
			goto repeat;
		}

		/* Has the page moved? */
		if (unlikely(page != *slot)) {
			put_page(head);
			goto repeat;
		}
export:
		indices[ret] = iter.index;
		entries[ret] = page;
		if (++ret == nr_entries)
			break;
	}
	rcu_read_unlock();
	return ret;
}

/**
 * find_get_pages - gang pagecache lookup
 * @mapping:	The address_space to search
 * @start:	The starting page index
 * @nr_pages:	The maximum number of pages
 * @pages:	Where the resulting pages are placed
 *
 * find_get_pages() will search for and return a group of up to
 * @nr_pages pages in the mapping.  The pages are placed at @pages.
 * find_get_pages() takes a reference against the returned pages.
 *
 * The search returns a group of mapping-contiguous pages with ascending
 * indexes.  There may be holes in the indices due to not-present pages.
 *
 * find_get_pages() returns the number of pages which were found.
 */
unsigned find_get_pages(struct address_space *mapping, pgoff_t start,
			    unsigned int nr_pages, struct page **pages)
{
	struct radix_tree_iter iter;
	void **slot;
	unsigned ret = 0;

	if (unlikely(!nr_pages))
		return 0;

	rcu_read_lock();
	radix_tree_for_each_slot(slot, &mapping->page_tree, &iter, start) {
		struct page *head, *page;
repeat:
		page = radix_tree_deref_slot(slot);
		if (unlikely(!page))
			continue;

		if (radix_tree_exception(page)) {
			if (radix_tree_deref_retry(page)) {
				slot = radix_tree_iter_retry(&iter);
				continue;
			}
			/*
			 * A shadow entry of a recently evicted page,
			 * or a swap entry from shmem/tmpfs.  Skip
			 * over it.
			 */
			continue;
		}

		head = compound_head(page);
		if (!page_cache_get_speculative(head))
			goto repeat;

		/* The page was split under us? */
		if (compound_head(page) != head) {
			put_page(head);
			goto repeat;
		}

		/* Has the page moved? */
		if (unlikely(page != *slot)) {
			put_page(head);
			goto repeat;
		}

		pages[ret] = page;
		if (++ret == nr_pages)
			break;
	}

	rcu_read_unlock();
	return ret;
}

/**
 * find_get_pages_contig - gang contiguous pagecache lookup
 * @mapping:	The address_space to search
 * @index:	The starting page index
 * @nr_pages:	The maximum number of pages
 * @pages:	Where the resulting pages are placed
 *
 * find_get_pages_contig() works exactly like find_get_pages(), except
 * that the returned number of pages are guaranteed to be contiguous.
 *
 * find_get_pages_contig() returns the number of pages which were found.
 */
unsigned find_get_pages_contig(struct address_space *mapping, pgoff_t index,
			       unsigned int nr_pages, struct page **pages)
{
	struct radix_tree_iter iter;
	void **slot;
	unsigned int ret = 0;

	if (unlikely(!nr_pages))
		return 0;

	rcu_read_lock();
	radix_tree_for_each_contig(slot, &mapping->page_tree, &iter, index) {
		struct page *head, *page;
repeat:
		page = radix_tree_deref_slot(slot);
		/* The hole, there no reason to continue */
		if (unlikely(!page))
			break;

		if (radix_tree_exception(page)) {
			if (radix_tree_deref_retry(page)) {
				slot = radix_tree_iter_retry(&iter);
				continue;
			}
			/*
			 * A shadow entry of a recently evicted page,
			 * or a swap entry from shmem/tmpfs.  Stop
			 * looking for contiguous pages.
			 */
			break;
		}

		head = compound_head(page);
		if (!page_cache_get_speculative(head))
			goto repeat;

		/* The page was split under us? */
		if (compound_head(page) != head) {
			put_page(head);
			goto repeat;
		}

		/* Has the page moved? */
		if (unlikely(page != *slot)) {
			put_page(head);
			goto repeat;
		}

		/*
		 * must check mapping and index after taking the ref.
		 * otherwise we can get both false positives and false
		 * negatives, which is just confusing to the caller.
		 */
		if (page->mapping == NULL || page_to_pgoff(page) != iter.index) {
			put_page(page);
			break;
		}

		pages[ret] = page;
		if (++ret == nr_pages)
			break;
	}
	rcu_read_unlock();
	return ret;
}
EXPORT_SYMBOL(find_get_pages_contig);

/**
 * find_get_pages_tag - find and return pages that match @tag
 * @mapping:	the address_space to search
 * @index:	the starting page index
 * @tag:	the tag index
 * @nr_pages:	the maximum number of pages
 * @pages:	where the resulting pages are placed
 *
 * Like find_get_pages, except we only return pages which are tagged with
 * @tag.   We update @index to index the next page for the traversal.
 */
unsigned find_get_pages_tag(struct address_space *mapping, pgoff_t *index,
			int tag, unsigned int nr_pages, struct page **pages)
{
	struct radix_tree_iter iter;
	void **slot;
	unsigned ret = 0;

	if (unlikely(!nr_pages))
		return 0;

	rcu_read_lock();
	radix_tree_for_each_tagged(slot, &mapping->page_tree,
				   &iter, *index, tag) {
		struct page *head, *page;
repeat:
		page = radix_tree_deref_slot(slot);
		if (unlikely(!page))
			continue;

		if (radix_tree_exception(page)) {
			if (radix_tree_deref_retry(page)) {
				slot = radix_tree_iter_retry(&iter);
				continue;
			}
			/*
			 * A shadow entry of a recently evicted page.
			 *
			 * Those entries should never be tagged, but
			 * this tree walk is lockless and the tags are
			 * looked up in bulk, one radix tree node at a
			 * time, so there is a sizable window for page
			 * reclaim to evict a page we saw tagged.
			 *
			 * Skip over it.
			 */
			continue;
		}

		head = compound_head(page);
		if (!page_cache_get_speculative(head))
			goto repeat;

		/* The page was split under us? */
		if (compound_head(page) != head) {
			put_page(head);
			goto repeat;
		}

		/* Has the page moved? */
		if (unlikely(page != *slot)) {
			put_page(head);
			goto repeat;
		}

		pages[ret] = page;
		if (++ret == nr_pages)
			break;
	}

	rcu_read_unlock();

	if (ret)
		*index = pages[ret - 1]->index + 1;

	return ret;
}
EXPORT_SYMBOL(find_get_pages_tag);

/**
 * find_get_entries_tag - find and return entries that match @tag
 * @mapping:	the address_space to search
 * @start:	the starting page cache index
 * @tag:	the tag index
 * @nr_entries:	the maximum number of entries
 * @entries:	where the resulting entries are placed
 * @indices:	the cache indices corresponding to the entries in @entries
 *
 * Like find_get_entries, except we only return entries which are tagged with
 * @tag.
 */
unsigned find_get_entries_tag(struct address_space *mapping, pgoff_t start,
			int tag, unsigned int nr_entries,
			struct page **entries, pgoff_t *indices)
{
	void **slot;
	unsigned int ret = 0;
	struct radix_tree_iter iter;

	if (!nr_entries)
		return 0;

	rcu_read_lock();
	radix_tree_for_each_tagged(slot, &mapping->page_tree,
				   &iter, start, tag) {
		struct page *head, *page;
repeat:
		page = radix_tree_deref_slot(slot);
		if (unlikely(!page))
			continue;
		if (radix_tree_exception(page)) {
			if (radix_tree_deref_retry(page)) {
				slot = radix_tree_iter_retry(&iter);
				continue;
			}

			/*
			 * A shadow entry of a recently evicted page, a swap
			 * entry from shmem/tmpfs or a DAX entry.  Return it
			 * without attempting to raise page count.
			 */
			goto export;
		}

		head = compound_head(page);
		if (!page_cache_get_speculative(head))
			goto repeat;

		/* The page was split under us? */
		if (compound_head(page) != head) {
			put_page(head);
			goto repeat;
		}

		/* Has the page moved? */
		if (unlikely(page != *slot)) {
			put_page(head);
			goto repeat;
		}
export:
		indices[ret] = iter.index;
		entries[ret] = page;
		if (++ret == nr_entries)
			break;
	}
	rcu_read_unlock();
	return ret;
}
EXPORT_SYMBOL(find_get_entries_tag);

/*
 * CD/DVDs are error prone. When a medium error occurs, the driver may fail
 * a _large_ part of the i/o request. Imagine the worst scenario:
 *
 *      ---R__________________________________________B__________
 *         ^ reading here                             ^ bad block(assume 4k)
 *
 * read(R) => miss => readahead(R...B) => media error => frustrating retries
 * => failing the whole request => read(R) => read(R+1) =>
 * readahead(R+1...B+1) => bang => read(R+2) => read(R+3) =>
 * readahead(R+3...B+2) => bang => read(R+3) => read(R+4) =>
 * readahead(R+4...B+3) => bang => read(R+4) => read(R+5) => ......
 *
 * It is going insane. Fix it by quickly scaling down the readahead size.
 *
 * CD/DVD很容易出错. 当发生介质错误时,驱动程序可能会使I/O请求的_large_部分失败.想象一下最糟糕的情况：
 *
 *	---R __________________________________________ B__________
 *	   ^ reading here				^ 坏块(假设4k)
 *
 * 读取(R)= > miss => readahead(R ... B) => 介质错误 =>令人沮丧的重试次数 => 整个请求失败 => 读取(R) => 读取(R+1) =>
 * 预读(R+1 ... B+1) => bang => 读取(R+2) => 读取(R+3) => 预读 (R+3 … B+2 ) => bang =>读取(R+3) => 读取(R+4) =>
 * 预读(R+4…B+3) => bang => 读(R+4) => 读(R+5) => .....
 * 这简直是疯了.通过快速缩小预读大小来解决此问题.
 */
static void shrink_readahead_size_eio(struct file *filp,
					struct file_ra_state *ra)
{
	ra->ra_pages /= 4;
}

/**
 * do_generic_file_read - generic file read routine
 * @filp:	the file to read
 * @ppos:	current file position
 * @iter:	data destination
 * @written:	already copied
 *
 * This is a generic file read routine, and uses the
 * mapping->a_ops->readpage() function for the actual low-level stuff.
 *
 * This is really ugly. But the goto's actually try to clarify some
 * of the logic when it comes to error handling etc.
 */
static ssize_t do_generic_file_read(struct file *filp, loff_t *ppos,
		struct iov_iter *iter, ssize_t written)
{
	struct address_space *mapping = filp->f_mapping;
	struct inode *inode = mapping->host;
	struct file_ra_state *ra = &filp->f_ra;
	pgoff_t index;
	pgoff_t last_index;
	pgoff_t prev_index;
	unsigned long offset;      /* offset into pagecache page */
	unsigned int prev_offset;
	int error = 0;
	/* s_maxbytes表示文件的最大长度
	 * 如果当前文件的偏移量大于等于了文件的最大长度，那么说明读完了，直接返回吧
	 */
	if (unlikely(*ppos >= inode->i_sb->s_maxbytes))
		return 0;
	/* 这里就是如果你的iov_iter->count也就是数据大小大于inode->i_sb->s_maxbytes
	 * 那么直接赋值给它
	 */
	iov_iter_truncate(iter, inode->i_sb->s_maxbytes);
	/* index表示当前正处理页面在页面缓存中的索引编号 */
	index = *ppos >> PAGE_SHIFT;
	/* prev_pos 字段存放着进程在上一次读操作中的偏移量 */
	prev_index = ra->prev_pos >> PAGE_SHIFT;
	prev_offset = ra->prev_pos & (PAGE_SIZE-1);
	/* last_index为要读取的最后一个页面在页面缓存中的索引编号 */
	last_index = (*ppos + iter->count + PAGE_SIZE-1) >> PAGE_SHIFT;
	/* offset为要读取的第一个字节在所属页面中的偏移 */
	offset = *ppos & ~PAGE_MASK;

	for (;;) {
		struct page *page;
		pgoff_t end_index;
		loff_t isize;
		unsigned long nr, ret;

		cond_resched();
find_page:
		if (fatal_signal_pending(current)) {
			error = -EINTR;
			goto out;
		}
		/* 在页面缓存中查到指定索引值的页面 */
		page = find_get_page(mapping, index);
		/* 如果没有，表示请求的页面不在页面缓存，尝试执行预读逻辑代码 */
		if (!page) {
			page_cache_sync_readahead(mapping,
					ra, filp,
					index, last_index - index);
			/* 预读后再次调用find_get_page函数查找页面，
			 * 如果依然没有找到，那么就跳转到no_cached_page处 */
			page = find_get_page(mapping, index);
			if (unlikely(page == NULL))
				goto no_cached_page;
		}
		/* 如果当前page设置了"PG_Readahead"预读标记位,说明本次读取的文件页数据正好命中上一次的预读窗口的文件页 */
		if (PageReadahead(page)) {
			/* 这里发起异步文件预读 */
			page_cache_async_readahead(mapping,
					ra, filp, page,
					index, last_index - index);
		}
		/* 如果Page不是最新的 */
		if (!PageUptodate(page)) {
			/*
			 * See comment in do_read_cache_page on why
			 * wait_on_page_locked is used to avoid unnecessarily
			 * serialisations and why it's safe.
			 */
			error = wait_on_page_locked_killable(page);
			if (unlikely(error))
				goto readpage_error;
			/* 如果页面是最新的 */
			if (PageUptodate(page))
				goto page_ok;
			/* 如果文件逻辑块长度和页面长度相同，
			 * 或者说地址空间操作表未定义is_partially_uptodate 回调函数
			 * mapping->a_ops->is_partially_uptodate检查页面中的buffer是否都处于
			 * update状态,因为块大小不等于页大小，一页可能包含多个块.
			 * 若是VM读取到所需的块数据，那么就无需等待整个页读取完毕
			 */
			if (inode->i_blkbits == PAGE_SHIFT ||
					!mapping->a_ops->is_partially_uptodate)
				goto page_not_up_to_date;
			/* pipes can't handle partially uptodate pages
			 * 管道无法处理部分最新的页面
			 */
			if (unlikely(iter->type & ITER_PIPE))
				goto page_not_up_to_date;
			/* is_partially_uptodate 函数调用需要外部对页面加锁,
			 * 如果尝试加锁失败，跳转到page_not_up_to_date
			 */
			if (!trylock_page(page))
				goto page_not_up_to_date;
			/* Did it get truncated before we got the lock? */
			if (!page->mapping)
				goto page_not_up_to_date_locked;
			/* mapping->a_ops->is_partially_uptodate检查页面中的buffer是否都处于
			 * update状态,因为块大小不等于页大小，一页可能包含多个块.
			 * 若是VM读取到所需的块数据，那么就无需等待整个页读取完毕
			 * 如果is_partially_uptodate回调函数返回0，说明页面不是最新的
			 * 那么就调转到page_not_up_to_date_locked
			 */
			if (!mapping->a_ops->is_partially_uptodate(page,
							offset, iter->count))
				goto page_not_up_to_date_locked;
			unlock_page(page);
		}
page_ok:
		/*
		 * i_size must be checked after we know the page is Uptodate.
		 *
		 * Checking i_size after the check allows us to calculate
		 * the correct value for "nr", which means the zero-filled
		 * part of the page is not copied back to userspace (unless
		 * another truncate extends the file - this is desired though).
		 */
		/*
		 * 在我们知道页面是最新的之后，必须检查i_size.
		 *
		 * 在检查允许我们去计算“nr”的正确值,这意味着页面的零填充部分不会复制回用户空间
		 * (除非另一个截断扩展了文件-这是需要的).
		 */
		/* 获取文件的大小 */
		isize = i_size_read(inode);
		/* 获取文件的end_index */
		end_index = (isize - 1) >> PAGE_SHIFT;
		/* 如果isize为0,请求的index大于end_index，那么就直接退出了 */
		if (unlikely(!isize || index > end_index)) {
			/* page引用计数 -1 */
			put_page(page);
			goto out;
		}

		/* nr is the maximum number of bytes to copy from this page
		 * nr是要从此页面复制的最大字节数
		 */
		nr = PAGE_SIZE;
		/* 需要考虑最后一个页面，如果文件长度不是页面对齐 */
		if (index == end_index) {
			nr = ((isize - 1) & ~PAGE_MASK) + 1;
			if (nr <= offset) {
				put_page(page);
				goto out;
			}
		}
		/* offset为要读取的第一个字节在所属页面中的偏移
		 * 那nr - offser 得到我们最终要拷贝到用户空间的字节数
		 */
		nr = nr - offset;

		/* If users can be writing to this page using arbitrary
		 * virtual addresses, take care about potential aliasing
		 * before reading the page on the kernel side.
		 *
		 * 如果用户可以使用任意虚拟地址对此页面进行写入，
		 * 那么在读取内核端的页面之前，请注意潜在的混叠。
		 *
		 */

		/* 也就是说如果用户使用不正常的虚拟地址写这个页，
		 * 要flush_dcache_page,将dcache相应的page里的数据
		 * 写到memory里面去，以保证dcache内的数据与memory内的数据的一致性
		 */
		if (mapping_writably_mapped(mapping))
			flush_dcache_page(page);

		/*
		 * When a sequential read accesses a page several times,
		 * only mark it as accessed the first time.
		 */
		/*
		 *
		 * mark_page_accessed函数设置PG_reference或PG_active标志
		 * 它表明页面当前正在被使用，不应该被缓存.
		 * 如果同一个页面(或者页面的一部分)在连续执行do_generic_file_read时
		 * 被多次读取，这一步只在第一次读取时做
		 */
		if (prev_index != index || offset != prev_offset)
			mark_page_accessed(page);
		/* 将prev_index赋值为我们现在访问的index */
		prev_index = index;

		/*
		 * Ok, we have the page, and it's up-to-date, so
		 * now we can copy it to user space...
		 */
		/* OK，我们有这个页面，它是最新的，
		 * 所以现在我们可以将它复制到用户空间...
		 */
		ret = copy_page_to_iter(page, offset, nr, iter);

		/* 根据有效传输到用户空间缓冲区的字节数修改局部变量index和offset.
		 * 通常情况下，如果页面的最有一个字节被复制到用户空间缓冲区,index
		 * 递增1，offset被设置为0;
		 * 否则index不变，而offset增加页面中已经复制到用户空间缓冲区的字节数
		 */

		/* 把offet加上ret,也就是我们复制给用户空间的字节数 */
		offset += ret;
		/* 更新我们的index */
		index += offset >> PAGE_SHIFT;
		/* 更新我们的prev_offset */
		offset &= ~PAGE_MASK;
		prev_offset = offset;
		/* 引用技术-1，如果为0的话就释放这个页面 */
		put_page(page);
		/* 更新已写会给用户空间的数据 */
		written += ret;
		/*
		 * 如果本次内容全部复制到用户空间，并且还有更多的数据需要复制,
		 * 则继续循环; 否则退出.
		 *
		 */

		/* i->count == 0，out */
		if (!iov_iter_count(iter))
			goto out;
		if (ret < nr) {
			error = -EFAULT;
			goto out;
		}
		continue;
		/* 标号为page_not_up_to_data的代码段获取对页面的互斥访问
		 * 具体是，在第1083行调用lock_page_killable函数获取对页面的互斥锁.
		 * 如果PG_locked标志已经设置，lock_page挂起当前进程，知道在这个位被清除
		 */
page_not_up_to_date:
		/* Get exclusive access to the page ... */
		error = lock_page_killable(page);
		if (unlikely(error))
			goto readpage_error;

page_not_up_to_date_locked:
		/* Did it get truncated before we got the lock? */
		/* 另一个进程可能就在前一步之前已经从页面缓存中删除了
		 * 这个页面;因此，它检查是否页面描述符的mapping域已经为NULL;
		 * 如果是，调用unlock_page解锁页面，递减其使用计数，继续循环，
		 * 在同一个页面上处理.
		 */
		if (!page->mapping) {
			unlock_page(page);
			put_page(page);
			continue;
		}

		/* Did somebody else fill it already? */
		/* 在获取锁的过程中，其他进程已经填充了这个页面.
		 * 在此检查PG_uptodate标志，因为另一个内核控制路径可能已经
		 * 成功读入数据，设置页面为已更新
		 * 如果标志被设置，它调用unlock_page，跳转到page_ok处，
		 * 跳过读操作，直接进行复制到用户空间的处理
		 */
		if (PageUptodate(page)) {
			unlock_page(page);
			goto page_ok;
		}

readpage:
		/*
		 * A previous I/O error may have been due to temporary
		 * failures, eg. multipath errors.
		 * PG_error will be set again if readpage fails.
		 */
		ClearPageError(page);
		/* Start the actual read. The read will unlock the page. */
		/* 调用文件的地址空间操作表上的readpage函数.
		 * 对应的函数负责激活从磁盘到页面的I/O数据传输
		 */
		error = mapping->a_ops->readpage(filp, page);

		if (unlikely(error)) {
			if (error == AOP_TRUNCATED_PAGE) {
				put_page(page);
				error = 0;
				goto find_page;
			}
			goto readpage_error;
		}
		/* 如果判断页面未更新，则调用lock_page_killable再次试图获得对页面的互斥锁,
		 * 但因为页面已经被前一次的lock_page_killable已经被锁住，这时该进程进入等待，
		 * 直到数据被读入后，页面设置为已更新，并被解锁(参见end_buffer_asyne_read和do_mpage_readpage函数).
		 * 解锁页面调用unlock_page函数，它将从等待该页面解锁的队列上唤醒一个线程.
		 * 我们没办法确保本次唤醒的是这个线程，因为有可能有别的线程因为读取该页面也由于
		 * 试图要锁住页面而在第1083行等待，但是即使唤醒的是那个线程，它会发现页面已更新，很快也会调用unlock_page解锁页面，
		 * 因而在此唤醒队列上的一个等待线程
		 */
		if (!PageUptodate(page)) {
			error = lock_page_killable(page);
			if (unlikely(error))
				goto readpage_error;
			/* 如果不幸，在再次获得页面的锁之后，发现页面依然不是最新状态.
			 * 有两种可能，一种是在等待锁的过程中另一个进程已经从页面缓存中
			 * 删除这个页面，这时页面描述符的mapping域应该为NULL.
			 * 这时调用unlock_page解锁页面，递减其使用计数，继续循环，在同一个页面上处理
			 * 另外一种可能就是从磁盘上读取数据失败，然后只能解锁该页面，然后缩减预读大小，设置错误码,
			 * 跳转到标号readpage_error进行处理.
			 */
			if (!PageUptodate(page)) {
				if (page->mapping == NULL) {
					/*
					 * invalidate_mapping_pages got it
					 */
					unlock_page(page);
					put_page(page);
					goto find_page;
				}
				unlock_page(page);
				shrink_readahead_size_eio(filp, ra);
				error = -EIO;
				goto readpage_error;
			}
			unlock_page(page);
		}

		goto page_ok;

readpage_error:
		/* UHHUH! A synchronous read error occurred. Report it */
		put_page(page);
		goto out;

no_cached_page:
		/*
		 * Ok, it wasn't cached, so we need to create a new
		 * page..
		 */
		/* 这个页面还没有被缓存，需要我们创建一个新的页面 */
		page = page_cache_alloc_cold(mapping);
		if (!page) {
			error = -ENOMEM;
			goto out;
		}
		/* 调用add_to_page_cache_lru将页面添加到地址空间
		 * 如果这个过程中出现错误，记录错误码，退出循环.
		 * 如果成功，则跳转到readpage标号处，这会从磁盘上读取数据到这个页面
		 */
		error = add_to_page_cache_lru(page, mapping, index,
				mapping_gfp_constraint(mapping, GFP_KERNEL));
		if (error) {
			put_page(page);
			if (error == -EEXIST) {
				error = 0;
				goto find_page;
			}
			goto out;
		}
		goto readpage;
	}

out:
	/* 退出循环后，除了设置一些预读状态的更新，最主要的是修改文件偏移量,
	 * 作为参数传递回调用者以及调用更新文件的访问时间
	 */
	ra->prev_pos = prev_index;
	ra->prev_pos <<= PAGE_SHIFT;
	ra->prev_pos |= prev_offset;

	*ppos = ((loff_t)index << PAGE_SHIFT) + offset;
	file_accessed(filp);
	return written ? written : error;
}

/**
 * generic_file_read_iter - generic filesystem read routine
 * @iocb:	kernel I/O control block
 * @iter:	destination for the data read
 *
 * This is the "read_iter()" routine for all filesystems
 * that can use the page cache directly.
 */
ssize_t
generic_file_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *file = iocb->ki_filp;
	ssize_t retval = 0;
	size_t count = iov_iter_count(iter);

	if (!count)
		goto out; /* skip atime */
	/* 处理direct io的情况 */
	/* 在大多数情况下，页面缓存有助于提高系统性能，但是不是所有情况都如此.
	 * 有时我们需要绕开页面缓存，在用户缓冲区和磁盘之间直接传输数据.
	 * 如果数据不会在短期内被再次使用(例如，在进行磁盘备份时)，或者应用程序有的缓存机制，
	 * 采用直接IO反而能够提升性能.
	 */
	if (iocb->ki_flags & IOCB_DIRECT) {
		struct address_space *mapping = file->f_mapping;
		struct inode *inode = mapping->host;
		struct iov_iter data = *iter;
		loff_t size;

		size = i_size_read(inode);
		/* 因为数据有可能保存在页面缓存，还没来得及写入磁盘，
		 * 因此，在进行I/O之前需要调用filemap_write_and_wait_range将相关数据冲刷到磁盘，并等待结束 */
		retval = filemap_write_and_wait_range(mapping, iocb->ki_pos,
					iocb->ki_pos + count - 1);
		if (retval < 0)
			goto out;

		file_accessed(file);
		/* 尽管需要绕开页面缓存(Page Cahe),直接IO操作还是定义在address_space_operations结构中 */
		retval = mapping->a_ops->direct_IO(iocb, &data);
		if (retval >= 0) {
			iocb->ki_pos += retval;
			iov_iter_advance(iter, retval);
		}

		/*
		 * Btrfs can have a short DIO read if we encounter
		 * compressed extents, so if there was an error, or if
		 * we've already read everything we wanted to, or if
		 * there was a short read because we hit EOF, go ahead
		 * and return.  Otherwise fallthrough to buffered io for
		 * the rest of the read.  Buffered reads will not work for
		 * DAX files, so don't bother trying.
		 */
		/* 如果是直接I/O读出的字节数，则返回给调用者.
		 * 如果返回为0,则切换到缓存I/O(Buffered I/O)的方式读取
		 */
		if (retval < 0 || !iov_iter_count(iter) || iocb->ki_pos >= size ||
		    IS_DAX(inode))
			goto out;
	}

	retval = do_generic_file_read(file, &iocb->ki_pos, iter, retval);
out:
	return retval;
}
EXPORT_SYMBOL(generic_file_read_iter);

#ifdef CONFIG_MMU
/**
 * page_cache_read - adds requested page to the page cache if not already there
 * @file:	file to read
 * @offset:	page index
 * @gfp_mask:	memory allocation flags
 *
 * This adds the requested page to the page cache if it isn't already there,
 * and schedules an I/O to read in its contents from disk.
 *
 * page_cache_read - 将请求的页面添加到页面缓存中如果还没有的话
 * @file:	要读取的文件
 * @offset:	页面索引
 * @gfp_mask:	内存分配标志
 *
 * 这会将请求的页面添加到页面缓存中(如果该页面还没有),并调度一个I/O从磁盘读取其内容.
 */
static int page_cache_read(struct file *file, pgoff_t offset, gfp_t gfp_mask)
{
	struct address_space *mapping = file->f_mapping;
	struct page *page;
	int ret;

	do {
		/* 分配一个页面 */
		page = __page_cache_alloc(gfp_mask|__GFP_COLD);
		/* 如果分配不出来,那么返回-ENOMEM */
		if (!page)
			return -ENOMEM;

		/* 把它添加到相关位置,已经lru链表里面去 */
		ret = add_to_page_cache_lru(page, mapping, offset, gfp_mask & GFP_KERNEL);
		/* 如果分配好了的话,那么就去读这一页 */
		if (ret == 0)
			ret = mapping->a_ops->readpage(file, page);
		else if (ret == -EEXIST)
			ret = 0; /* losing race to add is OK */

		put_page(page);

	} while (ret == AOP_TRUNCATED_PAGE);

	return ret;
}

#define MMAP_LOTSAMISS  (100)

/*
 * Synchronous readahead happens when we don't even find
 * a page in the page cache at all.
 *
 * 当我们在页面缓存中根本找不到页面时,就会发生同步预读.
 */
static void do_sync_mmap_readahead(struct vm_area_struct *vma,
				   struct file_ra_state *ra,
				   struct file *file,
				   pgoff_t offset)
{
	struct address_space *mapping = file->f_mapping;

	/* If we don't want any read-ahead, don't bother */
	if (vma->vm_flags & VM_RAND_READ)
		return;
	if (!ra->ra_pages)
		return;

	/* 如果是顺序读,那么就进行同步预读 */
	if (vma->vm_flags & VM_SEQ_READ) {
		page_cache_sync_readahead(mapping, ra, file, offset,
					  ra->ra_pages);
		return;
	}

	/* Avoid banging the cache line if not needed
	 * 如果不需要,避免撞击cache line
	 */

	/* #define MMAP_LOTSAMISS  (100),如果ra->mmap_miss < 1000,那么++ */
	if (ra->mmap_miss < MMAP_LOTSAMISS * 10)
		ra->mmap_miss++;

	/*
	 * Do we miss much more than hit in this file? If so,
	 * stop bothering with read-ahead. It will only hurt.
	 *
	 * 在这个文件中,我们miss的比命中的多得多吗?
	 * 如果是这样的话,就别再为预读而烦恼了.这只会很疼.
	 */
	if (ra->mmap_miss > MMAP_LOTSAMISS)
		return;

	/*
	 * mmap read-around
	 */
	/* 设置好预读参数之后开始提交预读 */
	/* 将预读的起始页索引设置为0和offset - ra->ra_pages/2的最大值
	 * 这个预读是想左右都预读ra_pages的50%? */
	ra->start = max_t(long, 0, offset - ra->ra_pages / 2);
	/* 设置预读的大小为最大预读页数 */
	ra->size = ra->ra_pages;
	/* 设置async_size为ra->ra_pages / 4
	 * async_size指定一个阈值，预读窗口剩余这么多页时，就开始异步预读
	 */
	ra->async_size = ra->ra_pages / 4;
	/* 提交预读的请求 */
	ra_submit(ra, mapping, file);
}

/*
 * Asynchronous readahead happens when we find the page and PG_readahead,
 * so we want to possibly extend the readahead further..
 *
 * 异步预读发生在我们找到页面和PG_readahead时,因此我们希望可能进一步扩展预读.
 */
static void do_async_mmap_readahead(struct vm_area_struct *vma,
				    struct file_ra_state *ra,
				    struct file *file,
				    struct page *page,
				    pgoff_t offset)
{
	struct address_space *mapping = file->f_mapping;

	/* If we don't want any read-ahead, don't bother
	 * 如果我们不想提前阅读，不要麻烦
	 */

	/* 这里表示如果是随机读,那么直接返回 */
	if (vma->vm_flags & VM_RAND_READ)
		return;
	/* 知道我们为什么到这个函数里面来吗,因为我们找到了这块地址所对应的page,
	 * 那你这个mmap_miss肯定要-1啦 */
	if (ra->mmap_miss > 0)
		ra->mmap_miss--;
	/* 如果page的内容不是有效的,或者如果当前page设置了"PG_Readahead"预读标记位,说明本次读取的文件页数据正好命中上一次的预读窗口的文件页
	 * 那么我们这里开始异步预读
	 */
	if (PageReadahead(page))
		page_cache_async_readahead(mapping, ra, file,
					   page, offset, ra->ra_pages);
}

/**
 * filemap_fault - read in file data for page fault handling
 * @vma:	vma in which the fault was taken
 * @vmf:	struct vm_fault containing details of the fault
 *
 * filemap_fault() is invoked via the vma operations vector for a
 * mapped memory region to read in file data during a page fault.
 *
 * The goto's are kind of ugly, but this streamlines the normal case of having
 * it in the page cache, and handles the special cases reasonably without
 * having a lot of duplicated code.
 *
 * vma->vm_mm->mmap_sem must be held on entry.
 *
 * If our return value has VM_FAULT_RETRY set, it's because
 * lock_page_or_retry() returned 0.
 * The mmap_sem has usually been released in this case.
 * See __lock_page_or_retry() for the exception.
 *
 * If our return value does not have VM_FAULT_RETRY set, the mmap_sem
 * has not been released.
 *
 * We never return with VM_FAULT_RETRY and a bit from VM_FAULT_ERROR set.
 *
 * filemap_fault - 为page fault handling读取文件数据
 * @vma: 发生falut的vma
 * @vmf: 包含fault详细信息的struct vm_fault
 *
 * filemap_fault()是通过映射内存区域的vma操作向量调用的,用于在页面故障期间读取文件数据.
 *
 * goto有点难看,但这简化了将其保存在页面缓存中的正常情况,并合理地处理了特殊情况,而没有大量重复的代码.
 *
 * vma->vm_mm->mmap_sem必须在entry中保留
 *
 * 如果我们的返回值设置了VM_FAULT_RETRY,那是因为lock_page_or_retry返回了0.
 * 在这种情况下,通常会释放mmap_sem.有关异常,请参见__lock_page_or_retry().
 *
 * 如果我们的返回值没有设置VM_FAULT_RETRY,则mmap_sem还没有被释放
 *
 * 我们从不返回VM_FAULT_RETRY和VM_FAULTE_ERROR集合中的一位。
 */
int filemap_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	int error;
	/* 拿到vma指向的文件 */
	struct file *file = vma->vm_file;
	/* 拿到文件的地址空间 */
	struct address_space *mapping = file->f_mapping;
	/* 拿到文件的预读状态 */
	struct file_ra_state *ra = &file->f_ra;
	/* 拿到文件对应的inode */
	struct inode *inode = mapping->host;
	/* 拿到pgoff */
	pgoff_t offset = vmf->pgoff;
	struct page *page;
	loff_t size;
	int ret = 0;

	/* 拿到文件的大小,然后要和PAGE_SIZE向上对齐 */
	size = round_up(i_size_read(inode), PAGE_SIZE);
	/* 如果offser比size >> PAGE_SHIFT还要大,那么可以返回VM_FAULT_SIGBUS了 */
	if (offset >= size >> PAGE_SHIFT)
		return VM_FAULT_SIGBUS;

	/*
	 * Do we have something in the page cache already?
	 *
	 * 页面缓存中已经有内容了吗?
	 */
	page = find_get_page(mapping, offset);
	/* 如果对应这块已经有page cache了
	 * 并且#define FAULT_FLAG_TRIED	0x20	Second try
	 * 不是第二次尝试
	 */
	if (likely(page) && !(vmf->flags & FAULT_FLAG_TRIED)) {
		/*
		 * We found the page, so try async readahead before
		 * waiting for the lock.
		 *
		 * 我们找到了页面,所以在等待锁定之前请尝试异步预读.
		 */
		do_async_mmap_readahead(vma, ra, file, page, offset);
		/* 如果没有在该文件中发现page */
	} else if (!page) {
		/* No page in the page cache at all */
		/* 同步预读 */
		do_sync_mmap_readahead(vma, ra, file, offset);
		/* vm_event_states的PGMAJFAULT event +1 */
		count_vm_event(PGMAJFAULT);
		mem_cgroup_count_vm_event(vma->vm_mm, PGMAJFAULT);
		/* 将VM_FAULT_MAJOR 赋值给ret */
		ret = VM_FAULT_MAJOR;
retry_find:
		/* 再去尝试找这一页 */
		page = find_get_page(mapping, offset);
		/* 如果还是没找到,那么就去no_cached_page */
		if (!page)
			goto no_cached_page;
	}

	/* lock page or retry,如果返回0表示page没有被lock,那么put_page
	 * 返回ret | VM_FAULT_RETRY
	 */
	if (!lock_page_or_retry(page, vma->vm_mm, vmf->flags)) {
		put_page(page);
		return ret | VM_FAULT_RETRY;
	}

	/* Did it get truncated?
	 * 如果说被截断了,看起来就是它已经不属于这个文件了
	 * 那么unlock_page、put_page之后
	 * goto retry_find
	 */
	if (unlikely(page->mapping != mapping)) {
		unlock_page(page);
		put_page(page);
		goto retry_find;
	}
	VM_BUG_ON_PAGE(page->index != offset, page);

	/*
	 * We have a locked page in the page cache, now we need to check
	 * that it's up-to-date. If not, it is going to be due to an error.
	 *
	 * 我们在页面缓存中有一个locked page,
	 * 现在我们需要检查它是否是最新的.
	 * 如果没有,那将是由于一个错误.
	 */
	if (unlikely(!PageUptodate(page)))
		goto page_not_uptodate;

	/*
	 * Found the page and have a reference on it.
	 * We must recheck i_size under page lock.
	 *
	 * 找到该页,并在上面有引用.
	 * 必须在page lock下重新检查i_size
	 */

	/* 拿到文件的大小,然后要和PAGE_SIZE向上对齐 */
	size = round_up(i_size_read(inode), PAGE_SIZE);
	/* 如果offser比size >> PAGE_SHIFT还要大,那么
	 * 在unlock page和put page之后可以返回VM_FAULT_SIGBUS了
	 */
	if (unlikely(offset >= size >> PAGE_SHIFT)) {
		unlock_page(page);
		put_page(page);
		return VM_FAULT_SIGBUS;
	}

	/* 然后把page设置到vmf的page */
	vmf->page = page;
	return ret | VM_FAULT_LOCKED;

no_cached_page:
	/*
	 * We're only likely to ever get here if MADV_RANDOM is in
	 * effect.
	 *
	 * 只有在MADV_RANDOM生效的情况下,我们才有可能到达这里.
	 *
	 * 如果大于等于0,说明分配了page cache并且读取了数据
	 */
	error = page_cache_read(file, offset, vmf->gfp_mask);

	/*
	 * The page we want has now been added to the page cache.
	 * In the unlikely event that someone removed it in the
	 * meantime, we'll just come back here and read it again.
	 *
	 * 我们想要的页面现在已经添加到页面缓存中.
	 * 在不太可能的情况下,有人在此期间删除了它,我们将回到这里重新阅读.
	 */
	if (error >= 0)
		goto retry_find;

	/*
	 * An error return from page_cache_read can result if the
	 * system is low on memory, or a problem occurs while trying
	 * to schedule I/O.
	 *
	 * 如果系统内存不足,page_cache_read将返回一个错误,
	 * 或者当试图调度I/O的时候发生了一个错误
	 */
	if (error == -ENOMEM)
		return VM_FAULT_OOM;
	return VM_FAULT_SIGBUS;

page_not_uptodate:
	/*
	 * Umm, take care of errors if the page isn't up-to-date.
	 * Try to re-read it _once_. We do this synchronously,
	 * because there really aren't any performance issues here
	 * and we need to check for errors.
	 *
	 * Umm,如果页面不是最新的,请注意错误.
	 * 试着重读一遍.我们是同步进行的,因为这里确实没有任何性能问题,我们需要检查错误.
	 */

	/* 走到这里是因为!PageUptodate(page),
	 * PG_uptodate tells whether the page's contents is valid.When a read completes,
	 * the page becomes uptodate, unless a disk I/O error happened.
	 */

	/* 清除PG_error
	 * PG_error is set to indicate that an I/O error occurred on this page.
	 */
	ClearPageError(page);
	/* 这里重新去读 */
	error = mapping->a_ops->readpage(file, page);
	/* 如果没有error,那么就等pageunlocked */
	if (!error) {
		wait_on_page_locked(page);
		/* 如果PG_uptodate还在置位,那么返回-EIO吧 */
		if (!PageUptodate(page))
			error = -EIO;
	}
	/* put_page */
	put_page(page);

	if (!error || error == AOP_TRUNCATED_PAGE)
		goto retry_find;
	/* Things didn't work out. Return zero to tell the mm layer so.
	 * 事情没有成功.返回零来告诉mm层是这样的.
	 */

	/* 否则这里缩小预读的大小
	 * ra->ra_pages /= 4;
	 */
	shrink_readahead_size_eio(file, ra);
	return VM_FAULT_SIGBUS;
}
EXPORT_SYMBOL(filemap_fault);

void filemap_map_pages(struct fault_env *fe,
		pgoff_t start_pgoff, pgoff_t end_pgoff)
{
	struct radix_tree_iter iter;
	void **slot;
	/* 拿到vma所对应的文件 */
	struct file *file = fe->vma->vm_file;
	/* 拿到该文件的地址空间 */
	struct address_space *mapping = file->f_mapping;
	pgoff_t last_pgoff = start_pgoff;
	loff_t size;
	struct page *head, *page;

	rcu_read_lock();
	/*
	 * #define radix_tree_for_each_slot(slot, root, iter, start)		\
	 *	for (slot = radix_tree_iter_init(iter, start) ;			\
	 *		slot || (slot = radix_tree_next_chunk(root, iter, 0)) ;	\
	 *		slot = radix_tree_next_slot(slot, iter, 0))
	 */

	/* 这里就是通过start来循环到end */
	radix_tree_for_each_slot(slot, &mapping->page_tree, &iter,
			start_pgoff) {
		/* 如果iter.index大于end_pgoff,那么直接退出循环,你已经超过end_pgoff了
		 * 不在我们的范围内
		 */
		if (iter.index > end_pgoff)
			break;
repeat:
		/* 找到这个slot的page */
		page = radix_tree_deref_slot(slot);
		/* 如果page为NULL,那么goto next */
		if (unlikely(!page))
			goto next;
		/* radix_tree_deref_slot返回任一异常? */
		if (radix_tree_exception(page)) {
			if (radix_tree_deref_retry(page)) {
				slot = radix_tree_iter_retry(&iter);
				continue;
			}
			goto next;
		}
		/* 如果是复合页面 */
		head = compound_head(page);
		if (!page_cache_get_speculative(head))
			goto repeat;

		/* The page was split under us?
		 * 如果页面被我们拆分了?
		 */
		if (compound_head(page) != head) {
			put_page(head);
			goto repeat;
		}

		/* Has the page moved?
		 * 页面被移动了?
		 */
		if (unlikely(page != *slot)) {
			put_page(head);
			goto repeat;
		}

		/* PG_uptodate tells whether the page's contents is valid.
		 * When a read completes,the page becomes uptodate,unless a disk I/O error happened.
		 *
		 * 如果page的内容不是有效的,或者如果当前page设置了"PG_Readahead"预读标记位,说明本次读取的文件页数据正好命中上一次的预读窗口的文件页
		 * 或者说是PageHWPosion
		 * 为什么预读page不能进行映射???
		 */
		if (!PageUptodate(page) ||
				PageReadahead(page) ||
				PageHWPoison(page))
			goto skip;
		/* 如果trylock_page,那么skip */
		if (!trylock_page(page))
			goto skip;

		/* 如果page->mapping被改了,或者page的内容不可用
		 * 那么goto unlock
		 */
		if (page->mapping != mapping || !PageUptodate(page))
			goto unlock;

		/* 将inode->size向上取证到PAGE_SIZE的倍数 */
		size = round_up(i_size_read(mapping->host), PAGE_SIZE);
		/* 如果page->index >= size >> PAGE_SHIFT,那么goto unlock */
		if (page->index >= size >> PAGE_SHIFT)
			goto unlock;

		/* mmap_miss: Cache miss stat for mmap accesses mmap
		 * 如果cache miss 大于0,那么--
		 */
		if (file->f_ra.mmap_miss > 0)
			file->f_ra.mmap_miss--;
		/* 计算出地址 */
		fe->address += (iter.index - last_pgoff) << PAGE_SHIFT;
		/* 拿到pte */
		if (fe->pte)
			fe->pte += iter.index - last_pgoff;
		last_pgoff = iter.index;
		/* 把page和pte绑起来 */
		if (alloc_set_pte(fe, NULL, page))
			goto unlock;
		unlock_page(page);
		goto next;
unlock:
		unlock_page(page);
skip:
		put_page(page);
next:
		/* Huge page is mapped? No need to proceed. */
		if (pmd_trans_huge(*fe->pmd))
			break;
		if (iter.index == end_pgoff)
			break;
	}
	rcu_read_unlock();
}
EXPORT_SYMBOL(filemap_map_pages);

int filemap_page_mkwrite(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct page *page = vmf->page;
	struct inode *inode = file_inode(vma->vm_file);
	int ret = VM_FAULT_LOCKED;

	sb_start_pagefault(inode->i_sb);
	file_update_time(vma->vm_file);
	lock_page(page);
	if (page->mapping != inode->i_mapping) {
		unlock_page(page);
		ret = VM_FAULT_NOPAGE;
		goto out;
	}
	/*
	 * We mark the page dirty already here so that when freeze is in
	 * progress, we are guaranteed that writeback during freezing will
	 * see the dirty page and writeprotect it again.
	 */
	set_page_dirty(page);
	wait_for_stable_page(page);
out:
	sb_end_pagefault(inode->i_sb);
	return ret;
}
EXPORT_SYMBOL(filemap_page_mkwrite);

const struct vm_operations_struct generic_file_vm_ops = {
	.fault		= filemap_fault,
	.map_pages	= filemap_map_pages,
	.page_mkwrite	= filemap_page_mkwrite,
};

/* This is used for a general mmap of a disk file */

int generic_file_mmap(struct file * file, struct vm_area_struct * vma)
{
	struct address_space *mapping = file->f_mapping;

	if (!mapping->a_ops->readpage)
		return -ENOEXEC;
	file_accessed(file);
	vma->vm_ops = &generic_file_vm_ops;
	return 0;
}

/*
 * This is for filesystems which do not implement ->writepage.
 */
int generic_file_readonly_mmap(struct file *file, struct vm_area_struct *vma)
{
	if ((vma->vm_flags & VM_SHARED) && (vma->vm_flags & VM_MAYWRITE))
		return -EINVAL;
	return generic_file_mmap(file, vma);
}
#else
int generic_file_mmap(struct file * file, struct vm_area_struct * vma)
{
	return -ENOSYS;
}
int generic_file_readonly_mmap(struct file * file, struct vm_area_struct * vma)
{
	return -ENOSYS;
}
#endif /* CONFIG_MMU */

EXPORT_SYMBOL(generic_file_mmap);
EXPORT_SYMBOL(generic_file_readonly_mmap);

static struct page *wait_on_page_read(struct page *page)
{
	if (!IS_ERR(page)) {
		wait_on_page_locked(page);
		if (!PageUptodate(page)) {
			put_page(page);
			page = ERR_PTR(-EIO);
		}
	}
	return page;
}

static struct page *do_read_cache_page(struct address_space *mapping,
				pgoff_t index,
				int (*filler)(void *, struct page *),
				void *data,
				gfp_t gfp)
{
	struct page *page;
	int err;
repeat:
	page = find_get_page(mapping, index);
	if (!page) {
		page = __page_cache_alloc(gfp | __GFP_COLD);
		if (!page)
			return ERR_PTR(-ENOMEM);
		err = add_to_page_cache_lru(page, mapping, index, gfp);
		if (unlikely(err)) {
			put_page(page);
			if (err == -EEXIST)
				goto repeat;
			/* Presumably ENOMEM for radix tree node */
			return ERR_PTR(err);
		}

filler:
		err = filler(data, page);
		if (err < 0) {
			put_page(page);
			return ERR_PTR(err);
		}

		page = wait_on_page_read(page);
		if (IS_ERR(page))
			return page;
		goto out;
	}
	if (PageUptodate(page))
		goto out;

	/*
	 * Page is not up to date and may be locked due one of the following
	 * case a: Page is being filled and the page lock is held
	 * case b: Read/write error clearing the page uptodate status
	 * case c: Truncation in progress (page locked)
	 * case d: Reclaim in progress
	 *
	 * Case a, the page will be up to date when the page is unlocked.
	 *    There is no need to serialise on the page lock here as the page
	 *    is pinned so the lock gives no additional protection. Even if the
	 *    the page is truncated, the data is still valid if PageUptodate as
	 *    it's a race vs truncate race.
	 * Case b, the page will not be up to date
	 * Case c, the page may be truncated but in itself, the data may still
	 *    be valid after IO completes as it's a read vs truncate race. The
	 *    operation must restart if the page is not uptodate on unlock but
	 *    otherwise serialising on page lock to stabilise the mapping gives
	 *    no additional guarantees to the caller as the page lock is
	 *    released before return.
	 * Case d, similar to truncation. If reclaim holds the page lock, it
	 *    will be a race with remove_mapping that determines if the mapping
	 *    is valid on unlock but otherwise the data is valid and there is
	 *    no need to serialise with page lock.
	 *
	 * As the page lock gives no additional guarantee, we optimistically
	 * wait on the page to be unlocked and check if it's up to date and
	 * use the page if it is. Otherwise, the page lock is required to
	 * distinguish between the different cases. The motivation is that we
	 * avoid spurious serialisations and wakeups when multiple processes
	 * wait on the same page for IO to complete.
	 */
	wait_on_page_locked(page);
	if (PageUptodate(page))
		goto out;

	/* Distinguish between all the cases under the safety of the lock */
	lock_page(page);

	/* Case c or d, restart the operation */
	if (!page->mapping) {
		unlock_page(page);
		put_page(page);
		goto repeat;
	}

	/* Someone else locked and filled the page in a very small window */
	if (PageUptodate(page)) {
		unlock_page(page);
		goto out;
	}
	goto filler;

out:
	mark_page_accessed(page);
	return page;
}

/**
 * read_cache_page - read into page cache, fill it if needed
 * @mapping:	the page's address_space
 * @index:	the page index
 * @filler:	function to perform the read
 * @data:	first arg to filler(data, page) function, often left as NULL
 *
 * Read into the page cache. If a page already exists, and PageUptodate() is
 * not set, try to fill the page and wait for it to become unlocked.
 *
 * If the page does not get brought uptodate, return -EIO.
 */
struct page *read_cache_page(struct address_space *mapping,
				pgoff_t index,
				int (*filler)(void *, struct page *),
				void *data)
{
	return do_read_cache_page(mapping, index, filler, data, mapping_gfp_mask(mapping));
}
EXPORT_SYMBOL(read_cache_page);

/**
 * read_cache_page_gfp - read into page cache, using specified page allocation flags.
 * @mapping:	the page's address_space
 * @index:	the page index
 * @gfp:	the page allocator flags to use if allocating
 *
 * This is the same as "read_mapping_page(mapping, index, NULL)", but with
 * any new page allocations done using the specified allocation flags.
 *
 * If the page does not get brought uptodate, return -EIO.
 */
struct page *read_cache_page_gfp(struct address_space *mapping,
				pgoff_t index,
				gfp_t gfp)
{
	filler_t *filler = (filler_t *)mapping->a_ops->readpage;

	return do_read_cache_page(mapping, index, filler, NULL, gfp);
}
EXPORT_SYMBOL(read_cache_page_gfp);

/*
 * Performs necessary checks before doing a write
 *
 * Can adjust writing position or amount of bytes to write.
 * Returns appropriate error code that caller should return or
 * zero in case that write should be allowed.
 *
 * 在做一次写入执行必要的检查
 *
 * 可以调整写入位置或要写入的字节数.
 * 如果允许写入,返回0.
 * 否则返回的适当错误代码给调用者
 */
inline ssize_t generic_write_checks(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file->f_mapping->host;
	/* RLIMIT_FSIZE 可以创建的文件的最大字节长度,
	 * 当超过此软限制时,则向该进程发送SIGXFSZ信号
	 */
	unsigned long limit = rlimit(RLIMIT_FSIZE);
	loff_t pos;
	/* 如果iov里面的count为0(即数据大小为0),那么也直接退出了 */
	if (!iov_iter_count(from))
		return 0;

	/* FIXME: this is for backwards compatibility with 2.4 */
	/* 如果是已append的形势打开,那么kiocb的ki_ops(表示当前进行I/O操作的文件位置)
	 * 等于文件的结尾
	 * 毕竟是追加模式打开的嘛
	 */
	if (iocb->ki_flags & IOCB_APPEND)
		iocb->ki_pos = i_size_read(inode);
	/* 将iocb->ki_pos赋值给pos */
	pos = iocb->ki_pos;
	/* 如果limut != RLIM_INFINITY说明有人对当前线程做了limit */
	if (limit != RLIM_INFINITY) {
		/* RLIMIT_FSIZE 可以创建的文件的最大字节长度
		 * 当超过此软限制时,则向该进程发送SIGXFSZ信号
		 */
		if (iocb->ki_pos >= limit) {
			send_sig(SIGXFSZ, current, 0);
			return -EFBIG;
		}
		/* 这边就怕数据的大小大于我们的limit
		 * if (i->count > limit - (unsigned long)pos )
		 *	i->count = limit - (unsigned long)pos
		 */
		iov_iter_truncate(from, limit - (unsigned long)pos);
	}

	/*
	 * LFS rule
	 */

	/* 同理不要让它坏了LFS的规则 */
	if (unlikely(pos + iov_iter_count(from) > MAX_NON_LFS &&
				!(file->f_flags & O_LARGEFILE))) {
		if (pos >= MAX_NON_LFS)
			return -EFBIG;
		iov_iter_truncate(from, MAX_NON_LFS - (unsigned long)pos);
	}

	/*
	 * Are we about to exceed the fs block limit ?
	 *
	 * If we have written data it becomes a short write.  If we have
	 * exceeded without writing data we send a signal and return EFBIG.
	 * Linus frestrict idea will clean these up nicely..
	 *
	 * 我们即将超过fs块限制吗？
	 *
	 * 如果我们已经写入了数据，那么它就变成了短写入.
	 * 如果我们在没有写入数据的情况下超过了,我们会发送信号并返回EFBIG.
	 *
	 */
	if (unlikely(pos >= inode->i_sb->s_maxbytes))
		return -EFBIG;

	iov_iter_truncate(from, inode->i_sb->s_maxbytes - pos);
	return iov_iter_count(from);
}
EXPORT_SYMBOL(generic_write_checks);

int pagecache_write_begin(struct file *file, struct address_space *mapping,
				loff_t pos, unsigned len, unsigned flags,
				struct page **pagep, void **fsdata)
{
	const struct address_space_operations *aops = mapping->a_ops;

	return aops->write_begin(file, mapping, pos, len, flags,
							pagep, fsdata);
}
EXPORT_SYMBOL(pagecache_write_begin);

int pagecache_write_end(struct file *file, struct address_space *mapping,
				loff_t pos, unsigned len, unsigned copied,
				struct page *page, void *fsdata)
{
	const struct address_space_operations *aops = mapping->a_ops;

	return aops->write_end(file, mapping, pos, len, copied, page, fsdata);
}
EXPORT_SYMBOL(pagecache_write_end);

ssize_t
generic_file_direct_write(struct kiocb *iocb, struct iov_iter *from)
{
	struct file	*file = iocb->ki_filp;
	struct address_space *mapping = file->f_mapping;
	struct inode	*inode = mapping->host;
	loff_t		pos = iocb->ki_pos;
	ssize_t		written;
	size_t		write_len;
	pgoff_t		end;
	struct iov_iter data;

	write_len = iov_iter_count(from);
	end = (pos + write_len - 1) >> PAGE_SHIFT;

	written = filemap_write_and_wait_range(mapping, pos, pos + write_len - 1);
	if (written)
		goto out;

	/*
	 * After a write we want buffered reads to be sure to go to disk to get
	 * the new data.  We invalidate clean cached page from the region we're
	 * about to write.  We do this *before* the write so that we can return
	 * without clobbering -EIOCBQUEUED from ->direct_IO().
	 */
	if (mapping->nrpages) {
		written = invalidate_inode_pages2_range(mapping,
					pos >> PAGE_SHIFT, end);
		/*
		 * If a page can not be invalidated, return 0 to fall back
		 * to buffered write.
		 */
		if (written) {
			if (written == -EBUSY)
				return 0;
			goto out;
		}
	}

	data = *from;
	written = mapping->a_ops->direct_IO(iocb, &data);

	/*
	 * Finally, try again to invalidate clean pages which might have been
	 * cached by non-direct readahead, or faulted in by get_user_pages()
	 * if the source of the write was an mmap'ed region of the file
	 * we're writing.  Either one is a pretty crazy thing to do,
	 * so we don't support it 100%.  If this invalidation
	 * fails, tough, the write still worked...
	 */
	if (mapping->nrpages) {
		invalidate_inode_pages2_range(mapping,
					      pos >> PAGE_SHIFT, end);
	}

	if (written > 0) {
		pos += written;
		iov_iter_advance(from, written);
		if (pos > i_size_read(inode) && !S_ISBLK(inode->i_mode)) {
			i_size_write(inode, pos);
			mark_inode_dirty(inode);
		}
		iocb->ki_pos = pos;
	}
out:
	return written;
}
EXPORT_SYMBOL(generic_file_direct_write);

/*
 * Find or create a page at the given pagecache position. Return the locked
 * page. This function is specifically for buffered writes.
 *
 * 在给定的页面缓存位置查找或创建页面.返回锁定的页面.
 * 此函数专门用于缓冲写入.
 */
struct page *grab_cache_page_write_begin(struct address_space *mapping,
					pgoff_t index, unsigned flags)
{
	struct page *page;
	int fgp_flags = FGP_LOCK|FGP_WRITE|FGP_CREAT;

	if (flags & AOP_FLAG_NOFS)
		fgp_flags |= FGP_NOFS;

	page = pagecache_get_page(mapping, index, fgp_flags,
			mapping_gfp_mask(mapping));
	if (page) /* wait for writeback to finish, if necessary. */
		wait_for_stable_page(page);

	return page;
}
EXPORT_SYMBOL(grab_cache_page_write_begin);

ssize_t generic_perform_write(struct file *file,
				struct iov_iter *i, loff_t pos)
{
	struct address_space *mapping = file->f_mapping;
	const struct address_space_operations *a_ops = mapping->a_ops;
	long status = 0;
	/* written用来记录已写的字节数 */
	ssize_t written = 0;
	unsigned int flags = 0;

	/*
	 * Copies from kernel address space cannot fail (NFSD is a big user).
	 */

	/* 若当前I/O操作是属于在内核中进行,显然是不能被中断的(用户态的I/O操作可以被中断),
	 * 就要设置AOP_FLAG_UNINTERRUPTIBLE
	 */
	if (!iter_is_iovec(i))
		flags |= AOP_FLAG_UNINTERRUPTIBLE;

	do {
		struct page *page;
		/* offset为在页面中的偏移 */
		unsigned long offset;	/* Offset into pagecache page */
		/* bytes为要写到页面的字节数 */
		unsigned long bytes;	/* Bytes to write to page */
		/* copied为用户空间复制过来的字节数 */
		size_t copied;		/* Bytes copied from user */
		void *fsdata;
		/* 拿到page的偏移量 */
		offset = (pos & (PAGE_SIZE - 1));
		/* 算出可写的数据量 */
		bytes = min_t(unsigned long, PAGE_SIZE - offset,
						iov_iter_count(i));

again:
		/*
		 * Bring in the user page that we will copy from _first_.
		 * Otherwise there's a nasty deadlock on copying from the
		 * same page as we're writing to, without it being marked
		 * up-to-date.
		 *
		 * Not only is this an optimisation, but it is also required
		 * to check that the address is actually valid, when atomic
		 * usercopies are used, below.
		 */
		if (unlikely(iov_iter_fault_in_readable(i, bytes))) {
			status = -EFAULT;
			break;
		}
		/* 致命信号要处理 */
		if (fatal_signal_pending(current)) {
			status = -EINTR;
			break;
		}
		/* 为写做准备,主要是把需要写的页面准备好,如果内存里还没有,就要从磁盘上读 */
		status = a_ops->write_begin(file, mapping, pos, bytes, flags,
						&page, &fsdata);
		if (unlikely(status < 0))
			break;
		/* 如果这个是共享的内存,那么就要flush_dcache_page,将dcache相应的page里的数据
		 * 写到memory里面去，以保证dcache内的数据与memory内的数据的一致性
		 */
		if (mapping_writably_mapped(mapping))
			flush_dcache_page(page);
		/* 从用户空间向页里写数据 */
		copied = iov_iter_copy_from_user_atomic(page, i, offset, bytes);
		flush_dcache_page(page);
		/* 写结束 */
		status = a_ops->write_end(file, mapping, pos, bytes, copied,
						page, fsdata);
		if (unlikely(status < 0))
			break;
		copied = status;

		cond_resched();
		/* 从count里减去已经复制的数据 */
		iov_iter_advance(i, copied);
		if (unlikely(copied == 0)) {
			/*
			 * If we were unable to copy any data at all, we must
			 * fall back to a single segment length write.
			 *
			 * If we didn't fallback here, we could livelock
			 * because not all segments in the iov can be copied at
			 * once without a pagefault.
			 */
			bytes = min_t(unsigned long, PAGE_SIZE - offset,
						iov_iter_single_seg_count(i));
			goto again;
		}
		pos += copied;
		written += copied;
		/* 刷新脏页,如果脏页太多,就会写磁盘 */
		balance_dirty_pages_ratelimited(mapping);
	} while (iov_iter_count(i));

	return written ? written : status;
}
EXPORT_SYMBOL(generic_perform_write);

/**
 * __generic_file_write_iter - write data to a file
 * @iocb:	IO state structure (file, offset, etc.)
 * @from:	iov_iter with data to write
 *
 * This function does all the work needed for actually writing data to a
 * file. It does all basic checks, removes SUID from the file, updates
 * modification times and calls proper subroutines depending on whether we
 * do direct IO or a standard buffered write.
 *
 * It expects i_mutex to be grabbed unless we work on a block device or similar
 * object which does not need locking at all.
 *
 * This function does *not* take care of syncing data in case of O_SYNC write.
 * A caller has to handle it. This is mainly due to the fact that we want to
 * avoid syncing under i_mutex.
 *
 * __generic_file_write_iter-将数据写入文件
 * @iocb:IO state structure(文件、偏移量等)
 * @from：iov_iter 其中包含要写入的数据
 *
 *
 * 此函数完成将数据实际写入文件所需的所有工作.
 * 它执行所有基本检查，从文件中删除SUID,更新修改时间,并调用适当的子例程这取决于我们是执行直接IO还是标准缓冲写入.
 * 它期望i_mutex被抓取,除非我们在一个根本不需要锁定的块设备或类似对象上工作.
 *
 * 在O_SYNC写入的情况下，此函数不负责同步数据。
 * 调用方必须处理它。这主要是因为我们希望避免在i_mutex下同步。
 *
 */
ssize_t __generic_file_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct address_space * mapping = file->f_mapping;
	struct inode 	*inode = mapping->host;
	ssize_t		written = 0;
	ssize_t		err;
	ssize_t		status;

	/* We can write back this queue in page reclaim
	 * 我们能写回这个队列当页面回收的时候
	 */
	current->backing_dev_info = inode_to_bdi(inode);
	/* Remove special file priviledges (suid, capabilities) when file is written
	 * to or truncated.
	 */
	err = file_remove_privs(file);
	if (err)
		goto out;
	/* update mtime and ctime time
	 * i_mtime 文件的最后修改时间
	 * i_ctime inode的最后修改时间
	 */
	err = file_update_time(file);
	if (err)
		goto out;
	/* 处理直接I/O,首先调用generic_file_direct_write,尽管需要绕开页面缓存,它还是调用地址空间操作表中的direct_IO来完成操作.
	 * 最终它可能写完了所有的字节,或者出现错误,
	 * 这两种情况下,都返回结果给调用者.
	 * 另一种情况是只写了部分数据,这通常出现在文件中有空洞的情况下,它转而使用缓存I/O,
	 * 也就是调用generic_file_buffered_write来完成剩余字节的I/O,并调用
	 * filemap_write_and_wait_range将通过这些字节冲刷到磁盘,同时让相应的页面缓存失效,
	 * 之所以这么做,是为了达到直接I/O所希望的语义
	 */
	if (iocb->ki_flags & IOCB_DIRECT) {
		loff_t pos, endbyte;

		written = generic_file_direct_write(iocb, from);
		/*
		 * If the write stopped short of completing, fall back to
		 * buffered writes.  Some filesystems do this for writes to
		 * holes, for example.  For DAX files, a buffered write will
		 * not succeed (even if it did, DAX does not handle dirty
		 * page-cache pages correctly).
		 */
		if (written < 0 || !iov_iter_count(from) || IS_DAX(inode))
			goto out;

		status = generic_perform_write(file, from, pos = iocb->ki_pos);
		/*
		 * If generic_perform_write() returned a synchronous error
		 * then we want to return the number of bytes which were
		 * direct-written, or the error code if that was zero.  Note
		 * that this differs from normal direct-io semantics, which
		 * will return -EFOO even if some bytes were written.
		 */
		if (unlikely(status < 0)) {
			err = status;
			goto out;
		}
		/*
		 * We need to ensure that the page cache pages are written to
		 * disk and invalidated to preserve the expected O_DIRECT
		 * semantics.
		 */
		endbyte = pos + status - 1;
		err = filemap_write_and_wait_range(mapping, pos, endbyte);
		if (err == 0) {
			iocb->ki_pos = endbyte + 1;
			written += status;
			invalidate_mapping_pages(mapping,
						 pos >> PAGE_SHIFT,
						 endbyte >> PAGE_SHIFT);
		} else {
			/*
			 * We don't know how much we wrote, so just return
			 * the number of bytes which were direct-written
			 */
		}
	} else {
		/* 处理缓存I/O */
		written = generic_perform_write(file, from, iocb->ki_pos);
		if (likely(written > 0))
			iocb->ki_pos += written;
	}
out:
	current->backing_dev_info = NULL;
	return written ? written : err;
}
EXPORT_SYMBOL(__generic_file_write_iter);

/**
 * generic_file_write_iter - write data to a file
 * @iocb:	IO state structure
 * @from:	iov_iter with data to write
 *
 * This is a wrapper around __generic_file_write_iter() to be used by most
 * filesystems. It takes care of syncing the file in case of O_SYNC file
 * and acquires i_mutex as needed.
 *
 * generic_file_write_iter-将数据写入文件
 * @iocb:IO状态结构
 * @from：iov_iter，其中包含要写入的数据
 *
 *
 * 这是大多数文件系统使用的__generic_file_write_iter()的包装.
 * 它负责在O_SYNC文件的情况下同步文件，并根据需要获取i_mutex。
 */
ssize_t generic_file_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file->f_mapping->host;
	ssize_t ret;

	inode_lock(inode);
	/* 做一些基本的检查
	 * 主要是检查你写入的文件大小超过一些限制
	 */
	ret = generic_write_checks(iocb, from);
	if (ret > 0)
		ret = __generic_file_write_iter(iocb, from);
	inode_unlock(inode);

	if (ret > 0)
		ret = generic_write_sync(iocb, ret);
	return ret;
}
EXPORT_SYMBOL(generic_file_write_iter);

/**
 * try_to_release_page() - release old fs-specific metadata on a page
 *
 * @page: the page which the kernel is trying to free
 * @gfp_mask: memory allocation flags (and I/O mode)
 *
 * The address_space is to try to release any data against the page
 * (presumably at page->private).  If the release was successful, return `1'.
 * Otherwise return zero.
 *
 * This may also be called if PG_fscache is set on a page, indicating that the
 * page is known to the local caching routines.
 *
 * The @gfp_mask argument specifies whether I/O may be performed to release
 * this page (__GFP_IO), and whether the call may block (__GFP_RECLAIM & __GFP_FS).
 *
 */
int try_to_release_page(struct page *page, gfp_t gfp_mask)
{
	struct address_space * const mapping = page->mapping;

	BUG_ON(!PageLocked(page));
	if (PageWriteback(page))
		return 0;

	if (mapping && mapping->a_ops->releasepage)
		return mapping->a_ops->releasepage(page, gfp_mask);
	return try_to_free_buffers(page);
}

EXPORT_SYMBOL(try_to_release_page);
