/*
 *  linux/mm/swap_state.c
 *
 *  Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 *  Swap reorganised 29.12.95, Stephen Tweedie
 *
 *  Rewritten to use page cache, (C) 1998 Stephen Tweedie
 */
#include <linux/mm.h>
#include <linux/gfp.h>
#include <linux/kernel_stat.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/init.h>
#include <linux/pagemap.h>
#include <linux/backing-dev.h>
#include <linux/blkdev.h>
#include <linux/pagevec.h>
#include <linux/migrate.h>

#include <asm/pgtable.h>

/*
 * swapper_space is a fiction, retained to simplify the path through
 * vmscan's shrink_page_list.
 */
static const struct address_space_operations swap_aops = {
	.writepage	= swap_writepage,
	.set_page_dirty	= swap_set_page_dirty,
#ifdef CONFIG_MIGRATION
	.migratepage	= migrate_page,
#endif
};

struct address_space swapper_spaces[MAX_SWAPFILES] = {
	[0 ... MAX_SWAPFILES - 1] = {
		.page_tree	= RADIX_TREE_INIT(GFP_ATOMIC|__GFP_NOWARN),
		.i_mmap_writable = ATOMIC_INIT(0),
		.a_ops		= &swap_aops,
		/* swap cache doesn't use writeback related tags */
		.flags		= 1 << AS_NO_WRITEBACK_TAGS,
	}
};

#define INC_CACHE_INFO(x)	do { swap_cache_info.x++; } while (0)

static struct {
	unsigned long add_total;
	unsigned long del_total;
	unsigned long find_success;
	unsigned long find_total;
} swap_cache_info;

unsigned long total_swapcache_pages(void)
{
	int i;
	unsigned long ret = 0;

	for (i = 0; i < MAX_SWAPFILES; i++)
		ret += swapper_spaces[i].nrpages;
	return ret;
}

static atomic_t swapin_readahead_hits = ATOMIC_INIT(4);

void show_swap_cache_info(void)
{
	printk("%lu pages in swap cache\n", total_swapcache_pages());
	printk("Swap cache stats: add %lu, delete %lu, find %lu/%lu\n",
		swap_cache_info.add_total, swap_cache_info.del_total,
		swap_cache_info.find_success, swap_cache_info.find_total);
	printk("Free swap  = %ldkB\n",
		get_nr_swap_pages() << (PAGE_SHIFT - 10));
	printk("Total swap = %lukB\n", total_swap_pages << (PAGE_SHIFT - 10));
}

/*
 * __add_to_swap_cache resembles add_to_page_cache_locked on swapper_space,
 * but sets SwapCache flag and private instead of mapping and index.
 *
 * __add_to_swap_cache函数与在交换空间(swapper_space)上使用的add_to_page_cache_locked函数类似,
 * 但它在将页面添加到缓存时设置了SwapCache标志和私有数据(private)而不是设置映射(mapping)和索引(index).
 */
int __add_to_swap_cache(struct page *page, swp_entry_t entry)
{
	int error;
	struct address_space *address_space;

	VM_BUG_ON_PAGE(!PageLocked(page), page);
	VM_BUG_ON_PAGE(PageSwapCache(page), page);
	VM_BUG_ON_PAGE(!PageSwapBacked(page), page);

	/* page->_refcount + 1 */
	get_page(page);
	/* 设置该page的PG_swapcache */
	SetPageSwapCache(page);
	/* (page)->private = entry.val */
	set_page_private(page, entry.val);
	/* 拿到对应entry对应的type对应的address_space */
	address_space = swap_address_space(entry);
	spin_lock_irq(&address_space->tree_lock);
	/* 这边就是把它添加到radix_tree中去 */
	error = radix_tree_insert(&address_space->page_tree,
				  swp_offset(entry), page);
	if (likely(!error)) {
		/* nrpages++ */
		address_space->nrpages++;
		/* node的NR_FILE_PAGES++ */
		__inc_node_page_state(page, NR_FILE_PAGES);
		/* swap_cache_info.add_total++; */
		INC_CACHE_INFO(add_total);
	}
	spin_unlock_irq(&address_space->tree_lock);

	if (unlikely(error)) {
		/*
		 * Only the context which have set SWAP_HAS_CACHE flag
		 * would call add_to_swap_cache().
		 * So add_to_swap_cache() doesn't returns -EEXIST.
		 *
		 * 只有那些已经设置了SWAP_HAS_CACHE标志的上下文会调用add_to_swap_cache()函数.
		 * 因此,add_to_swap_cache()函数不会返回-EEXIST(表示已存在的错误码)
		 */
		VM_BUG_ON(error == -EEXIST);
		/* 设置(page)->private 为0 */
		set_page_private(page, 0UL);
		/* 清除PG_swapcache */
		ClearPageSwapCache(page);
		/* page->_refcount - 1 */
		put_page(page);
	}

	return error;
}


int add_to_swap_cache(struct page *page, swp_entry_t entry, gfp_t gfp_mask)
{
	int error;

	error = radix_tree_maybe_preload(gfp_mask);
	if (!error) {
		error = __add_to_swap_cache(page, entry);
		radix_tree_preload_end();
	}
	return error;
}

/*
 * This must be called only on pages that have
 * been verified to be in the swap cache.
 *
 * 这个方法(或函数)仅应在已经确认处于swap缓存中的页面上调用.
 */
void __delete_from_swap_cache(struct page *page)
{
	swp_entry_t entry;
	struct address_space *address_space;

	VM_BUG_ON_PAGE(!PageLocked(page), page);
	VM_BUG_ON_PAGE(!PageSwapCache(page), page);
	VM_BUG_ON_PAGE(PageWriteback(page), page);

	/* 拿到swap_entry_t */
	entry.val = page_private(page);
	/* 拿到对应的地址空间 */
	address_space = swap_address_space(entry);
	/* 把它从对应的radix_tree里面删除掉 */
	radix_tree_delete(&address_space->page_tree, swp_offset(entry));
	/* 清除(page)->private */
	set_page_private(page, 0);
	/* 清除PG_swapcache */
	ClearPageSwapCache(page);
	/* 对应的address_space->nrpages-- */
	address_space->nrpages--;
	/* NR_FILE_PAGES -- */
	__dec_node_page_state(page, NR_FILE_PAGES);
	/* swap_cache_info.del_total-- */
	INC_CACHE_INFO(del_total);
}

/**
 * add_to_swap - allocate swap space for a page
 * @page: page we want to move to swap
 *
 * Allocate swap space for the page and add the page to the
 * swap cache.  Caller needs to hold the page lock.
 *
 * add_to_swap - 为一个页面分配swap空间
 * @page: 我们想要移动到swap空间的页面
 *
 * 为页面分配swap空间,并将该页面添加到swap缓存中.调用者需要持有页面的锁.
 */
int add_to_swap(struct page *page, struct list_head *list)
{
	swp_entry_t entry;
	int err;

	VM_BUG_ON_PAGE(!PageLocked(page), page);
	VM_BUG_ON_PAGE(!PageUptodate(page), page);

	entry = get_swap_page();
	if (!entry.val)
		return 0;

	if (mem_cgroup_try_charge_swap(page, entry)) {
		swapcache_free(entry);
		return 0;
	}

	if (unlikely(PageTransHuge(page)))
		if (unlikely(split_huge_page_to_list(page, list))) {
			swapcache_free(entry);
			return 0;
		}

	/*
	 * Radix-tree node allocations from PF_MEMALLOC contexts could
	 * completely exhaust the page allocator. __GFP_NOMEMALLOC
	 * stops emergency reserves from being allocated.
	 *
	 * 从PF_MEMALLOC上下文中分配Radix树节点可能会完全耗尽页面分配器.
	 * 使用__GFP_NOMEMALLOC标志会阻止分配紧急储备内存.
	 *
	 * TODO: this could cause a theoretical memory reclaim
	 * deadlock in the swap out path.
	 *
	 * 这可能会导致在内存交换出(swap-out)过程中理论上出现内存回收死锁.
	 */
	/*
	 * Add it to the swap cache.
	 * 把它添加到swap cache中
	 */
	err = add_to_swap_cache(page, entry,
			__GFP_HIGH|__GFP_NOMEMALLOC|__GFP_NOWARN);

	if (!err) {
		return 1;
	} else {	/* -ENOMEM radix-tree allocation failure */
		/*
		 * add_to_swap_cache() doesn't return -EEXIST, so we can safely
		 * clear SWAP_HAS_CACHE flag.
		 */
		swapcache_free(entry);
		return 0;
	}
}

/*
 * This must be called only on pages that have
 * been verified to be in the swap cache and locked.
 * It will never put the page into the free list,
 * the caller has a reference on the page.
 *
 * 这个方法(或函数)仅应在已经确认处于swap缓存中并且已被锁定的页面上调用.
 * 它永远不会将页面放入空闲列表,因为调用者已经对该页面持有了一个引用
 */
void delete_from_swap_cache(struct page *page)
{
	swp_entry_t entry;
	struct address_space *address_space;
	/* 拿到swp_entry_t */
	entry.val = page_private(page);

	/* 找到该地址空间 */
	address_space = swap_address_space(entry);
	spin_lock_irq(&address_space->tree_lock);
	/* 把它从swap_cacahe中删除 */
	__delete_from_swap_cache(page);
	spin_unlock_irq(&address_space->tree_lock);
	/* 释放swapcache */
	swapcache_free(entry);
	put_page(page);
}

/* 
 * If we are the only user, then try to free up the swap cache. 
 * 
 * Its ok to check for PageSwapCache without the page lock
 * here because we are going to recheck again inside
 * try_to_free_swap() _with_ the lock.
 * 					- Marcelo
 */
static inline void free_swap_cache(struct page *page)
{
	if (PageSwapCache(page) && !page_mapped(page) && trylock_page(page)) {
		try_to_free_swap(page);
		unlock_page(page);
	}
}

/* 
 * Perform a free_page(), also freeing any swap cache associated with
 * this page if it is the last user of the page.
 */
void free_page_and_swap_cache(struct page *page)
{
	free_swap_cache(page);
	if (!is_huge_zero_page(page))
		put_page(page);
}

/*
 * Passed an array of pages, drop them all from swapcache and then release
 * them.  They are removed from the LRU and freed if this is their last use.
 */
void free_pages_and_swap_cache(struct page **pages, int nr)
{
	struct page **pagep = pages;
	int i;

	lru_add_drain();
	for (i = 0; i < nr; i++)
		free_swap_cache(pagep[i]);
	release_pages(pagep, nr, false);
}

/*
 * Lookup a swap entry in the swap cache. A found page will be returned
 * unlocked and with its refcount incremented - we rely on the kernel
 * lock getting page table operations atomic even if we drop the page
 * lock before returning.
 *
 * 在swap缓存中查找一个swap条目.
 * 如果找到了页面,该页面将以未加锁的状态返回,并且其引用计数会增加 - 我们依赖内核锁来确保即使我们在返回前释放了页面锁,页表操作也是原子的.
 */
struct page * lookup_swap_cache(swp_entry_t entry)
{
	struct page *page;

	/* 在地址空间找到该page,也就是在entry对应的地址空间,找到该page */
	page = find_get_page(swap_address_space(entry), swp_offset(entry));
	/* 如果找到了page */
	if (page) {
		/* 那么swap_cache_info.find_success++ */
		INC_CACHE_INFO(find_success);
		/* 如果有预读位,那么清除 */
		if (TestClearPageReadahead(page))
			atomic_inc(&swapin_readahead_hits);
	}

	/* swap_cache_info.find_total++ */
	INC_CACHE_INFO(find_total);
	return page;
}

struct page *__read_swap_cache_async(swp_entry_t entry, gfp_t gfp_mask,
			struct vm_area_struct *vma, unsigned long addr,
			bool *new_page_allocated)
{
	struct page *found_page, *new_page = NULL;
	/* 拿到该entry对应的地址空间 */
	struct address_space *swapper_space = swap_address_space(entry);
	int err;
	*new_page_allocated = false;

	do {
		/*
		 * First check the swap cache.  Since this is normally
		 * called after lookup_swap_cache() failed, re-calling
		 * that would confuse statistics.
		 *
		 * 首先检查交换缓存.
		 * 由于这通常是在lookup_swap_cache()失败后调用的,因此重新调用会混淆统计数据
		 */
		/* 在swap cache中找该page,如果找到了就break */
		found_page = find_get_page(swapper_space, swp_offset(entry));
		if (found_page)
			break;

		/*
		 * Get a new page to read into from swap.
		 *
		 * 这边就是分配一个新page为了从swap中读取
		 */
		if (!new_page) {
			/* 分配一个新页面 */
			new_page = alloc_page_vma(gfp_mask, vma, addr);
			if (!new_page)
				break;		/* Out of memory */
		}

		/*
		 * call radix_tree_preload() while we can wait.
		 */
		err = radix_tree_maybe_preload(gfp_mask & GFP_KERNEL);
		if (err)
			break;

		/*
		 * Swap entry may have been freed since our caller observed it.
		 *
		 * 自从我们的调用者观察到交换条目以来,它可能已经被释放
		 */
		err = swapcache_prepare(entry);
		if (err == -EEXIST) {
			radix_tree_preload_end();
			/*
			 * We might race against get_swap_page() and stumble
			 * across a SWAP_HAS_CACHE swap_map entry whose page
			 * has not been brought into the swapcache yet, while
			 * the other end is scheduled away waiting on discard
			 * I/O completion at scan_swap_map().
			 *
			 * In order to avoid turning this transitory state
			 * into a permanent loop around this -EEXIST case
			 * if !CONFIG_PREEMPT and the I/O completion happens
			 * to be waiting on the CPU waitqueue where we are now
			 * busy looping, we just conditionally invoke the
			 * scheduler here, if there are some more important
			 * tasks to run.
			 *
			 * 我们可能会与get_swap_page()函数发生竞争,并遇到一个SWAP_HAS_CACHE状态的swap_map条目,
			 * 其对应的页面尚未被加入到交换缓存(swapcache)中,而与此同时,
			 * 另一端在scan_swap_map()函数中因为等待丢弃(discard)I/O操作的完成而被调度出去.
			 *
			 * 为了避免在!CONFIG_PREEMPT(即没有启用抢占式调度)的情况下,如果I/O完成操作恰好在我们当前正忙于循环的CPU等待队列上等待,
			 * 从而导致这种瞬态状态转变为围绕-EEXIST情况的永久循环,我们在这里会条件性地调用调度器,如果有更重要的任务需要运行的话.
			 */
			cond_resched();
			continue;
		}
		if (err) {		/* swp entry is obsolete ?
					 * swp条目已经过时了吗?
					 */
			radix_tree_preload_end();
			break;
		}

		/* May fail (-ENOMEM) if radix-tree node allocation failed. */
		/* 设置PG_locked */
		__SetPageLocked(new_page);
		/* 设置PG_swapbacked */
		__SetPageSwapBacked(new_page);
		/* 把它添加到swap_cache中 */
		err = __add_to_swap_cache(new_page, entry);
		/* 如果返回0 */
		if (likely(!err)) {
			radix_tree_preload_end();
			/*
			 * Initiate read into locked page and return.
			 *
			 * 准备把它添加到匿名页面中
			 */
			lru_cache_add_anon(new_page);
			/* 设置new_page_allocated = true; */
			*new_page_allocated = true;
			/* 返回分配的page */
			return new_page;
		}
		radix_tree_preload_end();
		/* 清除PG_locked */
		__ClearPageLocked(new_page);
		/*
		 * add_to_swap_cache() doesn't return -EEXIST, so we can safely
		 * clear SWAP_HAS_CACHE flag.
		 *
		 * add_to_swap_cache()不返回-EEXIST,因此我们可以安全地清除SWAP_HAS_CACHE标志.
		 */
		swapcache_free(entry);
	} while (err != -ENOMEM);

	/* __add_to_swap_cache会调用get_page,所以这里调用put_page */
	if (new_page)
		put_page(new_page);
	return found_page;
}

/*
 * Locate a page of swap in physical memory, reserving swap cache space
 * and reading the disk if it is not already cached.
 * A failure return means that either the page allocation failed or that
 * the swap entry is no longer in use.
 *
 * 在物理内存中定位一个交换(swap)页面,保留交换缓存空间,如果该页面尚未缓存,则从磁盘读取.
 * 如果操作失败返回,意味着页面分配失败或者该交换条目已不再被使用.
 */
struct page *read_swap_cache_async(swp_entry_t entry, gfp_t gfp_mask,
			struct vm_area_struct *vma, unsigned long addr)
{
	bool page_was_allocated;
	struct page *retpage = __read_swap_cache_async(entry, gfp_mask,
			vma, addr, &page_was_allocated);

	/* 如果page被分配了,那么还要调用swap_readpage去读 */
	if (page_was_allocated)
		swap_readpage(retpage);

	return retpage;
}

static unsigned long swapin_nr_pages(unsigned long offset)
{
	static unsigned long prev_offset;
	unsigned int pages, max_pages, last_ra;
	static atomic_t last_readahead_pages;

	/* max_pages = 1 << page_cluster */
	max_pages = 1 << READ_ONCE(page_cluster);
	/* 如果max_pages <= 1,那么直接返回1 */
	if (max_pages <= 1)
		return 1;

	/*
	 * This heuristic has been found to work well on both sequential and
	 * random loads, swapping to hard disk or to SSD: please don't ask
	 * what the "+ 2" means, it just happens to work well, that's all.
	 *
	 * 这种启发式方法已被发现在顺序加载和随机加载到硬盘或SSD时都工作得很好:
	 * 请不要问'+ 2'代表什么意思,它只是恰好工作得很好,仅此而已.
	 */

	/* 将将新值写入给定内存位置,并返回之前在该位置的值 */
	pages = atomic_xchg(&swapin_readahead_hits, 0) + 2;
	/* 如果之前的swapin_readahead_hits就是=0的 */
	if (pages == 2) {
		/*
		 * We can have no readahead hits to judge by: but must not get
		 * stuck here forever, so check for an adjacent offset instead
		 * (and don't even bother to check whether swap type is same).
		 *
		 * 我们无法仅凭预读命中来判断: 但绝不能永远卡在这里.因此改为检查相邻的偏移量(甚至无需费心去检查交换类型是否相同)
		 */
		/* 这个prev_offset是个static的,如果不是连续的,那么pages = 1 */
		if (offset != prev_offset + 1 && offset != prev_offset - 1)
			pages = 1;
		/* 设置prev_offset = offset,更新prev_offset的值 */
		prev_offset = offset;
	} else {
		unsigned int roundup = 4;
		/* roundup一直*2,直到roundup >= page */
		while (roundup < pages)
			roundup <<= 1;
		pages = roundup;
	}

	if (pages > max_pages)
		pages = max_pages;

	/* Don't shrink readahead too fast */
	last_ra = atomic_read(&last_readahead_pages) / 2;
	if (pages < last_ra)
		pages = last_ra;
	atomic_set(&last_readahead_pages, pages);

	return pages;
}

/**
 * swapin_readahead - swap in pages in hope we need them soon
 * @entry: swap entry of this memory
 * @gfp_mask: memory allocation flags
 * @vma: user vma this address belongs to
 * @addr: target address for mempolicy
 *
 * Returns the struct page for entry and addr, after queueing swapin.
 *
 * Primitive swap readahead code. We simply read an aligned block of
 * (1 << page_cluster) entries in the swap area. This method is chosen
 * because it doesn't cost us any seek time.  We also make sure to queue
 * the 'original' request together with the readahead ones...
 *
 * This has been extended to use the NUMA policies from the mm triggering
 * the readahead.
 *
 * Caller must hold down_read on the vma->vm_mm if vma is not NULL.
 *
 * swapin_readahead - 提前将页面交换进内存,希望我们很快需要它们
 *
 * @entry: 该内存对应的swap条目
 * @gfp_mask: 内存分配标志
 * @vma: 该地址所属的用户虚拟内存区域(vma)
 * @addr: 用于内存策略的目标地址
 *
 * 该函数在排队进行swapin操作后,返回与entry和addr对应的struct page.
 *
 * 这是原始的swap预读代码.
 * 我们简单地读取swap区域中一个对齐的块,该块包含(1 << page_cluster)个条目.选择这种方法是因为它不会消耗我们任何寻道时间.
 * 我们还确保将“原始”请求与预读请求一起排队...
 *
 * 此功能已被扩展为使用触发预读的内存管理(mm)的NUMA策略.
 *
 * 如果vma不为NULL,则调用者必须持有vma->vm_mm的down_read锁.
 */
struct page *swapin_readahead(swp_entry_t entry, gfp_t gfp_mask,
			struct vm_area_struct *vma, unsigned long addr)
{
	struct page *page;
	/* 拿到该entry的offset */
	unsigned long entry_offset = swp_offset(entry);
	unsigned long offset = entry_offset;
	unsigned long start_offset, end_offset;
	unsigned long mask;
	struct blk_plug plug;

	/* 在读入交换分区的页的时候也顺便预读旁边的页,函数swapin_nr_pages是计算预读的页数 */
	mask = swapin_nr_pages(offset) - 1;
	if (!mask)
		goto skip;

	/* Read a page_cluster sized and aligned cluster around offset.
	 * 读取一个page_cluster大小且围绕offset对齐的簇
	 */
	start_offset = offset & ~mask;
	end_offset = offset | mask;
	/* 第一个page是swap header,不用读 */
	if (!start_offset)	/* First page is swap header. */
		start_offset++;

	blk_start_plug(&plug);
	/* 逐页读取指定的页数 */
	for (offset = start_offset; offset <= end_offset ; offset++) {
		/* Ok, do the async read-ahead now */
		/* 从交换区读入一页数据 */
		page = read_swap_cache_async(swp_entry(swp_type(entry), offset),
						gfp_mask, vma, addr);
		if (!page)
			continue;
		/* 如果offset != entry_offset,那么设置PG_readahead */
		if (offset != entry_offset)
			SetPageReadahead(page);
		put_page(page);
	}
	blk_finish_plug(&plug);

	lru_add_drain();	/* Push any new pages onto the LRU now */
skip:
	return read_swap_cache_async(entry, gfp_mask, vma, addr);
}
