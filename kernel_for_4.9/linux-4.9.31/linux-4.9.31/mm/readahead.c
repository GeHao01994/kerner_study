/*
 * mm/readahead.c - address_space-level file readahead.
 *
 * Copyright (C) 2002, Linus Torvalds
 *
 * 09Apr2002	Andrew Morton
 *		Initial version.
 */

#include <linux/kernel.h>
#include <linux/dax.h>
#include <linux/gfp.h>
#include <linux/export.h>
#include <linux/blkdev.h>
#include <linux/backing-dev.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/pagevec.h>
#include <linux/pagemap.h>
#include <linux/syscalls.h>
#include <linux/file.h>
#include <linux/mm_inline.h>

#include "internal.h"

/*
 * Initialise a struct file's readahead state.  Assumes that the caller has
 * memset *ra to zero.
 */
void
file_ra_state_init(struct file_ra_state *ra, struct address_space *mapping)
{
	/* 将bdi的最大预读页设置到这里 */
	ra->ra_pages = inode_to_bdi(mapping->host)->ra_pages;
	/* prev_pos 字段存放着进程在上一次读操作时，最后的访问位置
	 * 它的初值是-1
	 */
	ra->prev_pos = -1;
}
EXPORT_SYMBOL_GPL(file_ra_state_init);

/*
 * see if a page needs releasing upon read_cache_pages() failure
 * - the caller of read_cache_pages() may have set PG_private or PG_fscache
 *   before calling, such as the NFS fs marking pages that are cached locally
 *   on disk, thus we need to give the fs a chance to clean up in the event of
 *   an error
 */
static void read_cache_pages_invalidate_page(struct address_space *mapping,
					     struct page *page)
{
	if (page_has_private(page)) {
		if (!trylock_page(page))
			BUG();
		page->mapping = mapping;
		do_invalidatepage(page, 0, PAGE_SIZE);
		page->mapping = NULL;
		unlock_page(page);
	}
	put_page(page);
}

/*
 * release a list of pages, invalidating them first if need be
 */
static void read_cache_pages_invalidate_pages(struct address_space *mapping,
					      struct list_head *pages)
{
	struct page *victim;

	while (!list_empty(pages)) {
		victim = lru_to_page(pages);
		list_del(&victim->lru);
		read_cache_pages_invalidate_page(mapping, victim);
	}
}

/**
 * read_cache_pages - populate an address space with some pages & start reads against them
 * @mapping: the address_space
 * @pages: The address of a list_head which contains the target pages.  These
 *   pages have their ->index populated and are otherwise uninitialised.
 * @filler: callback routine for filling a single page.
 * @data: private data for the callback routine.
 *
 * Hides the details of the LRU cache etc from the filesystems.
 */
int read_cache_pages(struct address_space *mapping, struct list_head *pages,
			int (*filler)(void *, struct page *), void *data)
{
	struct page *page;
	int ret = 0;

	while (!list_empty(pages)) {
		page = lru_to_page(pages);
		list_del(&page->lru);
		if (add_to_page_cache_lru(page, mapping, page->index,
				readahead_gfp_mask(mapping))) {
			read_cache_pages_invalidate_page(mapping, page);
			continue;
		}
		put_page(page);

		ret = filler(data, page);
		if (unlikely(ret)) {
			read_cache_pages_invalidate_pages(mapping, pages);
			break;
		}
		task_io_account_read(PAGE_SIZE);
	}
	return ret;
}

EXPORT_SYMBOL(read_cache_pages);

static int read_pages(struct address_space *mapping, struct file *filp,
		struct list_head *pages, unsigned int nr_pages, gfp_t gfp)
{
	struct blk_plug plug;
	unsigned page_idx;
	int ret;
	/* 这里就是初始化plug成员
	 * 初始化三个链表
	 * 然后把它放到current_task->plug = plug里面去
	 */
	blk_start_plug(&plug);
	/* 如果a_ops里面有readpages，那么就调用它 */
	if (mapping->a_ops->readpages) {
		ret = mapping->a_ops->readpages(filp, mapping, pages, nr_pages);
		/* Clean up the remaining pages */
		/* 清除剩余的页面 */
		put_pages_list(pages);
		goto out;
	}

	for (page_idx = 0; page_idx < nr_pages; page_idx++) {
		/* 拿到page */
		struct page *page = lru_to_page(pages);
		/* 把它从pages的链表里面删掉 */
		list_del(&page->lru);
		/* 加入LRU链表之后，然后读page */
		if (!add_to_page_cache_lru(page, mapping, page->index, gfp))
			mapping->a_ops->readpage(filp, page);
		/* 计数 -1 */
		put_page(page);
	}
	ret = 0;

out:
	blk_finish_plug(&plug);

	return ret;
}

/*
 * __do_page_cache_readahead() actually reads a chunk of disk.  It allocates all
 * the pages first, then submits them all for I/O. This avoids the very bad
 * behaviour which would occur if page allocations are causing VM writeback.
 * We really don't want to intermingle reads and writes like that.
 *
 * Returns the number of pages requested, or the maximum amount of I/O allowed.
 */

/* __do_page_cache_readahead（）实际上读取了一块磁盘.
 * 它首先分配所有页面，然后将它们全部提交给I/O.
 * 这样可以避免在页面分配导致VM写回时出现的非常糟糕的行为。
 * 我们真的不想把阅读和写作混在一起.
 * 返回请求的页数或允许的最大I/O量.
 */
int __do_page_cache_readahead(struct address_space *mapping, struct file *filp,
			pgoff_t offset, unsigned long nr_to_read,
			unsigned long lookahead_size)
{
	struct inode *inode = mapping->host;
	struct page *page;
	unsigned long end_index;	/* The last page we want to read */
	LIST_HEAD(page_pool);
	int page_idx;
	int ret = 0;
	/* 获得文件的长度 */
	loff_t isize = i_size_read(inode);
	/* 获得gpf的mask */
	gfp_t gfp_mask = readahead_gfp_mask(mapping);

	/* 如果长度为0，那么直接out */
	if (isize == 0)
		goto out;
	/* 算出文件的最大index */
	end_index = ((isize - 1) >> PAGE_SHIFT);

	/*
	 * Preallocate as many pages as we will need.
	 */
	for (page_idx = 0; page_idx < nr_to_read; page_idx++) {
		/* 算出page_offset，也就是相对于文件的页面偏移 */
		pgoff_t page_offset = offset + page_idx;
		/* 如果大于end_index,那么就退出吧 */
		if (page_offset > end_index)
			break;

		rcu_read_lock();
		/* 看一下这个page有没有被映射 */
		page = radix_tree_lookup(&mapping->page_tree, page_offset);
		rcu_read_unlock();
		if (page && !radix_tree_exceptional_entry(page))
			continue;
		/* 分配pagecache */
		page = __page_cache_alloc(gfp_mask);
		if (!page)
			break;
		/* 把page_offset设置到page->index中 */
		page->index = page_offset;
		/* 把page放入到page_pool里面去 */
		list_add(&page->lru, &page_pool);
		/* 将async_size的page标记为Readahead */
		if (page_idx == nr_to_read - lookahead_size)
			SetPageReadahead(page);
		ret++;
	}

	/*
	 * Now start the IO.  We ignore I/O errors - if the page is not
	 * uptodate then the caller will launch readpage again, and
	 * will then handle the error.
	 *
	 * 现在启动IO。我们忽略I/O错误-如果页面不是最新的，那么调用方将再次启动readpage，然后处理错误。
	 */
	if (ret)
		read_pages(mapping, filp, &page_pool, ret, gfp_mask);
	BUG_ON(!list_empty(&page_pool));
out:
	return ret;
}

/*
 * Chunk the readahead into 2 megabyte units, so that we don't pin too much
 * memory at once.
 */
int force_page_cache_readahead(struct address_space *mapping, struct file *filp,
		pgoff_t offset, unsigned long nr_to_read)
{
	if (unlikely(!mapping->a_ops->readpage && !mapping->a_ops->readpages))
		return -EINVAL;

	nr_to_read = min(nr_to_read, inode_to_bdi(mapping->host)->ra_pages);
	while (nr_to_read) {
		int err;

		unsigned long this_chunk = (2 * 1024 * 1024) / PAGE_SIZE;

		if (this_chunk > nr_to_read)
			this_chunk = nr_to_read;
		err = __do_page_cache_readahead(mapping, filp,
						offset, this_chunk, 0);
		if (err < 0)
			return err;

		offset += this_chunk;
		nr_to_read -= this_chunk;
	}
	return 0;
}

/*
 * Set the initial window size, round to next power of 2 and square
 * for small size, x 4 for medium, and x 2 for large
 * for 128k (32 page) max ra
 * 1-8 page = 32k initial, > 8 page = 128k initial
 */
/*
 * 设置初始窗口大小，四舍五入到2的次幂，
 * 平方表示小，x4表示中等，x2表示大
 * 对于128k（32页）max ra
 * 1-8页=32k初始，>8页=128k 初始
 */
static unsigned long get_init_ra_size(unsigned long size, unsigned long max)
{
	unsigned long newsize = roundup_pow_of_two(size);

	if (newsize <= max / 32)
		newsize = newsize * 4;
	else if (newsize <= max / 4)
		newsize = newsize * 2;
	else
		newsize = max;

	return newsize;
}

/*
 *  Get the previous window size, ramp it up, and
 *  return it as the new window size.
 */
static unsigned long get_next_ra_size(struct file_ra_state *ra,
						unsigned long max)
{
	/* ra->size表示当前预读的页数 */
	unsigned long cur = ra->size;
	unsigned long newsize;
	/* 如果当前预读的页数小于最大预读数/16
	 * 那么预读大小乘以4
	 * 否则乘以2
	 */
	if (cur < max / 16)
		newsize = 4 * cur;
	else
		newsize = 2 * cur;

	return min(newsize, max);
}

/*
 * On-demand readahead design.
 *
 * The fields in struct file_ra_state represent the most-recently-executed
 * readahead attempt:
 *
 *                        |<----- async_size ---------|
 *     |------------------- size -------------------->|
 *     |==================#===========================|
 *     ^start             ^page marked with PG_readahead
 *
 * To overlap application thinking time and disk I/O time, we do
 * `readahead pipelining': Do not wait until the application consumed all
 * readahead pages and stalled on the missing page at readahead_index;
 * Instead, submit an asynchronous readahead I/O as soon as there are
 * only async_size pages left in the readahead window. Normally async_size
 * will be equal to size, for maximum pipelining.
 *
 * In interleaved sequential reads, concurrent streams on the same fd can
 * be invalidating each other's readahead state. So we flag the new readahead
 * page at (start+size-async_size) with PG_readahead, and use it as readahead
 * indicator. The flag won't be set on already cached pages, to avoid the
 * readahead-for-nothing fuss, saving pointless page cache lookups.
 *
 * prev_pos tracks the last visited byte in the _previous_ read request.
 * It should be maintained by the caller, and will be used for detecting
 * small random reads. Note that the readahead algorithm checks loosely
 * for sequential patterns. Hence interleaved reads might be served as
 * sequential ones.
 *
 * There is a special-case: if the first page which the application tries to
 * read happens to be the first page of the file, it is assumed that a linear
 * read is about to happen and the window is immediately set to the initial size
 * based on I/O request size and the max_readahead.
 *
 * The code ramps up the readahead size aggressively at first, but slow down as
 * it approaches max_readhead.
 */
/* 按需预读设计
 * struct file_ra_state中的字段表示最近执行的预读尝试：
 * 为了使应用程序思考时间和磁盘I/O时间重叠，我们进行了“预读流水线”：不要等到应用程序消耗了所有预读页面并在readahead_index的缺失页面上停滞；
 * 相反，只要预读窗口中只剩下async_size页面，就提交异步预读I/O。通常，async_size将等于size，以实现最大流水线.
 *
 * 在交错顺序读取中，同一fd上的并发流可能会使彼此的预读状态无效.
 * 因此，我们用PG_readahead在（start+size-async_size）处标记新的预读页面，并将其用作预读指示符.
 * 该标志不会在已经缓存的页面上设置，以避免无需大惊小怪的预读，从而节省毫无意义的页面缓存查找.
 *
 * prev_pos跟踪前一次读请求中最后访问的字节.
 * 它应该由调用者维护,并将用于检测小的随机读取.
 * 请注意，预读算法检查顺序模式的松散。因此，交错读取可以作为顺序读取.
 *
 * 有一种特殊情况：如果应用程序试图读取的第一页恰好是文件的第一页，则假设即将发生线性读取，
 * 并且窗口立即设置为基于I/O请求大小和max_readahead的初始化大小
 *
 * 代码一开始会大幅增加预读大小，但随着接近max_readhead，速度会减慢.
 */

/*
 * Count contiguously cached pages from @offset-1 to @offset-@max,
 * this count is a conservative estimation of
 * 	- length of the sequential read sequence, or
 * 	- thrashing threshold in memory tight systems
 */
static pgoff_t count_history_pages(struct address_space *mapping,
				   pgoff_t offset, unsigned long max)
{
	pgoff_t head;

	rcu_read_lock();
	head = page_cache_prev_hole(mapping, offset - 1, max);
	rcu_read_unlock();

	return offset - 1 - head;
}

/*
 * page cache context based read-ahead
 */
static int try_context_readahead(struct address_space *mapping,
				 struct file_ra_state *ra,
				 pgoff_t offset,
				 unsigned long req_size,
				 unsigned long max)
{
	pgoff_t size;

	size = count_history_pages(mapping, offset, max);

	/*
	 * not enough history pages:
	 * it could be a random read
	 */
	if (size <= req_size)
		return 0;

	/*
	 * starts from beginning of file:
	 * it is a strong indication of long-run stream (or whole-file-read)
	 */
	if (size >= offset)
		size *= 2;

	ra->start = offset;
	ra->size = min(size + req_size, max);
	ra->async_size = 1;

	return 1;
}

/*
 * A minimal readahead algorithm for trivial sequential/random reads.
 */
static unsigned long
ondemand_readahead(struct address_space *mapping,
		   struct file_ra_state *ra, struct file *filp,
		   bool hit_readahead_marker, pgoff_t offset,
		   unsigned long req_size)
{
	/* 获得最大的预读页面 */
	unsigned long max = ra->ra_pages;
	pgoff_t prev_offset;

	/*
	 * start of file
	 */
	/* 第一次读文件成立，从文件头开始预读
	 * 也就是如果是文件头，跳转到initial_readahead */
	if (!offset)
		goto initial_readahead;

	/*
	 * It's the expected callback offset, assume sequential access.
	 * Ramp up sizes, and push forward the readahead window.
	 *
	 * 这是预期的回调偏移量，假设按顺序访问。加大尺寸，并向前推进预读窗口。
	 */
	/* start表示当前预读的第一页的索引
	 * size表示当前预读的页数
	 * async_size指定一个阈值，预读窗口剩余这么多页时，就开始异步预读
	 * 刚好等于说明是个连续顺序读 ?
	 */
	if ((offset == (ra->start + ra->size - ra->async_size) ||
	     offset == (ra->start + ra->size))) {
		ra->start += ra->size;
		/* 加大预读的步伐 */
		ra->size = get_next_ra_size(ra, max);
		/* 把预读的阈值设置成size */
		ra->async_size = ra->size;
		goto readit;
	}

	/*
	 * Hit a marked page without valid readahead state.
	 * E.g. interleaved reads.
	 * Query the pagecache for async_size, which normally equals to
	 * readahead size. Ramp it up and use it as the new readahead size.
	 */
	/* 在没有有效预读状态的情况下点击标记的页面.
	 * 例如，交错读取。
	 * 查询页面缓存中的async_size，它通常等于预读大小。将其放大并用作新的预读大小.
	 */
	/* 读取到PG_readahead的page时启动异步预读 */
	if (hit_readahead_marker) {
		pgoff_t start;

		rcu_read_lock();
		/* 从offset开始，找下一个未在cache中的page作为下一次预读window的起始page */
		start = page_cache_next_hole(mapping, offset + 1, max);
		rcu_read_unlock();
		/* 如果找不到未cache的page了或者如果找到的start - offeset大于max
		 * 那么直接返回算了
		 */
		if (!start || start - offset > max)
			return 0;
		/* 预读的start 设置为我们刚刚找到的那个 */
		ra->start = start;
		/* start - offset 看成是老的async_size */
		ra->size = start - offset;	/* old async_size */
		/* 加上我们req_size */
		ra->size += req_size;
		/* 然后加上我们扩充后的预读size */
		ra->size = get_next_ra_size(ra, max);
		/* 复制给asyn_size */
		ra->async_size = ra->size;
		goto readit;
	}

	/*
	 * oversize read
	 */
	/*  一次性读取大量page，直接开始新一轮预读 */
	if (req_size > max)
		goto initial_readahead;

	/*
	 * sequential cache miss
	 * trivial case: (offset - prev_offset) == 1
	 * unaligned reads: (offset - prev_offset) == 0
	 */
	/* 探测到有新的顺序读，开始新一轮预读
	 * 顺序缓存未命中
	 * 琐碎情况：（offset-prev_offset）==1
	 * 未对齐的读取：（offset-prev_offset）==0
	 *
	 */
	prev_offset = (unsigned long long)ra->prev_pos >> PAGE_SHIFT;
	if (offset - prev_offset <= 1UL)
		goto initial_readahead;

	/*
	 * Query the page cache and look for the traces(cached history pages)
	 * that a sequential stream would leave behind.
	 */
	/* 根据offset之前的page在cache里的情况判断是否是顺序读 */
	if (try_context_readahead(mapping, ra, offset, req_size, max))
		goto readit;

	/*
	 * standalone, small random read
	 * Read as is, and do not pollute the readahead state.
	 */
	/* 判断为随机读，仅读取请求大小的page，不改变file_ra_state和PG_readahead状态 */
	return __do_page_cache_readahead(mapping, filp, offset, req_size, 0);

initial_readahead:
	ra->start = offset;
	ra->size = get_init_ra_size(req_size, max);
	/* async_size如果ra->size > reqsize的情况，那么就取ra->size-req_size
	 * 否则就取ra->size
	 */
	ra->async_size = ra->size > req_size ? ra->size - req_size : ra->size;

readit:
	/*
	 * Will this read hit the readahead marker made by itself?
	 * If so, trigger the readahead marker hit now, and merge
	 * the resulted next readahead window into the current one.
	 */
	if (offset == ra->start && ra->size == ra->async_size) {
		ra->async_size = get_next_ra_size(ra, max);
		ra->size += ra->async_size;
	}
	/* 根据file_ra_state调用__do_page_cache_readahead()读取相应page，
	 * 设置(start+size-async_size)的page为PG_readahead
	 */
	return ra_submit(ra, mapping, filp);
}

/**
 * page_cache_sync_readahead - generic file readahead
 * @mapping: address_space which holds the pagecache and I/O vectors
 * @ra: file_ra_state which holds the readahead state
 * @filp: passed on to ->readpage() and ->readpages()
 * @offset: start offset into @mapping, in pagecache page-sized units
 * @req_size: hint: total size of the read which the caller is performing in
 *            pagecache pages
 *
 * page_cache_sync_readahead() should be called when a cache miss happened:
 * it will submit the read.  The readahead logic may decide to piggyback more
 * pages onto the read request if access patterns suggest it will improve
 * performance.
 */
/* page_cache_sync_readahead-通用文件readahead
 * @mapping：保存pagecache和I/O矢量的address_space
 * @ra:file_ra_state，它保持预读状态
 * @filp：传递到->readpage（）和->readpages（）
 * @offset：开始偏移到@mapping，以页面缓存页面大小为单位
 * @req_size:hint：caller执行在pageche pages整个读的大小
 *
 * 当缓存未命中时，应调用page_cache_sync_readahead（）：它将提交读取.
 * 如果访问模式表明预读逻辑将提高性能，则预读逻辑可以决定将更多页面装载到读取请求上
 */
void page_cache_sync_readahead(struct address_space *mapping,
			       struct file_ra_state *ra, struct file *filp,
			       pgoff_t offset, unsigned long req_size)
{
	/* no read-ahead */
	/* 如果当前预读最大页面为NULL，那么直接返回 */
	if (!ra->ra_pages)
		return;

	/* be dumb */
	/* 随机读 */
	if (filp && (filp->f_mode & FMODE_RANDOM)) {
		force_page_cache_readahead(mapping, filp, offset, req_size);
		return;
	}

	/* do read-ahead */
	ondemand_readahead(mapping, ra, filp, false, offset, req_size);
}
EXPORT_SYMBOL_GPL(page_cache_sync_readahead);

/**
 * page_cache_async_readahead - file readahead for marked pages
 * @mapping: address_space which holds the pagecache and I/O vectors
 * @ra: file_ra_state which holds the readahead state
 * @filp: passed on to ->readpage() and ->readpages()
 * @page: the page at @offset which has the PG_readahead flag set
 * @offset: start offset into @mapping, in pagecache page-sized units
 * @req_size: hint: total size of the read which the caller is performing in
 *            pagecache pages
 *
 * page_cache_async_readahead() should be called when a page is used which
 * has the PG_readahead flag; this is a marker to suggest that the application
 * has used up enough of the readahead window that we should start pulling in
 * more pages.
 */
void
page_cache_async_readahead(struct address_space *mapping,
			   struct file_ra_state *ra, struct file *filp,
			   struct page *page, pgoff_t offset,
			   unsigned long req_size)
{
	/* no read-ahead */
	if (!ra->ra_pages)
		return;

	/*
	 * Same bit is used for PG_readahead and PG_reclaim.
	 */
	if (PageWriteback(page))
		return;

	ClearPageReadahead(page);

	/*
	 * Defer asynchronous read-ahead on IO congestion.
	 */
	if (inode_read_congested(mapping->host))
		return;

	/* do read-ahead */
	ondemand_readahead(mapping, ra, filp, true, offset, req_size);
}
EXPORT_SYMBOL_GPL(page_cache_async_readahead);

static ssize_t
do_readahead(struct address_space *mapping, struct file *filp,
	     pgoff_t index, unsigned long nr)
{
	if (!mapping || !mapping->a_ops)
		return -EINVAL;

	/*
	 * Readahead doesn't make sense for DAX inodes, but we don't want it
	 * to report a failure either.  Instead, we just return success and
	 * don't do any work.
	 */
	if (dax_mapping(mapping))
		return 0;

	return force_page_cache_readahead(mapping, filp, index, nr);
}

SYSCALL_DEFINE3(readahead, int, fd, loff_t, offset, size_t, count)
{
	ssize_t ret;
	struct fd f;

	ret = -EBADF;
	f = fdget(fd);
	if (f.file) {
		if (f.file->f_mode & FMODE_READ) {
			struct address_space *mapping = f.file->f_mapping;
			pgoff_t start = offset >> PAGE_SHIFT;
			pgoff_t end = (offset + count - 1) >> PAGE_SHIFT;
			unsigned long len = end - start + 1;
			ret = do_readahead(mapping, f.file, start, len);
		}
		fdput(f);
	}
	return ret;
}
