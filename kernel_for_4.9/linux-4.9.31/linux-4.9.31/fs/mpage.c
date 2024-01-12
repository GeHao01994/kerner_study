/*
 * fs/mpage.c
 *
 * Copyright (C) 2002, Linus Torvalds.
 *
 * Contains functions related to preparing and submitting BIOs which contain
 * multiple pagecache pages.
 *
 * 15May2002	Andrew Morton
 *		Initial version
 * 27Jun2002	axboe@suse.de
 *		use bio_add_page() to build bio's just the right size
 */

#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/mm.h>
#include <linux/kdev_t.h>
#include <linux/gfp.h>
#include <linux/bio.h>
#include <linux/fs.h>
#include <linux/buffer_head.h>
#include <linux/blkdev.h>
#include <linux/highmem.h>
#include <linux/prefetch.h>
#include <linux/mpage.h>
#include <linux/mm_inline.h>
#include <linux/writeback.h>
#include <linux/backing-dev.h>
#include <linux/pagevec.h>
#include <linux/cleancache.h>
#include "internal.h"

/*
 * I/O completion handler for multipage BIOs.
 *
 * The mpage code never puts partial pages into a BIO (except for end-of-file).
 * If a page does not map to a contiguous run of blocks then it simply falls
 * back to block_read_full_page().
 *
 * Why is this?  If a page's completion depends on a number of different BIOs
 * which can complete in any order (or at the same time) then determining the
 * status of that page is hard.  See end_buffer_async_read() for the details.
 * There is no point in duplicating all that complexity.
 */
static void mpage_end_io(struct bio *bio)
{
	struct bio_vec *bv;
	int i;

	bio_for_each_segment_all(bv, bio, i) {
		struct page *page = bv->bv_page;
		page_endio(page, op_is_write(bio_op(bio)), bio->bi_error);
	}

	bio_put(bio);
}

static struct bio *mpage_bio_submit(int op, int op_flags, struct bio *bio)
{
	bio->bi_end_io = mpage_end_io;
	bio_set_op_attrs(bio, op, op_flags);
	guard_bio_eod(op, bio);
	submit_bio(bio);
	return NULL;
}

static struct bio *
mpage_alloc(struct block_device *bdev,
		sector_t first_sector, int nr_vecs,
		gfp_t gfp_flags)
{
	struct bio *bio;

	/* Restrict the given (page cache) mask for slab allocations */
	gfp_flags &= GFP_KERNEL;
	bio = bio_alloc(gfp_flags, nr_vecs);

	if (bio == NULL && (current->flags & PF_MEMALLOC)) {
		while (!bio && (nr_vecs /= 2))
			bio = bio_alloc(gfp_flags, nr_vecs);
	}

	if (bio) {
		bio->bi_bdev = bdev;
		bio->bi_iter.bi_sector = first_sector;
	}
	return bio;
}

/*
 * support function for mpage_readpages.  The fs supplied get_block might
 * return an up to date buffer.  This is used to map that buffer into
 * the page, which allows readpage to avoid triggering a duplicate call
 * to get_block.
 *
 * The idea is to avoid adding buffers to pages that don't already have
 * them.  So when the buffer is up to date and the page size == block size,
 * this marks the page up to date instead of adding new buffers.
 */
static void 
map_buffer_to_page(struct page *page, struct buffer_head *bh, int page_block) 
{
	struct inode *inode = page->mapping->host;
	struct buffer_head *page_bh, *head;
	int block = 0;

	if (!page_has_buffers(page)) {
		/*
		 * don't make any buffers if there is only one buffer on
		 * the page and the page just needs to be set up to date
		 */
		if (inode->i_blkbits == PAGE_SHIFT &&
		    buffer_uptodate(bh)) {
			SetPageUptodate(page);    
			return;
		}
		create_empty_buffers(page, 1 << inode->i_blkbits, 0);
	}
	head = page_buffers(page);
	page_bh = head;
	do {
		if (block == page_block) {
			page_bh->b_state = bh->b_state;
			page_bh->b_bdev = bh->b_bdev;
			page_bh->b_blocknr = bh->b_blocknr;
			break;
		}
		page_bh = page_bh->b_this_page;
		block++;
	} while (page_bh != head);
}

/*
 * This is the worker routine which does all the work of mapping the disk
 * blocks and constructs largest possible bios, submits them for IO if the
 * blocks are not contiguous on the disk.
 *
 * We pass a buffer_head back and forth and use its buffer_mapped() flag to
 * represent the validity of its disk mapping and to decide when to do the next
 * get_block() call.
 */

/* 理解do_mpage_readpage函数的关键在于它的应用,以及为此而设置的参数.
 * 尽管从我们的流程走来,只调用了一次.
 * 但是,在mpage_readpages函数中,这个函数被反复调用,可能将多个页面组织在一个bio中提交
 * 为此需要传递bio参数,last_block_in_bio参数记录它在磁盘上最后一个逻辑块的编号,
 * 处理新的页面时可根据它来判断是否和以前的请求在磁盘上连续.
 * 此外,我们还将buffer_head前后传递,使用它的buffer_mapped标志来表示它的磁盘映射的有效性,
 * 以确定什么时候需要进行下一次get_block的调用
 *
 * 因此这个函数的所有参数说明如下: 第一个参数bio为指向通用块层请求描述符的指针,
 * 第二个参数page为指向页面描述符的指针,第三个参数nr_pages为剩余的页面数目,
 * 这主要用在多个页面的场合下,指导分配包含多少个请求段的bio,实际上,是一次调用
 * do_mpage_readpage,还是只处理一个页面.
 * 第四个参数last_block_in_bio为输入/输出参数,仅在bio不为NULL时有效,表示请求的
 * 最后一个逻辑块在磁盘上的编号;
 * 第五个参数map_bh指向用于实现从文件逻辑块编号到磁盘逻辑块编号映射到缓冲头描述符的指针;
 * 第六个参数first_logical_block为输入/输出参数,仅在map_bh被映射时有效,表示映射的第一个文件逻辑块的编号,
 * 映射长度保存在缓冲头描述符的b_size域.
 * 第七个参数为用于从文件逻辑块映射到磁盘逻辑块的映射函数的指针.
 * 函数返回指向已构造好,但还没提交的bio的指针;在构造的bio已提交,或者采用缓冲页面方式处理的情况下,返回NULL
 */
static struct bio *
do_mpage_readpage(struct bio *bio, struct page *page, unsigned nr_pages,
		sector_t *last_block_in_bio, struct buffer_head *map_bh,
		unsigned long *first_logical_block, get_block_t get_block,
		gfp_t gfp)
{
	struct inode *inode = page->mapping->host;
	/* blkbits为逻辑块的位数 */
	const unsigned blkbits = inode->i_blkbits;
	/* blocks_per_page 表示每个页面包含逻辑块的数目 */
	const unsigned blocks_per_page = PAGE_SIZE >> blkbits;
	/* blocksize表示逻辑块的字节数 */
	const unsigned blocksize = 1 << blkbits;
	/* block_in_file为文件中的逻辑块的编号 */
	sector_t block_in_file;
	/* last_block为页面最后一个字节的逻辑块编号 */
	sector_t last_block;
	/* last_block_in_file为文件最后一个逻辑块编号 */
	sector_t last_block_in_file;
	/* blocks为映射数组,数组元素个数取决于每个页面包含的逻辑块数目 */
	sector_t blocks[MAX_BUF_PER_PAGE];
	/* page_block为页面中正处理的逻辑块编号 */
	unsigned page_block;
	/* first_hole为空洞起始位置在页面对应的数据块编号 */
	unsigned first_hole = blocks_per_page;
	struct block_device *bdev = NULL;
	int length;
	int fully_mapped = 1;
	/* nblocks为每个映射数据块所包含的逻辑块数目 */
	unsigned nblocks;
	unsigned relative_block;
	/* 首先检查页面PG_private标志;
	 * 若该标志已设置,则表明:(1)它是缓冲页面(即该页面与一个buffer head链表关联),且已经从磁盘上读取到内存中;
	 * (2)页面中的块在磁盘上不是相邻的;这样的话,就跳转到confused,一次读取页面的一个块
	 */
	if (page_has_buffers(page))
		goto confused;

	block_in_file = (sector_t)page->index << (PAGE_SHIFT - blkbits);
	last_block = block_in_file + nr_pages * blocks_per_page;
	last_block_in_file = (i_size_read(inode) + blocksize - 1) >> blkbits;
	if (last_block > last_block_in_file)
		last_block = last_block_in_file;
	page_block = 0;

	/*
	 * Map blocks using the result from the previous get_blocks call first.
	 */
	/* 算出buffer_head的块长度 */
	nblocks = map_bh->b_size >> blkbits;
	/* first_logical_block为映射的第一个文件逻辑块的编号，因此可知道有效映射的文件逻辑块范围
	 * 对于在该范围内的文件逻辑块编号,将对应的磁盘上的逻辑块编号记录在block数组中.
	 * 如果映射全部用光,清除缓存头的映射标志,以便下次重新调用get_block回调函数获取后面的逻辑信息
	 */
	if (buffer_mapped(map_bh) && block_in_file > *first_logical_block &&
			block_in_file < (*first_logical_block + nblocks)) {
		unsigned map_offset = block_in_file - *first_logical_block;
		unsigned last = nblocks - map_offset;

		for (relative_block = 0; ; relative_block++) {
			if (relative_block == last) {
				clear_buffer_mapped(map_bh);
				break;
			}
			if (page_block == blocks_per_page)
				break;
			blocks[page_block] = map_bh->b_blocknr + map_offset +
						relative_block;
			page_block++;
			block_in_file++;
		}
		bdev = map_bh->b_bdev;
	}

	/*
	 * Then do more get_blocks calls until we are done with this page.
	 */
	map_bh->b_page = page;
	/* 对于页内的每一块都来循环一下 */
	while (page_block < blocks_per_page) {
		map_bh->b_state = 0;
		map_bh->b_size = 0;
		/* block_in_file为文件中的逻辑块的编号
		 * last_block页面最后一个字节的逻辑块编号
		 * 是block_in_file + nr_pages * blocks_per_page
		 */
		if (block_in_file < last_block) {
			map_bh->b_size = (last_block-block_in_file) << blkbits;
			/* 调用get_block再次从文件逻辑块到磁盘逻辑块的映射,如果函数返回错误码,
			 * 跳转到标号confused 继续执行;
			 * 如果返回0,则更新*firsh_logical_block的值
			 */
			if (get_block(inode, block_in_file, map_bh, 0))
				goto confused;
			*first_logical_block = block_in_file;
		}
		/* 尽管上面函数返回0,作为其参数传入的缓冲头可能还是没有设置BH_Mapped标志,
		 * 这出现在后面会讲到的“断链”的情况下.
		 * 这个时候,清零局部变量fully_mapped,如果first_hole没有设置，那么设置它.
		 * 然后继续处理下一个逻辑块
		 */
		if (!buffer_mapped(map_bh)) {
			fully_mapped = 0;
			if (first_hole == blocks_per_page)
				first_hole = page_block;
			page_block++;
			block_in_file++;
			continue;
		}

		/* some filesystems will copy data into the page during
		 * the get_block call, in which case we don't want to
		 * read it again.  map_buffer_to_page copies the data
		 * we just collected from get_block into the page's buffers
		 * so readpage doesn't have to repeat the get_block call
		 */
		/* 某些文件系统会在get_block函数进行映射时复制数据到页面中,这就没必要在此从磁盘读取了.
		 * 调用map_buffer_to_page复制我们从get_block收集的数据到页面缓冲区中,然后跳转到标号confused
		 * 处继续执行，这样readpage不需要重复调用get_block
		 */
		if (buffer_uptodate(map_bh)) {
			map_buffer_to_page(page, map_bh, page_block);
			goto confused;
		}
		/* 程序继续运行,那一定是缓存头已经有映射的情况.
		 * 如果此时first_hole已经设置，说明这个页面在经过一个“空洞”后有重新被映射,没有办法用bio方式来提交
		 * 跳转到confused标号处
		 */
		if (first_hole != blocks_per_page)
			goto confused;		/* hole -> non-hole */

		/* Contiguous blocks? */
		/* 如果这个逻辑块不是页面的第一个,判断它是否和前一个逻辑块在磁盘上也是连续的.
		 * 如果不是,也没有办法用bio方式来提交,跳转到confused标号处
		 */
		if (page_block && blocks[page_block-1] != map_bh->b_blocknr-1)
			goto confused;
		/* 根据缓冲头的映射信息,记录页面每个逻辑块在磁盘上对应的逻辑块编号.
		 * 如果映射信息用光,清除缓冲头的BH_mapped标志,退出循环;
		 * 如果这个页面的所有逻辑块都已经处理完,也退出循环,如果此时映射信息可能还没有用光,则留给下一个页面
		 */
		nblocks = map_bh->b_size >> blkbits;
		for (relative_block = 0; ; relative_block++) {
			if (relative_block == nblocks) {
				clear_buffer_mapped(map_bh);
				break;
			} else if (page_block == blocks_per_page)
				break;
			blocks[page_block] = map_bh->b_blocknr+relative_block;
			page_block++;
			block_in_file++;
		}
		bdev = map_bh->b_bdev;
	}
	/* 页面的所有逻辑块都经过上面的处理后,可以采用bio方式提交的情况就清除了.
	 * 只可能会是三种情况.
	 * 页面的逻辑块被映射到磁盘上连续的逻辑块,这是设置页面的映射标志;
	 * 页面只有前面一些逻辑块被映射到磁盘,这时清0没有被映射部分的数据;
	 * 整个压面都没有被映射,清除整个页面,并设置最新标志,因为不需要再从磁盘上读取数据了,解锁页面后,直接返回传入的bio,这相当于跳过了
	 * 本页面.
	 */
	if (first_hole != blocks_per_page) {
		zero_user_segment(page, first_hole << blkbits, PAGE_SIZE);
		if (first_hole == 0) {
			SetPageUptodate(page);
			unlock_page(page);
			goto out;
		}
	} else if (fully_mapped) {
		SetPageMappedToDisk(page);
	}

	if (fully_mapped && blocks_per_page == 1 && !PageUptodate(page) &&
	    cleancache_get_page(page) == 0) {
		SetPageUptodate(page);
		goto confused;
	}

	/*
	 * This page will go to BIO.  Do we need to send this BIO off first?
	 */
	/* 如果传入了一个bio,需要判断本页面第一个逻辑块和传入bio的最后一个逻辑块在磁盘上是否连续,也就是看
	 * 是否可以将本页面作为一个请求段加入传入的bio中.
	 * 如果不连续,那么mpage_bio_submit调用提交前面的bio,这个函数恒返回NULL
	 */
	if (bio && (*last_block_in_bio != blocks[0] - 1))
		bio = mpage_bio_submit(REQ_OP_READ, 0, bio);
	/* 如果传入的bio为NULL,或者传入的bio已提交,那么我们需要调用mpage_alloc重新分配一个bio.
	 * 该bio的请求段的数目依赖于nr_pages参数,这是基于后面所有页面都可以作为请求段被合并到
	 * 这个bio的假设.当然bio的请求段的数目也受限于块设备.如果bio分配失败,跳转到confused标号处,
	 * 因为我们没有办法按bio方式处理.
	 */
alloc_new:
	if (bio == NULL) {
		if (first_hole == blocks_per_page) {
			if (!bdev_read_page(bdev, blocks[0] << (blkbits - 9),
								page))
				goto out;
		}
		bio = mpage_alloc(bdev, blocks[0] << (blkbits - 9),
				min_t(int, nr_pages, BIO_MAX_PAGES), gfp);
		if (bio == NULL)
			goto confused;
	}
	/* 现在我们已经有一个bio,它可能通过参数传入的,或者是由函数新分配的.
	 * 现在将这个页面作为请求段添加到bio,具体调用了bio_add_page函数.
	 * 该请求段在页面中的偏移为0,而长度取决于first_hole的值,在没有空洞时,
	 * 它被设置成页面所包含的逻辑块数.
	 * 如果bio_add_page函数返回0,那么没办法将页面添加到现在的bio中,调用
	 * mpage_bio_submit函数提交了这个bio,然后重新分配一个bio,重复上面的过程
	 *
	 */
	length = first_hole << blkbits;
	if (bio_add_page(bio, page, length, 0) < length) {
		bio = mpage_bio_submit(REQ_OP_READ, 0, bio);
		goto alloc_new;
	}
	/* 本页面已经被添加到bio,我们最后需要决定是否应该提交这个bio,还是保留
	 * 它作为参数传递到下一次函数调用以便合并新的页面.
	 * 提交的情况有两种
	 * 1、合并后一个页面可能导致I/O失序,get_block函数会为映射缓冲头设置BH_boudary标志;
	 * 2、本页面后面部分有空洞,不会和后一个页面在磁盘上连续,因此后一个页面不可能被合并到bio.
	 */
	relative_block = block_in_file - *first_logical_block;
	nblocks = map_bh->b_size >> blkbits;
	if ((buffer_boundary(map_bh) && relative_block == nblocks) ||
	    (first_hole != blocks_per_page))
		bio = mpage_bio_submit(REQ_OP_READ, 0, bio);
	else /* 我们暂时不提交这个bio,返回之后,并通过参数last_block_in_bio返回bio在磁盘上的最后一个逻辑块编号,作为下一次调用这个函数时判断页面是否和bio在磁盘上连续的依据 */
		*last_block_in_bio = blocks[blocks_per_page - 1];
out:
	return bio;

confused:
	/* 处理本页面无法作为bio的请求段处理的情况 */
	if (bio)
		bio = mpage_bio_submit(REQ_OP_READ, 0, bio);
	if (!PageUptodate(page))
	        block_read_full_page(page, get_block);
	else
		unlock_page(page);
	goto out;
}

/**
 * mpage_readpages - populate an address space with some pages & start reads against them
 * @mapping: the address_space
 * @pages: The address of a list_head which contains the target pages.  These
 *   pages have their ->index populated and are otherwise uninitialised.
 *   The page at @pages->prev has the lowest file offset, and reads should be
 *   issued in @pages->prev to @pages->next order.
 * @nr_pages: The number of pages at *@pages
 * @get_block: The filesystem's block mapper function.
 *
 * This function walks the pages and the blocks within each page, building and
 * emitting large BIOs.
 *
 * If anything unusual happens, such as:
 *
 * - encountering a page which has buffers
 * - encountering a page which has a non-hole after a hole
 * - encountering a page with non-contiguous blocks
 *
 * then this code just gives up and calls the buffer_head-based read function.
 * It does handle a page which has holes at the end - that is a common case:
 * the end-of-file on blocksize < PAGE_SIZE setups.
 *
 * BH_Boundary explanation:
 *
 * There is a problem.  The mpage read code assembles several pages, gets all
 * their disk mappings, and then submits them all.  That's fine, but obtaining
 * the disk mappings may require I/O.  Reads of indirect blocks, for example.
 *
 * So an mpage read of the first 16 blocks of an ext2 file will cause I/O to be
 * submitted in the following order:
 * 	12 0 1 2 3 4 5 6 7 8 9 10 11 13 14 15 16
 *
 * because the indirect block has to be read to get the mappings of blocks
 * 13,14,15,16.  Obviously, this impacts performance.
 *
 * So what we do it to allow the filesystem's get_block() function to set
 * BH_Boundary when it maps block 11.  BH_Boundary says: mapping of the block
 * after this one will require I/O against a block which is probably close to
 * this one.  So you should push what I/O you have currently accumulated.
 *
 * This all causes the disk requests to be issued in the correct order.
 */
int
mpage_readpages(struct address_space *mapping, struct list_head *pages,
				unsigned nr_pages, get_block_t get_block)
{
	struct bio *bio = NULL;
	unsigned page_idx;
	sector_t last_block_in_bio = 0;
	struct buffer_head map_bh;
	unsigned long first_logical_block = 0;
	gfp_t gfp = readahead_gfp_mask(mapping);

	map_bh.b_state = 0;
	map_bh.b_size = 0;
	for (page_idx = 0; page_idx < nr_pages; page_idx++) {
		struct page *page = lru_to_page(pages);

		prefetchw(&page->flags);
		list_del(&page->lru);
		if (!add_to_page_cache_lru(page, mapping,
					page->index,
					gfp)) {
			bio = do_mpage_readpage(bio, page,
					nr_pages - page_idx,
					&last_block_in_bio, &map_bh,
					&first_logical_block,
					get_block, gfp);
		}
		put_page(page);
	}
	BUG_ON(!list_empty(pages));
	if (bio)
		mpage_bio_submit(REQ_OP_READ, 0, bio);
	return 0;
}
EXPORT_SYMBOL(mpage_readpages);

/*
 * This isn't called much at all
 */
/* 缓存页面构造(block_read_full_page)的bio是固定长度的,尽管在块I/O层可能会有合并的动作,但是他们比较
 * 代表不同的访问上下文.
 * linux为基于磁盘的文件系统提供另一种策略,构造尽可能大的bio向下层提交,
 * 对应的函数是mpage_readpage
 */

/* mpage_readpage函数有两个参数: 第一个为指向页面描述符的指针,其索引值确定了页面在文件地址空间的逻辑位置,
 * 也就是要读取数据的逻辑块编号;
 * 第二个为将文件逻辑块编号映射为磁盘块编号的回调函数,这种特定于具体的文件系统类型
 */
int mpage_readpage(struct page *page, get_block_t get_block)
{
	struct bio *bio = NULL;
	sector_t last_block_in_bio = 0;
	struct buffer_head map_bh;
	unsigned long first_logical_block = 0;
	gfp_t gfp = mapping_gfp_constraint(page->mapping, GFP_KERNEL);

	map_bh.b_state = 0;
	map_bh.b_size = 0;
	bio = do_mpage_readpage(bio, page, 1, &last_block_in_bio,
			&map_bh, &first_logical_block, get_block, gfp);
	if (bio)
		mpage_bio_submit(REQ_OP_READ, 0, bio);
	return 0;
}
EXPORT_SYMBOL(mpage_readpage);

/*
 * Writing is not so simple.
 *
 * If the page has buffers then they will be used for obtaining the disk
 * mapping.  We only support pages which are fully mapped-and-dirty, with a
 * special case for pages which are unmapped at the end: end-of-file.
 *
 * If the page has no buffers (preferred) then the page is mapped here.
 *
 * If all blocks are found to be contiguous then the page can go into the
 * BIO.  Otherwise fall back to the mapping's writepage().
 * 
 * FIXME: This code wants an estimate of how many pages are still to be
 * written, so it can intelligently allocate a suitably-sized BIO.  For now,
 * just allocate full-size (16-page) BIOs.
 */

struct mpage_data {
	struct bio *bio;
	sector_t last_block_in_bio;
	get_block_t *get_block;
	unsigned use_writepage;
};

/*
 * We have our BIO, so we can now mark the buffers clean.  Make
 * sure to only clean buffers which we know we'll be writing.
 */
static void clean_buffers(struct page *page, unsigned first_unmapped)
{
	unsigned buffer_counter = 0;
	struct buffer_head *bh, *head;
	if (!page_has_buffers(page))
		return;
	head = page_buffers(page);
	bh = head;

	do {
		if (buffer_counter++ == first_unmapped)
			break;
		clear_buffer_dirty(bh);
		bh = bh->b_this_page;
	} while (bh != head);

	/*
	 * we cannot drop the bh if the page is not uptodate or a concurrent
	 * readpage would fail to serialize with the bh and it would read from
	 * disk before we reach the platter.
	 */
	if (buffer_heads_over_limit && PageUptodate(page))
		try_to_free_buffers(page);
}

static int __mpage_writepage(struct page *page, struct writeback_control *wbc,
		      void *data)
{
	struct mpage_data *mpd = data;
	struct bio *bio = mpd->bio;
	struct address_space *mapping = page->mapping;
	struct inode *inode = page->mapping->host;
	const unsigned blkbits = inode->i_blkbits;
	unsigned long end_index;
	const unsigned blocks_per_page = PAGE_SIZE >> blkbits;
	sector_t last_block;
	sector_t block_in_file;
	sector_t blocks[MAX_BUF_PER_PAGE];
	unsigned page_block;
	unsigned first_unmapped = blocks_per_page;
	struct block_device *bdev = NULL;
	int boundary = 0;
	sector_t boundary_block = 0;
	struct block_device *boundary_bdev = NULL;
	int length;
	struct buffer_head map_bh;
	loff_t i_size = i_size_read(inode);
	int ret = 0;
	int op_flags = (wbc->sync_mode == WB_SYNC_ALL ?  WRITE_SYNC : 0);

	if (page_has_buffers(page)) {
		struct buffer_head *head = page_buffers(page);
		struct buffer_head *bh = head;

		/* If they're all mapped and dirty, do it */
		page_block = 0;
		do {
			BUG_ON(buffer_locked(bh));
			if (!buffer_mapped(bh)) {
				/*
				 * unmapped dirty buffers are created by
				 * __set_page_dirty_buffers -> mmapped data
				 */
				if (buffer_dirty(bh))
					goto confused;
				if (first_unmapped == blocks_per_page)
					first_unmapped = page_block;
				continue;
			}

			if (first_unmapped != blocks_per_page)
				goto confused;	/* hole -> non-hole */

			if (!buffer_dirty(bh) || !buffer_uptodate(bh))
				goto confused;
			if (page_block) {
				if (bh->b_blocknr != blocks[page_block-1] + 1)
					goto confused;
			}
			blocks[page_block++] = bh->b_blocknr;
			boundary = buffer_boundary(bh);
			if (boundary) {
				boundary_block = bh->b_blocknr;
				boundary_bdev = bh->b_bdev;
			}
			bdev = bh->b_bdev;
		} while ((bh = bh->b_this_page) != head);

		if (first_unmapped)
			goto page_is_mapped;

		/*
		 * Page has buffers, but they are all unmapped. The page was
		 * created by pagein or read over a hole which was handled by
		 * block_read_full_page().  If this address_space is also
		 * using mpage_readpages then this can rarely happen.
		 */
		goto confused;
	}

	/*
	 * The page has no buffers: map it to disk
	 */
	BUG_ON(!PageUptodate(page));
	block_in_file = (sector_t)page->index << (PAGE_SHIFT - blkbits);
	last_block = (i_size - 1) >> blkbits;
	map_bh.b_page = page;
	for (page_block = 0; page_block < blocks_per_page; ) {

		map_bh.b_state = 0;
		map_bh.b_size = 1 << blkbits;
		if (mpd->get_block(inode, block_in_file, &map_bh, 1))
			goto confused;
		if (buffer_new(&map_bh))
			unmap_underlying_metadata(map_bh.b_bdev,
						map_bh.b_blocknr);
		if (buffer_boundary(&map_bh)) {
			boundary_block = map_bh.b_blocknr;
			boundary_bdev = map_bh.b_bdev;
		}
		if (page_block) {
			if (map_bh.b_blocknr != blocks[page_block-1] + 1)
				goto confused;
		}
		blocks[page_block++] = map_bh.b_blocknr;
		boundary = buffer_boundary(&map_bh);
		bdev = map_bh.b_bdev;
		if (block_in_file == last_block)
			break;
		block_in_file++;
	}
	BUG_ON(page_block == 0);

	first_unmapped = page_block;

page_is_mapped:
	end_index = i_size >> PAGE_SHIFT;
	if (page->index >= end_index) {
		/*
		 * The page straddles i_size.  It must be zeroed out on each
		 * and every writepage invocation because it may be mmapped.
		 * "A file is mapped in multiples of the page size.  For a file
		 * that is not a multiple of the page size, the remaining memory
		 * is zeroed when mapped, and writes to that region are not
		 * written out to the file."
		 */
		unsigned offset = i_size & (PAGE_SIZE - 1);

		if (page->index > end_index || !offset)
			goto confused;
		zero_user_segment(page, offset, PAGE_SIZE);
	}

	/*
	 * This page will go to BIO.  Do we need to send this BIO off first?
	 */
	if (bio && mpd->last_block_in_bio != blocks[0] - 1)
		bio = mpage_bio_submit(REQ_OP_WRITE, op_flags, bio);

alloc_new:
	if (bio == NULL) {
		if (first_unmapped == blocks_per_page) {
			if (!bdev_write_page(bdev, blocks[0] << (blkbits - 9),
								page, wbc)) {
				clean_buffers(page, first_unmapped);
				goto out;
			}
		}
		bio = mpage_alloc(bdev, blocks[0] << (blkbits - 9),
				BIO_MAX_PAGES, GFP_NOFS|__GFP_HIGH);
		if (bio == NULL)
			goto confused;

		wbc_init_bio(wbc, bio);
	}

	/*
	 * Must try to add the page before marking the buffer clean or
	 * the confused fail path above (OOM) will be very confused when
	 * it finds all bh marked clean (i.e. it will not write anything)
	 */
	wbc_account_io(wbc, page, PAGE_SIZE);
	length = first_unmapped << blkbits;
	if (bio_add_page(bio, page, length, 0) < length) {
		bio = mpage_bio_submit(REQ_OP_WRITE, op_flags, bio);
		goto alloc_new;
	}

	clean_buffers(page, first_unmapped);

	BUG_ON(PageWriteback(page));
	set_page_writeback(page);
	unlock_page(page);
	if (boundary || (first_unmapped != blocks_per_page)) {
		bio = mpage_bio_submit(REQ_OP_WRITE, op_flags, bio);
		if (boundary_block) {
			write_boundary_block(boundary_bdev,
					boundary_block, 1 << blkbits);
		}
	} else {
		mpd->last_block_in_bio = blocks[blocks_per_page - 1];
	}
	goto out;

confused:
	if (bio)
		bio = mpage_bio_submit(REQ_OP_WRITE, op_flags, bio);

	if (mpd->use_writepage) {
		ret = mapping->a_ops->writepage(page, wbc);
	} else {
		ret = -EAGAIN;
		goto out;
	}
	/*
	 * The caller has a ref on the inode, so *mapping is stable
	 */
	mapping_set_error(mapping, ret);
out:
	mpd->bio = bio;
	return ret;
}

/**
 * mpage_writepages - walk the list of dirty pages of the given address space & writepage() all of them
 * @mapping: address space structure to write
 * @wbc: subtract the number of written pages from *@wbc->nr_to_write
 * @get_block: the filesystem's block mapper function.
 *             If this is NULL then use a_ops->writepage.  Otherwise, go
 *             direct-to-BIO.
 *
 * This is a library function, which implements the writepages()
 * address_space_operation.
 *
 * If a page is already under I/O, generic_writepages() skips it, even
 * if it's dirty.  This is desirable behaviour for memory-cleaning writeback,
 * but it is INCORRECT for data-integrity system calls such as fsync().  fsync()
 * and msync() need to guarantee that all the data which was dirty at the time
 * the call was made get new I/O started against them.  If wbc->sync_mode is
 * WB_SYNC_ALL then we were called for data integrity and we must wait for
 * existing IO to complete.
 */
int
mpage_writepages(struct address_space *mapping,
		struct writeback_control *wbc, get_block_t get_block)
{
	struct blk_plug plug;
	int ret;

	blk_start_plug(&plug);

	if (!get_block)
		ret = generic_writepages(mapping, wbc);
	else {
		struct mpage_data mpd = {
			.bio = NULL,
			.last_block_in_bio = 0,
			.get_block = get_block,
			.use_writepage = 1,
		};

		ret = write_cache_pages(mapping, wbc, __mpage_writepage, &mpd);
		if (mpd.bio) {
			int op_flags = (wbc->sync_mode == WB_SYNC_ALL ?
				  WRITE_SYNC : 0);
			mpage_bio_submit(REQ_OP_WRITE, op_flags, mpd.bio);
		}
	}
	blk_finish_plug(&plug);
	return ret;
}
EXPORT_SYMBOL(mpage_writepages);

int mpage_writepage(struct page *page, get_block_t get_block,
	struct writeback_control *wbc)
{
	struct mpage_data mpd = {
		.bio = NULL,
		.last_block_in_bio = 0,
		.get_block = get_block,
		.use_writepage = 0,
	};
	int ret = __mpage_writepage(page, wbc, &mpd);
	if (mpd.bio) {
		int op_flags = (wbc->sync_mode == WB_SYNC_ALL ?
			  WRITE_SYNC : 0);
		mpage_bio_submit(REQ_OP_WRITE, op_flags, mpd.bio);
	}
	return ret;
}
EXPORT_SYMBOL(mpage_writepage);
