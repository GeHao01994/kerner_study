/*
 *  linux/mm/page_io.c
 *
 *  Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 *
 *  Swap reorganised 29.12.95, 
 *  Asynchronous swapping added 30.12.95. Stephen Tweedie
 *  Removed race in async swapping. 14.4.1996. Bruno Haible
 *  Add swap of shared pages through the page cache. 20.2.1998. Stephen Tweedie
 *  Always use brw_page, life becomes simpler. 12 May 1998 Eric Biederman
 */

#include <linux/mm.h>
#include <linux/kernel_stat.h>
#include <linux/gfp.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <linux/bio.h>
#include <linux/swapops.h>
#include <linux/buffer_head.h>
#include <linux/writeback.h>
#include <linux/frontswap.h>
#include <linux/blkdev.h>
#include <linux/uio.h>
#include <asm/pgtable.h>

static struct bio *get_swap_bio(gfp_t gfp_flags,
				struct page *page, bio_end_io_t end_io)
{
	struct bio *bio;

	bio = bio_alloc(gfp_flags, 1);
	if (bio) {
		bio->bi_iter.bi_sector = map_swap_page(page, &bio->bi_bdev);
		bio->bi_iter.bi_sector <<= PAGE_SHIFT - 9;
		bio->bi_end_io = end_io;

		bio_add_page(bio, page, PAGE_SIZE, 0);
		BUG_ON(bio->bi_iter.bi_size != PAGE_SIZE);
	}
	return bio;
}

void end_swap_bio_write(struct bio *bio)
{
	struct page *page = bio->bi_io_vec[0].bv_page;

	if (bio->bi_error) {
		SetPageError(page);
		/*
		 * We failed to write the page out to swap-space.
		 * Re-dirty the page in order to avoid it being reclaimed.
		 * Also print a dire warning that things will go BAD (tm)
		 * very quickly.
		 *
		 * Also clear PG_reclaim to avoid rotate_reclaimable_page()
		 */
		set_page_dirty(page);
		pr_alert("Write-error on swap-device (%u:%u:%llu)\n",
			 imajor(bio->bi_bdev->bd_inode),
			 iminor(bio->bi_bdev->bd_inode),
			 (unsigned long long)bio->bi_iter.bi_sector);
		ClearPageReclaim(page);
	}
	end_page_writeback(page);
	bio_put(bio);
}

static void swap_slot_free_notify(struct page *page)
{
	struct swap_info_struct *sis;
	struct gendisk *disk;

	/*
	 * There is no guarantee that the page is in swap cache - the software
	 * suspend code (at least) uses end_swap_bio_read() against a non-
	 * swapcache page.  So we must check PG_swapcache before proceeding with
	 * this optimization.
	 */
	if (unlikely(!PageSwapCache(page)))
		return;

	sis = page_swap_info(page);
	if (!(sis->flags & SWP_BLKDEV))
		return;

	/*
	 * The swap subsystem performs lazy swap slot freeing,
	 * expecting that the page will be swapped out again.
	 * So we can avoid an unnecessary write if the page
	 * isn't redirtied.
	 * This is good for real swap storage because we can
	 * reduce unnecessary I/O and enhance wear-leveling
	 * if an SSD is used as the as swap device.
	 * But if in-memory swap device (eg zram) is used,
	 * this causes a duplicated copy between uncompressed
	 * data in VM-owned memory and compressed data in
	 * zram-owned memory.  So let's free zram-owned memory
	 * and make the VM-owned decompressed page *dirty*,
	 * so the page should be swapped out somewhere again if
	 * we again wish to reclaim it.
	 */
	disk = sis->bdev->bd_disk;
	if (disk->fops->swap_slot_free_notify) {
		swp_entry_t entry;
		unsigned long offset;

		entry.val = page_private(page);
		offset = swp_offset(entry);

		SetPageDirty(page);
		disk->fops->swap_slot_free_notify(sis->bdev,
				offset);
	}
}

static void end_swap_bio_read(struct bio *bio)
{
	struct page *page = bio->bi_io_vec[0].bv_page;

	if (bio->bi_error) {
		SetPageError(page);
		ClearPageUptodate(page);
		pr_alert("Read-error on swap-device (%u:%u:%llu)\n",
			 imajor(bio->bi_bdev->bd_inode),
			 iminor(bio->bi_bdev->bd_inode),
			 (unsigned long long)bio->bi_iter.bi_sector);
		goto out;
	}

	SetPageUptodate(page);
	swap_slot_free_notify(page);
out:
	unlock_page(page);
	bio_put(bio);
}

/* 内核接下来必须查找并比较交换区中所有块的扇区地址,确定各个块是否是连续的.
 * 如果不是连续的,即可确定不连续.内核首先对构成一页的块数执行此操作.
 * 如果各块的扇区地址是连续的,那么就在磁盘上找到了长度等于一页的连续区域.
 * add_swap_extent将该信息插入到区间数据结构中.
 * 接下来重复整个操作,从下一个尚未检查扇区地址的文件块开始.
 * 在内核确认该页上的各扇区在磁盘上也是连续的之后,再次调用add_swap_extent将该信息添加到区间链表.
 * 如果每次调用add_swap_extent都向区间链表添加一个新的链表元素,是不可能合并邻接的连续
 * 区域从而构建长于一页的连续区的.因而,add_swap_extent试图自动保持链表尽可能紧凑.
 * 在添加一个新项时,如果其起始扇区紧接着最后一项的结束扇区(换言之,即最后一个swap_extent的
 * start_block 和 nr_pages 成员之和等于新项的起始扇区),则自动创建一个合并项,将两个项的数据
 * 合并起来.这确保了区间链表包含的数据项尽可能少.
 * 但在内核遇到不连续时,会如何处理呢?由于setup_swap_extents 只检查长度为一页的区域,
 * 当前区域完全可以丢弃.该区域没有任何用处,因为页交换的最小单位是一页.在发现扇区地址不连
 * 续时,内核将从下一个文件块的扇区地址重新开始搜索.该过程会重复下去,直至发现下一个在硬盘
 * 上连续的页.这种情况下,如果使用 add_swap_extent 将一个新数据项添加到区间链表,最后一项的
 * 结束扇区地址和新项的起始扇区地址不再匹配.这意味着这两个项无法合并,内核必须创建一个新的
 * 链表元素.
 * 上述过程会一直重复下去,直至已经处理了交换区中所有的块.在处理完成后,最后一步是将可
 * 用页的数目输入到相关的 swap_info 中.
 */
int generic_swapfile_activate(struct swap_info_struct *sis,
				struct file *swap_file,
				sector_t *span)
{
	/* 拿到对应文件的地址空间 */
	struct address_space *mapping = swap_file->f_mapping;
	struct inode *inode = mapping->host;
	unsigned blocks_per_page;
	unsigned long page_no;
	unsigned blkbits;
	sector_t probe_block;
	sector_t last_block;
	sector_t lowest_block = -1;
	sector_t highest_block = 0;
	int nr_extents = 0;
	int ret;

	/* 拿到块的大小 */
	blkbits = inode->i_blkbits;
	/* 算出每页有多少块 */
	blocks_per_page = PAGE_SIZE >> blkbits;

	/*
	 * Map all the blocks into the extent list.  This code doesn't try
	 * to be very smart.
	 *
	 * 将所有块映射到范围列表中. 这段代码并没有试图变得非常聪明.
	 */
	probe_block = 0;
	page_no = 0;
	/* 拿到last_block */
	last_block = i_size_read(inode) >> blkbits;
	/* 这边就是对每个块进行循环 */
	while ((probe_block + blocks_per_page) <= last_block &&
			page_no < sis->max) {
		unsigned block_in_page;
		sector_t first_block;

		cond_resched();
		/* 如果交换区是文件,内核需要完成的工作会多一些,因为必须逐个扫描该文件的各个块,来确定
		 * 块是如何分配到扇区的.
		 * bmap函数即用于该目的.它是虚拟文件系统的一部分,调用了特定文件系统的地址空间操作中的bmap方法.
		 * 这里不详细讲述各个特定文件系统的实现,因为它们都会得出同样的
		 * 结果,即给定块号的硬盘扇区编号
		 */
		first_block = bmap(inode, probe_block);
		if (first_block == 0)
			goto bad_bmap;

		/*
		 * It must be PAGE_SIZE aligned on-disk
		 * 它必须在磁盘上与PAGE_SIZE对齐
		 */
		if (first_block & (blocks_per_page - 1)) {
			probe_block++;
			goto reprobe;
		}

		/* 这里就是判断该block到blocks_per_page是否连续 */
		for (block_in_page = 1; block_in_page < blocks_per_page;
					block_in_page++) {
			sector_t block;

			block = bmap(inode, probe_block + block_in_page);
			if (block == 0)
				goto bad_bmap;
			/* 如果不连续,那么probe_block++,跳过该block */
			if (block != first_block + block_in_page) {
				/* Discontiguity */
				probe_block++;
				goto reprobe;
			}
		}

		/* 算first_block需要转换为以页面为单位对齐 */
		first_block >>= (PAGE_SHIFT - blkbits);
		/* 有page_no */
		if (page_no) {	/* exclude the header page */
			/* 设置lowest_block和highest_block */
			if (first_block < lowest_block)
				lowest_block = first_block;
			if (first_block > highest_block)
				highest_block = first_block;
		}

		/*
		 * We found a PAGE_SIZE-length, PAGE_SIZE-aligned run of blocks
		 *
		 * 我们发现了一个PAGE_SIZE-length、PAGE_SIZE对齐的块序列
		 */
		ret = add_swap_extent(sis, page_no, 1, first_block);
		if (ret < 0)
			goto out;
		/* 让nr_extents加上ret */
		nr_extents += ret;
		/* page_no++ */
		page_no++;
		/* 进行下一个block */
		probe_block += blocks_per_page;
reprobe:
		continue;
	}
	/* 拿到nr_extents */
	ret = nr_extents;
	*span = 1 + highest_block - lowest_block;
	if (page_no == 0)
		page_no = 1;	/* force Empty message */
	sis->max = page_no;
	sis->pages = page_no - 1;
	sis->highest_bit = page_no - 1;
out:
	return ret;
bad_bmap:
	pr_err("swapon: swapfile has holes\n");
	ret = -EINVAL;
	goto out;
}

/*
 * We may have stale swap cache pages in memory: notice
 * them here and get rid of the unnecessary final write.
 */
int swap_writepage(struct page *page, struct writeback_control *wbc)
{
	int ret = 0;

	if (try_to_free_swap(page)) {
		unlock_page(page);
		goto out;
	}
	if (frontswap_store(page) == 0) {
		set_page_writeback(page);
		unlock_page(page);
		end_page_writeback(page);
		goto out;
	}
	ret = __swap_writepage(page, wbc, end_swap_bio_write);
out:
	return ret;
}

static sector_t swap_page_sector(struct page *page)
{
	return (sector_t)__page_file_index(page) << (PAGE_SHIFT - 9);
}

int __swap_writepage(struct page *page, struct writeback_control *wbc,
		bio_end_io_t end_write_func)
{
	struct bio *bio;
	int ret;
	struct swap_info_struct *sis = page_swap_info(page);

	VM_BUG_ON_PAGE(!PageSwapCache(page), page);
	if (sis->flags & SWP_FILE) {
		struct kiocb kiocb;
		struct file *swap_file = sis->swap_file;
		struct address_space *mapping = swap_file->f_mapping;
		struct bio_vec bv = {
			.bv_page = page,
			.bv_len  = PAGE_SIZE,
			.bv_offset = 0
		};
		struct iov_iter from;

		iov_iter_bvec(&from, ITER_BVEC | WRITE, &bv, 1, PAGE_SIZE);
		init_sync_kiocb(&kiocb, swap_file);
		kiocb.ki_pos = page_file_offset(page);

		set_page_writeback(page);
		unlock_page(page);
		ret = mapping->a_ops->direct_IO(&kiocb, &from);
		if (ret == PAGE_SIZE) {
			count_vm_event(PSWPOUT);
			ret = 0;
		} else {
			/*
			 * In the case of swap-over-nfs, this can be a
			 * temporary failure if the system has limited
			 * memory for allocating transmit buffers.
			 * Mark the page dirty and avoid
			 * rotate_reclaimable_page but rate-limit the
			 * messages but do not flag PageError like
			 * the normal direct-to-bio case as it could
			 * be temporary.
			 */
			set_page_dirty(page);
			ClearPageReclaim(page);
			pr_err_ratelimited("Write error on dio swapfile (%llu)\n",
					   page_file_offset(page));
		}
		end_page_writeback(page);
		return ret;
	}

	ret = bdev_write_page(sis->bdev, swap_page_sector(page), page, wbc);
	if (!ret) {
		count_vm_event(PSWPOUT);
		return 0;
	}

	ret = 0;
	bio = get_swap_bio(GFP_NOIO, page, end_write_func);
	if (bio == NULL) {
		set_page_dirty(page);
		unlock_page(page);
		ret = -ENOMEM;
		goto out;
	}
	if (wbc->sync_mode == WB_SYNC_ALL)
		bio_set_op_attrs(bio, REQ_OP_WRITE, REQ_SYNC);
	else
		bio_set_op_attrs(bio, REQ_OP_WRITE, 0);
	count_vm_event(PSWPOUT);
	set_page_writeback(page);
	unlock_page(page);
	submit_bio(bio);
out:
	return ret;
}

int swap_readpage(struct page *page)
{
	struct bio *bio;
	int ret = 0;
	struct swap_info_struct *sis = page_swap_info(page);

	VM_BUG_ON_PAGE(!PageSwapCache(page), page);
	VM_BUG_ON_PAGE(!PageLocked(page), page);
	VM_BUG_ON_PAGE(PageUptodate(page), page);
	if (frontswap_load(page) == 0) {
		SetPageUptodate(page);
		unlock_page(page);
		goto out;
	}

	if (sis->flags & SWP_FILE) {
		struct file *swap_file = sis->swap_file;
		struct address_space *mapping = swap_file->f_mapping;

		ret = mapping->a_ops->readpage(swap_file, page);
		if (!ret)
			count_vm_event(PSWPIN);
		return ret;
	}

	ret = bdev_read_page(sis->bdev, swap_page_sector(page), page);
	if (!ret) {
		if (trylock_page(page)) {
			swap_slot_free_notify(page);
			unlock_page(page);
		}

		count_vm_event(PSWPIN);
		return 0;
	}

	ret = 0;
	bio = get_swap_bio(GFP_KERNEL, page, end_swap_bio_read);
	if (bio == NULL) {
		unlock_page(page);
		ret = -ENOMEM;
		goto out;
	}
	bio_set_op_attrs(bio, REQ_OP_READ, 0);
	count_vm_event(PSWPIN);
	submit_bio(bio);
out:
	return ret;
}

int swap_set_page_dirty(struct page *page)
{
	struct swap_info_struct *sis = page_swap_info(page);

	if (sis->flags & SWP_FILE) {
		struct address_space *mapping = sis->swap_file->f_mapping;

		VM_BUG_ON_PAGE(!PageSwapCache(page), page);
		return mapping->a_ops->set_page_dirty(page);
	} else {
		return __set_page_dirty_no_writeback(page);
	}
}
