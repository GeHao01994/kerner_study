/*
 * include/linux/buffer_head.h
 *
 * Everything to do with buffer_heads.
 */

#ifndef _LINUX_BUFFER_HEAD_H
#define _LINUX_BUFFER_HEAD_H

#include <linux/types.h>
#include <linux/fs.h>
#include <linux/linkage.h>
#include <linux/pagemap.h>
#include <linux/wait.h>
#include <linux/atomic.h>

#ifdef CONFIG_BLOCK

enum bh_state_bits {
	/* 缓冲区包含有效数据时被置位 */
	BH_Uptodate,	/* Contains valid data */
	/* 如果缓冲区脏就置位（表示缓冲区中的数据必须写回块设备) */
	BH_Dirty,	/* Is dirty */
	/* 如果缓冲区加锁就置位，通常发生在缓冲区进行磁盘传输时 */
	BH_Lock,	/* Is locked */
	/* 如果已经为初始化缓冲区而请求数据传输就置位 */
	BH_Req,		/* Has been submitted for I/O */
	/* 由页面中的第一个bh使用，以串行化页面中其他缓冲的IO完成 */
	BH_Uptodate_Lock,/* Used by the first bh in a page, to serialise
			  * IO completion of other buffers in the page
			  */
	/* 如果缓冲区被映射到磁盘就置位，即：如果相应的缓冲区首部的b_bdev和b_blocknr是有效的就置位 */
	BH_Mapped,	/* Has a disk mapping */
	/* 如果相应的块刚被分配而还没有被访问过就置位 */
	BH_New,		/* Disk mapping was newly created by get_block */
	/* 如果在异步地读缓冲区就置位 */
	BH_Async_Read,	/* Is under end_buffer_async_read I/O */
	/* 如果在异步地写缓冲区就置位 */
	BH_Async_Write,	/* Is under end_buffer_async_write I/O */
	/* 如果还没有在磁盘上分配缓冲区就置位 */
	BH_Delay,	/* Buffer is not yet allocated on disk */
	/* 如果两个相邻的块在其中一个提交之后不再相邻就置位 */
	BH_Boundary,	/* Block is followed by a discontiguity */
	/* 如果写块时出现I/O错误就置位 */
	BH_Write_EIO,	/* I/O error on write */
	/* 缓冲区已分配到磁盘上，但未写入 */
	BH_Unwritten,	/* Buffer is allocated on disk but not written */
	/* 缓冲区错误提示保持安静 */
	BH_Quiet,	/* Buffer Error Prinks to be quiet */
	/* 缓冲区包含元数据 */
	BH_Meta,	/* Buffer contains metadata */
	/* 缓冲区应与REQ_PRIO一起提交 */
	BH_Prio,	/* Buffer should be submitted with REQ_PRIO */
	/* 将AIO完成延迟到工作队列 */
	BH_Defer_Completion, /* Defer AIO completion to workqueue */
	/* 不是状态位，而是可供其他entities进行私有分配的第一个有效位 */
	BH_PrivateStart,/* not a state bit, but the first bit available
			 * for private allocation by other entities
			 */
};

#define MAX_BUF_PER_PAGE (PAGE_SIZE / 512)

struct page;
struct buffer_head;
struct address_space;
typedef void (bh_end_io_t)(struct buffer_head *bh, int uptodate);

/*
 * Historically, a buffer_head was used to map a single block
 * within a page, and of course as the unit of I/O through the
 * filesystem and block layers.  Nowadays the basic I/O unit
 * is the bio, and buffer_heads are used for extracting block
 * mappings (via a get_block_t call), for tracking state within
 * a page (via a page_mapping) and for wrapping bio submission
 * for backward compatibility reasons (e.g. submit_bh).
 */
/*
 * 所谓缓冲页面，是指将页面划分为一个个的缓冲块(Buffer Block,也称作为块缓冲区，Block Buffer)，
 * 以缓冲块为单位进行I/O.管理缓冲块的数据结构为buffer_head，被称作为缓冲头.
 * 历史上,buffer_head不仅被用来映射页面中的单个块,同时也是从文件系统到块层的I/O单元.
 * 如今，I/O的基本单元已经换成bio，而buffer_heads仅被用于提取块映射(通过get_block_t调用)、跟踪页面的状态(通过page_mapping)
 * 以及用于封装bio提交以向后兼容（例如submit_bh).
 */

/* 当一个页面用作缓冲页面，所有和它的块缓冲区相关的缓冲头组成一个循环单链表.
 * 缓冲页面描述符的private域指向页面第一个块的缓冲头;
 * 每个缓冲头的b_this_page域是指向链表中的下一个缓冲头的指针.
 * 此外，每个缓冲头在b_page域中保存了缓冲页面描述符的地址.
 * 如果页面在高端内存，那么b_data域保存了块缓冲区本身的偏移.
 */
struct buffer_head {
	/* 缓冲区状态位图 */
	unsigned long b_state;		/* buffer state bitmap (see above) */
	/* 指向所属缓冲页面的缓冲头链表中下一个元素的指针 */
	struct buffer_head *b_this_page;/* circular list of page's buffers */
	/* 指向存放这个逻辑块的缓冲页面的指针 */
	struct page *b_page;		/* the page this bh is mapped to */
	/* 在块设备上的逻辑块编号 */
	sector_t b_blocknr;		/* start block number */
	/* 逻辑块缓冲区的长度 */
	size_t b_size;			/* size of mapping */
	/* 逻辑块在缓冲页面中存放的位置
	 * bh->b_data应该是这个bh在内存中的位置，如果是高端页面就记录偏移
	 * 如果是NORMAL，即可获得其虚拟地址
	 */
	char *b_data;			/* pointer to data within the page */
	/* 指向块设备描述符的指针 */
	struct block_device *b_bdev;
	/* I/O 完成方法 */
	bh_end_io_t *b_end_io;		/* I/O completion */
	/* I/O 完成方法的参数 */
 	void *b_private;		/* reserved for b_end_io */
	/* 链入到所关联地址空间的私有链表的连接件 */
	struct list_head b_assoc_buffers; /* associated with another mapping */
	/* 这个缓冲区所关联到的地址空间映射.例如为文件的中间记录块分配的缓冲头被关联到文件的地址空间 */
	struct address_space *b_assoc_map;	/* mapping this buffer is
						   associated with */
	/* 引用计数器 */
	atomic_t b_count;		/* users using this buffer_head */
};

/*
 * macro tricks to expand the set_buffer_foo(), clear_buffer_foo()
 * and buffer_foo() functions.
 */
#define BUFFER_FNS(bit, name)						\
static __always_inline void set_buffer_##name(struct buffer_head *bh)	\
{									\
	set_bit(BH_##bit, &(bh)->b_state);				\
}									\
static __always_inline void clear_buffer_##name(struct buffer_head *bh)	\
{									\
	clear_bit(BH_##bit, &(bh)->b_state);				\
}									\
static __always_inline int buffer_##name(const struct buffer_head *bh)	\
{									\
	return test_bit(BH_##bit, &(bh)->b_state);			\
}

/*
 * test_set_buffer_foo() and test_clear_buffer_foo()
 */
#define TAS_BUFFER_FNS(bit, name)					\
static __always_inline int test_set_buffer_##name(struct buffer_head *bh) \
{									\
	return test_and_set_bit(BH_##bit, &(bh)->b_state);		\
}									\
static __always_inline int test_clear_buffer_##name(struct buffer_head *bh) \
{									\
	return test_and_clear_bit(BH_##bit, &(bh)->b_state);		\
}									\

/*
 * Emit the buffer bitops functions.   Note that there are also functions
 * of the form "mark_buffer_foo()".  These are higher-level functions which
 * do something in addition to setting a b_state bit.
 */
BUFFER_FNS(Uptodate, uptodate)
BUFFER_FNS(Dirty, dirty)
TAS_BUFFER_FNS(Dirty, dirty)
BUFFER_FNS(Lock, locked)
BUFFER_FNS(Req, req)
TAS_BUFFER_FNS(Req, req)
BUFFER_FNS(Mapped, mapped)
BUFFER_FNS(New, new)
BUFFER_FNS(Async_Read, async_read)
BUFFER_FNS(Async_Write, async_write)
BUFFER_FNS(Delay, delay)
BUFFER_FNS(Boundary, boundary)
BUFFER_FNS(Write_EIO, write_io_error)
BUFFER_FNS(Unwritten, unwritten)
BUFFER_FNS(Meta, meta)
BUFFER_FNS(Prio, prio)
BUFFER_FNS(Defer_Completion, defer_completion)

#define bh_offset(bh)		((unsigned long)(bh)->b_data & ~PAGE_MASK)

/* If we *know* page->private refers to buffer_heads */
#define page_buffers(page)					\
	({							\
		BUG_ON(!PagePrivate(page));			\
		((struct buffer_head *)page_private(page));	\
	})
#define page_has_buffers(page)	PagePrivate(page)

void buffer_check_dirty_writeback(struct page *page,
				     bool *dirty, bool *writeback);

/*
 * Declarations
 */

void mark_buffer_dirty(struct buffer_head *bh);
void init_buffer(struct buffer_head *, bh_end_io_t *, void *);
void touch_buffer(struct buffer_head *bh);
void set_bh_page(struct buffer_head *bh,
		struct page *page, unsigned long offset);
int try_to_free_buffers(struct page *);
struct buffer_head *alloc_page_buffers(struct page *page, unsigned long size,
		int retry);
void create_empty_buffers(struct page *, unsigned long,
			unsigned long b_state);
void end_buffer_read_sync(struct buffer_head *bh, int uptodate);
void end_buffer_write_sync(struct buffer_head *bh, int uptodate);
void end_buffer_async_write(struct buffer_head *bh, int uptodate);

/* Things to do with buffers at mapping->private_list */
void mark_buffer_dirty_inode(struct buffer_head *bh, struct inode *inode);
int inode_has_buffers(struct inode *);
void invalidate_inode_buffers(struct inode *);
int remove_inode_buffers(struct inode *inode);
int sync_mapping_buffers(struct address_space *mapping);
void unmap_underlying_metadata(struct block_device *bdev, sector_t block);

void mark_buffer_async_write(struct buffer_head *bh);
void __wait_on_buffer(struct buffer_head *);
wait_queue_head_t *bh_waitq_head(struct buffer_head *bh);
struct buffer_head *__find_get_block(struct block_device *bdev, sector_t block,
			unsigned size);
struct buffer_head *__getblk_gfp(struct block_device *bdev, sector_t block,
				  unsigned size, gfp_t gfp);
void __brelse(struct buffer_head *);
void __bforget(struct buffer_head *);
void __breadahead(struct block_device *, sector_t block, unsigned int size);
struct buffer_head *__bread_gfp(struct block_device *,
				sector_t block, unsigned size, gfp_t gfp);
void invalidate_bh_lrus(void);
struct buffer_head *alloc_buffer_head(gfp_t gfp_flags);
void free_buffer_head(struct buffer_head * bh);
void unlock_buffer(struct buffer_head *bh);
void __lock_buffer(struct buffer_head *bh);
void ll_rw_block(int, int, int, struct buffer_head * bh[]);
int sync_dirty_buffer(struct buffer_head *bh);
int __sync_dirty_buffer(struct buffer_head *bh, int op_flags);
void write_dirty_buffer(struct buffer_head *bh, int op_flags);
int _submit_bh(int op, int op_flags, struct buffer_head *bh,
	       unsigned long bio_flags);
int submit_bh(int, int, struct buffer_head *);
void write_boundary_block(struct block_device *bdev,
			sector_t bblock, unsigned blocksize);
int bh_uptodate_or_lock(struct buffer_head *bh);
int bh_submit_read(struct buffer_head *bh);

extern int buffer_heads_over_limit;

/*
 * Generic address_space_operations implementations for buffer_head-backed
 * address_spaces.
 */
void block_invalidatepage(struct page *page, unsigned int offset,
			  unsigned int length);
int block_write_full_page(struct page *page, get_block_t *get_block,
				struct writeback_control *wbc);
int __block_write_full_page(struct inode *inode, struct page *page,
			get_block_t *get_block, struct writeback_control *wbc,
			bh_end_io_t *handler);
int block_read_full_page(struct page*, get_block_t*);
int block_is_partially_uptodate(struct page *page, unsigned long from,
				unsigned long count);
int block_write_begin(struct address_space *mapping, loff_t pos, unsigned len,
		unsigned flags, struct page **pagep, get_block_t *get_block);
int __block_write_begin(struct page *page, loff_t pos, unsigned len,
		get_block_t *get_block);
int block_write_end(struct file *, struct address_space *,
				loff_t, unsigned, unsigned,
				struct page *, void *);
int generic_write_end(struct file *, struct address_space *,
				loff_t, unsigned, unsigned,
				struct page *, void *);
void page_zero_new_buffers(struct page *page, unsigned from, unsigned to);
int cont_write_begin(struct file *, struct address_space *, loff_t,
			unsigned, unsigned, struct page **, void **,
			get_block_t *, loff_t *);
int generic_cont_expand_simple(struct inode *inode, loff_t size);
int block_commit_write(struct page *page, unsigned from, unsigned to);
int block_page_mkwrite(struct vm_area_struct *vma, struct vm_fault *vmf,
				get_block_t get_block);
/* Convert errno to return value from ->page_mkwrite() call */
static inline int block_page_mkwrite_return(int err)
{
	if (err == 0)
		return VM_FAULT_LOCKED;
	if (err == -EFAULT)
		return VM_FAULT_NOPAGE;
	if (err == -ENOMEM)
		return VM_FAULT_OOM;
	if (err == -EAGAIN)
		return VM_FAULT_RETRY;
	/* -ENOSPC, -EDQUOT, -EIO ... */
	return VM_FAULT_SIGBUS;
}
sector_t generic_block_bmap(struct address_space *, sector_t, get_block_t *);
int block_truncate_page(struct address_space *, loff_t, get_block_t *);
int nobh_write_begin(struct address_space *, loff_t, unsigned, unsigned,
				struct page **, void **, get_block_t*);
int nobh_write_end(struct file *, struct address_space *,
				loff_t, unsigned, unsigned,
				struct page *, void *);
int nobh_truncate_page(struct address_space *, loff_t, get_block_t *);
int nobh_writepage(struct page *page, get_block_t *get_block,
                        struct writeback_control *wbc);

void buffer_init(void);

/*
 * inline definitions
 */

static inline void attach_page_buffers(struct page *page,
		struct buffer_head *head)
{
	get_page(page);
	SetPagePrivate(page);
	set_page_private(page, (unsigned long)head);
}

static inline void get_bh(struct buffer_head *bh)
{
        atomic_inc(&bh->b_count);
}

static inline void put_bh(struct buffer_head *bh)
{
        smp_mb__before_atomic();
        atomic_dec(&bh->b_count);
}

static inline void brelse(struct buffer_head *bh)
{
	if (bh)
		__brelse(bh);
}

static inline void bforget(struct buffer_head *bh)
{
	if (bh)
		__bforget(bh);
}

static inline struct buffer_head *
sb_bread(struct super_block *sb, sector_t block)
{
	return __bread_gfp(sb->s_bdev, block, sb->s_blocksize, __GFP_MOVABLE);
}

static inline struct buffer_head *
sb_bread_unmovable(struct super_block *sb, sector_t block)
{
	return __bread_gfp(sb->s_bdev, block, sb->s_blocksize, 0);
}

static inline void
sb_breadahead(struct super_block *sb, sector_t block)
{
	__breadahead(sb->s_bdev, block, sb->s_blocksize);
}

static inline struct buffer_head *
sb_getblk(struct super_block *sb, sector_t block)
{
	return __getblk_gfp(sb->s_bdev, block, sb->s_blocksize, __GFP_MOVABLE);
}


static inline struct buffer_head *
sb_getblk_gfp(struct super_block *sb, sector_t block, gfp_t gfp)
{
	return __getblk_gfp(sb->s_bdev, block, sb->s_blocksize, gfp);
}

static inline struct buffer_head *
sb_find_get_block(struct super_block *sb, sector_t block)
{
	return __find_get_block(sb->s_bdev, block, sb->s_blocksize);
}

static inline void
map_bh(struct buffer_head *bh, struct super_block *sb, sector_t block)
{
	set_buffer_mapped(bh);
	bh->b_bdev = sb->s_bdev;
	bh->b_blocknr = block;
	bh->b_size = sb->s_blocksize;
}

static inline void wait_on_buffer(struct buffer_head *bh)
{
	might_sleep();
	if (buffer_locked(bh))
		__wait_on_buffer(bh);
}

static inline int trylock_buffer(struct buffer_head *bh)
{
	return likely(!test_and_set_bit_lock(BH_Lock, &bh->b_state));
}

static inline void lock_buffer(struct buffer_head *bh)
{
	might_sleep();
	if (!trylock_buffer(bh))
		__lock_buffer(bh);
}

static inline struct buffer_head *getblk_unmovable(struct block_device *bdev,
						   sector_t block,
						   unsigned size)
{
	return __getblk_gfp(bdev, block, size, 0);
}

static inline struct buffer_head *__getblk(struct block_device *bdev,
					   sector_t block,
					   unsigned size)
{
	return __getblk_gfp(bdev, block, size, __GFP_MOVABLE);
}

/**
 *  __bread() - reads a specified block and returns the bh
 *  @bdev: the block_device to read from
 *  @block: number of block
 *  @size: size (in bytes) to read
 *
 *  Reads a specified block, and returns buffer head that contains it.
 *  The page cache is allocated from movable area so that it can be migrated.
 *  It returns NULL if the block was unreadable.
 */
static inline struct buffer_head *
__bread(struct block_device *bdev, sector_t block, unsigned size)
{
	return __bread_gfp(bdev, block, size, __GFP_MOVABLE);
}

extern int __set_page_dirty_buffers(struct page *page);

#else /* CONFIG_BLOCK */

static inline void buffer_init(void) {}
static inline int try_to_free_buffers(struct page *page) { return 1; }
static inline int inode_has_buffers(struct inode *inode) { return 0; }
static inline void invalidate_inode_buffers(struct inode *inode) {}
static inline int remove_inode_buffers(struct inode *inode) { return 1; }
static inline int sync_mapping_buffers(struct address_space *mapping) { return 0; }

#endif /* CONFIG_BLOCK */
#endif /* _LINUX_BUFFER_HEAD_H */
