#ifndef _LINUX_FS_H
#define _LINUX_FS_H

#include <linux/linkage.h>
#include <linux/wait.h>
#include <linux/kdev_t.h>
#include <linux/dcache.h>
#include <linux/path.h>
#include <linux/stat.h>
#include <linux/cache.h>
#include <linux/list.h>
#include <linux/list_lru.h>
#include <linux/llist.h>
#include <linux/radix-tree.h>
#include <linux/rbtree.h>
#include <linux/init.h>
#include <linux/pid.h>
#include <linux/bug.h>
#include <linux/mutex.h>
#include <linux/rwsem.h>
#include <linux/capability.h>
#include <linux/semaphore.h>
#include <linux/fiemap.h>
#include <linux/rculist_bl.h>
#include <linux/atomic.h>
#include <linux/shrinker.h>
#include <linux/migrate_mode.h>
#include <linux/uidgid.h>
#include <linux/lockdep.h>
#include <linux/percpu-rwsem.h>
#include <linux/blk_types.h>
#include <linux/workqueue.h>
#include <linux/percpu-rwsem.h>
#include <linux/delayed_call.h>

#include <asm/byteorder.h>
#include <uapi/linux/fs.h>

struct backing_dev_info;
struct bdi_writeback;
struct export_operations;
struct hd_geometry;
struct iovec;
struct kiocb;
struct kobject;
struct pipe_inode_info;
struct poll_table_struct;
struct kstatfs;
struct vm_area_struct;
struct vfsmount;
struct cred;
struct swap_info_struct;
struct seq_file;
struct workqueue_struct;
struct iov_iter;
struct fscrypt_info;
struct fscrypt_operations;

extern void __init inode_init(void);
extern void __init inode_init_early(void);
extern void __init files_init(void);
extern void __init files_maxfiles_init(void);

extern struct files_stat_struct files_stat;
extern unsigned long get_max_files(void);
extern unsigned int sysctl_nr_open;
extern struct inodes_stat_t inodes_stat;
extern int leases_enable, lease_break_time;
extern int sysctl_protected_symlinks;
extern int sysctl_protected_hardlinks;

struct buffer_head;
typedef int (get_block_t)(struct inode *inode, sector_t iblock,
			struct buffer_head *bh_result, int create);
typedef int (dio_iodone_t)(struct kiocb *iocb, loff_t offset,
			ssize_t bytes, void *private);

#define MAY_EXEC		0x00000001
#define MAY_WRITE		0x00000002
#define MAY_READ		0x00000004
#define MAY_APPEND		0x00000008
#define MAY_ACCESS		0x00000010
#define MAY_OPEN		0x00000020
#define MAY_CHDIR		0x00000040
/* called from RCU mode, don't block */
#define MAY_NOT_BLOCK		0x00000080

/*
 * flags in file.f_mode.  Note that FMODE_READ and FMODE_WRITE must correspond
 * to O_WRONLY and O_RDWR via the strange trick in __dentry_open()
 */

/* file is open for reading */
#define FMODE_READ		((__force fmode_t)0x1)
/* file is open for writing */
#define FMODE_WRITE		((__force fmode_t)0x2)
/* file is seekable */
#define FMODE_LSEEK		((__force fmode_t)0x4)
/* file can be accessed using pread */
#define FMODE_PREAD		((__force fmode_t)0x8)
/* file can be accessed using pwrite */
#define FMODE_PWRITE		((__force fmode_t)0x10)
/* File is opened for execution with sys_execve / sys_uselib */
#define FMODE_EXEC		((__force fmode_t)0x20)
/* File is opened with O_NDELAY (only set for block devices) */
#define FMODE_NDELAY		((__force fmode_t)0x40)
/* File is opened with O_EXCL (only set for block devices) */
#define FMODE_EXCL		((__force fmode_t)0x80)
/* File is opened using open(.., 3, ..) and is writeable only for ioctls
   (specialy hack for floppy.c) */
#define FMODE_WRITE_IOCTL	((__force fmode_t)0x100)
/* 32bit hashes as llseek() offset (for directories) */
#define FMODE_32BITHASH         ((__force fmode_t)0x200)
/* 64bit hashes as llseek() offset (for directories) */
#define FMODE_64BITHASH         ((__force fmode_t)0x400)

/*
 * Don't update ctime and mtime.
 *
 * Currently a special hack for the XFS open_by_handle ioctl, but we'll
 * hopefully graduate it to a proper O_CMTIME flag supported by open(2) soon.
 */
#define FMODE_NOCMTIME		((__force fmode_t)0x800)

/* Expect random access pattern */
#define FMODE_RANDOM		((__force fmode_t)0x1000)

/* File is huge (eg. /dev/kmem): treat loff_t as unsigned */
#define FMODE_UNSIGNED_OFFSET	((__force fmode_t)0x2000)

/* File is opened with O_PATH; almost nothing can be done with it */
#define FMODE_PATH		((__force fmode_t)0x4000)

/* File needs atomic accesses to f_pos */
#define FMODE_ATOMIC_POS	((__force fmode_t)0x8000)
/* Write access to underlying fs */
#define FMODE_WRITER		((__force fmode_t)0x10000)
/* Has read method(s) */
/*
 * if ((f->f_mode & FMODE_READ) && likely(f->f_op->read || f->f_op->aio_read))
 *	f->f_mode |= FMODE_CAN_READ;
 */
#define FMODE_CAN_READ          ((__force fmode_t)0x20000)
/* Has write method(s) */
/* if ((f->f_mode & FMODE_WRITE) && likely(f->f_op->write || f->f_op->aio_write))
 *	f->f_mode |= FMODE_CAN_WRITE;
 */
#define FMODE_CAN_WRITE         ((__force fmode_t)0x40000)

/* File was opened by fanotify and shouldn't generate fanotify events */
#define FMODE_NONOTIFY		((__force fmode_t)0x4000000)

/*
 * Flag for rw_copy_check_uvector and compat_rw_copy_check_uvector
 * that indicates that they should check the contents of the iovec are
 * valid, but not check the memory that the iovec elements
 * points too.
 */
#define CHECK_IOVEC_ONLY -1

/*
 * The below are the various read and write flags that we support. Some of
 * them include behavioral modifiers that send information down to the
 * block layer and IO scheduler. They should be used along with a req_op.
 * Terminology:
 *
 *	The block layer uses device plugging to defer IO a little bit, in
 *	the hope that we will see more IO very shortly. This increases
 *	coalescing of adjacent IO and thus reduces the number of IOs we
 *	have to send to the device. It also allows for better queuing,
 *	if the IO isn't mergeable. If the caller is going to be waiting
 *	for the IO, then he must ensure that the device is unplugged so
 *	that the IO is dispatched to the driver.
 *
 *	All IO is handled async in Linux. This is fine for background
 *	writes, but for reads or writes that someone waits for completion
 *	on, we want to notify the block layer and IO scheduler so that they
 *	know about it. That allows them to make better scheduling
 *	decisions. So when the below references 'sync' and 'async', it
 *	is referencing this priority hint.
 *
 * With that in mind, the available types are:
 *
 * READ			A normal read operation. Device will be plugged.
 * READ_SYNC		A synchronous read. Device is not plugged, caller can
 *			immediately wait on this read without caring about
 *			unplugging.
 * WRITE		A normal async write. Device will be plugged.
 * WRITE_SYNC		Synchronous write. Identical to WRITE, but passes down
 *			the hint that someone will be waiting on this IO
 *			shortly. The write equivalent of READ_SYNC.
 * WRITE_ODIRECT	Special case write for O_DIRECT only.
 * WRITE_FLUSH		Like WRITE_SYNC but with preceding cache flush.
 * WRITE_FUA		Like WRITE_SYNC but data is guaranteed to be on
 *			non-volatile media on completion.
 * WRITE_FLUSH_FUA	Combination of WRITE_FLUSH and FUA. The IO is preceded
 *			by a cache flush and data is guaranteed to be on
 *			non-volatile media on completion.
 *
 */
#define RW_MASK			REQ_OP_WRITE

#define READ			REQ_OP_READ
#define WRITE			REQ_OP_WRITE

#define READ_SYNC		REQ_SYNC
#define WRITE_SYNC		(REQ_SYNC | REQ_NOIDLE)
#define WRITE_ODIRECT		REQ_SYNC
#define WRITE_FLUSH		(REQ_SYNC | REQ_NOIDLE | REQ_PREFLUSH)
#define WRITE_FUA		(REQ_SYNC | REQ_NOIDLE | REQ_FUA)
#define WRITE_FLUSH_FUA		(REQ_SYNC | REQ_NOIDLE | REQ_PREFLUSH | REQ_FUA)

/*
 * Attribute flags.  These should be or-ed together to figure out what
 * has been changed!
 */
#define ATTR_MODE	(1 << 0)
#define ATTR_UID	(1 << 1)
#define ATTR_GID	(1 << 2)
#define ATTR_SIZE	(1 << 3)
#define ATTR_ATIME	(1 << 4)
#define ATTR_MTIME	(1 << 5)
#define ATTR_CTIME	(1 << 6)
#define ATTR_ATIME_SET	(1 << 7)
#define ATTR_MTIME_SET	(1 << 8)
#define ATTR_FORCE	(1 << 9) /* Not a change, but a change it */
#define ATTR_ATTR_FLAG	(1 << 10)
#define ATTR_KILL_SUID	(1 << 11)
#define ATTR_KILL_SGID	(1 << 12)
#define ATTR_FILE	(1 << 13)
#define ATTR_KILL_PRIV	(1 << 14)
#define ATTR_OPEN	(1 << 15) /* Truncating from open(O_TRUNC) */
#define ATTR_TIMES_SET	(1 << 16)
#define ATTR_TOUCH	(1 << 17)

/*
 * Whiteout is represented by a char device.  The following constants define the
 * mode and device number to use.
 */
/* Whiteout由char设备表示.
 * 以下常量定义要使用的模式和设备编号.
 */
#define WHITEOUT_MODE 0
#define WHITEOUT_DEV 0

/*
 * This is the Inode Attributes structure, used for notify_change().  It
 * uses the above definitions as flags, to know which values have changed.
 * Also, in this manner, a Filesystem can look at only the values it cares
 * about.  Basically, these are the attributes that the VFS layer can
 * request to change from the FS layer.
 * 这是用于notify_change（）的Inode属性结构体。
 * 它使用上面的定义作为标志，以了解哪些值发生了更改。
 * 同样，通过这种方式，文件系统能只查看它关心的值。
 * 基本上，这些是VFS层可以请求从FS层更改的属性。
 * Derek Atkins <warlord@MIT.EDU> 94-10-20
 */
struct iattr {
	/* 检验是否有权限被修改 */
	unsigned int	ia_valid;
	/* 该节点的模式 */
	umode_t		ia_mode;
	/* 所有者标识符 */
	kuid_t		ia_uid;
	/* 组标识符 */
	kgid_t		ia_gid;
	/* 文件的字节数 */
	loff_t		ia_size;
	/* 上次访问文件的时间 */
	struct timespec	ia_atime;
	/* 上次写文件的时间 */
	struct timespec	ia_mtime;
	/* 上次修改索引节点的时间 */
	struct timespec	ia_ctime;

	/*
	 * Not an attribute, but an auxiliary info for filesystems wanting to
	 * implement an ftruncate() like method.  NOTE: filesystem should
	 * check for (ia_valid & ATTR_FILE), and not for (ia_file != NULL).
	 */
	/* 这不是一个属性,
	 * 但是一个辅助信息对于文件系统想要去开发一个ftruncate（）像个方法.
	 * 注意： 文件系统应该检查(ia_valid & ATTR_FILE)，而不是(ia_file != NULL)
	 */
	struct file	*ia_file;
};

/*
 * Includes for diskquotas.
 */
#include <linux/quota.h>

/*
 * Maximum number of layers of fs stack.  Needs to be limited to
 * prevent kernel stack overflow
 */
#define FILESYSTEM_MAX_STACK_DEPTH 2

/** 
 * enum positive_aop_returns - aop return codes with specific semantics
 *
 * @AOP_WRITEPAGE_ACTIVATE: Informs the caller that page writeback has
 * 			    completed, that the page is still locked, and
 * 			    should be considered active.  The VM uses this hint
 * 			    to return the page to the active list -- it won't
 * 			    be a candidate for writeback again in the near
 * 			    future.  Other callers must be careful to unlock
 * 			    the page if they get this return.  Returned by
 * 			    writepage(); 
 *
 * @AOP_TRUNCATED_PAGE: The AOP method that was handed a locked page has
 *  			unlocked it and the page might have been truncated.
 *  			The caller should back up to acquiring a new page and
 *  			trying again.  The aop will be taking reasonable
 *  			precautions not to livelock.  If the caller held a page
 *  			reference, it should drop it before retrying.  Returned
 *  			by readpage().
 *
 * address_space_operation functions return these large constants to indicate
 * special semantics to the caller.  These are much larger than the bytes in a
 * page to allow for functions that return the number of bytes operated on in a
 * given page.
 *
 * enum-positive_aop_returns - 具有特定语义的aop返回代码
 *
 * @AOP_WRITEPAGE_ACTIVATE: 通知调用者页面写回已完成,页面仍处于锁定状态,应视为活动页面.
 *			    VM使用此提示将页面返回到活动列表 -- 在不久的将来,它不会再次成为回写的候选者.
 *			    如果其他调用者收到此返回,则必须小心解锁页面. writepage()返回;
 * @AOP_TRUNCATED_PAGE: 交给锁定页面的AOP方法已将其解锁,页面可能已被截断.
 *			调用者应备份以获取新页面并重试,aop将采取合理的预防措施,避免再次锁定.
 *			如果调用方持有页面引用,则应在重试之前将其删除.由readpage()返回.
 *
 * address_space_operation 函数返回这些大常量,以向调用方指示特殊的语义.
 * 这些字节比页面中的字节大得多,以允许函数返回给定页面中操作的字节数.
 */

enum positive_aop_returns {
	AOP_WRITEPAGE_ACTIVATE	= 0x80000,
	AOP_TRUNCATED_PAGE	= 0x80001,
};

#define AOP_FLAG_UNINTERRUPTIBLE	0x0001 /* will not do a short write */
#define AOP_FLAG_CONT_EXPAND		0x0002 /* called from cont_expand */
#define AOP_FLAG_NOFS			0x0004 /* used by filesystem to direct
						* helper code (eg buffer layer)
						* to clear GFP_FS from alloc */

/*
 * oh the beauties of C type declarations.
 */
struct page;
struct address_space;
struct writeback_control;

#define IOCB_EVENTFD		(1 << 0)
#define IOCB_APPEND		(1 << 1)
#define IOCB_DIRECT		(1 << 2)
#define IOCB_HIPRI		(1 << 3)
#define IOCB_DSYNC		(1 << 4)
#define IOCB_SYNC		(1 << 5)
#define IOCB_WRITE		(1 << 6)
/* 读/写操作是在内核控制块(kernel I/O Control Block)的控制之下进行的. */
struct kiocb {
	/* 指向和当前进行的I/O操作关联的文件对象的指针 */
	struct file		*ki_filp;
	/* 当前进行的I/O 操作的文件位置 */
	loff_t			ki_pos;
	/* IO完成时的回调 */
	void (*ki_complete)(struct kiocb *iocb, long ret, long ret2);
	void			*private;
	/* IO属性 */
	int			ki_flags;
};

static inline bool is_sync_kiocb(struct kiocb *kiocb)
{
	return kiocb->ki_complete == NULL;
}

static inline int iocb_flags(struct file *file);

static inline void init_sync_kiocb(struct kiocb *kiocb, struct file *filp)
{
	/* 将指和当前进行的I/O 操作关联的文件对象的指针ki_filp进行赋值 */
	*kiocb = (struct kiocb) {
		.ki_filp = filp,
		.ki_flags = iocb_flags(filp),
	};
}

/*
 * "descriptor" for what we're up to with a read.
 * This allows us to use the same read code yet
 * have multiple different users of the data that
 * we read from a file.
 *
 * The simplest case just copies the data to user
 * mode.
 */
/* 它之前是被do_generic_file_read使用的.
 * 假设已经将文件读到页面缓存，再如何使用这些数据就要看具体用户了,
 * 最简单的情况是将数据复制到用户空间缓冲区，这也是这个流程的用法.
 * 但是也可能有其他的用法，比如可以将从套接字读取,即网络上接收到的数据.
 * 写入管道或者写入iSCSI连接等.
 * 为了让这些不同的用户可以使用同一套读代码，所以引入了这个数据结构
 */
typedef struct {
	/* 数据用户已消耗的字节数(一般是复制到用户空间缓冲区的字节数) */
	size_t written;
	/* 剩余的字节数 */
	size_t count;
	union {
		/* 指向用户空间缓冲区的指针 */
		char __user *buf;
		/* 被其他用户，例如socket,自己定义和解释 */
		void *data;
	} arg;
	/* 保存负的错误码，如果出现错误的话 */
	int error;
} read_descriptor_t;

typedef int (*read_actor_t)(read_descriptor_t *, struct page *,
		unsigned long, unsigned long);

struct address_space_operations {
	/* writepage函数一般用于基于磁盘的文件系统，它将文件在内存页面中的数据更新到磁盘上.
	 * 在调用这个函数之前，内存页面中已经包含了文件的最新数据.
	 * 第一个参数为指向要写到磁盘的页面描述符的指针;
	 * 第二个参数为指向控制回写行为的结构的指针.
	 * writepage 可能为数据完整性原因，或者为释放内存目的，区别在于回写控制的sync_mode.
	 */
	int (*writepage)(struct page *page, struct writeback_control *wbc);
	/* readpage函数一般用于基于磁盘的文件系统，它从磁盘上读取文件到数据到内存页面中.
	 * 第一个参数为指向要读取的文件描述符的指针;
	 * 第二个参数为指向目标内存页面的指针，其中给出了所读取页面在页面缓存中的索引位置.
	 * 具体文件系统在该函数的实现中通常调用mpage_readpage或者block_read_full_page.
	 * 调用时传入一个函数指针，该函数被用来确定如何将相对于文件开始的文件块编号转换为相对于块设备开始的逻辑块编号
	 */
	int (*readpage)(struct file *, struct page *);
	/* 被调用从地址空间中写多个“脏”页面到磁盘.
	 * 第一个参数为指向地址空间的指针;
	 * 第二个参数为指向回写控制结构的指针.
	 * 如果同步模式为WBC_SYNC_ALL，则回写控制会指定要写出页面的范围;
	 * 否则，如果是WBC_SYNC_NONE,那么回写控制会给定要尽量写出的页面数目
	 */
	/* Write back some dirty pages from this mapping. */
	int (*writepages)(struct address_space *, struct writeback_control *);

	/* Set a page dirty.  Return true if this dirtied it */
	/* 设置页面为脏，特别用在具体文件系统的地址空间页面中有关联的私有数据,并且这些数据在页面“弄脏”的同时被更新的场合.
	 * 这个函数只有一个参数，为指向要处理页面的指针.
	 * 如果成功，返回true.
	 */
	int (*set_page_dirty)(struct page *page);
	/* 从磁盘上读取多个页面到地址空间中，它可以被看做readpage的向量版本，用于请求多个页面.
	 * 一般用在预读的场合，所以读取错误可以被忽略.
	 * 第一个参数为指向文件描述符的指针;
	 * 第二个参数为指向地址空间描述符的指针;
	 * 第三个参数为指向页面链表的表头;
	 * 第四个参数为链表中的页面数目
	 */
	int (*readpages)(struct file *filp, struct address_space *mapping,
			struct list_head *pages, unsigned nr_pages);
	/* 被调用的缓存I/O代码调用，要求具体文件系统准备将给定的偏移和长度的数据写入到文件.
	 * 换句话说，VFS通过调用write_begin通知具体文件系统，准备写文件的字节begin~end到给定的页面.
	 * 具体文件系统要负责确保本次写操作能够完成，包括必要时分配空间，在非覆写时先从磁盘读取数据到页面等
	 *
	 * 第一个参数为指向文件的指针;
	 * 第二个参数为指向地址空间的指针;
	 * 第三个参数为起始偏移值;
	 * 第四个字节为要写的字节数;
	 * 第五个参数为flags
	 * 第六个参数为指向页面描述符的双重指针，它是输入/输出参数，如果输入为NULL，则需要有具体文件系统分配的页面,
	 * 并通过它返回加锁的页面，以便调用者安全写入数据;
	 * 第七个参数为返回指向由具体文件系统解释的数据结构，它被传递给write_end函数,
	 * 例如，reiserfs文件系统使用它传递特定的标志，表示是否在cont_expand(expanding truncate)环境下被调用,
	 * 如果是这样，则用它通知write_end做协调处理.
	 * 这个函数在成功时返回0;否则返回负的错误码.
	 * 如果出错，write_end函数不会被调用
	 */
	int (*write_begin)(struct file *, struct address_space *mapping,
				loff_t pos, unsigned len, unsigned flags,
				struct page **pagep, void **fsdata);
	/* 在成功调用write_begin，并完成数据复制之后，write_end必须被调用.
	 * VFS通过调用write_end告诉具体文件系统，数据已经被复制到页面，现在可以被提交到磁盘上.
	 * 第一个参数为指向文件的指针;
	 * 第二个参数为指向地址空间的指针;
	 * 第三个参数为起始偏移值;
	 * 第四个字节为要写的字节数，即最初传递给write_begin的长度;
	 * 第五个字节为已写的字节数，即已从用户缓冲区复制到页面的字节数;
	 * 第六个参数为指向页面的指针;
	 * 第七个参数为指向由具体文件系统结束的数据结构，从write_begin函数传递过来.
	 * 具体文件系统需要负责解锁页面，释放它的引用计数，并更新i_size.失败返回负的错误码;
	 * 否则返回能够被复制到页面缓存页面的字节数(<=cpoied)
	 */
	int (*write_end)(struct file *, struct address_space *mapping,
				loff_t pos, unsigned len, unsigned copied,
				struct page *page, void *fsdata);

	/* Unfortunately this kludge is needed for FIBMAP. Don't use it */
	/* 将文件中的逻辑块扇区编号映射为对应设备上的物理块扇区编号.
	 * 这个回调函数被用于FIBMAP ioctl和交换文件(swap file)一起工作.
	 * 要交换到一个文件，文件必须在块设备上有稳定的映射.
	 * 交换系统并不通过文件系统，而是直接使用bmap找到并使用文件数据块在设备上的地址.
	 * 第一个参数为地址空间
	 * 第二个参数为文件的逻辑块扇区编号.
	 */
	sector_t (*bmap)(struct address_space *, sector_t);
	/* 使某个页面全部或部分失效，被用在截断文件时.
	 * 第一个参数为指向页面描述符的指针;
	 * 第二个参数为要使之失效的起始字节偏移，为0表示使整个页面失效.
	 */
	void (*invalidatepage) (struct page *, unsigned int, unsigned int);
	/* 被日志文件系统使用以准备释放页面.
	 * 第一个参数为指向页面描述符的指针;
	 * 第二个参数为分配标志
	 */
	int (*releasepage) (struct page *, gfp_t);
	void (*freepage)(struct page *);
	/* 被通用read/write函数调用执行direct_IO---即I/O请求会绕过页面缓存(Page Cache),
	 * 在磁盘与应用程序缓冲区之间进行直接数据传输.
	 * 第一个参数是指向内核I/O控制块的指针;
	 * 第二个参数iov_iter表示一个迭代器,用于迭代数据的读写
	 */
	ssize_t (*direct_IO)(struct kiocb *, struct iov_iter *iter);
	/*
	 * migrate the contents of a page to the specified target. If
	 * migrate_mode is MIGRATE_ASYNC, it must not block.
	 */
	/* 将页面的内容移动到指定的目标.
	 * 第一个参数为指向地址空间的指针;
	 * 第二个参数为指向新页面的指针;
	 * 第三个参数为指向旧页面的指针.
	 * 这个函数被用于compact物理内存使用.如果需要重新定位一个页面(比如接收到信号表明内存卡即将出错),
	 * 会换入一个新页面和一个旧页面到这个函数.
	 * 而它要负责转移所有的私有数据，以及更新引用计数.
	 * 页面成功完成分离后,内存管理的页面迁移就会调用migratepage 来迁移页面.
	 * migratepage的作用是将旧页面的内容移动到新页面，并设置new page的字段.
	 * 在完成页面迁移的动作后，驱动还需要`__ClearPageMovable(page)， 来指old page不再可移动.
	 */
	int (*migratepage) (struct address_space *,
			struct page *, struct page *, enum migrate_mode);
	/* 在页面迁移的某些场景中，如memory hotplug， memory compaction 会调用isolate_memory_page()函数来分离页面,
	 * 当页面分离之后，这些页面会被标记成PG_isolated, 这样其他CPU在并发分离页面时会忽略这个页面.
	 */
	bool (*isolate_page)(struct page *, isolate_mode_t);
	/* 在页面迁移失败时， 驱动需要把分离的页面返回到自己的数据结构中 */
	void (*putback_page)(struct page *);
	/* 在释放一个页面之前被调用——回写一个“脏”页面.
	 * 这个函数只有一个参数，即指向页面描述符的指针
	 */
	int (*launder_page) (struct page *);
	/* 在处理缓冲读I/O请求时，被调用以判断要读取的这部分数据在页面中是否为新的.
	 * 第一个参数为指向页面描述符的指针;
	 * 函数返回1表明页面相关数据已经被更新;否则返回0;
	 */
	int (*is_partially_uptodate) (struct page *, unsigned long,
					unsigned long);
	void (*is_dirty_writeback) (struct page *, bool *, bool *);
	/* 被内存故障处理代码使用.
	 * 第一个参数为指向地址空间描述符的指针.
	 * 第二个参数为指向页面描述符的指针
	 */
	int (*error_remove_page)(struct address_space *, struct page *);

	/* swapfile support */
	int (*swap_activate)(struct swap_info_struct *sis, struct file *file,
				sector_t *span);
	void (*swap_deactivate)(struct file *file);
};

extern const struct address_space_operations empty_aops;

/*
 * pagecache_write_begin/pagecache_write_end must be used by general code
 * to write into the pagecache.
 */
int pagecache_write_begin(struct file *, struct address_space *mapping,
				loff_t pos, unsigned len, unsigned flags,
				struct page **pagep, void **fsdata);

int pagecache_write_end(struct file *, struct address_space *mapping,
				loff_t pos, unsigned len, unsigned copied,
				struct page *page, void *fsdata);

struct address_space {
	/* 指向内嵌了(host)这个地址空间的inode指针
	 * 如果有的话，不管是常规文件或者块设备文件
	 */
	struct inode		*host;		/* owner: inode, block_device */
	/* 地址空间页面组成基树(Radix)的形式，page_tree为树根
	 * 文件的地址空间被分割为一个个以页面大小为单位的数据块，这些数据块(页)被组织成一个
	 * 多叉树，被称为基(radix)数.树中所有叶子节点为一个个页面结构(struct page),表示用于缓存该文件的每一个页.
	 * 在叶子层最左端的第一个页面保存着该文件的前4096个字节(如果页的大小为4096字节)，接下来的页面保存着文件第二个4096个字节，依次内推.
	 * 树中的所有中间节点为组织节点，指示某一地址上的数据所在的页面.
	 * 此树的层次可以从0层到6层，所支持的文件大小从0字节到16T个字节.
	 * 树的更节点为地址空间的page_tree域.
	 */
	struct radix_tree_root	page_tree;	/* radix tree of all pages */
	/* 用于保护基数的自旋锁 */
	spinlock_t		tree_lock;	/* and lock protecting it */
	/* 该地址空间中共享内存映射的数目 */
	atomic_t		i_mmap_writable;/* count VM_SHARED mappings */
	/* 为了便于查找，一个共享映射文件的所有虚拟内存区间或者私有映射文件的写时复制(copy-on-write)虚拟内存空间
	 * 被组织成一个radix优先查找树(Priority Search Tree),文件地址空间的i_mmap域为树根
	 *
	 * 为方便页面回收，内核采用反向映射技术，将内存区间(vm_area_struct)组织成radix优先
	 * 查找树的形式.该域为树根，vm_area_struct结构的prio_tree_node域为链入此树的链接件
	 */
	struct rb_root		i_mmap;		/* tree of private and shared mappings */
	struct rw_semaphore	i_mmap_rwsem;	/* protect tree, count, list */
	/* Protected by tree_lock together with the radix tree */
	/* 地址空间中页面的总数 */
	unsigned long		nrpages;	/* number of total pages */
	/* number of shadow or DAX exceptional entries */
	/* 影子或DAX异常项的数量 */
	unsigned long		nrexceptional;
	/*
	 * 为了不占用过多资源，Linux内核将地址空间中页面回写的行为分成若干轮次.
	 * writeback_index域记录了上次回写操作的最后页面索引，下一次回写操作将从该位置开始
	 */
	pgoff_t			writeback_index;/* writeback starts here */
	/* 地址空间(页面)的操作函数 */
	const struct address_space_operations *a_ops;	/* methods */
	/* 错误位和内存分配标志 */
	unsigned long		flags;		/* error bits */
	/* 用于保护地址空间私有链表的自旋锁 */
	spinlock_t		private_lock;	/* for use by the address_space */
	/* 用于分配的隐式gfp掩码 */
	gfp_t			gfp_mask;	/* implicit gfp mask for allocations */
	/* 地址空间的私有链表,通常用来链接为文件的中间记录块所分配的buffer_head结构 */
	struct list_head	private_list;	/* ditto */
	void			*private_data;	/* ditto */
} __attribute__((aligned(sizeof(long))));
	/*
	 * On most architectures that alignment is already the case; but
	 * must be enforced here for CRIS, to let the least significant bit
	 * of struct page's "mapping" pointer be used for PAGE_MAPPING_ANON.
	 */
struct request_queue;

struct block_device {
	dev_t			bd_dev;  /* not a kdev_t - it's a search key */
	int			bd_openers;
	struct inode *		bd_inode;	/* will die */
	struct super_block *	bd_super;
	struct mutex		bd_mutex;	/* open/close mutex */
	void *			bd_claiming;
	void *			bd_holder;
	int			bd_holders;
	bool			bd_write_holder;
#ifdef CONFIG_SYSFS
	struct list_head	bd_holder_disks;
#endif
	struct block_device *	bd_contains;
	unsigned		bd_block_size;
	struct hd_struct *	bd_part;
	/* number of times partitions within this device have been opened. */
	unsigned		bd_part_count;
	int			bd_invalidated;
	struct gendisk *	bd_disk;
	struct request_queue *  bd_queue;
	struct list_head	bd_list;
	/*
	 * Private data.  You must have bd_claim'ed the block_device
	 * to use this.  NOTE:  bd_claim allows an owner to claim
	 * the same device multiple times, the owner must take special
	 * care to not mess up bd_private for that case.
	 */
	unsigned long		bd_private;

	/* The counter of freeze processes */
	int			bd_fsfreeze_count;
	/* Mutex for freeze */
	struct mutex		bd_fsfreeze_mutex;
};

/*
 * Radix-tree tags, for tagging dirty and writeback pages within the pagecache
 * radix trees
 */
#define PAGECACHE_TAG_DIRTY	0
#define PAGECACHE_TAG_WRITEBACK	1
#define PAGECACHE_TAG_TOWRITE	2

int mapping_tagged(struct address_space *mapping, int tag);

static inline void i_mmap_lock_write(struct address_space *mapping)
{
	down_write(&mapping->i_mmap_rwsem);
}

static inline void i_mmap_unlock_write(struct address_space *mapping)
{
	up_write(&mapping->i_mmap_rwsem);
}

static inline void i_mmap_lock_read(struct address_space *mapping)
{
	down_read(&mapping->i_mmap_rwsem);
}

static inline void i_mmap_unlock_read(struct address_space *mapping)
{
	up_read(&mapping->i_mmap_rwsem);
}

/*
 * Might pages of this file be mapped into userspace?
 */
static inline int mapping_mapped(struct address_space *mapping)
{
	return	!RB_EMPTY_ROOT(&mapping->i_mmap);
}

/*
 * Might pages of this file have been modified in userspace?
 * Note that i_mmap_writable counts all VM_SHARED vmas: do_mmap_pgoff
 * marks vma as VM_SHARED if it is shared, and the file was opened for
 * writing i.e. vma may be mprotected writable even if now readonly.
 *
 * If i_mmap_writable is negative, no new writable mappings are allowed. You
 * can only deny writable mappings, if none exists right now.
 */
static inline int mapping_writably_mapped(struct address_space *mapping)
{
	return atomic_read(&mapping->i_mmap_writable) > 0;
}

static inline int mapping_map_writable(struct address_space *mapping)
{
	return atomic_inc_unless_negative(&mapping->i_mmap_writable) ?
		0 : -EPERM;
}

static inline void mapping_unmap_writable(struct address_space *mapping)
{
	atomic_dec(&mapping->i_mmap_writable);
}

static inline int mapping_deny_writable(struct address_space *mapping)
{
	return atomic_dec_unless_positive(&mapping->i_mmap_writable) ?
		0 : -EBUSY;
}

static inline void mapping_allow_writable(struct address_space *mapping)
{
	atomic_inc(&mapping->i_mmap_writable);
}

/*
 * Use sequence counter to get consistent i_size on 32-bit processors.
 */
#if BITS_PER_LONG==32 && defined(CONFIG_SMP)
#include <linux/seqlock.h>
#define __NEED_I_SIZE_ORDERED
#define i_size_ordered_init(inode) seqcount_init(&inode->i_size_seqcount)
#else
#define i_size_ordered_init(inode) do { } while (0)
#endif

struct posix_acl;
#define ACL_NOT_CACHED ((void *)(-1))
#define ACL_DONT_CACHE ((void *)(-3))

static inline struct posix_acl *
uncached_acl_sentinel(struct task_struct *task)
{
	return (void *)task + 1;
}

static inline bool
is_uncached_acl(struct posix_acl *acl)
{
	return (long)acl & 1;
}

#define IOP_FASTPERM	0x0001
#define IOP_LOOKUP	0x0002
#define IOP_NOFOLLOW	0x0004
#define IOP_XATTR	0x0008

/*
 * Keep mostly read-only and often accessed (especially for
 * the RCU path lookup and 'stat' data) fields at the beginning
 * of the 'struct inode'
 */

 /* inode包含了文件系统各种对象（文件、目录、块设备文件、字符设备文件等）的元数据。
  * 对于基于磁盘的文件系统，inode存在于磁盘上，其形式取决于文件系统的类型。
  * 在打开该对象进行访问时，其inode被读入内存。内存中inode有一部分是各种文件系统共有的
  */
struct inode {
	/* 文件类型和访问权限 */
	umode_t			i_mode;
	unsigned short		i_opflags;
	/* 创建该文件的用户ID */
	kuid_t			i_uid;
	/* 创建该文件的组ID */
	kgid_t			i_gid;
	/* 文件系统装载标志 */
	unsigned int		i_flags;

#ifdef CONFIG_FS_POSIX_ACL
	struct posix_acl	*i_acl;
	struct posix_acl	*i_default_acl;
#endif

	/* 指向inode操作表的指针 */
	const struct inode_operations	*i_op;
	/* 指向所属super block对象的指针 */
	struct super_block	*i_sb;
	/* 指向address_space 的指针 */
	struct address_space	*i_mapping;

#ifdef CONFIG_SECURITY
	void			*i_security;
#endif

	/* inode 编号 */
	/* Stat data, not accessed from path walking */
	unsigned long		i_ino;
	/*
	 * Filesystems may only read i_nlink directly.  They shall use the
	 * following functions for modification:
	 *
	 *    (set|clear|inc|drop)_nlink
	 *    inode_(inc|dec)_link_count
	 */
	union {
		const unsigned int i_nlink;
		unsigned int __i_nlink;
	};
	/* 设备号，如果本inode代表一个块设备或者是字符设备 */
	dev_t			i_rdev;
	/* 字节为单位的文件长度 */
	loff_t			i_size;
	/* 文件的最后访问时间 */
	struct timespec		i_atime;
	/* 文件的最后修改时间 */
	struct timespec		i_mtime;
	/* inode的最后修改时间 */
	struct timespec		i_ctime;
	/* 用于保护i_blocks、i_bytes和i_size等域的自旋锁 */
	spinlock_t		i_lock;	/* i_blocks, i_bytes, maybe i_size */
	/* 以512字节的块为单位，文件最后一个块的字节数 */
	unsigned short          i_bytes;
	unsigned int		i_blkbits;
	/* 文件的块数 */
	blkcnt_t		i_blocks;

#ifdef __NEED_I_SIZE_ORDERED
	/* 被smp系统用来正确获取和设置文件长度 */
	seqcount_t		i_size_seqcount;
#endif

	/* Misc */
	/* inode的状态标志 */
	unsigned long		i_state;
	struct rw_semaphore	i_rwsem;

	/* dirtied_when 值表示这个文件第一次（即inode的某个page）“脏”的时间，以jiffie为单位。
	 * 它被writeback代码用于确定是否将这个inode会写磁盘
	 */
	unsigned long		dirtied_when;	/* jiffies of first dirtying */
	unsigned long		dirtied_time_when;

	/* 链入到全局inode_hashtable 哈希表的“链接件” */
	struct hlist_node	i_hash;
	struct list_head	i_io_list;	/* backing dev IO list */
#ifdef CONFIG_CGROUP_WRITEBACK
	struct bdi_writeback	*i_wb;		/* the associated cgroup wb */

	/* foreign inode detection, see wbc_detach_inode() */
	int			i_wb_frn_winner;
	u16			i_wb_frn_avg_time;
	u16			i_wb_frn_history;
#endif
	struct list_head	i_lru;		/* inode LRU list */
	/* 链入到所属文件系统超级块 inode链表的“链接件” */
	struct list_head	i_sb_list;
	struct list_head	i_wb_list;	/* backing dev writeback list */
	union {
		/* 引用这个inode的dentry链表的表头.
		 * dentry结构的d_alias域链入到所属inode的i_dentry
		 * 链表的“链接件”.
		 */
		struct hlist_head	i_dentry;
		struct rcu_head		i_rcu;
	};

	/* 版本号，在每次使用后自动递增 */
	u64			i_version;
	/* 使用计数器 */
	atomic_t		i_count;
	atomic_t		i_dio_count;
	/* 用于写进程的使用计数 */
	atomic_t		i_writecount;
#ifdef CONFIG_IMA
	atomic_t		i_readcount; /* struct files open RO */
#endif
	/* 指向文件操作表的指针 */
	const struct file_operations	*i_fop;	/* former ->i_op->default_file_ops */
	struct file_lock_context	*i_flctx;
	/* 文件的address_space对象 */
	struct address_space	i_data;
	/* 如果这个inode表示一个块设备，则该域为链入到块设备的slave inode链表（表头为block_device结构的bd_inodes域）的“链接件”。
	 * 如果代表一个字符设备，则该域为链入到字符设备的inode链表（表头为cdev结构的list域）的“链接件”
	 */
	struct list_head	i_devices;
	/* inode可以表示多种对象，包括目录、文件、符号链接、字符设备、块设备等
	 * 如果inode表示块设备，则i_rdev保存了块设备编号，i_bdev为指向块设备
	 * 描述符（block_device）的指针，同时可以通过“连接件” i_devices链入到
	 * 块设备的inodes链表.
	 * 如果inode表示字符设备，则i_rdev保存了字符设备编号，i_cdev为指向字符设备
	 * 描述符（cdev）的指针，同时通过i_devices链入到字符设备的list链表
	 */
	union {
		struct pipe_inode_info	*i_pipe;
		struct block_device	*i_bdev;
		struct cdev		*i_cdev;
		char			*i_link;
		unsigned		i_dir_seq;
	};

	/* inode版本号 （在某些文件系统中使用）*/
	__u32			i_generation;

	/* 这个inode关心的所有事件 */
#ifdef CONFIG_FSNOTIFY
	__u32			i_fsnotify_mask; /* all events this inode cares about */
	struct hlist_head	i_fsnotify_marks;
#endif

#if IS_ENABLED(CONFIG_FS_ENCRYPTION)
	struct fscrypt_info	*i_crypt_info;
#endif

	void			*i_private; /* fs or device private pointer */
};

static inline int inode_unhashed(struct inode *inode)
{
	return hlist_unhashed(&inode->i_hash);
}

/*
 * inode->i_mutex nesting subclasses for the lock validator:
 *
 * 0: the object of the current VFS operation
 * 1: parent
 * 2: child/target
 * 3: xattr
 * 4: second non-directory
 * 5: second parent (when locking independent directories in rename)
 *
 * I_MUTEX_NONDIR2 is for certain operations (such as rename) which lock two
 * non-directories at once.
 *
 * The locking order between these classes is
 * parent[2] -> child -> grandchild -> normal -> xattr -> second non-directory
 */
enum inode_i_mutex_lock_class
{
	I_MUTEX_NORMAL,
	I_MUTEX_PARENT,
	I_MUTEX_CHILD,
	I_MUTEX_XATTR,
	I_MUTEX_NONDIR2,
	I_MUTEX_PARENT2,
};

static inline void inode_lock(struct inode *inode)
{
	down_write(&inode->i_rwsem);
}

static inline void inode_unlock(struct inode *inode)
{
	up_write(&inode->i_rwsem);
}

static inline void inode_lock_shared(struct inode *inode)
{
	down_read(&inode->i_rwsem);
}

static inline void inode_unlock_shared(struct inode *inode)
{
	up_read(&inode->i_rwsem);
}

static inline int inode_trylock(struct inode *inode)
{
	return down_write_trylock(&inode->i_rwsem);
}

static inline int inode_trylock_shared(struct inode *inode)
{
	return down_read_trylock(&inode->i_rwsem);
}

static inline int inode_is_locked(struct inode *inode)
{
	return rwsem_is_locked(&inode->i_rwsem);
}

static inline void inode_lock_nested(struct inode *inode, unsigned subclass)
{
	down_write_nested(&inode->i_rwsem, subclass);
}

void lock_two_nondirectories(struct inode *, struct inode*);
void unlock_two_nondirectories(struct inode *, struct inode*);

/*
 * NOTE: in a 32bit arch with a preemptable kernel and
 * an UP compile the i_size_read/write must be atomic
 * with respect to the local cpu (unlike with preempt disabled),
 * but they don't need to be atomic with respect to other cpus like in
 * true SMP (so they need either to either locally disable irq around
 * the read or for example on x86 they can be still implemented as a
 * cmpxchg8b without the need of the lock prefix). For SMP compiles
 * and 64bit archs it makes no difference if preempt is enabled or not.
 */
static inline loff_t i_size_read(const struct inode *inode)
{
#if BITS_PER_LONG==32 && defined(CONFIG_SMP)
	loff_t i_size;
	unsigned int seq;

	do {
		seq = read_seqcount_begin(&inode->i_size_seqcount);
		i_size = inode->i_size;
	} while (read_seqcount_retry(&inode->i_size_seqcount, seq));
	return i_size;
#elif BITS_PER_LONG==32 && defined(CONFIG_PREEMPT)
	loff_t i_size;

	preempt_disable();
	i_size = inode->i_size;
	preempt_enable();
	return i_size;
#else
	return inode->i_size;
#endif
}

/*
 * NOTE: unlike i_size_read(), i_size_write() does need locking around it
 * (normally i_mutex), otherwise on 32bit/SMP an update of i_size_seqcount
 * can be lost, resulting in subsequent i_size_read() calls spinning forever.
 */
static inline void i_size_write(struct inode *inode, loff_t i_size)
{
#if BITS_PER_LONG==32 && defined(CONFIG_SMP)
	preempt_disable();
	write_seqcount_begin(&inode->i_size_seqcount);
	inode->i_size = i_size;
	write_seqcount_end(&inode->i_size_seqcount);
	preempt_enable();
#elif BITS_PER_LONG==32 && defined(CONFIG_PREEMPT)
	preempt_disable();
	inode->i_size = i_size;
	preempt_enable();
#else
	inode->i_size = i_size;
#endif
}

static inline unsigned iminor(const struct inode *inode)
{
	return MINOR(inode->i_rdev);
}

static inline unsigned imajor(const struct inode *inode)
{
	return MAJOR(inode->i_rdev);
}

extern struct block_device *I_BDEV(struct inode *inode);

struct fown_struct {
	rwlock_t lock;          /* protects pid, uid, euid fields */
	struct pid *pid;	/* pid or -pgrp where SIGIO should be sent */
	enum pid_type pid_type;	/* Kind of process group SIGIO should be sent to */
	kuid_t uid, euid;	/* uid/euid of process setting the owner */
	int signum;		/* posix.1b rt signal to be delivered on IO */
};

/*
 * Track a single file's readahead state
 */
/*
 *                   |<----- async_size ---------|
 * |------------------- size -------------------->|
 * |==================#===========================|
 * ^start             ^page marked with PG_readahead
 */
struct file_ra_state {
	/* 当前预读第一页的索引 */
	pgoff_t start;			/* where readahead started */
	/* 当前预读的页数（当临时禁止预读时为-1，0表示当前预读为空）*/
	unsigned int size;		/* # of readahead pages */
	/* async_size指定一个阈值，预读窗口剩余这么多页时，就开始异步预读 */
	unsigned int async_size;	/* do asynchronous readahead when
					   there are only # of pages ahead */
	/* 当前预读的最大页数 */
	unsigned int ra_pages;		/* Maximum readahead window */
	/* 预读命中失败计数器（用于内存映射）*/
	unsigned int mmap_miss;		/* Cache miss stat for mmap accesses */
	/* prev_pos是前一次读取时，最后的访问位置
	 * 它的初值是-1
	 */
	loff_t prev_pos;		/* Cache last read() position */
};

/*
 * Check if @index falls in the readahead windows.
 */
static inline int ra_has_index(struct file_ra_state *ra, pgoff_t index)
{
	return (index >= ra->start &&
		index <  ra->start + ra->size);
}

struct file {
	union {
		/* 链入到所属文件系统超级块的s_files链表的“连接件” */
		/* 这个也用于delayed_fput的场景，详见fput_many */
		struct llist_node	fu_llist;
		/* 用于rcu机制的域 */
		/* 实际上是用于文件释放的时候，详情可以看看fput函数
		 * 就可以理解了
		 */
		struct rcu_head 	fu_rcuhead;
	} f_u;
	/* 文件路径，包含这个文件的vfsmount以及和文件关联的dentry */
	struct path		f_path;
	/* 指向相应的inode */
	struct inode		*f_inode;	/* cached value */
	/* 指向文件操作表的指针 */
	const struct file_operations	*f_op;

	/*
	 * Protects f_ep_links, f_flags.
	 * Must not be taken from IRQ context.
	 */
	/* 用户保护的自旋锁 */
	spinlock_t		f_lock;
	/* 引用计数 */
	atomic_long_t		f_count;
	/* 打开文件时指定的标志位 */
	unsigned int 		f_flags;
	/* 进程访问模式 */
	fmode_t			f_mode;
	struct mutex		f_pos_lock;
	/* 当前文件的偏移值 */
	loff_t			f_pos;
	/* 用于通过信号进行I/O事件通知的数据 */
	struct fown_struct	f_owner;
	/* f_cred.uid、f_cred.gid指定了用户的UID和GID */
	const struct cred	*f_cred;
	/* 文件预读状态 */
	struct file_ra_state	f_ra;
	/* 版本号，在每次使用后自动增加 */
	u64			f_version;
#ifdef CONFIG_SECURITY
	/* 指向file安全结构的指针 */
	void			*f_security;
#endif
	/* needed for tty driver, and maybe others */
	/* 用于文件系统或设备驱动的私有指针 */
	void			*private_data;

#ifdef CONFIG_EPOLL
	/* Used by fs/eventpoll.c to link all the hooks to this file */
	/* 这个文件的事件轮询等待着链表的表头。
	 * 等待者通过epitem结构的fllink域链入此链表
	 */
	struct list_head	f_ep_links;
	struct list_head	f_tfile_llink;
#endif /* #ifdef CONFIG_EPOLL */
	/* 指向文件地址空间描述符的指针 */
	struct address_space	*f_mapping;
} __attribute__((aligned(4)));	/* lest something weird decides that 2 is OK */

struct file_handle {
	__u32 handle_bytes;
	int handle_type;
	/* file identifier */
	unsigned char f_handle[0];
};

static inline struct file *get_file(struct file *f)
{
	atomic_long_inc(&f->f_count);
	return f;
}
#define get_file_rcu(x) atomic_long_inc_not_zero(&(x)->f_count)
#define fput_atomic(x)	atomic_long_add_unless(&(x)->f_count, -1, 1)
#define file_count(x)	atomic_long_read(&(x)->f_count)

#define	MAX_NON_LFS	((1UL<<31) - 1)

/* Page cache limit. The filesystems should put that into their s_maxbytes 
   limits, otherwise bad things can happen in VM. */ 
#if BITS_PER_LONG==32
#define MAX_LFS_FILESIZE	(((loff_t)PAGE_SIZE << (BITS_PER_LONG-1))-1)
#elif BITS_PER_LONG==64
#define MAX_LFS_FILESIZE 	((loff_t)0x7fffffffffffffffLL)
#endif

#define FL_POSIX	1
#define FL_FLOCK	2
#define FL_DELEG	4	/* NFSv4 delegation */
#define FL_ACCESS	8	/* not trying to lock, just looking */
#define FL_EXISTS	16	/* when unlocking, test for existence */
#define FL_LEASE	32	/* lease held on this file */
#define FL_CLOSE	64	/* unlock on close */
#define FL_SLEEP	128	/* A blocking lock */
#define FL_DOWNGRADE_PENDING	256 /* Lease is being downgraded */
#define FL_UNLOCK_PENDING	512 /* Lease is being broken */
#define FL_OFDLCK	1024	/* lock is "owned" by struct file */
#define FL_LAYOUT	2048	/* outstanding pNFS layout */

/*
 * Special return value from posix_lock_file() and vfs_lock_file() for
 * asynchronous locking.
 */
#define FILE_LOCK_DEFERRED 1

/* legacy typedef, should eventually be removed */
typedef void *fl_owner_t;

struct file_lock;

struct file_lock_operations {
	void (*fl_copy_lock)(struct file_lock *, struct file_lock *);
	void (*fl_release_private)(struct file_lock *);
};

struct lock_manager_operations {
	int (*lm_compare_owner)(struct file_lock *, struct file_lock *);
	unsigned long (*lm_owner_key)(struct file_lock *);
	fl_owner_t (*lm_get_owner)(fl_owner_t);
	void (*lm_put_owner)(fl_owner_t);
	void (*lm_notify)(struct file_lock *);	/* unblock callback */
	int (*lm_grant)(struct file_lock *, int);
	bool (*lm_break)(struct file_lock *);
	int (*lm_change)(struct file_lock *, int, struct list_head *);
	void (*lm_setup)(struct file_lock *, void **);
};

struct lock_manager {
	struct list_head list;
	/*
	 * NFSv4 and up also want opens blocked during the grace period;
	 * NLM doesn't care:
	 */
	bool block_opens;
};

struct net;
void locks_start_grace(struct net *, struct lock_manager *);
void locks_end_grace(struct lock_manager *);
int locks_in_grace(struct net *);
int opens_in_grace(struct net *);

/* that will die - we need it for nfs_lock_info */
#include <linux/nfs_fs_i.h>

/*
 * struct file_lock represents a generic "file lock". It's used to represent
 * POSIX byte range locks, BSD (flock) locks, and leases. It's important to
 * note that the same struct is used to represent both a request for a lock and
 * the lock itself, but the same object is never used for both.
 *
 * FIXME: should we create a separate "struct lock_request" to help distinguish
 * these two uses?
 *
 * The varous i_flctx lists are ordered by:
 *
 * 1) lock owner
 * 2) lock range start
 * 3) lock range end
 *
 * Obviously, the last two criteria only matter for POSIX locks.
 */
struct file_lock {
	struct file_lock *fl_next;	/* singly linked list for this inode  */
	struct list_head fl_list;	/* link into file_lock_context */
	struct hlist_node fl_link;	/* node in global lists */
	struct list_head fl_block;	/* circular list of blocked processes */
	fl_owner_t fl_owner;
	unsigned int fl_flags;
	unsigned char fl_type;
	unsigned int fl_pid;
	int fl_link_cpu;		/* what cpu's list is this on? */
	struct pid *fl_nspid;
	wait_queue_head_t fl_wait;
	struct file *fl_file;
	loff_t fl_start;
	loff_t fl_end;

	struct fasync_struct *	fl_fasync; /* for lease break notifications */
	/* for lease breaks: */
	unsigned long fl_break_time;
	unsigned long fl_downgrade_time;

	const struct file_lock_operations *fl_ops;	/* Callbacks for filesystems */
	const struct lock_manager_operations *fl_lmops;	/* Callbacks for lockmanagers */
	union {
		struct nfs_lock_info	nfs_fl;
		struct nfs4_lock_info	nfs4_fl;
		struct {
			struct list_head link;	/* link in AFS vnode's pending_locks list */
			int state;		/* state of grant or error if -ve */
		} afs;
	} fl_u;
};

struct file_lock_context {
	spinlock_t		flc_lock;
	struct list_head	flc_flock;
	struct list_head	flc_posix;
	struct list_head	flc_lease;
};

/* The following constant reflects the upper bound of the file/locking space */
#ifndef OFFSET_MAX
#define INT_LIMIT(x)	(~((x)1 << (sizeof(x)*8 - 1)))
#define OFFSET_MAX	INT_LIMIT(loff_t)
#define OFFT_OFFSET_MAX	INT_LIMIT(off_t)
#endif

#include <linux/fcntl.h>

extern void send_sigio(struct fown_struct *fown, int fd, int band);

/*
 * Return the inode to use for locking
 *
 * For overlayfs this should be the overlay inode, not the real inode returned
 * by file_inode().  For any other fs file_inode(filp) and locks_inode(filp) are
 * equal.
 */
static inline struct inode *locks_inode(const struct file *f)
{
	return f->f_path.dentry->d_inode;
}

#ifdef CONFIG_FILE_LOCKING
extern int fcntl_getlk(struct file *, unsigned int, struct flock __user *);
extern int fcntl_setlk(unsigned int, struct file *, unsigned int,
			struct flock __user *);

#if BITS_PER_LONG == 32
extern int fcntl_getlk64(struct file *, unsigned int, struct flock64 __user *);
extern int fcntl_setlk64(unsigned int, struct file *, unsigned int,
			struct flock64 __user *);
#endif

extern int fcntl_setlease(unsigned int fd, struct file *filp, long arg);
extern int fcntl_getlease(struct file *filp);

/* fs/locks.c */
void locks_free_lock_context(struct inode *inode);
void locks_free_lock(struct file_lock *fl);
extern void locks_init_lock(struct file_lock *);
extern struct file_lock * locks_alloc_lock(void);
extern void locks_copy_lock(struct file_lock *, struct file_lock *);
extern void locks_copy_conflock(struct file_lock *, struct file_lock *);
extern void locks_remove_posix(struct file *, fl_owner_t);
extern void locks_remove_file(struct file *);
extern void locks_release_private(struct file_lock *);
extern void posix_test_lock(struct file *, struct file_lock *);
extern int posix_lock_file(struct file *, struct file_lock *, struct file_lock *);
extern int posix_unblock_lock(struct file_lock *);
extern int vfs_test_lock(struct file *, struct file_lock *);
extern int vfs_lock_file(struct file *, unsigned int, struct file_lock *, struct file_lock *);
extern int vfs_cancel_lock(struct file *filp, struct file_lock *fl);
extern int locks_lock_inode_wait(struct inode *inode, struct file_lock *fl);
extern int __break_lease(struct inode *inode, unsigned int flags, unsigned int type);
extern void lease_get_mtime(struct inode *, struct timespec *time);
extern int generic_setlease(struct file *, long, struct file_lock **, void **priv);
extern int vfs_setlease(struct file *, long, struct file_lock **, void **);
extern int lease_modify(struct file_lock *, int, struct list_head *);
struct files_struct;
extern void show_fd_locks(struct seq_file *f,
			 struct file *filp, struct files_struct *files);
#else /* !CONFIG_FILE_LOCKING */
static inline int fcntl_getlk(struct file *file, unsigned int cmd,
			      struct flock __user *user)
{
	return -EINVAL;
}

static inline int fcntl_setlk(unsigned int fd, struct file *file,
			      unsigned int cmd, struct flock __user *user)
{
	return -EACCES;
}

#if BITS_PER_LONG == 32
static inline int fcntl_getlk64(struct file *file, unsigned int cmd,
				struct flock64 __user *user)
{
	return -EINVAL;
}

static inline int fcntl_setlk64(unsigned int fd, struct file *file,
				unsigned int cmd, struct flock64 __user *user)
{
	return -EACCES;
}
#endif
static inline int fcntl_setlease(unsigned int fd, struct file *filp, long arg)
{
	return -EINVAL;
}

static inline int fcntl_getlease(struct file *filp)
{
	return F_UNLCK;
}

static inline void
locks_free_lock_context(struct inode *inode)
{
}

static inline void locks_init_lock(struct file_lock *fl)
{
	return;
}

static inline void locks_copy_conflock(struct file_lock *new, struct file_lock *fl)
{
	return;
}

static inline void locks_copy_lock(struct file_lock *new, struct file_lock *fl)
{
	return;
}

static inline void locks_remove_posix(struct file *filp, fl_owner_t owner)
{
	return;
}

static inline void locks_remove_file(struct file *filp)
{
	return;
}

static inline void posix_test_lock(struct file *filp, struct file_lock *fl)
{
	return;
}

static inline int posix_lock_file(struct file *filp, struct file_lock *fl,
				  struct file_lock *conflock)
{
	return -ENOLCK;
}

static inline int posix_unblock_lock(struct file_lock *waiter)
{
	return -ENOENT;
}

static inline int vfs_test_lock(struct file *filp, struct file_lock *fl)
{
	return 0;
}

static inline int vfs_lock_file(struct file *filp, unsigned int cmd,
				struct file_lock *fl, struct file_lock *conf)
{
	return -ENOLCK;
}

static inline int vfs_cancel_lock(struct file *filp, struct file_lock *fl)
{
	return 0;
}

static inline int locks_lock_inode_wait(struct inode *inode, struct file_lock *fl)
{
	return -ENOLCK;
}

static inline int __break_lease(struct inode *inode, unsigned int mode, unsigned int type)
{
	return 0;
}

static inline void lease_get_mtime(struct inode *inode, struct timespec *time)
{
	return;
}

static inline int generic_setlease(struct file *filp, long arg,
				    struct file_lock **flp, void **priv)
{
	return -EINVAL;
}

static inline int vfs_setlease(struct file *filp, long arg,
			       struct file_lock **lease, void **priv)
{
	return -EINVAL;
}

static inline int lease_modify(struct file_lock *fl, int arg,
			       struct list_head *dispose)
{
	return -EINVAL;
}

struct files_struct;
static inline void show_fd_locks(struct seq_file *f,
			struct file *filp, struct files_struct *files) {}
#endif /* !CONFIG_FILE_LOCKING */

static inline struct inode *file_inode(const struct file *f)
{
	return f->f_inode;
}

static inline struct dentry *file_dentry(const struct file *file)
{
	return d_real(file->f_path.dentry, file_inode(file), 0);
}

static inline int locks_lock_file_wait(struct file *filp, struct file_lock *fl)
{
	return locks_lock_inode_wait(locks_inode(filp), fl);
}

struct fasync_struct {
	spinlock_t		fa_lock;
	int			magic;
	int			fa_fd;
	struct fasync_struct	*fa_next; /* singly linked list */
	struct file		*fa_file;
	struct rcu_head		fa_rcu;
};

#define FASYNC_MAGIC 0x4601

/* SMP safe fasync helpers: */
extern int fasync_helper(int, struct file *, int, struct fasync_struct **);
extern struct fasync_struct *fasync_insert_entry(int, struct file *, struct fasync_struct **, struct fasync_struct *);
extern int fasync_remove_entry(struct file *, struct fasync_struct **);
extern struct fasync_struct *fasync_alloc(void);
extern void fasync_free(struct fasync_struct *);

/* can be called from interrupts */
extern void kill_fasync(struct fasync_struct **, int, int);

extern void __f_setown(struct file *filp, struct pid *, enum pid_type, int force);
extern void f_setown(struct file *filp, unsigned long arg, int force);
extern void f_delown(struct file *filp);
extern pid_t f_getown(struct file *filp);
extern int send_sigurg(struct fown_struct *fown);

struct mm_struct;

/*
 *	Umount options
 */

#define MNT_FORCE	0x00000001	/* Attempt to forcibily umount */
#define MNT_DETACH	0x00000002	/* Just detach from the tree */
#define MNT_EXPIRE	0x00000004	/* Mark for expiry */
#define UMOUNT_NOFOLLOW	0x00000008	/* Don't follow symlink on umount */
#define UMOUNT_UNUSED	0x80000000	/* Flag guaranteed to be unused */

/* sb->s_iflags */
#define SB_I_CGROUPWB	0x00000001	/* cgroup-aware writeback enabled */
#define SB_I_NOEXEC	0x00000002	/* Ignore executables on this fs */
#define SB_I_NODEV	0x00000004	/* Ignore devices on this fs */

/* sb->s_iflags to limit user namespace mounts */
#define SB_I_USERNS_VISIBLE		0x00000010 /* fstype already mounted */

/* Possible states of 'frozen' field */
enum {
	SB_UNFROZEN = 0,		/* FS is unfrozen */
	SB_FREEZE_WRITE	= 1,		/* Writes, dir ops, ioctls frozen */
	SB_FREEZE_PAGEFAULT = 2,	/* Page faults stopped as well */
	SB_FREEZE_FS = 3,		/* For internal FS use (e.g. to stop
					 * internal threads if needed) */
	SB_FREEZE_COMPLETE = 4,		/* ->freeze_fs finished successfully */
};

#define SB_FREEZE_LEVELS (SB_FREEZE_COMPLETE - 1)

struct sb_writers {
	int				frozen;		/* Is sb frozen? */
	wait_queue_head_t		wait_unfrozen;	/* for get_super_thawed() */
	struct percpu_rw_semaphore	rw_sem[SB_FREEZE_LEVELS];
};
/* 超级块是整个文件系统的元数据的容器，对于基于磁盘的文件系统，超级块
 *（确切地，是磁盘上超级块）是保存在磁盘设备上固定位置的一个或者多个块，
 * 在装载该磁盘上的文件系统时，磁盘上超级块被读入内存，并根据它构造内存中
 * 超级块，其中一部分是各自文件系统共有的，被提取出来，即VFS超级块。
 * 在装载时，还根据文件系统类型设置超级块操作表,表示VFS超级块的结构就是
 * super_block。
 */
struct super_block {
	/* 链入到所有超级块对象链表的“连接件”*/
	/* 所有的超级块对象被链接到一个循环双链表。链表的第一个元素由super_blocks变量表示，
	 * 而超级块结构的s_list域保存了指向链表中相邻元素的指针
	 */
	struct list_head	s_list;		/* Keep this first */
	/* 存储超级块信息的块设备*/
	dev_t			s_dev;		/* search index; _not_ kdev_t */
	/* 文件系统的块长度的位数*/
	unsigned char		s_blocksize_bits;
	/* 文件系统的块长度（以字节为单位）*/
	unsigned long		s_blocksize;
	/* 文件的最大长度*/
	loff_t			s_maxbytes;	/* Max file size */
	/* 指回到文件系统类型的指针 */
	struct file_system_type	*s_type;
	/* 超级块操作函数 */
	const struct super_operations	*s_op;
	/* 指向磁盘配额操作表的函数 */
	const struct dquot_operations	*dq_op;
	/* 指向磁盘配额管理操作表的函数 */
	const struct quotactl_ops	*s_qcop;
	/* 指向导出操作表的指针，被网络文件系统使用*/
	const struct export_operations *s_export_op;
	/* 装载标志 */
	unsigned long		s_flags;
	/* 内部标志 */
	unsigned long		s_iflags;	/* internal SB_I_* flags */
	/* 文件系统魔数 */
	unsigned long		s_magic;
	/* 指向文件系统根目录的dentry对象 */
	struct dentry		*s_root;
	/* 用于卸载的信号量 */
	struct rw_semaphore	s_umount;
	/* 引用计数器 */
	int			s_count;
	/* 活动引用计数。super_block的引用数中有两个，一个是s_count,另一个是
	 *s_active。s_count是真正的引用数，表示这个super_block能否被释放，s_active
	 * 表示被mount了多少次。不管s_active的值为多少，反映到s_count中，一律算做S_BIAS
	 * 个s_count
	 */
	atomic_t		s_active;
#ifdef CONFIG_SECURITY
	/* 指向superblock 安全结构的指针 */
	void                    *s_security;
#endif
	/* 指向超级块扩展属性结构的指针 */
	const struct xattr_handler **s_xattr;

	const struct fscrypt_operations	*s_cop;

	/* 文件系统的匿名dentry哈希表头，用于处理远程网络文件系统 */
	struct hlist_bl_head	s_anon;		/* anonymous dentries for (nfs) exporting */
	
	struct list_head	s_mounts;		/* list of mounts; _not_ for fs use */
	/* 在磁盘文件系统，为指向块设备描述符的指针；否则为NULL */
	struct block_device	*s_bdev;
	/* 指向后备设备信息描述符的指针。对于某些磁盘文件系统，指向块设备请求队列的
	 * 内嵌设备信息;某些网络文件系统会定义自己的后备设备信息，而其他文件系统
	 * 可能使用空操作
	 */
	struct backing_dev_info *s_bdi;
	/* 对于基于MTD的超级块，该域为指向MTD信息结构的指针 */
	struct mtd_info		*s_mtd;
	/* 链入到所属文件系统类型的超级块实例链表的“链接件” */
	struct hlist_node	s_instances;
	/* 支持的配额类型位图 */
	unsigned int		s_quota_types;	/* Bitmask of supported quota types */
	/* 磁盘配额信息描述符号 */
	struct quota_info	s_dquot;	/* Diskquota specific options */

	struct sb_writers	s_writers;

	/* 对于磁盘文件系统，为块设备名字；否则为文件类型名字 */
	char s_id[32];				/* Informational name */
	u8 s_uuid[16];				/* UUID */
	
	/* 因为super_block 结构体只表示VFS层面的超级块对象。对于具体的文件系统，
	 * 需要定义自己的超级块对象，所以这个s_fs_info就是指向它的。
	 * 一般来说，s_fs_info域所指向的数据为效率考虑而从磁盘上复制到内存中的信息。
	 * 基于磁盘的文件系统在分配或释放磁盘块时会访问并更新位图。VFS允许这些
	 * 文件系统直接在内存中，也就是s_fs_info域上进行操作，而无需访问磁盘
	 */
	void 			*s_fs_info;	/* Filesystem private info */
	unsigned int		s_max_links;
	
	/* 对于磁盘文件系统，记录装载模式（只读、或读/写）*/
	fmode_t			s_mode;

	/* Granularity of c/m/atime in ns.
	   Cannot be worse than a second */
	/* 文件系统文件戳（访问/修改时间等）粒度，以ns为单位 */
	u32		   s_time_gran;

	/*
	 * The next field is for VFS *only*. No filesystems have any business
	 * even looking at it. You had been warned.
	 */
	struct mutex s_vfs_rename_mutex;	/* Kludge */

	/*
	 * Filesystem subtype.  If non-empty the filesystem type field
	 * in /proc/mounts will be "type.subtype"
	 */
	/* 文件系统子类型 */
	/* 基于FUSE（用户空间文件系统）的文件系统，文件系统的类型表示有点麻烦，
	 * 从内核的角度看，只有两种文件系统类型：fuse和fuseblk。但是从用户的角度，
	 * 可以用多种不同的文件系统类型。用户甚至不关心这个文件系统是不是基于FUSE。
	 * 因此，基于FUSE的文件系统会用到子类型。在fstab、mtab和/proc/mounts等中显示
	 * 为“type.subtype” 的形式。
         */
	char *s_subtype;

	/*
	 * Saved mount options for lazy filesystems using
	 * generic_show_options()
	 */
	/* 保存装载选项，以便以后显示，配合generic_show_options()使用，为不想实现更
	 *复杂的装载选项显示逻辑的文件系统提供
	 */
	char __rcu *s_options;
	const struct dentry_operations *s_d_op; /* default d_op for dentries */

	/*
	 * Saved pool identifier for cleancache (-1 means none)
	 */
	int cleancache_poolid;

	struct shrinker s_shrink;	/* per-sb shrinker handle */

	/* Number of inodes with nlink == 0 but still referenced */
	atomic_long_t s_remove_count;

	/* Being remounted read-only */
	int s_readonly_remount;

	/* AIO completions deferred from interrupt context */
	struct workqueue_struct *s_dio_done_wq;
	struct hlist_head s_pins;

	/*
	 * Owning user namespace and default context in which to
	 * interpret filesystem uids, gids, quotas, device nodes,
	 * xattrs and security labels.
	 */
	struct user_namespace *s_user_ns;

	/*
	 * Keep the lru lists last in the structure so they always sit on their
	 * own individual cachelines.
	 */
	/* 文件系统的未使用的dentry 和 inode分别链入到一个最近最少使用链表（lru）中*/
	struct list_lru		s_dentry_lru ____cacheline_aligned_in_smp;
	struct list_lru		s_inode_lru ____cacheline_aligned_in_smp;
	struct rcu_head		rcu;
	struct work_struct	destroy_work;

	struct mutex		s_sync_lock;	/* sync serialisation lock */

	/*
	 * Indicates how deep in a filesystem stack this SB is
	 */
	int s_stack_depth;

	/* s_inode_list_lock protects s_inodes */
	spinlock_t		s_inode_list_lock ____cacheline_aligned_in_smp;
	/* 文件系统的所有inode链表的表头 */
	struct list_head	s_inodes;	/* all inodes */

	spinlock_t		s_inode_wblist_lock;
	struct list_head	s_inodes_wb;	/* writeback inodes */
};

/* Helper functions so that in most cases filesystems will
 * not need to deal directly with kuid_t and kgid_t and can
 * instead deal with the raw numeric values that are stored
 * in the filesystem.
 */
static inline uid_t i_uid_read(const struct inode *inode)
{
	return from_kuid(inode->i_sb->s_user_ns, inode->i_uid);
}

static inline gid_t i_gid_read(const struct inode *inode)
{
	return from_kgid(inode->i_sb->s_user_ns, inode->i_gid);
}

static inline void i_uid_write(struct inode *inode, uid_t uid)
{
	inode->i_uid = make_kuid(inode->i_sb->s_user_ns, uid);
}

static inline void i_gid_write(struct inode *inode, gid_t gid)
{
	inode->i_gid = make_kgid(inode->i_sb->s_user_ns, gid);
}

extern struct timespec current_fs_time(struct super_block *sb);
extern struct timespec current_time(struct inode *inode);

/*
 * Snapshotting support.
 */

void __sb_end_write(struct super_block *sb, int level);
int __sb_start_write(struct super_block *sb, int level, bool wait);

#define __sb_writers_acquired(sb, lev)	\
	percpu_rwsem_acquire(&(sb)->s_writers.rw_sem[(lev)-1], 1, _THIS_IP_)
#define __sb_writers_release(sb, lev)	\
	percpu_rwsem_release(&(sb)->s_writers.rw_sem[(lev)-1], 1, _THIS_IP_)

/**
 * sb_end_write - drop write access to a superblock
 * @sb: the super we wrote to
 *
 * Decrement number of writers to the filesystem. Wake up possible waiters
 * wanting to freeze the filesystem.
 */
static inline void sb_end_write(struct super_block *sb)
{
	__sb_end_write(sb, SB_FREEZE_WRITE);
}

/**
 * sb_end_pagefault - drop write access to a superblock from a page fault
 * @sb: the super we wrote to
 *
 * Decrement number of processes handling write page fault to the filesystem.
 * Wake up possible waiters wanting to freeze the filesystem.
 */
static inline void sb_end_pagefault(struct super_block *sb)
{
	__sb_end_write(sb, SB_FREEZE_PAGEFAULT);
}

/**
 * sb_end_intwrite - drop write access to a superblock for internal fs purposes
 * @sb: the super we wrote to
 *
 * Decrement fs-internal number of writers to the filesystem.  Wake up possible
 * waiters wanting to freeze the filesystem.
 */
static inline void sb_end_intwrite(struct super_block *sb)
{
	__sb_end_write(sb, SB_FREEZE_FS);
}

/**
 * sb_start_write - get write access to a superblock
 * @sb: the super we write to
 *
 * When a process wants to write data or metadata to a file system (i.e. dirty
 * a page or an inode), it should embed the operation in a sb_start_write() -
 * sb_end_write() pair to get exclusion against file system freezing. This
 * function increments number of writers preventing freezing. If the file
 * system is already frozen, the function waits until the file system is
 * thawed.
 *
 * Since freeze protection behaves as a lock, users have to preserve
 * ordering of freeze protection and other filesystem locks. Generally,
 * freeze protection should be the outermost lock. In particular, we have:
 *
 * sb_start_write
 *   -> i_mutex			(write path, truncate, directory ops, ...)
 *   -> s_umount		(freeze_super, thaw_super)
 */
/* sb_start_write-获得对超级块的写访问权限
 *
 * 当进程想要将数据或元数据写入文件系统时（即dirty a page 或 an inode)
 * 他应该把操作嵌入到sb_start_write和sb_end_write这对的中间以获得针对文件系统freeze的排除
 * 此函数用于增加防止freeze 写入程序的数量，如果文件系统已经frozen(冻结)，则该函数将等待，直到文件系统解冻
 *
 * 由于freeze保护行为就像锁一样，用户必须保留freeze 保护的顺序和其他文件系统锁的locks。
 * 一般来说，freeze保护应该是最外层的锁。特别是，我们有：
 * sb_start_write
 *   -> i_mutex                 (write path, truncate, directory ops, ...)
 *   -> s_umount                (freeze_super, thaw_super)
 *
 * This is an internal function, please use sb_start_{write,pagefault,intwrite}
 * instead.
 * int __sb_start_write(struct super_block *sb, int level, bool wait)
 * {
 *	if (!wait)
 *		return percpu_down_read_trylock(sb->s_writers.rw_sem + level-1);
 *
 *	percpu_down_read(sb->s_writers.rw_sem + level-1);
 *	return 1;
 * }
 * 实际上就是把SB_FREEZE_WRITE读写信号量+1
 */
static inline void sb_start_write(struct super_block *sb)
{
	__sb_start_write(sb, SB_FREEZE_WRITE, true);
}

static inline int sb_start_write_trylock(struct super_block *sb)
{
	return __sb_start_write(sb, SB_FREEZE_WRITE, false);
}

/**
 * sb_start_pagefault - get write access to a superblock from a page fault
 * @sb: the super we write to
 *
 * When a process starts handling write page fault, it should embed the
 * operation into sb_start_pagefault() - sb_end_pagefault() pair to get
 * exclusion against file system freezing. This is needed since the page fault
 * is going to dirty a page. This function increments number of running page
 * faults preventing freezing. If the file system is already frozen, the
 * function waits until the file system is thawed.
 *
 * Since page fault freeze protection behaves as a lock, users have to preserve
 * ordering of freeze protection and other filesystem locks. It is advised to
 * put sb_start_pagefault() close to mmap_sem in lock ordering. Page fault
 * handling code implies lock dependency:
 *
 * mmap_sem
 *   -> sb_start_pagefault
 */
static inline void sb_start_pagefault(struct super_block *sb)
{
	__sb_start_write(sb, SB_FREEZE_PAGEFAULT, true);
}

/*
 * sb_start_intwrite - get write access to a superblock for internal fs purposes
 * @sb: the super we write to
 *
 * This is the third level of protection against filesystem freezing. It is
 * free for use by a filesystem. The only requirement is that it must rank
 * below sb_start_pagefault.
 *
 * For example filesystem can call sb_start_intwrite() when starting a
 * transaction which somewhat eases handling of freezing for internal sources
 * of filesystem changes (internal fs threads, discarding preallocation on file
 * close, etc.).
 */
static inline void sb_start_intwrite(struct super_block *sb)
{
	__sb_start_write(sb, SB_FREEZE_FS, true);
}


extern bool inode_owner_or_capable(const struct inode *inode);

/*
 * VFS helper functions..
 */
extern int vfs_create(struct inode *, struct dentry *, umode_t, bool);
extern int vfs_mkdir(struct inode *, struct dentry *, umode_t);
extern int vfs_mknod(struct inode *, struct dentry *, umode_t, dev_t);
extern int vfs_symlink(struct inode *, struct dentry *, const char *);
extern int vfs_link(struct dentry *, struct inode *, struct dentry *, struct inode **);
extern int vfs_rmdir(struct inode *, struct dentry *);
extern int vfs_unlink(struct inode *, struct dentry *, struct inode **);
extern int vfs_rename(struct inode *, struct dentry *, struct inode *, struct dentry *, struct inode **, unsigned int);
extern int vfs_whiteout(struct inode *, struct dentry *);

/*
 * VFS file helper functions.
 */
extern void inode_init_owner(struct inode *inode, const struct inode *dir,
			umode_t mode);
extern bool may_open_dev(const struct path *path);
/*
 * VFS FS_IOC_FIEMAP helper definitions.
 */
struct fiemap_extent_info {
	unsigned int fi_flags;		/* Flags as passed from user */
	unsigned int fi_extents_mapped;	/* Number of mapped extents */
	unsigned int fi_extents_max;	/* Size of fiemap_extent array */
	struct fiemap_extent __user *fi_extents_start; /* Start of
							fiemap_extent array */
};
int fiemap_fill_next_extent(struct fiemap_extent_info *info, u64 logical,
			    u64 phys, u64 len, u32 flags);
int fiemap_check_flags(struct fiemap_extent_info *fieinfo, u32 fs_flags);

/*
 * File types
 *
 * NOTE! These match bits 12..15 of stat.st_mode
 * (ie "(i_mode >> 12) & 15").
 */
#define DT_UNKNOWN	0
#define DT_FIFO		1
#define DT_CHR		2
#define DT_DIR		4
#define DT_BLK		6
#define DT_REG		8
#define DT_LNK		10
#define DT_SOCK		12
#define DT_WHT		14

/*
 * This is the "filldir" function type, used by readdir() to let
 * the kernel specify what kind of dirent layout it wants to have.
 * This allows the kernel to read directories into kernel space or
 * to have different dirent layouts depending on the binary type.
 */
struct dir_context;
typedef int (*filldir_t)(struct dir_context *, const char *, int, loff_t, u64,
			 unsigned);

struct dir_context {
	const filldir_t actor;
	loff_t pos;
};

struct block_device_operations;

/* These macros are for out of kernel modules to test that
 * the kernel supports the unlocked_ioctl and compat_ioctl
 * fields in struct file_operations. */
#define HAVE_COMPAT_IOCTL 1
#define HAVE_UNLOCKED_IOCTL 1

/*
 * These flags let !MMU mmap() govern direct device mapping vs immediate
 * copying more easily for MAP_PRIVATE, especially for ROM filesystems.
 *
 * NOMMU_MAP_COPY:	Copy can be mapped (MAP_PRIVATE)
 * NOMMU_MAP_DIRECT:	Can be mapped directly (MAP_SHARED)
 * NOMMU_MAP_READ:	Can be mapped for reading
 * NOMMU_MAP_WRITE:	Can be mapped for writing
 * NOMMU_MAP_EXEC:	Can be mapped for execution
 */
#define NOMMU_MAP_COPY		0x00000001
#define NOMMU_MAP_DIRECT	0x00000008
#define NOMMU_MAP_READ		VM_MAYREAD
#define NOMMU_MAP_WRITE		VM_MAYWRITE
#define NOMMU_MAP_EXEC		VM_MAYEXEC

#define NOMMU_VMFLAGS \
	(NOMMU_MAP_READ | NOMMU_MAP_WRITE | NOMMU_MAP_EXEC)


struct iov_iter;

struct file_operations {
	struct module *owner;
	loff_t (*llseek) (struct file *, loff_t, int);
	ssize_t (*read) (struct file *, char __user *, size_t, loff_t *);
	ssize_t (*write) (struct file *, const char __user *, size_t, loff_t *);
	ssize_t (*read_iter) (struct kiocb *, struct iov_iter *);
	ssize_t (*write_iter) (struct kiocb *, struct iov_iter *);
	int (*iterate) (struct file *, struct dir_context *);
	int (*iterate_shared) (struct file *, struct dir_context *);
	unsigned int (*poll) (struct file *, struct poll_table_struct *);
	long (*unlocked_ioctl) (struct file *, unsigned int, unsigned long);
	long (*compat_ioctl) (struct file *, unsigned int, unsigned long);
	int (*mmap) (struct file *, struct vm_area_struct *);
	int (*open) (struct inode *, struct file *);
	int (*flush) (struct file *, fl_owner_t id);
	int (*release) (struct inode *, struct file *);
	int (*fsync) (struct file *, loff_t, loff_t, int datasync);
	int (*fasync) (int, struct file *, int);
	int (*lock) (struct file *, int, struct file_lock *);
	ssize_t (*sendpage) (struct file *, struct page *, int, size_t, loff_t *, int);
	unsigned long (*get_unmapped_area)(struct file *, unsigned long, unsigned long, unsigned long, unsigned long);
	int (*check_flags)(int);
	int (*flock) (struct file *, int, struct file_lock *);
	ssize_t (*splice_write)(struct pipe_inode_info *, struct file *, loff_t *, size_t, unsigned int);
	ssize_t (*splice_read)(struct file *, loff_t *, struct pipe_inode_info *, size_t, unsigned int);
	int (*setlease)(struct file *, long, struct file_lock **, void **);
	long (*fallocate)(struct file *file, int mode, loff_t offset,
			  loff_t len);
	void (*show_fdinfo)(struct seq_file *m, struct file *f);
#ifndef CONFIG_MMU
	unsigned (*mmap_capabilities)(struct file *);
#endif
	ssize_t (*copy_file_range)(struct file *, loff_t, struct file *,
			loff_t, size_t, unsigned int);
	int (*clone_file_range)(struct file *, loff_t, struct file *, loff_t,
			u64);
	ssize_t (*dedupe_file_range)(struct file *, u64, u64, struct file *,
			u64);
};

struct inode_operations {
	/* 从文件系统中由父节点（inode）代表的那个目录中寻找当前节点（dentry）的目录项
	 * 并设置结构中的其他信息，且读入其索引节点，在内存中建立对应的inode结构。
	 * 该过程因文件系统而异。所以要通过父节点inode结构中的指针i_op找到相应的inode_operations数据结构。
	 * 该方法只对代表目录的inode有意义。
	 * 第一个参数指向父目录的inode描述符的指针;
	 * 第二个为指向子目录的dentry描述符的指针.
	 * 在调用函数之前，已经为子节点分配了dentry,并且将它关联到父目录的dentry,
	 * 但是它还没有被关联到inode
	 */
	struct dentry * (*lookup) (struct inode *,struct dentry *, unsigned int);
	const char * (*get_link) (struct dentry *, struct inode *, struct delayed_call *);
	/* 该方法适用于代表目录、常规文件和符号链接等的inode.
	 * 用来检查对某个inode是否有指定的权限。
	 * 第一个为指向vfs inode的指针
	 * 第二个为访问模式
	 */
	int (*permission) (struct inode *, int);
	struct posix_acl * (*get_acl)(struct inode *, int);
	/* 该方法只对代表符号链接的inode有意义，用于读取符号链接内容。
	 * 第一个参数为符号链接对应的dentry
	 * 第二个参数用户空间传入的缓冲区
	 * 第三个参数为缓冲区的长度。
	 */
	int (*readlink) (struct dentry *, char __user *,int);

	/* 该方法只对代表目录的inode才有意义，用来在该目录下创建常规文件
	 * 第一个参数为目录对应的inode;第二个参数为常规文件对应的dentry
	 * 第三个参数为文件模式
	 * 在调用这个函数之前，已经为常规文件分配了dentry描述符，但是inode还没有分配。
	 * 并且常规文件的dentry->d_parent已经指向目录的dentry描述符（inode->i_dentry）
	 */
	int (*create) (struct inode *,struct dentry *, umode_t, bool);
	/* 该方法只对代表目录的inode有意义，用来在该目录下创建硬链接。
	 * 第一个参数为链接目标对应的dentry
	 * 第二个参数为目录对应的inode
	 * 第三个参数为硬链接对应的dentry.
	 * 在调用这个函数之前，已经为硬链接分配了dentry,但是它还没有被关联到
	 * 链接目标的inode.硬链接的dentry->d_parent已经指向目录的dentry描述符（inode->i_dentry）
	 * 这个操作的实现应该: 1.递增链接目标的硬链接数（dentry->d_inode->i_nlink);
	 * 2.修改目录内容，添加一项和硬链接相对应.
	 * 3.将链接目标的inode和硬链接的dentry关联起来.
	 */
	int (*link) (struct dentry *,struct inode *,struct dentry *);
	/* 该方法只对代表目录的inode有意义，用于从该目录中删除硬链接.
	 * 函数有两个参数:第一个为目录对应的inode,第二个为硬链接对应的dentry.
	 */
	int (*unlink) (struct inode *,struct dentry *);
	/* 该方法只对代表目录的inode有意义，用于在该目录下创建符号链接。
	 * 注意这里和前面不一样 
	 * 前面是硬链接，这里是符号链接。
	 * 第一个为目录对应的inode
	 * 第二个为符号链接对应的dentry
	 * 第三个参数为符号名
	 * 在调用这个函数之前，已经为符号链接分配了dentry，但它还没有为它
	 * 分配inode,符号链接的dentry->d_parant已经指向目录的dentry描述符（inode->i_dentry）
	 * 这个操作的实现应该：
	 * 1、为符号链接新建一个具体的inode描述符.
	 * 2、修改目录内容，添加一项和符号链接对应.
	 * 3、将符号名写到符号链接对应的inode由（最终会被同步到磁盘上）
	 * 4、将符号链接的vfs inode和dentry关联起来。
	 */
	int (*symlink) (struct inode *,struct dentry *,const char *);
	/* 该方法只对代表目录的inode有意义，用来在该目录下创建子目录。
	 * 第一个参数为目录对应的inode
	 * 第二个参数为子目录对应的dentry
	 * 第三个参数为子目录的模式
	 * 在调用这个函数之前，已经为子目录分配了dentry,但是还没有为它分配inode,
	 * 子目录的dentry->d_parent已经指向目录的dentry描述符（inode->i_dentry）
	 * 这个操作的实现应该：
	 * 1、为子目录新建一个具体的inode描述符
	 * 2、修改目录内容，添加一项和子目录对应。
	 * 3、江子目录的vfs inode和dentry关联起来
	 */
	int (*mkdir) (struct inode *,struct dentry *,umode_t);
	/* 该方法只对代表目录的inode有意义，用来在目录中删除子目录.
	 * 函数有两个参数
	 * 第一个为目录对应的inode
	 * 第二个为子目录对应的dentry
	 */
	int (*rmdir) (struct inode *,struct dentry *);
	/* 该方法只对代表目录的inode有意义，用来在目录中创建一个块（或字符）special文件。
	 * 同常规文件一样，块（或字符）special文件也有自己的inode,但其中只需要保存块（或字符）special的主设备号和次设备号。
	 * 第一个参数为目录对应的inode
	 * 第二个为块（或字符）设备文件对应的dentry
	 * 第三个为文件模式
	 * 第四个为设备号
	 * 在调用这个函数之前，已经为块（或字符）设备分配了dentry,但是还没有为它分配inode.
	 * 文件的dentry->d_parent已经指向目录的dentry描述符（inode->i_dentry)
	 * 这个操作的实现应该：
	 * 1、为块（或字符）设备文件新建一个具体的inode描述符
	 * 2、修改目录内容，添加一项和块（字符）设备文件对应
	 * 3、将块（或字符）设备文件的vfs inode的i_rdev设置成为块（或字符）
设备的设备号
	 * (这个设备号最终会被同步到磁盘)
	 * 将块（或字符）设备文件的vfs inode和dentry关联起来
	 */
	int (*mknod) (struct inode *,struct dentry *,umode_t,dev_t);
	/* 该方法只对代表目录的inode有意义 */
	int (*rename) (struct inode *, struct dentry *,
			struct inode *, struct dentry *, unsigned int);
	/* 该方法适用于代表目录、常规文件和符号链接等的inode，用于设置其属性 */
	int (*setattr) (struct dentry *, struct iattr *);
	/* 该方法适用于代表目录、常规文件和符号链接等inode，用于获取其属性 */
	int (*getattr) (struct vfsmount *mnt, struct dentry *, struct kstat *);
	/* 该方法适用于代表目录、常规文件和符号链接等的inode，用于删除其扩展属性 */
	ssize_t (*listxattr) (struct dentry *, char *, size_t);
	int (*fiemap)(struct inode *, struct fiemap_extent_info *, u64 start,
		      u64 len);
	int (*update_time)(struct inode *, struct timespec *, int);
	int (*atomic_open)(struct inode *, struct dentry *,
			   struct file *, unsigned open_flag,
			   umode_t create_mode, int *opened);
	int (*tmpfile) (struct inode *, struct dentry *, umode_t);
	int (*set_acl)(struct inode *, struct posix_acl *, int);
} ____cacheline_aligned;

ssize_t rw_copy_check_uvector(int type, const struct iovec __user * uvector,
			      unsigned long nr_segs, unsigned long fast_segs,
			      struct iovec *fast_pointer,
			      struct iovec **ret_pointer);

extern ssize_t __vfs_read(struct file *, char __user *, size_t, loff_t *);
extern ssize_t __vfs_write(struct file *, const char __user *, size_t, loff_t *);
extern ssize_t vfs_read(struct file *, char __user *, size_t, loff_t *);
extern ssize_t vfs_write(struct file *, const char __user *, size_t, loff_t *);
extern ssize_t vfs_readv(struct file *, const struct iovec __user *,
		unsigned long, loff_t *, int);
extern ssize_t vfs_writev(struct file *, const struct iovec __user *,
		unsigned long, loff_t *, int);
extern ssize_t vfs_copy_file_range(struct file *, loff_t , struct file *,
				   loff_t, size_t, unsigned int);
extern int vfs_clone_file_range(struct file *file_in, loff_t pos_in,
		struct file *file_out, loff_t pos_out, u64 len);
extern int vfs_dedupe_file_range(struct file *file,
				 struct file_dedupe_range *same);

struct super_operations {
	/* 分配具体文件系统的inode */
   	struct inode *(*alloc_inode)(struct super_block *sb);
	/* 如果具体文件系统定义了自己的内存inode,则需要实现这个函数。
	 * 在具体文件系统的内存inode定义中，应该将VFS inode作为它的一个域。
	 * 如果具体文件系统没有定义自己的内存inode,则不需要实现这个函数
	 */
	void (*destroy_inode)(struct inode *);

	/* 这个方法被VFS核心调用，以标记一个inode为脏。它只有一个参数，即
	 * 指向对应的VFS inode的指针。某些具体的文件系统需要做特定的处理，
	 * 因此需要实现这个方法。例如日志文件系统。
	 */
   	void (*dirty_inode) (struct inode *, int flags);

	/* 这个方法在VFS核心需要将inode信息写回到磁盘上时调。它有两个参数：
	 * 第一个为指向VFS inode的指针，第二个为指向回写控制符的指针，通常
	 * 包含表面写操作是否需要同步的标志，并非所有的文件系统都检查这个标志。
	 * 因此典型的文件系统的write_inode函数实现中都不会执行I/O，只是将blockdev
	 * 映射中的缓冲区标记为“脏”。我们希望首先将执行所有的“脏”动作，然后
	 * 一次性通过blockdev mapping将所有的这些inode块回写到磁盘
	 */
	int (*write_inode) (struct inode *, struct writeback_control *wbc);
	/* 这个方法在inode的最后一个引用释放时被调用。它只有一个参数，即指向VFS inode的指针。
	 * 如果未定义该回调函数，将采用默认的语义，即在inode的链接数不为0时，将它保留到inode缓存，
	 * 否则删除该inode.某些文件系统不想缓存inode，则可以将此回调函数设置为generic_delete_inode，
	 * 这样不论inode的链接数为多少，总是删除inode.还有某些文件系统希望在删除
	 * 之前做其他的善后工作，则应该实现这个回调函数.
	 */
	int (*drop_inode) (struct inode *);
	/* 在 VFS 核心希望删除一个inode时被调用 */
	void (*evict_inode) (struct inode *);
	/* 在VFS核心释放超级块(即unmount）时被调用. */
	void (*put_super) (struct super_block *);
	/* 在VFS核心正在写出和一个超级块关联的所以“脏”数据时被调用。
	 * 这里的第二个参数表明是否这个方法应该等到写操作已经完成之后返回
	 */
	int (*sync_fs)(struct super_block *sb, int wait);
	int (*freeze_super) (struct super_block *);
	/* 在VFS核心锁住一个文件系统，强制使它进入一致状态时被调用。逻辑卷管理器（LVM）
	 * 目前使用这种方法.
	 */
	int (*freeze_fs) (struct super_block *);
	int (*thaw_super) (struct super_block *);
	/* 在VFS 核心解锁一个文件系统时被调用*/
	int (*unfreeze_fs) (struct super_block *);
	/* 在VFS 核心需要获得文件系统统计信息时被调用*/
	int (*statfs) (struct dentry *, struct kstatfs *);
	/*在文件系统被重新装载时被调用*/
	int (*remount_fs) (struct super_block *, int *, char *);
	/*在VFS 核心正在卸载一个文件系统时被调用*/
	void (*umount_begin) (struct super_block *);

	/* 如果文件系统接受装载选项，则必须实现这个回调函数，显示当前活动的选项。
	 * 规则如下: 不是默认或者值和默认不同的选项必须被显示；默认启用或者有默认
	 * 值的选项可以被显示
	 */
	int (*show_options)(struct seq_file *, struct dentry *);
	int (*show_devname)(struct seq_file *, struct dentry *);
	int (*show_path)(struct seq_file *, struct dentry *);
	/* 显示文件系统信息，例如配置、性能等。第一个参数为统计数，第二个参数
	 * 为指向已装载文件系统的指针。
	 */
	int (*show_stats)(struct seq_file *, struct dentry *);
#ifdef CONFIG_QUOTA
	ssize_t (*quota_read)(struct super_block *, int, char *, size_t, loff_t);
	ssize_t (*quota_write)(struct super_block *, int, const char *, size_t, loff_t);
	struct dquot **(*get_dquots)(struct inode *);
#endif
	int (*bdev_try_to_free_page)(struct super_block*, struct page*, gfp_t);
	long (*nr_cached_objects)(struct super_block *,
				  struct shrink_control *);
	long (*free_cached_objects)(struct super_block *,
				    struct shrink_control *);
};

/*
 * Inode flags - they have no relation to superblock flags now
 */
#define S_SYNC		1	/* Writes are synced at once */
#define S_NOATIME	2	/* Do not update access times */
#define S_APPEND	4	/* Append-only file */
/* immutable bit如果被置1了，会有如下行为:
 * 这个文件就不能被修改了，也就是说不可以被删除，不可以被改名,
 * 不可以创建指向这个文件的link（文件链接），文件里面的绝大多数属性信息都不能修改,
 * 也不允许用write mode来打开这个文件.
 */
#define S_IMMUTABLE	8	/* Immutable file */
#define S_DEAD		16	/* removed, but still open directory */
#define S_NOQUOTA	32	/* Inode is not counted to quota */
#define S_DIRSYNC	64	/* Directory modifications are synchronous */
#define S_NOCMTIME	128	/* Do not update file c/mtime */
#define S_SWAPFILE	256	/* Do not truncate: swapon got its bmaps */
#define S_PRIVATE	512	/* Inode is fs-internal */
#define S_IMA		1024	/* Inode has an associated IMA struct */
#define S_AUTOMOUNT	2048	/* Automount/referral quasi-directory */
#define S_NOSEC		4096	/* no suid or xattr security attributes */
#ifdef CONFIG_FS_DAX
#define S_DAX		8192	/* Direct Access, avoiding the page cache */
#else
#define S_DAX		0	/* Make all the DAX code disappear */
#endif

/*
 * Note that nosuid etc flags are inode-specific: setting some file-system
 * flags just means all the inodes inherit those flags by default. It might be
 * possible to override it selectively if you really wanted to with some
 * ioctl() that is not currently implemented.
 *
 * Exception: MS_RDONLY is always applied to the entire file system.
 *
 * Unfortunately, it is possible to change a filesystems flags with it mounted
 * with files in use.  This means that all of the inodes will not have their
 * i_flags updated.  Hence, i_flags no longer inherit the superblock mount
 * flags, so these have to be checked separately. -- rmk@arm.uk.linux.org
 */
#define __IS_FLG(inode, flg)	((inode)->i_sb->s_flags & (flg))

#define IS_RDONLY(inode)	((inode)->i_sb->s_flags & MS_RDONLY)
#define IS_SYNC(inode)		(__IS_FLG(inode, MS_SYNCHRONOUS) || \
					((inode)->i_flags & S_SYNC))
#define IS_DIRSYNC(inode)	(__IS_FLG(inode, MS_SYNCHRONOUS|MS_DIRSYNC) || \
					((inode)->i_flags & (S_SYNC|S_DIRSYNC)))
#define IS_MANDLOCK(inode)	__IS_FLG(inode, MS_MANDLOCK)
#define IS_NOATIME(inode)	__IS_FLG(inode, MS_RDONLY|MS_NOATIME)
#define IS_I_VERSION(inode)	__IS_FLG(inode, MS_I_VERSION)

#define IS_NOQUOTA(inode)	((inode)->i_flags & S_NOQUOTA)
#define IS_APPEND(inode)	((inode)->i_flags & S_APPEND)
#define IS_IMMUTABLE(inode)	((inode)->i_flags & S_IMMUTABLE)
#define IS_POSIXACL(inode)	__IS_FLG(inode, MS_POSIXACL)
/* 目录是否被删除？
 * 删除的时候会先设置dead标志,然后等没人用了再释放结构
 */
#define IS_DEADDIR(inode)	((inode)->i_flags & S_DEAD)
#define IS_NOCMTIME(inode)	((inode)->i_flags & S_NOCMTIME)
#define IS_SWAPFILE(inode)	((inode)->i_flags & S_SWAPFILE)
#define IS_PRIVATE(inode)	((inode)->i_flags & S_PRIVATE)
#define IS_IMA(inode)		((inode)->i_flags & S_IMA)
#define IS_AUTOMOUNT(inode)	((inode)->i_flags & S_AUTOMOUNT)
#define IS_NOSEC(inode)		((inode)->i_flags & S_NOSEC)
#define IS_DAX(inode)		((inode)->i_flags & S_DAX)

#define IS_WHITEOUT(inode)	(S_ISCHR(inode->i_mode) && \
				 (inode)->i_rdev == WHITEOUT_DEV)

static inline bool HAS_UNMAPPED_ID(struct inode *inode)
{
	return !uid_valid(inode->i_uid) || !gid_valid(inode->i_gid);
}

/*
 * Inode state bits.  Protected by inode->i_lock
 *
 * Three bits determine the dirty state of the inode, I_DIRTY_SYNC,
 * I_DIRTY_DATASYNC and I_DIRTY_PAGES.
 *
 * Four bits define the lifetime of an inode.  Initially, inodes are I_NEW,
 * until that flag is cleared.  I_WILL_FREE, I_FREEING and I_CLEAR are set at
 * various stages of removing an inode.
 *
 * Two bits are used for locking and completion notification, I_NEW and I_SYNC.
 *
 * I_DIRTY_SYNC		Inode is dirty, but doesn't have to be written on
 *			fdatasync().  i_atime is the usual cause.
 * I_DIRTY_DATASYNC	Data-related inode changes pending. We keep track of
 *			these changes separately from I_DIRTY_SYNC so that we
 *			don't have to write inode on fdatasync() when only
 *			mtime has changed in it.
 * I_DIRTY_PAGES	Inode has dirty pages.  Inode itself may be clean.
 * I_NEW		Serves as both a mutex and completion notification.
 *			New inodes set I_NEW.  If two processes both create
 *			the same inode, one of them will release its inode and
 *			wait for I_NEW to be released before returning.
 *			Inodes in I_WILL_FREE, I_FREEING or I_CLEAR state can
 *			also cause waiting on I_NEW, without I_NEW actually
 *			being set.  find_inode() uses this to prevent returning
 *			nearly-dead inodes.
 * I_WILL_FREE		Must be set when calling write_inode_now() if i_count
 *			is zero.  I_FREEING must be set when I_WILL_FREE is
 *			cleared.
 * I_FREEING		Set when inode is about to be freed but still has dirty
 *			pages or buffers attached or the inode itself is still
 *			dirty.
 * I_CLEAR		Added by clear_inode().  In this state the inode is
 *			clean and can be destroyed.  Inode keeps I_FREEING.
 *
 *			Inodes that are I_WILL_FREE, I_FREEING or I_CLEAR are
 *			prohibited for many purposes.  iget() must wait for
 *			the inode to be completely released, then create it
 *			anew.  Other functions will just ignore such inodes,
 *			if appropriate.  I_NEW is used for waiting.
 *
 * I_SYNC		Writeback of inode is running. The bit is set during
 *			data writeback, and cleared with a wakeup on the bit
 *			address once it is done. The bit is also used to pin
 *			the inode in memory for flusher thread.
 *
 * I_REFERENCED		Marks the inode as recently references on the LRU list.
 *
 * I_DIO_WAKEUP		Never set.  Only used as a key for wait_on_bit().
 *
 * I_WB_SWITCH		Cgroup bdi_writeback switching in progress.  Used to
 *			synchronize competing switching instances and to tell
 *			wb stat updates to grab mapping->tree_lock.  See
 *			inode_switch_wb_work_fn() for details.
 *
 * Q: What is the difference between I_WILL_FREE and I_FREEING?
 */

/* inode的属性(如:修改时间)改变
 * 1.无论是否有数据写入,文件的修改时间都会更新,即I_DIRTY_SYNC标志会置位
 * sys_write()
 * __generic_file_aio_write_nolock()
 * file_update_time()
 * mark_inode_dirty_sync()
 * __mark_inode_dirty(inode, I_DIRTY_SYNC);
 */
#define I_DIRTY_SYNC		(1 << 0)
/* 对于ext文件系统来说,至少可以认为I_DIRTY_DATASYNC表示文件的树结构发生了变化,
 * 因为sys_write()扩展文件后,文件的树结构肯定发生了变化,
 * 此后sys_fdatasync()就必须将最新的树结构(也就是inode本身)回写到磁盘才能保证文件数据的完整性,
 * 反之,如果文件的树结构未变化,sys_fdatasync()只需将脏页回写即可保证数据完整性.
 * 
 * 例子：
 * 扩展了文件后,I_DIRTY_DATASYNC标志会置位
 * sys_write()
 * generic_write_end()
 * if (pos+copied > inode->i_size){
 * mark_inode_dirty()
 *  __mark_inode_dirty(inode, I_DIRTY_SYNC|I_DIRTY_PAGES|I_DIRTY_DATASYNC);
 * }
 */
#define I_DIRTY_DATASYNC	(1 << 1)
/* inode有脏页
 *
 * 有数据写入成功时,I_DIRTY_PAGES标志会置位
 * sys_write()
 * __block_commit_write()
 * mark_buffer_dirty()
 * __set_page_dirty()
 * __mark_inode_dirty(mapping->host, I_DIRTY_PAGES);
 */
#define I_DIRTY_PAGES		(1 << 2)
#define __I_NEW			3
#define I_NEW			(1 << __I_NEW)
#define I_WILL_FREE		(1 << 4)
/* I_FREEING Set when inode is about to be freed 
 * but still has dirty pages or buffers attached or the inode itself is still dirty.
 *
 * I_FREEING设置当inode即将被释放，但是任然有脏页或者附带的缓冲区，或者本身inode是脏的
 */
#define I_FREEING		(1 << 5)
#define I_CLEAR			(1 << 6)
#define __I_SYNC		7
/* 回写的inode正在运行，该为是在数据回写时设置
 * 一旦完成，就会唤醒去清除这个bit位
 * 该bit也被用来把inode锁在内存中对于flusher线程
 */
#define I_SYNC			(1 << __I_SYNC)
#define I_REFERENCED		(1 << 8)
#define __I_DIO_WAKEUP		9
#define I_DIO_WAKEUP		(1 << __I_DIO_WAKEUP)
#define I_LINKABLE		(1 << 10)
/* 表示该文件的时间戳已经发生了跟新但还没有同步到磁盘上 */
#define I_DIRTY_TIME		(1 << 11)
#define __I_DIRTY_TIME_EXPIRED	12
#define I_DIRTY_TIME_EXPIRED	(1 << __I_DIRTY_TIME_EXPIRED)
#define I_WB_SWITCH		(1 << 13)

#define I_DIRTY (I_DIRTY_SYNC | I_DIRTY_DATASYNC | I_DIRTY_PAGES)
#define I_DIRTY_ALL (I_DIRTY | I_DIRTY_TIME)

extern void __mark_inode_dirty(struct inode *, int);
static inline void mark_inode_dirty(struct inode *inode)
{
	__mark_inode_dirty(inode, I_DIRTY);
}

static inline void mark_inode_dirty_sync(struct inode *inode)
{
	/* I_DIRTY_SYNC表示要进行同步操作 */
	__mark_inode_dirty(inode, I_DIRTY_SYNC);
}

extern void inc_nlink(struct inode *inode);
extern void drop_nlink(struct inode *inode);
extern void clear_nlink(struct inode *inode);
extern void set_nlink(struct inode *inode, unsigned int nlink);

static inline void inode_inc_link_count(struct inode *inode)
{
	inc_nlink(inode);
	mark_inode_dirty(inode);
}

static inline void inode_dec_link_count(struct inode *inode)
{
	drop_nlink(inode);
	mark_inode_dirty(inode);
}

/**
 * inode_inc_iversion - increments i_version
 * @inode: inode that need to be updated
 *
 * Every time the inode is modified, the i_version field will be incremented.
 * The filesystem has to be mounted with i_version flag
 */

static inline void inode_inc_iversion(struct inode *inode)
{
       spin_lock(&inode->i_lock);
       inode->i_version++;
       spin_unlock(&inode->i_lock);
}

enum file_time_flags {
	S_ATIME = 1,
	S_MTIME = 2,
	S_CTIME = 4,
	S_VERSION = 8,
};

extern void touch_atime(const struct path *);
static inline void file_accessed(struct file *file)
{
	if (!(file->f_flags & O_NOATIME))
		touch_atime(&file->f_path);
}

int sync_inode(struct inode *inode, struct writeback_control *wbc);
int sync_inode_metadata(struct inode *inode, int wait);

/* 
 *linux支持多种文件系统，每种文件系统都有一个文件系统类型
 *无聊是编译到内核，还是作为模块动态转载，文件系统类型需要
 *调用register_filesystem向VFS核心注册，不再使用时，应该
 *调用unregister_filesystem从VFS核心注销
 */	
struct file_system_type {
	/*文件系统类型名字*/
	const char *name;
	/*文件系统类型标志*/
	int fs_flags;
#define FS_REQUIRES_DEV		1 
#define FS_BINARY_MOUNTDATA	2
#define FS_HAS_SUBTYPE		4
#define FS_USERNS_MOUNT		8	/* Can be mounted by userns root */
#define FS_RENAME_DOES_D_MOVE	32768	/* FS will handle d_move() during rename() internally. */
	
	/*在这种类型的文件系统实例被装载时被调用*/
	struct dentry *(*mount) (struct file_system_type *, int,
		       const char *, void *);
	
	/*在这种类型的文件系统实例被卸载时被调用*/
	void (*kill_sb) (struct super_block *);
	
	/*指向实现了这个文件系统的模块的指针*/
	struct module *owner;
	
	/*指向文件系统类型链表的下一个元素*/
	struct file_system_type * next;
	
	/*该文件系统类型的所有超级快实例链表的表头*/
	/*比如/dev/sda1被格式化成某种文件系统然后被mount的时候加入到这个队列里面来*/
	struct hlist_head fs_supers;

	/*用于调试锁依赖性*/
	struct lock_class_key s_lock_key;
	struct lock_class_key s_umount_key;
	struct lock_class_key s_vfs_rename_key;
	struct lock_class_key s_writers_key[SB_FREEZE_LEVELS];

	struct lock_class_key i_lock_key;
	struct lock_class_key i_mutex_key;
	struct lock_class_key i_mutex_dir_key;
};

#define MODULE_ALIAS_FS(NAME) MODULE_ALIAS("fs-" NAME)

extern struct dentry *mount_ns(struct file_system_type *fs_type,
	int flags, void *data, void *ns, struct user_namespace *user_ns,
	int (*fill_super)(struct super_block *, void *, int));
extern struct dentry *mount_bdev(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data,
	int (*fill_super)(struct super_block *, void *, int));
extern struct dentry *mount_single(struct file_system_type *fs_type,
	int flags, void *data,
	int (*fill_super)(struct super_block *, void *, int));
extern struct dentry *mount_nodev(struct file_system_type *fs_type,
	int flags, void *data,
	int (*fill_super)(struct super_block *, void *, int));
extern struct dentry *mount_subtree(struct vfsmount *mnt, const char *path);
void generic_shutdown_super(struct super_block *sb);
void kill_block_super(struct super_block *sb);
void kill_anon_super(struct super_block *sb);
void kill_litter_super(struct super_block *sb);
void deactivate_super(struct super_block *sb);
void deactivate_locked_super(struct super_block *sb);
int set_anon_super(struct super_block *s, void *data);
int get_anon_bdev(dev_t *);
void free_anon_bdev(dev_t);
struct super_block *sget_userns(struct file_system_type *type,
			int (*test)(struct super_block *,void *),
			int (*set)(struct super_block *,void *),
			int flags, struct user_namespace *user_ns,
			void *data);
struct super_block *sget(struct file_system_type *type,
			int (*test)(struct super_block *,void *),
			int (*set)(struct super_block *,void *),
			int flags, void *data);
extern struct dentry *mount_pseudo_xattr(struct file_system_type *, char *,
					 const struct super_operations *ops,
					 const struct xattr_handler **xattr,
					 const struct dentry_operations *dops,
					 unsigned long);

static inline struct dentry *
mount_pseudo(struct file_system_type *fs_type, char *name,
	     const struct super_operations *ops,
	     const struct dentry_operations *dops, unsigned long magic)
{
	return mount_pseudo_xattr(fs_type, name, ops, NULL, dops, magic);
}

/* Alas, no aliases. Too much hassle with bringing module.h everywhere */
#define fops_get(fops) \
	(((fops) && try_module_get((fops)->owner) ? (fops) : NULL))
#define fops_put(fops) \
	do { if (fops) module_put((fops)->owner); } while(0)
/*
 * This one is to be used *ONLY* from ->open() instances.
 * fops must be non-NULL, pinned down *and* module dependencies
 * should be sufficient to pin the caller down as well.
 */
#define replace_fops(f, fops) \
	do {	\
		struct file *__file = (f); \
		fops_put(__file->f_op); \
		BUG_ON(!(__file->f_op = (fops))); \
	} while(0)

extern int register_filesystem(struct file_system_type *);
extern int unregister_filesystem(struct file_system_type *);
extern struct vfsmount *kern_mount_data(struct file_system_type *, void *data);
#define kern_mount(type) kern_mount_data(type, NULL)
extern void kern_unmount(struct vfsmount *mnt);
extern int may_umount_tree(struct vfsmount *);
extern int may_umount(struct vfsmount *);
extern long do_mount(const char *, const char __user *,
		     const char *, unsigned long, void *);
extern struct vfsmount *collect_mounts(struct path *);
extern void drop_collected_mounts(struct vfsmount *);
extern int iterate_mounts(int (*)(struct vfsmount *, void *), void *,
			  struct vfsmount *);
extern int vfs_statfs(struct path *, struct kstatfs *);
extern int user_statfs(const char __user *, struct kstatfs *);
extern int fd_statfs(int, struct kstatfs *);
extern int vfs_ustat(dev_t, struct kstatfs *);
extern int freeze_super(struct super_block *super);
extern int thaw_super(struct super_block *super);
extern bool our_mnt(struct vfsmount *mnt);

extern int current_umask(void);

extern void ihold(struct inode * inode);
extern void iput(struct inode *);
extern int generic_update_time(struct inode *, struct timespec *, int);

/* /sys/fs */
extern struct kobject *fs_kobj;
/* MAX_RW_COUNT是一个宏：INT_MAX & PAGE_MASK，INT_MAX是2^31，理论上每次write可写的buff大小是2^31-2^12=2147479552 */
#define MAX_RW_COUNT (INT_MAX & PAGE_MASK)

#ifdef CONFIG_MANDATORY_FILE_LOCKING
extern int locks_mandatory_locked(struct file *);
extern int locks_mandatory_area(struct inode *, struct file *, loff_t, loff_t, unsigned char);

/*
 * Candidates for mandatory locking have the setgid bit set
 * but no group execute bit -  an otherwise meaningless combination.
 */
/* 我们都知道rm -rf /在 Linux 中是非常危险的命令.如果我们以 root 用户身份执行该命令,它甚至可以删除正在运行的系统中的所有文件.
 * 这是因为 Linux 通常不会自动给打开的文件加锁，所以即使是正在运行的文件，仍然有可能被 rm 命令删除.
 * Linux 支持两种文件锁:协同锁(Advisory lock)和强制锁(Mandatory lock).
 *
 * 协同锁定不是强制性锁方案，仅当参与的进程通过显式获取锁进行协作时，它才有效.
 * 否则,如果某个进程根本不知道锁，则这个协同锁会被忽略掉(意味着各个进程间必须协商并遵守这个协同锁的机制，才能发挥锁的作用)
 *
 * 强制锁(Mandatory Lock)
 * 与协作锁不同，强制锁不需要参与进程之间的任何合作。一旦在文件上激活了强制锁，操作系统便会阻止其他进程读取或写入文件.
 * 要在 Linux 中启用强制性文件锁定，必须满足两个要求:
 * 1、我们必须使用 mand 选项挂载文件系统(挂载-o mand FILESYSTEM MOUNT_POINT).
 * 2、我们必须为要锁定的文件（chmod g + s，g-x FILE）打开 set-group-ID 位，并关闭组执行位.
 * 使用强制锁之后，这个锁会在操作系统级别进行管理和控制.
 */
static inline int __mandatory_lock(struct inode *ino)
{
	return (ino->i_mode & (S_ISGID | S_IXGRP)) == S_ISGID;
}

/*
 * ... and these candidates should be on MS_MANDLOCK mounted fs,
 * otherwise these will be advisory locks
 */

static inline int mandatory_lock(struct inode *ino)
{
	return IS_MANDLOCK(ino) && __mandatory_lock(ino);
}

static inline int locks_verify_locked(struct file *file)
{
	if (mandatory_lock(locks_inode(file)))
		return locks_mandatory_locked(file);
	return 0;
}

static inline int locks_verify_truncate(struct inode *inode,
				    struct file *f,
				    loff_t size)
{
	if (!inode->i_flctx || !mandatory_lock(inode))
		return 0;

	if (size < inode->i_size) {
		return locks_mandatory_area(inode, f, size, inode->i_size - 1,
				F_WRLCK);
	} else {
		return locks_mandatory_area(inode, f, inode->i_size, size - 1,
				F_WRLCK);
	}
}

#else /* !CONFIG_MANDATORY_FILE_LOCKING */

static inline int locks_mandatory_locked(struct file *file)
{
	return 0;
}

static inline int locks_mandatory_area(struct inode *inode, struct file *filp,
                                       loff_t start, loff_t end, unsigned char type)
{
	return 0;
}

static inline int __mandatory_lock(struct inode *inode)
{
	return 0;
}

static inline int mandatory_lock(struct inode *inode)
{
	return 0;
}

static inline int locks_verify_locked(struct file *file)
{
	return 0;
}

static inline int locks_verify_truncate(struct inode *inode, struct file *filp,
					size_t size)
{
	return 0;
}

#endif /* CONFIG_MANDATORY_FILE_LOCKING */


#ifdef CONFIG_FILE_LOCKING
static inline int break_lease(struct inode *inode, unsigned int mode)
{
	/*
	 * Since this check is lockless, we must ensure that any refcounts
	 * taken are done before checking i_flctx->flc_lease. Otherwise, we
	 * could end up racing with tasks trying to set a new lease on this
	 * file.
	 */
	smp_mb();
	if (inode->i_flctx && !list_empty_careful(&inode->i_flctx->flc_lease))
		return __break_lease(inode, mode, FL_LEASE);
	return 0;
}

static inline int break_deleg(struct inode *inode, unsigned int mode)
{
	/*
	 * Since this check is lockless, we must ensure that any refcounts
	 * taken are done before checking i_flctx->flc_lease. Otherwise, we
	 * could end up racing with tasks trying to set a new lease on this
	 * file.
	 */
	smp_mb();
	if (inode->i_flctx && !list_empty_careful(&inode->i_flctx->flc_lease))
		return __break_lease(inode, mode, FL_DELEG);
	return 0;
}

static inline int try_break_deleg(struct inode *inode, struct inode **delegated_inode)
{
	int ret;

	ret = break_deleg(inode, O_WRONLY|O_NONBLOCK);
	if (ret == -EWOULDBLOCK && delegated_inode) {
		*delegated_inode = inode;
		ihold(inode);
	}
	return ret;
}

static inline int break_deleg_wait(struct inode **delegated_inode)
{
	int ret;

	ret = break_deleg(*delegated_inode, O_WRONLY);
	iput(*delegated_inode);
	*delegated_inode = NULL;
	return ret;
}

static inline int break_layout(struct inode *inode, bool wait)
{
	smp_mb();
	if (inode->i_flctx && !list_empty_careful(&inode->i_flctx->flc_lease))
		return __break_lease(inode,
				wait ? O_WRONLY : O_WRONLY | O_NONBLOCK,
				FL_LAYOUT);
	return 0;
}

#else /* !CONFIG_FILE_LOCKING */
static inline int break_lease(struct inode *inode, unsigned int mode)
{
	return 0;
}

static inline int break_deleg(struct inode *inode, unsigned int mode)
{
	return 0;
}

static inline int try_break_deleg(struct inode *inode, struct inode **delegated_inode)
{
	return 0;
}

static inline int break_deleg_wait(struct inode **delegated_inode)
{
	BUG();
	return 0;
}

static inline int break_layout(struct inode *inode, bool wait)
{
	return 0;
}

#endif /* CONFIG_FILE_LOCKING */

/* fs/open.c */
struct audit_names;
struct filename {
	/* 指向实际的字符串*/ 
	const char		*name;	/* pointer to actual string */
	/* 指向用户空间的字符串的filename */
	const __user char	*uptr;	/* original userland pointer */
	struct audit_names	*aname;
	/* 引用计数 */
	int			refcnt;
	/* 如果字符串过小，那么存储内嵌的字符串内存
	 * 如果字符串大于offsetof(struct filename, iname[1]);
	 * 那么这里就留一个iname[0]
	 */
	const char		iname[];
};

extern long vfs_truncate(const struct path *, loff_t);
extern int do_truncate(struct dentry *, loff_t start, unsigned int time_attrs,
		       struct file *filp);
extern int vfs_fallocate(struct file *file, int mode, loff_t offset,
			loff_t len);
extern long do_sys_open(int dfd, const char __user *filename, int flags,
			umode_t mode);
extern struct file *file_open_name(struct filename *, int, umode_t);
extern struct file *filp_open(const char *, int, umode_t);
extern struct file *file_open_root(struct dentry *, struct vfsmount *,
				   const char *, int, umode_t);
extern struct file * dentry_open(const struct path *, int, const struct cred *);
extern int filp_close(struct file *, fl_owner_t id);

extern struct filename *getname_flags(const char __user *, int, int *);
extern struct filename *getname(const char __user *);
extern struct filename *getname_kernel(const char *);
extern void putname(struct filename *name);

enum {
	FILE_CREATED = 1,
	FILE_OPENED = 2
};
extern int finish_open(struct file *file, struct dentry *dentry,
			int (*open)(struct inode *, struct file *),
			int *opened);
extern int finish_no_open(struct file *file, struct dentry *dentry);

/* fs/ioctl.c */

extern int ioctl_preallocate(struct file *filp, void __user *argp);

/* fs/dcache.c */
extern void __init vfs_caches_init_early(void);
extern void __init vfs_caches_init(void);

extern struct kmem_cache *names_cachep;

#define __getname()		kmem_cache_alloc(names_cachep, GFP_KERNEL)
#define __putname(name)		kmem_cache_free(names_cachep, (void *)(name))

#ifdef CONFIG_BLOCK
extern int register_blkdev(unsigned int, const char *);
extern void unregister_blkdev(unsigned int, const char *);
extern struct block_device *bdget(dev_t);
extern struct block_device *bdgrab(struct block_device *bdev);
extern void bd_set_size(struct block_device *, loff_t size);
extern void bd_forget(struct inode *inode);
extern void bdput(struct block_device *);
extern void invalidate_bdev(struct block_device *);
extern void iterate_bdevs(void (*)(struct block_device *, void *), void *);
extern int sync_blockdev(struct block_device *bdev);
extern void kill_bdev(struct block_device *);
extern struct super_block *freeze_bdev(struct block_device *);
extern void emergency_thaw_all(void);
extern int thaw_bdev(struct block_device *bdev, struct super_block *sb);
extern int fsync_bdev(struct block_device *);

extern struct super_block *blockdev_superblock;

static inline bool sb_is_blkdev_sb(struct super_block *sb)
{
	return sb == blockdev_superblock;
}
#else
static inline void bd_forget(struct inode *inode) {}
static inline int sync_blockdev(struct block_device *bdev) { return 0; }
static inline void kill_bdev(struct block_device *bdev) {}
static inline void invalidate_bdev(struct block_device *bdev) {}

static inline struct super_block *freeze_bdev(struct block_device *sb)
{
	return NULL;
}

static inline int thaw_bdev(struct block_device *bdev, struct super_block *sb)
{
	return 0;
}

static inline void iterate_bdevs(void (*f)(struct block_device *, void *), void *arg)
{
}

static inline bool sb_is_blkdev_sb(struct super_block *sb)
{
	return false;
}
#endif
extern int sync_filesystem(struct super_block *);
extern const struct file_operations def_blk_fops;
extern const struct file_operations def_chr_fops;
#ifdef CONFIG_BLOCK
extern int ioctl_by_bdev(struct block_device *, unsigned, unsigned long);
extern int blkdev_ioctl(struct block_device *, fmode_t, unsigned, unsigned long);
extern long compat_blkdev_ioctl(struct file *, unsigned, unsigned long);
extern int blkdev_get(struct block_device *bdev, fmode_t mode, void *holder);
extern struct block_device *blkdev_get_by_path(const char *path, fmode_t mode,
					       void *holder);
extern struct block_device *blkdev_get_by_dev(dev_t dev, fmode_t mode,
					      void *holder);
extern void blkdev_put(struct block_device *bdev, fmode_t mode);
extern int __blkdev_reread_part(struct block_device *bdev);
extern int blkdev_reread_part(struct block_device *bdev);

#ifdef CONFIG_SYSFS
extern int bd_link_disk_holder(struct block_device *bdev, struct gendisk *disk);
extern void bd_unlink_disk_holder(struct block_device *bdev,
				  struct gendisk *disk);
#else
static inline int bd_link_disk_holder(struct block_device *bdev,
				      struct gendisk *disk)
{
	return 0;
}
static inline void bd_unlink_disk_holder(struct block_device *bdev,
					 struct gendisk *disk)
{
}
#endif
#endif

/* fs/char_dev.c */
#define CHRDEV_MAJOR_HASH_SIZE	255
/* Marks the bottom of the first segment of free char majors */
#define CHRDEV_MAJOR_DYN_END 234
extern int alloc_chrdev_region(dev_t *, unsigned, unsigned, const char *);
extern int register_chrdev_region(dev_t, unsigned, const char *);
extern int __register_chrdev(unsigned int major, unsigned int baseminor,
			     unsigned int count, const char *name,
			     const struct file_operations *fops);
extern void __unregister_chrdev(unsigned int major, unsigned int baseminor,
				unsigned int count, const char *name);
extern void unregister_chrdev_region(dev_t, unsigned);
extern void chrdev_show(struct seq_file *,off_t);

static inline int register_chrdev(unsigned int major, const char *name,
				  const struct file_operations *fops)
{
	return __register_chrdev(major, 0, 256, name, fops);
}

static inline void unregister_chrdev(unsigned int major, const char *name)
{
	__unregister_chrdev(major, 0, 256, name);
}

/* fs/block_dev.c */
#define BDEVNAME_SIZE	32	/* Largest string for a blockdev identifier */
#define BDEVT_SIZE	10	/* Largest string for MAJ:MIN for blkdev */

#ifdef CONFIG_BLOCK
#define BLKDEV_MAJOR_HASH_SIZE	255
extern const char *__bdevname(dev_t, char *buffer);
extern const char *bdevname(struct block_device *bdev, char *buffer);
extern struct block_device *lookup_bdev(const char *);
extern void blkdev_show(struct seq_file *,off_t);

#else
#define BLKDEV_MAJOR_HASH_SIZE	0
#endif

extern void init_special_inode(struct inode *, umode_t, dev_t);

/* Invalid inode operations -- fs/bad_inode.c */
extern void make_bad_inode(struct inode *);
extern bool is_bad_inode(struct inode *);

#ifdef CONFIG_BLOCK
static inline bool op_is_write(unsigned int op)
{
	return op == REQ_OP_READ ? false : true;
}

/*
 * return data direction, READ or WRITE
 */
static inline int bio_data_dir(struct bio *bio)
{
	return op_is_write(bio_op(bio)) ? WRITE : READ;
}

extern void check_disk_size_change(struct gendisk *disk,
				   struct block_device *bdev);
extern int revalidate_disk(struct gendisk *);
extern int check_disk_change(struct block_device *);
extern int __invalidate_device(struct block_device *, bool);
extern int invalidate_partition(struct gendisk *, int);
#endif
unsigned long invalidate_mapping_pages(struct address_space *mapping,
					pgoff_t start, pgoff_t end);

static inline void invalidate_remote_inode(struct inode *inode)
{
	if (S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode) ||
	    S_ISLNK(inode->i_mode))
		invalidate_mapping_pages(inode->i_mapping, 0, -1);
}
extern int invalidate_inode_pages2(struct address_space *mapping);
extern int invalidate_inode_pages2_range(struct address_space *mapping,
					 pgoff_t start, pgoff_t end);
extern int write_inode_now(struct inode *, int);
extern int filemap_fdatawrite(struct address_space *);
extern int filemap_flush(struct address_space *);
extern int filemap_fdatawait(struct address_space *);
extern void filemap_fdatawait_keep_errors(struct address_space *);
extern int filemap_fdatawait_range(struct address_space *, loff_t lstart,
				   loff_t lend);
extern int filemap_write_and_wait(struct address_space *mapping);
extern int filemap_write_and_wait_range(struct address_space *mapping,
				        loff_t lstart, loff_t lend);
extern int __filemap_fdatawrite_range(struct address_space *mapping,
				loff_t start, loff_t end, int sync_mode);
extern int filemap_fdatawrite_range(struct address_space *mapping,
				loff_t start, loff_t end);
extern int filemap_check_errors(struct address_space *mapping);

extern int vfs_fsync_range(struct file *file, loff_t start, loff_t end,
			   int datasync);
extern int vfs_fsync(struct file *file, int datasync);

/*
 * Sync the bytes written if this was a synchronous write.  Expect ki_pos
 * to already be updated for the write, and will return either the amount
 * of bytes passed in, or an error if syncing the file failed.
 */
static inline ssize_t generic_write_sync(struct kiocb *iocb, ssize_t count)
{
	if (iocb->ki_flags & IOCB_DSYNC) {
		int ret = vfs_fsync_range(iocb->ki_filp,
				iocb->ki_pos - count, iocb->ki_pos - 1,
				(iocb->ki_flags & IOCB_SYNC) ? 0 : 1);
		if (ret)
			return ret;
	}

	return count;
}

extern void emergency_sync(void);
extern void emergency_remount(void);
#ifdef CONFIG_BLOCK
extern sector_t bmap(struct inode *, sector_t);
#endif
extern int notify_change(struct dentry *, struct iattr *, struct inode **);
extern int inode_permission(struct inode *, int);
extern int __inode_permission(struct inode *, int);
extern int generic_permission(struct inode *, int);
extern int __check_sticky(struct inode *dir, struct inode *inode);

static inline bool execute_ok(struct inode *inode)
{
	return (inode->i_mode & S_IXUGO) || S_ISDIR(inode->i_mode);
}

static inline void file_start_write(struct file *file)
{
	/* 如果不是常规文件,那么就返回吧 */
	if (!S_ISREG(file_inode(file)->i_mode))
		return;
	/* 如果是常规文件 */
	__sb_start_write(file_inode(file)->i_sb, SB_FREEZE_WRITE, true);
}

static inline bool file_start_write_trylock(struct file *file)
{
	if (!S_ISREG(file_inode(file)->i_mode))
		return true;
	return __sb_start_write(file_inode(file)->i_sb, SB_FREEZE_WRITE, false);
}

static inline void file_end_write(struct file *file)
{
	if (!S_ISREG(file_inode(file)->i_mode))
		return;
	__sb_end_write(file_inode(file)->i_sb, SB_FREEZE_WRITE);
}

/*
 * get_write_access() gets write permission for a file.
 * put_write_access() releases this write permission.
 * This is used for regular files.
 * We cannot support write (and maybe mmap read-write shared) accesses and
 * MAP_DENYWRITE mmappings simultaneously. The i_writecount field of an inode
 * can have the following values:
 * 0: no writers, no VM_DENYWRITE mappings
 * < 0: (-i_writecount) vm_area_structs with VM_DENYWRITE set exist
 * > 0: (i_writecount) users are writing to the file.
 *
 * Normally we operate on that counter with atomic_{inc,dec} and it's safe
 * except for the cases where we don't hold i_writecount yet. Then we need to
 * use {get,deny}_write_access() - these functions check the sign and refuse
 * to do the change if sign is wrong.
 */
static inline int get_write_access(struct inode *inode)
{
	return atomic_inc_unless_negative(&inode->i_writecount) ? 0 : -ETXTBSY;
}
static inline int deny_write_access(struct file *file)
{
	struct inode *inode = file_inode(file);
	return atomic_dec_unless_positive(&inode->i_writecount) ? 0 : -ETXTBSY;
}
static inline void put_write_access(struct inode * inode)
{
	atomic_dec(&inode->i_writecount);
}
static inline void allow_write_access(struct file *file)
{
	if (file)
		atomic_inc(&file_inode(file)->i_writecount);
}
static inline bool inode_is_open_for_write(const struct inode *inode)
{
	return atomic_read(&inode->i_writecount) > 0;
}

#ifdef CONFIG_IMA
static inline void i_readcount_dec(struct inode *inode)
{
	BUG_ON(!atomic_read(&inode->i_readcount));
	atomic_dec(&inode->i_readcount);
}
static inline void i_readcount_inc(struct inode *inode)
{
	atomic_inc(&inode->i_readcount);
}
#else
static inline void i_readcount_dec(struct inode *inode)
{
	return;
}
static inline void i_readcount_inc(struct inode *inode)
{
	return;
}
#endif
extern int do_pipe_flags(int *, int);

#define __kernel_read_file_id(id) \
	id(UNKNOWN, unknown)		\
	id(FIRMWARE, firmware)		\
	id(FIRMWARE_PREALLOC_BUFFER, firmware)	\
	id(MODULE, kernel-module)		\
	id(KEXEC_IMAGE, kexec-image)		\
	id(KEXEC_INITRAMFS, kexec-initramfs)	\
	id(POLICY, security-policy)		\
	id(MAX_ID, )

#define __fid_enumify(ENUM, dummy) READING_ ## ENUM,
#define __fid_stringify(dummy, str) #str,

enum kernel_read_file_id {
	__kernel_read_file_id(__fid_enumify)
};

static const char * const kernel_read_file_str[] = {
	__kernel_read_file_id(__fid_stringify)
};

static inline const char *kernel_read_file_id_str(enum kernel_read_file_id id)
{
	if (id < 0 || id >= READING_MAX_ID)
		return kernel_read_file_str[READING_UNKNOWN];

	return kernel_read_file_str[id];
}

extern int kernel_read(struct file *, loff_t, char *, unsigned long);
extern int kernel_read_file(struct file *, void **, loff_t *, loff_t,
			    enum kernel_read_file_id);
extern int kernel_read_file_from_path(char *, void **, loff_t *, loff_t,
				      enum kernel_read_file_id);
extern int kernel_read_file_from_fd(int, void **, loff_t *, loff_t,
				    enum kernel_read_file_id);
extern ssize_t kernel_write(struct file *, const char *, size_t, loff_t);
extern ssize_t __kernel_write(struct file *, const char *, size_t, loff_t *);
extern struct file * open_exec(const char *);
 
/* fs/dcache.c -- generic fs support functions */
extern bool is_subdir(struct dentry *, struct dentry *);
extern bool path_is_under(struct path *, struct path *);

extern char *file_path(struct file *, char *, int);

#include <linux/err.h>

/* needed for stackable file system support */
extern loff_t default_llseek(struct file *file, loff_t offset, int whence);

extern loff_t vfs_llseek(struct file *file, loff_t offset, int whence);

extern int inode_init_always(struct super_block *, struct inode *);
extern void inode_init_once(struct inode *);
extern void address_space_init_once(struct address_space *mapping);
extern struct inode * igrab(struct inode *);
extern ino_t iunique(struct super_block *, ino_t);
extern int inode_needs_sync(struct inode *inode);
extern int generic_delete_inode(struct inode *inode);
static inline int generic_drop_inode(struct inode *inode)
{
	return !inode->i_nlink || inode_unhashed(inode);
}

extern struct inode *ilookup5_nowait(struct super_block *sb,
		unsigned long hashval, int (*test)(struct inode *, void *),
		void *data);
extern struct inode *ilookup5(struct super_block *sb, unsigned long hashval,
		int (*test)(struct inode *, void *), void *data);
extern struct inode *ilookup(struct super_block *sb, unsigned long ino);

extern struct inode * iget5_locked(struct super_block *, unsigned long, int (*test)(struct inode *, void *), int (*set)(struct inode *, void *), void *);
extern struct inode * iget_locked(struct super_block *, unsigned long);
extern struct inode *find_inode_nowait(struct super_block *,
				       unsigned long,
				       int (*match)(struct inode *,
						    unsigned long, void *),
				       void *data);
extern int insert_inode_locked4(struct inode *, unsigned long, int (*test)(struct inode *, void *), void *);
extern int insert_inode_locked(struct inode *);
#ifdef CONFIG_DEBUG_LOCK_ALLOC
extern void lockdep_annotate_inode_mutex_key(struct inode *inode);
#else
static inline void lockdep_annotate_inode_mutex_key(struct inode *inode) { };
#endif
extern void unlock_new_inode(struct inode *);
extern unsigned int get_next_ino(void);

extern void __iget(struct inode * inode);
extern void iget_failed(struct inode *);
extern void clear_inode(struct inode *);
extern void __destroy_inode(struct inode *);
extern struct inode *new_inode_pseudo(struct super_block *sb);
extern struct inode *new_inode(struct super_block *sb);
extern void free_inode_nonrcu(struct inode *inode);
extern int should_remove_suid(struct dentry *);
extern int file_remove_privs(struct file *);

extern void __insert_inode_hash(struct inode *, unsigned long hashval);
static inline void insert_inode_hash(struct inode *inode)
{
	__insert_inode_hash(inode, inode->i_ino);
}

extern void __remove_inode_hash(struct inode *);
static inline void remove_inode_hash(struct inode *inode)
{
	if (!inode_unhashed(inode) && !hlist_fake(&inode->i_hash))
		__remove_inode_hash(inode);
}

extern void inode_sb_list_add(struct inode *inode);

#ifdef CONFIG_BLOCK
extern blk_qc_t submit_bio(struct bio *);
extern int bdev_read_only(struct block_device *);
#endif
extern int set_blocksize(struct block_device *, int);
extern int sb_set_blocksize(struct super_block *, int);
extern int sb_min_blocksize(struct super_block *, int);

extern int generic_file_mmap(struct file *, struct vm_area_struct *);
extern int generic_file_readonly_mmap(struct file *, struct vm_area_struct *);
extern ssize_t generic_write_checks(struct kiocb *, struct iov_iter *);
extern ssize_t generic_file_read_iter(struct kiocb *, struct iov_iter *);
extern ssize_t __generic_file_write_iter(struct kiocb *, struct iov_iter *);
extern ssize_t generic_file_write_iter(struct kiocb *, struct iov_iter *);
extern ssize_t generic_file_direct_write(struct kiocb *, struct iov_iter *);
extern ssize_t generic_perform_write(struct file *, struct iov_iter *, loff_t);

ssize_t vfs_iter_read(struct file *file, struct iov_iter *iter, loff_t *ppos);
ssize_t vfs_iter_write(struct file *file, struct iov_iter *iter, loff_t *ppos);

/* fs/block_dev.c */
extern ssize_t blkdev_read_iter(struct kiocb *iocb, struct iov_iter *to);
extern ssize_t blkdev_write_iter(struct kiocb *iocb, struct iov_iter *from);
extern int blkdev_fsync(struct file *filp, loff_t start, loff_t end,
			int datasync);
extern void block_sync_page(struct page *page);

/* fs/splice.c */
extern ssize_t generic_file_splice_read(struct file *, loff_t *,
		struct pipe_inode_info *, size_t, unsigned int);
extern ssize_t iter_file_splice_write(struct pipe_inode_info *,
		struct file *, loff_t *, size_t, unsigned int);
extern ssize_t generic_splice_sendpage(struct pipe_inode_info *pipe,
		struct file *out, loff_t *, size_t len, unsigned int flags);
extern long do_splice_direct(struct file *in, loff_t *ppos, struct file *out,
		loff_t *opos, size_t len, unsigned int flags);


extern void
file_ra_state_init(struct file_ra_state *ra, struct address_space *mapping);
extern loff_t noop_llseek(struct file *file, loff_t offset, int whence);
extern loff_t no_llseek(struct file *file, loff_t offset, int whence);
extern loff_t vfs_setpos(struct file *file, loff_t offset, loff_t maxsize);
extern loff_t generic_file_llseek(struct file *file, loff_t offset, int whence);
extern loff_t generic_file_llseek_size(struct file *file, loff_t offset,
		int whence, loff_t maxsize, loff_t eof);
extern loff_t fixed_size_llseek(struct file *file, loff_t offset,
		int whence, loff_t size);
extern loff_t no_seek_end_llseek_size(struct file *, loff_t, int, loff_t);
extern loff_t no_seek_end_llseek(struct file *, loff_t, int);
extern int generic_file_open(struct inode * inode, struct file * filp);
extern int nonseekable_open(struct inode * inode, struct file * filp);

#ifdef CONFIG_BLOCK
typedef void (dio_submit_t)(struct bio *bio, struct inode *inode,
			    loff_t file_offset);

enum {
	/* need locking between buffered and direct access */
	DIO_LOCKING	= 0x01,

	/* filesystem does not support filling holes */
	DIO_SKIP_HOLES	= 0x02,

	/* filesystem can handle aio writes beyond i_size */
	DIO_ASYNC_EXTEND = 0x04,

	/* inode/fs/bdev does not need truncate protection */
	DIO_SKIP_DIO_COUNT = 0x08,
};

void dio_end_io(struct bio *bio, int error);

ssize_t __blockdev_direct_IO(struct kiocb *iocb, struct inode *inode,
			     struct block_device *bdev, struct iov_iter *iter,
			     get_block_t get_block,
			     dio_iodone_t end_io, dio_submit_t submit_io,
			     int flags);

static inline ssize_t blockdev_direct_IO(struct kiocb *iocb,
					 struct inode *inode,
					 struct iov_iter *iter,
					 get_block_t get_block)
{
	return __blockdev_direct_IO(iocb, inode, inode->i_sb->s_bdev, iter,
			get_block, NULL, NULL, DIO_LOCKING | DIO_SKIP_HOLES);
}
#endif

void inode_dio_wait(struct inode *inode);

/*
 * inode_dio_begin - signal start of a direct I/O requests
 * @inode: inode the direct I/O happens on
 *
 * This is called once we've finished processing a direct I/O request,
 * and is used to wake up callers waiting for direct I/O to be quiesced.
 */
static inline void inode_dio_begin(struct inode *inode)
{
	atomic_inc(&inode->i_dio_count);
}

/*
 * inode_dio_end - signal finish of a direct I/O requests
 * @inode: inode the direct I/O happens on
 *
 * This is called once we've finished processing a direct I/O request,
 * and is used to wake up callers waiting for direct I/O to be quiesced.
 */
static inline void inode_dio_end(struct inode *inode)
{
	if (atomic_dec_and_test(&inode->i_dio_count))
		wake_up_bit(&inode->i_state, __I_DIO_WAKEUP);
}

extern void inode_set_flags(struct inode *inode, unsigned int flags,
			    unsigned int mask);

extern const struct file_operations generic_ro_fops;

#define special_file(m) (S_ISCHR(m)||S_ISBLK(m)||S_ISFIFO(m)||S_ISSOCK(m))

extern int readlink_copy(char __user *, int, const char *);
extern int page_readlink(struct dentry *, char __user *, int);
extern const char *page_get_link(struct dentry *, struct inode *,
				 struct delayed_call *);
extern void page_put_link(void *);
extern int __page_symlink(struct inode *inode, const char *symname, int len,
		int nofs);
extern int page_symlink(struct inode *inode, const char *symname, int len);
extern const struct inode_operations page_symlink_inode_operations;
extern void kfree_link(void *);
extern int generic_readlink(struct dentry *, char __user *, int);
extern void generic_fillattr(struct inode *, struct kstat *);
int vfs_getattr_nosec(struct path *path, struct kstat *stat);
extern int vfs_getattr(struct path *, struct kstat *);
void __inode_add_bytes(struct inode *inode, loff_t bytes);
void inode_add_bytes(struct inode *inode, loff_t bytes);
void __inode_sub_bytes(struct inode *inode, loff_t bytes);
void inode_sub_bytes(struct inode *inode, loff_t bytes);
loff_t inode_get_bytes(struct inode *inode);
void inode_set_bytes(struct inode *inode, loff_t bytes);
const char *simple_get_link(struct dentry *, struct inode *,
			    struct delayed_call *);
extern const struct inode_operations simple_symlink_inode_operations;

extern int iterate_dir(struct file *, struct dir_context *);

extern int vfs_stat(const char __user *, struct kstat *);
extern int vfs_lstat(const char __user *, struct kstat *);
extern int vfs_fstat(unsigned int, struct kstat *);
extern int vfs_fstatat(int , const char __user *, struct kstat *, int);
extern const char *vfs_get_link(struct dentry *, struct delayed_call *);

extern int __generic_block_fiemap(struct inode *inode,
				  struct fiemap_extent_info *fieinfo,
				  loff_t start, loff_t len,
				  get_block_t *get_block);
extern int generic_block_fiemap(struct inode *inode,
				struct fiemap_extent_info *fieinfo, u64 start,
				u64 len, get_block_t *get_block);

extern void get_filesystem(struct file_system_type *fs);
extern void put_filesystem(struct file_system_type *fs);
extern struct file_system_type *get_fs_type(const char *name);
extern struct super_block *get_super(struct block_device *);
extern struct super_block *get_super_thawed(struct block_device *);
extern struct super_block *get_active_super(struct block_device *bdev);
extern void drop_super(struct super_block *sb);
extern void iterate_supers(void (*)(struct super_block *, void *), void *);
extern void iterate_supers_type(struct file_system_type *,
			        void (*)(struct super_block *, void *), void *);

extern int dcache_dir_open(struct inode *, struct file *);
extern int dcache_dir_close(struct inode *, struct file *);
extern loff_t dcache_dir_lseek(struct file *, loff_t, int);
extern int dcache_readdir(struct file *, struct dir_context *);
extern int simple_setattr(struct dentry *, struct iattr *);
extern int simple_getattr(struct vfsmount *, struct dentry *, struct kstat *);
extern int simple_statfs(struct dentry *, struct kstatfs *);
extern int simple_open(struct inode *inode, struct file *file);
extern int simple_link(struct dentry *, struct inode *, struct dentry *);
extern int simple_unlink(struct inode *, struct dentry *);
extern int simple_rmdir(struct inode *, struct dentry *);
extern int simple_rename(struct inode *, struct dentry *,
			 struct inode *, struct dentry *, unsigned int);
extern int noop_fsync(struct file *, loff_t, loff_t, int);
extern int simple_empty(struct dentry *);
extern int simple_readpage(struct file *file, struct page *page);
extern int simple_write_begin(struct file *file, struct address_space *mapping,
			loff_t pos, unsigned len, unsigned flags,
			struct page **pagep, void **fsdata);
extern int simple_write_end(struct file *file, struct address_space *mapping,
			loff_t pos, unsigned len, unsigned copied,
			struct page *page, void *fsdata);
extern int always_delete_dentry(const struct dentry *);
extern struct inode *alloc_anon_inode(struct super_block *);
extern int simple_nosetlease(struct file *, long, struct file_lock **, void **);
extern const struct dentry_operations simple_dentry_operations;

extern struct dentry *simple_lookup(struct inode *, struct dentry *, unsigned int flags);
extern ssize_t generic_read_dir(struct file *, char __user *, size_t, loff_t *);
extern const struct file_operations simple_dir_operations;
extern const struct inode_operations simple_dir_inode_operations;
extern void make_empty_dir_inode(struct inode *inode);
extern bool is_empty_dir_inode(struct inode *inode);
struct tree_descr { char *name; const struct file_operations *ops; int mode; };
struct dentry *d_alloc_name(struct dentry *, const char *);
extern int simple_fill_super(struct super_block *, unsigned long, struct tree_descr *);
extern int simple_pin_fs(struct file_system_type *, struct vfsmount **mount, int *count);
extern void simple_release_fs(struct vfsmount **mount, int *count);

extern ssize_t simple_read_from_buffer(void __user *to, size_t count,
			loff_t *ppos, const void *from, size_t available);
extern ssize_t simple_write_to_buffer(void *to, size_t available, loff_t *ppos,
		const void __user *from, size_t count);

extern int __generic_file_fsync(struct file *, loff_t, loff_t, int);
extern int generic_file_fsync(struct file *, loff_t, loff_t, int);

extern int generic_check_addressable(unsigned, u64);

#ifdef CONFIG_MIGRATION
extern int buffer_migrate_page(struct address_space *,
				struct page *, struct page *,
				enum migrate_mode);
#else
#define buffer_migrate_page NULL
#endif

extern int setattr_prepare(struct dentry *, struct iattr *);
extern int inode_newsize_ok(const struct inode *, loff_t offset);
extern void setattr_copy(struct inode *inode, const struct iattr *attr);

extern int file_update_time(struct file *file);

extern int generic_show_options(struct seq_file *m, struct dentry *root);
extern void save_mount_options(struct super_block *sb, char *options);
extern void replace_mount_options(struct super_block *sb, char *options);

static inline bool io_is_direct(struct file *filp)
{
	return (filp->f_flags & O_DIRECT) || IS_DAX(filp->f_mapping->host);
}

static inline int iocb_flags(struct file *file)
{
	int res = 0;
	/* 如果是追加的形势，这里设置IOCB_APPEND */
	if (file->f_flags & O_APPEND)
		res |= IOCB_APPEND;
	/* 如果是如果是Direct */
	if (io_is_direct(file))
		res |= IOCB_DIRECT;
	/* 如果设置了O_SYNC或者O_DSYNC标志就代表使用同步I/O了.
	 * 如果设置了O_DSYNC标志就需要等待文件数据写入磁盘后才返回.
	 * 而O_SYNC则在O_DSYNC的基础上要求文件元数据也要写入磁盘后才返回 */
	if ((file->f_flags & O_DSYNC) || IS_SYNC(file->f_mapping->host))
		res |= IOCB_DSYNC;
	if (file->f_flags & __O_SYNC)
		res |= IOCB_SYNC;
	return res;
}

static inline ino_t parent_ino(struct dentry *dentry)
{
	ino_t res;

	/*
	 * Don't strictly need d_lock here? If the parent ino could change
	 * then surely we'd have a deeper race in the caller?
	 */
	spin_lock(&dentry->d_lock);
	res = dentry->d_parent->d_inode->i_ino;
	spin_unlock(&dentry->d_lock);
	return res;
}

/* Transaction based IO helpers */

/*
 * An argresp is stored in an allocated page and holds the
 * size of the argument or response, along with its content
 */
struct simple_transaction_argresp {
	ssize_t size;
	char data[0];
};

#define SIMPLE_TRANSACTION_LIMIT (PAGE_SIZE - sizeof(struct simple_transaction_argresp))

char *simple_transaction_get(struct file *file, const char __user *buf,
				size_t size);
ssize_t simple_transaction_read(struct file *file, char __user *buf,
				size_t size, loff_t *pos);
int simple_transaction_release(struct inode *inode, struct file *file);

void simple_transaction_set(struct file *file, size_t n);

/*
 * simple attribute files
 *
 * These attributes behave similar to those in sysfs:
 *
 * Writing to an attribute immediately sets a value, an open file can be
 * written to multiple times.
 *
 * Reading from an attribute creates a buffer from the value that might get
 * read with multiple read calls. When the attribute has been read
 * completely, no further read calls are possible until the file is opened
 * again.
 *
 * All attributes contain a text representation of a numeric value
 * that are accessed with the get() and set() functions.
 */
#define DEFINE_SIMPLE_ATTRIBUTE(__fops, __get, __set, __fmt)		\
static int __fops ## _open(struct inode *inode, struct file *file)	\
{									\
	__simple_attr_check_format(__fmt, 0ull);			\
	return simple_attr_open(inode, file, __get, __set, __fmt);	\
}									\
static const struct file_operations __fops = {				\
	.owner	 = THIS_MODULE,						\
	.open	 = __fops ## _open,					\
	.release = simple_attr_release,					\
	.read	 = simple_attr_read,					\
	.write	 = simple_attr_write,					\
	.llseek	 = generic_file_llseek,					\
}

static inline __printf(1, 2)
void __simple_attr_check_format(const char *fmt, ...)
{
	/* don't do anything, just let the compiler check the arguments; */
}

int simple_attr_open(struct inode *inode, struct file *file,
		     int (*get)(void *, u64 *), int (*set)(void *, u64),
		     const char *fmt);
int simple_attr_release(struct inode *inode, struct file *file);
ssize_t simple_attr_read(struct file *file, char __user *buf,
			 size_t len, loff_t *ppos);
ssize_t simple_attr_write(struct file *file, const char __user *buf,
			  size_t len, loff_t *ppos);

struct ctl_table;
int proc_nr_files(struct ctl_table *table, int write,
		  void __user *buffer, size_t *lenp, loff_t *ppos);
int proc_nr_dentry(struct ctl_table *table, int write,
		  void __user *buffer, size_t *lenp, loff_t *ppos);
int proc_nr_inodes(struct ctl_table *table, int write,
		   void __user *buffer, size_t *lenp, loff_t *ppos);
int __init get_filesystem_list(char *buf);

#define __FMODE_EXEC		((__force int) FMODE_EXEC)
#define __FMODE_NONOTIFY	((__force int) FMODE_NONOTIFY)

#define ACC_MODE(x) ("\004\002\006\006"[(x)&O_ACCMODE])
#define OPEN_FMODE(flag) ((__force fmode_t)(((flag + 1) & O_ACCMODE) | \
					    (flag & __FMODE_NONOTIFY)))

static inline bool is_sxid(umode_t mode)
{
	return (mode & S_ISUID) || ((mode & S_ISGID) && (mode & S_IXGRP));
}

static inline int check_sticky(struct inode *dir, struct inode *inode)
{
	if (!(dir->i_mode & S_ISVTX))
		return 0;

	return __check_sticky(dir, inode);
}

static inline void inode_has_no_xattr(struct inode *inode)
{
	if (!is_sxid(inode->i_mode) && (inode->i_sb->s_flags & MS_NOSEC))
		inode->i_flags |= S_NOSEC;
}

static inline bool is_root_inode(struct inode *inode)
{
	return inode == inode->i_sb->s_root->d_inode;
}

static inline bool dir_emit(struct dir_context *ctx,
			    const char *name, int namelen,
			    u64 ino, unsigned type)
{
	return ctx->actor(ctx, name, namelen, ctx->pos, ino, type) == 0;
}
static inline bool dir_emit_dot(struct file *file, struct dir_context *ctx)
{
	return ctx->actor(ctx, ".", 1, ctx->pos,
			  file->f_path.dentry->d_inode->i_ino, DT_DIR) == 0;
}
static inline bool dir_emit_dotdot(struct file *file, struct dir_context *ctx)
{
	return ctx->actor(ctx, "..", 2, ctx->pos,
			  parent_ino(file->f_path.dentry), DT_DIR) == 0;
}
static inline bool dir_emit_dots(struct file *file, struct dir_context *ctx)
{
	if (ctx->pos == 0) {
		if (!dir_emit_dot(file, ctx))
			return false;
		ctx->pos = 1;
	}
	if (ctx->pos == 1) {
		if (!dir_emit_dotdot(file, ctx))
			return false;
		ctx->pos = 2;
	}
	return true;
}
static inline bool dir_relax(struct inode *inode)
{
	inode_unlock(inode);
	inode_lock(inode);
	return !IS_DEADDIR(inode);
}

static inline bool dir_relax_shared(struct inode *inode)
{
	inode_unlock_shared(inode);
	inode_lock_shared(inode);
	return !IS_DEADDIR(inode);
}

extern bool path_noexec(const struct path *path);
extern void inode_nohighmem(struct inode *inode);

#endif /* _LINUX_FS_H */
