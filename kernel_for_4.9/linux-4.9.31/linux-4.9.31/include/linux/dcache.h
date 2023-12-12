#ifndef __LINUX_DCACHE_H
#define __LINUX_DCACHE_H

#include <linux/atomic.h>
#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/rculist_bl.h>
#include <linux/spinlock.h>
#include <linux/seqlock.h>
#include <linux/cache.h>
#include <linux/rcupdate.h>
#include <linux/lockref.h>
#include <linux/stringhash.h>

struct path;
struct vfsmount;

/*
 * linux/include/linux/dcache.h
 *
 * Dirent cache data structures
 *
 * (C) Copyright 1997 Thomas Schoebel-Theuer,
 * with heavy changes by Linus Torvalds
 */

#define IS_ROOT(x) ((x) == (x)->d_parent)

/* The hash is always the low bits of hash_len */
#ifdef __LITTLE_ENDIAN
 #define HASH_LEN_DECLARE u32 hash; u32 len
 #define bytemask_from_count(cnt)	(~(~0ul << (cnt)*8))
#else
 #define HASH_LEN_DECLARE u32 len; u32 hash
 #define bytemask_from_count(cnt)	(~(~0ul >> (cnt)*8))
#endif

/*
 * "quick string" -- eases parameter passing, but more importantly
 * saves "metadata" about the string (ie length and the hash).
 *
 * hash comes first so it snuggles against d_parent in the
 * dentry.
 */
struct qstr {
	union {
		struct {
			HASH_LEN_DECLARE;
		};
		/* 字符串的hash长度 */
		u64 hash_len;
	};
	/* 字符串*/
	const unsigned char *name;
};

#define QSTR_INIT(n,l) { { { .len = l } }, .name = n }

struct dentry_stat_t {
	long nr_dentry;
	long nr_unused;
	long age_limit;          /* age in seconds */
	long want_pages;         /* pages requested by system */
	long dummy[2];
};
extern struct dentry_stat_t dentry_stat;

/*
 * Try to keep struct dentry aligned on 64 byte cachelines (this will
 * give reasonable cacheline footprint with larger lines without the
 * large memory footprint increase).
 */
#ifdef CONFIG_64BIT
# define DNAME_INLINE_LEN 32 /* 192 bytes */
#else
# ifdef CONFIG_SMP
#  define DNAME_INLINE_LEN 36 /* 128 bytes */
# else
#  define DNAME_INLINE_LEN 40 /* 128 bytes */
# endif
#endif

#define d_lock	d_lockref.lock

/* dentry虽然翻译为目录项，但它和文件系统中的目录并不是同一个概念。
 * 事实上，dentry属于所有文件系统对象，包括目录、常规文件、符号链接、块设备文件、字符设备文件等。
 * 反映的是文件系统对象在内核中所在文件系统树中的位置
 * 所有文件系统共有的内容被提炼处理，形成了vfs dentry,而对于具体文件系统，还可以有内存中
 * 目录项和磁盘上目录项两种形式。在打开对象时，磁盘上目录项被读取，用来构造vfs dentry和内存目录项
 * 因为inode反映的是文件系统对象的元数据，而dentry则表示文件系统对象在文件系统中的位置。
 * dentry和inode是多对一的关系，每个dentry只有一个inode,由d_inode指向；
 * 而一个inode可能对应多个dentry（例如硬链接），它将这些dentry组成以i_dentry的链表，每个dentry通过d_alias加入到所属inode的i_dentry链表中
 */
struct dentry {
	/* RCU lookup touched fields */
	/* dentry_cache 标志 */
	unsigned int d_flags;		/* protected by d_lock */
	seqcount_t d_seq;		/* per dentry seqlock */
	/* 链入到全局dentry_hashtable或者超级块的匿名dentry哈希链表的“连接件”，根dentry除外。
	 * 其哈希项的索引计算基于夫dentry描述符的地址以及它的文件名哈希值。
	 * 因此，这个哈希表的作用就是方便查找给定目录下的文件。
	 */
	struct hlist_bl_node d_hash;	/* lookup hash list */
	/* 父目录的dentry描述符，如果是根dentry,指向它自身 */
	struct dentry *d_parent;	/* parent directory */
	/* 本dentry所表示对象的文件名、长度、文件名的哈希值等信息 */
	struct qstr d_name;
	/* 这个dentry 对象所关联的inode描述符 */
	struct inode *d_inode;		/* Where the name belongs to - NULL is
					 * negative */
	/* 用于保存短文件名。如果文件名长度超过36，则另外分配空间 */
	unsigned char d_iname[DNAME_INLINE_LEN];	/* small names */

	/* Ref lookup also touches following */
	struct lockref d_lockref;	/* per-dentry lock and refcount */
	/* 指向dentry操作表的指针 */
	const struct dentry_operations *d_op;
	/* 指向本dentry所属文件系统超级块描述符指针 */
	struct super_block *d_sb;	/* The root of the dentry tree */
	/* 被d_revalidate函数用来作为判断dentry是否还有效的依据 */
	unsigned long d_time;		/* used by d_revalidate */
	/* 指向具体文件系统的dentry信息的指针 */
	void *d_fsdata;			/* fs-specific data */

	union {
		/* 文件系统的未使用dentry被链入到一个最近最少使用的链表（lru）中
		 * 该域被链入此链表的连接件，super_block的s_dentry_lru域为表头
		 */
		struct list_head d_lru;		/* LRU list */
		wait_queue_head_t *d_wait;	/* in-lookup ones only */
	};
	/* 链入到夫dentry的d_subdirs链表的“连接件” */
	struct list_head d_child;	/* child of parent list */
	/* 这个dentry的子dentry链表的表头 */
	struct list_head d_subdirs;	/* our children */
	/*
	 * d_alias and d_rcu can share memory
	 */
	union {
		/* 链入到所属inode的i_dentry(别名)链表的“连接件” */
		struct hlist_node d_alias;	/* inode alias list */
		/* 新创建dentry后，将其放入该表中，以便并发访问的其他程序能够找到。关联inode后，就从中删除不会用了 */
		struct hlist_bl_node d_in_lookup_hash;	/* only for in-lookup ones */
	 	struct rcu_head d_rcu;
	} d_u;
};

/*
 * dentry->d_lock spinlock nesting subclasses:
 *
 * 0: normal
 * 1: nested
 */
enum dentry_d_lock_class
{
	DENTRY_D_LOCK_NORMAL, /* implicitly used by plain spin_lock() APIs. */
	DENTRY_D_LOCK_NESTED
};

struct dentry_operations {
	/* 这个方法在路径查找时从dentry缓存中找到目标项之后，它被用来检查这个目录项
	 * 是否依然有效，因为它们可能在VFS之外被删除。若无效，则需要作废缓存中的目录项，
	 * 根据磁盘上的内容重新构造。
	 * 第一个参数为指向父目录dentry描述符的指针
	 * 如果未定义此回调函数，则默认认为dentry缓存中的信息是有效的，这适合于大多数文件系统。
	 * 某些（例如NFS）文件系统需要对dentry缓存中找到dentry结构进行验证（和处理），则需要提供此回调函数的实现
	 */
	int (*d_revalidate)(struct dentry *, unsigned int);
	int (*d_weak_revalidate)(struct dentry *, unsigned int);
	/* 在路径查找时，为提高效率，首先比较目录项的哈希值，然后比较目录项的字符串。
	 * 这个函数被用来计算给定名字字符串的哈希值。
	 * 第一个参数为父目录的dentry的指针
	 * 第二个为指向目标qstr描述符的指针，其中包含了目标的目录项名字、长度、并保存计算后的哈希值
	 * 如果未定义此回调函数，将采用默认的行为，即使用固定算法（参见文件include/linux/dcache.h中的函数full_name_hash）
	 * 对目标目录项名字中的所有字符串计算哈希值。
	 * 如果某些文件系统希望采用不同的算法，或者有选择性地针对名字中某些字符（例如SYSV文件系统截取前14个字符），
	 * 或者针对变换后的名字（例如JFS文件系统转换成小写）来计算哈希值，则实现这个函数
	 */
	int (*d_hash)(const struct dentry *, struct qstr *);
	/* 这个函数被用在路径查找时比较两个字符串。
	 * 第一个参数为父目录项dentry指针
	 * 第二个和第三个为指向qstr描述符的指针，其中包含了待比较的目录项名字、长度
	 * 如果未定义此回调函数，将采用默认的行为，即按内存比较方式，只有两个字符串在长度范围内
	 * 的内容都相同，才认为这两个字符串相同。
	 * 某些文件系统可能利用这个回调函数来实现特定的比较（例如JFS文件系统在比较时忽略名字字符串中的大小写）
	 */
	int (*d_compare)(const struct dentry *,
			unsigned int, const char *, const struct qstr *);
	/* 在dentry的最后一个引用被删除时调用。这个方法只有一个参数，即指向当时dentry描述符的指针。
	 * 如果函数返回1，则表示该dentry无效，应该从缓存中丢掉。
	 * 返回0则可以继续保留在dentry缓存中.
	 */
	int (*d_delete)(const struct dentry *);
	int (*d_init)(struct dentry *);
	/* 在dentry真正被销毁时调用。
	 * 这个方法只有一个参数，即指向当时dentry描述符的指针。
	 * 对于大多数文件系统，都不需要实现此函数。
	 * 但是某些文件系统在dentry带有特定信息（由d_fsdada指向），
	 * 则应该在这个回调函数中处理
	 */
	void (*d_release)(struct dentry *);
	void (*d_prune)(struct dentry *);
	/* 在dentry失去和inode的关联时被调用。
	 * 第一个参数为指向dentry的指针
	 * 第二个参数为指向inode的指针
	 * 如果为定义这个函数，则采取默认的行为，即调用iput递减inode的引用，并在引用计数值为0时，准备释放、甚至销毁这个inode.
	 * 某些文件系统需要做一些其他的处理，例如sysfs文件系统需要释放关联sysfs_dirent的引用，
	 * 则必须实现此回调函数，在回调函数最后仍然调用iput.
	 */
	void (*d_iput)(struct dentry *, struct inode *);
	/* 在需要为dentry生成路径名时被调用。
	 * 在某些伪文件系统（sockfs、pipefs等）中使用延迟路径名生成。
	 */
	char *(*d_dname)(struct dentry *, char *, int);
	struct vfsmount *(*d_automount)(struct path *);
	int (*d_manage)(struct dentry *, bool);
	struct dentry *(*d_real)(struct dentry *, const struct inode *,
				 unsigned int);
} ____cacheline_aligned;

/*
 * Locking rules for dentry_operations callbacks are to be found in
 * Documentation/filesystems/Locking. Keep it updated!
 *
 * FUrther descriptions are found in Documentation/filesystems/vfs.txt.
 * Keep it updated too!
 */

/* d_flags entries */
#define DCACHE_OP_HASH			0x00000001
#define DCACHE_OP_COMPARE		0x00000002
#define DCACHE_OP_REVALIDATE		0x00000004
#define DCACHE_OP_DELETE		0x00000008
#define DCACHE_OP_PRUNE			0x00000010

/* 这个dentry可能当前没有连接到dcache的树中，在这种情况下，它的父母将是它自己
 * 也将具有这个flag。
 * nfsd不会使用带了这个标志位的dentry，而是首先努力去清楚这个标志位当发现他已经
 * 链接的时候，或者指向查找操作的时候。
 *
 * 任何支持nfsd_operations的文件系统必须有一个lookup函数，如果如果它找到了一个
 * 带有DCACHE_DISCONNECTED的dentry,将d_move 这个dentry到位置，然后返回这个dentry
 * 而不是传递的那个，通常被d_splice_alias使用
 */
#define	DCACHE_DISCONNECTED		0x00000020
     /* This dentry is possibly not currently connected to the dcache tree, in
      * which case its parent will either be itself, or will have this flag as
      * well.  nfsd will not use a dentry with this bit set, but will first
      * endeavour to clear the bit either by discovering that it is connected,
      * or by performing lookup operations.   Any filesystem which supports
      * nfsd_operations MUST have a lookup function which, if it finds a
      * directory inode with a DCACHE_DISCONNECTED dentry, will d_move that
      * dentry into place and return that dentry rather than the passed one,
      * typically using d_splice_alias. */
#define DCACHE_REFERENCED		0x00000040 /* Recently used, don't discard. */
#define DCACHE_RCUACCESS		0x00000080 /* Entry has ever been RCU-visible */

#define DCACHE_CANT_MOUNT		0x00000100
#define DCACHE_GENOCIDE			0x00000200
#define DCACHE_SHRINK_LIST		0x00000400

#define DCACHE_OP_WEAK_REVALIDATE	0x00000800

#define DCACHE_NFSFS_RENAMED		0x00001000
     /* this dentry has been "silly renamed" and has to be deleted on the last
      * dput() */
#define DCACHE_COOKIE			0x00002000 /* For use by dcookie subsystem */
#define DCACHE_FSNOTIFY_PARENT_WATCHED	0x00004000
     /* Parent inode is watched by some fsnotify listener */

#define DCACHE_DENTRY_KILLED		0x00008000

#define DCACHE_MOUNTED			0x00010000 /* is a mountpoint */
#define DCACHE_NEED_AUTOMOUNT		0x00020000 /* handle automount on this dir */
#define DCACHE_MANAGE_TRANSIT		0x00040000 /* manage transit from this dirent */
#define DCACHE_MANAGED_DENTRY \
	(DCACHE_MOUNTED|DCACHE_NEED_AUTOMOUNT|DCACHE_MANAGE_TRANSIT)

#define DCACHE_LRU_LIST			0x00080000

#define DCACHE_ENTRY_TYPE		0x00700000
#define DCACHE_MISS_TYPE		0x00000000 /* Negative dentry (maybe fallthru to nowhere) */
#define DCACHE_WHITEOUT_TYPE		0x00100000 /* Whiteout dentry (stop pathwalk) */
#define DCACHE_DIRECTORY_TYPE		0x00200000 /* Normal directory */
#define DCACHE_AUTODIR_TYPE		0x00300000 /* Lookupless directory (presumed automount) */
#define DCACHE_REGULAR_TYPE		0x00400000 /* Regular file type (or fallthru to such) */
#define DCACHE_SPECIAL_TYPE		0x00500000 /* Other file type (or fallthru to such) */
#define DCACHE_SYMLINK_TYPE		0x00600000 /* Symlink (or fallthru to such) */

#define DCACHE_MAY_FREE			0x00800000
#define DCACHE_FALLTHRU			0x01000000 /* Fall through to lower layer */
#define DCACHE_ENCRYPTED_WITH_KEY	0x02000000 /* dir is encrypted with a valid key */
#define DCACHE_OP_REAL			0x04000000

#define DCACHE_PAR_LOOKUP		0x10000000 /* being looked up (with parent locked shared) */
#define DCACHE_DENTRY_CURSOR		0x20000000

extern seqlock_t rename_lock;

/*
 * These are the low-level FS interfaces to the dcache..
 */
extern void d_instantiate(struct dentry *, struct inode *);
extern struct dentry * d_instantiate_unique(struct dentry *, struct inode *);
extern int d_instantiate_no_diralias(struct dentry *, struct inode *);
extern void __d_drop(struct dentry *dentry);
extern void d_drop(struct dentry *dentry);
extern void d_delete(struct dentry *);
extern void d_set_d_op(struct dentry *dentry, const struct dentry_operations *op);

/* allocate/de-allocate */
extern struct dentry * d_alloc(struct dentry *, const struct qstr *);
extern struct dentry * d_alloc_pseudo(struct super_block *, const struct qstr *);
extern struct dentry * d_alloc_parallel(struct dentry *, const struct qstr *,
					wait_queue_head_t *);
extern struct dentry * d_splice_alias(struct inode *, struct dentry *);
extern struct dentry * d_add_ci(struct dentry *, struct inode *, struct qstr *);
extern struct dentry * d_exact_alias(struct dentry *, struct inode *);
extern struct dentry *d_find_any_alias(struct inode *inode);
extern struct dentry * d_obtain_alias(struct inode *);
extern struct dentry * d_obtain_root(struct inode *);
extern void shrink_dcache_sb(struct super_block *);
extern void shrink_dcache_parent(struct dentry *);
extern void shrink_dcache_for_umount(struct super_block *);
extern void d_invalidate(struct dentry *);

/* only used at mount-time */
extern struct dentry * d_make_root(struct inode *);

/* <clickety>-<click> the ramfs-type tree */
extern void d_genocide(struct dentry *);

extern void d_tmpfile(struct dentry *, struct inode *);

extern struct dentry *d_find_alias(struct inode *);
extern void d_prune_aliases(struct inode *);

/* test whether we have any submounts in a subdir tree */
extern int have_submounts(struct dentry *);

/*
 * This adds the entry to the hash queues.
 */
extern void d_rehash(struct dentry *);
 
extern void d_add(struct dentry *, struct inode *);

extern void dentry_update_name_case(struct dentry *, const struct qstr *);

/* used for rename() and baskets */
extern void d_move(struct dentry *, struct dentry *);
extern void d_exchange(struct dentry *, struct dentry *);
extern struct dentry *d_ancestor(struct dentry *, struct dentry *);

/* appendix may either be NULL or be used for transname suffixes */
extern struct dentry *d_lookup(const struct dentry *, const struct qstr *);
extern struct dentry *d_hash_and_lookup(struct dentry *, struct qstr *);
extern struct dentry *__d_lookup(const struct dentry *, const struct qstr *);
extern struct dentry *__d_lookup_rcu(const struct dentry *parent,
				const struct qstr *name, unsigned *seq);

static inline unsigned d_count(const struct dentry *dentry)
{
	return dentry->d_lockref.count;
}

/*
 * helper function for dentry_operations.d_dname() members
 */
extern __printf(4, 5)
char *dynamic_dname(struct dentry *, char *, int, const char *, ...);
extern char *simple_dname(struct dentry *, char *, int);

extern char *__d_path(const struct path *, const struct path *, char *, int);
extern char *d_absolute_path(const struct path *, char *, int);
extern char *d_path(const struct path *, char *, int);
extern char *dentry_path_raw(struct dentry *, char *, int);
extern char *dentry_path(struct dentry *, char *, int);

/* Allocation counts.. */

/**
 *	dget, dget_dlock -	get a reference to a dentry
 *	@dentry: dentry to get a reference to
 *
 *	Given a dentry or %NULL pointer increment the reference count
 *	if appropriate and return the dentry. A dentry will not be 
 *	destroyed when it has references.
 */
static inline struct dentry *dget_dlock(struct dentry *dentry)
{
	if (dentry)
		dentry->d_lockref.count++;
	return dentry;
}

static inline struct dentry *dget(struct dentry *dentry)
{
	if (dentry)
		lockref_get(&dentry->d_lockref);
	return dentry;
}

extern struct dentry *dget_parent(struct dentry *dentry);

/**
 *	d_unhashed -	is dentry hashed
 *	@dentry: entry to check
 *
 *	Returns true if the dentry passed is not currently hashed.
 */
 
static inline int d_unhashed(const struct dentry *dentry)
{
	return hlist_bl_unhashed(&dentry->d_hash);
}

static inline int d_unlinked(const struct dentry *dentry)
{
	return d_unhashed(dentry) && !IS_ROOT(dentry);
}

static inline int cant_mount(const struct dentry *dentry)
{
	return (dentry->d_flags & DCACHE_CANT_MOUNT);
}

static inline void dont_mount(struct dentry *dentry)
{
	spin_lock(&dentry->d_lock);
	dentry->d_flags |= DCACHE_CANT_MOUNT;
	spin_unlock(&dentry->d_lock);
}

extern void __d_lookup_done(struct dentry *);
/* 这个函数是检查有无DCACHE_PAR_LOOKUP标志
 * 这个标志表示dentry是新建立的
 */
static inline int d_in_lookup(struct dentry *dentry)
{
	return dentry->d_flags & DCACHE_PAR_LOOKUP;
}

static inline void d_lookup_done(struct dentry *dentry)
{
	if (unlikely(d_in_lookup(dentry))) {
		spin_lock(&dentry->d_lock);
		__d_lookup_done(dentry);
		spin_unlock(&dentry->d_lock);
	}
}

extern void dput(struct dentry *);

static inline bool d_managed(const struct dentry *dentry)
{
	return dentry->d_flags & DCACHE_MANAGED_DENTRY;
}

static inline bool d_mountpoint(const struct dentry *dentry)
{
	return dentry->d_flags & DCACHE_MOUNTED;
}

/*
 * Directory cache entry type accessor functions.
 */
static inline unsigned __d_entry_type(const struct dentry *dentry)
{
	return dentry->d_flags & DCACHE_ENTRY_TYPE;
}

static inline bool d_is_miss(const struct dentry *dentry)
{
	return __d_entry_type(dentry) == DCACHE_MISS_TYPE;
}

static inline bool d_is_whiteout(const struct dentry *dentry)
{
	return __d_entry_type(dentry) == DCACHE_WHITEOUT_TYPE;
}

static inline bool d_can_lookup(const struct dentry *dentry)
{
	return __d_entry_type(dentry) == DCACHE_DIRECTORY_TYPE;
}

static inline bool d_is_autodir(const struct dentry *dentry)
{
	return __d_entry_type(dentry) == DCACHE_AUTODIR_TYPE;
}

static inline bool d_is_dir(const struct dentry *dentry)
{
	return d_can_lookup(dentry) || d_is_autodir(dentry);
}

static inline bool d_is_symlink(const struct dentry *dentry)
{
	return __d_entry_type(dentry) == DCACHE_SYMLINK_TYPE;
}

static inline bool d_is_reg(const struct dentry *dentry)
{
	return __d_entry_type(dentry) == DCACHE_REGULAR_TYPE;
}

static inline bool d_is_special(const struct dentry *dentry)
{
	return __d_entry_type(dentry) == DCACHE_SPECIAL_TYPE;
}

static inline bool d_is_file(const struct dentry *dentry)
{
	return d_is_reg(dentry) || d_is_special(dentry);
}

static inline bool d_is_negative(const struct dentry *dentry)
{
	// TODO: check d_is_whiteout(dentry) also.
	return d_is_miss(dentry);
}

static inline bool d_is_positive(const struct dentry *dentry)
{
	return !d_is_negative(dentry);
}

/**
 * d_really_is_negative - Determine if a dentry is really negative (ignoring fallthroughs)
 * @dentry: The dentry in question
 *
 * Returns true if the dentry represents either an absent name or a name that
 * doesn't map to an inode (ie. ->d_inode is NULL).  The dentry could represent
 * a true miss, a whiteout that isn't represented by a 0,0 chardev or a
 * fallthrough marker in an opaque directory.
 *
 * Note!  (1) This should be used *only* by a filesystem to examine its own
 * dentries.  It should not be used to look at some other filesystem's
 * dentries.  (2) It should also be used in combination with d_inode() to get
 * the inode.  (3) The dentry may have something attached to ->d_lower and the
 * type field of the flags may be set to something other than miss or whiteout.
 */
static inline bool d_really_is_negative(const struct dentry *dentry)
{
	return dentry->d_inode == NULL;
}

/**
 * d_really_is_positive - Determine if a dentry is really positive (ignoring fallthroughs)
 * @dentry: The dentry in question
 *
 * Returns true if the dentry represents a name that maps to an inode
 * (ie. ->d_inode is not NULL).  The dentry might still represent a whiteout if
 * that is represented on medium as a 0,0 chardev.
 *
 * Note!  (1) This should be used *only* by a filesystem to examine its own
 * dentries.  It should not be used to look at some other filesystem's
 * dentries.  (2) It should also be used in combination with d_inode() to get
 * the inode.
 */
static inline bool d_really_is_positive(const struct dentry *dentry)
{
	return dentry->d_inode != NULL;
}

static inline int simple_positive(struct dentry *dentry)
{
	return d_really_is_positive(dentry) && !d_unhashed(dentry);
}

extern void d_set_fallthru(struct dentry *dentry);

static inline bool d_is_fallthru(const struct dentry *dentry)
{
	return dentry->d_flags & DCACHE_FALLTHRU;
}


extern int sysctl_vfs_cache_pressure;

static inline unsigned long vfs_pressure_ratio(unsigned long val)
{
	return mult_frac(val, sysctl_vfs_cache_pressure, 100);
}

/**
 * d_inode - Get the actual inode of this dentry
 * @dentry: The dentry to query
 *
 * This is the helper normal filesystems should use to get at their own inodes
 * in their own dentries and ignore the layering superimposed upon them.
 */
static inline struct inode *d_inode(const struct dentry *dentry)
{
	return dentry->d_inode;
}

/**
 * d_inode_rcu - Get the actual inode of this dentry with ACCESS_ONCE()
 * @dentry: The dentry to query
 *
 * This is the helper normal filesystems should use to get at their own inodes
 * in their own dentries and ignore the layering superimposed upon them.
 */
static inline struct inode *d_inode_rcu(const struct dentry *dentry)
{
	return ACCESS_ONCE(dentry->d_inode);
}

/**
 * d_backing_inode - Get upper or lower inode we should be using
 * @upper: The upper layer
 *
 * This is the helper that should be used to get at the inode that will be used
 * if this dentry were to be opened as a file.  The inode may be on the upper
 * dentry or it may be on a lower dentry pinned by the upper.
 *
 * Normal filesystems should not use this to access their own inodes.
 */
static inline struct inode *d_backing_inode(const struct dentry *upper)
{
	struct inode *inode = upper->d_inode;

	return inode;
}

/**
 * d_backing_dentry - Get upper or lower dentry we should be using
 * @upper: The upper layer
 *
 * This is the helper that should be used to get the dentry of the inode that
 * will be used if this dentry were opened as a file.  It may be the upper
 * dentry or it may be a lower dentry pinned by the upper.
 *
 * Normal filesystems should not use this to access their own dentries.
 */
static inline struct dentry *d_backing_dentry(struct dentry *upper)
{
	return upper;
}

/**
 * d_real - Return the real dentry
 * @dentry: the dentry to query
 * @inode: inode to select the dentry from multiple layers (can be NULL)
 * @flags: open flags to control copy-up behavior
 *
 * If dentry is on an union/overlay, then return the underlying, real dentry.
 * Otherwise return the dentry itself.
 *
 * See also: Documentation/filesystems/vfs.txt
 */
static inline struct dentry *d_real(struct dentry *dentry,
				    const struct inode *inode,
				    unsigned int flags)
{
	if (unlikely(dentry->d_flags & DCACHE_OP_REAL))
		return dentry->d_op->d_real(dentry, inode, flags);
	else
		return dentry;
}

/**
 * d_real_inode - Return the real inode
 * @dentry: The dentry to query
 *
 * If dentry is on an union/overlay, then return the underlying, real inode.
 * Otherwise return d_inode().
 */
static inline struct inode *d_real_inode(const struct dentry *dentry)
{
	/* This usage of d_real() results in const dentry */
	return d_backing_inode(d_real((struct dentry *) dentry, NULL, 0));
}


#endif	/* __LINUX_DCACHE_H */
