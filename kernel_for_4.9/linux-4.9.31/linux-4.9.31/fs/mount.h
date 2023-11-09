#include <linux/mount.h>
#include <linux/seq_file.h>
#include <linux/poll.h>
#include <linux/ns_common.h>
#include <linux/fs_pin.h>

struct mnt_namespace {
	atomic_t		count;
	struct ns_common	ns;
	struct mount *	root;
	struct list_head	list;
	struct user_namespace	*user_ns;
	struct ucounts		*ucounts;
	u64			seq;	/* Sequence number to prevent loops */
	wait_queue_head_t poll;
	u64 event;
	unsigned int		mounts; /* # of mounts in the namespace */
	unsigned int		pending_mounts;
};

struct mnt_pcp {
	/* 使用计数器？*/
	int mnt_count;
	int mnt_writers;
};

struct mountpoint {
	/* 散列链表节点成员,将实例链接到全局散列链表 */
	struct hlist_node m_hash;
	/* 指向挂载点 dentry 实例(根文件系统中目录项) */
	struct dentry *m_dentry;
	/* 链接 mount 实例 */
	struct hlist_head m_list;
	/* 挂载点挂载操作的次数 */
	int m_count;
};

struct mount {
	/* 链入全局已装载文件系统哈希表的“连接件” */
	struct hlist_node mnt_hash;
	/* 指向这个文件系统被装载到的父文件系统的指针 */
	struct mount *mnt_parent;
	/* 指向这个文件系统被装载到的装载点目录的dentry的指针 */
	struct dentry *mnt_mountpoint;
	struct vfsmount mnt;
	union {
		struct rcu_head mnt_rcu;
		struct llist_node mnt_llist;
	};
#ifdef CONFIG_SMP
	struct mnt_pcp __percpu *mnt_pcp;
#else
	int mnt_count;
	int mnt_writers;
#endif
	/* 装载到这个文件系统的目录上所有子文件系统的链表的表头 */
	struct list_head mnt_mounts;	/* list of children, anchored here */
	/* 链接到被装载到的父文件系统mnt_mounts链表的“连接件” */
	struct list_head mnt_child;	/* and going through their mnt_child */
	/*链接到其相关的super block的“连接件” */
	struct list_head mnt_instance;	/* mount instance on sb->s_mounts */
	/* 保存文件系统的块设备的设备文件名（或者特殊文件系统的文件系统类型名）*/
	const char *mnt_devname;	/* Name of device e.g. /dev/dsk/hda1 */
	/* 链入到进程名字空间中已装载文件系统链表的“连接件”，链表头为mnt_namespace结构的list域 */
	struct list_head mnt_list;
	/* 链入到文件系统专有的过期链表的连接件，用于NFS、CIFS、AFS等网络文件系统*/
	struct list_head mnt_expire;	/* link in fs-specific expiry list */
	/* 链入到共享装载循环链表的连接件。阐述propagation的概念。
	 * 所有在一个对等组（peer Group）中共享中的vfsmount通过mnt_share构成一个循环链表
	 */
	struct list_head mnt_share;	/* circular list of shared mounts */
	/* 这个文件系统的slave mount链表的表头 */
	struct list_head mnt_slave_list;/* list of slave mounts */
	/* 链入到master文件系统的slave mount链表的“连接件” */
	struct list_head mnt_slave;	/* slave list entry */
	/* 指向master文件系统的指针？*/
	struct mount *mnt_master;	/* slave is on master->mnt_slave_list */
	/* 所在的namespace */
	struct mnt_namespace *mnt_ns;	/* containing namespace */
	/* 挂载点相关的信息 */
	struct mountpoint *mnt_mp;	/* where is it mounted */
	struct hlist_node mnt_mp_list;	/* list mounts with the same mountpoint */
#ifdef CONFIG_FSNOTIFY
	struct hlist_head mnt_fsnotify_marks;
	__u32 mnt_fsnotify_mask;
#endif
	/* 装载id,mnt_id=ida_alloc(&mnt_id_ida, GFP_KERNEL); */
	int mnt_id;			/* mount identifier */
	/* 组id */
	int mnt_group_id;		/* peer group identifier */
	/* 如果为1，表示这个已装载文件系统被标记为过期 */
	int mnt_expiry_mark;		/* true if marked for expiry */
	struct hlist_head mnt_pins;
	struct fs_pin mnt_umount;
	struct dentry *mnt_ex_mountpoint;
};

#define MNT_NS_INTERNAL ERR_PTR(-EINVAL) /* distinct from any mnt_namespace */

static inline struct mount *real_mount(struct vfsmount *mnt)
{
	return container_of(mnt, struct mount, mnt);
}

static inline int mnt_has_parent(struct mount *mnt)
{
	return mnt != mnt->mnt_parent;
}

static inline int is_mounted(struct vfsmount *mnt)
{
	/* neither detached nor internal? */
	return !IS_ERR_OR_NULL(real_mount(mnt)->mnt_ns);
}

extern struct mount *__lookup_mnt(struct vfsmount *, struct dentry *);

extern int __legitimize_mnt(struct vfsmount *, unsigned);
extern bool legitimize_mnt(struct vfsmount *, unsigned);

extern void __detach_mounts(struct dentry *dentry);

static inline void detach_mounts(struct dentry *dentry)
{
	if (!d_mountpoint(dentry))
		return;
	__detach_mounts(dentry);
}

static inline void get_mnt_ns(struct mnt_namespace *ns)
{
	atomic_inc(&ns->count);
}

extern seqlock_t mount_lock;

static inline void lock_mount_hash(void)
{
	write_seqlock(&mount_lock);
}

static inline void unlock_mount_hash(void)
{
	write_sequnlock(&mount_lock);
}

struct proc_mounts {
	struct mnt_namespace *ns;
	struct path root;
	int (*show)(struct seq_file *, struct vfsmount *);
	void *cached_mount;
	u64 cached_event;
	loff_t cached_index;
};

extern const struct seq_operations mounts_op;

extern bool __is_local_mountpoint(struct dentry *dentry);
static inline bool is_local_mountpoint(struct dentry *dentry)
{
	if (!d_mountpoint(dentry))
		return false;

	return __is_local_mountpoint(dentry);
}
