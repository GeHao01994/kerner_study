/*
 *  linux/fs/proc/inode.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

#include <linux/time.h>
#include <linux/proc_fs.h>
#include <linux/kernel.h>
#include <linux/pid_namespace.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/stat.h>
#include <linux/completion.h>
#include <linux/poll.h>
#include <linux/printk.h>
#include <linux/file.h>
#include <linux/limits.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/sysctl.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/mount.h>
#include <linux/magic.h>

#include <asm/uaccess.h>

#include "internal.h"

static void proc_evict_inode(struct inode *inode)
{
	struct proc_dir_entry *de;
	struct ctl_table_header *head;

	truncate_inode_pages_final(&inode->i_data);
	clear_inode(inode);

	/* Stop tracking associated processes */
	put_pid(PROC_I(inode)->pid);

	/* Let go of any associated proc directory entry */
	de = PDE(inode);
	if (de)
		pde_put(de);
	head = PROC_I(inode)->sysctl;
	if (head) {
		RCU_INIT_POINTER(PROC_I(inode)->sysctl, NULL);
		sysctl_head_put(head);
	}
}

static struct kmem_cache * proc_inode_cachep;

static struct inode *proc_alloc_inode(struct super_block *sb)
{
	struct proc_inode *ei;
	struct inode *inode;

	ei = (struct proc_inode *)kmem_cache_alloc(proc_inode_cachep, GFP_KERNEL);
	if (!ei)
		return NULL;
	ei->pid = NULL;
	ei->fd = 0;
	ei->op.proc_get_link = NULL;
	ei->pde = NULL;
	ei->sysctl = NULL;
	ei->sysctl_entry = NULL;
	ei->ns_ops = NULL;
	inode = &ei->vfs_inode;
	return inode;
}

static void proc_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	kmem_cache_free(proc_inode_cachep, PROC_I(inode));
}

static void proc_destroy_inode(struct inode *inode)
{
	call_rcu(&inode->i_rcu, proc_i_callback);
}

static void init_once(void *foo)
{
	struct proc_inode *ei = (struct proc_inode *) foo;

	inode_init_once(&ei->vfs_inode);
}

void __init proc_init_inodecache(void)
{
	proc_inode_cachep = kmem_cache_create("proc_inode_cache",
					     sizeof(struct proc_inode),
					     0, (SLAB_RECLAIM_ACCOUNT|
						SLAB_MEM_SPREAD|SLAB_ACCOUNT|
						SLAB_PANIC),
					     init_once);
}

static int proc_show_options(struct seq_file *seq, struct dentry *root)
{
	struct super_block *sb = root->d_sb;
	struct pid_namespace *pid = sb->s_fs_info;

	if (!gid_eq(pid->pid_gid, GLOBAL_ROOT_GID))
		seq_printf(seq, ",gid=%u", from_kgid_munged(&init_user_ns, pid->pid_gid));
	if (pid->hide_pid != 0)
		seq_printf(seq, ",hidepid=%u", pid->hide_pid);

	return 0;
}

static const struct super_operations proc_sops = {
	.alloc_inode	= proc_alloc_inode,
	.destroy_inode	= proc_destroy_inode,
	.drop_inode	= generic_delete_inode,
	.evict_inode	= proc_evict_inode,
	.statfs		= simple_statfs,
	.remount_fs	= proc_remount,
	.show_options	= proc_show_options,
};

enum {BIAS = -1U<<31};

static inline int use_pde(struct proc_dir_entry *pde)
{
	return atomic_inc_unless_negative(&pde->in_use);
}

static void unuse_pde(struct proc_dir_entry *pde)
{
	if (atomic_dec_return(&pde->in_use) == BIAS)
		complete(pde->pde_unload_completion);
}

/* pde is locked */
static void close_pdeo(struct proc_dir_entry *pde, struct pde_opener *pdeo)
{
	if (pdeo->closing) {
		/* somebody else is doing that, just wait */
		DECLARE_COMPLETION_ONSTACK(c);
		pdeo->c = &c;
		spin_unlock(&pde->pde_unload_lock);
		wait_for_completion(&c);
		spin_lock(&pde->pde_unload_lock);
	} else {
		struct file *file;
		pdeo->closing = 1;
		spin_unlock(&pde->pde_unload_lock);
		file = pdeo->file;
		pde->proc_fops->release(file_inode(file), file);
		spin_lock(&pde->pde_unload_lock);
		list_del_init(&pdeo->lh);
		if (pdeo->c)
			complete(pdeo->c);
		kfree(pdeo);
	}
}

void proc_entry_rundown(struct proc_dir_entry *de)
{
	DECLARE_COMPLETION_ONSTACK(c);
	/* Wait until all existing callers into module are done. */
	de->pde_unload_completion = &c;
	if (atomic_add_return(BIAS, &de->in_use) != BIAS)
		wait_for_completion(&c);

	spin_lock(&de->pde_unload_lock);
	while (!list_empty(&de->pde_openers)) {
		struct pde_opener *pdeo;
		pdeo = list_first_entry(&de->pde_openers, struct pde_opener, lh);
		close_pdeo(de, pdeo);
	}
	spin_unlock(&de->pde_unload_lock);
}

static loff_t proc_reg_llseek(struct file *file, loff_t offset, int whence)
{
	struct proc_dir_entry *pde = PDE(file_inode(file));
	loff_t rv = -EINVAL;
	if (use_pde(pde)) {
		loff_t (*llseek)(struct file *, loff_t, int);
		llseek = pde->proc_fops->llseek;
		if (!llseek)
			llseek = default_llseek;
		rv = llseek(file, offset, whence);
		unuse_pde(pde);
	}
	return rv;
}

static ssize_t proc_reg_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	ssize_t (*read)(struct file *, char __user *, size_t, loff_t *);
	struct proc_dir_entry *pde = PDE(file_inode(file));
	ssize_t rv = -EIO;
	if (use_pde(pde)) {
		read = pde->proc_fops->read;
		if (read)
			rv = read(file, buf, count, ppos);
		unuse_pde(pde);
	}
	return rv;
}

static ssize_t proc_reg_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	ssize_t (*write)(struct file *, const char __user *, size_t, loff_t *);
	struct proc_dir_entry *pde = PDE(file_inode(file));
	ssize_t rv = -EIO;
	if (use_pde(pde)) {
		write = pde->proc_fops->write;
		if (write)
			rv = write(file, buf, count, ppos);
		unuse_pde(pde);
	}
	return rv;
}

static unsigned int proc_reg_poll(struct file *file, struct poll_table_struct *pts)
{
	struct proc_dir_entry *pde = PDE(file_inode(file));
	unsigned int rv = DEFAULT_POLLMASK;
	unsigned int (*poll)(struct file *, struct poll_table_struct *);
	if (use_pde(pde)) {
		poll = pde->proc_fops->poll;
		if (poll)
			rv = poll(file, pts);
		unuse_pde(pde);
	}
	return rv;
}

static long proc_reg_unlocked_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct proc_dir_entry *pde = PDE(file_inode(file));
	long rv = -ENOTTY;
	long (*ioctl)(struct file *, unsigned int, unsigned long);
	if (use_pde(pde)) {
		ioctl = pde->proc_fops->unlocked_ioctl;
		if (ioctl)
			rv = ioctl(file, cmd, arg);
		unuse_pde(pde);
	}
	return rv;
}

#ifdef CONFIG_COMPAT
static long proc_reg_compat_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct proc_dir_entry *pde = PDE(file_inode(file));
	long rv = -ENOTTY;
	long (*compat_ioctl)(struct file *, unsigned int, unsigned long);
	if (use_pde(pde)) {
		compat_ioctl = pde->proc_fops->compat_ioctl;
		if (compat_ioctl)
			rv = compat_ioctl(file, cmd, arg);
		unuse_pde(pde);
	}
	return rv;
}
#endif

static int proc_reg_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct proc_dir_entry *pde = PDE(file_inode(file));
	int rv = -EIO;
	int (*mmap)(struct file *, struct vm_area_struct *);
	if (use_pde(pde)) {
		mmap = pde->proc_fops->mmap;
		if (mmap)
			rv = mmap(file, vma);
		unuse_pde(pde);
	}
	return rv;
}

static unsigned long
proc_reg_get_unmapped_area(struct file *file, unsigned long orig_addr,
			   unsigned long len, unsigned long pgoff,
			   unsigned long flags)
{
	struct proc_dir_entry *pde = PDE(file_inode(file));
	unsigned long rv = -EIO;

	if (use_pde(pde)) {
		typeof(proc_reg_get_unmapped_area) *get_area;

		get_area = pde->proc_fops->get_unmapped_area;
#ifdef CONFIG_MMU
		if (!get_area)
			get_area = current->mm->get_unmapped_area;
#endif

		if (get_area)
			rv = get_area(file, orig_addr, len, pgoff, flags);
		else
			rv = orig_addr;
		unuse_pde(pde);
	}
	return rv;
}

static int proc_reg_open(struct inode *inode, struct file *file)
{
	struct proc_dir_entry *pde = PDE(inode);
	int rv = 0;
	int (*open)(struct inode *, struct file *);
	int (*release)(struct inode *, struct file *);
	struct pde_opener *pdeo;

	/*
	 * What for, you ask? Well, we can have open, rmmod, remove_proc_entry
	 * sequence. ->release won't be called because ->proc_fops will be
	 * cleared. Depending on complexity of ->release, consequences vary.
	 *
	 * We can't wait for mercy when close will be done for real, it's
	 * deadlockable: rmmod foo </proc/foo . So, we're going to do ->release
	 * by hand in remove_proc_entry(). For this, save opener's credentials
	 * for later.
	 */
	pdeo = kzalloc(sizeof(struct pde_opener), GFP_KERNEL);
	if (!pdeo)
		return -ENOMEM;

	if (!use_pde(pde)) {
		kfree(pdeo);
		return -ENOENT;
	}
	open = pde->proc_fops->open;
	release = pde->proc_fops->release;

	if (open)
		rv = open(inode, file);

	if (rv == 0 && release) {
		/* To know what to release. */
		pdeo->file = file;
		/* Strictly for "too late" ->release in proc_reg_release(). */
		spin_lock(&pde->pde_unload_lock);
		list_add(&pdeo->lh, &pde->pde_openers);
		spin_unlock(&pde->pde_unload_lock);
	} else
		kfree(pdeo);

	unuse_pde(pde);
	return rv;
}

static int proc_reg_release(struct inode *inode, struct file *file)
{
	struct proc_dir_entry *pde = PDE(inode);
	struct pde_opener *pdeo;
	spin_lock(&pde->pde_unload_lock);
	list_for_each_entry(pdeo, &pde->pde_openers, lh) {
		if (pdeo->file == file) {
			close_pdeo(pde, pdeo);
			break;
		}
	}
	spin_unlock(&pde->pde_unload_lock);
	return 0;
}

static const struct file_operations proc_reg_file_ops = {
	.llseek		= proc_reg_llseek,
	.read		= proc_reg_read,
	.write		= proc_reg_write,
	.poll		= proc_reg_poll,
	.unlocked_ioctl	= proc_reg_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= proc_reg_compat_ioctl,
#endif
	.mmap		= proc_reg_mmap,
	.get_unmapped_area = proc_reg_get_unmapped_area,
	.open		= proc_reg_open,
	.release	= proc_reg_release,
};

#ifdef CONFIG_COMPAT
static const struct file_operations proc_reg_file_ops_no_compat = {
	.llseek		= proc_reg_llseek,
	.read		= proc_reg_read,
	.write		= proc_reg_write,
	.poll		= proc_reg_poll,
	.unlocked_ioctl	= proc_reg_unlocked_ioctl,
	.mmap		= proc_reg_mmap,
	.get_unmapped_area = proc_reg_get_unmapped_area,
	.open		= proc_reg_open,
	.release	= proc_reg_release,
};
#endif

static void proc_put_link(void *p)
{
	unuse_pde(p);
}

static const char *proc_get_link(struct dentry *dentry,
				 struct inode *inode,
				 struct delayed_call *done)
{
	struct proc_dir_entry *pde = PDE(inode);
	if (unlikely(!use_pde(pde)))
		return ERR_PTR(-EINVAL);
	set_delayed_call(done, proc_put_link, pde);
	return pde->data;
}

const struct inode_operations proc_link_inode_operations = {
	.readlink	= generic_readlink,
	.get_link	= proc_get_link,
};

/* 第二个参数的成员具体如下
 struct proc_dir_entry proc_root = {
	.low_ino	= PROC_ROOT_INO,
	.namelen	= 5,
	.mode		= S_IFDIR | S_IRUGO | S_IXUGO,
	.nlink		= 2,
	.refcnt		= REFCOUNT_INIT(1),
	.proc_iops	= &proc_root_inode_operations,
	.proc_fops	= &proc_root_operations,
	.parent		= &proc_root,
	.subdir		= RB_ROOT,
	.name		= "/proc",
};
*/

struct inode *proc_get_inode(struct super_block *sb, struct proc_dir_entry *de)
{
	/* 分配一个inode结构体
	 * 初始化其中的i_state为0
	 * 初始化了链入到所属super_block的连接件i_sb_list
	 */
	struct inode *inode = new_inode_pseudo(sb);

	if (inode) {
		/* 设置inode的编号i_node编号为PROC_ROOT_INO */
		inode->i_ino = de->low_ino;
		/* 设置inode的文件的最后修改时间、文件的最后访问时间、inode的最后修改时间为当前时间
		 * 为什么要个inode作为参数，因为inode里面inode->i_sb->s_time_gran有个精度
		 * 这边把它换算了
		 */
		inode->i_mtime = inode->i_atime = inode->i_ctime = current_time(inode);
		PROC_I(inode)->pde = de;
		/* 如果这是一个空的目录节点，就创建一个空的目录节点之后就返回 */
		if (is_empty_pde(de)) {
			make_empty_dir_inode(inode);
			return inode;
		}
		if (de->mode) {
			inode->i_mode = de->mode;
			inode->i_uid = de->uid;
			inode->i_gid = de->gid;
		}
		/* 如果有文件长度，设置其文件长度，单位为字节 */
		if (de->size)
			inode->i_size = de->size;
		/* 如果有链接数，设置其链接数 */
		if (de->nlink)
			set_nlink(inode, de->nlink);
		WARN_ON(!de->proc_iops);
		inode->i_op = de->proc_iops;
		if (de->proc_fops) {
			/* 如果inode代表的是一个文件，设置其相关的文件操作表的指针 */
			if (S_ISREG(inode->i_mode)) {
#ifdef CONFIG_COMPAT
				if (!de->proc_fops->compat_ioctl)
					inode->i_fop =
						&proc_reg_file_ops_no_compat;
				else
#endif
					inode->i_fop = &proc_reg_file_ops;
			} else {
				inode->i_fop = de->proc_fops;
			}
		}
	} else
		/* 减少pde的引用计数 */
	       pde_put(de);
	return inode;
}

int proc_fill_super(struct super_block *s, void *data, int silent)
{
	struct pid_namespace *ns = get_pid_ns(s->s_fs_info);
	struct inode *root_inode;
	int ret;

	if (!proc_parse_options(data, ns))
		return -EINVAL;

	/* User space would break if executables or devices appear on proc */
	/* 将super_block的内部flag（即iflags）赋值为用户可见的、不可执行的
	 * 因为proc实际上没有实际的设备，所以这里还需要添加NODEV */
	s->s_iflags |= SB_I_USERNS_VISIBLE | SB_I_NOEXEC | SB_I_NODEV;
	s->s_flags |= MS_NODIRATIME | MS_NOSUID | MS_NOEXEC;
	/* 设置块大小为1024 */
	s->s_blocksize = 1024;
	/* 设置文件系统的块长度的位数为10 */
	s->s_blocksize_bits = 10;
	/* 设置文件系统魔数为PROC_SUPER_MAGIC */
	s->s_magic = PROC_SUPER_MAGIC;
	/* 设置超级块操作函数为proc_sops */
	s->s_op = &proc_sops;
	/* s_time_gran 文件系统文件戳（访问/修改时间等）粒度，以ns为单位
	 * 这里把它修改成1 ns
	 */
	s->s_time_gran = 1;

	/*
	 * procfs isn't actually a stacking filesystem; however, there is
	 * too much magic going on inside it to permit stacking things on
	 * top of it
	 */
	s->s_stack_depth = FILESYSTEM_MAX_STACK_DEPTH;

	/* 这里将proc_root的refcnt加1,因为下面要用到，所以避免其释放*/
	pde_get(&proc_root);

	/* 这里实际就是根据已经初始化的全局变量proc_root，来分配和填充root_inode */
	root_inode = proc_get_inode(s, &proc_root);
	if (!root_inode) {
		pr_err("proc_fill_super: get root inode failed\n");
		return -ENOMEM;
	}

	/* 根据root_inode节点创建相关的dentry */
	s->s_root = d_make_root(root_inode);
	if (!s->s_root) {
		pr_err("proc_fill_super: allocate dentry failed\n");
		return -ENOMEM;
	}

	/* 这个是在s_root节点下分配一个 名字为self的dentry，dentry的父dentry为root
	 * /proc/self
	 */
	ret = proc_setup_self(s);
	if (ret) {
		return ret;
	}

	/* 这个是在s_root节点下分配一个 名字为thread-self的dentry，dentry的父dentry为root
	 * /proc/thread-self
	 */
	return proc_setup_thread_self(s);
}
