/*
 *  linux/fs/file_table.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *  Copyright (C) 1997 David S. Miller (davem@caip.rutgers.edu)
 */

#include <linux/string.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/security.h>
#include <linux/eventpoll.h>
#include <linux/rcupdate.h>
#include <linux/mount.h>
#include <linux/capability.h>
#include <linux/cdev.h>
#include <linux/fsnotify.h>
#include <linux/sysctl.h>
#include <linux/percpu_counter.h>
#include <linux/percpu.h>
#include <linux/hardirq.h>
#include <linux/task_work.h>
#include <linux/ima.h>
#include <linux/swap.h>

#include <linux/atomic.h>

#include "internal.h"

/* sysctl tunables... */
struct files_stat_struct files_stat = {
	.max_files = NR_FILE
};

/* SLAB cache for file structures */
static struct kmem_cache *filp_cachep __read_mostly;

static struct percpu_counter nr_files __cacheline_aligned_in_smp;

static void file_free_rcu(struct rcu_head *head)
{
	struct file *f = container_of(head, struct file, f_u.fu_rcuhead);

	put_cred(f->f_cred);
	kmem_cache_free(filp_cachep, f);
}

static inline void file_free(struct file *f)
{
	percpu_counter_dec(&nr_files);
	call_rcu(&f->f_u.fu_rcuhead, file_free_rcu);
}

/*
 * Return the total number of open files in the system
 */
static long get_nr_files(void)
{
	return percpu_counter_read_positive(&nr_files);
}

/*
 * Return the maximum number of open files in the system
 */
unsigned long get_max_files(void)
{
	return files_stat.max_files;
}
EXPORT_SYMBOL_GPL(get_max_files);

/*
 * Handle nr_files sysctl
 */
#if defined(CONFIG_SYSCTL) && defined(CONFIG_PROC_FS)
int proc_nr_files(struct ctl_table *table, int write,
                     void __user *buffer, size_t *lenp, loff_t *ppos)
{
	files_stat.nr_files = get_nr_files();
	return proc_doulongvec_minmax(table, write, buffer, lenp, ppos);
}
#else
int proc_nr_files(struct ctl_table *table, int write,
                     void __user *buffer, size_t *lenp, loff_t *ppos)
{
	return -ENOSYS;
}
#endif

/* Find an unused file structure and return a pointer to it.
 * Returns an error pointer if some error happend e.g. we over file
 * structures limit, run out of memory or operation is not permitted.
 *
 * Be very careful using this.  You are responsible for
 * getting write access to any mount that you might assign
 * to this filp, if it is opened for write.  If this is not
 * done, you will imbalance int the mount's writer count
 * and a warning at __fput() time.
 */
/* 使用这个要非常小心。
 * 如果这个filp是为写入而打开的，
 * 那么您有责任获得写访问权限对于任何你可能分派给这个filp的任何挂载。
 * 如果不这样做，您将不平衡装载的写入程序计数，
 * 并在__fput（）时间发出警告
 */
struct file *get_empty_filp(void)
{
	const struct cred *cred = current_cred();
	static long old_max;
	struct file *f;
	int error;

	/*
	 * Privileged users can go above max_files
	 * 特权用户可以超过max_files
	 */
	/* 如果本地CPU的文件已经超过了max_files，并且还不是管理员权限 */
	if (get_nr_files() >= files_stat.max_files && !capable(CAP_SYS_ADMIN)) {
		/*
		 * percpu_counters are inaccurate.  Do an expensive check before
		 * we go and fail.
		 * percpu计数器不准确。在我们失败之前做一次昂贵的检查
		 */
		/* 将系统中所有的files加起来，如果大于max_files就不要分配了 */
		if (percpu_counter_sum_positive(&nr_files) >= files_stat.max_files)
			goto over;
	}
	/* 分配一个file struct */
	f = kmem_cache_zalloc(filp_cachep, GFP_KERNEL);
	if (unlikely(!f))
		return ERR_PTR(-ENOMEM);
	/* 将percpu里面nr_files +1 */
	percpu_counter_inc(&nr_files);
	f->f_cred = get_cred(cred);
	error = security_file_alloc(f);
	if (unlikely(error)) {
		file_free(f);
		return ERR_PTR(error);
	}
	/* 设置file->f_count即该文件的引用计数+1 */
	atomic_long_set(&f->f_count, 1);
	rwlock_init(&f->f_owner.lock);
	spin_lock_init(&f->f_lock);
	mutex_init(&f->f_pos_lock);
	/* eventpoll——init_file就是初始化两链表
	 * INIT_LIST_HEAD(&file->f_ep_links);
	 * INIT_LIST_HEAD(&file->f_tfile_llink);
	 */
	eventpoll_init_file(f);
	/* f->f_version: 0 */
	return f;

over:
	/* Ran out of filps - report that */
	if (get_nr_files() > old_max) {
		pr_info("VFS: file-max limit %lu reached\n", get_max_files());
		old_max = get_nr_files();
	}
	return ERR_PTR(-ENFILE);
}

/**
 * alloc_file - allocate and initialize a 'struct file'
 *
 * @path: the (dentry, vfsmount) pair for the new file
 * @mode: the mode with which the new file will be opened
 * @fop: the 'struct file_operations' for the new file
 */
struct file *alloc_file(struct path *path, fmode_t mode,
		const struct file_operations *fop)
{
	struct file *file;

	file = get_empty_filp();
	if (IS_ERR(file))
		return file;

	file->f_path = *path;
	file->f_inode = path->dentry->d_inode;
	file->f_mapping = path->dentry->d_inode->i_mapping;
	if ((mode & FMODE_READ) &&
	     likely(fop->read || fop->read_iter))
		mode |= FMODE_CAN_READ;
	if ((mode & FMODE_WRITE) &&
	     likely(fop->write || fop->write_iter))
		mode |= FMODE_CAN_WRITE;
	file->f_mode = mode;
	file->f_op = fop;
	if ((mode & (FMODE_READ | FMODE_WRITE)) == FMODE_READ)
		i_readcount_inc(path->dentry->d_inode);
	return file;
}
EXPORT_SYMBOL(alloc_file);

/* the real guts of fput() - releasing the last reference to file
 *
 * 释放对文件的最后一个引用
 */
static void __fput(struct file *file)
{
	/* 获得文件的dentry */
	struct dentry *dentry = file->f_path.dentry;
	/* 获得vfsmout */
	struct vfsmount *mnt = file->f_path.mnt;
	/* 获取inode */
	struct inode *inode = file->f_inode;

	might_sleep();
	/* 通知文件已经关闭 */
	fsnotify_close(file);
	/*
	 * The function eventpoll_release() should be the first called
	 * in the file cleanup chain.
	 */
	eventpoll_release(file);

	/* 释放文件锁相关 */
	locks_remove_file(file);
	/* 如果文件需要同步，则调用具体文件系统的接口来同步到磁盘 */
	if (unlikely(file->f_flags & FASYNC)) {
		if (file->f_op->fasync)
			file->f_op->fasync(-1, file, 0);
	}
	/* 释放静态度量 */
	ima_file_free(file);
	/* 调用具体文件系统的release接口 */
	if (file->f_op->release)
		file->f_op->release(inode, file);
	security_file_free(file);

	/* 如果是字符设备，则调用字符设备的释放接口 */
	if (unlikely(S_ISCHR(inode->i_mode) && inode->i_cdev != NULL &&
		     !(file->f_mode & FMODE_PATH))) {
		cdev_put(inode->i_cdev);
	}

	/* 递减f_op的引用计数 */
	fops_put(file->f_op);

	/* 递减pid的引用计数 */
	put_pid(file->f_owner.pid);

	/* 如果是只读，递减inode引用计数 */
	if ((file->f_mode & (FMODE_READ | FMODE_WRITE)) == FMODE_READ)
		i_readcount_dec(inode);

	/* 这个应该是如果有创建文件之类的操作，则释放相关资源 */
	if (file->f_mode & FMODE_WRITER) {
		put_write_access(inode);
		__mnt_drop_write(mnt);
	}
	file->f_path.dentry = NULL;
	file->f_path.mnt = NULL;
	file->f_inode = NULL;
	/* 调用kmem_cache_free释放file结构，把内存退还给file缓存 */
	file_free(file);
	/* 减少dentry引用计数，有可能释放或者缓存dentry */
	dput(dentry);
	/* 释放文件系统的引用计数 */
	mntput(mnt);
}

static LLIST_HEAD(delayed_fput_list);
static void delayed_fput(struct work_struct *unused)
{
	struct llist_node *node = llist_del_all(&delayed_fput_list);
	struct llist_node *next;

	for (; node; node = next) {
		next = llist_next(node);
		__fput(llist_entry(node, struct file, f_u.fu_llist));
	}
}

static void ____fput(struct callback_head *work)
{
	__fput(container_of(work, struct file, f_u.fu_rcuhead));
}

/*
 * If kernel thread really needs to have the final fput() it has done
 * to complete, call this.  The only user right now is the boot - we
 * *do* need to make sure our writes to binaries on initramfs has
 * not left us with opened struct file waiting for __fput() - execve()
 * won't work without that.  Please, don't add more callers without
 * very good reasons; in particular, never call that with locks
 * held and never call that from a thread that might need to do
 * some work on any kind of umount.
 */
void flush_delayed_fput(void)
{
	delayed_fput(NULL);
}

static DECLARE_DELAYED_WORK(delayed_fput_work, delayed_fput);
/*
 * 调用函数fput释放file实例:把引用计数减1,如果引用计数是0,那么把file实例添加到链表delayed_fput_list中,
 * 然后调用延迟工作项delayed_fput_work.
 * 延迟工作项delayed_fput_work的处理函数是flush_delayed_fput,遍历链表delayed_fput_list,针对每个file实例,
 * 调用函数__fput来加以释放.
 */
void fput(struct file *file)
{
	/* 将file->f_count减一，然后判断它是不是等于0，如果等于0的话说明没有人用它了 */
	if (atomic_long_dec_and_test(&file->f_count)) {
		struct task_struct *task = current;
		/* 如果不在中断上下文中，并且不是内核线程 */
		if (likely(!in_interrupt() && !(task->flags & PF_KTHREAD))) {
			/*
			 * 把____fput 赋值给file->f_u.fu_rcuhead的func成员
			 * static inline void init_task_work(struct callback_head *twork, task_work_func_t func)
			 * {
			 *	twork->func = func;
			 * }
			 */
			init_task_work(&file->f_u.fu_rcuhead, ____fput);
			/* */
			if (!task_work_add(task, &file->f_u.fu_rcuhead, true))
				return;
			/*
			 * After this task has run exit_task_work(),
			 * task_work_add() will fail.  Fall through to delayed
			 * fput to avoid leaking *file.
			 */
			/* 此任务运行exit_task_work（）后，task_work_add（）将失败。
			 * 通过延迟fput来避免*文件泄漏。
			 */
		}

		if (llist_add(&file->f_u.fu_llist, &delayed_fput_list))
			schedule_delayed_work(&delayed_fput_work, 1);
	}
}

/*
 * synchronous analog of fput(); for kernel threads that might be needed
 * in some umount() (and thus can't use flush_delayed_fput() without
 * risking deadlocks), need to wait for completion of __fput() and know
 * for this specific struct file it won't involve anything that would
 * need them.  Use only if you really need it - at the very least,
 * don't blindly convert fput() by kernel thread to that.
 */
void __fput_sync(struct file *file)
{
	if (atomic_long_dec_and_test(&file->f_count)) {
		struct task_struct *task = current;
		BUG_ON(!(task->flags & PF_KTHREAD));
		__fput(file);
	}
}

EXPORT_SYMBOL(fput);

void put_filp(struct file *file)
{
	if (atomic_long_dec_and_test(&file->f_count)) {
		security_file_free(file);
		file_free(file);
	}
}

void __init files_init(void)
{ 
	filp_cachep = kmem_cache_create("filp", sizeof(struct file), 0,
			SLAB_HWCACHE_ALIGN | SLAB_PANIC, NULL);
	percpu_counter_init(&nr_files, 0, GFP_KERNEL);
}

/*
 * One file with associated inode and dcache is very roughly 1K. Per default
 * do not use more than 10% of our memory for files.
 */
/* 一个带有相关inode和dcache的文件大约为1K。
 * 默认情况下不要将超过10%的内存用于文件
 */
void __init files_maxfiles_init(void)
{
	unsigned long n;
	/* 这里等于（totalram_pages - nr_free_pages）的1.5倍，
	 * 主要还是为了节省一点内存来给其他功能用
	 */
	unsigned long memreserve = (totalram_pages - nr_free_pages()) * 3/2;

	memreserve = min(memreserve, totalram_pages - 1);
	/* 一个带有相关的inode和dcache的文件大约为1K
	 * 所以这里用不超过10%的内存用于文件
	 * 这里就算出最大可以有多少个文件
	 */
	n = ((totalram_pages - memreserve) * (PAGE_SIZE / 1024)) / 10;
	/* 比较NR_FILE（8192）和 n的最大值
	 * 然后把它写入到最大文件数量files_stat.max_files中 */
	files_stat.max_files = max_t(unsigned long, n, NR_FILE);
} 
