/*
 * descriptor table internals; you almost certainly want file.h instead.
 */

#ifndef __LINUX_FDTABLE_H
#define __LINUX_FDTABLE_H

#include <linux/posix_types.h>
#include <linux/compiler.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/fs.h>

#include <linux/atomic.h>

/*
 * The default fd array needs to be at least BITS_PER_LONG,
 * as this is the granularity returned by copy_fdset().
 */
#define NR_OPEN_DEFAULT BITS_PER_LONG
/* 实际上，在Linux中，进程是通过文件句柄来访问文件的，文件句柄是一个整数。
 * 在其他文献中，它通常被成为文件描述符（File Descriptor），简记为fd.
 * 但文本用描述符来称呼某数据结构的实例，因此文件描述符指的是file结构的对象.
 *
 * 每个进程可以打开多个文件，将它们组织成打开文件表的形式，实际上是指向文件描述符的指针数组，
 * 数组的索引即为文件句柄。因而给定一个文件句柄，必然可以找到对应的文件结构，从而实现对此文件的操作。
 * 打开文件表在内核中对应fdtable结构。
 */
struct fdtable {
	/* max_fds指定了进程当前可打开文件的最大数目 */
	unsigned int max_fds;
	/* fd是一个指针数组，每个数组元素指向一个file结构的实例。
	 * 管理一个打开文件的所有信息。
	 * 用户空间进程的文件描述符充当数组索引，该数组当前的长度由max_fds定义。
	 * fd最初指向内置它的struct files_struct结构体的成员fs_array,当超过可打开的文件数量时，
	 * 就重新申请内存（struct file指针数组）并指向新的struct file指针数组来扩展可打开文件的数量
	 */
	struct file __rcu **fd;      /* current fd array */
	/* 文件描述符指针数组的close_on_exec位图 */
	/* close_on_exec是一个指向位图的指针，该位图保存了所有在exec系统调用时将要关闭的
	 * 文件描述符的信息。
	 */
	unsigned long *close_on_exec;
	/* 文件描述符指针数组的open_fds位图 */
	/* 是真正的文件描述符位图，也是一片连续的内存空间，每bit代表一个文件描述符(注意full_fds_bits每bit代表的是一组文件描述符)，
	 * 标记为0的bit表示该文件描述符没有被使用，标记为1的bit表示该文件描述符已经被使用，
	 * 例如从内存其实地址开始计算，第35比特为1，则表示文件描述符35已经被使用了
	 */
	unsigned long *open_fds;
	/* 每1bit代表的是一个64位的数组，也就是说代表了64个文件描述符；
	 * 内核中的位图是一片连续的内存空间，最低bit表示数值0，下一比特表示1，依次类推；
	 * full_fds_bits每1bit只有0和1两个值，0表示有该组有可用的文件描述符，1表示没有可用的文件描述符，
	 * 例如，位图bit 0代表的是0-63共64个文件描述符，bit1代表的是64-127共64个文件描述符，
	 * 假如0-63文件描述符都被使用了，那么位图bit0则应该标记为1，
	 * 如果64-127中有一个未使用的文件描述符，则bit1被标记为0，
	 * 当64-127中的所有文件描述符都被使用的时候，才标记为1
	 */
	unsigned long *full_fds_bits;
	struct rcu_head rcu;
};

static inline bool close_on_exec(unsigned int fd, const struct fdtable *fdt)
{
	return test_bit(fd, fdt->close_on_exec);
}

static inline bool fd_is_open(unsigned int fd, const struct fdtable *fdt)
{
	return test_bit(fd, fdt->open_fds);
}

/*
 * Open file table structure
 */
/* 每个进程都需要分配一个打开文件表以及对应数量的指针数组。
 * 对于大多数进程，打开文件的数量是有限的。
 * 一种优化的设计方式是为每个进程内置分配少量数目的文件描述符指针数组，
 * 当进程确实需要更多的指针时，可另行分配，即动态扩展。
 * 为此，进程并不直接使用打开文件表，而是引入一个新的files_struct结构
 */

/* 每个files_struct结构通过fdt域指向它实际使用的打开文件表。
 * 对于大多数进程来说，打开文件的数量并不会很多，不超过32个
 * 这个时候无需另外分配空间，直接指向本结构中已经内嵌的打开文件表，即fd_tab域。
 * 同理，fd_array域为内嵌的文件描述符指针数组
 */
struct files_struct {
  /*
   * read mostly part
   */
	/* 引用计数,也就是使用该表的进程数 */
	atomic_t count;
	/* 这个就是说当一个文件已append打开时，它会在文件结尾
	 * 写东西，导致大小改变
	 */
	bool resize_in_progress;
	wait_queue_head_t resize_wait;
	/* 指向打开文件表的指针 */
	struct fdtable __rcu *fdt;
	/* 内嵌的开发文件表 */
	struct fdtable fdtab;
  /*
   * written part on a separate cache line in SMP
   */
	spinlock_t file_lock ____cacheline_aligned_in_smp;
	/* next_fd域记录了要分配的下一个文件句柄的值。
	 * 一般来说文件句柄按递增的顺序分配，除非以前 分配的文件句柄对应文件被关闭。
	 * 这时，next_fd域被设置为关闭文件的文件句柄。因此，文件句柄按最低的可用值分配
	 */
	unsigned int next_fd;
	/* 内嵌的close_on_exec位图 */
	unsigned long close_on_exec_init[1];
	/* 内嵌的open_fds位图*/
	unsigned long open_fds_init[1];
	unsigned long full_fds_bits_init[1];
	/* 内存的文件对象指针数组 */
	struct file __rcu * fd_array[NR_OPEN_DEFAULT];
};

struct file_operations;
struct vfsmount;
struct dentry;

#define rcu_dereference_check_fdtable(files, fdtfd) \
	rcu_dereference_check((fdtfd), lockdep_is_held(&(files)->file_lock))

#define files_fdtable(files) \
	rcu_dereference_check_fdtable((files), (files)->fdt)

/*
 * The caller must ensure that fd table isn't shared or hold rcu or file lock
 */
static inline struct file *__fcheck_files(struct files_struct *files, unsigned int fd)
{
	/* 拿到我们的fdt */
	struct fdtable *fdt = rcu_dereference_raw(files->fdt);
	/* 如果fd小于当前可打开文件的最大数目
	 * 那么就返回数组里面对应的file
	 */
	if (fd < fdt->max_fds)
		return rcu_dereference_raw(fdt->fd[fd]);
	/* 否则，返回NULL */
	return NULL;
}

static inline struct file *fcheck_files(struct files_struct *files, unsigned int fd)
{
	RCU_LOCKDEP_WARN(!rcu_read_lock_held() &&
			   !lockdep_is_held(&files->file_lock),
			   "suspicious rcu_dereference_check() usage");
	return __fcheck_files(files, fd);
}

/*
 * Check whether the specified fd has an open file.
 */
#define fcheck(fd)	fcheck_files(current->files, fd)

struct task_struct;

struct files_struct *get_files_struct(struct task_struct *);
void put_files_struct(struct files_struct *fs);
void reset_files_struct(struct files_struct *);
int unshare_files(struct files_struct **);
struct files_struct *dup_fd(struct files_struct *, int *) __latent_entropy;
void do_close_on_exec(struct files_struct *);
int iterate_fd(struct files_struct *, unsigned,
		int (*)(const void *, struct file *, unsigned),
		const void *);

extern int __alloc_fd(struct files_struct *files,
		      unsigned start, unsigned end, unsigned flags);
extern void __fd_install(struct files_struct *files,
		      unsigned int fd, struct file *file);
extern int __close_fd(struct files_struct *files,
		      unsigned int fd);

extern struct kmem_cache *files_cachep;

#endif /* __LINUX_FDTABLE_H */
