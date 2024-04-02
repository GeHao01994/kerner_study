#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/compiler.h>
#include <linux/export.h>
#include <linux/err.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/mman.h>
#include <linux/hugetlb.h>
#include <linux/vmalloc.h>

#include <asm/sections.h>
#include <asm/uaccess.h>

#include "internal.h"

static inline int is_kernel_rodata(unsigned long addr)
{
	return addr >= (unsigned long)__start_rodata &&
		addr < (unsigned long)__end_rodata;
}

/**
 * kfree_const - conditionally free memory
 * @x: pointer to the memory
 *
 * Function calls kfree only if @x is not in .rodata section.
 */
void kfree_const(const void *x)
{
	if (!is_kernel_rodata((unsigned long)x))
		kfree(x);
}
EXPORT_SYMBOL(kfree_const);

/**
 * kstrdup - allocate space for and copy an existing string
 * @s: the string to duplicate
 * @gfp: the GFP mask used in the kmalloc() call when allocating memory
 */
char *kstrdup(const char *s, gfp_t gfp)
{
	size_t len;
	char *buf;

	if (!s)
		return NULL;

	len = strlen(s) + 1;
	buf = kmalloc_track_caller(len, gfp);
	if (buf)
		memcpy(buf, s, len);
	return buf;
}
EXPORT_SYMBOL(kstrdup);

/**
 * kstrdup_const - conditionally duplicate an existing const string
 * @s: the string to duplicate
 * @gfp: the GFP mask used in the kmalloc() call when allocating memory
 *
 * Function returns source string if it is in .rodata section otherwise it
 * fallbacks to kstrdup.
 * Strings allocated by kstrdup_const should be freed by kfree_const.
 */
const char *kstrdup_const(const char *s, gfp_t gfp)
{
	if (is_kernel_rodata((unsigned long)s))
		return s;

	return kstrdup(s, gfp);
}
EXPORT_SYMBOL(kstrdup_const);

/**
 * kstrndup - allocate space for and copy an existing string
 * @s: the string to duplicate
 * @max: read at most @max chars from @s
 * @gfp: the GFP mask used in the kmalloc() call when allocating memory
 */
char *kstrndup(const char *s, size_t max, gfp_t gfp)
{
	size_t len;
	char *buf;

	if (!s)
		return NULL;

	len = strnlen(s, max);
	buf = kmalloc_track_caller(len+1, gfp);
	if (buf) {
		memcpy(buf, s, len);
		buf[len] = '\0';
	}
	return buf;
}
EXPORT_SYMBOL(kstrndup);

/**
 * kmemdup - duplicate region of memory
 *
 * @src: memory region to duplicate
 * @len: memory region length
 * @gfp: GFP mask to use
 */
void *kmemdup(const void *src, size_t len, gfp_t gfp)
{
	void *p;

	p = kmalloc_track_caller(len, gfp);
	if (p)
		memcpy(p, src, len);
	return p;
}
EXPORT_SYMBOL(kmemdup);

/**
 * memdup_user - duplicate memory region from user space
 *
 * @src: source address in user space
 * @len: number of bytes to copy
 *
 * Returns an ERR_PTR() on failure.
 */
void *memdup_user(const void __user *src, size_t len)
{
	void *p;

	/*
	 * Always use GFP_KERNEL, since copy_from_user() can sleep and
	 * cause pagefault, which makes it pointless to use GFP_NOFS
	 * or GFP_ATOMIC.
	 */
	p = kmalloc_track_caller(len, GFP_KERNEL);
	if (!p)
		return ERR_PTR(-ENOMEM);

	if (copy_from_user(p, src, len)) {
		kfree(p);
		return ERR_PTR(-EFAULT);
	}

	return p;
}
EXPORT_SYMBOL(memdup_user);

/*
 * strndup_user - duplicate an existing string from user space
 * @s: The string to duplicate
 * @n: Maximum number of bytes to copy, including the trailing NUL.
 */
char *strndup_user(const char __user *s, long n)
{
	char *p;
	long length;

	length = strnlen_user(s, n);

	if (!length)
		return ERR_PTR(-EFAULT);

	if (length > n)
		return ERR_PTR(-EINVAL);

	p = memdup_user(s, length);

	if (IS_ERR(p))
		return p;

	p[length - 1] = '\0';

	return p;
}
EXPORT_SYMBOL(strndup_user);

/**
 * memdup_user_nul - duplicate memory region from user space and NUL-terminate
 *
 * @src: source address in user space
 * @len: number of bytes to copy
 *
 * Returns an ERR_PTR() on failure.
 */
void *memdup_user_nul(const void __user *src, size_t len)
{
	char *p;

	/*
	 * Always use GFP_KERNEL, since copy_from_user() can sleep and
	 * cause pagefault, which makes it pointless to use GFP_NOFS
	 * or GFP_ATOMIC.
	 */
	p = kmalloc_track_caller(len + 1, GFP_KERNEL);
	if (!p)
		return ERR_PTR(-ENOMEM);

	if (copy_from_user(p, src, len)) {
		kfree(p);
		return ERR_PTR(-EFAULT);
	}
	p[len] = '\0';

	return p;
}
EXPORT_SYMBOL(memdup_user_nul);

void __vma_link_list(struct mm_struct *mm, struct vm_area_struct *vma,
		struct vm_area_struct *prev, struct rb_node *rb_parent)
{
	struct vm_area_struct *next;

	vma->vm_prev = prev;
	if (prev) {
		next = prev->vm_next;
		prev->vm_next = vma;
	} else {
		mm->mmap = vma;
		if (rb_parent)
			next = rb_entry(rb_parent,
					struct vm_area_struct, vm_rb);
		else
			next = NULL;
	}
	vma->vm_next = next;
	if (next)
		next->vm_prev = vma;
}

/* Check if the vma is being used as a stack by this task */
int vma_is_stack_for_current(struct vm_area_struct *vma)
{
	struct task_struct * __maybe_unused t = current;

	return (vma->vm_start <= KSTK_ESP(t) && vma->vm_end >= KSTK_ESP(t));
}

#if defined(CONFIG_MMU) && !defined(HAVE_ARCH_PICK_MMAP_LAYOUT)
void arch_pick_mmap_layout(struct mm_struct *mm)
{
	mm->mmap_base = TASK_UNMAPPED_BASE;
	mm->get_unmapped_area = arch_get_unmapped_area;
}
#endif

/*
 * Like get_user_pages_fast() except its IRQ-safe in that it won't fall
 * back to the regular GUP.
 * If the architecture not support this function, simply return with no
 * page pinned
 */
int __weak __get_user_pages_fast(unsigned long start,
				 int nr_pages, int write, struct page **pages)
{
	return 0;
}
EXPORT_SYMBOL_GPL(__get_user_pages_fast);

/**
 * get_user_pages_fast() - pin user pages in memory
 * @start:	starting user address
 * @nr_pages:	number of pages from start to pin
 * @write:	whether pages will be written to
 * @pages:	array that receives pointers to the pages pinned.
 *		Should be at least nr_pages long.
 *
 * Returns number of pages pinned. This may be fewer than the number
 * requested. If nr_pages is 0 or negative, returns 0. If no pages
 * were pinned, returns -errno.
 *
 * get_user_pages_fast provides equivalent functionality to get_user_pages,
 * operating on current and current->mm, with force=0 and vma=NULL. However
 * unlike get_user_pages, it must be called without mmap_sem held.
 *
 * get_user_pages_fast may take mmap_sem and page table locks, so no
 * assumptions can be made about lack of locking. get_user_pages_fast is to be
 * implemented in a way that is advantageous (vs get_user_pages()) when the
 * user memory area is already faulted in and present in ptes. However if the
 * pages have to be faulted in, it may turn out to be slightly slower so
 * callers need to carefully consider what to use. On many architectures,
 * get_user_pages_fast simply falls back to get_user_pages.
 */
int __weak get_user_pages_fast(unsigned long start,
				int nr_pages, int write, struct page **pages)
{
	return get_user_pages_unlocked(start, nr_pages, pages,
				       write ? FOLL_WRITE : 0);
}
EXPORT_SYMBOL_GPL(get_user_pages_fast);

unsigned long vm_mmap_pgoff(struct file *file, unsigned long addr,
	unsigned long len, unsigned long prot,
	unsigned long flag, unsigned long pgoff)
{
	unsigned long ret;
	struct mm_struct *mm = current->mm;
	unsigned long populate;

	ret = security_mmap_file(file, prot, flag);
	if (!ret) {
		if (down_write_killable(&mm->mmap_sem))
			return -EINTR;
		ret = do_mmap_pgoff(file, addr, len, prot, flag, pgoff,
				    &populate);
		up_write(&mm->mmap_sem);
		if (populate)
			mm_populate(ret, populate);
	}
	return ret;
}

unsigned long vm_mmap(struct file *file, unsigned long addr,
	unsigned long len, unsigned long prot,
	unsigned long flag, unsigned long offset)
{
	if (unlikely(offset + PAGE_ALIGN(len) < offset))
		return -EINVAL;
	if (unlikely(offset_in_page(offset)))
		return -EINVAL;

	return vm_mmap_pgoff(file, addr, len, prot, flag, offset >> PAGE_SHIFT);
}
EXPORT_SYMBOL(vm_mmap);

void kvfree(const void *addr)
{
	if (is_vmalloc_addr(addr))
		vfree(addr);
	else
		kfree(addr);
}
EXPORT_SYMBOL(kvfree);

static inline void *__page_rmapping(struct page *page)
{
	unsigned long mapping;

	mapping = (unsigned long)page->mapping;
	mapping &= ~PAGE_MAPPING_FLAGS;

	return (void *)mapping;
}

/* Neutral page->mapping pointer to address_space or anon_vma or other */
void *page_rmapping(struct page *page)
{
	page = compound_head(page);
	return __page_rmapping(page);
}

/*
 * Return true if this page is mapped into pagetables.
 * For compound page it returns true if any subpage of compound page is mapped.
 */
bool page_mapped(struct page *page)
{
	int i;

	if (likely(!PageCompound(page)))
		return atomic_read(&page->_mapcount) >= 0;
	page = compound_head(page);
	if (atomic_read(compound_mapcount_ptr(page)) >= 0)
		return true;
	if (PageHuge(page))
		return false;
	for (i = 0; i < hpage_nr_pages(page); i++) {
		if (atomic_read(&page[i]._mapcount) >= 0)
			return true;
	}
	return false;
}
EXPORT_SYMBOL(page_mapped);

struct anon_vma *page_anon_vma(struct page *page)
{
	unsigned long mapping;

	page = compound_head(page);
	mapping = (unsigned long)page->mapping;
	if ((mapping & PAGE_MAPPING_FLAGS) != PAGE_MAPPING_ANON)
		return NULL;
	return __page_rmapping(page);
}

struct address_space *page_mapping(struct page *page)
{
	struct address_space *mapping;
	/* 如果是组合页，那么拿到头，否则就是它自己啊 */
	page = compound_head(page);

	/* This happens if someone calls flush_dcache_page on slab page */
	/* 如果这个页用于SLAB */
	if (unlikely(PageSlab(page)))
		return NULL;
	/* swapcache表示匿名页面已经交换(swap)到磁盘,那么返回它的swap_address_space空间 */
	if (unlikely(PageSwapCache(page))) {
		swp_entry_t entry;

		entry.val = page_private(page);
		return swap_address_space(entry);
	}

	mapping = page->mapping;
	/* 如果是匿名页面，那么返回NULL */
	if ((unsigned long)mapping & PAGE_MAPPING_ANON)
		return NULL;
	/* 否则返回mapping的地址 */
	return (void *)((unsigned long)mapping & ~PAGE_MAPPING_FLAGS);
}
EXPORT_SYMBOL(page_mapping);

/* Slow path of page_mapcount() for compound pages */
int __page_mapcount(struct page *page)
{
	int ret;

	ret = atomic_read(&page->_mapcount) + 1;
	/*
	 * For file THP page->_mapcount contains total number of mapping
	 * of the page: no need to look into compound_mapcount.
	 */
	if (!PageAnon(page) && !PageHuge(page))
		return ret;
	page = compound_head(page);
	ret += atomic_read(compound_mapcount_ptr(page)) + 1;
	if (PageDoubleMap(page))
		ret--;
	return ret;
}
EXPORT_SYMBOL_GPL(__page_mapcount);

int sysctl_overcommit_memory __read_mostly = OVERCOMMIT_GUESS;
int sysctl_overcommit_ratio __read_mostly = 50;
unsigned long sysctl_overcommit_kbytes __read_mostly;
int sysctl_max_map_count __read_mostly = DEFAULT_MAX_MAP_COUNT;
unsigned long sysctl_user_reserve_kbytes __read_mostly = 1UL << 17; /* 128MB */
unsigned long sysctl_admin_reserve_kbytes __read_mostly = 1UL << 13; /* 8MB */

int overcommit_ratio_handler(struct ctl_table *table, int write,
			     void __user *buffer, size_t *lenp,
			     loff_t *ppos)
{
	int ret;

	ret = proc_dointvec(table, write, buffer, lenp, ppos);
	if (ret == 0 && write)
		sysctl_overcommit_kbytes = 0;
	return ret;
}

int overcommit_kbytes_handler(struct ctl_table *table, int write,
			     void __user *buffer, size_t *lenp,
			     loff_t *ppos)
{
	int ret;

	ret = proc_doulongvec_minmax(table, write, buffer, lenp, ppos);
	if (ret == 0 && write)
		sysctl_overcommit_ratio = 0;
	return ret;
}

/*
 * Committed memory limit enforced when OVERCOMMIT_NEVER policy is used
 */
unsigned long vm_commit_limit(void)
{
	unsigned long allowed;

	/* /proc/sys/vm/overcommit_kbytes */
	if (sysctl_overcommit_kbytes)	/* 这个操作实际上是将kB转换成以page为单位 */
		allowed = sysctl_overcommit_kbytes >> (PAGE_SHIFT - 10);
	else /* 否则使用overcommit_ratio */
		allowed = ((totalram_pages - hugetlb_total_pages())
			   * sysctl_overcommit_ratio / 100);
	allowed += total_swap_pages;

	/* 返回判断overcommit的阈值,是以page为单位的 */
	return allowed;
}

/*
 * Make sure vm_committed_as in one cacheline and not cacheline shared with
 * other variables. It can be updated by several CPUs frequently.
 */
struct percpu_counter vm_committed_as ____cacheline_aligned_in_smp;

/*
 * The global memory commitment made in the system can be a metric
 * that can be used to drive ballooning decisions when Linux is hosted
 * as a guest. On Hyper-V, the host implements a policy engine for dynamically
 * balancing memory across competing virtual machines that are hosted.
 * Several metrics drive this policy engine including the guest reported
 * memory commitment.
 */
unsigned long vm_memory_committed(void)
{
	return percpu_counter_read_positive(&vm_committed_as);
}
EXPORT_SYMBOL_GPL(vm_memory_committed);

/*
 * Check that a process has enough memory to allocate a new virtual
 * mapping. 0 means there is enough memory for the allocation to
 * succeed and -ENOMEM implies there is not.
 *
 * We currently support three overcommit policies, which are set via the
 * vm.overcommit_memory sysctl.  See Documentation/vm/overcommit-accounting
 *
 * Strict overcommit modes added 2002 Feb 26 by Alan Cox.
 * Additional code 2002 Jul 20 by Robert Love.
 *
 * cap_sys_admin is 1 if the process has admin privileges, 0 otherwise.
 *
 * Note this is a helper function intended to be used by LSMs which
 * wish to use this logic.
 *
 * 检查进程是否有足够的内存来分配新的虚拟映射. 0表示有足够的内存用于成功分配,而-ENOMM表示没有.
 *
 * 我们目前支持三种overcommit策略，它们是通过vm.overcommit_memory sysctl设置的.See Documentation/vm/overcommit-accounting
 *
 * Alan Cox于2002年2月26日增加了overcommit模式。
 * Robert Love于2002年7月20日添加了附加代码
 *
 * 如果进程具有管理员权限,则cap_sys_admin为1,否则为0.
 * 请注意,这是一个帮助函数,旨在由希望使用此逻辑的LSM使用。
 */
int __vm_enough_memory(struct mm_struct *mm, long pages, int cap_sys_admin)
{
	long free, allowed, reserve;

	VM_WARN_ONCE(percpu_counter_read(&vm_committed_as) <
			-(s64)vm_committed_as_batch * num_online_cpus(),
			"memory commitment underflow");

	/*  static inline void vm_acct_memory(long pages)
	 * {
	 *	__percpu_counter_add(&vm_committed_as, pages, vm_committed_as_batch);
	 * }
	 * 将这次要分配的pages数量传入到vm_committed_as中
	 */
	vm_acct_memory(pages);

	/*
	 * Sometimes we want to use more memory than we have
	 */
	/* 由于内核不限制overcommit,直接返回0,
	 * sysctl_overcommit_memory受内核参数/proc/sys/vm/overcommit_memory控制
	 */
	if (sysctl_overcommit_memory == OVERCOMMIT_ALWAYS)
		return 0;

	/* 若为OVERCOMMIT_GUESS,内核会进行判断内存分配是否合理 */
	if (sysctl_overcommit_memory == OVERCOMMIT_GUESS) {
		/* 1.首先会计算当前系统的可用内存
		 * (1)计算有多少空闲page
		 */
		free = global_page_state(NR_FREE_PAGES);
		/* 计算有多少page cache使用的page frame,主要是用户空间进程读写文件造成的
		 * 这些cache都是为了加快系统性能而增加的,提高CPU读写命中率,因此,如果直接操作到磁盘,本质上这些page cache都是free的
		 */
		free += global_node_page_state(NR_FILE_PAGES);

		/*
		 * shmem pages shouldn't be counted as free in this
		 * case, they can't be purged, only swapped out, and
		 * that won't affect the overall amount of available
		 * memory in the system.
		 *
		 * 在这种情况下,shmem页面不应被视为空闲,它们不能被清除,只能交换出去,这不会影响系统中可用内存的总量.
		 */

		/* (3)用于进程间的share memory机制的这些shmem page frame不能认为是free的，需要减去
		 * 而且它们不能被清除(free),只能换出(swap out)
		 */
		free -= global_node_page_state(NR_SHMEM);

		/* (4)加上swap file或者swap device上空闲的“page frame”数目.
		 * 本质上,swap file或者swap device上的磁盘空间都是给anonymous page做腾挪之用,其实这里的“page frame”不是真的page frame.称之swap page好了
		 * 这里把free swap page的数目也计入free主要是因为可以把使用中的page frame swap out到free swap page上,因此也算是free page
		 */
		free += get_nr_swap_pages();

		/*
		 * Any slabs which are created with the
		 * SLAB_RECLAIM_ACCOUNT flag claim to have contents
		 * which are reclaimable, under pressure.  The dentry
		 * cache and most inode caches should fall into this
		 *
		 * 使用SLAB_RECLAIM_ACCOUNT标志创建的任何slab都声称其内容可在压力下回收.
		 * dentry缓存和大多数inode缓存应该属于这种
		 */

		/* (5)加上被标记为可回收的slab对应的页面 */
		free += global_page_state(NR_SLAB_RECLAIMABLE);

		/*
		 * Leave reserved pages. The pages are not for anonymous pages.
		 */

		/* totalreserve_pages，这是一个能让系统运行需要预留的page frame的数目，
		 * (7)因此我们要从减去totalreserve_pages.如果当前free page数目小于totalreserve_pages,则拒绝本次对内核空间里面的虚拟内存的申请.
		 */
		if (free <= totalreserve_pages)
			goto error;
		else
			free -= totalreserve_pages;

		/*
		 * Reserve some for root
		 */
		/* (8)如果是普通的进程,还需要保留admin_reserve_kbytes(/proc/sys/vm/admin_reserve_kbytes)的free page,
		 *    以便在出问题时可以让root用户可以登录并进行恢复操作
		 */
		if (!cap_sys_admin)
			free -= sysctl_admin_reserve_kbytes >> (PAGE_SHIFT - 10);

		/* 最关键的判断来了
		 * 比对当前系统的可用内存(free)和本次请求分配virtual memory的page数目(pages),
		 * 如果在前面减去了所必须的page frame之后,还有足够的page可以满足本次分配,那么就批准本次对内核空间里面的虚拟内存的分配.
		 */
		if (free > pages)
			return 0;

		goto error;
	}

	/* 2.下面为OVERCOMMIT_NEVER的情况，是禁止出现overcommit
	 * (1)这里调用vm_commit_limit得到判断是否出现overcommit的阈值allowed,以page为单位
	 */
	allowed = vm_commit_limit();
	/*
	 * Reserve some for root
	 */
	/* (2)同前面一样，需要减去预留给root用户的内存 */
	if (!cap_sys_admin)
		allowed -= sysctl_admin_reserve_kbytes >> (PAGE_SHIFT - 10);

	/*
	 * Don't let a single process grow so big a user can't recover
	 */
	/* (3)如果是用户空间的进程,要为用户能够从绝境中恢复而保留一些page frame,具体保留多少需要考量两个因素,
	 * 一个是单一进程的total virtual memory,
	 * 一个是用户设定的运行时参数user_reserve_kbytes
	 * 更具体的考量因素可以参考https://lkml.org/lkml/2013/3/18/812
	 */
	if (mm) {
		reserve = sysctl_user_reserve_kbytes >> (PAGE_SHIFT - 10);
		allowed -= min_t(long, mm->total_vm / 32, reserve);
	}

	/* allowed变量保存了判断overcommit的上限(CommitLimit),vm_committed_as(Committed_AS)保存了当前系统中已经申请(包括本次)
	 * 的virtual memory的数目.如果大于这个上限就判断overcommit,本次申请虚拟内存失败.
	 */
	if (percpu_counter_read_positive(&vm_committed_as) < allowed)
		return 0;
error:
	vm_unacct_memory(pages);

	return -ENOMEM;
}

/**
 * get_cmdline() - copy the cmdline value to a buffer.
 * @task:     the task whose cmdline value to copy.
 * @buffer:   the buffer to copy to.
 * @buflen:   the length of the buffer. Larger cmdline values are truncated
 *            to this length.
 * Returns the size of the cmdline field copied. Note that the copy does
 * not guarantee an ending NULL byte.
 */
int get_cmdline(struct task_struct *task, char *buffer, int buflen)
{
	int res = 0;
	unsigned int len;
	struct mm_struct *mm = get_task_mm(task);
	unsigned long arg_start, arg_end, env_start, env_end;
	if (!mm)
		goto out;
	if (!mm->arg_end)
		goto out_mm;	/* Shh! No looking before we're done */

	down_read(&mm->mmap_sem);
	arg_start = mm->arg_start;
	arg_end = mm->arg_end;
	env_start = mm->env_start;
	env_end = mm->env_end;
	up_read(&mm->mmap_sem);

	len = arg_end - arg_start;

	if (len > buflen)
		len = buflen;

	res = access_process_vm(task, arg_start, buffer, len, FOLL_FORCE);

	/*
	 * If the nul at the end of args has been overwritten, then
	 * assume application is using setproctitle(3).
	 */
	if (res > 0 && buffer[res-1] != '\0' && len < buflen) {
		len = strnlen(buffer, res);
		if (len < res) {
			res = len;
		} else {
			len = env_end - env_start;
			if (len > buflen - res)
				len = buflen - res;
			res += access_process_vm(task, env_start,
						 buffer+res, len,
						 FOLL_FORCE);
			res = strnlen(buffer, res);
		}
	}
out_mm:
	mmput(mm);
out:
	return res;
}
