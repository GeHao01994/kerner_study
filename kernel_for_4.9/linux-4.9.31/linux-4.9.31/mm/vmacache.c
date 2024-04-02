/*
 * Copyright (C) 2014 Davidlohr Bueso.
 */
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/vmacache.h>

/*
 * Flush vma caches for threads that share a given mm.
 *
 * The operation is safe because the caller holds the mmap_sem
 * exclusively and other threads accessing the vma cache will
 * have mmap_sem held at least for read, so no extra locking
 * is required to maintain the vma cache.
 *
 * 为共享给定mm的线程刷新vma缓存.
 *
 * 此操作是安全的,因为调用者独占地持有mmap_sem,访问vma缓存的其他线程将至少保留mmapsem以供读取，因此不需要额外的锁定来维护vma缓存。
 */
void vmacache_flush_all(struct mm_struct *mm)
{
	struct task_struct *g, *p;

	count_vm_vmacache_event(VMACACHE_FULL_FLUSHES);

	/*
	 * Single threaded tasks need not iterate the entire
	 * list of process. We can avoid the flushing as well
	 * since the mm's seqnum was increased and don't have
	 * to worry about other threads' seqnum. Current's
	 * flush will occur upon the next lookup.
	 *
	 * 单线程任务不需要迭代整个进程列表.
	 * 我们也可以避免冲刷,因为mm's seqnum增加了,而且不必担心其他线程的sequm.
	 * Current的刷新将在下一次查找时发生.
	 */
	if (atomic_read(&mm->mm_users) == 1)
		return;

	rcu_read_lock();
	for_each_process_thread(g, p) {
		/*
		 * Only flush the vmacache pointers as the
		 * mm seqnum is already set and curr's will
		 * be set upon invalidation when the next
		 * lookup is done.
		 *
		 * 只刷新vmacache指针,因为mm seqnum早就被设置了,
		 * 并且curr将被设置为invalidation当下一次循环完成时
		 */
		if (mm == p->mm)
			vmacache_flush(p);
	}
	rcu_read_unlock();
}

/*
 * This task may be accessing a foreign mm via (for example)
 * get_user_pages()->find_vma().  The vmacache is task-local and this
 * task's vmacache pertains to a different mm (ie, its own).  There is
 * nothing we can do here.
 *
 * Also handle the case where a kernel thread has adopted this mm via use_mm().
 * That kernel thread's vmacache is not applicable to this mm.
 *
 * 此任务可能通过(例如)get_user_pages()->find_vma()访问外部mm.
 * vmacache是task-local,该任务的vmacache属于不同的mm(即它自己的).
 * 我们在这里无能为力.
 *
 * 还要处理内核线程通过use_mm()采用此mm的情况.
 * 该内核线程的vmacache不适用于此mm.
 */
static inline bool vmacache_valid_mm(struct mm_struct *mm)
{
	return current->mm == mm && !(current->flags & PF_KTHREAD);
}

void vmacache_update(unsigned long addr, struct vm_area_struct *newvma)
{
	if (vmacache_valid_mm(newvma->vm_mm))
		current->vmacache[VMACACHE_HASH(addr)] = newvma;
}

static bool vmacache_valid(struct mm_struct *mm)
{
	struct task_struct *curr;
	/* 这里是去判断当前进程是不是内核进程或者说当前进程的mm是不是传进来的mm
	 * 如果是内核线程或者说该mm不是当前进程的mm
	 * 那么返回false
	 */
	if (!vmacache_valid_mm(mm))
		return false;

	curr = current;
	/* 当一个VMA被移除/合并时,其对应的"vm_area_struct"就不复存在了,
	 * 如果它存在于VMA cache中,那么这个VMA cache就应该被标记为invalidate状态,避免接下来继续访问已经不存在的VMA.
	 * 因为很多线程的VMA cache中可能都含有这个"vm_area_struct",一个个去设置为NULL来标记比较麻烦,所以同硬件cache使用"modified"和"invalidate"标志位不同,
	 * "per-thread VMA cache"是用数字"vmacache_seqnum"的相对大小来表达这种关系.
	 *
	 * 当一个VMA cache失效后,其所属进程(地址空间)的"mm_struct"中的"vmacache_seqnum"的值就会加1,而VMA cache中的"seqnum"的值保持不变.
	 * 人家变你不变,就是“过时”,挺巧妙的.
	 *
	 * 接下来线程每次查找VMA cache的时候,都会比较自己手头的VMA cache中的"seqnum"的值,和线程所属进程地址空间的"vmacache_seqnum"的值,
	 * 如果不等,就说明这个VMA cache是失效的.
	 * 这时再做cache的invalidate/flush操作也不迟,又一个"lazy"延迟操作思想的体现.
	 */
	if (mm->vmacache_seqnum != curr->vmacache_seqnum) {
		/*
		 * First attempt will always be invalid, initialize
		 * the new cache for this task here.
		 *
		 * 第一次尝试总是无效的,请在此处初始化此任务的新缓存.
		 */
		curr->vmacache_seqnum = mm->vmacache_seqnum;
		vmacache_flush(curr);
		return false;
	}
	return true;
}

struct vm_area_struct *vmacache_find(struct mm_struct *mm, unsigned long addr)
{
	int i;

	/* 增加本CPU VMACACHE_FIND_CALLS的count */
	count_vm_vmacache_event(VMACACHE_FIND_CALLS);

	/* 如果vmacache是无效的,那么返回NULL */
	if (!vmacache_valid(mm))
		return NULL;

	/* 如果vmacache是有效的,那么循环去查找 */
	for (i = 0; i < VMACACHE_SIZE; i++) {
		/* 拿到对应的vma指针 */
		struct vm_area_struct *vma = current->vmacache[i];

		/* 如果vma是空的,那么就continue */
		if (!vma)
			continue;
		/* 如果vma->vm_mm != mm,那么break */
		if (WARN_ON_ONCE(vma->vm_mm != mm))
			break;
		/* 如果vma->vm_start <= addr < vma->vm_end */
		if (vma->vm_start <= addr && vma->vm_end > addr) {
			/* 那么增加本CPU的VMACACHE_FIND_HITS计数 */
			count_vm_vmacache_event(VMACACHE_FIND_HITS);
			/* 返回本vma */
			return vma;
		}
	}

	/* 如果没有就返回NULL */
	return NULL;
}

#ifndef CONFIG_MMU
struct vm_area_struct *vmacache_find_exact(struct mm_struct *mm,
					   unsigned long start,
					   unsigned long end)
{
	int i;

	count_vm_vmacache_event(VMACACHE_FIND_CALLS);

	if (!vmacache_valid(mm))
		return NULL;

	for (i = 0; i < VMACACHE_SIZE; i++) {
		struct vm_area_struct *vma = current->vmacache[i];

		if (vma && vma->vm_start == start && vma->vm_end == end) {
			count_vm_vmacache_event(VMACACHE_FIND_HITS);
			return vma;
		}
	}

	return NULL;
}
#endif
