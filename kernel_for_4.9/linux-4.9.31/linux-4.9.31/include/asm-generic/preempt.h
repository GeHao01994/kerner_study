#ifndef __ASM_PREEMPT_H
#define __ASM_PREEMPT_H

#include <linux/thread_info.h>

#define PREEMPT_ENABLED	(0)

static __always_inline int preempt_count(void)
{
	return READ_ONCE(current_thread_info()->preempt_count);
}

static __always_inline volatile int *preempt_count_ptr(void)
{
	return &current_thread_info()->preempt_count;
}

static __always_inline void preempt_count_set(int pc)
{
	*preempt_count_ptr() = pc;
}

/*
 * must be macros to avoid header recursion hell
 */
/* 初始化thread_info数据结构中的preempt_count计数,为了支持内核抢占而引入该字段.
 * 当preempt_count为0时表示内核可以被安全地抢占,大于0时,则禁止抢占.
 *
 * preempt_count计数的结构如下图
 *
 * |----------------------preempt_count计数-----------------------|
 * ↓--------------------------------------------------------------↓
 * |        | PREEMPT_ACTIVE | NMI | hardirq | sortirq | preempt  |
 *  --------------------------------------------------------------
 *                   21            20       16         8          0
 *
 * PREEMPT_MASK(0x000000ff)表示抢占计数,记录内核显式地被禁止抢占的次数.
 * 每次调用preempt_disable时该域的值会加1,调用preempt_enable该域的值会减1.
 * preempt_disable和preempt_enable成对出现,可以嵌套的深度最大为255.
 *
 * SOFTIRQ_MASK(0x0000ff000)表示软中断嵌套数量或嵌套的深度.
 *
 * HARDIRQ_MASK(0x000f0000)表示硬件中断嵌套数量或嵌套的深度.
 *
 * NMI_MASK(0x00100000)表示NMI中断
 *
 * PREEMPT_ACTIVE(0x00200000)表示当前已经被抢占或刚刚被抢占,通常用于表示抢占调度
 *
 * 以上任何一个字段的值非零,那么内核的抢占功能都会被禁用.
 */
#define init_task_preempt_count(p) do { \
	task_thread_info(p)->preempt_count = FORK_PREEMPT_COUNT; \
} while (0)

#define init_idle_preempt_count(p, cpu) do { \
	task_thread_info(p)->preempt_count = PREEMPT_ENABLED; \
} while (0)

static __always_inline void set_preempt_need_resched(void)
{
}

static __always_inline void clear_preempt_need_resched(void)
{
}

static __always_inline bool test_preempt_need_resched(void)
{
	return false;
}

/*
 * The various preempt_count add/sub methods
 */

static __always_inline void __preempt_count_add(int val)
{
	*preempt_count_ptr() += val;
}

static __always_inline void __preempt_count_sub(int val)
{
	*preempt_count_ptr() -= val;
}

static __always_inline bool __preempt_count_dec_and_test(void)
{
	/*
	 * Because of load-store architectures cannot do per-cpu atomic
	 * operations; we cannot use PREEMPT_NEED_RESCHED because it might get
	 * lost.
	 */
	return !--*preempt_count_ptr() && tif_need_resched();
}

/*
 * Returns true when we need to resched and can (barring IRQ state).
 */
static __always_inline bool should_resched(int preempt_offset)
{
	return unlikely(preempt_count() == preempt_offset &&
			tif_need_resched());
}

#ifdef CONFIG_PREEMPT
extern asmlinkage void preempt_schedule(void);
#define __preempt_schedule() preempt_schedule()
extern asmlinkage void preempt_schedule_notrace(void);
#define __preempt_schedule_notrace() preempt_schedule_notrace()
#endif /* CONFIG_PREEMPT */

#endif /* __ASM_PREEMPT_H */
