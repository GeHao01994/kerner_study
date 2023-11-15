#ifndef __LINUX_SPINLOCK_API_SMP_H
#define __LINUX_SPINLOCK_API_SMP_H

#ifndef __LINUX_SPINLOCK_H
# error "please don't include this file directly"
#endif

/*
 * include/linux/spinlock_api_smp.h
 *
 * spinlock API declarations on SMP (and debug)
 * (implemented in kernel/spinlock.c)
 *
 * portions Copyright 2005, Red Hat, Inc., Ingo Molnar
 * Released under the General Public License (GPL).
 */

int in_lock_functions(unsigned long addr);

#define assert_raw_spin_locked(x)	BUG_ON(!raw_spin_is_locked(x))

void __lockfunc _raw_spin_lock(raw_spinlock_t *lock)		__acquires(lock);
void __lockfunc _raw_spin_lock_nested(raw_spinlock_t *lock, int subclass)
								__acquires(lock);
void __lockfunc _raw_spin_lock_bh_nested(raw_spinlock_t *lock, int subclass)
								__acquires(lock);
void __lockfunc
_raw_spin_lock_nest_lock(raw_spinlock_t *lock, struct lockdep_map *map)
								__acquires(lock);
void __lockfunc _raw_spin_lock_bh(raw_spinlock_t *lock)		__acquires(lock);
void __lockfunc _raw_spin_lock_irq(raw_spinlock_t *lock)
								__acquires(lock);

unsigned long __lockfunc _raw_spin_lock_irqsave(raw_spinlock_t *lock)
								__acquires(lock);
unsigned long __lockfunc
_raw_spin_lock_irqsave_nested(raw_spinlock_t *lock, int subclass)
								__acquires(lock);
int __lockfunc _raw_spin_trylock(raw_spinlock_t *lock);
int __lockfunc _raw_spin_trylock_bh(raw_spinlock_t *lock);
void __lockfunc _raw_spin_unlock(raw_spinlock_t *lock)		__releases(lock);
void __lockfunc _raw_spin_unlock_bh(raw_spinlock_t *lock)	__releases(lock);
void __lockfunc _raw_spin_unlock_irq(raw_spinlock_t *lock)	__releases(lock);
void __lockfunc
_raw_spin_unlock_irqrestore(raw_spinlock_t *lock, unsigned long flags)
								__releases(lock);

#ifdef CONFIG_INLINE_SPIN_LOCK
#define _raw_spin_lock(lock) __raw_spin_lock(lock)
#endif

#ifdef CONFIG_INLINE_SPIN_LOCK_BH
#define _raw_spin_lock_bh(lock) __raw_spin_lock_bh(lock)
#endif

#ifdef CONFIG_INLINE_SPIN_LOCK_IRQ
#define _raw_spin_lock_irq(lock) __raw_spin_lock_irq(lock)
#endif

#ifdef CONFIG_INLINE_SPIN_LOCK_IRQSAVE
#define _raw_spin_lock_irqsave(lock) __raw_spin_lock_irqsave(lock)
#endif

#ifdef CONFIG_INLINE_SPIN_TRYLOCK
#define _raw_spin_trylock(lock) __raw_spin_trylock(lock)
#endif

#ifdef CONFIG_INLINE_SPIN_TRYLOCK_BH
#define _raw_spin_trylock_bh(lock) __raw_spin_trylock_bh(lock)
#endif

#ifndef CONFIG_UNINLINE_SPIN_UNLOCK
#define _raw_spin_unlock(lock) __raw_spin_unlock(lock)
#endif

#ifdef CONFIG_INLINE_SPIN_UNLOCK_BH
#define _raw_spin_unlock_bh(lock) __raw_spin_unlock_bh(lock)
#endif

#ifdef CONFIG_INLINE_SPIN_UNLOCK_IRQ
#define _raw_spin_unlock_irq(lock) __raw_spin_unlock_irq(lock)
#endif

#ifdef CONFIG_INLINE_SPIN_UNLOCK_IRQRESTORE
#define _raw_spin_unlock_irqrestore(lock, flags) __raw_spin_unlock_irqrestore(lock, flags)
#endif

static inline int __raw_spin_trylock(raw_spinlock_t *lock)
{
	preempt_disable();
	if (do_raw_spin_trylock(lock)) {
		spin_acquire(&lock->dep_map, 0, 1, _RET_IP_);
		return 1;
	}
	preempt_enable();
	return 0;
}

/*
 * If lockdep is enabled then we use the non-preemption spin-ops
 * even on CONFIG_PREEMPT, because lockdep assumes that interrupts are
 * not re-enabled during lock-acquire (which the preempt-spin-ops do):
 */
#if !defined(CONFIG_GENERIC_LOCKBREAK) || defined(CONFIG_DEBUG_LOCK_ALLOC)

static inline unsigned long __raw_spin_lock_irqsave(raw_spinlock_t *lock)
{
	unsigned long flags;

	local_irq_save(flags);
	preempt_disable();
	spin_acquire(&lock->dep_map, 0, 0, _RET_IP_);
	/*
	 * On lockdep we dont want the hand-coded irq-enable of
	 * do_raw_spin_lock_flags() code, because lockdep assumes
	 * that interrupts are not re-enabled during lock-acquire:
	 */
#ifdef CONFIG_LOCKDEP
	LOCK_CONTENDED(lock, do_raw_spin_trylock, do_raw_spin_lock);
#else
	do_raw_spin_lock_flags(lock, &flags);
#endif
	return flags;
}
/* 在驱动代码编写过程中常常会遇到这样一个问题，假设某个驱动程序中
 * 有一个链表a_driver_list，在驱动中很多操作都需要访问和更新该链表
 * 例如open、ioctl等，因此操作链表的地方就是一个临界区，需要spinlock来保护。
 * 当处于临界区时发生了外部硬件中断，此时系统暂停当前进程的执行而转去处理该中断。
 * 假设中断处理程序恰巧也要操作该链表，链表的操作是一个临界区，所以在操作之前
 * 要调用spin_lock函数来对该链表进行保护.
 * 中断处理函数试图去获取该spinlock，但因为它已经被别人持有了，于是导致中断处理函数
 * 进入忙等待状态或者WFE睡眠状态.在中断上下文出现忙等待或者睡眠等待是致命的
 * 中断处理程序要求“短”和“快”，锁的持有者因为被中断打断而不能尽快释放锁，而中断处理程序
 * 一直都在忙等待锁，从而导致死锁的发生。Linux内核的spinlock的变种spin_lock_irq函数在
 * 获取spinlock时关闭本地CPU中断，可以解决该问题
 */
static inline void __raw_spin_lock_irq(raw_spinlock_t *lock)
{
	local_irq_disable();
	preempt_disable();
	spin_acquire(&lock->dep_map, 0, 0, _RET_IP_);
	LOCK_CONTENDED(lock, do_raw_spin_trylock, do_raw_spin_lock);
}

static inline void __raw_spin_lock_bh(raw_spinlock_t *lock)
{
	__local_bh_disable_ip(_RET_IP_, SOFTIRQ_LOCK_OFFSET);
	spin_acquire(&lock->dep_map, 0, 0, _RET_IP_);
	LOCK_CONTENDED(lock, do_raw_spin_trylock, do_raw_spin_lock);
}

static inline void __raw_spin_lock(raw_spinlock_t *lock)
{
	/* 首先要关闭内核抢占，这是spinlock锁的实现关键点之一.
	 * 如果spinlock临界区内发生中断，中断返回时会去检查抢占调度，
	 * 这里有两个问题，一是抢占调度相当于持有锁的进程睡眠，违背了spinlock
	 * 锁不能睡眠和快速执行完成的设计语义；
	 * 二是抢占调度进程也有可能会去申请spinlock锁，那么会导致发生死锁
	 */
	preempt_disable();
	spin_acquire(&lock->dep_map, 0, 0, _RET_IP_);
	LOCK_CONTENDED(lock, do_raw_spin_trylock, do_raw_spin_lock);
}

#endif /* !CONFIG_GENERIC_LOCKBREAK || CONFIG_DEBUG_LOCK_ALLOC */

static inline void __raw_spin_unlock(raw_spinlock_t *lock)
{
	spin_release(&lock->dep_map, 1, _RET_IP_);
	do_raw_spin_unlock(lock);
	preempt_enable();
}

static inline void __raw_spin_unlock_irqrestore(raw_spinlock_t *lock,
					    unsigned long flags)
{
	spin_release(&lock->dep_map, 1, _RET_IP_);
	do_raw_spin_unlock(lock);
	local_irq_restore(flags);
	preempt_enable();
}

static inline void __raw_spin_unlock_irq(raw_spinlock_t *lock)
{
	spin_release(&lock->dep_map, 1, _RET_IP_);
	do_raw_spin_unlock(lock);
	local_irq_enable();
	preempt_enable();
}

static inline void __raw_spin_unlock_bh(raw_spinlock_t *lock)
{
	spin_release(&lock->dep_map, 1, _RET_IP_);
	do_raw_spin_unlock(lock);
	__local_bh_enable_ip(_RET_IP_, SOFTIRQ_LOCK_OFFSET);
}

static inline int __raw_spin_trylock_bh(raw_spinlock_t *lock)
{
	__local_bh_disable_ip(_RET_IP_, SOFTIRQ_LOCK_OFFSET);
	if (do_raw_spin_trylock(lock)) {
		spin_acquire(&lock->dep_map, 0, 1, _RET_IP_);
		return 1;
	}
	__local_bh_enable_ip(_RET_IP_, SOFTIRQ_LOCK_OFFSET);
	return 0;
}

#include <linux/rwlock_api_smp.h>

#endif /* __LINUX_SPINLOCK_API_SMP_H */
