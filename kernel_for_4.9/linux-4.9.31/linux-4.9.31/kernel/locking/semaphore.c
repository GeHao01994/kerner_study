/*
 * Copyright (c) 2008 Intel Corporation
 * Author: Matthew Wilcox <willy@linux.intel.com>
 *
 * Distributed under the terms of the GNU GPL, version 2
 *
 * This file implements counting semaphores.
 * A counting semaphore may be acquired 'n' times before sleeping.
 * See mutex.c for single-acquisition sleeping locks which enforce
 * rules which allow code to be debugged more easily.
 */

/*
 * Some notes on the implementation:
 *
 * The spinlock controls access to the other members of the semaphore.
 * down_trylock() and up() can be called from interrupt context, so we
 * have to disable interrupts when taking the lock.  It turns out various
 * parts of the kernel expect to be able to use down() on a semaphore in
 * interrupt context when they know it will succeed, so we have to use
 * irqsave variants for down(), down_interruptible() and down_killable()
 * too.
 *
 * The ->count variable represents how many more tasks can acquire this
 * semaphore.  If it's zero, there may be tasks waiting on the wait_list.
 */

#include <linux/compiler.h>
#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/sched.h>
#include <linux/semaphore.h>
#include <linux/spinlock.h>
#include <linux/ftrace.h>

static noinline void __down(struct semaphore *sem);
static noinline int __down_interruptible(struct semaphore *sem);
static noinline int __down_killable(struct semaphore *sem);
static noinline int __down_timeout(struct semaphore *sem, long timeout);
static noinline void __up(struct semaphore *sem);

/**
 * down - acquire the semaphore
 * @sem: the semaphore to be acquired
 *
 * Acquires the semaphore.  If no more tasks are allowed to acquire the
 * semaphore, calling this function will put the task to sleep until the
 * semaphore is released.
 *
 * Use of this function is deprecated, please use down_interruptible() or
 * down_killable() instead.
 */
void down(struct semaphore *sem)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&sem->lock, flags);
	if (likely(sem->count > 0))
		sem->count--;
	else
		__down(sem);
	raw_spin_unlock_irqrestore(&sem->lock, flags);
}
EXPORT_SYMBOL(down);

/**
 * down_interruptible - acquire the semaphore unless interrupted
 * @sem: the semaphore to be acquired
 *
 * Attempts to acquire the semaphore.  If no more tasks are allowed to
 * acquire the semaphore, calling this function will put the task to sleep.
 * If the sleep is interrupted by a signal, this function will return -EINTR.
 * If the semaphore is successfully acquired, this function returns 0.
 */
int down_interruptible(struct semaphore *sem)
{
	unsigned long flags;
	int result = 0;
	/* 这是一个临界区，注意后面的操作会临时打开spinlock，涉及到对信号量中最重要的
	 * count计数的操作，需要spinlock锁来保护，并且在某些中断处理函数里
	 * 也可能会操作该信号量，所以需要关闭本地CPU中断，因此这里采用raw_spin_lock_irqsave()函数
	 */
	raw_spin_lock_irqsave(&sem->lock, flags);
	/* 但成功进入该临界区之后，首先判断sem->count是否大于0，如果大于0，则表明
	 * 当前进程可以成功获取信号量，并将sem->count值减一，然后退出。
	 * 如果sem->count小于等于0，表明当前进程无法获得该信号量，则调用__down_interruptible函数来执行睡眠等待操作。
	 */
	if (likely(sem->count > 0))
		sem->count--;
	else
		result = __down_interruptible(sem);
	raw_spin_unlock_irqrestore(&sem->lock, flags);

	return result;
}
EXPORT_SYMBOL(down_interruptible);

/**
 * down_killable - acquire the semaphore unless killed
 * @sem: the semaphore to be acquired
 *
 * Attempts to acquire the semaphore.  If no more tasks are allowed to
 * acquire the semaphore, calling this function will put the task to sleep.
 * If the sleep is interrupted by a fatal signal, this function will return
 * -EINTR.  If the semaphore is successfully acquired, this function returns
 * 0.
 */
int down_killable(struct semaphore *sem)
{
	unsigned long flags;
	int result = 0;

	raw_spin_lock_irqsave(&sem->lock, flags);
	if (likely(sem->count > 0))
		sem->count--;
	else
		result = __down_killable(sem);
	raw_spin_unlock_irqrestore(&sem->lock, flags);

	return result;
}
EXPORT_SYMBOL(down_killable);

/**
 * down_trylock - try to acquire the semaphore, without waiting
 * @sem: the semaphore to be acquired
 *
 * Try to acquire the semaphore atomically.  Returns 0 if the semaphore has
 * been acquired successfully or 1 if it it cannot be acquired.
 *
 * NOTE: This return value is inverted from both spin_trylock and
 * mutex_trylock!  Be careful about this when converting code.
 *
 * Unlike mutex_trylock, this function can be used from interrupt context,
 * and the semaphore can be released by any task or interrupt.
 */
int down_trylock(struct semaphore *sem)
{
	unsigned long flags;
	int count;

	raw_spin_lock_irqsave(&sem->lock, flags);
	count = sem->count - 1;
	if (likely(count >= 0))
		sem->count = count;
	raw_spin_unlock_irqrestore(&sem->lock, flags);

	return (count < 0);
}
EXPORT_SYMBOL(down_trylock);

/**
 * down_timeout - acquire the semaphore within a specified time
 * @sem: the semaphore to be acquired
 * @timeout: how long to wait before failing
 *
 * Attempts to acquire the semaphore.  If no more tasks are allowed to
 * acquire the semaphore, calling this function will put the task to sleep.
 * If the semaphore is not released within the specified number of jiffies,
 * this function returns -ETIME.  It returns 0 if the semaphore was acquired.
 */
int down_timeout(struct semaphore *sem, long timeout)
{
	unsigned long flags;
	int result = 0;

	raw_spin_lock_irqsave(&sem->lock, flags);
	if (likely(sem->count > 0))
		sem->count--;
	else
		result = __down_timeout(sem, timeout);
	raw_spin_unlock_irqrestore(&sem->lock, flags);

	return result;
}
EXPORT_SYMBOL(down_timeout);

/**
 * up - release the semaphore
 * @sem: the semaphore to release
 *
 * Release the semaphore.  Unlike mutexes, up() may be called from any
 * context and even by tasks which have never called down().
 */
void up(struct semaphore *sem)
{
	unsigned long flags;
	/* 如果信号量上的等待队列sem->wait_list为空，则说明没有进程在等待该信号量，
	 * 那么直接把sem->count加1即可。
	 * 如果有进程在等待队列里面睡眠，需要调用_up函数唤醒他们
	 */
	raw_spin_lock_irqsave(&sem->lock, flags);
	if (likely(list_empty(&sem->wait_list)))
		sem->count++;
	else
		__up(sem);
	raw_spin_unlock_irqrestore(&sem->lock, flags);
}
EXPORT_SYMBOL(up);

/* Functions for the contended case */

struct semaphore_waiter {
	struct list_head list;
	struct task_struct *task;
	bool up;
};

/*
 * Because this function is inlined, the 'state' parameter will be
 * constant, and thus optimised away by the compiler.  Likewise the
 * 'timeout' parameter for the cases without timeouts.
 */
static inline int __sched __down_common(struct semaphore *sem, long state,
								long timeout)
{
	struct task_struct *task = current;
	/* struct semaphore_waiter 数据结构用于描述获取信号量失败的进程，每个进程会有一个struct semaphore_waiter数据结构，
	 * 并把当前进程放到信号量sem的成员变量wait_list链表中。
	struct semaphore_waiter waiter;

	list_add_tail(&waiter.list, &sem->wait_list);
	waiter.task = task;
	waiter.up = false;
	/* 接下来的for循环将当前进程task_struct状态设置成TASK_INTERRUPTIBLE，然后调用schedule_timeout主动让出CPU，相当于当前进程睡眠
	 */
	for (;;) {
		if (signal_pending_state(state, task))
			goto interrupted;
		if (unlikely(timeout <= 0))
			goto timed_out;
		__set_task_state(task, state);
		raw_spin_unlock_irq(&sem->lock);
		/* 注意schedule_timeout的参数是MAX_SCHEDULE_TIMEOUT，它并没有实际等待MAX_SCHEDULE_TIMEOUT的时间。
		 * 当进程在再次被调度回来执行时，schedule_timeout返回并判断
		 * 在此被调度原因，例如waiter.up为true时，说明睡眠在wait_list队列中的进程被该信号量的UP操作唤醒,
		 * 进程可以获取该信号量。
		 * 如果进程是被其他人发送信号（signal）或者超时等原因引发的唤醒，则跳转到timed_out或interrupted标签处，并返回错误码
		 */
		timeout = schedule_timeout(timeout);
		raw_spin_lock_irq(&sem->lock);
		if (waiter.up)
			return 0;
	}

 timed_out:
	list_del(&waiter.list);
	return -ETIME;

 interrupted:
	list_del(&waiter.list);
	return -EINTR;
}

static noinline void __sched __down(struct semaphore *sem)
{
	__down_common(sem, TASK_UNINTERRUPTIBLE, MAX_SCHEDULE_TIMEOUT);
}
/* __down_interruptible函数内部调用__down_common函数来实现，state参数为
 * TASK_INTERRUPTIBLE,timeout参数MAX_SCHEDULE_TIMEOUT是个很大的值LONG_MAX
 */
static noinline int __sched __down_interruptible(struct semaphore *sem)
{
	return __down_common(sem, TASK_INTERRUPTIBLE, MAX_SCHEDULE_TIMEOUT);
}

static noinline int __sched __down_killable(struct semaphore *sem)
{
	return __down_common(sem, TASK_KILLABLE, MAX_SCHEDULE_TIMEOUT);
}

static noinline int __sched __down_timeout(struct semaphore *sem, long timeout)
{
	return __down_common(sem, TASK_UNINTERRUPTIBLE, timeout);
}

static noinline void __sched __up(struct semaphore *sem)
{
	/* sem—>wait_list等待队列中第一个成员waiter，这个等待队列是先进先出队列
	 * 在down操作时通过list_add_tail函数添加到等待队列尾部。
	 * waiter—>up设置为true，然后调用wake_up_process函数唤醒waiter->task
	 * 进程。在down函数中，waiter->task进程醒来后会判断waiter->up变量是否为true，如果为true，则直接返回0
	 * 表示该进程成功获取了信号量
	 */
	struct semaphore_waiter *waiter = list_first_entry(&sem->wait_list,
						struct semaphore_waiter, list);
	list_del(&waiter->list);
	waiter->up = true;
	wake_up_process(waiter->task);
}
