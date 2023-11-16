/*
 * Copyright (c) 2008 Intel Corporation
 * Author: Matthew Wilcox <willy@linux.intel.com>
 *
 * Distributed under the terms of the GNU GPL, version 2
 *
 * Please see kernel/semaphore.c for documentation of these functions
 */
#ifndef __LINUX_SEMAPHORE_H
#define __LINUX_SEMAPHORE_H

#include <linux/list.h>
#include <linux/spinlock.h>

/* Please don't access any members of this structure directly */
/* 信号量（semaphore)是操作系统中最常用的同步原语之一。
 * spinlock是实现一种忙等待的锁，而信号量则允许进程进入睡眠状态。
 * 简单来说，信号量是一个计数器，它支持两个操作原语，即P和V操作。
 * P和V是指荷兰语中的两个单词，分别表示减少和增加，后来美国人把
 * 它改成down和up，现在Linux内核里也叫这两个名字。
 * 信号量中最经典的例子莫过于生产者和消费者问题，它是一个操作系统
 * 发展历史上最经典的进程同步问题。假设生产者生产商品，消费者
 * 购买商品，通常消费者需要到实体商店或者网上商城购买。计算机来模拟这个场景，
 * 一个线程代表生产者，另外一个线程代表消费者，内存buffer代表商店。生产者生产的商品
 * 被放置到buffer中供消费者消费，消费者线程从buffer中获取物品，然后释放buffer.
 * 当生产者线程生产商品时发现没有空闲buffer可用，那么生产者必须等待消费者释放出一个空闲buffer.
 * 当消费者线程购买商品时发现商店没货了，那么消费者必须等待，直到新的商品生产出来。
 * 如果是spinlock,当消费者发现商品没货，那么搬个凳子坐在商店门口一直等送货员送货过来；
 * 如果是信号量，商店服务员会记录消费者的电话，等到货了通知消费者来购买。
 */
struct semaphore {
	/* lock是spinlock变量,用于对信号量数据结构里的count和wait_list成员保护 */
	raw_spinlock_t		lock;
	/* count用于表示允许进入临界区的内核执行路径个数 */
	unsigned int		count;
	/* 链表用于管理所有在该信号量上睡眠的进程，没有成功获取锁的进程会睡眠在这个链表上 */
	struct list_head	wait_list;
};

#define __SEMAPHORE_INITIALIZER(name, n)				\
{									\
	.lock		= __RAW_SPIN_LOCK_UNLOCKED((name).lock),	\
	.count		= n,						\
	.wait_list	= LIST_HEAD_INIT((name).wait_list),		\
}

#define DEFINE_SEMAPHORE(name)	\
	struct semaphore name = __SEMAPHORE_INITIALIZER(name, 1)

/* 通常通过sema_init函数进行信号的初始化，其中__SEMAPHORE_INITIALIZER宏
 * 会完成对信号量数据结构的填充，val值通常为1
 */
static inline void sema_init(struct semaphore *sem, int val)
{
	static struct lock_class_key __key;
	*sem = (struct semaphore) __SEMAPHORE_INITIALIZER(*sem, val);
	lockdep_init_map(&sem->lock.dep_map, "semaphore->lock", &__key, 0);
}

/* down函数有如下一些变种。其中down和down_interruptible的区别在于，down_interruptible在争用
 * 信号量失败时进入可中断的睡眠的状态，而down进入不可中断的睡眠状态。
 * down_trylock函数返回0表示成功获取了锁，返回1表示获取锁失败
 */
extern void down(struct semaphore *sem);
extern int __must_check down_interruptible(struct semaphore *sem);
extern int __must_check down_killable(struct semaphore *sem);
extern int __must_check down_trylock(struct semaphore *sem);
extern int __must_check down_timeout(struct semaphore *sem, long jiffies);
extern void up(struct semaphore *sem);

#endif /* __LINUX_SEMAPHORE_H */
