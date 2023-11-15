/*
 * Copyright (C) 2012 ARM Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef __ASM_SPINLOCK_TYPES_H
#define __ASM_SPINLOCK_TYPES_H

#if !defined(__LINUX_SPINLOCK_TYPES_H) && !defined(__ASM_SPINLOCK_H)
# error "please don't include this file directly"
#endif

#include <linux/types.h>

#define TICKET_SHIFT	16
/* 在Linux 2.6.25之前，spinlock数据结构就是一个简单的无符号类型的变量，
 * 为1表示锁未被持有，值为0或者负数表示锁被持有.
 * 之前的spinlock机制实现比较简洁，特别是在没有锁争用的情况下，当时也存在
 * 很多问题，特别是在很多CPU争用同一个spinlock时，会导致严重的不公平性及
 * 性能下降。当释放锁时，事实上有可能刚刚释放该锁的CPU马上又获得了该锁的
 * 使用权，或者说在同一个NUMA节点上的CPU都有可能抢先获取了该锁，而没有考虑
 * 那些已经在锁外面等待了很久的CPU。因为刚刚释放锁的CPU的L1 cache中存储了该锁
 * 它比别的CPU更快获得锁，这对于那些已经等待很久的CPU是不公平的。
 * 在NUMA处理器中，锁争用的情况会严重影响系统的性能。有测试表明，在一个2 socket
 * 的8核处理器中，spinlock争用情况愈发明显，有些线程甚至需要尝试1000000次才能获得
 * 锁。为此在Linux 2.6.25内核后，spinlock实现了一套名为“FIFO ticked-based”算法的
 * spinlock机制，本文简称为排队自旋锁。
 * owner表示锁持有者的等号牌，next表示外面排队队列中末尾者的等号牌。这类似于排队吃饭的
 * 场景，在用餐高峰时段，各大饭店人满为患，顾客来晚了都需要排队。为了模型简化，假设某个
 * 饭店只有一张饭桌，刚开市时，next和owner都是0，第一个客户A来时，因为nexit和owner都是0，
 * 说明锁没有被人持有。此时因为饭店还没有顾客，所以客户A的等号牌是0，直接进餐，这是next++
 * 第二个客户B来时，因为next为1，owner为0，说明锁被人持有。这时服务员给他1号的等号牌，让
 * 他在饭店门口等待，next++
 * 第三个客户C来了，因为next为2，owner为0，服务员给他2号的等号牌，让他在饭店门口排队等待，
 * next++
 * 这时第一个客户A吃完买单了，owner++，owner的值变成1。服务员会让等号牌和owner值相等的客户就餐，
 * 客户B的等号牌为1，所以现在客户B就餐。有新客户来时next++,服务员分配等号牌，客户买单时owner++，
 * 服务员叫号，owner值和等号牌相等的客户就餐。
 */
typedef struct {
#ifdef __AARCH64EB__
	u16 next;
	u16 owner;
#else
	u16 owner;
	u16 next;
#endif
} __aligned(4) arch_spinlock_t;

#define __ARCH_SPIN_LOCK_UNLOCKED	{ 0 , 0 }

typedef struct {
	volatile unsigned int lock;
} arch_rwlock_t;

#define __ARCH_RW_LOCK_UNLOCKED		{ 0 }

#endif
