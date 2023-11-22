#ifndef _ASM_GENERIC_RWSEM_H
#define _ASM_GENERIC_RWSEM_H

#ifndef _LINUX_RWSEM_H
#error "Please don't include <asm/rwsem.h> directly, use <linux/rwsem.h> instead."
#endif

#ifdef __KERNEL__

/*
 * R/W semaphores originally for PPC using the stuff in lib/rwsem.c.
 * Adapted largely from include/asm-i386/rwsem.h
 * by Paul Mackerras <paulus@samba.org>.
 */

/*
 * the semaphore definition
 */
/* 这里的宏定义看起来比较复杂，翻译成十进制数值会清晰一些
 * count的值和activety值一样，表示读者和写者的关系
 * count初始化为0，表示没有读者也没有写者
 * count为正数，表示有count个读者
 * 当有写者申请锁时，count值要加上RWSEM_ACTIVE_WRITE_BIAS
 * 当有多个写者申请锁时，判断count值是否等于RWSEM_ACTIVE_WRITE_BIAS，不等于说明已经有写者抢先持有锁了，要么自旋等待或者睡眠等待
 * 当有读者申请锁时，count值加上RWSEM_ACTIVE_READ_BIAS 后还小于0，说明已经有一个写者已经成功申请锁，那么只能睡眠等待写者释放锁
 * 把count 值当做十六进制来看待不是代码作者的原本设计意图，其实应该把count值分为两个域，
 * bit[0~15]为低字段，表示正在持有锁的读者或者写者的个数；
 * bit[16~31]为高字段，通常为负数，表示有一个正在持有锁或者pending状态的写者，以及睡眠等待队列中有人在睡眠等待.
 * 因此count值可以看做是一个二元数，例如
 * RWSEM_ACTIVE_READ_BIAS = 0x0000_0001=[0,1] 表示有一个读者
 * RWSEM_ACTIVE_WRITE_BIAS = 0xffff0001=[-1,1] 表示当前只有一个活跃的写者
 * RWSEM_WAITING_BIAS = 0xffff0000=[-1,0] 表示睡眠等待队列中有人在睡眠等待
 */
#ifdef CONFIG_64BIT
# define RWSEM_ACTIVE_MASK		0xffffffffL
#else
# define RWSEM_ACTIVE_MASK		0x0000ffffL
#endif

#define RWSEM_UNLOCKED_VALUE		0x00000000L
#define RWSEM_ACTIVE_BIAS		0x00000001L
/* 负数的表示法是用补码的形势，也就是取反+1的操作
 * 所以在32位系统里面这里就是0xffff0000+1 -1 = 0xffff0000
 */
#define RWSEM_WAITING_BIAS		(-RWSEM_ACTIVE_MASK-1)
#define RWSEM_ACTIVE_READ_BIAS		RWSEM_ACTIVE_BIAS
/* RWSEM_ACTIVE_WRITE_BIAS = 0xffff0000 + 1 = 0xffff0001 */
#define RWSEM_ACTIVE_WRITE_BIAS		(RWSEM_WAITING_BIAS + RWSEM_ACTIVE_BIAS)

/*
 * lock for reading
 */
static inline void __down_read(struct rw_semaphore *sem)
{
	/* 一个写者成功拥有了锁，那么count值被加上RWSEM_ACTIVE_WRITE_BIAS即在32位上就是0xffff0001
	 * 首先sem->count+1后结果大于0，则成功获得这个读者锁，否则说明在这之前已经有一个写者锁持有了
	 * 该锁 */
	if (unlikely(atomic_long_inc_return_acquire((atomic_long_t *)&sem->count) <= 0))
		rwsem_down_read_failed(sem);
}

static inline int __down_read_trylock(struct rw_semaphore *sem)
{
	long tmp;

	while ((tmp = atomic_long_read(&sem->count)) >= 0) {
		if (tmp == atomic_long_cmpxchg_acquire(&sem->count, tmp,
				   tmp + RWSEM_ACTIVE_READ_BIAS)) {
			return 1;
		}
	}
	return 0;
}

/*
 * lock for writing
 */
static inline void __down_write(struct rw_semaphore *sem)
{
	long tmp;
	/* sem->count 要加上RWSEM_ACTIVE_WRITE_BIAS  0xffff0001
	 */
	tmp = atomic_long_add_return_acquire(RWSEM_ACTIVE_WRITE_BIAS,
				     (atomic_long_t *)&sem->count);
	if (unlikely(tmp != RWSEM_ACTIVE_WRITE_BIAS))
		rwsem_down_write_failed(sem);
}

static inline int __down_write_killable(struct rw_semaphore *sem)
{
	long tmp;

	tmp = atomic_long_add_return_acquire(RWSEM_ACTIVE_WRITE_BIAS,
				     (atomic_long_t *)&sem->count);
	if (unlikely(tmp != RWSEM_ACTIVE_WRITE_BIAS))
		if (IS_ERR(rwsem_down_write_failed_killable(sem)))
			return -EINTR;
	return 0;
}

static inline int __down_write_trylock(struct rw_semaphore *sem)
{
	long tmp;

	tmp = atomic_long_cmpxchg_acquire(&sem->count, RWSEM_UNLOCKED_VALUE,
		      RWSEM_ACTIVE_WRITE_BIAS);
	return tmp == RWSEM_UNLOCKED_VALUE;
}

/*
 * unlock after reading
 */
static inline void __up_read(struct rw_semaphore *sem)
{
	long tmp;
	/* 获取读者锁时count加1，释放自然是-1，他们是成对出现的
	 * 如果整个过程没有写者来干扰，那么所有读者锁释放完毕后count值应该
	 * 是0.count变成负数，说明这期间有写者出现，并且“悄悄地”处于等待队列
	 * 中，那么就唤醒它
	 */
	tmp = atomic_long_dec_return_release((atomic_long_t *)&sem->count);
	if (unlikely(tmp < -1 && (tmp & RWSEM_ACTIVE_MASK) == 0))
		rwsem_wake(sem);
}

/*
 * unlock after writing
 */
static inline void __up_write(struct rw_semaphore *sem)
{
	/* 释放锁需要count减去RWSEM_ACTIVE_WRITE_BIAS，如果sem->count仍然小于0，
	 * 说明等待队列里面有人在睡眠等待
	 */
	if (unlikely(atomic_long_sub_return_release(RWSEM_ACTIVE_WRITE_BIAS,
				 (atomic_long_t *)&sem->count) < 0))
		rwsem_wake(sem);
}

/*
 * downgrade write lock to read lock
 */
static inline void __downgrade_write(struct rw_semaphore *sem)
{
	long tmp;

	/*
	 * When downgrading from exclusive to shared ownership,
	 * anything inside the write-locked region cannot leak
	 * into the read side. In contrast, anything in the
	 * read-locked region is ok to be re-ordered into the
	 * write side. As such, rely on RELEASE semantics.
	 */
	tmp = atomic_long_add_return_release(-RWSEM_WAITING_BIAS,
				     (atomic_long_t *)&sem->count);
	if (tmp < 0)
		rwsem_downgrade_wake(sem);
}

#endif	/* __KERNEL__ */
#endif	/* _ASM_GENERIC_RWSEM_H */
