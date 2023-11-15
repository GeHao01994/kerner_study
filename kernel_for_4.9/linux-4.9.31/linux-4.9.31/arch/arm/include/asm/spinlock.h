#ifndef __ASM_SPINLOCK_H
#define __ASM_SPINLOCK_H

#if __LINUX_ARM_ARCH__ < 6
#error SMP not supported on pre-ARMv6 CPUs
#endif

#include <linux/prefetch.h>
#include <asm/barrier.h>
#include <asm/processor.h>

/*
 * sev and wfe are ARMv6K extensions.  Uniprocessor ARMv6 may not have the K
 * extensions, so when running on UP, we have to patch these instructions away.
 */
#ifdef CONFIG_THUMB2_KERNEL
/*
 * For Thumb-2, special care is needed to ensure that the conditional WFE
 * instruction really does assemble to exactly 4 bytes (as required by
 * the SMP_ON_UP fixup code).   By itself "wfene" might cause the
 * assembler to insert a extra (16-bit) IT instruction, depending on the
 * presence or absence of neighbouring conditional instructions.
 *
 * To avoid this unpredictableness, an approprite IT is inserted explicitly:
 * the assembler won't change IT instructions which are explicitly present
 * in the input.
 */
#define WFE(cond)	__ALT_SMP_ASM(		\
	"it " cond "\n\t"			\
	"wfe" cond ".n",			\
						\
	"nop.w"					\
)
#else
#define WFE(cond)	__ALT_SMP_ASM("wfe" cond, "nop")
#endif

#define SEV		__ALT_SMP_ASM(WASM(sev), WASM(nop))

static inline void dsb_sev(void)
{

	dsb(ishst);
	__asm__(SEV);
}

/*
 * ARMv6 ticket-based spin-locking.
 *
 * A memory barrier is required after we get a lock, and before we
 * release it, because V6 CPUs are assumed to have weakly ordered
 * memory.
 */

static inline void arch_spin_unlock_wait(arch_spinlock_t *lock)
{
	u16 owner = READ_ONCE(lock->tickets.owner);

	for (;;) {
		arch_spinlock_t tmp = READ_ONCE(*lock);

		if (tmp.tickets.owner == tmp.tickets.next ||
		    tmp.tickets.owner != owner)
			break;

		wfe();
	}
	smp_acquire__after_ctrl_dep();
}

#define arch_spin_lock_flags(lock, flags) arch_spin_lock(lock)

static inline void arch_spin_lock(arch_spinlock_t *lock)
{
	unsigned long tmp;
	u32 newval;
	arch_spinlock_t lockval;
	/* prefetchw 提前把原子变量的值加载到cache中，以便提高性能 */
	prefetchw(&lock->slock);
	/* ARM 使用ldrex 和 strex指令来保证add操作的原子性，指令后缀ex表示exclusive.
	 * ldrex Rt,[Rn] 把Rn寄存器指向的内存地址的内容加载到Rt寄存器中，监视器会把这个内存地址标记
	 * 为独占访问，保证其独占的方式来访问。
	 * strex Rd,Rt,[Rn] 把Rt寄存器的值保存到Rn寄存器指向的内存地址中，Rd保存更新的结果
	 * 0表示更新成功，1表示失败
	 * strex是有条件地存储内存，刚才ldrex标志的内存地址被独占的方式存储了
	 */
	/* asm它是一个关键字，它表面是一个GNU的扩展.你写的asm，编译器一看到这个关键字就知道
	 * 你是一个GNU的扩展
	 * 第二个volatile就是告诉编译器，后面这些汇编指令你就关闭优化.
	 ******
	 * 输出部：用于描述在指令部中可以被修改的C语言变量以及约束条件。
	 * 这里面大家不要被output给迷惑了，看名字还以为是输出的C语言变量呢，其实不是，
	 * 它这里的output意思是说这个C语言的变量，它能不能在指令部里面被修改。
	 * 如果它能被修改的话，我们就把它放到OutputOperands里面。
	 * 它如果是只读的，就把它放到输入部里面，输入部是只读的。
	 * 所以输出部是用于描述在指令部中可以被修改的C语言变量以及约束条件。
	 * 怎么去描述输出部呢，实际上它有一个比较特殊的约束条件的，
	 * 每个输出约束（constraint）通常以“=”号开头，接着的字母表示对操作数类型的说明，然后是关于变量结合的约束。
	 * 如 “=/+” + 约束修饰符 + 变量
	 * 输出部通常使用“=”或者“+”作为输出约束，
	 * 其中“=”表示被修饰的操作符只具有可写属性，
	 * “+”表示被修饰的操作数只具有可读可写属性，输出部可以是空的
	 * *****
	 * 输入部描述的参数是只有只读属性的，不要试图去修改输入部参数的内容，
	 * 因为GCC编译器假定，输入部的参数的内容在内嵌汇编之前和之后都是一致的。
	 * 在输入部中不能使用“=”或者“+”约束条件，否则编译器会报错。输入部可以是空的
	 *******
	 * 损坏部:“memory”告诉gcc编译器内联汇编指令改变了内存中的值，强迫编译器在执行该汇编代码前存储所有缓存的值,
	 * 在执行完汇编代码之后重新加载该值，目的是防止编译乱序.
	 * “cc”表示内嵌汇编代码修改了状态寄存器相关的标志位.
	 *******
	 * 指令部中的参数表示：在内嵌汇编代码中，使用%0对应输出部和输入部的第一个参数，使用%1表示第二个参数，依次类推
	 */
	__asm__ __volatile__(
	/* 把&lock->slock 地址的值读入到lockval中去 */
"1:	ldrex	%0, [%3]\n"
	/* 将lockval的值 + 1 << TICKET_SHIFT,也就是next+1 */
"	add	%1, %0, %4\n"
	/* 将新的lockval的值写到spinlock的slock里面去 */
"	strex	%2, %1, [%3]\n"
	/* 如果返回值为0，表示成功，可以退出来了，如果为1表示失败，那么跳到1接着弄 */
"	teq	%2, #0\n"
"	bne	1b"
	: "=&r" (lockval), "=&r" (newval), "=&r" (tmp)
	: "r" (&lock->slock), "I" (1 << TICKET_SHIFT)
	: "cc");
	/* 判断变量lockval中的next域和owner域是否相等，如果不相等，则调用wfe
	 * 指令让CPU进入等待状态。
	 * 当有CPU唤醒本CPU时，说明该spinlock锁的owner域发生了变化，即有人释放了锁
	 * 当新的owner域的值和next相等时，即onwer等于该CPU持有的等号牌(lockval.next)时
	 * 说明该CPU成功获取了spinlock锁，然后返回
	 */
	/* ARM体系结构中的WFI(Wait for interrupt)和WFE(Wait for event)指令都是让ARM核进入
	 * standby睡眠模式.WFI是直到有WFI唤醒事件发生才会唤醒CPU，WFE是直到有WFE唤醒事件发生，
	 * 这两类事件大部分相同，唯一不同在于WFE可以被其他CPU上的SEV指令唤醒，SEV指令用于修改EVENT寄存器的指令
	 */
	while (lockval.tickets.next != lockval.tickets.owner) {
		wfe();
		lockval.tickets.owner = ACCESS_ONCE(lock->tickets.owner);
	}

	smp_mb();
}

static inline int arch_spin_trylock(arch_spinlock_t *lock)
{
	unsigned long contended, res;
	u32 slock;

	prefetchw(&lock->slock);
	do {
		__asm__ __volatile__(
		"	ldrex	%0, [%3]\n"
		"	mov	%2, #0\n"
		"	subs	%1, %0, %0, ror #16\n"
		"	addeq	%0, %0, %4\n"
		"	strexeq	%2, %0, [%3]"
		: "=&r" (slock), "=&r" (contended), "=&r" (res)
		: "r" (&lock->slock), "I" (1 << TICKET_SHIFT)
		: "cc");
	} while (res);

	if (!contended) {
		smp_mb();
		return 1;
	} else {
		return 0;
	}
}

/* arch_spin_unlock函数实现比较简单，首先调用smp_mb内存屏蔽指令
 * 在ARM中smp_mb函数也是调用dmb指令来保证把调用该函数之前所有的
 * 访问内存指令都执行完成，然后给lock->owner域加1.
 * 最后调用dsb_sev函数，该函数有两个作用，一个是调用dsb指令保证
 * owner域已经写入内存中，二是执行SEV指令来唤醒通过WFE指令进入
 * 睡眠状态CPU
 */
static inline void arch_spin_unlock(arch_spinlock_t *lock)
{
	smp_mb();
	lock->tickets.owner++;
	dsb_sev();
}

static inline int arch_spin_value_unlocked(arch_spinlock_t lock)
{
	return lock.tickets.owner == lock.tickets.next;
}

static inline int arch_spin_is_locked(arch_spinlock_t *lock)
{
	return !arch_spin_value_unlocked(READ_ONCE(*lock));
}

static inline int arch_spin_is_contended(arch_spinlock_t *lock)
{
	struct __raw_tickets tickets = READ_ONCE(lock->tickets);
	return (tickets.next - tickets.owner) > 1;
}
#define arch_spin_is_contended	arch_spin_is_contended

/*
 * RWLOCKS
 *
 *
 * Write locks are easy - we just set bit 31.  When unlocking, we can
 * just write zero since the lock is exclusively held.
 */

static inline void arch_write_lock(arch_rwlock_t *rw)
{
	unsigned long tmp;

	prefetchw(&rw->lock);
	__asm__ __volatile__(
"1:	ldrex	%0, [%1]\n"
"	teq	%0, #0\n"
	WFE("ne")
"	strexeq	%0, %2, [%1]\n"
"	teq	%0, #0\n"
"	bne	1b"
	: "=&r" (tmp)
	: "r" (&rw->lock), "r" (0x80000000)
	: "cc");

	smp_mb();
}

static inline int arch_write_trylock(arch_rwlock_t *rw)
{
	unsigned long contended, res;

	prefetchw(&rw->lock);
	do {
		__asm__ __volatile__(
		"	ldrex	%0, [%2]\n"
		"	mov	%1, #0\n"
		"	teq	%0, #0\n"
		"	strexeq	%1, %3, [%2]"
		: "=&r" (contended), "=&r" (res)
		: "r" (&rw->lock), "r" (0x80000000)
		: "cc");
	} while (res);

	if (!contended) {
		smp_mb();
		return 1;
	} else {
		return 0;
	}
}

static inline void arch_write_unlock(arch_rwlock_t *rw)
{
	smp_mb();

	__asm__ __volatile__(
	"str	%1, [%0]\n"
	:
	: "r" (&rw->lock), "r" (0)
	: "cc");

	dsb_sev();
}

/* write_can_lock - would write_trylock() succeed? */
#define arch_write_can_lock(x)		(ACCESS_ONCE((x)->lock) == 0)

/*
 * Read locks are a bit more hairy:
 *  - Exclusively load the lock value.
 *  - Increment it.
 *  - Store new lock value if positive, and we still own this location.
 *    If the value is negative, we've already failed.
 *  - If we failed to store the value, we want a negative result.
 *  - If we failed, try again.
 * Unlocking is similarly hairy.  We may have multiple read locks
 * currently active.  However, we know we won't have any write
 * locks.
 */
static inline void arch_read_lock(arch_rwlock_t *rw)
{
	unsigned long tmp, tmp2;

	prefetchw(&rw->lock);
	__asm__ __volatile__(
"1:	ldrex	%0, [%2]\n"
"	adds	%0, %0, #1\n"
"	strexpl	%1, %0, [%2]\n"
	WFE("mi")
"	rsbpls	%0, %1, #0\n"
"	bmi	1b"
	: "=&r" (tmp), "=&r" (tmp2)
	: "r" (&rw->lock)
	: "cc");

	smp_mb();
}

static inline void arch_read_unlock(arch_rwlock_t *rw)
{
	unsigned long tmp, tmp2;

	smp_mb();

	prefetchw(&rw->lock);
	__asm__ __volatile__(
"1:	ldrex	%0, [%2]\n"
"	sub	%0, %0, #1\n"
"	strex	%1, %0, [%2]\n"
"	teq	%1, #0\n"
"	bne	1b"
	: "=&r" (tmp), "=&r" (tmp2)
	: "r" (&rw->lock)
	: "cc");

	if (tmp == 0)
		dsb_sev();
}

static inline int arch_read_trylock(arch_rwlock_t *rw)
{
	unsigned long contended, res;

	prefetchw(&rw->lock);
	do {
		__asm__ __volatile__(
		"	ldrex	%0, [%2]\n"
		"	mov	%1, #0\n"
		"	adds	%0, %0, #1\n"
		"	strexpl	%1, %0, [%2]"
		: "=&r" (contended), "=&r" (res)
		: "r" (&rw->lock)
		: "cc");
	} while (res);

	/* If the lock is negative, then it is already held for write. */
	if (contended < 0x80000000) {
		smp_mb();
		return 1;
	} else {
		return 0;
	}
}

/* read_can_lock - would read_trylock() succeed? */
#define arch_read_can_lock(x)		(ACCESS_ONCE((x)->lock) < 0x80000000)

#define arch_read_lock_flags(lock, flags) arch_read_lock(lock)
#define arch_write_lock_flags(lock, flags) arch_write_lock(lock)

#define arch_spin_relax(lock)	cpu_relax()
#define arch_read_relax(lock)	cpu_relax()
#define arch_write_relax(lock)	cpu_relax()

#endif /* __ASM_SPINLOCK_H */
