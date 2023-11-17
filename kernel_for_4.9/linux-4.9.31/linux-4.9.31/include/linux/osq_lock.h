#ifndef __LINUX_OSQ_LOCK_H
#define __LINUX_OSQ_LOCK_H

/*
 * An MCS like lock especially tailored for optimistic spinning for sleeping
 * lock implementations (mutex, rwsem, etc).
 */
/* MCS锁是一种自旋锁的优化方案
 * 自旋锁是linux内核使用最广泛的一种锁机制，长期依赖内核社区一直再关注
 * 自旋锁的高效性和可扩展性。
 * 在Linux 2.6.25内核中自旋锁已经采用排队自旋算法进行优化，以解决早期自旋锁
 * 争用不公平的问题。
 * 但是在多处理器和NUMA系统中，排队自旋锁依然存在一个比较严重的问题。
 * 假设在一个锁争用激烈的系统中，所有的自旋等待锁的线程都在同一个共享
 * 变量上自旋，申请和释放锁都在同一个变量上修改，由cache一致性原理
 * （例如MESI协议）导致参与自旋的CPU中的cacheline变得无效。
 * 在锁争用激烈过程中，导致严重的CPU高速缓存行颠簸现象，即多个CPU上的
 * cacheline反复失效，大大降低系统的整体性能。
 *
 * MCS算法可以解决自旋锁遇到的问题，显著减少CPU cacheline bouncing问题
 * MCS算法的核心思想是每个锁的申请者只在本地CPU的变量上自旋，而不是全局变量.
 * 虽然MCS算法设计是针对自旋锁的，但是目前Linux 4.0内核依然没有把MCS算法用在
 * 自旋锁上，其中一个很重要的原因是MCS算法的实现需要比较大的数据结构，而spin * lock常嵌入到系统中的一些比较关键的数据结构中，例如物理页面数据结构struct page，这类数据结构对大小相当敏感
 * 因此目前MCS算法只用在读写信号量和mutex的自旋等待机制中，后来MCS锁优化成了现在的osq_lock
 */

/* struct optimistic_spin_node数据结构表示本地CPU上的节点，它可以组织成一个双向链表，
 * 包含next和prev指针，lock成员用于表示加锁状态，cpu成员用于重新编码CPU编号，
 * 表示该node是在哪个CPU上。struct optimistic_spin_node数据结构会定义成per-cpu变量，即每个CPU有一个node结构
 */
struct optimistic_spin_node {
	struct optimistic_spin_node *next, *prev;
	int locked; /* 1 if lock acquired */
	int cpu; /* encoded CPU # + 1 value */
};
/* 每个MCS锁有一个optimistic_spin_queue数据结构，该数据结构只有一个成员tail,
 * 初始化为0.
 */
struct optimistic_spin_queue {
	/*
	 * Stores an encoded value of the CPU # of the tail node in the queue.
	 * If the queue is empty, then it's set to OSQ_UNLOCKED_VAL.
	 */
	atomic_t tail;
};

#define OSQ_UNLOCKED_VAL (0)

/* Init macro and function. */
#define OSQ_LOCK_UNLOCKED { ATOMIC_INIT(OSQ_UNLOCKED_VAL) }

static inline void osq_lock_init(struct optimistic_spin_queue *lock)
{
	/* 将lock->tail设置为0
	 * If the queue is empty, then it's set to OSQ_UNLOCKED_VAL.
	 */
	atomic_set(&lock->tail, OSQ_UNLOCKED_VAL);
}

extern bool osq_lock(struct optimistic_spin_queue *lock);
extern void osq_unlock(struct optimistic_spin_queue *lock);

static inline bool osq_is_locked(struct optimistic_spin_queue *lock)
{
	return atomic_read(&lock->tail) != OSQ_UNLOCKED_VAL;
}

#endif
