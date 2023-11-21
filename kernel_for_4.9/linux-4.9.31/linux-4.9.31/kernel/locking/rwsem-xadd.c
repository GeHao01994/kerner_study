/* rwsem.c: R/W semaphores: contention handling functions
 *
 * Written by David Howells (dhowells@redhat.com).
 * Derived from arch/i386/kernel/semaphore.c
 *
 * Writer lock-stealing by Alex Shi <alex.shi@intel.com>
 * and Michel Lespinasse <walken@google.com>
 *
 * Optimistic spinning by Tim Chen <tim.c.chen@intel.com>
 * and Davidlohr Bueso <davidlohr@hp.com>. Based on mutexes.
 */
#include <linux/rwsem.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/export.h>
#include <linux/sched/rt.h>
#include <linux/osq_lock.h>

#include "rwsem.h"

/*
 * Guide to the rw_semaphore's count field for common values.
 * (32-bit case illustrated, similar for 64-bit)
 *
 * 0x0000000X	(1) X readers active or attempting lock, no writer waiting
 *		    X = #active_readers + #readers attempting to lock
 *		    (X*ACTIVE_BIAS)
 *
 * 0x00000000	rwsem is unlocked, and no one is waiting for the lock or
 *		attempting to read lock or write lock.
 *
 * 0xffff000X	(1) X readers active or attempting lock, with waiters for lock
 *		    X = #active readers + # readers attempting lock
 *		    (X*ACTIVE_BIAS + WAITING_BIAS)
 *		(2) 1 writer attempting lock, no waiters for lock
 *		    X-1 = #active readers + #readers attempting lock
 *		    ((X-1)*ACTIVE_BIAS + ACTIVE_WRITE_BIAS)
 *		(3) 1 writer active, no waiters for lock
 *		    X-1 = #active readers + #readers attempting lock
 *		    ((X-1)*ACTIVE_BIAS + ACTIVE_WRITE_BIAS)
 *
 * 0xffff0001	(1) 1 reader active or attempting lock, waiters for lock
 *		    (WAITING_BIAS + ACTIVE_BIAS)
 *		(2) 1 writer active or attempting lock, no waiters for lock
 *		    (ACTIVE_WRITE_BIAS)
 *
 * 0xffff0000	(1) There are writers or readers queued but none active
 *		    or in the process of attempting lock.
 *		    (WAITING_BIAS)
 *		Note: writer can attempt to steal lock for this count by adding
 *		ACTIVE_WRITE_BIAS in cmpxchg and checking the old count
 *
 * 0xfffe0001	(1) 1 writer active, or attempting lock. Waiters on queue.
 *		    (ACTIVE_WRITE_BIAS + WAITING_BIAS)
 *
 * Note: Readers attempt to lock by adding ACTIVE_BIAS in down_read and checking
 *	 the count becomes more than 0 for successful lock acquisition,
 *	 i.e. the case where there are only readers or nobody has lock.
 *	 (1st and 2nd case above).
 *
 *	 Writers attempt to lock by adding ACTIVE_WRITE_BIAS in down_write and
 *	 checking the count becomes ACTIVE_WRITE_BIAS for successful lock
 *	 acquisition (i.e. nobody else has lock or attempts lock).  If
 *	 unsuccessful, in rwsem_down_write_failed, we'll check to see if there
 *	 are only waiters but none active (5th case above), and attempt to
 *	 steal the lock.
 *
 */

/*
 * Initialize an rwsem:
 */
void __init_rwsem(struct rw_semaphore *sem, const char *name,
		  struct lock_class_key *key)
{
#ifdef CONFIG_DEBUG_LOCK_ALLOC
	/*
	 * Make sure we are not reinitializing a held semaphore:
	 */
	debug_check_no_locks_freed((void *)sem, sizeof(*sem));
	lockdep_init_map(&sem->dep_map, name, key, 0);
#endif
	atomic_long_set(&sem->count, RWSEM_UNLOCKED_VALUE);
	raw_spin_lock_init(&sem->wait_lock);
	INIT_LIST_HEAD(&sem->wait_list);
#ifdef CONFIG_RWSEM_SPIN_ON_OWNER
	sem->owner = NULL;
	osq_lock_init(&sem->osq);
#endif
}

EXPORT_SYMBOL(__init_rwsem);

enum rwsem_waiter_type {
	RWSEM_WAITING_FOR_WRITE,
	RWSEM_WAITING_FOR_READ
};

struct rwsem_waiter {
	struct list_head list;
	struct task_struct *task;
	enum rwsem_waiter_type type;
};

enum rwsem_wake_type {
	/* 唤醒等待队列头部的waiter(一个writer或者若干个reader) */
	RWSEM_WAKE_ANY,		/* Wake whatever's at head of wait list */
	/* 唤醒等待队列头部的若干reader */
	RWSEM_WAKE_READERS,	/* Wake readers only */
	/* 同RWSEM_WAKE_READERS,只不过唤醒者已经持有了读写锁 */
	RWSEM_WAKE_READ_OWNED	/* Waker thread holds the read lock */
};

/*
 * handle the lock release when processes blocked on it that can now run
 * - if we come here from up_xxxx(), then:
 *   - the 'active part' of count (&0x0000ffff) reached 0 (but may have changed)
 *   - the 'waiting part' of count (&0xffff0000) is -ve (and will still be so)
 * - there must be someone on the queue
 * - the wait_lock must be held by the caller
 * - tasks are marked for wakeup, the caller must later invoke wake_up_q()
 *   to actually wakeup the blocked task(s) and drop the reference count,
 *   preferably when the wait_lock is released
 * - woken process blocks are discarded from the list after having task zeroed
 * - writers are only marked woken if downgrading is false
 */
static void __rwsem_mark_wake(struct rw_semaphore *sem,
			      enum rwsem_wake_type wake_type,
			      struct wake_q_head *wake_q)
{
	struct rwsem_waiter *waiter, *tmp;
	long oldcount, woken = 0, adjustment = 0;

	/*
	 * Take a peek at the queue head waiter such that we can determine
	 * the wakeup(s) to perform.
	 */
	/* 首先从sem->wait_list等待队列中取出第一个排队的waiter,等待队列是先进先出队列 */
	waiter = list_first_entry(&sem->wait_list, struct rwsem_waiter, list);
	/* 如果第一个排队者是写者，那么直接唤醒它即可，因为只能一个写者独占临界区，具有排他性 */
	if (waiter->type == RWSEM_WAITING_FOR_WRITE) {
		if (wake_type == RWSEM_WAKE_ANY) {
			/*
			 * Mark writer at the front of the queue for wakeup.
			 * Until the task is actually later awoken later by
			 * the caller, other writers are able to steal it.
			 * Readers, on the other hand, will block as they
			 * will notice the queued writer.
			 */
			wake_q_add(wake_q, waiter->task);
		}

		return;
	}

	/*
	 * Writers might steal the lock before we grant it to the next reader.
	 * We prefer to do the first reader grant before counting readers
	 * so we can bail out early if a writer stole the lock.
	 */
	/* 当前进程申请读者锁失败才进入了rwsem_down_read_failed中来，恰好有一个写锁释放了锁。
	 * 这里有一个关键点，如果有另外一个写者又来申请锁，那么会比较麻烦，代码把这个写者称为“小偷”.
	 */
	if (wake_type != RWSEM_WAKE_READ_OWNED) {
		adjustment = RWSEM_ACTIVE_READ_BIAS;
 try_reader_grant:
		/* 这里想先下手为强，人为的假装先申请一个读者锁，oldcount反应的是真实的值 */
		oldcount = atomic_long_fetch_add(adjustment, &sem->count);
		/* 如果sem->count值小于RWSEM_WAITING_BIAS，说明这个锁被小偷偷走了 */
		if (unlikely(oldcount < RWSEM_WAITING_BIAS)) {
			/*
			 * If the count is still less than RWSEM_WAITING_BIAS
			 * after removing the adjustment, it is assumed that
			 * a writer has stolen the lock. We have to undo our
			 * reader grant.
			 */
			/* 既然已经被小偷偷走了，那么只能无法继续唤醒睡眠在等待队列的读者了
			 * 这里就是sem->count -1,因为上面+1了，所以这里减去1
			 */
			if (atomic_long_add_return(-adjustment, &sem->count) <
			    RWSEM_WAITING_BIAS)
				return;

			/* Last active locker left. Retry waking readers. */
			goto try_reader_grant;
		}
		/*
		 * It is not really necessary to set it to reader-owned here,
		 * but it gives the spinners an early indication that the
		 * readers now have the lock.
		 */
		rwsem_set_reader_owned(sem);
	}

	/*
	 * Grant an infinite number of read locks to the readers at the front
	 * of the queue. We know that woken will be at least 1 as we accounted
	 * for above. Note we increment the 'active part' of the count by the
	 * number of readers before waking any processes up.
	 */
	list_for_each_entry_safe(waiter, tmp, &sem->wait_list, list) {
		struct task_struct *tsk;
		/* 接下来就到了爽局
		 * 我们开始唤醒了，如果等待者不是RWSEM_WAITING_FOR_WRITE，那说明是读者
		 * 其实这里就是拉出连续个读者，有这么一种情况
		 * 读 读 读 写 读
		 * 那么就捞出前面3个连续的读者
		 */
		if (waiter->type == RWSEM_WAITING_FOR_WRITE)
			break;
		/* 计数，计有多少个读者 */
		woken++;
		tsk = waiter->task;

		wake_q_add(wake_q, tsk);
		list_del(&waiter->list);
		/*
		 * Ensure that the last operation is setting the reader
		 * waiter to nil such that rwsem_down_read_failed() cannot
		 * race with do_exit() by always holding a reference count
		 * to the task to wakeup.
		 */
		smp_store_release(&waiter->task, NULL);
	}
	/* 更新一下 sem->count的值 */
	adjustment = woken * RWSEM_ACTIVE_READ_BIAS - adjustment;
	if (list_empty(&sem->wait_list)) {
		/* hit end of list above */
		adjustment -= RWSEM_WAITING_BIAS;
	}

	if (adjustment)
		atomic_long_add(adjustment, &sem->count);
}

/*
 * Wait for the read lock to be granted
 */
__visible
struct rw_semaphore __sched *rwsem_down_read_failed(struct rw_semaphore *sem)
{
	/* adjustmen = -RWSEM_ACTIVE_READ_BIAS = -0x1 = 0xffffffff */
	long count, adjustment = -RWSEM_ACTIVE_READ_BIAS;
	/* rwsem_waiter数据结构描述一个获取读写锁失败的"失意者",
	 * 当前情景是获取读者锁失败 */
	struct rwsem_waiter waiter;
	struct task_struct *tsk = current;
	WAKE_Q(wake_q);

	waiter.task = tsk;
	/* waiter.type = RWSEM_WAITING_FOR_READ = 1 */
	waiter.type = RWSEM_WAITING_FOR_READ;

	raw_spin_lock_irq(&sem->wait_lock);
	/* 如果等待队列没有人，即sem->wait_list链表为空，那么就adjustment加上RWSEM_WAITING_BIAS 0xffff0000
	 * 为什么等待队列的第一个人要加上RWSEM_WAITING_BIAS，RWSEM_WAITING_BIAS通常用于等待队列中还有其他正在排队的人
	 * 持有锁和释放锁对count的操作是成对出现的，当判断count值等于RWSEM_WAITING_BIAS时，
	 * 表面当前已经没有活跃的锁，即没有人持有锁，但有人在等待队列中
	 */
	if (list_empty(&sem->wait_list))
		adjustment += RWSEM_WAITING_BIAS;
	list_add_tail(&waiter.list, &sem->wait_list);
	/* 函数atomic_add_return()的功能是将原子类型的变量v的值原子地增加i，并返回增加i后的v的值
	 * count = adjustment + sem->count;
	 * 其实这里进来的条件是写者拥有了锁,所以这里的初始值count应该是RWSEM_ACTIVE_WRITE_BIAS 加上进入这个函数的条件的时候加了1
	 * 所以这里就是 -RWSEM_ACTIVE_READ_BIAS + RWSEM_WAITING_BIAS + RWSEM_ACTIVE_WRITE_BIAS + 1 = RWSEM_WAITING_BIAS + RWSEM_ACTIVE_WRITE_BIAS
	 */
	/* we're now waiting on the lock, but no longer actively locking */
	count = atomic_long_add_return(adjustment, &sem->count);
	/* 这里的意思是如果执行上面这行代码之前，
	 * sem被写锁给释放掉了，那么这里就会返回RWSEM_WAITING_BIAS，
	 * 所以这里的代码正好捕捉到了这个细节部分
	 */
	/*
	 * If there are no active locks, wake the front queued process(es).
	 *
	 * If there are no writers and we are first in the queue,
	 * wake our own waiter to join the existing active readers !
	 */
	if (count == RWSEM_WAITING_BIAS ||
	    (count > RWSEM_WAITING_BIAS &&
	     adjustment != -RWSEM_ACTIVE_READ_BIAS))
		/* __rwsem_mark_wake 函数去唤醒在等待队列中的人们 */
		__rwsem_mark_wake(sem, RWSEM_WAKE_ANY, &wake_q);

	raw_spin_unlock_irq(&sem->wait_lock);
	wake_up_q(&wake_q);

	/* wait to be given the lock */
	while (true) {
		set_task_state(tsk, TASK_UNINTERRUPTIBLE);
		if (!waiter.task)
			break;
		schedule();
	}

	__set_task_state(tsk, TASK_RUNNING);
	return sem;
}
EXPORT_SYMBOL(rwsem_down_read_failed);

/*
 * This function must be called with the sem->wait_lock held to prevent
 * race conditions between checking the rwsem wait list and setting the
 * sem->count accordingly.
 */
static inline bool rwsem_try_write_lock(long count, struct rw_semaphore *sem)
{
	/*
	 * Avoid trying to acquire write lock if count isn't RWSEM_WAITING_BIAS.
	 */
	if (count != RWSEM_WAITING_BIAS)
		return false;

	/*
	 * Acquire the lock by trying to set it to ACTIVE_WRITE_BIAS. If there
	 * are other tasks on the wait list, we need to add on WAITING_BIAS.
	 */
	count = list_is_singular(&sem->wait_list) ?
			RWSEM_ACTIVE_WRITE_BIAS :
			RWSEM_ACTIVE_WRITE_BIAS + RWSEM_WAITING_BIAS;

	if (atomic_long_cmpxchg_acquire(&sem->count, RWSEM_WAITING_BIAS, count)
							== RWSEM_WAITING_BIAS) {
		rwsem_set_owner(sem);
		return true;
	}

	return false;
}

#ifdef CONFIG_RWSEM_SPIN_ON_OWNER
/*
 * Try to acquire write lock before the writer has been put on wait queue.
 */
static inline bool rwsem_try_write_lock_unqueued(struct rw_semaphore *sem)
{
	long old, count = atomic_long_read(&sem->count);

	while (true) {
		/* 写者释放了锁，那么该锁的sem->count的值应该是0或者是RWSEM_WAITING_BIAS. */
		if (!(count == 0 || count == RWSEM_WAITING_BIAS))
			return false;
		/* 为什么要这样，因为有可能锁在这两行中间被偷了 */
		/* 如果sem->count和count相等，那么加上RWSEM_ACTIVE_WRITE_BIAS的值，返回原来的count的值 */
		old = atomic_long_cmpxchg_acquire(&sem->count, count,
				      count + RWSEM_ACTIVE_WRITE_BIAS);
		if (old == count) {
			rwsem_set_owner(sem);
			return true;
		}

		count = old;
	}
}

static inline bool rwsem_can_spin_on_owner(struct rw_semaphore *sem)
{
	struct task_struct *owner;
	bool ret = true;

	if (need_resched())
		return false;
	/* 程序运行到这里并发现sem->owner指向NULL，那么申请写者信号量失败的原因是
	 * 有一个读者已经持有了该锁，而不是一个写者。因为如果写者成功获取了该锁，那么sem->owner应该指向写者线程的task_struct,
	 * 该函数返回false,并且应该进入rwsem_down_write_failed函数里的慢车道
	 * 而不应该在这里自旋等待。另外一种情况是sem->owner成员有设置，说明在这之前
	 * 有一个线程持有了该写者锁，那就返回该线程的on_cpu值，如果on_cpu为1，说明该线程正在临界区
	 * 执行中，正是自旋等待的好时机
	 */
	rcu_read_lock();
	owner = READ_ONCE(sem->owner);
	if (!rwsem_owner_is_writer(owner)) {
		/*
		 * Don't spin if the rwsem is readers owned.
		 */
		ret = !rwsem_owner_is_reader(owner);
		goto done;
	}

	ret = owner->on_cpu;
done:
	rcu_read_unlock();
	return ret;
}

/*
 * Return true only if we can still spin on the owner field of the rwsem.
 */
static noinline bool rwsem_spin_on_owner(struct rw_semaphore *sem)
{
	struct task_struct *owner = READ_ONCE(sem->owner);
	/* 如果此时锁的拥有者不是写者呢，那么退出自旋 */
	if (!rwsem_owner_is_writer(owner))
		goto out;

	rcu_read_lock();
	/* 这里会一直监听sem->onwer值是否有修改 */
	while (sem->owner == owner) {
		/*
		 * Ensure we emit the owner->on_cpu, dereference _after_
		 * checking sem->owner still matches owner, if that fails,
		 * owner might point to free()d memory, if it still matches,
		 * the rcu_read_lock() ensures the memory stays valid.
		 */
		barrier();
		/* 如果拥有锁的进程没有在临界区运行，或者说当前进程需要被调度出去
		 * 如果当前进程有被调度出去的需求时，那么一直自旋下去会浪费CPU；
		 * 另外也是为了减低系统的延迟
		 */
		/* abort spinning when need_resched or owner is not running */
		if (!owner->on_cpu || need_resched()) {
			rcu_read_unlock();
			return false;
		}

		cpu_relax_lowlatency();
	}
	rcu_read_unlock();
out:
	/*
	 * If there is a new owner or the owner is not set, we continue
	 * spinning.
	 */
	/* 判断拿到新锁的是不是个读者，如果不是读者则返回true
	 * 也有可能这个锁空出来了
	 */
	return !rwsem_owner_is_reader(READ_ONCE(sem->owner));
}

static bool rwsem_optimistic_spin(struct rw_semaphore *sem)
{
	bool taken = false;

	preempt_disable();

	/* sem->wait_lock should not be held when doing optimistic spinning */
	if (!rwsem_can_spin_on_owner(sem))
		goto done;
	/* osq_lock函数获取OSQ锁，这和mutex机制里相同 */
	if (!osq_lock(&sem->osq))
		goto done;

	/*
	 * Optimistically spin on the owner field and attempt to acquire the
	 * lock whenever the owner changes. Spinning will be stopped when:
	 *  1) the owning writer isn't running; or
	 *  2) readers own the lock as we can't determine if they are
	 *     actively running or not.
	 */
	/* 前面可以看到自旋的前提是被另外一个写者锁抢先成功获取了锁(sem->owner指向写者的task_struct数据结构)
	 * 并且该写者线程正在临界区中执行，那么期待写者应该尽快释放锁，
	 * 从而避免进程切换的开销
	 */
	 /* rwsem_spin_on_owner 会一直等待写者释放锁 */
	while (rwsem_spin_on_owner(sem)) {
		/*
		 * Try to acquire the lock
		 */
		/* 尝试获取锁 */
		if (rwsem_try_write_lock_unqueued(sem)) {
			taken = true;
			break;
		}

		/*
		 * When there's no owner, we might have preempted between the
		 * owner acquiring the lock and setting the owner field. If
		 * we're an RT task that will live-lock because we won't let
		 * the owner complete.
		 */
		/* 如果锁被拥有然后需要调度出去，或者当前进程是rt线程 */
		if (!sem->owner && (need_resched() || rt_task(current)))
			break;

		/*
		 * The cpu_relax() call is a compiler barrier which forces
		 * everything in this loop to be re-loaded. We don't need
		 * memory barriers as we'll eventually observe the right
		 * values at the cost of a few extra spins.
		 */
		cpu_relax_lowlatency();
	}
	osq_unlock(&sem->osq);
done:
	preempt_enable();
	return taken;
}

/*
 * Return true if the rwsem has active spinner
 */
static inline bool rwsem_has_spinner(struct rw_semaphore *sem)
{
	return osq_is_locked(&sem->osq);
}

#else
static bool rwsem_optimistic_spin(struct rw_semaphore *sem)
{
	return false;
}

static inline bool rwsem_has_spinner(struct rw_semaphore *sem)
{
	return false;
}
#endif

/*
 * Wait until we successfully acquire the write lock
 */
static inline struct rw_semaphore *
__rwsem_down_write_failed_common(struct rw_semaphore *sem, int state)
{
	long count;
	bool waiting = true; /* any queued threads before us */
	struct rwsem_waiter waiter;
	struct rw_semaphore *ret = sem;
	WAKE_Q(wake_q);
	/* 因为没有成功获取锁，这里首先把刚才增加的RWSEM_ACTIVE_WRITE_BIAS值再减回去 */
	/* undo write bias from down_write operation, stop active locking */
	count = atomic_long_sub_return(RWSEM_ACTIVE_WRITE_BIAS, &sem->count);

	/* do optimistic spinning and steal lock if possible */
	/* rwsem_optimistic_spin 函数的作用是一直在门外自旋，有机会就下手偷锁 */
	if (rwsem_optimistic_spin(sem))
		return sem;

	/*
	 * Optimistic spinning failed, proceed to the slowpath
	 * and block until we can acquire the sem.
	 */
	/* 进入慢车道 */
	waiter.task = current;
	waiter.type = RWSEM_WAITING_FOR_WRITE;

	raw_spin_lock_irq(&sem->wait_lock);

	/* account for this before adding a new element to the list */
	if (list_empty(&sem->wait_list))
		waiting = false;

	list_add_tail(&waiter.list, &sem->wait_list);

	/* we're now waiting on the lock, but no longer actively locking */
	if (waiting) {
		count = atomic_long_read(&sem->count);

		/*
		 * If there were already threads queued before us and there are
		 * no active writers, the lock must be read owned; so we try to
		 * wake any read locks that were queued ahead of us.
		 */
		/* 如果count大于RWSEM_WAITING_BIAS说明现在没有活跃的写者锁，即写者已经释放了锁
		 * 但是有读者已经成功抢先获得了锁，因此调用__rwsem_mark_wake唤醒排在等待队列前面的读者锁
		 */
		if (count > RWSEM_WAITING_BIAS) {
			WAKE_Q(wake_q);

			__rwsem_mark_wake(sem, RWSEM_WAKE_READERS, &wake_q);
			/*
			 * The wakeup is normally called _after_ the wait_lock
			 * is released, but given that we are proactively waking
			 * readers we can deal with the wake_q overhead as it is
			 * similar to releasing and taking the wait_lock again
			 * for attempting rwsem_try_write_lock().
			 */
			wake_up_q(&wake_q);
		}

	} else
		count = atomic_long_add_return(RWSEM_WAITING_BIAS, &sem->count);

	/* wait until we successfully acquire the lock */
	set_current_state(state);
	while (true) {
		if (rwsem_try_write_lock(count, sem))
			break;
		raw_spin_unlock_irq(&sem->wait_lock);

		/* Block until there are no active lockers. */
		do {
			if (signal_pending_state(state, current))
				goto out_nolock;

			schedule();
			set_current_state(state);
		} while ((count = atomic_long_read(&sem->count)) & RWSEM_ACTIVE_MASK);

		raw_spin_lock_irq(&sem->wait_lock);
	}
	__set_current_state(TASK_RUNNING);
	list_del(&waiter.list);
	raw_spin_unlock_irq(&sem->wait_lock);

	return ret;

out_nolock:
	__set_current_state(TASK_RUNNING);
	raw_spin_lock_irq(&sem->wait_lock);
	list_del(&waiter.list);
	if (list_empty(&sem->wait_list))
		atomic_long_add(-RWSEM_WAITING_BIAS, &sem->count);
	else
		__rwsem_mark_wake(sem, RWSEM_WAKE_ANY, &wake_q);
	raw_spin_unlock_irq(&sem->wait_lock);
	wake_up_q(&wake_q);

	return ERR_PTR(-EINTR);
}

__visible struct rw_semaphore * __sched
rwsem_down_write_failed(struct rw_semaphore *sem)
{
	return __rwsem_down_write_failed_common(sem, TASK_UNINTERRUPTIBLE);
}
EXPORT_SYMBOL(rwsem_down_write_failed);

__visible struct rw_semaphore * __sched
rwsem_down_write_failed_killable(struct rw_semaphore *sem)
{
	return __rwsem_down_write_failed_common(sem, TASK_KILLABLE);
}
EXPORT_SYMBOL(rwsem_down_write_failed_killable);

/*
 * handle waking up a waiter on the semaphore
 * - up_read/up_write has decremented the active part of count if we come here
 */
__visible
struct rw_semaphore *rwsem_wake(struct rw_semaphore *sem)
{
	unsigned long flags;
	WAKE_Q(wake_q);

	/*
	 * If a spinner is present, it is not necessary to do the wakeup.
	 * Try to do wakeup only if the trylock succeeds to minimize
	 * spinlock contention which may introduce too much delay in the
	 * unlock operation.
	 *
	 *    spinning writer		up_write/up_read caller
	 *    ---------------		-----------------------
	 * [S]   osq_unlock()		[L]   osq
	 *	 MB			      RMB
	 * [RmW] rwsem_try_write_lock() [RmW] spin_trylock(wait_lock)
	 *
	 * Here, it is important to make sure that there won't be a missed
	 * wakeup while the rwsem is free and the only spinning writer goes
	 * to sleep without taking the rwsem. Even when the spinning writer
	 * is just going to break out of the waiting loop, it will still do
	 * a trylock in rwsem_down_write_failed() before sleeping. IOW, if
	 * rwsem_has_spinner() is true, it will guarantee at least one
	 * trylock attempt on the rwsem later on.
	 */
	if (rwsem_has_spinner(sem)) {
		/*
		 * The smp_rmb() here is to make sure that the spinner
		 * state is consulted before reading the wait_lock.
		 */
		smp_rmb();
		if (!raw_spin_trylock_irqsave(&sem->wait_lock, flags))
			return sem;
		goto locked;
	}
	raw_spin_lock_irqsave(&sem->wait_lock, flags);
locked:

	if (!list_empty(&sem->wait_list))
		__rwsem_mark_wake(sem, RWSEM_WAKE_ANY, &wake_q);

	raw_spin_unlock_irqrestore(&sem->wait_lock, flags);
	wake_up_q(&wake_q);

	return sem;
}
EXPORT_SYMBOL(rwsem_wake);

/*
 * downgrade a write lock into a read lock
 * - caller incremented waiting part of count and discovered it still negative
 * - just wake up any readers at the front of the queue
 */
__visible
struct rw_semaphore *rwsem_downgrade_wake(struct rw_semaphore *sem)
{
	unsigned long flags;
	WAKE_Q(wake_q);

	raw_spin_lock_irqsave(&sem->wait_lock, flags);

	if (!list_empty(&sem->wait_list))
		__rwsem_mark_wake(sem, RWSEM_WAKE_READ_OWNED, &wake_q);

	raw_spin_unlock_irqrestore(&sem->wait_lock, flags);
	wake_up_q(&wake_q);

	return sem;
}
EXPORT_SYMBOL(rwsem_downgrade_wake);
