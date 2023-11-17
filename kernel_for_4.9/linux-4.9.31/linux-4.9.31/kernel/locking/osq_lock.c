#include <linux/percpu.h>
#include <linux/sched.h>
#include <linux/osq_lock.h>

/*
 * An MCS like lock especially tailored for optimistic spinning for sleeping
 * lock implementations (mutex, rwsem, etc).
 *
 * Using a single mcs node per CPU is safe because sleeping locks should not be
 * called from interrupt context and we have preemption disabled while
 * spinning.
 */
/* struct optimistic_spin_node 数据结构会定义成per-CPU变量，即每个CPU有一个node结构 */
static DEFINE_PER_CPU_SHARED_ALIGNED(struct optimistic_spin_node, osq_node);

/*
 * We use the value 0 to represent "no CPU", thus the encoded value
 * will be the CPU number incremented by 1.
 */
static inline int encode_cpu(int cpu_nr)
{
	return cpu_nr + 1;
}

static inline struct optimistic_spin_node *decode_cpu(int encoded_cpu_val)
{
	int cpu_nr = encoded_cpu_val - 1;

	return per_cpu_ptr(&osq_node, cpu_nr);
}

/*
 * Get a stable @node->next pointer, either for unlock() or unqueue() purposes.
 * Can return NULL in case we were the last queued and we updated @lock instead.
 */
static inline struct optimistic_spin_node *
osq_wait_next(struct optimistic_spin_queue *lock,
	      struct optimistic_spin_node *node,
	      struct optimistic_spin_node *prev)
{
	struct optimistic_spin_node *next = NULL;
	/* 得到当前CPU的optimistic_spin_node计数中的数值 */
	int curr = encode_cpu(smp_processor_id());
	int old;

	/*
	 * If there is a prev node in queue, then the 'old' value will be
	 * the prev node's CPU #, else it's set to OSQ_UNLOCKED_VAL since if
	 * we're currently last in queue, then the queue will then become empty.
	 */
	/* old为前继节点prev_node所在的CPU编号，如果前继节点为空，那么old值为0 */
	old = prev ? prev->cpu : OSQ_UNLOCKED_VAL;

	for (;;) {
		/* 如果当前节点是队尾，那么比较lock->tail和当前的CPU数值是否相等
		 * 如果相等，那么把lock->tail赋值给old，也就是前继节点prev_node
		 */
		if (atomic_read(&lock->tail) == curr &&
		    atomic_cmpxchg_acquire(&lock->tail, curr, old) == curr) {
			/*
			 * We were the last queued, we moved @lock back. @prev
			 * will now observe @lock and will complete its
			 * unlock()/unqueue().
			 */
			break;
		}

		/*
		 * We must xchg() the @node->next value, because if we were to
		 * leave it in, a concurrent unlock()/unqueue() from
		 * @node->next might complete Step-A and think its @prev is
		 * still valid.
		 *
		 * If the concurrent unlock()/unqueue() wins the race, we'll
		 * wait for either @lock to point to us, through its Step-B, or
		 * wait for a new @node->next from its Step-C.
		 */
		/* 如果当前节点curr_node有后续节点，那么就把当前节点curr_node->next设置为NULL
		 * 这样就完成了步骤2
		 * xchg为交换两值，返回原来的值
		 */
		if (node->next) {
			next = xchg(&node->next, NULL);
			if (next)
				break;
		}
		/* cpu_relax_lowlatency函数指向ARM中是一条barrier指令 */
		cpu_relax_lowlatency();
	}

	return next;
}

bool osq_lock(struct optimistic_spin_queue *lock)
{
	/* node指向当前CPU的optimistic_spin_node节点 */
	struct optimistic_spin_node *node = this_cpu_ptr(&osq_node);
	struct optimistic_spin_node *prev, *next;
	/* 可以自己去看这个函数，这里的编号方式和CPU编号方式不太一样，
	 * 0表示没有CPU，1表示CPU0，以此内推
	 */
	int curr = encode_cpu(smp_processor_id());
	int old;

	node->locked = 0;
	node->next = NULL;
	node->cpu = curr;

	/*
	 * We need both ACQUIRE (pairs with corresponding RELEASE in
	 * unlock() uncontended, or fastpath) and RELEASE (to publish
	 * the node fields we just initialised) semantics when updating
	 * the lock tail.
	 */
	/* 把当前CPU给lock->tail，把之前lock->tail里面存放的值(也就是之前拿到锁的CPU的值)给old */
	old = atomic_xchg(&lock->tail, curr);
	/* 如果lock->tail的旧值等于初始化值OSQ_UNLOCKED_VAL(0),说明还没有人
	 * 持有锁，那么让lock->tail等于当前CPU编号表示当前CPU成功持有了锁
	 * 这是最快捷的方式
	 */
	if (old == OSQ_UNLOCKED_VAL)
		return true;
	/* 到这下面的code说明获取锁失败了 */
	/* 拿到之前CPU的optimistic_spin_node结构体 */
	prev = decode_cpu(old);
	/* 将本node的prev放入前一个的optimistic_spin_node */
	node->prev = prev;
	/* 把当前的optimistic_spin_node放入前一个的next */
	WRITE_ONCE(prev->next, node);

	/*
	 * Normally @prev is untouchable after the above store; because at that
	 * moment unlock can proceed and wipe the node element from stack.
	 *
	 * However, since our nodes are static per-cpu storage, we're
	 * guaranteed their existence -- this allows us to apply
	 * cmpxchg in an attempt to undo our queueing.
	 */
	/* while循环一直查询当前节点curr_node的locked是否变成1，因为前继节点prev_node释放锁
	 * 会把它的下一个节点中的locked成员设置为1，然后才能成功释放锁。
	 * 在理想情况下，前继节点释放锁，那么当前进程也退出自旋，返回true.
	 */
	while (!READ_ONCE(node->locked)) {
		/*
		 * If we need to reschedule bail... so we can block.
		 */
		/* 在自旋等待过程中，如果有更高优先级进程抢占或者被调度器要求调度出去
		 * 那么放弃自旋等待，退出MCS链表，跳转到unqueue标签处处理MCS链表删除
		 * 节点的情况。unqueue标签处是异常情况处理，正常情况是要在while循环中等待锁
		 */
		if (need_resched())
			goto unqueue;

		cpu_relax_lowlatency();
	}
	return true;

unqueue:
	/*
	 * Step - A  -- stabilize @prev
	 *
	 * Undo our @prev->next assignment; this will make @prev's
	 * unlock()/unqueue() wait for a next pointer since @lock points to us
	 * (or later).
	 */
	/* 删除MSC链表节点分为如下3个步骤
	 * 1、解除前继节点（prev_node）的next指针的指向
	 * 2、解除当前节点（curr_node）的next指针的指向，并且找出当前节点的下一个确定的节点next_node
	 * 3、让前继节点prev_node->next指向next_node,next_node->prev指向prev_node
	 */
	for (;;) {
		/* 这里的prev是前面代码获取的前继节点，如果前继节点的next指针
		 * 指向当前节点，说明这期间还没有人来修改链表，接着用cmpxchg函数原子地判断前继节点的next
		 * 指针是否指向当前节点，如果是，则把prev->next指针指向NULL
		 * 并判断返回的前继节点的next指针是否指向当前节点，如果都正确
		 * 那么就达到步骤（1）解除前继节点next指针指向的目的了
		 */
		if (prev->next == node &&
		    cmpxchg(&prev->next, node, NULL) == node)
			break;

		/*
		 * We can only fail the cmpxchg() racing against an unlock(),
		 * in which case we should observe @node->locked becomming
		 * true.
		 */
		/* 如果上面失败了，说明这期间有人修改了MCS链表
		 * smp_load_acquire宏再一次判断当前节点是否持有了锁
		 * 如果这时判断当前节点的curr_node->locked为1，说明
		 * 当前节点持有了锁，返回true，这里可能会有疑问，为什么当前
		 * 节点莫名其妙持有了锁呢，这时前继节点释放锁并且把锁传点给当前节点的
		 *
		 */
		if (smp_load_acquire(&node->locked))
			return true;

		cpu_relax_lowlatency();

		/*
		 * Or we race against a concurrent unqueue()'s step-B, in which
		 * case its step-C will write us a new @node->prev pointer.
		 */
		/* 之前cmpxchg判断失败说明当前节点的前继节点prev_node发生了变化，
		 * 这里重新加载新的前继节点，继续下一次循环
		 */
		prev = READ_ONCE(node->prev);
	}

	/*
	 * Step - B -- stabilize @next
	 *
	 * Similar to unlock(), wait for @node->next or move @lock from @node
	 * back to @prev.
	 */
	/* 步骤（1）是处理前继节点prev_node的next指针指向问题，现在轮到处理当前节点curr_node
	 * 的next指针指向问题，关键实现是在osq_wait_next函数里
	 */
	next = osq_wait_next(lock, node, prev);
	if (!next)
		return false;

	/*
	 * Step - C -- unlink
	 *
	 * @prev is stable because its still waiting for a new @prev->next
	 * pointer, @next is stable because our @node->next pointer is NULL and
	 * it will wait in Step-A.
	 */
	/* 后继节点的next_node的prev指针指向前继节点prev_node，前继节点prev_node的next指针指向后续
	 * 节点next_node，这样就完成了当前节点curr_node脱离MCS链表的操作，最后
	 * 返回false，因为没有成功取得锁
	 */
	WRITE_ONCE(next->prev, prev);
	WRITE_ONCE(prev->next, next);

	return false;
}

void osq_unlock(struct optimistic_spin_queue *lock)
{
	struct optimistic_spin_node *node, *next;
	int curr = encode_cpu(smp_processor_id());

	/*
	 * Fast path for the uncontended case.
	 */
	/* 如果lock->tail保存的CPU编号正好是当前进程的CPU编号，说明没有人来竞争该锁，
	 * 那么直接把lock->tail设置为0释放锁，这是最理想的情况
	 */
	if (likely(atomic_cmpxchg_release(&lock->tail, curr,
					  OSQ_UNLOCKED_VAL) == curr))
		return;

	/*
	 * Second most likely case.
	 */
	/* 首先把当前节点的next指针指向NULL，如果当前节点有后续节点，那么把后继
	 * 节点next_node->locked成员设置位1，相当于把锁传递给后续节点，
	 * 如果后续节点next->node为空，那么说明在执行osq_unlock期间有人
	 * 擅自离队，那么只能调用osq_wait_next函数来确定或者等待确定的后继节点
	 * 也许当前节点就在队尾，当然也会有后续无人的情况
	 */
	node = this_cpu_ptr(&osq_node);
	next = xchg(&node->next, NULL);
	if (next) {
		WRITE_ONCE(next->locked, 1);
		return;
	}

	next = osq_wait_next(lock, node, NULL);
	if (next)
		WRITE_ONCE(next->locked, 1);
}
