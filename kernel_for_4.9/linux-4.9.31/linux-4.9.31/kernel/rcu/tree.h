/*
 * Read-Copy Update mechanism for mutual exclusion (tree-based version)
 * Internal non-public definitions.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, you can access it online at
 * http://www.gnu.org/licenses/gpl-2.0.html.
 *
 * Copyright IBM Corporation, 2008
 *
 * Author: Ingo Molnar <mingo@elte.hu>
 *	   Paul E. McKenney <paulmck@linux.vnet.ibm.com>
 */

#include <linux/cache.h>
#include <linux/spinlock.h>
#include <linux/threads.h>
#include <linux/cpumask.h>
#include <linux/seqlock.h>
#include <linux/swait.h>
#include <linux/stop_machine.h>

/*
 * Define shape of hierarchy based on NR_CPUS, CONFIG_RCU_FANOUT, and
 * CONFIG_RCU_FANOUT_LEAF.
 * In theory, it should be possible to add more levels straightforwardly.
 * In practice, this did work well going from three levels to four.
 * Of course, your mileage may vary.
 */
/* Tree RCU根据CPU数量的大小按照树形结构来组成其层次结构，称为RCU Hierarchy.
 * 内核中有两个宏帮助构建RCU层次结构，其中CONFIG_RCU_FANOUT_LEAF表示一个子叶子的CPU数量，
 * CONFIG_RCU_FANOUT表示每个层数最多支持的叶子数量，MAX_RCU_LVLS表示4等于内最多支持4层结构
 */
#ifdef CONFIG_RCU_FANOUT
#define RCU_FANOUT CONFIG_RCU_FANOUT
#else /* #ifdef CONFIG_RCU_FANOUT */
# ifdef CONFIG_64BIT
# define RCU_FANOUT 64
# else
# define RCU_FANOUT 32
# endif
#endif /* #else #ifdef CONFIG_RCU_FANOUT */

#ifdef CONFIG_RCU_FANOUT_LEAF
#define RCU_FANOUT_LEAF CONFIG_RCU_FANOUT_LEAF
#else /* #ifdef CONFIG_RCU_FANOUT_LEAF */
# ifdef CONFIG_64BIT
# define RCU_FANOUT_LEAF 64
# else
# define RCU_FANOUT_LEAF 32
# endif
#endif /* #else #ifdef CONFIG_RCU_FANOUT_LEAF */

#define RCU_FANOUT_1	      (RCU_FANOUT_LEAF)
#define RCU_FANOUT_2	      (RCU_FANOUT_1 * RCU_FANOUT)
#define RCU_FANOUT_3	      (RCU_FANOUT_2 * RCU_FANOUT)
#define RCU_FANOUT_4	      (RCU_FANOUT_3 * RCU_FANOUT)
/* 这里可以好好算一下，如果我们只有4个CPU，那么这里RCU层次结构就是系统只有一个层级即level0,
 * 并且level 0层级只需要一个struct rcu_node节点就可以容纳4个struct rcu_data数据结构。
 * struct rcu_data数据结构是per-CPU变量，每个CPU有一个独立的struct rcu_data数据结构，其中mynode成员指向所属的struct_node节点。
 */
#if NR_CPUS <= RCU_FANOUT_1
#  define RCU_NUM_LVLS	      1
#  define NUM_RCU_LVL_0	      1
#  define NUM_RCU_NODES	      NUM_RCU_LVL_0
#  define NUM_RCU_LVL_INIT    { NUM_RCU_LVL_0 }
#  define RCU_NODE_NAME_INIT  { "rcu_node_0" }
#  define RCU_FQS_NAME_INIT   { "rcu_node_fqs_0" }
#elif NR_CPUS <= RCU_FANOUT_2
#  define RCU_NUM_LVLS	      2
#  define NUM_RCU_LVL_0	      1
#  define NUM_RCU_LVL_1	      DIV_ROUND_UP(NR_CPUS, RCU_FANOUT_1)
#  define NUM_RCU_NODES	      (NUM_RCU_LVL_0 + NUM_RCU_LVL_1)
#  define NUM_RCU_LVL_INIT    { NUM_RCU_LVL_0, NUM_RCU_LVL_1 }
#  define RCU_NODE_NAME_INIT  { "rcu_node_0", "rcu_node_1" }
#  define RCU_FQS_NAME_INIT   { "rcu_node_fqs_0", "rcu_node_fqs_1" }
#elif NR_CPUS <= RCU_FANOUT_3
#  define RCU_NUM_LVLS	      3
#  define NUM_RCU_LVL_0	      1
#  define NUM_RCU_LVL_1	      DIV_ROUND_UP(NR_CPUS, RCU_FANOUT_2)
#  define NUM_RCU_LVL_2	      DIV_ROUND_UP(NR_CPUS, RCU_FANOUT_1)
#  define NUM_RCU_NODES	      (NUM_RCU_LVL_0 + NUM_RCU_LVL_1 + NUM_RCU_LVL_2)
#  define NUM_RCU_LVL_INIT    { NUM_RCU_LVL_0, NUM_RCU_LVL_1, NUM_RCU_LVL_2 }
#  define RCU_NODE_NAME_INIT  { "rcu_node_0", "rcu_node_1", "rcu_node_2" }
#  define RCU_FQS_NAME_INIT   { "rcu_node_fqs_0", "rcu_node_fqs_1", "rcu_node_fqs_2" }
#elif NR_CPUS <= RCU_FANOUT_4
#  define RCU_NUM_LVLS	      4
#  define NUM_RCU_LVL_0	      1
#  define NUM_RCU_LVL_1	      DIV_ROUND_UP(NR_CPUS, RCU_FANOUT_3)
#  define NUM_RCU_LVL_2	      DIV_ROUND_UP(NR_CPUS, RCU_FANOUT_2)
#  define NUM_RCU_LVL_3	      DIV_ROUND_UP(NR_CPUS, RCU_FANOUT_1)
#  define NUM_RCU_NODES	      (NUM_RCU_LVL_0 + NUM_RCU_LVL_1 + NUM_RCU_LVL_2 + NUM_RCU_LVL_3)
#  define NUM_RCU_LVL_INIT    { NUM_RCU_LVL_0, NUM_RCU_LVL_1, NUM_RCU_LVL_2, NUM_RCU_LVL_3 }
#  define RCU_NODE_NAME_INIT  { "rcu_node_0", "rcu_node_1", "rcu_node_2", "rcu_node_3" }
#  define RCU_FQS_NAME_INIT   { "rcu_node_fqs_0", "rcu_node_fqs_1", "rcu_node_fqs_2", "rcu_node_fqs_3" }
#else
# error "CONFIG_RCU_FANOUT insufficient for NR_CPUS"
#endif /* #if (NR_CPUS) <= RCU_FANOUT_1 */

extern int rcu_num_lvls;
extern int rcu_num_nodes;

/*
 * Dynticks per-CPU state.
 */
struct rcu_dynticks {
	/* 这个整型值是嵌套计数，表示在相应的CPU中，应当被监控的RCU读端临界区的数量。
	 * 如果CPU出于dynticks-idle模式，那么就不应该存在RCU读端临界区。
	 * 此时这个值是中断嵌套级别，否则它比irq中断嵌套级别更大
	 */
	long long dynticks_nesting; /* Track irq/process nesting level. */
				    /* Process level is worth LLONG_MAX/2. */
	/* 如果相应的CPU处于NMI处理函数，则这个整型计数器的值是奇数。否则，该计数器是偶数 */
	int dynticks_nmi_nesting;   /* Track NMI nesting level. */
	/* 如果相应的CPU处于dynticks-idle模式，并且没有中断处理函数正在该CPU上运行，
	 * 则这个计数值是偶数，否则是奇数。
	 *换句话说，如果计数值是奇数，那么相应的CPU可能处于RCU读端临界区中。
	 */
	atomic_t dynticks;	    /* Even value for idle, else odd. */
#ifdef CONFIG_NO_HZ_FULL_SYSIDLE
	long long dynticks_idle_nesting;
				    /* irq/process nesting level from idle. */
	atomic_t dynticks_idle;	    /* Even value for idle, else odd. */
				    /*  "Idle" excludes userspace execution. */
	unsigned long dynticks_idle_jiffies;
				    /* End of last non-NMI non-idle period. */
#endif /* #ifdef CONFIG_NO_HZ_FULL_SYSIDLE */
#ifdef CONFIG_RCU_FAST_NO_HZ
	bool all_lazy;		    /* Are all CPU's CBs lazy? */
	unsigned long nonlazy_posted;
				    /* # times non-lazy CBs posted to CPU. */
	unsigned long nonlazy_posted_snap;
				    /* idle-period nonlazy_posted snapshot. */
	unsigned long last_accelerate;
				    /* Last jiffy CBs were accelerated. */
	unsigned long last_advance_all;
				    /* Last jiffy CBs were all advanced. */
	int tick_nohz_enabled_snap; /* Previously seen value from sysfs. */
#endif /* #ifdef CONFIG_RCU_FAST_NO_HZ */
};

/* RCU's kthread states for tracing. */
#define RCU_KTHREAD_STOPPED  0
#define RCU_KTHREAD_RUNNING  1
#define RCU_KTHREAD_WAITING  2
#define RCU_KTHREAD_OFFCPU   3
#define RCU_KTHREAD_YIELDING 4
#define RCU_KTHREAD_MAX      4

/*
 * Definition for node within the RCU grace-period-detection hierarchy.
 */
/* RCU全程为read_copy_update，是linux内核中一种重要的同步机制。
 * rwsem只允许多个读者同时存在，但是读者和写者不能同事存在。那么RCU机制要实现的目标是，
 * 希望读者线程没有同步开销，或者说同步开销变得很小，甚至可以忽略不计，不需要额外的锁，
 * 不需要使用原子操作指令和内存屏障，即可畅通无阻地访问；
 * 而把需要同步的任务交给写者线程，写者线程等待所有读者线程完成后才会把旧数据销毁。
 * 在RCU中，如果有多个写者同时存在，那么需要额外的保护机制。RCU机制的原理可以概括
 * 为RCU记录了所有指向共享数据的指针的使用者，当要修改该共享数据时，首先创建一个副本，
 * 在副本中修改。所有读访问线程都离开临界区之后，指针指向新的修改后的副本的指针，并删除旧数据。
 */
/* RCU里有两个很重要的概念，分别是宽限期（Grace Period，GP）和静止状态（Quiescent State,QS）。
 * Grace Period，宽限期。GP有生命周期，有开始和结束之分。在GP开始那一刻算起，当所有处于读者临界区
 * 的CPU都离开临界区，也就是都至少发生了一次Quiescent State，那么认为一个GP可以结束了。
 * GP结束后，RCU会调用注册的回调函数，例如销毁旧数据等。
 * Quiescent State，静止状态。在RCU设计中，如果一个CPU处于RCU读者临界区中，说明它的状态是活跃的；
 * 相反，如果在时钟tick中检测到该CPU处于用户模式或idle模式，说明该CPU已经离开了读者
 * 临界区。在不支持抢占的RCU实现中,只要检测到CPU上下文切换，就可以知道离开了读者临界区
 */
/* RCU在Linux2.5内核开发时已经加入到Linux内核了，但是在Linux2.6.29之前的RCU通常被成为经典的RCU(Classic RCU)。
 * 经典的RCU在大型系统中遇到了性能问题，后来在Linux 2.6.29中IBM的内核专家Paul E.Mckenney提出了Tree RCU的实现，Tree RCU也被成为Hierarchical RCU。
 * 经典的RCU的实现在超级大系统中遇到了问题，特别是有些系统的CPU核心超过了1024,甚至达到4096个。
 * 经典的RCU在判断是否完成一次GP时采用全局的cpumask位图，每个比特位表示一个CPU，那么在1024个CPU核心的系统中，cpumask位图就有1024个比特位。
 * 每个CPU在GP开始时要设置位图中对应的比特位，GP结束时要清相应的比特位。
 * 全局的cpumask位图会导致很多CPU竞争使用，那么需要spinlock锁来保护位图。
 * 这样导致该锁争用变得很激烈，惨烈程度随着CPU的个数线性递增。
 * Tree RCU实现巧妙地解决了CPU mask位图竞争锁的问题。以四核处理器为例，假设Tree RCU
 * 把两个CPU分成1个rcu_node节点，这样4个CPU被分配到两个rcu_node节点上，另外还有一个根rcu_node节点来管理这两个rcu_node节点。
 * 节点1管理cpu 0和cpu1,节点2管理cpu2和cpu3,而节点0是根节点，管理节点1和节点2.
 * 每个节点只需要两个比特位的位图就可以管理各自的CPU或者节点，每个节点都有各自的spinlock锁来保护相应的位图。
 *
 * 假设4个CPU都经历过一个QS状态，那么4个CPU首先在Level0层级的节点1和节点2上修改位图.
 * 对于节点1或者节点2来说，只有两个CPU来竞争锁，这比经典RCU上的锁争用要减小一半。
 * 当level 0上节点1和节点2上位图都被清除干净后，才会清除上一节点的位图，并且
 * 只有最后清除节点的CPU才有机会去尝试清除上一节点的位图。
 * 因此对于节点0来说，还是两个CPU来争用锁。整个过程都是只有两个CPU去争取一个锁，比经典RCU实现要减小一半。
 * Tree RCU为了实现分层的结构，定义了3个很重要的数据结构，分别是struct rcu_data、struct rcu_node和struct rcu_state,
 * 另外还维护了一个比较隐晦的状态机
 */



/* struct rcu_node是Tree RCU中重要的组成部分，它有根节点（Root Node)和叶节点之分。如果Tree RCU只有一层
 * 那么根节点下面直接管理着一个或者多个rcu_data;
 * 如果Tree RCU有多层结构，那么根节点管理多个叶节点，最底层的叶节点管理一个或多个rcu_data
 */
struct rcu_node {
	/* rcu_node节点内部的spinlock,用于该节点所管辖的rcu_data或叶节点之间的互斥操作 */
	raw_spinlock_t __private lock;	/* Root rcu_node's lock protects */
					/*  some rcu_state fields as well as */
					/*  following. */
	/* 表示当前GP在该节点的计数。系统初始化为-300，每当开始一个GP，该值就会加1 */
	unsigned long gpnum;	/* Current grace period for this node. */
				/*  This will either be equal to or one */
				/*  behind the root rcu_node's gpnum. */
	/* 表示该节点上一次GP完成时的计数。系统初始化时，和gpnum一样为-300.
	 * 每当一个GP完成时，completed才会加1.
	 */
	unsigned long completed; /* Last GP completed for this node. */
				/*  This will either be equal to or one */
				/*  behind the root rcu_node's gpnum. */
	/* 该节点用于管理所属的rcu_data或子节点的位图。每个比特位表示一个rcu_data或子节点。
	 * 每当rcu_data或子节点完成了Quiescent State状态，相应的比特位会被清除
	 */
	unsigned long qsmask;	/* CPUs or groups that need to switch in */
				/*  order for current grace period to proceed.*/
				/*  In leaf rcu_node, each bit corresponds to */
				/*  an rcu_data structure, otherwise, each */
				/*  bit corresponds to a child rcu_node */
				/*  structure. */
	/* 每个GP初始化时，qsmaskinit等于qsmark的初始值 */
	unsigned long qsmaskinit;
				/* Per-GP initial value for qsmask. */
				/*  Initialized from ->qsmaskinitnext at the */
				/*  beginning of each grace period. */
	unsigned long qsmaskinitnext;
				/* Online CPUs for next grace period. */
	unsigned long expmask;	/* CPUs or groups that need to check in */
				/*  to allow the current expedited GP */
				/*  to complete. */
	unsigned long expmaskinit;
				/* Per-GP initial values for expmask. */
				/*  Initialized from ->expmaskinitnext at the */
				/*  beginning of each expedited GP. */
	unsigned long expmaskinitnext;
				/* Online CPUs for next expedited GP. */
				/*  Any CPU that has ever been online will */
				/*  have its bit set. */
	/* 对应其父节点的qsmark位图相应的比特位 */
	unsigned long grpmask;	/* Mask to apply to parent qsmask. */
				/*  Only one bit will be set in this mask. */
	/* 该节点最小管理的CPU编号 */
	int	grplo;		/* lowest-numbered CPU or group here. */
	/* 该节点最大管理CPU或子节点的编号 */
	int	grphi;		/* highest-numbered CPU or group here. */
	/* node在上一层node中的编号 */
	u8	grpnum;		/* CPU/group number for next level up. */
	/* 表示该节点在Tree RCU中的第几层，根节点在第0层 */
	u8	level;		/* root is at level 0. */
	bool	wait_blkd_tasks;/* Necessary to wait for blocked tasks to */
				/*  exit RCU read-side critical sections */
				/*  before propagating offline up the */
				/*  rcu_node tree? */
	/* 指向父节点 */
	struct rcu_node *parent;
	struct list_head blkd_tasks;
				/* Tasks blocked in RCU read-side critical */
				/*  section.  Tasks are placed at the head */
				/*  of this list and age towards the tail. */
	struct list_head *gp_tasks;
				/* Pointer to the first task blocking the */
				/*  current grace period, or NULL if there */
				/*  is no such task. */
	struct list_head *exp_tasks;
				/* Pointer to the first task blocking the */
				/*  current expedited grace period, or NULL */
				/*  if there is no such task.  If there */
				/*  is no current expedited grace period, */
				/*  then there can cannot be any such task. */
	struct list_head *boost_tasks;
				/* Pointer to first task that needs to be */
				/*  priority boosted, or NULL if no priority */
				/*  boosting is needed for this rcu_node */
				/*  structure.  If there are no tasks */
				/*  queued on this rcu_node structure that */
				/*  are blocking the current grace period, */
				/*  there can be no such task. */
	struct rt_mutex boost_mtx;
				/* Used only for the priority-boosting */
				/*  side effect, not as a lock. */
	unsigned long boost_time;
				/* When to start boosting (jiffies). */
	struct task_struct *boost_kthread_task;
				/* kthread that takes care of priority */
				/*  boosting for this rcu_node structure. */
	unsigned int boost_kthread_status;
				/* State of boost_kthread_task for tracing. */
	unsigned long n_tasks_boosted;
				/* Total number of tasks boosted. */
	unsigned long n_exp_boosts;
				/* Number of tasks boosted for expedited GP. */
	unsigned long n_normal_boosts;
				/* Number of tasks boosted for normal GP. */
	unsigned long n_balk_blkd_tasks;
				/* Refused to boost: no blocked tasks. */
	unsigned long n_balk_exp_gp_tasks;
				/* Refused to boost: nothing blocking GP. */
	unsigned long n_balk_boost_tasks;
				/* Refused to boost: already boosting. */
	unsigned long n_balk_notblocked;
				/* Refused to boost: RCU RS CS still running. */
	unsigned long n_balk_notyet;
				/* Refused to boost: not yet time. */
	unsigned long n_balk_nos;
				/* Refused to boost: not sure why, though. */
				/*  This can happen due to race conditions. */
#ifdef CONFIG_RCU_NOCB_CPU
	struct swait_queue_head nocb_gp_wq[2];
				/* Place for rcu_nocb_kthread() to wait GP. */
#endif /* #ifdef CONFIG_RCU_NOCB_CPU */
	int need_future_gp[2];
				/* Counts of upcoming no-CB GP requests. */
	raw_spinlock_t fqslock ____cacheline_internodealigned_in_smp;

	spinlock_t exp_lock ____cacheline_internodealigned_in_smp;
	unsigned long exp_seq_rq;
	wait_queue_head_t exp_wq[4];
} ____cacheline_internodealigned_in_smp;

/*
 * Bitmasks in an rcu_node cover the interval [grplo, grphi] of CPU IDs, and
 * are indexed relative to this interval rather than the global CPU ID space.
 * This generates the bit for a CPU in node-local masks.
 */
/* 计算CPU在相关node的CPU 位图的bit位 */
#define leaf_node_cpu_bit(rnp, cpu) (1UL << ((cpu) - (rnp)->grplo))

/*
 * Do a full breadth-first scan of the rcu_node structures for the
 * specified rcu_state structure.
 */
#define rcu_for_each_node_breadth_first(rsp, rnp) \
	for ((rnp) = &(rsp)->node[0]; \
	     (rnp) < &(rsp)->node[rcu_num_nodes]; (rnp)++)

/*
 * Do a breadth-first scan of the non-leaf rcu_node structures for the
 * specified rcu_state structure.  Note that if there is a singleton
 * rcu_node tree with but one rcu_node structure, this loop is a no-op.
 */
#define rcu_for_each_nonleaf_node_breadth_first(rsp, rnp) \
	for ((rnp) = &(rsp)->node[0]; \
	     (rnp) < (rsp)->level[rcu_num_lvls - 1]; (rnp)++)

/*
 * Scan the leaves of the rcu_node hierarchy for the specified rcu_state
 * structure.  Note that if there is a singleton rcu_node tree with but
 * one rcu_node structure, this loop -will- visit the rcu_node structure.
 * It is still a leaf node, even if it is also the root node.
 */
#define rcu_for_each_leaf_node(rsp, rnp) \
	for ((rnp) = (rsp)->level[rcu_num_lvls - 1]; \
	     (rnp) < &(rsp)->node[rcu_num_nodes]; (rnp)++)

/*
 * Iterate over all possible CPUs in a leaf RCU node.
 */
#define for_each_leaf_node_possible_cpu(rnp, cpu) \
	for ((cpu) = cpumask_next(rnp->grplo - 1, cpu_possible_mask); \
	     cpu <= rnp->grphi; \
	     cpu = cpumask_next((cpu), cpu_possible_mask))

/*
 * Union to allow "aggregate OR" operation on the need for a quiescent
 * state by the normal and expedited grace periods.
 */
union rcu_noqs {
	struct {
		u8 norm;
		u8 exp;
	} b; /* Bits. */
	u16 s; /* Set of bits, aggregate OR here. */
};

/* Index values for nxttail array in struct rcu_data. */
#define RCU_DONE_TAIL		0	/* Also RCU_WAIT head. */
#define RCU_WAIT_TAIL		1	/* Also RCU_NEXT_READY head. */
#define RCU_NEXT_READY_TAIL	2	/* Also RCU_NEXT head. */
#define RCU_NEXT_TAIL		3
#define RCU_NEXT_SIZE		4

/* Per-CPU data for read-copy update. */
/* struct rcu_data数据结构定义成per-CPU变量，每个CPU有一个独立的struct rcu_data
 */
struct rcu_data {
	/* 1) quiescent-state and grace-period handling : */
	/* 当GP完成时，该成员会加1.系统初始化时，complete和gpnum成员都等于-300，从这两个成员值的变化可以窥探出GP状态机的运行状态 */
	unsigned long	completed;	/* Track rsp->completed gp number */
					/*  in order to detect GP end. */
	/* RCU内部对GP的一个计数。系统初始化时该值从-300开始计数,每当新建一个GP，该值会加1 */
	unsigned long	gpnum;		/* Highest gp number that this CPU */
					/*  is aware of having started. */
	unsigned long	rcu_qs_ctr_snap;/* Snapshot of rcu_qs_ctr to check */
					/*  for rcu_all_qs() invocations. */
	/* 表示CPU是否未度过norm或exp静止态，例如进程切换时会调用union成员rcu_qs设置为false */
	union rcu_noqs	cpu_no_qs;	/* No QSes yet for this CPU. */
	/* 表示RCU是否需要此CPU上报QS状态 */
	bool		core_needs_qs;	/* Core waits for quiesc state. */
	/* CPU最近的一次状态是否是online */
	bool		beenonline;	/* CPU online at least once. */
	/* gp_seq溢出后，sh此变量会设置成true */
	bool		gpwrap;		/* Possible gpnum/completed wrap. */
	/* 指向父节点的rcu_node */
	struct rcu_node *mynode;	/* This CPU's leaf of hierarchy */
	/* 父节点的rcu_node中有一个qsmark位图。该位图中每个比特位代表一个子节点
	 * 或者对应的rcu_data。grpmask代表在qsmark位图中相应的比特位
	 */
	unsigned long grpmask;		/* Mask to apply to leaf qsmask. */
	 /*当前gp已经历过多少个tick中断，每个tick中断中都会对它加1*/
	unsigned long	ticks_this_gp;	/* The number of scheduling-clock */
					/*  ticks this CPU has handled */
					/*  during and after the last grace */
					/* period it is aware of. */

	/* 2) batch handling */
	/*
	 * If nxtlist is not NULL, it is partitioned as follows.
	 * Any of the partitions might be empty, in which case the
	 * pointer to that partition will be equal to the pointer for
	 * the following partition.  When the list is empty, all of
	 * the nxttail elements point to the ->nxtlist pointer itself,
	 * which in that case is NULL.
	 *
	 * [nxtlist, *nxttail[RCU_DONE_TAIL]):
	 *	Entries that batch # <= ->completed
	 *	The grace period for these entries has completed, and
	 *	the other grace-period-completed entries may be moved
	 *	here temporarily in rcu_process_callbacks().
	 * [*nxttail[RCU_DONE_TAIL], *nxttail[RCU_WAIT_TAIL]):
	 *	Entries that batch # <= ->completed - 1: waiting for current GP
	 * [*nxttail[RCU_WAIT_TAIL], *nxttail[RCU_NEXT_READY_TAIL]):
	 *	Entries known to have arrived before current GP ended
	 * [*nxttail[RCU_NEXT_READY_TAIL], *nxttail[RCU_NEXT_TAIL]):
	 *	Entries that might have arrived after current GP ended
	 *	Note that the value of *nxttail[RCU_NEXT_TAIL] will
	 *	always be NULL, as this is the end of the list.
	 */
	/* 批处理
	 * 如果nxtlist不是空，则按如下方式对其进行分割
	 * 任何分区都可能是空的，在这种情况下,指向该分区的指针等于下一个分区的指针
	 * 当这个链表是空的时，所有的nxttail成员都指向它自己的nxtlist指针，在这种情况下为空
	 *
	 * [nxtlist, *nxttail[RCU_DONE_TAIL]):
	 * 批处理的成员 # <= ->completed
	 * 这些成员的GP已经完成了，其他CP完成的成员可能在rcu_process_callbacks 临时的移动到这里
	 *
	 * [*nxttail[RCU_DONE_TAIL], *nxttail[RCU_WAIT_TAIL]):
	 * 批处理成员 # <= ->completed - 1
	 * 等待当前GP
	 *
	 * [*nxttail[RCU_WAIT_TAIL], *nxttail[RCU_NEXT_READY_TAIL]):
	 * 已知在当前CP结束前到达的成员
	 *
	 * [*nxttail[RCU_NEXT_READY_TAIL], *nxttail[RCU_NEXT_TAIL])
	 * 成员可能在当前GP结束之后到达
	 * 注意 这个 *nxttail[RCU_NEXT_TAIL]的值总是为空，因为他是链表的结尾
	 */
	struct rcu_head *nxtlist;
	struct rcu_head **nxttail[RCU_NEXT_SIZE];
	unsigned long	nxtcompleted[RCU_NEXT_SIZE];
					/* grace periods for sublists. */
	long		qlen_lazy;	/* # of lazy queued callbacks */
	long		qlen;		/* # of queued callbacks, incl lazy */
	long		qlen_last_fqs_check;
					/* qlen at last check for QS forcing */
	unsigned long	n_cbs_invoked;	/* count of RCU cbs invoked. */
	unsigned long	n_nocbs_invoked; /* count of no-CBs RCU cbs invoked. */
	unsigned long   n_cbs_orphaned; /* RCU cbs orphaned by dying CPU */
	unsigned long   n_cbs_adopted;  /* RCU cbs adopted from dying CPU */
	unsigned long	n_force_qs_snap;
					/* did other CPU force QS recently? */
	long		blimit;		/* Upper limit on a processed batch */

	/* 3) dynticks interface. */
	struct rcu_dynticks *dynticks;	/* Shared per-CPU dynticks state. */
	int dynticks_snap;		/* Per-GP tracking for dynticks. */

	/* 4) reasons this CPU needed to be kicked by force_quiescent_state */
	unsigned long dynticks_fqs;	/* Kicked due to dynticks idle. */
	unsigned long offline_fqs;	/* Kicked due to being offline. */
	unsigned long cond_resched_completed;
					/* Grace period that needs help */
					/*  from cond_resched(). */

	/* 5) __rcu_pending() statistics. */
	unsigned long n_rcu_pending;	/* rcu_pending() calls since boot. */
	unsigned long n_rp_core_needs_qs;
	unsigned long n_rp_report_qs;
	unsigned long n_rp_cb_ready;
	unsigned long n_rp_cpu_needs_gp;
	unsigned long n_rp_gp_completed;
	unsigned long n_rp_gp_started;
	unsigned long n_rp_nocb_defer_wakeup;
	unsigned long n_rp_need_nothing;

	/* 6) _rcu_barrier(), OOM callbacks, and expediting. */
	struct rcu_head barrier_head;
#ifdef CONFIG_RCU_FAST_NO_HZ
	struct rcu_head oom_head;
#endif /* #ifdef CONFIG_RCU_FAST_NO_HZ */
	atomic_long_t exp_workdone0;	/* # done by workqueue. */
	atomic_long_t exp_workdone1;	/* # done by others #1. */
	atomic_long_t exp_workdone2;	/* # done by others #2. */
	atomic_long_t exp_workdone3;	/* # done by others #3. */

	/* 7) Callback offloading. */
#ifdef CONFIG_RCU_NOCB_CPU
	struct rcu_head *nocb_head;	/* CBs waiting for kthread. */
	struct rcu_head **nocb_tail;
	atomic_long_t nocb_q_count;	/* # CBs waiting for nocb */
	atomic_long_t nocb_q_count_lazy; /*  invocation (all stages). */
	struct rcu_head *nocb_follower_head; /* CBs ready to invoke. */
	struct rcu_head **nocb_follower_tail;
	struct swait_queue_head nocb_wq; /* For nocb kthreads to sleep on. */
	struct task_struct *nocb_kthread;
	int nocb_defer_wakeup;		/* Defer wakeup of nocb_kthread. */

	/* The following fields are used by the leader, hence own cacheline. */
	struct rcu_head *nocb_gp_head ____cacheline_internodealigned_in_smp;
					/* CBs waiting for GP. */
	struct rcu_head **nocb_gp_tail;
	bool nocb_leader_sleep;		/* Is the nocb leader thread asleep? */
	struct rcu_data *nocb_next_follower;
					/* Next follower in wakeup chain. */

	/* The following fields are used by the follower, hence new cachline. */
	struct rcu_data *nocb_leader ____cacheline_internodealigned_in_smp;
					/* Leader CPU takes GP-end wakeups. */
#endif /* #ifdef CONFIG_RCU_NOCB_CPU */

	/* 8) RCU CPU stall data. */
	unsigned int softirq_snap;	/* Snapshot of softirq activity. */
	/* 指向rcu_data所属的CPU ID */
	int cpu;
	/* 指向rcu_state数据结构 */
	struct rcu_state *rsp;
};

/* Values for nocb_defer_wakeup field in struct rcu_data. */
#define RCU_NOGP_WAKE_NOT	0
#define RCU_NOGP_WAKE		1
#define RCU_NOGP_WAKE_FORCE	2

#define RCU_JIFFIES_TILL_FORCE_QS (1 + (HZ > 250) + (HZ > 500))
					/* For jiffies_till_first_fqs and */
					/*  and jiffies_till_next_fqs. */

#define RCU_JIFFIES_FQS_DIV	256	/* Very large systems need more */
					/*  delay between bouts of */
					/*  quiescent-state forcing. */

#define RCU_STALL_RAT_DELAY	2	/* Allow other CPUs time to take */
					/*  at least one scheduling clock */
					/*  irq before ratting on them. */

#define rcu_wait(cond)							\
do {									\
	for (;;) {							\
		set_current_state(TASK_INTERRUPTIBLE);			\
		if (cond)						\
			break;						\
		schedule();						\
	}								\
	__set_current_state(TASK_RUNNING);				\
} while (0)

/*
 * RCU global state, including node hierarchy.  This hierarchy is
 * represented in "heap" form in a dense array.  The root (first level)
 * of the hierarchy is in ->node[0] (referenced by ->level[0]), the second
 * level in ->node[1] through ->node[m] (->node[1] referenced by ->level[1]),
 * and the third level in ->node[m+1] and following (->node[m+1] referenced
 * by ->level[2]).  The number of levels is determined by the number of
 * CPUs and by CONFIG_RCU_FANOUT.  Small systems will have a "hierarchy"
 * consisting of a single rcu_node.
 */
/* RCU系统支持多个不同类型的RCU状态，例如rcu_sched_stat、rcu_bh_state和
 * rcu_preempt_state，它们分别使用struct rcu_state数据结构来描述这些状态。
 * 每种RCU类型都有独立的层次结构，即根节点和rcu_data数据结构
 */
struct rcu_state {
	/* 所有的rcu_node节点都放在此数组中，方便进行全部的节点扫描，
	 * 例如rcu_for_each_node_breadth_frist宏
	 */
	struct rcu_node node[NUM_RCU_NODES];	/* Hierarchy. */
	/* 指针数组，每个成员指向Tree RCU每一层中的第一个rcu_node节点 */
	struct rcu_node *level[RCU_NUM_LVLS + 1];
						/* Hierarchy levels (+1 to */
						/*  shut bogus gcc warning) */
	u8 flavor_mask;				/* bit in flavor mask. */
	/* 指向rcu_data的Per-CPU变量 */
	struct rcu_data __percpu *rda;		/* pointer of percu rcu_data. */
	/* 指向RCU的call_rcu_sched()、call_rcu_bh和call_rcu函数 */
	call_rcu_func_t call;			/* call_rcu() flavor. */
	int ncpus;				/* # CPUs seen so far. */

	/* The following fields are guarded by the root rcu_node's lock. */

	u8	boost ____cacheline_internodealigned_in_smp;
						/* Subject to priority boost. */
	unsigned long gpnum;			/* Current gp number. */
	unsigned long completed;		/* # of last completed gp. */
	/* RCU内核线程，处理函数为rcu_gp_kthread */
	struct task_struct *gp_kthread;		/* Task for grace periods. */
	/* 在RCU内核线程中管理睡眠唤醒的等待队列 */
	struct swait_queue_head gp_wq;		/* Where GP task waits. */
	short gp_flags;				/* Commands for GP task. */
	/* 管理RCU内核线程睡眠唤醒的状态 */
	short gp_state;				/* GP kthread sleep state. */

	/* End of fields guarded by root rcu_node's lock. */

	raw_spinlock_t orphan_lock ____cacheline_internodealigned_in_smp;
						/* Protect following fields. */
	struct rcu_head *orphan_nxtlist;	/* Orphaned callbacks that */
						/*  need a grace period. */
	struct rcu_head **orphan_nxttail;	/* Tail of above. */
	struct rcu_head *orphan_donelist;	/* Orphaned callbacks that */
						/*  are ready to invoke. */
	struct rcu_head **orphan_donetail;	/* Tail of above. */
	long qlen_lazy;				/* Number of lazy callbacks. */
	long qlen;				/* Total number of callbacks. */
	/* End of fields guarded by orphan_lock. */

	struct mutex barrier_mutex;		/* Guards barrier fields. */
	atomic_t barrier_cpu_count;		/* # CPUs waiting on. */
	struct completion barrier_completion;	/* Wake at barrier end. */
	unsigned long barrier_sequence;		/* ++ at start and end of */
						/*  _rcu_barrier(). */
	/* End of fields guarded by barrier_mutex. */

	struct mutex exp_mutex;			/* Serialize expedited GP. */
	struct mutex exp_wake_mutex;		/* Serialize wakeup. */
	unsigned long expedited_sequence;	/* Take a ticket. */
	atomic_long_t expedited_normal;		/* # fallbacks to normal. */
	atomic_t expedited_need_qs;		/* # CPUs left to check in. */
	struct swait_queue_head expedited_wq;	/* Wait for check-ins. */
	int ncpus_snap;				/* # CPUs seen last time. */

	unsigned long jiffies_force_qs;		/* Time at which to invoke */
						/*  force_quiescent_state(). */
	unsigned long jiffies_kick_kthreads;	/* Time at which to kick */
						/*  kthreads, if configured. */
	unsigned long n_force_qs;		/* Number of calls to */
						/*  force_quiescent_state(). */
	unsigned long n_force_qs_lh;		/* ~Number of calls leaving */
						/*  due to lock unavailable. */
	unsigned long n_force_qs_ngp;		/* Number of calls leaving */
						/*  due to no GP active. */
	unsigned long gp_start;			/* Time at which GP started, */
						/*  but in jiffies. */
	unsigned long gp_activity;		/* Time of last GP kthread */
						/*  activity in jiffies. */
	unsigned long jiffies_stall;		/* Time at which to check */
						/*  for CPU stalls. */
	unsigned long jiffies_resched;		/* Time at which to resched */
						/*  a reluctant CPU. */
	unsigned long n_force_qs_gpstart;	/* Snapshot of n_force_qs at */
						/*  GP start. */
	unsigned long gp_max;			/* Maximum GP duration in */
						/*  jiffies. */
	/* 该rcu_state的名字 */
	const char *name;			/* Name of structure. */
	char abbr;				/* Abbreviated name. */
	/* 几个独立的rcu_state串成的一个链表 */
	struct list_head flavors;		/* List of RCU flavors. */
};

/* Values for rcu_state structure's gp_flags field. */
#define RCU_GP_FLAG_INIT 0x1	/* Need grace-period initialization. */
#define RCU_GP_FLAG_FQS  0x2	/* Need grace-period quiescent-state forcing. */

/* Values for rcu_state structure's gp_state field. */
#define RCU_GP_IDLE	 0	/* Initial state and no GP in progress. */
#define RCU_GP_WAIT_GPS  1	/* Wait for grace-period start. */
#define RCU_GP_DONE_GPS  2	/* Wait done for grace-period start. */
#define RCU_GP_WAIT_FQS  3	/* Wait for force-quiescent-state time. */
#define RCU_GP_DOING_FQS 4	/* Wait done for force-quiescent-state time. */
#define RCU_GP_CLEANUP   5	/* Grace-period cleanup started. */
#define RCU_GP_CLEANED   6	/* Grace-period cleanup complete. */

#ifndef RCU_TREE_NONCORE
static const char * const gp_state_names[] = {
	"RCU_GP_IDLE",
	"RCU_GP_WAIT_GPS",
	"RCU_GP_DONE_GPS",
	"RCU_GP_WAIT_FQS",
	"RCU_GP_DOING_FQS",
	"RCU_GP_CLEANUP",
	"RCU_GP_CLEANED",
};
#endif /* #ifndef RCU_TREE_NONCORE */

extern struct list_head rcu_struct_flavors;

/* Sequence through rcu_state structures for each RCU flavor. */
#define for_each_rcu_flavor(rsp) \
	list_for_each_entry((rsp), &rcu_struct_flavors, flavors)

/*
 * RCU implementation internal declarations:
 */
extern struct rcu_state rcu_sched_state;

extern struct rcu_state rcu_bh_state;

#ifdef CONFIG_PREEMPT_RCU
extern struct rcu_state rcu_preempt_state;
#endif /* #ifdef CONFIG_PREEMPT_RCU */

#ifdef CONFIG_RCU_BOOST
DECLARE_PER_CPU(unsigned int, rcu_cpu_kthread_status);
DECLARE_PER_CPU(int, rcu_cpu_kthread_cpu);
DECLARE_PER_CPU(unsigned int, rcu_cpu_kthread_loops);
DECLARE_PER_CPU(char, rcu_cpu_has_work);
#endif /* #ifdef CONFIG_RCU_BOOST */

#ifndef RCU_TREE_NONCORE

/* Forward declarations for rcutree_plugin.h */
static void rcu_bootup_announce(void);
static void rcu_preempt_note_context_switch(void);
static int rcu_preempt_blocked_readers_cgp(struct rcu_node *rnp);
#ifdef CONFIG_HOTPLUG_CPU
static bool rcu_preempt_has_tasks(struct rcu_node *rnp);
#endif /* #ifdef CONFIG_HOTPLUG_CPU */
static void rcu_print_detail_task_stall(struct rcu_state *rsp);
static int rcu_print_task_stall(struct rcu_node *rnp);
static int rcu_print_task_exp_stall(struct rcu_node *rnp);
static void rcu_preempt_check_blocked_tasks(struct rcu_node *rnp);
static void rcu_preempt_check_callbacks(void);
void call_rcu(struct rcu_head *head, rcu_callback_t func);
static void __init __rcu_init_preempt(void);
static void rcu_initiate_boost(struct rcu_node *rnp, unsigned long flags);
static void rcu_preempt_boost_start_gp(struct rcu_node *rnp);
static void invoke_rcu_callbacks_kthread(void);
static bool rcu_is_callbacks_kthread(void);
#ifdef CONFIG_RCU_BOOST
static void rcu_preempt_do_callbacks(void);
static int rcu_spawn_one_boost_kthread(struct rcu_state *rsp,
						 struct rcu_node *rnp);
#endif /* #ifdef CONFIG_RCU_BOOST */
static void __init rcu_spawn_boost_kthreads(void);
static void rcu_prepare_kthreads(int cpu);
static void rcu_cleanup_after_idle(void);
static void rcu_prepare_for_idle(void);
static void rcu_idle_count_callbacks_posted(void);
static bool rcu_preempt_has_tasks(struct rcu_node *rnp);
static void print_cpu_stall_info_begin(void);
static void print_cpu_stall_info(struct rcu_state *rsp, int cpu);
static void print_cpu_stall_info_end(void);
static void zero_cpu_stall_ticks(struct rcu_data *rdp);
static void increment_cpu_stall_ticks(void);
static bool rcu_nocb_cpu_needs_barrier(struct rcu_state *rsp, int cpu);
static void rcu_nocb_gp_set(struct rcu_node *rnp, int nrq);
static struct swait_queue_head *rcu_nocb_gp_get(struct rcu_node *rnp);
static void rcu_nocb_gp_cleanup(struct swait_queue_head *sq);
static void rcu_init_one_nocb(struct rcu_node *rnp);
static bool __call_rcu_nocb(struct rcu_data *rdp, struct rcu_head *rhp,
			    bool lazy, unsigned long flags);
static bool rcu_nocb_adopt_orphan_cbs(struct rcu_state *rsp,
				      struct rcu_data *rdp,
				      unsigned long flags);
static int rcu_nocb_need_deferred_wakeup(struct rcu_data *rdp);
static void do_nocb_deferred_wakeup(struct rcu_data *rdp);
static void rcu_boot_init_nocb_percpu_data(struct rcu_data *rdp);
static void rcu_spawn_all_nocb_kthreads(int cpu);
static void __init rcu_spawn_nocb_kthreads(void);
#ifdef CONFIG_RCU_NOCB_CPU
static void __init rcu_organize_nocb_kthreads(struct rcu_state *rsp);
#endif /* #ifdef CONFIG_RCU_NOCB_CPU */
static void __maybe_unused rcu_kick_nohz_cpu(int cpu);
static bool init_nocb_callback_list(struct rcu_data *rdp);
static void rcu_sysidle_enter(int irq);
static void rcu_sysidle_exit(int irq);
static void rcu_sysidle_check_cpu(struct rcu_data *rdp, bool *isidle,
				  unsigned long *maxj);
static bool is_sysidle_rcu_state(struct rcu_state *rsp);
static void rcu_sysidle_report_gp(struct rcu_state *rsp, int isidle,
				  unsigned long maxj);
static void rcu_bind_gp_kthread(void);
static void rcu_sysidle_init_percpu_data(struct rcu_dynticks *rdtp);
static bool rcu_nohz_full_cpu(struct rcu_state *rsp);
static void rcu_dynticks_task_enter(void);
static void rcu_dynticks_task_exit(void);

#endif /* #ifndef RCU_TREE_NONCORE */

#ifdef CONFIG_RCU_TRACE
/* Read out queue lengths for tracing. */
static inline void rcu_nocb_q_lengths(struct rcu_data *rdp, long *ql, long *qll)
{
#ifdef CONFIG_RCU_NOCB_CPU
	*ql = atomic_long_read(&rdp->nocb_q_count);
	*qll = atomic_long_read(&rdp->nocb_q_count_lazy);
#else /* #ifdef CONFIG_RCU_NOCB_CPU */
	*ql = 0;
	*qll = 0;
#endif /* #else #ifdef CONFIG_RCU_NOCB_CPU */
}
#endif /* #ifdef CONFIG_RCU_TRACE */

/*
 * Place this after a lock-acquisition primitive to guarantee that
 * an UNLOCK+LOCK pair act as a full barrier.  This guarantee applies
 * if the UNLOCK and LOCK are executed by the same CPU or if the
 * UNLOCK and LOCK operate on the same lock variable.
 */
#ifdef CONFIG_PPC
#define smp_mb__after_unlock_lock()	smp_mb()  /* Full ordering for lock. */
#else /* #ifdef CONFIG_PPC */
#define smp_mb__after_unlock_lock()	do { } while (0)
#endif /* #else #ifdef CONFIG_PPC */

/*
 * Wrappers for the rcu_node::lock acquire and release.
 *
 * Because the rcu_nodes form a tree, the tree traversal locking will observe
 * different lock values, this in turn means that an UNLOCK of one level
 * followed by a LOCK of another level does not imply a full memory barrier;
 * and most importantly transitivity is lost.
 *
 * In order to restore full ordering between tree levels, augment the regular
 * lock acquire functions with smp_mb__after_unlock_lock().
 *
 * As ->lock of struct rcu_node is a __private field, therefore one should use
 * these wrappers rather than directly call raw_spin_{lock,unlock}* on ->lock.
 */
static inline void raw_spin_lock_rcu_node(struct rcu_node *rnp)
{
	raw_spin_lock(&ACCESS_PRIVATE(rnp, lock));
	smp_mb__after_unlock_lock();
}

static inline void raw_spin_unlock_rcu_node(struct rcu_node *rnp)
{
	raw_spin_unlock(&ACCESS_PRIVATE(rnp, lock));
}

static inline void raw_spin_lock_irq_rcu_node(struct rcu_node *rnp)
{
	raw_spin_lock_irq(&ACCESS_PRIVATE(rnp, lock));
	smp_mb__after_unlock_lock();
}

static inline void raw_spin_unlock_irq_rcu_node(struct rcu_node *rnp)
{
	raw_spin_unlock_irq(&ACCESS_PRIVATE(rnp, lock));
}

#define raw_spin_lock_irqsave_rcu_node(rnp, flags)			\
do {									\
	typecheck(unsigned long, flags);				\
	raw_spin_lock_irqsave(&ACCESS_PRIVATE(rnp, lock), flags);	\
	smp_mb__after_unlock_lock();					\
} while (0)

#define raw_spin_unlock_irqrestore_rcu_node(rnp, flags)			\
do {									\
	typecheck(unsigned long, flags);				\
	raw_spin_unlock_irqrestore(&ACCESS_PRIVATE(rnp, lock), flags);	\
} while (0)

static inline bool raw_spin_trylock_rcu_node(struct rcu_node *rnp)
{
	bool locked = raw_spin_trylock(&ACCESS_PRIVATE(rnp, lock));

	if (locked)
		smp_mb__after_unlock_lock();
	return locked;
}
