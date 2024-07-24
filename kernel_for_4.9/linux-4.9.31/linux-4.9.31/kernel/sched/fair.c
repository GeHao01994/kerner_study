/*
 * Completely Fair Scheduling (CFS) Class (SCHED_NORMAL/SCHED_BATCH)
 *
 *  Copyright (C) 2007 Red Hat, Inc., Ingo Molnar <mingo@redhat.com>
 *
 *  Interactivity improvements by Mike Galbraith
 *  (C) 2007 Mike Galbraith <efault@gmx.de>
 *
 *  Various enhancements by Dmitry Adamushko.
 *  (C) 2007 Dmitry Adamushko <dmitry.adamushko@gmail.com>
 *
 *  Group scheduling enhancements by Srivatsa Vaddagiri
 *  Copyright IBM Corporation, 2007
 *  Author: Srivatsa Vaddagiri <vatsa@linux.vnet.ibm.com>
 *
 *  Scaled math optimizations by Thomas Gleixner
 *  Copyright (C) 2007, Thomas Gleixner <tglx@linutronix.de>
 *
 *  Adaptive scheduling granularity, math enhancements by Peter Zijlstra
 *  Copyright (C) 2007 Red Hat, Inc., Peter Zijlstra
 */

#include <linux/sched.h>
#include <linux/latencytop.h>
#include <linux/cpumask.h>
#include <linux/cpuidle.h>
#include <linux/slab.h>
#include <linux/profile.h>
#include <linux/interrupt.h>
#include <linux/mempolicy.h>
#include <linux/migrate.h>
#include <linux/task_work.h>

#include <trace/events/sched.h>

#include "sched.h"

/*
 * Targeted preemption latency for CPU-bound tasks:
 * (default: 6ms * (1 + ilog(ncpus)), units: nanoseconds)
 *
 * NOTE: this latency value is not the same as the concept of
 * 'timeslice length' - timeslices in CFS are of variable length
 * and have no persistent notion like in traditional, time-slice
 * based scheduling concepts.
 *
 * (to see the precise effective timeslice length of your workload,
 *  run vmstat and monitor the context-switches (cs) field)
 */
unsigned int sysctl_sched_latency = 6000000ULL;
unsigned int normalized_sysctl_sched_latency = 6000000ULL;

/*
 * The initial- and re-scaling of tunables is configurable
 * (default SCHED_TUNABLESCALING_LOG = *(1+ilog(ncpus))
 *
 * Options are:
 * SCHED_TUNABLESCALING_NONE - unscaled, always *1
 * SCHED_TUNABLESCALING_LOG - scaled logarithmical, *1+ilog(ncpus)
 * SCHED_TUNABLESCALING_LINEAR - scaled linear, *ncpus
 */
enum sched_tunable_scaling sysctl_sched_tunable_scaling
	= SCHED_TUNABLESCALING_LOG;

/*
 * Minimal preemption granularity for CPU-bound tasks:
 * (default: 0.75 msec * (1 + ilog(ncpus)), units: nanoseconds)
 */
unsigned int sysctl_sched_min_granularity = 750000ULL;
unsigned int normalized_sysctl_sched_min_granularity = 750000ULL;

/*
 * is kept at sysctl_sched_latency / sysctl_sched_min_granularity
 */
static unsigned int sched_nr_latency = 8;

/*
 * After fork, child runs first. If set to 0 (default) then
 * parent will (try to) run first.
 */
unsigned int sysctl_sched_child_runs_first __read_mostly;

/*
 * SCHED_OTHER wake-up granularity.
 * (default: 1 msec * (1 + ilog(ncpus)), units: nanoseconds)
 *
 * This option delays the preemption effects of decoupled workloads
 * and reduces their over-scheduling. Synchronous workloads will still
 * have immediate wakeup/sleep latencies.
 *
 * SCHED_OTHER唤醒粒度.
 *
 * (默认值：1毫秒*（1+ilog（ncpus)), 单位:纳秒)
 *
 * 此选项延迟了解耦工作负载的抢占效应,并减少了它们的过度调度.
 * 同步工作负载仍将具有即时唤醒/睡眠延迟.
 */
unsigned int sysctl_sched_wakeup_granularity = 1000000UL;
unsigned int normalized_sysctl_sched_wakeup_granularity = 1000000UL;

const_debug unsigned int sysctl_sched_migration_cost = 500000UL;

/*
 * The exponential sliding  window over which load is averaged for shares
 * distribution.
 * (default: 10msec)
 */
unsigned int __read_mostly sysctl_sched_shares_window = 10000000UL;

#ifdef CONFIG_CFS_BANDWIDTH
/*
 * Amount of runtime to allocate from global (tg) to local (per-cfs_rq) pool
 * each time a cfs_rq requests quota.
 *
 * Note: in the case that the slice exceeds the runtime remaining (either due
 * to consumption or the quota being specified to be smaller than the slice)
 * we will always only issue the remaining available time.
 *
 * default: 5 msec, units: microseconds
  */
unsigned int sysctl_sched_cfs_bandwidth_slice = 5000UL;
#endif

/*
 * The margin used when comparing utilization with CPU capacity:
 * util * 1024 < capacity * margin
 *
 * 将利用率与CPU容量进行比较时使用的余量: util * 1024 < capacity * margin
 */
unsigned int capacity_margin = 1280; /* ~20% */

static inline void update_load_add(struct load_weight *lw, unsigned long inc)
{
	lw->weight += inc;
	lw->inv_weight = 0;
}

static inline void update_load_sub(struct load_weight *lw, unsigned long dec)
{
	lw->weight -= dec;
	lw->inv_weight = 0;
}

static inline void update_load_set(struct load_weight *lw, unsigned long w)
{
	lw->weight = w;
	lw->inv_weight = 0;
}

/*
 * Increase the granularity value when there are more CPUs,
 * because with more CPUs the 'effective latency' as visible
 * to users decreases. But the relationship is not linear,
 * so pick a second-best guess by going with the log2 of the
 * number of CPUs.
 *
 * This idea comes from the SD scheduler of Con Kolivas:
 */
static unsigned int get_update_sysctl_factor(void)
{
	unsigned int cpus = min_t(unsigned int, num_online_cpus(), 8);
	unsigned int factor;

	switch (sysctl_sched_tunable_scaling) {
	case SCHED_TUNABLESCALING_NONE:
		factor = 1;
		break;
	case SCHED_TUNABLESCALING_LINEAR:
		factor = cpus;
		break;
	case SCHED_TUNABLESCALING_LOG:
	default:
		factor = 1 + ilog2(cpus);
		break;
	}

	return factor;
}

static void update_sysctl(void)
{
	unsigned int factor = get_update_sysctl_factor();

#define SET_SYSCTL(name) \
	(sysctl_##name = (factor) * normalized_sysctl_##name)
	SET_SYSCTL(sched_min_granularity);
	SET_SYSCTL(sched_latency);
	SET_SYSCTL(sched_wakeup_granularity);
#undef SET_SYSCTL
}

void sched_init_granularity(void)
{
	update_sysctl();
}

#define WMULT_CONST	(~0U)
#define WMULT_SHIFT	32

static void __update_inv_weight(struct load_weight *lw)
{
	unsigned long w;

	if (likely(lw->inv_weight))
		return;

	w = scale_load_down(lw->weight);

	if (BITS_PER_LONG > 32 && unlikely(w >= WMULT_CONST))
		lw->inv_weight = 1;
	else if (unlikely(!w))
		lw->inv_weight = WMULT_CONST;
	else
		lw->inv_weight = WMULT_CONST / w;
}

/*
 * delta_exec * weight / lw.weight
 *   OR
 * (delta_exec * (weight * lw->inv_weight)) >> WMULT_SHIFT
 *
 * Either weight := NICE_0_LOAD and lw \e sched_prio_to_wmult[], in which case
 * we're guaranteed shift stays positive because inv_weight is guaranteed to
 * fit 32 bits, and NICE_0_LOAD gives another 10 bits; therefore shift >= 22.
 *
 * Or, weight =< lw.weight (because lw.weight is the runqueue weight), thus
 * weight/lw.weight <= 1, and therefore our shift will also be positive.
 *
 * delta_exec * weight / lw.weight
 *   OR
 * (delta_exec * (weight * lw->inv_weight)) >> WMULT_SHIFT
 *
 * 任一权重 := NICE_0_LOAD 和lw \e sched_prio_to_wmult[],
 * 在这种情况下,我们保证移位保持积极乐观的,因为inv_weight保证适合32位,
 * 并且NICE_0_LOAD给出另外10位; 因此移位 >= 22.
 *
 * 或者,weight =< lw.weight(因为lw.weight 是运行队列的权重),因此weight/lw.weight <= 1,因此我们的偏移也将是正的.
 */
/* vruntime = (delta_exec * nice_0_weight) / weight
 * 因为上述公式会涉及浮点运算,为了计算高效,函数calc_delta_fair的计算公式变成乘法和移位运算公式如下:
 * vruntime = (delta_exec * nice_0_weight * inv_weight) >> shift
 * 把inv_weight带入计算公式后,得到如下计算公式:
 * vruntime = (delta_exec * nice_0_weight * 2^32 / weight ) >> 32
 * 所以下面这就是对这个公式的计算
 */
static u64 __calc_delta(u64 delta_exec, unsigned long weight, struct load_weight *lw)
{
	u64 fact = scale_load_down(weight);
	/* #define WMULT_SHIFT	32 */
	int shift = WMULT_SHIFT;

	__update_inv_weight(lw);

	if (unlikely(fact >> 32)) {
		while (fact >> 32) {
			fact >>= 1;
			shift--;
		}
	}

	/* hint to use a 32x32->64 mul */
	fact = (u64)(u32)fact * lw->inv_weight;

	while (fact >> 32) {
		fact >>= 1;
		shift--;
	}

	return mul_u64_u32_shr(delta_exec, fact, shift);
}


const struct sched_class fair_sched_class;

/**************************************************************
 * CFS operations on generic schedulable entities:
 */

#ifdef CONFIG_FAIR_GROUP_SCHED

/* cpu runqueue to which this cfs_rq is attached */
static inline struct rq *rq_of(struct cfs_rq *cfs_rq)
{
	return cfs_rq->rq;
}

/* An entity is a task if it doesn't "own" a runqueue */
#define entity_is_task(se)	(!se->my_q)

static inline struct task_struct *task_of(struct sched_entity *se)
{
	SCHED_WARN_ON(!entity_is_task(se));
	return container_of(se, struct task_struct, se);
}

/* Walk up scheduling entities hierarchy */
#define for_each_sched_entity(se) \
		for (; se; se = se->parent)

static inline struct cfs_rq *task_cfs_rq(struct task_struct *p)
{
	return p->se.cfs_rq;
}

/* runqueue on which this entity is (to be) queued */
static inline struct cfs_rq *cfs_rq_of(struct sched_entity *se)
{
	return se->cfs_rq;
}

/* runqueue "owned" by this group */
static inline struct cfs_rq *group_cfs_rq(struct sched_entity *grp)
{
	return grp->my_q;
}

static inline void list_add_leaf_cfs_rq(struct cfs_rq *cfs_rq)
{
	if (!cfs_rq->on_list) {
		/*
		 * Ensure we either appear before our parent (if already
		 * enqueued) or force our parent to appear after us when it is
		 * enqueued.  The fact that we always enqueue bottom-up
		 * reduces this to two cases.
		 */
		if (cfs_rq->tg->parent &&
		    cfs_rq->tg->parent->cfs_rq[cpu_of(rq_of(cfs_rq))]->on_list) {
			list_add_rcu(&cfs_rq->leaf_cfs_rq_list,
				&rq_of(cfs_rq)->leaf_cfs_rq_list);
		} else {
			list_add_tail_rcu(&cfs_rq->leaf_cfs_rq_list,
				&rq_of(cfs_rq)->leaf_cfs_rq_list);
		}

		cfs_rq->on_list = 1;
	}
}

static inline void list_del_leaf_cfs_rq(struct cfs_rq *cfs_rq)
{
	if (cfs_rq->on_list) {
		list_del_rcu(&cfs_rq->leaf_cfs_rq_list);
		cfs_rq->on_list = 0;
	}
}

/* Iterate thr' all leaf cfs_rq's on a runqueue */
#define for_each_leaf_cfs_rq(rq, cfs_rq) \
	list_for_each_entry_rcu(cfs_rq, &rq->leaf_cfs_rq_list, leaf_cfs_rq_list)

/* Do the two (enqueued) entities belong to the same group ? */
static inline struct cfs_rq *
is_same_group(struct sched_entity *se, struct sched_entity *pse)
{
	if (se->cfs_rq == pse->cfs_rq)
		return se->cfs_rq;

	return NULL;
}

static inline struct sched_entity *parent_entity(struct sched_entity *se)
{
	return se->parent;
}

static void
find_matching_se(struct sched_entity **se, struct sched_entity **pse)
{
	int se_depth, pse_depth;

	/*
	 * preemption test can be made between sibling entities who are in the
	 * same cfs_rq i.e who have a common parent. Walk up the hierarchy of
	 * both tasks until we find their ancestors who are siblings of common
	 * parent.
	 */

	/* First walk up until both entities are at same depth */
	se_depth = (*se)->depth;
	pse_depth = (*pse)->depth;

	while (se_depth > pse_depth) {
		se_depth--;
		*se = parent_entity(*se);
	}

	while (pse_depth > se_depth) {
		pse_depth--;
		*pse = parent_entity(*pse);
	}

	while (!is_same_group(*se, *pse)) {
		*se = parent_entity(*se);
		*pse = parent_entity(*pse);
	}
}

#else	/* !CONFIG_FAIR_GROUP_SCHED */

static inline struct task_struct *task_of(struct sched_entity *se)
{
	return container_of(se, struct task_struct, se);
}

static inline struct rq *rq_of(struct cfs_rq *cfs_rq)
{
	return container_of(cfs_rq, struct rq, cfs);
}

#define entity_is_task(se)	1

#define for_each_sched_entity(se) \
		for (; se; se = NULL)

static inline struct cfs_rq *task_cfs_rq(struct task_struct *p)
{
	return &task_rq(p)->cfs;
}

static inline struct cfs_rq *cfs_rq_of(struct sched_entity *se)
{
	struct task_struct *p = task_of(se);
	struct rq *rq = task_rq(p);

	return &rq->cfs;
}

/* runqueue "owned" by this group */
static inline struct cfs_rq *group_cfs_rq(struct sched_entity *grp)
{
	return NULL;
}

static inline void list_add_leaf_cfs_rq(struct cfs_rq *cfs_rq)
{
}

static inline void list_del_leaf_cfs_rq(struct cfs_rq *cfs_rq)
{
}

#define for_each_leaf_cfs_rq(rq, cfs_rq) \
		for (cfs_rq = &rq->cfs; cfs_rq; cfs_rq = NULL)

static inline struct sched_entity *parent_entity(struct sched_entity *se)
{
	return NULL;
}

static inline void
find_matching_se(struct sched_entity **se, struct sched_entity **pse)
{
}

#endif	/* CONFIG_FAIR_GROUP_SCHED */

static __always_inline
void account_cfs_rq_runtime(struct cfs_rq *cfs_rq, u64 delta_exec);

/**************************************************************
 * Scheduling class tree data structure manipulation methods:
 */

static inline u64 max_vruntime(u64 max_vruntime, u64 vruntime)
{
	s64 delta = (s64)(vruntime - max_vruntime);
	if (delta > 0)
		max_vruntime = vruntime;

	return max_vruntime;
}

static inline u64 min_vruntime(u64 min_vruntime, u64 vruntime)
{
	s64 delta = (s64)(vruntime - min_vruntime);
	if (delta < 0)
		min_vruntime = vruntime;

	return min_vruntime;
}

static inline int entity_before(struct sched_entity *a,
				struct sched_entity *b)
{
	return (s64)(a->vruntime - b->vruntime) < 0;
}

static void update_min_vruntime(struct cfs_rq *cfs_rq)
{
	/* 拿到当前cfs_rq的运行的sched_entity
	 * 如果是fork的话,那么这里指的就是父进程
	 */
	struct sched_entity *curr = cfs_rq->curr;

	/* 拿到该cfs_rq最小的vruntime */
	u64 vruntime = cfs_rq->min_vruntime;

	/* 如果当前cfs_rq有正在运行的sched_entity */
	if (curr) {
		/* 如果当前sched_entity在rq上 */
		if (curr->on_rq)	/* vruntime = curr->vruntime */
			vruntime = curr->vruntime;
		else
			curr = NULL;
	}
	/* 函数本身并不会遍历数找到最左叶子节点(即就是所有进程中vruntime最小的那个),因为该值已经缓存在rb_leftmost字段中 */
	if (cfs_rq->rb_leftmost) {
		struct sched_entity *se = rb_entry(cfs_rq->rb_leftmost,
						   struct sched_entity,
						   run_node);
		/* 如果curr没有值,那么vruntime就是se->vruntime */
		if (!curr)
			vruntime = se->vruntime;
		else	/* 如果有值,那么vruntime就是vruntime和se->vruntime中最小的那个 */
			vruntime = min_vruntime(vruntime, se->vruntime);
	}

	/* ensure we never gain time by being placed backwards.
	 * 确保我们永远不会因为落后而获得时间.
	 */
	/* min_vruntime算出cfs_rq->min_vruntime 和 vruntime的最大值??? */
	/* 由于正常情况当前运行进程的vruntime,应该比就绪队列中其它调度实体的值要小.
	 * 但也有一些特殊情况,如睡眠进程唤醒后获得了奖励,从而使其加入就绪队列后比当前进程的vruntime值更小.
	 * 因此,最小运行时间需要通过比较它们的值来确定
	 * 与cfs_rq->min_vruntime比较,将较大值赋给cfs_rq->min_vruntime,这样可以保证cfs_rq->min_vruntime推进的同时不会倒流
	 * 也就是说内核保证min_vruntime只能增加不能减少
	 */
	cfs_rq->min_vruntime = max_vruntime(cfs_rq->min_vruntime, vruntime);
#ifndef CONFIG_64BIT
	smp_wmb();
	cfs_rq->min_vruntime_copy = cfs_rq->min_vruntime;
#endif
}

/*
 * Enqueue an entity into the rb-tree:
 */
static void __enqueue_entity(struct cfs_rq *cfs_rq, struct sched_entity *se)
{
	struct rb_node **link = &cfs_rq->tasks_timeline.rb_node;
	struct rb_node *parent = NULL;
	struct sched_entity *entry;
	int leftmost = 1;

	/*
	 * Find the right place in the rbtree:
	 *
	 * 在rbtree中找到正确的位置
	 */
	while (*link) {
		parent = *link;
		/* 通过run_node找到sched_entity */
		entry = rb_entry(parent, struct sched_entity, run_node);
		/*
		 * We dont care about collisions. Nodes with
		 * the same key stay together.
		 *
		 * 我们不在乎碰撞. 具有相同密钥的节点保持在一起.
		 */

		/* static inline int entity_before(struct sched_entity *a,
		 *				   struct sched_entity *b)
		 * {
		 *	return (s64)(a->vruntime - b->vruntime) < 0;
		 * }
		 *
		 * 如果a->vruntime小于b->vruntime,那么左边
		 */
		if (entity_before(se, entry)) {
			link = &parent->rb_left;
		} else {
			/* 否则是右边,那么就设置leftmost为0 */
			link = &parent->rb_right;
			leftmost = 0;
		}
	}

	/*
	 * Maintain a cache of leftmost tree entries (it is frequently
	 * used):
	 *
	 * 维护最左边树项的缓存(这是经常使用的):
	 */
	if (leftmost)
		cfs_rq->rb_leftmost = &se->run_node;

	/* 设置它的位置 */
	rb_link_node(&se->run_node, parent, link);
	rb_insert_color(&se->run_node, &cfs_rq->tasks_timeline);
}

static void __dequeue_entity(struct cfs_rq *cfs_rq, struct sched_entity *se)
{
	if (cfs_rq->rb_leftmost == &se->run_node) {
		struct rb_node *next_node;

		next_node = rb_next(&se->run_node);
		cfs_rq->rb_leftmost = next_node;
	}

	rb_erase(&se->run_node, &cfs_rq->tasks_timeline);
}

struct sched_entity *__pick_first_entity(struct cfs_rq *cfs_rq)
{
	struct rb_node *left = cfs_rq->rb_leftmost;

	if (!left)
		return NULL;

	return rb_entry(left, struct sched_entity, run_node);
}

static struct sched_entity *__pick_next_entity(struct sched_entity *se)
{
	struct rb_node *next = rb_next(&se->run_node);

	if (!next)
		return NULL;

	return rb_entry(next, struct sched_entity, run_node);
}

#ifdef CONFIG_SCHED_DEBUG
struct sched_entity *__pick_last_entity(struct cfs_rq *cfs_rq)
{
	struct rb_node *last = rb_last(&cfs_rq->tasks_timeline);

	if (!last)
		return NULL;

	return rb_entry(last, struct sched_entity, run_node);
}

/**************************************************************
 * Scheduling class statistics methods:
 */

int sched_proc_update_handler(struct ctl_table *table, int write,
		void __user *buffer, size_t *lenp,
		loff_t *ppos)
{
	int ret = proc_dointvec_minmax(table, write, buffer, lenp, ppos);
	unsigned int factor = get_update_sysctl_factor();

	if (ret || !write)
		return ret;

	sched_nr_latency = DIV_ROUND_UP(sysctl_sched_latency,
					sysctl_sched_min_granularity);

#define WRT_SYSCTL(name) \
	(normalized_sysctl_##name = sysctl_##name / (factor))
	WRT_SYSCTL(sched_min_granularity);
	WRT_SYSCTL(sched_latency);
	WRT_SYSCTL(sched_wakeup_granularity);
#undef WRT_SYSCTL

	return 0;
}
#endif

/*
 * delta /= w
 */
/* 这个函数实际上就是去计算vruntime
 * 计算公式为vruntime = (delta_exec * nice_0_weight)/weight
 */
static inline u64 calc_delta_fair(u64 delta, struct sched_entity *se)
{
	/* 所以说如果se->load.weight == NICE_0_LOAD
	 * 那么不需要进入__calc_delta
	 * 直接返回delta
	 */
	if (unlikely(se->load.weight != NICE_0_LOAD))
		delta = __calc_delta(delta, NICE_0_LOAD, &se->load);

	return delta;
}

/*
 * The idea is to set a period in which each task runs once.
 *
 * When there are too many tasks (sched_nr_latency) we have to stretch
 * this period because otherwise the slices get too small.
 *
 * p = (nr <= nl) ? l : l*nr/nl
 *
 * 其想法是设置一个周期,每个任务在该周期内运行一次.
 *
 * 当任务太多(sched_nr_latency)时,我们必须延长这段时间,否则时间片会变得太小.
 *
 * p=(nr <= nl) ? l : l * nr/nl
 */

/* __sched_period函数会计算CFS就绪队列中的一个调度周期的长度,可以理解为一个调度周期的时间片,
 * 它会根据当前运行的进程数目来计算.
 * CFS调度器有一个默认调度时间片,默认值为6毫秒,详见sysctl_sched_latency变量(/proc/sys/kernel/sched_min_granularity_ns)
 * 当运行中的进程数目大于8时,按照进程最小的调度延时sysctl_sched_min_granularity乘以进程数目来计算调度时间片.
 * 反之使用系统默认的调度时间片,即sysctl_sched_latency
 */
static u64 __sched_period(unsigned long nr_running)
{
	if (unlikely(nr_running > sched_nr_latency))
		return nr_running * sysctl_sched_min_granularity;
	else
		return sysctl_sched_latency;
}

/*
 * We calculate the wall-time slice from the period by taking a part
 * proportional to the weight.
 *
 * 我们通过取与权重成比例的部分来计算周期的wall-time时间片
 *
 * s = p*P[w/rw]
 */
/* sched_slice根据当前进程的权重来计算在CFS就绪队列总权重中可以瓜分到的调度时间 */
static u64 sched_slice(struct cfs_rq *cfs_rq, struct sched_entity *se)
{
	/* 拿到时间片 */
	u64 slice = __sched_period(cfs_rq->nr_running + !se->on_rq);

	/* 这里主要是考虑组调度,如果没有组调度,那么就只考虑他自己的sched_entity */
	for_each_sched_entity(se) {
		struct load_weight *load;
		struct load_weight lw;

		/* 拿到这个sched_entity的cfs_rq */
		cfs_rq = cfs_rq_of(se);
		/* 获取CFS就绪队列的总权重 */
		load = &cfs_rq->load;

		/* 如果调度实体不在就绪队列 struct rq 上,即se->on_rq = 0
		 * 这里用 unlikely 修饰代表这是小概率事件,通常该调度实体都在就绪队列 struct rq 上
		 */
		if (unlikely(!se->on_rq)) {
			/* 获取CFS就绪队列的总权重,赋值给lw */
			lw = cfs_rq->load;
			/* 那么CFS就绪队列的总权重加上该调度实体的权重
			 *
			 *  static inline void update_load_add(struct load_weight *lw, unsigned long inc)
			 * {
			 *	lw->weight += inc;
			 *	lw->inv_weight = 0;
			 * }
			 */
			update_load_add(&lw, se->load.weight);
			load = &lw;
			/* 实际上这里就是直接返回0了,因为下面的计算根本对我们的这个没有任何用处 */
		}
		/* 计算进程调度实体可以在CFS就绪队列总权重可以获取的调度周期 */
		slice = __calc_delta(slice, se->load.weight, load);
	}
	return slice;
}

/*
 * We calculate the vruntime slice of a to-be-inserted task.
 * 我们计算要插入的任务的vruntime惩罚.
 * vs = s/w
 */
static u64 sched_vslice(struct cfs_rq *cfs_rq, struct sched_entity *se)
{
	return calc_delta_fair(sched_slice(cfs_rq, se), se);
}

#ifdef CONFIG_SMP
static int select_idle_sibling(struct task_struct *p, int prev_cpu, int cpu);
static unsigned long task_h_load(struct task_struct *p);

/*
 * We choose a half-life close to 1 scheduling period.
 * Note: The tables runnable_avg_yN_inv and runnable_avg_yN_sum are
 * dependent on this value.
 */
#define LOAD_AVG_PERIOD 32
#define LOAD_AVG_MAX 47742 /* maximum possible load avg */
#define LOAD_AVG_MAX_N 345 /* number of full periods to produce LOAD_AVG_MAX */

/* Give new sched_entity start runnable values to heavy its load in infant time */
void init_entity_runnable_average(struct sched_entity *se)
{
	struct sched_avg *sa = &se->avg;

	sa->last_update_time = 0;
	/*
	 * sched_avg's period_contrib should be strictly less then 1024, so
	 * we give it 1023 to make sure it is almost a period (1024us), and
	 * will definitely be update (after enqueue).
	 */
	sa->period_contrib = 1023;
	/*
	 * Tasks are intialized with full load to be seen as heavy tasks until
	 * they get a chance to stabilize to their real load level.
	 * Group entities are intialized with zero load to reflect the fact that
	 * nothing has been attached to the task group yet.
	 */
	if (entity_is_task(se))
		sa->load_avg = scale_load_down(se->load.weight);
	sa->load_sum = sa->load_avg * LOAD_AVG_MAX;
	/*
	 * At this point, util_avg won't be used in select_task_rq_fair anyway
	 */
	sa->util_avg = 0;
	sa->util_sum = 0;
	/* when this task enqueue'ed, it will contribute to its cfs_rq's load_avg */
}

static inline u64 cfs_rq_clock_task(struct cfs_rq *cfs_rq);
static int update_cfs_rq_load_avg(u64 now, struct cfs_rq *cfs_rq, bool update_freq);
static void update_tg_load_avg(struct cfs_rq *cfs_rq, int force);
static void attach_entity_load_avg(struct cfs_rq *cfs_rq, struct sched_entity *se);

/*
 * With new tasks being created, their initial util_avgs are extrapolated
 * based on the cfs_rq's current util_avg:
 *
 *   util_avg = cfs_rq->util_avg / (cfs_rq->load_avg + 1) * se.load.weight
 *
 * However, in many cases, the above util_avg does not give a desired
 * value. Moreover, the sum of the util_avgs may be divergent, such
 * as when the series is a harmonic series.
 *
 * To solve this problem, we also cap the util_avg of successive tasks to
 * only 1/2 of the left utilization budget:
 *
 *   util_avg_cap = (1024 - cfs_rq->avg.util_avg) / 2^n
 *
 * where n denotes the nth task.
 *
 * For example, a simplest series from the beginning would be like:
 *
 *  task  util_avg: 512, 256, 128,  64,  32,   16,    8, ...
 * cfs_rq util_avg: 512, 768, 896, 960, 992, 1008, 1016, ...
 *
 * Finally, that extrapolated util_avg is clamped to the cap (util_avg_cap)
 * if util_avg > util_avg_cap.
 *
 * 随着新任务的创建,它们的初始util_avg将基于cfs_rq的当前util_avg进行推测:
 *
 * util_avg = cfs_rq->util_avg / (cfs_rq->load_avg + 1 ) * se.load.weight
 *
 * 然而,在许多情况下,上述util_avg并没有给出所需的值.此外,util_avgs的和可以是发散的,例如当级数是调和级数时.
 *
 * 为了解决这个问题,我们还将连续任务的util_avg限制为仅剩余利用率预算的1/2:
 *
 * util_avg_cap = (1024 - cfs_rq->avg.util_avg）/ 2^n
 *
 * 其中n表示第n个任务.
 *
 * 例如,一个最简单的系列从一开始就是这样的:
 *
 * task   util_avg: 512, 256, 128, 64,  32,    16, 8,   ...
 * cfs_rq util_avg: 512, 768, 896, 960, 992, 1008, 1016 ...
 *
 * 最后,如果util_avg > util_ag_cap,则推测的util_avg 被固定到cap (util_avg_cap)
 */
void post_init_entity_util_avg(struct sched_entity *se)
{
	/* 拿到该sched_entity的cfs_rq */
	struct cfs_rq *cfs_rq = cfs_rq_of(se);
	/* 拿到该sched_entity的负载sched_avg */
	struct sched_avg *sa = &se->avg;
	/* 计算cap (当第一个任务创建时,cfs_rq->avg.util_avg = 0),因此这时task se的util_avg等于cap;
	 * 这里就是把cap赋值为SCHED_CAPACITY_SCALE和cfs_rq平均利用率差值的一半 */
	long cap = (long)(SCHED_CAPACITY_SCALE - cfs_rq->avg.util_avg) / 2;
	/* 获得cfs_rq clock */
	u64 now = cfs_rq_clock_task(cfs_rq);

	/* 如果cap大于0 */
	if (cap > 0) {
		/* 如果cfs_rq的平均利用率不等于0 */
		if (cfs_rq->avg.util_avg != 0) {
			/* 那么sa的平均利用率就等于(cfs_rq->avg.util_avg) * se->load.weight / (cfs_rq->avg.load_avg + 1) */
			sa->util_avg  = cfs_rq->avg.util_avg * se->load.weight;
			sa->util_avg /= (cfs_rq->avg.load_avg + 1);
			/* 如果sa->util_avg > cap,那么把cap给它 */
			if (sa->util_avg > cap)
				sa->util_avg = cap;
		} else {
			/* 如果cfs_rq->avg.util_avg == 0,那么把sa->util_avg = cap */
			sa->util_avg = cap;
		}
		/* util_sum: 对于sched_entity: 正在运行状态下的累计衰减总时间(decay_sum_time).(使用cfs_rq->curr == se来判断进程是否正在运行); */
		/* 把sa->util_sum 赋值为 sa->util_avg * LOAD_AVG_MAX
		 * #define LOAD_AVG_MAX 47742 maximum possible load avg
		 */
		sa->util_sum = sa->util_avg * LOAD_AVG_MAX;
	}

	/* An entity is a task if it doesn't "own" a runqueue
	 * #define entity_is_task(se)	(!se->my_q)
	 */
	if (entity_is_task(se)) {
		struct task_struct *p = task_of(se);
		/* 如果不是cfs调度策略 */
		if (p->sched_class != &fair_sched_class) {
			/*
			 * For !fair tasks do:
			 *
			update_cfs_rq_load_avg(now, cfs_rq, false);
			attach_entity_load_avg(cfs_rq, se);
			switched_from_fair(rq, p);
			 *
			 * such that the next switched_to_fair() has the
			 * expected state.
			 *
			 * 使得下一次switched_to_fair()具有预期状态.
			 */
			se->avg.last_update_time = now;
			return;
		}
	}

	/* 更新cfs_rq的平均负载 */
	update_cfs_rq_load_avg(now, cfs_rq, false);
	/* 这个把当前进程的se相关的成员添加到cfs_rq中 */
	attach_entity_load_avg(cfs_rq, se);
	update_tg_load_avg(cfs_rq, false);
}

#else /* !CONFIG_SMP */
void init_entity_runnable_average(struct sched_entity *se)
{
}
void post_init_entity_util_avg(struct sched_entity *se)
{
}
static void update_tg_load_avg(struct cfs_rq *cfs_rq, int force)
{
}
#endif /* CONFIG_SMP */

/*
 * Update the current task's runtime statistics.
 */
/* update_curr函数的参数是当前进程对应的CFS就绪队列 */
static void update_curr(struct cfs_rq *cfs_rq)
{
	/* curr指针指向的调度实体是当前进程,即父进程 */
	struct sched_entity *curr = cfs_rq->curr;
	/* rq_lock_task获取当前就绪队列保存的clock_task值,该变量在每次时钟滴答(tick)到来时更新 */
	u64 now = rq_clock_task(rq_of(cfs_rq));
	u64 delta_exec;

	if (unlikely(!curr))
		return;
	/* delta_exec计算该进程从上次调用update_curr函数到现在的时间差 */
	delta_exec = now - curr->exec_start;
	if (unlikely((s64)delta_exec <= 0))
		return;
	/* 将curr的exec_start设置为now */
	curr->exec_start = now;

	schedstat_set(curr->statistics.exec_max,
		      max(delta_exec, curr->statistics.exec_max));

	/* 让当前的sum_exec_runtime加上delta_exec */
	curr->sum_exec_runtime += delta_exec;
	schedstat_add(cfs_rq->exec_clock, delta_exec);
	/* 用当前的delta_exec时间差来就算该进程的虚拟时间vruntime */
	curr->vruntime += calc_delta_fair(delta_exec, curr);
	/* 更新当前cfs_rq的min_vruntime */
	update_min_vruntime(cfs_rq);

	if (entity_is_task(curr)) {
		struct task_struct *curtask = task_of(curr);

		trace_sched_stat_runtime(curtask, delta_exec, curr->vruntime);
		cpuacct_charge(curtask, delta_exec);
		account_group_exec_runtime(curtask, delta_exec);
	}

	account_cfs_rq_runtime(cfs_rq, delta_exec);
}

static void update_curr_fair(struct rq *rq)
{
	update_curr(cfs_rq_of(&rq->curr->se));
}

static inline void
update_stats_wait_start(struct cfs_rq *cfs_rq, struct sched_entity *se)
{
	u64 wait_start, prev_wait_start;

	if (!schedstat_enabled())
		return;

	wait_start = rq_clock(rq_of(cfs_rq));
	prev_wait_start = schedstat_val(se->statistics.wait_start);

	if (entity_is_task(se) && task_on_rq_migrating(task_of(se)) &&
	    likely(wait_start > prev_wait_start))
		wait_start -= prev_wait_start;

	schedstat_set(se->statistics.wait_start, wait_start);
}

static inline void
update_stats_wait_end(struct cfs_rq *cfs_rq, struct sched_entity *se)
{
	struct task_struct *p;
	u64 delta;
	/* 如果schedstat没有使能,那么直接返回 */
	if (!schedstat_enabled())
		return;

	/* 用当前的rq_clock减去se->statistics.wait_start得到delta */
	delta = rq_clock(rq_of(cfs_rq)) - schedstat_val(se->statistics.wait_start);

	/* 如果entity是个task */
	if (entity_is_task(se)) {
		/* 拿到这个se的task_struct */
		p = task_of(se);
		/* 表示处于迁移过程中的进程,可能不在就绪队列中 */
		if (task_on_rq_migrating(p)) {
			/*
			 * Preserve migrating task's wait time so wait_start
			 * time stamp can be adjusted to accumulate wait time
			 * prior to migration.
			 *
			 * 保留迁移进程的等待时间,以便可以调整wait_start时间戳以累积迁移前的等待时间。
			 */
			/* 这里是把delta写到wait_start里面去 */
			schedstat_set(se->statistics.wait_start, delta);
			return;
		}
		trace_sched_stat_wait(p, delta);
	}

	/* 设置se->statistics.wait_max为se->statistics.wait_max和delat的最大值 */
	schedstat_set(se->statistics.wait_max,
		      max(schedstat_val(se->statistics.wait_max), delta));
	/* 让wait_count +1 */
	schedstat_inc(se->statistics.wait_count);
	/* 让这个调度对象的wait_sum加上我们这个delta */
	schedstat_add(se->statistics.wait_sum, delta);
	/* 设置wait_start等于0 */
	schedstat_set(se->statistics.wait_start, 0);
}

static inline void
update_stats_enqueue_sleeper(struct cfs_rq *cfs_rq, struct sched_entity *se)
{
	struct task_struct *tsk = NULL;
	u64 sleep_start, block_start;

	if (!schedstat_enabled())
		return;

	sleep_start = schedstat_val(se->statistics.sleep_start);
	block_start = schedstat_val(se->statistics.block_start);

	if (entity_is_task(se))
		tsk = task_of(se);

	if (sleep_start) {
		u64 delta = rq_clock(rq_of(cfs_rq)) - sleep_start;

		if ((s64)delta < 0)
			delta = 0;

		if (unlikely(delta > schedstat_val(se->statistics.sleep_max)))
			schedstat_set(se->statistics.sleep_max, delta);

		schedstat_set(se->statistics.sleep_start, 0);
		schedstat_add(se->statistics.sum_sleep_runtime, delta);

		if (tsk) {
			account_scheduler_latency(tsk, delta >> 10, 1);
			trace_sched_stat_sleep(tsk, delta);
		}
	}
	if (block_start) {
		u64 delta = rq_clock(rq_of(cfs_rq)) - block_start;

		if ((s64)delta < 0)
			delta = 0;

		if (unlikely(delta > schedstat_val(se->statistics.block_max)))
			schedstat_set(se->statistics.block_max, delta);

		schedstat_set(se->statistics.block_start, 0);
		schedstat_add(se->statistics.sum_sleep_runtime, delta);

		if (tsk) {
			if (tsk->in_iowait) {
				schedstat_add(se->statistics.iowait_sum, delta);
				schedstat_inc(se->statistics.iowait_count);
				trace_sched_stat_iowait(tsk, delta);
			}

			trace_sched_stat_blocked(tsk, delta);

			/*
			 * Blocking time is in units of nanosecs, so shift by
			 * 20 to get a milliseconds-range estimation of the
			 * amount of time that the task spent sleeping:
			 */
			if (unlikely(prof_on == SLEEP_PROFILING)) {
				profile_hits(SLEEP_PROFILING,
						(void *)get_wchan(tsk),
						delta >> 20);
			}
			account_scheduler_latency(tsk, delta >> 10, 0);
		}
	}
}

/*
 * Task is being enqueued - update stats:
 */
static inline void
update_stats_enqueue(struct cfs_rq *cfs_rq, struct sched_entity *se, int flags)
{
	if (!schedstat_enabled())
		return;

	/*
	 * Are we enqueueing a waiting task? (for current tasks
	 * a dequeue/enqueue event is a NOP)
	 */
	if (se != cfs_rq->curr)
		update_stats_wait_start(cfs_rq, se);

	if (flags & ENQUEUE_WAKEUP)
		update_stats_enqueue_sleeper(cfs_rq, se);
}

static inline void
update_stats_dequeue(struct cfs_rq *cfs_rq, struct sched_entity *se, int flags)
{

	/* 如果定义了schedstat */
	if (!schedstat_enabled())
		return;

	/*
	 * Mark the end of the wait period if dequeueing a
	 * waiting task:
	 *
	 * 如果将一个等待的任务退出运行队列,请标记等待期的结束：
	 */
	if (se != cfs_rq->curr)
		update_stats_wait_end(cfs_rq, se);

	/* 如果flag是DEQUEUE_SLEEP,也就是说睡眠,并且entity是个task */
	if ((flags & DEQUEUE_SLEEP) && entity_is_task(se)) {
		/* 拿到该se的task_struct */
		struct task_struct *tsk = task_of(se);

		/* 如果tsk_state是TASK_INTERRUPTIBLE,那么就设置sleep_start,否则就设置block_start */
		if (tsk->state & TASK_INTERRUPTIBLE)
			schedstat_set(se->statistics.sleep_start,
				      rq_clock(rq_of(cfs_rq)));
		if (tsk->state & TASK_UNINTERRUPTIBLE)
			schedstat_set(se->statistics.block_start,
				      rq_clock(rq_of(cfs_rq)));
	}
}

/*
 * We are picking a new current task - update its stats:
 */
static inline void
update_stats_curr_start(struct cfs_rq *cfs_rq, struct sched_entity *se)
{
	/*
	 * We are starting a new run period:
	 */
	se->exec_start = rq_clock_task(rq_of(cfs_rq));
}

/**************************************************
 * Scheduling class queueing methods:
 */

#ifdef CONFIG_NUMA_BALANCING
/*
 * Approximate time to scan a full NUMA task in ms. The task scan period is
 * calculated based on the tasks virtual memory size and
 * numa_balancing_scan_size.
 */
unsigned int sysctl_numa_balancing_scan_period_min = 1000;
unsigned int sysctl_numa_balancing_scan_period_max = 60000;

/* Portion of address space to scan in MB */
unsigned int sysctl_numa_balancing_scan_size = 256;

/* Scan @scan_size MB every @scan_period after an initial @scan_delay in ms */
unsigned int sysctl_numa_balancing_scan_delay = 1000;

static unsigned int task_nr_scan_windows(struct task_struct *p)
{
	unsigned long rss = 0;
	unsigned long nr_scan_pages;

	/*
	 * Calculations based on RSS as non-present and empty pages are skipped
	 * by the PTE scanner and NUMA hinting faults should be trapped based
	 * on resident pages
	 */
	nr_scan_pages = sysctl_numa_balancing_scan_size << (20 - PAGE_SHIFT);
	rss = get_mm_rss(p->mm);
	if (!rss)
		rss = nr_scan_pages;

	rss = round_up(rss, nr_scan_pages);
	return rss / nr_scan_pages;
}

/* For sanitys sake, never scan more PTEs than MAX_SCAN_WINDOW MB/sec. */
#define MAX_SCAN_WINDOW 2560

static unsigned int task_scan_min(struct task_struct *p)
{
	unsigned int scan_size = READ_ONCE(sysctl_numa_balancing_scan_size);
	unsigned int scan, floor;
	unsigned int windows = 1;

	if (scan_size < MAX_SCAN_WINDOW)
		windows = MAX_SCAN_WINDOW / scan_size;
	floor = 1000 / windows;

	scan = sysctl_numa_balancing_scan_period_min / task_nr_scan_windows(p);
	return max_t(unsigned int, floor, scan);
}

static unsigned int task_scan_max(struct task_struct *p)
{
	unsigned int smin = task_scan_min(p);
	unsigned int smax;

	/* Watch for min being lower than max due to floor calculations */
	smax = sysctl_numa_balancing_scan_period_max / task_nr_scan_windows(p);
	return max(smin, smax);
}

static void account_numa_enqueue(struct rq *rq, struct task_struct *p)
{
	rq->nr_numa_running += (p->numa_preferred_nid != -1);
	rq->nr_preferred_running += (p->numa_preferred_nid == task_node(p));
}

static void account_numa_dequeue(struct rq *rq, struct task_struct *p)
{
	rq->nr_numa_running -= (p->numa_preferred_nid != -1);
	rq->nr_preferred_running -= (p->numa_preferred_nid == task_node(p));
}

struct numa_group {
	atomic_t refcount;

	spinlock_t lock; /* nr_tasks, tasks */
	int nr_tasks;
	pid_t gid;
	int active_nodes;

	struct rcu_head rcu;
	unsigned long total_faults;
	unsigned long max_faults_cpu;
	/*
	 * Faults_cpu is used to decide whether memory should move
	 * towards the CPU. As a consequence, these stats are weighted
	 * more by CPU use than by memory faults.
	 */
	unsigned long *faults_cpu;
	unsigned long faults[0];
};

/* Shared or private faults. */
#define NR_NUMA_HINT_FAULT_TYPES 2

/* Memory and CPU locality */
#define NR_NUMA_HINT_FAULT_STATS (NR_NUMA_HINT_FAULT_TYPES * 2)

/* Averaged statistics, and temporary buffers. */
#define NR_NUMA_HINT_FAULT_BUCKETS (NR_NUMA_HINT_FAULT_STATS * 2)

pid_t task_numa_group_id(struct task_struct *p)
{
	return p->numa_group ? p->numa_group->gid : 0;
}

/*
 * The averaged statistics, shared & private, memory & cpu,
 * occupy the first half of the array. The second half of the
 * array is for current counters, which are averaged into the
 * first set by task_numa_placement.
 */
static inline int task_faults_idx(enum numa_faults_stats s, int nid, int priv)
{
	return NR_NUMA_HINT_FAULT_TYPES * (s * nr_node_ids + nid) + priv;
}

static inline unsigned long task_faults(struct task_struct *p, int nid)
{
	if (!p->numa_faults)
		return 0;

	return p->numa_faults[task_faults_idx(NUMA_MEM, nid, 0)] +
		p->numa_faults[task_faults_idx(NUMA_MEM, nid, 1)];
}

static inline unsigned long group_faults(struct task_struct *p, int nid)
{
	if (!p->numa_group)
		return 0;

	return p->numa_group->faults[task_faults_idx(NUMA_MEM, nid, 0)] +
		p->numa_group->faults[task_faults_idx(NUMA_MEM, nid, 1)];
}

static inline unsigned long group_faults_cpu(struct numa_group *group, int nid)
{
	return group->faults_cpu[task_faults_idx(NUMA_MEM, nid, 0)] +
		group->faults_cpu[task_faults_idx(NUMA_MEM, nid, 1)];
}

/*
 * A node triggering more than 1/3 as many NUMA faults as the maximum is
 * considered part of a numa group's pseudo-interleaving set. Migrations
 * between these nodes are slowed down, to allow things to settle down.
 */
#define ACTIVE_NODE_FRACTION 3

static bool numa_is_active_node(int nid, struct numa_group *ng)
{
	return group_faults_cpu(ng, nid) * ACTIVE_NODE_FRACTION > ng->max_faults_cpu;
}

/* Handle placement on systems where not all nodes are directly connected. */
static unsigned long score_nearby_nodes(struct task_struct *p, int nid,
					int maxdist, bool task)
{
	unsigned long score = 0;
	int node;

	/*
	 * All nodes are directly connected, and the same distance
	 * from each other. No need for fancy placement algorithms.
	 */
	if (sched_numa_topology_type == NUMA_DIRECT)
		return 0;

	/*
	 * This code is called for each node, introducing N^2 complexity,
	 * which should be ok given the number of nodes rarely exceeds 8.
	 */
	for_each_online_node(node) {
		unsigned long faults;
		int dist = node_distance(nid, node);

		/*
		 * The furthest away nodes in the system are not interesting
		 * for placement; nid was already counted.
		 */
		if (dist == sched_max_numa_distance || node == nid)
			continue;

		/*
		 * On systems with a backplane NUMA topology, compare groups
		 * of nodes, and move tasks towards the group with the most
		 * memory accesses. When comparing two nodes at distance
		 * "hoplimit", only nodes closer by than "hoplimit" are part
		 * of each group. Skip other nodes.
		 */
		if (sched_numa_topology_type == NUMA_BACKPLANE &&
					dist > maxdist)
			continue;

		/* Add up the faults from nearby nodes. */
		if (task)
			faults = task_faults(p, node);
		else
			faults = group_faults(p, node);

		/*
		 * On systems with a glueless mesh NUMA topology, there are
		 * no fixed "groups of nodes". Instead, nodes that are not
		 * directly connected bounce traffic through intermediate
		 * nodes; a numa_group can occupy any set of nodes.
		 * The further away a node is, the less the faults count.
		 * This seems to result in good task placement.
		 */
		if (sched_numa_topology_type == NUMA_GLUELESS_MESH) {
			faults *= (sched_max_numa_distance - dist);
			faults /= (sched_max_numa_distance - LOCAL_DISTANCE);
		}

		score += faults;
	}

	return score;
}

/*
 * These return the fraction of accesses done by a particular task, or
 * task group, on a particular numa node.  The group weight is given a
 * larger multiplier, in order to group tasks together that are almost
 * evenly spread out between numa nodes.
 */
static inline unsigned long task_weight(struct task_struct *p, int nid,
					int dist)
{
	unsigned long faults, total_faults;

	if (!p->numa_faults)
		return 0;

	total_faults = p->total_numa_faults;

	if (!total_faults)
		return 0;

	faults = task_faults(p, nid);
	faults += score_nearby_nodes(p, nid, dist, true);

	return 1000 * faults / total_faults;
}

static inline unsigned long group_weight(struct task_struct *p, int nid,
					 int dist)
{
	unsigned long faults, total_faults;

	if (!p->numa_group)
		return 0;

	total_faults = p->numa_group->total_faults;

	if (!total_faults)
		return 0;

	faults = group_faults(p, nid);
	faults += score_nearby_nodes(p, nid, dist, false);

	return 1000 * faults / total_faults;
}

bool should_numa_migrate_memory(struct task_struct *p, struct page * page,
				int src_nid, int dst_cpu)
{
	struct numa_group *ng = p->numa_group;
	int dst_nid = cpu_to_node(dst_cpu);
	int last_cpupid, this_cpupid;

	this_cpupid = cpu_pid_to_cpupid(dst_cpu, current->pid);

	/*
	 * Multi-stage node selection is used in conjunction with a periodic
	 * migration fault to build a temporal task<->page relation. By using
	 * a two-stage filter we remove short/unlikely relations.
	 *
	 * Using P(p) ~ n_p / n_t as per frequentist probability, we can equate
	 * a task's usage of a particular page (n_p) per total usage of this
	 * page (n_t) (in a given time-span) to a probability.
	 *
	 * Our periodic faults will sample this probability and getting the
	 * same result twice in a row, given these samples are fully
	 * independent, is then given by P(n)^2, provided our sample period
	 * is sufficiently short compared to the usage pattern.
	 *
	 * This quadric squishes small probabilities, making it less likely we
	 * act on an unlikely task<->page relation.
	 */
	last_cpupid = page_cpupid_xchg_last(page, this_cpupid);
	if (!cpupid_pid_unset(last_cpupid) &&
				cpupid_to_nid(last_cpupid) != dst_nid)
		return false;

	/* Always allow migrate on private faults */
	if (cpupid_match_pid(p, last_cpupid))
		return true;

	/* A shared fault, but p->numa_group has not been set up yet. */
	if (!ng)
		return true;

	/*
	 * Destination node is much more heavily used than the source
	 * node? Allow migration.
	 */
	if (group_faults_cpu(ng, dst_nid) > group_faults_cpu(ng, src_nid) *
					ACTIVE_NODE_FRACTION)
		return true;

	/*
	 * Distribute memory according to CPU & memory use on each node,
	 * with 3/4 hysteresis to avoid unnecessary memory migrations:
	 *
	 * faults_cpu(dst)   3   faults_cpu(src)
	 * --------------- * - > ---------------
	 * faults_mem(dst)   4   faults_mem(src)
	 */
	return group_faults_cpu(ng, dst_nid) * group_faults(p, src_nid) * 3 >
	       group_faults_cpu(ng, src_nid) * group_faults(p, dst_nid) * 4;
}

static unsigned long weighted_cpuload(const int cpu);
static unsigned long source_load(int cpu, int type);
static unsigned long target_load(int cpu, int type);
static unsigned long capacity_of(int cpu);
static long effective_load(struct task_group *tg, int cpu, long wl, long wg);

/* Cached statistics for all CPUs within a node */
struct numa_stats {
	unsigned long nr_running;
	unsigned long load;

	/* Total compute capacity of CPUs on a node */
	unsigned long compute_capacity;

	/* Approximate capacity in terms of runnable tasks on a node */
	unsigned long task_capacity;
	int has_free_capacity;
};

/*
 * XXX borrowed from update_sg_lb_stats
 */
static void update_numa_stats(struct numa_stats *ns, int nid)
{
	int smt, cpu, cpus = 0;
	unsigned long capacity;

	memset(ns, 0, sizeof(*ns));
	for_each_cpu(cpu, cpumask_of_node(nid)) {
		struct rq *rq = cpu_rq(cpu);

		ns->nr_running += rq->nr_running;
		ns->load += weighted_cpuload(cpu);
		ns->compute_capacity += capacity_of(cpu);

		cpus++;
	}

	/*
	 * If we raced with hotplug and there are no CPUs left in our mask
	 * the @ns structure is NULL'ed and task_numa_compare() will
	 * not find this node attractive.
	 *
	 * We'll either bail at !has_free_capacity, or we'll detect a huge
	 * imbalance and bail there.
	 */
	if (!cpus)
		return;

	/* smt := ceil(cpus / capacity), assumes: 1 < smt_power < 2 */
	smt = DIV_ROUND_UP(SCHED_CAPACITY_SCALE * cpus, ns->compute_capacity);
	capacity = cpus / smt; /* cores */

	ns->task_capacity = min_t(unsigned, capacity,
		DIV_ROUND_CLOSEST(ns->compute_capacity, SCHED_CAPACITY_SCALE));
	ns->has_free_capacity = (ns->nr_running < ns->task_capacity);
}

struct task_numa_env {
	struct task_struct *p;

	int src_cpu, src_nid;
	int dst_cpu, dst_nid;

	struct numa_stats src_stats, dst_stats;

	int imbalance_pct;
	int dist;

	struct task_struct *best_task;
	long best_imp;
	int best_cpu;
};

static void task_numa_assign(struct task_numa_env *env,
			     struct task_struct *p, long imp)
{
	if (env->best_task)
		put_task_struct(env->best_task);
	if (p)
		get_task_struct(p);

	env->best_task = p;
	env->best_imp = imp;
	env->best_cpu = env->dst_cpu;
}

static bool load_too_imbalanced(long src_load, long dst_load,
				struct task_numa_env *env)
{
	long imb, old_imb;
	long orig_src_load, orig_dst_load;
	long src_capacity, dst_capacity;

	/*
	 * The load is corrected for the CPU capacity available on each node.
	 *
	 * src_load        dst_load
	 * ------------ vs ---------
	 * src_capacity    dst_capacity
	 */
	src_capacity = env->src_stats.compute_capacity;
	dst_capacity = env->dst_stats.compute_capacity;

	/* We care about the slope of the imbalance, not the direction. */
	if (dst_load < src_load)
		swap(dst_load, src_load);

	/* Is the difference below the threshold? */
	imb = dst_load * src_capacity * 100 -
	      src_load * dst_capacity * env->imbalance_pct;
	if (imb <= 0)
		return false;

	/*
	 * The imbalance is above the allowed threshold.
	 * Compare it with the old imbalance.
	 */
	orig_src_load = env->src_stats.load;
	orig_dst_load = env->dst_stats.load;

	if (orig_dst_load < orig_src_load)
		swap(orig_dst_load, orig_src_load);

	old_imb = orig_dst_load * src_capacity * 100 -
		  orig_src_load * dst_capacity * env->imbalance_pct;

	/* Would this change make things worse? */
	return (imb > old_imb);
}

/*
 * This checks if the overall compute and NUMA accesses of the system would
 * be improved if the source tasks was migrated to the target dst_cpu taking
 * into account that it might be best if task running on the dst_cpu should
 * be exchanged with the source task
 */
static void task_numa_compare(struct task_numa_env *env,
			      long taskimp, long groupimp)
{
	struct rq *src_rq = cpu_rq(env->src_cpu);
	struct rq *dst_rq = cpu_rq(env->dst_cpu);
	struct task_struct *cur;
	long src_load, dst_load;
	long load;
	long imp = env->p->numa_group ? groupimp : taskimp;
	long moveimp = imp;
	int dist = env->dist;

	rcu_read_lock();
	cur = task_rcu_dereference(&dst_rq->curr);
	if (cur && ((cur->flags & PF_EXITING) || is_idle_task(cur)))
		cur = NULL;

	/*
	 * Because we have preemption enabled we can get migrated around and
	 * end try selecting ourselves (current == env->p) as a swap candidate.
	 */
	if (cur == env->p)
		goto unlock;

	/*
	 * "imp" is the fault differential for the source task between the
	 * source and destination node. Calculate the total differential for
	 * the source task and potential destination task. The more negative
	 * the value is, the more rmeote accesses that would be expected to
	 * be incurred if the tasks were swapped.
	 */
	if (cur) {
		/* Skip this swap candidate if cannot move to the source cpu */
		if (!cpumask_test_cpu(env->src_cpu, tsk_cpus_allowed(cur)))
			goto unlock;

		/*
		 * If dst and source tasks are in the same NUMA group, or not
		 * in any group then look only at task weights.
		 */
		if (cur->numa_group == env->p->numa_group) {
			imp = taskimp + task_weight(cur, env->src_nid, dist) -
			      task_weight(cur, env->dst_nid, dist);
			/*
			 * Add some hysteresis to prevent swapping the
			 * tasks within a group over tiny differences.
			 */
			if (cur->numa_group)
				imp -= imp/16;
		} else {
			/*
			 * Compare the group weights. If a task is all by
			 * itself (not part of a group), use the task weight
			 * instead.
			 */
			if (cur->numa_group)
				imp += group_weight(cur, env->src_nid, dist) -
				       group_weight(cur, env->dst_nid, dist);
			else
				imp += task_weight(cur, env->src_nid, dist) -
				       task_weight(cur, env->dst_nid, dist);
		}
	}

	if (imp <= env->best_imp && moveimp <= env->best_imp)
		goto unlock;

	if (!cur) {
		/* Is there capacity at our destination? */
		if (env->src_stats.nr_running <= env->src_stats.task_capacity &&
		    !env->dst_stats.has_free_capacity)
			goto unlock;

		goto balance;
	}

	/* Balance doesn't matter much if we're running a task per cpu */
	if (imp > env->best_imp && src_rq->nr_running == 1 &&
			dst_rq->nr_running == 1)
		goto assign;

	/*
	 * In the overloaded case, try and keep the load balanced.
	 */
balance:
	load = task_h_load(env->p);
	dst_load = env->dst_stats.load + load;
	src_load = env->src_stats.load - load;

	if (moveimp > imp && moveimp > env->best_imp) {
		/*
		 * If the improvement from just moving env->p direction is
		 * better than swapping tasks around, check if a move is
		 * possible. Store a slightly smaller score than moveimp,
		 * so an actually idle CPU will win.
		 */
		if (!load_too_imbalanced(src_load, dst_load, env)) {
			imp = moveimp - 1;
			cur = NULL;
			goto assign;
		}
	}

	if (imp <= env->best_imp)
		goto unlock;

	if (cur) {
		load = task_h_load(cur);
		dst_load -= load;
		src_load += load;
	}

	if (load_too_imbalanced(src_load, dst_load, env))
		goto unlock;

	/*
	 * One idle CPU per node is evaluated for a task numa move.
	 * Call select_idle_sibling to maybe find a better one.
	 */
	if (!cur) {
		/*
		 * select_idle_siblings() uses an per-cpu cpumask that
		 * can be used from IRQ context.
		 */
		local_irq_disable();
		env->dst_cpu = select_idle_sibling(env->p, env->src_cpu,
						   env->dst_cpu);
		local_irq_enable();
	}

assign:
	task_numa_assign(env, cur, imp);
unlock:
	rcu_read_unlock();
}

static void task_numa_find_cpu(struct task_numa_env *env,
				long taskimp, long groupimp)
{
	int cpu;

	for_each_cpu(cpu, cpumask_of_node(env->dst_nid)) {
		/* Skip this CPU if the source task cannot migrate */
		if (!cpumask_test_cpu(cpu, tsk_cpus_allowed(env->p)))
			continue;

		env->dst_cpu = cpu;
		task_numa_compare(env, taskimp, groupimp);
	}
}

/* Only move tasks to a NUMA node less busy than the current node. */
static bool numa_has_capacity(struct task_numa_env *env)
{
	struct numa_stats *src = &env->src_stats;
	struct numa_stats *dst = &env->dst_stats;

	if (src->has_free_capacity && !dst->has_free_capacity)
		return false;

	/*
	 * Only consider a task move if the source has a higher load
	 * than the destination, corrected for CPU capacity on each node.
	 *
	 *      src->load                dst->load
	 * --------------------- vs ---------------------
	 * src->compute_capacity    dst->compute_capacity
	 */
	if (src->load * dst->compute_capacity * env->imbalance_pct >

	    dst->load * src->compute_capacity * 100)
		return true;

	return false;
}

static int task_numa_migrate(struct task_struct *p)
{
	struct task_numa_env env = {
		.p = p,

		.src_cpu = task_cpu(p),
		.src_nid = task_node(p),

		.imbalance_pct = 112,

		.best_task = NULL,
		.best_imp = 0,
		.best_cpu = -1,
	};
	struct sched_domain *sd;
	unsigned long taskweight, groupweight;
	int nid, ret, dist;
	long taskimp, groupimp;

	/*
	 * Pick the lowest SD_NUMA domain, as that would have the smallest
	 * imbalance and would be the first to start moving tasks about.
	 *
	 * And we want to avoid any moving of tasks about, as that would create
	 * random movement of tasks -- counter the numa conditions we're trying
	 * to satisfy here.
	 */
	rcu_read_lock();
	sd = rcu_dereference(per_cpu(sd_numa, env.src_cpu));
	if (sd)
		env.imbalance_pct = 100 + (sd->imbalance_pct - 100) / 2;
	rcu_read_unlock();

	/*
	 * Cpusets can break the scheduler domain tree into smaller
	 * balance domains, some of which do not cross NUMA boundaries.
	 * Tasks that are "trapped" in such domains cannot be migrated
	 * elsewhere, so there is no point in (re)trying.
	 */
	if (unlikely(!sd)) {
		p->numa_preferred_nid = task_node(p);
		return -EINVAL;
	}

	env.dst_nid = p->numa_preferred_nid;
	dist = env.dist = node_distance(env.src_nid, env.dst_nid);
	taskweight = task_weight(p, env.src_nid, dist);
	groupweight = group_weight(p, env.src_nid, dist);
	update_numa_stats(&env.src_stats, env.src_nid);
	taskimp = task_weight(p, env.dst_nid, dist) - taskweight;
	groupimp = group_weight(p, env.dst_nid, dist) - groupweight;
	update_numa_stats(&env.dst_stats, env.dst_nid);

	/* Try to find a spot on the preferred nid. */
	if (numa_has_capacity(&env))
		task_numa_find_cpu(&env, taskimp, groupimp);

	/*
	 * Look at other nodes in these cases:
	 * - there is no space available on the preferred_nid
	 * - the task is part of a numa_group that is interleaved across
	 *   multiple NUMA nodes; in order to better consolidate the group,
	 *   we need to check other locations.
	 */
	if (env.best_cpu == -1 || (p->numa_group && p->numa_group->active_nodes > 1)) {
		for_each_online_node(nid) {
			if (nid == env.src_nid || nid == p->numa_preferred_nid)
				continue;

			dist = node_distance(env.src_nid, env.dst_nid);
			if (sched_numa_topology_type == NUMA_BACKPLANE &&
						dist != env.dist) {
				taskweight = task_weight(p, env.src_nid, dist);
				groupweight = group_weight(p, env.src_nid, dist);
			}

			/* Only consider nodes where both task and groups benefit */
			taskimp = task_weight(p, nid, dist) - taskweight;
			groupimp = group_weight(p, nid, dist) - groupweight;
			if (taskimp < 0 && groupimp < 0)
				continue;

			env.dist = dist;
			env.dst_nid = nid;
			update_numa_stats(&env.dst_stats, env.dst_nid);
			if (numa_has_capacity(&env))
				task_numa_find_cpu(&env, taskimp, groupimp);
		}
	}

	/*
	 * If the task is part of a workload that spans multiple NUMA nodes,
	 * and is migrating into one of the workload's active nodes, remember
	 * this node as the task's preferred numa node, so the workload can
	 * settle down.
	 * A task that migrated to a second choice node will be better off
	 * trying for a better one later. Do not set the preferred node here.
	 */
	if (p->numa_group) {
		struct numa_group *ng = p->numa_group;

		if (env.best_cpu == -1)
			nid = env.src_nid;
		else
			nid = env.dst_nid;

		if (ng->active_nodes > 1 && numa_is_active_node(env.dst_nid, ng))
			sched_setnuma(p, env.dst_nid);
	}

	/* No better CPU than the current one was found. */
	if (env.best_cpu == -1)
		return -EAGAIN;

	/*
	 * Reset the scan period if the task is being rescheduled on an
	 * alternative node to recheck if the tasks is now properly placed.
	 */
	p->numa_scan_period = task_scan_min(p);

	if (env.best_task == NULL) {
		ret = migrate_task_to(p, env.best_cpu);
		if (ret != 0)
			trace_sched_stick_numa(p, env.src_cpu, env.best_cpu);
		return ret;
	}

	ret = migrate_swap(p, env.best_task);
	if (ret != 0)
		trace_sched_stick_numa(p, env.src_cpu, task_cpu(env.best_task));
	put_task_struct(env.best_task);
	return ret;
}

/* Attempt to migrate a task to a CPU on the preferred node. */
static void numa_migrate_preferred(struct task_struct *p)
{
	unsigned long interval = HZ;

	/* This task has no NUMA fault statistics yet */
	if (unlikely(p->numa_preferred_nid == -1 || !p->numa_faults))
		return;

	/* Periodically retry migrating the task to the preferred node */
	interval = min(interval, msecs_to_jiffies(p->numa_scan_period) / 16);
	p->numa_migrate_retry = jiffies + interval;

	/* Success if task is already running on preferred CPU */
	if (task_node(p) == p->numa_preferred_nid)
		return;

	/* Otherwise, try migrate to a CPU on the preferred node */
	task_numa_migrate(p);
}

/*
 * Find out how many nodes on the workload is actively running on. Do this by
 * tracking the nodes from which NUMA hinting faults are triggered. This can
 * be different from the set of nodes where the workload's memory is currently
 * located.
 */
static void numa_group_count_active_nodes(struct numa_group *numa_group)
{
	unsigned long faults, max_faults = 0;
	int nid, active_nodes = 0;

	for_each_online_node(nid) {
		faults = group_faults_cpu(numa_group, nid);
		if (faults > max_faults)
			max_faults = faults;
	}

	for_each_online_node(nid) {
		faults = group_faults_cpu(numa_group, nid);
		if (faults * ACTIVE_NODE_FRACTION > max_faults)
			active_nodes++;
	}

	numa_group->max_faults_cpu = max_faults;
	numa_group->active_nodes = active_nodes;
}

/*
 * When adapting the scan rate, the period is divided into NUMA_PERIOD_SLOTS
 * increments. The more local the fault statistics are, the higher the scan
 * period will be for the next scan window. If local/(local+remote) ratio is
 * below NUMA_PERIOD_THRESHOLD (where range of ratio is 1..NUMA_PERIOD_SLOTS)
 * the scan period will decrease. Aim for 70% local accesses.
 */
#define NUMA_PERIOD_SLOTS 10
#define NUMA_PERIOD_THRESHOLD 7

/*
 * Increase the scan period (slow down scanning) if the majority of
 * our memory is already on our local node, or if the majority of
 * the page accesses are shared with other processes.
 * Otherwise, decrease the scan period.
 */
static void update_task_scan_period(struct task_struct *p,
			unsigned long shared, unsigned long private)
{
	unsigned int period_slot;
	int ratio;
	int diff;

	unsigned long remote = p->numa_faults_locality[0];
	unsigned long local = p->numa_faults_locality[1];

	/*
	 * If there were no record hinting faults then either the task is
	 * completely idle or all activity is areas that are not of interest
	 * to automatic numa balancing. Related to that, if there were failed
	 * migration then it implies we are migrating too quickly or the local
	 * node is overloaded. In either case, scan slower
	 */
	if (local + shared == 0 || p->numa_faults_locality[2]) {
		p->numa_scan_period = min(p->numa_scan_period_max,
			p->numa_scan_period << 1);

		p->mm->numa_next_scan = jiffies +
			msecs_to_jiffies(p->numa_scan_period);

		return;
	}

	/*
	 * Prepare to scale scan period relative to the current period.
	 *	 == NUMA_PERIOD_THRESHOLD scan period stays the same
	 *       <  NUMA_PERIOD_THRESHOLD scan period decreases (scan faster)
	 *	 >= NUMA_PERIOD_THRESHOLD scan period increases (scan slower)
	 */
	period_slot = DIV_ROUND_UP(p->numa_scan_period, NUMA_PERIOD_SLOTS);
	ratio = (local * NUMA_PERIOD_SLOTS) / (local + remote);
	if (ratio >= NUMA_PERIOD_THRESHOLD) {
		int slot = ratio - NUMA_PERIOD_THRESHOLD;
		if (!slot)
			slot = 1;
		diff = slot * period_slot;
	} else {
		diff = -(NUMA_PERIOD_THRESHOLD - ratio) * period_slot;

		/*
		 * Scale scan rate increases based on sharing. There is an
		 * inverse relationship between the degree of sharing and
		 * the adjustment made to the scanning period. Broadly
		 * speaking the intent is that there is little point
		 * scanning faster if shared accesses dominate as it may
		 * simply bounce migrations uselessly
		 */
		ratio = DIV_ROUND_UP(private * NUMA_PERIOD_SLOTS, (private + shared + 1));
		diff = (diff * ratio) / NUMA_PERIOD_SLOTS;
	}

	p->numa_scan_period = clamp(p->numa_scan_period + diff,
			task_scan_min(p), task_scan_max(p));
	memset(p->numa_faults_locality, 0, sizeof(p->numa_faults_locality));
}

/*
 * Get the fraction of time the task has been running since the last
 * NUMA placement cycle. The scheduler keeps similar statistics, but
 * decays those on a 32ms period, which is orders of magnitude off
 * from the dozens-of-seconds NUMA balancing period. Use the scheduler
 * stats only if the task is so new there are no NUMA statistics yet.
 */
static u64 numa_get_avg_runtime(struct task_struct *p, u64 *period)
{
	u64 runtime, delta, now;
	/* Use the start of this time slice to avoid calculations. */
	now = p->se.exec_start;
	runtime = p->se.sum_exec_runtime;

	if (p->last_task_numa_placement) {
		delta = runtime - p->last_sum_exec_runtime;
		*period = now - p->last_task_numa_placement;
	} else {
		delta = p->se.avg.load_sum / p->se.load.weight;
		*period = LOAD_AVG_MAX;
	}

	p->last_sum_exec_runtime = runtime;
	p->last_task_numa_placement = now;

	return delta;
}

/*
 * Determine the preferred nid for a task in a numa_group. This needs to
 * be done in a way that produces consistent results with group_weight,
 * otherwise workloads might not converge.
 */
static int preferred_group_nid(struct task_struct *p, int nid)
{
	nodemask_t nodes;
	int dist;

	/* Direct connections between all NUMA nodes. */
	if (sched_numa_topology_type == NUMA_DIRECT)
		return nid;

	/*
	 * On a system with glueless mesh NUMA topology, group_weight
	 * scores nodes according to the number of NUMA hinting faults on
	 * both the node itself, and on nearby nodes.
	 */
	if (sched_numa_topology_type == NUMA_GLUELESS_MESH) {
		unsigned long score, max_score = 0;
		int node, max_node = nid;

		dist = sched_max_numa_distance;

		for_each_online_node(node) {
			score = group_weight(p, node, dist);
			if (score > max_score) {
				max_score = score;
				max_node = node;
			}
		}
		return max_node;
	}

	/*
	 * Finding the preferred nid in a system with NUMA backplane
	 * interconnect topology is more involved. The goal is to locate
	 * tasks from numa_groups near each other in the system, and
	 * untangle workloads from different sides of the system. This requires
	 * searching down the hierarchy of node groups, recursively searching
	 * inside the highest scoring group of nodes. The nodemask tricks
	 * keep the complexity of the search down.
	 */
	nodes = node_online_map;
	for (dist = sched_max_numa_distance; dist > LOCAL_DISTANCE; dist--) {
		unsigned long max_faults = 0;
		nodemask_t max_group = NODE_MASK_NONE;
		int a, b;

		/* Are there nodes at this distance from each other? */
		if (!find_numa_distance(dist))
			continue;

		for_each_node_mask(a, nodes) {
			unsigned long faults = 0;
			nodemask_t this_group;
			nodes_clear(this_group);

			/* Sum group's NUMA faults; includes a==b case. */
			for_each_node_mask(b, nodes) {
				if (node_distance(a, b) < dist) {
					faults += group_faults(p, b);
					node_set(b, this_group);
					node_clear(b, nodes);
				}
			}

			/* Remember the top group. */
			if (faults > max_faults) {
				max_faults = faults;
				max_group = this_group;
				/*
				 * subtle: at the smallest distance there is
				 * just one node left in each "group", the
				 * winner is the preferred nid.
				 */
				nid = a;
			}
		}
		/* Next round, evaluate the nodes within max_group. */
		if (!max_faults)
			break;
		nodes = max_group;
	}
	return nid;
}

static void task_numa_placement(struct task_struct *p)
{
	int seq, nid, max_nid = -1, max_group_nid = -1;
	unsigned long max_faults = 0, max_group_faults = 0;
	unsigned long fault_types[2] = { 0, 0 };
	unsigned long total_faults;
	u64 runtime, period;
	spinlock_t *group_lock = NULL;

	/*
	 * The p->mm->numa_scan_seq field gets updated without
	 * exclusive access. Use READ_ONCE() here to ensure
	 * that the field is read in a single access:
	 */
	seq = READ_ONCE(p->mm->numa_scan_seq);
	if (p->numa_scan_seq == seq)
		return;
	p->numa_scan_seq = seq;
	p->numa_scan_period_max = task_scan_max(p);

	total_faults = p->numa_faults_locality[0] +
		       p->numa_faults_locality[1];
	runtime = numa_get_avg_runtime(p, &period);

	/* If the task is part of a group prevent parallel updates to group stats */
	if (p->numa_group) {
		group_lock = &p->numa_group->lock;
		spin_lock_irq(group_lock);
	}

	/* Find the node with the highest number of faults */
	for_each_online_node(nid) {
		/* Keep track of the offsets in numa_faults array */
		int mem_idx, membuf_idx, cpu_idx, cpubuf_idx;
		unsigned long faults = 0, group_faults = 0;
		int priv;

		for (priv = 0; priv < NR_NUMA_HINT_FAULT_TYPES; priv++) {
			long diff, f_diff, f_weight;

			mem_idx = task_faults_idx(NUMA_MEM, nid, priv);
			membuf_idx = task_faults_idx(NUMA_MEMBUF, nid, priv);
			cpu_idx = task_faults_idx(NUMA_CPU, nid, priv);
			cpubuf_idx = task_faults_idx(NUMA_CPUBUF, nid, priv);

			/* Decay existing window, copy faults since last scan */
			diff = p->numa_faults[membuf_idx] - p->numa_faults[mem_idx] / 2;
			fault_types[priv] += p->numa_faults[membuf_idx];
			p->numa_faults[membuf_idx] = 0;

			/*
			 * Normalize the faults_from, so all tasks in a group
			 * count according to CPU use, instead of by the raw
			 * number of faults. Tasks with little runtime have
			 * little over-all impact on throughput, and thus their
			 * faults are less important.
			 */
			f_weight = div64_u64(runtime << 16, period + 1);
			f_weight = (f_weight * p->numa_faults[cpubuf_idx]) /
				   (total_faults + 1);
			f_diff = f_weight - p->numa_faults[cpu_idx] / 2;
			p->numa_faults[cpubuf_idx] = 0;

			p->numa_faults[mem_idx] += diff;
			p->numa_faults[cpu_idx] += f_diff;
			faults += p->numa_faults[mem_idx];
			p->total_numa_faults += diff;
			if (p->numa_group) {
				/*
				 * safe because we can only change our own group
				 *
				 * mem_idx represents the offset for a given
				 * nid and priv in a specific region because it
				 * is at the beginning of the numa_faults array.
				 */
				p->numa_group->faults[mem_idx] += diff;
				p->numa_group->faults_cpu[mem_idx] += f_diff;
				p->numa_group->total_faults += diff;
				group_faults += p->numa_group->faults[mem_idx];
			}
		}

		if (faults > max_faults) {
			max_faults = faults;
			max_nid = nid;
		}

		if (group_faults > max_group_faults) {
			max_group_faults = group_faults;
			max_group_nid = nid;
		}
	}

	update_task_scan_period(p, fault_types[0], fault_types[1]);

	if (p->numa_group) {
		numa_group_count_active_nodes(p->numa_group);
		spin_unlock_irq(group_lock);
		max_nid = preferred_group_nid(p, max_group_nid);
	}

	if (max_faults) {
		/* Set the new preferred node */
		if (max_nid != p->numa_preferred_nid)
			sched_setnuma(p, max_nid);

		if (task_node(p) != p->numa_preferred_nid)
			numa_migrate_preferred(p);
	}
}

static inline int get_numa_group(struct numa_group *grp)
{
	return atomic_inc_not_zero(&grp->refcount);
}

static inline void put_numa_group(struct numa_group *grp)
{
	if (atomic_dec_and_test(&grp->refcount))
		kfree_rcu(grp, rcu);
}

static void task_numa_group(struct task_struct *p, int cpupid, int flags,
			int *priv)
{
	struct numa_group *grp, *my_grp;
	struct task_struct *tsk;
	bool join = false;
	int cpu = cpupid_to_cpu(cpupid);
	int i;

	if (unlikely(!p->numa_group)) {
		unsigned int size = sizeof(struct numa_group) +
				    4*nr_node_ids*sizeof(unsigned long);

		grp = kzalloc(size, GFP_KERNEL | __GFP_NOWARN);
		if (!grp)
			return;

		atomic_set(&grp->refcount, 1);
		grp->active_nodes = 1;
		grp->max_faults_cpu = 0;
		spin_lock_init(&grp->lock);
		grp->gid = p->pid;
		/* Second half of the array tracks nids where faults happen */
		grp->faults_cpu = grp->faults + NR_NUMA_HINT_FAULT_TYPES *
						nr_node_ids;

		for (i = 0; i < NR_NUMA_HINT_FAULT_STATS * nr_node_ids; i++)
			grp->faults[i] = p->numa_faults[i];

		grp->total_faults = p->total_numa_faults;

		grp->nr_tasks++;
		rcu_assign_pointer(p->numa_group, grp);
	}

	rcu_read_lock();
	tsk = READ_ONCE(cpu_rq(cpu)->curr);

	if (!cpupid_match_pid(tsk, cpupid))
		goto no_join;

	grp = rcu_dereference(tsk->numa_group);
	if (!grp)
		goto no_join;

	my_grp = p->numa_group;
	if (grp == my_grp)
		goto no_join;

	/*
	 * Only join the other group if its bigger; if we're the bigger group,
	 * the other task will join us.
	 */
	if (my_grp->nr_tasks > grp->nr_tasks)
		goto no_join;

	/*
	 * Tie-break on the grp address.
	 */
	if (my_grp->nr_tasks == grp->nr_tasks && my_grp > grp)
		goto no_join;

	/* Always join threads in the same process. */
	if (tsk->mm == current->mm)
		join = true;

	/* Simple filter to avoid false positives due to PID collisions */
	if (flags & TNF_SHARED)
		join = true;

	/* Update priv based on whether false sharing was detected */
	*priv = !join;

	if (join && !get_numa_group(grp))
		goto no_join;

	rcu_read_unlock();

	if (!join)
		return;

	BUG_ON(irqs_disabled());
	double_lock_irq(&my_grp->lock, &grp->lock);

	for (i = 0; i < NR_NUMA_HINT_FAULT_STATS * nr_node_ids; i++) {
		my_grp->faults[i] -= p->numa_faults[i];
		grp->faults[i] += p->numa_faults[i];
	}
	my_grp->total_faults -= p->total_numa_faults;
	grp->total_faults += p->total_numa_faults;

	my_grp->nr_tasks--;
	grp->nr_tasks++;

	spin_unlock(&my_grp->lock);
	spin_unlock_irq(&grp->lock);

	rcu_assign_pointer(p->numa_group, grp);

	put_numa_group(my_grp);
	return;

no_join:
	rcu_read_unlock();
	return;
}

void task_numa_free(struct task_struct *p)
{
	struct numa_group *grp = p->numa_group;
	void *numa_faults = p->numa_faults;
	unsigned long flags;
	int i;

	if (grp) {
		spin_lock_irqsave(&grp->lock, flags);
		for (i = 0; i < NR_NUMA_HINT_FAULT_STATS * nr_node_ids; i++)
			grp->faults[i] -= p->numa_faults[i];
		grp->total_faults -= p->total_numa_faults;

		grp->nr_tasks--;
		spin_unlock_irqrestore(&grp->lock, flags);
		RCU_INIT_POINTER(p->numa_group, NULL);
		put_numa_group(grp);
	}

	p->numa_faults = NULL;
	kfree(numa_faults);
}

/*
 * Got a PROT_NONE fault for a page on @node.
 */
void task_numa_fault(int last_cpupid, int mem_node, int pages, int flags)
{
	struct task_struct *p = current;
	bool migrated = flags & TNF_MIGRATED;
	int cpu_node = task_node(current);
	int local = !!(flags & TNF_FAULT_LOCAL);
	struct numa_group *ng;
	int priv;

	if (!static_branch_likely(&sched_numa_balancing))
		return;

	/* for example, ksmd faulting in a user's mm */
	if (!p->mm)
		return;

	/* Allocate buffer to track faults on a per-node basis */
	if (unlikely(!p->numa_faults)) {
		int size = sizeof(*p->numa_faults) *
			   NR_NUMA_HINT_FAULT_BUCKETS * nr_node_ids;

		p->numa_faults = kzalloc(size, GFP_KERNEL|__GFP_NOWARN);
		if (!p->numa_faults)
			return;

		p->total_numa_faults = 0;
		memset(p->numa_faults_locality, 0, sizeof(p->numa_faults_locality));
	}

	/*
	 * First accesses are treated as private, otherwise consider accesses
	 * to be private if the accessing pid has not changed
	 */
	if (unlikely(last_cpupid == (-1 & LAST_CPUPID_MASK))) {
		priv = 1;
	} else {
		priv = cpupid_match_pid(p, last_cpupid);
		if (!priv && !(flags & TNF_NO_GROUP))
			task_numa_group(p, last_cpupid, flags, &priv);
	}

	/*
	 * If a workload spans multiple NUMA nodes, a shared fault that
	 * occurs wholly within the set of nodes that the workload is
	 * actively using should be counted as local. This allows the
	 * scan rate to slow down when a workload has settled down.
	 */
	ng = p->numa_group;
	if (!priv && !local && ng && ng->active_nodes > 1 &&
				numa_is_active_node(cpu_node, ng) &&
				numa_is_active_node(mem_node, ng))
		local = 1;

	task_numa_placement(p);

	/*
	 * Retry task to preferred node migration periodically, in case it
	 * case it previously failed, or the scheduler moved us.
	 */
	if (time_after(jiffies, p->numa_migrate_retry))
		numa_migrate_preferred(p);

	if (migrated)
		p->numa_pages_migrated += pages;
	if (flags & TNF_MIGRATE_FAIL)
		p->numa_faults_locality[2] += pages;

	p->numa_faults[task_faults_idx(NUMA_MEMBUF, mem_node, priv)] += pages;
	p->numa_faults[task_faults_idx(NUMA_CPUBUF, cpu_node, priv)] += pages;
	p->numa_faults_locality[local] += pages;
}

static void reset_ptenuma_scan(struct task_struct *p)
{
	/*
	 * We only did a read acquisition of the mmap sem, so
	 * p->mm->numa_scan_seq is written to without exclusive access
	 * and the update is not guaranteed to be atomic. That's not
	 * much of an issue though, since this is just used for
	 * statistical sampling. Use READ_ONCE/WRITE_ONCE, which are not
	 * expensive, to avoid any form of compiler optimizations:
	 */
	WRITE_ONCE(p->mm->numa_scan_seq, READ_ONCE(p->mm->numa_scan_seq) + 1);
	p->mm->numa_scan_offset = 0;
}

/*
 * The expensive part of numa migration is done from task_work context.
 * Triggered from task_tick_numa().
 */
void task_numa_work(struct callback_head *work)
{
	unsigned long migrate, next_scan, now = jiffies;
	struct task_struct *p = current;
	struct mm_struct *mm = p->mm;
	u64 runtime = p->se.sum_exec_runtime;
	struct vm_area_struct *vma;
	unsigned long start, end;
	unsigned long nr_pte_updates = 0;
	long pages, virtpages;

	SCHED_WARN_ON(p != container_of(work, struct task_struct, numa_work));

	work->next = work; /* protect against double add */
	/*
	 * Who cares about NUMA placement when they're dying.
	 *
	 * NOTE: make sure not to dereference p->mm before this check,
	 * exit_task_work() happens _after_ exit_mm() so we could be called
	 * without p->mm even though we still had it when we enqueued this
	 * work.
	 */
	if (p->flags & PF_EXITING)
		return;

	if (!mm->numa_next_scan) {
		mm->numa_next_scan = now +
			msecs_to_jiffies(sysctl_numa_balancing_scan_delay);
	}

	/*
	 * Enforce maximal scan/migration frequency..
	 */
	migrate = mm->numa_next_scan;
	if (time_before(now, migrate))
		return;

	if (p->numa_scan_period == 0) {
		p->numa_scan_period_max = task_scan_max(p);
		p->numa_scan_period = task_scan_min(p);
	}

	next_scan = now + msecs_to_jiffies(p->numa_scan_period);
	if (cmpxchg(&mm->numa_next_scan, migrate, next_scan) != migrate)
		return;

	/*
	 * Delay this task enough that another task of this mm will likely win
	 * the next time around.
	 */
	p->node_stamp += 2 * TICK_NSEC;

	start = mm->numa_scan_offset;
	pages = sysctl_numa_balancing_scan_size;
	pages <<= 20 - PAGE_SHIFT; /* MB in pages */
	virtpages = pages * 8;	   /* Scan up to this much virtual space */
	if (!pages)
		return;


	down_read(&mm->mmap_sem);
	vma = find_vma(mm, start);
	if (!vma) {
		reset_ptenuma_scan(p);
		start = 0;
		vma = mm->mmap;
	}
	for (; vma; vma = vma->vm_next) {
		if (!vma_migratable(vma) || !vma_policy_mof(vma) ||
			is_vm_hugetlb_page(vma) || (vma->vm_flags & VM_MIXEDMAP)) {
			continue;
		}

		/*
		 * Shared library pages mapped by multiple processes are not
		 * migrated as it is expected they are cache replicated. Avoid
		 * hinting faults in read-only file-backed mappings or the vdso
		 * as migrating the pages will be of marginal benefit.
		 */
		if (!vma->vm_mm ||
		    (vma->vm_file && (vma->vm_flags & (VM_READ|VM_WRITE)) == (VM_READ)))
			continue;

		/*
		 * Skip inaccessible VMAs to avoid any confusion between
		 * PROT_NONE and NUMA hinting ptes
		 */
		if (!(vma->vm_flags & (VM_READ | VM_EXEC | VM_WRITE)))
			continue;

		do {
			start = max(start, vma->vm_start);
			end = ALIGN(start + (pages << PAGE_SHIFT), HPAGE_SIZE);
			end = min(end, vma->vm_end);
			nr_pte_updates = change_prot_numa(vma, start, end);

			/*
			 * Try to scan sysctl_numa_balancing_size worth of
			 * hpages that have at least one present PTE that
			 * is not already pte-numa. If the VMA contains
			 * areas that are unused or already full of prot_numa
			 * PTEs, scan up to virtpages, to skip through those
			 * areas faster.
			 */
			if (nr_pte_updates)
				pages -= (end - start) >> PAGE_SHIFT;
			virtpages -= (end - start) >> PAGE_SHIFT;

			start = end;
			if (pages <= 0 || virtpages <= 0)
				goto out;

			cond_resched();
		} while (end != vma->vm_end);
	}

out:
	/*
	 * It is possible to reach the end of the VMA list but the last few
	 * VMAs are not guaranteed to the vma_migratable. If they are not, we
	 * would find the !migratable VMA on the next scan but not reset the
	 * scanner to the start so check it now.
	 */
	if (vma)
		mm->numa_scan_offset = start;
	else
		reset_ptenuma_scan(p);
	up_read(&mm->mmap_sem);

	/*
	 * Make sure tasks use at least 32x as much time to run other code
	 * than they used here, to limit NUMA PTE scanning overhead to 3% max.
	 * Usually update_task_scan_period slows down scanning enough; on an
	 * overloaded system we need to limit overhead on a per task basis.
	 */
	if (unlikely(p->se.sum_exec_runtime != runtime)) {
		u64 diff = p->se.sum_exec_runtime - runtime;
		p->node_stamp += 32 * diff;
	}
}

/*
 * Drive the periodic memory faults..
 */
void task_tick_numa(struct rq *rq, struct task_struct *curr)
{
	struct callback_head *work = &curr->numa_work;
	u64 period, now;

	/*
	 * We don't care about NUMA placement if we don't have memory.
	 */
	if (!curr->mm || (curr->flags & PF_EXITING) || work->next != work)
		return;

	/*
	 * Using runtime rather than walltime has the dual advantage that
	 * we (mostly) drive the selection from busy threads and that the
	 * task needs to have done some actual work before we bother with
	 * NUMA placement.
	 */
	now = curr->se.sum_exec_runtime;
	period = (u64)curr->numa_scan_period * NSEC_PER_MSEC;

	if (now > curr->node_stamp + period) {
		if (!curr->node_stamp)
			curr->numa_scan_period = task_scan_min(curr);
		curr->node_stamp += period;

		if (!time_before(jiffies, curr->mm->numa_next_scan)) {
			init_task_work(work, task_numa_work); /* TODO: move this into sched_fork() */
			task_work_add(curr, work, true);
		}
	}
}
#else
static void task_tick_numa(struct rq *rq, struct task_struct *curr)
{
}

static inline void account_numa_enqueue(struct rq *rq, struct task_struct *p)
{
}

static inline void account_numa_dequeue(struct rq *rq, struct task_struct *p)
{
}
#endif /* CONFIG_NUMA_BALANCING */

static void
account_entity_enqueue(struct cfs_rq *cfs_rq, struct sched_entity *se)
{
	/* 把它加到cfs的权重加到cfs_rq->load 里面去 */
	update_load_add(&cfs_rq->load, se->load.weight);
	/*  static inline struct sched_entity *parent_entity(struct sched_entity *se)
	 * {
	 *	return se->parent;
	 * }
	 *
	 * 如果没有parent还要加到该cfs属于rq的那个load中 */
	if (!parent_entity(se))
		update_load_add(&rq_of(cfs_rq)->load, se->load.weight);
#ifdef CONFIG_SMP
	if (entity_is_task(se)) {
		struct rq *rq = rq_of(cfs_rq);

		account_numa_enqueue(rq, task_of(se));
		list_add(&se->group_node, &rq->cfs_tasks);
	}
#endif
	/* 让cfs_rq的nr_running++ */
	cfs_rq->nr_running++;
}

static void
account_entity_dequeue(struct cfs_rq *cfs_rq, struct sched_entity *se)
{
	/* 这边就是让cfs_rq的权重减去se->load.weight */
	update_load_sub(&cfs_rq->load, se->load.weight);
	if (!parent_entity(se))
		update_load_sub(&rq_of(cfs_rq)->load, se->load.weight);
#ifdef CONFIG_SMP
	if (entity_is_task(se)) {
		account_numa_dequeue(rq_of(cfs_rq), task_of(se));
		list_del_init(&se->group_node);
	}
#endif
	/* 让cfs_rq的nr_running -1 */
	cfs_rq->nr_running--;
}

#ifdef CONFIG_FAIR_GROUP_SCHED
# ifdef CONFIG_SMP
static long calc_cfs_shares(struct cfs_rq *cfs_rq, struct task_group *tg)
{
	long tg_weight, load, shares;

	/*
	 * This really should be: cfs_rq->avg.load_avg, but instead we use
	 * cfs_rq->load.weight, which is its upper bound. This helps ramp up
	 * the shares for small weight interactive tasks.
	 */
	load = scale_load_down(cfs_rq->load.weight);

	tg_weight = atomic_long_read(&tg->load_avg);

	/* Ensure tg_weight >= load */
	tg_weight -= cfs_rq->tg_load_avg_contrib;
	tg_weight += load;

	shares = (tg->shares * load);
	if (tg_weight)
		shares /= tg_weight;

	if (shares < MIN_SHARES)
		shares = MIN_SHARES;
	if (shares > tg->shares)
		shares = tg->shares;

	return shares;
}
# else /* CONFIG_SMP */
static inline long calc_cfs_shares(struct cfs_rq *cfs_rq, struct task_group *tg)
{
	return tg->shares;
}
# endif /* CONFIG_SMP */

static void reweight_entity(struct cfs_rq *cfs_rq, struct sched_entity *se,
			    unsigned long weight)
{
	if (se->on_rq) {
		/* commit outstanding execution time */
		if (cfs_rq->curr == se)
			update_curr(cfs_rq);
		account_entity_dequeue(cfs_rq, se);
	}

	update_load_set(&se->load, weight);

	if (se->on_rq)
		account_entity_enqueue(cfs_rq, se);
}

static inline int throttled_hierarchy(struct cfs_rq *cfs_rq);

static void update_cfs_shares(struct cfs_rq *cfs_rq)
{
	struct task_group *tg;
	struct sched_entity *se;
	long shares;

	tg = cfs_rq->tg;
	se = tg->se[cpu_of(rq_of(cfs_rq))];
	if (!se || throttled_hierarchy(cfs_rq))
		return;
#ifndef CONFIG_SMP
	if (likely(se->load.weight == tg->shares))
		return;
#endif
	shares = calc_cfs_shares(cfs_rq, tg);

	reweight_entity(cfs_rq_of(se), se, shares);
}
#else /* CONFIG_FAIR_GROUP_SCHED */
static inline void update_cfs_shares(struct cfs_rq *cfs_rq)
{
}
#endif /* CONFIG_FAIR_GROUP_SCHED */

#ifdef CONFIG_SMP
/* Precomputed fixed inverse multiplies for multiplication by y^n */

/* 我们把1毫秒(准确来说是1024微妙,为了方便移位操作)的时间跨度算出一个周期,称为period,简称PI.
 * 一个调度实体(可以是一个进程,也可以是一个调度组)在一个PI周期内对系统负载的贡献除了权重外,还有在PI周期内可运行的时间,包括运行时间或等待CPU时间.
 * 一个理想的计算方式是: 统计多个实际的PI周期,并是有一个衰减系数来计算过去PI周期对负载的贡献.
 * 假设Li是一个调度实体在第i个周期内的负载贡献,那么一个调度实体的负载总和计算公式如下:
 *	L = L0 + L1*y + L2*y^2 + L3*y^3 +...+L32 *y^32 + ...
 * 这个公式用于计算调度实体的最近的负载,过去的负载也是影响因素,它是一个衰减因子.
 * 因此调度实体的负载需要考虑时间的因素,不能只考虑当前的负载,还要考虑其在过去一段时间内的表项.
 * 衰减的意义类似于信号处理中的采样,距离当前时间点越远,衰减系数越大,对总体影响越小.
 * 其中,y是一个预先选好的衰减系数,y^32约等于0.5,因此统计过去第32个周期的负载可以被简单地认为负载减半.
 * 该计算公式还有简化计算方式,内核不需要使用数组来存放过去PI个周期的负载贡献,只需要用过去周期贡献和乘以衰减系数y,并加上当前时间点的负载L0即可.
 * 内核定义表runnable_avg_yN_inv来方便使用衰减因子
 *
 * 为了处理器计算方法方便,该表对应的因子乘以2^32,计算完成后在右移32位.
 * 在处理器中,乘法运算比浮点运算快得多,其公式等同于
 *
 * A / B = (A * 2 ^ 32) / (B * 2^32) = (A * (2^32/B))/2^32
 *
 * 其中,除以2^32可以用右移32位来计算.
 * runable_avg_yN_inv相当于提前计算了公式中的2^32/B的值.runable_avg_yN_inv表包括32个下标,对应过去0~32毫秒的负载贡献的衰减因子.
 * 举例说明,加上当前进程的负载贡献度是100,要求计算过去第32毫秒的负载.首先查表得到过去32毫秒周期的衰减因子: runable_avg_yN_inv[31].
 * 计算公式为: Load = (100 * runable_avg_yN_inv[31] >>32 ),最后计算结果为51.
 */
static const u32 runnable_avg_yN_inv[] = {
	0xffffffff, 0xfa83b2da, 0xf5257d14, 0xefe4b99a, 0xeac0c6e6, 0xe5b906e6,
	0xe0ccdeeb, 0xdbfbb796, 0xd744fcc9, 0xd2a81d91, 0xce248c14, 0xc9b9bd85,
	0xc5672a10, 0xc12c4cc9, 0xbd08a39e, 0xb8fbaf46, 0xb504f333, 0xb123f581,
	0xad583ee9, 0xa9a15ab4, 0xa5fed6a9, 0xa2704302, 0x9ef5325f, 0x9b8d39b9,
	0x9837f050, 0x94f4efa8, 0x91c3d373, 0x8ea4398a, 0x8b95c1e3, 0x88980e80,
	0x85aac367, 0x82cd8698,
};

/*
 * Precomputed \Sum y^k { 1<=k<=n }.  These are floor(true_value) to prevent
 * over-estimates when re-combining.
 */
/* 为了计算更加方便,内核又维护了一个表runnable_avg_yN_sum,已预先计算好如下公式的值.
 * runnable_avg_yN_sump[] = 1024 * (y + y^2 + y^3 + ... + y^n )
 * 其中,n取1~32.为什么系数是1024呢?因为内核的runnable_avg_yN_sum[]表通常用于计算时间的衰减,
 * 准确地说是周期period,一个周期是1024微妙.
 * 例如n=2时,sum = 1024 * (runnable_avg_yN_inv[1] + runnable_avg_yN_inv[2]) >> 32 = 1024 *(0.978 + 0.957) = 1981.44,就约等于runnable_avg_yN_sum[2].
 */
static const u32 runnable_avg_yN_sum[] = {
	    0, 1002, 1982, 2941, 3880, 4798, 5697, 6576, 7437, 8279, 9103,
	 9909,10698,11470,12226,12966,13690,14398,15091,15769,16433,17082,
	17718,18340,18949,19545,20128,20698,21256,21802,22336,22859,23371,
};

/*
 * Precomputed \Sum y^k { 1<=k<=n, where n%32=0). Values are rolled down to
 * lower integers. See Documentation/scheduler/sched-avg.txt how these
 * were generated:
 */
static const u32 __accumulated_sum_N32[] = {
	    0, 23371, 35056, 40899, 43820, 45281,
	46011, 46376, 46559, 46650, 46696, 46719,
};

/*
 * Approximate:
 *   val * y^n,    where y^32 ~= 0.5 (~1 scheduling period)
 */
/* 内核中的decay_load函数用于计算第n个周期的衰减值
 * 参数val表示n个周期前的负载值,n表示第n个周期,其计算公式,即第n个周期的衰减值为val * y ^ n,计算y^n采用查表的方式,因此计算公式变为:
 *	(val * runnable_avg_yN_inv[n]) >> 32.
 * 因此定义了32毫秒的衰减系数为1/2,每增加32毫秒都要衰减1/2,因此如果period太大,衰减后值会变得很小几乎等于0.
 * 代码 n > LOAD_AVG_PERIOD * 63,当period大于2016就直接等于0.
 */
static __always_inline u64 decay_load(u64 val, u64 n)
{
	unsigned int local_n;
	/* 如果n为0,那么没必要衰减,直接返回val */
	if (!n)
		return val;
	/* 如果period大于2016,那么直接返回0 */
	else if (unlikely(n > LOAD_AVG_PERIOD * 63))
		return 0;

	/* after bounds checking we can collapse to 32-bit */
	local_n = n;

	/*
	 * As y^PERIOD = 1/2, we can combine
	 *    y^n = 1/2^(n/PERIOD) * y^(n%PERIOD)
	 * With a look-up table which covers y^n (n<PERIOD)
	 *
	 * To achieve constant time decay_load.
	 */
	/* 每增加32毫秒就要衰减1/2,相当于右移一位 */
	/* #define LOAD_AVG_PERIOD 32 */
	if (unlikely(local_n >= LOAD_AVG_PERIOD)) {
		val >>= local_n / LOAD_AVG_PERIOD;
		local_n %= LOAD_AVG_PERIOD;
	}

	/* 这里就是val *  runnable_avg_yN_inv[local_n] / 2^32 */
	val = mul_u64_u32_shr(val, runnable_avg_yN_inv[local_n], 32);
	return val;
}

/*
 * For updates fully spanning n periods, the contribution to runnable
 * average will be: \Sum 1024*y^n
 *
 * We can compute this reasonably efficiently by combining:
 *   y^PERIOD = 1/2 with precomputed \Sum 1024*y^n {for  n <PERIOD}
 */
/* __compute_runnable_contrib会使用该表来计算连续n个PI周期的负载累计贡献值.
 * __compute_runnable_contrib函数中的参数n表示PI周期的个数.
 * 如果n小于等于LOAD_AVG_PERIOD(32个周期),那么直接查表runnable_avg_yN_sum[]取值,
 * 如果n大于等于LOAD_AVG_MAX_N(345个周期),那么直接得到极限值LOAD_AVG_MAX(47742).
 * 如果n的范围为32~345,那么每次递进32个衰减周期进行计算,然后把不能凑成32个周期的单独计算并累加.
 */
static u32 __compute_runnable_contrib(u64 n)
{
	u32 contrib = 0;

	/* 如果n小于LOAD_AVG_PERIOD(32个周期),那么直接查表runnable_avg_yN_sum[]取值 */
	if (likely(n <= LOAD_AVG_PERIOD))
		return runnable_avg_yN_sum[n];
	/* 如果n大于等于LOAD_AVG_MAX_N(345个周期),那么直接得到极限值LOAD_AVG_MAX(47742) */
	else if (unlikely(n >= LOAD_AVG_MAX_N))
		return LOAD_AVG_MAX;

	/* Since n < LOAD_AVG_MAX_N, n/LOAD_AVG_PERIOD < 11 */
	/* 如果n的范围为32~345
	 * 用n/32 去查__accumulated_sum_N32[]表
	 */
	contrib = __accumulated_sum_N32[n/LOAD_AVG_PERIOD];
	/* 在得到除以32的余数 */
	n %= LOAD_AVG_PERIOD;
	/* 然后不足32个周期的单独计算并累加 */
	contrib = decay_load(contrib, n);
	/* 返回负载累计贡献值 */
	return contrib + runnable_avg_yN_sum[n];
}

#define cap_scale(v, s) ((v)*(s) >> SCHED_CAPACITY_SHIFT)

/*
 * We can represent the historical contribution to runnable average as the
 * coefficients of a geometric series.  To do this we sub-divide our runnable
 * history into segments of approximately 1ms (1024us); label the segment that
 * occurred N-ms ago p_N, with p_0 corresponding to the current period, e.g.
 *
 * 我们可以将对可运行平均值的历史贡献表示为几何级数的系数.
 * 为此,我们将可运行历史细分为大约1ms(1024us)的片段;
 * 将N毫秒前发生的分段标记为p_N,其中p_0对应于当前时段,例如.
 * [<- 1024us ->|<- 1024us ->|<- 1024us ->| ...
 *      p0            p1           p2
 *     (now)       (~1ms ago)  (~2ms ago)
 *
 * Let u_i denote the fraction of p_i that the entity was runnable.
 * 设u_i表示实体可运行的p_i的分数.
 *
 * We then designate the fractions u_i as our co-efficients, yielding the
 * following representation of historical load:
 *   u_0 + u_1*y + u_2*y^2 + u_3*y^3 + ...
 *
 * 然后,我们将分数u_i指定为我们的系数,得到历史负荷的以下表示:
 *	u_0 + u1*y + u2*y^2 + u_3*y^3 + ...
 * We choose y based on the with of a reasonably scheduling period, fixing:
 *   y^32 = 0.5
 * 我们根据合理的调度周期选择y,固定：y^32=0.5
 *
 * This means that the contribution to load ~32ms ago (u_32) will be weighted
 * approximately half as much as the contribution to load within the last ms
 * (u_0).
 * 这意味着~32ms前(u_32)对负载的贡献将被加权,大约是最后ms内(u_0)对负载贡献的一半.
 *
 * When a period "rolls over" and we have new u_0`, multiplying the previous
 * sum again by y is sufficient to update:
 *   load_avg = u_0` + y*(u_0 + u_1*y + u_2*y^2 + ... )
 *            = u_0 + u_1*y + u_2*y^2 + ... [re-labeling u_i --> u_{i+1}]
 *
 * 当一个周期“滚动”并且我们有新的u_0`时，将之前的总和再次乘以y就足以更新：
 *	load_avg= u_0` + y*(u_0 + u1*y + u2*y^2 + ...)
 *		= u_0 + u1*y + u2*y^2 + ... [re-labeling u_i--> u_{i+1}]
 */
static __always_inline int
__update_load_avg(u64 now, int cpu, struct sched_avg *sa,
		  unsigned long weight, int running, struct cfs_rq *cfs_rq)
{
	u64 delta, scaled_delta, periods;
	u32 contrib;
	unsigned int delta_w, scaled_delta_w, decayed = 0;
	unsigned long scale_freq, scale_cpu;
	/* delta是指从上次更新到本次更新的时间差,单位是纳秒 */
	delta = now - sa->last_update_time;
	/*
	 * This should only happen when time goes backwards, which it
	 * unfortunately does during sched clock init when we swap over to TSC.
	 *
	 * 这应该只在时间倒退时发生,不幸的是,当我们切换到TSC时,在调度时钟初始化期间会发生这种情况.
	 */

	/* 如果delta < 0,那么更新last_update_time之后返回0 */
	if ((s64)delta < 0) {
		sa->last_update_time = now;
		return 0;
	}

	/*
	 * Use 1024ns as the unit of measurement since it's a reasonable
	 * approximation of 1us and fast to compute.
	 *
	 * 使用1024ns作为测量单位,因为它是1us的合理近似值,计算速度快.
	 */
	/* delta时间转换成微妙,注意这里为了计算效率右移10位,相当于除以1024.*/
	delta >>= 10;
	if (!delta)
		return 0;
	sa->last_update_time = now;

	scale_freq = arch_scale_freq_capacity(NULL, cpu); /* 1024*curr_freq/max_freq */

	/* arch_scale_cpu_capacity函数用于计算并返回一个CPU的“容量”值.
	 * 这个值代表了该CPU相对于系统中其他CPU的性能或能力.
	 * 该函数通常是架构特定的,因为不同的CPU架构可能有不同的性能和功耗特性.
	 * 容量值通常会被归一化到一个固定的范围内(例如,0到1024),以便于比较和计算.
	 * 归一化后的值可以与由实体负载跟踪(PELT)机制算出的利用率信号做对比,从而帮助调度器更准确地评估系统的整体负载和性能.
	 */
	scale_cpu = arch_scale_cpu_capacity(NULL, cpu);

	/* delta_w is the amount already accumulated against our next period
	 * delta_w是我们下一个周期已经累积的数额
	 */
	/* delta_w是上一次总周期数中不能凑成一个周期(1024微妙)的剩余的时间 */
	delta_w = sa->period_contrib;
	/* 如果上次剩余delta_w加上本次时间差delta大于一个周期,那么就要进行衰减计算. */
	/*             周期1024微秒  ←------n个周期period-----→|
	 *  __________|_____________|__________________________|________|
	 * |	      |		    |			       |	|
	 * |__________|_____________|__________________________|________|
	 *  	      |      ↑      |                          |←--T2--→|
	 *	      |← T0 →|← T1 →| 					↑
	 *                                                           本次更新节点now
	 */
	if (delta + delta_w >= 1024) {
		decayed = 1;

		/* how much left for next period will start over, we don't know yet
		 * 我们还不知道下一周期还有多少left要重新开始
		 */
		/* 这里把上一次总周期数中不能凑成一个周期(1024微妙)的剩余的时间设置为0,因为我们现在还不知道 */
		sa->period_contrib = 0;

		/*
		 * Now that we know we're crossing a period boundary, figure
		 * out how much from delta we need to complete the current
		 * period and accrue it.
		 *
		 * 现在我们知道我们正在跨越一个周期边界,计算出我们需要从delta中获得多少来完成当前周期并累积它.
		 */
		/* 所以这里就是算出图中的T1,这部分时间是上次更新中不满一个周期的剩余时间段 */
		delta_w = 1024 - delta_w;
		/* #define cap_scale(v, s) ((v)*(s) >> SCHED_CAPACITY_SHIFT) */
		scaled_delta_w = cap_scale(delta_w, scale_freq);
		if (weight) {
			/* load_sum: 对于sched_entity: 进程在就绪队列里的可运行状态下的累计衰减总时间(decay_sum_time),计算的是时间值
			 *           对于cfs_rq: 调度队列中所有进程的累计工作总负载(decay_sum_load)
			 * 所以这里对load_sum进行衰减计算 */
			sa->load_sum += weight * scaled_delta_w;
			/* runnable_load_sum应该是指的可运行状态下的累计衰减总和,应该是该rq可运行状态的所有进程的总和 */
			if (cfs_rq) {
				cfs_rq->runnable_load_sum +=
						weight * scaled_delta_w;
			}
		}
		/* util_sum: 对于sched_entity: 正在运行状态下的累计衰减总时间(decay_sum_time).(使用cfs_rq->curr == se来判断进程是否正在运行);
		 *	     对于cfs_rq: 就绪队列中所有处于运行状态进程的累计衰减总时间(decay_sum_time).只要就绪队列里有正在运行的进程,它就会累加
		 */
		/* 注意的是这里乘以的是scale_cpu */
		if (running)
			sa->util_sum += scaled_delta_w * scale_cpu;

		/* 这里delta减去delta_w就得到了完整的周期段从上图中就是n个周期period + T2 */
		delta -= delta_w;

		/* Figure out how many additional periods this update spans
		 * 计算此更新所跨的额外的周期
		 */
		/* 用delta / 1024 算出多少个周期 */
		periods = delta / 1024;
		/* 算出剩余的不足一个周期的 */
		delta %= 1024;
		/* 这里计算load_sum经历过periods + 1的衰减值(decay_load函数用于计算第n个周期的衰减值) */
		sa->load_sum = decay_load(sa->load_sum, periods + 1);
		/* 计算cfs_rq->runnable_load_sum经历过periods + 1的衰减值 */
		if (cfs_rq) {
			cfs_rq->runnable_load_sum =
				decay_load(cfs_rq->runnable_load_sum, periods + 1);
		}
		/* 计算sa->util_sum的衰减值 */
		sa->util_sum = decay_load((u64)(sa->util_sum), periods + 1);

		/* Efficiently calculate \sum (1..n_period) 1024*y^i */
		/* __compute_runnable_contrib会使用runnable_avg_yN_sum来计算连续n个PI周期的负载累计贡献值 */
		contrib = __compute_runnable_contrib(periods);
		/* #define cap_scale(v, s) ((v)*(s) >> SCHED_CAPACITY_SHIFT) */
		contrib = cap_scale(contrib, scale_freq);
		/* 如果有权重,那么还需要让sa->load_sum + weight * contrib */
		if (weight) {
			sa->load_sum += weight * contrib;
			/* 让cfs_rq->runnable_load_sum加上权重 * 贡献值 */
			if (cfs_rq)
				cfs_rq->runnable_load_sum += weight * contrib;
		}
		/* 让sa->util_sum 加上贡献值 * scale_cpu */
		if (running)
			sa->util_sum += contrib * scale_cpu;
	}

	/* Remainder of delta accrued against u_0` */
	/* 对u_0累计的增量的剩余部分 */
	/* 这里就是不满1个周期的部分进行统计,它就不用做衰减了 */
	scaled_delta = cap_scale(delta, scale_freq);
	if (weight) {
		sa->load_sum += weight * scaled_delta;
		if (cfs_rq)
			cfs_rq->runnable_load_sum += weight * scaled_delta;
	}
	/* 指的注意的是这里是乘以的scale_cpu */
	if (running)
		sa->util_sum += scaled_delta * scale_cpu;
	/* 这里把delta赋值给period_contrib */
	sa->period_contrib += delta;
	/* decayed等于1说明如果上次剩余delta_w加上本次时间差delta大于一个周期 */
	if (decayed) {
		/* load_avg: 对于sched_entity: 可运行状态下的量化负载(decay_avg_load).负载均衡中,使用该成员来衡量一个进程的负载贡献值,如衡量迁移进程的负载量.
		 *	     对于cfs_rq：就绪队列中总的量化负载
		 *
		 * #define LOAD_AVG_MAX 47742 maximum possible load avg
		 * 这里load_avg = sa->load_sum / 47742
		 */
		sa->load_avg = div_u64(sa->load_sum, LOAD_AVG_MAX);
		/* 同理 */
		if (cfs_rq) {
			cfs_rq->runnable_load_avg =
				div_u64(cfs_rq->runnable_load_sum, LOAD_AVG_MAX);
		}
		/* 同理 */
		sa->util_avg = sa->util_sum / LOAD_AVG_MAX;
	}

	return decayed;
}

#ifdef CONFIG_FAIR_GROUP_SCHED
/**
 * update_tg_load_avg - update the tg's load avg
 * @cfs_rq: the cfs_rq whose avg changed
 * @force: update regardless of how small the difference
 *
 * This function 'ensures': tg->load_avg := \Sum tg->cfs_rq[]->avg.load.
 * However, because tg->load_avg is a global value there are performance
 * considerations.
 *
 * In order to avoid having to look at the other cfs_rq's, we use a
 * differential update where we store the last value we propagated. This in
 * turn allows skipping updates if the differential is 'small'.
 *
 * Updating tg's load_avg is necessary before update_cfs_share() (which is
 * done) and effective_load() (which is not done because it is too costly).
 */
static inline void update_tg_load_avg(struct cfs_rq *cfs_rq, int force)
{
	long delta = cfs_rq->avg.load_avg - cfs_rq->tg_load_avg_contrib;

	/*
	 * No need to update load_avg for root_task_group as it is not used.
	 */
	if (cfs_rq->tg == &root_task_group)
		return;

	if (force || abs(delta) > cfs_rq->tg_load_avg_contrib / 64) {
		atomic_long_add(delta, &cfs_rq->tg->load_avg);
		cfs_rq->tg_load_avg_contrib = cfs_rq->avg.load_avg;
	}
}

/*
 * Called within set_task_rq() right before setting a task's cpu. The
 * caller only guarantees p->pi_lock is held; no other assumptions,
 * including the state of rq->lock, should be made.
 */
void set_task_rq_fair(struct sched_entity *se,
		      struct cfs_rq *prev, struct cfs_rq *next)
{
	if (!sched_feat(ATTACH_AGE_LOAD))
		return;

	/*
	 * We are supposed to update the task to "current" time, then its up to
	 * date and ready to go to new CPU/cfs_rq. But we have difficulty in
	 * getting what current time is, so simply throw away the out-of-date
	 * time. This will result in the wakee task is less decayed, but giving
	 * the wakee more load sounds not bad.
	 */
	if (se->avg.last_update_time && prev) {
		u64 p_last_update_time;
		u64 n_last_update_time;

#ifndef CONFIG_64BIT
		u64 p_last_update_time_copy;
		u64 n_last_update_time_copy;

		do {
			p_last_update_time_copy = prev->load_last_update_time_copy;
			n_last_update_time_copy = next->load_last_update_time_copy;

			smp_rmb();

			p_last_update_time = prev->avg.last_update_time;
			n_last_update_time = next->avg.last_update_time;

		} while (p_last_update_time != p_last_update_time_copy ||
			 n_last_update_time != n_last_update_time_copy);
#else
		p_last_update_time = prev->avg.last_update_time;
		n_last_update_time = next->avg.last_update_time;
#endif
		__update_load_avg(p_last_update_time, cpu_of(rq_of(prev)),
				  &se->avg, 0, 0, NULL);
		se->avg.last_update_time = n_last_update_time;
	}
}
#else /* CONFIG_FAIR_GROUP_SCHED */
static inline void update_tg_load_avg(struct cfs_rq *cfs_rq, int force) {}
#endif /* CONFIG_FAIR_GROUP_SCHED */

static inline void cfs_rq_util_change(struct cfs_rq *cfs_rq)
{
	if (&this_rq()->cfs == cfs_rq) {
		/*
		 * There are a few boundary cases this might miss but it should
		 * get called often enough that that should (hopefully) not be
		 * a real problem -- added to that it only calls on the local
		 * CPU, so if we enqueue remotely we'll miss an update, but
		 * the next tick/schedule should update.
		 *
		 * It will not get called when we go idle, because the idle
		 * thread is a different class (!fair), nor will the utilization
		 * number include things like RT tasks.
		 *
		 * As is, the util number is not freq-invariant (we'd have to
		 * implement arch_scale_freq_capacity() for that).
		 *
		 * See cpu_util().
		 */
		cpufreq_update_util(rq_of(cfs_rq), 0);
	}
}

/*
 * Unsigned subtract and clamp on underflow.
 *
 * Explicitly do a load-store to ensure the intermediate value never hits
 * memory. This allows lockless observations without ever seeing the negative
 * values.
 */
#define sub_positive(_ptr, _val) do {				\
	typeof(_ptr) ptr = (_ptr);				\
	typeof(*ptr) val = (_val);				\
	typeof(*ptr) res, var = READ_ONCE(*ptr);		\
	res = var - val;					\
	if (res > var)						\
		res = 0;					\
	WRITE_ONCE(*ptr, res);					\
} while (0)

/**
 * update_cfs_rq_load_avg - update the cfs_rq's load/util averages
 * @now: current time, as per cfs_rq_clock_task()
 * @cfs_rq: cfs_rq to update
 * @update_freq: should we call cfs_rq_util_change() or will the call do so
 *
 * The cfs_rq avg is the direct sum of all its entities (blocked and runnable)
 * avg. The immediate corollary is that all (fair) tasks must be attached, see
 * post_init_entity_util_avg().
 *
 * cfs_rq->avg is used for task_h_load() and update_cfs_share() for example.
 *
 * Returns true if the load decayed or we removed load.
 *
 * Since both these conditions indicate a changed cfs_rq->avg.load we should
 * call update_tg_load_avg() when this function returns true.
 *
 * update_cfs_rq_load_avg - 更新cfs_rq的负载/util平均值
 * @now: 当前时间,根据cfs_rq_clock_task()
 * @cfs_rq: 要更新的cfs_rq
 * @update_freq: 我们应该调用cfg_rq_util_change或者将会调用
 *
 * cfs_rq平均值是其所有实体(阻塞和可运行)平均值的直接和.
 * 直接的推论是必须附加所有(公平)task,请参阅post_init_entity_util_avg().
 *
 * cfs_rq->avg用于task_h_load()和update_cfs_share()
 *
 * 如果负载衰减或我们移除了负载,则返回true.
 *
 * 由于这两个条件都表示cfs_rq->avg.load发生了变化,因此当此函数返回true时,我们应该调用update_tg_load_avg().
 */
static inline int
update_cfs_rq_load_avg(u64 now, struct cfs_rq *cfs_rq, bool update_freq)
{
	/* 拿到cfs_rq的复制结构体 */
	struct sched_avg *sa = &cfs_rq->avg;
	int decayed, removed_load = 0, removed_util = 0;
	/* 是否设置了remove_load_avg和remove_util_avg,如果设置了就修正之前计算的load/util数值 */
	if (atomic_long_read(&cfs_rq->removed_load_avg)) {
		/* 将cfs_rq->removed_load_avg复制为0,然后把旧值赋值给r */
		s64 r = atomic_long_xchg(&cfs_rq->removed_load_avg, 0);
		/* sub_positive: if(arg1-arg2 > arg1) arg1=0; 说明arg2是个负数(溢出)
		 * 这里就是减去 r
		 */
		sub_positive(&sa->load_avg, r);
		sub_positive(&sa->load_sum, r * LOAD_AVG_MAX);
		/* 然后把removed_load = 1 */
		removed_load = 1;
	}

	if (atomic_long_read(&cfs_rq->removed_util_avg)) {
		long r = atomic_long_xchg(&cfs_rq->removed_util_avg, 0);
		sub_positive(&sa->util_avg, r);
		sub_positive(&sa->util_sum, r * LOAD_AVG_MAX);
		removed_util = 1;
	}

	decayed = __update_load_avg(now, cpu_of(rq_of(cfs_rq)), sa,
		scale_load_down(cfs_rq->load.weight), cfs_rq->curr != NULL, cfs_rq);

#ifndef CONFIG_64BIT
	smp_wmb();
	cfs_rq->load_last_update_time_copy = sa->last_update_time;
#endif

	if (update_freq && (decayed || removed_util))
		cfs_rq_util_change(cfs_rq);

	return decayed || removed_load;
}

/* Update task and its cfs_rq load average */
static inline void update_load_avg(struct sched_entity *se, int update_tg)
{
	struct cfs_rq *cfs_rq = cfs_rq_of(se);
	u64 now = cfs_rq_clock_task(cfs_rq);
	struct rq *rq = rq_of(cfs_rq);
	int cpu = cpu_of(rq);

	/*
	 * Track task load average for carrying it to new CPU after migrated, and
	 * track group sched_entity load average for task_h_load calc in migration
	 */
	__update_load_avg(now, cpu, &se->avg,
			  se->on_rq * scale_load_down(se->load.weight),
			  cfs_rq->curr == se, NULL);

	if (update_cfs_rq_load_avg(now, cfs_rq, true) && update_tg)
		update_tg_load_avg(cfs_rq, 0);
}

/**
 * attach_entity_load_avg - attach this entity to its cfs_rq load avg
 * @cfs_rq: cfs_rq to attach to
 * @se: sched_entity to attach
 *
 * Must call update_cfs_rq_load_avg() before this, since we rely on
 * cfs_rq->avg.last_update_time being current.
 *
 * attach_entity_load_avg-将此实体附加到其cfs_rq负载平均值
 * @cfs_rq: 要附加的cfs_rq
 * @se: 要附加的sched_entity
 *
 * 在此之前必须调用update_cfs_rq_load_avg(),因为我们依赖于当前的cfg_rq>avg.last_update_time.
 */
static void attach_entity_load_avg(struct cfs_rq *cfs_rq, struct sched_entity *se)
{
	/* 这个应该是说赋值的时候不要经过衰减 */
	if (!sched_feat(ATTACH_AGE_LOAD))
		goto skip_aging;

	/*
	 * If we got migrated (either between CPUs or between cgroups) we'll
	 * have aged the average right before clearing @last_update_time.
	 *
	 * Or we're fresh through post_init_entity_util_avg().
	 *
	 * 如果我们被迁移(在CPU之间或在cgroups之间),我们将在清除@last_update_time之前对平均值进行老化.
	 *
	 * 或者我们刚刚通过post_init_entity_util_avg().
	 */
	/* 这边就是去衰减这个se->avg */
	if (se->avg.last_update_time) {
		__update_load_avg(cfs_rq->avg.last_update_time, cpu_of(rq_of(cfs_rq)),
				  &se->avg, 0, 0, NULL);

		/*
		 * XXX: we could have just aged the entire load away if we've been
		 * absent from the fair class for too long.
		 *
		 * XXX: 如果我们在fair class缺席太久的话,我们可能会把所有的东西都老化掉。
		 */
	}

skip_aging:
	/* 这边就是让cfs_rq的avg加上这个进程相关的东西 */
	se->avg.last_update_time = cfs_rq->avg.last_update_time;
	cfs_rq->avg.load_avg += se->avg.load_avg;
	cfs_rq->avg.load_sum += se->avg.load_sum;
	cfs_rq->avg.util_avg += se->avg.util_avg;
	cfs_rq->avg.util_sum += se->avg.util_sum;

	cfs_rq_util_change(cfs_rq);
}

/**
 * detach_entity_load_avg - detach this entity from its cfs_rq load avg
 * @cfs_rq: cfs_rq to detach from
 * @se: sched_entity to detach
 *
 * Must call update_cfs_rq_load_avg() before this, since we rely on
 * cfs_rq->avg.last_update_time being current.
 */
static void detach_entity_load_avg(struct cfs_rq *cfs_rq, struct sched_entity *se)
{
	__update_load_avg(cfs_rq->avg.last_update_time, cpu_of(rq_of(cfs_rq)),
			  &se->avg, se->on_rq * scale_load_down(se->load.weight),
			  cfs_rq->curr == se, NULL);

	sub_positive(&cfs_rq->avg.load_avg, se->avg.load_avg);
	sub_positive(&cfs_rq->avg.load_sum, se->avg.load_sum);
	sub_positive(&cfs_rq->avg.util_avg, se->avg.util_avg);
	sub_positive(&cfs_rq->avg.util_sum, se->avg.util_sum);

	cfs_rq_util_change(cfs_rq);
}

/* Add the load generated by se into cfs_rq's load average */
static inline void
enqueue_entity_load_avg(struct cfs_rq *cfs_rq, struct sched_entity *se)
{
	/* 拿到se的sched_avg */
	struct sched_avg *sa = &se->avg;
	/* 拿到当前task的cfs_rq的clock */
	u64 now = cfs_rq_clock_task(cfs_rq);
	int migrated, decayed;

	/* 如果说sa->last_update_time为0,那么说明它是迁移的 */
	migrated = !sa->last_update_time;
	/* 如果不是迁移的,那么就要进行衰减了 */
	if (!migrated) {
		__update_load_avg(now, cpu_of(rq_of(cfs_rq)), sa,
			se->on_rq * scale_load_down(se->load.weight),
			cfs_rq->curr == se, NULL);
	}
	/* 更新cfs rq的权重 */
	decayed = update_cfs_rq_load_avg(now, cfs_rq, !migrated);

	/* 加上这个task的 平均负载,(load_sum*load->weight)/最大衰减值
	 * runnable_load_avg;  // runnable状态平均负载贡献
	 *
	 * load_sum: 对于sched_entity: 进程在就绪队列里的可运行状态下的累计衰减总时间(decay_sum_time),计算的是时间值
	 *	     对于cfs_rq: 调度队列中所有进程的累计工作总负载(decay_sum_load)
	 */
	cfs_rq->runnable_load_avg += sa->load_avg;
	cfs_rq->runnable_load_sum += sa->load_sum;

	/* 如果是迁移的,还需要加上当前进程的一些负载信息 */
	if (migrated)
		attach_entity_load_avg(cfs_rq, se);

	if (decayed || migrated)
		update_tg_load_avg(cfs_rq, 0);
}

/* Remove the runnable load generated by se from cfs_rq's runnable load average */
static inline void
dequeue_entity_load_avg(struct cfs_rq *cfs_rq, struct sched_entity *se)
{
	/* 更新权重 */
	update_load_avg(se, 1);

	/* 让cfs_rq减去这些这个进程的权重等 */
	cfs_rq->runnable_load_avg =
		max_t(long, cfs_rq->runnable_load_avg - se->avg.load_avg, 0);
	cfs_rq->runnable_load_sum =
		max_t(s64,  cfs_rq->runnable_load_sum - se->avg.load_sum, 0);
}

#ifndef CONFIG_64BIT
static inline u64 cfs_rq_last_update_time(struct cfs_rq *cfs_rq)
{
	u64 last_update_time_copy;
	u64 last_update_time;

	do {
		last_update_time_copy = cfs_rq->load_last_update_time_copy;
		smp_rmb();
		last_update_time = cfs_rq->avg.last_update_time;
	} while (last_update_time != last_update_time_copy);

	return last_update_time;
}
#else
static inline u64 cfs_rq_last_update_time(struct cfs_rq *cfs_rq)
{
	return cfs_rq->avg.last_update_time;
}
#endif

/*
 * Task first catches up with cfs_rq, and then subtract
 * itself from the cfs_rq (task must be off the queue now).
 */
void remove_entity_load_avg(struct sched_entity *se)
{
	struct cfs_rq *cfs_rq = cfs_rq_of(se);
	u64 last_update_time;

	/*
	 * tasks cannot exit without having gone through wake_up_new_task() ->
	 * post_init_entity_util_avg() which will have added things to the
	 * cfs_rq, so we can remove unconditionally.
	 *
	 * Similarly for groups, they will have passed through
	 * post_init_entity_util_avg() before unregister_sched_fair_group()
	 * calls this.
	 */

	last_update_time = cfs_rq_last_update_time(cfs_rq);

	__update_load_avg(last_update_time, cpu_of(rq_of(cfs_rq)), &se->avg, 0, 0, NULL);
	atomic_long_add(se->avg.load_avg, &cfs_rq->removed_load_avg);
	atomic_long_add(se->avg.util_avg, &cfs_rq->removed_util_avg);
}

static inline unsigned long cfs_rq_runnable_load_avg(struct cfs_rq *cfs_rq)
{
	return cfs_rq->runnable_load_avg;
}

static inline unsigned long cfs_rq_load_avg(struct cfs_rq *cfs_rq)
{
	return cfs_rq->avg.load_avg;
}

static int idle_balance(struct rq *this_rq);

#else /* CONFIG_SMP */

static inline int
update_cfs_rq_load_avg(u64 now, struct cfs_rq *cfs_rq, bool update_freq)
{
	return 0;
}

static inline void update_load_avg(struct sched_entity *se, int not_used)
{
	cpufreq_update_util(rq_of(cfs_rq_of(se)), 0);
}

static inline void
enqueue_entity_load_avg(struct cfs_rq *cfs_rq, struct sched_entity *se) {}
static inline void
dequeue_entity_load_avg(struct cfs_rq *cfs_rq, struct sched_entity *se) {}
static inline void remove_entity_load_avg(struct sched_entity *se) {}

static inline void
attach_entity_load_avg(struct cfs_rq *cfs_rq, struct sched_entity *se) {}
static inline void
detach_entity_load_avg(struct cfs_rq *cfs_rq, struct sched_entity *se) {}

static inline int idle_balance(struct rq *rq)
{
	return 0;
}

#endif /* CONFIG_SMP */

static void check_spread(struct cfs_rq *cfs_rq, struct sched_entity *se)
{
#ifdef CONFIG_SCHED_DEBUG
	s64 d = se->vruntime - cfs_rq->min_vruntime;

	if (d < 0)
		d = -d;

	if (d > 3*sysctl_sched_latency)
		schedstat_inc(cfs_rq->nr_spread_over);
#endif
}

/* place_entity参数cfs_rq指父进程对应的cfs就绪队列,se是新进程的调度实体.
 * initial值为1.
 * 如果每个cfs_rq就绪队列中都有一个成员min_vruntime. min_vruntime其实是单独递增的,
 * 用于跟踪整个CFS就绪队列中红黑树里的最小vruntime值.
 */
static void
place_entity(struct cfs_rq *cfs_rq, struct sched_entity *se, int initial)
{
	u64 vruntime = cfs_rq->min_vruntime;

	/*
	 * The 'current' period is already promised to the current tasks,
	 * however the extra weight of the new task will slow them down a
	 * little, place the new task so that it fits in the slot that
	 * stays open at the end.
	 *
	 * "current"周期已经承诺给当前任务,但是新任务的额外权重会使它们慢一点,将新任务放置在合适的位置最后保持开放.
	 */

	/* sched_features的START_DEBIT位: 规定新进程的第一次运行要有延迟 */
	/* 如果当前进程用于fork新进程,那么这里会对新进程的vruntime做一些惩罚,因为新创建了一个进程导致CFS运行队列的权重发生了
	 * 变化.惩罚值通过sched_vslice函数来计算
	 */
	if (initial && sched_feat(START_DEBIT))
		vruntime += sched_vslice(cfs_rq, se);

	/* sleeps up to a single latency don't count.
	 * 睡眠达一个延迟不算在内.
	 */
	if (!initial) {
		/* unsigned int sysctl_sched_latency = 6000000ULL; 6ms */
		unsigned long thresh = sysctl_sched_latency;

		/*
		 * Halve their sleep time's effect, to allow
		 * for a gentler effect of sleepers:
		 *
		 * 将睡眠时间的影响减半,以便对睡眠者产生更温和的影响:
		 */
		/* initial等于0,表示为唤醒的进程,对唤醒的进程进行一定的补偿
		 * 补偿为默认调度周期的一半，即3ms，减去调度周期的一半: 3ms
		 */

		/* GENTLE_FAIR_SLEEPERS
		 * 该功能用来限制睡眠线程的补偿时间为sysctl_sched_latency的50%,可以减少其他任务的调度延迟,该功能内核默认打开.
		 * 如果关闭该特性,则唤醒线程可以获得更多的执行时间,但于此同时,调度队列上的其他任务则会由较大的调度延迟.
		 */
		/* 这里将睡眠线程的最大补偿时间设置为内核调度延迟的一半,这样做可以
		 * 防止睡眠时间较长的线程被唤醒后获得的时间片过长,让调度队列上
		 * 的其他任务出现较大的调度延迟毛刺
		 */
		if (sched_feat(GENTLE_FAIR_SLEEPERS))
			thresh >>= 1;

		vruntime -= thresh;
	}

	/* ensure we never gain time by being placed backwards. */
	se->vruntime = max_vruntime(se->vruntime, vruntime);
}

static void check_enqueue_throttle(struct cfs_rq *cfs_rq);

static inline void check_schedstat_required(void)
{
#ifdef CONFIG_SCHEDSTATS
	if (schedstat_enabled())
		return;

	/* Force schedstat enabled if a dependent tracepoint is active */
	if (trace_sched_stat_wait_enabled()    ||
			trace_sched_stat_sleep_enabled()   ||
			trace_sched_stat_iowait_enabled()  ||
			trace_sched_stat_blocked_enabled() ||
			trace_sched_stat_runtime_enabled())  {
		printk_deferred_once("Scheduler tracepoints stat_sleep, stat_iowait, "
			     "stat_blocked and stat_runtime require the "
			     "kernel parameter schedstats=enabled or "
			     "kernel.sched_schedstats=1\n");
	}
#endif
}


/*
 * MIGRATION
 *
 *	dequeue
 *	  update_curr()
 *	    update_min_vruntime()
 *	  vruntime -= min_vruntime
 *
 *	enqueue
 *	  update_curr()
 *	    update_min_vruntime()
 *	  vruntime += min_vruntime
 *
 * this way the vruntime transition between RQs is done when both
 * min_vruntime are up-to-date.
 *
 * WAKEUP (remote)
 *
 *	->migrate_task_rq_fair() (p->state == TASK_WAKING)
 *	  vruntime -= min_vruntime
 *
 *	enqueue
 *	  update_curr()
 *	    update_min_vruntime()
 *	  vruntime += min_vruntime
 *
 * this way we don't have the most up-to-date min_vruntime on the originating
 * CPU and an up-to-date min_vruntime on the destination CPU.
 */

static void
enqueue_entity(struct cfs_rq *cfs_rq, struct sched_entity *se, int flags)
{
	/* 如果不是被WAKEUP入队的或者说是迁移入队的,那么renorm为1 */
	bool renorm = !(flags & ENQUEUE_WAKEUP) || (flags & ENQUEUE_MIGRATED);
	/* 这里判断当前队列运行的进程是不是se */
	bool curr = cfs_rq->curr == se;

	/*
	 * If we're the current task, we must renormalise before calling
	 * update_curr().
	 *
	 * 如果我们是当前任务,则必须在调用update_curr()之前重新规范化.
	 */
	/* 如果我们是被WAKEUP入队,或者被迁移入队的,并且当前队列运行的进程就是我,那么se->vruntime += cfs_rq->min_vruntime */
	if (renorm && curr)
		se->vruntime += cfs_rq->min_vruntime;

	/* 因为vruntime发生了变化,所以更新一下当前进程的vruntime和该CFS就绪队列的min_vruntime  */
	update_curr(cfs_rq);

	/*
	 * Otherwise, renormalise after, such that we're placed at the current
	 * moment in time, instead of some random moment in the past. Being
	 * placed in the past could significantly boost this task to the
	 * fairness detriment of existing tasks.
	 *
	 * 否则,在之后重新规范化,这样我们就被放置在当前时刻,而不是过去的某个随机时刻.
	 * 被放在过去可能会大大促进这项任务,损害现有任务的公平性.
	 */

	/* 实际新进程刚创建的时候,应该是走的这里
	 * 因此该进程的vruntime要加上min_vruntime.
	 * 回想之前在task_fork_fair函数里vruntime减去min_vruntime,这里又添加回来,因为task_fork_fair只是创建进程还没有把该进程添加到调度器,这期间min_vruntime已经发生了变化,因此添加上min_vruntime是比较准确的
	 */
	if (renorm && !curr)
		se->vruntime += cfs_rq->min_vruntime;
	/* 计算该调度实体se的平均负载,然后添加到整个CFS就绪队列的总平均负载*/
	enqueue_entity_load_avg(cfs_rq, se);
	/* 给cfs_rq加上我们的权重 */
	account_entity_enqueue(cfs_rq, se);
	update_cfs_shares(cfs_rq);
	/* 处理刚被唤醒的进程,place_entity对唤醒进程有一定的补偿,最多可以补偿一个调度周期的一半(默认值sysctl_sched_latency/2,3毫秒),即vruntime减去半个调度周期时间 */
	if (flags & ENQUEUE_WAKEUP)
		place_entity(cfs_rq, se, 0);

	check_schedstat_required();
	update_stats_enqueue(cfs_rq, se, flags);
	check_spread(cfs_rq, se);
	/* 那该调度实体键入到CFS就绪队列的红黑树中 */
	if (!curr)
		__enqueue_entity(cfs_rq, se);
	/* 设置on_rq为1 */
	se->on_rq = 1;

	if (cfs_rq->nr_running == 1) {
		list_add_leaf_cfs_rq(cfs_rq);
		check_enqueue_throttle(cfs_rq);
	}
}

static void __clear_buddies_last(struct sched_entity *se)
{
	for_each_sched_entity(se) {
		struct cfs_rq *cfs_rq = cfs_rq_of(se);
		if (cfs_rq->last != se)
			break;

		cfs_rq->last = NULL;
	}
}

static void __clear_buddies_next(struct sched_entity *se)
{
	for_each_sched_entity(se) {
		struct cfs_rq *cfs_rq = cfs_rq_of(se);
		if (cfs_rq->next != se)
			break;

		cfs_rq->next = NULL;
	}
}

static void __clear_buddies_skip(struct sched_entity *se)
{
	for_each_sched_entity(se) {
		struct cfs_rq *cfs_rq = cfs_rq_of(se);
		if (cfs_rq->skip != se)
			break;

		cfs_rq->skip = NULL;
	}
}

static void clear_buddies(struct cfs_rq *cfs_rq, struct sched_entity *se)
{
	if (cfs_rq->last == se)
		__clear_buddies_last(se);

	if (cfs_rq->next == se)
		__clear_buddies_next(se);

	if (cfs_rq->skip == se)
		__clear_buddies_skip(se);
}

static __always_inline void return_cfs_rq_runtime(struct cfs_rq *cfs_rq);

static void
dequeue_entity(struct cfs_rq *cfs_rq, struct sched_entity *se, int flags)
{
	/*
	 * Update run-time statistics of the 'current'.
	 *
	 * 更新“current”的运行时统计信息.
	 */
	update_curr(cfs_rq);
	/* 这边是减去se的负载相关的成员变量 */
	dequeue_entity_load_avg(cfs_rq, se);

	/* 这边就是更新se->statistics相关的成员 */
	update_stats_dequeue(cfs_rq, se, flags);

	/* 清掉buddy里的指针 */
	clear_buddies(cfs_rq, se);
	/* 如果要拔出的是在运行队列里面等待的进程,那么直接把它踢出运行队列
	 * 这里主要是把它从红黑树里面抹去
	 */
	if (se != cfs_rq->curr)
		__dequeue_entity(cfs_rq, se);
	/* 设置se->on_rq为0 */
	se->on_rq = 0;
	/* 这边是对cfs_rq的一些计数的减法 */
	account_entity_dequeue(cfs_rq, se);

	/*
	 * Normalize after update_curr(); which will also have moved
	 * min_vruntime if @se is the one holding it back. But before doing
	 * update_min_vruntime() again, which will discount @se's position and
	 * can move min_vruntime forward still more.
	 *
	 * update_curr()后进行规格化;
	 * 如果@se阻碍了min_vruntime,那么它也将移动min_vruntime.
	 * 但在再次执行update_min_vruntime()之前.这将降低@se的位置.并可以进一步向前移动min_vruntime.
	 */

	/* 如果不是退出队列睡眠,那么让se->vruntime减去cfs_rq->min_vruntime */
	if (!(flags & DEQUEUE_SLEEP))
		se->vruntime -= cfs_rq->min_vruntime;

	/* return excess runtime on last dequeue
	 * 在最后一次出列时返回多余的运行时间
	 */
	return_cfs_rq_runtime(cfs_rq);

	update_cfs_shares(cfs_rq);

	/*
	 * Now advance min_vruntime if @se was the entity holding it back,
	 * except when: DEQUEUE_SAVE && !DEQUEUE_MOVE, in this case we'll be
	 * put back on, and if we advance min_vruntime, we'll be placed back
	 * further than we started -- ie. we'll be penalized.
	 *
	 * 现在,如果@se是阻碍min_vruntime前进的实体,则前进min_vruntime,除非出现以下情况:
	 * DEQUEUE_SAVE && !DEQUEUE_MOVE,在这种情况下,我们将被重新安排,如果我们提前min_vruntime,
	 * 我们将比开始时被安排得更远 —— 也就是说,我们将受到惩罚.
	 */
	if ((flags & (DEQUEUE_SAVE | DEQUEUE_MOVE)) == DEQUEUE_SAVE)
		update_min_vruntime(cfs_rq);
}

/*
 * Preempt the current task with a newly woken task if needed:
 *
 * 如果需要,使用新唤醒的任务抢占当前任务
 */
static void
check_preempt_tick(struct cfs_rq *cfs_rq, struct sched_entity *curr)
{
	unsigned long ideal_runtime, delta_exec;
	struct sched_entity *se;
	s64 delta;

	/* ideal_runtime是理论运行时间,即该进程更加权重在一个调度周期里分到的实际运行时间 */
	ideal_runtime = sched_slice(cfs_rq, curr);
	/* delta_exec是实际运行时间 */
	delta_exec = curr->sum_exec_runtime - curr->prev_sum_exec_runtime;
	/* 如果实际运行时间已经超过了理论运行时间,那么进程要被调度出去,设置该进程中的thread_info中的TIF_NEED_RESCHED标志位 */
	if (delta_exec > ideal_runtime) {
		resched_curr(rq_of(cfs_rq));
		/*
		 * The current task ran long enough, ensure it doesn't get
		 * re-elected due to buddy favours.
		 *
		 * 目前的任务持续了足够长的时间,以确保它不会因为好友的青睐而再次当选.
		 */
		clear_buddies(cfs_rq, curr);
		return;
	}

	/*
	 * Ensure that a task that missed wakeup preemption by a
	 * narrow margin doesn't have to wait for a full slice.
	 * This also mitigates buddy induced latencies under load.
	 *
	 * 确保以微弱优势错过唤醒抢占的任务不必等待完整的切片.
	 * 这也减轻了负载下好友引起的延迟.
	 */

	/* 系统中有一个变量定义进程最少运行时间sysctl_sched_min_granularity,默认是0.75毫秒.
	 * 如果该进程实际运行时间小于这个值,也不需要调度.
	 */
	if (delta_exec < sysctl_sched_min_granularity)
		return;

	/* 最后将该进程的虚拟时间和就绪队列红黑树中最左边的调度实体的虚拟时间做比较,
	 * 如果小于最左边的时间,则不用触发调度.
	 * 反之,则这个差值大于该进程的理论运行时间,会触发调度.
	 */
	se = __pick_first_entity(cfs_rq);
	delta = curr->vruntime - se->vruntime;

	if (delta < 0)
		return;

	if (delta > ideal_runtime)
		resched_curr(rq_of(cfs_rq));
}

static void
set_next_entity(struct cfs_rq *cfs_rq, struct sched_entity *se)
{
	/* 'current' is not kept within the tree. */
	/* 运行中的进程是不在rq上保留的,所以将其从cfs_rq上dequeue */
	if (se->on_rq) {
		/*
		 * Any task has to be enqueued before it get to execute on
		 * a CPU. So account for the time it spent waiting on the
		 * runqueue.
		 */
		/* entity即将获得cpu,统计调度延时等. 与put_prev_entity->update_stats_wait_start配对 */
		update_stats_wait_end(cfs_rq, se);
		/* 从cfs_rq上移除entity */
		__dequeue_entity(cfs_rq, se);
		/* cfs_rq上移除后更新rq的负载 */
		update_load_avg(se, 1);
	}

	/* 开始计时se的execute时间,用rq的clock_task赋值给se->exec_start */
	update_stats_curr_start(cfs_rq, se);
	/* 更新cfs_rq的curr为se,即挑选出来的next进程 */
	cfs_rq->curr = se;

	/*
	 * Track our maximum slice length, if the CPU's load is at
	 * least twice that of our own weight (i.e. dont track it
	 * when there are only lesser-weight tasks around):
	 */
	if (schedstat_enabled() && rq_of(cfs_rq)->load.weight >= 2*se->load.weight) {
		schedstat_set(se->statistics.slice_max,
			max((u64)schedstat_val(se->statistics.slice_max),
			    se->sum_exec_runtime - se->prev_sum_exec_runtime));
	}

	/* 更新se的prev_sum_exec_runtime */
	se->prev_sum_exec_runtime = se->sum_exec_runtime;
}

static int
wakeup_preempt_entity(struct sched_entity *curr, struct sched_entity *se);

/*
 * Pick the next process, keeping these things in mind, in this order:
 * 1) keep things fair between processes/task groups
 * 2) pick the "next" process, since someone really wants that to run
 * 3) pick the "last" process, for cache locality
 * 4) do not run the "skip" process, if something else is available
 *
 * 选择下一个流程,记住以下事项,按以下顺序:
 * 1) 在进程/进程组之间保持公平
 * 2) 选择“next”进程,因为有人真的希望它运行
 * 3) 选择“last”进程作为缓存位置
 * 4) 如果有其他可用的程序,请不要运行“跳过”程序
 */
static struct sched_entity *
pick_next_entity(struct cfs_rq *cfs_rq, struct sched_entity *curr)
{
	/* 拿到红黑树最左边的进程 */
	struct sched_entity *left = __pick_first_entity(cfs_rq);
	struct sched_entity *se;

	/*
	 * If curr is set we have to see if its left of the leftmost entity
	 * still in the tree, provided there was anything in the tree at all.
	 *
	 * 如果设置了curr，我们必须看看它在最左边实体的左边是否仍在树中,前提是树中有任何东西.
	 */

	/* 如果left为NULL,或者说curr在left的左边,那么left = curr */
	if (!left || (curr && entity_before(curr, left)))
		left = curr;

	/* 理想情况下,我们运行最左边的实体 */
	se = left; /* ideally we run the leftmost entity */

	/*
	 * Avoid running the skip buddy, if running something else can
	 * be done without getting too unfair.
	 *
	 * 如果可以在不太不公平的情况下完成其他任务,请避免运行skip buddy.
	 */

	/* 如果是被取到的进程自动放弃运行权利
	 *
	 * cfs_rq队列中的*skip指向暂时不需要被调度执行的进程,这样的进程一般通过sched_yield()
         * (在CFS中是通过yield_task_fair)放弃执行权的,同时在sched_yield设置skip之前,总是将上一个被设置为skip的进程清除掉,以防止放弃
         * 运行权利的进程永远得不到调度.
	 */
	if (cfs_rq->skip == se) {
		struct sched_entity *second;
		/* 如果se == curr,那么摘取红黑树上第二左的进程节点 */
		if (se == curr) {
			second = __pick_first_entity(cfs_rq);
		} else {
			second = __pick_next_entity(se);
			/* 如果second为NULL或者说curr比second还在左,那么设置second = curr */
			if (!second || (curr && entity_before(curr, second)))
				second = curr;
		}

		/* left应该抢占second么? */
		if (second && wakeup_preempt_entity(second, left) < 1)
			se = second;
	}

	/*
	 * Prefer last buddy, try to return the CPU to a preempted task.
	 */
	/* 如果上一次执行的进程尚在cfs_rq队列中,并且left不能抢占它,这里我们应该能够想到为什么内核线程的active_mm要借用
         * 上一个进程的active_mm.这样的话上一个activ_mm就不用从tlb中清洗掉,而下一次调度的时候有可能重新调度到该进程,增加了tlb的命中率
	 * cfs_rq->last为当前的运行进程
	 */
	if (cfs_rq->last && wakeup_preempt_entity(cfs_rq->last, left) < 1)
		se = cfs_rq->last;

	/*
	 * Someone really wants this to run. If it's not unfair, run it.
	 *
	 * cfs_rq->next设置为唤醒的进程
	 */
	if (cfs_rq->next && wakeup_preempt_entity(cfs_rq->next, left) < 1)
		se = cfs_rq->next;

	/* 清除cfs_rq的buddies */
	clear_buddies(cfs_rq, se);

	/* 返回se */
	return se;
}

static bool check_cfs_rq_runtime(struct cfs_rq *cfs_rq);

/*
 * 说明1: 若se->on_rq为1则说明此次是抢占,而非主动调度.
 * 说明2: 正在运行的进程是不在rq上的,所以prev不在runqueue上,因为set_next_entity时已将它从rq上移除.
 * 说明3: 主动睡眠时__schedule调deactivate_task将on_rq置0,抢占的情况on_rq一直为1.
 * 说明4: on_rq写0情况:参考说明3; on_rq写1情况：进程ttwu时;
 */
static void put_prev_entity(struct cfs_rq *cfs_rq, struct sched_entity *prev)
{
	/*
	 * If still on the runqueue then deactivate_task()
	 * was not called and update_curr() has to be done:
	 */
	/* on_rq为0说明是主动调度,此前调deactivate_task时包含了update_curr;
	 * 否则这里需要调update_curr
	 */
	if (prev->on_rq)
		update_curr(cfs_rq);

	/* throttle cfs_rqs exceeding runtime */
	/* 组调度带宽控制*/
	check_cfs_rq_runtime(cfs_rq);
	/* 检查prev进程的vruntime是否和min_vruntime差了太多(三倍的sysctl_sched_latency) */
	check_spread(cfs_rq, prev);

	/* 说明是抢占的情况,则prev需要保持runnable的状态,做些处理 */
	if (prev->on_rq) {
		/* 计时,记录开始加入rq的起始时间,和update_stats_wait_end成对,统计调度延时. */
		update_stats_wait_start(cfs_rq, prev);
		/* Put 'current' back into the tree. */
		/* 将prev进程重新加入cfs_rq,因为运行时虽然on_rq为1,但其实已经不在rq上了(进程运行时会被从rq上移除) */
		__enqueue_entity(cfs_rq, prev);
		/* in !on_rq case, update occurred at dequeue */
		/* 重新更新负载 */
		update_load_avg(prev, 0);
	}
	cfs_rq->curr = NULL;
}

static void
entity_tick(struct cfs_rq *cfs_rq, struct sched_entity *curr, int queued)
{
	/*
	 * Update run-time statistics of the 'current'.
	 */

	/* 更新当前进程的vruntime和就绪队列的min_vruntime */
	update_curr(cfs_rq);

	/*
	 * Ensure that runnable average is periodically updated.
	 */

	/* 更新该调度实体的和该就绪队列的平均负载 */
	update_load_avg(curr, 1);
	update_cfs_shares(cfs_rq);

#ifdef CONFIG_SCHED_HRTICK
	/*
	 * queued ticks are scheduled to match the slice, so don't bother
	 * validating it and just reschedule.
	 *
	 * queued tick被调度为与时间片匹配,所以不用费力验证它,只需重新调度即可
	 */
	if (queued) {
		resched_curr(rq_of(cfs_rq));
		return;
	}
	/*
	 * don't let the period tick interfere with the hrtick preemption
	 *
	 * 不要让周期tick干扰hrtick抢占
	 */
	if (!sched_feat(DOUBLE_TICK) &&
			hrtimer_active(&rq_of(cfs_rq)->hrtick_timer))
		return;
#endif

	/* 如果这个队列上运行的进程不止一个,那么调用check_preempt_tick函数检查当前进程是否需要被调度出去 */
	if (cfs_rq->nr_running > 1)
		check_preempt_tick(cfs_rq, curr);
}


/**************************************************
 * CFS bandwidth control machinery
 */

#ifdef CONFIG_CFS_BANDWIDTH

#ifdef HAVE_JUMP_LABEL
static struct static_key __cfs_bandwidth_used;

static inline bool cfs_bandwidth_used(void)
{
	return static_key_false(&__cfs_bandwidth_used);
}

void cfs_bandwidth_usage_inc(void)
{
	static_key_slow_inc(&__cfs_bandwidth_used);
}

void cfs_bandwidth_usage_dec(void)
{
	static_key_slow_dec(&__cfs_bandwidth_used);
}
#else /* HAVE_JUMP_LABEL */
static bool cfs_bandwidth_used(void)
{
	return true;
}

void cfs_bandwidth_usage_inc(void) {}
void cfs_bandwidth_usage_dec(void) {}
#endif /* HAVE_JUMP_LABEL */

/*
 * default period for cfs group bandwidth.
 * default: 0.1s, units: nanoseconds
 */
static inline u64 default_cfs_period(void)
{
	return 100000000ULL;
}

static inline u64 sched_cfs_bandwidth_slice(void)
{
	return (u64)sysctl_sched_cfs_bandwidth_slice * NSEC_PER_USEC;
}

/*
 * Replenish runtime according to assigned quota and update expiration time.
 * We use sched_clock_cpu directly instead of rq->clock to avoid adding
 * additional synchronization around rq->lock.
 *
 * requires cfs_b->lock
 */
void __refill_cfs_bandwidth_runtime(struct cfs_bandwidth *cfs_b)
{
	u64 now;

	if (cfs_b->quota == RUNTIME_INF)
		return;

	now = sched_clock_cpu(smp_processor_id());
	cfs_b->runtime = cfs_b->quota;
	cfs_b->runtime_expires = now + ktime_to_ns(cfs_b->period);
}

static inline struct cfs_bandwidth *tg_cfs_bandwidth(struct task_group *tg)
{
	return &tg->cfs_bandwidth;
}

/* rq->task_clock normalized against any time this cfs_rq has spent throttled */
static inline u64 cfs_rq_clock_task(struct cfs_rq *cfs_rq)
{
	if (unlikely(cfs_rq->throttle_count))
		return cfs_rq->throttled_clock_task - cfs_rq->throttled_clock_task_time;

	return rq_clock_task(rq_of(cfs_rq)) - cfs_rq->throttled_clock_task_time;
}

/* returns 0 on failure to allocate runtime */
static int assign_cfs_rq_runtime(struct cfs_rq *cfs_rq)
{
	struct task_group *tg = cfs_rq->tg;
	struct cfs_bandwidth *cfs_b = tg_cfs_bandwidth(tg);
	u64 amount = 0, min_amount, expires;

	/* note: this is a positive sum as runtime_remaining <= 0 */
	min_amount = sched_cfs_bandwidth_slice() - cfs_rq->runtime_remaining;

	raw_spin_lock(&cfs_b->lock);
	if (cfs_b->quota == RUNTIME_INF)
		amount = min_amount;
	else {
		start_cfs_bandwidth(cfs_b);

		if (cfs_b->runtime > 0) {
			amount = min(cfs_b->runtime, min_amount);
			cfs_b->runtime -= amount;
			cfs_b->idle = 0;
		}
	}
	expires = cfs_b->runtime_expires;
	raw_spin_unlock(&cfs_b->lock);

	cfs_rq->runtime_remaining += amount;
	/*
	 * we may have advanced our local expiration to account for allowed
	 * spread between our sched_clock and the one on which runtime was
	 * issued.
	 */
	if ((s64)(expires - cfs_rq->runtime_expires) > 0)
		cfs_rq->runtime_expires = expires;

	return cfs_rq->runtime_remaining > 0;
}

/*
 * Note: This depends on the synchronization provided by sched_clock and the
 * fact that rq->clock snapshots this value.
 */
static void expire_cfs_rq_runtime(struct cfs_rq *cfs_rq)
{
	struct cfs_bandwidth *cfs_b = tg_cfs_bandwidth(cfs_rq->tg);

	/* if the deadline is ahead of our clock, nothing to do */
	if (likely((s64)(rq_clock(rq_of(cfs_rq)) - cfs_rq->runtime_expires) < 0))
		return;

	if (cfs_rq->runtime_remaining < 0)
		return;

	/*
	 * If the local deadline has passed we have to consider the
	 * possibility that our sched_clock is 'fast' and the global deadline
	 * has not truly expired.
	 *
	 * Fortunately we can check determine whether this the case by checking
	 * whether the global deadline has advanced. It is valid to compare
	 * cfs_b->runtime_expires without any locks since we only care about
	 * exact equality, so a partial write will still work.
	 */

	if (cfs_rq->runtime_expires != cfs_b->runtime_expires) {
		/* extend local deadline, drift is bounded above by 2 ticks */
		cfs_rq->runtime_expires += TICK_NSEC;
	} else {
		/* global deadline is ahead, expiration has passed */
		cfs_rq->runtime_remaining = 0;
	}
}

static void __account_cfs_rq_runtime(struct cfs_rq *cfs_rq, u64 delta_exec)
{
	/* dock delta_exec before expiring quota (as it could span periods) */
	cfs_rq->runtime_remaining -= delta_exec;
	expire_cfs_rq_runtime(cfs_rq);

	if (likely(cfs_rq->runtime_remaining > 0))
		return;

	/*
	 * if we're unable to extend our runtime we resched so that the active
	 * hierarchy can be throttled
	 */
	if (!assign_cfs_rq_runtime(cfs_rq) && likely(cfs_rq->curr))
		resched_curr(rq_of(cfs_rq));
}

static __always_inline
void account_cfs_rq_runtime(struct cfs_rq *cfs_rq, u64 delta_exec)
{
	if (!cfs_bandwidth_used() || !cfs_rq->runtime_enabled)
		return;

	__account_cfs_rq_runtime(cfs_rq, delta_exec);
}

static inline int cfs_rq_throttled(struct cfs_rq *cfs_rq)
{
	return cfs_bandwidth_used() && cfs_rq->throttled;
}

/* check whether cfs_rq, or any parent, is throttled */
static inline int throttled_hierarchy(struct cfs_rq *cfs_rq)
{
	return cfs_bandwidth_used() && cfs_rq->throttle_count;
}

/*
 * Ensure that neither of the group entities corresponding to src_cpu or
 * dest_cpu are members of a throttled hierarchy when performing group
 * load-balance operations.
 */
static inline int throttled_lb_pair(struct task_group *tg,
				    int src_cpu, int dest_cpu)
{
	struct cfs_rq *src_cfs_rq, *dest_cfs_rq;

	src_cfs_rq = tg->cfs_rq[src_cpu];
	dest_cfs_rq = tg->cfs_rq[dest_cpu];

	return throttled_hierarchy(src_cfs_rq) ||
	       throttled_hierarchy(dest_cfs_rq);
}

/* updated child weight may affect parent so we have to do this bottom up */
static int tg_unthrottle_up(struct task_group *tg, void *data)
{
	struct rq *rq = data;
	struct cfs_rq *cfs_rq = tg->cfs_rq[cpu_of(rq)];

	cfs_rq->throttle_count--;
	if (!cfs_rq->throttle_count) {
		/* adjust cfs_rq_clock_task() */
		cfs_rq->throttled_clock_task_time += rq_clock_task(rq) -
					     cfs_rq->throttled_clock_task;
	}

	return 0;
}

static int tg_throttle_down(struct task_group *tg, void *data)
{
	struct rq *rq = data;
	struct cfs_rq *cfs_rq = tg->cfs_rq[cpu_of(rq)];

	/* group is entering throttled state, stop time */
	if (!cfs_rq->throttle_count)
		cfs_rq->throttled_clock_task = rq_clock_task(rq);
	cfs_rq->throttle_count++;

	return 0;
}

static void throttle_cfs_rq(struct cfs_rq *cfs_rq)
{
	struct rq *rq = rq_of(cfs_rq);
	struct cfs_bandwidth *cfs_b = tg_cfs_bandwidth(cfs_rq->tg);
	struct sched_entity *se;
	long task_delta, dequeue = 1;
	bool empty;

	se = cfs_rq->tg->se[cpu_of(rq_of(cfs_rq))];

	/* freeze hierarchy runnable averages while throttled */
	rcu_read_lock();
	walk_tg_tree_from(cfs_rq->tg, tg_throttle_down, tg_nop, (void *)rq);
	rcu_read_unlock();

	task_delta = cfs_rq->h_nr_running;
	for_each_sched_entity(se) {
		struct cfs_rq *qcfs_rq = cfs_rq_of(se);
		/* throttled entity or throttle-on-deactivate */
		if (!se->on_rq)
			break;

		if (dequeue)
			dequeue_entity(qcfs_rq, se, DEQUEUE_SLEEP);
		qcfs_rq->h_nr_running -= task_delta;

		if (qcfs_rq->load.weight)
			dequeue = 0;
	}

	if (!se)
		sub_nr_running(rq, task_delta);

	cfs_rq->throttled = 1;
	cfs_rq->throttled_clock = rq_clock(rq);
	raw_spin_lock(&cfs_b->lock);
	empty = list_empty(&cfs_b->throttled_cfs_rq);

	/*
	 * Add to the _head_ of the list, so that an already-started
	 * distribute_cfs_runtime will not see us
	 */
	list_add_rcu(&cfs_rq->throttled_list, &cfs_b->throttled_cfs_rq);

	/*
	 * If we're the first throttled task, make sure the bandwidth
	 * timer is running.
	 */
	if (empty)
		start_cfs_bandwidth(cfs_b);

	raw_spin_unlock(&cfs_b->lock);
}

void unthrottle_cfs_rq(struct cfs_rq *cfs_rq)
{
	struct rq *rq = rq_of(cfs_rq);
	struct cfs_bandwidth *cfs_b = tg_cfs_bandwidth(cfs_rq->tg);
	struct sched_entity *se;
	int enqueue = 1;
	long task_delta;

	se = cfs_rq->tg->se[cpu_of(rq)];

	cfs_rq->throttled = 0;

	update_rq_clock(rq);

	raw_spin_lock(&cfs_b->lock);
	cfs_b->throttled_time += rq_clock(rq) - cfs_rq->throttled_clock;
	list_del_rcu(&cfs_rq->throttled_list);
	raw_spin_unlock(&cfs_b->lock);

	/* update hierarchical throttle state */
	walk_tg_tree_from(cfs_rq->tg, tg_nop, tg_unthrottle_up, (void *)rq);

	if (!cfs_rq->load.weight)
		return;

	task_delta = cfs_rq->h_nr_running;
	for_each_sched_entity(se) {
		if (se->on_rq)
			enqueue = 0;

		cfs_rq = cfs_rq_of(se);
		if (enqueue)
			enqueue_entity(cfs_rq, se, ENQUEUE_WAKEUP);
		cfs_rq->h_nr_running += task_delta;

		if (cfs_rq_throttled(cfs_rq))
			break;
	}

	if (!se)
		add_nr_running(rq, task_delta);

	/* determine whether we need to wake up potentially idle cpu */
	if (rq->curr == rq->idle && rq->cfs.nr_running)
		resched_curr(rq);
}

static u64 distribute_cfs_runtime(struct cfs_bandwidth *cfs_b,
		u64 remaining, u64 expires)
{
	struct cfs_rq *cfs_rq;
	u64 runtime;
	u64 starting_runtime = remaining;

	rcu_read_lock();
	list_for_each_entry_rcu(cfs_rq, &cfs_b->throttled_cfs_rq,
				throttled_list) {
		struct rq *rq = rq_of(cfs_rq);

		raw_spin_lock(&rq->lock);
		if (!cfs_rq_throttled(cfs_rq))
			goto next;

		runtime = -cfs_rq->runtime_remaining + 1;
		if (runtime > remaining)
			runtime = remaining;
		remaining -= runtime;

		cfs_rq->runtime_remaining += runtime;
		cfs_rq->runtime_expires = expires;

		/* we check whether we're throttled above */
		if (cfs_rq->runtime_remaining > 0)
			unthrottle_cfs_rq(cfs_rq);

next:
		raw_spin_unlock(&rq->lock);

		if (!remaining)
			break;
	}
	rcu_read_unlock();

	return starting_runtime - remaining;
}

/*
 * Responsible for refilling a task_group's bandwidth and unthrottling its
 * cfs_rqs as appropriate. If there has been no activity within the last
 * period the timer is deactivated until scheduling resumes; cfs_b->idle is
 * used to track this state.
 */
static int do_sched_cfs_period_timer(struct cfs_bandwidth *cfs_b, int overrun)
{
	u64 runtime, runtime_expires;
	int throttled;

	/* no need to continue the timer with no bandwidth constraint */
	if (cfs_b->quota == RUNTIME_INF)
		goto out_deactivate;

	throttled = !list_empty(&cfs_b->throttled_cfs_rq);
	cfs_b->nr_periods += overrun;

	/*
	 * idle depends on !throttled (for the case of a large deficit), and if
	 * we're going inactive then everything else can be deferred
	 */
	if (cfs_b->idle && !throttled)
		goto out_deactivate;

	__refill_cfs_bandwidth_runtime(cfs_b);

	if (!throttled) {
		/* mark as potentially idle for the upcoming period */
		cfs_b->idle = 1;
		return 0;
	}

	/* account preceding periods in which throttling occurred */
	cfs_b->nr_throttled += overrun;

	runtime_expires = cfs_b->runtime_expires;

	/*
	 * This check is repeated as we are holding onto the new bandwidth while
	 * we unthrottle. This can potentially race with an unthrottled group
	 * trying to acquire new bandwidth from the global pool. This can result
	 * in us over-using our runtime if it is all used during this loop, but
	 * only by limited amounts in that extreme case.
	 */
	while (throttled && cfs_b->runtime > 0) {
		runtime = cfs_b->runtime;
		raw_spin_unlock(&cfs_b->lock);
		/* we can't nest cfs_b->lock while distributing bandwidth */
		runtime = distribute_cfs_runtime(cfs_b, runtime,
						 runtime_expires);
		raw_spin_lock(&cfs_b->lock);

		throttled = !list_empty(&cfs_b->throttled_cfs_rq);

		cfs_b->runtime -= min(runtime, cfs_b->runtime);
	}

	/*
	 * While we are ensured activity in the period following an
	 * unthrottle, this also covers the case in which the new bandwidth is
	 * insufficient to cover the existing bandwidth deficit.  (Forcing the
	 * timer to remain active while there are any throttled entities.)
	 */
	cfs_b->idle = 0;

	return 0;

out_deactivate:
	return 1;
}

/* a cfs_rq won't donate quota below this amount */
static const u64 min_cfs_rq_runtime = 1 * NSEC_PER_MSEC;
/* minimum remaining period time to redistribute slack quota */
static const u64 min_bandwidth_expiration = 2 * NSEC_PER_MSEC;
/* how long we wait to gather additional slack before distributing */
static const u64 cfs_bandwidth_slack_period = 5 * NSEC_PER_MSEC;

/*
 * Are we near the end of the current quota period?
 *
 * Requires cfs_b->lock for hrtimer_expires_remaining to be safe against the
 * hrtimer base being cleared by hrtimer_start. In the case of
 * migrate_hrtimers, base is never cleared, so we are fine.
 */
static int runtime_refresh_within(struct cfs_bandwidth *cfs_b, u64 min_expire)
{
	struct hrtimer *refresh_timer = &cfs_b->period_timer;
	u64 remaining;

	/* if the call-back is running a quota refresh is already occurring */
	if (hrtimer_callback_running(refresh_timer))
		return 1;

	/* is a quota refresh about to occur? */
	remaining = ktime_to_ns(hrtimer_expires_remaining(refresh_timer));
	if (remaining < min_expire)
		return 1;

	return 0;
}

static void start_cfs_slack_bandwidth(struct cfs_bandwidth *cfs_b)
{
	u64 min_left = cfs_bandwidth_slack_period + min_bandwidth_expiration;

	/* if there's a quota refresh soon don't bother with slack */
	if (runtime_refresh_within(cfs_b, min_left))
		return;

	hrtimer_start(&cfs_b->slack_timer,
			ns_to_ktime(cfs_bandwidth_slack_period),
			HRTIMER_MODE_REL);
}

/* we know any runtime found here is valid as update_curr() precedes return
 * 我们知道这里找到的任何运行时间都是有效的,因为updatecurr()在返回之前
 */
static void __return_cfs_rq_runtime(struct cfs_rq *cfs_rq)
{
	struct cfs_bandwidth *cfs_b = tg_cfs_bandwidth(cfs_rq->tg);
	s64 slack_runtime = cfs_rq->runtime_remaining - min_cfs_rq_runtime;

	if (slack_runtime <= 0)
		return;

	raw_spin_lock(&cfs_b->lock);
	if (cfs_b->quota != RUNTIME_INF &&
	    cfs_rq->runtime_expires == cfs_b->runtime_expires) {
		cfs_b->runtime += slack_runtime;

		/* we are under rq->lock, defer unthrottling using a timer */
		if (cfs_b->runtime > sched_cfs_bandwidth_slice() &&
		    !list_empty(&cfs_b->throttled_cfs_rq))
			start_cfs_slack_bandwidth(cfs_b);
	}
	raw_spin_unlock(&cfs_b->lock);

	/* even if it's not valid for return we don't want to try again */
	cfs_rq->runtime_remaining -= slack_runtime;
}

static __always_inline void return_cfs_rq_runtime(struct cfs_rq *cfs_rq)
{
	if (!cfs_bandwidth_used())
		return;

	if (!cfs_rq->runtime_enabled || cfs_rq->nr_running)
		return;

	__return_cfs_rq_runtime(cfs_rq);
}

/*
 * This is done with a timer (instead of inline with bandwidth return) since
 * it's necessary to juggle rq->locks to unthrottle their respective cfs_rqs.
 */
static void do_sched_cfs_slack_timer(struct cfs_bandwidth *cfs_b)
{
	u64 runtime = 0, slice = sched_cfs_bandwidth_slice();
	u64 expires;

	/* confirm we're still not at a refresh boundary */
	raw_spin_lock(&cfs_b->lock);
	if (runtime_refresh_within(cfs_b, min_bandwidth_expiration)) {
		raw_spin_unlock(&cfs_b->lock);
		return;
	}

	if (cfs_b->quota != RUNTIME_INF && cfs_b->runtime > slice)
		runtime = cfs_b->runtime;

	expires = cfs_b->runtime_expires;
	raw_spin_unlock(&cfs_b->lock);

	if (!runtime)
		return;

	runtime = distribute_cfs_runtime(cfs_b, runtime, expires);

	raw_spin_lock(&cfs_b->lock);
	if (expires == cfs_b->runtime_expires)
		cfs_b->runtime -= min(runtime, cfs_b->runtime);
	raw_spin_unlock(&cfs_b->lock);
}

/*
 * When a group wakes up we want to make sure that its quota is not already
 * expired/exceeded, otherwise it may be allowed to steal additional ticks of
 * runtime as update_curr() throttling can not not trigger until it's on-rq.
 */
static void check_enqueue_throttle(struct cfs_rq *cfs_rq)
{
	if (!cfs_bandwidth_used())
		return;

	/* an active group must be handled by the update_curr()->put() path */
	if (!cfs_rq->runtime_enabled || cfs_rq->curr)
		return;

	/* ensure the group is not already throttled */
	if (cfs_rq_throttled(cfs_rq))
		return;

	/* update runtime allocation */
	account_cfs_rq_runtime(cfs_rq, 0);
	if (cfs_rq->runtime_remaining <= 0)
		throttle_cfs_rq(cfs_rq);
}

static void sync_throttle(struct task_group *tg, int cpu)
{
	struct cfs_rq *pcfs_rq, *cfs_rq;

	if (!cfs_bandwidth_used())
		return;

	if (!tg->parent)
		return;

	cfs_rq = tg->cfs_rq[cpu];
	pcfs_rq = tg->parent->cfs_rq[cpu];

	cfs_rq->throttle_count = pcfs_rq->throttle_count;
	cfs_rq->throttled_clock_task = rq_clock_task(cpu_rq(cpu));
}

/* conditionally throttle active cfs_rq's from put_prev_entity() */
static bool check_cfs_rq_runtime(struct cfs_rq *cfs_rq)
{
	if (!cfs_bandwidth_used())
		return false;

	if (likely(!cfs_rq->runtime_enabled || cfs_rq->runtime_remaining > 0))
		return false;

	/*
	 * it's possible for a throttled entity to be forced into a running
	 * state (e.g. set_curr_task), in this case we're finished.
	 */
	if (cfs_rq_throttled(cfs_rq))
		return true;

	throttle_cfs_rq(cfs_rq);
	return true;
}

static enum hrtimer_restart sched_cfs_slack_timer(struct hrtimer *timer)
{
	struct cfs_bandwidth *cfs_b =
		container_of(timer, struct cfs_bandwidth, slack_timer);

	do_sched_cfs_slack_timer(cfs_b);

	return HRTIMER_NORESTART;
}

static enum hrtimer_restart sched_cfs_period_timer(struct hrtimer *timer)
{
	struct cfs_bandwidth *cfs_b =
		container_of(timer, struct cfs_bandwidth, period_timer);
	int overrun;
	int idle = 0;

	raw_spin_lock(&cfs_b->lock);
	for (;;) {
		overrun = hrtimer_forward_now(timer, cfs_b->period);
		if (!overrun)
			break;

		idle = do_sched_cfs_period_timer(cfs_b, overrun);
	}
	if (idle)
		cfs_b->period_active = 0;
	raw_spin_unlock(&cfs_b->lock);

	return idle ? HRTIMER_NORESTART : HRTIMER_RESTART;
}

void init_cfs_bandwidth(struct cfs_bandwidth *cfs_b)
{
	raw_spin_lock_init(&cfs_b->lock);
	cfs_b->runtime = 0;
	cfs_b->quota = RUNTIME_INF;
	cfs_b->period = ns_to_ktime(default_cfs_period());

	INIT_LIST_HEAD(&cfs_b->throttled_cfs_rq);
	hrtimer_init(&cfs_b->period_timer, CLOCK_MONOTONIC, HRTIMER_MODE_ABS_PINNED);
	cfs_b->period_timer.function = sched_cfs_period_timer;
	hrtimer_init(&cfs_b->slack_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	cfs_b->slack_timer.function = sched_cfs_slack_timer;
}

static void init_cfs_rq_runtime(struct cfs_rq *cfs_rq)
{
	cfs_rq->runtime_enabled = 0;
	INIT_LIST_HEAD(&cfs_rq->throttled_list);
}

void start_cfs_bandwidth(struct cfs_bandwidth *cfs_b)
{
	lockdep_assert_held(&cfs_b->lock);

	if (!cfs_b->period_active) {
		cfs_b->period_active = 1;
		hrtimer_forward_now(&cfs_b->period_timer, cfs_b->period);
		hrtimer_start_expires(&cfs_b->period_timer, HRTIMER_MODE_ABS_PINNED);
	}
}

static void destroy_cfs_bandwidth(struct cfs_bandwidth *cfs_b)
{
	/* init_cfs_bandwidth() was not called */
	if (!cfs_b->throttled_cfs_rq.next)
		return;

	hrtimer_cancel(&cfs_b->period_timer);
	hrtimer_cancel(&cfs_b->slack_timer);
}

static void __maybe_unused update_runtime_enabled(struct rq *rq)
{
	struct cfs_rq *cfs_rq;

	for_each_leaf_cfs_rq(rq, cfs_rq) {
		struct cfs_bandwidth *cfs_b = &cfs_rq->tg->cfs_bandwidth;

		raw_spin_lock(&cfs_b->lock);
		cfs_rq->runtime_enabled = cfs_b->quota != RUNTIME_INF;
		raw_spin_unlock(&cfs_b->lock);
	}
}

static void __maybe_unused unthrottle_offline_cfs_rqs(struct rq *rq)
{
	struct cfs_rq *cfs_rq;

	for_each_leaf_cfs_rq(rq, cfs_rq) {
		if (!cfs_rq->runtime_enabled)
			continue;

		/*
		 * clock_task is not advancing so we just need to make sure
		 * there's some valid quota amount
		 */
		cfs_rq->runtime_remaining = 1;
		/*
		 * Offline rq is schedulable till cpu is completely disabled
		 * in take_cpu_down(), so we prevent new cfs throttling here.
		 */
		cfs_rq->runtime_enabled = 0;

		if (cfs_rq_throttled(cfs_rq))
			unthrottle_cfs_rq(cfs_rq);
	}
}

#else /* CONFIG_CFS_BANDWIDTH */
static inline u64 cfs_rq_clock_task(struct cfs_rq *cfs_rq)
{
	return rq_clock_task(rq_of(cfs_rq));
}

static void account_cfs_rq_runtime(struct cfs_rq *cfs_rq, u64 delta_exec) {}
static bool check_cfs_rq_runtime(struct cfs_rq *cfs_rq) { return false; }
static void check_enqueue_throttle(struct cfs_rq *cfs_rq) {}
static inline void sync_throttle(struct task_group *tg, int cpu) {}
static __always_inline void return_cfs_rq_runtime(struct cfs_rq *cfs_rq) {}

static inline int cfs_rq_throttled(struct cfs_rq *cfs_rq)
{
	return 0;
}

static inline int throttled_hierarchy(struct cfs_rq *cfs_rq)
{
	return 0;
}

static inline int throttled_lb_pair(struct task_group *tg,
				    int src_cpu, int dest_cpu)
{
	return 0;
}

void init_cfs_bandwidth(struct cfs_bandwidth *cfs_b) {}

#ifdef CONFIG_FAIR_GROUP_SCHED
static void init_cfs_rq_runtime(struct cfs_rq *cfs_rq) {}
#endif

static inline struct cfs_bandwidth *tg_cfs_bandwidth(struct task_group *tg)
{
	return NULL;
}
static inline void destroy_cfs_bandwidth(struct cfs_bandwidth *cfs_b) {}
static inline void update_runtime_enabled(struct rq *rq) {}
static inline void unthrottle_offline_cfs_rqs(struct rq *rq) {}

#endif /* CONFIG_CFS_BANDWIDTH */

/**************************************************
 * CFS operations on tasks:
 */

#ifdef CONFIG_SCHED_HRTICK
static void hrtick_start_fair(struct rq *rq, struct task_struct *p)
{
	struct sched_entity *se = &p->se;
	struct cfs_rq *cfs_rq = cfs_rq_of(se);

	SCHED_WARN_ON(task_rq(p) != rq);

	/* 如果cfs的可运行进程数量大于1 */
	if (rq->cfs.h_nr_running > 1) {
		/* 这里表示一个调度周期内,se能获得的时间片 */
		u64 slice = sched_slice(cfs_rq, se);
		/* 可以使用sum_exec_runtime- prev_sum_exec_runtime计算进程最近一次调度内获取cpu使用权的时间. */
		u64 ran = se->sum_exec_runtime - se->prev_sum_exec_runtime;
		/* delta表示时间片减去已经运行的时间 */
		s64 delta = slice - ran;

		/* 如果小于0,说明时间片已经用完了,那么就重新调度 */
		if (delta < 0) {
			if (rq->curr == p)
				resched_curr(rq);
			return;
		}
		hrtick_start(rq, delta);
	}
}

/*
 * called from enqueue/dequeue and updates the hrtick when the
 * current task is from our class and nr_running is low enough
 * to matter.
 */
static void hrtick_update(struct rq *rq)
{
	struct task_struct *curr = rq->curr;

	if (!hrtick_enabled(rq) || curr->sched_class != &fair_sched_class)
		return;

	if (cfs_rq_of(&curr->se)->nr_running < sched_nr_latency)
		hrtick_start_fair(rq, curr);
}
#else /* !CONFIG_SCHED_HRTICK */
static inline void
hrtick_start_fair(struct rq *rq, struct task_struct *p)
{
}

static inline void hrtick_update(struct rq *rq)
{
}
#endif

/*
 * The enqueue_task method is called before nr_running is
 * increased. Here we update the fair scheduling stats and
 * then put the task into the rbtree:
 *
 * enqueue_task方法在nr_running增加之前调用.
 * 在这里,我们更新公平调度统计数据,然后将任务放入rbtree:
 */
static void
enqueue_task_fair(struct rq *rq, struct task_struct *p, int flags)
{
	struct cfs_rq *cfs_rq;
	/* 拿到该task的sched_entity */
	struct sched_entity *se = &p->se;

	/*
	 * If in_iowait is set, the code below may not trigger any cpufreq
	 * utilization updates, so do it here explicitly with the IOWAIT flag
	 * passed.
	 *
	 * 如果设置了in_iowait,下面的代码可能不会触发任何cpufreq利用率更新,所以在这里显式地执行,并传递IOWAIT标志.
	 */
	if (p->in_iowait)
		cpufreq_update_this_cpu(rq, SCHED_CPUFREQ_IOWAIT);
	/* for循环对于没有定义FAIR_GROUP_SCHED的系统来说,其实就是调度实体se */
	for_each_sched_entity(se) {
		/* 如果se在rq中,那么直接break */
		if (se->on_rq)
			break;
		/* 拿到这个sched_entity的cfs_rq */
		cfs_rq = cfs_rq_of(se);
		/* 把调度实体se添加到cfs_rq就绪队列中 */
		enqueue_entity(cfs_rq, se, flags);

		/*
		 * end evaluation on encountering a throttled cfs_rq
		 *
		 * note: in the case of encountering a throttled cfs_rq we will
		 * post the final h_nr_running increment below.
		 */
		if (cfs_rq_throttled(cfs_rq))
			break;
		cfs_rq->h_nr_running++;

		flags = ENQUEUE_WAKEUP;
	}

	for_each_sched_entity(se) {
		cfs_rq = cfs_rq_of(se);
		cfs_rq->h_nr_running++;

		if (cfs_rq_throttled(cfs_rq))
			break;

		update_load_avg(se, 1);
		update_cfs_shares(cfs_rq);
	}

	if (!se)
		add_nr_running(rq, 1);

	hrtick_update(rq);
}

static void set_next_buddy(struct sched_entity *se);

/*
 * The dequeue_task method is called before nr_running is
 * decreased. We remove the task from the rbtree and
 * update the fair scheduling stats:
 *
 * 在减少nr_running之前调用dequeue_task方法。我们从rbtree中删除该任务，并更新公平调度统计信息：
 */
static void dequeue_task_fair(struct rq *rq, struct task_struct *p, int flags)
{
	struct cfs_rq *cfs_rq;
	struct sched_entity *se = &p->se;
	int task_sleep = flags & DEQUEUE_SLEEP;

	for_each_sched_entity(se) {
		/* 拿到cfs_rq */
		cfs_rq = cfs_rq_of(se);
		/* 这里就是让entity退出运行队列 */
		dequeue_entity(cfs_rq, se, flags);

		/*
		 * end evaluation on encountering a throttled cfs_rq
		 *
		 * note: in the case of encountering a throttled cfs_rq we will
		 * post the final h_nr_running decrement below.
		 *
		 * 遇到节流cfsrq的末端评估
		 * 注意: 如果遇到节流的cfs_rq,我们将在下面发布最终的h_nr_running递减量
		 */
		if (cfs_rq_throttled(cfs_rq))
			break;
		/* 让cfs_rq的h_nr_running-- */
		cfs_rq->h_nr_running--;

		/* Don't dequeue parent if it has other entities besides us */
		if (cfs_rq->load.weight) {
			/* Avoid re-evaluating load for this entity: */
			se = parent_entity(se);
			/*
			 * Bias pick_next to pick a task from this cfs_rq, as
			 * p is sleeping when it is within its sched_slice.
			 */
			if (task_sleep && se && !throttled_hierarchy(cfs_rq))
				set_next_buddy(se);
			break;
		}
		flags |= DEQUEUE_SLEEP;
	}

	for_each_sched_entity(se) {
		cfs_rq = cfs_rq_of(se);
		cfs_rq->h_nr_running--;

		if (cfs_rq_throttled(cfs_rq))
			break;

		update_load_avg(se, 1);
		update_cfs_shares(cfs_rq);
	}

	if (!se)
		sub_nr_running(rq, 1);

	hrtick_update(rq);
}

#ifdef CONFIG_SMP

/* Working cpumask for: load_balance, load_balance_newidle. */
DEFINE_PER_CPU(cpumask_var_t, load_balance_mask);
DEFINE_PER_CPU(cpumask_var_t, select_idle_mask);

#ifdef CONFIG_NO_HZ_COMMON
/*
 * per rq 'load' arrray crap; XXX kill this.
 */

/*
 * The exact cpuload calculated at every tick would be:
 *
 *   load' = (1 - 1/2^i) * load + (1/2^i) * cur_load
 *
 * If a cpu misses updates for n ticks (as it was idle) and update gets
 * called on the n+1-th tick when cpu may be busy, then we have:
 *
 *   load_n   = (1 - 1/2^i)^n * load_0
 *   load_n+1 = (1 - 1/2^i)   * load_n + (1/2^i) * cur_load
 *
 * decay_load_missed() below does efficient calculation of
 *
 *   load' = (1 - 1/2^i)^n * load
 *
 * Because x^(n+m) := x^n * x^m we can decompose any x^n in power-of-2 factors.
 * This allows us to precompute the above in said factors, thereby allowing the
 * reduction of an arbitrary n in O(log_2 n) steps. (See also
 * fixed_power_int())
 *
 * The calculation is approximated on a 128 point scale.
 */
#define DEGRADE_SHIFT		7

static const u8 degrade_zero_ticks[CPU_LOAD_IDX_MAX] = {0, 8, 32, 64, 128};
static const u8 degrade_factor[CPU_LOAD_IDX_MAX][DEGRADE_SHIFT + 1] = {
	{   0,   0,  0,  0,  0,  0, 0, 0 },
	{  64,  32,  8,  0,  0,  0, 0, 0 },
	{  96,  72, 40, 12,  1,  0, 0, 0 },
	{ 112,  98, 75, 43, 15,  1, 0, 0 },
	{ 120, 112, 98, 76, 45, 16, 2, 0 }
};

/*
 * Update cpu_load for any missed ticks, due to tickless idle. The backlog
 * would be when CPU is idle and so we just decay the old load without
 * adding any new load.
 */
static unsigned long
decay_load_missed(unsigned long load, unsigned long missed_updates, int idx)
{
	int j = 0;

	if (!missed_updates)
		return load;

	if (missed_updates >= degrade_zero_ticks[idx])
		return 0;

	if (idx == 1)
		return load >> missed_updates;

	while (missed_updates) {
		if (missed_updates % 2)
			load = (load * degrade_factor[idx][j]) >> DEGRADE_SHIFT;

		missed_updates >>= 1;
		j++;
	}
	return load;
}
#endif /* CONFIG_NO_HZ_COMMON */

/**
 * __cpu_load_update - update the rq->cpu_load[] statistics
 * @this_rq: The rq to update statistics for
 * @this_load: The current load
 * @pending_updates: The number of missed updates
 *
 * Update rq->cpu_load[] statistics. This function is usually called every
 * scheduler tick (TICK_NSEC).
 *
 * This function computes a decaying average:
 *
 *   load[i]' = (1 - 1/2^i) * load[i] + (1/2^i) * load
 *
 * Because of NOHZ it might not get called on every tick which gives need for
 * the @pending_updates argument.
 *
 *   load[i]_n = (1 - 1/2^i) * load[i]_n-1 + (1/2^i) * load_n-1
 *             = A * load[i]_n-1 + B ; A := (1 - 1/2^i), B := (1/2^i) * load
 *             = A * (A * load[i]_n-2 + B) + B
 *             = A * (A * (A * load[i]_n-3 + B) + B) + B
 *             = A^3 * load[i]_n-3 + (A^2 + A + 1) * B
 *             = A^n * load[i]_0 + (A^(n-1) + A^(n-2) + ... + 1) * B
 *             = A^n * load[i]_0 + ((1 - A^n) / (1 - A)) * B
 *             = (1 - 1/2^i)^n * (load[i]_0 - load) + load
 *
 * In the above we've assumed load_n := load, which is true for NOHZ_FULL as
 * any change in load would have resulted in the tick being turned back on.
 *
 * For regular NOHZ, this reduces to:
 *
 *   load[i]_n = (1 - 1/2^i)^n * load[i]_0
 *
 * see decay_load_misses(). For NOHZ_FULL we get to subtract and add the extra
 * term.
 */
static void cpu_load_update(struct rq *this_rq, unsigned long this_load,
			    unsigned long pending_updates)
{
	unsigned long __maybe_unused tickless_load = this_rq->cpu_load[0];
	int i, scale;

	this_rq->nr_load_updates++;

	/* Update our load: */
	this_rq->cpu_load[0] = this_load; /* Fasttrack for idx 0 */
	for (i = 1, scale = 2; i < CPU_LOAD_IDX_MAX; i++, scale += scale) {
		unsigned long old_load, new_load;

		/* scale is effectively 1 << i now, and >> i divides by scale */

		old_load = this_rq->cpu_load[i];
#ifdef CONFIG_NO_HZ_COMMON
		old_load = decay_load_missed(old_load, pending_updates - 1, i);
		if (tickless_load) {
			old_load -= decay_load_missed(tickless_load, pending_updates - 1, i);
			/*
			 * old_load can never be a negative value because a
			 * decayed tickless_load cannot be greater than the
			 * original tickless_load.
			 */
			old_load += tickless_load;
		}
#endif
		new_load = this_load;
		/*
		 * Round up the averaging division if load is increasing. This
		 * prevents us from getting stuck on 9 if the load is 10, for
		 * example.
		 */
		if (new_load > old_load)
			new_load += scale - 1;

		this_rq->cpu_load[i] = (old_load * (scale - 1) + new_load) >> i;
	}

	sched_avg_update(this_rq);
}

/* Used instead of source_load when we know the type == 0 */
static unsigned long weighted_cpuload(const int cpu)
{
	return cfs_rq_runnable_load_avg(&cpu_rq(cpu)->cfs);
}

#ifdef CONFIG_NO_HZ_COMMON
/*
 * There is no sane way to deal with nohz on smp when using jiffies because the
 * cpu doing the jiffies update might drift wrt the cpu doing the jiffy reading
 * causing off-by-one errors in observed deltas; {0,2} instead of {1,1}.
 *
 * Therefore we need to avoid the delta approach from the regular tick when
 * possible since that would seriously skew the load calculation. This is why we
 * use cpu_load_update_periodic() for CPUs out of nohz. However we'll rely on
 * jiffies deltas for updates happening while in nohz mode (idle ticks, idle
 * loop exit, nohz_idle_balance, nohz full exit...)
 *
 * This means we might still be one tick off for nohz periods.
 */

static void cpu_load_update_nohz(struct rq *this_rq,
				 unsigned long curr_jiffies,
				 unsigned long load)
{
	unsigned long pending_updates;

	pending_updates = curr_jiffies - this_rq->last_load_update_tick;
	if (pending_updates) {
		this_rq->last_load_update_tick = curr_jiffies;
		/*
		 * In the regular NOHZ case, we were idle, this means load 0.
		 * In the NOHZ_FULL case, we were non-idle, we should consider
		 * its weighted load.
		 */
		cpu_load_update(this_rq, load, pending_updates);
	}
}

/*
 * Called from nohz_idle_balance() to update the load ratings before doing the
 * idle balance.
 */
static void cpu_load_update_idle(struct rq *this_rq)
{
	/*
	 * bail if there's load or we're actually up-to-date.
	 */
	if (weighted_cpuload(cpu_of(this_rq)))
		return;

	cpu_load_update_nohz(this_rq, READ_ONCE(jiffies), 0);
}

/*
 * Record CPU load on nohz entry so we know the tickless load to account
 * on nohz exit. cpu_load[0] happens then to be updated more frequently
 * than other cpu_load[idx] but it should be fine as cpu_load readers
 * shouldn't rely into synchronized cpu_load[*] updates.
 */
void cpu_load_update_nohz_start(void)
{
	struct rq *this_rq = this_rq();

	/*
	 * This is all lockless but should be fine. If weighted_cpuload changes
	 * concurrently we'll exit nohz. And cpu_load write can race with
	 * cpu_load_update_idle() but both updater would be writing the same.
	 */
	this_rq->cpu_load[0] = weighted_cpuload(cpu_of(this_rq));
}

/*
 * Account the tickless load in the end of a nohz frame.
 */
void cpu_load_update_nohz_stop(void)
{
	unsigned long curr_jiffies = READ_ONCE(jiffies);
	struct rq *this_rq = this_rq();
	unsigned long load;

	if (curr_jiffies == this_rq->last_load_update_tick)
		return;

	load = weighted_cpuload(cpu_of(this_rq));
	raw_spin_lock(&this_rq->lock);
	update_rq_clock(this_rq);
	cpu_load_update_nohz(this_rq, curr_jiffies, load);
	raw_spin_unlock(&this_rq->lock);
}
#else /* !CONFIG_NO_HZ_COMMON */
static inline void cpu_load_update_nohz(struct rq *this_rq,
					unsigned long curr_jiffies,
					unsigned long load) { }
#endif /* CONFIG_NO_HZ_COMMON */

static void cpu_load_update_periodic(struct rq *this_rq, unsigned long load)
{
#ifdef CONFIG_NO_HZ_COMMON
	/* See the mess around cpu_load_update_nohz(). */
	this_rq->last_load_update_tick = READ_ONCE(jiffies);
#endif
	cpu_load_update(this_rq, load, 1);
}

/*
 * Called from scheduler_tick()
 */
void cpu_load_update_active(struct rq *this_rq)
{
	unsigned long load = weighted_cpuload(cpu_of(this_rq));

	if (tick_nohz_tick_stopped())
		cpu_load_update_nohz(this_rq, READ_ONCE(jiffies), load);
	else
		cpu_load_update_periodic(this_rq, load);
}

/*
 * Return a low guess at the load of a migration-source cpu weighted
 * according to the scheduling class and "nice" value.
 *
 * We want to under-estimate the load of migration sources, to
 * balance conservatively.
 *
 * 返回根据调度类和"nice"值加权的迁移源cpu负载的低猜测值.
 *
 * 我们希望低估迁移源的负载,以保守的方式进行平衡
 */
static unsigned long source_load(int cpu, int type)
{
	struct rq *rq = cpu_rq(cpu);
	unsigned long total = weighted_cpuload(cpu);

	if (type == 0 || !sched_feat(LB_BIAS))
		return total;

	return min(rq->cpu_load[type-1], total);
}

/*
 * Return a high guess at the load of a migration-target cpu weighted
 * according to the scheduling class and "nice" value.
 *
 * 根据调度类和"nice"值对迁移目标cpu的负载进行加权,返回一个较高的猜测值.
 */
static unsigned long target_load(int cpu, int type)
{
	/* 拿到该cpu的rq */
	struct rq *rq = cpu_rq(cpu);
	/* 注意计算一个CPU的负载使用cfs_rq->runnable_load_avg而不是cfs_rq->load,load权重只描述该CPU上所有的权重,并没有考虑时间的因素.
	 */
	/* 拿到CPU的cfs_rq->runnable_load_avg; */
	unsigned long total = weighted_cpuload(cpu);

	if (type == 0 || !sched_feat(LB_BIAS))
		return total;

	/* 每个就绪队列维护一个cpu_load[5]数组,在每个scheduler_tick时会重新计算,让CPU的负载显得更加平滑,详见update_cpu_load_active函数
	 * 这里返回cpu_load和runnable_load_avg的最大值
	 */
	return max(rq->cpu_load[type-1], total);
}

static unsigned long capacity_of(int cpu)
{
	return cpu_rq(cpu)->cpu_capacity;
}

static unsigned long capacity_orig_of(int cpu)
{
	return cpu_rq(cpu)->cpu_capacity_orig;
}

static unsigned long cpu_avg_load_per_task(int cpu)
{
	struct rq *rq = cpu_rq(cpu);
	unsigned long nr_running = READ_ONCE(rq->cfs.h_nr_running);
	unsigned long load_avg = weighted_cpuload(cpu);

	if (nr_running)
		return load_avg / nr_running;

	return 0;
}

#ifdef CONFIG_FAIR_GROUP_SCHED
/*
 * effective_load() calculates the load change as seen from the root_task_group
 *
 * Adding load to a group doesn't make a group heavier, but can cause movement
 * of group shares between cpus. Assuming the shares were perfectly aligned one
 * can calculate the shift in shares.
 *
 * Calculate the effective load difference if @wl is added (subtracted) to @tg
 * on this @cpu and results in a total addition (subtraction) of @wg to the
 * total group weight.
 *
 * Given a runqueue weight distribution (rw_i) we can compute a shares
 * distribution (s_i) using:
 *
 *   s_i = rw_i / \Sum rw_j						(1)
 *
 * Suppose we have 4 CPUs and our @tg is a direct child of the root group and
 * has 7 equal weight tasks, distributed as below (rw_i), with the resulting
 * shares distribution (s_i):
 *
 *   rw_i = {   2,   4,   1,   0 }
 *   s_i  = { 2/7, 4/7, 1/7,   0 }
 *
 * As per wake_affine() we're interested in the load of two CPUs (the CPU the
 * task used to run on and the CPU the waker is running on), we need to
 * compute the effect of waking a task on either CPU and, in case of a sync
 * wakeup, compute the effect of the current task going to sleep.
 *
 * So for a change of @wl to the local @cpu with an overall group weight change
 * of @wl we can compute the new shares distribution (s'_i) using:
 *
 *   s'_i = (rw_i + @wl) / (@wg + \Sum rw_j)				(2)
 *
 * Suppose we're interested in CPUs 0 and 1, and want to compute the load
 * differences in waking a task to CPU 0. The additional task changes the
 * weight and shares distributions like:
 *
 *   rw'_i = {   3,   4,   1,   0 }
 *   s'_i  = { 3/8, 4/8, 1/8,   0 }
 *
 * We can then compute the difference in effective weight by using:
 *
 *   dw_i = S * (s'_i - s_i)						(3)
 *
 * Where 'S' is the group weight as seen by its parent.
 *
 * Therefore the effective change in loads on CPU 0 would be 5/56 (3/8 - 2/7)
 * times the weight of the group. The effect on CPU 1 would be -4/56 (4/8 -
 * 4/7) times the weight of the group.
 */
static long effective_load(struct task_group *tg, int cpu, long wl, long wg)
{
	struct sched_entity *se = tg->se[cpu];

	if (!tg->parent)	/* the trivial, non-cgroup case */
		return wl;

	for_each_sched_entity(se) {
		struct cfs_rq *cfs_rq = se->my_q;
		long W, w = cfs_rq_load_avg(cfs_rq);

		tg = cfs_rq->tg;

		/*
		 * W = @wg + \Sum rw_j
		 */
		W = wg + atomic_long_read(&tg->load_avg);

		/* Ensure \Sum rw_j >= rw_i */
		W -= cfs_rq->tg_load_avg_contrib;
		W += w;

		/*
		 * w = rw_i + @wl
		 */
		w += wl;

		/*
		 * wl = S * s'_i; see (2)
		 */
		if (W > 0 && w < W)
			wl = (w * (long)scale_load_down(tg->shares)) / W;
		else
			wl = scale_load_down(tg->shares);

		/*
		 * Per the above, wl is the new se->load.weight value; since
		 * those are clipped to [MIN_SHARES, ...) do so now. See
		 * calc_cfs_shares().
		 */
		if (wl < MIN_SHARES)
			wl = MIN_SHARES;

		/*
		 * wl = dw_i = S * (s'_i - s_i); see (3)
		 */
		wl -= se->avg.load_avg;

		/*
		 * Recursively apply this logic to all parent groups to compute
		 * the final effective load change on the root group. Since
		 * only the @tg group gets extra weight, all parent groups can
		 * only redistribute existing shares. @wl is the shift in shares
		 * resulting from this level per the above.
		 */
		wg = 0;
	}

	return wl;
}
#else

static long effective_load(struct task_group *tg, int cpu, long wl, long wg)
{
	return wl;
}

#endif

/* 每次waker唤醒wakee的时候都会调用record_wakee来更新上面的成员 */
/* 每隔一秒对wakee_flips进行衰减.
 * 如果一个线程能够经常的唤醒不同的其他线程,那么该线程的wakee_flips会保持在一个较高的值.
 * 相反,如果仅仅是偶尔唤醒一次其他线程,和某个固定的线程有唤醒关系,那么这里的wakee_flips应该会趋向0B、如果上次唤醒的不是p,
 * 那么要切换wakee,并累加wakee翻转次数
 * Waker唤醒wakee的场景中,有两种placement思路:
 * 一种是聚合的思路,即让waker和wakee尽量的close,从而提高cache hit.
 * 另外一种思考是分散,即让load尽量平均分配在多个cpu上.不同的唤醒模型使用不同的放置策略.
 * 我们来看看下面两种简单的唤醒模型:(1) 在1：N模型中,一个server会不断的唤醒多个不同的client
 * (2) 1：1模型,线程A和线程B不断的唤醒对方在1:N模型中,如果N是一个较大的数值,那么让waker和wakee尽量的close会导致负荷的极度不平均,
 * 这会waker所在的sched domain会承担太多的task,从而引起性能下降.
 * 在1：1模型中,让waker和wakee尽量的close不存在这样的问题,同时还能提高性能.
 * 当然,实际的程序中,唤醒关系可能没有那么简单,一个wakee可能是另外一个关系中的waker,交互可能是M：N的形式.
 * 考虑这样一个场景: waker把wakee拉近,而wakee自身的wakeeflips比较大,那么更多的线程也会拉近waker所在的sched domain,从而进一步加剧CPU资源的竞争.
 * 因此waker和wakee的wakee flips的数值都不能太大,太大的时候应该禁止wake affine.
 * 内核中通过wake_wide来判断是否使能wake affine.
 */
static void record_wakee(struct task_struct *p)
{
	/*
	 * Only decay a single time; tasks that have less then 1 wakeup per
	 * jiffy will not have built up many flips.
	 *
	 * 只衰减一次;
	 * 每jiffy唤醒次数少于1次的任务不会产生很多flips
	 */
	/* 如果jiffies比current->wakee_flip_decay_ts + HZ大,那么衰减current->wakee_flips */
	if (time_after(jiffies, current->wakee_flip_decay_ts + HZ)) {
		/* current->wakee_flips / 2 */
		current->wakee_flips >>= 1;
		/* 设置上次进行酸碱的时间点为本jiffies */
		current->wakee_flip_decay_ts = jiffies;
	}

	/* 如果current->last_wakee(也就是说上次唤醒的线程不是本进程) */
	if (current->last_wakee != p) {
		/* 设置上次唤醒的进程为本进程,让current->wakee_flips++ */
		current->last_wakee = p;
		current->wakee_flips++;
	}
}

/*
 * Detect M:N waker/wakee relationships via a switching-frequency heuristic.
 *
 * A waker of many should wake a different task than the one last awakened
 * at a frequency roughly N times higher than one of its wakees.
 *
 * In order to determine whether we should let the load spread vs consolidating
 * to shared cache, we look for a minimum 'flip' frequency of llc_size in one
 * partner, and a factor of lls_size higher frequency in the other.
 *
 * With both conditions met, we can be relatively sure that the relationship is
 * non-monogamous, with partner count exceeding socket size.
 *
 * Waker/wakee being client/server, worker/dispatcher, interrupt source or
 * whatever is irrelevant, spread criteria is apparent partner count exceeds
 * socket size.
 *
 * 通过切换频率启发式方法检测M:N唤醒者/被唤醒者关系.
 *
 * 如果一个唤醒者唤醒多个任务,那么它应该以大约是其任一被唤醒者N倍高的频率唤醒与上一次不同的任务.
 *
 * 为了确定我们是应该让负载分散还是合并到共享缓存中,我们会寻找一个伙伴中的llc_size的“翻转”频率的最小值,以及另一个伙伴中比该值高lls_size倍的频率.
 *
 * 如果这两个条件都满足,我们可以相对确定这种关系是非一夫一妻制的,即伙伴数量超过了插槽（socket）数量.
 *
 * 唤醒者/被唤醒者是客户端/服务器、工作者/调度器、中断源或任何其他角色都无关紧要,分散的标准是明显的伙伴数量超过了插槽数量
 */
static int wake_wide(struct task_struct *p)
{

	/* 这里的场景是current task唤醒任务p的场景,master是current唤醒不同线程的次数,slave是被唤醒的任务p唤醒不同线程的次数. */
	unsigned int master = current->wakee_flips;
	unsigned int slave = p->wakee_flips;
	/* Wake affine场景下任务放置要走快速路径,即在LLC上选择空闲的CPU.
	 * sd_llc_size是LLC domain上CPU的个数.
	 * Wake affine本质上是把wakee线程们拉到waker所在的LLC domain,如果超过了LLC domain的cpu个数,那么必然有任务需要等待,这也就失去了wake affine提升性能的初衷.
	 * 对于手机平台,llc domain是MC domain.
	 */
	int factor = this_cpu_read(sd_llc_size);

	/* 一般而言,执行更多唤醒动作(并且唤醒不同task)的任务是master,因此这里根据翻转次数来交换master和slave,确保master的翻转次数大于slave */
	if (master < slave)
		swap(master, slave);
	/* Slave和master的wakee_flips如果比较小,那么启动wake affine,否则disable wake affine,走正常选核逻辑.
	 * 这里的or逻辑是存疑的,因为master和slave其一的wakee_flips比较小就会wake affine,这会使得任务太容易在LLC domain堆积了.
	 * 在1：N模型中(例如手机转屏的时候,一个线程会唤醒非常非常多的线程来处理configChange消息),master的wakee_flips巨大无比,slave的wakee_flips非常小,如果仍然wake affine是不合理的.
	 *
	 * 如果判断需要进行wake affine,那么我们需要在waking cpu和该任务的prev cpu中选择一个CPU,后续在该CPU的LLC domain上进行wakeaffine.
	 * 选择waking cpu还是prev cpu的逻辑是在wake_affine中实现
	 */
	if (slave < factor || master < slave * factor)
		return 0;
	return 1;
}

static int wake_affine(struct sched_domain *sd, struct task_struct *p,
		       int prev_cpu, int sync)
{
	s64 this_load, load;
	s64 this_eff_load, prev_eff_load;
	int idx, this_cpu;
	struct task_group *tg;
	unsigned long weight;
	int balanced;

	idx	  = sd->wake_idx;
	this_cpu  = smp_processor_id();
	/* 算出prev_cpu的cfs_rq->runnable_load_avg; */
	load	  = source_load(prev_cpu, idx);
	/* 算出this_cpu的cfs_rq->runnable_load_avg; */
	this_load = target_load(this_cpu, idx);

	/*
	 * If sync wakeup then subtract the (maximum possible)
	 * effect of the currently running task from the load
	 * of the current CPU:
	 *
	 * 如果同步唤醒,则从当前CPU的负载中减去当前运行任务的(最大可能)影响:
	 */

	/* 如果是同步唤醒 */
	if (sync) {
		/* 拿到当前进程的task_group */
		tg = task_group(current);
		/* 拿到当前进程的负载贡献值 */
		weight = current->se.avg.load_avg;

		/* this_load - weight */
		this_load += effective_load(tg, this_cpu, -weight, -weight);
		/* load - weight */
		load += effective_load(tg, prev_cpu, 0, -weight);
	}

	/* 拿到要唤醒进程的task_group */
	tg = task_group(p);
	/* 拿到要唤醒进程的负载贡献值 */
	weight = p->se.avg.load_avg;

	/*
	 * In low-load situations, where prev_cpu is idle and this_cpu is idle
	 * due to the sync cause above having dropped this_load to 0, we'll
	 * always have an imbalance, but there's really nothing you can do
	 * about that, so that's good too.
	 *
	 * Otherwise check if either cpus are near enough in load to allow this
	 * task to be woken on this_cpu.
	 *
	 * 在低负载情况下,如果prev_cpu(前一个CPU)和this_cpu(当前CPU)的负载由于该同步操作降至0处于空闲状态,那么总会存在负载不平衡的情况.
	 * 然而,在这种情况下,实际上并没有太多可以做的,所以这也算是一种好的状态.
	 *
	 * 否则,检查这两个CPU的负载是否相近到足以允许该任务在当前CPU(this_cpu)上被唤醒.
	 *
	 * 这段描述涉及到Linux调度器(scheduler)在处理任务迁移(或唤醒)时的一个场景,特别是在考虑CPU负载和空闲状态时.
	 * Linux调度器负责决定哪个任务应该在哪个CPU上运行,以优化系统性能和响应能力.
	 * 在这种情况下,如果两个CPU都相对空闲,那么即使存在轻微的负载不平衡,调度器也可能不会进行任务迁移,因为这可能会引入不必要的开销.
	 * 然而,如果两个CPU的负载相近,那么调度器可能会考虑在当前CPU上唤醒任务,以减少跨CPU的迁移开销.
	 */

	/* this_eff_load = 100 * capacity_of(prev_cpu) */
	this_eff_load = 100;
	this_eff_load *= capacity_of(prev_cpu);

	/* prev_eff_load =(100 + (sd->imbalance_pct - 100) / 2 ) * capacity_of(this_cpu) */
	prev_eff_load = 100 + (sd->imbalance_pct - 100) / 2;
	prev_eff_load *= capacity_of(this_cpu);

	/* 如果this_load > 0,那说明还有任务 */
	if (this_load > 0) {
		/* 那么this_eff_load = this_eff_load *(this_load + effective_load(tg, this_cpu, weight, weight));
		 * 这里应该说的是p把current从当前CPU上挤下去后,CPU上CFS任务的总负载 */
		this_eff_load *= this_load +
			effective_load(tg, this_cpu, weight, weight);
		/* 这里原封不动？ */
		prev_eff_load *= load + effective_load(tg, prev_cpu, 0, weight);
	}

	/* balanced = this_eff_load和prev_eff_load大小比 */
	balanced = this_eff_load <= prev_eff_load;

	schedstat_inc(p->se.statistics.nr_wakeups_affine_attempts);

	/* 如果this_eff_load > prev_eff_load,那么等于0 */
	if (!balanced)
		return 0;

	schedstat_inc(sd->ttwu_move_affine);
	schedstat_inc(p->se.statistics.nr_wakeups_affine);

	/* 如果this_eff_load <= prev_eff_load返回1 */
	return 1;
}

/*
 * find_idlest_group finds and returns the least busy CPU group within the
 * domain.
 */
static struct sched_group *
find_idlest_group(struct sched_domain *sd, struct task_struct *p,
		  int this_cpu, int sd_flag)
{
	struct sched_group *idlest = NULL, *group = sd->groups;
	unsigned long min_load = ULONG_MAX, this_load = 0;
	int load_idx = sd->forkexec_idx;
	int imbalance = 100 + (sd->imbalance_pct-100)/2;

	/*根据sd_flag数值,设定load_idx数值(只有被wakeup的进程才会设置) */
	if (sd_flag & SD_BALANCE_WAKE)
		load_idx = sd->wake_idx;

	/* 开始对sd内的所有sg遍历 */
	do {
		unsigned long load, avg_load;
		int local_group;
		int i;

		/* Skip over this group if it has no CPUs allowed */
		/* sg内的cpu与进程的cpu亲和数没有交集,直接进行下次遍历 */
		if (!cpumask_intersects(sched_group_cpus(group),
					tsk_cpus_allowed(p)))
			continue;

		/* 由于sd是最底层MC SDTL,所以cpumask_weight(sched_group_cpus(group))=1
		 * local_group目的是确定this_cpu是否在本次遍历的group中
		 */
		local_group = cpumask_test_cpu(this_cpu,
					       sched_group_cpus(group));

		/* Tally up the load of all CPUs in the group
		 * 统计组中所有CPU的负载
		 */
		avg_load = 0;

		/* 在这个group计算累加负载 */
		for_each_cpu(i, sched_group_cpus(group)) {
			/* Bias balancing toward cpus of our domain */
			if (local_group)
				load = source_load(i, load_idx);
			else
				load = target_load(i, load_idx);
			/* 累加负载,后面会归一化为相对负载 */
			avg_load += load;
		}

		/* Adjust by relative CPU capacity of the group */
		avg_load = (avg_load * SCHED_CAPACITY_SCALE) / group->sgc->capacity;

		/* 根据每次遍历的local_group的数值,来update相应的一些决策变量 */
		if (local_group) {
			this_load = avg_load;
		/* 获取最小load的group */
		} else if (avg_load < min_load) {
			min_load = avg_load;
			idlest = group;
		}
	} while (group = group->next, group != sd->groups);

	/* 如果idlest == NULL 或者说100 * this_load < imbalance * min_load */
	if (!idlest || 100*this_load < imbalance*min_load)
		return NULL;
	return idlest;
}

/*
 * find_idlest_cpu - find the idlest cpu among the cpus in group.
 */
static int
find_idlest_cpu(struct sched_group *group, struct task_struct *p, int this_cpu)
{
	unsigned long load, min_load = ULONG_MAX;
	unsigned int min_exit_latency = UINT_MAX;
	u64 latest_idle_timestamp = 0;
	int least_loaded_cpu = this_cpu;
	int shallowest_idle_cpu = -1;
	int i;

	/* Check if we have any choice: */
	/* 如果group->group_weight == 1,说明只有这个CPU,那么直接返回就好了 */
	if (group->group_weight == 1)
		return cpumask_first(sched_group_cpus(group));

	/* Traverse only the allowed CPUs */
	/* 对group中的CPU和该task allow的CPU进行遍历 */
	for_each_cpu_and(i, sched_group_cpus(group), tsk_cpus_allowed(p)) {
		/* 如果该CPU处于idle状态 */
		if (idle_cpu(i)) {
			struct rq *rq = cpu_rq(i);
			struct cpuidle_state *idle = idle_get_state(rq);
			/* cpu处于idle并且退出时延最小,那么cpu肯定是最浅idle状态的cpu了,idle状态越深,退出时延越大 */
			if (idle && idle->exit_latency < min_exit_latency) {
				/*
				 * We give priority to a CPU whose idle state
				 * has the smallest exit latency irrespective
				 * of any idle timestamp.
				 */
				min_exit_latency = idle->exit_latency;
				latest_idle_timestamp = rq->idle_stamp;
				shallowest_idle_cpu = i;
			/* 如果退出时延是最小退出时延并且此cpu之前进入过idle状态.那么挑选刚刚进入idle的cpu最为idle状态最浅的cpu.注释很清楚 */
			} else if ((!idle || idle->exit_latency == min_exit_latency) &&
				   rq->idle_stamp > latest_idle_timestamp) {
				/*
				 * If equal or no active idle state, then
				 * the most recently idled CPU might have
				 * a warmer cache.
				 */
				latest_idle_timestamp = rq->idle_stamp;
				shallowest_idle_cpu = i;
			}
		 /* 如果没有cpu处于idle,那么选择load最轻的cpu作为返回值 */
		} else if (shallowest_idle_cpu == -1) {
			load = weighted_cpuload(i);
			if (load < min_load || (load == min_load && i == this_cpu)) {
				min_load = load;
				least_loaded_cpu = i;
			}
		}
	}

	/* 根据系统是否有idle cpu来决策是选择最浅idle状态的cpu还是选择最轻负载的cpu */
	return shallowest_idle_cpu != -1 ? shallowest_idle_cpu : least_loaded_cpu;
}

/*
 * Implement a for_each_cpu() variant that starts the scan at a given cpu
 * (@start), and wraps around.
 *
 * This is used to scan for idle CPUs; such that not all CPUs looking for an
 * idle CPU find the same CPU. The down-side is that tasks tend to cycle
 * through the LLC domain.
 *
 * Especially tbench is found sensitive to this.
 */

static int cpumask_next_wrap(int n, const struct cpumask *mask, int start, int *wrapped)
{
	int next;

again:
	next = find_next_bit(cpumask_bits(mask), nr_cpumask_bits, n+1);

	if (*wrapped) {
		if (next >= start)
			return nr_cpumask_bits;
	} else {
		if (next >= nr_cpumask_bits) {
			*wrapped = 1;
			n = -1;
			goto again;
		}
	}

	return next;
}

#define for_each_cpu_wrap(cpu, mask, start, wrap)				\
	for ((wrap) = 0, (cpu) = (start)-1;					\
		(cpu) = cpumask_next_wrap((cpu), (mask), (start), &(wrap)),	\
		(cpu) < nr_cpumask_bits; )

#ifdef CONFIG_SCHED_SMT

static inline void set_idle_cores(int cpu, int val)
{
	struct sched_domain_shared *sds;

	sds = rcu_dereference(per_cpu(sd_llc_shared, cpu));
	if (sds)
		WRITE_ONCE(sds->has_idle_cores, val);
}

static inline bool test_idle_cores(int cpu, bool def)
{
	struct sched_domain_shared *sds;

	sds = rcu_dereference(per_cpu(sd_llc_shared, cpu));
	if (sds)
		return READ_ONCE(sds->has_idle_cores);

	return def;
}

/*
 * Scans the local SMT mask to see if the entire core is idle, and records this
 * information in sd_llc_shared->has_idle_cores.
 *
 * Since SMT siblings share all cache levels, inspecting this limited remote
 * state should be fairly cheap.
 */
void __update_idle_core(struct rq *rq)
{
	int core = cpu_of(rq);
	int cpu;

	rcu_read_lock();
	if (test_idle_cores(core, true))
		goto unlock;

	for_each_cpu(cpu, cpu_smt_mask(core)) {
		if (cpu == core)
			continue;

		if (!idle_cpu(cpu))
			goto unlock;
	}

	set_idle_cores(core, 1);
unlock:
	rcu_read_unlock();
}

/*
 * Scan the entire LLC domain for idle cores; this dynamically switches off if
 * there are no idle cores left in the system; tracked through
 * sd_llc->shared->has_idle_cores and enabled through update_idle_core() above.
 */
static int select_idle_core(struct task_struct *p, struct sched_domain *sd, int target)
{
	struct cpumask *cpus = this_cpu_cpumask_var_ptr(select_idle_mask);
	int core, cpu, wrap;

	if (!static_branch_likely(&sched_smt_present))
		return -1;

	if (!test_idle_cores(target, false))
		return -1;

	cpumask_and(cpus, sched_domain_span(sd), tsk_cpus_allowed(p));

	for_each_cpu_wrap(core, cpus, target, wrap) {
		bool idle = true;

		for_each_cpu(cpu, cpu_smt_mask(core)) {
			cpumask_clear_cpu(cpu, cpus);
			if (!idle_cpu(cpu))
				idle = false;
		}

		if (idle)
			return core;
	}

	/*
	 * Failed to find an idle core; stop looking for one.
	 */
	set_idle_cores(target, 0);

	return -1;
}

/*
 * Scan the local SMT mask for idle CPUs.
 */
static int select_idle_smt(struct task_struct *p, struct sched_domain *sd, int target)
{
	int cpu;

	if (!static_branch_likely(&sched_smt_present))
		return -1;

	for_each_cpu(cpu, cpu_smt_mask(target)) {
		if (!cpumask_test_cpu(cpu, tsk_cpus_allowed(p)))
			continue;
		if (idle_cpu(cpu))
			return cpu;
	}

	return -1;
}

#else /* CONFIG_SCHED_SMT */

static inline int select_idle_core(struct task_struct *p, struct sched_domain *sd, int target)
{
	return -1;
}

static inline int select_idle_smt(struct task_struct *p, struct sched_domain *sd, int target)
{
	return -1;
}

#endif /* CONFIG_SCHED_SMT */

/*
 * Scan the LLC domain for idle CPUs; this is dynamically regulated by
 * comparing the average scan cost (tracked in sd->avg_scan_cost) against the
 * average idle time for this rq (as found in rq->avg_idle).
 */
static int select_idle_cpu(struct task_struct *p, struct sched_domain *sd, int target)
{
	struct sched_domain *this_sd;
	u64 avg_cost, avg_idle = this_rq()->avg_idle;
	u64 time, cost;
	s64 delta;
	int cpu, wrap;

	this_sd = rcu_dereference(*this_cpu_ptr(&sd_llc));
	if (!this_sd)
		return -1;

	avg_cost = this_sd->avg_scan_cost;

	/*
	 * Due to large variance we need a large fuzz factor; hackbench in
	 * particularly is sensitive here.
	 */
	if ((avg_idle / 512) < avg_cost)
		return -1;

	time = local_clock();

	for_each_cpu_wrap(cpu, sched_domain_span(sd), target, wrap) {
		if (!cpumask_test_cpu(cpu, tsk_cpus_allowed(p)))
			continue;
		if (idle_cpu(cpu))
			break;
	}

	time = local_clock() - time;
	cost = this_sd->avg_scan_cost;
	delta = (s64)(time - cost) / 8;
	this_sd->avg_scan_cost += delta;

	return cpu;
}

/*
 * Try and locate an idle core/thread in the LLC cache domain.
 */

/* select_idle_sibling函数优先选择idle CPU,如果没找到idle CPU,那么只能选择prev CPU或wakeup CPU.
 * 参数target指prev CPU或wakeup CPU中的一个.
 */
static int select_idle_sibling(struct task_struct *p, int prev, int target)
{
	struct sched_domain *sd;
	int i;

	/* 如果target是idle cpu,那么直接返回target */
	if (idle_cpu(target))
		return target;

	/*
	 * If the previous cpu is cache affine and idle, don't be stupid.
	 */
	/* cpus_share_cache函数判断两个CPU是否具有cache亲缘性.
	 * 若它们同属于一个SMT或MC调度域,则共享L1 cache或L2 cache,这是通过Per-CPU变量sd_llc_id来判断的,sd_llc_id变量在update_top_cache_domain函数中赋值.
	 * update_top_cache_domain函数会从下而上遍历和查找第一个包含SD_SHARE_PKG_RESOURCES标志位的调度域,
	 * 并把调度域中第一个CPU ID赋值给sd_llc_id变量.
	 * 通常SMT或MC调度域的CPU会设置SD_SHARE_PKG_RESOURCES标志位.
	 * cpu_share_cache函数判断两个CPU是否在同一个包含SD_SHARE_PKG_RESOURCES标志位的调度域中,从而知道他们是否具有cache亲缘性.
	 */

	/* 如果prev和target不相等,并且他们是共享cache,并且prev是idle cpu,那么就选择prev */
	if (prev != target && cpus_share_cache(prev, target) && idle_cpu(prev))
		return prev;

	/* 拿到指向第一个包含SD_SHARE_PKG_RESOURCES标志位的调度域.
	 * 以4核CPU为例,包含MC和DIE的SDTL层级,那么sd_llc指向CPU对应的MC调度域 */
	sd = rcu_dereference(per_cpu(sd_llc, target));
	if (!sd)
		return target;

	/* CONFIG_SCHED_SMT未定义为空函数 */
	i = select_idle_core(p, sd, target);
	if ((unsigned)i < nr_cpumask_bits)
		return i;

	i = select_idle_cpu(p, sd, target);
	if ((unsigned)i < nr_cpumask_bits)
		return i;

	i = select_idle_smt(p, sd, target);
	if ((unsigned)i < nr_cpumask_bits)
		return i;

	return target;
}

/*
 * cpu_util returns the amount of capacity of a CPU that is used by CFS
 * tasks. The unit of the return value must be the one of capacity so we can
 * compare the utilization with the capacity of the CPU that is available for
 * CFS task (ie cpu_capacity).
 *
 * cfs_rq.avg.util_avg is the sum of running time of runnable tasks plus the
 * recent utilization of currently non-runnable tasks on a CPU. It represents
 * the amount of utilization of a CPU in the range [0..capacity_orig] where
 * capacity_orig is the cpu_capacity available at the highest frequency
 * (arch_scale_freq_capacity()).
 * The utilization of a CPU converges towards a sum equal to or less than the
 * current capacity (capacity_curr <= capacity_orig) of the CPU because it is
 * the running time on this CPU scaled by capacity_curr.
 *
 * Nevertheless, cfs_rq.avg.util_avg can be higher than capacity_curr or even
 * higher than capacity_orig because of unfortunate rounding in
 * cfs.avg.util_avg or just after migrating tasks and new task wakeups until
 * the average stabilizes with the new running time. We need to check that the
 * utilization stays within the range of [0..capacity_orig] and cap it if
 * necessary. Without utilization capping, a group could be seen as overloaded
 * (CPU0 utilization at 121% + CPU1 utilization at 80%) whereas CPU1 has 20% of
 * available capacity. We allow utilization to overshoot capacity_curr (but not
 * capacity_orig) as it useful for predicting the capacity required after task
 * migrations (scheduler-driven DVFS).
 *
 * cpu_util 返回的是由CFS（Completely Fair Scheduler，完全公平调度器）任务所使用的CPU的容量大小.
 * 返回值的单位必须是容量的单位,这样我们才能将利用率与可用于CFS任务的CPU容量（即cpu_capacity）进行比较.
 *
 * cfs_rq.avg.util_avg是CPU上可运行任务的运行时间总和加上当前不可运行任务的最近利用率.
 * 它代表了CPU在[0..capacity_orig]范围内的利用率,其中capacity_orig是在最高频率下可用的cpu_capacity(通过arch_scale_freq_capacity()计算得出).
 * CPU的利用率会趋向于等于或小于CPU的当前容量(capacity_curr <= capacity_orig),因为这是在CPU上运行的时间按capacity_curr进行缩放的.
 *
 * 然而,cfs_rq.avg.util_avg可能因为cfs.avg.util_avg中的不幸舍入或任务迁移和新任务唤醒后直到平均值与新运行时间稳定下来之前的这段时间,而高于capacity_curr甚至高于capacity_orig.
 * 我们需要检查利用率是否保持在[0..capacity_orig]范围内,并在必要时进行限制.
 * 如果不进行利用率限制,一个组可能会被错误地视为过载(例如,CPU0利用率为121% + CPU1利用率为80%),而实际上CPU1还有20%的可用容量.
 * 我们允许利用率超过capacity_curr(但不超过capacity_orig),因为这有助于在任务迁移后预测所需的容量(由调度器驱动的DVFS，即动态电压和频率缩放).
 */
static int cpu_util(int cpu)
{
	unsigned long util = cpu_rq(cpu)->cfs.avg.util_avg;
	unsigned long capacity = capacity_orig_of(cpu);

	return (util >= capacity) ? capacity : util;
}

static inline int task_util(struct task_struct *p)
{
	return p->se.avg.util_avg;
}

/*
 * Disable WAKE_AFFINE in the case where task @p doesn't fit in the
 * capacity of either the waking CPU @cpu or the previous CPU @prev_cpu.
 *
 * In that case WAKE_AFFINE doesn't make sense and we'll let
 * BALANCE_WAKE sort things out.
 *
 * 如果task @p不适合唤醒的CPU @cpu或前一个CPU@prev_CPU的容量,请禁用WAKE_AFFINE.
 *
 * 在这种情况下,WAKE_AFFINE没有意义,我们会让BALANCE_WAKE来解决问题.
 */
static int wake_cap(struct task_struct *p, int cpu, int prev_cpu)
{
	long min_cap, max_cap;

	/* 拿到prev_cpu和本cpu最小的capacity */
	min_cap = min(capacity_orig_of(prev_cpu), capacity_orig_of(cpu));
	/* 获得该cpu rd的最大cpu的capacity */
	max_cap = cpu_rq(cpu)->rd->max_cpu_capacity;

	/* Minimum capacity is close to max, no need to abort wake_affine
	 * 最小容量接近最大,无需中止wake_affiine
	 */

	/* 如果max_cap - min_cap < max_cap >> 3,也就是不超过max_cap - min_cap < max_cap /8
	 * 大小核能力悬殊不超过12.5%
	 */
	if (max_cap - min_cap < max_cap >> 3)
		return 0;

	/* min_cap * 1024 < task_util(p) * 1280 */
	return min_cap * 1024 < task_util(p) * capacity_margin;
}

/*
 * select_task_rq_fair: Select target runqueue for the waking task in domains
 * that have the 'sd_flag' flag set. In practice, this is SD_BALANCE_WAKE,
 * SD_BALANCE_FORK, or SD_BALANCE_EXEC.
 *
 * Balances load by selecting the idlest cpu in the idlest group, or under
 * certain conditions an idle sibling cpu if the domain has SD_WAKE_AFFINE set.
 *
 * Returns the target cpu number.
 *
 * preempt must be disabled.
 *
 * select_task_rq_fair: 在设置了"sd_flag"标志的域中为唤醒任务选择目标运行队列.
 * 在实践中,这是SD_BALANCE_WAKE、SD_BALANCE_FORK或SD_BALANCE _EXEC.
 *
 * 通过选择最空闲组中最空闲的cpu来平衡负载,或者在某些情况下,如果域设置了SD_WAKE_AFFINE,则选择空闲的兄弟cpu.
 *
 * 返回目标cpu编号. 必须禁用抢占
 */

/* 参数p表示要唤醒的进程,prev_cpu指上一次运行该进程的CPU,sd_flag为SD_BALANCE_WAKE,
 * wake_flags为0.
 */
static int
select_task_rq_fair(struct task_struct *p, int prev_cpu, int sd_flag, int wake_flags)
{
	struct sched_domain *tmp, *affine_sd = NULL, *sd = NULL;
	/* 拿到本地CPU */
	int cpu = smp_processor_id();
	int new_cpu = prev_cpu;
	int want_affine = 0;
	/* sync为0表示不需要同步
	 *
	 * Wakeup有两种,一种是sync wakeup,另外一种是non-sync wakeup.
	 *
	 * 所谓sync wakeup就是waker在唤醒wakee的时候就已经知道自己很快就进入sleep 状态,而在调用try_to_wake_up的时候最好不要进行抢占,
	 * 因为waker很快就主动发起调度了.
	 * 此外,一般而言,waker和wakee会有一定的亲和性(例如它们通过share memory进行通信),
	 * 在SMP场景下,waker和wakee调度在一个CPU上执行的时候往往可以获取较佳的性能.
	 * 而如果在try_to_wake_up的时候就进行调度,这时候wakee往往会调度到系统中其他空闲的CPU上去.
	 * 这时候,通过sync wakeup,我们往往可以避免不必要的CPU bouncing.
	 * 对于non-sync wakeup而言,waker和wakee没有上面描述的同步关系,waker在唤醒wakee之后,它们之间是独立运作,因此在唤醒的时候就可以尝试去触发一次调度.
	 *
	 * 当然,也不是说sync wakeup就一定不调度,假设waker在CPU A上唤醒wakee,而根据wakee进程的cpus_allowed成员发现它根本不能在CPU A上调度执行,
	 * 那么管他sync不sync,这时候都需要去尝试调度(调用reschedule_idle函数),反正waker和wakee命中注定是天各一方(在不同的CPU上执行).
	 */
	int sync = wake_flags & WF_SYNC;

	/* 如果sd_flag带了SD_BALANCE_WAKE
	 * want_affine表示wake up CPU是进程允许运行的CPU,有机会用wake up CPU来唤醒以及运行这个进程.
	 */
	if (sd_flag & SD_BALANCE_WAKE) {
		record_wakee(p);
		/* 如果wake_wide返回0,
		 * 在异构的cpu当中,如果大核能力悬殊过大,放在能力更大的cpu上或许可以获得更好的性能,所以,又需要判断能力是否有悬殊.
		 * 注意这里的亲和性会在当前cpu与task原来所在的cpu之间进行选择.
		 * 然后看看当前CPU有没有在p的cpus_list里面
		 * 如果都满足,那么就走快速路径
		 */
		want_affine = !wake_wide(p) && !wake_cap(p, cpu, prev_cpu)
			      && cpumask_test_cpu(cpu, tsk_cpus_allowed(p));
	}

	rcu_read_lock();
	/* 从wake up CPU开始从下至上遍历调度域 */
	for_each_domain(cpu, tmp) {

		/* 如果该调度域不参与负载均衡,那么break */
		if (!(tmp->flags & SD_LOAD_BALANCE))
			break;

		/*
		 * If both cpu and prev_cpu are part of this domain,
		 * cpu is a valid SD_WAKE_AFFINE target.
		 */

		/* 如果wakeup cpu和prev_cpu在同一个调度域且这个调度域包含了SD_WAKE_AFFINE标志位,那么affine_sd调度域具有亲和性 */
		if (want_affine && (tmp->flags & SD_WAKE_AFFINE) &&
		    cpumask_test_cpu(prev_cpu, sched_domain_span(tmp))) {
			affine_sd = tmp;
			break;
		}

		/* 如果tmp调度域的flags有包含我们传进来的sd_flag,那么sd = tmp,这里的作用是找到支持sd_flag的最高层级的sd */
		if (tmp->flags & sd_flag)
			sd = tmp; /* 如果want_affine 等于false,那么直接break吧 */
		else if (!want_affine)
			break;
	}

	/* 当找到亲和性调度域时 */
	if (affine_sd) {
		sd = NULL; /* Prefer wake_affine over balance flags */
		/* 如果wakeup CPU和prev CPU不是同一个CPU,那么可以考虑使用wakeup CPU来唤醒进程.
		 * wake_affine会重新计算wake cpu和prev cpu的负载情况.
		 * 如果wakeup CPU的负载加上唤醒进程的负载比prev CPU负载小,那么wakeup CPU是可以唤醒进程的
		 *
		 * wake_affine希望把被唤醒进程尽可能地运行在wakeup CPU上,这样可以让一些有相关性的进程尽可能地运行在具有cache共享的调度域中,获得一些cache-hit带来的性能提升
		 */
		if (cpu != prev_cpu && wake_affine(affine_sd, p, prev_cpu, sync))
			new_cpu = cpu;
	}

	if (!sd) {
		if (sd_flag & SD_BALANCE_WAKE) /* XXX always ? */	/* 选择一个合适的CPU */
			new_cpu = select_idle_sibling(p, prev_cpu, new_cpu);

	/* 有sd表示tmp->flags & sd_flags为true */
	} else while (sd) {
		/* 否则开始从下遍历查找最悠闲的调度组和最悠闲的CPU来唤醒该进程 */
		struct sched_group *group;
		int weight;

		if (!(sd->flags & sd_flag)) {
			sd = sd->child;
			continue;
		}

		/* 找到最闲的group */
		group = find_idlest_group(sd, p, cpu, sd_flag);
		if (!group) {
			sd = sd->child;
			continue;
		}

		/* 找到最闲的group中最idle的CPU */
		new_cpu = find_idlest_cpu(group, p, cpu);
		if (new_cpu == -1 || new_cpu == cpu) {
			/* Now try balancing at a lower domain level of cpu */
			sd = sd->child;
			continue;
		}

		/* Now try balancing at a lower domain level of new_cpu
		 * 现在尝试在new_cpu的较低域domain level进行平衡
		 */
		cpu = new_cpu;
		/* 拿到该sched_span_weight */
		weight = sd->span_weight;
		sd = NULL;
		/* 对于这个cpu的每个sched_domain */
		for_each_domain(cpu, tmp) {
			/* 如果weight <= tpm->span_weight,那么也就是说较低的sched_domain,MC->DIE */
			if (weight <= tmp->span_weight)
				break;
			if (tmp->flags & sd_flag)
				sd = tmp;
		}
		/* while loop will break here if sd == NULL */
	}
	rcu_read_unlock();

	return new_cpu;
}

/*
 * Called immediately before a task is migrated to a new cpu; task_cpu(p) and
 * cfs_rq_of(p) references at time of call are still valid and identify the
 * previous cpu. The caller guarantees p->pi_lock or task_rq(p)->lock is held.
 */
static void migrate_task_rq_fair(struct task_struct *p)
{
	/*
	 * As blocked tasks retain absolute vruntime the migration needs to
	 * deal with this by subtracting the old and adding the new
	 * min_vruntime -- the latter is done by enqueue_entity() when placing
	 * the task on the new runqueue.
	 */
	if (p->state == TASK_WAKING) {
		struct sched_entity *se = &p->se;
		struct cfs_rq *cfs_rq = cfs_rq_of(se);
		u64 min_vruntime;

#ifndef CONFIG_64BIT
		u64 min_vruntime_copy;

		do {
			min_vruntime_copy = cfs_rq->min_vruntime_copy;
			smp_rmb();
			min_vruntime = cfs_rq->min_vruntime;
		} while (min_vruntime != min_vruntime_copy);
#else
		min_vruntime = cfs_rq->min_vruntime;
#endif

		se->vruntime -= min_vruntime;
	}

	/*
	 * We are supposed to update the task to "current" time, then its up to date
	 * and ready to go to new CPU/cfs_rq. But we have difficulty in getting
	 * what current time is, so simply throw away the out-of-date time. This
	 * will result in the wakee task is less decayed, but giving the wakee more
	 * load sounds not bad.
	 */
	remove_entity_load_avg(&p->se);

	/* Tell new CPU we are migrated */
	p->se.avg.last_update_time = 0;

	/* We have migrated, no longer consider this task hot */
	p->se.exec_start = 0;
}

static void task_dead_fair(struct task_struct *p)
{
	remove_entity_load_avg(&p->se);
}
#endif /* CONFIG_SMP */

static unsigned long
wakeup_gran(struct sched_entity *curr, struct sched_entity *se)
{
	unsigned long gran = sysctl_sched_wakeup_granularity;

	/*
	 * Since its curr running now, convert the gran from real-time
	 * to virtual-time in his units.
	 *
	 * By using 'se' instead of 'curr' we penalize light tasks, so
	 * they get preempted easier. That is, if 'se' < 'curr' then
	 * the resulting gran will be larger, therefore penalizing the
	 * lighter, if otoh 'se' > 'curr' then the resulting gran will
	 * be smaller, again penalizing the lighter task.
	 *
	 * This is especially important for buddies when the leftmost
	 * task is higher priority than the buddy.
	 *
	 * 由于它现在正在运行,请将gran从实时时间转换为虚拟时间.
	 *
	 * 通过使用“se”而不是“curr”,我们会惩罚较轻的任务,因此它们更容易被抢占.
	 * 也就是说,如果“se”<“curr”,则产生的gran将更大,因此惩罚较轻的任务,
	 * 如果otoh“se”>“curr’,则产生了的gran会更小,再次惩罚较轻任务.
	 *
	 * 当最左边的任务优先级高于好友时，这对好友来说尤其重要。
	 */
	return calc_delta_fair(gran, se);
}

/*
 * Should 'se' preempt 'curr'.
 *
 *             |s1
 *        |s2
 *   |s3
 *         g
 *      |<--->|c
 *
 *  w(c, s1) = -1
 *  w(c, s2) =  0
 *  w(c, s3) =  1
 *
 */
static int
wakeup_preempt_entity(struct sched_entity *curr, struct sched_entity *se)
{
	/* vdiff是说curr的虚拟时间比se的虚拟时间的差值 */
	s64 gran, vdiff = curr->vruntime - se->vruntime;

	/* 如果差值<=0,说明curr->vruntime比较小,则se不能抢占curr,那么直接返回-1 */
	if (vdiff <= 0)
		return -1;

	/* 计算调度粒度
	 * 调度粒度是什么概念呢? 进程调度的时候每次都简单选择vruntime最小的进程调度,其实也不完全是这样.
	 * 假设进程A和B的vruntime很接近,那么A先运行了一个tick,vruntime比B大了,B又运行一个tick,vruntime又比A大了,切换到A,
	 * 这样就会在AB间频繁切换,对性能影响很大,因此如果当前进程的时间没有用完,就只有当有进程的vruntime比当前进程小超过调度粒度时,才能进行进程切换.
	 * 函数上面注释中那个图就是这个意思,我们看下:
	 * 横坐标表示vruntime,s1 s2 s3分别表示新进程,c表示当前进程,g表示调度粒度。
	 * s3肯定能抢占c;而s1不可能抢占c.
	 * s2虽然vruntime比c小,但是在调度粒度之内,能否抢占要看情况,像现在这种状况就不能抢占.
	 */
	gran = wakeup_gran(curr, se);
	if (vdiff > gran)
		return 1;

	return 0;
}

static void set_last_buddy(struct sched_entity *se)
{
	if (entity_is_task(se) && unlikely(task_of(se)->policy == SCHED_IDLE))
		return;

	for_each_sched_entity(se)
		cfs_rq_of(se)->last = se;
}

static void set_next_buddy(struct sched_entity *se)
{
	if (entity_is_task(se) && unlikely(task_of(se)->policy == SCHED_IDLE))
		return;

	for_each_sched_entity(se)
		cfs_rq_of(se)->next = se;
}

static void set_skip_buddy(struct sched_entity *se)
{
	for_each_sched_entity(se)
		cfs_rq_of(se)->skip = se;
}

/*
 * Preempt the current task with a newly woken task if needed:
 */
static void check_preempt_wakeup(struct rq *rq, struct task_struct *p, int wake_flags)
{
	struct task_struct *curr = rq->curr;
	struct sched_entity *se = &curr->se, *pse = &p->se;
	struct cfs_rq *cfs_rq = task_cfs_rq(curr);
	int scale = cfs_rq->nr_running >= sched_nr_latency;
	int next_buddy_marked = 0;

	if (unlikely(se == pse))
		return;

	/*
	 * This is possible from callers such as attach_tasks(), in which we
	 * unconditionally check_prempt_curr() after an enqueue (which may have
	 * lead to a throttle).  This both saves work and prevents false
	 * next-buddy nomination below.
	 */
	if (unlikely(throttled_hierarchy(cfs_rq_of(pse))))
		return;

	if (sched_feat(NEXT_BUDDY) && scale && !(wake_flags & WF_FORK)) {
		set_next_buddy(pse);
		next_buddy_marked = 1;
	}

	/*
	 * We can come here with TIF_NEED_RESCHED already set from new task
	 * wake up path.
	 *
	 * Note: this also catches the edge-case of curr being in a throttled
	 * group (e.g. via set_curr_task), since update_curr() (in the
	 * enqueue of curr) will have resulted in resched being set.  This
	 * prevents us from potentially nominating it as a false LAST_BUDDY
	 * below.
	 */
	if (test_tsk_need_resched(curr))
		return;

	/* Idle tasks are by definition preempted by non-idle tasks. */
	if (unlikely(curr->policy == SCHED_IDLE) &&
	    likely(p->policy != SCHED_IDLE))
		goto preempt;

	/*
	 * Batch and idle tasks do not preempt non-idle tasks (their preemption
	 * is driven by the tick):
	 */
	if (unlikely(p->policy != SCHED_NORMAL) || !sched_feat(WAKEUP_PREEMPTION))
		return;

	find_matching_se(&se, &pse);
	update_curr(cfs_rq_of(se));
	BUG_ON(!pse);
	if (wakeup_preempt_entity(se, pse) == 1) {
		/*
		 * Bias pick_next to pick the sched entity that is
		 * triggering this preemption.
		 */
		if (!next_buddy_marked)
			set_next_buddy(pse);
		goto preempt;
	}

	return;

preempt:
	resched_curr(rq);
	/*
	 * Only set the backward buddy when the current task is still
	 * on the rq. This can happen when a wakeup gets interleaved
	 * with schedule on the ->pre_schedule() or idle_balance()
	 * point, either of which can * drop the rq lock.
	 *
	 * Also, during early boot the idle thread is in the fair class,
	 * for obvious reasons its a bad idea to schedule back to it.
	 */
	if (unlikely(!se->on_rq || curr == rq->idle))
		return;

	if (sched_feat(LAST_BUDDY) && scale && entity_is_task(se))
		set_last_buddy(se);
}

static struct task_struct *
pick_next_task_fair(struct rq *rq, struct task_struct *prev, struct pin_cookie cookie)
{
	/* 拿到rq的cfs_rq */
	struct cfs_rq *cfs_rq = &rq->cfs;
	struct sched_entity *se;
	struct task_struct *p;
	int new_tasks;

again:
#ifdef CONFIG_FAIR_GROUP_SCHED
	/* 如果cfs_rq里面没有可运行的进程,那么直接goto idle */
	if (!cfs_rq->nr_running)
		goto idle;

	/* 如果prev->sched_class不等于fair_sched_class,那么直接goto simple */
	if (prev->sched_class != &fair_sched_class)
		goto simple;

	/*
	 * Because of the set_next_buddy() in dequeue_task_fair() it is rather
	 * likely that a next task is from the same cgroup as the current.
	 *
	 * Therefore attempt to avoid putting and setting the entire cgroup
	 * hierarchy, only change the part that actually changes.
	 *
	 * 由于dequeue_task_fair()中的set_next_buddy(),下一个任务很可能与当前任务来自同一个cgroup.
	 *
	 * 因此,尽量避免放置和设置整个cgroup层次结构,只更改实际更改的部分.
	 */

	do {
		/* 拿到当前队列正在运行的sched_entity */
		struct sched_entity *curr = cfs_rq->curr;

		/*
		 * Since we got here without doing put_prev_entity() we also
		 * have to consider cfs_rq->curr. If it is still a runnable
		 * entity, update_curr() will update its vruntime, otherwise
		 * forget we've ever seen it.
		 *
		 * 由于我们没有执行put_prev_entity(),因此我们还必须考虑cfg_rq->curr.
		 * 如果它仍然是一个可运行的实体,update_curr()将更新它的vruntime,否则就忘了我们见过它.
		 */
		/* 如果有curr */
		if (curr) {
			/* 如果它还在调度队列里面,更新它的vruntime */
			if (curr->on_rq)
				update_curr(cfs_rq);
			else	/* 否则设置curr为NULL */
				curr = NULL;

			/*
			 * This call to check_cfs_rq_runtime() will do the
			 * throttle and dequeue its entity in the parent(s).
			 * Therefore the 'simple' nr_running test will indeed
			 * be correct.
			 *
			 * 这个对check_cfs_rq_runtime()的调用将执行节流操作,并使其实体在父级中出列.
			 * 因此,"simple"的nr_running测试确实是正确的.
			 */
			if (unlikely(check_cfs_rq_runtime(cfs_rq)))
				goto simple;
		}

		/* pick_next_entity选择CFS就绪队列中的红黑树中最左边的进程 */
		se = pick_next_entity(cfs_rq, curr);
		cfs_rq = group_cfs_rq(se);
	} while (cfs_rq);

	/* 拿到这个se对应的task_struct */
	p = task_of(se);

	/*
	 * Since we haven't yet done put_prev_entity and if the selected task
	 * is a different task than we started out with, try and touch the
	 * least amount of cfs_rqs.
	 *
	 * 由于我们还没有完成put_prev_entity,如果所选任务与我们开始时的任务不同,请尝试使用最少的cfs_rq.
	 */

	/* 如果prev和p不同 */
	if (prev != p) {
		/* 拿到prev的sched_entity */
		struct sched_entity *pse = &prev->se;

		while (!(cfs_rq = is_same_group(se, pse))) {
			int se_depth = se->depth;
			int pse_depth = pse->depth;

			if (se_depth <= pse_depth) {
				put_prev_entity(cfs_rq_of(pse), pse);
				pse = parent_entity(pse);
			}
			if (se_depth >= pse_depth) {
				set_next_entity(cfs_rq_of(se), se);
				se = parent_entity(se);
			}
		}
		/* 切换前对prev进程做处理 */
		put_prev_entity(cfs_rq, pse);
		/* 对即将运行的next进程做处理 */
		set_next_entity(cfs_rq, se);
	}

	/* 在enqueue和dequeue操作返回前,如果cfs的就绪队列上面进程数量足够少,那么我们就调用hrtick_start_fair检查是否需要发起延迟调度抢占rq->curr.
	 * 之所以在dequeue/enqueue的最后要设计hrtick_timer去推进调度器.
	 * 在dequeue/enqueue的最后,rq->curr很可能已经运行了一段时间,如果我们要等到System Tick到才去切换进程,那很有可能rq->curr已经运行超过0.75ms了,
	 * 所以我们需要另外一个hrtimer来推进进程切换,而dequeue/enqueue正好是比较方便去检查rq->curr运行时间进而start hrtick_timer的时间点.
	 * 这应该是也是提升实时性的一个操作.
	 */
	if (hrtick_enabled(rq))
		hrtick_start_fair(rq, p);

	return p;
simple:

	/* 拿到该rq的cfs队列 */
	cfs_rq = &rq->cfs;
#endif

	/* 如果cfs_rq中没有可运行的进程,那么goto idle */
	if (!cfs_rq->nr_running)
		goto idle;

	/* 切换前对prev进程做处理 */
	put_prev_task(rq, prev);

	do {
		/* 选择下一个进程 */
		se = pick_next_entity(cfs_rq, NULL);
		/* 对即将运行的next进程做处理 */
		set_next_entity(cfs_rq, se);
		cfs_rq = group_cfs_rq(se);
	} while (cfs_rq);

	p = task_of(se);

	if (hrtick_enabled(rq))
		hrtick_start_fair(rq, p);

	return p;

idle:
	/*
	 * This is OK, because current is on_cpu, which avoids it being picked
	 * for load-balance and preemption/IRQs are still disabled avoiding
	 * further scheduler activity on it and we're being very careful to
	 * re-start the picking loop.
	 *
	 * 这是可以的,因为current是on_cpu,这避免了它被挑选用于负载平衡,抢占/IRQ仍然被禁用,避免了它上的进一步调度程序活动,
	 * 我们非常小心地重新启动挑选循环。
	 */
	lockdep_unpin_lock(&rq->lock, cookie);
	new_tasks = idle_balance(rq);
	lockdep_repin_lock(&rq->lock, cookie);
	/*
	 * Because idle_balance() releases (and re-acquires) rq->lock, it is
	 * possible for any higher priority task to appear. In that case we
	 * must re-start the pick_next_entity() loop.
	 */
	if (new_tasks < 0)
		return RETRY_TASK;

	if (new_tasks > 0)
		goto again;

	return NULL;
}

/*
 * Account for a descheduled task:
 */
static void put_prev_task_fair(struct rq *rq, struct task_struct *prev)
{
	struct sched_entity *se = &prev->se;
	struct cfs_rq *cfs_rq;

	for_each_sched_entity(se) {
		cfs_rq = cfs_rq_of(se);
		put_prev_entity(cfs_rq, se);
	}
}

/*
 * sched_yield() is very simple
 *
 * The magic of dealing with the ->skip buddy is in pick_next_entity.
 */
static void yield_task_fair(struct rq *rq)
{
	struct task_struct *curr = rq->curr;
	struct cfs_rq *cfs_rq = task_cfs_rq(curr);
	struct sched_entity *se = &curr->se;

	/*
	 * Are we the only task in the tree?
	 */
	if (unlikely(rq->nr_running == 1))
		return;

	clear_buddies(cfs_rq, se);

	if (curr->policy != SCHED_BATCH) {
		update_rq_clock(rq);
		/*
		 * Update run-time statistics of the 'current'.
		 */
		update_curr(cfs_rq);
		/*
		 * Tell update_rq_clock() that we've just updated,
		 * so we don't do microscopic update in schedule()
		 * and double the fastpath cost.
		 */
		rq_clock_skip_update(rq, true);
	}

	set_skip_buddy(se);
}

static bool yield_to_task_fair(struct rq *rq, struct task_struct *p, bool preempt)
{
	struct sched_entity *se = &p->se;

	/* throttled hierarchies are not runnable */
	if (!se->on_rq || throttled_hierarchy(cfs_rq_of(se)))
		return false;

	/* Tell the scheduler that we'd really like pse to run next. */
	set_next_buddy(se);

	yield_task_fair(rq);

	return true;
}

#ifdef CONFIG_SMP
/**************************************************
 * Fair scheduling class load-balancing methods.
 *
 * BASICS
 *
 * The purpose of load-balancing is to achieve the same basic fairness the
 * per-cpu scheduler provides, namely provide a proportional amount of compute
 * time to each task. This is expressed in the following equation:
 *
 *   W_i,n/P_i == W_j,n/P_j for all i,j                               (1)
 *
 * Where W_i,n is the n-th weight average for cpu i. The instantaneous weight
 * W_i,0 is defined as:
 *
 *   W_i,0 = \Sum_j w_i,j                                             (2)
 *
 * Where w_i,j is the weight of the j-th runnable task on cpu i. This weight
 * is derived from the nice value as per sched_prio_to_weight[].
 *
 * The weight average is an exponential decay average of the instantaneous
 * weight:
 *
 *   W'_i,n = (2^n - 1) / 2^n * W_i,n + 1 / 2^n * W_i,0               (3)
 *
 * C_i is the compute capacity of cpu i, typically it is the
 * fraction of 'recent' time available for SCHED_OTHER task execution. But it
 * can also include other factors [XXX].
 *
 * To achieve this balance we define a measure of imbalance which follows
 * directly from (1):
 *
 *   imb_i,j = max{ avg(W/C), W_i/C_i } - min{ avg(W/C), W_j/C_j }    (4)
 *
 * We them move tasks around to minimize the imbalance. In the continuous
 * function space it is obvious this converges, in the discrete case we get
 * a few fun cases generally called infeasible weight scenarios.
 *
 * [XXX expand on:
 *     - infeasible weights;
 *     - local vs global optima in the discrete case. ]
 *
 *
 * SCHED DOMAINS
 *
 * In order to solve the imbalance equation (4), and avoid the obvious O(n^2)
 * for all i,j solution, we create a tree of cpus that follows the hardware
 * topology where each level pairs two lower groups (or better). This results
 * in O(log n) layers. Furthermore we reduce the number of cpus going up the
 * tree to only the first of the previous level and we decrease the frequency
 * of load-balance at each level inv. proportional to the number of cpus in
 * the groups.
 *
 * This yields:
 *
 *     log_2 n     1     n
 *   \Sum       { --- * --- * 2^i } = O(n)                            (5)
 *     i = 0      2^i   2^i
 *                               `- size of each group
 *         |         |     `- number of cpus doing load-balance
 *         |         `- freq
 *         `- sum over all levels
 *
 * Coupled with a limit on how many tasks we can migrate every balance pass,
 * this makes (5) the runtime complexity of the balancer.
 *
 * An important property here is that each CPU is still (indirectly) connected
 * to every other cpu in at most O(log n) steps:
 *
 * The adjacency matrix of the resulting graph is given by:
 *
 *             log_2 n
 *   A_i,j = \Union     (i % 2^k == 0) && i / 2^(k+1) == j / 2^(k+1)  (6)
 *             k = 0
 *
 * And you'll find that:
 *
 *   A^(log_2 n)_i,j != 0  for all i,j                                (7)
 *
 * Showing there's indeed a path between every cpu in at most O(log n) steps.
 * The task movement gives a factor of O(m), giving a convergence complexity
 * of:
 *
 *   O(nm log n),  n := nr_cpus, m := nr_tasks                        (8)
 *
 *
 * WORK CONSERVING
 *
 * In order to avoid CPUs going idle while there's still work to do, new idle
 * balancing is more aggressive and has the newly idle cpu iterate up the domain
 * tree itself instead of relying on other CPUs to bring it work.
 *
 * This adds some complexity to both (5) and (8) but it reduces the total idle
 * time.
 *
 * [XXX more?]
 *
 *
 * CGROUPS
 *
 * Cgroups make a horror show out of (2), instead of a simple sum we get:
 *
 *                                s_k,i
 *   W_i,0 = \Sum_j \Prod_k w_k * -----                               (9)
 *                                 S_k
 *
 * Where
 *
 *   s_k,i = \Sum_j w_i,j,k  and  S_k = \Sum_i s_k,i                 (10)
 *
 * w_i,j,k is the weight of the j-th runnable task in the k-th cgroup on cpu i.
 *
 * The big problem is S_k, its a global sum needed to compute a local (W_i)
 * property.
 *
 * [XXX write more on how we solve this.. _after_ merging pjt's patches that
 *      rewrite all of this once again.]
 */

static unsigned long __read_mostly max_load_balance_interval = HZ/10;

enum fbq_type { regular, remote, all };

#define LBF_ALL_PINNED	0x01
#define LBF_NEED_BREAK	0x02
#define LBF_DST_PINNED  0x04
#define LBF_SOME_PINNED	0x08

struct lb_env {
	/* 要进行负载均衡的domain */
	struct sched_domain	*sd;

	/* 此sd中最忙的cpu和rq,均衡目标就是从其中拉取任务 */
	struct rq		*src_rq;
	int			src_cpu;

	/*
	 * 本次均衡的目标CPU,均衡尝试从sd中的最忙的cpu的rq上拉取任务到dst cpu的rq上,
	 * 第一轮均衡的dst cpu通常为发起均衡的cpu,但后续若有需要,可以从新设定为local
	 * group中其它的cpu.
	 */
	int			dst_cpu;
	struct rq		*dst_rq;

	/* dst cpu所在sched group的cpu mask,MC层级就是dst cpu自己,DIE层级是其cluster. */
	struct cpumask		*dst_grpmask;
	/*
	 * 一般而言,均衡的dst cpu是发起均衡的cpu,但如果由于affinity原因,src上有任务
	 * 无法迁移到dst cpu从而无法完成负载均衡操作时,会从dst cpu的logcal group中选出
	 * 一个新的cpu发起第二轮负载均衡.
	 */
	int			new_dst_cpu;
	/* 均衡时dst cpu的idle状态,其会影响负载均衡的走向 */
	enum cpu_idle_type	idle;
	/*
	 * 对此成员的解释需要结合migration_type成员,calculate_imbalance:
	 * migrate_load: 表示要迁移的负载量
	 * migrate_util：表示要迁移的utility
	 * migrate_task: MC:表示要迁移的任务个数,DIE: busiest group需要增加的idle cpu个数
	 * migrate_misfit: 设定为1,表示一次迁移一个任务
	 * group_imbalanced：设定为1,表示一次迁移一个任务
	 */
	long			imbalance;
	/* The set of CPUs under consideration for load-balancing */
	/*
	 * 负载均衡过程会有多轮操作,不同轮次的操作会涉及不同cpus,此成员表示此次均衡
	 * 有哪些cpus参与
	 */
	struct cpumask		*cpus;

	/*
	 * 负载均衡标志,位掩码.LBF_NOHZ_STATS和LBF_NOHZ_AGAIN主要用于均衡过程中更
	 * 新nohz状态. 当选中的最忙的cpu上所有任务都由于affinity无法迁移时会设置
	 * LBF_ALL_PINNED,此时会寻找次忙的cpu进行下一轮均衡.
	 * LBF_NEED_BREAK 主要用于减短均衡过程中关中断的时间的.
	 */
	unsigned int		flags;
	/*
	 * 当确定要迁移任务时,load_balance()会循环遍历src rq上的cfs task链表来确定迁移
	 * 的任务数量.loop用于跟踪循环次数,其值不能超过loop_max成员.
	 */
	unsigned int		loop;
	/*
	 * 如果一次迁移的任务比较多,那么每迁移sched_nr_migrate_break个任务(默认32)就要休息一
	 * 下,让关中断的临界区小一点.
	 */
	unsigned int		loop_break;
	unsigned int		loop_max;

	enum fbq_type		fbq_type;
	/* 需要迁移的任务会挂到这个链表中 */
	struct list_head	tasks;
};

/*
 * Is this task likely cache-hot:
 */
static int task_hot(struct task_struct *p, struct lb_env *env)
{
	s64 delta;

	lockdep_assert_held(&env->src_rq->lock);

	if (p->sched_class != &fair_sched_class)
		return 0;

	if (unlikely(p->policy == SCHED_IDLE))
		return 0;

	/*
	 * Buddy candidates are cache hot:
	 */
	if (sched_feat(CACHE_HOT_BUDDY) && env->dst_rq->nr_running &&
			(&p->se == cfs_rq_of(&p->se)->next ||
			 &p->se == cfs_rq_of(&p->se)->last))
		return 1;

	if (sysctl_sched_migration_cost == -1)
		return 1;
	if (sysctl_sched_migration_cost == 0)
		return 0;

	delta = rq_clock_task(env->src_rq) - p->se.exec_start;

	return delta < (s64)sysctl_sched_migration_cost;
}

#ifdef CONFIG_NUMA_BALANCING
/*
 * Returns 1, if task migration degrades locality
 * Returns 0, if task migration improves locality i.e migration preferred.
 * Returns -1, if task migration is not affected by locality.
 */
static int migrate_degrades_locality(struct task_struct *p, struct lb_env *env)
{
	struct numa_group *numa_group = rcu_dereference(p->numa_group);
	unsigned long src_faults, dst_faults;
	int src_nid, dst_nid;

	if (!static_branch_likely(&sched_numa_balancing))
		return -1;

	if (!p->numa_faults || !(env->sd->flags & SD_NUMA))
		return -1;

	src_nid = cpu_to_node(env->src_cpu);
	dst_nid = cpu_to_node(env->dst_cpu);

	if (src_nid == dst_nid)
		return -1;

	/* Migrating away from the preferred node is always bad. */
	if (src_nid == p->numa_preferred_nid) {
		if (env->src_rq->nr_running > env->src_rq->nr_preferred_running)
			return 1;
		else
			return -1;
	}

	/* Encourage migration to the preferred node. */
	if (dst_nid == p->numa_preferred_nid)
		return 0;

	if (numa_group) {
		src_faults = group_faults(p, src_nid);
		dst_faults = group_faults(p, dst_nid);
	} else {
		src_faults = task_faults(p, src_nid);
		dst_faults = task_faults(p, dst_nid);
	}

	return dst_faults < src_faults;
}

#else
static inline int migrate_degrades_locality(struct task_struct *p,
					     struct lb_env *env)
{
	return -1;
}
#endif

/*
 * can_migrate_task - may task p from runqueue rq be migrated to this_cpu?
 */
static
int can_migrate_task(struct task_struct *p, struct lb_env *env)
{
	int tsk_cache_hot;

	lockdep_assert_held(&env->src_rq->lock);

	/*
	 * We do not migrate tasks that are:
	 * 1) throttled_lb_pair, or
	 * 2) cannot be migrated to this CPU due to cpus_allowed, or
	 * 3) running (obviously), or
	 * 4) are cache-hot on their current CPU.
	 */

	/*
	 * 如果任务p所在的task group在src cpu 或 在dest cpu上被限流了,那么不
	 * 能迁移该任务,否者限流的逻辑会有问题.
	 */
	if (throttled_lb_pair(task_group(p), env->src_cpu, env->dst_cpu))
		return 0;

	/* 若dst cpu不在任务p的cpu亲和性里面 */
	if (!cpumask_test_cpu(env->dst_cpu, tsk_cpus_allowed(p))) {
		int cpu;

		/* 统计由于cpu亲和性不能迁移到dst cpu */
		schedstat_inc(p->se.statistics.nr_failed_migrations_affine);

		/*
		 * 任务由于affinity的原因不能在dest cpu上运行,因此这里设置上
		 * LBF_SOME_PINNED 标志,表示至少有一个任务由于affinity无法迁移
		 */
		env->flags |= LBF_SOME_PINNED;

		/*
		 * Remember if this task can be migrated to any other cpu in
		 * our sched_group. We may want to revisit it if we couldn't
		 * meet load balance goals by pulling other tasks on src_cpu.
		 *
		 * Also avoid computing new_dst_cpu if we have already computed
		 * one in current iteration.
		 *
		 * 记住这个任务是否可以迁移到我们调度组(sched_group)中的任何其他CPU上.
		 * 如果我们通过从源CPU(src_cpu)上拉取其他任务而无法达到负载均衡目标,我们可能希望重新考虑这个任务.
		 *
		 * 另外,如果我们在当前迭代中已经计算了一个new_dst_cpu,那么也要避免重新计算它
		 */

		if (!env->dst_grpmask || (env->flags & LBF_DST_PINNED))
			return 0;

		/* Prevent to re-select dst_cpu via env's cpus */
		/*
		 * 设定备选CPU,以便后续第二轮的均衡可以把任务迁移到备选CPU上
		 * MC层级只有dst cpu一个,DIE层级是dst cpu所在cluster的所有cpu
		 */
		for_each_cpu_and(cpu, env->dst_grpmask, env->cpus) {
			if (cpumask_test_cpu(cpu, tsk_cpus_allowed(p))) {
				env->flags |= LBF_DST_PINNED;
				env->new_dst_cpu = cpu;
				break;
			}
		}

		return 0;
	}

	/* 下面就是dst cpu 在 p->cpus_ptr 中了 */
	/* Record that we found atleast one task that could run on dst_cpu */

	/* 至少有一个任务是可以运行在dest cpu上(从affinity角度),因此清除all pinned标记 */
	env->flags &= ~LBF_ALL_PINNED;

	 /* 正处于运行状态的任务不参与迁移,迁移running task是后续active migration 的逻辑. */
	if (task_running(env->src_rq, p)) {
		schedstat_inc(p->se.statistics.nr_failed_migrations_running);
		return 0;
	}

	/*
	 * Aggressive migration if:
	 * 1) destination numa is preferred
	 * 2) task is cache cold, or
	 * 3) too many balance attempts have failed.
	 */

	/*
	 * 判断该任务是否是cache-hot的,这主要从近期在src cpu上的执行时间点来判断,如果上
	 * 次任务在src cpu上开始执行的时间比较久远(sysctl_sched_migration_cost 是门限,默认0.5ms),
	 * 那么其在cache中的内容大概率是被刷掉了,可以认为是cache-cold的. 此外如果任务p是
	 * src cpu上的next buddy或者last buddy,那么任务是cache hot的.
	 */
	tsk_cache_hot = migrate_degrades_locality(p, env);
	if (tsk_cache_hot == -1)
		tsk_cache_hot = task_hot(p, env);

	/*
	 * 一般而言,我们只迁移cache cold的任务.但是如果进行了太多轮的尝试仍然未能让负
	 * 载达到均衡,那么cache hot的任务也一样迁移.
	 * sd_init()中MC和DIE的cache_nice_tries都初始化为1。
	 * nr_balance_failed：load_balance中判断非new idle balance且一个任务都没迁移就加1
	 */
	if (tsk_cache_hot <= 0 ||
	    env->sd->nr_balance_failed > env->sd->cache_nice_tries) {
		/* 由于上两次尝试一个任务都没迁移成功,这次cache_hot的也迁移 */
		if (tsk_cache_hot == 1) {
			schedstat_inc(env->sd->lb_hot_gained[env->idle]);
			schedstat_inc(p->se.statistics.nr_forced_migrations);
		}
		return 1;
	}

	schedstat_inc(p->se.statistics.nr_failed_migrations_hot);
	return 0;
}

/*
 * detach_task() -- detach the task for the migration specified in env
 *
 * detach_task函数让进程退出运行队列,然后设置进程的运行CPU为迁移目的的CPU,并设置p->on_rq为TASK_ON_RQ_MIGRATING
 *
 */
static void detach_task(struct task_struct *p, struct lb_env *env)
{
	lockdep_assert_held(&env->src_rq->lock);

	p->on_rq = TASK_ON_RQ_MIGRATING;
	deactivate_task(env->src_rq, p, 0);
	set_task_cpu(p, env->dst_cpu);
}

/*
 * detach_one_task() -- tries to dequeue exactly one task from env->src_rq, as
 * part of active balancing operations within "domain".
 *
 * Returns a task if successful and NULL otherwise.
 */
static struct task_struct *detach_one_task(struct lb_env *env)
{
	struct task_struct *p, *n;

	lockdep_assert_held(&env->src_rq->lock);

	list_for_each_entry_safe(p, n, &env->src_rq->cfs_tasks, se.group_node) {
		if (!can_migrate_task(p, env))
			continue;

		detach_task(p, env);

		/*
		 * Right now, this is only the second place where
		 * lb_gained[env->idle] is updated (other is detach_tasks)
		 * so we can safely collect stats here rather than
		 * inside detach_tasks().
		 */
		schedstat_inc(env->sd->lb_gained[env->idle]);
		return p;
	}
	return NULL;
}

static const unsigned int sched_nr_migrate_break = 32;

/*
 * detach_tasks() -- tries to detach up to imbalance weighted load from
 * busiest_rq, as part of a balancing operation within domain "sd".
 *
 * Returns number of detached tasks if successful and 0 otherwise.
 *
 * detach_tasks() -- 作为域"sd"内平衡操作的一部分,尝试从busiest_rq中分离不平衡加权负载.
 * 如果成功,则返回分离的任务数,否则返回0.
 */
static int detach_tasks(struct lb_env *env)
{
	/* 拿到busiest_rq中cfs_tasks链表 */
	struct list_head *tasks = &env->src_rq->cfs_tasks;
	struct task_struct *p;
	unsigned long load;
	int detached = 0;

	lockdep_assert_held(&env->src_rq->lock);

	/* 已经均衡完毕了 */
	if (env->imbalance <= 0)
		return 0;

	/*
	 * src rq的cfs_tasks链表就是该rq上的全部cfs任务,detach_tasks函数的主要逻辑就是遍历这
	 * 个cfs_tasks链表,找到最适合迁移到目标cpu rq的任务,并挂入 lb_env->tasks 链表.
	 *
	 * 为了达到均衡,一个任务可能会被多次扫描,也就是说tasks链表可能会被扫描多次！
	 */
	while (!list_empty(tasks)) {
		/*
		 * We don't want to steal all, otherwise we may be treated likewise,
		 * which could at worst lead to a livelock crash.
		 */

		/*
		 * 在idle balance的时候,没有必要把src上的唯一的task拉取到本cpu上,否则的话任务
		 * 可能会在两个CPU上来回拉扯.
		 */
		if (env->idle != CPU_NOT_IDLE && env->src_rq->nr_running <= 1)
			break;

		/*
		 * 这个后面已经改成list_last_entry了
		 * 从src_rq->cfs_tasks链表队尾获取一个任务(只是获取,并没有摘除).这个链表的头部
		 * 是最近访问的任务,从尾部摘任务可以保证任务是cache cold的.
		 * 上次不合适的已经move到这个链表头了.
		 */
		p = list_first_entry(tasks, struct task_struct, se.group_node);

		/*
		 * 当把src rq上的任务都遍历过之后,或者当达到循环上限,env->loop_max=min(sysctl_sched_nr_migrate,
		 * busiest->nr_running)的时候退出循环,之后若判断需要继续搬移任务再重新进入这个函数,目的是使对src
		 * cpu 关中断的临界区小一点
		 */
		env->loop++;
		/* We've more or less seen every task there is, call it quits */
		if (env->loop > env->loop_max)
			break;

		/* take a breather every nr_migrate tasks */
		/*
		 * 当src rq上的任务数比较多的时候,并且需要迁移大量的任务才能完成均衡,为了减少关中断的区间,
		 * 迁移需要分段进行(每 sched_nr_migrate_break 暂停一下),把大的临界区分成几个小的临界区,确保
		 * 系统的延迟性能
		 */
		if (env->loop > env->loop_break) {
			env->loop_break += sched_nr_migrate_break;
			/* 外层函数load_balnace判断这个标志位后会重跳转到从src rq摘取任务的逻辑处 */
			env->flags |= LBF_NEED_BREAK;
			break;
		}

		/* 如果该任务不适合迁移,那么将其移到 cfs_tasks 链表头部 */
		if (!can_migrate_task(p, env))
			goto next;

		/* 计算该任务的负载 */
		load = task_h_load(p);

		/*
		 * LB_MIN特性限制迁移小任务,默认为false,如果LB_MIN等于true,那么task load小于
		 * 16的任务将不参与负载均衡.
		 */
		if (sched_feat(LB_MIN) && load < 16 && !env->sd->nr_balance_failed)
			goto next;

		/* 不要迁移过多的load,确保迁移的load/2 不大于env->imbalance */
		if ((load / 2) > env->imbalance)
			goto next;

		/*
		 * 程序执行至此,说明任务p需要被迁移(不能迁移的都跳转到next标号了),此时才从tasks(env->src_rq->cfs_tasks)
		 * 链表上摘取下来挂入 env->tasks 链表.
		 */
		detach_task(p, env);
		list_add(&p->se.group_node, &env->tasks);

		detached++;
		env->imbalance -= load;

#ifdef CONFIG_PREEMPT
		/*
		 * NEWIDLE balancing is a source of latency, so preemptible
		 * kernels will stop after the first task is detached to minimize
		 * the critical section.
		 *
		 * NEWIDLE balancing是延迟的一个来源,因此可抢占的内核将在分离第一个任务后停止,以最小化关键部分.
		 *
		 * NEWIDLE balance是调度延迟的一个来源,所有对于NEWIDLE balance,
		 * 一次只迁移一个任务
		 */
		if (env->idle == CPU_NEWLY_IDLE)
			break;
#endif

		/*
		 * We only want to steal up to the prescribed amount of
		 * weighted load.
		 */
		/* 如果完成迁移,那么就退出遍历src rq的cfs task链表 */
		if (env->imbalance <= 0)
			break;

		continue;
next:
		/* 对于不适合迁移的任务将其移动到链表头部,因为是从尾部进行扫描判断的 */
		list_move_tail(&p->se.group_node, tasks);
	}

	/*
	 * Right now, this is one of only two places we collect this stat
	 * so we can safely collect detach_one_task() stats here rather
	 * than inside detach_one_task().
	 */
	schedstat_add(env->sd->lb_gained[env->idle], detached);

	return detached;
}

/*
 * attach_task() -- attach the task detached by detach_task() to its new rq.
 */
static void attach_task(struct rq *rq, struct task_struct *p)
{
	lockdep_assert_held(&rq->lock);

	BUG_ON(task_rq(p) != rq);
	activate_task(rq, p, 0);
	p->on_rq = TASK_ON_RQ_QUEUED;
	check_preempt_curr(rq, p, 0);
}

/*
 * attach_one_task() -- attaches the task returned from detach_one_task() to
 * its new rq.
 */
static void attach_one_task(struct rq *rq, struct task_struct *p)
{
	raw_spin_lock(&rq->lock);
	attach_task(rq, p);
	raw_spin_unlock(&rq->lock);
}

/*
 * attach_tasks() -- attaches all tasks detached by detach_tasks() to their
 * new rq.
 */
static void attach_tasks(struct lb_env *env)
{
	struct list_head *tasks = &env->tasks;
	struct task_struct *p;

	raw_spin_lock(&env->dst_rq->lock);

	while (!list_empty(tasks)) {
		p = list_first_entry(tasks, struct task_struct, se.group_node);
		list_del_init(&p->se.group_node);

		attach_task(env->dst_rq, p);
	}

	raw_spin_unlock(&env->dst_rq->lock);
}

#ifdef CONFIG_FAIR_GROUP_SCHED
static void update_blocked_averages(int cpu)
{
	/* 拿到该cpu的rq */
	struct rq *rq = cpu_rq(cpu);
	struct cfs_rq *cfs_rq;
	unsigned long flags;

	raw_spin_lock_irqsave(&rq->lock, flags);
	/* 更新rq的clock */
	update_rq_clock(rq);

	/*
	 * Iterates the task_group tree in a bottom up fashion, see
	 * list_add_leaf_cfs_rq() for details.
	 *
	 * 以自下而上的方式迭代task_group树,有关详细信息,请参阅list_add_leaf_cfs_rq().
	 */
	for_each_leaf_cfs_rq(rq, cfs_rq) {
		/* throttled entities do not contribute to load */
		if (throttled_hierarchy(cfs_rq))
			continue;

		if (update_cfs_rq_load_avg(cfs_rq_clock_task(cfs_rq), cfs_rq, true))
			update_tg_load_avg(cfs_rq, 0);
	}
	raw_spin_unlock_irqrestore(&rq->lock, flags);
}

/*
 * Compute the hierarchical load factor for cfs_rq and all its ascendants.
 * This needs to be done in a top-down fashion because the load of a child
 * group is a fraction of its parents load.
 */
static void update_cfs_rq_h_load(struct cfs_rq *cfs_rq)
{
	struct rq *rq = rq_of(cfs_rq);
	struct sched_entity *se = cfs_rq->tg->se[cpu_of(rq)];
	unsigned long now = jiffies;
	unsigned long load;

	if (cfs_rq->last_h_load_update == now)
		return;

	cfs_rq->h_load_next = NULL;
	for_each_sched_entity(se) {
		cfs_rq = cfs_rq_of(se);
		cfs_rq->h_load_next = se;
		if (cfs_rq->last_h_load_update == now)
			break;
	}

	if (!se) {
		cfs_rq->h_load = cfs_rq_load_avg(cfs_rq);
		cfs_rq->last_h_load_update = now;
	}

	while ((se = cfs_rq->h_load_next) != NULL) {
		load = cfs_rq->h_load;
		load = div64_ul(load * se->avg.load_avg,
			cfs_rq_load_avg(cfs_rq) + 1);
		cfs_rq = group_cfs_rq(se);
		cfs_rq->h_load = load;
		cfs_rq->last_h_load_update = now;
	}
}

static unsigned long task_h_load(struct task_struct *p)
{
	struct cfs_rq *cfs_rq = task_cfs_rq(p);

	update_cfs_rq_h_load(cfs_rq);
	return div64_ul(p->se.avg.load_avg * cfs_rq->h_load,
			cfs_rq_load_avg(cfs_rq) + 1);
}
#else
static inline void update_blocked_averages(int cpu)
{
	struct rq *rq = cpu_rq(cpu);
	struct cfs_rq *cfs_rq = &rq->cfs;
	unsigned long flags;

	raw_spin_lock_irqsave(&rq->lock, flags);
	update_rq_clock(rq);
	update_cfs_rq_load_avg(cfs_rq_clock_task(cfs_rq), cfs_rq, true);
	raw_spin_unlock_irqrestore(&rq->lock, flags);
}

static unsigned long task_h_load(struct task_struct *p)
{
	return p->se.avg.load_avg;
}
#endif

/********** Helpers for find_busiest_group ************************/

enum group_type {
	group_other = 0,
	/* group_imbalanced表示该组有负载不均衡的情况 */
	group_imbalanced,
	/* group_overloaded表示组里正在运行的进程数量大于group_capacity_factor. 当运行中的进程大于group_capacity_factor时,返回group_overloaded.
	 * sched_group_capacity中的成员imbalance为1时,返回group_imbalanced.如果group_capacity_factor大于当前运行中的进程数目,说明该组还可以利用,调度盈余group_has_free_capacity为1
	 * 假设一个调度组中有两个CPU,每个CPU的能力系数都是SHCED_CAPACITY_SCALE(1024),那么该调度组的group_capacity_factor等于2
	 */
	group_overloaded,
};

/*
 * sg_lb_stats - stats of a sched_group required for load_balancing
 */
struct sg_lb_stats {
	/*
	 * 该sg上所有cpu的平均负载. 仅在sg处于group_overloaded
	 * 状态下才计算该值,方便计算迁移负载量
	 */
	unsigned long avg_load; /*Avg load across the CPUs of the group */
	/* 该sg上所有cpu的负载之和 */
	unsigned long group_load; /* Total load over the CPUs of the group */
	/* 该sg上所有任务的权重负载,包括rt、dl任务 */
	unsigned long sum_weighted_load; /* Weighted load of group's tasks */
	unsigned long load_per_task;
	/* 该sg上所有cpu的可用于cfs任务的算力之和 */
	unsigned long group_capacity;
	/* 该sg上所有cpu的利用率之和 */
	unsigned long group_util; /* Total utilization of the group */
	/* 该sg上所有cfs任务的数量 */
	unsigned int sum_nr_running; /* Nr tasks running in the group */
	/* 该sg中idle cpu的数量 */
	unsigned int idle_cpus;
	/* 该sg中cpu的数量 */
	unsigned int group_weight;
	/* 该sg在负载均衡时所处的状态 */
	enum group_type group_type;
	int group_no_capacity;
#ifdef CONFIG_NUMA_BALANCING
	unsigned int nr_numa_running;
	unsigned int nr_preferred_running;
#endif
};

/*
 * sd_lb_stats - Structure to store the statistics of a sched_domain
 *		 during load balancing.
 */
struct sd_lb_stats {
	/* 该sd中最忙的那sg,非local group */
	struct sched_group *busiest;	/* Busiest group in this sd */
	/* 均衡时用于标记sd中哪个group是local group,即dst cpu所在的group */
	struct sched_group *local;	/* Local group in this sd */
	/* 此sd中所有sg的负载之和. 若无特别说明,这里的负载指的是cfs任务的负载 */
	unsigned long total_load;	/* Total load of all groups in sd */
	/* 此sd中所有sg的cpu算力之和(可用于cfs任务的算力) */
	unsigned long total_capacity;	/* Total capacity of all groups in sd */
	/* 该sd中所有sg的平均负载 */
	unsigned long avg_load;	/* Average load across all groups in sd */

	/* 该sd中最忙的那个sg的负载统计信息 */
	struct sg_lb_stats busiest_stat;/* Statistics of the busiest group */
	/* dst cpu所在的本地sg的负载统计信息 */
	struct sg_lb_stats local_stat;	/* Statistics of the local group */
};

static inline void init_sd_lb_stats(struct sd_lb_stats *sds)
{
	/*
	 * Skimp on the clearing to avoid duplicate work. We can avoid clearing
	 * local_stat because update_sg_lb_stats() does a full clear/assignment.
	 * We must however clear busiest_stat::avg_load because
	 * update_sd_pick_busiest() reads this before assignment.
	 *
	 * 跳过清除以避免重复工作.我们可以避免清除local_stat,因为update_sg_lb_stats()会执行完整的清除/赋值.
	 * 然而,我们必须清除busiest_stat::avg_load,因为update_sd_pick_busiest()在赋值之前会读取它.
	 */
	*sds = (struct sd_lb_stats){
		.busiest = NULL,
		.local = NULL,
		.total_load = 0UL,
		.total_capacity = 0UL,
		.busiest_stat = {
			.avg_load = 0UL,
			.sum_nr_running = 0,
			.group_type = group_other,
		},
	};
}

/**
 * get_sd_load_idx - Obtain the load index for a given sched domain.
 * @sd: The sched_domain whose load_idx is to be obtained.
 * @idle: The idle status of the CPU for whose sd load_idx is obtained.
 *
 * Return: The load index.
 */
static inline int get_sd_load_idx(struct sched_domain *sd,
					enum cpu_idle_type idle)
{
	int load_idx;

	switch (idle) {
	case CPU_NOT_IDLE:
		load_idx = sd->busy_idx;
		break;

	case CPU_NEWLY_IDLE:
		load_idx = sd->newidle_idx;
		break;
	default:
		load_idx = sd->idle_idx;
		break;
	}

	return load_idx;
}

static unsigned long scale_rt_capacity(int cpu)
{
	struct rq *rq = cpu_rq(cpu);
	u64 total, used, age_stamp, avg;
	s64 delta;

	/*
	 * Since we're reading these variables without serialization make sure
	 * we read them once before doing sanity checks on them.
	 */
	age_stamp = READ_ONCE(rq->age_stamp);
	avg = READ_ONCE(rq->rt_avg);
	delta = __rq_clock_broken(rq) - age_stamp;

	if (unlikely(delta < 0))
		delta = 0;

	total = sched_avg_period() + delta;

	used = div_u64(avg, total);

	if (likely(used < SCHED_CAPACITY_SCALE))
		return SCHED_CAPACITY_SCALE - used;

	return 1;
}

static void update_cpu_capacity(struct sched_domain *sd, int cpu)
{
	unsigned long capacity = arch_scale_cpu_capacity(sd, cpu);
	struct sched_group *sdg = sd->groups;

	cpu_rq(cpu)->cpu_capacity_orig = capacity;

	capacity *= scale_rt_capacity(cpu);
	capacity >>= SCHED_CAPACITY_SHIFT;

	if (!capacity)
		capacity = 1;

	cpu_rq(cpu)->cpu_capacity = capacity;
	sdg->sgc->capacity = capacity;
}

void update_group_capacity(struct sched_domain *sd, int cpu)
{
	struct sched_domain *child = sd->child;
	struct sched_group *group, *sdg = sd->groups;
	unsigned long capacity;
	unsigned long interval;

	/* 这边拿到sched_domain的均衡的基础时间间隔 */
	interval = msecs_to_jiffies(sd->balance_interval);
	/* 看interval取1 - max_load_balance_interval范围内的数 */
	interval = clamp(interval, 1UL, max_load_balance_interval);
	/* 设置sched_group_capacity的next_update为jiffies + interval */
	sdg->sgc->next_update = jiffies + interval;

	/* 如果没有child,那么直接更新cpu的capacity了,然后return */
	if (!child) {
		update_cpu_capacity(sd, cpu);
		return;
	}

	capacity = 0;

	if (child->flags & SD_OVERLAP) {
		/*
		 * SD_OVERLAP domains cannot assume that child groups
		 * span the current group.
		 */

		for_each_cpu(cpu, sched_group_cpus(sdg)) {
			struct sched_group_capacity *sgc;
			struct rq *rq = cpu_rq(cpu);

			/*
			 * build_sched_domains() -> init_sched_groups_capacity()
			 * gets here before we've attached the domains to the
			 * runqueues.
			 *
			 * Use capacity_of(), which is set irrespective of domains
			 * in update_cpu_capacity().
			 *
			 * This avoids capacity from being 0 and
			 * causing divide-by-zero issues on boot.
			 */
			if (unlikely(!rq->sd)) {
				capacity += capacity_of(cpu);
				continue;
			}

			sgc = rq->sd->groups->sgc;
			capacity += sgc->capacity;
		}
	} else  {
		/*
		 * !SD_OVERLAP domains can assume that child groups
		 * span the current group.
		 */

		/* 否则就加上sched_domain下面所有的capacity */
		group = child->groups;
		do {
			capacity += group->sgc->capacity;
			group = group->next;
		} while (group != child->groups);
	}

	/* 把capacity赋值给sdg->sgc->capacity */
	sdg->sgc->capacity = capacity;
}

/*
 * Check whether the capacity of the rq has been noticeably reduced by side
 * activity. The imbalance_pct is used for the threshold.
 * Return true is the capacity is reduced
 *
 * 检查rq的容量是否因其他活动而明显降低.
 * 使用imbalance_pct作为阈值. 如果容量降低,则返回true.
 */
static inline int
check_cpu_capacity(struct rq *rq, struct sched_domain *sd)
{
	/* rq->cpu_capacity <  rq->cpu_capacity_orig /sd->imbalance_pct * 100 */
	return ((rq->cpu_capacity * sd->imbalance_pct) <
				(rq->cpu_capacity_orig * 100));
}

/*
 * Group imbalance indicates (and tries to solve) the problem where balancing
 * groups is inadequate due to tsk_cpus_allowed() constraints.
 *
 * Imagine a situation of two groups of 4 cpus each and 4 tasks each with a
 * cpumask covering 1 cpu of the first group and 3 cpus of the second group.
 * Something like:
 *
 * 	{ 0 1 2 3 } { 4 5 6 7 }
 * 	        *     * * *
 *
 * If we were to balance group-wise we'd place two tasks in the first group and
 * two tasks in the second group. Clearly this is undesired as it will overload
 * cpu 3 and leave one of the cpus in the second group unused.
 *
 * The current solution to this issue is detecting the skew in the first group
 * by noticing the lower domain failed to reach balance and had difficulty
 * moving tasks due to affinity constraints.
 *
 * When this is so detected; this group becomes a candidate for busiest; see
 * update_sd_pick_busiest(). And calculate_imbalance() and
 * find_busiest_group() avoid some of the usual balance conditions to allow it
 * to create an effective group imbalance.
 *
 * This is a somewhat tricky proposition since the next run might not find the
 * group imbalance and decide the groups need to be balanced again. A most
 * subtle and fragile situation.
 *
 * "组不平衡"指的是(并尝试解决)由于tsk_cpus_allowed()约束导致组平衡不足的问题.
 *
 * 想象一下这样一个场景: 有两个组,每组各有4个CPU,以及4个任务,每个任务的CPU掩码(cpumask)覆盖了第一个组的1个CPU和第二个组的3个CPU.类似于这样:
 *
 * { 0 1 2 3 } { 4 5 6 7 }
 *	   *     * * *
 *
 * 如果我们按照组来平衡任务,那么会在第一个组放置两个任务,在第二个组也放置两个任务.
 * 这显然是不理想的,因为它会导致CPU 3过载,而第二个组中的一个CPU则未被使用.
 *
 * 当前解决这个问题的方案是通过注意到较低层域未能达到平衡,并且由于亲和性约束而难以移动任务,从而检测到第一组中的偏差.
 *
 * 当检测到这种情况时,该组成为最繁忙组的候选;
 * 参见update_sd_pick_busiest().而calculate_imbalance()和find_busiest_group()则避免了一些通常的平衡条件,以便它能够创建有效的组不平衡.
 *
 * 这是一个相当棘手的提议,因为下一次运行可能找不到组不平衡,并决定需要再次平衡组.这是一个非常微妙且易碎的情况.
 */

static inline int sg_imbalanced(struct sched_group *group)
{
	return group->sgc->imbalance;
}

/*
 * group_has_capacity returns true if the group has spare capacity that could
 * be used by some tasks.
 * We consider that a group has spare capacity if the  * number of task is
 * smaller than the number of CPUs or if the utilization is lower than the
 * available capacity for CFS tasks.
 * For the latter, we use a threshold to stabilize the state, to take into
 * account the variance of the tasks' load and to return true if the available
 * capacity in meaningful for the load balancer.
 * As an example, an available capacity of 1% can appear but it doesn't make
 * any benefit for the load balance.
 */
static inline bool
group_has_capacity(struct lb_env *env, struct sg_lb_stats *sgs)
{
	if (sgs->sum_nr_running < sgs->group_weight)
		return true;

	if ((sgs->group_capacity * 100) >
			(sgs->group_util * env->sd->imbalance_pct))
		return true;

	return false;
}

/*
 *  group_is_overloaded returns true if the group has more tasks than it can
 *  handle.
 *  group_is_overloaded is not equals to !group_has_capacity because a group
 *  with the exact right number of tasks, has no more spare capacity but is not
 *  overloaded so both group_has_capacity and group_is_overloaded return
 *  false.
 *
 * 如果组的任务超出其处理能力,group_is_overloaded将返回true.
 * group_is_overloaded不等于!group_has_capacity,因为具有正确任务数量的组没有多余容量,但没有过载,因此group_has_capacity和group_is_overloaded都返回false.
 */

/* 确实,group_is_overloaded和group_has_capacity这两个函数在判断任务组状态时扮演着不同的角色,尽管它们都与任务组的负载能力有关.
 *
 * group_has_capacity: 这个函数检查任务组是否还有剩余的处理能力来接受更多的任务。
 * 如果任务组的当前负载低于其最大处理能力(即还有剩余容量),则该函数返回true;否则,返回false.
 * 这意味着,即使任务组已经满负荷运行(但没有超出其最大容量),该函数也可能返回false,因为它侧重于是否有额外的处理能力.
 *
 * group_is_overloaded: 这个函数则更侧重于任务组是否因为任务过多而“过载”.
 * 如果任务组的当前负载已经超出了它能够高效处理的能力范围(即它正在处理的任务数量超过了其设计或期望的负载水平),则该函数返回 true.
 * 这并不一定意味着任务组没有剩余的处理能力(因为剩余能力可能非常小或几乎为零),而是说它已经达到了一个被认为是“过载”的阈值.
 */
static inline bool
group_is_overloaded(struct lb_env *env, struct sg_lb_stats *sgs)
{
	/* 如果sgs上面运行的进程小于CPU数量,那么返回false */
	if (sgs->sum_nr_running <= sgs->group_weight)
		return false;

	if ((sgs->group_capacity * 100) <
			(sgs->group_util * env->sd->imbalance_pct))
		return true;

	return false;
}

static inline enum
group_type group_classify(struct sched_group *group,
			  struct sg_lb_stats *sgs)
{
	if (sgs->group_no_capacity)
		return group_overloaded;

	if (sg_imbalanced(group))
		return group_imbalanced;

	return group_other;
}

/**
 * update_sg_lb_stats - Update sched_group's statistics for load balancing.
 * @env: The load balancing environment.
 * @group: sched_group whose statistics are to be updated.
 * @load_idx: Load index of sched_domain of this_cpu for load calc.
 * @local_group: Does group contain this_cpu.
 * @sgs: variable to hold the statistics for this group.
 * @overload: Indicate more than one runnable task for any CPU.
 *
 * update_sg_lb_stats - 更新sched_group的统计数据以实现负载平衡.
 * @env: 负载平衡环境.
 * @group: sched_group,其统计信息将被更新。
 * @load_idx: 用于负载计算的this_cpu的sched_domain的负载索引.
 * @local_group: 该组是否包含this_cpu.
 * @sgs: 用于保存此组统计信息的变量.
 * @overload; 表示任何CPU都有多个可运行的任务.
 */
static inline void update_sg_lb_stats(struct lb_env *env,
			struct sched_group *group, int load_idx,
			int local_group, struct sg_lb_stats *sgs,
			bool *overload)
{
	unsigned long load;
	int i, nr_running;

	/* 清除sg_lb_stats */
	memset(sgs, 0, sizeof(*sgs));

	/* 首先遍历该调度组里所有的CPU,计算该调度组里的总负载,各个CPU的负载通过target_load或source_load计算,本地组用target_load,两者的计算方法类似 */
	for_each_cpu_and(i, sched_group_cpus(group), env->cpus) {
		/* 拿到该cpu的rq */
		struct rq *rq = cpu_rq(i);

		/* Bias balancing toward cpus of our domain */
		/* 如果是本地CPU的group,那么就通过target_load
		 * 否则就用source_load
		 */
		if (local_group)
			load = target_load(i, load_idx);
		else
			load = source_load(i, load_idx);

		/* 让sgs->group_load加上我们刚刚算出来的load
		 * 所以这个sgs->group_load是我们调度组的总负载
		 */
		sgs->group_load += load;
		/* cpu_util返回CFS任务使用的cpu容量 */
		sgs->group_util += cpu_util(i);
		/*
		 * cfs_rq->nr_runing记录cfs_rq上所有调度实体个数,不包含子就绪队列.
		 * cfs_rq->h_nr_running记录cfs_rq上所有调度实体的个数，包含 group se 对应 group cfs_rq 上的调度实体.
		 * rq->nr_running，还包含rt、dl的。
		 */

		/* 这里加上cfs.h_nr_running(cfs_rq上所有调度实体的个数) */
		sgs->sum_nr_running += rq->cfs.h_nr_running;

		/* nr_running赋值为rq->nr_running */
		nr_running = rq->nr_running;
		/* 只要该sg上有一个CPU上有2个及以上的任务,那么就让overload = true */
		if (nr_running > 1)
			*overload = true;

#ifdef CONFIG_NUMA_BALANCING
		sgs->nr_numa_running += rq->nr_numa_running;
		sgs->nr_preferred_running += rq->nr_preferred_running;
#endif
		/* 让它加上cfs_rq->runnable_load_avg? */
		sgs->sum_weighted_load += weighted_cpuload(i);
		/*
		 * No need to call idle_cpu() if nr_running is not 0
		 */
		/* 统计该sched group中的idle cpu的个数 */
		if (!nr_running && idle_cpu(i))
			sgs->idle_cpus++;
	}

	/* Adjust by relative CPU capacity of the group */
	/* 更新sg的总算力,再次强调一下,这里的capacity是指cpu可以用于cfs任务的算力 */
	sgs->group_capacity = group->sgc->capacity;

	/* 计算sg的平均负载 */
	sgs->avg_load = (sgs->group_load*SCHED_CAPACITY_SCALE) / sgs->group_capacity;

	/* 如果sgs->sum_nr_running大于0,那么算出平均负载 */
	if (sgs->sum_nr_running)
		sgs->load_per_task = sgs->sum_weighted_load / sgs->sum_nr_running;

	/* 算出这个group中CPU的个数 */
	sgs->group_weight = group->group_weight;

	sgs->group_no_capacity = group_is_overloaded(env, sgs);
	/* 这里就是检查这个group是否平衡 */
	sgs->group_type = group_classify(group, sgs);
}

/**
 * update_sd_pick_busiest - return 1 on busiest group
 * @env: The load balancing environment.
 * @sds: sched_domain statistics
 * @sg: sched_group candidate to be checked for being the busiest
 * @sgs: sched_group statistics
 *
 * Determine if @sg is a busier group than the previously selected
 * busiest group.
 *
 * Return: %true if @sg is a busier group than the previously selected
 * busiest group. %false otherwise.
 *
 * update_sd_pick_busiest - 在最繁忙的组上返回1
 * @env: 负载平衡环境.
 * @sds: sched_domain统计信息
 * @sg: 检查sched_group候选者是否最繁忙
 * @sgs:sched_group统计信息
 *
 * 确定@sg是否比之前选择的最繁忙组更繁忙.
 *
 * 如果@sg是比之前选择的最繁忙组更繁忙的组,则返回true,否则为false
 */
static bool update_sd_pick_busiest(struct lb_env *env,
				   struct sd_lb_stats *sds,
				   struct sched_group *sg,
				   struct sg_lb_stats *sgs)
{
	struct sg_lb_stats *busiest = &sds->busiest_stat;

	/* sgs代表的sg的负载更重 */
	if (sgs->group_type > busiest->group_type)
		return true;

	if (sgs->group_type < busiest->group_type)
		return false;

	/* 平均负载更重？ */
	if (sgs->avg_load <= busiest->avg_load)
		return false;

	/* This is the busiest node in its class. */

	/* 如果这个sched_domain没有SD_ASYM_PACKING,也就是说没有大小核,那么就返回true
	 */
	if (!(env->sd->flags & SD_ASYM_PACKING))
		return true;

	/* No ASYM_PACKING if target cpu is already busy */
	/* 如果没有ASYM_PACKING,但是目标CPU不是IDLE的,那么直接返回true */
	if (env->idle == CPU_NOT_IDLE)
		return true;
	/*
	 * ASYM_PACKING needs to move all the work to the lowest
	 * numbered CPUs in the group, therefore mark all groups
	 * higher than ourself as busy.
	 *
	 * ASYM_PACKING需要将所有工作转移到组中编号最低的CPU,因此将所有高于我们自己的组标记为忙碌.
	 */
	/* 如果sgs->sum_nr_running && env->dst_cpu比组里的第一个CPU小 */
	if (sgs->sum_nr_running && env->dst_cpu < group_first_cpu(sg)) {
		/* 如果sds不是最忙碌的,那么返回true */
		if (!sds->busiest)
			return true;

		/* Prefer to move from highest possible cpu's work */
		/* 如果最忙碌的那个组比这个组里面的第一个CPU还要小,那么返回true */
		if (group_first_cpu(sds->busiest) < group_first_cpu(sg))
			return true;
	}

	/* 否则返回false */
	return false;
}

#ifdef CONFIG_NUMA_BALANCING
static inline enum fbq_type fbq_classify_group(struct sg_lb_stats *sgs)
{
	if (sgs->sum_nr_running > sgs->nr_numa_running)
		return regular;
	if (sgs->sum_nr_running > sgs->nr_preferred_running)
		return remote;
	return all;
}

static inline enum fbq_type fbq_classify_rq(struct rq *rq)
{
	if (rq->nr_running > rq->nr_numa_running)
		return regular;
	if (rq->nr_running > rq->nr_preferred_running)
		return remote;
	return all;
}
#else
static inline enum fbq_type fbq_classify_group(struct sg_lb_stats *sgs)
{
	return all;
}

static inline enum fbq_type fbq_classify_rq(struct rq *rq)
{
	return regular;
}
#endif /* CONFIG_NUMA_BALANCING */

/**
 * update_sd_lb_stats - Update sched_domain's statistics for load balancing.
 * @env: The load balancing environment.
 * @sds: variable to hold the statistics for this sched_domain.
 */
static inline void update_sd_lb_stats(struct lb_env *env, struct sd_lb_stats *sds)
{
	/* 拿到env->sd的child sched_domain */
	struct sched_domain *child = env->sd->child;
	/* 拿到env->sd的groups */
	struct sched_group *sg = env->sd->groups;
	struct sg_lb_stats tmp_sgs;
	int load_idx, prefer_sibling = 0;
	bool overload = false;

	/* 如果有child,且child->flags有SD_PREFER_SIBLING,那么设置prefer_sibling = 1 */
	if (child && child->flags & SD_PREFER_SIBLING)
		prefer_sibling = 1;

	/* get_sd_load_idx函数根据当前CPU的空闲与否来获取load_idx参数.
	 * 通常空闲CPU取值为1,非空闲CPU取值为2,具体见sd_init函数
	 */
	load_idx = get_sd_load_idx(env->sd, env->idle);

	/* 遍历该调度域的所有调度组 */
	do {
		struct sg_lb_stats *sgs = &tmp_sgs;
		/* 遍历local_group用于判断一个调度组是否为本地调度组(local_group),即是否包含当前CPU */
		int local_group;

		/* 判断一个调度组是否为本地调度组 */
		local_group = cpumask_test_cpu(env->dst_cpu, sched_group_cpus(sg));
		/* 如果是本地调度组 */

		/*
		 * 更新算力没有必要更新的太频繁,这里做了两个限制:
		 * 1.只有local group才进行算力更新,
		 * 2.对于newidle类型的balance通过时间间隔来减少频繁的更新算力,这个时间间隔来自balance_interval:
		 * jiffies + msecs_to_jiffies(sd->balance_interval).
		 * 3.其它类型的idle可以更新算力
		 */
		if (local_group) {
			/* 设置sd_lb_stats的local为该sg */
			sds->local = sg;
			/* 设置sgs为sds->local_stat */
			sgs = &sds->local_stat;

			if (env->idle != CPU_NEWLY_IDLE ||
			    time_after_eq(jiffies, sg->sgc->next_update))
				/* 更新sd->sg->sgc里面的相关capacity成员,DIE层级的MC里面的也一并更新 */
				update_group_capacity(env->sd, env->dst_cpu);
		}
		/* 上面是更新算力,这里是更新该sched group的负载统计 */
		update_sg_lb_stats(env, sg, load_idx, local_group, sgs,
						&overload);

		/*
		 * 在sched domain的各个group遍历中,我们需要两个group信息,一个是local group,另外一个就是
		 * non local group中的最忙的那个group.
		 * 显然,如果是local group,不需要下面的比拼最忙的过程.
		 */
		if (local_group)
			goto next_group;

		/*
		 * In case the child domain prefers tasks go to siblings
		 * first, lower the sg capacity so that we'll try
		 * and move all the excess tasks away. We lower the capacity
		 * of a group only if the local group has the capacity to fit
		 * these excess tasks. The extra check prevents the case where
		 * you always pull from the heaviest group when it is already
		 * under-utilized (possible with a large weight task outweighs
		 * the tasks on the system).
		 *
		 * 如果child domain更倾向于任务首先分配给兄弟节点,则降低sg容量,以便我们尝试将所有多余的任务移出.
		 * 我们仅当local group有能力容纳这些多余任务时,才会降低组的容量.
		 * 这个额外的检查可以防止在已经利用率不足的情况下(这可能在系统上存在一个大权重任务时发生,该任务权重超过了系统上的其他任务),总是从最重的组中拉取任务的情况.
		 */

		/* 如果prefer_sibling并且有local_group
		 * 并且local_group还有剩余的能力,并且sgs->sum_nr_running > 1
		 */
		if (prefer_sibling && sds->local &&
		    group_has_capacity(env, &sds->local_stat) &&
		    (sgs->sum_nr_running > 1)) {
			/* 设置sgs->group_no_capacity = 1 */
			sgs->group_no_capacity = 1;
			/* 设置sgs->group_type为 group_overloaded */
			sgs->group_type = group_classify(sg, sgs);
		}

		/* 对于non local group的sg,和之前找到最忙的那个group进行PK,更忙的选中为busiest sg */
		if (update_sd_pick_busiest(env, sds, sg, sgs)) {
			/* 设置sds->busiest为该sg */
			sds->busiest = sg;
			/* 设置sds的busiest_stat为该sgs */
			sds->busiest_stat = *sgs;
		}

next_group:
		/* Now, start updating sd_lb_stats */
		/* 累计各个sg的负载和算力到sds */
		sds->total_load += sgs->group_load;
		sds->total_capacity += sgs->group_capacity;

		sg = sg->next;
	} while (sg != env->sd->groups);

	/* */
	if (env->sd->flags & SD_NUMA)
		env->fbq_type = fbq_classify_group(&sds->busiest_stat);

	/* 如果env->sd_parent没有了,也就是到了最顶层了 */
	if (!env->sd->parent) {
		/* update overload indicator if we are at root domain */
		/* 更新root domain的overload */
		if (env->dst_rq->rd->overload != overload)
			env->dst_rq->rd->overload = overload;
	}

}

/**
 * check_asym_packing - Check to see if the group is packed into the
 *			sched doman.
 *
 * This is primarily intended to used at the sibling level.  Some
 * cores like POWER7 prefer to use lower numbered SMT threads.  In the
 * case of POWER7, it can move to lower SMT modes only when higher
 * threads are idle.  When in lower SMT modes, the threads will
 * perform better since they share less core resources.  Hence when we
 * have idle threads, we want them to be the higher ones.
 *
 * This packing function is run on idle threads.  It checks to see if
 * the busiest CPU in this domain (core in the P7 case) has a higher
 * CPU number than the packing function is being run on.  Here we are
 * assuming lower CPU number will be equivalent to lower a SMT thread
 * number.
 *
 * Return: 1 when packing is required and a task should be moved to
 * this CPU.  The amount of the imbalance is returned in *imbalance.
 *
 * @env: The load balancing environment.
 * @sds: Statistics of the sched_domain which is to be packed
 */
static int check_asym_packing(struct lb_env *env, struct sd_lb_stats *sds)
{
	int busiest_cpu;

	if (!(env->sd->flags & SD_ASYM_PACKING))
		return 0;

	if (env->idle == CPU_NOT_IDLE)
		return 0;

	if (!sds->busiest)
		return 0;

	busiest_cpu = group_first_cpu(sds->busiest);
	if (env->dst_cpu > busiest_cpu)
		return 0;

	env->imbalance = DIV_ROUND_CLOSEST(
		sds->busiest_stat.avg_load * sds->busiest_stat.group_capacity,
		SCHED_CAPACITY_SCALE);

	return 1;
}

/**
 * fix_small_imbalance - Calculate the minor imbalance that exists
 *			amongst the groups of a sched_domain, during
 *			load balancing.
 * @env: The load balancing environment.
 * @sds: Statistics of the sched_domain whose imbalance is to be calculated.
 *
 * fix_small_imbalance - 计算负载平衡期间sched_domain组之间存在的微小不平衡.
 * @env: 负载平衡环境.
 * @sds: 要计算其不平衡的sched_domain的统计信息
 */
static inline
void fix_small_imbalance(struct lb_env *env, struct sd_lb_stats *sds)
{
	unsigned long tmp, capa_now = 0, capa_move = 0;
	unsigned int imbn = 2;
	unsigned long scaled_busy_load_per_task;
	struct sg_lb_stats *local, *busiest;

	/* local_stat和busiest_stat */
	local = &sds->local_stat;
	busiest = &sds->busiest_stat;

	/* 如果local group没有运行的进程,那么local->load_per_task = 该CPU的avg_load */
	if (!local->sum_nr_running)
		local->load_per_task = cpu_avg_load_per_task(env->dst_cpu);
	/* 如果最繁忙的group的load_per_task 大于local的load_per_task,那么imbn等于1 */
	else if (busiest->load_per_task > local->load_per_task)
		imbn = 1;

	/* scaled_busy_load_per_task是一个重要的计算值,它表示每个CPU上每个任务的平均负载.
	 * 这个值通常是根据CPU的当前负载、CPU的能力(如频率、核心数等)以及任务的特性(如优先级、执行时间等)来计算的.
	 */
	scaled_busy_load_per_task =
		(busiest->load_per_task * SCHED_CAPACITY_SCALE) /
		busiest->group_capacity;

	/* 如果busiest->avg_load + scaled_busy_load_per_task >= local->avg_load + scaled_busy_load_per_task * imbn(倍数)
	 * 设置imbalance为busiest->load_per_task
	 */
	if (busiest->avg_load + scaled_busy_load_per_task >=
	    local->avg_load + (scaled_busy_load_per_task * imbn)) {
		env->imbalance = busiest->load_per_task;
		return;
	}

	/*
	 * OK, we don't have enough imbalance to justify moving tasks,
	 * however we may be able to increase total CPU capacity used by
	 * moving them.
	 *
	 * 好的,我们没有足够的不平衡来证明移动任务是合理的,但是我们可以通过移动任务来增加CPU的总容量.
	 */

	/* 下面这3次capa_now的计算统计了busiest和local的用量总和 */

	/* 如果用的是avg_load,相当于计算回原来的group load
	 * 如果用的是load_per_task,那计算的是load_per_task * group_capacity / 1024 */
	capa_now += busiest->group_capacity *
			min(busiest->load_per_task, busiest->avg_load);
	capa_now += local->group_capacity *
			min(local->load_per_task, local->avg_load);
	capa_now /= SCHED_CAPACITY_SCALE;

	/* Amount of load we'd subtract */
	/* 我们要减去的量(capa_move)
	 * 如果busiest->avg_load > scaled_busy_load_per_task,说明有可以
	 * 迁移的load
	 * 计算可以迁移capa_move
	 */
	if (busiest->avg_load > scaled_busy_load_per_task) {
		capa_move += busiest->group_capacity *
			    min(busiest->load_per_task,
				busiest->avg_load - scaled_busy_load_per_task);
	}

	/* Amount of load we'd add */
	/* 我们要增加的量(tmp) */
	if (busiest->avg_load * busiest->group_capacity <
	    busiest->load_per_task * SCHED_CAPACITY_SCALE) {
		tmp = (busiest->avg_load * busiest->group_capacity) /
		      local->group_capacity;
	} else {
		tmp = (busiest->load_per_task * SCHED_CAPACITY_SCALE) /
		      local->group_capacity;
	}

	/* 计算迁移之后的用量总和(capa_move) */
	capa_move += local->group_capacity *
		    min(local->load_per_task, local->avg_load + tmp);
	capa_move /= SCHED_CAPACITY_SCALE;

	/* Move if we gain throughput */
	/* 判断移动之后,是否会将整体的用量总和是否会提高(目标看上去是尽量提高使用率) */
	if (capa_move > capa_now)
		env->imbalance = busiest->load_per_task;
}

/**
 * calculate_imbalance - Calculate the amount of imbalance present within the
 *			 groups of a given sched_domain during load balance.
 * @env: load balance environment
 * @sds: statistics of the sched_domain whose imbalance is to be calculated.
 *
 * calculate_imbalance - 计算负载平衡期间给定sched_domain组内存在的不平衡量.
 * @env: 负载平衡环境
 * @sds: 要计算其不平衡的sched_domain的统计数据
 */
static inline void calculate_imbalance(struct lb_env *env, struct sd_lb_stats *sds)
{
	unsigned long max_pull, load_above_capacity = ~0UL;
	struct sg_lb_stats *local, *busiest;

	/* 拿到local_stat和busiest_stat */
	local = &sds->local_stat;
	busiest = &sds->busiest_stat;

	/* 如果最繁忙的group是不平衡的 */
	if (busiest->group_type == group_imbalanced) {
		/*
		 * In the group_imb case we cannot rely on group-wide averages
		 * to ensure cpu-load equilibrium, look at wider averages. XXX
		 *
		 * 在group_imb的情况下,我们不能依赖组内的平均值来确保cpu负载平衡,请查看更广泛的平均值.XXX
		 */

		/* 找到busiest->load_per_task和sds->avg_load的平均值 */
		busiest->load_per_task =
			min(busiest->load_per_task, sds->avg_load);
	}

	/*
	 * Avg load of busiest sg can be less and avg load of local sg can
	 * be greater than avg load across all sgs of sd because avg load
	 * factors in sg capacity and sgs with smaller group_type are
	 * skipped when updating the busiest sg:
	 *
	 * 最繁忙sg的平均负载可能较小,而本地sg的均值负载可能大于sd所有sgs的均值负载,
	 * 因为在更新最繁忙的sg时,跳过了sg容量和group_type较小的sgs中的均值负载系数:
	 */

	/* 如果最繁忙组的平均负载小于等于该调度域的平均负载或者说本地调度组的平均负载大于该调度域的平均负载,说明该调度域处于平衡状态 */
	if (busiest->avg_load <= sds->avg_load ||
	    local->avg_load >= sds->avg_load) {
		env->imbalance = 0;
		return fix_small_imbalance(env, sds);
	}

	/*
	 * If there aren't any idle cpus, avoid creating some.
	 */
	/* 如果最繁忙调度组和本地调度组都出现group_overloaded的情况,即运行中的进程数目大于该组能力系数(group_capacity_factor),那么先计算load_above_capacity,然后计算需要迁移多少负载才能实现该调度域的平衡 */
	if (busiest->group_type == group_overloaded &&
	    local->group_type   == group_overloaded) {
		/* load_above_capacity = 最繁忙的调度组里面运行的进程数量 * SCHED_CAPACITY_SCALE */
		load_above_capacity = busiest->sum_nr_running * SCHED_CAPACITY_SCALE;
		/* 如果load_above_capacity大于该组的capacity */
		if (load_above_capacity > busiest->group_capacity) {
			/* 那么算出其超出的部分 */
			load_above_capacity -= busiest->group_capacity;
			/* 让它 * scale_load_down(NICE_0_LOAD) */
			load_above_capacity *= scale_load_down(NICE_0_LOAD);
			/* 然后除以busiest->group_capacity */
			load_above_capacity /= busiest->group_capacity;
		} else
			load_above_capacity = ~0UL;
	}

	/*
	 * We're trying to get all the cpus to the average_load, so we don't
	 * want to push ourselves above the average load, nor do we wish to
	 * reduce the max loaded cpu below the average load. At the same time,
	 * we also don't want to reduce the group load below the group
	 * capacity. Thus we look for the minimum possible imbalance.
	 *
	 * 我们正试图让所有cpu达到average_load,所以我们不想把自己推到平均负载之上,也不想把最大负载的cpu降低到平均负载之下.
	 * 同时,我们也不想将组负载降低到组能力以下.
	 * 因此,我们寻求最小可能的不平衡.
	 */

	/* 用最繁忙的组的平均负载 - 这个sched_domain的平均负载,取它和load_above_capacity的最小值 */
	max_pull = min(busiest->avg_load - sds->avg_load, load_above_capacity);

	/* How much load to actually move to equalise the imbalance */
	/* 实际移动多少负载以平衡不平衡 */
	env->imbalance = min(
		max_pull * busiest->group_capacity,
		(sds->avg_load - local->avg_load) * local->group_capacity
	) / SCHED_CAPACITY_SCALE;

	/*
	 * if *imbalance is less than the average load per runnable task
	 * there is no guarantee that any tasks will be moved so we'll have
	 * a think about bumping its value to force at least one task to be
	 * moved
	 *
	 * 如果*不平衡 小于每个可运行任务的平均负载,无法保证任何任务都会被移动,因此我们将考虑提高其值,以强制至少移动一个任务
	 */
	if (env->imbalance < busiest->load_per_task)
		return fix_small_imbalance(env, sds);
}

/******* find_busiest_group() helpers end here *********************/

/**
 * find_busiest_group - Returns the busiest group within the sched_domain
 * if there is an imbalance.
 *
 * Also calculates the amount of weighted load which should be moved
 * to restore balance.
 *
 * @env: The load balancing environment.
 *
 * Return:	- The busiest group if imbalance exists.
 */
static struct sched_group *find_busiest_group(struct lb_env *env)
{
	struct sg_lb_stats *local, *busiest;
	struct sd_lb_stats sds;

	init_sd_lb_stats(&sds);

	/*
	 * Compute the various statistics relavent for load balancing at
	 * this level.
	 */
	/*
	 * 负载信息都是不断的在变化,在寻找最繁忙group的时候,我们首先要更新sd负载均衡信息,
	 * 以便可以根据最新的负载情况来搜寻.
	 * 此函数会更新该sd上各个sg的负载和算力,得到local group以及
	 * 非local group最忙的那个group的均衡信息,以便后续给出最适合的均衡决策.
	 */
	update_sd_lb_stats(env, &sds);
	/* 找出 busiest sg 还要与local sg进行PK */
	local = &sds.local_stat;
	busiest = &sds.busiest_stat;

	/*
	 * ASYM feature bypasses nice load balance check
	 * ASYM feature绕过了良好的负载平衡检查
	 */
	if (check_asym_packing(env, &sds))
		return sds.busiest;

	/* There is no busy sibling group to pull tasks from */
	/* 如果没有找到最忙的那个group.说明当前sd中.其他的非local的最繁忙的group(后文称之busiest group)没有可以拉取到local group的任务,不需要均衡处理. */
	/* 如果没有找到最繁忙的组或者最繁忙的调度组没有正在运行的进程,那么跳过该调度域 */
	if (!sds.busiest || busiest->sum_nr_running == 0)
		goto out_balanced;

	/* 计算出该调度域的平均负载 */
	sds.avg_load = (SCHED_CAPACITY_SCALE * sds.total_load)
						/ sds.total_capacity;

	/*
	 * If the busiest group is imbalanced the below checks don't
	 * work because they assume all things are equal, which typically
	 * isn't true due to cpus_allowed constraints and the like.
	 *
	 * 如果最繁忙的组不平衡,则以下检查不起作用,因为它们假设所有事情都是平等的,但由于cpus_allowed约束等,这通常不是真的.
	 */

	/* busiest group是一个由于cpu affinity导致的不均衡,MC层级均衡时发现均衡不了设置的 */
	/* 如果最繁忙调度组的组类型是group_imbalanced,那么跳转到force_balance */
	if (busiest->group_type == group_imbalanced)
		goto force_balance;

	/* SD_BALANCE_NEWIDLE trumps SMP nice when underutilized
	 * SD_BALANCE_NEWIDLE在未充分利用时胜过SMP
	 */

	/* 如果env->idle是CPU_NEWLY_IDLE,并且本地CPU还有capacity,并且最忙的组没有capacity了 */
	if (env->idle == CPU_NEWLY_IDLE && group_has_capacity(env, local) &&
	    busiest->group_no_capacity)
		goto force_balance;

	/*
	 * If the local group is busier than the selected busiest group
	 * don't try and pull any tasks.
	 */

	/* 如果local group的平均负载比busiest group还要高,那么不需要进行均衡 */
	if (local->avg_load >= busiest->avg_load)
		goto out_balanced;

	/*
	 * Don't pull any tasks if this group is already above the domain
	 * average load.
	 */
	/* 如果local group的平均负载高于sd的平均负载,那么也不需要进行均衡 */
	if (local->avg_load >= sds.avg_load)
		goto out_balanced;

	/* 如果本CPU是IDLE CPU */
	if (env->idle == CPU_IDLE) {
		/*
		 * This cpu is idle. If the busiest group is not overloaded
		 * and there is no imbalance between this and busiest group
		 * wrt idle cpus, it is balanced. The imbalance becomes
		 * significant if the diff is greater than 1 otherwise we
		 * might end up to just move the imbalance on another group
		 *
		 * 这个CPU处于空闲状态.如果最繁忙的组没有过载,并且该组与最繁忙组之间在空闲CPU方面没有不平衡,那么它就是平衡的.
		 * 如果差值大于1,则不平衡变得显著,否则我们可能只是将不平衡转移到另一个组上.
		 */
		/* 如果最忙的gourp_type也没有过载,最繁忙的组里的idle cpu数量 +1 大于等于本地调度组里的idle cpu数量,那么也不需要做负载均衡 */
		if ((busiest->group_type != group_overloaded) &&
				(local->idle_cpus <= (busiest->idle_cpus + 1)))
			goto out_balanced;
	} else {
		/*
		 * In the CPU_NEWLY_IDLE, CPU_NOT_IDLE cases, use
		 * imbalance_pct to be conservative.
		 */
		/* 如果本地CPU不是idle状态,那么比较本地调度组的平均负载和最繁忙调度组的平均负载,这里使用了imbalance_pct系数,它在sd_init函数中初始化,默认为125.
		 * 如果本地调度组的平均负载大于等于最繁忙组的平均负载,说明调度域不忙,不需要做负载均衡
		 */
		if (100 * busiest->avg_load <=
				env->sd->imbalance_pct * local->avg_load)
			goto out_balanced;
	}

force_balance:
	/* Looks like there is an imbalance. Compute it */
	/* 计算需要迁移多少负载量才能达到平衡 */
	calculate_imbalance(env, &sds);
	return sds.busiest;

out_balanced:
	env->imbalance = 0;
	return NULL;
}

/*
 * find_busiest_queue - find the busiest runqueue among the cpus in group.
 */
static struct rq *find_busiest_queue(struct lb_env *env,
				     struct sched_group *group)
{
	struct rq *busiest = NULL, *rq;
	unsigned long busiest_load = 0, busiest_capacity = 1;
	int i;

	/* 对这个group中所有的CPU进行轮询 */
	for_each_cpu_and(i, sched_group_cpus(group), env->cpus) {
		unsigned long capacity, wl;
		enum fbq_type rt;

		/* 拿到该cpu的运行队列 */
		rq = cpu_rq(i);
		rt = fbq_classify_rq(rq);

		/*
		 * We classify groups/runqueues into three groups:
		 *  - regular: there are !numa tasks
		 *  - remote:  there are numa tasks that run on the 'wrong' node
		 *  - all:     there is no distinction
		 *
		 * In order to avoid migrating ideally placed numa tasks,
		 * ignore those when there's better options.
		 *
		 * If we ignore the actual busiest queue to migrate another
		 * task, the next balance pass can still reduce the busiest
		 * queue by moving tasks around inside the node.
		 *
		 * If we cannot move enough load due to this classification
		 * the next pass will adjust the group classification and
		 * allow migration of more tasks.
		 *
		 * Both cases only affect the total convergence complexity.
		 *
		 * 我们将组/运行队列 分为三组:
		 * 普通组: 这是非NUMA任务
		 * 远程组: 包含在“错误”节点上运行的NUMA任务
		 * 全部组: 不进行区分
		 *
		 * 为了避免迁移理想放置的NUMA任务,当存在更优选项时,请忽略这些任务.
		 *
		 * 如果我们忽略最繁忙的队列以迁移另一个任务,下一次平衡传递仍然可以通过在节点内移动任务来减少最繁忙队列的负载.
		 *
		 * 如果由于这种分类而无法移动足够的负载,则下一次传递将调整组分类并允许迁移更多任务.
		 *
		 * 这两种情况仅影响总收敛复杂度.
		 */
		if (rt > env->fbq_type)
			continue;

		/* cpu当前算力 */
		capacity = capacity_of(i);

		/* cfs_rq->runnable_load_avg; */
		wl = weighted_cpuload(i);

		/*
		 * When comparing with imbalance, use weighted_cpuload()
		 * which is not scaled with the cpu capacity.
		 *
		 * 当与imbalance进行比较时,使用未随cpu容量缩放的weighted_cpuload()
		 */

		/* 如果rq->nr_running == 1,也就是说该rq上只有一个进程在运行
		 * 如果wl比env->imbalance还要大
		 * check_cpu_capacity返回false
		 * 则continue
		 * 也就是说此cpu中只有一个任务且负载大于不均衡值且可用于cfs任务的算力充足
		 */
		if (rq->nr_running == 1 && wl > env->imbalance &&
		    !check_cpu_capacity(rq, env->sd))
			continue;

		/*
		 * For the load comparisons with the other cpu's, consider
		 * the weighted_cpuload() scaled with the cpu capacity, so
		 * that the load can be moved away from the cpu that is
		 * potentially running at a lower capacity.
		 *
		 * Thus we're looking for max(wl_i / capacity_i), crosswise
		 * multiplication to rid ourselves of the division works out
		 * to: wl_i * capacity_j > wl_j * capacity_i;  where j is
		 * our previous maximum.
		 *
		 * 对于与其他 CPU 的负载比较请考虑随CPU容量缩放的weighted_cpuload(),以便可以将负载从可能以较低算力
		 * 运行的CPU上移开.
		 *
		 * 因此,我们正在寻找max(wl_i / capacity_i),横向乘法以摆脱除法的结果: wl_i * capacity_j > wl_j * capacity_i;
		 * 其中 j 是我们之前的最大值.
		 *
		 * 判断 load / capacity > busiest_load / busiest_capacity 来定最忙的cpu
		 */
		if (wl * busiest_capacity > busiest_load * capacity) {
			busiest_load = wl;
			busiest_capacity = capacity;
			busiest = rq;
		}
	}

	return busiest;
}

/*
 * Max backoff if we encounter pinned tasks. Pretty arbitrary value, but
 * so long as it is large enough.
 */
#define MAX_PINNED_INTERVAL	512

static int need_active_balance(struct lb_env *env)
{
	struct sched_domain *sd = env->sd;

	if (env->idle == CPU_NEWLY_IDLE) {

		/*
		 * ASYM_PACKING needs to force migrate tasks from busy but
		 * higher numbered CPUs in order to pack all tasks in the
		 * lowest numbered CPUs.
		 */
		if ((sd->flags & SD_ASYM_PACKING) && env->src_cpu > env->dst_cpu)
			return 1;
	}

	/*
	 * The dst_cpu is idle and the src_cpu CPU has only 1 CFS task.
	 * It's worth migrating the task if the src_cpu's capacity is reduced
	 * because of other sched_class or IRQs if more capacity stays
	 * available on dst_cpu.
	 */
	if ((env->idle != CPU_NOT_IDLE) &&
	    (env->src_rq->cfs.h_nr_running == 1)) {
		if ((check_cpu_capacity(env->src_rq, sd)) &&
		    (capacity_of(env->src_cpu)*sd->imbalance_pct < capacity_of(env->dst_cpu)*100))
			return 1;
	}

	return unlikely(sd->nr_balance_failed > sd->cache_nice_tries+2);
}

static int active_load_balance_cpu_stop(void *data);

static int should_we_balance(struct lb_env *env)
{
	/* sg指向调度域中的第一个调度组 */
	struct sched_group *sg = env->sd->groups;
	struct cpumask *sg_cpus, *sg_mask;
	int cpu, balance_cpu = -1;

	/*
	 * In the newly idle case, we will allow all the cpu's
	 * to do the newly idle load balance.
	 *
	 * 在newly idle情况下,我们将允许所有cpu进行去做newly idle负载均衡.
	 */
	if (env->idle == CPU_NEWLY_IDLE)
		return 1;

	/* 拿到该sched_group的cpu mask */
	sg_cpus = sched_group_cpus(sg);
	/* to_cpumask(sg->sgc->cpumask);
	 * 获取该调度组对应调度能力系数的数据结构(struct sched_group_capacity)中的cpumask位图,它在build_sched_groups函数里把bitmap初始化成系统所有的CPU
	 */
	sg_mask = sched_group_mask(sg);
	/* Try to find first idle cpu */
	/* 试图去找到第一个idle的cpu */
	/* 对于sg_cpus和env->cpus的与级的CPU进行轮询
	 * 也就是说查找当前调度组是否有空闲CPU(idle cpu),
	 * 如果有空闲CPU,那么变量balance_cpu记录该CPU.
	 */
	for_each_cpu_and(cpu, sg_cpus, env->cpus) {
		if (!cpumask_test_cpu(cpu, sg_mask) || !idle_cpu(cpu))
			continue;

		balance_cpu = cpu;
		break;
	}

	/* 如果没有空闲CPU,就返回该调度组里第一个CPU. */
	if (balance_cpu == -1)
		balance_cpu = group_balance_cpu(sg);

	/*
	 * First idle cpu or the first cpu(busiest) in this sched group
	 * is eligible for doing load balancing at this and above domains.
	 */
	/* 如果当前CPU是空闲CPU或者组里第一个CPU,那么当前CPU可以做负载均衡,即只有当前CPU是该调度域的第一个CPU或者当前CPU是idle CPU才可以做负载均衡.
	 * 举个例子,CPU0和CPU1同属于第一个调度域,假设CPU0和CPU1都不是idle cpu,CPU1运行load_balance(),所以不能做负载均衡,
	 * 只有CPU0运行load_balance时才可以做负载均衡,道理比较简单,就是默认约定优先由调度域中的第一个CPU做负载均衡.
	 * 假设CPU0不是空闲CPU,CPU1处于idle状态,那么CPU才可以做负载均衡
	 */
	return balance_cpu == env->dst_cpu;
}

/*
 * Check this_cpu to ensure it is balanced within domain. Attempt to move
 * tasks if there is an imbalance.
 *
 * 检查this_cpu以确保它在domain是平衡的.
 * 如果不平衡,尝试迁移tasks.
 */
static int load_balance(int this_cpu, struct rq *this_rq,
			struct sched_domain *sd, enum cpu_idle_type idle,
			int *continue_balancing)
{
	int ld_moved, cur_ld_moved, active_balance = 0;
	struct sched_domain *sd_parent = sd->parent;
	struct sched_group *group;
	struct rq *busiest;
	unsigned long flags;
	struct cpumask *cpus = this_cpu_cpumask_var_ptr(load_balance_mask);

	/* struct lb_env结构体在load_balance函数内部使用,用于传递一些重要的参数,其中,sd表示当前的调度域;
	 * dst_cpu是当前的CPU,后面可能要把一些频繁的进程迁移到该CPU上.
	 * dst_rq是当前的CPU对应的就绪队列
	 * dst_grpmask是当前调用域里的第一个调度组的CPU位图
	 * look_break本次最大迁移32个进程
	 * cpus是cpu_active_mask位图
	 * idle表示当前cpu是不是idle的
	 */
	struct lb_env env = {
		.sd		= sd,
		.dst_cpu	= this_cpu,
		.dst_rq		= this_rq,
		.dst_grpmask    = sched_group_cpus(sd->groups),
		.idle		= idle,
		.loop_break	= sched_nr_migrate_break,
		.cpus		= cpus,
		.fbq_type	= all,
		.tasks		= LIST_HEAD_INIT(env.tasks),
	};

	/*
	 * For NEWLY_IDLE load_balancing, we don't need to consider
	 * other cpus in our group
	 *
	 * 对于NEWLY_IDLE负载均衡,我们不需要考虑我们组中的其他cpu
	 */
	/* 如果本cpu为CPU_NEWLY_IDLE */
	if (idle == CPU_NEWLY_IDLE)
		env.dst_grpmask = NULL;

	/*
	 * 只在active的cpu之间做均衡,active就是非isolate和非offline的cpu
	 *
	 * 由于是第一轮均衡,sd的所有cpu都要参与,后续若发现一些异常状况,
	 * 比如affinity导致无法完成任务迁移,那么会清除选定的busiest cpu,
	 * 跳转到redo标号处进行新的一轮均衡.
	 *
	 * MC: 是一个cluster的cpu,DIE:是所有的cpu.
	 * 也就是说若传参sd是MC
	 * 层级的就只在dst cpu cluster内部均衡,若是DIE层级的就在所有cluster
	 * 的核之间均衡.
	 */
	cpumask_copy(cpus, cpu_active_mask);

	/* 对应的idle type 的 balance计数加1,在cat /proc/schedstat 中打印 */
	schedstat_inc(sd->lb_count[idle]);

redo:
	/* 对哪些cpu可以发起均衡做一个限制 */
	if (!should_we_balance(&env)) {
		/* 如果判断为不适合均衡了,那么后续更高层sd的均衡也不需要进行了,将其设置为0 */
		*continue_balancing = 0;
		goto out_balanced;
	}

	/* 在该sd中寻找最忙的sg,如果没有找到就退出本level的均衡 */
	group = find_busiest_group(&env);
	if (!group) {
		schedstat_inc(sd->lb_nobusyg[idle]);
		goto out_balanced;
	}

	/* 在找出的最忙的sg中寻找最忙的cpu,如果没有找到就退出本level的均衡 */
	busiest = find_busiest_queue(&env, group);
	if (!busiest) {
		schedstat_inc(sd->lb_nobusyq[idle]);
		goto out_balanced;
	}

	/*
	 * 至此就找到了最忙的src cpu,dst cpu就是发起均衡的cpu,至此,就可以发起第一轮负载均衡了.
	 * 找出的最忙的cpu不能是发起均衡的cpu
	 */
	BUG_ON(busiest == env.dst_rq);

	/* 增加统计计数 */
	schedstat_add(sd->lb_imbalance[idle], env.imbalance);

	/* 将找到的最忙的cpu更新到lb_env这个均衡上下文中 */
	env.src_cpu = busiest->cpu;
	env.src_rq = busiest;

	/* 要从busiest cpu迁移任务到this cpu,至少要有可拉取的任务 */
	ld_moved = 0;
	if (busiest->nr_running > 1) {
		/*
		 * Attempt to move tasks. If find_busiest_group has found
		 * an imbalance but busiest->nr_running <= 1, the group is
		 * still unbalanced. ld_moved simply stays zero, so it is
		 * correctly treated as an imbalance.
		 *
		 * 尝试移动任务. 如果find_busiest_group发现存在不平衡,但busiest->nr_running <= 1,这意味着尽管该组仍被标记为不平衡.
		 * 但实际上该组中最繁忙的CPU上运行的任务数不超过1个.
		 * 在这种情况下,ld_moved(表示移动的任务数)保持为零,但这仍然被正确地视为一种不平衡状态。
		 *
		 * 简而言之,尽管该组中最繁忙的CPU看起来并不那么繁忙(因为它上面只有一个或没有正在运行的任务),但由于与其他组相比存在某种不平衡
		 * (可能是根据其他指标,如平均负载、缓存命中率等),系统仍然会尝试进行负载均衡操作,尽管在这种情况下实际上没有任务可以被移动(ld_moved为0),
		 * 然而,这种不平衡状态本身是被识别并记录的,以便系统可以在未来进行更全面的负载均衡决策.
		 */

		/*
		 * 拉取任务之前先假定all pinned标志,若后续在can_migrate_task()中发现至少有一个任务可
		 * 以迁移到dst cpu上时就清除这个标志
		 */
		env.flags |= LBF_ALL_PINNED;
		/*
		 * loop_max就是扫描src rq上runnable任务的次数,取busiest->nr_running,但是被钳位在
		 * sysctl_sched_nr_migrate上，因为一次迁移任务不宜过多，因为关中断时间不宜过长.
		 */
		env.loop_max  = min(sysctl_sched_nr_migrate, busiest->nr_running);

more_balance:

		raw_spin_lock_irqsave(&busiest->lock, flags);

		/*
		 * cur_ld_moved - load moved in current iteration
		 * ld_moved     - cumulative load moved across iterations
		 */
		/*
		 * 至此,我们已经确定了从busiest cpu的rq中搬移若干load/util/task到dst rq.
		 * 不过无论是load还是util,最后还是要转成任务.
		 *
		 * 此函数用来从busiest cpu的rq中摘取适合的任务,并把这些任务挂入lb_env->tasks链表
		 * 中.由于关中断时长的问题,此函数也不会一次性把所有任务迁移到dest cpu上.
		 */
		cur_ld_moved = detach_tasks(&env);

		/*
		 * We've detached some tasks from busiest_rq. Every
		 * task is masked "TASK_ON_RQ_MIGRATING", so we can safely
		 * unlock busiest->lock, and we are able to be sure
		 * that nobody can manipulate the tasks in parallel.
		 * See task_rq_lock() family for the details.
		 */

		raw_spin_unlock(&busiest->lock);

		/*
		 * 将 detach_tasks()摘下的任务挂入到dst rq上去. 由于detach_tasks、attach_tasks 会
		 * 进行多轮，ld_moved 记录了总共迁移的任务数量,cur_ld_moved 是本轮迁移的任务数
		 */
		if (cur_ld_moved) {
			attach_tasks(&env);
			ld_moved += cur_ld_moved;
		}

		local_irq_restore(flags);

		/*
		 * 在任务迁移过程中,src cpu 也就是找出的最忙的那个cpu的中断是关闭的,为了降低这个关
		 * 中断的时间,迁移大量任务的时候需要break一下. 就是上面的关中断.
		 * detach_tasks 中判断扫描src rq的次数大于 env->loop_break 时置此标志位并退出它那次循环
		 */
		if (env.flags & LBF_NEED_BREAK) {
			env.flags &= ~LBF_NEED_BREAK;
			goto more_balance;
		}

		/*
		 * Revisit (affine) tasks on src_cpu that couldn't be moved to
		 * us and move them to an alternate dst_cpu in our sched_group
		 * where they can run. The upper limit on how many times we
		 * iterate on same src_cpu is dependent on number of cpus in our
		 * sched_group.
		 *
		 * This changes load balance semantics a bit on who can move
		 * load to a given_cpu. In addition to the given_cpu itself
		 * (or a ilb_cpu acting on its behalf where given_cpu is
		 * nohz-idle), we now have balance_cpu in a position to move
		 * load to given_cpu. In rare situations, this may cause
		 * conflicts (balance_cpu and given_cpu/ilb_cpu deciding
		 * _independently_ and at _same_ time to move some load to
		 * given_cpu) causing exceess load to be moved to given_cpu.
		 * This however should not happen so much in practice and
		 * moreover subsequent load balance cycles should correct the
		 * excess load moved.
		 */

		/*
		 * 至此,已经完成了对src rq上任务列表 loop_max 次的扫描,要看情况是否要发起下一轮次的均衡
		 *
		 * LBF_DST_PINNED标志是在can_migrate_task()中判断dst cpu不在任务的cpu亲和性中时设置的
		 * 上面detach_task()会一直循环直到env.imbalance<=0,否则就是有任务不能被迁移到dst cpu.
		 *
		 * 如果sd仍然未达均衡状态,并且在之前的均衡过程中,有因为affinity的原因导致任务无法迁移到dst cpu,
		 * 这时候要继续在src rq上搜索任务,迁移到备选的dst cpu,因此,这里再次发起均衡操作.
		 * 这里的均衡上下文的dst cpu改为备选的cpu,loop也被清零,重新开始扫描.
		 */
		if ((env.flags & LBF_DST_PINNED) && env.imbalance > 0) {

			/* Prevent to re-select dst_cpu via env's cpus */
			/*
			 * 将dst cpu从env.cpus中清除,避免重新被选中为dst cpu,这个被踢出去的dst cpu不会再参与接下来
			 * 有affinity限制任务的均衡了.
			 */
			cpumask_clear_cpu(env.dst_cpu, env.cpus);

			/*
			 * env.new_dst_cpu是在detach_task-->can_migrate_task()中判断赋值的,并用LBF_DST_PINNED表识有
			 * 可用new_dst_cpu,MC层级中只有dst cpu就不会赋值,只有DIE层级可能会赋值.
			 */
			env.dst_rq	 = cpu_rq(env.new_dst_cpu);
			env.dst_cpu	 = env.new_dst_cpu;
			env.flags	&= ~LBF_DST_PINNED;
			env.loop	 = 0;
			env.loop_break	 = sched_nr_migrate_break;

			/*
			 * Go back to "more_balance" rather than "redo" since we
			 * need to continue with same src_cpu.
			 */
			goto more_balance;
		}

		/*
		 * We failed to reach balance because of affinity.
		 */
		/* 若还是上次sd层级存在,说明本轮是MC层级的balance */
		if (sd_parent) {
			/* 指向DIE层级 */
			int *group_imbalance = &sd_parent->groups->sgc->imbalance;

			/*
			 * 如果本层级(MC层级)的sd以为affinity而无法达到均衡状态,需要把这个标志标记到上层sd->sg中,以便
			 * 在上层sd均衡的时候会判断该sg为imablanced,从而有更大的机会被选中为busiest group,从而解决sd的均
			 * 衡问题.
			 */
			if ((env.flags & LBF_SOME_PINNED) && env.imbalance > 0)
				*group_imbalance = 1;
		}

		/* All tasks on this runqueue were pinned by CPU affinity */
		/*
		 * 如果选中的busiest cpu的所有task都是通过affinity锁定在该cpu上,那么清除该cpu,以便下轮均衡不再考虑
		 * 该cpu. 这种情况下需要搜索新的src cpu,因此跳转到redo
		 */
		if (unlikely(env.flags & LBF_ALL_PINNED)) {
			cpumask_clear_cpu(cpu_of(busiest), cpus);
			if (!cpumask_empty(cpus)) {
				env.loop = 0;
				env.loop_break = sched_nr_migrate_break;
				goto redo;
			}
			goto out_all_pinned;
		}
	}
	/*
	 * 至此,src rq上cfs任务链表已经被遍历(也可能被遍历多次),基本上对runnable任务的扫描已经到位了,如果还
	 * 不行就只能考虑running task了,代码如下:
	 */
	if (!ld_moved) {
		schedstat_inc(sd->lb_failed[idle]);
		/*
		 * Increment the failure counter only on periodic balance.
		 * We do not want newidle balance, which can be very
		 * frequent, pollute the failure counter causing
		 * excessive cache_hot migrations and active balances.
		 */
		/*
		 * 经过上面一系列的操作但没有完成任何任务迁移,那么就累加均衡失败的计数,此计数会导致后续更激进的均衡,
		 * 比如迁移cache hot任务、启动active balance.
		 * 这里过滤掉new idle banlance只统计周期banlance的,因为new idle balnace次数太多,累计其失败次数会导致
		 * nr_balance_failed 过大,很容易触发更激进的均衡.
		 */
		if (idle != CPU_NEWLY_IDLE)
			sd->nr_balance_failed++;

		/*
		 * 判断是否需要启动active balance,就是判断是否需要将src cpu当前正在running的任务迁移到dst cpu,因为前面一番
		 * 折腾后发现无法迁移runnable的任务,那么就再考虑一下running的任务
		 */
		if (need_active_balance(&env)) {
			raw_spin_lock_irqsave(&busiest->lock, flags);

			/* don't kick the active_load_balance_cpu_stop,
			 * if the curr task on busiest cpu can't be
			 * moved to this_cpu
			 */

			/* 尝试迁移前先判断一下src cpu上当前running的任务是否由于亲和性不能迁移到dst cpu. */
			if (!cpumask_test_cpu(this_cpu,
					tsk_cpus_allowed(busiest->curr))) {
				raw_spin_unlock_irqrestore(&busiest->lock,
							    flags);
				env.flags |= LBF_ALL_PINNED;
				goto out_one_pinned;
			}

			/*
			 * ->active_balance synchronizes accesses to
			 * ->active_balance_work.  Once set, it's cleared
			 * only after active load balance is finished.
			 */

			/* 在busiest rq上设置active_balance标记 */
			if (!busiest->active_balance) {
				busiest->active_balance = 1;
				busiest->push_cpu = this_cpu;
				active_balance = 1;
			}
			raw_spin_unlock_irqrestore(&busiest->lock, flags);

			if (active_balance) {
				/*
				 * 就是向busiest cpu的stop调度类的"migration/X"线程queue一个work,然后唤醒它,执行流程为
				 * per-cpu cpu_stopper.thread --> smpboot_thread_fn --> cpu_stopper_thread --> fn(arg) --> active_load_balance_cpu_stop(busiest rq)
				 */
				stop_one_cpu_nowait(cpu_of(busiest),
					active_load_balance_cpu_stop, busiest,
					&busiest->active_balance_work);
			}

			/* We've kicked active balancing, force task migration. */
			sd->nr_balance_failed = sd->cache_nice_tries+1;
		}
	} else  //至少完成了一个任务的迁移,重置均衡失败的计数
		sd->nr_balance_failed = 0;

	if (likely(!active_balance)) {
		/* We were unbalanced, so reset the balancing interval */
		sd->balance_interval = sd->min_interval;
	} else {
		/*
		 * If we've begun active balancing, start to back off. This
		 * case may not be covered by the all_pinned logic if there
		 * is only 1 task on the busy runqueue (because we don't call
		 * detach_tasks).
		 */
		if (sd->balance_interval < sd->max_interval)
			sd->balance_interval *= 2;
	}

	goto out;

/* 判断不适合均衡,没有找到最忙的rq都会跳转到这里 */
out_balanced:
	/*
	 * We reach balance although we may have faced some affinity
	 * constraints. Clear the imbalance flag if it was set.
	 *
	 * 翻译: 尽管我们可能面临一些亲和力限制,但我们达到了平衡.
	 * 仅当其他任务有机会移动并修复不平衡时才清除不平衡标志.
	 *
	 * 只有此次均衡sd是MC层级的,sd_parent才存在.
	 * 跳转到这里时LBF_ALL_PINNED还没有机会被赋值上呢
	 */
	if (sd_parent) {
		int *group_imbalance = &sd_parent->groups->sgc->imbalance;

		/* 这里MC层级的均衡,只要不是all pinned,又将其清除了 */
		if (*group_imbalance)
			*group_imbalance = 0;
	}

/* 在判断busiest cpu上由于亲和性没有一个任务可以迁移到dst cpu上时就跳到这里: */
out_all_pinned:
	/*
	 * We reach balance because all tasks are pinned at this level so
	 * we can't migrate them. Let the imbalance flag set so parent level
	 * can try to migrate them.
	 */
	schedstat_inc(sd->lb_balanced[idle]);

	sd->nr_balance_failed = 0;

/* 最后的active balance发现src cpu上running的任务由于亲和性也不能迁移到dst cpu上就跳转到这里 */
out_one_pinned:
	/* tune up the balancing interval */
	if (((env.flags & LBF_ALL_PINNED) &&
			sd->balance_interval < MAX_PINNED_INTERVAL) ||
			(sd->balance_interval < sd->max_interval))
		sd->balance_interval *= 2;

	ld_moved = 0;
out:
	return ld_moved;
}

static inline unsigned long
get_sd_balance_interval(struct sched_domain *sd, int cpu_busy)
{
	/* balance_interval定义了均衡的时间间隔,这边就是去得到时间间隔 */
	unsigned long interval = sd->balance_interval;

	/* 如果cpu不是idle的,那么设置间隔为busy_factor * interval */
	if (cpu_busy)
		interval *= sd->busy_factor;

	/* scale ms to jiffies */
	/* 将毫秒转换成jiffies */
	interval = msecs_to_jiffies(interval);
	/* 让interval落在1 ~ max_load_balanced_interval之间 */
	interval = clamp(interval, 1UL, max_load_balance_interval);

	return interval;
}

static inline void
update_next_balance(struct sched_domain *sd, unsigned long *next_balance)
{
	unsigned long interval, next;

	/* used by idle balance, so cpu_busy = 0 */
	interval = get_sd_balance_interval(sd, 0);
	next = sd->last_balance + interval;

	if (time_after(*next_balance, next))
		*next_balance = next;
}

/*
 * idle_balance is called by schedule() if this_cpu is about to become
 * idle. Attempts to pull tasks from other CPUs.
 */
static int idle_balance(struct rq *this_rq)
{
	unsigned long next_balance = jiffies + HZ;
	int this_cpu = this_rq->cpu;
	struct sched_domain *sd;
	int pulled_task = 0;
	u64 curr_cost = 0;

	/*
	 * We must set idle_stamp _before_ calling idle_balance(), such that we
	 * measure the duration of idle_balance() as idle time.
	 */
	this_rq->idle_stamp = rq_clock(this_rq);

	if (this_rq->avg_idle < sysctl_sched_migration_cost ||
	    !this_rq->rd->overload) {
		rcu_read_lock();
		sd = rcu_dereference_check_sched_domain(this_rq->sd);
		if (sd)
			update_next_balance(sd, &next_balance);
		rcu_read_unlock();

		goto out;
	}

	raw_spin_unlock(&this_rq->lock);
	/* 更新运行队列rq的lock、衰减的负载 */
	update_blocked_averages(this_cpu);
	rcu_read_lock();
	/* for循环从当前CPU开始从下到上遍历调度域 */
	for_each_domain(this_cpu, sd) {
		int continue_balancing = 1;
		u64 t0, domain_cost;
		/* 如果该调度域里没有设置SD_LOAD_BALANCE,表示该调度域不需要做负载均衡,那么跳过该调度域 */
		if (!(sd->flags & SD_LOAD_BALANCE))
			continue;

		/* 更新在这个domain上的最大newidle balance时间长度max_newidle_ld_cost.
		 * max_newidle_lb_cost是sched domain上的最大newidle load balance的开销.
		 * 这个开销会随着时间进行衰减,每1秒衰减1%.
		 */
		if (this_rq->avg_idle < curr_cost + sd->max_newidle_lb_cost) {
			update_next_balance(sd, &next_balance);
			break;
		}

		if (sd->flags & SD_BALANCE_NEWIDLE) {
			t0 = sched_clock_cpu(this_cpu);

			pulled_task = load_balance(this_cpu, this_rq,
						   sd, CPU_NEWLY_IDLE,
						   &continue_balancing);

			domain_cost = sched_clock_cpu(this_cpu) - t0;
			if (domain_cost > sd->max_newidle_lb_cost)
				sd->max_newidle_lb_cost = domain_cost;

			curr_cost += domain_cost;
		}

		update_next_balance(sd, &next_balance);

		/*
		 * Stop searching for tasks to pull if there are
		 * now runnable tasks on this rq.
		 */
		if (pulled_task || this_rq->nr_running > 0)
			break;
	}
	rcu_read_unlock();

	raw_spin_lock(&this_rq->lock);

	if (curr_cost > this_rq->max_idle_balance_cost)
		this_rq->max_idle_balance_cost = curr_cost;

	/*
	 * While browsing the domains, we released the rq lock, a task could
	 * have been enqueued in the meantime. Since we're not going idle,
	 * pretend we pulled a task.
	 */
	if (this_rq->cfs.h_nr_running && !pulled_task)
		pulled_task = 1;

out:
	/* Move the next balance forward */
	if (time_after(this_rq->next_balance, next_balance))
		this_rq->next_balance = next_balance;

	/* Is there a task of a high priority class? */
	if (this_rq->nr_running != this_rq->cfs.h_nr_running)
		pulled_task = -1;

	if (pulled_task)
		this_rq->idle_stamp = 0;

	return pulled_task;
}

/*
 * active_load_balance_cpu_stop is run by cpu stopper. It pushes
 * running tasks off the busiest CPU onto idle CPUs. It requires at
 * least 1 task to be running on each physical CPU where possible, and
 * avoids physical / logical imbalances.
 */
static int active_load_balance_cpu_stop(void *data)
{
	struct rq *busiest_rq = data;
	int busiest_cpu = cpu_of(busiest_rq);
	int target_cpu = busiest_rq->push_cpu;
	struct rq *target_rq = cpu_rq(target_cpu);
	struct sched_domain *sd;
	struct task_struct *p = NULL;

	raw_spin_lock_irq(&busiest_rq->lock);

	/* make sure the requested cpu hasn't gone down in the meantime */
	if (unlikely(busiest_cpu != smp_processor_id() ||
		     !busiest_rq->active_balance))
		goto out_unlock;

	/* Is there any task to move? */
	if (busiest_rq->nr_running <= 1)
		goto out_unlock;

	/*
	 * This condition is "impossible", if it occurs
	 * we need to fix it. Originally reported by
	 * Bjorn Helgaas on a 128-cpu setup.
	 */
	BUG_ON(busiest_rq == target_rq);

	/* Search for an sd spanning us and the target CPU. */
	rcu_read_lock();
	for_each_domain(target_cpu, sd) {
		if ((sd->flags & SD_LOAD_BALANCE) &&
		    cpumask_test_cpu(busiest_cpu, sched_domain_span(sd)))
				break;
	}

	if (likely(sd)) {
		struct lb_env env = {
			.sd		= sd,
			.dst_cpu	= target_cpu,
			.dst_rq		= target_rq,
			.src_cpu	= busiest_rq->cpu,
			.src_rq		= busiest_rq,
			.idle		= CPU_IDLE,
		};

		schedstat_inc(sd->alb_count);

		p = detach_one_task(&env);
		if (p) {
			schedstat_inc(sd->alb_pushed);
			/* Active balancing done, reset the failure counter. */
			sd->nr_balance_failed = 0;
		} else {
			schedstat_inc(sd->alb_failed);
		}
	}
	rcu_read_unlock();
out_unlock:
	busiest_rq->active_balance = 0;
	raw_spin_unlock(&busiest_rq->lock);

	if (p)
		attach_one_task(target_rq, p);

	local_irq_enable();

	return 0;
}

static inline int on_null_domain(struct rq *rq)
{
	return unlikely(!rcu_dereference_sched(rq->sd));
}

#ifdef CONFIG_NO_HZ_COMMON
/*
 * idle load balancing details
 * - When one of the busy CPUs notice that there may be an idle rebalancing
 *   needed, they will kick the idle load balancer, which then does idle
 *   load balancing for all the idle CPUs.
 */
static struct {
	cpumask_var_t idle_cpus_mask;
	atomic_t nr_cpus;
	unsigned long next_balance;     /* in jiffy units */
} nohz ____cacheline_aligned;

static inline int find_new_ilb(void)
{
	int ilb = cpumask_first(nohz.idle_cpus_mask);

	if (ilb < nr_cpu_ids && idle_cpu(ilb))
		return ilb;

	return nr_cpu_ids;
}

/*
 * Kick a CPU to do the nohz balancing, if it is time for it. We pick the
 * nohz_load_balancer CPU (if there is one) otherwise fallback to any idle
 * CPU (if there is one).
 */
static void nohz_balancer_kick(void)
{
	int ilb_cpu;

	nohz.next_balance++;

	ilb_cpu = find_new_ilb();

	if (ilb_cpu >= nr_cpu_ids)
		return;

	if (test_and_set_bit(NOHZ_BALANCE_KICK, nohz_flags(ilb_cpu)))
		return;
	/*
	 * Use smp_send_reschedule() instead of resched_cpu().
	 * This way we generate a sched IPI on the target cpu which
	 * is idle. And the softirq performing nohz idle load balance
	 * will be run before returning from the IPI.
	 */
	smp_send_reschedule(ilb_cpu);
	return;
}

void nohz_balance_exit_idle(unsigned int cpu)
{
	if (unlikely(test_bit(NOHZ_TICK_STOPPED, nohz_flags(cpu)))) {
		/*
		 * Completely isolated CPUs don't ever set, so we must test.
		 */
		if (likely(cpumask_test_cpu(cpu, nohz.idle_cpus_mask))) {
			cpumask_clear_cpu(cpu, nohz.idle_cpus_mask);
			atomic_dec(&nohz.nr_cpus);
		}
		clear_bit(NOHZ_TICK_STOPPED, nohz_flags(cpu));
	}
}

static inline void set_cpu_sd_state_busy(void)
{
	struct sched_domain *sd;
	int cpu = smp_processor_id();

	rcu_read_lock();
	sd = rcu_dereference(per_cpu(sd_llc, cpu));

	if (!sd || !sd->nohz_idle)
		goto unlock;
	sd->nohz_idle = 0;

	atomic_inc(&sd->shared->nr_busy_cpus);
unlock:
	rcu_read_unlock();
}

void set_cpu_sd_state_idle(void)
{
	struct sched_domain *sd;
	int cpu = smp_processor_id();

	rcu_read_lock();
	sd = rcu_dereference(per_cpu(sd_llc, cpu));

	if (!sd || sd->nohz_idle)
		goto unlock;
	sd->nohz_idle = 1;

	atomic_dec(&sd->shared->nr_busy_cpus);
unlock:
	rcu_read_unlock();
}

/*
 * This routine will record that the cpu is going idle with tick stopped.
 * This info will be used in performing idle load balancing in the future.
 */
void nohz_balance_enter_idle(int cpu)
{
	/*
	 * If this cpu is going down, then nothing needs to be done.
	 */
	if (!cpu_active(cpu))
		return;

	if (test_bit(NOHZ_TICK_STOPPED, nohz_flags(cpu)))
		return;

	/*
	 * If we're a completely isolated CPU, we don't play.
	 */
	if (on_null_domain(cpu_rq(cpu)))
		return;

	cpumask_set_cpu(cpu, nohz.idle_cpus_mask);
	atomic_inc(&nohz.nr_cpus);
	set_bit(NOHZ_TICK_STOPPED, nohz_flags(cpu));
}
#endif

static DEFINE_SPINLOCK(balancing);

/*
 * Scale the max load_balance interval with the number of CPUs in the system.
 * This trades load-balance latency on larger machines for less cross talk.
 */
void update_max_interval(void)
{
	max_load_balance_interval = HZ*num_online_cpus()/10;
}

/*
 * It checks each scheduling domain to see if it is due to be balanced,
 * and initiates a balancing operation if so.
 *
 * Balancing parameters are set up in init_sched_domains.
 *
 * 它检查每个调度域是否要进行平衡,如果是,则启动平衡操作。
 *
 * 平衡参数在init_sched_domains中设置.
 */

/* rebalance_domains有两个参数,rq表示当前CPU的通用就绪队列.
 * 如果当前CPU是idle cpu,idle参数为CPU_IDLE,否则为CPU_NOT_IDLE.
 */
static void rebalance_domains(struct rq *rq, enum cpu_idle_type idle)
{
	int continue_balancing = 1;
	/* 拿到该CPU所在的CPU */
	int cpu = rq->cpu;
	unsigned long interval;
	struct sched_domain *sd;
	/* Earliest time when we have to do rebalance again
	 * 我们必须再次重新平衡的最早时间
	 */
	unsigned long next_balance = jiffies + 60*HZ;
	int update_next_balance = 0;
	int need_serialize, need_decay = 0;
	u64 max_cost = 0;

	/* 更新运行队列rq的lock、衰减的负载 */
	update_blocked_averages(cpu);

	rcu_read_lock();
	/* for循环从当前CPU开始从下到上遍历调度域 */
	for_each_domain(cpu, sd) {
		/*
		 * Decay the newidle max times here because this is a regular
		 * visit to all the domains. Decay ~1% per second.
		 *
		 * 在此处衰减newidle最大时间,因为这是对所有域的定期访问.每秒衰减约1%.
		 *
		 * next_decay_max_lb_cost: max_newidle_lb_cost会记录最近在该sched domain上进行newidle balance的最大时间长度,
		 * 这个max cost不是一成不变的,它有一个衰减过程,每秒衰减1%,这个成员就是用来控制衰减的.
		 *
		 * max_newidle_lb_cost: 在该domain上进行newidle balance的最大时间长度(即newidle balance的开销).
		 * 每次在该domain上进行newidle balance的时候都会记录时长,然后把最大值记录在这个成员中.
		 * 这个值会随着时间衰减,防止一次极值会造成永久的影响.
		 */

		/* max_newidle_lb_cost是做load balance所花时间.如上面注释所说,max_newidle_lb_cost每个1s衰减1%
		 * next_decay_max_lb_cost 是下一次进行衰减的时间.
		 * 老化公式: new = old * (253/256)
		 */
		/* 也就是说现在的时间比next_decay_max_lb_cost还要大,那么就对max_newidle_lb_cost衰减 */
		if (time_after(jiffies, sd->next_decay_max_lb_cost)) {
			/* new = old * (253/256) */
			sd->max_newidle_lb_cost =
				(sd->max_newidle_lb_cost * 253) / 256;
			/* 设置next_decay_max_lb_cost为jiffies + HZ */
			sd->next_decay_max_lb_cost = jiffies + HZ;
			/* 设置need_decay等于1 */
			need_decay = 1;
		}
		/* 然后让max_cost加上sd->max_newidle_lb_cost */
		max_cost += sd->max_newidle_lb_cost;

		/* 如果该调度域没有设置SD_LOAD_BALANCE标志
		 * 表示此调度域不需要做负载均衡,那么跳过该调度域.
		 */
		if (!(sd->flags & SD_LOAD_BALANCE))
			continue;

		/*
		 * Stop the load balance at this level. There is another
		 * CPU in our sched group which is doing load balancing more
		 * actively.
		 *
		 * 将负载均衡停止在此层. 我们的调度组中还有另一个CPU正在更积极地进行负载平衡.
		 */
		/* 如果continue_balancing设置为了false,也就是说要停止了,那么如果need_decay(需要衰减)设置为了1
		 * 那么continue,否则就break
		 */
		if (!continue_balancing) {
			if (need_decay)
				continue;
			break;
		}

		/* 拿到该sched_domain的balance_interval */
		interval = get_sd_balance_interval(sd, idle != CPU_IDLE);

		/* 如果说sd需要串行话,也就是sd->flags带了SD_SERIALIZE,那么设置need_serialize等于true */
		need_serialize = sd->flags & SD_SERIALIZE;
		if (need_serialize) {
			/* 如果需要串行话,那么就去拿到锁,如果拿不到那么就goto out */
			if (!spin_trylock(&balancing))
				goto out;
		}
		/* 如果说到了做balance的时间(也就是说jiffies大于等于上次做balance的时间 + 时间间隔),那么就要做balance了 */
		if (time_after_eq(jiffies, sd->last_balance + interval)) {
			if (load_balance(cpu, rq, sd, idle, &continue_balancing)) {
				/*
				 * The LBF_DST_PINNED logic could have changed
				 * env->dst_cpu, so we can't know our idle
				 * state even if we migrated tasks. Update it.
				 */
				idle = idle_cpu(cpu) ? CPU_IDLE : CPU_NOT_IDLE;
			}
			sd->last_balance = jiffies;
			interval = get_sd_balance_interval(sd, idle != CPU_IDLE);
		}
		if (need_serialize)
			spin_unlock(&balancing);
out:
		if (time_after(next_balance, sd->last_balance + interval)) {
			next_balance = sd->last_balance + interval;
			update_next_balance = 1;
		}
	}
	if (need_decay) {
		/*
		 * Ensure the rq-wide value also decays but keep it at a
		 * reasonable floor to avoid funnies with rq->avg_idle.
		 */
		rq->max_idle_balance_cost =
			max((u64)sysctl_sched_migration_cost, max_cost);
	}
	rcu_read_unlock();

	/*
	 * next_balance will be updated only when there is a need.
	 * When the cpu is attached to null domain for ex, it will not be
	 * updated.
	 */
	if (likely(update_next_balance)) {
		rq->next_balance = next_balance;

#ifdef CONFIG_NO_HZ_COMMON
		/*
		 * If this CPU has been elected to perform the nohz idle
		 * balance. Other idle CPUs have already rebalanced with
		 * nohz_idle_balance() and nohz.next_balance has been
		 * updated accordingly. This CPU is now running the idle load
		 * balance for itself and we need to update the
		 * nohz.next_balance accordingly.
		 */
		if ((idle == CPU_IDLE) && time_after(nohz.next_balance, rq->next_balance))
			nohz.next_balance = rq->next_balance;
#endif
	}
}

#ifdef CONFIG_NO_HZ_COMMON
/*
 * In CONFIG_NO_HZ_COMMON case, the idle balance kickee will do the
 * rebalancing for all the cpus for whom scheduler ticks are stopped.
 */
static void nohz_idle_balance(struct rq *this_rq, enum cpu_idle_type idle)
{
	int this_cpu = this_rq->cpu;
	struct rq *rq;
	int balance_cpu;
	/* Earliest time when we have to do rebalance again */
	unsigned long next_balance = jiffies + 60*HZ;
	int update_next_balance = 0;

	if (idle != CPU_IDLE ||
	    !test_bit(NOHZ_BALANCE_KICK, nohz_flags(this_cpu)))
		goto end;

	for_each_cpu(balance_cpu, nohz.idle_cpus_mask) {
		if (balance_cpu == this_cpu || !idle_cpu(balance_cpu))
			continue;

		/*
		 * If this cpu gets work to do, stop the load balancing
		 * work being done for other cpus. Next load
		 * balancing owner will pick it up.
		 */
		if (need_resched())
			break;

		rq = cpu_rq(balance_cpu);

		/*
		 * If time for next balance is due,
		 * do the balance.
		 */
		if (time_after_eq(jiffies, rq->next_balance)) {
			raw_spin_lock_irq(&rq->lock);
			update_rq_clock(rq);
			cpu_load_update_idle(rq);
			raw_spin_unlock_irq(&rq->lock);
			rebalance_domains(rq, CPU_IDLE);
		}

		if (time_after(next_balance, rq->next_balance)) {
			next_balance = rq->next_balance;
			update_next_balance = 1;
		}
	}

	/*
	 * next_balance will be updated only when there is a need.
	 * When the CPU is attached to null domain for ex, it will not be
	 * updated.
	 */
	if (likely(update_next_balance))
		nohz.next_balance = next_balance;
end:
	clear_bit(NOHZ_BALANCE_KICK, nohz_flags(this_cpu));
}

/*
 * Current heuristic for kicking the idle load balancer in the presence
 * of an idle cpu in the system.
 *   - This rq has more than one task.
 *   - This rq has at least one CFS task and the capacity of the CPU is
 *     significantly reduced because of RT tasks or IRQs.
 *   - At parent of LLC scheduler domain level, this cpu's scheduler group has
 *     multiple busy cpu.
 *   - For SD_ASYM_PACKING, if the lower numbered cpu's in the scheduler
 *     domain span are idle.
 */
static inline bool nohz_kick_needed(struct rq *rq)
{
	unsigned long now = jiffies;
	struct sched_domain_shared *sds;
	struct sched_domain *sd;
	int nr_busy, cpu = rq->cpu;
	bool kick = false;

	if (unlikely(rq->idle_balance))
		return false;

       /*
	* We may be recently in ticked or tickless idle mode. At the first
	* busy tick after returning from idle, we will update the busy stats.
	*/
	set_cpu_sd_state_busy();
	nohz_balance_exit_idle(cpu);

	/*
	 * None are in tickless mode and hence no need for NOHZ idle load
	 * balancing.
	 */
	if (likely(!atomic_read(&nohz.nr_cpus)))
		return false;

	if (time_before(now, nohz.next_balance))
		return false;

	if (rq->nr_running >= 2)
		return true;

	rcu_read_lock();
	sds = rcu_dereference(per_cpu(sd_llc_shared, cpu));
	if (sds) {
		/*
		 * XXX: write a coherent comment on why we do this.
		 * See also: http://lkml.kernel.org/r/20111202010832.602203411@sbsiddha-desk.sc.intel.com
		 */
		nr_busy = atomic_read(&sds->nr_busy_cpus);
		if (nr_busy > 1) {
			kick = true;
			goto unlock;
		}

	}

	sd = rcu_dereference(rq->sd);
	if (sd) {
		if ((rq->cfs.h_nr_running >= 1) &&
				check_cpu_capacity(rq, sd)) {
			kick = true;
			goto unlock;
		}
	}

	sd = rcu_dereference(per_cpu(sd_asym, cpu));
	if (sd && (cpumask_first_and(nohz.idle_cpus_mask,
				  sched_domain_span(sd)) < cpu)) {
		kick = true;
		goto unlock;
	}

unlock:
	rcu_read_unlock();
	return kick;
}
#else
static void nohz_idle_balance(struct rq *this_rq, enum cpu_idle_type idle) { }
#endif

/*
 * run_rebalance_domains is triggered when needed from the scheduler tick.
 * Also triggered for nohz idle balancing (with nohz_balancing_kick set).
 *
 * run_rebalance_domains在scheduler tick需要时触发.
 * 还触发了nohz idle balancing(设置了nohz_balancing_kick).
 */
static __latent_entropy void run_rebalance_domains(struct softirq_action *h)
{
	/* 拿到本cpu的rq */
	struct rq *this_rq = this_rq();
	/* 判断当前rq是否是idle */
	enum cpu_idle_type idle = this_rq->idle_balance ?
						CPU_IDLE : CPU_NOT_IDLE;

	/*
	 * If this cpu has a pending nohz_balance_kick, then do the
	 * balancing on behalf of the other idle cpus whose ticks are
	 * stopped. Do nohz_idle_balance *before* rebalance_domains to
	 * give the idle cpus a chance to load balance. Else we may
	 * load balance only within the local sched_domain hierarchy
	 * and abort nohz_idle_balance altogether if we pull some load.
	 *
	 * 如果此cpu有一个挂起的nohz_balance_ick,则代表其ticks停止的其他空闲cpu进行平衡.
	 * 在*重新平衡域之前执行nohz_idle_balance*.
	 * 给空闲的cpu一个负载平衡的机会.
	 * 否则,我们可能只在本地sched_domain层次结构内进行负载平衡,如果我们拉取一些负载,则完全中止nohz_idle_balance.
	 */
	nohz_idle_balance(this_rq, idle);
	rebalance_domains(this_rq, idle);
}

/*
 * Trigger the SCHED_SOFTIRQ if it is time to do periodic load balancing.
 */
void trigger_load_balance(struct rq *rq)
{
	/* Don't need to rebalance while attached to NULL domain */
	if (unlikely(on_null_domain(rq)))
		return;

	if (time_after_eq(jiffies, rq->next_balance))
		raise_softirq(SCHED_SOFTIRQ);
#ifdef CONFIG_NO_HZ_COMMON
	if (nohz_kick_needed(rq))
		nohz_balancer_kick();
#endif
}

static void rq_online_fair(struct rq *rq)
{
	update_sysctl();

	update_runtime_enabled(rq);
}

static void rq_offline_fair(struct rq *rq)
{
	update_sysctl();

	/* Ensure any throttled groups are reachable by pick_next_task */
	unthrottle_offline_cfs_rqs(rq);
}

#endif /* CONFIG_SMP */

/*
 * scheduler tick hitting a task of our scheduling class:
 *
 * 调度器勾选了我们调度类的task:
 */
static void task_tick_fair(struct rq *rq, struct task_struct *curr, int queued)
{
	struct cfs_rq *cfs_rq;
	/* 拿到当前运行的task_struct的sched_entity */
	struct sched_entity *se = &curr->se;

	for_each_sched_entity(se) {
		/* 拿到该sched_entity的cfs_rq */
		cfs_rq = cfs_rq_of(se);
		/* 调用entity_tick检查是否需要调度 */
		entity_tick(cfs_rq, se, queued);
	}

	if (static_branch_unlikely(&sched_numa_balancing))
		task_tick_numa(rq, curr);
}

/*
 * called on fork with the child task as argument from the parent's context
 *  - child not yet on the tasklist
 *  - preemption disabled
 */
/* task_fork_fair函数的参数p表示新创建的进程.
 * 进程task_struct数据结构中内嵌了调度实体struct sched_entity结构体,
 * 因此由task_struct可以得到该进程的调度实体.
 */
static void task_fork_fair(struct task_struct *p)
{
	struct cfs_rq *cfs_rq;
	struct sched_entity *se = &p->se, *curr;
	/* 拿到当前CPU的就绪队列数据结构struct rq */
	struct rq *rq = this_rq();

	raw_spin_lock(&rq->lock);
	update_rq_clock(rq);
	/* 由current变量取得当前进程对应的CFS调度器就绪队列的数据结构(cfs_rq) */
	cfs_rq = task_cfs_rq(current);
	/* 拿到当前cfs_rq正在运行的进程的sched_entity */
	curr = cfs_rq->curr;
	if (curr) {
		/* update_curr是CFS调度器中比较核心的函数 */
		update_curr(cfs_rq);
		/* 这里会设置se->runtime为curr->vruntime,因为此时的crru已经是vruntime最小的了
		 * 后面还有个惩罚可以给它
		 */
		se->vruntime = curr->vruntime;
	}

	/* 新创建的进程会得到惩罚,惩罚的时间根据新进程的权重由sched_vslice函数计算虚拟时间.
	 * 最后新进程调度实体的虚拟时间是在调度实体的实际虚拟时间和CFS运行队列中min_vruntime取最大值
	 */
	place_entity(cfs_rq, se, 1);
	/* 如果设置了sysctl_sched_child_runs_first,代表fork之后子进程先运行
	 * 这里如果sysctl_sched_child_runs_first被置位了
	 * 并且curr不为空
	 * 并且
	 * static inline int entity_before(struct sched_entity *a,
	 *				   struct sched_entity *b)
	 * {
	 *	return (s64)(a->vruntime - b->vruntime) < 0;
	 * }
	 * 也就是parent的vruntime比子进程的要小
	 */
	if (sysctl_sched_child_runs_first && curr && entity_before(curr, se)) {
		/*
		 * Upon rescheduling, sched_class::put_prev_task() will place
		 * 'current' within the tree based on its new key value.
		 *
		 * 重新调度后,sched_class::put_prev_task()将根据其新键值在树中放置“current”.
		 */
		/* 把父子进程的给换过来 */
		swap(curr->vruntime, se->vruntime);
		/* 设置当前进程的TIF_NEED_RESCHED,方便在返回到用户空间的时候抢占父进程 */
		resched_curr(rq);
	}

	/* 在place_entity函数计算得到的se->vruntime要减去min_vruntime?
	 * 难道不用担心该vruntime变得很小会恶意占用调度器吗?
	 * 新进程还没有加入到调度器中,加入调度器时会重新增加min_vruntime值.
	 * 换个角度来思考,新进程在place_entity函数中得到了一些惩罚,惩罚的虚拟实践由sched_vslice计算,
	 * 在某种程度上也是为了防止新进程恶意占用CPU时间
	 */
	se->vruntime -= cfs_rq->min_vruntime;
	raw_spin_unlock(&rq->lock);
}

/*
 * Priority of the task has changed. Check to see if we preempt
 * the current task.
 */
static void
prio_changed_fair(struct rq *rq, struct task_struct *p, int oldprio)
{
	if (!task_on_rq_queued(p))
		return;

	/*
	 * Reschedule if we are currently running on this runqueue and
	 * our priority decreased, or if we are not currently running on
	 * this runqueue and our priority is higher than the current's
	 */
	if (rq->curr == p) {
		if (p->prio > oldprio)
			resched_curr(rq);
	} else
		check_preempt_curr(rq, p, 0);
}

static inline bool vruntime_normalized(struct task_struct *p)
{
	struct sched_entity *se = &p->se;

	/*
	 * In both the TASK_ON_RQ_QUEUED and TASK_ON_RQ_MIGRATING cases,
	 * the dequeue_entity(.flags=0) will already have normalized the
	 * vruntime.
	 */
	if (p->on_rq)
		return true;

	/*
	 * When !on_rq, vruntime of the task has usually NOT been normalized.
	 * But there are some cases where it has already been normalized:
	 *
	 * - A forked child which is waiting for being woken up by
	 *   wake_up_new_task().
	 * - A task which has been woken up by try_to_wake_up() and
	 *   waiting for actually being woken up by sched_ttwu_pending().
	 */
	if (!se->sum_exec_runtime || p->state == TASK_WAKING)
		return true;

	return false;
}

static void detach_task_cfs_rq(struct task_struct *p)
{
	struct sched_entity *se = &p->se;
	struct cfs_rq *cfs_rq = cfs_rq_of(se);
	u64 now = cfs_rq_clock_task(cfs_rq);

	if (!vruntime_normalized(p)) {
		/*
		 * Fix up our vruntime so that the current sleep doesn't
		 * cause 'unlimited' sleep bonus.
		 */
		place_entity(cfs_rq, se, 0);
		se->vruntime -= cfs_rq->min_vruntime;
	}

	/* Catch up with the cfs_rq and remove our load when we leave */
	update_cfs_rq_load_avg(now, cfs_rq, false);
	detach_entity_load_avg(cfs_rq, se);
	update_tg_load_avg(cfs_rq, false);
}

static void attach_task_cfs_rq(struct task_struct *p)
{
	struct sched_entity *se = &p->se;
	struct cfs_rq *cfs_rq = cfs_rq_of(se);
	u64 now = cfs_rq_clock_task(cfs_rq);

#ifdef CONFIG_FAIR_GROUP_SCHED
	/*
	 * Since the real-depth could have been changed (only FAIR
	 * class maintain depth value), reset depth properly.
	 */
	se->depth = se->parent ? se->parent->depth + 1 : 0;
#endif

	/* Synchronize task with its cfs_rq */
	update_cfs_rq_load_avg(now, cfs_rq, false);
	attach_entity_load_avg(cfs_rq, se);
	update_tg_load_avg(cfs_rq, false);

	if (!vruntime_normalized(p))
		se->vruntime += cfs_rq->min_vruntime;
}

static void switched_from_fair(struct rq *rq, struct task_struct *p)
{
	detach_task_cfs_rq(p);
}

static void switched_to_fair(struct rq *rq, struct task_struct *p)
{
	attach_task_cfs_rq(p);

	if (task_on_rq_queued(p)) {
		/*
		 * We were most likely switched from sched_rt, so
		 * kick off the schedule if running, otherwise just see
		 * if we can still preempt the current task.
		 */
		if (rq->curr == p)
			resched_curr(rq);
		else
			check_preempt_curr(rq, p, 0);
	}
}

/* Account for a task changing its policy or group.
 *
 * This routine is mostly called to set cfs_rq->curr field when a task
 * migrates between groups/classes.
 */
static void set_curr_task_fair(struct rq *rq)
{
	struct sched_entity *se = &rq->curr->se;

	for_each_sched_entity(se) {
		struct cfs_rq *cfs_rq = cfs_rq_of(se);

		set_next_entity(cfs_rq, se);
		/* ensure bandwidth has been allocated on our new cfs_rq */
		account_cfs_rq_runtime(cfs_rq, 0);
	}
}

void init_cfs_rq(struct cfs_rq *cfs_rq)
{
	cfs_rq->tasks_timeline = RB_ROOT;
	cfs_rq->min_vruntime = (u64)(-(1LL << 20));
#ifndef CONFIG_64BIT
	cfs_rq->min_vruntime_copy = cfs_rq->min_vruntime;
#endif
#ifdef CONFIG_SMP
	atomic_long_set(&cfs_rq->removed_load_avg, 0);
	atomic_long_set(&cfs_rq->removed_util_avg, 0);
#endif
}

#ifdef CONFIG_FAIR_GROUP_SCHED
static void task_set_group_fair(struct task_struct *p)
{
	struct sched_entity *se = &p->se;

	set_task_rq(p, task_cpu(p));
	se->depth = se->parent ? se->parent->depth + 1 : 0;
}

static void task_move_group_fair(struct task_struct *p)
{
	detach_task_cfs_rq(p);
	set_task_rq(p, task_cpu(p));

#ifdef CONFIG_SMP
	/* Tell se's cfs_rq has been changed -- migrated */
	p->se.avg.last_update_time = 0;
#endif
	attach_task_cfs_rq(p);
}

static void task_change_group_fair(struct task_struct *p, int type)
{
	switch (type) {
	case TASK_SET_GROUP:
		task_set_group_fair(p);
		break;

	case TASK_MOVE_GROUP:
		task_move_group_fair(p);
		break;
	}
}

void free_fair_sched_group(struct task_group *tg)
{
	int i;

	destroy_cfs_bandwidth(tg_cfs_bandwidth(tg));

	for_each_possible_cpu(i) {
		if (tg->cfs_rq)
			kfree(tg->cfs_rq[i]);
		if (tg->se)
			kfree(tg->se[i]);
	}

	kfree(tg->cfs_rq);
	kfree(tg->se);
}

int alloc_fair_sched_group(struct task_group *tg, struct task_group *parent)
{
	struct sched_entity *se;
	struct cfs_rq *cfs_rq;
	int i;

	tg->cfs_rq = kzalloc(sizeof(cfs_rq) * nr_cpu_ids, GFP_KERNEL);
	if (!tg->cfs_rq)
		goto err;
	tg->se = kzalloc(sizeof(se) * nr_cpu_ids, GFP_KERNEL);
	if (!tg->se)
		goto err;

	tg->shares = NICE_0_LOAD;

	init_cfs_bandwidth(tg_cfs_bandwidth(tg));

	for_each_possible_cpu(i) {
		cfs_rq = kzalloc_node(sizeof(struct cfs_rq),
				      GFP_KERNEL, cpu_to_node(i));
		if (!cfs_rq)
			goto err;

		se = kzalloc_node(sizeof(struct sched_entity),
				  GFP_KERNEL, cpu_to_node(i));
		if (!se)
			goto err_free_rq;

		init_cfs_rq(cfs_rq);
		init_tg_cfs_entry(tg, cfs_rq, se, i, parent->se[i]);
		init_entity_runnable_average(se);
	}

	return 1;

err_free_rq:
	kfree(cfs_rq);
err:
	return 0;
}

void online_fair_sched_group(struct task_group *tg)
{
	struct sched_entity *se;
	struct rq *rq;
	int i;

	for_each_possible_cpu(i) {
		rq = cpu_rq(i);
		se = tg->se[i];

		raw_spin_lock_irq(&rq->lock);
		post_init_entity_util_avg(se);
		sync_throttle(tg, i);
		raw_spin_unlock_irq(&rq->lock);
	}
}

void unregister_fair_sched_group(struct task_group *tg)
{
	unsigned long flags;
	struct rq *rq;
	int cpu;

	for_each_possible_cpu(cpu) {
		if (tg->se[cpu])
			remove_entity_load_avg(tg->se[cpu]);

		/*
		 * Only empty task groups can be destroyed; so we can speculatively
		 * check on_list without danger of it being re-added.
		 */
		if (!tg->cfs_rq[cpu]->on_list)
			continue;

		rq = cpu_rq(cpu);

		raw_spin_lock_irqsave(&rq->lock, flags);
		list_del_leaf_cfs_rq(tg->cfs_rq[cpu]);
		raw_spin_unlock_irqrestore(&rq->lock, flags);
	}
}

void init_tg_cfs_entry(struct task_group *tg, struct cfs_rq *cfs_rq,
			struct sched_entity *se, int cpu,
			struct sched_entity *parent)
{
	struct rq *rq = cpu_rq(cpu);

	cfs_rq->tg = tg;
	cfs_rq->rq = rq;
	init_cfs_rq_runtime(cfs_rq);

	tg->cfs_rq[cpu] = cfs_rq;
	tg->se[cpu] = se;

	/* se could be NULL for root_task_group */
	if (!se)
		return;

	if (!parent) {
		se->cfs_rq = &rq->cfs;
		se->depth = 0;
	} else {
		se->cfs_rq = parent->my_q;
		se->depth = parent->depth + 1;
	}

	se->my_q = cfs_rq;
	/* guarantee group entities always have weight */
	update_load_set(&se->load, NICE_0_LOAD);
	se->parent = parent;
}

static DEFINE_MUTEX(shares_mutex);

int sched_group_set_shares(struct task_group *tg, unsigned long shares)
{
	int i;
	unsigned long flags;

	/*
	 * We can't change the weight of the root cgroup.
	 */
	if (!tg->se[0])
		return -EINVAL;

	shares = clamp(shares, scale_load(MIN_SHARES), scale_load(MAX_SHARES));

	mutex_lock(&shares_mutex);
	if (tg->shares == shares)
		goto done;

	tg->shares = shares;
	for_each_possible_cpu(i) {
		struct rq *rq = cpu_rq(i);
		struct sched_entity *se;

		se = tg->se[i];
		/* Propagate contribution to hierarchy */
		raw_spin_lock_irqsave(&rq->lock, flags);

		/* Possible calls to update_curr() need rq clock */
		update_rq_clock(rq);
		for_each_sched_entity(se)
			update_cfs_shares(group_cfs_rq(se));
		raw_spin_unlock_irqrestore(&rq->lock, flags);
	}

done:
	mutex_unlock(&shares_mutex);
	return 0;
}
#else /* CONFIG_FAIR_GROUP_SCHED */

void free_fair_sched_group(struct task_group *tg) { }

int alloc_fair_sched_group(struct task_group *tg, struct task_group *parent)
{
	return 1;
}

void online_fair_sched_group(struct task_group *tg) { }

void unregister_fair_sched_group(struct task_group *tg) { }

#endif /* CONFIG_FAIR_GROUP_SCHED */


static unsigned int get_rr_interval_fair(struct rq *rq, struct task_struct *task)
{
	struct sched_entity *se = &task->se;
	unsigned int rr_interval = 0;

	/*
	 * Time slice is 0 for SCHED_OTHER tasks that are on an otherwise
	 * idle runqueue:
	 */
	if (rq->cfs.load.weight)
		rr_interval = NS_TO_JIFFIES(sched_slice(cfs_rq_of(se), se));

	return rr_interval;
}

/*
 * All the scheduling class methods:
 */
const struct sched_class fair_sched_class = {
	.next			= &idle_sched_class,
	.enqueue_task		= enqueue_task_fair,
	.dequeue_task		= dequeue_task_fair,
	.yield_task		= yield_task_fair,
	.yield_to_task		= yield_to_task_fair,

	.check_preempt_curr	= check_preempt_wakeup,

	.pick_next_task		= pick_next_task_fair,
	.put_prev_task		= put_prev_task_fair,

#ifdef CONFIG_SMP
	.select_task_rq		= select_task_rq_fair,
	.migrate_task_rq	= migrate_task_rq_fair,

	.rq_online		= rq_online_fair,
	.rq_offline		= rq_offline_fair,

	.task_dead		= task_dead_fair,
	.set_cpus_allowed	= set_cpus_allowed_common,
#endif

	.set_curr_task          = set_curr_task_fair,
	.task_tick		= task_tick_fair,
	.task_fork		= task_fork_fair,

	.prio_changed		= prio_changed_fair,
	.switched_from		= switched_from_fair,
	.switched_to		= switched_to_fair,

	.get_rr_interval	= get_rr_interval_fair,

	.update_curr		= update_curr_fair,

#ifdef CONFIG_FAIR_GROUP_SCHED
	.task_change_group	= task_change_group_fair,
#endif
};

#ifdef CONFIG_SCHED_DEBUG
void print_cfs_stats(struct seq_file *m, int cpu)
{
	struct cfs_rq *cfs_rq;

	rcu_read_lock();
	for_each_leaf_cfs_rq(cpu_rq(cpu), cfs_rq)
		print_cfs_rq(m, cpu, cfs_rq);
	rcu_read_unlock();
}

#ifdef CONFIG_NUMA_BALANCING
void show_numa_stats(struct task_struct *p, struct seq_file *m)
{
	int node;
	unsigned long tsf = 0, tpf = 0, gsf = 0, gpf = 0;

	for_each_online_node(node) {
		if (p->numa_faults) {
			tsf = p->numa_faults[task_faults_idx(NUMA_MEM, node, 0)];
			tpf = p->numa_faults[task_faults_idx(NUMA_MEM, node, 1)];
		}
		if (p->numa_group) {
			gsf = p->numa_group->faults[task_faults_idx(NUMA_MEM, node, 0)],
			gpf = p->numa_group->faults[task_faults_idx(NUMA_MEM, node, 1)];
		}
		print_numa_stats(m, node, tsf, tpf, gsf, gpf);
	}
}
#endif /* CONFIG_NUMA_BALANCING */
#endif /* CONFIG_SCHED_DEBUG */

__init void init_sched_fair_class(void)
{
#ifdef CONFIG_SMP
	/* SMP负载均衡机制从注册软中断开始,每次系统处理调度tick时会检查当前是否需要处理SMP负载均衡 */
	open_softirq(SCHED_SOFTIRQ, run_rebalance_domains);

#ifdef CONFIG_NO_HZ_COMMON
	nohz.next_balance = jiffies;
	zalloc_cpumask_var(&nohz.idle_cpus_mask, GFP_NOWAIT);
#endif
#endif /* SMP */

}
