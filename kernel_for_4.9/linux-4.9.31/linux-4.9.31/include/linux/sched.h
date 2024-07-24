#ifndef _LINUX_SCHED_H
#define _LINUX_SCHED_H

#include <uapi/linux/sched.h>

#include <linux/sched/prio.h>


struct sched_param {
	int sched_priority;
};

#include <asm/param.h>	/* for HZ */

#include <linux/capability.h>
#include <linux/threads.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/timex.h>
#include <linux/jiffies.h>
#include <linux/plist.h>
#include <linux/rbtree.h>
#include <linux/thread_info.h>
#include <linux/cpumask.h>
#include <linux/errno.h>
#include <linux/nodemask.h>
#include <linux/mm_types.h>
#include <linux/preempt.h>

#include <asm/page.h>
#include <asm/ptrace.h>
#include <linux/cputime.h>

#include <linux/smp.h>
#include <linux/sem.h>
#include <linux/shm.h>
#include <linux/signal.h>
#include <linux/compiler.h>
#include <linux/completion.h>
#include <linux/pid.h>
#include <linux/percpu.h>
#include <linux/topology.h>
#include <linux/seccomp.h>
#include <linux/rcupdate.h>
#include <linux/rculist.h>
#include <linux/rtmutex.h>

#include <linux/time.h>
#include <linux/param.h>
#include <linux/resource.h>
#include <linux/timer.h>
#include <linux/hrtimer.h>
#include <linux/kcov.h>
#include <linux/task_io_accounting.h>
#include <linux/latencytop.h>
#include <linux/cred.h>
#include <linux/llist.h>
#include <linux/uidgid.h>
#include <linux/gfp.h>
#include <linux/magic.h>
#include <linux/cgroup-defs.h>

#include <asm/processor.h>

#define SCHED_ATTR_SIZE_VER0	48	/* sizeof first published struct */

/*
 * Extended scheduling parameters data structure.
 *
 * This is needed because the original struct sched_param can not be
 * altered without introducing ABI issues with legacy applications
 * (e.g., in sched_getparam()).
 *
 * However, the possibility of specifying more than just a priority for
 * the tasks may be useful for a wide variety of application fields, e.g.,
 * multimedia, streaming, automation and control, and many others.
 *
 * This variant (sched_attr) is meant at describing a so-called
 * sporadic time-constrained task. In such model a task is specified by:
 *  - the activation period or minimum instance inter-arrival time;
 *  - the maximum (or average, depending on the actual scheduling
 *    discipline) computation time of all instances, a.k.a. runtime;
 *  - the deadline (relative to the actual activation time) of each
 *    instance.
 * Very briefly, a periodic (sporadic) task asks for the execution of
 * some specific computation --which is typically called an instance--
 * (at most) every period. Moreover, each instance typically lasts no more
 * than the runtime and must be completed by time instant t equal to
 * the instance activation time + the deadline.
 *
 * This is reflected by the actual fields of the sched_attr structure:
 *
 *  @size		size of the structure, for fwd/bwd compat.
 *
 *  @sched_policy	task's scheduling policy
 *  @sched_flags	for customizing the scheduler behaviour
 *  @sched_nice		task's nice value      (SCHED_NORMAL/BATCH)
 *  @sched_priority	task's static priority (SCHED_FIFO/RR)
 *  @sched_deadline	representative of the task's deadline
 *  @sched_runtime	representative of the task's runtime
 *  @sched_period	representative of the task's period
 *
 * Given this task model, there are a multiplicity of scheduling algorithms
 * and policies, that can be used to ensure all the tasks will make their
 * timing constraints.
 *
 * As of now, the SCHED_DEADLINE policy (sched_dl scheduling class) is the
 * only user of this new interface. More information about the algorithm
 * available in the scheduling class file or in Documentation/.
 */
struct sched_attr {
	u32 size;

	u32 sched_policy;
	u64 sched_flags;

	/* SCHED_NORMAL, SCHED_BATCH */
	s32 sched_nice;

	/* SCHED_FIFO, SCHED_RR */
	u32 sched_priority;

	/* SCHED_DEADLINE */
	u64 sched_runtime;
	u64 sched_deadline;
	u64 sched_period;
};

struct futex_pi_state;
struct robust_list_head;
struct bio_list;
struct fs_struct;
struct perf_event_context;
struct blk_plug;
struct filename;
struct nameidata;

#define VMACACHE_BITS 2
#define VMACACHE_SIZE (1U << VMACACHE_BITS)
#define VMACACHE_MASK (VMACACHE_SIZE - 1)

/*
 * These are the constant used to fake the fixed-point load-average
 * counting. Some notes:
 *  - 11 bit fractions expand to 22 bits by the multiplies: this gives
 *    a load-average precision of 10 bits integer + 11 bits fractional
 *  - if you want to count load-averages more often, you need more
 *    precision, or rounding will get you. With 2-second counting freq,
 *    the EXP_n values would be 1981, 2034 and 2043 if still using only
 *    11 bit fractions.
 */
extern unsigned long avenrun[];		/* Load averages */
extern void get_avenrun(unsigned long *loads, unsigned long offset, int shift);

#define FSHIFT		11		/* nr of bits of precision */
#define FIXED_1		(1<<FSHIFT)	/* 1.0 as fixed-point */
#define LOAD_FREQ	(5*HZ+1)	/* 5 sec intervals */
#define EXP_1		1884		/* 1/exp(5sec/1min) as fixed-point */
#define EXP_5		2014		/* 1/exp(5sec/5min) */
#define EXP_15		2037		/* 1/exp(5sec/15min) */

#define CALC_LOAD(load,exp,n) \
	load *= exp; \
	load += n*(FIXED_1-exp); \
	load >>= FSHIFT;

extern unsigned long total_forks;
extern int nr_threads;
DECLARE_PER_CPU(unsigned long, process_counts);
extern int nr_processes(void);
extern unsigned long nr_running(void);
extern bool single_task_running(void);
extern unsigned long nr_iowait(void);
extern unsigned long nr_iowait_cpu(int cpu);
extern void get_iowait_load(unsigned long *nr_waiters, unsigned long *load);

extern void calc_global_load(unsigned long ticks);

#if defined(CONFIG_SMP) && defined(CONFIG_NO_HZ_COMMON)
extern void cpu_load_update_nohz_start(void);
extern void cpu_load_update_nohz_stop(void);
#else
static inline void cpu_load_update_nohz_start(void) { }
static inline void cpu_load_update_nohz_stop(void) { }
#endif

extern void dump_cpu_task(int cpu);

struct seq_file;
struct cfs_rq;
struct task_group;
#ifdef CONFIG_SCHED_DEBUG
extern void proc_sched_show_task(struct task_struct *p, struct seq_file *m);
extern void proc_sched_set_task(struct task_struct *p);
#endif

/*
 * Task state bitmask. NOTE! These bits are also
 * encoded in fs/proc/array.c: get_task_state().
 *
 * We have two separate sets of flags: task->state
 * is about runnability, while task->exit_state are
 * about the task exiting. Confusing, but this way
 * modifying one set can't modify the other one by
 * mistake.
 */
/* 表示进程要么正在执行,要么正要准备执行(已经就绪),正在等待cpu时间片的调度 */
#define TASK_RUNNING		0
/* 进程因为等待一些条件而被挂起(阻塞)而所处的状态.
 * 这些条件主要包括:硬中断、资源、一些信号……,一旦等待的条件成立,进程就会从该状态(阻塞)迅速转化成为就绪状态TASK_RUNNING */
#define TASK_INTERRUPTIBLE	1
/* 意义与TASK_INTERRUPTIBLE类似,除了不能通过接受一个信号来唤醒以外,对于处于TASK_UNINTERRUPIBLE状态的进程,
 * 哪怕我们传递一个信号或者有一个外部中断都不能唤醒他们.
 * 只有它所等待的资源可用的时候,他才会被唤醒.
 * 这个标志很少用,但是并不代表没有任何用处,其实他的作用非常大,特别是对于驱动刺探相关的硬件过程很重要,
 * 这个刺探过程不能被一些其他的东西给中断,否则就会让进城进入不可预测的状态
 */
#define TASK_UNINTERRUPTIBLE	2
/* 进程被停止执行,当进程接收到SIGSTOP、SIGTTIN、SIGTSTP或者SIGTTOU信号之后就会进入该状态 */
#define __TASK_STOPPED		4
/* 表示进程被debugger等进程监视,进程执行被调试程序所停止,当一个进程被另外的进程所监视,每一个信号都会让进程进入该状态 */
#define __TASK_TRACED		8
/* in tsk->exit_state */
/* 其实还有两个附加的进程状态既可以被添加到state域中,又可以被添加到exit_state域中.
 * 只有当进程终止的时候,才会达到这两种状态.
 *
 * EXIT_ZOMBIE: 进程的执行被终止,但是其父进程还没有使用wait()等系统调用来获知它的终止信息,此时进程成为僵尸进程
 * EXIT_DEAD: 进程的最终状态
 */
#define EXIT_DEAD		16
#define EXIT_ZOMBIE		32
#define EXIT_TRACE		(EXIT_ZOMBIE | EXIT_DEAD)
/* in tsk->state again */
#define TASK_DEAD		64
/* TASK_WAKEKILL 用于在接收到致命信号时唤醒进程 */
#define TASK_WAKEKILL		128
#define TASK_WAKING		256
#define TASK_PARKED		512
#define TASK_NOLOAD		1024
#define TASK_NEW		2048
#define TASK_STATE_MAX		4096

#define TASK_STATE_TO_CHAR_STR "RSDTtXZxKWPNn"

extern char ___assert_task_state[1 - 2*!!(
		sizeof(TASK_STATE_TO_CHAR_STR)-1 != ilog2(TASK_STATE_MAX)+1)];

/* Convenience macros for the sake of set_task_state */
/* TASK_KILLABLE(可杀的深度睡眠): 可以被等到的资源唤醒,不能被常规信号唤醒,但是可以被致命信号唤醒,醒后即死. */
#define TASK_KILLABLE		(TASK_WAKEKILL | TASK_UNINTERRUPTIBLE)
#define TASK_STOPPED		(TASK_WAKEKILL | __TASK_STOPPED)
#define TASK_TRACED		(TASK_WAKEKILL | __TASK_TRACED)

#define TASK_IDLE		(TASK_UNINTERRUPTIBLE | TASK_NOLOAD)

/* Convenience macros for the sake of wake_up */
#define TASK_NORMAL		(TASK_INTERRUPTIBLE | TASK_UNINTERRUPTIBLE)
#define TASK_ALL		(TASK_NORMAL | __TASK_STOPPED | __TASK_TRACED)

/* get_task_state() */
#define TASK_REPORT		(TASK_RUNNING | TASK_INTERRUPTIBLE | \
				 TASK_UNINTERRUPTIBLE | __TASK_STOPPED | \
				 __TASK_TRACED | EXIT_ZOMBIE | EXIT_DEAD)

#define task_is_traced(task)	((task->state & __TASK_TRACED) != 0)
#define task_is_stopped(task)	((task->state & __TASK_STOPPED) != 0)
#define task_is_stopped_or_traced(task)	\
			((task->state & (__TASK_STOPPED | __TASK_TRACED)) != 0)
#define task_contributes_to_load(task)	\
				((task->state & TASK_UNINTERRUPTIBLE) != 0 && \
				 (task->flags & PF_FROZEN) == 0 && \
				 (task->state & TASK_NOLOAD) == 0)

#ifdef CONFIG_DEBUG_ATOMIC_SLEEP

#define __set_task_state(tsk, state_value)			\
	do {							\
		(tsk)->task_state_change = _THIS_IP_;		\
		(tsk)->state = (state_value);			\
	} while (0)
#define set_task_state(tsk, state_value)			\
	do {							\
		(tsk)->task_state_change = _THIS_IP_;		\
		smp_store_mb((tsk)->state, (state_value));		\
	} while (0)

/*
 * set_current_state() includes a barrier so that the write of current->state
 * is correctly serialised wrt the caller's subsequent test of whether to
 * actually sleep:
 *
 *	set_current_state(TASK_UNINTERRUPTIBLE);
 *	if (do_i_need_to_sleep())
 *		schedule();
 *
 * If the caller does not need such serialisation then use __set_current_state()
 */
#define __set_current_state(state_value)			\
	do {							\
		current->task_state_change = _THIS_IP_;		\
		current->state = (state_value);			\
	} while (0)
#define set_current_state(state_value)				\
	do {							\
		current->task_state_change = _THIS_IP_;		\
		smp_store_mb(current->state, (state_value));		\
	} while (0)

#else

#define __set_task_state(tsk, state_value)		\
	do { (tsk)->state = (state_value); } while (0)
#define set_task_state(tsk, state_value)		\
	smp_store_mb((tsk)->state, (state_value))

/*
 * set_current_state() includes a barrier so that the write of current->state
 * is correctly serialised wrt the caller's subsequent test of whether to
 * actually sleep:
 *
 *	set_current_state(TASK_UNINTERRUPTIBLE);
 *	if (do_i_need_to_sleep())
 *		schedule();
 *
 * If the caller does not need such serialisation then use __set_current_state()
 */
#define __set_current_state(state_value)		\
	do { current->state = (state_value); } while (0)
#define set_current_state(state_value)			\
	smp_store_mb(current->state, (state_value))

#endif

/* Task command name length */
#define TASK_COMM_LEN 16

#include <linux/spinlock.h>

/*
 * This serializes "schedule()" and also protects
 * the run-queue from deletions/modifications (but
 * _adding_ to the beginning of the run-queue has
 * a separate lock).
 */
extern rwlock_t tasklist_lock;
extern spinlock_t mmlist_lock;

struct task_struct;

#ifdef CONFIG_PROVE_RCU
extern int lockdep_tasklist_lock_is_held(void);
#endif /* #ifdef CONFIG_PROVE_RCU */

extern void sched_init(void);
extern void sched_init_smp(void);
extern asmlinkage void schedule_tail(struct task_struct *prev);
extern void init_idle(struct task_struct *idle, int cpu);
extern void init_idle_bootup_task(struct task_struct *idle);

extern cpumask_var_t cpu_isolated_map;

extern int runqueue_is_locked(int cpu);

#if defined(CONFIG_SMP) && defined(CONFIG_NO_HZ_COMMON)
extern void nohz_balance_enter_idle(int cpu);
extern void set_cpu_sd_state_idle(void);
extern int get_nohz_timer_target(void);
#else
static inline void nohz_balance_enter_idle(int cpu) { }
static inline void set_cpu_sd_state_idle(void) { }
#endif

/*
 * Only dump TASK_* tasks. (0 for all tasks)
 */
extern void show_state_filter(unsigned long state_filter);

static inline void show_state(void)
{
	show_state_filter(0);
}

extern void show_regs(struct pt_regs *);

/*
 * TASK is a pointer to the task whose backtrace we want to see (or NULL for current
 * task), SP is the stack pointer of the first frame that should be shown in the back
 * trace (or NULL if the entire call-chain of the task should be shown).
 */
extern void show_stack(struct task_struct *task, unsigned long *sp);

extern void cpu_init (void);
extern void trap_init(void);
extern void update_process_times(int user);
extern void scheduler_tick(void);
extern int sched_cpu_starting(unsigned int cpu);
extern int sched_cpu_activate(unsigned int cpu);
extern int sched_cpu_deactivate(unsigned int cpu);

#ifdef CONFIG_HOTPLUG_CPU
extern int sched_cpu_dying(unsigned int cpu);
#else
# define sched_cpu_dying	NULL
#endif

extern void sched_show_task(struct task_struct *p);

#ifdef CONFIG_LOCKUP_DETECTOR
extern void touch_softlockup_watchdog_sched(void);
extern void touch_softlockup_watchdog(void);
extern void touch_softlockup_watchdog_sync(void);
extern void touch_all_softlockup_watchdogs(void);
extern int proc_dowatchdog_thresh(struct ctl_table *table, int write,
				  void __user *buffer,
				  size_t *lenp, loff_t *ppos);
extern unsigned int  softlockup_panic;
extern unsigned int  hardlockup_panic;
void lockup_detector_init(void);
#else
static inline void touch_softlockup_watchdog_sched(void)
{
}
static inline void touch_softlockup_watchdog(void)
{
}
static inline void touch_softlockup_watchdog_sync(void)
{
}
static inline void touch_all_softlockup_watchdogs(void)
{
}
static inline void lockup_detector_init(void)
{
}
#endif

#ifdef CONFIG_DETECT_HUNG_TASK
void reset_hung_task_detector(void);
#else
static inline void reset_hung_task_detector(void)
{
}
#endif

/* Attach to any functions which should be ignored in wchan output. */
#define __sched		__attribute__((__section__(".sched.text")))

/* Linker adds these: start and end of __sched functions */
extern char __sched_text_start[], __sched_text_end[];

/* Is this address in the __sched functions? */
extern int in_sched_functions(unsigned long addr);

#define	MAX_SCHEDULE_TIMEOUT	LONG_MAX
extern signed long schedule_timeout(signed long timeout);
extern signed long schedule_timeout_interruptible(signed long timeout);
extern signed long schedule_timeout_killable(signed long timeout);
extern signed long schedule_timeout_uninterruptible(signed long timeout);
extern signed long schedule_timeout_idle(signed long timeout);
asmlinkage void schedule(void);
extern void schedule_preempt_disabled(void);

extern long io_schedule_timeout(long timeout);

static inline void io_schedule(void)
{
	io_schedule_timeout(MAX_SCHEDULE_TIMEOUT);
}

void __noreturn do_task_dead(void);

struct nsproxy;
struct user_namespace;

#ifdef CONFIG_MMU
extern void arch_pick_mmap_layout(struct mm_struct *mm);
extern unsigned long
arch_get_unmapped_area(struct file *, unsigned long, unsigned long,
		       unsigned long, unsigned long);
extern unsigned long
arch_get_unmapped_area_topdown(struct file *filp, unsigned long addr,
			  unsigned long len, unsigned long pgoff,
			  unsigned long flags);
#else
static inline void arch_pick_mmap_layout(struct mm_struct *mm) {}
#endif

#define SUID_DUMP_DISABLE	0	/* No setuid dumping */
#define SUID_DUMP_USER		1	/* Dump as user of process */
#define SUID_DUMP_ROOT		2	/* Dump as root */

/* mm flags */

/* for SUID_DUMP_* above */
#define MMF_DUMPABLE_BITS 2
#define MMF_DUMPABLE_MASK ((1 << MMF_DUMPABLE_BITS) - 1)

extern void set_dumpable(struct mm_struct *mm, int value);
/*
 * This returns the actual value of the suid_dumpable flag. For things
 * that are using this for checking for privilege transitions, it must
 * test against SUID_DUMP_USER rather than treating it as a boolean
 * value.
 */
static inline int __get_dumpable(unsigned long mm_flags)
{
	return mm_flags & MMF_DUMPABLE_MASK;
}

static inline int get_dumpable(struct mm_struct *mm)
{
	return __get_dumpable(mm->flags);
}

/* coredump filter bits */
#define MMF_DUMP_ANON_PRIVATE	2
#define MMF_DUMP_ANON_SHARED	3
#define MMF_DUMP_MAPPED_PRIVATE	4
#define MMF_DUMP_MAPPED_SHARED	5
#define MMF_DUMP_ELF_HEADERS	6
#define MMF_DUMP_HUGETLB_PRIVATE 7
#define MMF_DUMP_HUGETLB_SHARED  8
#define MMF_DUMP_DAX_PRIVATE	9
#define MMF_DUMP_DAX_SHARED	10

#define MMF_DUMP_FILTER_SHIFT	MMF_DUMPABLE_BITS
#define MMF_DUMP_FILTER_BITS	9
#define MMF_DUMP_FILTER_MASK \
	(((1 << MMF_DUMP_FILTER_BITS) - 1) << MMF_DUMP_FILTER_SHIFT)
#define MMF_DUMP_FILTER_DEFAULT \
	((1 << MMF_DUMP_ANON_PRIVATE) |	(1 << MMF_DUMP_ANON_SHARED) |\
	 (1 << MMF_DUMP_HUGETLB_PRIVATE) | MMF_DUMP_MASK_DEFAULT_ELF)

#ifdef CONFIG_CORE_DUMP_DEFAULT_ELF_HEADERS
# define MMF_DUMP_MASK_DEFAULT_ELF	(1 << MMF_DUMP_ELF_HEADERS)
#else
# define MMF_DUMP_MASK_DEFAULT_ELF	0
#endif
					/* leave room for more dump flags */
#define MMF_VM_MERGEABLE	16	/* KSM may merge identical pages */
#define MMF_VM_HUGEPAGE		17	/* set when VM_HUGEPAGE is set on vma */
#define MMF_EXE_FILE_CHANGED	18	/* see prctl_set_mm_exe_file() */

#define MMF_HAS_UPROBES		19	/* has uprobes */
#define MMF_RECALC_UPROBES	20	/* MMF_HAS_UPROBES can be wrong */
#define MMF_OOM_SKIP		21	/* mm is of no interest for the OOM killer */
#define MMF_UNSTABLE		22	/* mm is unstable for copy_from_user */
#define MMF_HUGE_ZERO_PAGE	23      /* mm has ever used the global huge zero page */

#define MMF_INIT_MASK		(MMF_DUMPABLE_MASK | MMF_DUMP_FILTER_MASK)

struct sighand_struct {
	atomic_t		count;
	struct k_sigaction	action[_NSIG];
	spinlock_t		siglock;
	wait_queue_head_t	signalfd_wqh;
};

struct pacct_struct {
	int			ac_flag;
	long			ac_exitcode;
	unsigned long		ac_mem;
	cputime_t		ac_utime, ac_stime;
	unsigned long		ac_minflt, ac_majflt;
};

struct cpu_itimer {
	cputime_t expires;
	cputime_t incr;
	u32 error;
	u32 incr_error;
};

/**
 * struct prev_cputime - snaphsot of system and user cputime
 * @utime: time spent in user mode
 * @stime: time spent in system mode
 * @lock: protects the above two fields
 *
 * Stores previous user/system time values such that we can guarantee
 * monotonicity.
 */
struct prev_cputime {
#ifndef CONFIG_VIRT_CPU_ACCOUNTING_NATIVE
	cputime_t utime;
	cputime_t stime;
	raw_spinlock_t lock;
#endif
};

static inline void prev_cputime_init(struct prev_cputime *prev)
{
#ifndef CONFIG_VIRT_CPU_ACCOUNTING_NATIVE
	prev->utime = prev->stime = 0;
	raw_spin_lock_init(&prev->lock);
#endif
}

/**
 * struct task_cputime - collected CPU time counts
 * @utime:		time spent in user mode, in &cputime_t units
 * @stime:		time spent in kernel mode, in &cputime_t units
 * @sum_exec_runtime:	total time spent on the CPU, in nanoseconds
 *
 * This structure groups together three kinds of CPU time that are tracked for
 * threads and thread groups.  Most things considering CPU time want to group
 * these counts together and treat all three of them in parallel.
 */
struct task_cputime {
	cputime_t utime;
	cputime_t stime;
	unsigned long long sum_exec_runtime;
};

/* Alternate field names when used to cache expirations. */
#define virt_exp	utime
#define prof_exp	stime
#define sched_exp	sum_exec_runtime

#define INIT_CPUTIME	\
	(struct task_cputime) {					\
		.utime = 0,					\
		.stime = 0,					\
		.sum_exec_runtime = 0,				\
	}

/*
 * This is the atomic variant of task_cputime, which can be used for
 * storing and updating task_cputime statistics without locking.
 */
struct task_cputime_atomic {
	atomic64_t utime;
	atomic64_t stime;
	atomic64_t sum_exec_runtime;
};

#define INIT_CPUTIME_ATOMIC \
	(struct task_cputime_atomic) {				\
		.utime = ATOMIC64_INIT(0),			\
		.stime = ATOMIC64_INIT(0),			\
		.sum_exec_runtime = ATOMIC64_INIT(0),		\
	}

#define PREEMPT_DISABLED	(PREEMPT_DISABLE_OFFSET + PREEMPT_ENABLED)

/*
 * Disable preemption until the scheduler is running -- use an unconditional
 * value so that it also works on !PREEMPT_COUNT kernels.
 *
 * Reset by start_kernel()->sched_init()->init_idle()->init_idle_preempt_count().
 */
#define INIT_PREEMPT_COUNT	PREEMPT_OFFSET

/*
 * Initial preempt_count value; reflects the preempt_count schedule invariant
 * which states that during context switches:
 *
 *    preempt_count() == 2*PREEMPT_DISABLE_OFFSET
 *
 * Note: PREEMPT_DISABLE_OFFSET is 0 for !PREEMPT_COUNT kernels.
 * Note: See finish_task_switch().
 */
#define FORK_PREEMPT_COUNT	(2*PREEMPT_DISABLE_OFFSET + PREEMPT_ENABLED)

/**
 * struct thread_group_cputimer - thread group interval timer counts
 * @cputime_atomic:	atomic thread group interval timers.
 * @running:		true when there are timers running and
 *			@cputime_atomic receives updates.
 * @checking_timer:	true when a thread in the group is in the
 *			process of checking for thread group timers.
 *
 * This structure contains the version of task_cputime, above, that is
 * used for thread group CPU timer calculations.
 */
struct thread_group_cputimer {
	struct task_cputime_atomic cputime_atomic;
	bool running;
	bool checking_timer;
};

#include <linux/rwsem.h>
struct autogroup;

/*
 * NOTE! "signal_struct" does not have its own
 * locking, because a shared signal_struct always
 * implies a shared sighand_struct, so locking
 * sighand_struct is always a proper superset of
 * the locking of signal_struct.
 */
struct signal_struct {
	atomic_t		sigcnt;
	atomic_t		live;
	int			nr_threads;
	struct list_head	thread_head;

	wait_queue_head_t	wait_chldexit;	/* for wait4() */

	/* current thread group signal load-balancing target: */
	struct task_struct	*curr_target;

	/* shared signal handling: */
	struct sigpending	shared_pending;

	/* thread group exit support */
	int			group_exit_code;
	/* overloaded:
	 * - notify group_exit_task when ->count is equal to notify_count
	 * - everyone except group_exit_task is stopped during signal delivery
	 *   of fatal signals, group_exit_task processes the signal.
	 */
	int			notify_count;
	struct task_struct	*group_exit_task;

	/* thread group stop support, overloads group_exit_code too */
	int			group_stop_count;
	unsigned int		flags; /* see SIGNAL_* flags below */

	/*
	 * PR_SET_CHILD_SUBREAPER marks a process, like a service
	 * manager, to re-parent orphan (double-forking) child processes
	 * to this process instead of 'init'. The service manager is
	 * able to receive SIGCHLD signals and is able to investigate
	 * the process until it calls wait(). All children of this
	 * process will inherit a flag if they should look for a
	 * child_subreaper process at exit.
	 */
	unsigned int		is_child_subreaper:1;
	unsigned int		has_child_subreaper:1;

	/* POSIX.1b Interval Timers */
	int			posix_timer_id;
	struct list_head	posix_timers;

	/* ITIMER_REAL timer for the process */
	struct hrtimer real_timer;
	struct pid *leader_pid;
	ktime_t it_real_incr;

	/*
	 * ITIMER_PROF and ITIMER_VIRTUAL timers for the process, we use
	 * CPUCLOCK_PROF and CPUCLOCK_VIRT for indexing array as these
	 * values are defined to 0 and 1 respectively
	 */
	struct cpu_itimer it[2];

	/*
	 * Thread group totals for process CPU timers.
	 * See thread_group_cputimer(), et al, for details.
	 */
	struct thread_group_cputimer cputimer;

	/* Earliest-expiration cache. */
	struct task_cputime cputime_expires;

#ifdef CONFIG_NO_HZ_FULL
	atomic_t tick_dep_mask;
#endif

	struct list_head cpu_timers[3];

	struct pid *tty_old_pgrp;

	/* boolean value for session group leader */
	int leader;

	struct tty_struct *tty; /* NULL if no tty */

#ifdef CONFIG_SCHED_AUTOGROUP
	struct autogroup *autogroup;
#endif
	/*
	 * Cumulative resource counters for dead threads in the group,
	 * and for reaped dead child processes forked by this group.
	 * Live threads maintain their own counters and add to these
	 * in __exit_signal, except for the group leader.
	 */
	seqlock_t stats_lock;
	cputime_t utime, stime, cutime, cstime;
	cputime_t gtime;
	cputime_t cgtime;
	struct prev_cputime prev_cputime;
	unsigned long nvcsw, nivcsw, cnvcsw, cnivcsw;
	unsigned long min_flt, maj_flt, cmin_flt, cmaj_flt;
	unsigned long inblock, oublock, cinblock, coublock;
	unsigned long maxrss, cmaxrss;
	struct task_io_accounting ioac;

	/*
	 * Cumulative ns of schedule CPU time fo dead threads in the
	 * group, not including a zombie group leader, (This only differs
	 * from jiffies_to_ns(utime + stime) if sched_clock uses something
	 * other than jiffies.)
	 */
	unsigned long long sum_sched_runtime;

	/*
	 * We don't bother to synchronize most readers of this at all,
	 * because there is no reader checking a limit that actually needs
	 * to get both rlim_cur and rlim_max atomically, and either one
	 * alone is a single word that can safely be read normally.
	 * getrlimit/setrlimit use task_lock(current->group_leader) to
	 * protect this instead of the siglock, because they really
	 * have no need to disable irqs.
	 */
	struct rlimit rlim[RLIM_NLIMITS];

#ifdef CONFIG_BSD_PROCESS_ACCT
	struct pacct_struct pacct;	/* per-process accounting information */
#endif
#ifdef CONFIG_TASKSTATS
	struct taskstats *stats;
#endif
#ifdef CONFIG_AUDIT
	unsigned audit_tty;
	struct tty_audit_buf *tty_audit_buf;
#endif

	/*
	 * Thread is the potential origin of an oom condition; kill first on
	 * oom
	 */
	bool oom_flag_origin;
	short oom_score_adj;		/* OOM kill score adjustment */
	short oom_score_adj_min;	/* OOM kill score adjustment min value.
					 * Only settable by CAP_SYS_RESOURCE. */
	struct mm_struct *oom_mm;	/* recorded mm when the thread group got
					 * killed by the oom killer */

	struct mutex cred_guard_mutex;	/* guard against foreign influences on
					 * credential calculations
					 * (notably. ptrace) */
};

/*
 * Bits in flags field of signal_struct.
 */
#define SIGNAL_STOP_STOPPED	0x00000001 /* job control stop in effect */
#define SIGNAL_STOP_CONTINUED	0x00000002 /* SIGCONT since WCONTINUED reap */
#define SIGNAL_GROUP_EXIT	0x00000004 /* group exit in progress */
#define SIGNAL_GROUP_COREDUMP	0x00000008 /* coredump in progress */
/*
 * Pending notifications to parent.
 */
#define SIGNAL_CLD_STOPPED	0x00000010
#define SIGNAL_CLD_CONTINUED	0x00000020
#define SIGNAL_CLD_MASK		(SIGNAL_CLD_STOPPED|SIGNAL_CLD_CONTINUED)

#define SIGNAL_UNKILLABLE	0x00000040 /* for init: ignore fatal signals */

/* If true, all threads except ->group_exit_task have pending SIGKILL */
static inline int signal_group_exit(const struct signal_struct *sig)
{
	return	(sig->flags & SIGNAL_GROUP_EXIT) ||
		(sig->group_exit_task != NULL);
}

/*
 * Some day this will be a full-fledged user tracking system..
 */
struct user_struct {
	atomic_t __count;	/* reference count */
	atomic_t processes;	/* How many processes does this user have? */
	atomic_t sigpending;	/* How many pending signals does this user have? */
#ifdef CONFIG_INOTIFY_USER
	atomic_t inotify_watches; /* How many inotify watches does this user have? */
	atomic_t inotify_devs;	/* How many inotify devs does this user have opened? */
#endif
#ifdef CONFIG_FANOTIFY
	atomic_t fanotify_listeners;
#endif
#ifdef CONFIG_EPOLL
	atomic_long_t epoll_watches; /* The number of file descriptors currently watched */
#endif
#ifdef CONFIG_POSIX_MQUEUE
	/* protected by mq_lock	*/
	unsigned long mq_bytes;	/* How many bytes can be allocated to mqueue? */
#endif
	unsigned long locked_shm; /* How many pages of mlocked shm ? */
	unsigned long unix_inflight;	/* How many files in flight in unix sockets */
	atomic_long_t pipe_bufs;  /* how many pages are allocated in pipe buffers */

#ifdef CONFIG_KEYS
	struct key *uid_keyring;	/* UID specific keyring */
	struct key *session_keyring;	/* UID's default session keyring */
#endif

	/* Hash table maintenance information */
	struct hlist_node uidhash_node;
	kuid_t uid;

#if defined(CONFIG_PERF_EVENTS) || defined(CONFIG_BPF_SYSCALL)
	atomic_long_t locked_vm;
#endif
};

extern int uids_sysfs_init(void);

extern struct user_struct *find_user(kuid_t);

extern struct user_struct root_user;
#define INIT_USER (&root_user)


struct backing_dev_info;
struct reclaim_state;

#ifdef CONFIG_SCHED_INFO
struct sched_info {
	/* cumulative counters */
	/* 运行在这个CPU的次数 */
	unsigned long pcount;	      /* # of times run on this cpu */
	/* 在linux中一个任务被创建、被唤醒后并非立刻运行,而是需要先放置到一个叫做”就绪队列”的合适位置上等待CPU调度运行;
	 * 此外,一个任务运行过程中由于时间片到期或者高优先级任务抢占或者主动放弃CPU等情况发生时.内核会将当前运行的任务
	 * 暂放到就绪队列上选择其他任务到CPU运行。
	 *
	 * 上面不论是第一种首次进入就绪队列等待还是暂时进入就绪队列等待的情况,他们在就绪队列上等待CPU调度的时间,就是run_delay,我把它称作为调度延迟.
	 */
	unsigned long long run_delay; /* time spent waiting on a runqueue */

	/* timestamps */
	/* 任务得到CPU资源运行时刻的时间戳,其实是用于计算CPU粒度调度延迟 */
	unsigned long long last_arrival,/* when we last ran on a cpu */
			   /* 任务进入就绪队列时刻的时间戳 */
			   last_queued;	/* when we were last queued to run */
};
#endif /* CONFIG_SCHED_INFO */

#ifdef CONFIG_TASK_DELAY_ACCT
struct task_delay_info {
	spinlock_t	lock;
	unsigned int	flags;	/* Private per-task flags */

	/* For each stat XXX, add following, aligned appropriately
	 *
	 * struct timespec XXX_start, XXX_end;
	 * u64 XXX_delay;
	 * u32 XXX_count;
	 *
	 * Atomicity of updates to XXX_delay, XXX_count protected by
	 * single lock above (split into XXX_lock if contention is an issue).
	 */

	/*
	 * XXX_count is incremented on every XXX operation, the delay
	 * associated with the operation is added to XXX_delay.
	 * XXX_delay contains the accumulated delay time in nanoseconds.
	 */
	u64 blkio_start;	/* Shared by blkio, swapin */
	u64 blkio_delay;	/* wait for sync block io completion */
	u64 swapin_delay;	/* wait for swapin block io completion */
	u32 blkio_count;	/* total count of the number of sync block */
				/* io operations performed */
	u32 swapin_count;	/* total count of the number of swapin block */
				/* io operations performed */

	u64 freepages_start;
	u64 freepages_delay;	/* wait for memory reclaim */
	u32 freepages_count;	/* total count of memory reclaim */
};
#endif	/* CONFIG_TASK_DELAY_ACCT */

static inline int sched_info_on(void)
{
#ifdef CONFIG_SCHEDSTATS
	return 1;
#elif defined(CONFIG_TASK_DELAY_ACCT)
	extern int delayacct_on;
	return delayacct_on;
#else
	return 0;
#endif
}

#ifdef CONFIG_SCHEDSTATS
void force_schedstat_enabled(void);
#endif

enum cpu_idle_type {
	CPU_IDLE,
	CPU_NOT_IDLE,
	CPU_NEWLY_IDLE,
	CPU_MAX_IDLE_TYPES
};

/*
 * Integer metrics need fixed point arithmetic, e.g., sched/fair
 * has a few: load, load_avg, util_avg, freq, and capacity.
 *
 * We define a basic fixed point arithmetic range, and then formalize
 * all these metrics based on that basic range.
 */
# define SCHED_FIXEDPOINT_SHIFT	10
# define SCHED_FIXEDPOINT_SCALE	(1L << SCHED_FIXEDPOINT_SHIFT)

/*
 * Increase resolution of cpu_capacity calculations
 */
#define SCHED_CAPACITY_SHIFT	SCHED_FIXEDPOINT_SHIFT
#define SCHED_CAPACITY_SCALE	(1L << SCHED_CAPACITY_SHIFT)

/*
 * Wake-queues are lists of tasks with a pending wakeup, whose
 * callers have already marked the task as woken internally,
 * and can thus carry on. A common use case is being able to
 * do the wakeups once the corresponding user lock as been
 * released.
 *
 * We hold reference to each task in the list across the wakeup,
 * thus guaranteeing that the memory is still valid by the time
 * the actual wakeups are performed in wake_up_q().
 *
 * One per task suffices, because there's never a need for a task to be
 * in two wake queues simultaneously; it is forbidden to abandon a task
 * in a wake queue (a call to wake_up_q() _must_ follow), so if a task is
 * already in a wake queue, the wakeup will happen soon and the second
 * waker can just skip it.
 *
 * The WAKE_Q macro declares and initializes the list head.
 * wake_up_q() does NOT reinitialize the list; it's expected to be
 * called near the end of a function, where the fact that the queue is
 * not used again will be easy to see by inspection.
 *
 * Note that this can cause spurious wakeups. schedule() callers
 * must ensure the call is done inside a loop, confirming that the
 * wakeup condition has in fact occurred.
 */
struct wake_q_node {
	struct wake_q_node *next;
};

struct wake_q_head {
	struct wake_q_node *first;
	struct wake_q_node **lastp;
};

#define WAKE_Q_TAIL ((struct wake_q_node *) 0x01)

#define WAKE_Q(name)					\
	struct wake_q_head name = { WAKE_Q_TAIL, &name.first }

extern void wake_q_add(struct wake_q_head *head,
		       struct task_struct *task);
extern void wake_up_q(struct wake_q_head *head);

/*
 * sched-domains (multiprocessor balancing) declarations:
 */
#ifdef CONFIG_SMP
#define SD_LOAD_BALANCE		0x0001	/* Do load balancing on this domain. */
#define SD_BALANCE_NEWIDLE	0x0002	/* Balance when about to become idle */
#define SD_BALANCE_EXEC		0x0004	/* Balance on exec */
#define SD_BALANCE_FORK		0x0008	/* Balance on fork, clone */
/* 在Linux调度的上下文中,SD_BALANCE_WAKE是一个与调度域(Scheduler Domain)相关的标志位,它用于指示在任务唤醒(wakeup)时进行负载均衡.
 * 具体来说,当一个任务(进程)被唤醒并准备执行时,调度器会检查该任务所属的调度域是否设置了SD_BALANCE_WAKE标志位.
 * 如果设置了该标志位,调度器会尝试在调度域内重新分配任务,以优化系统的负载均衡.
 * 以下是关于SD_BALANCE_WAKE的详细解释:
 * 作用与目的
 * 负载均衡: SD_BALANCE_WAKE的主要目的是在任务唤醒时,通过负载均衡来优化系统性能.这有助于避免某些CPU过载而其他CPU空闲的情况,从而提高系统的整体利用率和响应性.
 * 优化资源分配: 通过在任务唤醒时进行负载均衡,调度器可以更好地管理系统的计算资源,确保任务能够尽快在合适的CPU上执行.
 * 触发条件
 * 任务唤醒: 当一个任务(进程)从睡眠状态被唤醒并准备执行时,会触发SD_BALANCE_WAKE的负载均衡机制.
 * 调度域设置: 只有在任务所属的调度域设置了SD_BALANCE_WAKE标志位时,才会在任务唤醒时进行负载均衡.
 */
#define SD_BALANCE_WAKE		0x0010  /* Balance on wakeup */
/* Linux调度的SD_WAKE_AFFINE是一个调度标志,用于指示调度器在唤醒任务时尽可能地将任务放置在唤醒它的CPU上.
 * 这个机制是在Linux内核的调度器设计中实现的,特别是在CFS(Completely Fair Scheduler)调度器中有所体现.
 *
 * 一、背景与原理
 * 在Linux系统中,当进程(或任务)被唤醒时,调度器需要为该进程选择一个合适的CPU来执行.这个过程称为选核(或选CPU),它涉及多个因素,如CPU的负载、任务的亲和性(affinity)
 * 以及系统的拓扑结构等.SD_WAKE_AFFINE就是在这个过程中发挥作用的一个标志。
 *
 * SD_WAKE_AFFINE的基本原理是,有唤醒关系的进程(即waker和wakee)往往是相互关联的,它们之间可能存在数据共享或通信.
 * 因此,将wakee进程放置在waker进程所在的CPU上执行,可以减少缓存未命中(cache-miss)等开销,从而提高系统性能.
 * 这就是所谓的“亲和性调度”(affine scheduling).
 *
 * 二、实现与优化
 * 实现方式：
 * 在Linux内核中,SD_WAKE_AFFINE标志是通过sched_domain结构体中的flags字段来设置的.sched_domain是调度器用来组织CPU层次关系的数据结构,它包含了调度域的各种参数和标志.
 * 当调度器在唤醒一个进程时,会检查该进程的sched_domain是否设置了SD_WAKE_AFFINE标志.如果设置了,调度器会尝试将进程放置在唤醒它的CPU上执行.
 * 优化机制：
 * 尽管SD_WAKE_AFFINE可以提高系统性能,但它也可能导致资源竞争和waker进程饥饿的问题,特别是在1:N的唤醒场景下(即一个waker进程唤醒多个wakee进程).
 * 为了解决这一问题,Linux内核在后续版本中引入了智能的wake-affine逻辑(如COMMIT 62470419e993所示).
 * 这种优化机制通过识别复杂的唤醒模型(如1:N),并只在认为wake-affine能提升性能时才进行亲和性调度.
 */
#define SD_WAKE_AFFINE		0x0020	/* Wake task to waking CPU */
/* 在Linux调度的上下文中,SD_ASYM_CPUCAPACITY是一个与调度域(Scheduler Domain)相关的标志位,用于指示调度域中的CPU成员具有不同的CPU容量(Capacity)或性能特性.
 * 这个标志位通常定义在Linux内核的调度器代码中,用于指导调度器在具有异构CPU(即性能不同的CPU)的系统中如何更有效地进行任务分配和负载均衡.
 *
 * 具体来说,SD_ASYM_CPUCAPACITY标志位的作用可能包括:
 * 识别异构CPU: 在具有不同性能特性的CPU(如大小核架构、不同微架构的CPU等)的系统中,SD_ASYM_CPUCAPACITY标志位帮助调度器识别这种异构性.
 * 优化任务分配: 基于CPU的容量或性能差异,调度器可以做出更智能的决策,将任务分配给最适合的CPU,以提高系统的整体性能和效率.
 * 负载均衡考虑: 在进行负载均衡时,调度器会考虑CPU的容量差异,避免将过多任务分配给性能较低的CPU,从而导致性能瓶颈.
 */
#define SD_ASYM_CPUCAPACITY	0x0040  /* Groups have different max cpu capacities */
/* Linux调度的SD_SHARE_CPUCAPACITY是一个调度标志,用于指示调度域(sched_domain)中的CPU可以共享CPU资源.
 * 这个标志在Linux内核的调度器设计中扮演着重要角色,特别是在处理多核CPU和多处理器系统时.
 *
 * 一、背景与原理
 * 在Linux系统中,CPU的算力(capacity)是调度器进行任务分配和负载均衡时考虑的关键因素之一.不同的CPU可能因为架构、频率、核心数等因素而具有不同的算力。
 * SD_SHARE_CPUCAPACITY标志的引入,旨在帮助调度器更好地理解和利用这些CPU资源,从而实现更高效的任务调度和负载均衡.
 *
 * 二、作用与影响
 * 资源共享: 当调度域中的CPU设置了SD_SHARE_CPUCAPACITY标志时,调度器会将这些CPU视为一个整体,它们在调度过程中可以共享CPU资源.这意味着调度器在分配任务时,会考虑整个调度域的CPU算力,而不是单个CPU的算力.
 * 负载均衡: 通过共享CPU资源,SD_SHARE_CPUCAPACITY有助于实现更均衡的负载分布.调度器可以根据整个调度域的负载情况,将任务迁移到算力较空闲的CPU上执行,从而提高系统的整体性能.
 * 优化调度: 除了负载均衡外,SD_SHARE_CPUCAPACITY还可以帮助调度器进行更优化的调度决策.例如,在选择唤醒任务的CPU时,调度器可以考虑整个调度域的CPU算力分布,从而选择最合适的CPU来执行任务.
 */
#define SD_SHARE_CPUCAPACITY	0x0080	/* Domain members share cpu capacity */
#define SD_SHARE_POWERDOMAIN	0x0100	/* Domain members share power domain */
/* SD_SHARE_PKG_RESOURCES在Linux中表示调度域中的CPU可以共享高速缓存资源.
 * 在Linux内核中,调度域(scheduling domain)是用于决定任务如何在CPU之间分配的一个抽象概念.
 * 这些调度域可以基于不同的参数进行配置,以适应不同的硬件架构和工作负载需求.
 * SD_SHARE_PKG_RESOURCES是这些参数之一,它指示调度域中的CPU可以共享物理包级别的资源,如高速缓存.
 * 这种共享允许更高效的资源利用,特别是在多核处理器中,其中不同的核心可能共享相同的缓存层次结构.
 * 在负载均衡的上下文中,SD_SHARE_PKG_RESOURCES的影响是显著的.当任务放置(task placement)时,系统会尽量选择idle的CPU,以优化性能.
 * 如果没有设置SD_SHARE_PKG_RESOURCES,系统可能会使用migrate_util方式来达到均衡.这表明,在存在SD_SHARE_PKG_RESOURCES的调度域中,
 * 负载均衡的策略和实现会有所不同,旨在更好地利用共享资源,提高系统的整体性能和效率
 */
#define SD_SHARE_PKG_RESOURCES	0x0200	/* Domain members share cpu pkg resources */
/* SD_SERIALIZE是sched_domain结构体中一个标志位(flag),它用于控制对该调度域内CPU的访问方式.
 * 在Linux内核的调度器上下文中,SD_SERIALIZE标志的主要作用是表明在访问或修改该调度域内的某些资源或状态时,需要采取额外的序列化(或称为同步)措施来避免竞争条件.
 * 具体来说,当SD_SERIALIZE被设置时,调度器在访问或修改该调度域相关的资源(如负载信息、运行队列等)时,会采取某种形式的锁或其他同步机制来确保数据的一致性和完整性.
 * 这是因为在多处理器系统中,多个处理器可能同时尝试访问或修改同一调度域内的数据,如果没有适当的同步机制,就可能导致数据竞争和不一致.
 * 然而,值得注意的是,SD_SERIALIZE 的使用并不是无条件的.它通常只在特定情况下被设置,比如在某些特定类型的调度域(如跨NUMA节点的调度域)中,
 * 或者当调度器认为需要更强的同步保证时.
 * 此外,SD_SERIALIZE 的使用也会带来性能开销,因为同步操作(如加锁和解锁)会消耗处理器资源.
 */
#define SD_SERIALIZE		0x0400	/* Only a single load balancing instance */
#define SD_ASYM_PACKING		0x0800  /* Place busy groups earlier in the domain */
/* Linux调度的SD_PREFER_SIBLING是一个调度标志,用于指示调度器在分配任务时,如果可能的话,更倾向于将任务放置在同一个调度域(sched_domain)内的“兄弟”(sibling)CPU上.
 * 这里的“兄弟”CPU通常指的是在同一物理处理器或封装(package)内的其他逻辑CPU.
 * 作用与影响
 * 减少缓存未命中: 将任务放置在同一个物理处理器内的CPU上,可以减少缓存未命中的次数,因为CPU之间的缓存(如L3缓存)是共享的.这样可以提高数据访问的速度,从而提升系统性能.
 * 优化任务迁移: 在需要迁移任务时,如果目标CPU与当前CPU在同一个调度域内,且为兄弟CPU,那么迁移的开销通常会更小.这是因为它们之间的物理距离较近,共享的资源也更多.
 * 提高资源利用率: 通过优先考虑兄弟CPU,可以更好地利用物理处理器内的资源,避免资源在不同物理处理器之间的不均衡分配.
 */
#define SD_PREFER_SIBLING	0x1000	/* Prefer to place tasks in a sibling domain */
#define SD_OVERLAP		0x2000	/* sched_domains of this level overlap */
#define SD_NUMA			0x4000	/* cross-node balancing */

#ifdef CONFIG_SCHED_SMT
static inline int cpu_smt_flags(void)
{
	return SD_SHARE_CPUCAPACITY | SD_SHARE_PKG_RESOURCES;
}
#endif

#ifdef CONFIG_SCHED_MC
static inline int cpu_core_flags(void)
{
	return SD_SHARE_PKG_RESOURCES;
}
#endif

#ifdef CONFIG_NUMA
static inline int cpu_numa_flags(void)
{
	return SD_NUMA;
}
#endif

struct sched_domain_attr {
	int relax_domain_level;
};

#define SD_ATTR_INIT	(struct sched_domain_attr) {	\
	.relax_domain_level = -1,			\
}

extern int sched_domain_level_max;

struct sched_group;

struct sched_domain_shared {
	atomic_t	ref;
	atomic_t	nr_busy_cpus;
	int		has_idle_cores;
};

struct sched_domain {
	/* These fields must be setup */
	struct sched_domain *parent;	/* top domain must be null terminated */
	struct sched_domain *child;	/* bottom domain must be null terminated */
	struct sched_group *groups;	/* the balancing groups of the domain */
	/* 设置此CPU进行负载均衡的最小间隔时间,在上一次负载均衡到这个时间内都不能再进行负载均衡 */
	unsigned long min_interval;	/* Minimum balance interval ms */
	/* 设置此CPU进行负载均衡的最长间隔时间,上一次做了负载均衡经过了这个时间一定要再进行一次 */
	unsigned long max_interval;	/* Maximum balance interval ms */
	/* 正常情况下,balance_interval定义了均衡的时间间隔,如果cpu繁忙,那么均衡要时间间隔长一些,
	 * 即时间间隔定义为busy_factor * balance_interval
	 */
	unsigned int busy_factor;	/* less balancing by factor if busy */
	/* 调度域内的不均衡状态达到了一定的程度之后就开始进行负载均衡的操作.
	 * imbalance_pct这个成员定义了判定不均衡的门限
	 */
	unsigned int imbalance_pct;	/* No balance until over watermark */
	/* 这个成员应该是和nr_balance_failed配合控制负载均衡过程的迁移力度.
	 * 当nr_balance_failed大于cache_nice_tries的时候,负载均衡会变得更加激进.
	 */
	unsigned int cache_nice_tries;	/* Leave cache hot tasks for # tries */
	unsigned int busy_idx;
	unsigned int idle_idx;
	unsigned int newidle_idx;
	/* wake_idx的主要作用是在任务唤醒时,帮助调度器决定在哪些CPU上查找空闲的CPU来放置被唤醒的任务.
	 * 具体来说,当一个任务被唤醒时,调度器需要决定这个任务应该在哪一个CPU上运行.
	 * 如果当前CPU(即唤醒任务的CPU)是合适的,那么任务可能就在这个CPU上继续运行.
	 * 但是,如果当前CPU负载较重或者不是最优的选择,调度器可能会考虑将任务迁移到另一个CPU上.
	 * 这时,wake_idx就派上用场了.
	 * 它提供了一个起始点,调度器从这个起始点开始,在当前的调度域(或跨调度域,取决于调度策略)中搜索合适的CPU来放置被唤醒的任务.
	 * wake_idx 的值通常基于某种启发式算法或策略来确定,旨在减少搜索时间并找到尽可能好的CPU放置位置
	 */
	unsigned int wake_idx;
	unsigned int forkexec_idx;
	unsigned int smt_gain;

	/* 每个cpu都有其对应LLC sched domain,而LLC SD记录对应cpu的idle状态得到该domain中busy cpu的个数 */
	int nohz_idle;			/* NOHZ IDLE status */
	/* 调度域标志 */
	int flags;			/* See SD_* */
	 /* 该sched domain在整个调度域层级结构中的level */
	int level;

	/* Runtime fields. */
	/* 上次进行balance的时间点 */
	unsigned long last_balance;	/* init to jiffies. units in jiffies */
	/* 定义了该sched domain均衡的基础时间间隔.last_balance加上这个计算得到的均衡时间间隔就是下一次均衡的时间点 */
	unsigned int balance_interval;	/* initialise to 1. units in ms. */
	/* 本sched domain中进行负载均衡失败的次数 */
	unsigned int nr_balance_failed; /* initialise to 0 */

	/* idle_balance() stats */
	/* 在该domain上进行newidle balance的最大时间长度 */
	u64 max_newidle_lb_cost;

	unsigned long next_decay_max_lb_cost;
	/* 平均扫描成本 */
	u64 avg_scan_cost;		/* select_idle_sibling */

#ifdef CONFIG_SCHEDSTATS
	/* load_balance() stats */
	unsigned int lb_count[CPU_MAX_IDLE_TYPES];
	unsigned int lb_failed[CPU_MAX_IDLE_TYPES];
	unsigned int lb_balanced[CPU_MAX_IDLE_TYPES];
	unsigned int lb_imbalance[CPU_MAX_IDLE_TYPES];
	unsigned int lb_gained[CPU_MAX_IDLE_TYPES];
	unsigned int lb_hot_gained[CPU_MAX_IDLE_TYPES];
	unsigned int lb_nobusyg[CPU_MAX_IDLE_TYPES];
	unsigned int lb_nobusyq[CPU_MAX_IDLE_TYPES];

	/* Active load balancing */
	unsigned int alb_count;
	unsigned int alb_failed;
	unsigned int alb_pushed;

	/* SD_BALANCE_EXEC stats */
	unsigned int sbe_count;
	unsigned int sbe_balanced;
	unsigned int sbe_pushed;

	/* SD_BALANCE_FORK stats */
	unsigned int sbf_count;
	unsigned int sbf_balanced;
	unsigned int sbf_pushed;

	/* try_to_wake_up() stats */
	unsigned int ttwu_wake_remote;
	unsigned int ttwu_move_affine;
	unsigned int ttwu_move_balance;
#endif
#ifdef CONFIG_SCHED_DEBUG
	char *name;
#endif
	union {
		void *private;		/* used during construction */
		struct rcu_head rcu;	/* used during destruction */
	};


	/* 为了降低锁竞争,Sched domain是per-CPU的,该sched domain中的busy cpu的个数,
	 * 该sched domain中是否有idle的cpu
	 */
	struct sched_domain_shared *shared;

	/* span_weight说明该sched domain中CPU的个数 */
	unsigned int span_weight;
	/*
	 * Span of all CPUs in this domain.
	 *
	 * NOTE: this field is variable length. (Allocated dynamically
	 * by attaching extra space to the end of the structure,
	 * depending on how many CPUs the kernel has booted up with)
	 *
	 * 此域中所有CPU的跨度.
	 *
	 * 注意: 此字段的长度可变. (根据内核启动的CPU数量,通过在结构末端附加额外空间来动态分配)
	 */
	unsigned long span[0];
};

static inline struct cpumask *sched_domain_span(struct sched_domain *sd)
{
	return to_cpumask(sd->span);
}

extern void partition_sched_domains(int ndoms_new, cpumask_var_t doms_new[],
				    struct sched_domain_attr *dattr_new);

/* Allocate an array of sched domains, for partition_sched_domains(). */
cpumask_var_t *alloc_sched_domains(unsigned int ndoms);
void free_sched_domains(cpumask_var_t doms[], unsigned int ndoms);

bool cpus_share_cache(int this_cpu, int that_cpu);

typedef const struct cpumask *(*sched_domain_mask_f)(int cpu);
typedef int (*sched_domain_flags_f)(void);

#define SDTL_OVERLAP	0x01

struct sd_data {
	struct sched_domain **__percpu sd;
	struct sched_domain_shared **__percpu sds;
	struct sched_group **__percpu sg;
	struct sched_group_capacity **__percpu sgc;
};

/* 内核中有一个数据结构struct sched_domain_topology_level来描述CPU的层次关系 */
struct sched_domain_topology_level {
	/* 函数指针,用于指定某个SDTL层级的cpumask位图 */
	sched_domain_mask_f mask;
	/* 函数指针,用于指定某个SDTL层级的标志位 */
	sched_domain_flags_f sd_flags;
	int		    flags;
	int		    numa_level;
	struct sd_data      data;
#ifdef CONFIG_SCHED_DEBUG
	char                *name;
#endif
};

extern void set_sched_topology(struct sched_domain_topology_level *tl);
extern void wake_up_if_idle(int cpu);

#ifdef CONFIG_SCHED_DEBUG
# define SD_INIT_NAME(type)		.name = #type
#else
# define SD_INIT_NAME(type)
#endif

#else /* CONFIG_SMP */

struct sched_domain_attr;

static inline void
partition_sched_domains(int ndoms_new, cpumask_var_t doms_new[],
			struct sched_domain_attr *dattr_new)
{
}

static inline bool cpus_share_cache(int this_cpu, int that_cpu)
{
	return true;
}

#endif	/* !CONFIG_SMP */


struct io_context;			/* See blkdev.h */


#ifdef ARCH_HAS_PREFETCH_SWITCH_STACK
extern void prefetch_stack(struct task_struct *t);
#else
static inline void prefetch_stack(struct task_struct *t) { }
#endif

struct audit_context;		/* See audit.c */
struct mempolicy;
struct pipe_inode_info;
struct uts_namespace;

/* 内核使用load_weight数据结构来记录调度实体的权重信息(weight) */
struct load_weight {
	/* weight是调度实体的权重 */
	unsigned long weight;
	/* inv_weight是inverse weight的缩写,它是权重的一个中间计算结果. */
	u32 inv_weight;
};

/*
 * The load_avg/util_avg accumulates an infinite geometric series
 * (see __update_load_avg() in kernel/sched/fair.c).
 *
 * [load_avg definition]
 *
 *   load_avg = runnable% * scale_load_down(load)
 *
 * where runnable% is the time ratio that a sched_entity is runnable.
 * For cfs_rq, it is the aggregated load_avg of all runnable and
 * blocked sched_entities.
 *
 * load_avg may also take frequency scaling into account:
 *
 *   load_avg = runnable% * scale_load_down(load) * freq%
 *
 * where freq% is the CPU frequency normalized to the highest frequency.
 *
 * [util_avg definition]
 *
 *   util_avg = running% * SCHED_CAPACITY_SCALE
 *
 * where running% is the time ratio that a sched_entity is running on
 * a CPU. For cfs_rq, it is the aggregated util_avg of all runnable
 * and blocked sched_entities.
 *
 * util_avg may also factor frequency scaling and CPU capacity scaling:
 *
 *   util_avg = running% * SCHED_CAPACITY_SCALE * freq% * capacity%
 *
 * where freq% is the same as above, and capacity% is the CPU capacity
 * normalized to the greatest capacity (due to uarch differences, etc).
 *
 * N.B., the above ratios (runnable%, running%, freq%, and capacity%)
 * themselves are in the range of [0, 1]. To do fixed point arithmetics,
 * we therefore scale them to as large a range as necessary. This is for
 * example reflected by util_avg's SCHED_CAPACITY_SCALE.
 *
 * [Overflow issue]
 *
 * The 64-bit load_sum can have 4353082796 (=2^64/47742/88761) entities
 * with the highest load (=88761), always runnable on a single cfs_rq,
 * and should not overflow as the number already hits PID_MAX_LIMIT.
 *
 * For all other cases (including 32-bit kernels), struct load_weight's
 * weight will overflow first before we do, because:
 *
 *    Max(load_avg) <= Max(load.weight)
 *
 * Then it is the load_weight's responsibility to consider overflow
 * issues.
 *
 * load_avg/util_avg累积一个无限几何级数
 * (请参阅kernel/sched/fair.c中的__update_load_avg()).
 *
 * [load_avg definition]
 *
 * load_avg = runnable% * scale_load_down(load)
 *
 * 其中runnable% 是sched_entity可运行的时间比率. 对于cfs_rq,它是所有可运行和阻塞的sched_entities的聚合load_avg.
 *
 * load_avg还可以考虑频率缩放：
 *
 * load_avg = runnable% * scale_load_down(load) * freq%
 *
 * 其中freq%是归一化到最高频率的CPU频率.
 *
 * [util_avg definition]
 *
 * util_avg = running% * SCHED_CAPACITY_SCALE
 *
 * 其中running%是sched_entity在CPU上运行的时间比率.
 * 对于cfs_rq,它是所有可运行和阻塞的sched_entities的聚合util_avg.
 *
 * util_avg还可以将频率缩放和CPU容量缩放作为因子:
 *
 * util_avg = running% * SCHED_CAPACITY_SCALE * freq% * capacity%
 *
 * 其中freq%与上述相同,capacity%是标准化为最大容量的CPU容量(由于uarch差异等).
 *
 * 注意,上述比率(runnable%, running%, freq%, and capacity%)本身在[0，1]的范围内.
 * 因此,为了进行浮点运算,我们将它们缩放到必要的大范围.例如,util_avg的SCHED_CAPACITY_SCALE反映了这一点.
 *
 * [Overflow issue]
 *
 * 64位load_sum可以有4353082796(=2^64/47742/88761)个实体
 * 具有最高负载(=88761),始终可在单个cfs_rq上运行,
 * 并且不应该溢出,因为该数字已经命中PID_MAX_LIMIT.
 *
 * 对于所有其他情况(包括32位内核),struct load_weight的权重会在我们之前先溢出,因为:
 *
 * Max(load_avg) <= Max(load.weight)
 *
 * 那么load_weight有责任考虑溢出
 */

/* 下面来关注CPU的负载计算问题.
 * 计算一个CPU的负载,最简单的方法是计算CPU上就绪队列上所有进程的权重.
 * 仅考虑优先级权重是有问题的,因为没有考虑该进程的行为.
 * 有的进程使用的CPU是突发性的,有的是恒定的,有的是CPU密集型的,也有的是IO密集型的.
 * 进程调度考虑优先级权重的方法可行,但是如果延伸到多个CPU之间的负载均衡就显得不准确了.
 * 因此从Linux 3.8内核以后进程的负载计算不仅考虑权重,而且跟踪每个调度实体的负载情况,该方法称为PELT(Pre-entry Load Tracking).
 * 调度实体数据结构中有一个struct sched_avg用于描述进程的负载
 */
struct sched_avg {
	/* last_update_time: 上一次更新的时间点,用于计算时间间隔,单位是纳秒
	 * load_sum: 对于sched_entity: 进程在就绪队列里的可运行状态下的累计衰减总时间(decay_sum_time),计算的是时间值
	 *	     对于cfs_rq: 调度队列中所有进程的累计工作总负载(decay_sum_load)
	 */
	u64 last_update_time, load_sum;
	/* util_sum: 对于sched_entity: 正在运行状态下的累计衰减总时间(decay_sum_time).(使用cfs_rq->curr == se来判断进程是否正在运行);
	 *	     对于cfs_rq: 就绪队列中所有处于运行状态进程的累计衰减总时间(decay_sum_time).只要就绪队列里有正在运行的进程,它就会累加
	 * period_contrib: 存放上一次时间采样时,不能凑成一个周期(1024us)的剩余的时间
	 */
	u32 util_sum, period_contrib;
	/* load_avg: 对于sched_entity: 可运行状态下的量化负载(decay_avg_load).负载均衡中,使用该成员来衡量一个进程的负载贡献值,如衡量迁移进程的负载量.
	 *	     对于cfs_rq：就绪队列中总的量化负载
	 * util_avg: 实际算力.通常体现于一个调度实体或者CPU的实际算力需求
	 */
	unsigned long load_avg, util_avg;
};

#ifdef CONFIG_SCHEDSTATS
struct sched_statistics {
	u64			wait_start;
	u64			wait_max;
	u64			wait_count;
	u64			wait_sum;
	u64			iowait_count;
	u64			iowait_sum;

	u64			sleep_start;
	u64			sleep_max;
	s64			sum_sleep_runtime;

	u64			block_start;
	u64			block_max;
	u64			exec_max;
	u64			slice_max;

	u64			nr_migrations_cold;
	u64			nr_failed_migrations_affine;
	u64			nr_failed_migrations_running;
	u64			nr_failed_migrations_hot;
	u64			nr_forced_migrations;

	u64			nr_wakeups;
	u64			nr_wakeups_sync;
	u64			nr_wakeups_migrate;
	u64			nr_wakeups_local;
	u64			nr_wakeups_remote;
	u64			nr_wakeups_affine;
	u64			nr_wakeups_affine_attempts;
	u64			nr_wakeups_passive;
	u64			nr_wakeups_idle;
};
#endif
/* 进程调度有一个非常重要的数据结构struct sched_entity,称为调度实体,该数据结构描述进程作为一个调度
 * 实体参与调度所需要的所有信息
 */
struct sched_entity {
	/* load 表示该调度实体的权重 */
	struct load_weight	load;		/* for load-balancing */
	/* run_node表示该调度实体在红黑树中的节点 */
	struct rb_node		run_node;
	struct list_head	group_node;
	/* on_rq表示该调度实体是否在就绪队列中接受调度 */
	unsigned int		on_rq;
	/* 当前调度实体的开始执行时间,感觉是调用update_curr函数的时间 */
	u64			exec_start;
	/* 进程执行的总时间大小 */
	u64			sum_exec_runtime;
	/* vruntime表示虚拟运行时间 */
	u64			vruntime;
	/* prev_sum_exec_runtime表示进程截止目前获取cpu的时间(即执行时间)；
	 * 可以使用sum_exec_runtime- prev_sum_exec_runtime计算进程最近一次调度内获取cpu使用权的时间.
	 * 不过sum_exec_runtime是使用exec_start计算出的时间差的累加
	 */
	u64			prev_sum_exec_runtime;
	/* 负载均衡,迁移的次数? */
	u64			nr_migrations;

#ifdef CONFIG_SCHEDSTATS
	/* 统计信息 */
	struct sched_statistics statistics;
#endif

#ifdef CONFIG_FAIR_GROUP_SCHED
	/* 任务组的深度,其中根任务组的深度为0,逐级往下增加 */
	int			depth;
	/* 指向调度实体的父对象 */
	struct sched_entity	*parent;
	/* rq on which this entity is (to be) queued: */
	/* 指向调度实体归属的CFS队列,也就是需要入列的CFS队列 */
	struct cfs_rq		*cfs_rq;
	/* rq "owned" by this entity/group: */
	/* 指向归属于当前调度实体的CFS队列,用于包含子任务或子的任务组 */
	struct cfs_rq		*my_q;
#endif

#ifdef CONFIG_SMP
	/*
	 * Per entity load average tracking.
	 *
	 * Put into separate cache line so it does not
	 * collide with read-mostly values above.
	 */
	/* 用于调度实体的负载计算('PELT') */
	struct sched_avg	avg ____cacheline_aligned_in_smp;
#endif
};

struct sched_rt_entity {
	struct list_head run_list;
	unsigned long timeout;
	unsigned long watchdog_stamp;
	unsigned int time_slice;
	unsigned short on_rq;
	unsigned short on_list;

	struct sched_rt_entity *back;
#ifdef CONFIG_RT_GROUP_SCHED
	struct sched_rt_entity	*parent;
	/* rq on which this entity is (to be) queued: */
	struct rt_rq		*rt_rq;
	/* rq "owned" by this entity/group: */
	struct rt_rq		*my_q;
#endif
};

struct sched_dl_entity {
	struct rb_node	rb_node;

	/*
	 * Original scheduling parameters. Copied here from sched_attr
	 * during sched_setattr(), they will remain the same until
	 * the next sched_setattr().
	 */
	u64 dl_runtime;		/* maximum runtime for each instance	*/
	u64 dl_deadline;	/* relative deadline of each instance	*/
	u64 dl_period;		/* separation of two instances (period) */
	u64 dl_bw;		/* dl_runtime / dl_deadline		*/

	/*
	 * Actual scheduling parameters. Initialized with the values above,
	 * they are continously updated during task execution. Note that
	 * the remaining runtime could be < 0 in case we are in overrun.
	 */
	s64 runtime;		/* remaining runtime for this instance	*/
	u64 deadline;		/* absolute deadline for this instance	*/
	unsigned int flags;	/* specifying the scheduler behaviour	*/

	/*
	 * Some bool flags:
	 *
	 * @dl_throttled tells if we exhausted the runtime. If so, the
	 * task has to wait for a replenishment to be performed at the
	 * next firing of dl_timer.
	 *
	 * @dl_boosted tells if we are boosted due to DI. If so we are
	 * outside bandwidth enforcement mechanism (but only until we
	 * exit the critical section);
	 *
	 * @dl_yielded tells if task gave up the cpu before consuming
	 * all its available runtime during the last job.
	 */
	int dl_throttled, dl_boosted, dl_yielded;

	/*
	 * Bandwidth enforcement timer. Each -deadline task has its
	 * own bandwidth to be enforced, thus we need one timer per task.
	 */
	struct hrtimer dl_timer;
};

union rcu_special {
	struct {
		u8 blocked;
		u8 need_qs;
		u8 exp_need_qs;
		u8 pad;	/* Otherwise the compiler can store garbage here. */
	} b; /* Bits. */
	u32 s; /* Set of bits. */
};
struct rcu_node;

enum perf_event_task_context {
	perf_invalid_context = -1,
	perf_hw_context = 0,
	perf_sw_context,
	perf_nr_task_contexts,
};

/* Track pages that require TLB flushes */
struct tlbflush_unmap_batch {
	/*
	 * Each bit set is a CPU that potentially has a TLB entry for one of
	 * the PFNs being flushed. See set_tlb_ubc_flush_pending().
	 */
	struct cpumask cpumask;

	/* True if any bit in cpumask is set */
	bool flush_required;

	/*
	 * If true then the PTE was dirty when unmapped. The entry must be
	 * flushed before IO is initiated or a stale TLB entry potentially
	 * allows an update without redirtying the page.
	 */
	bool writable;
};

/*
 * 进程是Linux内核最基本的抽象之一,它是处于执行期的程序,或者说“进程=程序+执行”.
 * 但是进程并不仅局限于一段可执行代码(代码段),它还包括进程需要的其他资源,
 * 例如打开的文件、挂起的信号量、内存管理、处理器状态、一个或者多个执行线程的数据段等.
 * Linux内核通常把进程叫作是任务(task),因此进程控制块(processing control block,PCB)也被命名为struct task_struct.
 * 在20世纪60年代设计的分时操作系统进程最开始被称为工作(iob),后来改名为进程(process).
 *
 * 线程被称为轻量级进程,它是操作系统调度的最小单元,通常一个进程可以拥有多个线程.
 * 线程和进程的区别在于进程拥有独立的资源空间,而线程则共享进程的资源空间.
 * Linux内核并没有对线程有特别的调度算法或定义特别的数据结构来标识线程,线程和进程都使用相同的进程PCB数据结构.
 * 内核里使用clone方法来创建线程,其工作方式和创建进程fork方法类似,但会确定哪些资源和父进程共享,哪些资源为线程独享.
 *
 * 操作系统好比是一个人类社会,时时刻刻都有进程被创建或结束.
 * 进程自有它的生存之道,进程通常通过fork系统调用来创新一个新的进程,新创建的进程可以通过exec函数创建新的地址空间,并载入新的程序.
 * 进程结束可以资源退出或者非自愿退出.
 */
struct task_struct {
#ifdef CONFIG_THREAD_INFO_IN_TASK
	/*
	 * For reasons of header soup (see current_thread_info()), this
	 * must be the first element of task_struct.
	 */
	struct thread_info thread_info;
#endif
	/* 进程的状态 */
	volatile long state;	/* -1 unrunnable, 0 runnable, >0 stopped */
	/* 进程内核栈 */
	void *stack;
	/* 进程描述符使用计数,被置为2时,表示进程描述符正在被使用而且其相应的进程处于活动状态 */
	atomic_t usage;
	/* 进程标记 */
	unsigned int flags;	/* per process flags, defined below */
	/* Ptrace 提供了一种父进程可以控制子进程运行,并可以检查和改变它的核心image.
	 * 它主要用于实现断点调试.
	 * 一个被跟踪的进程运行中,直到发生一个信号.则进程被中止,并且通知其父进程.
	 * 在进程中止的状态下,进程的内存空间可以被读写.
	 * 父进程还可以使子进程继续执行,并选择是否是否忽略引起中止的信号.
	 */
	unsigned int ptrace;

#ifdef CONFIG_SMP
	struct llist_node wake_entry;
	int on_cpu;
#ifdef CONFIG_THREAD_INFO_IN_TASK
	unsigned int cpu;	/* current CPU */
#endif
	/* 该线程唤醒不同wakee的次数,wakee_flips数值越大,则说明该线程唤醒多个不同的任务,并且数值越大,说明唤醒频率较快 */
	unsigned int wakee_flips;
	/* wakee_flips会随时间衰减,这里定义了上次进行衰减的时间点 */
	unsigned long wakee_flip_decay_ts;
	/* 该线程上次唤醒的线程 */
	struct task_struct *last_wakee;

	int wake_cpu;
#endif
	int on_rq;
	/* static_prio: 是静态优先级,在进程启动时分配.
	 *		内核不存储nice值,取而代之的是static_prio.
	 *		内核中宏NICE_TO_PRIO实现由nice值转换成static_prio.
	 *		它之所以被成为静态优先级是因为它不会随着时间而改变,用户可以通过nice或sched_setscheduler等系统调用来修改该值.
	 *
	 * rt_priority 用于保存实时优先级
	 * normal_prio: 是基于static_prio和调度策略计算出来的优先级,在创建进程时会继承父进程的normal_prio.
	 *		对于普通进程来说,normal_prio等同于static_prio,对于实时进程,会根据rt_priority重新计算normal_prio,
	 *		详见effective_prio函数.
	 * prio: 保存着进程的动态优先级,是调度类考虑的优先级,有些情况下是需要暂时提高进程优先级,例如实时互斥量.
	 * rt_priority是实时进程的优先级.
	 */
	int prio, static_prio, normal_prio;
	unsigned int rt_priority;
	/* sched_class 调度类 */
	const struct sched_class *sched_class;
	/* se 普通进程的调用实体,每个进程都有的实体 */
	struct sched_entity se;
	/* rt 实时进程的调用实体,每个进程都有其中之一的实体 */
	struct sched_rt_entity rt;
#ifdef CONFIG_CGROUP_SCHED
	struct task_group *sched_task_group;
#endif
	struct sched_dl_entity dl;

#ifdef CONFIG_PREEMPT_NOTIFIERS
	/* list of struct preempt_notifier: */
	struct hlist_head preempt_notifiers;
#endif

#ifdef CONFIG_BLK_DEV_IO_TRACE
	unsigned int btrace_seq;
#endif
	/* policy 调度策略 */
	unsigned int policy;
	int nr_cpus_allowed;
	/* cpus_allowed	用于控制进程可以在哪里处理器上运行 */
	cpumask_t cpus_allowed;

#ifdef CONFIG_PREEMPT_RCU
	int rcu_read_lock_nesting;
	union rcu_special rcu_read_unlock_special;
	struct list_head rcu_node_entry;
	struct rcu_node *rcu_blocked_node;
#endif /* #ifdef CONFIG_PREEMPT_RCU */
#ifdef CONFIG_TASKS_RCU
	unsigned long rcu_tasks_nvcsw;
	bool rcu_tasks_holdout;
	struct list_head rcu_tasks_holdout_list;
	int rcu_tasks_idle_cpu;
#endif /* #ifdef CONFIG_TASKS_RCU */

#ifdef CONFIG_SCHED_INFO
	struct sched_info sched_info;
#endif

	struct list_head tasks;
#ifdef CONFIG_SMP
	struct plist_node pushable_tasks;
	struct rb_node pushable_dl_tasks;
#endif
	/* mm: 进程所拥有的用户空间内存描述符,内核线程无的mm为NULL
	 * active_mm: active_mm指向进程运行时所使用的内存描述符,对于普通进程而言,这两个指针变量的值相同.
	 * 但是内核线程kernel thread是没有进程地址空间的,所以内核线程的tsk->mm域是空(NULL).
	 * 但是内核必须知道用户空间包含了什么,因此它的active_mm成员被初始化为前一个运行进程的active_mm值.
	 */
	struct mm_struct *mm, *active_mm;
	/* per-thread vma caching */
	u32 vmacache_seqnum;
	struct vm_area_struct *vmacache[VMACACHE_SIZE];
#if defined(SPLIT_RSS_COUNTING)
	/* 用来记录缓冲信息 */
	struct task_rss_stat	rss_stat;
#endif
/* task state */
	int exit_state;
	/* exit_code: 用于设置进程的终止代号,这个值要么是_exit()或exit_group()系统调用参数(正常终止),
	 *	      要么是由内核提供的一个错误代号(异常终止).
	 *
	 * exit_signal: 被置为-1时表示是某个线程组中的一员.
	 *		只有当线程组的最后一个成员终止时,才会产生一个信号,以通知线程组的领头进程的父进程.
	 */
	int exit_code, exit_signal;
	/* pdeath_signal: 用于判断父进程终止时发送信号. */
	int pdeath_signal;  /*  The signal sent when the parent dies  */
	unsigned long jobctl;	/* JOBCTL_*, siglock protected */

	/* Used for emulating ABI behavior of previous Linux versions */
	/* personality: 用于处理不同的ABI
	 * https://man7.org/linux/man-pages/man2/personality.2.html
	 */
	unsigned int personality;

	/* scheduler bits, serialized by scheduler locks */
	/* sched_reset_on_fork: 用于判断是否恢复默认的优先级或调度策略 */
	unsigned sched_reset_on_fork:1;
	unsigned sched_contributes_to_load:1;
	unsigned sched_migrated:1;
	unsigned sched_remote_wakeup:1;
	unsigned :0; /* force alignment to the next boundary */

	/* unserialized, strictly 'current' */
	/* in_execve 用于通知LSM是否被do_execve()函数所调用.
	 * https://lkml.indiana.edu/hypermail/linux/kernel/0901.1/00014.html
	 */
	unsigned in_execve:1; /* bit to tell LSMs we're in execve */
	/* in_iowait: 用于判断是否进行iowait计数 */
	unsigned in_iowait:1;
#if !defined(TIF_RESTORE_SIGMASK)
	unsigned restore_sigmask:1;
#endif
#ifdef CONFIG_MEMCG
	unsigned memcg_may_oom:1;
#ifndef CONFIG_SLOB
	unsigned memcg_kmem_skip_account:1;
#endif
#endif
#ifdef CONFIG_COMPAT_BRK
	/* 用来确定对随机堆内存的探测.
	 * https://lkml.indiana.edu/hypermail/linux/kernel/1104.1/00196.html
	 */
	unsigned brk_randomized:1;
#endif
#ifdef CONFIG_CGROUPS
	/* disallow userland-initiated cgroup migration */
	unsigned no_cgroup_migration:1;
#endif

	unsigned long atomic_flags; /* Flags needing atomic access. */

	struct restart_block restart_block;
	/* Unix系统通过pid来标识进程,linux把不同的pid与系统中每个进程或轻量级线程关联,
	 * 而unix程序员希望同一组线程具有共同的pid,遵照这个标准linux引入线程组的概念.
	 * 一个线程组所有线程与领头线程具有相同的pid,存入tgid字段,getpid()返回当前进程的tgid值而不是pid的值.
	 * 在CONFIG_BASE_SMALL配置为0的情况下,PID的取值范围是0到32767,即系统中的进程数最大为32768个.
	 * #define PID_MAX_DEFAULT (CONFIG_BASE_SMALL ? 0x1000 : 0x8000)
	 * 在Linux系统中,一个线程组中的所有线程使用和该线程组的领头线程(该组中的第一个轻量级进程)相同的PID,并被存放在tgid成员中.
	 * 只有线程组的领头线程的pid成员才会被设置为与tgid相同的值.
	 * 注意,getpid()系统调用返回的是当前进程的tgid值而不是pid值.
	 */
	pid_t pid;
	pid_t tgid;

#ifdef CONFIG_CC_STACKPROTECTOR
	/* Canary value for the -fstack-protector gcc feature */
	unsigned long stack_canary;
#endif
	/*
	 * pointers to (original) parent process, youngest child, younger sibling,
	 * older sibling, respectively.  (p->father can be replaced with
	 * p->real_parent->pid)
	 */

	/* real_parent 指向其父进程,如果创建它的父进程不再存在,则指向PID为1的init进程 */
	struct task_struct __rcu *real_parent; /* real parent process */
	/* 指向其父进程,当它终止时,必须向它的父进程发送信号.它的值通常与real_parent相同 */
	struct task_struct __rcu *parent; /* recipient of SIGCHLD, wait4() reports */
	/*
	 * children/sibling forms the list of my natural children
	 */
	/* children 表示链表的头部,链表中的所有元素都是它的子进程 */
	struct list_head children;	/* list of my children */
	/* sibling 用于把当前进程插入到兄弟链表中 */
	struct list_head sibling;	/* linkage in my parent's children list */
	/* group_leader 指向其所在进程组的领头进程 */
	struct task_struct *group_leader;	/* threadgroup leader */

	/*
	 * ptraced is the list of tasks this task is using ptrace on.
	 * This includes both natural children and PTRACE_ATTACH targets.
	 * p->ptrace_entry is p's link on the p->parent->ptraced list.
	 */
	struct list_head ptraced;
	struct list_head ptrace_entry;

	/* PID/PID hash table linkage. */
	struct pid_link pids[PIDTYPE_MAX];
	struct list_head thread_group;
	struct list_head thread_node;

	struct completion *vfork_done;		/* for vfork() */
	int __user *set_child_tid;		/* CLONE_CHILD_SETTID */
	int __user *clear_child_tid;		/* CLONE_CHILD_CLEARTID */

	/* utime/stime 用于记录进程在用户态/内核态下所经过的节拍数
	 *
	 * utimescaled/stimescaled 用于记录进程在用户态/内核态的运行时间,但它们以处理器的频率为刻度
	 */
	cputime_t utime, stime, utimescaled, stimescaled;
	/* 以节拍计数的虚拟机运行时间(guest time) */
	cputime_t gtime;
	/* 先前的运行时间 */
	struct prev_cputime prev_cputime;
#ifdef CONFIG_VIRT_CPU_ACCOUNTING_GEN
	seqcount_t vtime_seqcount;
	unsigned long long vtime_snap;
	enum {
		/* Task is sleeping or running in a CPU with VTIME inactive */
		VTIME_INACTIVE = 0,
		/* Task runs in userspace in a CPU with VTIME active */
		VTIME_USER,
		/* Task runs in kernelspace in a CPU with VTIME active */
		VTIME_SYS,
	} vtime_snap_whence;
#endif

#ifdef CONFIG_NO_HZ_FULL
	atomic_t tick_dep_mask;
#endif
	/* nvcsw/nivcsw是自愿(voluntary)/非自愿(involuntary)上下文切换计数 */
	unsigned long nvcsw, nivcsw; /* context switch counts */
	/* start_time进程创建时间,real_start_time还包含了进程睡眠时间,常用于/proc/pid/stat
	 * https://lkml.indiana.edu/hypermail/linux/kernel/0705.0/2094.html
	 */
	u64 start_time;		/* monotonic time in nsec */
	u64 real_start_time;	/* boot based time in nsec */
/* mm fault and swap info: this can arguably be seen as either mm-specific or thread-specific */
	unsigned long min_flt, maj_flt;

	/* cputime_expires 用来统计进程或进程组被跟踪的处理器时间,其中的三个成员对应着cpu_timers[3]的三个链表 */
	struct task_cputime cputime_expires;
	struct list_head cpu_timers[3];

/* process credentials */
	const struct cred __rcu *ptracer_cred; /* Tracer's credentials at attach */
	const struct cred __rcu *real_cred; /* objective and real subjective task
					 * credentials (COW) */
	const struct cred __rcu *cred;	/* effective (overridable) subjective task
					 * credentials (COW) */
	char comm[TASK_COMM_LEN]; /* executable name excluding path
				     - access with [gs]et_task_comm (which lock
				       it with task_lock())
				     - initialized normally by setup_new_exec */
/* file system info */
	struct nameidata *nameidata;
#ifdef CONFIG_SYSVIPC
/* ipc stuff */
	struct sysv_sem sysvsem;
	struct sysv_shm sysvshm;
#endif
#ifdef CONFIG_DETECT_HUNG_TASK
/* hung task detection */
	/* nvcsw和nivcsw的总和 */
	unsigned long last_switch_count;
#endif
/* filesystem information */
	struct fs_struct *fs;
/* open file information */
	struct files_struct *files;
/* namespaces */
	struct nsproxy *nsproxy;
/* signal handlers */
	/* signal 指向进程的信号描述符 */
	struct signal_struct *signal;
	/* 指向进程的信号处理程序描述符 */
	struct sighand_struct *sighand;
	/* blocked表示被阻塞信号的掩码,real_blocked表示临时掩码 */
	sigset_t blocked, real_blocked;
	/* 存放私有挂起信号的数据结构 */
	sigset_t saved_sigmask;	/* restored if set_restore_sigmask() was used */
	struct sigpending pending;
	/* sas_ss_sp是信号处理程序备用堆栈的地址,sas_ss_size表示堆栈的大小 */
	unsigned long sas_ss_sp;
	size_t sas_ss_size;
	unsigned sas_ss_flags;

	struct callback_head *task_works;

	struct audit_context *audit_context;
#ifdef CONFIG_AUDITSYSCALL
	kuid_t loginuid;
	unsigned int sessionid;
#endif
	struct seccomp seccomp;

/* Thread group tracking */
   	u32 parent_exec_id;
   	u32 self_exec_id;
/* Protection of (de-)allocation: mm, files, fs, tty, keyrings, mems_allowed,
 * mempolicy */
	/* 用于保护资源分配或释放的自旋锁 */
	spinlock_t alloc_lock;

	/* Protection of the PI data structures: */
	raw_spinlock_t pi_lock;

	struct wake_q_node wake_q;

#ifdef CONFIG_RT_MUTEXES
	/* PI waiters blocked on a rt_mutex held by this task */
	struct rb_root pi_waiters;
	struct rb_node *pi_waiters_leftmost;
	/* Deadlock detection and priority inheritance handling */
	struct rt_mutex_waiter *pi_blocked_on;
#endif

#ifdef CONFIG_DEBUG_MUTEXES
	/* mutex deadlock detection */
	struct mutex_waiter *blocked_on;
#endif
#ifdef CONFIG_TRACE_IRQFLAGS
	unsigned int irq_events;
	unsigned long hardirq_enable_ip;
	unsigned long hardirq_disable_ip;
	unsigned int hardirq_enable_event;
	unsigned int hardirq_disable_event;
	int hardirqs_enabled;
	int hardirq_context;
	unsigned long softirq_disable_ip;
	unsigned long softirq_enable_ip;
	unsigned int softirq_disable_event;
	unsigned int softirq_enable_event;
	int softirqs_enabled;
	int softirq_context;
#endif
#ifdef CONFIG_LOCKDEP
# define MAX_LOCK_DEPTH 48UL
	u64 curr_chain_key;
	int lockdep_depth;
	unsigned int lockdep_recursion;
	struct held_lock held_locks[MAX_LOCK_DEPTH];
	gfp_t lockdep_reclaim_gfp;
#endif
#ifdef CONFIG_UBSAN
	unsigned int in_ubsan;
#endif

/* journalling filesystem info */
	void *journal_info;

/* stacked block device info */
	struct bio_list *bio_list;

#ifdef CONFIG_BLOCK
/* stack plugging */
	struct blk_plug *plug;
#endif

/* VM state */
	struct reclaim_state *reclaim_state;

	struct backing_dev_info *backing_dev_info;

	struct io_context *io_context;

	unsigned long ptrace_message;
	siginfo_t *last_siginfo; /* For ptrace use.  */
	struct task_io_accounting ioac;
#if defined(CONFIG_TASK_XACCT)
	u64 acct_rss_mem1;	/* accumulated rss usage */
	u64 acct_vm_mem1;	/* accumulated virtual memory usage */
	cputime_t acct_timexpd;	/* stime + utime since last update */
#endif
#ifdef CONFIG_CPUSETS
	nodemask_t mems_allowed;	/* Protected by alloc_lock */
	seqcount_t mems_allowed_seq;	/* Seqence no to catch updates */
	int cpuset_mem_spread_rotor;
	int cpuset_slab_spread_rotor;
#endif
#ifdef CONFIG_CGROUPS
	/* Control Group info protected by css_set_lock */
	struct css_set __rcu *cgroups;
	/* cg_list protected by css_set_lock and tsk->alloc_lock */
	struct list_head cg_list;
#endif
#ifdef CONFIG_FUTEX
	struct robust_list_head __user *robust_list;
#ifdef CONFIG_COMPAT
	struct compat_robust_list_head __user *compat_robust_list;
#endif
	struct list_head pi_state_list;
	struct futex_pi_state *pi_state_cache;
#endif
#ifdef CONFIG_PERF_EVENTS
	struct perf_event_context *perf_event_ctxp[perf_nr_task_contexts];
	struct mutex perf_event_mutex;
	struct list_head perf_event_list;
#endif
#ifdef CONFIG_DEBUG_PREEMPT
	unsigned long preempt_disable_ip;
#endif
#ifdef CONFIG_NUMA
	/* 进程的NUMA内存分配策略 */
	struct mempolicy *mempolicy;	/* Protected by alloc_lock */
	/* task_struct结构的il_next变量获取本次进行分配的节点号，
	 * 并把下次要进行分配的节点号存入il_next变量.
	 */
	short il_next;
	short pref_node_fork;
#endif
#ifdef CONFIG_NUMA_BALANCING
	int numa_scan_seq;
	unsigned int numa_scan_period;
	unsigned int numa_scan_period_max;
	int numa_preferred_nid;
	unsigned long numa_migrate_retry;
	u64 node_stamp;			/* migration stamp  */
	u64 last_task_numa_placement;
	u64 last_sum_exec_runtime;
	struct callback_head numa_work;

	struct list_head numa_entry;
	struct numa_group *numa_group;

	/*
	 * numa_faults is an array split into four regions:
	 * faults_memory, faults_cpu, faults_memory_buffer, faults_cpu_buffer
	 * in this precise order.
	 *
	 * faults_memory: Exponential decaying average of faults on a per-node
	 * basis. Scheduling placement decisions are made based on these
	 * counts. The values remain static for the duration of a PTE scan.
	 * faults_cpu: Track the nodes the process was running on when a NUMA
	 * hinting fault was incurred.
	 * faults_memory_buffer and faults_cpu_buffer: Record faults per node
	 * during the current scan window. When the scan completes, the counts
	 * in faults_memory and faults_cpu decay and these values are copied.
	 */
	unsigned long *numa_faults;
	unsigned long total_numa_faults;

	/*
	 * numa_faults_locality tracks if faults recorded during the last
	 * scan window were remote/local or failed to migrate. The task scan
	 * period is adapted based on the locality of the faults with different
	 * weights depending on whether they were shared or private faults
	 */
	unsigned long numa_faults_locality[3];

	unsigned long numa_pages_migrated;
#endif /* CONFIG_NUMA_BALANCING */

#ifdef CONFIG_ARCH_WANT_BATCHED_UNMAP_TLB_FLUSH
	struct tlbflush_unmap_batch tlb_ubc;
#endif

	struct rcu_head rcu;

	/*
	 * cache last used pipe for splice
	 */
	struct pipe_inode_info *splice_pipe;

	struct page_frag task_frag;

#ifdef	CONFIG_TASK_DELAY_ACCT
	struct task_delay_info *delays;
#endif
#ifdef CONFIG_FAULT_INJECTION
	int make_it_fail;
#endif
	/*
	 * when (nr_dirtied >= nr_dirtied_pause), it's time to call
	 * balance_dirty_pages() for some dirty throttling pause
	 */
	/* nr_dirtied表明当前进程脏页数量,初始化为0.
	 * nr_dirtied_pause是一个限制值,初始为32,即128KB
	 * 进行写文件,nr_dirtied值增加1,每写一个page就会增加1,并每次都会在balance_dirty_pages_ratelimited中查看
	 * nr_dirtied值是否达到了nr_dirtied_pause的限制值,如果达到了则启用脏页平衡机制(balance_drity_pages)
	 */
	int nr_dirtied;
	int nr_dirtied_pause;
	/* dirty_paused_when是进程上一次执行balance_dirty_pages()脏页平衡的时间点(或者再加上休眠的时间点) */
	unsigned long dirty_paused_when; /* start of a write-and-pause period */

#ifdef CONFIG_LATENCYTOP
	int latency_record_count;
	struct latency_record latency_record[LT_SAVECOUNT];
#endif
	/*
	 * time slack values; these are used to round up poll() and
	 * select() etc timeout values. These are in nanoseconds.
	 */
	u64 timer_slack_ns;
	u64 default_timer_slack_ns;

#ifdef CONFIG_KASAN
	unsigned int kasan_depth;
#endif
#ifdef CONFIG_FUNCTION_GRAPH_TRACER
	/* Index of current stored address in ret_stack */
	int curr_ret_stack;
	/* Stack of return addresses for return function tracing */
	struct ftrace_ret_stack	*ret_stack;
	/* time stamp for last schedule */
	unsigned long long ftrace_timestamp;
	/*
	 * Number of functions that haven't been traced
	 * because of depth overrun.
	 */
	atomic_t trace_overrun;
	/* Pause for the tracing */
	atomic_t tracing_graph_pause;
#endif
#ifdef CONFIG_TRACING
	/* state flags for use by tracers */
	unsigned long trace;
	/* bitmask and counter of trace recursion */
	unsigned long trace_recursion;
#endif /* CONFIG_TRACING */
#ifdef CONFIG_KCOV
	/* Coverage collection mode enabled for this task (0 if disabled). */
	enum kcov_mode kcov_mode;
	/* Size of the kcov_area. */
	unsigned	kcov_size;
	/* Buffer for coverage collection. */
	void		*kcov_area;
	/* kcov desciptor wired with this task or NULL. */
	struct kcov	*kcov;
#endif
#ifdef CONFIG_MEMCG
	struct mem_cgroup *memcg_in_oom;
	gfp_t memcg_oom_gfp_mask;
	int memcg_oom_order;

	/* number of pages to reclaim on returning to userland */
	unsigned int memcg_nr_pages_over_high;
#endif
#ifdef CONFIG_UPROBES
	struct uprobe_task *utask;
#endif
#if defined(CONFIG_BCACHE) || defined(CONFIG_BCACHE_MODULE)
	unsigned int	sequential_io;
	unsigned int	sequential_io_avg;
#endif
#ifdef CONFIG_DEBUG_ATOMIC_SLEEP
	unsigned long	task_state_change;
#endif
	int pagefault_disabled;
#ifdef CONFIG_MMU
	struct task_struct *oom_reaper_list;
#endif
#ifdef CONFIG_VMAP_STACK
	struct vm_struct *stack_vm_area;
#endif
#ifdef CONFIG_THREAD_INFO_IN_TASK
	/* A live task holds one reference. */
	atomic_t stack_refcount;
#endif
/* CPU-specific state of this task */
	struct thread_struct thread;
/*
 * WARNING: on x86, 'thread_struct' contains a variable-sized
 * structure.  It *MUST* be at the end of 'task_struct'.
 *
 * Do not put anything below here!
 */
};

#ifdef CONFIG_ARCH_WANTS_DYNAMIC_TASK_STRUCT
extern int arch_task_struct_size __read_mostly;
#else
# define arch_task_struct_size (sizeof(struct task_struct))
#endif

#ifdef CONFIG_VMAP_STACK
static inline struct vm_struct *task_stack_vm_area(const struct task_struct *t)
{
	return t->stack_vm_area;
}
#else
static inline struct vm_struct *task_stack_vm_area(const struct task_struct *t)
{
	return NULL;
}
#endif

/* Future-safe accessor for struct task_struct's cpus_allowed. */
#define tsk_cpus_allowed(tsk) (&(tsk)->cpus_allowed)

static inline int tsk_nr_cpus_allowed(struct task_struct *p)
{
	return p->nr_cpus_allowed;
}

#define TNF_MIGRATED	0x01
#define TNF_NO_GROUP	0x02
#define TNF_SHARED	0x04
#define TNF_FAULT_LOCAL	0x08
#define TNF_MIGRATE_FAIL 0x10

static inline bool in_vfork(struct task_struct *tsk)
{
	bool ret;

	/*
	 * need RCU to access ->real_parent if CLONE_VM was used along with
	 * CLONE_PARENT.
	 *
	 * We check real_parent->mm == tsk->mm because CLONE_VFORK does not
	 * imply CLONE_VM
	 *
	 * CLONE_VFORK can be used with CLONE_PARENT/CLONE_THREAD and thus
	 * ->real_parent is not necessarily the task doing vfork(), so in
	 * theory we can't rely on task_lock() if we want to dereference it.
	 *
	 * And in this case we can't trust the real_parent->mm == tsk->mm
	 * check, it can be false negative. But we do not care, if init or
	 * another oom-unkillable task does this it should blame itself.
	 */
	rcu_read_lock();
	ret = tsk->vfork_done && tsk->real_parent->mm == tsk->mm;
	rcu_read_unlock();

	return ret;
}

#ifdef CONFIG_NUMA_BALANCING
extern void task_numa_fault(int last_node, int node, int pages, int flags);
extern pid_t task_numa_group_id(struct task_struct *p);
extern void set_numabalancing_state(bool enabled);
extern void task_numa_free(struct task_struct *p);
extern bool should_numa_migrate_memory(struct task_struct *p, struct page *page,
					int src_nid, int dst_cpu);
#else
static inline void task_numa_fault(int last_node, int node, int pages,
				   int flags)
{
}
static inline pid_t task_numa_group_id(struct task_struct *p)
{
	return 0;
}
static inline void set_numabalancing_state(bool enabled)
{
}
static inline void task_numa_free(struct task_struct *p)
{
}
static inline bool should_numa_migrate_memory(struct task_struct *p,
				struct page *page, int src_nid, int dst_cpu)
{
	return true;
}
#endif

static inline struct pid *task_pid(struct task_struct *task)
{
	return task->pids[PIDTYPE_PID].pid;
}

static inline struct pid *task_tgid(struct task_struct *task)
{
	return task->group_leader->pids[PIDTYPE_PID].pid;
}

/*
 * Without tasklist or rcu lock it is not safe to dereference
 * the result of task_pgrp/task_session even if task == current,
 * we can race with another thread doing sys_setsid/sys_setpgid.
 */
static inline struct pid *task_pgrp(struct task_struct *task)
{
	return task->group_leader->pids[PIDTYPE_PGID].pid;
}

static inline struct pid *task_session(struct task_struct *task)
{
	return task->group_leader->pids[PIDTYPE_SID].pid;
}

struct pid_namespace;

/*
 * the helpers to get the task's different pids as they are seen
 * from various namespaces
 *
 * task_xid_nr()     : global id, i.e. the id seen from the init namespace;
 * task_xid_vnr()    : virtual id, i.e. the id seen from the pid namespace of
 *                     current.
 * task_xid_nr_ns()  : id seen from the ns specified;
 *
 * set_task_vxid()   : assigns a virtual id to a task;
 *
 * see also pid_nr() etc in include/linux/pid.h
 */
pid_t __task_pid_nr_ns(struct task_struct *task, enum pid_type type,
			struct pid_namespace *ns);

static inline pid_t task_pid_nr(struct task_struct *tsk)
{
	return tsk->pid;
}

static inline pid_t task_pid_nr_ns(struct task_struct *tsk,
					struct pid_namespace *ns)
{
	return __task_pid_nr_ns(tsk, PIDTYPE_PID, ns);
}

static inline pid_t task_pid_vnr(struct task_struct *tsk)
{
	return __task_pid_nr_ns(tsk, PIDTYPE_PID, NULL);
}


static inline pid_t task_tgid_nr(struct task_struct *tsk)
{
	return tsk->tgid;
}

pid_t task_tgid_nr_ns(struct task_struct *tsk, struct pid_namespace *ns);

static inline pid_t task_tgid_vnr(struct task_struct *tsk)
{
	return pid_vnr(task_tgid(tsk));
}


static inline int pid_alive(const struct task_struct *p);
static inline pid_t task_ppid_nr_ns(const struct task_struct *tsk, struct pid_namespace *ns)
{
	pid_t pid = 0;

	rcu_read_lock();
	if (pid_alive(tsk))
		pid = task_tgid_nr_ns(rcu_dereference(tsk->real_parent), ns);
	rcu_read_unlock();

	return pid;
}

static inline pid_t task_ppid_nr(const struct task_struct *tsk)
{
	return task_ppid_nr_ns(tsk, &init_pid_ns);
}

static inline pid_t task_pgrp_nr_ns(struct task_struct *tsk,
					struct pid_namespace *ns)
{
	return __task_pid_nr_ns(tsk, PIDTYPE_PGID, ns);
}

static inline pid_t task_pgrp_vnr(struct task_struct *tsk)
{
	return __task_pid_nr_ns(tsk, PIDTYPE_PGID, NULL);
}


static inline pid_t task_session_nr_ns(struct task_struct *tsk,
					struct pid_namespace *ns)
{
	return __task_pid_nr_ns(tsk, PIDTYPE_SID, ns);
}

static inline pid_t task_session_vnr(struct task_struct *tsk)
{
	return __task_pid_nr_ns(tsk, PIDTYPE_SID, NULL);
}

/* obsolete, do not use */
static inline pid_t task_pgrp_nr(struct task_struct *tsk)
{
	return task_pgrp_nr_ns(tsk, &init_pid_ns);
}

/**
 * pid_alive - check that a task structure is not stale
 * @p: Task structure to be checked.
 *
 * Test if a process is not yet dead (at most zombie state)
 * If pid_alive fails, then pointers within the task structure
 * can be stale and must not be dereferenced.
 *
 * Return: 1 if the process is alive. 0 otherwise.
 */
static inline int pid_alive(const struct task_struct *p)
{
	return p->pids[PIDTYPE_PID].pid != NULL;
}

/**
 * is_global_init - check if a task structure is init. Since init
 * is free to have sub-threads we need to check tgid.
 * @tsk: Task structure to be checked.
 *
 * Check if a task structure is the first user space task the kernel created.
 *
 * Return: 1 if the task structure is init. 0 otherwise.
 */
static inline int is_global_init(struct task_struct *tsk)
{
	return task_tgid_nr(tsk) == 1;
}

extern struct pid *cad_pid;

extern void free_task(struct task_struct *tsk);
#define get_task_struct(tsk) do { atomic_inc(&(tsk)->usage); } while(0)

extern void __put_task_struct(struct task_struct *t);

static inline void put_task_struct(struct task_struct *t)
{
	if (atomic_dec_and_test(&t->usage))
		__put_task_struct(t);
}

struct task_struct *task_rcu_dereference(struct task_struct **ptask);
struct task_struct *try_get_task_struct(struct task_struct **ptask);

#ifdef CONFIG_VIRT_CPU_ACCOUNTING_GEN
extern void task_cputime(struct task_struct *t,
			 cputime_t *utime, cputime_t *stime);
extern void task_cputime_scaled(struct task_struct *t,
				cputime_t *utimescaled, cputime_t *stimescaled);
extern cputime_t task_gtime(struct task_struct *t);
#else
static inline void task_cputime(struct task_struct *t,
				cputime_t *utime, cputime_t *stime)
{
	if (utime)
		*utime = t->utime;
	if (stime)
		*stime = t->stime;
}

static inline void task_cputime_scaled(struct task_struct *t,
				       cputime_t *utimescaled,
				       cputime_t *stimescaled)
{
	if (utimescaled)
		*utimescaled = t->utimescaled;
	if (stimescaled)
		*stimescaled = t->stimescaled;
}

static inline cputime_t task_gtime(struct task_struct *t)
{
	return t->gtime;
}
#endif
extern void task_cputime_adjusted(struct task_struct *p, cputime_t *ut, cputime_t *st);
extern void thread_group_cputime_adjusted(struct task_struct *p, cputime_t *ut, cputime_t *st);

/*
 * Per process flags
 */
#define PF_EXITING	0x00000004	/* getting shut down */
#define PF_EXITPIDONE	0x00000008	/* pi exit done on shut down */
#define PF_VCPU		0x00000010	/* I'm a virtual CPU */
/* worker线程,worker线程由工作队列机制创建 */
#define PF_WQ_WORKER	0x00000020	/* I'm a workqueue worker */
/* fork了但是不执行 */
#define PF_FORKNOEXEC	0x00000040	/* forked but didn't exec */
#define PF_MCE_PROCESS  0x00000080      /* process policy on mce errors */
/* 使用超级用户权限 */
#define PF_SUPERPRIV	0x00000100	/* used super-user privileges */
#define PF_DUMPCORE	0x00000200	/* dumped core */
#define PF_SIGNALED	0x00000400	/* killed by a signal */
#define PF_MEMALLOC	0x00000800	/* Allocating memory */
#define PF_NPROC_EXCEEDED 0x00001000	/* set_user noticed that RLIMIT_NPROC was exceeded */
#define PF_USED_MATH	0x00002000	/* if unset the fpu must be initialized before use */
#define PF_USED_ASYNC	0x00004000	/* used async_schedule*(), used by module init */
#define PF_NOFREEZE	0x00008000	/* this thread should not be frozen */
#define PF_FROZEN	0x00010000	/* frozen for system suspend */
#define PF_FSTRANS	0x00020000	/* inside a filesystem transaction */
#define PF_KSWAPD	0x00040000	/* I am kswapd */
#define PF_MEMALLOC_NOIO 0x00080000	/* Allocating memory without IO involved */
#define PF_LESS_THROTTLE 0x00100000	/* Throttle me less: I clean memory */
#define PF_KTHREAD	0x00200000	/* I am a kernel thread */
#define PF_RANDOMIZE	0x00400000	/* randomize virtual address space */
#define PF_SWAPWRITE	0x00800000	/* Allowed to write to swap */
#define PF_NO_SETAFFINITY 0x04000000	/* Userland is not allowed to meddle with cpus_allowed */
#define PF_MCE_EARLY    0x08000000      /* Early kill for mce process policy */
#define PF_MUTEX_TESTER	0x20000000	/* Thread belongs to the rt mutex tester */
#define PF_FREEZER_SKIP	0x40000000	/* Freezer should not count it as freezable */
#define PF_SUSPEND_TASK 0x80000000      /* this thread called freeze_processes and should not be frozen */

/*
 * Only the _current_ task can read/write to tsk->flags, but other
 * tasks can access tsk->flags in readonly mode for example
 * with tsk_used_math (like during threaded core dumping).
 * There is however an exception to this rule during ptrace
 * or during fork: the ptracer task is allowed to write to the
 * child->flags of its traced child (same goes for fork, the parent
 * can write to the child->flags), because we're guaranteed the
 * child is not running and in turn not changing child->flags
 * at the same time the parent does it.
 */
#define clear_stopped_child_used_math(child) do { (child)->flags &= ~PF_USED_MATH; } while (0)
#define set_stopped_child_used_math(child) do { (child)->flags |= PF_USED_MATH; } while (0)
#define clear_used_math() clear_stopped_child_used_math(current)
#define set_used_math() set_stopped_child_used_math(current)
#define conditional_stopped_child_used_math(condition, child) \
	do { (child)->flags &= ~PF_USED_MATH, (child)->flags |= (condition) ? PF_USED_MATH : 0; } while (0)
#define conditional_used_math(condition) \
	conditional_stopped_child_used_math(condition, current)
#define copy_to_stopped_child_used_math(child) \
	do { (child)->flags &= ~PF_USED_MATH, (child)->flags |= current->flags & PF_USED_MATH; } while (0)
/* NOTE: this will return 0 or PF_USED_MATH, it will never return 1 */
#define tsk_used_math(p) ((p)->flags & PF_USED_MATH)
#define used_math() tsk_used_math(current)

/* __GFP_IO isn't allowed if PF_MEMALLOC_NOIO is set in current->flags
 * __GFP_FS is also cleared as it implies __GFP_IO.
 */
static inline gfp_t memalloc_noio_flags(gfp_t flags)
{
	if (unlikely(current->flags & PF_MEMALLOC_NOIO))
		flags &= ~(__GFP_IO | __GFP_FS);
	return flags;
}

static inline unsigned int memalloc_noio_save(void)
{
	unsigned int flags = current->flags & PF_MEMALLOC_NOIO;
	current->flags |= PF_MEMALLOC_NOIO;
	return flags;
}

static inline void memalloc_noio_restore(unsigned int flags)
{
	current->flags = (current->flags & ~PF_MEMALLOC_NOIO) | flags;
}

/* Per-process atomic flags. */
#define PFA_NO_NEW_PRIVS 0	/* May not gain new privileges. */
#define PFA_SPREAD_PAGE  1      /* Spread page cache over cpuset */
#define PFA_SPREAD_SLAB  2      /* Spread some slab caches over cpuset */
#define PFA_LMK_WAITING  3      /* Lowmemorykiller is waiting */


#define TASK_PFA_TEST(name, func)					\
	static inline bool task_##func(struct task_struct *p)		\
	{ return test_bit(PFA_##name, &p->atomic_flags); }
#define TASK_PFA_SET(name, func)					\
	static inline void task_set_##func(struct task_struct *p)	\
	{ set_bit(PFA_##name, &p->atomic_flags); }
#define TASK_PFA_CLEAR(name, func)					\
	static inline void task_clear_##func(struct task_struct *p)	\
	{ clear_bit(PFA_##name, &p->atomic_flags); }

TASK_PFA_TEST(NO_NEW_PRIVS, no_new_privs)
TASK_PFA_SET(NO_NEW_PRIVS, no_new_privs)

TASK_PFA_TEST(SPREAD_PAGE, spread_page)
TASK_PFA_SET(SPREAD_PAGE, spread_page)
TASK_PFA_CLEAR(SPREAD_PAGE, spread_page)

TASK_PFA_TEST(SPREAD_SLAB, spread_slab)
TASK_PFA_SET(SPREAD_SLAB, spread_slab)
TASK_PFA_CLEAR(SPREAD_SLAB, spread_slab)

TASK_PFA_TEST(LMK_WAITING, lmk_waiting)
TASK_PFA_SET(LMK_WAITING, lmk_waiting)

/*
 * task->jobctl flags
 */
#define JOBCTL_STOP_SIGMASK	0xffff	/* signr of the last group stop */

#define JOBCTL_STOP_DEQUEUED_BIT 16	/* stop signal dequeued */
#define JOBCTL_STOP_PENDING_BIT	17	/* task should stop for group stop */
#define JOBCTL_STOP_CONSUME_BIT	18	/* consume group stop count */
#define JOBCTL_TRAP_STOP_BIT	19	/* trap for STOP */
#define JOBCTL_TRAP_NOTIFY_BIT	20	/* trap for NOTIFY */
#define JOBCTL_TRAPPING_BIT	21	/* switching to TRACED */
#define JOBCTL_LISTENING_BIT	22	/* ptracer is listening for events */

#define JOBCTL_STOP_DEQUEUED	(1UL << JOBCTL_STOP_DEQUEUED_BIT)
#define JOBCTL_STOP_PENDING	(1UL << JOBCTL_STOP_PENDING_BIT)
#define JOBCTL_STOP_CONSUME	(1UL << JOBCTL_STOP_CONSUME_BIT)
#define JOBCTL_TRAP_STOP	(1UL << JOBCTL_TRAP_STOP_BIT)
#define JOBCTL_TRAP_NOTIFY	(1UL << JOBCTL_TRAP_NOTIFY_BIT)
#define JOBCTL_TRAPPING		(1UL << JOBCTL_TRAPPING_BIT)
#define JOBCTL_LISTENING	(1UL << JOBCTL_LISTENING_BIT)

#define JOBCTL_TRAP_MASK	(JOBCTL_TRAP_STOP | JOBCTL_TRAP_NOTIFY)
#define JOBCTL_PENDING_MASK	(JOBCTL_STOP_PENDING | JOBCTL_TRAP_MASK)

extern bool task_set_jobctl_pending(struct task_struct *task,
				    unsigned long mask);
extern void task_clear_jobctl_trapping(struct task_struct *task);
extern void task_clear_jobctl_pending(struct task_struct *task,
				      unsigned long mask);

static inline void rcu_copy_process(struct task_struct *p)
{
#ifdef CONFIG_PREEMPT_RCU
	p->rcu_read_lock_nesting = 0;
	p->rcu_read_unlock_special.s = 0;
	p->rcu_blocked_node = NULL;
	INIT_LIST_HEAD(&p->rcu_node_entry);
#endif /* #ifdef CONFIG_PREEMPT_RCU */
#ifdef CONFIG_TASKS_RCU
	p->rcu_tasks_holdout = false;
	INIT_LIST_HEAD(&p->rcu_tasks_holdout_list);
	p->rcu_tasks_idle_cpu = -1;
#endif /* #ifdef CONFIG_TASKS_RCU */
}

static inline void tsk_restore_flags(struct task_struct *task,
				unsigned long orig_flags, unsigned long flags)
{
	task->flags &= ~flags;
	task->flags |= orig_flags & flags;
}

extern int cpuset_cpumask_can_shrink(const struct cpumask *cur,
				     const struct cpumask *trial);
extern int task_can_attach(struct task_struct *p,
			   const struct cpumask *cs_cpus_allowed);
#ifdef CONFIG_SMP
extern void do_set_cpus_allowed(struct task_struct *p,
			       const struct cpumask *new_mask);

extern int set_cpus_allowed_ptr(struct task_struct *p,
				const struct cpumask *new_mask);
#else
static inline void do_set_cpus_allowed(struct task_struct *p,
				      const struct cpumask *new_mask)
{
}
static inline int set_cpus_allowed_ptr(struct task_struct *p,
				       const struct cpumask *new_mask)
{
	if (!cpumask_test_cpu(0, new_mask))
		return -EINVAL;
	return 0;
}
#endif

#ifdef CONFIG_NO_HZ_COMMON
void calc_load_enter_idle(void);
void calc_load_exit_idle(void);
#else
static inline void calc_load_enter_idle(void) { }
static inline void calc_load_exit_idle(void) { }
#endif /* CONFIG_NO_HZ_COMMON */

/*
 * Do not use outside of architecture code which knows its limitations.
 *
 * sched_clock() has no promise of monotonicity or bounded drift between
 * CPUs, use (which you should not) requires disabling IRQs.
 *
 * Please use one of the three interfaces below.
 */
extern unsigned long long notrace sched_clock(void);
/*
 * See the comment in kernel/sched/clock.c
 */
extern u64 running_clock(void);
extern u64 sched_clock_cpu(int cpu);


extern void sched_clock_init(void);

#ifndef CONFIG_HAVE_UNSTABLE_SCHED_CLOCK
static inline void sched_clock_tick(void)
{
}

static inline void sched_clock_idle_sleep_event(void)
{
}

static inline void sched_clock_idle_wakeup_event(u64 delta_ns)
{
}

static inline u64 cpu_clock(int cpu)
{
	return sched_clock();
}

static inline u64 local_clock(void)
{
	return sched_clock();
}
#else
/*
 * Architectures can set this to 1 if they have specified
 * CONFIG_HAVE_UNSTABLE_SCHED_CLOCK in their arch Kconfig,
 * but then during bootup it turns out that sched_clock()
 * is reliable after all:
 */
extern int sched_clock_stable(void);
extern void set_sched_clock_stable(void);
extern void clear_sched_clock_stable(void);

extern void sched_clock_tick(void);
extern void sched_clock_idle_sleep_event(void);
extern void sched_clock_idle_wakeup_event(u64 delta_ns);

/*
 * As outlined in clock.c, provides a fast, high resolution, nanosecond
 * time source that is monotonic per cpu argument and has bounded drift
 * between cpus.
 *
 * ######################### BIG FAT WARNING ##########################
 * # when comparing cpu_clock(i) to cpu_clock(j) for i != j, time can #
 * # go backwards !!                                                  #
 * ####################################################################
 */
static inline u64 cpu_clock(int cpu)
{
	return sched_clock_cpu(cpu);
}

static inline u64 local_clock(void)
{
	return sched_clock_cpu(raw_smp_processor_id());
}
#endif

#ifdef CONFIG_IRQ_TIME_ACCOUNTING
/*
 * An i/f to runtime opt-in for irq time accounting based off of sched_clock.
 * The reason for this explicit opt-in is not to have perf penalty with
 * slow sched_clocks.
 */
extern void enable_sched_clock_irqtime(void);
extern void disable_sched_clock_irqtime(void);
#else
static inline void enable_sched_clock_irqtime(void) {}
static inline void disable_sched_clock_irqtime(void) {}
#endif

extern unsigned long long
task_sched_runtime(struct task_struct *task);

/* sched_exec is called by processes performing an exec */
#ifdef CONFIG_SMP
extern void sched_exec(void);
#else
#define sched_exec()   {}
#endif

extern void sched_clock_idle_sleep_event(void);
extern void sched_clock_idle_wakeup_event(u64 delta_ns);

#ifdef CONFIG_HOTPLUG_CPU
extern void idle_task_exit(void);
#else
static inline void idle_task_exit(void) {}
#endif

#if defined(CONFIG_NO_HZ_COMMON) && defined(CONFIG_SMP)
extern void wake_up_nohz_cpu(int cpu);
#else
static inline void wake_up_nohz_cpu(int cpu) { }
#endif

#ifdef CONFIG_NO_HZ_FULL
extern u64 scheduler_tick_max_deferment(void);
#endif

#ifdef CONFIG_SCHED_AUTOGROUP
extern void sched_autogroup_create_attach(struct task_struct *p);
extern void sched_autogroup_detach(struct task_struct *p);
extern void sched_autogroup_fork(struct signal_struct *sig);
extern void sched_autogroup_exit(struct signal_struct *sig);
extern void sched_autogroup_exit_task(struct task_struct *p);
#ifdef CONFIG_PROC_FS
extern void proc_sched_autogroup_show_task(struct task_struct *p, struct seq_file *m);
extern int proc_sched_autogroup_set_nice(struct task_struct *p, int nice);
#endif
#else
static inline void sched_autogroup_create_attach(struct task_struct *p) { }
static inline void sched_autogroup_detach(struct task_struct *p) { }
static inline void sched_autogroup_fork(struct signal_struct *sig) { }
static inline void sched_autogroup_exit(struct signal_struct *sig) { }
static inline void sched_autogroup_exit_task(struct task_struct *p) { }
#endif

extern int yield_to(struct task_struct *p, bool preempt);
extern void set_user_nice(struct task_struct *p, long nice);
extern int task_prio(const struct task_struct *p);
/**
 * task_nice - return the nice value of a given task.
 * @p: the task in question.
 *
 * Return: The nice value [ -20 ... 0 ... 19 ].
 */
static inline int task_nice(const struct task_struct *p)
{
	return PRIO_TO_NICE((p)->static_prio);
}
extern int can_nice(const struct task_struct *p, const int nice);
extern int task_curr(const struct task_struct *p);
extern int idle_cpu(int cpu);
extern int sched_setscheduler(struct task_struct *, int,
			      const struct sched_param *);
extern int sched_setscheduler_nocheck(struct task_struct *, int,
				      const struct sched_param *);
extern int sched_setattr(struct task_struct *,
			 const struct sched_attr *);
extern struct task_struct *idle_task(int cpu);
/**
 * is_idle_task - is the specified task an idle task?
 * @p: the task in question.
 *
 * Return: 1 if @p is an idle task. 0 otherwise.
 */
static inline bool is_idle_task(const struct task_struct *p)
{
	return p->pid == 0;
}
extern struct task_struct *curr_task(int cpu);
extern void ia64_set_curr_task(int cpu, struct task_struct *p);

void yield(void);

union thread_union {
#ifndef CONFIG_THREAD_INFO_IN_TASK
	struct thread_info thread_info;
#endif
	unsigned long stack[THREAD_SIZE/sizeof(long)];
};

#ifndef __HAVE_ARCH_KSTACK_END
static inline int kstack_end(void *addr)
{
	/* Reliable end of stack detection:
	 * Some APM bios versions misalign the stack
	 */
	return !(((unsigned long)addr+sizeof(void*)-1) & (THREAD_SIZE-sizeof(void*)));
}
#endif

extern union thread_union init_thread_union;
extern struct task_struct init_task;

extern struct   mm_struct init_mm;

extern struct pid_namespace init_pid_ns;

/*
 * find a task by one of its numerical ids
 *
 * find_task_by_pid_ns():
 *      finds a task by its pid in the specified namespace
 * find_task_by_vpid():
 *      finds a task by its virtual pid
 *
 * see also find_vpid() etc in include/linux/pid.h
 */

extern struct task_struct *find_task_by_vpid(pid_t nr);
extern struct task_struct *find_task_by_pid_ns(pid_t nr,
		struct pid_namespace *ns);

/* per-UID process charging. */
extern struct user_struct * alloc_uid(kuid_t);
static inline struct user_struct *get_uid(struct user_struct *u)
{
	atomic_inc(&u->__count);
	return u;
}
extern void free_uid(struct user_struct *);

#include <asm/current.h>

extern void xtime_update(unsigned long ticks);

extern int wake_up_state(struct task_struct *tsk, unsigned int state);
extern int wake_up_process(struct task_struct *tsk);
extern void wake_up_new_task(struct task_struct *tsk);
#ifdef CONFIG_SMP
 extern void kick_process(struct task_struct *tsk);
#else
 static inline void kick_process(struct task_struct *tsk) { }
#endif
extern int sched_fork(unsigned long clone_flags, struct task_struct *p);
extern void sched_dead(struct task_struct *p);

extern void proc_caches_init(void);
extern void flush_signals(struct task_struct *);
extern void ignore_signals(struct task_struct *);
extern void flush_signal_handlers(struct task_struct *, int force_default);
extern int dequeue_signal(struct task_struct *tsk, sigset_t *mask, siginfo_t *info);

static inline int kernel_dequeue_signal(siginfo_t *info)
{
	struct task_struct *tsk = current;
	siginfo_t __info;
	int ret;

	spin_lock_irq(&tsk->sighand->siglock);
	ret = dequeue_signal(tsk, &tsk->blocked, info ?: &__info);
	spin_unlock_irq(&tsk->sighand->siglock);

	return ret;
}

static inline void kernel_signal_stop(void)
{
	spin_lock_irq(&current->sighand->siglock);
	if (current->jobctl & JOBCTL_STOP_DEQUEUED)
		__set_current_state(TASK_STOPPED);
	spin_unlock_irq(&current->sighand->siglock);

	schedule();
}

extern void release_task(struct task_struct * p);
extern int send_sig_info(int, struct siginfo *, struct task_struct *);
extern int force_sigsegv(int, struct task_struct *);
extern int force_sig_info(int, struct siginfo *, struct task_struct *);
extern int __kill_pgrp_info(int sig, struct siginfo *info, struct pid *pgrp);
extern int kill_pid_info(int sig, struct siginfo *info, struct pid *pid);
extern int kill_pid_info_as_cred(int, struct siginfo *, struct pid *,
				const struct cred *, u32);
extern int kill_pgrp(struct pid *pid, int sig, int priv);
extern int kill_pid(struct pid *pid, int sig, int priv);
extern int kill_proc_info(int, struct siginfo *, pid_t);
extern __must_check bool do_notify_parent(struct task_struct *, int);
extern void __wake_up_parent(struct task_struct *p, struct task_struct *parent);
extern void force_sig(int, struct task_struct *);
extern int send_sig(int, struct task_struct *, int);
extern int zap_other_threads(struct task_struct *p);
extern struct sigqueue *sigqueue_alloc(void);
extern void sigqueue_free(struct sigqueue *);
extern int send_sigqueue(struct sigqueue *,  struct task_struct *, int group);
extern int do_sigaction(int, struct k_sigaction *, struct k_sigaction *);

#ifdef TIF_RESTORE_SIGMASK
/*
 * Legacy restore_sigmask accessors.  These are inefficient on
 * SMP architectures because they require atomic operations.
 */

/**
 * set_restore_sigmask() - make sure saved_sigmask processing gets done
 *
 * This sets TIF_RESTORE_SIGMASK and ensures that the arch signal code
 * will run before returning to user mode, to process the flag.  For
 * all callers, TIF_SIGPENDING is already set or it's no harm to set
 * it.  TIF_RESTORE_SIGMASK need not be in the set of bits that the
 * arch code will notice on return to user mode, in case those bits
 * are scarce.  We set TIF_SIGPENDING here to ensure that the arch
 * signal code always gets run when TIF_RESTORE_SIGMASK is set.
 */
static inline void set_restore_sigmask(void)
{
	set_thread_flag(TIF_RESTORE_SIGMASK);
	WARN_ON(!test_thread_flag(TIF_SIGPENDING));
}
static inline void clear_restore_sigmask(void)
{
	clear_thread_flag(TIF_RESTORE_SIGMASK);
}
static inline bool test_restore_sigmask(void)
{
	return test_thread_flag(TIF_RESTORE_SIGMASK);
}
static inline bool test_and_clear_restore_sigmask(void)
{
	return test_and_clear_thread_flag(TIF_RESTORE_SIGMASK);
}

#else	/* TIF_RESTORE_SIGMASK */

/* Higher-quality implementation, used if TIF_RESTORE_SIGMASK doesn't exist. */
static inline void set_restore_sigmask(void)
{
	current->restore_sigmask = true;
	WARN_ON(!test_thread_flag(TIF_SIGPENDING));
}
static inline void clear_restore_sigmask(void)
{
	current->restore_sigmask = false;
}
static inline bool test_restore_sigmask(void)
{
	return current->restore_sigmask;
}
static inline bool test_and_clear_restore_sigmask(void)
{
	if (!current->restore_sigmask)
		return false;
	current->restore_sigmask = false;
	return true;
}
#endif

static inline void restore_saved_sigmask(void)
{
	if (test_and_clear_restore_sigmask())
		__set_current_blocked(&current->saved_sigmask);
}

static inline sigset_t *sigmask_to_save(void)
{
	sigset_t *res = &current->blocked;
	if (unlikely(test_restore_sigmask()))
		res = &current->saved_sigmask;
	return res;
}

static inline int kill_cad_pid(int sig, int priv)
{
	return kill_pid(cad_pid, sig, priv);
}

/* These can be the second arg to send_sig_info/send_group_sig_info.  */
#define SEND_SIG_NOINFO ((struct siginfo *) 0)
#define SEND_SIG_PRIV	((struct siginfo *) 1)
#define SEND_SIG_FORCED	((struct siginfo *) 2)

/*
 * True if we are on the alternate signal stack.
 */
static inline int on_sig_stack(unsigned long sp)
{
	/*
	 * If the signal stack is SS_AUTODISARM then, by construction, we
	 * can't be on the signal stack unless user code deliberately set
	 * SS_AUTODISARM when we were already on it.
	 *
	 * This improves reliability: if user state gets corrupted such that
	 * the stack pointer points very close to the end of the signal stack,
	 * then this check will enable the signal to be handled anyway.
	 */
	if (current->sas_ss_flags & SS_AUTODISARM)
		return 0;

#ifdef CONFIG_STACK_GROWSUP
	return sp >= current->sas_ss_sp &&
		sp - current->sas_ss_sp < current->sas_ss_size;
#else
	return sp > current->sas_ss_sp &&
		sp - current->sas_ss_sp <= current->sas_ss_size;
#endif
}

static inline int sas_ss_flags(unsigned long sp)
{
	if (!current->sas_ss_size)
		return SS_DISABLE;

	return on_sig_stack(sp) ? SS_ONSTACK : 0;
}

static inline void sas_ss_reset(struct task_struct *p)
{
	p->sas_ss_sp = 0;
	p->sas_ss_size = 0;
	p->sas_ss_flags = SS_DISABLE;
}

static inline unsigned long sigsp(unsigned long sp, struct ksignal *ksig)
{
	if (unlikely((ksig->ka.sa.sa_flags & SA_ONSTACK)) && ! sas_ss_flags(sp))
#ifdef CONFIG_STACK_GROWSUP
		return current->sas_ss_sp;
#else
		return current->sas_ss_sp + current->sas_ss_size;
#endif
	return sp;
}

/*
 * Routines for handling mm_structs
 */
extern struct mm_struct * mm_alloc(void);

/* mmdrop drops the mm and the page tables */
extern void __mmdrop(struct mm_struct *);
static inline void mmdrop(struct mm_struct *mm)
{
	if (unlikely(atomic_dec_and_test(&mm->mm_count)))
		__mmdrop(mm);
}

static inline void mmdrop_async_fn(struct work_struct *work)
{
	struct mm_struct *mm = container_of(work, struct mm_struct, async_put_work);
	__mmdrop(mm);
}

static inline void mmdrop_async(struct mm_struct *mm)
{
	if (unlikely(atomic_dec_and_test(&mm->mm_count))) {
		INIT_WORK(&mm->async_put_work, mmdrop_async_fn);
		schedule_work(&mm->async_put_work);
	}
}

static inline bool mmget_not_zero(struct mm_struct *mm)
{
	return atomic_inc_not_zero(&mm->mm_users);
}

/* mmput gets rid of the mappings and all user-space */
extern void mmput(struct mm_struct *);
#ifdef CONFIG_MMU
/* same as above but performs the slow path from the async context. Can
 * be called from the atomic context as well
 */
extern void mmput_async(struct mm_struct *);
#endif

/* Grab a reference to a task's mm, if it is not already going away */
extern struct mm_struct *get_task_mm(struct task_struct *task);
/*
 * Grab a reference to a task's mm, if it is not already going away
 * and ptrace_may_access with the mode parameter passed to it
 * succeeds.
 */
extern struct mm_struct *mm_access(struct task_struct *task, unsigned int mode);
/* Remove the current tasks stale references to the old mm_struct */
extern void mm_release(struct task_struct *, struct mm_struct *);

#ifdef CONFIG_HAVE_COPY_THREAD_TLS
extern int copy_thread_tls(unsigned long, unsigned long, unsigned long,
			struct task_struct *, unsigned long);
#else
extern int copy_thread(unsigned long, unsigned long, unsigned long,
			struct task_struct *);

/* Architectures that haven't opted into copy_thread_tls get the tls argument
 * via pt_regs, so ignore the tls argument passed via C. */
static inline int copy_thread_tls(
		unsigned long clone_flags, unsigned long sp, unsigned long arg,
		struct task_struct *p, unsigned long tls)
{
	return copy_thread(clone_flags, sp, arg, p);
}
#endif
extern void flush_thread(void);

#ifdef CONFIG_HAVE_EXIT_THREAD
extern void exit_thread(struct task_struct *tsk);
#else
static inline void exit_thread(struct task_struct *tsk)
{
}
#endif

extern void exit_files(struct task_struct *);
extern void __cleanup_sighand(struct sighand_struct *);

extern void exit_itimers(struct signal_struct *);
extern void flush_itimer_signals(void);

extern void do_group_exit(int);

extern int do_execve(struct filename *,
		     const char __user * const __user *,
		     const char __user * const __user *);
extern int do_execveat(int, struct filename *,
		       const char __user * const __user *,
		       const char __user * const __user *,
		       int);
extern long _do_fork(unsigned long, unsigned long, unsigned long, int __user *, int __user *, unsigned long);
extern long do_fork(unsigned long, unsigned long, unsigned long, int __user *, int __user *);
struct task_struct *fork_idle(int);
extern pid_t kernel_thread(int (*fn)(void *), void *arg, unsigned long flags);

extern void __set_task_comm(struct task_struct *tsk, const char *from, bool exec);
static inline void set_task_comm(struct task_struct *tsk, const char *from)
{
	__set_task_comm(tsk, from, false);
}
extern char *get_task_comm(char *to, struct task_struct *tsk);

#ifdef CONFIG_SMP
void scheduler_ipi(void);
extern unsigned long wait_task_inactive(struct task_struct *, long match_state);
#else
static inline void scheduler_ipi(void) { }
static inline unsigned long wait_task_inactive(struct task_struct *p,
					       long match_state)
{
	return 1;
}
#endif

#define tasklist_empty() \
	list_empty(&init_task.tasks)

#define next_task(p) \
	list_entry_rcu((p)->tasks.next, struct task_struct, tasks)

#define for_each_process(p) \
	for (p = &init_task ; (p = next_task(p)) != &init_task ; )

extern bool current_is_single_threaded(void);

/*
 * Careful: do_each_thread/while_each_thread is a double loop so
 *          'break' will not work as expected - use goto instead.
 */
#define do_each_thread(g, t) \
	for (g = t = &init_task ; (g = t = next_task(g)) != &init_task ; ) do

#define while_each_thread(g, t) \
	while ((t = next_thread(t)) != g)

#define __for_each_thread(signal, t)	\
	list_for_each_entry_rcu(t, &(signal)->thread_head, thread_node)

#define for_each_thread(p, t)		\
	__for_each_thread((p)->signal, t)

/* Careful: this is a double loop, 'break' won't work as expected. */
#define for_each_process_thread(p, t)	\
	for_each_process(p) for_each_thread(p, t)

static inline int get_nr_threads(struct task_struct *tsk)
{
	return tsk->signal->nr_threads;
}

static inline bool thread_group_leader(struct task_struct *p)
{
	return p->exit_signal >= 0;
}

/* Do to the insanities of de_thread it is possible for a process
 * to have the pid of the thread group leader without actually being
 * the thread group leader.  For iteration through the pids in proc
 * all we care about is that we have a task with the appropriate
 * pid, we don't actually care if we have the right task.
 */
static inline bool has_group_leader_pid(struct task_struct *p)
{
	return task_pid(p) == p->signal->leader_pid;
}

static inline
bool same_thread_group(struct task_struct *p1, struct task_struct *p2)
{
	return p1->signal == p2->signal;
}

static inline struct task_struct *next_thread(const struct task_struct *p)
{
	return list_entry_rcu(p->thread_group.next,
			      struct task_struct, thread_group);
}

static inline int thread_group_empty(struct task_struct *p)
{
	return list_empty(&p->thread_group);
}

#define delay_group_leader(p) \
		(thread_group_leader(p) && !thread_group_empty(p))

/*
 * Protects ->fs, ->files, ->mm, ->group_info, ->comm, keyring
 * subscriptions and synchronises with wait4().  Also used in procfs.  Also
 * pins the final release of task.io_context.  Also protects ->cpuset and
 * ->cgroup.subsys[]. And ->vfork_done.
 *
 * Nests both inside and outside of read_lock(&tasklist_lock).
 * It must not be nested with write_lock_irq(&tasklist_lock),
 * neither inside nor outside.
 */
static inline void task_lock(struct task_struct *p)
{
	spin_lock(&p->alloc_lock);
}

static inline void task_unlock(struct task_struct *p)
{
	spin_unlock(&p->alloc_lock);
}

extern struct sighand_struct *__lock_task_sighand(struct task_struct *tsk,
							unsigned long *flags);

static inline struct sighand_struct *lock_task_sighand(struct task_struct *tsk,
						       unsigned long *flags)
{
	struct sighand_struct *ret;

	ret = __lock_task_sighand(tsk, flags);
	(void)__cond_lock(&tsk->sighand->siglock, ret);
	return ret;
}

static inline void unlock_task_sighand(struct task_struct *tsk,
						unsigned long *flags)
{
	spin_unlock_irqrestore(&tsk->sighand->siglock, *flags);
}

/**
 * threadgroup_change_begin - mark the beginning of changes to a threadgroup
 * @tsk: task causing the changes
 *
 * All operations which modify a threadgroup - a new thread joining the
 * group, death of a member thread (the assertion of PF_EXITING) and
 * exec(2) dethreading the process and replacing the leader - are wrapped
 * by threadgroup_change_{begin|end}().  This is to provide a place which
 * subsystems needing threadgroup stability can hook into for
 * synchronization.
 */
static inline void threadgroup_change_begin(struct task_struct *tsk)
{
	might_sleep();
	cgroup_threadgroup_change_begin(tsk);
}

/**
 * threadgroup_change_end - mark the end of changes to a threadgroup
 * @tsk: task causing the changes
 *
 * See threadgroup_change_begin().
 */
static inline void threadgroup_change_end(struct task_struct *tsk)
{
	cgroup_threadgroup_change_end(tsk);
}

#ifdef CONFIG_THREAD_INFO_IN_TASK

static inline struct thread_info *task_thread_info(struct task_struct *task)
{
	return &task->thread_info;
}

/*
 * When accessing the stack of a non-current task that might exit, use
 * try_get_task_stack() instead.  task_stack_page will return a pointer
 * that could get freed out from under you.
 */
static inline void *task_stack_page(const struct task_struct *task)
{
	return task->stack;
}

#define setup_thread_stack(new,old)	do { } while(0)

static inline unsigned long *end_of_stack(const struct task_struct *task)
{
	return task->stack;
}

#elif !defined(__HAVE_THREAD_FUNCTIONS)

#define task_thread_info(task)	((struct thread_info *)(task)->stack)
#define task_stack_page(task)	((void *)(task)->stack)

static inline void setup_thread_stack(struct task_struct *p, struct task_struct *org)
{
	*task_thread_info(p) = *task_thread_info(org);
	task_thread_info(p)->task = p;
}

/*
 * Return the address of the last usable long on the stack.
 *
 * When the stack grows down, this is just above the thread
 * info struct. Going any lower will corrupt the threadinfo.
 *
 * When the stack grows up, this is the highest address.
 * Beyond that position, we corrupt data on the next page.
 */
static inline unsigned long *end_of_stack(struct task_struct *p)
{
#ifdef CONFIG_STACK_GROWSUP
	return (unsigned long *)((unsigned long)task_thread_info(p) + THREAD_SIZE) - 1;
#else
	return (unsigned long *)(task_thread_info(p) + 1);
#endif
}

#endif

#ifdef CONFIG_THREAD_INFO_IN_TASK
static inline void *try_get_task_stack(struct task_struct *tsk)
{
	return atomic_inc_not_zero(&tsk->stack_refcount) ?
		task_stack_page(tsk) : NULL;
}

extern void put_task_stack(struct task_struct *tsk);
#else
static inline void *try_get_task_stack(struct task_struct *tsk)
{
	return task_stack_page(tsk);
}

static inline void put_task_stack(struct task_struct *tsk) {}
#endif

#define task_stack_end_corrupted(task) \
		(*(end_of_stack(task)) != STACK_END_MAGIC)

static inline int object_is_on_stack(void *obj)
{
	void *stack = task_stack_page(current);

	return (obj >= stack) && (obj < (stack + THREAD_SIZE));
}

extern void thread_stack_cache_init(void);

#ifdef CONFIG_DEBUG_STACK_USAGE
static inline unsigned long stack_not_used(struct task_struct *p)
{
	unsigned long *n = end_of_stack(p);

	do { 	/* Skip over canary */
# ifdef CONFIG_STACK_GROWSUP
		n--;
# else
		n++;
# endif
	} while (!*n);

# ifdef CONFIG_STACK_GROWSUP
	return (unsigned long)end_of_stack(p) - (unsigned long)n;
# else
	return (unsigned long)n - (unsigned long)end_of_stack(p);
# endif
}
#endif
extern void set_task_stack_end_magic(struct task_struct *tsk);

/* set thread flags in other task's structures
 * - see asm/thread_info.h for TIF_xxxx flags available
 */
static inline void set_tsk_thread_flag(struct task_struct *tsk, int flag)
{
	set_ti_thread_flag(task_thread_info(tsk), flag);
}

static inline void clear_tsk_thread_flag(struct task_struct *tsk, int flag)
{
	clear_ti_thread_flag(task_thread_info(tsk), flag);
}

static inline int test_and_set_tsk_thread_flag(struct task_struct *tsk, int flag)
{
	return test_and_set_ti_thread_flag(task_thread_info(tsk), flag);
}

static inline int test_and_clear_tsk_thread_flag(struct task_struct *tsk, int flag)
{
	return test_and_clear_ti_thread_flag(task_thread_info(tsk), flag);
}

static inline int test_tsk_thread_flag(struct task_struct *tsk, int flag)
{
	return test_ti_thread_flag(task_thread_info(tsk), flag);
}

static inline void set_tsk_need_resched(struct task_struct *tsk)
{
	set_tsk_thread_flag(tsk,TIF_NEED_RESCHED);
}

static inline void clear_tsk_need_resched(struct task_struct *tsk)
{
	clear_tsk_thread_flag(tsk,TIF_NEED_RESCHED);
}

static inline int test_tsk_need_resched(struct task_struct *tsk)
{
	return unlikely(test_tsk_thread_flag(tsk,TIF_NEED_RESCHED));
}

static inline int restart_syscall(void)
{
	set_tsk_thread_flag(current, TIF_SIGPENDING);
	return -ERESTARTNOINTR;
}

static inline int signal_pending(struct task_struct *p)
{
	return unlikely(test_tsk_thread_flag(p,TIF_SIGPENDING));
}

static inline int __fatal_signal_pending(struct task_struct *p)
{
	return unlikely(sigismember(&p->pending.signal, SIGKILL));
}

static inline int fatal_signal_pending(struct task_struct *p)
{
	return signal_pending(p) && __fatal_signal_pending(p);
}

/*
 * 函数功能: 检查task是否有pending 的信号
 *
 * 参数：
 * state: task的状态
 * struct task_struct *p: 待检查的task
 *
 * 返回值:
 * 0: 表示没有pending signal
 * 1: 表示有pending signal
 */
static inline int signal_pending_state(long state, struct task_struct *p)
{
	/*
	 * state需要包含TASK_INTERRUPTIBLE 和 TASK_WAKEKILL 两种状态之一
	 * 才能进一步判断是否有pending signal,否则返回0
	 */
	if (!(state & (TASK_INTERRUPTIBLE | TASK_WAKEKILL)))
		return 0;
	/*
	 * 程序走到这里说明,state一定包含TASK_INTERRUPTIBLE 和 TASK_WAKEKILL 两种状态之一
	 * 这时检查TIF_SIGPENDING 标记是否设置。没有该标记，直接返回0
	 */
	if (!signal_pending(p))
		return 0;
	/*
	 * 程序走到这里说明,state一定包含TASK_INTERRUPTIBLE 和 TASK_WAKEKILL 两种状态之一
	 * 并且task_struct *p 上有pending signal
	 * 如果state包含TASK_INTERRUPTIBLE,返回1
	 * 如果task_struct *p 上的pending signal有SIGKILL,则返回1
	 */
	return (state & TASK_INTERRUPTIBLE) || __fatal_signal_pending(p);
}

/*
 * cond_resched() and cond_resched_lock(): latency reduction via
 * explicit rescheduling in places that are safe. The return
 * value indicates whether a reschedule was done in fact.
 * cond_resched_lock() will drop the spinlock before scheduling,
 * cond_resched_softirq() will enable bhs before scheduling.
 */
#ifndef CONFIG_PREEMPT
extern int _cond_resched(void);
#else
static inline int _cond_resched(void) { return 0; }
#endif

#define cond_resched() ({			\
	___might_sleep(__FILE__, __LINE__, 0);	\
	_cond_resched();			\
})

extern int __cond_resched_lock(spinlock_t *lock);

#define cond_resched_lock(lock) ({				\
	___might_sleep(__FILE__, __LINE__, PREEMPT_LOCK_OFFSET);\
	__cond_resched_lock(lock);				\
})

extern int __cond_resched_softirq(void);

#define cond_resched_softirq() ({					\
	___might_sleep(__FILE__, __LINE__, SOFTIRQ_DISABLE_OFFSET);	\
	__cond_resched_softirq();					\
})

static inline void cond_resched_rcu(void)
{
#if defined(CONFIG_DEBUG_ATOMIC_SLEEP) || !defined(CONFIG_PREEMPT_RCU)
	rcu_read_unlock();
	cond_resched();
	rcu_read_lock();
#endif
}

static inline unsigned long get_preempt_disable_ip(struct task_struct *p)
{
#ifdef CONFIG_DEBUG_PREEMPT
	return p->preempt_disable_ip;
#else
	return 0;
#endif
}

/*
 * Does a critical section need to be broken due to another
 * task waiting?: (technically does not depend on CONFIG_PREEMPT,
 * but a general need for low latency)
 */
static inline int spin_needbreak(spinlock_t *lock)
{
#ifdef CONFIG_PREEMPT
	return spin_is_contended(lock);
#else
	return 0;
#endif
}

/*
 * Idle thread specific functions to determine the need_resched
 * polling state.
 */
#ifdef TIF_POLLING_NRFLAG
static inline int tsk_is_polling(struct task_struct *p)
{
	return test_tsk_thread_flag(p, TIF_POLLING_NRFLAG);
}

static inline void __current_set_polling(void)
{
	set_thread_flag(TIF_POLLING_NRFLAG);
}

static inline bool __must_check current_set_polling_and_test(void)
{
	__current_set_polling();

	/*
	 * Polling state must be visible before we test NEED_RESCHED,
	 * paired by resched_curr()
	 */
	smp_mb__after_atomic();

	return unlikely(tif_need_resched());
}

static inline void __current_clr_polling(void)
{
	clear_thread_flag(TIF_POLLING_NRFLAG);
}

static inline bool __must_check current_clr_polling_and_test(void)
{
	__current_clr_polling();

	/*
	 * Polling state must be visible before we test NEED_RESCHED,
	 * paired by resched_curr()
	 */
	smp_mb__after_atomic();

	return unlikely(tif_need_resched());
}

#else
static inline int tsk_is_polling(struct task_struct *p) { return 0; }
static inline void __current_set_polling(void) { }
static inline void __current_clr_polling(void) { }

static inline bool __must_check current_set_polling_and_test(void)
{
	return unlikely(tif_need_resched());
}
static inline bool __must_check current_clr_polling_and_test(void)
{
	return unlikely(tif_need_resched());
}
#endif

static inline void current_clr_polling(void)
{
	__current_clr_polling();

	/*
	 * Ensure we check TIF_NEED_RESCHED after we clear the polling bit.
	 * Once the bit is cleared, we'll get IPIs with every new
	 * TIF_NEED_RESCHED and the IPI handler, scheduler_ipi(), will also
	 * fold.
	 */
	smp_mb(); /* paired with resched_curr() */

	preempt_fold_need_resched();
}

static __always_inline bool need_resched(void)
{
	return unlikely(tif_need_resched());
}

/*
 * Thread group CPU time accounting.
 */
void thread_group_cputime(struct task_struct *tsk, struct task_cputime *times);
void thread_group_cputimer(struct task_struct *tsk, struct task_cputime *times);

/*
 * Reevaluate whether the task has signals pending delivery.
 * Wake the task if so.
 * This is required every time the blocked sigset_t changes.
 * callers must hold sighand->siglock.
 */
extern void recalc_sigpending_and_wake(struct task_struct *t);
extern void recalc_sigpending(void);

extern void signal_wake_up_state(struct task_struct *t, unsigned int state);

static inline void signal_wake_up(struct task_struct *t, bool resume)
{
	signal_wake_up_state(t, resume ? TASK_WAKEKILL : 0);
}
static inline void ptrace_signal_wake_up(struct task_struct *t, bool resume)
{
	signal_wake_up_state(t, resume ? __TASK_TRACED : 0);
}

/*
 * Wrappers for p->thread_info->cpu access. No-op on UP.
 */
#ifdef CONFIG_SMP

static inline unsigned int task_cpu(const struct task_struct *p)
{
#ifdef CONFIG_THREAD_INFO_IN_TASK
	return p->cpu;
#else
	return task_thread_info(p)->cpu;
#endif
}

static inline int task_node(const struct task_struct *p)
{
	return cpu_to_node(task_cpu(p));
}

extern void set_task_cpu(struct task_struct *p, unsigned int cpu);

#else

static inline unsigned int task_cpu(const struct task_struct *p)
{
	return 0;
}

static inline void set_task_cpu(struct task_struct *p, unsigned int cpu)
{
}

#endif /* CONFIG_SMP */

extern long sched_setaffinity(pid_t pid, const struct cpumask *new_mask);
extern long sched_getaffinity(pid_t pid, struct cpumask *mask);

#ifdef CONFIG_CGROUP_SCHED
extern struct task_group root_task_group;
#endif /* CONFIG_CGROUP_SCHED */

extern int task_can_switch_user(struct user_struct *up,
					struct task_struct *tsk);

#ifdef CONFIG_TASK_XACCT
static inline void add_rchar(struct task_struct *tsk, ssize_t amt)
{
	tsk->ioac.rchar += amt;
}

static inline void add_wchar(struct task_struct *tsk, ssize_t amt)
{
	tsk->ioac.wchar += amt;
}

static inline void inc_syscr(struct task_struct *tsk)
{
	tsk->ioac.syscr++;
}

static inline void inc_syscw(struct task_struct *tsk)
{
	tsk->ioac.syscw++;
}
#else
static inline void add_rchar(struct task_struct *tsk, ssize_t amt)
{
}

static inline void add_wchar(struct task_struct *tsk, ssize_t amt)
{
}

static inline void inc_syscr(struct task_struct *tsk)
{
}

static inline void inc_syscw(struct task_struct *tsk)
{
}
#endif

#ifndef TASK_SIZE_OF
#define TASK_SIZE_OF(tsk)	TASK_SIZE
#endif

#ifdef CONFIG_MEMCG
extern void mm_update_next_owner(struct mm_struct *mm);
#else
static inline void mm_update_next_owner(struct mm_struct *mm)
{
}
#endif /* CONFIG_MEMCG */

static inline unsigned long task_rlimit(const struct task_struct *tsk,
		unsigned int limit)
{
	return READ_ONCE(tsk->signal->rlim[limit].rlim_cur);
}

static inline unsigned long task_rlimit_max(const struct task_struct *tsk,
		unsigned int limit)
{
	return READ_ONCE(tsk->signal->rlim[limit].rlim_max);
}

static inline unsigned long rlimit(unsigned int limit)
{
	return task_rlimit(current, limit);
}

static inline unsigned long rlimit_max(unsigned int limit)
{
	return task_rlimit_max(current, limit);
}

#define SCHED_CPUFREQ_RT	(1U << 0)
#define SCHED_CPUFREQ_DL	(1U << 1)
#define SCHED_CPUFREQ_IOWAIT	(1U << 2)

#define SCHED_CPUFREQ_RT_DL	(SCHED_CPUFREQ_RT | SCHED_CPUFREQ_DL)

#ifdef CONFIG_CPU_FREQ
struct update_util_data {
       void (*func)(struct update_util_data *data, u64 time, unsigned int flags);
};

void cpufreq_add_update_util_hook(int cpu, struct update_util_data *data,
                       void (*func)(struct update_util_data *data, u64 time,
				    unsigned int flags));
void cpufreq_remove_update_util_hook(int cpu);
#endif /* CONFIG_CPU_FREQ */

#endif
