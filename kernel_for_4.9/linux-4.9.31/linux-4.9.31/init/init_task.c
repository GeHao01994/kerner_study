#include <linux/init_task.h>
#include <linux/export.h>
#include <linux/mqueue.h>
#include <linux/sched.h>
#include <linux/sched/sysctl.h>
#include <linux/sched/rt.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/mm.h>

#include <asm/pgtable.h>
#include <asm/uaccess.h>

static struct signal_struct init_signals = INIT_SIGNALS(init_signals);
static struct sighand_struct init_sighand = INIT_SIGHAND(init_sighand);

/* Initial task structure */
/* Linux内核在启动时会有一个init_task进程,它是系统所有进程的“鼻祖”,称为0号进程或idle进程,
 * 当系统没有进程需要调度时,调度器就会执行idle进程.
 * idle进程在内核启动(start_kernel())时静态创建,所有的核心数据结构都预先静态赋值.
 * init_task进程的task_struct数据结构通过INIT_TASK宏来赋值
 */
struct task_struct init_task = INIT_TASK(init_task);
EXPORT_SYMBOL(init_task);

/*
 * Initial thread structure. Alignment of this is handled by a special
 * linker map entry.
 */

/* __init_task_data存放在“.data..init_task”段中,__init_task_data声明为thread_union类型,
 * thread_union类型描述了整个内核栈stackp[],栈的最下面存放struct thread_info数据结构,
 * 因此__init_task_data也通过INIT_THREAD_INFO宏来初始化struct thread_info数据结构.
 */
union thread_union init_thread_union __init_task_data = {
#ifndef CONFIG_THREAD_INFO_IN_TASK
	INIT_THREAD_INFO(init_task)
#endif
};
