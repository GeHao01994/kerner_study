#ifndef _UAPI_LINUX_SCHED_H
#define _UAPI_LINUX_SCHED_H

/*
 * cloning flags:
 */

#define CSIGNAL		0x000000ff	/* signal mask to be sent at exit
					 * 在退出时发送的信号掩码
					 */
/* 父子进程之间共享内存空间
 * CLONE_VM: 父进程和子进程运行在同一个虚拟地址空间,一个进程对全局变量改动,另外一个进程也可以看到.
 */
#define CLONE_VM	0x00000100	/* set if VM shared between processes */
/* 父子进程之间共享相同的文件系统
 * 父进程和子进程共享文件系统信息,例如根目录、当前工作目录等.
 * 其中一个进程对文件系统信息进行改变,将会影响到另外一个进程,例如调用chroot()或chdir()等.
 */
#define CLONE_FS	0x00000200	/* set if fs info shared between processes */
/* 父子进程共享相同的文件描述符
 * 父进程和子进程共享文件描述符表.文件描述符表里面保存进程打开文件描述符的信息,因此一个进程打开的文件,在另外一个进程用同样的描述符也可以访问.
 * 一个进程关闭了一个文件或者使用fcntl()改变了一个文件属性,另外一个进程也可以看到.
 */
#define CLONE_FILES	0x00000400	/* set if open files shared between processes */
/* 父子进程共享相同的信号处理等相关信息
 * 父进程和子进程共享信号处理器函数表.一个进程改变了某个信号处理函数,这个改动对于另外一个进程也有效.
 */
#define CLONE_SIGHAND	0x00000800	/* set if signal handlers and blocked signals shared */
/*
 * 父进程被trace,子进程也同样被trace
 * 父进程被跟踪(ptrace),子进程也会被跟踪
 */
#define CLONE_PTRACE	0x00002000	/* set if we want to let tracing continue on the child too */
/* 父进程被挂起,直到子进程释放了虚拟内存资源
 * 在创建子进程时启用Linux内核的完成机制(completion).
 * wait_for_completion会使父进程进入睡眠等待,直到子进程调用execve()或者exit()释放虚拟内存资源
 */
#define CLONE_VFORK	0x00004000	/* set if the parent wants the child to wake it up on mm_release */
#define CLONE_PARENT	0x00008000	/* set if we want to have the same parent as the cloner */
#define CLONE_THREAD	0x00010000	/* Same thread group? */
#define CLONE_NEWNS	0x00020000	/* New mount namespace group */
#define CLONE_SYSVSEM	0x00040000	/* share system V SEM_UNDO semantics */
#define CLONE_SETTLS	0x00080000	/* create a new TLS for the child */
#define CLONE_PARENT_SETTID	0x00100000	/* set the TID in the parent */
#define CLONE_CHILD_CLEARTID	0x00200000	/* clear the TID in the child */
#define CLONE_DETACHED		0x00400000	/* Unused, ignored */
#define CLONE_UNTRACED		0x00800000	/* set if the tracing process can't force CLONE_PTRACE on this clone */
#define CLONE_CHILD_SETTID	0x01000000	/* set the TID in the child */
#define CLONE_NEWCGROUP		0x02000000	/* New cgroup namespace */
#define CLONE_NEWUTS		0x04000000	/* New utsname namespace */
#define CLONE_NEWIPC		0x08000000	/* New ipc namespace */
#define CLONE_NEWUSER		0x10000000	/* New user namespace */
#define CLONE_NEWPID		0x20000000	/* New pid namespace */
#define CLONE_NEWNET		0x40000000	/* New network namespace */
#define CLONE_IO		0x80000000	/* Clone io context */

/*
 * Scheduling policies
 */
/* SCHED_NORMAL(也叫SCHED_OTHER)用于普通进程,通过CFS调度器实现.
 * SCHED_BATCH用于非交互的处理器消耗型进程.
 * SCHED_IDLE是在系统负载很低时使用
 */
#define SCHED_NORMAL		0
/* 先入先出调度算法(实时调度策略),相同优先级的任务先到先服务,高优先级的任务可以抢占低优先级的任务 */
#define SCHED_FIFO		1
/* SCHED_RR 轮流调度算法(实时调度策略),后者提供Roound-Robin语义,采用时间片,
 * 相同优先级的任务当用完时间片会被放到队列尾部,以保证公平性,同样,高优先级的任务可以抢占低优先级的任务.
 * 不同要求的实时任务可以根据需要用sched_setscheduler()API 设置策略
 */
#define SCHED_RR		2
/* SCHED_NORMAL普通进程策略的分化版本.采用分时策略,根据动态优先级(可用nice()API设置),分配 CPU 运算资源.
 * 注意: 这类进程比上述两类实时进程优先级低,换言之,在有实时进程存在时,实时进程优先调度.
 * 但针对吞吐量优化
 */
#define SCHED_BATCH		3
/* SCHED_ISO: reserved but not implemented yet */
/* 优先级最低,在系统空闲时才跑这类进程(如利用闲散计算机资源跑地外文明搜索,蛋白质结构分析等任务,是此调度策略的适用者) */
#define SCHED_IDLE		5
/* 新支持的实时进程调度策略,针对突发型计算,且对延迟和完成时间高度敏感的任务适用.
 * 基于Earliest Deadline First (EDF) 调度算法
 */
#define SCHED_DEADLINE		6

/* Can be ORed in to make sure the process is reverted back to SCHED_NORMAL on fork */
#define SCHED_RESET_ON_FORK     0x40000000

/*
 * For the sched_{set,get}attr() calls
 */
#define SCHED_FLAG_RESET_ON_FORK	0x01

#endif /* _UAPI_LINUX_SCHED_H */
