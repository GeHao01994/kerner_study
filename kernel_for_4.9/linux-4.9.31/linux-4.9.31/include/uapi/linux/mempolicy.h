/*
 * NUMA memory policies for Linux.
 * Copyright 2003,2004 Andi Kleen SuSE Labs
 */
#ifndef _UAPI_LINUX_MEMPOLICY_H
#define _UAPI_LINUX_MEMPOLICY_H

#include <linux/errno.h>


/*
 * Both the MPOL_* mempolicy mode and the MPOL_F_* optional mode flags are
 * passed by the user to either set_mempolicy() or mbind() in an 'int' actual.
 * The MPOL_MODE_FLAGS macro determines the legal set of optional mode flags.
 */

/* Policies */
/* 详见手册 https://man7.org/linux/man-pages/man2/set_mempolicy.2.html */
enum {
	/* MPOL_DEFAULT策略 该策略表示删除任何非默认线程内存策略,便于内存策略能够回退到系统默认内存策略,系统默认策略是"local allocation",
	 * 也就是说,分配内存只在触发内存分配的CPU节点上进行,nodemask参数必须指定为NULL，如果"local node"没有可用内存，那么系统将试图从"near by"(临近)节点分配内存.
	 */
	MPOL_DEFAULT,
	/* 该模式为页面分配设置优选节点.
	 * 此模式下,内核将尝试首先从该节点开始分配页面,如果首选节点可用内存较少,那么就会去临近节点分配页面.
	 * 如果nodemask指定了多个节点ID,那么node掩码中的第一个节点必须选为优选节点.
	 * 如果nodemask和最大节点参数为空,则采用"local allocation"策略,即为上述讨论的系统默认策略.
	 */
	MPOL_PREFERRED,
	/* 该模式是一种严格的内存分配策略,会将内存分配限制到有nodemask指定的节点上完成.
	 * 如果nodemask指定了多个节点,那么将首先从最小节点ID对应的节点开始执行页面分配,直到节点不包含可用内存为止.
	 * 接下来将从下一个更高节点ID的节点开始分配页面,以此类推,直到指定节点不再包含可用内存为止.
	 * 不在nodemask指定的节点范围内的节点不会参与页面分配.
	 */
	MPOL_BIND,
	/* 该模式是按照节点ID的顺序,在nodemask指定节点之间交错分配页面.
	 * 这样通过隔离多个节点的页面分配和内存访问,优化带宽,但是不会优化时延.
	 * 然而,单个页面的访问将受到单个节点的内存带宽的限制
	 */
	MPOL_INTERLEAVE,
	/* 该策略从Linux-3.8版本开始产生的,此模式指明了“local allocation”策略,也就是内存在触发分配行为的CPU上完成分配,该CPU就是所谓的"local node".
	 * nodemask和最大节点参数必须是空的,这是使用该策略的前提条件.如果"local node"可用内存不够,内核将尝试从其他节点上分配内存.
	 * 如果进程的当前cpuset上下文不允许使用"local node"，那么内核也会尝试从其他节点上分配内存.
	 * 无论进程的当前cpuset上下文什么时候允许"local node"，内核都会从该节点分配内存.
	 */
	MPOL_LOCAL,
	MPOL_MAX,	/* always last member of enum */
};

enum mpol_rebind_step {
	MPOL_REBIND_ONCE,	/* do rebind work at once(not by two step) */
	MPOL_REBIND_STEP1,	/* first step(set all the newly nodes) */
	MPOL_REBIND_STEP2,	/* second step(clean all the disallowed nodes)*/
	MPOL_REBIND_NSTEP,
};

/* Flags for set_mempolicy */
#define MPOL_F_STATIC_NODES	(1 << 15)
#define MPOL_F_RELATIVE_NODES	(1 << 14)

/*
 * MPOL_MODE_FLAGS is the union of all possible optional mode flags passed to
 * either set_mempolicy() or mbind().
 */
#define MPOL_MODE_FLAGS	(MPOL_F_STATIC_NODES | MPOL_F_RELATIVE_NODES)

/* Flags for get_mempolicy */
#define MPOL_F_NODE	(1<<0)	/* return next IL mode instead of node mask */
#define MPOL_F_ADDR	(1<<1)	/* look up vma using address */
#define MPOL_F_MEMS_ALLOWED (1<<2) /* return allowed memories */

/* Flags for mbind */
#define MPOL_MF_STRICT	(1<<0)	/* Verify existing pages in the mapping */
#define MPOL_MF_MOVE	 (1<<1)	/* Move pages owned by this process to conform
				   to policy */
#define MPOL_MF_MOVE_ALL (1<<2)	/* Move every page to conform to policy */
#define MPOL_MF_LAZY	 (1<<3)	/* Modifies '_MOVE:  lazy migrate on fault */
#define MPOL_MF_INTERNAL (1<<4)	/* Internal flags start here */

#define MPOL_MF_VALID	(MPOL_MF_STRICT   | 	\
			 MPOL_MF_MOVE     | 	\
			 MPOL_MF_MOVE_ALL)

/*
 * Internal flags that share the struct mempolicy flags word with
 * "mode flags".  These flags are allocated from bit 0 up, as they
 * are never OR'ed into the mode in mempolicy API arguments.
 *
 * 与“mode flags” 共享struct mempolicy flags的内部flag.
 * 这些flags是从0位开始分配的,因为它们从未被“或”到mempolicy API参数中的模式中.
 */
#define MPOL_F_SHARED  (1 << 0)	/* identify shared policies */
#define MPOL_F_LOCAL   (1 << 1)	/* preferred local allocation */
#define MPOL_F_REBINDING (1 << 2)	/* identify policies in rebinding */
#define MPOL_F_MOF	(1 << 3) /* this policy wants migrate on fault */
#define MPOL_F_MORON	(1 << 4) /* Migrate On protnone Reference On Node */


#endif /* _UAPI_LINUX_MEMPOLICY_H */
