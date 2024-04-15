/*
 * Based on arch/arm/mm/fault.c
 *
 * Copyright (C) 1995  Linus Torvalds
 * Copyright (C) 1995-2004 Russell King
 * Copyright (C) 2012 ARM Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/extable.h>
#include <linux/signal.h>
#include <linux/mm.h>
#include <linux/hardirq.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/page-flags.h>
#include <linux/sched.h>
#include <linux/highmem.h>
#include <linux/perf_event.h>
#include <linux/preempt.h>

#include <asm/bug.h>
#include <asm/cpufeature.h>
#include <asm/exception.h>
#include <asm/debug-monitors.h>
#include <asm/esr.h>
#include <asm/sysreg.h>
#include <asm/system_misc.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>


/* struct fault_info数据结构用于描述一条失效状态对应的处理方案 */
struct fault_info {
	/* fn表示修复这条失效状态的函数指针 */
	int	(*fn)(unsigned long addr, unsigned int esr,
		      struct pt_regs *regs);
	/* sig表示处理失败时Linux内核要发送的信号类型 */
	int	sig;
	int	code;
	/* name成员表示这条失效状态的名称 */
	const char *name;
};

static const struct fault_info fault_info[];

static inline const struct fault_info *esr_to_fault_info(unsigned int esr)
{
	/* fault_info + esr & 0b111111 */
	return fault_info + (esr & 63);
}

#ifdef CONFIG_KPROBES
static inline int notify_page_fault(struct pt_regs *regs, unsigned int esr)
{
	int ret = 0;

	/* kprobe_running() needs smp_processor_id() */
	if (!user_mode(regs)) {
		preempt_disable();
		if (kprobe_running() && kprobe_fault_handler(regs, esr))
			ret = 1;
		preempt_enable();
	}

	return ret;
}
#else
static inline int notify_page_fault(struct pt_regs *regs, unsigned int esr)
{
	return 0;
}
#endif

/*
 * Dump out the page tables associated with 'addr' in mm 'mm'.
 */
void show_pte(struct mm_struct *mm, unsigned long addr)
{
	pgd_t *pgd;

	if (!mm)
		mm = &init_mm;
	/* 按指针的形式打出pgd起始值 */
	pr_alert("pgd = %p\n", mm->pgd);
	/* 通过首地址pgd得到addr对应的pgd的指针 */
	pgd = pgd_offset(mm, addr);
	/* 打印出pgd的值,也就是pud的地址加上相关状态位 */
	pr_alert("[%08lx] *pgd=%016llx", addr, pgd_val(*pgd));

	do {
		pud_t *pud;
		pmd_t *pmd;
		pte_t *pte;
		/* 如果pgd为none或者bad,那么break,所以你这里只看到了两个打印,也就是pgd = xxx,*pgd = xxx */
		if (pgd_none(*pgd) || pgd_bad(*pgd))
			break;
		/* 拿到对应地址的pud的指针 */
		pud = pud_offset(pgd, addr);
		/* 打印pud的值,也就是pmd的地址加上相关状态位 */
		printk(", *pud=%016llx", pud_val(*pud));
		/*  如果pud为none或者bad,那么break,所以你这里只看到三个打印,也就是pgd = xxx,*pgd = xxx, *pud = xxx*/
		if (pud_none(*pud) || pud_bad(*pud))
			break;
		/* 拿到对应地址的pmd的指针 */
		pmd = pmd_offset(pud, addr);
		/* 打印pmd的值,也就是pte的地址加上相关状态位 */
		printk(", *pmd=%016llx", pmd_val(*pmd));
		if (pmd_none(*pmd) || pmd_bad(*pmd))
			break;

		/* 拿到对应地址的pte的指针 */
		pte = pte_offset_map(pmd, addr);
		/* 打印pte的值,也就是对应的物理地址加上相关状态位 */
		printk(", *pte=%016llx", pte_val(*pte));
		/* ARM64这里是空的 */
		pte_unmap(pte);
	} while(0);

	printk("\n");
}

#ifdef CONFIG_ARM64_HW_AFDBM
/*
 * This function sets the access flags (dirty, accessed), as well as write
 * permission, and only to a more permissive setting.
 *
 * It needs to cope with hardware update of the accessed/dirty state by other
 * agents in the system and can safely skip the __sync_icache_dcache() call as,
 * like set_pte_at(), the PTE is never changed from no-exec to exec here.
 *
 * Returns whether or not the PTE actually changed.
 */
int ptep_set_access_flags(struct vm_area_struct *vma,
			  unsigned long address, pte_t *ptep,
			  pte_t entry, int dirty)
{
	pteval_t old_pteval;
	unsigned int tmp;

	if (pte_same(*ptep, entry))
		return 0;

	/* only preserve the access flags and write permission */
	pte_val(entry) &= PTE_AF | PTE_WRITE | PTE_DIRTY;

	/*
	 * PTE_RDONLY is cleared by default in the asm below, so set it in
	 * back if necessary (read-only or clean PTE).
	 */
	if (!pte_write(entry) || !pte_sw_dirty(entry))
		pte_val(entry) |= PTE_RDONLY;

	/*
	 * Setting the flags must be done atomically to avoid racing with the
	 * hardware update of the access/dirty state.
	 */
	asm volatile("//	ptep_set_access_flags\n"
	"	prfm	pstl1strm, %2\n"
	"1:	ldxr	%0, %2\n"
	"	and	%0, %0, %3		// clear PTE_RDONLY\n"
	"	orr	%0, %0, %4		// set flags\n"
	"	stxr	%w1, %0, %2\n"
	"	cbnz	%w1, 1b\n"
	: "=&r" (old_pteval), "=&r" (tmp), "+Q" (pte_val(*ptep))
	: "L" (~PTE_RDONLY), "r" (pte_val(entry)));

	flush_tlb_fix_spurious_fault(vma, address);
	return 1;
}
#endif

static bool is_el1_instruction_abort(unsigned int esr)
{
	return ESR_ELx_EC(esr) == ESR_ELx_EC_IABT_CUR;
}

/*
 * The kernel tried to access some page that wasn't present.
 */
static void __do_kernel_fault(struct mm_struct *mm, unsigned long addr,
			      unsigned int esr, struct pt_regs *regs)
{
	/*
	 * Are we prepared to handle this kernel fault?
	 * We are almost certainly not prepared to handle instruction faults.
	 *
	 * 我们准备好处理这个内核fault了吗?
	 * 我们几乎肯定没有准备好处理指令错误
	 */
	if (!is_el1_instruction_abort(esr) && fixup_exception(regs))
		return;

	/*
	 * No handler, we'll have to terminate things with extreme prejudice.
	 *
	 * 没有处理者,我们将不得不带着极端的偏见终止时间.
	 */
	bust_spinlocks(1);
	/* 如果addr < PAGE_SIZE,那么就是NULL pointer dereference
	 * 否则就是paging request
	 */
	pr_alert("Unable to handle kernel %s at virtual address %08lx\n",
		 (addr < PAGE_SIZE) ? "NULL pointer dereference" :
		 "paging request", addr);

	/* 答应相关的pte映射信息 */
	show_pte(mm, addr);
	/* 然后die Oops */
	die("Oops", regs, esr);
	bust_spinlocks(0);
	do_exit(SIGKILL);
}

/*
 * Something tried to access memory that isn't in our memory map. User mode
 * accesses just cause a SIGSEGV
 *
 * 有东西试图访问我们内存映射中没有的内存.
 * 用户模式访问只会导致SIGSEGV
 */
static void __do_user_fault(struct task_struct *tsk, unsigned long addr,
			    unsigned int esr, unsigned int sig, int code,
			    struct pt_regs *regs)
{
	struct siginfo si;
	const struct fault_info *inf;

	if (unhandled_signal(tsk, sig) && show_unhandled_signals_ratelimited()) {
		inf = esr_to_fault_info(esr);
		pr_info("%s[%d]: unhandled %s (%d) at 0x%08lx, esr 0x%03x\n",
			tsk->comm, task_pid_nr(tsk), inf->name, sig,
			addr, esr);
		show_pte(tsk->mm, addr);
		show_regs(regs);
	}

	tsk->thread.fault_address = addr;
	tsk->thread.fault_code = esr;
	si.si_signo = sig;
	si.si_errno = 0;
	si.si_code = code;
	si.si_addr = (void __user *)addr;
	force_sig_info(sig, &si, tsk);
}

static void do_bad_area(unsigned long addr, unsigned int esr, struct pt_regs *regs)
{
	struct task_struct *tsk = current;
	struct mm_struct *mm = tsk->active_mm;
	const struct fault_info *inf;

	/*
	 * If we are in kernel mode at this point, we have no context to
	 * handle this fault with.
	 */
	if (user_mode(regs)) {
		inf = esr_to_fault_info(esr);
		__do_user_fault(tsk, addr, esr, inf->sig, inf->code, regs);
	} else
		__do_kernel_fault(mm, addr, esr, regs);
}

#define VM_FAULT_BADMAP		0x010000
#define VM_FAULT_BADACCESS	0x020000

static int __do_page_fault(struct mm_struct *mm, unsigned long addr,
			   unsigned int mm_flags, unsigned long vm_flags,
			   struct task_struct *tsk)
{
	struct vm_area_struct *vma;
	int fault;

	/* 首先通过失效地址addr来查找vma,如果find_vma找不到vma,说明addr地址还没有在进程地址空间中,返回VM_FAULT_BADMAP错误 */
	vma = find_vma(mm, addr);
	fault = VM_FAULT_BADMAP;
	if (unlikely(!vma))
		goto out;
	/* 如果说起始地址比它大,那么goto check_stack标签处,也就是落在了外面 */
	if (unlikely(vma->vm_start > addr))
		goto check_stack;

	/*
	 * Ok, we have a good vm_area for this memory access, so we can handle
	 * it.
	 */
good_area:
	/*
	 * Check that the permissions on the VMA allow for the fault which
	 * occurred.
	 * 检查VMA上的权限是否允许发生fault
	 *
	 * 这里判断vma是否具备可写或可执行等权限.
	 * 如果发生一个写错误的缺页中断,首先判断vma属性是否具有可写属性,
	 * 如果没有,则返回VM_FAULT_BADACCESS
	 */
	if (!(vma->vm_flags & vm_flags)) {
		fault = VM_FAULT_BADACCESS;
		goto out;
	}

	return handle_mm_fault(vma, addr & PAGE_MASK, mm_flags);

check_stack:
	if (vma->vm_flags & VM_GROWSDOWN && !expand_stack(vma, addr))
		goto good_area;
out:
	return fault;
}

static inline bool is_permission_fault(unsigned int esr)
{
	unsigned int ec       = ESR_ELx_EC(esr);
	unsigned int fsc_type = esr & ESR_ELx_FSC_TYPE;

	return (ec == ESR_ELx_EC_DABT_CUR && fsc_type == ESR_ELx_FSC_PERM) ||
	       (ec == ESR_ELx_EC_IABT_CUR && fsc_type == ESR_ELx_FSC_PERM);
}

static bool is_el0_instruction_abort(unsigned int esr)
{
	return ESR_ELx_EC(esr) == ESR_ELx_EC_IABT_LOW;
}

static int __kprobes do_page_fault(unsigned long addr, unsigned int esr,
				   struct pt_regs *regs)
{
	struct task_struct *tsk;
	struct mm_struct *mm;
	int fault, sig, code;
	unsigned long vm_flags = VM_READ | VM_WRITE;
	unsigned int mm_flags = FAULT_FLAG_ALLOW_RETRY | FAULT_FLAG_KILLABLE;

	if (notify_page_fault(regs, esr))
		return 0;

	tsk = current;
	mm  = tsk->mm;

	/*
	 * If we're in an interrupt or have no user context, we must not take
	 * the fault.
	 */

	/* 如果current->pagefault_disabled,
	 * in_atomit判断当前状态是否处于中断上下文或者禁止抢占状态,
	 * 如果是,说明系统运行在原子上下文中(atomic context),那么跳转到
	 * no_context标签处的__do_kernel_fault函数.
	 * 如果当前进程中没有struct mm_struct数据结构,说明这是个内核线程,
	 * 同样跳转到__do_kernel_fault函数中
	 */
	if (faulthandler_disabled() || !mm)
		goto no_context;

	/* #define user_mode(regs)	\
	 *	(((regs)->pstate & PSR_MODE_MASK) == PSR_MODE_EL0t)
	 * 如果是用户空间的地址,那么flag置位FAULT_FLAG_USER
	 */
	if (user_mode(regs))
		mm_flags |= FAULT_FLAG_USER;

	/* 判断是否为低异常等级的指令异常,若为指令异常,说明该地址具有可执行权限 */
	if (is_el0_instruction_abort(esr)) {
		vm_flags = VM_EXEC;
		/* ESR_ELx_WNR 表示: Write not Read.Indicates whether a synchronous abort was caused by an instruction writing to a memory
		 * location, or by an instruction reading from a memory location.
		 *
		 * WnR		Meaning
		 * 0b0		Abort caused by an instruction reading from a memory location.
		 * 0b1		Abort caused by an instruction writing to a memory
		 *
		 * 并且CM没有设置为0
		 */

		/* 如果是写内存导致的fault,那么设置vm_flags为VM_WRITE
		 * mm_flags |= FAULT_FLAG_WRITE
		 */
	} else if ((esr & ESR_ELx_WNR) && !(esr & ESR_ELx_CM)) {
		vm_flags = VM_WRITE;
		mm_flags |= FAULT_FLAG_WRITE;
	}

	/* 如果是权限fault,并且地址是用户空间的地址 */
	if (is_permission_fault(esr) && (addr < USER_DS)) {
		/* regs->orig_addr_limit may be 0 if we entered from EL0 */
		/* 地址属于用户空间,但是出错是在内核空间,也就是内核空间访问了用户空间的地址,报错 */
		if (regs->orig_addr_limit == KERNEL_DS)
			die("Accessing user space memory with fs=KERNEL_DS", regs, esr);

		/* 如果是el1的指令异常,那么die */
		if (is_el1_instruction_abort(esr))
			die("Attempting to execute userspace memory", regs, esr);

		/* 这里是去异常向量表里面去找pc指针对应的 */
		if (!search_exception_tables(regs->pc))
			die("Accessing user space memory outside uaccess.h routines", regs, esr);
	}

	/*
	 * As per x86, we may deadlock here. However, since the kernel only
	 * validly references user space from well defined areas of the code,
	 * we can bug out early if this is from code which shouldn't.
	 */

	/* down_read_trylock函数判断当前进程的mm->mmap_sem读写信号量是否可以获取,返回1则表示成功获得锁,返回0则表示锁已被被人占用.
	 * mm->mmap_sem锁被别人占用时要区分两种情况,一种是发生在内核空间,另外一种是发生在用户空间.
	 * 发生在用户空间的情况可以调用down_read来睡眠等待锁持有者释放该锁;
	 * 发生在内核空间时,如果没有在exception table查询到该地址,那么跳转到no_context标签处的__do_kernel_fault函数
	 */
	if (!down_read_trylock(&mm->mmap_sem)) {
		if (!user_mode(regs) && !search_exception_tables(regs->pc))
			goto no_context;
retry:
		down_read(&mm->mmap_sem);
	} else {
		/*
		 * The above down_read_trylock() might have succeeded in which
		 * case, we'll have missed the might_sleep() from down_read().
		 */
		might_sleep();
#ifdef CONFIG_DEBUG_VM
		if (!user_mode(regs) && !search_exception_tables(regs->pc))
			goto no_context;
#endif
	}

	fault = __do_page_fault(mm, addr, mm_flags, vm_flags, tsk);

	/*
	 * If we need to retry but a fatal signal is pending, handle the
	 * signal first. We do not need to release the mmap_sem because it
	 * would already be released in __lock_page_or_retry in mm/filemap.c.
	 *
	 * 如果我们需要retry,但有一个致命信号挂起,请先处理该信号.
	 * 我们不需要释放mmap_sem,因为它已经在mm/filemap.c中的__lock_page_or_retry中释放了.
	 */
	if ((fault & VM_FAULT_RETRY) && fatal_signal_pending(current))
		return 0;

	/*
	 * Major/minor page fault accounting is only done on the initial
	 * attempt. If we go through a retry, it is extremely likely that the
	 * page will be found in page cache at that point.
	 *
	 * Major/minor page fault仅在初次尝试时完成计数.
	 * 如果我们进行重试,那么很可能会在页面缓存中找到该页面。
	 */

	perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS, 1, regs, addr);
	/* 如果handle_mm_fault()函数成功地给进程分配一个页框,则返回VM_FAULT_MINOR或VM_FAULT_MAJOR.
	 * 值VM_FAULT_MINOR表示在没有阻塞当前进程的情况下处理了缺页,这种缺页叫做次缺页(minor fault).
	 * 值VM_FAULT_MAJOR表示缺页迫使当前进程睡眠(很可能是由于当用磁盘上的数据填充所分配的页框时花费时间);阻塞当前进程的缺页就叫做主缺页(major fault).
	 * 函数也返回VM_FAULT_OOM(没有足够的内存)或VM_FAULT_STGBOS(其他任何错误).
	 */
	if (mm_flags & FAULT_FLAG_ALLOW_RETRY) {
		if (fault & VM_FAULT_MAJOR) {
			tsk->maj_flt++;
			perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS_MAJ, 1, regs,
				      addr);
		} else {
			tsk->min_flt++;
			perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS_MIN, 1, regs,
				      addr);
		}
		if (fault & VM_FAULT_RETRY) {
			/*
			 * Clear FAULT_FLAG_ALLOW_RETRY to avoid any risk of
			 * starvation.
			 *
			 * 清除FAULT_FLAG_ALLOW_RETRY以避免任何饥饿风险.
			 */
			mm_flags &= ~FAULT_FLAG_ALLOW_RETRY;
			/* #define FAULT_FLAG_TRIED	0x20	Second try */
			mm_flags |= FAULT_FLAG_TRIED;
			goto retry;
		}
	}

	up_read(&mm->mmap_sem);

	/*
	 * Handle the "normal" case first - VM_FAULT_MAJOR
	 */

	/* 如果没有返回(VM_FAULT_ERROR | VM_FAULT_BADMAP | VM_FAULT_BADACCESS) 说明缺页中断就处理完成了 */
	if (likely(!(fault & (VM_FAULT_ERROR | VM_FAULT_BADMAP |
			      VM_FAULT_BADACCESS))))
		return 0;

	/*
	 * If we are in kernel mode at this point, we have no context to
	 * handle this fault with.
	 *
	 * 如果我们现在处于内核模式,那么我们没有上下文来处理这个fault.
	 */
	if (!user_mode(regs))
		goto no_context;

	/* 如果错误类型是VM_FAULT_OOM,说明当前系统没有足够的内存,那么调用pagefault_out_of_memory函数触发OOM机制. */
	if (fault & VM_FAULT_OOM) {
		/*
		 * We ran out of memory, call the OOM killer, and return to
		 * userspace (which will retry the fault, or kill us if we got
		 * oom-killed).
		 *
		 * 我们耗尽了内存,调用OOM killer,然后返回到用户空间(这将重试fault,或者如果我们得到oom-killed,那就kill掉我们).
		 */
		pagefault_out_of_memory();
		return 0;
	}

	if (fault & VM_FAULT_SIGBUS) {
		/*
		 * We had some memory, but were unable to successfully fix up
		 * this page fault.
		 *
		 * 我们有一些内存,但无法成功修复此页面错误.
		 */
		sig = SIGBUS;
		code = BUS_ADRERR;
	} else {
		/*
		 * Something tried to access memory that isn't in our memory
		 * map.
		 *
		 * 有东西试图访问我们内存映射中没有的内存
		 */
		sig = SIGSEGV;
		code = fault == VM_FAULT_BADACCESS ?
			SEGV_ACCERR : SEGV_MAPERR;
	}

	/* __do_user_fault给用户进程发信号,因为这时内核已经无能为力了 */
	__do_user_fault(tsk, addr, esr, sig, code, regs);
	return 0;

no_context:
	__do_kernel_fault(mm, addr, esr, regs);
	return 0;
}

/*
 * First Level Translation Fault Handler
 *
 * We enter here because the first level page table doesn't contain a valid
 * entry for the address.
 *
 * If the address is in kernel space (>= TASK_SIZE), then we are probably
 * faulting in the vmalloc() area.
 *
 * If the init_task's first level page tables contains the relevant entry, we
 * copy the it to this task.  If not, we send the process a signal, fixup the
 * exception, or oops the kernel.
 *
 * NOTE! We MUST NOT take any locks for this case. We may be in an interrupt
 * or a critical region, and should only copy the information from the master
 * page table, nothing more.
 */
static int __kprobes do_translation_fault(unsigned long addr,
					  unsigned int esr,
					  struct pt_regs *regs)
{
	if (addr < TASK_SIZE)
		return do_page_fault(addr, esr, regs);

	do_bad_area(addr, esr, regs);
	return 0;
}

static int do_alignment_fault(unsigned long addr, unsigned int esr,
			      struct pt_regs *regs)
{
	do_bad_area(addr, esr, regs);
	return 0;
}

/*
 * This abort handler always returns "fault".
 */
static int do_bad(unsigned long addr, unsigned int esr, struct pt_regs *regs)
{
	return 1;
}

static const struct fault_info fault_info[] = {
	{ do_bad,		SIGBUS,  0,		"ttbr address size fault"	},
	{ do_bad,		SIGBUS,  0,		"level 1 address size fault"	},
	{ do_bad,		SIGBUS,  0,		"level 2 address size fault"	},
	{ do_bad,		SIGBUS,  0,		"level 3 address size fault"	},
	{ do_translation_fault,	SIGSEGV, SEGV_MAPERR,	"level 0 translation fault"	},
	{ do_translation_fault,	SIGSEGV, SEGV_MAPERR,	"level 1 translation fault"	},
	{ do_translation_fault,	SIGSEGV, SEGV_MAPERR,	"level 2 translation fault"	},
	{ do_page_fault,	SIGSEGV, SEGV_MAPERR,	"level 3 translation fault"	},
	{ do_bad,		SIGBUS,  0,		"unknown 8"			},
	{ do_page_fault,	SIGSEGV, SEGV_ACCERR,	"level 1 access flag fault"	},
	{ do_page_fault,	SIGSEGV, SEGV_ACCERR,	"level 2 access flag fault"	},
	{ do_page_fault,	SIGSEGV, SEGV_ACCERR,	"level 3 access flag fault"	},
	{ do_bad,		SIGBUS,  0,		"unknown 12"			},
	{ do_page_fault,	SIGSEGV, SEGV_ACCERR,	"level 1 permission fault"	},
	{ do_page_fault,	SIGSEGV, SEGV_ACCERR,	"level 2 permission fault"	},
	{ do_page_fault,	SIGSEGV, SEGV_ACCERR,	"level 3 permission fault"	},
	{ do_bad,		SIGBUS,  0,		"synchronous external abort"	},
	{ do_bad,		SIGBUS,  0,		"unknown 17"			},
	{ do_bad,		SIGBUS,  0,		"unknown 18"			},
	{ do_bad,		SIGBUS,  0,		"unknown 19"			},
	{ do_bad,		SIGBUS,  0,		"synchronous abort (translation table walk)" },
	{ do_bad,		SIGBUS,  0,		"synchronous abort (translation table walk)" },
	{ do_bad,		SIGBUS,  0,		"synchronous abort (translation table walk)" },
	{ do_bad,		SIGBUS,  0,		"synchronous abort (translation table walk)" },
	{ do_bad,		SIGBUS,  0,		"synchronous parity error"	},
	{ do_bad,		SIGBUS,  0,		"unknown 25"			},
	{ do_bad,		SIGBUS,  0,		"unknown 26"			},
	{ do_bad,		SIGBUS,  0,		"unknown 27"			},
	{ do_bad,		SIGBUS,  0,		"synchronous parity error (translation table walk)" },
	{ do_bad,		SIGBUS,  0,		"synchronous parity error (translation table walk)" },
	{ do_bad,		SIGBUS,  0,		"synchronous parity error (translation table walk)" },
	{ do_bad,		SIGBUS,  0,		"synchronous parity error (translation table walk)" },
	{ do_bad,		SIGBUS,  0,		"unknown 32"			},
	{ do_alignment_fault,	SIGBUS,  BUS_ADRALN,	"alignment fault"		},
	{ do_bad,		SIGBUS,  0,		"unknown 34"			},
	{ do_bad,		SIGBUS,  0,		"unknown 35"			},
	{ do_bad,		SIGBUS,  0,		"unknown 36"			},
	{ do_bad,		SIGBUS,  0,		"unknown 37"			},
	{ do_bad,		SIGBUS,  0,		"unknown 38"			},
	{ do_bad,		SIGBUS,  0,		"unknown 39"			},
	{ do_bad,		SIGBUS,  0,		"unknown 40"			},
	{ do_bad,		SIGBUS,  0,		"unknown 41"			},
	{ do_bad,		SIGBUS,  0,		"unknown 42"			},
	{ do_bad,		SIGBUS,  0,		"unknown 43"			},
	{ do_bad,		SIGBUS,  0,		"unknown 44"			},
	{ do_bad,		SIGBUS,  0,		"unknown 45"			},
	{ do_bad,		SIGBUS,  0,		"unknown 46"			},
	{ do_bad,		SIGBUS,  0,		"unknown 47"			},
	{ do_bad,		SIGBUS,  0,		"TLB conflict abort"		},
	{ do_bad,		SIGBUS,  0,		"unknown 49"			},
	{ do_bad,		SIGBUS,  0,		"unknown 50"			},
	{ do_bad,		SIGBUS,  0,		"unknown 51"			},
	{ do_bad,		SIGBUS,  0,		"implementation fault (lockdown abort)" },
	{ do_bad,		SIGBUS,  0,		"implementation fault (unsupported exclusive)" },
	{ do_bad,		SIGBUS,  0,		"unknown 54"			},
	{ do_bad,		SIGBUS,  0,		"unknown 55"			},
	{ do_bad,		SIGBUS,  0,		"unknown 56"			},
	{ do_bad,		SIGBUS,  0,		"unknown 57"			},
	{ do_bad,		SIGBUS,  0,		"unknown 58" 			},
	{ do_bad,		SIGBUS,  0,		"unknown 59"			},
	{ do_bad,		SIGBUS,  0,		"unknown 60"			},
	{ do_bad,		SIGBUS,  0,		"section domain fault"		},
	{ do_bad,		SIGBUS,  0,		"page domain fault"		},
	{ do_bad,		SIGBUS,  0,		"unknown 63"			},
};

/*
 * Dispatch a data abort to the relevant handler.
 */
asmlinkage void __exception do_mem_abort(unsigned long addr, unsigned int esr,
					 struct pt_regs *regs)
{
	/* 将esr转换成fault_info */
	const struct fault_info *inf = esr_to_fault_info(esr);
	struct siginfo info;

	/* 这里就是调用fault_info对应的function */
	if (!inf->fn(addr, esr, regs))
		return;

	pr_alert("Unhandled fault: %s (0x%08x) at 0x%016lx\n",
		 inf->name, esr, addr);

	info.si_signo = inf->sig;
	info.si_errno = 0;
	info.si_code  = inf->code;
	info.si_addr  = (void __user *)addr;
	arm64_notify_die("", regs, &info, esr);
}

/*
 * Handle stack alignment exceptions.
 */
asmlinkage void __exception do_sp_pc_abort(unsigned long addr,
					   unsigned int esr,
					   struct pt_regs *regs)
{
	struct siginfo info;
	struct task_struct *tsk = current;

	if (show_unhandled_signals && unhandled_signal(tsk, SIGBUS))
		pr_info_ratelimited("%s[%d]: %s exception: pc=%p sp=%p\n",
				    tsk->comm, task_pid_nr(tsk),
				    esr_get_class_string(esr), (void *)regs->pc,
				    (void *)regs->sp);

	info.si_signo = SIGBUS;
	info.si_errno = 0;
	info.si_code  = BUS_ADRALN;
	info.si_addr  = (void __user *)addr;
	arm64_notify_die("Oops - SP/PC alignment exception", regs, &info, esr);
}

int __init early_brk64(unsigned long addr, unsigned int esr,
		       struct pt_regs *regs);

/*
 * __refdata because early_brk64 is __init, but the reference to it is
 * clobbered at arch_initcall time.
 * See traps.c and debug-monitors.c:debug_traps_init().
 */
static struct fault_info __refdata debug_fault_info[] = {
	{ do_bad,	SIGTRAP,	TRAP_HWBKPT,	"hardware breakpoint"	},
	{ do_bad,	SIGTRAP,	TRAP_HWBKPT,	"hardware single-step"	},
	{ do_bad,	SIGTRAP,	TRAP_HWBKPT,	"hardware watchpoint"	},
	{ do_bad,	SIGBUS,		0,		"unknown 3"		},
	{ do_bad,	SIGTRAP,	TRAP_BRKPT,	"aarch32 BKPT"		},
	{ do_bad,	SIGTRAP,	0,		"aarch32 vector catch"	},
	{ early_brk64,	SIGTRAP,	TRAP_BRKPT,	"aarch64 BRK"		},
	{ do_bad,	SIGBUS,		0,		"unknown 7"		},
};

void __init hook_debug_fault_code(int nr,
				  int (*fn)(unsigned long, unsigned int, struct pt_regs *),
				  int sig, int code, const char *name)
{
	BUG_ON(nr < 0 || nr >= ARRAY_SIZE(debug_fault_info));

	debug_fault_info[nr].fn		= fn;
	debug_fault_info[nr].sig	= sig;
	debug_fault_info[nr].code	= code;
	debug_fault_info[nr].name	= name;
}

asmlinkage int __exception do_debug_exception(unsigned long addr,
					      unsigned int esr,
					      struct pt_regs *regs)
{
	const struct fault_info *inf = debug_fault_info + DBG_ESR_EVT(esr);
	struct siginfo info;
	int rv;

	/*
	 * Tell lockdep we disabled irqs in entry.S. Do nothing if they were
	 * already disabled to preserve the last enabled/disabled addresses.
	 */
	if (interrupts_enabled(regs))
		trace_hardirqs_off();

	if (!inf->fn(addr, esr, regs)) {
		rv = 1;
	} else {
		pr_alert("Unhandled debug exception: %s (0x%08x) at 0x%016lx\n",
			 inf->name, esr, addr);

		info.si_signo = inf->sig;
		info.si_errno = 0;
		info.si_code  = inf->code;
		info.si_addr  = (void __user *)addr;
		arm64_notify_die("", regs, &info, 0);
		rv = 0;
	}

	if (interrupts_enabled(regs))
		trace_hardirqs_on();

	return rv;
}
NOKPROBE_SYMBOL(do_debug_exception);

#ifdef CONFIG_ARM64_PAN
int cpu_enable_pan(void *__unused)
{
	/*
	 * We modify PSTATE. This won't work from irq context as the PSTATE
	 * is discarded once we return from the exception.
	 */
	WARN_ON_ONCE(in_interrupt());

	config_sctlr_el1(SCTLR_EL1_SPAN, 0);
	asm(SET_PSTATE_PAN(1));
	return 0;
}
#endif /* CONFIG_ARM64_PAN */

#ifdef CONFIG_ARM64_UAO
/*
 * Kernel threads have fs=KERNEL_DS by default, and don't need to call
 * set_fs(), devtmpfs in particular relies on this behaviour.
 * We need to enable the feature at runtime (instead of adding it to
 * PSR_MODE_EL1h) as the feature may not be implemented by the cpu.
 */
int cpu_enable_uao(void *__unused)
{
	asm(SET_PSTATE_UAO(1));
	return 0;
}
#endif /* CONFIG_ARM64_UAO */
