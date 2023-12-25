/*
 * Based on arch/arm/include/asm/tlbflush.h
 *
 * Copyright (C) 1999-2003 Russell King
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
#ifndef __ASM_TLBFLUSH_H
#define __ASM_TLBFLUSH_H

#ifndef __ASSEMBLY__

#include <linux/sched.h>
#include <asm/cputype.h>

/*
 * Raw TLBI operations.
 *
 * Where necessary, use the __tlbi() macro to avoid asm()
 * boilerplate. Drivers and most kernel code should use the TLB
 * management routines in preference to the macro below.
 *
 * The macro can be used as __tlbi(op) or __tlbi(op, arg), depending
 * on whether a particular TLBI operation takes an argument or
 * not. The macros handles invoking the asm with or without the
 * register argument as appropriate.
 */
#define __TLBI_0(op, arg)		asm ("tlbi " #op)
#define __TLBI_1(op, arg)		asm ("tlbi " #op ", %0" : : "r" (arg))
#define __TLBI_N(op, arg, n, ...)	__TLBI_##n(op, arg)
/* 在ARMv8-A中，TLB flush/invalidate（通常ARM/x86处理器手册中称为invalidate，linux系统中称为flush，以下的讨论统称为flush）的指令为：
 * TLBI <type><level>{IS} {, <Xt>}
 * 其中，"level"为1到3，对应ARMv8的三个exception level，即EL1，EL2，EL3，通常EL1运行linux等操作系统，EL2在虚拟化模式下运行hypervisor。
 * "type"相当于一个filter，指按照什么规则去选择被flush的item，
 * 包括VA(Virtual Address)，IPA(Intermediate Physical Address)，ASID（Adress Space Identifier），VMID（Virtual Mechine Identifier）等。
 * 在虚拟化模式下，IPA即EL1层的物理地址，它需要经过EL2层的转化才能成为最终的物理地址。
 * ASID是区别有相同虚拟地址的不同进程的，VMID是区别有相同虚拟地址的不同虚拟机的。
 * "Xt"是可选参数，表示通用寄存器X0到X30。例如 “TLBI VAE1, X0”，表示将flush虚拟地址（type为VA）等于X0寄存器值的这个TLB entry。
 * 当然也可以使用“TLBI ALLELn”将TLB中的所有entries全部flush。
 * "IS"（Inner Shareable）也是可选参数。Inner和Outer是描述cache属性的，通常一个CPU独有的（比如L1 cache）和一个cluster下的CPU共享的（比如L2 cache）被定义为inner，
 * 不同cluster的CPU共享的（比如L3 cache）被定义为outer。
 * TLB也是一种cache，但不管是L1 data/instuction TLB，还是L2 LTB，都是每个CPU单独一份，所以都是inner的。
 * Shareable是描述内存属性的，表示该内存区域是否可被多核共享。
 * 对于多核共享的内存，当其中的某个核，比如，对共享内存中的某个page做了访问限制，它需要通过发出IPI（Inter Processor Interrupt）的方式，
 * 来通知其他核flush各自的TLB，这种方式被称为TLB击落（shootdown），在ARM指令上的体现就是TLBI IS.
 */
#define __tlbi(op, ...)		__TLBI_N(op, ##__VA_ARGS__, 1, 0)

/*
 *	TLB Management
 *	==============
 *
 *	The TLB specific code is expected to perform whatever tests it needs
 *	to determine if it should invalidate the TLB for each call.  Start
 *	addresses are inclusive and end addresses are exclusive; it is safe to
 *	round these addresses down.
 *
 *	flush_tlb_all()
 *
 *		Invalidate the entire TLB.
 *
 *	flush_tlb_mm(mm)
 *
 *		Invalidate all TLB entries in a particular address space.
 *		- mm	- mm_struct describing address space
 *
 *	flush_tlb_range(mm,start,end)
 *
 *		Invalidate a range of TLB entries in the specified address
 *		space.
 *		- mm	- mm_struct describing address space
 *		- start - start address (may not be aligned)
 *		- end	- end address (exclusive, may not be aligned)
 *
 *	flush_tlb_page(vaddr,vma)
 *
 *		Invalidate the specified page in the specified address range.
 *		- vaddr - virtual address (may not be aligned)
 *		- vma	- vma_struct describing address range
 *
 *	flush_kern_tlb_page(kaddr)
 *
 *		Invalidate the TLB entry for the specified page.  The address
 *		will be in the kernels virtual memory space.  Current uses
 *		only require the D-TLB to be invalidated.
 *		- kaddr - Kernel virtual memory address
 */
static inline void local_flush_tlb_all(void)
{
	dsb(nshst);
	/* tlbi vmalle1 */
	__tlbi(vmalle1);
	dsb(nsh);
	isb();
}

static inline void flush_tlb_all(void)
{
	dsb(ishst);
	__tlbi(vmalle1is);
	dsb(ish);
	isb();
}

static inline void flush_tlb_mm(struct mm_struct *mm)
{
	unsigned long asid = ASID(mm) << 48;

	dsb(ishst);
	__tlbi(aside1is, asid);
	dsb(ish);
}

static inline void flush_tlb_page(struct vm_area_struct *vma,
				  unsigned long uaddr)
{
	unsigned long addr = uaddr >> 12 | (ASID(vma->vm_mm) << 48);

	dsb(ishst);
	__tlbi(vale1is, addr);
	dsb(ish);
}

/*
 * This is meant to avoid soft lock-ups on large TLB flushing ranges and not
 * necessarily a performance improvement.
 */
#define MAX_TLB_RANGE	(1024UL << PAGE_SHIFT)

static inline void __flush_tlb_range(struct vm_area_struct *vma,
				     unsigned long start, unsigned long end,
				     bool last_level)
{
	/* 获得asid */
	unsigned long asid = ASID(vma->vm_mm) << 48;
	unsigned long addr;
	/* 如果end-start 大于这个函数上面定义的最大的TLB RANGE */
	if ((end - start) > MAX_TLB_RANGE) {
		flush_tlb_mm(vma->vm_mm);
		return;
	}

	start = asid | (start >> 12);
	end = asid | (end >> 12);

	dsb(ishst);
	for (addr = start; addr < end; addr += 1 << (PAGE_SHIFT - 12)) {
		if (last_level)
			__tlbi(vale1is, addr);
		else
			__tlbi(vae1is, addr);
	}
	dsb(ish);
}

static inline void flush_tlb_range(struct vm_area_struct *vma,
				   unsigned long start, unsigned long end)
{
	__flush_tlb_range(vma, start, end, false);
}

static inline void flush_tlb_kernel_range(unsigned long start, unsigned long end)
{
	unsigned long addr;

	if ((end - start) > MAX_TLB_RANGE) {
		flush_tlb_all();
		return;
	}

	start >>= 12;
	end >>= 12;

	dsb(ishst);
	for (addr = start; addr < end; addr += 1 << (PAGE_SHIFT - 12))
		__tlbi(vaae1is, addr);
	dsb(ish);
	isb();
}

/*
 * Used to invalidate the TLB (walk caches) corresponding to intermediate page
 * table levels (pgd/pud/pmd).
 */
static inline void __flush_tlb_pgtable(struct mm_struct *mm,
				       unsigned long uaddr)
{
	unsigned long addr = uaddr >> 12 | (ASID(mm) << 48);

	__tlbi(vae1is, addr);
	dsb(ish);
}

#endif

#endif
