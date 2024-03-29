/*
 * arch/arm/mm/proc-v7-2level.S
 *
 * Copyright (C) 2001 Deep Blue Solutions Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#define TTB_S		(1 << 1)
#define TTB_RGN_NC	(0 << 3)
#define TTB_RGN_OC_WBWA	(1 << 3)
#define TTB_RGN_OC_WT	(2 << 3)
#define TTB_RGN_OC_WB	(3 << 3)
#define TTB_NOS		(1 << 5)
#define TTB_IRGN_NC	((0 << 0) | (0 << 6))
#define TTB_IRGN_WBWA	((0 << 0) | (1 << 6))
#define TTB_IRGN_WT	((1 << 0) | (0 << 6))
#define TTB_IRGN_WB	((1 << 0) | (1 << 6))

/* PTWs cacheable, inner WB not shareable, outer WB not shareable */
#define TTB_FLAGS_UP	TTB_IRGN_WB|TTB_RGN_OC_WB
#define PMD_FLAGS_UP	PMD_SECT_WB

/* PTWs cacheable, inner WBWA shareable, outer WBWA not shareable */
#define TTB_FLAGS_SMP	TTB_IRGN_WBWA|TTB_S|TTB_NOS|TTB_RGN_OC_WBWA
#define PMD_FLAGS_SMP	PMD_SECT_WBWA|PMD_SECT_S

/*
 *	cpu_v7_switch_mm(pgd_phys, tsk)
 *
 *	Set the translation table base pointer to be pgd_phys
 *
 *	- pgd_phys - physical address of new TTB
 *
 *	It is assumed that:
 *	- we are not using split page tables
 *
 *	Note that we always need to flush BTAC/BTB if IBE is set
 *	even on Cortex-A8 revisions not affected by 430973.
 *	If IBE is not set, the flush BTAC/BTB won't do anything.
 */
ENTRY(cpu_ca8_switch_mm)
#ifdef CONFIG_MMU
	mov	r2, #0
	mcr	p15, 0, r2, c7, c5, 6		@ flush BTAC/BTB
#endif
ENTRY(cpu_v7_switch_mm)
#ifdef CONFIG_MMU
	mmid	r1, r1				@ get mm->context.id
	ALT_SMP(orr	r0, r0, #TTB_FLAGS_SMP)
	ALT_UP(orr	r0, r0, #TTB_FLAGS_UP)
#ifdef CONFIG_PID_IN_CONTEXTIDR
	mrc	p15, 0, r2, c13, c0, 1		@ read current context ID
	lsr	r2, r2, #8			@ extract the PID
	bfi	r1, r2, #8, #24			@ insert into new context ID
#endif
#ifdef CONFIG_ARM_ERRATA_754322
	dsb
#endif
	mcr	p15, 0, r1, c13, c0, 1		@ set context ID
	isb
	mcr	p15, 0, r0, c2, c0, 0		@ set TTB 0
	isb
#endif
	bx	lr
ENDPROC(cpu_v7_switch_mm)
ENDPROC(cpu_ca8_switch_mm)

/*
 *	cpu_v7_set_pte_ext(ptep, pte)
 *
 *	Set a level 2 translation table entry.
 *
 *	- ptep  - pointer to level 2 translation table entry
 *		  (hardware version is stored at +2048 bytes)
 *	- pte   - PTE value to store
 *	- ext	- value for extended PTE bits
 */
/* cpu_v7_set_pte_ext函数参数r0表示PTE entry页面表项的指针,
 * 注意ARM linux中实现了两份页表,硬件页表的地址r0 + 2048.
 * 因此r0指Linux版本的页面表地址,r1表示要写入的linux版本PTE页面表项的内容,
 * 这里指linux版本的页面表项的内容,而非硬件版本的页面表项的内容.
 * 该函数的主要目的是根据Linux版本的页面表项内容来填充ARM硬件版本的页表项
 *
 * 首先把Linux版本的页面表项内容写入Linux版本的页表中,然后根据mem_type数据
 * 结构prot_pte的标志位来设置ARMv7-A硬件相关的标志位.
 * prot_pte的标志位是Linux内核中采用的,定义在arch/arm/include/asm/pgtable-2level.h头文件中,
 * 而硬件相关的标志位定义在arch/arm/include/asm/pgteble-2level-hwdef.h头文件.
 * 这两份标志位对应的偏移是不一样的,所以不同架构的处理器需要单独处理
 *
 */
ENTRY(cpu_v7_set_pte_ext)
#ifdef CONFIG_MMU
	str	r1, [r0]			@ linux version

	bic	r3, r1, #0x000003f0
	bic	r3, r3, #PTE_TYPE_MASK
	orr	r3, r3, r2
	orr	r3, r3, #PTE_EXT_AP0 | 2

	tst	r1, #1 << 4
	orrne	r3, r3, #PTE_EXT_TEX(1)		/* 设置TEX */

	eor	r1, r1, #L_PTE_DIRTY
	tst	r1, #L_PTE_RDONLY | L_PTE_DIRTY
	orrne	r3, r3, #PTE_EXT_APX		/* 设置AP[2] */

	tst	r1, #L_PTE_USER
	orrne	r3, r3, #PTE_EXT_AP1		/* 设置AP[1 : 0 ] */

	tst	r1, #L_PTE_XN
	orrne	r3, r3, #PTE_EXT_XN		/* 设置PXN */
	/* 如果没有设置L_PTE_YOUNG并且L_PTE_PRESENT置位,那就保持Linux版本的页表保持不变,
	 * 把ARM32硬件版本的页面表项内容清零.
	 * 代码中L_PTE_VALID和L_PTE_NONE这两个软件比特位是后来添加的,
	 * 因此在Linux 3.7及以前的内核版本中更容易理解一些.
	 *
	 * 为什么这里要把ARM硬件版本的页面表项内容清零呢?我们观察ARM32硬件版本的页面表相关标志会发现,
	 * 没有表示页面被访问和压面在内存中的硬件标志位.
	 * Linux内核最早基于X86体系结构设计的,所以Linux内核关于页表的很多术语和设计都针对于x86架构,
	 * 而ARM Linux只能从软件架构上去跟随了,因此设计了两套页表,在x86的页面表中有3个标志位是从ARM32硬件页面表没有提供的.
	 *
	 * PTE_DIRTY: CPU在写操作的时候会设置该标志位,表示对应页面被写过,为脏页.
	 * PTE_YOUNG: CPU访问该页时会设置该标志位.在页面换出时,如果该标志位置位了,说明该页刚被访问过,页面是young的,不适合把该页换出,同时清除该标志位.
	 * PTE_PRESENT:表示页在内存中.
	 * 因此在ARM Linux实现中需要模拟上述3个比特位.
	 *
	 * 如何模拟PTE DIRTY呢,在ARM MMU硬件为一个干净页面建立映射时,设置硬件页表项是只读权限.
	 * 当往一个干净的页面写入时,会触发写权限缺页中断(虽然Linux版本的页面的页表项标记了可写权限,
	 * 但是ARM硬件页面表项还不具有写入权限),那么在缺页中断handle_pte_fault中会在该页的Linux版本PTE页面表项标记为drity“”,
	 * 并且发现PTE页表项内容改变了,ptep_set_access_flags函数会把新的Linux版本的页表项内容写入硬件页表,从而完成模拟过程
	 */
	tst	r1, #L_PTE_YOUNG
	tstne	r1, #L_PTE_VALID
	eorne	r1, r1, #L_PTE_NONE
	tstne	r1, #L_PTE_NONE
	moveq	r3, #0
	/* 写入硬件页表,硬件页表在软件页表+ 2048 Byte */
 ARM(	str	r3, [r0, #2048]! )
 THUMB(	add	r0, r0, #2048 )
 THUMB(	str	r3, [r0] )
	ALT_SMP(W(nop))
	ALT_UP (mcr	p15, 0, r0, c7, c10, 1)		@ flush_pte
#endif
	bx	lr
ENDPROC(cpu_v7_set_pte_ext)

	/*
	 * Memory region attributes with SCTLR.TRE=1
	 *
	 *   n = TEX[0],C,B
	 *   TR = PRRR[2n+1:2n]		- memory type
	 *   IR = NMRR[2n+1:2n]		- inner cacheable property
	 *   OR = NMRR[2n+17:2n+16]	- outer cacheable property
	 *
	 *			n	TR	IR	OR
	 *   UNCACHED		000	00
	 *   BUFFERABLE		001	10	00	00
	 *   WRITETHROUGH	010	10	10	10
	 *   WRITEBACK		011	10	11	11
	 *   reserved		110
	 *   WRITEALLOC		111	10	01	01
	 *   DEV_SHARED		100	01
	 *   DEV_NONSHARED	100	01
	 *   DEV_WC		001	10
	 *   DEV_CACHED		011	10
	 *
	 * Other attributes:
	 *
	 *   DS0 = PRRR[16] = 0		- device shareable property
	 *   DS1 = PRRR[17] = 1		- device shareable property
	 *   NS0 = PRRR[18] = 0		- normal shareable property
	 *   NS1 = PRRR[19] = 1		- normal shareable property
	 *   NOS = PRRR[24+n] = 1	- not outer shareable
	 */
.equ	PRRR,	0xff0a81a8
.equ	NMRR,	0x40e040e0

	/*
	 * Macro for setting up the TTBRx and TTBCR registers.
	 * - \ttb0 and \ttb1 updated with the corresponding flags.
	 */
	.macro	v7_ttb_setup, zero, ttbr0l, ttbr0h, ttbr1, tmp
	mcr	p15, 0, \zero, c2, c0, 2	@ TTB control register
	ALT_SMP(orr	\ttbr0l, \ttbr0l, #TTB_FLAGS_SMP)
	ALT_UP(orr	\ttbr0l, \ttbr0l, #TTB_FLAGS_UP)
	ALT_SMP(orr	\ttbr1, \ttbr1, #TTB_FLAGS_SMP)
	ALT_UP(orr	\ttbr1, \ttbr1, #TTB_FLAGS_UP)
	mcr	p15, 0, \ttbr1, c2, c0, 1	@ load TTB1
	.endm

	/*   AT
	 *  TFR   EV X F   I D LR    S
	 * .EEE ..EE PUI. .T.T 4RVI ZWRS BLDP WCAM
	 * rxxx rrxx xxx0 0101 xxxx xxxx x111 xxxx < forced
	 *   01    0 110       0011 1100 .111 1101 < we want
	 */
	.align	2
	.type	v7_crval, #object
v7_crval:
	crval	clear=0x2120c302, mmuset=0x10c03c7d, ucset=0x00c01c7c
