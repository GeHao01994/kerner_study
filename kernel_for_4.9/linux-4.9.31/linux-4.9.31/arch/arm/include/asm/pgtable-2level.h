/*
 *  arch/arm/include/asm/pgtable-2level.h
 *
 *  Copyright (C) 1995-2002 Russell King
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#ifndef _ASM_PGTABLE_2LEVEL_H
#define _ASM_PGTABLE_2LEVEL_H

#define __PAGETABLE_PMD_FOLDED

/* ARM32系统只用到了两层映射,因此在实际代码中就要在3层映射模型中合并1层.
 * 在ARM32架构中,可以按段(section)来映射,这时采用单层映射模式.
 * 使用页面映射需要两层映射结构,页面的选择可以是64KB的大页面或4KB的小页面.
 * 如下图,linux内核通常默认使用4KB大小的小页面
 *  ____________________ _______________ _______________
 * |                    |               |               |
 * |____________________|_______________|_______________|
 * 31       |         20 19     |     12 11             0
 *	    |                   |
 *          |                   |
 *          |                   |
 *          |                   |
 *          ↓                   ↓
 *       ______             ________
 *      |      |           |        |
 *      |      |           |        |
 *      |      |           |        |
 *      |      |           |        |
 *      |______|           |________|
 *      |______|------     |________|----------
 *      |      |     |     |        |         |
 *      |______|     |----→|________|         |
 *	 PGD页表            PTE页表项         |
 *    4096个页表项          256个表项         |
 *       ↑                                    |
 *       |                                    ↓
 *    ______	 	  _____________________________________________ __________
 *   |	    |		 |                                             |          |
 *   |______|	 	 |_____________________________________________|__________|
 *  页表基地址寄存器     31                                          12 11        0
 *    TTBRx
 *			arm32 处理器查询页表
 *
 * 段映射:
 * 如果采用单层的段映射,内存中有一个段映射表,表中有4096个表项,每个表项的大小都是4Byte,所以这个段映射表的大小是16KB,而且其位置必须与16KB边界对齐.
 * 每个段表项可以寻址1MB大小的空间地址.当CPU访问内存时,32位虚拟地址的高12位(bit[31:20])用作访问段映射表的索引,从表中找到相应的表项.
 * 每个表项提供一个12位的物理地址,以及相应的标志位,如可读、可写等标志位.
 * 将这个12位物理地址和虚拟地址的低20位拼凑在一起,就可以得到32位物理地址.
 *
 * 页表映射:
 * 如果采用页表映射的方式,段映射表就变成一级映射表(First Level Table,在Linux内核中称为PGD),其表项提供的不再是物理段的地址,而是二级页表的基地址.
 * 32位虚拟地址的高12位(bit[31 : 20])作为访问一级页表的索引值,找到相应的表项,每个表项指向一个二级页表.以虚拟地址的次8位(bit[19:12])作为访问二级
 * 页表的索引值,得到相应的页表项,从这个页表项中找到20位的物理页面地址.
 * 最后将这个20位物理页面地址和虚拟地址的低12位拼凑在一起,最终得到的32位物理地址.这个过程在ARM32架构中由MMU硬件完成,软件不需要接入
 */
/*
 * Hardware-wise, we have a two level page table structure, where the first
 * level has 4096 entries, and the second level has 256 entries.  Each entry
 * is one 32-bit word.  Most of the bits in the second level entry are used
 * by hardware, and there aren't any "accessed" and "dirty" bits.
 *
 * 在硬件方面,我们有一个两级页表结构,其中第一级有4096个entries,第二级有256个entries.
 * 每个entries是一个32位的word.
 * 第二级entry中的大多数位由硬件使用,并且没有任何“accessed”和“dirty”位.
 *
 * Linux on the other hand has a three level page table structure, which can
 * be wrapped to fit a two level page table structure easily - using the PGD
 * and PTE only.  However, Linux also expects one "PTE" table per page, and
 * at least a "dirty" bit.
 *
 * Linux在另一方面有三级页表结构,它可以很容易地包装成适合两级页表的结构 - 只使用PGD和PTE.
 * 然而,Linux也期望每页有一个“PTE”表,并且至少有一个”dirty“位.
 *
 * Therefore, we tweak the implementation slightly - we tell Linux that we
 * have 2048 entries in the first level, each of which is 8 bytes (iow, two
 * hardware pointers to the second level.)  The second level contains two
 * hardware PTE tables arranged contiguously, preceded by Linux versions
 * which contain the state information Linux needs.  We, therefore, end up
 * with 512 entries in the "PTE" level.
 *
 * 因此,我们稍微调整了一下实现 - 我们告诉Linux,我们在第一级中有2048个条目,
 * 每个条目都是8个字节(iow，两个硬件页表的指针指向第二级).
 * 第二级包含两个连续排列的硬件PTE页表,前面是包含Linux所需的状态信息的Linux版本.
 * 因此，我们最终在“PTE”级别中有512个条目.
 *
 * This leads to the page tables having the following layout:
 * 这导致页面表具有以下布局
 *
 *    pgd             pte
 * |        |
 * +--------+
 * |        |       +------------+ +0
 * +- - - - +       | Linux pt 0 |
 * |        |       +------------+ +1024
 * +--------+ +0    | Linux pt 1 |
 * |        |-----> +------------+ +2048
 * +- - - - + +4    |  h/w pt 0  |
 * |        |-----> +------------+ +3072
 * +--------+ +8    |  h/w pt 1  |
 * |        |       +------------+ +4096
 *
 * See L_PTE_xxx below for definitions of bits in the "Linux pt", and
 * PTE_xxx for definitions of bits appearing in the "h/w pt".
 *
 * 有关“Linux pt”中的位的定义,请参见下面的L_PTE_xxx.
 * 有关“h/w pt”中出现的位的描述，请参见PTE_xxx.
 *
 * PMD_xxx definitions refer to bits in the first level page table.
 * PMD_xxx定义是指一级页面表中的位.
 *
 * The "dirty" bit is emulated by only granting hardware write permission
 * iff the page is marked "writable" and "dirty" in the Linux PTE.  This
 * means that a write to a clean page will cause a permission fault, and
 * the Linux MM layer will mark the page dirty via handle_pte_fault().
 * For the hardware to notice the permission change, the TLB entry must
 * be flushed, and ptep_set_access_flags() does that for us.
 *
 * 当页面在Linux PTE中标记为“writable”和“dirty”时,仅通过授予硬件写入权限来模拟“dirty”位
 * 这意味着写一个干净的页面将造成权限fault,Linux MM层将通过handle_pte_fault()将页面标记为脏.
 * 要使硬件注意到权限更改，TLB条目必须被刷新,而ptep_set_access_flags()为我们执行此操作.
 *
 * The "accessed" or "young" bit is emulated by a similar method; we only
 * allow accesses to the page if the "young" bit is set.  Accesses to the
 * page will cause a fault, and handle_pte_fault() will set the young bit
 * for us as long as the page is marked present in the corresponding Linux
 * PTE entry.  Again, ptep_set_access_flags() will ensure that the TLB is
 * up to date.
 *
 * 通过类似的方法模拟“accessed”或“young”位;
 * 只有在设置了“young”位的情况下,我们才允许访问该页面.
 * 对页面的访问将导致fault,只要页面在相应的Linux PTE entry中标记为present,
 * handle_pte_fault()就会为我们设置young bit.
 *
 * However, when the "young" bit is cleared, we deny access to the page
 * by clearing the hardware PTE.  Currently Linux does not flush the TLB
 * for us in this case, which means the TLB will retain the transation
 * until either the TLB entry is evicted under pressure, or a context
 * switch which changes the user space mapping occurs.
 *
 * 然而,当“young”位被清除时,我们通过清除硬件PTE来拒绝对页面的访问.
 * 目前Linux在这种情况下不会为我们刷新TLB，这意味着TLB将保留转换,直到TLB entry在压力下被驱逐,
 * 或者发生改变用户空间映射的上下文切换.
 */
#define PTRS_PER_PTE		512
#define PTRS_PER_PMD		1
#define PTRS_PER_PGD		2048

#define PTE_HWTABLE_PTRS	(PTRS_PER_PTE)
#define PTE_HWTABLE_OFF		(PTE_HWTABLE_PTRS * sizeof(pte_t))
#define PTE_HWTABLE_SIZE	(PTRS_PER_PTE * sizeof(u32))

/*
 * PMD_SHIFT determines the size of the area a second-level page table can map
 * PGDIR_SHIFT determines what a third-level page table entry can map
 */
#define PMD_SHIFT		21
#define PGDIR_SHIFT		21

#define PMD_SIZE		(1UL << PMD_SHIFT)
#define PMD_MASK		(~(PMD_SIZE-1))
#define PGDIR_SIZE		(1UL << PGDIR_SHIFT)
#define PGDIR_MASK		(~(PGDIR_SIZE-1))

/*
 * section address mask and size definitions.
 */
#define SECTION_SHIFT		20
#define SECTION_SIZE		(1UL << SECTION_SHIFT)
#define SECTION_MASK		(~(SECTION_SIZE-1))

/*
 * ARMv6 supersection address mask and size definitions.
 */
#define SUPERSECTION_SHIFT	24
#define SUPERSECTION_SIZE	(1UL << SUPERSECTION_SHIFT)
#define SUPERSECTION_MASK	(~(SUPERSECTION_SIZE-1))

#define USER_PTRS_PER_PGD	(TASK_SIZE / PGDIR_SIZE)

/*
 * "Linux" PTE definitions.
 *
 * We keep two sets of PTEs - the hardware and the linux version.
 * This allows greater flexibility in the way we map the Linux bits
 * onto the hardware tables, and allows us to have YOUNG and DIRTY
 * bits.
 *
 * The PTE table pointer refers to the hardware entries; the "Linux"
 * entries are stored 1024 bytes below.
 *
 * “Linux” PTE定义。
 *
 * 我们保留了两组PTE - 硬件版本和linux版本.
 * 这允许我们将Linux bit映射到硬件表的方式上具有更大的灵活性,
 * 并允许我们使用YOUNG和DIRTY bits
 *
 * PTE表指针指的是硬件entries；“Linux”条目存储在1024字节以下.
 */

/* prot_pte成员用于页表项的控制位和标志位 */
#define L_PTE_VALID		(_AT(pteval_t, 1) << 0)		/* Valid */
#define L_PTE_PRESENT		(_AT(pteval_t, 1) << 0)
#define L_PTE_YOUNG		(_AT(pteval_t, 1) << 1)
#define L_PTE_DIRTY		(_AT(pteval_t, 1) << 6)
#define L_PTE_RDONLY		(_AT(pteval_t, 1) << 7)
#define L_PTE_USER		(_AT(pteval_t, 1) << 8)
#define L_PTE_XN		(_AT(pteval_t, 1) << 9)
#define L_PTE_SHARED		(_AT(pteval_t, 1) << 10)	/* shared(v6), coherent(xsc3) */
#define L_PTE_NONE		(_AT(pteval_t, 1) << 11)

/*
 * These are the memory types, defined to be compatible with
 * pre-ARMv6 CPUs cacheable and bufferable bits: n/a,n/a,C,B
 * ARMv6+ without TEX remapping, they are a table index.
 * ARMv6+ with TEX remapping, they correspond to n/a,TEX(0),C,B
 *
 * MT type		Pre-ARMv6	ARMv6+ type / cacheable status
 * UNCACHED		Uncached	Strongly ordered
 * BUFFERABLE		Bufferable	Normal memory / non-cacheable
 * WRITETHROUGH		Writethrough	Normal memory / write through
 * WRITEBACK		Writeback	Normal memory / write back, read alloc
 * MINICACHE		Minicache	N/A
 * WRITEALLOC		Writeback	Normal memory / write back, write alloc
 * DEV_SHARED		Uncached	Device memory (shared)
 * DEV_NONSHARED	Uncached	Device memory (non-shared)
 * DEV_WC		Bufferable	Normal memory / non-cacheable
 * DEV_CACHED		Writeback	Normal memory / write back, read alloc
 * VECTORS		Variable	Normal memory / variable
 *
 * All normal memory mappings have the following properties:
 * - reads can be repeated with no side effects
 * - repeated reads return the last value written
 * - reads can fetch additional locations without side effects
 * - writes can be repeated (in certain cases) with no side effects
 * - writes can be merged before accessing the target
 * - unaligned accesses can be supported
 *
 * All device mappings have the following properties:
 * - no access speculation
 * - no repetition (eg, on return from an exception)
 * - number, order and size of accesses are maintained
 * - unaligned accesses are "unpredictable"
 */
#define L_PTE_MT_UNCACHED	(_AT(pteval_t, 0x00) << 2)	/* 0000 */
#define L_PTE_MT_BUFFERABLE	(_AT(pteval_t, 0x01) << 2)	/* 0001 */
#define L_PTE_MT_WRITETHROUGH	(_AT(pteval_t, 0x02) << 2)	/* 0010 */
#define L_PTE_MT_WRITEBACK	(_AT(pteval_t, 0x03) << 2)	/* 0011 */
#define L_PTE_MT_MINICACHE	(_AT(pteval_t, 0x06) << 2)	/* 0110 (sa1100, xscale) */
#define L_PTE_MT_WRITEALLOC	(_AT(pteval_t, 0x07) << 2)	/* 0111 */
#define L_PTE_MT_DEV_SHARED	(_AT(pteval_t, 0x04) << 2)	/* 0100 */
#define L_PTE_MT_DEV_NONSHARED	(_AT(pteval_t, 0x0c) << 2)	/* 1100 */
#define L_PTE_MT_DEV_WC		(_AT(pteval_t, 0x09) << 2)	/* 1001 */
#define L_PTE_MT_DEV_CACHED	(_AT(pteval_t, 0x0b) << 2)	/* 1011 */
#define L_PTE_MT_VECTORS	(_AT(pteval_t, 0x0f) << 2)	/* 1111 */
#define L_PTE_MT_MASK		(_AT(pteval_t, 0x0f) << 2)

#ifndef __ASSEMBLY__

/*
 * The "pud_xxx()" functions here are trivial when the pmd is folded into
 * the pud: the pud entry is never bad, always exists, and can't be set or
 * cleared.
 */
#define pud_none(pud)		(0)
#define pud_bad(pud)		(0)
#define pud_present(pud)	(1)
#define pud_clear(pudp)		do { } while (0)
#define set_pud(pud,pudp)	do { } while (0)

static inline pmd_t *pmd_offset(pud_t *pud, unsigned long addr)
{
	return (pmd_t *)pud;
}

#define pmd_large(pmd)		(pmd_val(pmd) & 2)
#define pmd_bad(pmd)		(pmd_val(pmd) & 2)
#define pmd_present(pmd)	(pmd_val(pmd))

#define copy_pmd(pmdpd,pmdps)		\
	do {				\
		pmdpd[0] = pmdps[0];	\
		pmdpd[1] = pmdps[1];	\
		flush_pmd_entry(pmdpd);	\
	} while (0)

#define pmd_clear(pmdp)			\
	do {				\
		pmdp[0] = __pmd(0);	\
		pmdp[1] = __pmd(0);	\
		clean_pmd_entry(pmdp);	\
	} while (0)

/* we don't need complex calculations here as the pmd is folded into the pgd */
#define pmd_addr_end(addr,end) (end)

#define set_pte_ext(ptep,pte,ext) cpu_set_pte_ext(ptep,pte,ext)
#define pte_special(pte)	(0)
static inline pte_t pte_mkspecial(pte_t pte) { return pte; }

/*
 * We don't have huge page support for short descriptors, for the moment
 * define empty stubs for use by pin_page_for_write.
 */
#define pmd_hugewillfault(pmd)	(0)
#define pmd_thp_or_huge(pmd)	(0)

#endif /* __ASSEMBLY__ */

#endif /* _ASM_PGTABLE_2LEVEL_H */
