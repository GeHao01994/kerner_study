/* include/asm-generic/tlb.h
 *
 *	Generic TLB shootdown code
 *
 * Copyright 2001 Red Hat, Inc.
 * Based on code from mm/memory.c Copyright Linus Torvalds and others.
 *
 * Copyright 2011 Red Hat, Inc., Peter Zijlstra
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */
#ifndef _ASM_GENERIC__TLB_H
#define _ASM_GENERIC__TLB_H

#include <linux/swap.h>
#include <asm/pgalloc.h>
#include <asm/tlbflush.h>

#ifdef CONFIG_HAVE_RCU_TABLE_FREE
/*
 * Semi RCU freeing of the page directories.
 *
 * This is needed by some architectures to implement software pagetable walkers.
 *
 * gup_fast() and other software pagetable walkers do a lockless page-table
 * walk and therefore needs some synchronization with the freeing of the page
 * directories. The chosen means to accomplish that is by disabling IRQs over
 * the walk.
 *
 * Architectures that use IPIs to flush TLBs will then automagically DTRT,
 * since we unlink the page, flush TLBs, free the page. Since the disabling of
 * IRQs delays the completion of the TLB flush we can never observe an already
 * freed page.
 *
 * Architectures that do not have this (PPC) need to delay the freeing by some
 * other means, this is that means.
 *
 * What we do is batch the freed directory pages (tables) and RCU free them.
 * We use the sched RCU variant, as that guarantees that IRQ/preempt disabling
 * holds off grace periods.
 *
 * However, in order to batch these pages we need to allocate storage, this
 * allocation is deep inside the MM code and can thus easily fail on memory
 * pressure. To guarantee progress we fall back to single table freeing, see
 * the implementation of tlb_remove_table_one().
 *
 */
/* 用于积聚进程使用的各级页目录的物理页，在释放进程相关的页目录的物理页时使用（文章中称为页表批次的积聚结构) */
struct mmu_table_batch {
	/* rcu 用于rcu延迟释放页目录的物理页 */
	struct rcu_head		rcu;
	/* 表示页目录的物理页的积聚结构的page数组中页面个数 */
	unsigned int		nr;
	/* tables 表示页表积聚结构的page数组 */
	void			*tables[0];
};

#define MAX_TABLE_BATCH		\
	((PAGE_SIZE - sizeof(struct mmu_table_batch)) / sizeof(void *))

extern void tlb_table_flush(struct mmu_gather *tlb);
extern void tlb_remove_table(struct mmu_gather *tlb, void *table);

#endif

/*
 * If we can't allocate a page to make a big batch of page pointers
 * to work on, then just handle a few from the on-stack structure.
 */
#define MMU_GATHER_BUNDLE	8

struct mmu_gather_batch {
	/* next 用于多批次积聚物理页时，连接下一个积聚批次结构 */
	struct mmu_gather_batch	*next;
	/* nr 表示本次批次的积聚数组的页面个数 */
	unsigned int		nr;
	/* max 表示本次批次的积聚数组最大的页面个数 */
	unsigned int		max;
	/* pages 表示本次批次积聚结构的page数组 */
	struct page		*pages[0];
};

#define MAX_GATHER_BATCH	\
	((PAGE_SIZE - sizeof(struct mmu_gather_batch)) / sizeof(void *))

/*
 * Limit the maximum number of mmu_gather batches to reduce a risk of soft
 * lockups for non-preemptible kernels on huge machines when a lot of memory
 * is zapped during unmapping.
 * 10K pages freed at once should be safe even without a preemption point.
 */
/* 限制mmu_gather批次的最大数量以降低在大型机器上安装不可抢占的内核当大量内存在取消映射过程中被占用时soft lockups的影响
 * 即使没有抢占点，一次释放的10K页也应该是安全的
 */
#define MAX_GATHER_BATCH_COUNT	(10000UL/MAX_GATHER_BATCH)

/* struct mmu_gather is an opaque type used by the mm code for passing around
 * any data needed by arch specific code for tlb_remove_page.
 */
/* 通常在进程退出或者执行munmap的时候，内核会解除相关虚拟内存区域的页表映射，刷/无效tlb,
 * 并释放/回收相关的物理页面，这一过程的正确顺序如下
 * 1、解除页表映射
 * 2、刷相关tlb
 * 3、释放物理页面
 * 在刷相关虚拟内存区域tlb之前，绝对不能先释放物理页面，否则可能导致不正确的结构，
 * 而mmu-gather(mmu积聚)的作用就是保证这种顺序，并将需要释放的相关的物理页面聚集起来统一释放
 */
struct mmu_gather {
	/*  mm 表示操作哪个进程的虚拟内存 */
	struct mm_struct	*mm;
#ifdef CONFIG_HAVE_RCU_TABLE_FREE
	/* batch 用于积聚进程各级页目录的物理页 */
	struct mmu_table_batch	*batch;
#endif
	/* start和end 表示操作的起始和结束虚拟地址
	 * 这两个地址在处理过程中会被相应的赋值
	 */
	unsigned long		start;
	unsigned long		end;
	/* we are in the middle of an operation to clear
	 * a full mm and can make some optimizations */
	/* 我们正在进行清除整个mm的操作，可以进行一些优化 */
	/* fullmm 表示是否操作整个用户地址空间 */
	unsigned int		fullmm : 1,
	/* we have performed an operation which
	 * requires a complete flush of the tlb */
	/* 我们已经执行了一个操作，该操作需要完全刷新tlb */
				need_flush_all : 1;
	/* active、local和__pages 和多批次释放物理页面相关;
	 * active表示当前处理的批次，local表示“本地”批次，
	 * __pages表示“本地”批次积聚的物理页面.这里需要说明一点就是，mmu积聚操作会涉及到local批次和多批次操作，
	 * local批次操作的物理页面相关的struct page数组内嵌到mmu_gather结构的__pages中，
	 * 且我们发现这个数组大小为8，也就是local批次最大积聚8 * 4k = 32k的内存大小，
	 * 这因为mmu_gather结构通常在内核栈中分配，不能占用太多的内核栈空间，
	 * 而多批次由于动态分配批次积聚结构所以每个批次能积聚更多的页面
	 */
	struct mmu_gather_batch *active;
	struct mmu_gather_batch	local;
	struct page		*__pages[MMU_GATHER_BUNDLE];
	/* batch_count 表示积聚了多少个“批次” */
	unsigned int		batch_count;
	/*
	 * __tlb_adjust_range  will track the new addr here,
	 * that that we can adjust the range after the flush
	 */
	unsigned long addr;
	int page_size;
};

#define HAVE_GENERIC_MMU_GATHER

void tlb_gather_mmu(struct mmu_gather *tlb, struct mm_struct *mm, unsigned long start, unsigned long end);
void tlb_flush_mmu(struct mmu_gather *tlb);
void tlb_finish_mmu(struct mmu_gather *tlb, unsigned long start,
							unsigned long end);
extern bool __tlb_remove_page_size(struct mmu_gather *tlb, struct page *page,
				   int page_size);

static inline void __tlb_adjust_range(struct mmu_gather *tlb,
				      unsigned long address)
{
	/* 计算start的地址，取start和address的最小值 */
	tlb->start = min(tlb->start, address);
	/* 计算end的地址，取tlb->end和address+PAGE_SIZE的最大值 */
	tlb->end = max(tlb->end, address + PAGE_SIZE);
	/*
	 * Track the last address with which we adjusted the range. This
	 * will be used later to adjust again after a mmu_flush due to
	 * failed __tlb_remove_page
	 */
	/* Track 当我们调整range时最后的地址.
	 * 它将在一个mmu_flush因为__tlb_remove_page失败后在此用于调整
	 */
	/* 把address给它 */
	tlb->addr = address;
}

static inline void __tlb_reset_range(struct mmu_gather *tlb)
{
	/* 如果是fullmm,也就是说整个地址空间，那么就把
	 * tlb->start和tlb->end全都赋值给0xffffffff
	 */
	if (tlb->fullmm) {
		tlb->start = tlb->end = ~0;
	} else {
		/* 如果不是，那么就把start赋值给TASK_SIZE
		 * end赋值给0
		 */
		tlb->start = TASK_SIZE;
		tlb->end = 0;
	}
}

static inline void tlb_remove_page_size(struct mmu_gather *tlb,
					struct page *page, int page_size)
{
	/* 这里的话，是为了聚集而做的，只有在batch->nr == batch->max
	 * 或者tlb->batch_count == MAX_GATHER_BATCH_COUNT
	 */
	if (__tlb_remove_page_size(tlb, page, page_size)) {
		/* 刷tlb */
		tlb_flush_mmu(tlb);
		/* 设置page_size */
		tlb->page_size = page_size;
		/*  计算range,然后在做一次 */
		__tlb_adjust_range(tlb, tlb->addr);
		__tlb_remove_page_size(tlb, page, page_size);
	}
}

static bool __tlb_remove_page(struct mmu_gather *tlb, struct page *page)
{
	return __tlb_remove_page_size(tlb, page, PAGE_SIZE);
}

/* tlb_remove_page
 *	Similar to __tlb_remove_page but will call tlb_flush_mmu() itself when
 *	required.
 */
static inline void tlb_remove_page(struct mmu_gather *tlb, struct page *page)
{
	return tlb_remove_page_size(tlb, page, PAGE_SIZE);
}

static inline bool __tlb_remove_pte_page(struct mmu_gather *tlb, struct page *page)
{
	/* active->nr should be zero when we call this */
	VM_BUG_ON_PAGE(tlb->active->nr, page);
	tlb->page_size = PAGE_SIZE;
	__tlb_adjust_range(tlb, tlb->addr);
	return __tlb_remove_page(tlb, page);
}

/*
 * In the case of tlb vma handling, we can optimise these away in the
 * case where we're doing a full MM flush.  When we're doing a munmap,
 * the vmas are adjusted to only cover the region to be torn down.
 */
#ifndef tlb_start_vma
#define tlb_start_vma(tlb, vma) do { } while (0)
#endif

#define __tlb_end_vma(tlb, vma)					\
	do {							\
		if (!tlb->fullmm && tlb->end) {			\
			tlb_flush(tlb);				\
			__tlb_reset_range(tlb);			\
		}						\
	} while (0)

#ifndef tlb_end_vma
#define tlb_end_vma	__tlb_end_vma
#endif

#ifndef __tlb_remove_tlb_entry
#define __tlb_remove_tlb_entry(tlb, ptep, address) do { } while (0)
#endif

/**
 * tlb_remove_tlb_entry - remember a pte unmapping for later tlb invalidation.
 *
 * Record the fact that pte's were really unmapped by updating the range,
 * so we can later optimise away the tlb invalidate.   This helps when
 * userspace is unmapping already-unmapped pages, which happens quite a lot.
 */
/* 为之后的tlb 无效 记录 pte的unmappping
 *
 * 记录通过更新range确实未映射的pte，这样我们之后能优化消除tlb无效.
 * 当用户空间取消映射已经映射的页面时，这会有所帮助，这种情况经常发生
 */
#define tlb_remove_tlb_entry(tlb, ptep, address)		\
	do {							\
		__tlb_adjust_range(tlb, address);		\
		__tlb_remove_tlb_entry(tlb, ptep, address);	\
	} while (0)

/**
 * tlb_remove_pmd_tlb_entry - remember a pmd mapping for later tlb invalidation
 * This is a nop so far, because only x86 needs it.
 */
#ifndef __tlb_remove_pmd_tlb_entry
#define __tlb_remove_pmd_tlb_entry(tlb, pmdp, address) do {} while (0)
#endif

#define tlb_remove_pmd_tlb_entry(tlb, pmdp, address)		\
	do {							\
		__tlb_adjust_range(tlb, address);		\
		__tlb_remove_pmd_tlb_entry(tlb, pmdp, address);	\
	} while (0)

#define pte_free_tlb(tlb, ptep, address)			\
	do {							\
		__tlb_adjust_range(tlb, address);		\
		__pte_free_tlb(tlb, ptep, address);		\
	} while (0)

#ifndef __ARCH_HAS_4LEVEL_HACK
#define pud_free_tlb(tlb, pudp, address)			\
	do {							\
		__tlb_adjust_range(tlb, address);		\
		__pud_free_tlb(tlb, pudp, address);		\
	} while (0)
#endif

#define pmd_free_tlb(tlb, pmdp, address)			\
	do {							\
		__tlb_adjust_range(tlb, address);		\
		__pmd_free_tlb(tlb, pmdp, address);		\
	} while (0)

#define tlb_migrate_finish(mm) do {} while (0)

#endif /* _ASM_GENERIC__TLB_H */
