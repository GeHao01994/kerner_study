/*
 *  linux/mm/memory.c
 *
 *  Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 */

/*
 * demand-loading started 01.12.91 - seems it is high on the list of
 * things wanted, and it should be easy to implement. - Linus
 */

/*
 * Ok, demand-loading was easy, shared pages a little bit tricker. Shared
 * pages started 02.12.91, seems to work. - Linus.
 *
 * Tested sharing by executing about 30 /bin/sh: under the old kernel it
 * would have taken more than the 6M I have free, but it worked well as
 * far as I could see.
 *
 * Also corrected some "invalidate()"s - I wasn't doing enough of them.
 */

/*
 * Real VM (paging to/from disk) started 18.12.91. Much more work and
 * thought has to go into this. Oh, well..
 * 19.12.91  -  works, somewhat. Sometimes I get faults, don't know why.
 *		Found it. Everything seems to work now.
 * 20.12.91  -  Ok, making the swap-device changeable like the root.
 */

/*
 * 05.04.94  -  Multi-page memory management added for v1.1.
 * 		Idea by Alex Bligh (alex@cconcepts.co.uk)
 *
 * 16.07.99  -  Support of BIGMEM added by Gerhard Wichert, Siemens AG
 *		(Gerhard.Wichert@pdb.siemens.de)
 *
 * Aug/Sep 2004 Changed to four level page tables (Andi Kleen)
 */

#include <linux/kernel_stat.h>
#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <linux/mman.h>
#include <linux/swap.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/ksm.h>
#include <linux/rmap.h>
#include <linux/export.h>
#include <linux/delayacct.h>
#include <linux/init.h>
#include <linux/pfn_t.h>
#include <linux/writeback.h>
#include <linux/memcontrol.h>
#include <linux/mmu_notifier.h>
#include <linux/kallsyms.h>
#include <linux/swapops.h>
#include <linux/elf.h>
#include <linux/gfp.h>
#include <linux/migrate.h>
#include <linux/string.h>
#include <linux/dma-debug.h>
#include <linux/debugfs.h>
#include <linux/userfaultfd_k.h>
#include <linux/dax.h>

#include <asm/io.h>
#include <asm/mmu_context.h>
#include <asm/pgalloc.h>
#include <asm/uaccess.h>
#include <asm/tlb.h>
#include <asm/tlbflush.h>
#include <asm/pgtable.h>

#include "internal.h"

#ifdef LAST_CPUPID_NOT_IN_PAGE_FLAGS
#warning Unfortunate NUMA and NUMA Balancing config, growing page-frame for last_cpupid.
#endif

#ifndef CONFIG_NEED_MULTIPLE_NODES
/* use the per-pgdat data instead for discontigmem - mbligh */
unsigned long max_mapnr;
struct page *mem_map;

EXPORT_SYMBOL(max_mapnr);
EXPORT_SYMBOL(mem_map);
#endif

/*
 * A number of key systems in x86 including ioremap() rely on the assumption
 * that high_memory defines the upper bound on direct map memory, then end
 * of ZONE_NORMAL.  Under CONFIG_DISCONTIG this means that max_low_pfn and
 * highstart_pfn must be the same; there must be no gap between ZONE_NORMAL
 * and ZONE_HIGHMEM.
 */
void * high_memory;

EXPORT_SYMBOL(high_memory);

/*
 * Randomize the address space (stacks, mmaps, brk, etc.).
 *
 * ( When CONFIG_COMPAT_BRK=y we exclude brk from randomization,
 *   as ancient (libc5 based) binaries can segfault. )
 */
int randomize_va_space __read_mostly =
#ifdef CONFIG_COMPAT_BRK
					1;
#else
					2;
#endif

static int __init disable_randmaps(char *s)
{
	randomize_va_space = 0;
	return 1;
}
__setup("norandmaps", disable_randmaps);

unsigned long zero_pfn __read_mostly;
unsigned long highest_memmap_pfn __read_mostly;

EXPORT_SYMBOL(zero_pfn);

/*
 * CONFIG_MMU architectures set up ZERO_PAGE in their paging_init()
 */
static int __init init_zero_pfn(void)
{
	zero_pfn = page_to_pfn(ZERO_PAGE(0));
	return 0;
}
core_initcall(init_zero_pfn);


#if defined(SPLIT_RSS_COUNTING)

void sync_mm_rss(struct mm_struct *mm)
{
	int i;

	for (i = 0; i < NR_MM_COUNTERS; i++) {
		if (current->rss_stat.count[i]) {
			add_mm_counter(mm, i, current->rss_stat.count[i]);
			current->rss_stat.count[i] = 0;
		}
	}
	current->rss_stat.events = 0;
}

static void add_mm_counter_fast(struct mm_struct *mm, int member, int val)
{
	struct task_struct *task = current;

	if (likely(task->mm == mm))
		task->rss_stat.count[member] += val;
	else
		add_mm_counter(mm, member, val);
}
#define inc_mm_counter_fast(mm, member) add_mm_counter_fast(mm, member, 1)
#define dec_mm_counter_fast(mm, member) add_mm_counter_fast(mm, member, -1)

/* sync counter once per 64 page faults */
#define TASK_RSS_EVENTS_THRESH	(64)
static void check_sync_rss_stat(struct task_struct *task)
{
	if (unlikely(task != current))
		return;
	if (unlikely(task->rss_stat.events++ > TASK_RSS_EVENTS_THRESH))
		sync_mm_rss(task->mm);
}
#else /* SPLIT_RSS_COUNTING */

#define inc_mm_counter_fast(mm, member) inc_mm_counter(mm, member)
#define dec_mm_counter_fast(mm, member) dec_mm_counter(mm, member)

static void check_sync_rss_stat(struct task_struct *task)
{
}

#endif /* SPLIT_RSS_COUNTING */

#ifdef HAVE_GENERIC_MMU_GATHER

static bool tlb_next_batch(struct mmu_gather *tlb)
{
	struct mmu_gather_batch *batch;
	/* 拿到active的tlb */
	batch = tlb->active;
	/* 如果有next就把active指向next之后返回true */
	if (batch->next) {
		tlb->active = batch->next;
		return true;
	}
	/* 如果tlb的batch_out等于了最大的batch
	 * 那么就返回false吧
	 */
	if (tlb->batch_count == MAX_GATHER_BATCH_COUNT)
		return false;
	/* 分配一个batch */
	batch = (void *)__get_free_pages(GFP_NOWAIT | __GFP_NOWARN, 0);
	if (!batch)
		return false;
	/* batch_count++ */
	tlb->batch_count++;
	/* batch->next 设置为NULL */
	batch->next = NULL;
	/* batch->nr 设置为0
	 * 将本batch的页面个数设置为0
	 */
	batch->nr   = 0;
	/* 设置本batch的最大页面个数为MAX_GATHER_BATCH */
	batch->max  = MAX_GATHER_BATCH;
	/* 设置active->next为此batch */
	tlb->active->next = batch;
	/* 设置此batch为active batch */
	tlb->active = batch;

	return true;
}

/* tlb_gather_mmu
 *	Called to initialize an (on-stack) mmu_gather structure for page-table
 *	tear-down from @mm. The @fullmm argument is used when @mm is without
 *	users and we're going to destroy the full address space (exit/execve).
 */
/* 调用以初始化（在堆栈上）mmu_gather结构，以便从@mm中拆下页表.
 * @fullmm参数在@mm没有使用者，我们将破坏整个地址空间(exit/execve)
 */
void tlb_gather_mmu(struct mmu_gather *tlb, struct mm_struct *mm, unsigned long start, unsigned long end)
{
	/* 赋值进程的内存描述符 */
	tlb->mm = mm;
	/* Is it from 0 to ~0? */
	/* 如果是操作进程整个地址空间,则 start=0,end=-1，这个时候 fullmm会被赋值1 */
	tlb->fullmm     = !(start | (end+1));
	/* 把需要刷新全部的tlb设置为0 */
	tlb->need_flush_all = 0;
	/* 把本地批次的next指针设置为NULL */
	tlb->local.next = NULL;
	/* 把本地批次的积聚数组的页面个数设置为0 */
	tlb->local.nr   = 0;
	/* __pages表示“本地”批次积聚的物理页面.这里需要说明一点就是，mmu积聚操作会涉及到local批次和多批次操作，
	 * local批次操作的物理页面相关的struct page数组内嵌到mmu_gather结构的__pages中.
	 * 所以这里会把tlb->pages的数组大小给local.max
	 */
	tlb->local.max  = ARRAY_SIZE(tlb->__pages);
	/* 把当前处理的的批次指向tlb->local */
	tlb->active     = &tlb->local;
	/* batch_count 表示积聚了多少个“批次” */
	tlb->batch_count = 0;

#ifdef CONFIG_HAVE_RCU_TABLE_FREE
	tlb->batch = NULL;
#endif
	tlb->page_size = 0;
	/* static inline void __tlb_reset_range(struct mmu_gather *tlb)
	 * {
	 *	 * 如果是fullmm,也就是说整个地址空间，那么就把
	 *	 * tlb->start和tlb->end全都赋值给0xffffffff
	 * 	 *
	 *	if (tlb->fullmm) {
	 *		tlb->start = tlb->end = ~0;
	 *	} else {
	 *		* 如果不是，那么就把start赋值给TASK_SIZE
	 *		* end赋值给0
	 *		*
	 *		tlb->start = TASK_SIZE;
	 *		tlb->end = 0;
	 *	}
	 * }
	 */
	__tlb_reset_range(tlb);
}

static void tlb_flush_mmu_tlbonly(struct mmu_gather *tlb)
{
	if (!tlb->end)
		return;

	tlb_flush(tlb);
	mmu_notifier_invalidate_range(tlb->mm, tlb->start, tlb->end);
#ifdef CONFIG_HAVE_RCU_TABLE_FREE
	tlb_table_flush(tlb);
#endif
	__tlb_reset_range(tlb);
}

static void tlb_flush_mmu_free(struct mmu_gather *tlb)
{
	struct mmu_gather_batch *batch;

	for (batch = &tlb->local; batch && batch->nr; batch = batch->next) {
		free_pages_and_swap_cache(batch->pages, batch->nr);
		batch->nr = 0;
	}
	tlb->active = &tlb->local;
}

void tlb_flush_mmu(struct mmu_gather *tlb)
{
	/* 刷TLB */
	tlb_flush_mmu_tlbonly(tlb);
	/* free相关的page */
	tlb_flush_mmu_free(tlb);
}

/* tlb_finish_mmu
 *	Called at the end of the shootdown operation to free up any resources
 *	that were required.
 */
void tlb_finish_mmu(struct mmu_gather *tlb, unsigned long start, unsigned long end)
{
	struct mmu_gather_batch *batch, *next;

	tlb_flush_mmu(tlb);

	/* keep the page table cache within bounds */
	check_pgt_cache();

	for (batch = tlb->local.next; batch; batch = next) {
		next = batch->next;
		free_pages((unsigned long)batch, 0);
	}
	tlb->local.next = NULL;
}

/* __tlb_remove_page
 *	Must perform the equivalent to __free_pte(pte_get_and_clear(ptep)), while
 *	handling the additional races in SMP caused by other CPUs caching valid
 *	mappings in their TLBs. Returns the number of free page slots left.
 *	When out of page slots we must call tlb_flush_mmu().
 *returns true if the caller should flush.
 */
/*
 * __tlb_remove_page
 * 必须执行等效于__free_pte（pte_get_and_clear（ptep））的操作，处理SMP中由其他CPU在其TLB中缓存有效映射引起的额外争用。
 * 返回剩余的可用页面插槽数。当页面插槽不足时，我们必须调用tlb_flush_mmu（）。如果调用者应该刷新，则返回true
 */
bool __tlb_remove_page_size(struct mmu_gather *tlb, struct page *page, int page_size)
{
	struct mmu_gather_batch *batch;

	VM_BUG_ON(!tlb->end);
	/* 如果tlb->page_size为空
	 * 那么填充这个page_size
	 */
	if (!tlb->page_size)
		tlb->page_size = page_size;
	else {
		/* 如果page_size和tlb->page_size不相等
		 * 那么也返回true
		 */
		if (page_size != tlb->page_size)
			return true;
	}
	/* 拿到active的mmu_gather_batch */
	batch = tlb->active;
	/* 如果number已经等于max了，那么再申请一个？ */
	if (batch->nr == batch->max) {
		if (!tlb_next_batch(tlb))
			return true;
		batch = tlb->active;
	}
	VM_BUG_ON_PAGE(batch->nr > batch->max, page);
	/* 然后把这个page添加到这个batch里面去 */
	batch->pages[batch->nr++] = page;
	return false;
}

#endif /* HAVE_GENERIC_MMU_GATHER */

#ifdef CONFIG_HAVE_RCU_TABLE_FREE

/*
 * See the comment near struct mmu_table_batch.
 */

static void tlb_remove_table_smp_sync(void *arg)
{
	/* Simply deliver the interrupt */
}

static void tlb_remove_table_one(void *table)
{
	/*
	 * This isn't an RCU grace period and hence the page-tables cannot be
	 * assumed to be actually RCU-freed.
	 *
	 * It is however sufficient for software page-table walkers that rely on
	 * IRQ disabling. See the comment near struct mmu_table_batch.
	 */
	smp_call_function(tlb_remove_table_smp_sync, NULL, 1);
	__tlb_remove_table(table);
}

static void tlb_remove_table_rcu(struct rcu_head *head)
{
	struct mmu_table_batch *batch;
	int i;

	batch = container_of(head, struct mmu_table_batch, rcu);

	for (i = 0; i < batch->nr; i++)
		__tlb_remove_table(batch->tables[i]);

	free_page((unsigned long)batch);
}

void tlb_table_flush(struct mmu_gather *tlb)
{
	struct mmu_table_batch **batch = &tlb->batch;

	if (*batch) {
		call_rcu_sched(&(*batch)->rcu, tlb_remove_table_rcu);
		*batch = NULL;
	}
}

void tlb_remove_table(struct mmu_gather *tlb, void *table)
{
	struct mmu_table_batch **batch = &tlb->batch;

	/*
	 * When there's less then two users of this mm there cannot be a
	 * concurrent page-table walk.
	 */
	if (atomic_read(&tlb->mm->mm_users) < 2) {
		__tlb_remove_table(table);
		return;
	}

	if (*batch == NULL) {
		*batch = (struct mmu_table_batch *)__get_free_page(GFP_NOWAIT | __GFP_NOWARN);
		if (*batch == NULL) {
			tlb_remove_table_one(table);
			return;
		}
		(*batch)->nr = 0;
	}
	(*batch)->tables[(*batch)->nr++] = table;
	if ((*batch)->nr == MAX_TABLE_BATCH)
		tlb_table_flush(tlb);
}

#endif /* CONFIG_HAVE_RCU_TABLE_FREE */

/*
 * Note: this doesn't free the actual pages themselves. That
 * has been handled earlier when unmapping all the memory regions.
 */
static void free_pte_range(struct mmu_gather *tlb, pmd_t *pmd,
			   unsigned long addr)
{
	pgtable_t token = pmd_pgtable(*pmd);
	pmd_clear(pmd);
	pte_free_tlb(tlb, token, addr);
	atomic_long_dec(&tlb->mm->nr_ptes);
}

static inline void free_pmd_range(struct mmu_gather *tlb, pud_t *pud,
				unsigned long addr, unsigned long end,
				unsigned long floor, unsigned long ceiling)
{
	pmd_t *pmd;
	unsigned long next;
	unsigned long start;

	start = addr;
	pmd = pmd_offset(pud, addr);
	do {
		next = pmd_addr_end(addr, end);
		if (pmd_none_or_clear_bad(pmd))
			continue;
		free_pte_range(tlb, pmd, addr);
	} while (pmd++, addr = next, addr != end);

	start &= PUD_MASK;
	if (start < floor)
		return;
	if (ceiling) {
		ceiling &= PUD_MASK;
		if (!ceiling)
			return;
	}
	if (end - 1 > ceiling - 1)
		return;

	pmd = pmd_offset(pud, start);
	pud_clear(pud);
	pmd_free_tlb(tlb, pmd, start);
	mm_dec_nr_pmds(tlb->mm);
}

static inline void free_pud_range(struct mmu_gather *tlb, pgd_t *pgd,
				unsigned long addr, unsigned long end,
				unsigned long floor, unsigned long ceiling)
{
	pud_t *pud;
	unsigned long next;
	unsigned long start;

	start = addr;
	pud = pud_offset(pgd, addr);
	do {
		next = pud_addr_end(addr, end);
		if (pud_none_or_clear_bad(pud))
			continue;
		free_pmd_range(tlb, pud, addr, next, floor, ceiling);
	} while (pud++, addr = next, addr != end);

	start &= PGDIR_MASK;
	if (start < floor)
		return;
	if (ceiling) {
		ceiling &= PGDIR_MASK;
		if (!ceiling)
			return;
	}
	if (end - 1 > ceiling - 1)
		return;

	pud = pud_offset(pgd, start);
	pgd_clear(pgd);
	pud_free_tlb(tlb, pud, start);
}

/*
 * This function frees user-level page tables of a process.
 */
void free_pgd_range(struct mmu_gather *tlb,
			unsigned long addr, unsigned long end,
			unsigned long floor, unsigned long ceiling)
{
	pgd_t *pgd;
	unsigned long next;

	/*
	 * The next few lines have given us lots of grief...
	 *
	 * Why are we testing PMD* at this top level?  Because often
	 * there will be no work to do at all, and we'd prefer not to
	 * go all the way down to the bottom just to discover that.
	 *
	 * Why all these "- 1"s?  Because 0 represents both the bottom
	 * of the address space and the top of it (using -1 for the
	 * top wouldn't help much: the masks would do the wrong thing).
	 * The rule is that addr 0 and floor 0 refer to the bottom of
	 * the address space, but end 0 and ceiling 0 refer to the top
	 * Comparisons need to use "end - 1" and "ceiling - 1" (though
	 * that end 0 case should be mythical).
	 *
	 * Wherever addr is brought up or ceiling brought down, we must
	 * be careful to reject "the opposite 0" before it confuses the
	 * subsequent tests.  But what about where end is brought down
	 * by PMD_SIZE below? no, end can't go down to 0 there.
	 *
	 * Whereas we round start (addr) and ceiling down, by different
	 * masks at different levels, in order to test whether a table
	 * now has no other vmas using it, so can be freed, we don't
	 * bother to round floor or end up - the tests don't need that.
	 */

	addr &= PMD_MASK;
	if (addr < floor) {
		addr += PMD_SIZE;
		if (!addr)
			return;
	}
	if (ceiling) {
		ceiling &= PMD_MASK;
		if (!ceiling)
			return;
	}
	if (end - 1 > ceiling - 1)
		end -= PMD_SIZE;
	if (addr > end - 1)
		return;

	pgd = pgd_offset(tlb->mm, addr);
	do {
		next = pgd_addr_end(addr, end);
		if (pgd_none_or_clear_bad(pgd))
			continue;
		free_pud_range(tlb, pgd, addr, next, floor, ceiling);
	} while (pgd++, addr = next, addr != end);
}

void free_pgtables(struct mmu_gather *tlb, struct vm_area_struct *vma,
		unsigned long floor, unsigned long ceiling)
{
	while (vma) {
		struct vm_area_struct *next = vma->vm_next;
		unsigned long addr = vma->vm_start;

		/*
		 * Hide vma from rmap and truncate_pagecache before freeing
		 * pgtables
		 */
		unlink_anon_vmas(vma);
		unlink_file_vma(vma);

		if (is_vm_hugetlb_page(vma)) {
			hugetlb_free_pgd_range(tlb, addr, vma->vm_end,
				floor, next? next->vm_start: ceiling);
		} else {
			/*
			 * Optimization: gather nearby vmas into one call down
			 */
			while (next && next->vm_start <= vma->vm_end + PMD_SIZE
			       && !is_vm_hugetlb_page(next)) {
				vma = next;
				next = vma->vm_next;
				unlink_anon_vmas(vma);
				unlink_file_vma(vma);
			}
			free_pgd_range(tlb, addr, vma->vm_end,
				floor, next? next->vm_start: ceiling);
		}
		vma = next;
	}
}

int __pte_alloc(struct mm_struct *mm, pmd_t *pmd, unsigned long address)
{
	spinlock_t *ptl;
	pgtable_t new = pte_alloc_one(mm, address);
	if (!new)
		return -ENOMEM;

	/*
	 * Ensure all pte setup (eg. pte page lock and page clearing) are
	 * visible before the pte is made visible to other CPUs by being
	 * put into page tables.
	 *
	 * The other side of the story is the pointer chasing in the page
	 * table walking code (when walking the page table without locking;
	 * ie. most of the time). Fortunately, these data accesses consist
	 * of a chain of data-dependent loads, meaning most CPUs (alpha
	 * being the notable exception) will already guarantee loads are
	 * seen in-order. See the alpha page table accessors for the
	 * smp_read_barrier_depends() barriers in page table walking code.
	 */
	smp_wmb(); /* Could be smp_wmb__xxx(before|after)_spin_lock */

	ptl = pmd_lock(mm, pmd);
	if (likely(pmd_none(*pmd))) {	/* Has another populated it ? */
		atomic_long_inc(&mm->nr_ptes);
		pmd_populate(mm, pmd, new);
		new = NULL;
	}
	spin_unlock(ptl);
	if (new)
		pte_free(mm, new);
	return 0;
}

int __pte_alloc_kernel(pmd_t *pmd, unsigned long address)
{
	pte_t *new = pte_alloc_one_kernel(&init_mm, address);
	if (!new)
		return -ENOMEM;

	smp_wmb(); /* See comment in __pte_alloc */

	spin_lock(&init_mm.page_table_lock);
	if (likely(pmd_none(*pmd))) {	/* Has another populated it ? */
		pmd_populate_kernel(&init_mm, pmd, new);
		new = NULL;
	}
	spin_unlock(&init_mm.page_table_lock);
	if (new)
		pte_free_kernel(&init_mm, new);
	return 0;
}

static inline void init_rss_vec(int *rss)
{
	memset(rss, 0, sizeof(int) * NR_MM_COUNTERS);
}

static inline void add_mm_rss_vec(struct mm_struct *mm, int *rss)
{
	int i;

	/* 如果当前进程的mm和我们的mm是一致的
	 * 那就先sync当前进程的current->rss_stat.count
	 */
	if (current->mm == mm)
		sync_mm_rss(mm);
	/* 然后再加上带进来的rss的值 */
	for (i = 0; i < NR_MM_COUNTERS; i++)
		if (rss[i])
			add_mm_counter(mm, i, rss[i]);
}

/*
 * This function is called to print an error when a bad pte
 * is found. For example, we might have a PFN-mapped pte in
 * a region that doesn't allow it.
 *
 * The calling function must still handle the error.
 */
static void print_bad_pte(struct vm_area_struct *vma, unsigned long addr,
			  pte_t pte, struct page *page)
{
	pgd_t *pgd = pgd_offset(vma->vm_mm, addr);
	pud_t *pud = pud_offset(pgd, addr);
	pmd_t *pmd = pmd_offset(pud, addr);
	struct address_space *mapping;
	pgoff_t index;
	static unsigned long resume;
	static unsigned long nr_shown;
	static unsigned long nr_unshown;

	/*
	 * Allow a burst of 60 reports, then keep quiet for that minute;
	 * or allow a steady drip of one report per second.
	 */
	if (nr_shown == 60) {
		if (time_before(jiffies, resume)) {
			nr_unshown++;
			return;
		}
		if (nr_unshown) {
			pr_alert("BUG: Bad page map: %lu messages suppressed\n",
				 nr_unshown);
			nr_unshown = 0;
		}
		nr_shown = 0;
	}
	if (nr_shown++ == 0)
		resume = jiffies + 60 * HZ;

	mapping = vma->vm_file ? vma->vm_file->f_mapping : NULL;
	index = linear_page_index(vma, addr);

	pr_alert("BUG: Bad page map in process %s  pte:%08llx pmd:%08llx\n",
		 current->comm,
		 (long long)pte_val(pte), (long long)pmd_val(*pmd));
	if (page)
		dump_page(page, "bad pte");
	pr_alert("addr:%p vm_flags:%08lx anon_vma:%p mapping:%p index:%lx\n",
		 (void *)addr, vma->vm_flags, vma->anon_vma, mapping, index);
	/*
	 * Choose text because data symbols depend on CONFIG_KALLSYMS_ALL=y
	 */
	pr_alert("file:%pD fault:%pf mmap:%pf readpage:%pf\n",
		 vma->vm_file,
		 vma->vm_ops ? vma->vm_ops->fault : NULL,
		 vma->vm_file ? vma->vm_file->f_op->mmap : NULL,
		 mapping ? mapping->a_ops->readpage : NULL);
	dump_stack();
	add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
}

/*
 * vm_normal_page -- This function gets the "struct page" associated with a pte.
 *
 * "Special" mappings do not wish to be associated with a "struct page" (either
 * it doesn't exist, or it exists but they don't want to touch it). In this
 * case, NULL is returned here. "Normal" mappings do have a struct page.
 *
 * There are 2 broad cases. Firstly, an architecture may define a pte_special()
 * pte bit, in which case this function is trivial. Secondly, an architecture
 * may not have a spare pte bit, which requires a more complicated scheme,
 * described below.
 *
 * A raw VM_PFNMAP mapping (ie. one that is not COWed) is always considered a
 * special mapping (even if there are underlying and valid "struct pages").
 * COWed pages of a VM_PFNMAP are always normal.
 *
 * The way we recognize COWed pages within VM_PFNMAP mappings is through the
 * rules set up by "remap_pfn_range()": the vma will have the VM_PFNMAP bit
 * set, and the vm_pgoff will point to the first PFN mapped: thus every special
 * mapping will always honor the rule
 *
 *	pfn_of_page == vma->vm_pgoff + ((addr - vma->vm_start) >> PAGE_SHIFT)
 *
 * vm_normal_page -- 此函数获取与pte关联的"struct page".
 *
 * “Special” 映射不希望与“struct page”关联(要么它不存在,要么它存在但他们不想接触它).
 * 在这种情况下,此处返回NULL.“Normal”映射确实有struct page.
 *
 * 有两种广泛的情况.首先,一个体系结构可以定义一个pte_special() pte位,在这种情况下,这个函数是微不足道的.
 * 其次,架构可能没有空闲的pte位,这需要更复杂的方案,如下所述.
 *
 * 原始VM_PFNMAP映射(即非COWed映射)始终被视为special映射(即使存在底层有效的“struct pages”).
 * VM_PFNMAP的COWed页面总是正常的.
 *
 * 我们在VM_PFNMAP映射中识别COWed页面的方式是通过由"remap_pfn_range()"设置的规则:vma将设置VM_PFNMAP位,
 * 并且vm_pgoff将指向映射的第一个PFN: 因此,每个特殊映射都将始终遵循该规则
 *
 * pfn_of_page == vma->vm_pgoff + ((addr-vma->vm_start) >> PAGE_SHIFT)
 *
 * And for normal mappings this is false.
 *
 * This restricts such mappings to be a linear translation from virtual address
 * to pfn. To get around this restriction, we allow arbitrary mappings so long
 * as the vma is not a COW mapping; in that case, we know that all ptes are
 * special (because none can have been COWed).
 *
 *
 * In order to support COW of arbitrary special mappings, we have VM_MIXEDMAP.
 *
 * VM_MIXEDMAP mappings can likewise contain memory with or without "struct
 * page" backing, however the difference is that _all_ pages with a struct
 * page (that is, those where pfn_valid is true) are refcounted and considered
 * normal pages by the VM. The disadvantage is that pages are refcounted
 * (which can be slower and simply not an option for some PFNMAP users). The
 * advantage is that we don't have to follow the strict linearity rule of
 * PFNMAP mappings in order to support COWable mappings.
 *
 * 对于正常映射,这是错误的.
 *
 * 这将这种映射限制为从虚拟地址到pfn的线性转换.为了绕过这个限制,我们允许任意映射,只要vma不是COW映射;
 * 在这种情况下,我们知道所有的ptes都是special(因为没有一个可能是COWed).
 *
 * 为了支持任意特殊映射的COW,我们有VM_MIXEDMAP.
 *
 * VM_MIXEDMAP映射同样可以包含带有或不带有“struct page”的内存.
 * 然而不同的是带有struct page 的_all_ pages(即pfn_valid为true的那些页)被VM重新计数并视为normal page.
 * 缺点是页面被重新计数(这可能会更慢,而且对于一些PFNMAP用户来说根本不是一个选项).
 * 优点是我们不必遵循PFNMAP映射的严格线性规则来支持COWable映射.
 *
 */

/* vm_normal_page函数是一个很有意思的函数,它返回normal mapping页面的struct page数据结构,
 * 一些特殊映射的页面是不会返回struct page数据结构的,这些页面不需要被参与到内存管理的一些活动中,
 * 例如页面回收、页迁移和KSM等.
 * HAVE_PTE_SPECIAL宏利用PTE页表项的空闲比特位来做一些有意义的事情,在ARM32架构的3级页表和ARM64的代码中会用到这个特性,
 * 而ARM32架构的2级页表里没有实现这个特性.
 * 在ARM64中,定义了PTE_SPECIAL比特位,注意这是利用硬件上的空闲比特位来定义
 *
 * 内核通常使用pte_mkspecial宏来设置PTE_SPECIAL软件定义的比特位,主要有以下用途.
 * 1、内核的零页面zero page.
 * 2、大量的驱动程序使用remap_pfn_range()函数来实现映射内核页面到用户空间.这些用户程序使用的VMA通常设置了(VM_IO | VM_PFNMAP | VM_DONTEXPAND | VM_DONTDUMP)属性.
 * 3、vm_insert_page/vm_insert_pfn映射内核到用户空间
 *
 * vm_normal_page函数把page页面分为两个阵营,一个是normal page,另外一个是special page.
 * (1) normal page通常指正常mapping的页面,例如匿名页面、page cache和共享内存页面等
 * (2) special page通常指不正常mapping的页面,这些页面不希望参与内存管理的回收或者合并的功能,例如映射如下特性页面.
 *	1、VM_IO: 为I/O设备映射内存.
 *	2、VM_PFN_MAP: 纯PFN映射
 *	3、VM_MIXEDMAP: 固定映射
 */
#ifdef __HAVE_ARCH_PTE_SPECIAL
# define HAVE_PTE_SPECIAL 1
#else
# define HAVE_PTE_SPECIAL 0
#endif
struct page *vm_normal_page(struct vm_area_struct *vma, unsigned long addr,
				pte_t pte)
{
	unsigned long pfn = pte_pfn(pte);

	/* 处理定义了HAVE_PTE_SPECIAL的情况 */
	if (HAVE_PTE_SPECIAL) {
		/* 如果pte的PTE_SOECIAL比特位没有置位,那么跳转到check_pfn继续检查 */
		if (likely(!pte_special(pte)))
			goto check_pfn;
		/* 如果vma有操作符且定义了find_special_page函数指针,那么调用这个函数继续检查 */
		if (vma->vm_ops && vma->vm_ops->find_special_page)
			return vma->vm_ops->find_special_page(vma, addr);
		/* 如果vm_flags设置了(VM_PFNMAP | VM_MIXEDMAP),那么这是special mapping,返回NULL */
		if (vma->vm_flags & (VM_PFNMAP | VM_MIXEDMAP))
			return NULL;
		/* 如果不是内核的zero page,那么输出bad_pte之后返回NULL */
		if (!is_zero_pfn(pfn))
			print_bad_pte(vma, addr, pte, NULL);
		return NULL;
	}

	/* !HAVE_PTE_SPECIAL case follows: */

	/* 如果没有定义HAVE_PTE_SPECIAL */
	/* 下面是检查VM_PFNMAP | VM_MIXEDMAP的情况 */
	if (unlikely(vma->vm_flags & (VM_PFNMAP|VM_MIXEDMAP))) {
		if (vma->vm_flags & VM_MIXEDMAP) {
			/* 如果pfn不是有效的,那么返回NULL */
			if (!pfn_valid(pfn))
				return NULL;
			/* 否则 goto out */
			goto out;
		} else {
			/* 这里就是VM_PFNMAP的情况
			 * remap_pfn_range函数通常使用VM_PFNMAP比特位且vm_pgoff指向第一个PFN映射,所以我们可以使用如下公式来判断这种情况的special mapping
			 * pfn_of_page == vma->vm_pgoff + (addr - vma->vm_start) >> PAGE_SHIFT */
			unsigned long off;
			off = (addr - vma->vm_start) >> PAGE_SHIFT;
			if (pfn == vma->vm_pgoff + off)
				return NULL;
			/* 如果映射是COW mapping(写时复制映射),那么页面也是normal 映射 */
			if (!is_cow_mapping(vma->vm_flags))
				return NULL;
		}
	}

	/* 如果是zero page,那么也返回NULL */
	if (is_zero_pfn(pfn))
		return NULL;
check_pfn:
	/* 如果pfn大于high memory的地址范围,则返回NULL */
	if (unlikely(pfn > highest_memmap_pfn)) {
		print_bad_pte(vma, addr, pte, NULL);
		return NULL;
	}

	/*
	 * NOTE! We still have PageReserved() pages in the page tables.
	 * eg. VDSO mappings can cause them to exist.
	 */
out:
	/* 最后通过 pfn_to_page返回struct page数据结构实例 */
	return pfn_to_page(pfn);
}

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
struct page *vm_normal_page_pmd(struct vm_area_struct *vma, unsigned long addr,
				pmd_t pmd)
{
	unsigned long pfn = pmd_pfn(pmd);

	/*
	 * There is no pmd_special() but there may be special pmds, e.g.
	 * in a direct-access (dax) mapping, so let's just replicate the
	 * !HAVE_PTE_SPECIAL case from vm_normal_page() here.
	 */
	if (unlikely(vma->vm_flags & (VM_PFNMAP|VM_MIXEDMAP))) {
		if (vma->vm_flags & VM_MIXEDMAP) {
			if (!pfn_valid(pfn))
				return NULL;
			goto out;
		} else {
			unsigned long off;
			off = (addr - vma->vm_start) >> PAGE_SHIFT;
			if (pfn == vma->vm_pgoff + off)
				return NULL;
			if (!is_cow_mapping(vma->vm_flags))
				return NULL;
		}
	}

	if (is_zero_pfn(pfn))
		return NULL;
	if (unlikely(pfn > highest_memmap_pfn))
		return NULL;

	/*
	 * NOTE! We still have PageReserved() pages in the page tables.
	 * eg. VDSO mappings can cause them to exist.
	 */
out:
	return pfn_to_page(pfn);
}
#endif

/*
 * copy one vm_area from one task to the other. Assumes the page tables
 * already present in the new task to be cleared in the whole range
 * covered by this vma.
 *
 * 将一个vma_area从一个task复制到另一个task.
 * 假设在该vma覆盖的整个范围内,要清除的新任务中已经存在的页表。
 */

static inline unsigned long
copy_one_pte(struct mm_struct *dst_mm, struct mm_struct *src_mm,
		pte_t *dst_pte, pte_t *src_pte, struct vm_area_struct *vma,
		unsigned long addr, int *rss)
{
	unsigned long vm_flags = vma->vm_flags;
	pte_t pte = *src_pte;
	struct page *page;

	/* pte contains position in swap or file, so copy. */
	/* 首先判断父进程pte对应的页面是否在内存中(pte_present(pte)).
	 * 如果不在内存中,那么有两种可能,这是一个swap entry或者迁移entry(migration entry).
	 * 这两种情况要设置父进程pte页表项内容到子进程中,因此跳转到out_set_pte标签处
	 */
	if (unlikely(!pte_present(pte))) {
		swp_entry_t entry = pte_to_swp_entry(pte);

		if (likely(!non_swap_entry(entry))) {
			if (swap_duplicate(entry) < 0)
				return entry.val;

			/* make sure dst_mm is on swapoff's mmlist. */
			if (unlikely(list_empty(&dst_mm->mmlist))) {
				spin_lock(&mmlist_lock);
				if (list_empty(&dst_mm->mmlist))
					list_add(&dst_mm->mmlist,
							&src_mm->mmlist);
				spin_unlock(&mmlist_lock);
			}
			rss[MM_SWAPENTS]++;
		} else if (is_migration_entry(entry)) {
			page = migration_entry_to_page(entry);

			rss[mm_counter(page)]++;

			if (is_write_migration_entry(entry) &&
					is_cow_mapping(vm_flags)) {
				/*
				 * COW mappings require pages in both
				 * parent and child to be set to read.
				 */
				make_migration_entry_read(&entry);
				pte = swp_entry_to_pte(entry);
				if (pte_swp_soft_dirty(*src_pte))
					pte = pte_swp_mksoft_dirty(pte);
				set_pte_at(src_mm, addr, src_pte, pte);
			}
		}
		goto out_set_pte;
	}

	/*
	 * If it's a COW mapping, write protect it both
	 * in the parent and the child
	 */
	/* 如果父进程VMA属性是一个写时复制映射,即不是共享的进程地址空间(没有设置VM_SHARED),那么父进程和子进程对应的pte页表都要设置成写保护.
	 * pte_wrprotect()函数设置pte为只读属性.
	 */
	if (is_cow_mapping(vm_flags)) {
		ptep_set_wrprotect(src_mm, addr, src_pte);
		pte = pte_wrprotect(pte);
	}

	/*
	 * If it's a shared mapping, mark it clean in
	 * the child
	 */
	 /* 如果VMA对应属性是共享(VM_SHARED)的,那么调用pte_mkclean函数清除pte页表项的DIRTY标志位 */
	if (vm_flags & VM_SHARED)
		pte = pte_mkclean(pte);
	/* pte_mkold函数清除pte页表项中的L_PTE_YOUNG比特位 */
	pte = pte_mkold(pte);

	/* 由父进程pte通过vm_normal_page函数找到相应页面的struct page数据结构,
	 * 注意返回的页面是normal mapping的.
	 * 这里主要增加rss统计计数,并增加该页面的_refcount计数和_mapcout计数
	 * get_page函数增加_refcount计数,page_dup_rmao函数增加_mapcount计数*/
	page = vm_normal_page(vma, addr, pte);
	if (page) {
		get_page(page);
		page_dup_rmap(page, false);
		rss[mm_counter(page)]++;
	}

out_set_pte:
	/* 设置pte到子进程对应的页表项dst_pte中 */
	set_pte_at(dst_mm, addr, dst_pte, pte);
	return 0;
}

/* copy_pte_range函数中的addr和end分别表示VMA对应的起始地址和结束地址,
 * 从VMA起始地址开始到结束地址依次调用copy_one_pte,利用父进程的pte设置到
 * 对应的子进程pte页表中
 */
static int copy_pte_range(struct mm_struct *dst_mm, struct mm_struct *src_mm,
		   pmd_t *dst_pmd, pmd_t *src_pmd, struct vm_area_struct *vma,
		   unsigned long addr, unsigned long end)
{
	pte_t *orig_src_pte, *orig_dst_pte;
	pte_t *src_pte, *dst_pte;
	spinlock_t *src_ptl, *dst_ptl;
	int progress = 0;
	/* rss: 驻留内存大小,是进程当前实际占用的物理内存大小,包括进程独自占用的物理内存、和其他进程共享的内存 */
	int rss[NR_MM_COUNTERS];
	swp_entry_t entry = (swp_entry_t){0};

again:
	/* 初始化rss vec */
	init_rss_vec(rss);

	/* 分配pte 并且上锁 */
	dst_pte = pte_alloc_map_lock(dst_mm, dst_pmd, addr, &dst_ptl);
	if (!dst_pte)
		return -ENOMEM;
	/* 拿到src_pte */
	src_pte = pte_offset_map(src_pmd, addr);
	/* 上锁 */
	src_ptl = pte_lockptr(src_mm, src_pmd);
	spin_lock_nested(src_ptl, SINGLE_DEPTH_NESTING);
	/* 把src_pte赋值给orig_src_pte */
	orig_src_pte = src_pte;
	/* 把dst_pte赋值给orig_dst_pte */
	orig_dst_pte = dst_pte;
	arch_enter_lazy_mmu_mode();

	do {
		/*
		 * We are holding two locks at this point - either of them
		 * could generate latencies in another task on another CPU.
		 *
		 * 在这一点上,我们持有两个锁 - 它们中的任何一个都可能在另一个CPU上的另一个任务中产生延迟.
		 */
		/* 如果progess >=32 */
		if (progress >= 32) {
			/* 把progress设置为0 */
			progress = 0;

			/* 因为如果页表项很多.复制很耗时间,所以如果有进程需要调度,则先跳出循环,去调度
			 * 新进程
			 */
			/* 如果需要调度或者说因为另外一个进程的等待需要跳出spinlock,那么直接break */
			if (need_resched() ||
			    spin_needbreak(src_ptl) || spin_needbreak(dst_ptl))
				break;
		}
		/* 如果src_pte是none的,那么progress + 1之后continue */
		if (pte_none(*src_pte)) {
			/* progress+1,因为此操作耗时短,所以只加一 */
			progress++;
			continue;
		}
		entry.val = copy_one_pte(dst_mm, src_mm, dst_pte, src_pte,
							vma, addr, rss);
		if (entry.val)
			break;
		/* copy_one_pte耗时稍微长,所以progress + 8 */
		progress += 8;
	} while (dst_pte++, src_pte++, addr += PAGE_SIZE, addr != end);

	arch_leave_lazy_mmu_mode();
	/* 解锁 */
	spin_unlock(src_ptl);
	pte_unmap(orig_src_pte);
	/* 将rss更新到对应的mm中 */
	add_mm_rss_vec(dst_mm, rss);
	pte_unmap_unlock(orig_dst_pte, dst_ptl);
	cond_resched();

	if (entry.val) {
		if (add_swap_count_continuation(entry, GFP_KERNEL) < 0)
			return -ENOMEM;
		progress = 0;
	}
	if (addr != end)
		goto again;
	return 0;
}

static inline int copy_pmd_range(struct mm_struct *dst_mm, struct mm_struct *src_mm,
		pud_t *dst_pud, pud_t *src_pud, struct vm_area_struct *vma,
		unsigned long addr, unsigned long end)
{
	pmd_t *src_pmd, *dst_pmd;
	unsigned long next;
	/* 为dst_pmd分配pmd_alloc,并且填充到pud里面去 */
	dst_pmd = pmd_alloc(dst_mm, dst_pud, addr);
	if (!dst_pmd)
		return -ENOMEM;
	/* 这里轮询pmd */
	src_pmd = pmd_offset(src_pud, addr);
	do {
		next = pmd_addr_end(addr, end);
		if (pmd_trans_huge(*src_pmd) || pmd_devmap(*src_pmd)) {
			int err;
			VM_BUG_ON(next-addr != HPAGE_PMD_SIZE);
			err = copy_huge_pmd(dst_mm, src_mm,
					    dst_pmd, src_pmd, addr, vma);
			if (err == -ENOMEM)
				return -ENOMEM;
			if (!err)
				continue;
			/* fall through */
		}
		if (pmd_none_or_clear_bad(src_pmd))
			continue;
		if (copy_pte_range(dst_mm, src_mm, dst_pmd, src_pmd,
						vma, addr, next))
			return -ENOMEM;
	} while (dst_pmd++, src_pmd++, addr = next, addr != end);
	return 0;
}

static inline int copy_pud_range(struct mm_struct *dst_mm, struct mm_struct *src_mm,
		pgd_t *dst_pgd, pgd_t *src_pgd, struct vm_area_struct *vma,
		unsigned long addr, unsigned long end)
{
	pud_t *src_pud, *dst_pud;
	unsigned long next;

	/* 为dst_pud分配pud_alloc,并且填充到pgd里面去 */
	dst_pud = pud_alloc(dst_mm, dst_pgd, addr);
	/* 分配不到直接返回-ENOMEM */
	if (!dst_pud)
		return -ENOMEM;
	/* 然后进行pud的轮询拷贝 */
	src_pud = pud_offset(src_pgd, addr);
	do {
		next = pud_addr_end(addr, end);
		if (pud_none_or_clear_bad(src_pud))
			continue;
		if (copy_pmd_range(dst_mm, src_mm, dst_pud, src_pud,
						vma, addr, next))
			return -ENOMEM;
	} while (dst_pud++, src_pud++, addr = next, addr != end);
	return 0;
}

int copy_page_range(struct mm_struct *dst_mm, struct mm_struct *src_mm,
		struct vm_area_struct *vma)
{
	pgd_t *src_pgd, *dst_pgd;
	unsigned long next;
	unsigned long addr = vma->vm_start;
	unsigned long end = vma->vm_end;
	unsigned long mmun_start;	/* For mmu_notifiers */
	unsigned long mmun_end;		/* For mmu_notifiers */
	bool is_cow;
	int ret;

	/*
	 * Don't copy ptes where a page fault will fill them correctly.
	 * Fork becomes much lighter when there are big shared or private
	 * readonly mappings. The tradeoff is that copy_page_range is more
	 * efficient than faulting.
	 *
	 * 不要复制page faults会正确填充的pte.
	 * 当存在大的共享或私有只读映射时,Fork会变得更轻.
	 * 折中的办法是copy_page_range比faulting更有效。
	 */

	/* VM_MIXEDMAP表示映射混合使用页帧号和页描述符
	 * VM_PFNMAP表示页帧号(Page Frame Number,PFN)映射,特殊映射不希望关联页描述符,直接使用页帧号,
	 * 可能是因为页描述符不存在,也可能是因为不想使用页描述符.
	 * VM_HUGETLB表示虚拟内存区域使用标准巨型页
	 */
	/* 这里是说如果vma->vm_flags和VM_HUGETLB、VM_PFNMAP、VM_MIXEDMAP不搭边
	 * 或者说vma->anon_vma为空(也就是不是匿名映射)
	 * 那么直接返回0
	 */
	if (!(vma->vm_flags & (VM_HUGETLB | VM_PFNMAP | VM_MIXEDMAP)) &&
			!vma->anon_vma)
		return 0;

	if (is_vm_hugetlb_page(vma))
		return copy_hugetlb_page_range(dst_mm, src_mm, vma);

	if (unlikely(vma->vm_flags & VM_PFNMAP)) {
		/*
		 * We do not free on error cases below as remove_vma
		 * gets called on error from higher level routine
		 *
		 * 我们不排除以下错误情况,因为remove_vma会在更高级别的例程出现错误时被调用
		 */
		ret = track_pfn_copy(vma);
		if (ret)
			return ret;
	}

	/*
	 * We need to invalidate the secondary MMU mappings only when
	 * there could be a permission downgrade on the ptes of the
	 * parent mm. And a permission downgrade will only happen if
	 * is_cow_mapping() returns true.
	 *
	 * 只有当父mm的pte上可能存在权限降级时,我们才需要使辅助MMU映射无效.
	 * 只有当is_cow_mapping()返回true时,权限降级才会发生.
	 */
	is_cow = is_cow_mapping(vma->vm_flags);

	mmun_start = addr;
	mmun_end   = end;
	if (is_cow)
		mmu_notifier_invalidate_range_start(src_mm, mmun_start,
						    mmun_end);

	ret = 0;
	/* 拿到dst_mm的pgd */
	dst_pgd = pgd_offset(dst_mm, addr);
	/* 拿到src_mm的src_pgd */
	src_pgd = pgd_offset(src_mm, addr);
	do {
		/* 拿到这个pgd_t的结束地址 */
		next = pgd_addr_end(addr, end);
		/* 如果这块pgd是none或者说是bad的,那么continue */
		if (pgd_none_or_clear_bad(src_pgd))
			continue;
		/* 下面就是拷贝pud了 */
		if (unlikely(copy_pud_range(dst_mm, src_mm, dst_pgd, src_pgd,
					    vma, addr, next))) {
			ret = -ENOMEM;
			break;
		}
	} while (dst_pgd++, src_pgd++, addr = next, addr != end);

	if (is_cow)
		mmu_notifier_invalidate_range_end(src_mm, mmun_start, mmun_end);
	return ret;
}

static unsigned long zap_pte_range(struct mmu_gather *tlb,
				struct vm_area_struct *vma, pmd_t *pmd,
				unsigned long addr, unsigned long end,
				struct zap_details *details)
{
	struct mm_struct *mm = tlb->mm;
	int force_flush = 0;
	int rss[NR_MM_COUNTERS];
	spinlock_t *ptl;
	pte_t *start_pte;
	pte_t *pte;
	swp_entry_t entry;
	struct page *pending_page = NULL;

again:
	/* 初始化rss数组 */
	init_rss_vec(rss);
	/* 拿到pte的指针 */
	start_pte = pte_offset_map_lock(mm, pmd, addr, &ptl);
	pte = start_pte;
	arch_enter_lazy_mmu_mode();
	do {
		pte_t ptent = *pte;
		/* 如果pte是node，那就下一个吧 */
		if (pte_none(ptent)) {
			continue;
		}
		/* 虚拟页相关的物理页在内存中（如没有被换出到swap) */
		if (pte_present(ptent)) {
			struct page *page;
			/* 获得虚拟页相关的物理页 */
			page = vm_normal_page(vma, addr, ptent);
			if (unlikely(details) && page) {
				/*
				 * unmap_shared_mapping_pages() wants to
				 * invalidate cache without truncating:
				 * unmap shared but keep private pages.
				 */
				if (details->check_mapping &&
				    details->check_mapping != page_rmapping(page))
					continue;
			}
			/* 将页表项清空（即是解除了映射关系），并返回原来的页表项的内容 */
			ptent = ptep_get_and_clear_full(mm, addr, pte,
							tlb->fullmm);
			/* 这就是把地址放到mmu_gather里面 */
			tlb_remove_tlb_entry(tlb, pte, addr);
			if (unlikely(!page))
				continue;
			/* 如果是文件页 */
			if (!PageAnon(page)) {
				/* 是脏页 */
				if (pte_dirty(ptent)) {
					/*
					 * oom_reaper cannot tear down dirty
					 * pages
					 * oom_reaper无法撕下脏页
					 */
					if (unlikely(details && details->ignore_dirty))
						continue;
					force_flush = 1;
					/* 脏标志传递到page结构 */
					set_page_dirty(page);
				}
				/* 如果页表项访问标志置位
				 * VM_SEQ_READ 的设置用来暗示内核，应用程序对这块虚拟内存区域的读取是会采用顺序读的方式进行，
				 * 内核会根据实际情况决定预读后续的内存页数，以便加快下次顺序访问速度.
				 * 则标记页面被访问
				 */
				if (pte_young(ptent) &&
				    likely(!(vma->vm_flags & VM_SEQ_READ)))
					mark_page_accessed(page);
			}
			rss[mm_counter(page)]--;
			/* 移除page的映射 */
			page_remove_rmap(page, false);
			/* 如果mapcount小于0，那么直接输出bad pte */
			if (unlikely(page_mapcount(page) < 0))
				print_bad_pte(vma, addr, ptent, page);
			/* 加入到tlb释放的page数组里面去
			 * 只有tlb->batch_count == MAX_GATHER_BATCH_COUNT
			 * 或者page_size变了，再要么就是没有内存了这里才会返回
			 * true
			 * 将物理页记录到积聚结构中， 如果达到最大值进行批量释放
			 */
			if (unlikely(__tlb_remove_page(tlb, page))) {
				force_flush = 1;
				pending_page = page;
				addr += PAGE_SIZE;
				break;
			}
			continue;
		}
		/* only check swap_entries if explicitly asked for in details */
		/* 只有在details里要求才会检查swap_entries
		 * 所以这里只有details->check_swap_entries为true是才往下走
		 */
		if (unlikely(details && !details->check_swap_entries))
			continue;
		/* 获取我们的swap entry */
		entry = pte_to_swp_entry(ptent);
		/* 如果是传统的swap entry,那么MM_SWAPENTS -- */
		if (!non_swap_entry(entry))
			rss[MM_SWAPENTS]--;
		/* 如果是迁移标记进来的 */
		else if (is_migration_entry(entry)) {
			struct page *page;
			/* 拿到这个迁移过来的page */
			page = migration_entry_to_page(entry);
			/* 将其对应的页面类型 - 1 */
			rss[mm_counter(page)]--;
		}
		/* 删掉swap和对应的cache空间 */
		if (unlikely(!free_swap_and_cache(entry)))
			print_bad_pte(vma, addr, ptent, NULL);
		/* 再清一次？*/
		pte_clear_not_present_full(mm, addr, pte, tlb->fullmm);
	} while (pte++, addr += PAGE_SIZE, addr != end);
	/* 将结果同步到mm的rss里面去 */
	add_mm_rss_vec(mm, rss);
	arch_leave_lazy_mmu_mode();

	/* Do the actual TLB flush before dropping ptl */
	/* 如果说前面的__tlb_remove_page 返回啦false
	 * 那么这里先刷掉TLB
	 */
	if (force_flush)
		tlb_flush_mmu_tlbonly(tlb);
	pte_unmap_unlock(start_pte, ptl);

	/*
	 * If we forced a TLB flush (either due to running out of
	 * batch buffers or because we needed to flush dirty TLB
	 * entries before releasing the ptl), free the batched
	 * memory too. Restart if we didn't do everything.
	 */
	/* 如果我们强制执行TLB刷新（要么是因为批处理缓冲区用完，
	 * 要么是因为我们需要在释放ptl之前刷新脏的TLB条目），
	 * 也要释放批处理内存。如果我们没有做好所有事情，就重新开始
	 */
	if (force_flush) {
		force_flush = 0;
		/* 释放掉我们mmu_gather里面所有的页面 */
		tlb_flush_mmu_free(tlb);
		/* 如果还有pending_page,那么把它放进来 */
		if (pending_page) {
			/* remove the page with new size */
			__tlb_remove_pte_page(tlb, pending_page);
			pending_page = NULL;
		}
		if (addr != end)
			goto again;
	}

	return addr;
}

static inline unsigned long zap_pmd_range(struct mmu_gather *tlb,
				struct vm_area_struct *vma, pud_t *pud,
				unsigned long addr, unsigned long end,
				struct zap_details *details)
{
	pmd_t *pmd;
	unsigned long next;
	/* 拿到PMD项页表项的基地址 */
	pmd = pmd_offset(pud, addr);
	do {
		/* 拿到下一个PMD的地址 */
		next = pmd_addr_end(addr, end);
		/* #define pmd_trans_huge(pmd)	(pmd_val(pmd) && !(pmd_val(pmd) & PMD_TABLE_BIT))
		 * 也就是说pmd这里是块类型的，而不是页表类型的
		 * 块类型是说它描述的是一块非常大的内存，这个页表项里面包含的输出地址就是最终的非常大块连续的物理内存的最终的物理地址，
		 * 比如说2MB，比如说1G大小的物理内存
		 */
		if (pmd_trans_huge(*pmd) || pmd_devmap(*pmd)) {
			/* 这种情况为什么会发生呢，也就是说我addr很调皮，没有在PAGE对齐
			 * 也就是在一个PAGE中间的地址，你只想切断一部分，那我也只好
			 * 把我的大页切成小页吧
			 */
			if (next - addr != HPAGE_PMD_SIZE) {
				/* 如果是匿名页且读写锁没有人占有,那么就报个BUG吧 */
				VM_BUG_ON_VMA(vma_is_anonymous(vma) &&
				    !rwsem_is_locked(&tlb->mm->mmap_sem), vma);
				/* 那就把大页给切成小页吧 */
				/* 注意，切成小页之后并没有返回，而是接着往下走
				 * 也就是说下面再解除映射
				 */
				split_huge_pmd(vma, pmd, addr);
				/* 跑到下面的else if说明我是整个THP,那我就取消映射整个THP吧 */
			} else if (zap_huge_pmd(tlb, vma, pmd, addr))
				goto next;
			/* fall through */
		}
		/*
		 * Here there can be other concurrent MADV_DONTNEED or
		 * trans huge page faults running, and if the pmd is
		 * none or trans huge it can change under us. This is
		 * because MADV_DONTNEED holds the mmap_sem in read
		 * mode.
		 */
		/* 这里可能有其他并发的MADV_DONTNEED或trans huge page faults 运行
		 * 如果pmd为none或trans huge,它可能会在我们的控制下更改。
		 * 这是因为MADV_DONTNED在读取模式下保持mmap_sem
		 */
		if (pmd_none_or_trans_huge_or_clear_bad(pmd))
			goto next;
		next = zap_pte_range(tlb, vma, pmd, addr, next, details);
next:
		cond_resched();
	} while (pmd++, addr = next, addr != end);

	return addr;
}

static inline unsigned long zap_pud_range(struct mmu_gather *tlb,
				struct vm_area_struct *vma, pgd_t *pgd,
				unsigned long addr, unsigned long end,
				struct zap_details *details)
{
	pud_t *pud;
	unsigned long next;
	/* 拿到PUD页表项的基地址 */
	pud = pud_offset(pgd, addr);
	do {
		/* #define pud_addr_end(addr, end)	\
		 * ({	unsigned long __boundary = ((addr) + PUD_SIZE) & PUD_MASK;	\
		 * (__boundary - 1 < (end) - 1)? __boundary: (end);	\
		 * })
		 */
		next = pud_addr_end(addr, end);
		/* 如果pgd没填充东西，或者说是bad，那么直接continue吧 */
		if (pud_none_or_clear_bad(pud))
			continue;
		next = zap_pmd_range(tlb, vma, pud, addr, next, details);
	} while (pud++, addr = next, addr != end);

	return addr;
}

void unmap_page_range(struct mmu_gather *tlb,
			     struct vm_area_struct *vma,
			     unsigned long addr, unsigned long end,
			     struct zap_details *details)
{
	pgd_t *pgd;
	unsigned long next;
	/* 如果地址大于结束地址，那肯定要报bug啦 */
	BUG_ON(addr >= end);
	tlb_start_vma(tlb, vma);
	/* 拿到你这个address的pgd */
	pgd = pgd_offset(vma->vm_mm, addr);
	do {
		/* #define pmd_addr_end(addr, end)	\
		 * ({	unsigned long __boundary = ((addr) + PMD_SIZE) & PMD_MASK;	\
		 * (__boundary - 1 < (end) - 1)? __boundary: (end);		\
		 * })
		 */
		/* 算出下一个pgd的地址 */
		next = pgd_addr_end(addr, end);
		/*  如果pgd没填充东西，或者说是bad，那么直接continue吧 */
		if (pgd_none_or_clear_bad(pgd))
			continue;
		next = zap_pud_range(tlb, vma, pgd, addr, next, details);
	} while (pgd++, addr = next, addr != end);
	tlb_end_vma(tlb, vma);
}


static void unmap_single_vma(struct mmu_gather *tlb,
		struct vm_area_struct *vma, unsigned long start_addr,
		unsigned long end_addr,
		struct zap_details *details)
{
	/* 找到vma->vm_start和start_addr的最大值,避免误伤啊 */
	unsigned long start = max(vma->vm_start, start_addr);
	unsigned long end;
	/* 如果start大于vma->vm_end,那也不用去干了 */
	if (start >= vma->vm_end)
		return;
	/* 然后找到vma->vm_end和end_addr的最小值，也是防止误伤啊 */
	end = min(vma->vm_end, end_addr);
	/* 如果end比vm->start还小，那么也不用干了啊 */
	if (end <= vma->vm_start)
		return;
	/* 处理uprobe ? */
	if (vma->vm_file)
		uprobe_munmap(vma, start, end);
	/* VM_PFNMAP表示页帧号（Page Frame Number, PFN）映射，特殊映射不希望关联页描述符，直接使用页帧号，
	 * 可能是因为页描述符不存在，也可能是因为不想使用页描述符
	 */
	if (unlikely(vma->vm_flags & VM_PFNMAP))
		untrack_pfn(vma, 0, 0);

	if (start != end) {
		if (unlikely(is_vm_hugetlb_page(vma))) {
			/*
			 * It is undesirable to test vma->vm_file as it
			 * should be non-null for valid hugetlb area.
			 * However, vm_file will be NULL in the error
			 * cleanup path of mmap_region. When
			 * hugetlbfs ->mmap method fails,
			 * mmap_region() nullifies vma->vm_file
			 * before calling this function to clean up.
			 * Since no pte has actually been setup, it is
			 * safe to do nothing in this case.
			 */
			if (vma->vm_file) {
				i_mmap_lock_write(vma->vm_file->f_mapping);
				__unmap_hugepage_range_final(tlb, vma, start, end, NULL);
				i_mmap_unlock_write(vma->vm_file->f_mapping);
			}
		} else
			/* 开始unmap了 */
			unmap_page_range(tlb, vma, start, end, details);
	}
}

/**
 * unmap_vmas - unmap a range of memory covered by a list of vma's
 * @tlb: address of the caller's struct mmu_gather
 * @vma: the starting vma
 * @start_addr: virtual address at which to start unmapping
 * @end_addr: virtual address at which to end unmapping
 *
 * Unmap all pages in the vma list.
 *
 * Only addresses between `start' and `end' will be unmapped.
 *
 * The VMA list must be sorted in ascending virtual address order.
 *
 * unmap_vmas() assumes that the caller will flush the whole unmapped address
 * range after unmap_vmas() returns.  So the only responsibility here is to
 * ensure that any thus-far unmapped pages are flushed before unmap_vmas()
 * drops the lock and schedules.
 */
void unmap_vmas(struct mmu_gather *tlb,
		struct vm_area_struct *vma, unsigned long start_addr,
		unsigned long end_addr)
{
	struct mm_struct *mm = vma->vm_mm;

	mmu_notifier_invalidate_range_start(mm, start_addr, end_addr);
	for ( ; vma && vma->vm_start < end_addr; vma = vma->vm_next)
		unmap_single_vma(tlb, vma, start_addr, end_addr, NULL);
	mmu_notifier_invalidate_range_end(mm, start_addr, end_addr);
}

/**
 * zap_page_range - remove user pages in a given range
 * @vma: vm_area_struct holding the applicable pages
 * @start: starting address of pages to zap
 * @size: number of bytes to zap
 * @details: details of shared cache invalidation
 *
 * Caller must protect the VMA list
 */
void zap_page_range(struct vm_area_struct *vma, unsigned long start,
		unsigned long size, struct zap_details *details)
{
	struct mm_struct *mm = vma->vm_mm;
	struct mmu_gather tlb;
	unsigned long end = start + size;
	/* 清掉你CPU里面的各种pagevec的页表,让他们指向该执行的操作*/
	lru_add_drain();
	/* 初始化一个mmu_gather结构体，用于拆解页表 */
	tlb_gather_mmu(&tlb, mm, start, end);
	/* 更新高水位线上的rss，也就是已经占用的物理页页数 */
	update_hiwater_rss(mm);
	/* mmu_notifier_invalidate_range_start/end只是調用MMU notifier鉤子;這些鉤子只存在於TLB失效時可以告訴其他內核代碼.
	 * 設置MMU通知器的唯一地點是
	 * KVM（硬件輔助虛擬化）使用它們處理換頁;它需要知道主機TLB失效以保持虛擬客機MMU與主機同步。
	 * GRU（用於巨型SGI系統中專用硬件的驅動程序）使用MMU通知程序來保持GRU硬件中的映射表與CPU MMU同步。
	 * 但是幾乎任何你稱之爲MMU notifier鉤子的地方，如果內核還沒有爲你做，你也應該調用TLB射擊函數
	 */
	/* 一个vma 一个vma的去拆解 */
	mmu_notifier_invalidate_range_start(mm, start, end);
	for ( ; vma && vma->vm_start < end; vma = vma->vm_next)
		unmap_single_vma(&tlb, vma, start, end, details);
	mmu_notifier_invalidate_range_end(mm, start, end);
	tlb_finish_mmu(&tlb, start, end);
}

/**
 * zap_page_range_single - remove user pages in a given range
 * @vma: vm_area_struct holding the applicable pages
 * @address: starting address of pages to zap
 * @size: number of bytes to zap
 * @details: details of shared cache invalidation
 *
 * The range must fit into one VMA.
 */
/*
 * zap_page_range_single - 删除给定range的user page
 * vma: 持有合适页面的vm_area_struct
 * address：要移除页面起始地址
 * size：要移除的大小（字节为单位）
 * details：shared cache无效的详细信息
 */
static void zap_page_range_single(struct vm_area_struct *vma, unsigned long address,
		unsigned long size, struct zap_details *details)
{
	struct mm_struct *mm = vma->vm_mm;
	struct mmu_gather tlb;
	unsigned long end = address + size;

	lru_add_drain();
	tlb_gather_mmu(&tlb, mm, address, end);
	update_hiwater_rss(mm);
	mmu_notifier_invalidate_range_start(mm, address, end);
	unmap_single_vma(&tlb, vma, address, end, details);
	mmu_notifier_invalidate_range_end(mm, address, end);
	tlb_finish_mmu(&tlb, address, end);
}

/**
 * zap_vma_ptes - remove ptes mapping the vma
 * @vma: vm_area_struct holding ptes to be zapped
 * @address: starting address of pages to zap
 * @size: number of bytes to zap
 *
 * This function only unmaps ptes assigned to VM_PFNMAP vmas.
 *
 * The entire address range must be fully contained within the vma.
 *
 * Returns 0 if successful.
 */
int zap_vma_ptes(struct vm_area_struct *vma, unsigned long address,
		unsigned long size)
{
	if (address < vma->vm_start || address + size > vma->vm_end ||
	    		!(vma->vm_flags & VM_PFNMAP))
		return -1;
	zap_page_range_single(vma, address, size, NULL);
	return 0;
}
EXPORT_SYMBOL_GPL(zap_vma_ptes);

pte_t *__get_locked_pte(struct mm_struct *mm, unsigned long addr,
			spinlock_t **ptl)
{
	pgd_t * pgd = pgd_offset(mm, addr);
	pud_t * pud = pud_alloc(mm, pgd, addr);
	if (pud) {
		pmd_t * pmd = pmd_alloc(mm, pud, addr);
		if (pmd) {
			VM_BUG_ON(pmd_trans_huge(*pmd));
			return pte_alloc_map_lock(mm, pmd, addr, ptl);
		}
	}
	return NULL;
}

/*
 * This is the old fallback for page remapping.
 *
 * For historical reasons, it only allows reserved pages. Only
 * old drivers should use this, and they needed to mark their
 * pages reserved for the old functions anyway.
 */
static int insert_page(struct vm_area_struct *vma, unsigned long addr,
			struct page *page, pgprot_t prot)
{
	struct mm_struct *mm = vma->vm_mm;
	int retval;
	pte_t *pte;
	spinlock_t *ptl;

	retval = -EINVAL;
	if (PageAnon(page))
		goto out;
	retval = -ENOMEM;
	flush_dcache_page(page);
	pte = get_locked_pte(mm, addr, &ptl);
	if (!pte)
		goto out;
	retval = -EBUSY;
	if (!pte_none(*pte))
		goto out_unlock;

	/* Ok, finally just insert the thing.. */
	get_page(page);
	inc_mm_counter_fast(mm, mm_counter_file(page));
	page_add_file_rmap(page, false);
	set_pte_at(mm, addr, pte, mk_pte(page, prot));

	retval = 0;
	pte_unmap_unlock(pte, ptl);
	return retval;
out_unlock:
	pte_unmap_unlock(pte, ptl);
out:
	return retval;
}

/**
 * vm_insert_page - insert single page into user vma
 * @vma: user vma to map to
 * @addr: target user address of this page
 * @page: source kernel page
 *
 * This allows drivers to insert individual pages they've allocated
 * into a user vma.
 *
 * The page has to be a nice clean _individual_ kernel allocation.
 * If you allocate a compound page, you need to have marked it as
 * such (__GFP_COMP), or manually just split the page up yourself
 * (see split_page()).
 *
 * NOTE! Traditionally this was done with "remap_pfn_range()" which
 * took an arbitrary page protection parameter. This doesn't allow
 * that. Your vma protection will have to be set up correctly, which
 * means that if you want a shared writable mapping, you'd better
 * ask for a shared writable mapping!
 *
 * The page does not need to be reserved.
 *
 * Usually this function is called from f_op->mmap() handler
 * under mm->mmap_sem write-lock, so it can change vma->vm_flags.
 * Caller must set VM_MIXEDMAP on vma if it wants to call this
 * function from other places, for example from page-fault handler.
 */
int vm_insert_page(struct vm_area_struct *vma, unsigned long addr,
			struct page *page)
{
	if (addr < vma->vm_start || addr >= vma->vm_end)
		return -EFAULT;
	if (!page_count(page))
		return -EINVAL;
	if (!(vma->vm_flags & VM_MIXEDMAP)) {
		BUG_ON(down_read_trylock(&vma->vm_mm->mmap_sem));
		BUG_ON(vma->vm_flags & VM_PFNMAP);
		vma->vm_flags |= VM_MIXEDMAP;
	}
	return insert_page(vma, addr, page, vma->vm_page_prot);
}
EXPORT_SYMBOL(vm_insert_page);

static int insert_pfn(struct vm_area_struct *vma, unsigned long addr,
			pfn_t pfn, pgprot_t prot)
{
	struct mm_struct *mm = vma->vm_mm;
	int retval;
	pte_t *pte, entry;
	spinlock_t *ptl;

	retval = -ENOMEM;
	pte = get_locked_pte(mm, addr, &ptl);
	if (!pte)
		goto out;
	retval = -EBUSY;
	if (!pte_none(*pte))
		goto out_unlock;

	/* Ok, finally just insert the thing.. */
	if (pfn_t_devmap(pfn))
		entry = pte_mkdevmap(pfn_t_pte(pfn, prot));
	else
		entry = pte_mkspecial(pfn_t_pte(pfn, prot));
	set_pte_at(mm, addr, pte, entry);
	update_mmu_cache(vma, addr, pte); /* XXX: why not for insert_page? */

	retval = 0;
out_unlock:
	pte_unmap_unlock(pte, ptl);
out:
	return retval;
}

/**
 * vm_insert_pfn - insert single pfn into user vma
 * @vma: user vma to map to
 * @addr: target user address of this page
 * @pfn: source kernel pfn
 *
 * Similar to vm_insert_page, this allows drivers to insert individual pages
 * they've allocated into a user vma. Same comments apply.
 *
 * This function should only be called from a vm_ops->fault handler, and
 * in that case the handler should return NULL.
 *
 * vma cannot be a COW mapping.
 *
 * As this is called only for pages that do not currently exist, we
 * do not need to flush old virtual caches or the TLB.
 */
int vm_insert_pfn(struct vm_area_struct *vma, unsigned long addr,
			unsigned long pfn)
{
	return vm_insert_pfn_prot(vma, addr, pfn, vma->vm_page_prot);
}
EXPORT_SYMBOL(vm_insert_pfn);

/**
 * vm_insert_pfn_prot - insert single pfn into user vma with specified pgprot
 * @vma: user vma to map to
 * @addr: target user address of this page
 * @pfn: source kernel pfn
 * @pgprot: pgprot flags for the inserted page
 *
 * This is exactly like vm_insert_pfn, except that it allows drivers to
 * to override pgprot on a per-page basis.
 *
 * This only makes sense for IO mappings, and it makes no sense for
 * cow mappings.  In general, using multiple vmas is preferable;
 * vm_insert_pfn_prot should only be used if using multiple VMAs is
 * impractical.
 */
int vm_insert_pfn_prot(struct vm_area_struct *vma, unsigned long addr,
			unsigned long pfn, pgprot_t pgprot)
{
	int ret;
	/*
	 * Technically, architectures with pte_special can avoid all these
	 * restrictions (same for remap_pfn_range).  However we would like
	 * consistency in testing and feature parity among all, so we should
	 * try to keep these invariants in place for everybody.
	 */
	BUG_ON(!(vma->vm_flags & (VM_PFNMAP|VM_MIXEDMAP)));
	BUG_ON((vma->vm_flags & (VM_PFNMAP|VM_MIXEDMAP)) ==
						(VM_PFNMAP|VM_MIXEDMAP));
	BUG_ON((vma->vm_flags & VM_PFNMAP) && is_cow_mapping(vma->vm_flags));
	BUG_ON((vma->vm_flags & VM_MIXEDMAP) && pfn_valid(pfn));

	if (addr < vma->vm_start || addr >= vma->vm_end)
		return -EFAULT;
	if (track_pfn_insert(vma, &pgprot, __pfn_to_pfn_t(pfn, PFN_DEV)))
		return -EINVAL;

	ret = insert_pfn(vma, addr, __pfn_to_pfn_t(pfn, PFN_DEV), pgprot);

	return ret;
}
EXPORT_SYMBOL(vm_insert_pfn_prot);

int vm_insert_mixed(struct vm_area_struct *vma, unsigned long addr,
			pfn_t pfn)
{
	pgprot_t pgprot = vma->vm_page_prot;

	BUG_ON(!(vma->vm_flags & VM_MIXEDMAP));

	if (addr < vma->vm_start || addr >= vma->vm_end)
		return -EFAULT;
	if (track_pfn_insert(vma, &pgprot, pfn))
		return -EINVAL;

	/*
	 * If we don't have pte special, then we have to use the pfn_valid()
	 * based VM_MIXEDMAP scheme (see vm_normal_page), and thus we *must*
	 * refcount the page if pfn_valid is true (hence insert_page rather
	 * than insert_pfn).  If a zero_pfn were inserted into a VM_MIXEDMAP
	 * without pte special, it would there be refcounted as a normal page.
	 */
	if (!HAVE_PTE_SPECIAL && !pfn_t_devmap(pfn) && pfn_t_valid(pfn)) {
		struct page *page;

		/*
		 * At this point we are committed to insert_page()
		 * regardless of whether the caller specified flags that
		 * result in pfn_t_has_page() == false.
		 */
		page = pfn_to_page(pfn_t_to_pfn(pfn));
		return insert_page(vma, addr, page, pgprot);
	}
	return insert_pfn(vma, addr, pfn, pgprot);
}
EXPORT_SYMBOL(vm_insert_mixed);

/*
 * maps a range of physical memory into the requested pages. the old
 * mappings are removed. any references to nonexistent pages results
 * in null mappings (currently treated as "copy-on-access")
 */
static int remap_pte_range(struct mm_struct *mm, pmd_t *pmd,
			unsigned long addr, unsigned long end,
			unsigned long pfn, pgprot_t prot)
{
	pte_t *pte;
	spinlock_t *ptl;

	pte = pte_alloc_map_lock(mm, pmd, addr, &ptl);
	if (!pte)
		return -ENOMEM;
	arch_enter_lazy_mmu_mode();
	do {
		BUG_ON(!pte_none(*pte));
		set_pte_at(mm, addr, pte, pte_mkspecial(pfn_pte(pfn, prot)));
		pfn++;
	} while (pte++, addr += PAGE_SIZE, addr != end);
	arch_leave_lazy_mmu_mode();
	pte_unmap_unlock(pte - 1, ptl);
	return 0;
}

static inline int remap_pmd_range(struct mm_struct *mm, pud_t *pud,
			unsigned long addr, unsigned long end,
			unsigned long pfn, pgprot_t prot)
{
	pmd_t *pmd;
	unsigned long next;

	pfn -= addr >> PAGE_SHIFT;
	pmd = pmd_alloc(mm, pud, addr);
	if (!pmd)
		return -ENOMEM;
	VM_BUG_ON(pmd_trans_huge(*pmd));
	do {
		next = pmd_addr_end(addr, end);
		if (remap_pte_range(mm, pmd, addr, next,
				pfn + (addr >> PAGE_SHIFT), prot))
			return -ENOMEM;
	} while (pmd++, addr = next, addr != end);
	return 0;
}

static inline int remap_pud_range(struct mm_struct *mm, pgd_t *pgd,
			unsigned long addr, unsigned long end,
			unsigned long pfn, pgprot_t prot)
{
	pud_t *pud;
	unsigned long next;

	pfn -= addr >> PAGE_SHIFT;
	pud = pud_alloc(mm, pgd, addr);
	if (!pud)
		return -ENOMEM;
	do {
		next = pud_addr_end(addr, end);
		if (remap_pmd_range(mm, pud, addr, next,
				pfn + (addr >> PAGE_SHIFT), prot))
			return -ENOMEM;
	} while (pud++, addr = next, addr != end);
	return 0;
}

/**
 * remap_pfn_range - remap kernel memory to userspace
 * @vma: user vma to map to
 * @addr: target user address to start at
 * @pfn: physical address of kernel memory
 * @size: size of map area
 * @prot: page protection flags for this mapping
 *
 *  Note: this is only safe if the mm semaphore is held when called.
 */
int remap_pfn_range(struct vm_area_struct *vma, unsigned long addr,
		    unsigned long pfn, unsigned long size, pgprot_t prot)
{
	pgd_t *pgd;
	unsigned long next;
	unsigned long end = addr + PAGE_ALIGN(size);
	struct mm_struct *mm = vma->vm_mm;
	unsigned long remap_pfn = pfn;
	int err;

	/*
	 * Physically remapped pages are special. Tell the
	 * rest of the world about it:
	 *   VM_IO tells people not to look at these pages
	 *	(accesses can have side effects).
	 *   VM_PFNMAP tells the core MM that the base pages are just
	 *	raw PFN mappings, and do not have a "struct page" associated
	 *	with them.
	 *   VM_DONTEXPAND
	 *      Disable vma merging and expanding with mremap().
	 *   VM_DONTDUMP
	 *      Omit vma from core dump, even when VM_IO turned off.
	 *
	 * There's a horrible special case to handle copy-on-write
	 * behaviour that some programs depend on. We mark the "original"
	 * un-COW'ed pages by matching them up with "vma->vm_pgoff".
	 * See vm_normal_page() for details.
	 */
	if (is_cow_mapping(vma->vm_flags)) {
		if (addr != vma->vm_start || end != vma->vm_end)
			return -EINVAL;
		vma->vm_pgoff = pfn;
	}

	err = track_pfn_remap(vma, &prot, remap_pfn, addr, PAGE_ALIGN(size));
	if (err)
		return -EINVAL;

	vma->vm_flags |= VM_IO | VM_PFNMAP | VM_DONTEXPAND | VM_DONTDUMP;

	BUG_ON(addr >= end);
	pfn -= addr >> PAGE_SHIFT;
	pgd = pgd_offset(mm, addr);
	flush_cache_range(vma, addr, end);
	do {
		next = pgd_addr_end(addr, end);
		err = remap_pud_range(mm, pgd, addr, next,
				pfn + (addr >> PAGE_SHIFT), prot);
		if (err)
			break;
	} while (pgd++, addr = next, addr != end);

	if (err)
		untrack_pfn(vma, remap_pfn, PAGE_ALIGN(size));

	return err;
}
EXPORT_SYMBOL(remap_pfn_range);

/**
 * vm_iomap_memory - remap memory to userspace
 * @vma: user vma to map to
 * @start: start of area
 * @len: size of area
 *
 * This is a simplified io_remap_pfn_range() for common driver use. The
 * driver just needs to give us the physical memory range to be mapped,
 * we'll figure out the rest from the vma information.
 *
 * NOTE! Some drivers might want to tweak vma->vm_page_prot first to get
 * whatever write-combining details or similar.
 */
int vm_iomap_memory(struct vm_area_struct *vma, phys_addr_t start, unsigned long len)
{
	unsigned long vm_len, pfn, pages;

	/* Check that the physical memory area passed in looks valid */
	if (start + len < start)
		return -EINVAL;
	/*
	 * You *really* shouldn't map things that aren't page-aligned,
	 * but we've historically allowed it because IO memory might
	 * just have smaller alignment.
	 */
	len += start & ~PAGE_MASK;
	pfn = start >> PAGE_SHIFT;
	pages = (len + ~PAGE_MASK) >> PAGE_SHIFT;
	if (pfn + pages < pfn)
		return -EINVAL;

	/* We start the mapping 'vm_pgoff' pages into the area */
	if (vma->vm_pgoff > pages)
		return -EINVAL;
	pfn += vma->vm_pgoff;
	pages -= vma->vm_pgoff;

	/* Can we fit all of the mapping? */
	vm_len = vma->vm_end - vma->vm_start;
	if (vm_len >> PAGE_SHIFT > pages)
		return -EINVAL;

	/* Ok, let it rip */
	return io_remap_pfn_range(vma, vma->vm_start, pfn, vm_len, vma->vm_page_prot);
}
EXPORT_SYMBOL(vm_iomap_memory);

static int apply_to_pte_range(struct mm_struct *mm, pmd_t *pmd,
				     unsigned long addr, unsigned long end,
				     pte_fn_t fn, void *data)
{
	pte_t *pte;
	int err;
	pgtable_t token;
	spinlock_t *uninitialized_var(ptl);

	pte = (mm == &init_mm) ?
		pte_alloc_kernel(pmd, addr) :
		pte_alloc_map_lock(mm, pmd, addr, &ptl);
	if (!pte)
		return -ENOMEM;

	BUG_ON(pmd_huge(*pmd));

	arch_enter_lazy_mmu_mode();

	token = pmd_pgtable(*pmd);

	do {
		err = fn(pte++, token, addr, data);
		if (err)
			break;
	} while (addr += PAGE_SIZE, addr != end);

	arch_leave_lazy_mmu_mode();

	if (mm != &init_mm)
		pte_unmap_unlock(pte-1, ptl);
	return err;
}

static int apply_to_pmd_range(struct mm_struct *mm, pud_t *pud,
				     unsigned long addr, unsigned long end,
				     pte_fn_t fn, void *data)
{
	pmd_t *pmd;
	unsigned long next;
	int err;

	BUG_ON(pud_huge(*pud));

	pmd = pmd_alloc(mm, pud, addr);
	if (!pmd)
		return -ENOMEM;
	do {
		next = pmd_addr_end(addr, end);
		err = apply_to_pte_range(mm, pmd, addr, next, fn, data);
		if (err)
			break;
	} while (pmd++, addr = next, addr != end);
	return err;
}

static int apply_to_pud_range(struct mm_struct *mm, pgd_t *pgd,
				     unsigned long addr, unsigned long end,
				     pte_fn_t fn, void *data)
{
	pud_t *pud;
	unsigned long next;
	int err;

	pud = pud_alloc(mm, pgd, addr);
	if (!pud)
		return -ENOMEM;
	do {
		next = pud_addr_end(addr, end);
		err = apply_to_pmd_range(mm, pud, addr, next, fn, data);
		if (err)
			break;
	} while (pud++, addr = next, addr != end);
	return err;
}

/*
 * Scan a region of virtual memory, filling in page tables as necessary
 * and calling a provided function on each leaf page table.
 *
 * 扫描虚拟内存的一个区域,根据需要填写页表,并在每个层页表上调用提供的函数
 */
int apply_to_page_range(struct mm_struct *mm, unsigned long addr,
			unsigned long size, pte_fn_t fn, void *data)
{
	pgd_t *pgd;
	unsigned long next;
	/* 算出结束地址 */
	unsigned long end = addr + size;
	int err;

	/* 如果起始地址大于结束地址,返回-EINVAL */
	if (WARN_ON(addr >= end))
		return -EINVAL;

	pgd = pgd_offset(mm, addr);
	do {
		next = pgd_addr_end(addr, end);
		err = apply_to_pud_range(mm, pgd, addr, next, fn, data);
		if (err)
			break;
	} while (pgd++, addr = next, addr != end);

	return err;
}
EXPORT_SYMBOL_GPL(apply_to_page_range);

/*
 * handle_pte_fault chooses page fault handler according to an entry which was
 * read non-atomically.  Before making any commitment, on those architectures
 * or configurations (e.g. i386 with PAE) which might give a mix of unmatched
 * parts, do_swap_page must check under lock before unmapping the pte and
 * proceeding (but do_wp_page is only called after already making such a check;
 * and do_anonymous_page can safely check later on).
 */
static inline int pte_unmap_same(struct mm_struct *mm, pmd_t *pmd,
				pte_t *page_table, pte_t orig_pte)
{
	int same = 1;
#if defined(CONFIG_SMP) || defined(CONFIG_PREEMPT)
	if (sizeof(pte_t) > sizeof(unsigned long)) {
		spinlock_t *ptl = pte_lockptr(mm, pmd);
		spin_lock(ptl);
		same = pte_same(*page_table, orig_pte);
		spin_unlock(ptl);
	}
#endif
	pte_unmap(page_table);
	return same;
}

static inline void cow_user_page(struct page *dst, struct page *src, unsigned long va, struct vm_area_struct *vma)
{
	debug_dma_assert_idle(src);

	/*
	 * If the source page was a PFN mapping, we don't have
	 * a "struct page" for it. We do a best-effort copy by
	 * just copying from the original user address. If that
	 * fails, we just zero-fill it. Live with it.
	 */
	if (unlikely(!src)) {
		void *kaddr = kmap_atomic(dst);
		void __user *uaddr = (void __user *)(va & PAGE_MASK);

		/*
		 * This really shouldn't fail, because the page is there
		 * in the page tables. But it might just be unreadable,
		 * in which case we just give up and fill the result with
		 * zeroes.
		 */
		if (__copy_from_user_inatomic(kaddr, uaddr, PAGE_SIZE))
			clear_page(kaddr);
		kunmap_atomic(kaddr);
		flush_dcache_page(dst);
	} else
		copy_user_highpage(dst, src, va, vma);
}

static gfp_t __get_fault_gfp_mask(struct vm_area_struct *vma)
{
	struct file *vm_file = vma->vm_file;

	if (vm_file)
		return mapping_gfp_mask(vm_file->f_mapping) | __GFP_FS | __GFP_IO;

	/*
	 * Special mappings (e.g. VDSO) do not have any file so fake
	 * a default GFP_KERNEL for them.
	 */
	return GFP_KERNEL;
}

/*
 * Notify the address space that the page is about to become writable so that
 * it can prohibit this or wait for the page to get into an appropriate state.
 *
 * We do this without the lock held, so that it can sleep if it needs to.
 *
 * 通知地址空间该页即将变为可写,以便它可以禁止此操作或等待该页进入适当的状态.
 *
 * 我们这样做不需要锁,以至于它就可以在需要的时候睡眠
 */
static int do_page_mkwrite(struct vm_area_struct *vma, struct page *page,
	       unsigned long address)
{
	struct vm_fault vmf;
	int ret;

	vmf.virtual_address = (void __user *)(address & PAGE_MASK);
	vmf.pgoff = page->index;
	vmf.flags = FAULT_FLAG_WRITE|FAULT_FLAG_MKWRITE;
	vmf.gfp_mask = __get_fault_gfp_mask(vma);
	vmf.page = page;
	vmf.cow_page = NULL;

	ret = vma->vm_ops->page_mkwrite(vma, &vmf);
	if (unlikely(ret & (VM_FAULT_ERROR | VM_FAULT_NOPAGE)))
		return ret;
	if (unlikely(!(ret & VM_FAULT_LOCKED))) {
		lock_page(page);
		if (!page->mapping) {
			unlock_page(page);
			return 0; /* retry */
		}
		ret |= VM_FAULT_LOCKED;
	} else
		VM_BUG_ON_PAGE(!PageLocked(page), page);
	return ret;
}

/*
 * Handle write page faults for pages that can be reused in the current vma
 *
 * This can happen either due to the mapping being with the VM_SHARED flag,
 * or due to us being the last reference standing to the page. In either
 * case, all we need to do here is to mark the page as writable and update
 * any related book-keeping.
 *
 * 处理可在当前vma中重用的页面的写入页面错误
 *
 * 这可能是由于映射带有VM_SHARED标志,也可能是由于我们是页面的最后一个引用.
 * 无论哪种情况,我们在这里所需要做的就是将页面标记为可写,并更新任何相关的记账.
 */
static inline int wp_page_reuse(struct fault_env *fe, pte_t orig_pte,
			struct page *page, int page_mkwrite, int dirty_shared)
	__releases(fe->ptl)
{
	struct vm_area_struct *vma = fe->vma;
	pte_t entry;
	/*
	 * Clear the pages cpupid information as the existing
	 * information potentially belongs to a now completely
	 * unrelated process.
	 *
	 * 清除页面cpupid信息.因为现有信息可能属于现在完全不相关的进程.
	 */
	if (page)
		page_cpupid_xchg_last(page, (1 << LAST_CPUPID_SHIFT) - 1);

	flush_cache_page(vma, fe->address, pte_pfn(orig_pte));
	/* pte_mkyoung设置pte的访问位,x86处理器是_PAGE_ACCESSED,
	 * ARM32处理器中是Linux版本的页面项中的L_PTE_YOUNG位,
	 * ARM64处理器是PTE_AF.
	 */
	entry = pte_mkyoung(orig_pte);
	/* pte_mkdirty设置pte中的DIRTY位.
	 * maybe_mkwrite根据VMA属性是否具有可写属性来设置pte中的可写标志位,ARM32处理器清空linux版本页表的L_PTE_RDONLY位,ARM64处理器设置PTE_WRITE位 */
	entry = maybe_mkwrite(pte_mkdirty(entry), vma);
	/* ptep_set_access_flags把PTE entry设置到硬件的页表项pte中 */
	if (ptep_set_access_flags(vma, fe->address, fe->pte, entry, 1))
		update_mmu_cache(vma, fe->address, fe->pte);
	pte_unmap_unlock(fe->pte, fe->ptl);

	/* 这里用于处理drity_shared,有如下两种情况不处理页面的DIRTY情况
	 * 1、可写且共享的special mapping页面
	 * 2、最多只有一个进程映射的匿名页面
	 * 因为special mapping的页面不参与系统的回写操作,另外只有一个进程匿名页面也只设置pte的可写标志位
	 */
	if (dirty_shared) {
		struct address_space *mapping;
		int dirtied;

		if (!page_mkwrite)
			lock_page(page);

		/* 设置page的DIRTY状态,然后调用balance_dirty_pages_ratelimited 函数去平衡并回写一部分脏页 */
		dirtied = set_page_dirty(page);
		VM_BUG_ON_PAGE(PageAnon(page), page);
		mapping = page->mapping;
		unlock_page(page);
		put_page(page);

		if ((dirtied || page_mkwrite) && mapping) {
			/*
			 * Some device drivers do not set page.mapping
			 * but still dirty their pages
			 */
			balance_dirty_pages_ratelimited(mapping);
		}

		if (!page_mkwrite)
			file_update_time(vma->vm_file);
	}

	return VM_FAULT_WRITE;
}

/*
 * Handle the case of a page which we actually need to copy to a new page.
 *
 * Called with mmap_sem locked and the old page referenced, but
 * without the ptl held.
 *
 * High level logic flow:
 *
 * - Allocate a page, copy the content of the old page to the new one.
 * - Handle book keeping and accounting - cgroups, mmu-notifiers, etc.
 * - Take the PTL. If the pte changed, bail out and release the allocated page
 * - If the pte is still the way we remember it, update the page table and all
 *   relevant references. This includes dropping the reference the page-table
 *   held to the old page, as well as updating the rmap.
 * - In any case, unlock the PTL and drop the reference we took to the old page.
 *
 * 处理我们实际需要复制到新页面的页面的情况.
 *
 * 在mmap_sem被锁定并且引用了旧页面的情况下调用,但没有拿到ptl的锁
 *
 * 高级逻辑流程:
 *
 * - 分配一个页面,将旧页面的内容复制到新页面。
 * - 处理记账和会计 - cgroups、mmu-notifiers等.
 * - 拿到PTL. 如果pte已更改,请退出并释放分配的页面
 * - 如果pte仍然是我们记忆中的方式,请更新页面表和所有相关引用.这包括删除页面表对旧页面的引用,以及更新rmap.
 * - 在任何情况下,请解锁PTL并将我们释放旧页面到reference
 */
static int wp_page_copy(struct fault_env *fe, pte_t orig_pte,
		struct page *old_page)
{
	struct vm_area_struct *vma = fe->vma;
	struct mm_struct *mm = vma->vm_mm;
	struct page *new_page = NULL;
	pte_t entry;
	int page_copied = 0;
	/* 拿到fault 地址的页面起始地址 */
	const unsigned long mmun_start = fe->address & PAGE_MASK;
	/* 拿到这块page的结束地址 */
	const unsigned long mmun_end = mmun_start + PAGE_SIZE;
	struct mem_cgroup *memcg;

	/* 分配一个anon_vma到相应的vma中 */
	if (unlikely(anon_vma_prepare(vma)))
		goto oom;

	/* 如果pte为系统零页面,调用alloc_zeroed_user_highpage_movable分配一个内容全是0的页面,分配掩码是__GFP_MOVABLE | GFP_HIGHUSER
	 * 也就是优先分配高端内存HIGHMEM
	 */
	if (is_zero_pfn(pte_pfn(orig_pte))) {
		new_page = alloc_zeroed_user_highpage_movable(vma, fe->address);
		if (!new_page)
			goto oom;
	} else { /* 如果不是系统零页面,使用alloc_page_vma来分配一个页面 */
		new_page = alloc_page_vma(GFP_HIGHUSER_MOVABLE, vma,
				fe->address);
		if (!new_page)
			goto oom;
		/* 把old_page页面的内容复制到这个新的页面new_page中 */
		cow_user_page(new_page, old_page, fe->address, vma);
	}

	if (mem_cgroup_try_charge(new_page, mm, GFP_KERNEL, &memcg, false))
		goto oom_free_new;

	/* 设置new_page的PG_uptodate,表示内容有效 */
	__SetPageUptodate(new_page);

	mmu_notifier_invalidate_range_start(mm, mmun_start, mmun_end);

	/*
	 * Re-check the pte - we dropped the lock
	 */
	/* 重新读取pte,并且判断pte的内容是否被修改过.
	 * 如果old_page是文件映射页面,那么需要增加系统匿名页面的计数且减少一个文件映射页面计数,因为刚才新建了一个匿名页面
	 */
	fe->pte = pte_offset_map_lock(mm, fe->pmd, fe->address, &fe->ptl);
	if (likely(pte_same(*fe->pte, orig_pte))) {
		if (old_page) {
			if (!PageAnon(old_page)) {
				dec_mm_counter_fast(mm,
						mm_counter_file(old_page));
				inc_mm_counter_fast(mm, MM_ANONPAGES);
			}
		} else {
			inc_mm_counter_fast(mm, MM_ANONPAGES);
		}
		flush_cache_page(vma, fe->address, pte_pfn(orig_pte));
		/* 利用新建new_page和VMA的属性新生成一个PTE entry */
		entry = mk_pte(new_page, vma->vm_page_prot);
		/* 设置PTE entry的DIRTY和WRITEABLE位 */
		entry = maybe_mkwrite(pte_mkdirty(entry), vma);
		/*
		 * Clear the pte entry and flush it first, before updating the
		 * pte with the new entry. This will avoid a race condition
		 * seen in the presence of one thread doing SMC and another
		 * thread doing COW.
		 */
		ptep_clear_flush_notify(vma, fe->address, fe->pte);
		/* 把new page添加到RMAP反向映射机制,设置新页面的_mapcount计数为0 */
		page_add_new_anon_rmap(new_page, vma, fe->address, false);
		mem_cgroup_commit_charge(new_page, memcg, false, false);
		/* 把new_page添加到活跃LRU链表中 */
		lru_cache_add_active_or_unevictable(new_page, vma);
		/*
		 * We call the notify macro here because, when using secondary
		 * mmu page tables (such as kvm shadow page tables), we want the
		 * new page to be mapped directly into the secondary page table.
		 */
		/* 把新建的pte entry设置到硬件页表项中 */
		set_pte_at_notify(mm, fe->address, fe->pte, entry);
		update_mmu_cache(vma, fe->address, fe->pte);
		if (old_page) {
			/*
			 * Only after switching the pte to the new page may
			 * we remove the mapcount here. Otherwise another
			 * process may come and find the rmap count decremented
			 * before the pte is switched to the new page, and
			 * "reuse" the old page writing into it while our pte
			 * here still points into it and can be read by other
			 * threads.
			 *
			 * The critical issue is to order this
			 * page_remove_rmap with the ptp_clear_flush above.
			 * Those stores are ordered by (if nothing else,)
			 * the barrier present in the atomic_add_negative
			 * in page_remove_rmap.
			 *
			 * Then the TLB flush in ptep_clear_flush ensures that
			 * no process can access the old page before the
			 * decremented mapcount is visible. And the old page
			 * cannot be reused until after the decremented
			 * mapcount is visible. So transitively, TLBs to
			 * old page will be flushed before it can be reused.
			 */
			page_remove_rmap(old_page, false);
		}

		/* Free the old page.. */
		new_page = old_page;
		page_copied = 1;
	} else {
		mem_cgroup_cancel_charge(new_page, memcg, false);
	}

	if (new_page)
		put_page(new_page);

	pte_unmap_unlock(fe->pte, fe->ptl);
	mmu_notifier_invalidate_range_end(mm, mmun_start, mmun_end);
	if (old_page) {
		/*
		 * Don't let another task, with possibly unlocked vma,
		 * keep the mlocked page.
		 */
		if (page_copied && (vma->vm_flags & VM_LOCKED)) {
			lock_page(old_page);	/* LRU manipulation */
			if (PageMlocked(old_page))
				munlock_vma_page(old_page);
			unlock_page(old_page);
		}
		put_page(old_page);
	}
	return page_copied ? VM_FAULT_WRITE : 0;
oom_free_new:
	put_page(new_page);
oom:
	if (old_page)
		put_page(old_page);
	return VM_FAULT_OOM;
}

/*
 * Handle write page faults for VM_MIXEDMAP or VM_PFNMAP for a VM_SHARED
 * mapping
 */
static int wp_pfn_shared(struct fault_env *fe,  pte_t orig_pte)
{
	struct vm_area_struct *vma = fe->vma;

	if (vma->vm_ops && vma->vm_ops->pfn_mkwrite) {
		struct vm_fault vmf = {
			.page = NULL,
			.pgoff = linear_page_index(vma, fe->address),
			.virtual_address =
				(void __user *)(fe->address & PAGE_MASK),
			.flags = FAULT_FLAG_WRITE | FAULT_FLAG_MKWRITE,
		};
		int ret;

		pte_unmap_unlock(fe->pte, fe->ptl);
		ret = vma->vm_ops->pfn_mkwrite(vma, &vmf);
		if (ret & VM_FAULT_ERROR)
			return ret;
		fe->pte = pte_offset_map_lock(vma->vm_mm, fe->pmd, fe->address,
				&fe->ptl);
		/*
		 * We might have raced with another page fault while we
		 * released the pte_offset_map_lock.
		 */
		if (!pte_same(*fe->pte, orig_pte)) {
			pte_unmap_unlock(fe->pte, fe->ptl);
			return 0;
		}
	}
	return wp_page_reuse(fe, orig_pte, NULL, 0, 0);
}

static int wp_page_shared(struct fault_env *fe, pte_t orig_pte,
		struct page *old_page)
	__releases(fe->ptl)
{
	struct vm_area_struct *vma = fe->vma;
	int page_mkwrite = 0;

	get_page(old_page);

	/* 如果vma的操作函数定义了page_mkwrite指针,那么调用do_page_mkwrite函数. page_mkwrite函数用于通知之前只读页面现在要变成可写页面了 */
	if (vma->vm_ops && vma->vm_ops->page_mkwrite) {
		int tmp;

		pte_unmap_unlock(fe->pte, fe->ptl);
		tmp = do_page_mkwrite(vma, old_page, fe->address);
		if (unlikely(!tmp || (tmp &
				      (VM_FAULT_ERROR | VM_FAULT_NOPAGE)))) {
			put_page(old_page);
			return tmp;
		}
		/*
		 * Since we dropped the lock we need to revalidate
		 * the PTE as someone else may have changed it.  If
		 * they did, we just return, as we can count on the
		 * MMU to tell us if they didn't also make it writable.
		 */
		fe->pte = pte_offset_map_lock(vma->vm_mm, fe->pmd, fe->address,
						 &fe->ptl);
		if (!pte_same(*fe->pte, orig_pte)) {
			unlock_page(old_page);
			pte_unmap_unlock(fe->pte, fe->ptl);
			put_page(old_page);
			return 0;
		}
		page_mkwrite = 1;
	}

	return wp_page_reuse(fe, orig_pte, old_page, page_mkwrite, 1);
}

/*
 * This routine handles present pages, when users try to write
 * to a shared page. It is done by copying the page to a new address
 * and decrementing the shared-page counter for the old page.
 *
 * Note that this routine assumes that the protection checks have been
 * done by the caller (the low-level page fault routine in most cases).
 * Thus we can safely just mark it writable once we've done any necessary
 * COW.
 *
 * We also mark the page dirty at this point even though the page will
 * change only once the write actually happens. This avoids a few races,
 * and potentially makes it more efficient.
 *
 * We enter with non-exclusive mmap_sem (to exclude vma changes,
 * but allow concurrent faults), with pte both mapped and locked.
 * We return with mmap_sem still held, but pte unmapped and unlocked.
 *
 * 当用户试图写入共享页面时,此例程处理present页面.
 * 这是通过将页面复制到新地址并递减旧页面的共享页面计数器来完成的.
 *
 * 请注意,此例程假定protection检查已由调用方完成(在大多数情况下为low-level 页面故障例程).
 * 因此,一旦我们完成了任何必要的COW,我们就可以安全地将其标记为可写.
 *
 * 在这一点上,我们还将页面标记为脏的,即使只有在实际写入时页面才会更改.这避免了竞争,潜在地提高效率.
 *
 * 我们以非独占的mmap_sem进入(以排除vma更改,但允许并发fault),pte同时映射和锁定.
 * 我们带着mmap_sem返回,但pte未映射并解锁。
 */
static int do_wp_page(struct fault_env *fe, pte_t orig_pte)
	__releases(fe->ptl)
{
	struct vm_area_struct *vma = fe->vma;
	struct page *old_page;
	/* 首先通过vm_normal_page函数查找缺页异常地址addr对应的struct page数据结构,返回normal mapping页面. */
	old_page = vm_normal_page(vma, fe->address, orig_pte);
	/* 如果vm_normal_page函数返回page指针为NULL,说明这是个special mapping的页面 */
	if (!old_page) {
		/*
		 * VM_MIXEDMAP !pfn_valid() case, or VM_SOFTDIRTY clear on a
		 * VM_PFNMAP VMA.
		 *
		 * We should not cow pages in a shared writeable mapping.
		 * Just mark the pages writable and/or call ops->pfn_mkwrite.
		 *
		 * VM_MIXEDMAP !pfn_valid()情况,或者VM_SOFTDIRTY在一个VM_PFMMAP VMA中清除
		 *
		 * 我们不应该在共享的可写映射中cow page.
		 * 只需将页面标记为可写 and/or 调用ops->pfn_mkwrite.
		 */
		if ((vma->vm_flags & (VM_WRITE|VM_SHARED)) ==
				     (VM_WRITE|VM_SHARED))
			return wp_pfn_shared(fe, orig_pte);

		pte_unmap_unlock(fe->pte, fe->ptl);
		return wp_page_copy(fe, orig_pte, old_page);
	}

	/*
	 * Take out anonymous pages first, anonymous shared vmas are
	 * not dirty accountable.
	 *
	 * 先去掉匿名页面,匿名共享的vma不会被追究责任.
	 */

	/* 判断当前页面是否为不属于KSM的匿名页面.
	 * 利用page->mapping成员的最低2个比特位来判断匿名页面使用PageAnon宏*/
	if (PageAnon(old_page) && !PageKsm(old_page)) {
		int total_mapcount;
		/* trylock_page(old_page)函数判断当前old_page是否已经加锁,
		 * trylock_pages返回false,说明这个页面已经被别的进程加锁,所以下面会使用lock_page等待其他进程释放了锁才有机会获取锁
		 */
		if (!trylock_page(old_page)) {
			/* page->_refcount +1 */
			get_page(old_page);
			/*
			 * #define pte_unmap_unlock(pte, ptl)	do {		\
			 * spin_unlock(ptl);				\
			 * pte_unmap(pte);					\
			 * } while (0)
			 */
			pte_unmap_unlock(fe->pte, fe->ptl);
			/* 等old_page的锁直到获取到该锁 */
			lock_page(old_page);
			/* 拿到pte,并且锁上fe->ptl */
			fe->pte = pte_offset_map_lock(vma->vm_mm, fe->pmd,
					fe->address, &fe->ptl);
			/* 然后判断PTE是否发生变化,若发生变化,就退出异常处理 */
			if (!pte_same(*fe->pte, orig_pte)) {
				unlock_page(old_page);
				pte_unmap_unlock(fe->pte, fe->ptl);
				put_page(old_page);
				return 0;
			}
			put_page(old_page);
		}
		/* reuse_swap_page函数判断old_page页面是否只有一个进程映射匿名页面.
		 * 如果只是单独映射,那么可以继续使用这个页面并且不需要写时复制
		 */
		if (reuse_swap_page(old_page, &total_mapcount)) {
			if (total_mapcount == 1) {
				/*
				 * The page is all ours. Move it to
				 * our anon_vma so the rmap code will
				 * not search our parent or siblings.
				 * Protected against the rmap code by
				 * the page lock.
				 *
				 * 这一页都是我们的.
				 * 将它移到我们的anon_vma中,这样rmap代码就不会搜索我们的parent或siblings.
				 * 通过页面锁定防止rmap代码.
				 */
				/* 这里就是让page->mapping指向我们的(void *) vma->anon_vma + PAGE_MAPPING_ANON */
				page_move_anon_rmap(old_page, vma);
			}
			unlock_page(old_page);
			return wp_page_reuse(fe, orig_pte, old_page, 0, 0);
		}
		unlock_page(old_page);
		/* 到了这个位置,我们可以考虑的页面只剩下page cache页面和KSM页面了,这里处理可写且可共享的上述两种页面 */
	} else if (unlikely((vma->vm_flags & (VM_WRITE|VM_SHARED)) ==
					(VM_WRITE|VM_SHARED))) {
		return wp_page_shared(fe, orig_pte, old_page);
	}

	/*
	 * Ok, we need to copy. Oh, well..
	 */
	get_page(old_page);

	pte_unmap_unlock(fe->pte, fe->ptl);
	return wp_page_copy(fe, orig_pte, old_page);
}

static void unmap_mapping_range_vma(struct vm_area_struct *vma,
		unsigned long start_addr, unsigned long end_addr,
		struct zap_details *details)
{
	zap_page_range_single(vma, start_addr, end_addr - start_addr, details);
}

static inline void unmap_mapping_range_tree(struct rb_root *root,
					    struct zap_details *details)
{
	struct vm_area_struct *vma;
	pgoff_t vba, vea, zba, zea;

	vma_interval_tree_foreach(vma, root,
			details->first_index, details->last_index) {
		/* vm_pgoff 指向文件映射的偏移量，这个变量的单位不是Byte,而是页面的大小(PAGE_SIZE)
		 * 这里就是得到这块vma的文件映射偏移量
		 */
		vba = vma->vm_pgoff;
		/* 得到这块vma结束的偏移量
		 * static inline unsigned long vma_pages(struct vm_area_struct *vma)
		 * {
		 *	return (vma->vm_end - vma->vm_start) >> PAGE_SHIFT;
		 * }
		 */
		vea = vba + vma_pages(vma) - 1;
		/* 拿到details的first_index，也就是我们要unmap的起始index */
		zba = details->first_index;
		/* 如果需要unmap的起始index小于vma的起始index,说明我有部分区域不在
		 * 你这范围内，你帮我unmap掉在你区域内的好了
		 * 那么就把你这vma的起始index给我好了
		 */
		if (zba < vba)
			zba = vba;
		/* 如果需要unmap的结束index大于vma的结束index,说明我有部分区域不在
		 * 你这范围内，你帮我unmap掉在你区域内的好了
		 * 那么就把你这vma的结束index给我好了
		 */
		zea = details->last_index;
		if (zea > vea)
			zea = vea;
		/* zba - vba 得到开始的page_index，然后加上vma->vm_start就得到了起始地址
		 * zea- vba + 1得到的是结束的index,然后加上vma->vm_start就得到了结束的地址
		 */
		unmap_mapping_range_vma(vma,
			((zba - vba) << PAGE_SHIFT) + vma->vm_start,
			((zea - vba + 1) << PAGE_SHIFT) + vma->vm_start,
				details);
	}
}

/**
 * unmap_mapping_range - unmap the portion of all mmaps in the specified
 * address_space corresponding to the specified page range in the underlying
 * file.
 *
 * @mapping: the address space containing mmaps to be unmapped.
 * @holebegin: byte in first page to unmap, relative to the start of
 * the underlying file.  This will be rounded down to a PAGE_SIZE
 * boundary.  Note that this is different from truncate_pagecache(), which
 * must keep the partial page.  In contrast, we must get rid of
 * partial pages.
 * @holelen: size of prospective hole in bytes.  This will be rounded
 * up to a PAGE_SIZE boundary.  A holelen of zero truncates to the
 * end of the file.
 * @even_cows: 1 when truncating a file, unmap even private COWed pages;
 * but 0 when invalidating pagecache, don't throw away private data.
 */
/* unmap_mapping_range- unmap 指定底层文件相应的page range的address_space
 * 所有的mmaps
 *
 * @mapping：包含要取消映射的mmap的地址空间
 * holebegin：相对于底层的开头,第一个page要umap的字节数。
 * 这将PAGE_SIZE向下取整。
 * 请注意，这与truncate_pagecache（）不同，后者必须保留部分页面。
 * 相比之下，我们必须去掉部分页面.
 *
 * holelen：以字节为单位的预期hole的大小。这将PAGE_SIZE向下取整.
 * 0的holelen将截断到文件末尾
 *
 * 当截断文件是，如果是1，甚至unmap私有的COWed的page
 * 如果为0，当pagecache无效时，不要丢弃private data
 */
void unmap_mapping_range(struct address_space *mapping,
		loff_t const holebegin, loff_t const holelen, int even_cows)
{
	struct zap_details details = { };
	/* 算出holebegin相对于page的偏移  */
	pgoff_t hba = holebegin >> PAGE_SHIFT;
	/* 算出以PAGE大小为单位的长度 */
	pgoff_t hlen = (holelen + PAGE_SIZE - 1) >> PAGE_SHIFT;

	/* Check for overflow. */
	if (sizeof(holelen) > sizeof(hlen)) {
		long long holeend =
			(holebegin + holelen + PAGE_SIZE - 1) >> PAGE_SHIFT;
		if (holeend & ~(long long)ULONG_MAX)
			hlen = ULONG_MAX - hba + 1;
	}
	/* 如果even_cows为1，那么check_mapping就赋值为NULL
	 * 如果为0时，那么为我们带进来的mapping
	 */
	details.check_mapping = even_cows? NULL: mapping;
	details.first_index = hba;
	details.last_index = hba + hlen - 1;
	/* 如果最后一个last_index小于details.first_index
	 * 也就是说如果为0，那么就一直清除到文件结尾 */
	if (details.last_index < details.first_index)
		details.last_index = ULONG_MAX;

	i_mmap_lock_write(mapping);
	if (unlikely(!RB_EMPTY_ROOT(&mapping->i_mmap)))
		unmap_mapping_range_tree(&mapping->i_mmap, &details);
	i_mmap_unlock_write(mapping);
}
EXPORT_SYMBOL(unmap_mapping_range);

/*
 * We enter with non-exclusive mmap_sem (to exclude vma changes,
 * but allow concurrent faults), and pte mapped but not yet locked.
 * We return with pte unmapped and unlocked.
 *
 * We return with the mmap_sem locked or unlocked in the same cases
 * as does filemap_fault().
 */
int do_swap_page(struct fault_env *fe, pte_t orig_pte)
{
	struct vm_area_struct *vma = fe->vma;
	struct page *page, *swapcache;
	struct mem_cgroup *memcg;
	swp_entry_t entry;
	pte_t pte;
	int locked;
	int exclusive = 0;
	int ret = 0;

	/* 这里就是判断fe->pte和orig_pte是否相等,如果不相等那么直接goto out */
	if (!pte_unmap_same(vma->vm_mm, fe->pmd, fe->pte, orig_pte))
		goto out;

	/* 通过pte找到swp_entry_t */
	entry = pte_to_swp_entry(orig_pte);
	/* 如果不是swap_entry */
	if (unlikely(non_swap_entry(entry))) {
		/* 如果是迁移的entry */
		if (is_migration_entry(entry)) {
			/* 等待迁移完成 */
			migration_entry_wait(vma->vm_mm, fe->pmd, fe->address);
			/* 如果是hardware poisoned pages,那么ret = VM_FAULT_HWPOISON */
		} else if (is_hwpoison_entry(entry)) {
			ret = VM_FAULT_HWPOISON;
		} else {
			/* 否则输出坏页 */
			print_bad_pte(vma, fe->address, orig_pte, NULL);
			ret = VM_FAULT_SIGBUS;
		}
		goto out;
	}
	/*
	 * if (current->delays)
	 *	current->delays->flags |= flag;
	 */
	delayacct_set_flag(DELAYACCT_PF_SWAPIN);
	/* 在swap cache中查找swap entry,这里不会带FGP_CREAT,也就是说找到了就找到了,没找到就没找到 */
	page = lookup_swap_cache(entry);
	if (!page) {
		/* 这里就是swapin的预读 */
		page = swapin_readahead(entry,
					GFP_HIGHUSER_MOVABLE, vma, fe->address);
		/* 如果page为NULL */
		if (!page) {
			/*
			 * Back out if somebody else faulted in this pte
			 * while we released the pte lock.
			 *
			 * 在我们释放页表项(PTE)锁的过程中,如果其他人因为fault而在这个页表项中进行了操作,则回退(取消更改)
			 */

			/* 拿到pte */
			fe->pte = pte_offset_map_lock(vma->vm_mm, fe->pmd,
					fe->address, &fe->ptl);
			/* 如果pte还是一样的,那么就说明可能是没有内存了 */
			if (likely(pte_same(*fe->pte, orig_pte)))
				ret = VM_FAULT_OOM;
			/* 如果pte被更改了,那么就清除DELAYACCT_PF_SWAPIN flag */
			delayacct_clear_flag(DELAYACCT_PF_SWAPIN);
			goto unlock;
		}

		/* Had to read the page from swap area: Major fault */
		/* 必须从交换区域读取页面: 主要错误(或称为大页错误)
		 *
		 * 在Linux系统中,当物理内存(RAM)不足以满足当前运行的程序需求时,系统会将部分内存页(pages)的内容交换(swap)到磁盘上的交换空间(swap space)中,
		 * 以释放物理内存供其他程序使用.当这些被交换出去的页面再次被访问时,系统需要从交换空间中读取这些页面回物理内存,这个过程就称为"页错误"(page fault).
		 *
		 * "主要错误"(Major fault)或"大页错误"通常指的是那些需要从磁盘(即交换空间)读取页面到物理内存中的页错误,
		 * 与之相对的是"次要错误"(Minor fault),后者通常指的是页面已经在物理内存中,但相关的页表项(PTE)需要被更新以反映页面的新位置或状态,而不需要从磁盘读取数据.
		 */
		ret = VM_FAULT_MAJOR;
		/* PGMAJFAULT event + 1 */
		count_vm_event(PGMAJFAULT);
		mem_cgroup_count_vm_event(vma->vm_mm, PGMAJFAULT);
	} else if (PageHWPoison(page)) {
		/*
		 * hwpoisoned dirty swapcache pages are kept for killing
		 * owner processes (which may be unknown at hwpoison time)
		 */
		ret = VM_FAULT_HWPOISON;
		delayacct_clear_flag(DELAYACCT_PF_SWAPIN);
		swapcache = page;
		goto out_release;
	}

	/* 将page赋值给swapcache */
	swapcache = page;
	/* lock该page */
	locked = lock_page_or_retry(page, vma->vm_mm, fe->flags);

	/* 清除DELAYACCT_PF_SWAPIN的flag */
	delayacct_clear_flag(DELAYACCT_PF_SWAPIN);
	/* 处理没lock住的情况 */
	if (!locked) {
		ret |= VM_FAULT_RETRY;
		goto out_release;
	}

	/*
	 * Make sure try_to_free_swap or reuse_swap_page or swapoff did not
	 * release the swapcache from under us.  The page pin, and pte_same
	 * test below, are not enough to exclude that.  Even if it is still
	 * swapcache, we need to check that the page's swap has not changed.
	 *
	 * 确保try_to_free_swap、reuse_swap_page或swapoff操作没有在我们不知情的情况下释放了交换缓存(swapcache).
	 * 仅仅依靠页面锁定(page pin)和下面的pte_same测试是不够的来排除这种情况.
	 * 即使它仍然是交换缓存的一部分,我们也需要检查该页面的交换信息是否没有发生变化
	 */

	/* 如果page没有设置PG_swapcache或者说page_private(page) != entry.val,那么goto out_page */
	if (unlikely(!PageSwapCache(page) || page_private(page) != entry.val))
		goto out_page;

	/* 这边就是去拷贝,也就是说从ksm里面给分离出一个page出来 */
	page = ksm_might_need_to_copy(page, vma, fe->address);
	if (unlikely(!page)) {
		ret = VM_FAULT_OOM;
		page = swapcache;
		goto out_page;
	}

	if (mem_cgroup_try_charge(page, vma->vm_mm, GFP_KERNEL,
				&memcg, false)) {
		ret = VM_FAULT_OOM;
		goto out_page;
	}

	/*
	 * Back out if somebody else already faulted in this pte.
	 *
	 * 如果其他人已经因为页错误(page fault)而修改了这个页表项(PTE),则回退(取消当前操作)
	 */
	fe->pte = pte_offset_map_lock(vma->vm_mm, fe->pmd, fe->address,
			&fe->ptl);
	/* 如果已经不想等了,说明已经有人修改了这个页表项,那么goto out_nomap */
	if (unlikely(!pte_same(*fe->pte, orig_pte)))
		goto out_nomap;

	/* 如果该页不是最新的,那么返回VM_FAULT_SIGBUS */
	if (unlikely(!PageUptodate(page))) {
		ret = VM_FAULT_SIGBUS;
		goto out_nomap;
	}

	/*
	 * The page isn't present yet, go ahead with the fault.
	 *
	 * Be careful about the sequence of operations here.
	 * To get its accounting right, reuse_swap_page() must be called
	 * while the page is counted on swap but not yet in mapcount i.e.
	 * before page_add_anon_rmap() and swap_free(); try_to_free_swap()
	 * must be called after the swap_free(), or it will never succeed.
	 *
	 * 该页面当前不在物理内存中,请继续处理错误。
	 *
	 * 注意这里的操作顺序.为了正确计算,必须在页面在swap上计数但尚未在mapcount中计数时调用reuse_swap_page(),
	 * 即在page_add_anon_rmap()和swap_free()之前;
	 * try_to_free_swap()必须在swap_free()之后调用,否则它永远不会成功.
	 */
	/* task->rss_stat.count[MM_ANONPAGES]++ */
	inc_mm_counter_fast(vma->vm_mm, MM_ANONPAGES);
	/* task->rss_stat.count[MM_SWAPENTS]-- */
	dec_mm_counter_fast(vma->vm_mm, MM_SWAPENTS);
	/* 通过page和vma->vm_page_prot构造一个pte */
	pte = mk_pte(page, vma->vm_page_prot);
	/* 如果是写操作导致的fault,如果没有其他引用,我们可以在没有COW的情况下写入一个匿名页面.*/
	if ((fe->flags & FAULT_FLAG_WRITE) && reuse_swap_page(page, NULL)) {
		/* 设置该pte的PTE_WRITE位 */
		pte = maybe_mkwrite(pte_mkdirty(pte), vma);
		/* 清除fe->flags的FAULT_FLAG_WRITE */
		fe->flags &= ~FAULT_FLAG_WRITE;
		/* ref |= VM_FAULT_WRITE */
		ret |= VM_FAULT_WRITE;
		exclusive = RMAP_EXCLUSIVE;
	}
	flush_icache_page(vma, page);
	if (pte_swp_soft_dirty(orig_pte))
		pte = pte_mksoft_dirty(pte);

	/* 把它设置到页表项里面去 */
	set_pte_at(vma->vm_mm, fe->address, fe->pte, pte);
	if (page == swapcache) {
		do_page_add_anon_rmap(page, vma, fe->address, exclusive);
		mem_cgroup_commit_charge(page, memcg, true, false);
		activate_page(page);
	} else { /* ksm created a completely new copy */
		page_add_new_anon_rmap(page, vma, fe->address, false);
		mem_cgroup_commit_charge(page, memcg, false, false);
		lru_cache_add_active_or_unevictable(page, vma);
	}

	/* 释放掉swap_cache */
	swap_free(entry);
	if (mem_cgroup_swap_full(page) ||
	    (vma->vm_flags & VM_LOCKED) || PageMlocked(page))
		try_to_free_swap(page);
	unlock_page(page);
	if (page != swapcache) {
		/*
		 * Hold the lock to avoid the swap entry to be reused
		 * until we take the PT lock for the pte_same() check
		 * (to avoid false positives from pte_same). For
		 * further safety release the lock after the swap_free
		 * so that the swap count won't change under a
		 * parallel locked swapcache.
		 */
		unlock_page(swapcache);
		put_page(swapcache);
	}

	if (fe->flags & FAULT_FLAG_WRITE) {
		ret |= do_wp_page(fe, pte);
		if (ret & VM_FAULT_ERROR)
			ret &= VM_FAULT_ERROR;
		goto out;
	}

	/* No need to invalidate - it was non-present before */
	update_mmu_cache(vma, fe->address, fe->pte);
unlock:
	pte_unmap_unlock(fe->pte, fe->ptl);
out:
	return ret;
out_nomap:
	mem_cgroup_cancel_charge(page, memcg, false);
	pte_unmap_unlock(fe->pte, fe->ptl);
out_page:
	unlock_page(page);
out_release:
	put_page(page);
	if (page != swapcache) {
		unlock_page(swapcache);
		put_page(swapcache);
	}
	return ret;
}

/*
 * This is like a special single-page "expand_{down|up}wards()",
 * except we must first make sure that 'address{-|+}PAGE_SIZE'
 * doesn't hit another vma.
 */
static inline int check_stack_guard_page(struct vm_area_struct *vma, unsigned long address)
{
	address &= PAGE_MASK;
	if ((vma->vm_flags & VM_GROWSDOWN) && address == vma->vm_start) {
		struct vm_area_struct *prev = vma->vm_prev;

		/*
		 * Is there a mapping abutting this one below?
		 *
		 * That's only ok if it's the same stack mapping
		 * that has gotten split..
		 */
		if (prev && prev->vm_end == address)
			return prev->vm_flags & VM_GROWSDOWN ? 0 : -ENOMEM;

		return expand_downwards(vma, address - PAGE_SIZE);
	}
	if ((vma->vm_flags & VM_GROWSUP) && address + PAGE_SIZE == vma->vm_end) {
		struct vm_area_struct *next = vma->vm_next;

		/* As VM_GROWSDOWN but s/below/above/ */
		if (next && next->vm_start == address + PAGE_SIZE)
			return next->vm_flags & VM_GROWSUP ? 0 : -ENOMEM;

		return expand_upwards(vma, address + PAGE_SIZE);
	}
	return 0;
}

/*
 * We enter with non-exclusive mmap_sem (to exclude vma changes,
 * but allow concurrent faults), and pte mapped but not yet locked.
 * We return with mmap_sem still held, but pte unmapped and unlocked.
 */
static int do_anonymous_page(struct fault_env *fe)
{
	struct vm_area_struct *vma = fe->vma;
	struct mem_cgroup *memcg;
	struct page *page;
	pte_t entry;

	/* File mapping without ->vm_ops ? */
	/* 判断映射虚拟内存vma是否需要在不同进程间共享 */
	if (vma->vm_flags & VM_SHARED)
		return VM_FAULT_SIGBUS;

	/* Check if we need to add a guard page to the stack
	 * check_stack_guard_page函数判断当前VMA是否需要添加一个guard page作为安全垫 */
	 *
	if (check_stack_guard_page(vma, fe->address) < 0)
		return VM_FAULT_SIGSEGV;

	/*
	 * Use pte_alloc() instead of pte_alloc_map().  We can't run
	 * pte_offset_map() on pmds where a huge pmd might be created
	 * from a different thread.
	 *
	 * pte_alloc_map() is safe to use under down_write(mmap_sem) or when
	 * parallel threads are excluded by other means.
	 *
	 * Here we only have down_read(mmap_sem).
	 *
	 * 使用pte_alloc()而不是pte_alloc_map().
	 * 我们无法在可能从不同线程创建巨大pmd的pmd上运行pte_offset_map()
	 *
	 * pte_alloc_map()在down_write(mmap_sem)下或通过其他方式排除并行线程时使用是安全的.
	 *
	 * 这里我们只有down_read（mmap_sem）。
	 */

	/* 分配pte,如果返回NG,返回VM_FAULT_OOM */
	if (pte_alloc(vma->vm_mm, fe->pmd, fe->address))
		return VM_FAULT_OOM;

	/* See the comment in pte_alloc_one_map() */
	if (unlikely(pmd_trans_unstable(fe->pmd)))
		return 0;

	/* Use the zero-page for reads */
	/* 分配属性是只读的.
	 * 当需要分配的内存只有只读属性,系统会使用一个全填充为0的全局页面empty_zero_page,称为零页面(ZERO_PAGE).
	 * 这个零页面是一个special mapping的页面
	 */
	if (!(fe->flags & FAULT_FLAG_WRITE) &&
			!mm_forbids_zeropage(vma->vm_mm)) {
		/* 使用零页面来生成一个新的PTE entry,然后使用pte_mkspecial设置PTE entry中的PTE_SPECIAL位. */
		entry = pte_mkspecial(pfn_pte(my_zero_pfn(fe->address),
						vma->vm_page_prot));

		/*
		 * #define pte_offset_map_lock(mm, pmd, address, ptlp)	\
		 * ({							\
		 *	spinlock_t *__ptl = pte_lockptr(mm, pmd);	\
		 *	pte_t *__pte = pte_offset_map(pmd, address);	\
		 *	*(ptlp) = __ptl;				\
		 *	spin_lock(__ptl);				\
		 *	__pte;						\
		 * })
		 *
		 * 这里会去获取当前pte页表项,注意这里获取了一个spinlock锁,所以在函数返回时需要释放这个锁
		 */
		fe->pte = pte_offset_map_lock(vma->vm_mm, fe->pmd, fe->address,
				&fe->ptl);
		/* 如果获取的pte表项内容为空,那么goto unlock */
		if (!pte_none(*fe->pte))
			goto unlock;
		/* Deliver the page fault to userland, check inside PT lock */
		if (userfaultfd_missing(vma)) {
			pte_unmap_unlock(fe->pte, fe->ptl);
			return handle_userfault(fe, VM_UFFD_MISSING);
		}
		/* 否则跳转到setpte标签处去设置硬件pte表项,即把新的PTE entry设置到硬件页表中 */
		goto setpte;
	}

	/* Allocate our own private page. */
	if (unlikely(anon_vma_prepare(vma)))
		goto oom;
	/* 这里就是去分配一个可写的匿名页面,最终还是调用伙伴系统的核心API函数alloc_pages,但是这里分配的页面会优先使用高端内存 */
	page = alloc_zeroed_user_highpage_movable(vma, fe->address);
	if (!page)
		goto oom;

	if (mem_cgroup_try_charge(page, vma->vm_mm, GFP_KERNEL, &memcg, false))
		goto oom_free_page;

	/*
	 * The memory barrier inside __SetPageUptodate makes sure that
	 * preceeding stores to the page contents become visible before
	 * the set_pte_at() write.
	 *
	 * __SetPageUptodate内部的内存屏障确保在写入set_pte_at()之前,页面内容的先行的存储可见.
	 *
	 * 调用__SetPageUptodate设置page的PG_uptodate标志
	 *
	 * PG_uptodate tells whether the page's contents is valid.When a read completes,the page becomes uptodate,unless a disk I/O error happened.
	 */
	__SetPageUptodate(page);
	/* 更新pte */
	entry = mk_pte(page, vma->vm_page_prot);
	/* 如果VM是可写的,那么设置drity位 */
	if (vma->vm_flags & VM_WRITE)
		entry = pte_mkwrite(pte_mkdirty(entry));

	/* 同上 */
	fe->pte = pte_offset_map_lock(vma->vm_mm, fe->pmd, fe->address,
			&fe->ptl);
	/* 如果pte是none,那么goto release */
	if (!pte_none(*fe->pte))
		goto release;

	/* Deliver the page fault to userland, check inside PT lock */
	if (userfaultfd_missing(vma)) {
		pte_unmap_unlock(fe->pte, fe->ptl);
		mem_cgroup_cancel_charge(page, memcg, false);
		put_page(page);
		return handle_userfault(fe, VM_UFFD_MISSING);
	}
	/* 增加系统中匿名页面的统计计数 */
	inc_mm_counter_fast(vma->vm_mm, MM_ANONPAGES);
	/* 把匿名页面添加到RMAP反向映射系统中去
	 * 这里面会去调用__SetPageSwapBacked(page);
	 * 下面的lru_cache_add_active_or_unevictable会根据这个来把其加入到匿名页面的lru链表里面去
	 */
	page_add_new_anon_rmap(page, vma, fe->address, false);
	mem_cgroup_commit_charge(page, memcg, false, false);
	/* 把匿名页面添加到LRU链表中 */
	lru_cache_add_active_or_unevictable(page, vma);
setpte:
	/* 把新的PTE entry设置到硬件页表中 */
	set_pte_at(vma->vm_mm, fe->address, fe->pte, entry);

	/* No need to invalidate - it was non-present before */
	update_mmu_cache(vma, fe->address, fe->pte);
unlock:
	pte_unmap_unlock(fe->pte, fe->ptl);
	return 0;
release:
	mem_cgroup_cancel_charge(page, memcg, false);
	put_page(page);
	goto unlock;
oom_free_page:
	put_page(page);
oom:
	return VM_FAULT_OOM;
}

/*
 * The mmap_sem must have been held on entry, and may have been
 * released depending on flags and vma->vm_ops->fault() return value.
 * See filemap_fault() and __lock_page_retry().
 *
 * mmap_sem必须已保存在entry中,并且可能已根据flags和vma->vm_ops->fault()返回值释放.
 * 请参见filemap_fault()和__lock_page_retry()
 *
 */
static int __do_fault(struct fault_env *fe, pgoff_t pgoff,
		struct page *cow_page, struct page **page, void **entry)
{
	struct vm_area_struct *vma = fe->vma;
	struct vm_fault vmf;
	int ret;

	vmf.virtual_address = (void __user *)(fe->address & PAGE_MASK);
	vmf.pgoff = pgoff;
	vmf.flags = fe->flags;
	vmf.page = NULL;
	vmf.gfp_mask = __get_fault_gfp_mask(vma);
	vmf.cow_page = cow_page;
	/* 调用vma->vm_ops->fault(vma, &vmf)函数新建一个page cache
	 * 这里可以看一下filemap.c里面的filemap_fault
	 */
	ret = vma->vm_ops->fault(vma, &vmf);
	if (unlikely(ret & (VM_FAULT_ERROR | VM_FAULT_NOPAGE | VM_FAULT_RETRY)))
		return ret;
	if (ret & VM_FAULT_DAX_LOCKED) {
		*entry = vmf.entry;
		return ret;
	}

	if (unlikely(PageHWPoison(vmf.page))) {
		if (ret & VM_FAULT_LOCKED)
			unlock_page(vmf.page);
		put_page(vmf.page);
		return VM_FAULT_HWPOISON;
	}

	/* 如果返回值ret不包含VM_FAULT_LOCKED,那么调用lock_page函数为page加锁PG_locked,否则在打开了CONFIG_DEBUG_VM情况下,会去检查这个page是否已经locked了 */
	if (unlikely(!(ret & VM_FAULT_LOCKED)))
		lock_page(vmf.page);
	else
		VM_BUG_ON_PAGE(!PageLocked(vmf.page), vmf.page);

	*page = vmf.page;
	return ret;
}

static int pte_alloc_one_map(struct fault_env *fe)
{
	struct vm_area_struct *vma = fe->vma;

	/* 如果pmd不是空的,那么直接沟通map_pte */
	if (!pmd_none(*fe->pmd))
		goto map_pte;
	/* 如果有fe->prealloc_pte */
	if (fe->prealloc_pte) {
		/* 那么拿到page->ptl,也就是自旋锁 */
		fe->ptl = pmd_lock(vma->vm_mm, fe->pmd);
		/* 如果fe->pmd里面有东西,那么goto map_pte */
		if (unlikely(!pmd_none(*fe->pmd))) {
			spin_unlock(fe->ptl);
			goto map_pte;
		}

		/* 那么vma->vm_mm->nr_ptes + 1
		 * PTE page table pages
		 */
		atomic_long_inc(&vma->vm_mm->nr_ptes);
		/* 把它设置进fe-pmd里面去 */
		pmd_populate(vma->vm_mm, fe->pmd, fe->prealloc_pte);
		/* 解锁,设置fe->prealloc_pte为0 */
		spin_unlock(fe->ptl);
		fe->prealloc_pte = 0;
		/* 否则就分配pte */
	} else if (unlikely(pte_alloc(vma->vm_mm, fe->pmd, fe->address))) {
		return VM_FAULT_OOM;
	}
map_pte:
	/*
	 * If a huge pmd materialized under us just retry later.  Use
	 * pmd_trans_unstable() instead of pmd_trans_huge() to ensure the pmd
	 * didn't become pmd_trans_huge under us and then back to pmd_none, as
	 * a result of MADV_DONTNEED running immediately after a huge pmd fault
	 * in a different thread of this mm, in turn leading to a misleading
	 * pmd_trans_huge() retval.  All we have to ensure is that it is a
	 * regular pmd that we can walk with pte_offset_map() and we can do that
	 * through an atomic read in C, which is what pmd_trans_unstable()
	 * provides.
	 *
	 * 如果在我们下面出现了一个huge pmd,请稍后重试.使用pmd_trans_unstable()而不是pmd_trans_huge为了确保pmd在我们下面不会变成pmd_trans_huge,这时返回pmd_none.
	 * 由于MADV_DONTNEED在该mm的另一个线程中出现huge pmd fault后立即运行,进而导致错误的pmd_trans_huge()返回.
	 * 我们所要确保的是,它是一个常规的pmd,我们可以使用pte_offset_map()进行遍历,并且我们可以通过C中的原子读取来实现这一点,
	 * 这就是pmd_trans_unstable()所提供的
	 */
	if (pmd_trans_unstable(fe->pmd) || pmd_devmap(*fe->pmd))
		return VM_FAULT_NOPAGE;

	/* 这里就是去拿到pte,同时会spin_lock page->ptl */
	fe->pte = pte_offset_map_lock(vma->vm_mm, fe->pmd, fe->address,
			&fe->ptl);
	return 0;
}

#ifdef CONFIG_TRANSPARENT_HUGE_PAGECACHE

#define HPAGE_CACHE_INDEX_MASK (HPAGE_PMD_NR - 1)
static inline bool transhuge_vma_suitable(struct vm_area_struct *vma,
		unsigned long haddr)
{
	if (((vma->vm_start >> PAGE_SHIFT) & HPAGE_CACHE_INDEX_MASK) !=
			(vma->vm_pgoff & HPAGE_CACHE_INDEX_MASK))
		return false;
	if (haddr < vma->vm_start || haddr + HPAGE_PMD_SIZE > vma->vm_end)
		return false;
	return true;
}

static int do_set_pmd(struct fault_env *fe, struct page *page)
{
	struct vm_area_struct *vma = fe->vma;
	bool write = fe->flags & FAULT_FLAG_WRITE;
	unsigned long haddr = fe->address & HPAGE_PMD_MASK;
	pmd_t entry;
	int i, ret;

	if (!transhuge_vma_suitable(vma, haddr))
		return VM_FAULT_FALLBACK;

	ret = VM_FAULT_FALLBACK;
	page = compound_head(page);

	fe->ptl = pmd_lock(vma->vm_mm, fe->pmd);
	if (unlikely(!pmd_none(*fe->pmd)))
		goto out;

	for (i = 0; i < HPAGE_PMD_NR; i++)
		flush_icache_page(vma, page + i);

	entry = mk_huge_pmd(page, vma->vm_page_prot);
	if (write)
		entry = maybe_pmd_mkwrite(pmd_mkdirty(entry), vma);

	add_mm_counter(vma->vm_mm, MM_FILEPAGES, HPAGE_PMD_NR);
	page_add_file_rmap(page, true);

	set_pmd_at(vma->vm_mm, haddr, fe->pmd, entry);

	update_mmu_cache_pmd(vma, haddr, fe->pmd);

	/* fault is handled */
	ret = 0;
	count_vm_event(THP_FILE_MAPPED);
out:
	spin_unlock(fe->ptl);
	return ret;
}
#else
static int do_set_pmd(struct fault_env *fe, struct page *page)
{
	BUILD_BUG();
	return 0;
}
#endif

/**
 * alloc_set_pte - setup new PTE entry for given page and add reverse page
 * mapping. If needed, the fucntion allocates page table or use pre-allocated.
 *
 * @fe: fault environment
 * @memcg: memcg to charge page (only for private mappings)
 * @page: page to map
 *
 * Caller must take care of unlocking fe->ptl, if fe->pte is non-NULL on return.
 *
 * Target users are page handler itself and implementations of
 * vm_ops->map_pages.
 *
 * alloc_set_pte- 为给定页面设置新的PTE entry并 添加反向页面映射.
 * 如果需要,这个函数会分配页面表或使用预先分配的.
 *
 * @fe: fault environment
 * @memcg: memcg去计数页面(仅适用于私有映射)
 * @page: 要映射的页面
 *
 * 调用者必须小心unlocking fe->ptl,如果fe->pte非空那么返回
 *
 * 目标用户是页面处理程序本身和vm_ops->map_pages的实现.
 */
int alloc_set_pte(struct fault_env *fe, struct mem_cgroup *memcg,
		struct page *page)
{
	/* 拿到vma */
	struct vm_area_struct *vma = fe->vma;
	/* 判断它是否可写 */
	bool write = fe->flags & FAULT_FLAG_WRITE;
	pte_t entry;
	int ret;

	/* 大页 */
	if (pmd_none(*fe->pmd) && PageTransCompound(page) &&
			IS_ENABLED(CONFIG_TRANSPARENT_HUGE_PAGECACHE)) {
		/* THP on COW? */
		VM_BUG_ON_PAGE(memcg, page);

		ret = do_set_pmd(fe, page);
		if (ret != VM_FAULT_FALLBACK)
			return ret;
	}

	/* 如果没有pte,那么分配一个pte */
	if (!fe->pte) {
		/* 这里是去分配pte,注意这里还会拿到page->ptl的锁 */
		ret = pte_alloc_one_map(fe);
		if (ret)
			return ret;
	}

	/* Re-check under ptl
	 * 在ptl下再次检查
	 */
	/* 再次检查fe->pte是否为NULL,为NULL就返回VM_FAULT_NOPAGE */
	if (unlikely(!pte_none(*fe->pte)))
		return VM_FAULT_NOPAGE;


	flush_icache_page(vma, page);
	/* 将page设置为pte */
	entry = mk_pte(page, vma->vm_page_prot);
	/* 如果是可写的,那么这里设置PTE_WRITE */
	if (write)
		entry = maybe_mkwrite(pte_mkdirty(entry), vma);
	/* copy-on-write page
	 * 如果vma->vm_flags不是共享的,但是是可写的
	 * 那么说明是写时复制
	 */
	if (write && !(vma->vm_flags & VM_SHARED)) {
		/* 快速增加vma的匿名页数量 */
		inc_mm_counter_fast(vma->vm_mm, MM_ANONPAGES);
		/* 匿名页面添加到RMAP系统 */
		page_add_new_anon_rmap(page, vma, fe->address, false);
		mem_cgroup_commit_charge(page, memcg, false, false);
		/* 把物理页添加到LRU(最近最少使用)链表,方便页回收算法从LRU链表祖选择合适的物理页进行回收 */
		lru_cache_add_active_or_unevictable(page, vma);
	} else {
		/*
		 *  static inline int mm_counter_file(struct page *page)
		 * {
		 *	if (PageSwapBacked(page))
		 *		return MM_SHMEMPAGES;
		 *	return MM_FILEPAGES;
		 * }
		 */
		/* 添加共享内存或者是文件页的计数 */
		inc_mm_counter_fast(vma->vm_mm, mm_counter_file(page));
		page_add_file_rmap(page, false);
	}

	/* 设置pte */
	set_pte_at(vma->vm_mm, fe->address, fe->pte, entry);

	/* no need to invalidate: a not-present page won't be cached */
	update_mmu_cache(vma, fe->address, fe->pte);

	return 0;
}

static unsigned long fault_around_bytes __read_mostly =
	rounddown_pow_of_two(65536);

#ifdef CONFIG_DEBUG_FS
static int fault_around_bytes_get(void *data, u64 *val)
{
	*val = fault_around_bytes;
	return 0;
}

/*
 * fault_around_pages() and fault_around_mask() expects fault_around_bytes
 * rounded down to nearest page order. It's what do_fault_around() expects to
 * see.
 */
static int fault_around_bytes_set(void *data, u64 val)
{
	if (val / PAGE_SIZE > PTRS_PER_PTE)
		return -EINVAL;
	if (val > PAGE_SIZE)
		fault_around_bytes = rounddown_pow_of_two(val);
	else
		fault_around_bytes = PAGE_SIZE; /* rounddown_pow_of_two(0) is undefined */
	return 0;
}
DEFINE_SIMPLE_ATTRIBUTE(fault_around_bytes_fops,
		fault_around_bytes_get, fault_around_bytes_set, "%llu\n");

static int __init fault_around_debugfs(void)
{
	void *ret;

	ret = debugfs_create_file("fault_around_bytes", 0644, NULL, NULL,
			&fault_around_bytes_fops);
	if (!ret)
		pr_warn("Failed to create fault_around_bytes in debugfs");
	return 0;
}
late_initcall(fault_around_debugfs);
#endif

/*
 * do_fault_around() tries to map few pages around the fault address. The hope
 * is that the pages will be needed soon and this will lower the number of
 * faults to handle.
 *
 * It uses vm_ops->map_pages() to map the pages, which skips the page if it's
 * not ready to be mapped: not up-to-date, locked, etc.
 *
 * This function is called with the page table lock taken. In the split ptlock
 * case the page table lock only protects only those entries which belong to
 * the page table corresponding to the fault address.
 *
 * This function doesn't cross the VMA boundaries, in order to call map_pages()
 * only once.
 *
 * fault_around_pages() defines how many pages we'll try to map.
 * do_fault_around() expects it to return a power of two less than or equal to
 * PTRS_PER_PTE.
 *
 * The virtual address of the area that we map is naturally aligned to the
 * fault_around_pages() value (and therefore to page order).  This way it's
 * easier to guarantee that we don't cross page table boundaries.
 *
 * do_fault_around尝试在fault地址周围映射几个页面.
 * 希望这些页面很快就会被需要,这将减少需要处理的fault数量.
 *
 * 它使用vm_ops->map_pages()来映射页面,如果页面还没有准备好映射,则会跳过该页面: not up_to_data、locked等等.
 *
 * 调用此函数时使用页表锁.在拆分ptlock的情况下,页表锁仅保护属于与fault地址对应的页表的那些条目.
 *
 * 此函数不跨越VMA边界,以便只调用map_pages()一次.
 *
 * fault_around_pages()定义了我们将尝试映射的页面数量.
 * do_fault_around()期望它返回小于或等于PTRS_PER_PTE的二次方.
 *
 * 我们映射的区域的虚拟地址自然与fault_around_pages()值对齐(因此与页面顺序对齐).
 * 这样可以更容易地保证我们不会跨越页面表边界.
 */
static int do_fault_around(struct fault_env *fe, pgoff_t start_pgoff)
{
	unsigned long address = fe->address, nr_pages, mask;
	pgoff_t end_pgoff;
	int off, ret = 0;

	/* 读取要在缺页异常地址周围提前映射的页数 */
	nr_pages = READ_ONCE(fault_around_bytes) >> PAGE_SHIFT;
	/* (nr_pages * PAGE_SIZE - 1)按位取反之后 & PAGE_MASK
	 *
	 * 假设PAGE_SIZE是4KB,那么nr_pages = 16
	 * 16*1024*4 = 0x10000,-1之后按位取反就是0xffff ffff ffff 0000
	 * 0xffff ffff ffff 0000 &  ~(0xfff)
	 * 0xffff ffff ffff 0000 & 0x ffff ffff ffff 000
	 * mask = 0xffff ffff ffff 0000
	 */
	mask = ~(nr_pages * PAGE_SIZE - 1) & PAGE_MASK;

	/*       pgoff
	 *  __________________
	 * |		      |
	 * ↓ _________________↓____________________________________________
	 * |           |      |               |                            |
	 * |	       |      |               |                            |
	 * |           |      |               |                            |
	 * |___________|______|_______________|____________________________|
	 *vma_start    ↑      ↑		      ↑				   vm_end
	 *	   以16 page  缺页异常	    end_pgoff
	 *	 对齐的addr1  地址addr        ↑
	 *             ↑		      |
	 *	       |______________________|
	 *		从addr开始到end_pgoff,检查每个pte
	 *		当pte内容为空,那么调用vm_ops->map_pages()去映射pte
	 */
	/* 这里选address & mask 和 fe->vma->vm_start最大的 */
	fe->address = max(address & mask, fe->vma->vm_start);
	/* 这里计算fe->address在进行调整之后相对于它的偏移量,这里需要和(PTRS_PER_PTE - 1)
	 * 因为你这么pmd已经确定了,不可能超过page table的大小
	 */
	off = ((address - fe->address) >> PAGE_SHIFT) & (PTRS_PER_PTE - 1);
	/* 让start_pgoff减去它,在上图中最终得到的就是以16 page对齐的addr1的pgoff */
	start_pgoff -= off;

	/*
	 *  end_pgoff is either end of page table or end of vma
	 *  or fault_around_pages() from start_pgoff, depending what is nearest.
	 *
	 * end_pgoff是页表的末尾,或者是start_pgoff中vma或fault_around_pages()的末尾,
	 * 具体取决于最接近的值。
	 */

	/* 这里就是pte的末尾 */
	end_pgoff = start_pgoff -
		((fe->address >> PAGE_SHIFT) & (PTRS_PER_PTE - 1)) +
		PTRS_PER_PTE - 1;
	/* 这里取end_pgoff、
	 * (vma->vm_end - vma->vm_start) >> PAGE_SHIFT + fe->vma->vm_pgoff - 1 这里就是vma结束
	 * 还有start_pgoff + nr_pages - 1的最小值
	 */
	end_pgoff = min3(end_pgoff, vma_pages(fe->vma) + fe->vma->vm_pgoff - 1,
			start_pgoff + nr_pages - 1);

	/* 如果fe->pmd是空的,就分配pte */
	if (pmd_none(*fe->pmd)) {
		fe->prealloc_pte = pte_alloc_one(fe->vma->vm_mm, fe->address);
		/* 如果分配不到,就goto out */
		if (!fe->prealloc_pte)
			goto out;
		smp_wmb(); /* See comment in __pte_alloc() */
	}

	/* 这里就是去做映射
	 * 如果是ext4可以那就等于filemap_map_pages
	 */
	fe->vma->vm_ops->map_pages(fe, start_pgoff, end_pgoff);

	/* preallocated pagetable is unused: free it
	 * 预分配的页表未使用: 释放它
	 */
	if (fe->prealloc_pte) {
		pte_free(fe->vma->vm_mm, fe->prealloc_pte);
		fe->prealloc_pte = 0;
	}

	/* Huge page is mapped? Page fault is solved
	 * 如果是大页,也就是THP,那么说明page fault被解决了
	 * 返回VM_FAULT_NOPAGE
	 */
	if (pmd_trans_huge(*fe->pmd)) {
		ret = VM_FAULT_NOPAGE;
		goto out;
	}

	/* ->map_pages() haven't done anything useful. Cold page cache?
	 * ->map_pages()没有做任何有用的事情.Cold page 缓存?
	 */
	if (!fe->pte)
		goto out;

	/* check if the page fault is solved */
	/* 这里就是用fe->pte减去对齐的pte + fault地址的pte */
	fe->pte -= (fe->address >> PAGE_SHIFT) - (address >> PAGE_SHIFT);
	/* 如果为none,说明已经安装了pte
	 * #define VM_FAULT_NOPAGE	0x0100	->fault installed the pte, not return page
	 */
	if (!pte_none(*fe->pte))
		ret = VM_FAULT_NOPAGE;
	pte_unmap_unlock(fe->pte, fe->ptl);
out:
	fe->address = address;
	fe->pte = NULL;
	return ret;
}

static int do_read_fault(struct fault_env *fe, pgoff_t pgoff)
{
	struct vm_area_struct *vma = fe->vma;
	struct page *fault_page;
	int ret = 0;

	/*
	 * Let's call ->map_pages() first and use ->fault() as fallback
	 * if page by the offset is not ready to be mapped (cold cache or
	 * something).
	 *
	 * 让我们先调用->map_pages(),如果偏移量的页面还没有准备好映射(cold cache或其他),则使用->fault()作为回退.
	 */
	/* 如果vma定义了map_pages方法,可以围绕在缺页异常地址周围提前映射尽可能多的页面.
	 * 提前建立进程地址空间和page cache的映射关系有利于减少发生缺页中断的次数,从而提高效率.
	 * 注意这里只是和现存的page cache提前建立映射关系,而不是去创建page cahce,创建新的page cache是在__do_fault函数中.
	 * fault_around_bytes是个定义在mm/memory.c的全局变量,默认是65536Byte,即16个页面的大小
	 */
	if (vma->vm_ops->map_pages && fault_around_bytes >> PAGE_SHIFT > 1) {
		ret = do_fault_around(fe, pgoff);
		if (ret)
			return ret;
	}

	/* 如果没有vma->vm_ops->map_pages 或者 fault_around_bytes >> PAGE_SHIFT <= 1
	 * 这里就是真正为异常地址分配page cahce的地方
	 */
	ret = __do_fault(fe, pgoff, NULL, &fault_page, NULL);
	if (unlikely(ret & (VM_FAULT_ERROR | VM_FAULT_NOPAGE | VM_FAULT_RETRY)))
		return ret;

	ret |= alloc_set_pte(fe, NULL, fault_page);
	/* alloc_set_pte里面会lock住,所以解锁 */
	if (fe->pte)
		pte_unmap_unlock(fe->pte, fe->ptl);
	unlock_page(fault_page);
	if (unlikely(ret & (VM_FAULT_ERROR | VM_FAULT_NOPAGE | VM_FAULT_RETRY)))
		put_page(fault_page);
	return ret;
}

static int do_cow_fault(struct fault_env *fe, pgoff_t pgoff)
{
	struct vm_area_struct *vma = fe->vma;
	struct page *fault_page, *new_page;
	void *fault_entry;
	struct mem_cgroup *memcg;
	int ret;

	if (unlikely(anon_vma_prepare(vma)))
		return VM_FAULT_OOM;

	/* 分配一个分配掩码为GFP_HIGIUSER | __GFP_MOVABLE的新页面new_page
	 * 也就是有效使用高端内存highmem
	 */
	new_page = alloc_page_vma(GFP_HIGHUSER_MOVABLE, vma, fe->address);
	if (!new_page)
		return VM_FAULT_OOM;

	if (mem_cgroup_try_charge(new_page, vma->vm_mm, GFP_KERNEL,
				&memcg, false)) {
		put_page(new_page);
		return VM_FAULT_OOM;
	}

	/* __do_fault函数通过vma->vm_ops->fault韩式读取文件内容到fault_page页面里 */
	ret = __do_fault(fe, pgoff, new_page, &fault_page, &fault_entry);
	if (unlikely(ret & (VM_FAULT_ERROR | VM_FAULT_NOPAGE | VM_FAULT_RETRY)))
		goto uncharge_out;

	/* 这里是把fault_page页面的内容复制到刚才新分配的new_page中 */
	if (!(ret & VM_FAULT_DAX_LOCKED))
		copy_user_highpage(new_page, fault_page, fe->address, vma);
	__SetPageUptodate(new_page);

	/* 利用new_page新生成一个PTE entry并设置到硬件页表项pte中 */
	ret |= alloc_set_pte(fe, memcg, new_page);
	if (fe->pte)
		pte_unmap_unlock(fe->pte, fe->ptl);
	/* 这里释放fault page */
	if (!(ret & VM_FAULT_DAX_LOCKED)) {
		unlock_page(fault_page);
		put_page(fault_page);
	} else {
		dax_unlock_mapping_entry(vma->vm_file->f_mapping, pgoff);
	}
	if (unlikely(ret & (VM_FAULT_ERROR | VM_FAULT_NOPAGE | VM_FAULT_RETRY)))
		goto uncharge_out;
	return ret;
uncharge_out:
	mem_cgroup_cancel_charge(new_page, memcg, false);
	put_page(new_page);
	return ret;
}

/* do_shared_fault函数处理在一个可写的共享映射中发生缺页中断的情况 */
static int do_shared_fault(struct fault_env *fe, pgoff_t pgoff)
{
	struct vm_area_struct *vma = fe->vma;
	struct page *fault_page;
	struct address_space *mapping;
	int dirtied = 0;
	int ret, tmp;

	/* __do_fault函数读取文件内容到fault_page页面中 */
	ret = __do_fault(fe, pgoff, NULL, &fault_page, NULL);
	if (unlikely(ret & (VM_FAULT_ERROR | VM_FAULT_NOPAGE | VM_FAULT_RETRY)))
		return ret;

	/*
	 * Check if the backing address space wants to know that the page is
	 * about to become writable
	 */
	/* 如果VMA的操作函数中定义了page_mkwrite方法,那么调用page_mkwrite来通知进程地址空间,page将变成可写的.
	 * 一个页面变成可写的,那么进程有可能需要等待这个page的内容回写成功
	 */
	if (vma->vm_ops->page_mkwrite) {
		unlock_page(fault_page);
		tmp = do_page_mkwrite(vma, fault_page, fe->address);
		if (unlikely(!tmp ||
				(tmp & (VM_FAULT_ERROR | VM_FAULT_NOPAGE)))) {
			put_page(fault_page);
			return tmp;
		}
	}
	/* 利用fault_page新生成一个PTE entry并设置到硬件页表项pte中,注意这里设置pte为可写属性 */
	ret |= alloc_set_pte(fe, NULL, fault_page);
	if (fe->pte)
		pte_unmap_unlock(fe->pte, fe->ptl);
	if (unlikely(ret & (VM_FAULT_ERROR | VM_FAULT_NOPAGE |
					VM_FAULT_RETRY))) {
		unlock_page(fault_page);
		put_page(fault_page);
		return ret;
	}

	/* 设置page为脏页面 */
	if (set_page_dirty(fault_page))
		dirtied = 1;
	/*
	 * Take a local copy of the address_space - page.mapping may be zeroed
	 * by truncate after unlock_page().   The address_space itself remains
	 * pinned by vma->vm_file's reference.  We rely on unlock_page()'s
	 * release semantics to prevent the compiler from undoing this copying.
	 *
	 * 获取address_space的本地副本 - page.mapping在unlock_page()之后的截断可以变成0.
	 * address_space本身仍然通过vma->vm_file的引用而固定.
	 * 我们依靠unlock_page()的释放语义来防止编译器撤消此复制.
	 */
	mapping = page_rmapping(fault_page);
	unlock_page(fault_page);
	if ((dirtied || vma->vm_ops->page_mkwrite) && mapping) {
		/*
		 * Some device drivers do not set page.mapping but still
		 * dirty their pages
		 */
		balance_dirty_pages_ratelimited(mapping);
	}

	if (!vma->vm_ops->page_mkwrite)
		file_update_time(vma->vm_file);

	return ret;
}

/*
 * We enter with non-exclusive mmap_sem (to exclude vma changes,
 * but allow concurrent faults).
 * The mmap_sem may have been released depending on flags and our
 * return value.  See filemap_fault() and __lock_page_or_retry().
 *
 * 我们以非独占的mmap_sem进入(以排除vma更改,但允许并发faults).
 * mmap_sem可能已经释放,这取决于标志和我们的返回值.
 * 请参见filemap_fault()和__lock_page_or_retry()
 */
static int do_fault(struct fault_env *fe)
{
	struct vm_area_struct *vma = fe->vma;
	/* 算出pgoff */
	pgoff_t pgoff = linear_page_index(vma, fe->address);

	/* The VMA was not fully populated on mmap() or missing VM_DONTEXPAND
	 * 在mmap()上未完全填充VMA或缺少VM_DONTEXPAND
	 */

	/* 如果vm_ops里面没有fault函数,那么就返回VM_FAULT_SIGBUS */
	if (!vma->vm_ops->fault)
		return VM_FAULT_SIGBUS;
	/* 如果flags没有FAULT_FLAG_WRITE,那么是只读异常,调用do_read_fault */
	if (!(fe->flags & FAULT_FLAG_WRITE))
		return do_read_fault(fe, pgoff);
	/* 如果vma的vm_flags没有定义VM_SHARED,即这是一个私有映射,那么调用写时复制 */
	if (!(vma->vm_flags & VM_SHARED))
		return do_cow_fault(fe, pgoff);
	/* 其余情况是在共享映射中发生了写缺页异常 */
	return do_shared_fault(fe, pgoff);
}

static int numa_migrate_prep(struct page *page, struct vm_area_struct *vma,
				unsigned long addr, int page_nid,
				int *flags)
{
	get_page(page);

	count_vm_numa_event(NUMA_HINT_FAULTS);
	if (page_nid == numa_node_id()) {
		count_vm_numa_event(NUMA_HINT_FAULTS_LOCAL);
		*flags |= TNF_FAULT_LOCAL;
	}

	return mpol_misplaced(page, vma, addr);
}

static int do_numa_page(struct fault_env *fe, pte_t pte)
{
	struct vm_area_struct *vma = fe->vma;
	struct page *page = NULL;
	int page_nid = -1;
	int last_cpupid;
	int target_nid;
	bool migrated = false;
	bool was_writable = pte_write(pte);
	int flags = 0;

	/*
	* The "pte" at this point cannot be used safely without
	* validation through pte_unmap_same(). It's of NUMA type but
	* the pfn may be screwed if the read is non atomic.
	*
	* We can safely just do a "set_pte_at()", because the old
	* page table entry is not accessible, so there would be no
	* concurrent hardware modifications to the PTE.
	*/
	fe->ptl = pte_lockptr(vma->vm_mm, fe->pmd);
	spin_lock(fe->ptl);
	if (unlikely(!pte_same(*fe->pte, pte))) {
		pte_unmap_unlock(fe->pte, fe->ptl);
		goto out;
	}

	/* Make it present again */
	pte = pte_modify(pte, vma->vm_page_prot);
	pte = pte_mkyoung(pte);
	if (was_writable)
		pte = pte_mkwrite(pte);
	set_pte_at(vma->vm_mm, fe->address, fe->pte, pte);
	update_mmu_cache(vma, fe->address, fe->pte);

	page = vm_normal_page(vma, fe->address, pte);
	if (!page) {
		pte_unmap_unlock(fe->pte, fe->ptl);
		return 0;
	}

	/* TODO: handle PTE-mapped THP */
	if (PageCompound(page)) {
		pte_unmap_unlock(fe->pte, fe->ptl);
		return 0;
	}

	/*
	 * Avoid grouping on RO pages in general. RO pages shouldn't hurt as
	 * much anyway since they can be in shared cache state. This misses
	 * the case where a mapping is writable but the process never writes
	 * to it but pte_write gets cleared during protection updates and
	 * pte_dirty has unpredictable behaviour between PTE scan updates,
	 * background writeback, dirty balancing and application behaviour.
	 */
	if (!pte_write(pte))
		flags |= TNF_NO_GROUP;

	/*
	 * Flag if the page is shared between multiple address spaces. This
	 * is later used when determining whether to group tasks together
	 */
	if (page_mapcount(page) > 1 && (vma->vm_flags & VM_SHARED))
		flags |= TNF_SHARED;

	last_cpupid = page_cpupid_last(page);
	page_nid = page_to_nid(page);
	target_nid = numa_migrate_prep(page, vma, fe->address, page_nid,
			&flags);
	pte_unmap_unlock(fe->pte, fe->ptl);
	if (target_nid == -1) {
		put_page(page);
		goto out;
	}

	/* Migrate to the requested node */
	migrated = migrate_misplaced_page(page, vma, target_nid);
	if (migrated) {
		page_nid = target_nid;
		flags |= TNF_MIGRATED;
	} else
		flags |= TNF_MIGRATE_FAIL;

out:
	if (page_nid != -1)
		task_numa_fault(last_cpupid, page_nid, 1, flags);
	return 0;
}

static int create_huge_pmd(struct fault_env *fe)
{
	struct vm_area_struct *vma = fe->vma;
	if (vma_is_anonymous(vma))
		return do_huge_pmd_anonymous_page(fe);
	if (vma->vm_ops->pmd_fault)
		return vma->vm_ops->pmd_fault(vma, fe->address, fe->pmd,
				fe->flags);
	return VM_FAULT_FALLBACK;
}

static int wp_huge_pmd(struct fault_env *fe, pmd_t orig_pmd)
{
	if (vma_is_anonymous(fe->vma))
		return do_huge_pmd_wp_page(fe, orig_pmd);
	if (fe->vma->vm_ops->pmd_fault)
		return fe->vma->vm_ops->pmd_fault(fe->vma, fe->address, fe->pmd,
				fe->flags);

	/* COW handled on pte level: split pmd */
	VM_BUG_ON_VMA(fe->vma->vm_flags & VM_SHARED, fe->vma);
	split_huge_pmd(fe->vma, fe->pmd, fe->address);

	return VM_FAULT_FALLBACK;
}

static inline bool vma_is_accessible(struct vm_area_struct *vma)
{
	return vma->vm_flags & (VM_READ | VM_EXEC | VM_WRITE);
}

/*
 * These routines also need to handle stuff like marking pages dirty
 * and/or accessed for architectures that don't do it in hardware (most
 * RISC architectures).  The early dirtying is also good on the i386.
 *
 * There is also a hook called "update_mmu_cache()" that architectures
 * with external mmu caches can use to update those (ie the Sparc or
 * PowerPC hashed page tables that act as extended TLBs).
 *
 * We enter with non-exclusive mmap_sem (to exclude vma changes, but allow
 * concurrent faults).
 *
 * The mmap_sem may have been released depending on flags and our return value.
 * See filemap_fault() and __lock_page_or_retry().
 *
 * 这些例程还需要处理诸如将页面标记为脏 and/or accessed 在没有在硬件中这样做的体系结构(大多数RISC体系结构),i386的早期dritying也很好.
 *
 * 还有一个名为"update_mmu_cache()"的钩子函数,具有外部mmu cache的体系结构可以用来更新这些外部 mmu cache(即充当扩展TLB的Sparc或PowerPC哈希页表).
 *
 * 我们以非独占的mmap_sem进入(以排除vma更改,但允许并发faults).
 *
 * mmap_sem可能已经release,这取决于标志和我们的返回值.请参见filemap_fault()和__lock_page_or_retry().
 */
static int handle_pte_fault(struct fault_env *fe)
{
	pte_t entry;

	if (unlikely(pmd_none(*fe->pmd))) {
		/*
		 * Leave __pte_alloc() until later: because vm_ops->fault may
		 * want to allocate huge page, and if we expose page table
		 * for an instant, it will be difficult to retract from
		 * concurrent faults and from rmap lookups.
		 *
		 * 将__pte_alloc()留到稍后: 因为vm_ops->fault可能想要分配huge page,并且如果我们暂时公开页面表,
		 * 则很难从并发错误回收和rmap查询
		 */
		fe->pte = NULL;
	} else {
		/* See comment in pte_alloc_one_map() */
		if (pmd_trans_unstable(fe->pmd) || pmd_devmap(*fe->pmd))
			return 0;
		/*
		 * A regular pmd is established and it can't morph into a huge
		 * pmd from under us anymore at this point because we hold the
		 * mmap_sem read mode and khugepaged takes it in write mode.
		 * So now it's safe to run pte_offset_map().
		 *
		 * 一个常规的pmd已经建立,它现在不能再从我们下面变成一个huge pmd,因为我们保持mmap_sem读取模式,
		 * 而khugepaged在写入模式下使用它.
		 * 所以现在可以安全地运行pte_offset_map()了.
		 */

		/* 拿到地址所对应的pte,复制给fe->pte */
		fe->pte = pte_offset_map(fe->pmd, fe->address);
		/* 将pte的值复制给entry */
		entry = *fe->pte;

		/*
		 * some architectures can have larger ptes than wordsize,
		 * e.g.ppc44x-defconfig has CONFIG_PTE_64BIT=y and
		 * CONFIG_32BIT=y, so READ_ONCE or ACCESS_ONCE cannot guarantee
		 * atomic accesses.  The code below just needs a consistent
		 * view for the ifs and we later double check anyway with the
		 * ptl lock held. So here a barrier will do.
		 *
		 * 有些体系结构的PTE可能大于字大小,
		 * 例如ppc44x-defconfig的CONFIG_PTE_64BIT=y和CONFIG_32BIT=y,
		 * 因此READ_ONCE或ACCESS_ONCE不能保证原子访问.
		 * 下面的代码只需要一个一致的查看ifs,
		 * 然后我们在保持ptl锁的情况下再次检查.
		 * 所以在这里设置一个屏障就可以了。
		 */
		barrier();
		/* 如果pte为none,那么pte_unmap(arm64为NULL) */
		if (pte_none(entry)) {
			pte_unmap(fe->pte);
			fe->pte = NULL;
		}
	}
	/* 如果pte的内容是空的,也就是说pte还没映射物理页面,这是真正的缺页 */
	if (!fe->pte) {
		/* 如果是匿名页面,调用do_anonymous_page */
		if (vma_is_anonymous(fe->vma))
			return do_anonymous_page(fe);
		else	/* 对于文件映射,通常VMA的vm_ops操作函数定义了fault函数指针,那么调用do_fault函数 */
			return do_fault(fe);
	}

	/* 如果pte内容不为空且PRESENT没有置位,那么说明该页被交换到swap分区,则调用do_swap_page函数 */
	if (!pte_present(entry))
		return do_swap_page(fe, entry);

	if (pte_protnone(entry) && vma_is_accessible(fe->vma))
		return do_numa_page(fe, entry);

	/* 如果pte有映射物理页面,但因为之前的pte设置了只读,现在需要可写操作,所以触发了写时复制缺页中断. */
	fe->ptl = pte_lockptr(fe->vma->vm_mm, fe->pmd);
	spin_lock(fe->ptl);
	if (unlikely(!pte_same(*fe->pte, entry)))
		goto unlock;
	/* 如果传进来的flag设置了可写属性且当前pte是只读的,那么调用do_wp_page函数并返回 */
	if (fe->flags & FAULT_FLAG_WRITE) {
		if (!pte_write(entry))
			return do_wp_page(fe, entry);
		entry = pte_mkdirty(entry);
	}
	/* pte_mkyoung对于x86体系结构是设置_PAGE_ACCESSED位,这相对简单些.
	 * 对于ARM体系结构是设置Linux版本的页表中PTE页表项的L_PTE_YOUNG位,s是否需要写入ARM硬件版本的页表由set_pte_at函数来决定 */
	entry = pte_mkyoung(entry);
	/* 如果pte内容发生了变化,则需要把新的内容写到pte页表项中,并且要flush对应的TLB和cache */
	if (ptep_set_access_flags(fe->vma, fe->address, fe->pte, entry,
				fe->flags & FAULT_FLAG_WRITE)) {
		update_mmu_cache(fe->vma, fe->address, fe->pte);
	} else {
		/*
		 * This is needed only for protection faults but the arch code
		 * is not yet telling us if this is a protection fault or not.
		 * This still avoids useless tlb flushes for .text page faults
		 * with threads.
		 */
		if (fe->flags & FAULT_FLAG_WRITE)
			flush_tlb_fix_spurious_fault(fe->vma, fe->address);
	}
unlock:
	pte_unmap_unlock(fe->pte, fe->ptl);
	return 0;
}

/*
 * By the time we get here, we already hold the mm semaphore
 *
 * The mmap_sem may have been released depending on flags and our
 * return value.  See filemap_fault() and __lock_page_or_retry().
 *
 * 当我们到达这里时，我们已经获得了mm semaphore
 *
 * mmap_sem可能已经被释放,这取决于flag和我们的返回值.
 * 请参见filemap_fault()和__lock_page_or_retry()
 */
static int __handle_mm_fault(struct vm_area_struct *vma, unsigned long address,
		unsigned int flags)
{
	struct fault_env fe = {
		.vma = vma,
		.address = address,
		.flags = flags,
	};
	struct mm_struct *mm = vma->vm_mm;
	pgd_t *pgd;
	pud_t *pud;
	/* pgd_offset(mm, address);获取addr对应在当前进程页表的PGD页面目录项. */
	pgd = pgd_offset(mm, address);
	/* 获取或者分配(如果为空的话,分配完之后还会把值填入到pgd中)对应的PUD表项,如果PUD表项为空,
	 * 则返回VM_FAULT_OOM错误
	 */
	pud = pud_alloc(mm, pgd, address);
	if (!pud)
		return VM_FAULT_OOM;
	/* 这里同样获得对应的pmd */
	fe.pmd = pmd_alloc(mm, pud, address);
	if (!fe.pmd)
		return VM_FAULT_OOM;
	/* 看要不要弄hugepage */
	if (pmd_none(*fe.pmd) && transparent_hugepage_enabled(vma)) {
		int ret = create_huge_pmd(&fe);
		if (!(ret & VM_FAULT_FALLBACK))
			return ret;
	} else {
		pmd_t orig_pmd = *fe.pmd;
		int ret;

		barrier();
		/* 看pmd是不是块映射,或者devmap,如果是的话进入下面 */
		if (pmd_trans_huge(orig_pmd) || pmd_devmap(orig_pmd)) {
			/* 如果pmd不是VALID,并且
			 *  static inline bool vma_is_accessible(struct vm_area_struct *vma)
			 * {
			 *	return vma->vm_flags & (VM_READ | VM_EXEC | VM_WRITE);
			 * }
			 */
			if (pmd_protnone(orig_pmd) && vma_is_accessible(vma))
				return do_huge_pmd_numa_page(&fe, orig_pmd);
			/* 如果是写出发的FAULT,但是pmd里面没有写的权限 */
			if ((fe.flags & FAULT_FLAG_WRITE) &&
					!pmd_write(orig_pmd)) {
				/* 那就触发写写时复制 */
				ret = wp_huge_pmd(&fe, orig_pmd);
				/* #define VM_FAULT_FALLBACK 0x0800	huge page fault failed,fall back to small */
				if (!(ret & VM_FAULT_FALLBACK))
					return ret;
			} else {
				huge_pmd_set_accessed(&fe, orig_pmd);
				return 0;
			}
		}
	}

	return handle_pte_fault(&fe);
}

/*
 * By the time we get here, we already hold the mm semaphore
 *
 * The mmap_sem may have been released depending on flags and our
 * return value.  See filemap_fault() and __lock_page_or_retry().
 */
int handle_mm_fault(struct vm_area_struct *vma, unsigned long address,
		unsigned int flags)
{
	int ret;

	__set_current_state(TASK_RUNNING);

	count_vm_event(PGFAULT);
	mem_cgroup_count_vm_event(vma->vm_mm, PGFAULT);

	/* do counter updates before entering really critical section. */
	check_sync_rss_stat(current);

	/*
	 * Enable the memcg OOM handling for faults triggered in user
	 * space.  Kernel faults are handled more gracefully.
	 */
	if (flags & FAULT_FLAG_USER)
		mem_cgroup_oom_enable();

	if (!arch_vma_access_permitted(vma, flags & FAULT_FLAG_WRITE,
					    flags & FAULT_FLAG_INSTRUCTION,
					    flags & FAULT_FLAG_REMOTE))
		return VM_FAULT_SIGSEGV;

	if (unlikely(is_vm_hugetlb_page(vma)))
		ret = hugetlb_fault(vma->vm_mm, vma, address, flags);
	else
		ret = __handle_mm_fault(vma, address, flags);

	if (flags & FAULT_FLAG_USER) {
		mem_cgroup_oom_disable();
                /*
                 * The task may have entered a memcg OOM situation but
                 * if the allocation error was handled gracefully (no
                 * VM_FAULT_OOM), there is no need to kill anything.
                 * Just clean up the OOM state peacefully.
                 */
                if (task_in_memcg_oom(current) && !(ret & VM_FAULT_OOM))
                        mem_cgroup_oom_synchronize(false);
	}

	/*
	 * This mm has been already reaped by the oom reaper and so the
	 * refault cannot be trusted in general. Anonymous refaults would
	 * lose data and give a zero page instead e.g. This is especially
	 * problem for use_mm() because regular tasks will just die and
	 * the corrupted data will not be visible anywhere while kthread
	 * will outlive the oom victim and potentially propagate the date
	 * further.
	 */
	if (unlikely((current->flags & PF_KTHREAD) && !(ret & VM_FAULT_ERROR)
				&& test_bit(MMF_UNSTABLE, &vma->vm_mm->flags)))
		ret = VM_FAULT_SIGBUS;

	return ret;
}
EXPORT_SYMBOL_GPL(handle_mm_fault);

#ifndef __PAGETABLE_PUD_FOLDED
/*
 * Allocate page upper directory.
 * We've already handled the fast-path in-line.
 */
int __pud_alloc(struct mm_struct *mm, pgd_t *pgd, unsigned long address)
{
	pud_t *new = pud_alloc_one(mm, address);
	if (!new)
		return -ENOMEM;

	smp_wmb(); /* See comment in __pte_alloc */

	spin_lock(&mm->page_table_lock);
	if (pgd_present(*pgd))		/* Another has populated it */
		pud_free(mm, new);
	else
		pgd_populate(mm, pgd, new);
	spin_unlock(&mm->page_table_lock);
	return 0;
}
#endif /* __PAGETABLE_PUD_FOLDED */

#ifndef __PAGETABLE_PMD_FOLDED
/*
 * Allocate page middle directory.
 * We've already handled the fast-path in-line.
 */
int __pmd_alloc(struct mm_struct *mm, pud_t *pud, unsigned long address)
{
	pmd_t *new = pmd_alloc_one(mm, address);
	if (!new)
		return -ENOMEM;

	smp_wmb(); /* See comment in __pte_alloc */

	spin_lock(&mm->page_table_lock);
#ifndef __ARCH_HAS_4LEVEL_HACK
	if (!pud_present(*pud)) {
		mm_inc_nr_pmds(mm);
		pud_populate(mm, pud, new);
	} else	/* Another has populated it */
		pmd_free(mm, new);
#else
	if (!pgd_present(*pud)) {
		mm_inc_nr_pmds(mm);
		pgd_populate(mm, pud, new);
	} else /* Another has populated it */
		pmd_free(mm, new);
#endif /* __ARCH_HAS_4LEVEL_HACK */
	spin_unlock(&mm->page_table_lock);
	return 0;
}
#endif /* __PAGETABLE_PMD_FOLDED */

static int __follow_pte(struct mm_struct *mm, unsigned long address,
		pte_t **ptepp, spinlock_t **ptlp)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep;

	pgd = pgd_offset(mm, address);
	if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd)))
		goto out;

	pud = pud_offset(pgd, address);
	if (pud_none(*pud) || unlikely(pud_bad(*pud)))
		goto out;

	pmd = pmd_offset(pud, address);
	VM_BUG_ON(pmd_trans_huge(*pmd));
	if (pmd_none(*pmd) || unlikely(pmd_bad(*pmd)))
		goto out;

	/* We cannot handle huge page PFN maps. Luckily they don't exist. */
	if (pmd_huge(*pmd))
		goto out;

	ptep = pte_offset_map_lock(mm, pmd, address, ptlp);
	if (!ptep)
		goto out;
	if (!pte_present(*ptep))
		goto unlock;
	*ptepp = ptep;
	return 0;
unlock:
	pte_unmap_unlock(ptep, *ptlp);
out:
	return -EINVAL;
}

static inline int follow_pte(struct mm_struct *mm, unsigned long address,
			     pte_t **ptepp, spinlock_t **ptlp)
{
	int res;

	/* (void) is needed to make gcc happy */
	(void) __cond_lock(*ptlp,
			   !(res = __follow_pte(mm, address, ptepp, ptlp)));
	return res;
}

/**
 * follow_pfn - look up PFN at a user virtual address
 * @vma: memory mapping
 * @address: user virtual address
 * @pfn: location to store found PFN
 *
 * Only IO mappings and raw PFN mappings are allowed.
 *
 * Returns zero and the pfn at @pfn on success, -ve otherwise.
 */
int follow_pfn(struct vm_area_struct *vma, unsigned long address,
	unsigned long *pfn)
{
	int ret = -EINVAL;
	spinlock_t *ptl;
	pte_t *ptep;

	if (!(vma->vm_flags & (VM_IO | VM_PFNMAP)))
		return ret;

	ret = follow_pte(vma->vm_mm, address, &ptep, &ptl);
	if (ret)
		return ret;
	*pfn = pte_pfn(*ptep);
	pte_unmap_unlock(ptep, ptl);
	return 0;
}
EXPORT_SYMBOL(follow_pfn);

#ifdef CONFIG_HAVE_IOREMAP_PROT
int follow_phys(struct vm_area_struct *vma,
		unsigned long address, unsigned int flags,
		unsigned long *prot, resource_size_t *phys)
{
	int ret = -EINVAL;
	pte_t *ptep, pte;
	spinlock_t *ptl;

	if (!(vma->vm_flags & (VM_IO | VM_PFNMAP)))
		goto out;

	if (follow_pte(vma->vm_mm, address, &ptep, &ptl))
		goto out;
	pte = *ptep;

	if ((flags & FOLL_WRITE) && !pte_write(pte))
		goto unlock;

	*prot = pgprot_val(pte_pgprot(pte));
	*phys = (resource_size_t)pte_pfn(pte) << PAGE_SHIFT;

	ret = 0;
unlock:
	pte_unmap_unlock(ptep, ptl);
out:
	return ret;
}

int generic_access_phys(struct vm_area_struct *vma, unsigned long addr,
			void *buf, int len, int write)
{
	resource_size_t phys_addr;
	unsigned long prot = 0;
	void __iomem *maddr;
	int offset = addr & (PAGE_SIZE-1);

	if (follow_phys(vma, addr, write, &prot, &phys_addr))
		return -EINVAL;

	maddr = ioremap_prot(phys_addr, PAGE_ALIGN(len + offset), prot);
	if (write)
		memcpy_toio(maddr + offset, buf, len);
	else
		memcpy_fromio(buf, maddr + offset, len);
	iounmap(maddr);

	return len;
}
EXPORT_SYMBOL_GPL(generic_access_phys);
#endif

/*
 * Access another process' address space as given in mm.  If non-NULL, use the
 * given task for page fault accounting.
 */
int __access_remote_vm(struct task_struct *tsk, struct mm_struct *mm,
		unsigned long addr, void *buf, int len, unsigned int gup_flags)
{
	struct vm_area_struct *vma;
	void *old_buf = buf;
	int write = gup_flags & FOLL_WRITE;

	down_read(&mm->mmap_sem);
	/* ignore errors, just check how much was successfully transferred */
	while (len) {
		int bytes, ret, offset;
		void *maddr;
		struct page *page = NULL;

		ret = get_user_pages_remote(tsk, mm, addr, 1,
				gup_flags, &page, &vma);
		if (ret <= 0) {
#ifndef CONFIG_HAVE_IOREMAP_PROT
			break;
#else
			/*
			 * Check if this is a VM_IO | VM_PFNMAP VMA, which
			 * we can access using slightly different code.
			 */
			vma = find_vma(mm, addr);
			if (!vma || vma->vm_start > addr)
				break;
			if (vma->vm_ops && vma->vm_ops->access)
				ret = vma->vm_ops->access(vma, addr, buf,
							  len, write);
			if (ret <= 0)
				break;
			bytes = ret;
#endif
		} else {
			bytes = len;
			offset = addr & (PAGE_SIZE-1);
			if (bytes > PAGE_SIZE-offset)
				bytes = PAGE_SIZE-offset;

			maddr = kmap(page);
			if (write) {
				copy_to_user_page(vma, page, addr,
						  maddr + offset, buf, bytes);
				set_page_dirty_lock(page);
			} else {
				copy_from_user_page(vma, page, addr,
						    buf, maddr + offset, bytes);
			}
			kunmap(page);
			put_page(page);
		}
		len -= bytes;
		buf += bytes;
		addr += bytes;
	}
	up_read(&mm->mmap_sem);

	return buf - old_buf;
}

/**
 * access_remote_vm - access another process' address space
 * @mm:		the mm_struct of the target address space
 * @addr:	start address to access
 * @buf:	source or destination buffer
 * @len:	number of bytes to transfer
 * @gup_flags:	flags modifying lookup behaviour
 *
 * The caller must hold a reference on @mm.
 */
int access_remote_vm(struct mm_struct *mm, unsigned long addr,
		void *buf, int len, unsigned int gup_flags)
{
	return __access_remote_vm(NULL, mm, addr, buf, len, gup_flags);
}

/*
 * Access another process' address space.
 * Source/target buffer must be kernel space,
 * Do not walk the page table directly, use get_user_pages
 */
int access_process_vm(struct task_struct *tsk, unsigned long addr,
		void *buf, int len, unsigned int gup_flags)
{
	struct mm_struct *mm;
	int ret;

	mm = get_task_mm(tsk);
	if (!mm)
		return 0;

	ret = __access_remote_vm(tsk, mm, addr, buf, len, gup_flags);

	mmput(mm);

	return ret;
}

/*
 * Print the name of a VMA.
 */
void print_vma_addr(char *prefix, unsigned long ip)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;

	/*
	 * Do not print if we are in atomic
	 * contexts (in exception stacks, etc.):
	 */
	if (preempt_count())
		return;

	down_read(&mm->mmap_sem);
	vma = find_vma(mm, ip);
	if (vma && vma->vm_file) {
		struct file *f = vma->vm_file;
		char *buf = (char *)__get_free_page(GFP_KERNEL);
		if (buf) {
			char *p;

			p = file_path(f, buf, PAGE_SIZE);
			if (IS_ERR(p))
				p = "?";
			printk("%s%s[%lx+%lx]", prefix, kbasename(p),
					vma->vm_start,
					vma->vm_end - vma->vm_start);
			free_page((unsigned long)buf);
		}
	}
	up_read(&mm->mmap_sem);
}

#if defined(CONFIG_PROVE_LOCKING) || defined(CONFIG_DEBUG_ATOMIC_SLEEP)
void __might_fault(const char *file, int line)
{
	/*
	 * Some code (nfs/sunrpc) uses socket ops on kernel memory while
	 * holding the mmap_sem, this is safe because kernel memory doesn't
	 * get paged out, therefore we'll never actually fault, and the
	 * below annotations will generate false positives.
	 */
	if (segment_eq(get_fs(), KERNEL_DS))
		return;
	if (pagefault_disabled())
		return;
	__might_sleep(file, line, 0);
#if defined(CONFIG_DEBUG_ATOMIC_SLEEP)
	if (current->mm)
		might_lock_read(&current->mm->mmap_sem);
#endif
}
EXPORT_SYMBOL(__might_fault);
#endif

#if defined(CONFIG_TRANSPARENT_HUGEPAGE) || defined(CONFIG_HUGETLBFS)
static void clear_gigantic_page(struct page *page,
				unsigned long addr,
				unsigned int pages_per_huge_page)
{
	int i;
	struct page *p = page;

	might_sleep();
	for (i = 0; i < pages_per_huge_page;
	     i++, p = mem_map_next(p, page, i)) {
		cond_resched();
		clear_user_highpage(p, addr + i * PAGE_SIZE);
	}
}
void clear_huge_page(struct page *page,
		     unsigned long addr, unsigned int pages_per_huge_page)
{
	int i;

	if (unlikely(pages_per_huge_page > MAX_ORDER_NR_PAGES)) {
		clear_gigantic_page(page, addr, pages_per_huge_page);
		return;
	}

	might_sleep();
	for (i = 0; i < pages_per_huge_page; i++) {
		cond_resched();
		clear_user_highpage(page + i, addr + i * PAGE_SIZE);
	}
}

static void copy_user_gigantic_page(struct page *dst, struct page *src,
				    unsigned long addr,
				    struct vm_area_struct *vma,
				    unsigned int pages_per_huge_page)
{
	int i;
	struct page *dst_base = dst;
	struct page *src_base = src;

	for (i = 0; i < pages_per_huge_page; ) {
		cond_resched();
		copy_user_highpage(dst, src, addr + i*PAGE_SIZE, vma);

		i++;
		dst = mem_map_next(dst, dst_base, i);
		src = mem_map_next(src, src_base, i);
	}
}

void copy_user_huge_page(struct page *dst, struct page *src,
			 unsigned long addr, struct vm_area_struct *vma,
			 unsigned int pages_per_huge_page)
{
	int i;

	if (unlikely(pages_per_huge_page > MAX_ORDER_NR_PAGES)) {
		copy_user_gigantic_page(dst, src, addr, vma,
					pages_per_huge_page);
		return;
	}

	might_sleep();
	for (i = 0; i < pages_per_huge_page; i++) {
		cond_resched();
		copy_user_highpage(dst + i, src + i, addr + i*PAGE_SIZE, vma);
	}
}
#endif /* CONFIG_TRANSPARENT_HUGEPAGE || CONFIG_HUGETLBFS */

#if USE_SPLIT_PTE_PTLOCKS && ALLOC_SPLIT_PTLOCKS

static struct kmem_cache *page_ptl_cachep;

void __init ptlock_cache_init(void)
{
	page_ptl_cachep = kmem_cache_create("page->ptl", sizeof(spinlock_t), 0,
			SLAB_PANIC, NULL);
}

bool ptlock_alloc(struct page *page)
{
	spinlock_t *ptl;

	ptl = kmem_cache_alloc(page_ptl_cachep, GFP_KERNEL);
	if (!ptl)
		return false;
	page->ptl = ptl;
	return true;
}

void ptlock_free(struct page *page)
{
	kmem_cache_free(page_ptl_cachep, page->ptl);
}
#endif
