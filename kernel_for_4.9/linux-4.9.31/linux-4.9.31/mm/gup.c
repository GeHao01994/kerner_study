#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/spinlock.h>

#include <linux/mm.h>
#include <linux/memremap.h>
#include <linux/pagemap.h>
#include <linux/rmap.h>
#include <linux/swap.h>
#include <linux/swapops.h>

#include <linux/sched.h>
#include <linux/rwsem.h>
#include <linux/hugetlb.h>

#include <asm/mmu_context.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>

#include "internal.h"

static struct page *no_page_table(struct vm_area_struct *vma,
		unsigned int flags)
{
	/*
	 * When core dumping an enormous anonymous area that nobody
	 * has touched so far, we don't want to allocate unnecessary pages or
	 * page tables.  Return error instead of NULL to skip handle_mm_fault,
	 * then get_dump_page() will return NULL to leave a hole in the dump.
	 * But we can only make this optimization where a hole would surely
	 * be zero-filled if handle_mm_fault() actually did handle it.
	 *
	 * 当core dumping到目前为止还没有人接触过的巨大匿名区域时,我们不想分配不必要的页面或页面表.
	 * 返回error而不是NULL 以跳过handle_mm_fault,然后get_dump_page()将返回NULL以在转储中留下一个洞.
	 * 但是,如果handle_mm_fault()确实处理了一个洞,那么我们只能在这个洞肯定是零填充的情况下进行优化。
	 */
	if ((flags & FOLL_DUMP) && (!vma->vm_ops || !vma->vm_ops->fault))
		return ERR_PTR(-EFAULT);
	return NULL;
}

static int follow_pfn_pte(struct vm_area_struct *vma, unsigned long address,
		pte_t *pte, unsigned int flags)
{
	/* No page to get reference */
	/* 如果flags带有FOLL_GET,返回-EFAULT */
	if (flags & FOLL_GET)
		return -EFAULT;

	/* 如果flags设置了FOLL_TOUCH时,需要标记page可访问 */
	if (flags & FOLL_TOUCH) {
		pte_t entry = *pte;

		/* 如果flags包含FOLL_WRITE,表示可写,表示该pte为drity */
		if (flags & FOLL_WRITE)
			entry = pte_mkdirty(entry);
		/*  static inline pte_t pte_mkyoung(pte_t pte)
		 * {
		 *	return set_pte_bit(pte, __pgprot(PTE_AF));
		 * }
		 *
		 * 标记该pte为可访问的
		 */
		entry = pte_mkyoung(entry);

		/* 如果说pte和entry不同,也就是说改变了某些属性,那么把它从新设置下去 */
		if (!pte_same(*pte, entry)) {
			set_pte_at(vma->vm_mm, address, pte, entry);
			update_mmu_cache(vma, address, pte);
		}
	}

	/* Proper page table entry exists, but no corresponding struct page
	 * 存在适当的页表条目,但没有相应的结构页
	 */
	return -EEXIST;
}

/*
 * FOLL_FORCE can write to even unwritable pte's, but only
 * after we've gone through a COW cycle and they are dirty.
 */
static inline bool can_follow_write_pte(pte_t pte, unsigned int flags)
{
	return pte_write(pte) ||
		((flags & FOLL_FORCE) && (flags & FOLL_COW) && pte_dirty(pte));
}

static struct page *follow_page_pte(struct vm_area_struct *vma,
		unsigned long address, pmd_t *pmd, unsigned int flags)
{
	struct mm_struct *mm = vma->vm_mm;
	struct dev_pagemap *pgmap = NULL;
	struct page *page;
	spinlock_t *ptl;
	pte_t *ptep, pte;

retry:
	/* 如果pmd是坏的,那么返回NULL */
	if (unlikely(pmd_bad(*pmd)))
		return no_page_table(vma, flags);

	/* pte_offset_map_lock宏通过PMD和地址addr获取pte页表项,这里还获取一个spinlock锁,
	 * 这个函数在返回时需要调用pte_unmap_unlock来释放spinlock锁.
	 */
	ptep = pte_offset_map_lock(mm, pmd, address, &ptl);
	pte = *ptep;
	/* pte_present判断pte页表中的L_PTE_PRESENT位是否置位,L_PTE_PRESENT标志位表示该页在内存中
	 * 下面是不在内存中的情况
	 */
	if (!pte_present(pte)) {
		swp_entry_t entry;
		/*
		 * KSM's break_ksm() relies upon recognizing a ksm page
		 * even while it is being migrated, so for that case we
		 * need migration_entry_wait().
		 *
		 * KSM的break_ksm依赖于识别一个ksm页面,即使它正在被迁移,所以在这种情况下,我们需要migration_entry_wait()
		 */

		/* 如果flags没有定义FOLL_MIGRATION,即这个页面没有在页面合并过程中,那么错误返回 */
		if (likely(!(flags & FOLL_MIGRATION)))
			goto no_page;
		/* 如果pte为空,则错误返回 */
		if (pte_none(pte))
			goto no_page;
		/* 如果pte是正在合并中的swap页面,那么调用migration_entry_wait合并完成后再尝试 */
		entry = pte_to_swp_entry(pte);
		if (!is_migration_entry(entry))
			goto no_page;
		pte_unmap_unlock(ptep, ptl);
		migration_entry_wait(mm, pmd, address);
		goto retry;
	}
	if ((flags & FOLL_NUMA) && pte_protnone(pte))
		goto no_page;
	/* 如果flags支持可写属性(FOLL_WRITE),但是pte的表项只具有只读属性,那么返回NULL */
	if ((flags & FOLL_WRITE) && !can_follow_write_pte(pte, flags)) {
		pte_unmap_unlock(ptep, ptl);
		return NULL;
	}

	/* vm_normal_page函数根据pte来返回normal mapping页面的struct page数据结构 */
	page = vm_normal_page(vma, address, pte);
	/* 如果page为NULL,并且是_PAGE_DEVMAP(ARM64 没有),并且flag带有FOLL_GET */
	if (!page && pte_devmap(pte) && (flags & FOLL_GET)) {
		/*
		 * Only return device mapping pages in the FOLL_GET case since
		 * they are only valid while holding the pgmap reference.
		 *
		 * 仅在FOLL_GET情况下返回设备映射页,因为它们仅在保存pgmap引用时有效.
		 */
		pgmap = get_dev_pagemap(pte_pfn(pte), NULL);
		if (pgmap)
			page = pte_page(pte);
		else
			goto no_page;
		/* 如果page为NULL */
	} else if (unlikely(!page)) {
		/* 如果flags带有FOLL_DUMP */
		if (flags & FOLL_DUMP) {
			/* Avoid special (like zero) pages in core dumps
			 * 避免在core dumps中使用特殊(如零)页面
			 */
			page = ERR_PTR(-EFAULT);
			goto out;
		}

		/* 如果是零页面,那么返回零页面的struct page */
		if (is_zero_pfn(pte_pfn(pte))) {
			page = pte_page(pte);
		} else {
			int ret;

			ret = follow_pfn_pte(vma, address, ptep, flags);
			page = ERR_PTR(ret);
			goto out;
		}
	}

	/* 这里就是切割大页 */
	if (flags & FOLL_SPLIT && PageTransCompound(page)) {
		int ret;
		get_page(page);
		pte_unmap_unlock(ptep, ptl);
		lock_page(page);
		ret = split_huge_page(page);
		unlock_page(page);
		put_page(page);
		if (ret)
			return ERR_PTR(ret);
		goto retry;
	}

	/* 如果flags设置了FOLL_GET,get_page会增加page的_refcount计数 */
	if (flags & FOLL_GET) {
		get_page(page);

		/* drop the pgmap reference now that we hold the page */
		if (pgmap) {
			put_dev_pagemap(pgmap);
			pgmap = NULL;
		}
	}
	/* 如果flags设置了FOLL_TOUCH,需要标记page可访问 */
	if (flags & FOLL_TOUCH) {
		/* 如果flags带有了FOLL_WRITE,表示是可写的
		 * 但是drity位没被设置,PG_Dirty也没被设置
		 * 那么设置PG_Dirty位
		 */
		if ((flags & FOLL_WRITE) &&
		    !pte_dirty(pte) && !PageDirty(page))
			set_page_dirty(page);
		/*
		 * pte_mkyoung() would be more correct here, but atomic care
		 * is needed to avoid losing the dirty bit: it is easier to use
		 * mark_page_accessed().
		 *
		 * pte_mkyoung()在这里更正确，但atomic 照顾是需要的注意避免丢失脏位:
		 * 使用mark_page_accessed()更容易
		 */
		mark_page_accessed(page);
	}
	/* 如果flags & FOLL_MLOCK并且vma->vm_flags & VM_LOCKED */
	if ((flags & FOLL_MLOCK) && (vma->vm_flags & VM_LOCKED)) {
		/* Do not mlock pte-mapped THP
		 * 不要mlock pte-mapped的THP
		 */
		if (PageTransCompound(page))
			goto out;

		/*
		 * The preliminary mapping check is mainly to avoid the
		 * pointless overhead of lock_page on the ZERO_PAGE
		 * which might bounce very badly if there is contention.
		 *
		 * If the page is already locked, we don't need to
		 * handle it now - vmscan will handle it later if and
		 * when it attempts to reclaim the page.
		 *
		 * 初步映射检查主要是为了避免在ZERO_PAGE上lock_page的无意义开销,如果存在争用,这种开销可能会非常严重地反弹.
		 *
		 * 如果页面已经被锁定,我们现在不需要处理它 - 如果vmscan尝试回收页面,它稍后会处理它。
		 */
		if (page->mapping && trylock_page(page)) {
			lru_add_drain();  /* push cached pages to LRU */
			/*
			 * Because we lock page here, and migration is
			 * blocked by the pte's page reference, and we
			 * know the page is still mapped, we don't even
			 * need to check for file-cache page truncation.
			 *
			 * 因为我们在这里锁定了页面,并且pte的页面引用阻止了迁移,
			 * 所以我们知道页面仍然被映射,我们甚至不需要检查文件缓存页面截断.
			 */
			mlock_vma_page(page);
			unlock_page(page);
		}
	}
out:
	pte_unmap_unlock(ptep, ptl);
	return page;
no_page:
	pte_unmap_unlock(ptep, ptl);
	if (!pte_none(pte))
		return NULL;
	return no_page_table(vma, flags);
}

/**
 * follow_page_mask - look up a page descriptor from a user-virtual address
 * @vma: vm_area_struct mapping @address
 * @address: virtual address to look up
 * @flags: flags modifying lookup behaviour
 * @page_mask: on output, *page_mask is set according to the size of the page
 *
 * @flags can have FOLL_ flags set, defined in <linux/mm.h>
 *
 * Returns the mapped (struct page *), %NULL if no mapping exists, or
 * an error pointer if there is a mapping to something not represented
 * by a page descriptor (see also vm_normal_page()).
 *
 * follow_page_mask - 从用户虚拟地址查找页面描述符
 * @vma: 映射@address的vm_area-struct
 * @address：要查找的虚拟地址
 * @flags: 修改查找行为的标志
 * @page_mask: 输出时,根据页面大小设置*page_mask
 *
 * @flags 可以设置FOLL_标志,在<linux/mm.h>中定义
 *
 * 返回映射的(struct page*),如果不存在映射,则返回 %NULL,
 * 如果存在到未由页描述符表示的内容的映射,则返返回错误指针(另请参阅vm_normal_page()).
 */
struct page *follow_page_mask(struct vm_area_struct *vma,
			      unsigned long address, unsigned int flags,
			      unsigned int *page_mask)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	spinlock_t *ptl;
	struct page *page;
	struct mm_struct *mm = vma->vm_mm;

	*page_mask = 0;

	page = follow_huge_addr(mm, address, flags & FOLL_WRITE);
	if (!IS_ERR(page)) {
		BUG_ON(flags & FOLL_GET);
		return page;
	}

	/* 首先通过pgd_offset辅助函数由mm和地址addr找到当前进程页表对应的PGD页面目录项.
	 * 用户进程内存管理的struct mm_struct数据结构的pgd成员(mm->pgd)指向用户进程的页表的基地址
	 */
	pgd = pgd_offset(mm, address);
	/* 如果PGD页表项的内容为空,或表项无效,那么报错返回 */
	if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd)))
		return no_page_table(vma, flags);

	/* 通过pgd找pud */
	pud = pud_offset(pgd, address);
	/* 如果pud是none,返回NULL */
	if (pud_none(*pud))
		return no_page_table(vma, flags);

	/* 如果pud是块映射,且vma->vm_flags带有VM_HUGETLB标志 */
	if (pud_huge(*pud) && vma->vm_flags & VM_HUGETLB) {
		/* 返回对应的page */
		page = follow_huge_pud(mm, address, pud, flags);
		/* 如果有page,那么返回page结构体 */
		if (page)
			return page;
		/* 否则报错返回 */
		return no_page_table(vma, flags);
	}
	/* 如果pud为bad,那么也返回NULL,或者报错返回 */
	if (unlikely(pud_bad(*pud)))
		return no_page_table(vma, flags);

	/* 通过pud找到pmd */
	pmd = pmd_offset(pud, address);
	/* 如果pmd为NULL,那么报错返回 */
	if (pmd_none(*pmd))
		return no_page_table(vma, flags);
	/* 如果pmd是块映射,并且vma->vm_flags带有VM_HUGETLB标志 */
	if (pmd_huge(*pmd) && vma->vm_flags & VM_HUGETLB) {
		/* 找到对应的page */
		page = follow_huge_pmd(mm, address, pmd, flags);
		 /* 如果有page,那么返回page结构体 */
		if (page)
			return page;
		/* 否则报错返回 */
		return no_page_table(vma, flags);
	}

	/* 如果flags带有FOLL_NUMA,并且
	 * (pte_val(pte) & (PTE_VALID | PTE_PROT_NONE)) == PTE_PROT_NONE;
	 * 也就是说!PTE_VALID
	 * 那么报错返回
	 */
	if ((flags & FOLL_NUMA) && pmd_protnone(*pmd))
		return no_page_table(vma, flags);
	if (pmd_devmap(*pmd)) {
		ptl = pmd_lock(mm, pmd);
		page = follow_devmap_pmd(vma, address, pmd, flags);
		spin_unlock(ptl);
		if (page)
			return page;
	}

	/* 如果pmd不是块映射
	 * #define pmd_trans_huge(pmd)	(pmd_val(pmd) && !(pmd_val(pmd) & PMD_TABLE_BIT))
	 */
	if (likely(!pmd_trans_huge(*pmd)))
		return follow_page_pte(vma, address, pmd, flags);

	ptl = pmd_lock(mm, pmd);
	if (unlikely(!pmd_trans_huge(*pmd))) {
		spin_unlock(ptl);
		return follow_page_pte(vma, address, pmd, flags);
	}
	if (flags & FOLL_SPLIT) {
		int ret;
		page = pmd_page(*pmd);
		if (is_huge_zero_page(page)) {
			spin_unlock(ptl);
			ret = 0;
			split_huge_pmd(vma, pmd, address);
			if (pmd_trans_unstable(pmd))
				ret = -EBUSY;
		} else {
			get_page(page);
			spin_unlock(ptl);
			lock_page(page);
			ret = split_huge_page(page);
			unlock_page(page);
			put_page(page);
			if (pmd_none(*pmd))
				return no_page_table(vma, flags);
		}

		return ret ? ERR_PTR(ret) :
			follow_page_pte(vma, address, pmd, flags);
	}

	page = follow_trans_huge_pmd(vma, address, pmd, flags);
	spin_unlock(ptl);
	*page_mask = HPAGE_PMD_NR - 1;
	return page;
}

static int get_gate_page(struct mm_struct *mm, unsigned long address,
		unsigned int gup_flags, struct vm_area_struct **vma,
		struct page **page)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	int ret = -EFAULT;

	/* user gate pages are read-only */
	if (gup_flags & FOLL_WRITE)
		return -EFAULT;
	if (address > TASK_SIZE)
		pgd = pgd_offset_k(address);
	else
		pgd = pgd_offset_gate(mm, address);
	BUG_ON(pgd_none(*pgd));
	pud = pud_offset(pgd, address);
	BUG_ON(pud_none(*pud));
	pmd = pmd_offset(pud, address);
	if (pmd_none(*pmd))
		return -EFAULT;
	VM_BUG_ON(pmd_trans_huge(*pmd));
	pte = pte_offset_map(pmd, address);
	if (pte_none(*pte))
		goto unmap;
	*vma = get_gate_vma(mm);
	if (!page)
		goto out;
	*page = vm_normal_page(*vma, address, *pte);
	if (!*page) {
		if ((gup_flags & FOLL_DUMP) || !is_zero_pfn(pte_pfn(*pte)))
			goto unmap;
		*page = pte_page(*pte);
	}
	get_page(*page);
out:
	ret = 0;
unmap:
	pte_unmap(pte);
	return ret;
}

/*
 * mmap_sem must be held on entry.  If @nonblocking != NULL and
 * *@flags does not include FOLL_NOWAIT, the mmap_sem may be released.
 * If it is, *@nonblocking will be set to 0 and -EBUSY returned.
 */
static int faultin_page(struct task_struct *tsk, struct vm_area_struct *vma,
		unsigned long address, unsigned int *flags, int *nonblocking)
{
	unsigned int fault_flags = 0;
	int ret;

	/* mlock all present pages, but do not fault in new pages */
	if ((*flags & (FOLL_POPULATE | FOLL_MLOCK)) == FOLL_MLOCK)
		return -ENOENT;
	/* For mm_populate(), just skip the stack guard page. */
	if ((*flags & FOLL_POPULATE) &&
			(stack_guard_page_start(vma, address) ||
			 stack_guard_page_end(vma, address + PAGE_SIZE)))
		return -ENOENT;
	if (*flags & FOLL_WRITE)
		fault_flags |= FAULT_FLAG_WRITE;
	if (*flags & FOLL_REMOTE)
		fault_flags |= FAULT_FLAG_REMOTE;
	if (nonblocking)
		fault_flags |= FAULT_FLAG_ALLOW_RETRY;
	if (*flags & FOLL_NOWAIT)
		fault_flags |= FAULT_FLAG_ALLOW_RETRY | FAULT_FLAG_RETRY_NOWAIT;
	if (*flags & FOLL_TRIED) {
		VM_WARN_ON_ONCE(fault_flags & FAULT_FLAG_ALLOW_RETRY);
		fault_flags |= FAULT_FLAG_TRIED;
	}

	ret = handle_mm_fault(vma, address, fault_flags);
	if (ret & VM_FAULT_ERROR) {
		if (ret & VM_FAULT_OOM)
			return -ENOMEM;
		if (ret & (VM_FAULT_HWPOISON | VM_FAULT_HWPOISON_LARGE))
			return *flags & FOLL_HWPOISON ? -EHWPOISON : -EFAULT;
		if (ret & (VM_FAULT_SIGBUS | VM_FAULT_SIGSEGV))
			return -EFAULT;
		BUG();
	}

	if (tsk) {
		if (ret & VM_FAULT_MAJOR)
			tsk->maj_flt++;
		else
			tsk->min_flt++;
	}

	if (ret & VM_FAULT_RETRY) {
		if (nonblocking)
			*nonblocking = 0;
		return -EBUSY;
	}

	/*
	 * The VM_FAULT_WRITE bit tells us that do_wp_page has broken COW when
	 * necessary, even if maybe_mkwrite decided not to set pte_write. We
	 * can thus safely do subsequent page lookups as if they were reads.
	 * But only do so when looping for pte_write is futile: in some cases
	 * userspace may also be wanting to write to the gotten user page,
	 * which a read fault here might prevent (a readonly page might get
	 * reCOWed by userspace write).
	 */
	if ((ret & VM_FAULT_WRITE) && !(vma->vm_flags & VM_WRITE))
	        *flags |= FOLL_COW;
	return 0;
}

static int check_vma_flags(struct vm_area_struct *vma, unsigned long gup_flags)
{
	vm_flags_t vm_flags = vma->vm_flags;
	int write = (gup_flags & FOLL_WRITE);
	int foreign = (gup_flags & FOLL_REMOTE);

	if (vm_flags & (VM_IO | VM_PFNMAP))
		return -EFAULT;

	if (write) {
		if (!(vm_flags & VM_WRITE)) {
			if (!(gup_flags & FOLL_FORCE))
				return -EFAULT;
			/*
			 * We used to let the write,force case do COW in a
			 * VM_MAYWRITE VM_SHARED !VM_WRITE vma, so ptrace could
			 * set a breakpoint in a read-only mapping of an
			 * executable, without corrupting the file (yet only
			 * when that file had been opened for writing!).
			 * Anon pages in shared mappings are surprising: now
			 * just reject it.
			 */
			if (!is_cow_mapping(vm_flags))
				return -EFAULT;
		}
	} else if (!(vm_flags & VM_READ)) {
		if (!(gup_flags & FOLL_FORCE))
			return -EFAULT;
		/*
		 * Is there actually any vma we can reach here which does not
		 * have VM_MAYREAD set?
		 */
		if (!(vm_flags & VM_MAYREAD))
			return -EFAULT;
	}
	/*
	 * gups are always data accesses, not instruction
	 * fetches, so execute=false here
	 */
	if (!arch_vma_access_permitted(vma, write, false, foreign))
		return -EFAULT;
	return 0;
}

/**
 * __get_user_pages() - pin user pages in memory
 * @tsk:	task_struct of target task
 * @mm:		mm_struct of target mm
 * @start:	starting user address
 * @nr_pages:	number of pages from start to pin
 * @gup_flags:	flags modifying pin behaviour
 * @pages:	array that receives pointers to the pages pinned.
 *		Should be at least nr_pages long. Or NULL, if caller
 *		only intends to ensure the pages are faulted in.
 * @vmas:	array of pointers to vmas corresponding to each page.
 *		Or NULL if the caller does not require them.
 * @nonblocking: whether waiting for disk IO or mmap_sem contention
 *
 * _get_user_pages() - 在内存中固定用户页面
 * @tsk:	目标task的task_struct
 * @mm:		目标mm的mm_struct
 * @start:	起始用户地址
 * @nr_pages:	从开始到结束的页数
 * @gup_flags:	修改pin行为的标志
 * @pages:	接收指向固定页面的指针的数组。
 *		应至少为nr_pages长.
 *		或者NULL,如果调用者只想确保页面faulted in.
 * @vmas:	指向与每个页面对应的vmas的指针数组.如果调用方不需要它们，则为NULL。
 * @nonblocking:是否等待磁盘IO或mmap_sem争用
 *
 * Returns number of pages pinned. This may be fewer than the number
 * requested. If nr_pages is 0 or negative, returns 0. If no pages
 * were pinned, returns -errno. Each page returned must be released
 * with a put_page() call when it is finished with. vmas will only
 * remain valid while mmap_sem is held.
 *
 * 返回固定的页数. 这可能少于请求的数量.如果nr_pages为0或为负数,则返回0.
 * 如果没有固定任何页面,则返回-errno.
 * 返回的每个页面在完成时都必须通过put_page()调用来释放.
 * vmas将仅在mmap_sem保持期间保持有效。
 *
 * Must be called with mmap_sem held.  It may be released.  See below.
 * 必须在保持mmap_sem的情况下调用.它可能会被释放.请参见下文。
 *
 *
 * __get_user_pages walks a process's page tables and takes a reference to
 * each struct page that each user address corresponds to at a given
 * instant. That is, it takes the page that would be accessed if a user
 * thread accesses the given user virtual address at that instant.
 *
 * _get_user_pages遍历进程的页面表,并引用每个用户地址在给定时刻对应的每个结构页面.
 * 也就是说,如果用户线程在该时刻访问给定的用户虚拟地址,它将获取将被访问的页面.
 *
 * This does not guarantee that the page exists in the user mappings when
 * __get_user_pages returns, and there may even be a completely different
 * page there in some cases (eg. if mmapped pagecache has been invalidated
 * and subsequently re faulted). However it does guarantee that the page
 * won't be freed completely. And mostly callers simply care that the page
 * contains data that was valid *at some point in time*. Typically, an IO
 * or similar operation cannot guarantee anything stronger anyway because
 * locks can't be held over the syscall boundary.
 *
 * 当__get_user_pages返回时,这并不能保证该页面存在于用户映射中,
 * 在某些情况下甚至可能存在完全不同的页面(例如,如果mmapped pagecache已无效,随后再次出现故障).
 * 然而,它确实保证了页面不会被完全释放.
 * 大多数调用方只关心页面是否包含在某个时间点有效的数据.
 * 通常,IO或类似操作无论如何都不能保证任何更强的东西,因为锁不能在系统调用边界上持有。
 *
 * If @gup_flags & FOLL_WRITE == 0, the page must not be written to. If
 * the page is written to, set_page_dirty (or set_page_dirty_lock, as
 * appropriate) must be called after the page is finished with, and
 * before put_page is called.
 *
 * 如果@gup_flags & FOLL_WRITE == 0,则不得写入该页.
 * 如果写入该页,则必须在完成该页之后,调用put_page之前调用set_page_dirty(或set_page_dirty_lock,视情况而定).
 *
 * If @nonblocking != NULL, __get_user_pages will not wait for disk IO
 * or mmap_sem contention, and if waiting is needed to pin all pages,
 * *@nonblocking will be set to 0.  Further, if @gup_flags does not
 * include FOLL_NOWAIT, the mmap_sem will be released via up_read() in
 * this case.
 *
 * 如果@nonblocking != NULL,__get_user_pages将不会等待磁盘IO或mmap_sem争用,
 * 如果需要等待来固定所有页面,*@nonblocking将设置为0.
 * 此外,如果@gup_flags不包括FOLL_NOWAIT,则在这种情况下,mmap_sem将通过up_read()释放。
 *
 * A caller using such a combination of @nonblocking and @gup_flags
 * must therefore hold the mmap_sem for reading only, and recognize
 * when it's been released.  Otherwise, it must be held for either
 * reading or writing and will not be released.
 *
 * 因此,使用@nonblocking和@gup_flags组合的调用程序必须持有mmap_sem以便只读,并识别它何时被释放.
 * 否则,它必须被保持以供读或写,并且不会被释放.
 *
 * In most cases, get_user_pages or get_user_pages_fast should be used
 * instead of __get_user_pages. __get_user_pages should be used only if
 * you need some special @gup_flags.
 *
 * 在大多数情况下,应使用get_user_pages或get_user_pages_fast,而不是__get_user_pages.
 * 只有当您需要一些特殊的@gup_flags时,才应该使用__get_user_pages。
 */
static long __get_user_pages(struct task_struct *tsk, struct mm_struct *mm,
		unsigned long start, unsigned long nr_pages,
		unsigned int gup_flags, struct page **pages,
		struct vm_area_struct **vmas, int *nonblocking)
{
	long i = 0;
	unsigned int page_mask;
	struct vm_area_struct *vma = NULL;

	/* 如果nr_pages等于0,那么返回0 */
	if (!nr_pages)
		return 0;

	VM_BUG_ON(!!pages != !!(gup_flags & FOLL_GET));

	/*
	 * If FOLL_FORCE is set then do not force a full fault as the hinting
	 * fault information is unrelated to the reference behaviour of a task
	 * using the address space
	 *
	 *
	 * 如果设置了FOLL_FORCE,则不要强制执行完全fault,因为提示fault信息与使用地址空间的任务的引用行为无关
	 */
	/* #define FOLL_FORCE	0x10	get_user_pages read/write w/o permission */
	/* 如果没有定义FOLL_FORCE,那么就带上FOLL_NUMA */
	if (!(gup_flags & FOLL_FORCE))
		gup_flags |= FOLL_NUMA;

	do {
		struct page *page;
		unsigned int foll_flags = gup_flags;
		unsigned int page_increm;

		/* first iteration or cross vma bound
		 * 第一次迭代或跨越了vma边界
		 *
		 * 如果vma为NULL,或者说start >= vma->vm_end
		 */
		if (!vma || start >= vma->vm_end) {
			/* find_extend_vma函数查找VMA,它会调用find_vma查找VMA.
			 * 如果VMA->start大于查找地址start,那么它尝试去扩增VMA,把VMA->vm_start边界扩大到start中
			 */
			vma = find_extend_vma(mm, start);
			/* 如果find_extend_vma没有找到合适的VMA,且start地址恰好在gata_vma中,那么使用gate页面,当然这种情况比较罕见
			 */
			if (!vma && in_gate_area(mm, start)) {
				int ret;
				ret = get_gate_page(mm, start & PAGE_MASK,
						gup_flags, &vma,
						pages ? &pages[i] : NULL);
				if (ret)
					return i ? : ret;
				page_mask = 0;
				goto next_page;
			}

			if (!vma || check_vma_flags(vma, gup_flags))
				return i ? : -EFAULT;
			if (is_vm_hugetlb_page(vma)) {
				i = follow_hugetlb_page(mm, vma, pages, vmas,
						&start, &nr_pages, i,
						gup_flags);
				continue;
			}
		}
retry:
		/*
		 * If we have a pending SIGKILL, don't keep faulting pages and
		 * potentially allocating memory.
		 */

		/* 如果当前进程收到了一个SIGKILL信号,那么不需要继续做内存分配,直接报错退出 */
		if (unlikely(fatal_signal_pending(current)))
			return i ? i : -ERESTARTSYS;
		/* cond_resched判断当前进程是否需要被调度,内核代码通常在while循环中添加cond_resched,从而优化系统的延迟 */
		cond_resched();
		/* 调用follow_page_mask查看VMA中的虚拟页面是否已经分配了物理内存 */
		page = follow_page_mask(vma, start, foll_flags, &page_mask);
		if (!page) {
			int ret;
			ret = faultin_page(tsk, vma, start, &foll_flags,
					nonblocking);
			switch (ret) {
			case 0:
				goto retry;
			case -EFAULT:
			case -ENOMEM:
			case -EHWPOISON:
				return i ? i : ret;
			case -EBUSY:
				return i;
			case -ENOENT:
				goto next_page;
			}
			BUG();
		} else if (PTR_ERR(page) == -EEXIST) {
			/*
			 * Proper page table entry exists, but no corresponding
			 * struct page.
			 */
			goto next_page;
		} else if (IS_ERR(page)) {
			return i ? i : PTR_ERR(page);
		}
		if (pages) {
			pages[i] = page;
			flush_anon_page(vma, page, start);
			flush_dcache_page(page);
			page_mask = 0;
		}
next_page:
		if (vmas) {
			vmas[i] = vma;
			page_mask = 0;
		}
		page_increm = 1 + (~(start >> PAGE_SHIFT) & page_mask);
		if (page_increm > nr_pages)
			page_increm = nr_pages;
		i += page_increm;
		start += page_increm * PAGE_SIZE;
		nr_pages -= page_increm;
	} while (nr_pages);
	return i;
}

bool vma_permits_fault(struct vm_area_struct *vma, unsigned int fault_flags)
{
	bool write   = !!(fault_flags & FAULT_FLAG_WRITE);
	bool foreign = !!(fault_flags & FAULT_FLAG_REMOTE);
	vm_flags_t vm_flags = write ? VM_WRITE : VM_READ;

	if (!(vm_flags & vma->vm_flags))
		return false;

	/*
	 * The architecture might have a hardware protection
	 * mechanism other than read/write that can deny access.
	 *
	 * gup always represents data access, not instruction
	 * fetches, so execute=false here:
	 */
	if (!arch_vma_access_permitted(vma, write, false, foreign))
		return false;

	return true;
}

/*
 * fixup_user_fault() - manually resolve a user page fault
 * @tsk:	the task_struct to use for page fault accounting, or
 *		NULL if faults are not to be recorded.
 * @mm:		mm_struct of target mm
 * @address:	user address
 * @fault_flags:flags to pass down to handle_mm_fault()
 * @unlocked:	did we unlock the mmap_sem while retrying, maybe NULL if caller
 *		does not allow retry
 *
 * This is meant to be called in the specific scenario where for locking reasons
 * we try to access user memory in atomic context (within a pagefault_disable()
 * section), this returns -EFAULT, and we want to resolve the user fault before
 * trying again.
 *
 * Typically this is meant to be used by the futex code.
 *
 * The main difference with get_user_pages() is that this function will
 * unconditionally call handle_mm_fault() which will in turn perform all the
 * necessary SW fixup of the dirty and young bits in the PTE, while
 * get_user_pages() only guarantees to update these in the struct page.
 *
 * This is important for some architectures where those bits also gate the
 * access permission to the page because they are maintained in software.  On
 * such architectures, gup() will not be enough to make a subsequent access
 * succeed.
 *
 * This function will not return with an unlocked mmap_sem. So it has not the
 * same semantics wrt the @mm->mmap_sem as does filemap_fault().
 */
int fixup_user_fault(struct task_struct *tsk, struct mm_struct *mm,
		     unsigned long address, unsigned int fault_flags,
		     bool *unlocked)
{
	struct vm_area_struct *vma;
	int ret, major = 0;

	if (unlocked)
		fault_flags |= FAULT_FLAG_ALLOW_RETRY;

retry:
	vma = find_extend_vma(mm, address);
	if (!vma || address < vma->vm_start)
		return -EFAULT;

	if (!vma_permits_fault(vma, fault_flags))
		return -EFAULT;

	ret = handle_mm_fault(vma, address, fault_flags);
	major |= ret & VM_FAULT_MAJOR;
	if (ret & VM_FAULT_ERROR) {
		if (ret & VM_FAULT_OOM)
			return -ENOMEM;
		if (ret & (VM_FAULT_HWPOISON | VM_FAULT_HWPOISON_LARGE))
			return -EHWPOISON;
		if (ret & (VM_FAULT_SIGBUS | VM_FAULT_SIGSEGV))
			return -EFAULT;
		BUG();
	}

	if (ret & VM_FAULT_RETRY) {
		down_read(&mm->mmap_sem);
		if (!(fault_flags & FAULT_FLAG_TRIED)) {
			*unlocked = true;
			fault_flags &= ~FAULT_FLAG_ALLOW_RETRY;
			fault_flags |= FAULT_FLAG_TRIED;
			goto retry;
		}
	}

	if (tsk) {
		if (major)
			tsk->maj_flt++;
		else
			tsk->min_flt++;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(fixup_user_fault);

static __always_inline long __get_user_pages_locked(struct task_struct *tsk,
						struct mm_struct *mm,
						unsigned long start,
						unsigned long nr_pages,
						struct page **pages,
						struct vm_area_struct **vmas,
						int *locked, bool notify_drop,
						unsigned int flags)
{
	long ret, pages_done;
	bool lock_dropped;

	if (locked) {
		/* if VM_FAULT_RETRY can be returned, vmas become invalid */
		BUG_ON(vmas);
		/* check caller initialized locked */
		BUG_ON(*locked != 1);
	}

	if (pages)
		flags |= FOLL_GET;

	pages_done = 0;
	lock_dropped = false;
	for (;;) {
		ret = __get_user_pages(tsk, mm, start, nr_pages, flags, pages,
				       vmas, locked);
		if (!locked)
			/* VM_FAULT_RETRY couldn't trigger, bypass */
			return ret;

		/* VM_FAULT_RETRY cannot return errors */
		if (!*locked) {
			BUG_ON(ret < 0);
			BUG_ON(ret >= nr_pages);
		}

		if (!pages)
			/* If it's a prefault don't insist harder */
			return ret;

		if (ret > 0) {
			nr_pages -= ret;
			pages_done += ret;
			if (!nr_pages)
				break;
		}
		if (*locked) {
			/* VM_FAULT_RETRY didn't trigger */
			if (!pages_done)
				pages_done = ret;
			break;
		}
		/* VM_FAULT_RETRY triggered, so seek to the faulting offset */
		pages += ret;
		start += ret << PAGE_SHIFT;

		/*
		 * Repeat on the address that fired VM_FAULT_RETRY
		 * without FAULT_FLAG_ALLOW_RETRY but with
		 * FAULT_FLAG_TRIED.
		 */
		*locked = 1;
		lock_dropped = true;
		down_read(&mm->mmap_sem);
		ret = __get_user_pages(tsk, mm, start, 1, flags | FOLL_TRIED,
				       pages, NULL, NULL);
		if (ret != 1) {
			BUG_ON(ret > 1);
			if (!pages_done)
				pages_done = ret;
			break;
		}
		nr_pages--;
		pages_done++;
		if (!nr_pages)
			break;
		pages++;
		start += PAGE_SIZE;
	}
	if (notify_drop && lock_dropped && *locked) {
		/*
		 * We must let the caller know we temporarily dropped the lock
		 * and so the critical section protected by it was lost.
		 */
		up_read(&mm->mmap_sem);
		*locked = 0;
	}
	return pages_done;
}

/*
 * We can leverage the VM_FAULT_RETRY functionality in the page fault
 * paths better by using either get_user_pages_locked() or
 * get_user_pages_unlocked().
 *
 * get_user_pages_locked() is suitable to replace the form:
 *
 *      down_read(&mm->mmap_sem);
 *      do_something()
 *      get_user_pages(tsk, mm, ..., pages, NULL);
 *      up_read(&mm->mmap_sem);
 *
 *  to:
 *
 *      int locked = 1;
 *      down_read(&mm->mmap_sem);
 *      do_something()
 *      get_user_pages_locked(tsk, mm, ..., pages, &locked);
 *      if (locked)
 *          up_read(&mm->mmap_sem);
 */
long get_user_pages_locked(unsigned long start, unsigned long nr_pages,
			   unsigned int gup_flags, struct page **pages,
			   int *locked)
{
	return __get_user_pages_locked(current, current->mm, start, nr_pages,
				       pages, NULL, locked, true,
				       gup_flags | FOLL_TOUCH);
}
EXPORT_SYMBOL(get_user_pages_locked);

/*
 * Same as get_user_pages_unlocked(...., FOLL_TOUCH) but it allows to
 * pass additional gup_flags as last parameter (like FOLL_HWPOISON).
 *
 * NOTE: here FOLL_TOUCH is not set implicitly and must be set by the
 * caller if required (just like with __get_user_pages). "FOLL_GET",
 * "FOLL_WRITE" and "FOLL_FORCE" are set implicitly as needed
 * according to the parameters "pages", "write", "force"
 * respectively.
 */
__always_inline long __get_user_pages_unlocked(struct task_struct *tsk, struct mm_struct *mm,
					       unsigned long start, unsigned long nr_pages,
					       struct page **pages, unsigned int gup_flags)
{
	long ret;
	int locked = 1;

	down_read(&mm->mmap_sem);
	ret = __get_user_pages_locked(tsk, mm, start, nr_pages, pages, NULL,
				      &locked, false, gup_flags);
	if (locked)
		up_read(&mm->mmap_sem);
	return ret;
}
EXPORT_SYMBOL(__get_user_pages_unlocked);

/*
 * get_user_pages_unlocked() is suitable to replace the form:
 *
 *      down_read(&mm->mmap_sem);
 *      get_user_pages(tsk, mm, ..., pages, NULL);
 *      up_read(&mm->mmap_sem);
 *
 *  with:
 *
 *      get_user_pages_unlocked(tsk, mm, ..., pages);
 *
 * It is functionally equivalent to get_user_pages_fast so
 * get_user_pages_fast should be used instead, if the two parameters
 * "tsk" and "mm" are respectively equal to current and current->mm,
 * or if "force" shall be set to 1 (get_user_pages_fast misses the
 * "force" parameter).
 */
long get_user_pages_unlocked(unsigned long start, unsigned long nr_pages,
			     struct page **pages, unsigned int gup_flags)
{
	return __get_user_pages_unlocked(current, current->mm, start, nr_pages,
					 pages, gup_flags | FOLL_TOUCH);
}
EXPORT_SYMBOL(get_user_pages_unlocked);

/*
 * get_user_pages_remote() - pin user pages in memory
 * @tsk:	the task_struct to use for page fault accounting, or
 *		NULL if faults are not to be recorded.
 * @mm:		mm_struct of target mm
 * @start:	starting user address
 * @nr_pages:	number of pages from start to pin
 * @gup_flags:	flags modifying lookup behaviour
 * @pages:	array that receives pointers to the pages pinned.
 *		Should be at least nr_pages long. Or NULL, if caller
 *		only intends to ensure the pages are faulted in.
 * @vmas:	array of pointers to vmas corresponding to each page.
 *		Or NULL if the caller does not require them.
 *
 * Returns number of pages pinned. This may be fewer than the number
 * requested. If nr_pages is 0 or negative, returns 0. If no pages
 * were pinned, returns -errno. Each page returned must be released
 * with a put_page() call when it is finished with. vmas will only
 * remain valid while mmap_sem is held.
 *
 * Must be called with mmap_sem held for read or write.
 *
 * get_user_pages walks a process's page tables and takes a reference to
 * each struct page that each user address corresponds to at a given
 * instant. That is, it takes the page that would be accessed if a user
 * thread accesses the given user virtual address at that instant.
 *
 * This does not guarantee that the page exists in the user mappings when
 * get_user_pages returns, and there may even be a completely different
 * page there in some cases (eg. if mmapped pagecache has been invalidated
 * and subsequently re faulted). However it does guarantee that the page
 * won't be freed completely. And mostly callers simply care that the page
 * contains data that was valid *at some point in time*. Typically, an IO
 * or similar operation cannot guarantee anything stronger anyway because
 * locks can't be held over the syscall boundary.
 *
 * If gup_flags & FOLL_WRITE == 0, the page must not be written to. If the page
 * is written to, set_page_dirty (or set_page_dirty_lock, as appropriate) must
 * be called after the page is finished with, and before put_page is called.
 *
 * get_user_pages is typically used for fewer-copy IO operations, to get a
 * handle on the memory by some means other than accesses via the user virtual
 * addresses. The pages may be submitted for DMA to devices or accessed via
 * their kernel linear mapping (via the kmap APIs). Care should be taken to
 * use the correct cache flushing APIs.
 *
 * See also get_user_pages_fast, for performance critical applications.
 *
 * get_user_pages should be phased out in favor of
 * get_user_pages_locked|unlocked or get_user_pages_fast. Nothing
 * should use get_user_pages because it cannot pass
 * FAULT_FLAG_ALLOW_RETRY to handle_mm_fault.
 */
long get_user_pages_remote(struct task_struct *tsk, struct mm_struct *mm,
		unsigned long start, unsigned long nr_pages,
		unsigned int gup_flags, struct page **pages,
		struct vm_area_struct **vmas)
{
	return __get_user_pages_locked(tsk, mm, start, nr_pages, pages, vmas,
				       NULL, false,
				       gup_flags | FOLL_TOUCH | FOLL_REMOTE);
}
EXPORT_SYMBOL(get_user_pages_remote);

/*
 * This is the same as get_user_pages_remote(), just with a
 * less-flexible calling convention where we assume that the task
 * and mm being operated on are the current task's.  We also
 * obviously don't pass FOLL_REMOTE in here.
 */
long get_user_pages(unsigned long start, unsigned long nr_pages,
		unsigned int gup_flags, struct page **pages,
		struct vm_area_struct **vmas)
{
	return __get_user_pages_locked(current, current->mm, start, nr_pages,
				       pages, vmas, NULL, false,
				       gup_flags | FOLL_TOUCH);
}
EXPORT_SYMBOL(get_user_pages);

/**
 * populate_vma_page_range() -  populate a range of pages in the vma.
 * @vma:   target vma
 * @start: start address
 * @end:   end address
 * @nonblocking:
 *
 * This takes care of mlocking the pages too if VM_LOCKED is set.
 *
 * return 0 on success, negative error code on error.
 *
 * vma->vm_mm->mmap_sem must be held.
 *
 * If @nonblocking is NULL, it may be held for read or write and will
 * be unperturbed.
 *
 * If @nonblocking is non-NULL, it must held for read only and may be
 * released.  If it's released, *@nonblocking will be set to 0.
 *
 * populate_vma_page_range() - 填充vma中的一系列页面.
 * @vma: 目标vma
 * @start: 起始地址
 * @end: 结束地址
 * @nonblocking:
 *
 * 如果设置了VM_LOCKED,这也会处理锁定页面的问题.
 *
 * 成功时返回0,错误时返回负错误代码.
 * 必须保持vma->vm_mm->mmap_sem
 *
 * 如果@nonblocking为NULL，则它可能被保留用于读取或写入,并且不会受到干扰.
 *
 * 如果@nonblocking为非NULL,则它必须保持为只读,并且可以释放.
 * 如果它被释放,*@nonblocking将被设置为0。
 */
long populate_vma_page_range(struct vm_area_struct *vma,
		unsigned long start, unsigned long end, int *nonblocking)
{
	struct mm_struct *mm = vma->vm_mm;
	/* 算出页面数量 */
	unsigned long nr_pages = (end - start) / PAGE_SIZE;
	int gup_flags;

	VM_BUG_ON(start & ~PAGE_MASK);
	VM_BUG_ON(end   & ~PAGE_MASK);
	VM_BUG_ON_VMA(start < vma->vm_start, vma);
	VM_BUG_ON_VMA(end   > vma->vm_end, vma);
	VM_BUG_ON_MM(!rwsem_is_locked(&mm->mmap_sem), mm);

	/* #define FOLL_TOUCH		0x02		mark page accessed 标记页面可访问
	 * #define FOLL_POPULATE	0x40		fault in page
	 * #define FOLL_MLOCK		0x1000		lock present pages
	 */
	gup_flags = FOLL_TOUCH | FOLL_POPULATE | FOLL_MLOCK;

	/* #define VM_LOCKONFAULT	0x00080000	Lock the pages covered when they are faulted in
	 *						在faulted in时锁定所覆盖的page
	 */
	if (vma->vm_flags & VM_LOCKONFAULT)
		gup_flags &= ~FOLL_POPULATE;
	/*
	 * We want to touch writable mappings with a write fault in order
	 * to break COW, except for shared mappings because these don't COW
	 * and we would not want to dirty them for nothing.
	 *
	 *
	 * 除了共享映射之外,我们希望用write fault来触发可写映射,以破坏COW,
	 * 因为共享映射不具有COW,我们不想白白弄脏它们.
	 */
	if ((vma->vm_flags & (VM_WRITE | VM_SHARED)) == VM_WRITE)
		gup_flags |= FOLL_WRITE;

	/*
	 * We want mlock to succeed for regions that have any permissions
	 * other than PROT_NONE.
	 *
	 * 我们希望mlock对具有PROT_NONE以外的任何权限的区域成功.
	 */
	if (vma->vm_flags & (VM_READ | VM_WRITE | VM_EXEC))
		gup_flags |= FOLL_FORCE;

	/*
	 * We made sure addr is within a VMA, so the following will
	 * not result in a stack expansion that recurses back here.
	 *
	 * 我们确保addr在VMA中,因此以下操作不会导致堆扩展重复出现在此处.
	 */
	return __get_user_pages(current, mm, start, nr_pages, gup_flags,
				NULL, NULL, nonblocking);
}

/*
 * __mm_populate - populate and/or mlock pages within a range of address space.
 *
 * This is used to implement mlock() and the MAP_POPULATE / MAP_LOCKED mmap
 * flags. VMAs must be already marked with the desired vm_flags, and
 * mmap_sem must not be held.
 *
 * __mm_populate-在地址空间范围内填充 and/or mlock页面.
 *
 * 这用于实现mlock()和MAP_POPULATE/MAP_LOCKED mmap标志.
 * VMA必须已经标记有所需的vm_flags,并且不能持有mmap_sem.
 */
int __mm_populate(unsigned long start, unsigned long len, int ignore_errors)
{
	struct mm_struct *mm = current->mm;
	unsigned long end, nstart, nend;
	struct vm_area_struct *vma = NULL;
	int locked = 0;
	long ret = 0;

	/* 如果start不是按page对齐,那么报个BUG */
	VM_BUG_ON(start & ~PAGE_MASK);
	/* 如果长度不是按PAGE对齐,那么也报个BUG */
	VM_BUG_ON(len != PAGE_ALIGN(len));
	/* end = start + len */
	end = start + len;

	/* 然后这里开始循环 */
	for (nstart = start; nstart < end; nstart = nend) {
		/*
		 * We want to fault in pages for [nstart; end) address range.
		 * Find first corresponding VMA.
		 *
		 * 我们想在[nstart；end）地址范围内fault in pages.
		 * 首先查找相应的VMA.
		 */

		/* 如果还没有锁,那么锁住之后find_vma */
		if (!locked) {
			locked = 1;
			down_read(&mm->mmap_sem);
			vma = find_vma(mm, nstart);
		} else if (nstart >= vma->vm_end)
			vma = vma->vm_next;
		/* 如果vma=NULL 或者vma->vm_start >= end
		 * 那么可以break掉了
		 */
		if (!vma || vma->vm_start >= end)
			break;
		/*
		 * Set [nstart; nend) to intersection of desired address
		 * range with the first VMA. Also, skip undesirable VMA types.
		 *
		 * 将[nstart; nend)设置为所需地址范围和第一个VMA的交集.此外,跳过不需要的VMA类型。
		 */

		/* 这里就是让它在nstart和nend范围内 */
		nend = min(end, vma->vm_end);
		if (vma->vm_flags & (VM_IO | VM_PFNMAP))
			continue;
		if (nstart < vma->vm_start)
			nstart = vma->vm_start;
		/*
		 * Now fault in a range of pages. populate_vma_page_range()
		 * double checks the vma flags, so that it won't mlock pages
		 * if the vma was already munlocked.
		 *
		 * 现在fault在一个范围内的pages.
		 * populate_vma_page_range()仔细检查vma标志,这样,如果vma已经解锁,它就不会锁定页面.
		 */
		ret = populate_vma_page_range(vma, nstart, nend, &locked);
		if (ret < 0) {
			if (ignore_errors) {
				ret = 0;
				continue;	/* continue at next VMA */
			}
			break;
		}
		nend = nstart + ret * PAGE_SIZE;
		ret = 0;
	}
	if (locked)
		up_read(&mm->mmap_sem);
	return ret;	/* 0 or negative error code */
}

/**
 * get_dump_page() - pin user page in memory while writing it to core dump
 * @addr: user address
 *
 * Returns struct page pointer of user page pinned for dump,
 * to be freed afterwards by put_page().
 *
 * Returns NULL on any kind of failure - a hole must then be inserted into
 * the corefile, to preserve alignment with its headers; and also returns
 * NULL wherever the ZERO_PAGE, or an anonymous pte_none, has been found -
 * allowing a hole to be left in the corefile to save diskspace.
 *
 * Called without mmap_sem, but after all other threads have been killed.
 */
#ifdef CONFIG_ELF_CORE
struct page *get_dump_page(unsigned long addr)
{
	struct vm_area_struct *vma;
	struct page *page;

	if (__get_user_pages(current, current->mm, addr, 1,
			     FOLL_FORCE | FOLL_DUMP | FOLL_GET, &page, &vma,
			     NULL) < 1)
		return NULL;
	flush_cache_page(vma, addr, page_to_pfn(page));
	return page;
}
#endif /* CONFIG_ELF_CORE */

/*
 * Generic RCU Fast GUP
 *
 * get_user_pages_fast attempts to pin user pages by walking the page
 * tables directly and avoids taking locks. Thus the walker needs to be
 * protected from page table pages being freed from under it, and should
 * block any THP splits.
 *
 * One way to achieve this is to have the walker disable interrupts, and
 * rely on IPIs from the TLB flushing code blocking before the page table
 * pages are freed. This is unsuitable for architectures that do not need
 * to broadcast an IPI when invalidating TLBs.
 *
 * Another way to achieve this is to batch up page table containing pages
 * belonging to more than one mm_user, then rcu_sched a callback to free those
 * pages. Disabling interrupts will allow the fast_gup walker to both block
 * the rcu_sched callback, and an IPI that we broadcast for splitting THPs
 * (which is a relatively rare event). The code below adopts this strategy.
 *
 * Before activating this code, please be aware that the following assumptions
 * are currently made:
 *
 *  *) HAVE_RCU_TABLE_FREE is enabled, and tlb_remove_table is used to free
 *      pages containing page tables.
 *
 *  *) ptes can be read atomically by the architecture.
 *
 *  *) access_ok is sufficient to validate userspace address ranges.
 *
 * The last two assumptions can be relaxed by the addition of helper functions.
 *
 * This code is based heavily on the PowerPC implementation by Nick Piggin.
 */
#ifdef CONFIG_HAVE_GENERIC_RCU_GUP

#ifdef __HAVE_ARCH_PTE_SPECIAL
static int gup_pte_range(pmd_t pmd, unsigned long addr, unsigned long end,
			 int write, struct page **pages, int *nr)
{
	pte_t *ptep, *ptem;
	int ret = 0;

	ptem = ptep = pte_offset_map(&pmd, addr);
	do {
		/*
		 * In the line below we are assuming that the pte can be read
		 * atomically. If this is not the case for your architecture,
		 * please wrap this in a helper function!
		 *
		 * for an example see gup_get_pte in arch/x86/mm/gup.c
		 */
		pte_t pte = READ_ONCE(*ptep);
		struct page *head, *page;

		/*
		 * Similar to the PMD case below, NUMA hinting must take slow
		 * path using the pte_protnone check.
		 */
		if (!pte_present(pte) || pte_special(pte) ||
			pte_protnone(pte) || (write && !pte_write(pte)))
			goto pte_unmap;

		if (!arch_pte_access_permitted(pte, write))
			goto pte_unmap;

		VM_BUG_ON(!pfn_valid(pte_pfn(pte)));
		page = pte_page(pte);
		head = compound_head(page);

		if (!page_cache_get_speculative(head))
			goto pte_unmap;

		if (unlikely(pte_val(pte) != pte_val(*ptep))) {
			put_page(head);
			goto pte_unmap;
		}

		VM_BUG_ON_PAGE(compound_head(page) != head, page);
		pages[*nr] = page;
		(*nr)++;

	} while (ptep++, addr += PAGE_SIZE, addr != end);

	ret = 1;

pte_unmap:
	pte_unmap(ptem);
	return ret;
}
#else

/*
 * If we can't determine whether or not a pte is special, then fail immediately
 * for ptes. Note, we can still pin HugeTLB and THP as these are guaranteed not
 * to be special.
 *
 * For a futex to be placed on a THP tail page, get_futex_key requires a
 * __get_user_pages_fast implementation that can pin pages. Thus it's still
 * useful to have gup_huge_pmd even if we can't operate on ptes.
 */
static int gup_pte_range(pmd_t pmd, unsigned long addr, unsigned long end,
			 int write, struct page **pages, int *nr)
{
	return 0;
}
#endif /* __HAVE_ARCH_PTE_SPECIAL */

static int gup_huge_pmd(pmd_t orig, pmd_t *pmdp, unsigned long addr,
		unsigned long end, int write, struct page **pages, int *nr)
{
	struct page *head, *page;
	int refs;

	if (write && !pmd_write(orig))
		return 0;

	refs = 0;
	head = pmd_page(orig);
	page = head + ((addr & ~PMD_MASK) >> PAGE_SHIFT);
	do {
		VM_BUG_ON_PAGE(compound_head(page) != head, page);
		pages[*nr] = page;
		(*nr)++;
		page++;
		refs++;
	} while (addr += PAGE_SIZE, addr != end);

	if (!page_cache_add_speculative(head, refs)) {
		*nr -= refs;
		return 0;
	}

	if (unlikely(pmd_val(orig) != pmd_val(*pmdp))) {
		*nr -= refs;
		while (refs--)
			put_page(head);
		return 0;
	}

	return 1;
}

static int gup_huge_pud(pud_t orig, pud_t *pudp, unsigned long addr,
		unsigned long end, int write, struct page **pages, int *nr)
{
	struct page *head, *page;
	int refs;

	if (write && !pud_write(orig))
		return 0;

	refs = 0;
	head = pud_page(orig);
	page = head + ((addr & ~PUD_MASK) >> PAGE_SHIFT);
	do {
		VM_BUG_ON_PAGE(compound_head(page) != head, page);
		pages[*nr] = page;
		(*nr)++;
		page++;
		refs++;
	} while (addr += PAGE_SIZE, addr != end);

	if (!page_cache_add_speculative(head, refs)) {
		*nr -= refs;
		return 0;
	}

	if (unlikely(pud_val(orig) != pud_val(*pudp))) {
		*nr -= refs;
		while (refs--)
			put_page(head);
		return 0;
	}

	return 1;
}

static int gup_huge_pgd(pgd_t orig, pgd_t *pgdp, unsigned long addr,
			unsigned long end, int write,
			struct page **pages, int *nr)
{
	int refs;
	struct page *head, *page;

	if (write && !pgd_write(orig))
		return 0;

	refs = 0;
	head = pgd_page(orig);
	page = head + ((addr & ~PGDIR_MASK) >> PAGE_SHIFT);
	do {
		VM_BUG_ON_PAGE(compound_head(page) != head, page);
		pages[*nr] = page;
		(*nr)++;
		page++;
		refs++;
	} while (addr += PAGE_SIZE, addr != end);

	if (!page_cache_add_speculative(head, refs)) {
		*nr -= refs;
		return 0;
	}

	if (unlikely(pgd_val(orig) != pgd_val(*pgdp))) {
		*nr -= refs;
		while (refs--)
			put_page(head);
		return 0;
	}

	return 1;
}

static int gup_pmd_range(pud_t pud, unsigned long addr, unsigned long end,
		int write, struct page **pages, int *nr)
{
	unsigned long next;
	pmd_t *pmdp;

	pmdp = pmd_offset(&pud, addr);
	do {
		pmd_t pmd = READ_ONCE(*pmdp);

		next = pmd_addr_end(addr, end);
		if (pmd_none(pmd))
			return 0;

		if (unlikely(pmd_trans_huge(pmd) || pmd_huge(pmd))) {
			/*
			 * NUMA hinting faults need to be handled in the GUP
			 * slowpath for accounting purposes and so that they
			 * can be serialised against THP migration.
			 */
			if (pmd_protnone(pmd))
				return 0;

			if (!gup_huge_pmd(pmd, pmdp, addr, next, write,
				pages, nr))
				return 0;

		} else if (unlikely(is_hugepd(__hugepd(pmd_val(pmd))))) {
			/*
			 * architecture have different format for hugetlbfs
			 * pmd format and THP pmd format
			 */
			if (!gup_huge_pd(__hugepd(pmd_val(pmd)), addr,
					 PMD_SHIFT, next, write, pages, nr))
				return 0;
		} else if (!gup_pte_range(pmd, addr, next, write, pages, nr))
				return 0;
	} while (pmdp++, addr = next, addr != end);

	return 1;
}

static int gup_pud_range(pgd_t pgd, unsigned long addr, unsigned long end,
			 int write, struct page **pages, int *nr)
{
	unsigned long next;
	pud_t *pudp;

	pudp = pud_offset(&pgd, addr);
	do {
		pud_t pud = READ_ONCE(*pudp);

		next = pud_addr_end(addr, end);
		if (pud_none(pud))
			return 0;
		if (unlikely(pud_huge(pud))) {
			if (!gup_huge_pud(pud, pudp, addr, next, write,
					  pages, nr))
				return 0;
		} else if (unlikely(is_hugepd(__hugepd(pud_val(pud))))) {
			if (!gup_huge_pd(__hugepd(pud_val(pud)), addr,
					 PUD_SHIFT, next, write, pages, nr))
				return 0;
		} else if (!gup_pmd_range(pud, addr, next, write, pages, nr))
			return 0;
	} while (pudp++, addr = next, addr != end);

	return 1;
}

/*
 * Like get_user_pages_fast() except it's IRQ-safe in that it won't fall back to
 * the regular GUP. It will only return non-negative values.
 */
int __get_user_pages_fast(unsigned long start, int nr_pages, int write,
			  struct page **pages)
{
	struct mm_struct *mm = current->mm;
	unsigned long addr, len, end;
	unsigned long next, flags;
	pgd_t *pgdp;
	int nr = 0;

	start &= PAGE_MASK;
	addr = start;
	len = (unsigned long) nr_pages << PAGE_SHIFT;
	end = start + len;

	if (unlikely(!access_ok(write ? VERIFY_WRITE : VERIFY_READ,
					start, len)))
		return 0;

	/*
	 * Disable interrupts.  We use the nested form as we can already have
	 * interrupts disabled by get_futex_key.
	 *
	 * With interrupts disabled, we block page table pages from being
	 * freed from under us. See mmu_gather_tlb in asm-generic/tlb.h
	 * for more details.
	 *
	 * We do not adopt an rcu_read_lock(.) here as we also want to
	 * block IPIs that come from THPs splitting.
	 */

	local_irq_save(flags);
	pgdp = pgd_offset(mm, addr);
	do {
		pgd_t pgd = READ_ONCE(*pgdp);

		next = pgd_addr_end(addr, end);
		if (pgd_none(pgd))
			break;
		if (unlikely(pgd_huge(pgd))) {
			if (!gup_huge_pgd(pgd, pgdp, addr, next, write,
					  pages, &nr))
				break;
		} else if (unlikely(is_hugepd(__hugepd(pgd_val(pgd))))) {
			if (!gup_huge_pd(__hugepd(pgd_val(pgd)), addr,
					 PGDIR_SHIFT, next, write, pages, &nr))
				break;
		} else if (!gup_pud_range(pgd, addr, next, write, pages, &nr))
			break;
	} while (pgdp++, addr = next, addr != end);
	local_irq_restore(flags);

	return nr;
}

/**
 * get_user_pages_fast() - pin user pages in memory
 * @start:	starting user address
 * @nr_pages:	number of pages from start to pin
 * @write:	whether pages will be written to
 * @pages:	array that receives pointers to the pages pinned.
 *		Should be at least nr_pages long.
 *
 * Attempt to pin user pages in memory without taking mm->mmap_sem.
 * If not successful, it will fall back to taking the lock and
 * calling get_user_pages().
 *
 * Returns number of pages pinned. This may be fewer than the number
 * requested. If nr_pages is 0 or negative, returns 0. If no pages
 * were pinned, returns -errno.
 */
int get_user_pages_fast(unsigned long start, int nr_pages, int write,
			struct page **pages)
{
	int nr, ret;

	start &= PAGE_MASK;
	nr = __get_user_pages_fast(start, nr_pages, write, pages);
	ret = nr;

	if (nr < nr_pages) {
		/* Try to get the remaining pages with get_user_pages */
		start += nr << PAGE_SHIFT;
		pages += nr;

		ret = get_user_pages_unlocked(start, nr_pages - nr, pages,
				write ? FOLL_WRITE : 0);

		/* Have to be a bit careful with return values */
		if (nr > 0) {
			if (ret < 0)
				ret = nr;
			else
				ret += nr;
		}
	}

	return ret;
}

#endif /* CONFIG_HAVE_GENERIC_RCU_GUP */
