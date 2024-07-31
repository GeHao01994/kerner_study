/*
 * Contiguous Memory Allocator
 *
 * Copyright (c) 2010-2011 by Samsung Electronics.
 * Copyright IBM Corporation, 2013
 * Copyright LG Electronics Inc., 2014
 * Written by:
 *	Marek Szyprowski <m.szyprowski@samsung.com>
 *	Michal Nazarewicz <mina86@mina86.com>
 *	Aneesh Kumar K.V <aneesh.kumar@linux.vnet.ibm.com>
 *	Joonsoo Kim <iamjoonsoo.kim@lge.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License or (at your optional) any later version of the license.
 */

#define pr_fmt(fmt) "cma: " fmt

#ifdef CONFIG_CMA_DEBUG
#ifndef DEBUG
#  define DEBUG
#endif
#endif
#define CREATE_TRACE_POINTS

#include <linux/memblock.h>
#include <linux/err.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/log2.h>
#include <linux/cma.h>
#include <linux/highmem.h>
#include <linux/io.h>
#include <trace/events/cma.h>

#include "cma.h"

struct cma cma_areas[MAX_CMA_AREAS];
unsigned cma_area_count;
static DEFINE_MUTEX(cma_mutex);

phys_addr_t cma_get_base(const struct cma *cma)
{
	return PFN_PHYS(cma->base_pfn);
}

unsigned long cma_get_size(const struct cma *cma)
{
	return cma->count << PAGE_SHIFT;
}

static unsigned long cma_bitmap_aligned_mask(const struct cma *cma,
					     int align_order)
{
	if (align_order <= cma->order_per_bit)
		return 0;
	return (1UL << (align_order - cma->order_per_bit)) - 1;
}

/*
 * Find a PFN aligned to the specified order and return an offset represented in
 * order_per_bits.
 */
static unsigned long cma_bitmap_aligned_offset(const struct cma *cma,
					       int align_order)
{
	if (align_order <= cma->order_per_bit)
		return 0;

	return (ALIGN(cma->base_pfn, (1UL << align_order))
		- cma->base_pfn) >> cma->order_per_bit;
}

static unsigned long cma_bitmap_pages_to_bits(const struct cma *cma,
					      unsigned long pages)
{
	return ALIGN(pages, 1UL << cma->order_per_bit) >> cma->order_per_bit;
}

static void cma_clear_bitmap(struct cma *cma, unsigned long pfn,
			     unsigned int count)
{
	unsigned long bitmap_no, bitmap_count;

	bitmap_no = (pfn - cma->base_pfn) >> cma->order_per_bit;
	bitmap_count = cma_bitmap_pages_to_bits(cma, count);

	mutex_lock(&cma->lock);
	bitmap_clear(cma->bitmap, bitmap_no, bitmap_count);
	mutex_unlock(&cma->lock);
}

static int __init cma_activate_area(struct cma *cma)
{
	/* static inline unsigned long cma_bitmap_maxno(struct cma *cma)
	 * {
	 *	return cma->count >> cma->order_per_bit;
	 * }
	 *
	 * 算它位图的大小
	 */
	int bitmap_size = BITS_TO_LONGS(cma_bitmap_maxno(cma)) * sizeof(long);
	unsigned long base_pfn = cma->base_pfn, pfn = base_pfn;
	/* 算出它有多少个pageblock_order */
	unsigned i = cma->count >> pageblock_order;
	struct zone *zone;

	/* 这里就是分配bitmap的内存 */
	cma->bitmap = kzalloc(bitmap_size, GFP_KERNEL);

	if (!cma->bitmap)
		return -ENOMEM;

	/* 如果!pfn_valid,然后报个WARN */pageblock_order
	WARN_ON_ONCE(!pfn_valid(pfn));
	/* 拿到该page的zone */
	zone = page_zone(pfn_to_page(pfn));

	do {
		unsigned j;

		base_pfn = pfn;
		/* 这里就是对该pageblock的每个page去做循环 */
		for (j = pageblock_nr_pages; j; --j, pfn++) {
			WARN_ON_ONCE(!pfn_valid(pfn));
			/*
			 * alloc_contig_range requires the pfn range
			 * specified to be in the same zone. Make this
			 * simple by forcing the entire CMA resv range
			 * to be in the same zone.
			 *
			 * alloc_contig_range要求指定的pfn范围位于同一区域.
			 * 这个通过强制整个CMA resv范围位于同一zone,可以很简单地实现.
			 */

			/* 判断是不是同一个zone,如果不是,那么就goto err */
			if (page_zone(pfn_to_page(pfn)) != zone)
				goto err;
		}
		init_cma_reserved_pageblock(pfn_to_page(base_pfn));
	} while (--i);

	mutex_init(&cma->lock);

#ifdef CONFIG_CMA_DEBUGFS
	INIT_HLIST_HEAD(&cma->mem_head);
	spin_lock_init(&cma->mem_head_lock);
#endif

	return 0;

err:
	kfree(cma->bitmap);
	cma->count = 0;
	return -EINVAL;
}

static int __init cma_init_reserved_areas(void)
{
	int i;

	/* 对每个cma区域进行active */
	for (i = 0; i < cma_area_count; i++) {
		int ret = cma_activate_area(&cma_areas[i]);

		if (ret)
			return ret;
	}

	return 0;
}
core_initcall(cma_init_reserved_areas);

/**
 * cma_init_reserved_mem() - create custom contiguous area from reserved memory
 * @base: Base address of the reserved area
 * @size: Size of the reserved area (in bytes),
 * @order_per_bit: Order of pages represented by one bit on bitmap.
 * @res_cma: Pointer to store the created cma region.
 *
 * This function creates custom contiguous area from already reserved memory.
 */
int __init cma_init_reserved_mem(phys_addr_t base, phys_addr_t size,
				 unsigned int order_per_bit,
				 struct cma **res_cma)
{
	struct cma *cma;
	phys_addr_t alignment;

	/* Sanity checks */
	/* 如果cma_area_count == ARRAY_SIZE(cma_areas),说明已经满了,那么直接返回-ENOSPC */
	if (cma_area_count == ARRAY_SIZE(cma_areas)) {
		pr_err("Not enough slots for CMA reserved regions!\n");
		return -ENOSPC;
	}

	/* 如果size为0,或者说memblock不是reserves区域,那么也返回-EINVAL */
	if (!size || !memblock_is_region_reserved(base, size))
		return -EINVAL;

	/* ensure minimal alignment required by mm core */
	/* 确保mm core所需的最小对齐 */
	alignment = PAGE_SIZE <<
			max_t(unsigned long, MAX_ORDER - 1, pageblock_order);

	/* alignment should be aligned with order_per_bit
	 * alignment应与order_per_bit对齐
	 */
	if (!IS_ALIGNED(alignment >> PAGE_SHIFT, 1 << order_per_bit))
		return -EINVAL;

	/* 如果base和size没有align,那么直接返回-EINVAL */
	if (ALIGN(base, alignment) != base || ALIGN(size, alignment) != size)
		return -EINVAL;

	/*
	 * Each reserved area must be initialised later, when more kernel
	 * subsystems (like slab allocator) are available.
	 *
	 * 稍后,当有更多的内核子系统(如slab分配器)可用时,必须对每个保留区域进行初始化
	 */

	/* 取一个cma_areas结构体 */
	cma = &cma_areas[cma_area_count];
	/* 拿到base_pfn */
	cma->base_pfn = PFN_DOWN(base);
	/* count表示它的page数量 */
	cma->count = size >> PAGE_SHIFT;
	/* 设置cma->order_per_bit */
	cma->order_per_bit = order_per_bit;
	/* 把这个cma返回出去 */
	*res_cma = cma;
	/* cma_area_count++ */
	cma_area_count++;
	/* totalcma_pages += cma->count */
	totalcma_pages += (size / PAGE_SIZE);

	return 0;
}

/**
 * cma_declare_contiguous() - reserve custom contiguous area
 * @base: Base address of the reserved area optional, use 0 for any
 * @size: Size of the reserved area (in bytes),
 * @limit: End address of the reserved memory (optional, 0 for any).
 * @alignment: Alignment for the CMA area, should be power of 2 or zero
 * @order_per_bit: Order of pages represented by one bit on bitmap.
 * @fixed: hint about where to place the reserved area
 * @res_cma: Pointer to store the created cma region.
 *
 * This function reserves memory from early allocator. It should be
 * called by arch specific code once the early allocator (memblock or bootmem)
 * has been activated and all other subsystems have already allocated/reserved
 * memory. This function allows to create custom reserved areas.
 *
 * If @fixed is true, reserve contiguous area at exactly @base.  If false,
 * reserve in range from @base to @limit.
 *
 * cma_declare_contiguous() - 保留自定义的连续内存区域
 * @base: 保留区域的基地址(可选),如果不指定,则使用 0 表示任意地址.
 * @size: 保留区域的大小(以字节为单位).
 * @limit: 保留内存区域的结束地址(可选),如果不指定,则使用 0 表示任意结束地址.
 * @alignment: CMA区域的对齐要求,应为2的幂或零.
 * @order_per_bit: 在位图中,一个位代表的页面order.
 * @fixed: 提示保留区域应该放置在哪里.
 * @res_cma: 指向存储创建的CMA(连续内存分配器)区域的指针.
 *
 * 这个函数从早期的内存分配器中保留内存.它应该在早期分配器(如memblock或bootmem)被激活且所有其他子系统都已经分配/保留了内存之后,
 * 由特定架构的代码调用.此函数允许创建自定义的保留区域.
 *
 * 如果@fixed为真,则在确切的@base地址上保留连续的内存区域.如果为假,则在@base到@limit的范围内保留内存.
 */
int __init cma_declare_contiguous(phys_addr_t base,
			phys_addr_t size, phys_addr_t limit,
			phys_addr_t alignment, unsigned int order_per_bit,
			bool fixed, struct cma **res_cma)
{
	phys_addr_t memblock_end = memblock_end_of_DRAM();
	phys_addr_t highmem_start;
	int ret = 0;

#ifdef CONFIG_X86
	/*
	 * high_memory isn't direct mapped memory so retrieving its physical
	 * address isn't appropriate.  But it would be useful to check the
	 * physical address of the highmem boundary so it's justifiable to get
	 * the physical address from it.  On x86 there is a validation check for
	 * this case, so the following workaround is needed to avoid it.
	 *
	 * high_memory 并不是直接映射的内存,因此获取它的物理地址是不合适的.
	 * 但是,检查highmem边界的物理地址是有用的,因此从它那里获取物理地址是有正当理由的.
	 * 在 x86 架构上,对于这种情况有一个验证检查,因此需要以下变通方法来避免这个问题
	 */
	highmem_start = __pa_nodebug(high_memory);
#else
	highmem_start = __pa(high_memory);
#endif
	pr_debug("%s(size %pa, base %pa, limit %pa alignment %pa)\n",
		__func__, &size, &base, &limit, &alignment);

	/* 如果说cma_areas已经满了,那么就返回-ENOSPC */
	if (cma_area_count == ARRAY_SIZE(cma_areas)) {
		pr_err("Not enough slots for CMA reserved regions!\n");
		return -ENOSPC;
	}

	/* 如果size为0,那么返回-EINVAL */
	if (!size)
		return -EINVAL;

	/* 如果有align但是align又不是2的order次幂,那么返回-EINVAL */
	if (alignment && !is_power_of_2(alignment))
		return -EINVAL;

	/*
	 * Sanitise input arguments.
	 * 对输入参数进行检验
	 * Pages both ends in CMA area could be merged into adjacent unmovable
	 * migratetype page by page allocator's buddy algorithm. In the case,
	 * you couldn't get a contiguous memory, which is not what we want.
	 *
	 * 在CMA(连续内存分配器)区域的两端,页面可能会被页面分配器的伙伴算法合并到相邻的不可移动迁移类型页中.
	 * 在这种情况下,你可能无法获得连续的内存,而这并不是我们想要的.
	 */
	/* 这里就要算出alignment和PAGE_SIZE <<(MAX_ORDER - 1,pageblock_order的最大值)的最大值 */
	alignment = max(alignment,  (phys_addr_t)PAGE_SIZE <<
			  max_t(unsigned long, MAX_ORDER - 1, pageblock_order));
	/* 让base进行ALIGN */
	base = ALIGN(base, alignment);
	/* size进行ALIGN */
	size = ALIGN(size, alignment);
	/* limit也进行align的操作 */
	limit &= ~(alignment - 1);

	/* 如果base等于0,那么设置fixed设置为false */
	if (!base)
		fixed = false;

	/* size should be aligned with order_per_bit */
	/* 如果size >> PAGE_SHIFT没有和order_per_bit对齐,那么也返回-EINVAL */
	if (!IS_ALIGNED(size >> PAGE_SHIFT, 1 << order_per_bit))
		return -EINVAL;

	/*
	 * If allocating at a fixed base the request region must not cross the
	 * low/high memory boundary.
	 *
	 * 如果在固定基地址进行分配,那么请求的区域必须不能跨越低内存(low memory)和高内存(high memory)的边界.
	 */

	/* 如果fixed定义了,如果base < highmem_start < base + size,说明他跨越了低内存和高内存的边界,那么报个err之后返回-EINVAL */
	if (fixed && base < highmem_start && base + size > highmem_start) {
		ret = -EINVAL;
		pr_err("Region at %pa defined on low/high memory boundary (%pa)\n",
			&base, &highmem_start);
		goto err;
	}

	/*
	 * If the limit is unspecified or above the memblock end, its effective
	 * value will be the memblock end. Set it explicitly to simplify further
	 * checks.
	 *
	 * 如果限制未指定或高于memblock的结束地址,那么它的有效值将被视为memblock的结束地址.
	 * 为了简化后续的检查,建议明确设置这个限制
	 */

	if (limit == 0 || limit > memblock_end)
		limit = memblock_end;

	/* Reserve memory */
	if (fixed) {
		/* 如果这块区域已经是reserves了,那么直接返回-EBUSY
		 * 如果这块区域还不是reserves,那么把它添加到reserves
		 */
		if (memblock_is_region_reserved(base, size) ||
		    memblock_reserve(base, size) < 0) {
			ret = -EBUSY;
			goto err;
		}
	} else {
		phys_addr_t addr = 0;

		/*
		 * All pages in the reserved area must come from the same zone.
		 * If the requested region crosses the low/high memory boundary,
		 * try allocating from high memory first and fall back to low
		 * memory in case of failure.
		 *
		 * 保留区域中的所有页面必须来自同一zone.
		 * 如果请求的区域越过低/高内存边界,请尝试先从高内存分配,如果失败,则回退到低内存.
		 */

		/* 如果base < highmen_start < limit */
		if (base < highmem_start && limit > highmem_start) {
			/* 从highmem_start ~ limit分配memblock */
			addr = memblock_alloc_range(size, alignment,
						    highmem_start, limit,
						    MEMBLOCK_NONE);
			limit = highmem_start;
		}

		/* 如果addr是空 */
		if (!addr) {
			/* 那么从base - limit分配memblock */
			addr = memblock_alloc_range(size, alignment, base,
						    limit,
						    MEMBLOCK_NONE);
			if (!addr) {
				ret = -ENOMEM;
				goto err;
			}
		}

		/*
		 * kmemleak scans/reads tracked objects for pointers to other
		 * objects but this address isn't mapped and accessible
		 *
		 * kmemleak扫描/读取被跟踪的对象以查找指向其他对象的指针,但此地址未映射且无法访问
		 */
		kmemleak_ignore_phys(addr);
		/* 设置base */
		base = addr;
	}

	/* cma_init_reserved_mem从保留内存块里面获取一块地址为base、大小为size的内存,用解析出来的地址信息来初始化CMA */
	ret = cma_init_reserved_mem(base, size, order_per_bit, res_cma);
	if (ret)
		goto err;

	pr_info("Reserved %ld MiB at %pa\n", (unsigned long)size / SZ_1M,
		&base);
	return 0;

err:
	pr_err("Failed to reserve %ld MiB\n", (unsigned long)size / SZ_1M);
	return ret;
}

/**
 * cma_alloc() - allocate pages from contiguous area
 * @cma:   Contiguous memory region for which the allocation is performed.
 * @count: Requested number of pages.
 * @align: Requested alignment of pages (in PAGE_SIZE order).
 *
 * This function allocates part of contiguous memory on specific
 * contiguous memory area.
 */
struct page *cma_alloc(struct cma *cma, size_t count, unsigned int align)
{
	unsigned long mask, offset;
	unsigned long pfn = -1;
	unsigned long start = 0;
	unsigned long bitmap_maxno, bitmap_no, bitmap_count;
	struct page *page = NULL;
	int ret;

	if (!cma || !cma->count)
		return NULL;

	pr_debug("%s(cma %p, count %zu, align %d)\n", __func__, (void *)cma,
		 count, align);

	if (!count)
		return NULL;

	mask = cma_bitmap_aligned_mask(cma, align);
	offset = cma_bitmap_aligned_offset(cma, align);
	bitmap_maxno = cma_bitmap_maxno(cma);
	bitmap_count = cma_bitmap_pages_to_bits(cma, count);

	if (bitmap_count > bitmap_maxno)
		return NULL;

	for (;;) {
		mutex_lock(&cma->lock);
		bitmap_no = bitmap_find_next_zero_area_off(cma->bitmap,
				bitmap_maxno, start, bitmap_count, mask,
				offset);
		if (bitmap_no >= bitmap_maxno) {
			mutex_unlock(&cma->lock);
			break;
		}
		bitmap_set(cma->bitmap, bitmap_no, bitmap_count);
		/*
		 * It's safe to drop the lock here. We've marked this region for
		 * our exclusive use. If the migration fails we will take the
		 * lock again and unmark it.
		 */
		mutex_unlock(&cma->lock);

		pfn = cma->base_pfn + (bitmap_no << cma->order_per_bit);
		mutex_lock(&cma_mutex);
		ret = alloc_contig_range(pfn, pfn + count, MIGRATE_CMA);
		mutex_unlock(&cma_mutex);
		if (ret == 0) {
			page = pfn_to_page(pfn);
			break;
		}

		cma_clear_bitmap(cma, pfn, count);
		if (ret != -EBUSY)
			break;

		pr_debug("%s(): memory range at %p is busy, retrying\n",
			 __func__, pfn_to_page(pfn));
		/* try again with a bit different memory target */
		start = bitmap_no + mask + 1;
	}

	trace_cma_alloc(pfn, page, count, align);

	pr_debug("%s(): returned %p\n", __func__, page);
	return page;
}

/**
 * cma_release() - release allocated pages
 * @cma:   Contiguous memory region for which the allocation is performed.
 * @pages: Allocated pages.
 * @count: Number of allocated pages.
 *
 * This function releases memory allocated by alloc_cma().
 * It returns false when provided pages do not belong to contiguous area and
 * true otherwise.
 */
bool cma_release(struct cma *cma, const struct page *pages, unsigned int count)
{
	unsigned long pfn;

	if (!cma || !pages)
		return false;

	pr_debug("%s(page %p)\n", __func__, (void *)pages);

	pfn = page_to_pfn(pages);

	if (pfn < cma->base_pfn || pfn >= cma->base_pfn + cma->count)
		return false;

	VM_BUG_ON(pfn + count > cma->base_pfn + cma->count);

	free_contig_range(pfn, count);
	cma_clear_bitmap(cma, pfn, count);
	trace_cma_release(pfn, pages, count);

	return true;
}
