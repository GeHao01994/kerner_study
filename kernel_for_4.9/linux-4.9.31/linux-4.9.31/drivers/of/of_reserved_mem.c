/*
 * Device tree based initialization code for reserved memory.
 *
 * Copyright (c) 2013, 2015 The Linux Foundation. All Rights Reserved.
 * Copyright (c) 2013,2014 Samsung Electronics Co., Ltd.
 *		http://www.samsung.com
 * Author: Marek Szyprowski <m.szyprowski@samsung.com>
 * Author: Josh Cartwright <joshc@codeaurora.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License or (at your optional) any later version of the license.
 */

#define pr_fmt(fmt)	"OF: reserved mem: " fmt

#include <linux/err.h>
#include <linux/of.h>
#include <linux/of_fdt.h>
#include <linux/of_platform.h>
#include <linux/mm.h>
#include <linux/sizes.h>
#include <linux/of_reserved_mem.h>
#include <linux/sort.h>
#include <linux/slab.h>

#define MAX_RESERVED_REGIONS	16
static struct reserved_mem reserved_mem[MAX_RESERVED_REGIONS];
static int reserved_mem_count;

#if defined(CONFIG_HAVE_MEMBLOCK)
#include <linux/memblock.h>
int __init __weak early_init_dt_alloc_reserved_memory_arch(phys_addr_t size,
	phys_addr_t align, phys_addr_t start, phys_addr_t end, bool nomap,
	phys_addr_t *res_base)
{
	phys_addr_t base;
	/*
	 * We use __memblock_alloc_base() because memblock_alloc_base()
	 * panic()s on allocation failure.
	 *
	 * 我们使用__memblock_alloc_base(),因为memblock_alloc_base会在分配失败时触发panic()
	 *
	 */

	/* 如果end == 0的话
	 * #define MEMBLOCK_ALLOC_ANYWHERE	(~(phys_addr_t)0)
	 * 那么end = 0xffffffff....
	 */
	end = !end ? MEMBLOCK_ALLOC_ANYWHERE : end;
	base = __memblock_alloc_base(size, align, end);
	if (!base)
		return -ENOMEM;

	/*
	 * Check if the allocated region fits in to start..end window
	 *
	 * 检查分配的区域是否适合start..end窗口
	 */

	/* 如果base < start,那么free掉分配的memblock */
	if (base < start) {
		memblock_free(base, size);
		return -ENOMEM;
	}

	/* 把base带出去 */
	*res_base = base;
	if (nomap)
		return memblock_remove(base, size);
	return 0;
}
#else
int __init __weak early_init_dt_alloc_reserved_memory_arch(phys_addr_t size,
	phys_addr_t align, phys_addr_t start, phys_addr_t end, bool nomap,
	phys_addr_t *res_base)
{
	pr_err("Reserved memory not supported, ignoring region 0x%llx%s\n",
		  size, nomap ? " (nomap)" : "");
	return -ENOSYS;
}
#endif

/**
 * res_mem_save_node() - save fdt node for second pass initialization
 */
void __init fdt_reserved_mem_save_node(unsigned long node, const char *uname,
				      phys_addr_t base, phys_addr_t size)
{
	struct reserved_mem *rmem = &reserved_mem[reserved_mem_count];

	if (reserved_mem_count == ARRAY_SIZE(reserved_mem)) {
		pr_err("not enough space all defined regions.\n");
		return;
	}

	rmem->fdt_node = node;
	rmem->name = uname;
	rmem->base = base;
	rmem->size = size;

	reserved_mem_count++;
	return;
}

/**
 * res_mem_alloc_size() - allocate reserved memory described by 'size', 'align'
 *			  and 'alloc-ranges' properties
 *
 * res_mem_alloc_size() - 分配由"size"、"align"和"alloc range"属性描述的保留内存
 */
static int __init __reserved_mem_alloc_size(unsigned long node,
	const char *uname, phys_addr_t *res_base, phys_addr_t *res_size)
{
	int t_len = (dt_root_addr_cells + dt_root_size_cells) * sizeof(__be32);
	phys_addr_t start = 0, end = 0;
	phys_addr_t base = 0, align = 0, size;
	int len;
	const __be32 *prop;
	int nomap;
	int ret;

	/* 如果没有名为"size"的prop,那么直接返回-EINVAL */
	prop = of_get_flat_dt_prop(node, "size", &len);
	if (!prop)
		return -EINVAL;

	if (len != dt_root_size_cells * sizeof(__be32)) {
		pr_err("invalid size property in '%s' node.\n", uname);
		return -EINVAL;
	}

	/* 拿到size */
	size = dt_mem_next_cell(dt_root_size_cells, &prop);

	/* 如果定义了no-map属性,那么nomap就为true */
	nomap = of_get_flat_dt_prop(node, "no-map", NULL) != NULL;

	/* 如果定义了alignment */
	prop = of_get_flat_dt_prop(node, "alignment", &len);
	if (prop) {
		if (len != dt_root_addr_cells * sizeof(__be32)) {
			pr_err("invalid alignment property in '%s' node.\n",
				uname);
			return -EINVAL;
		}
		/* 拿到align */
		align = dt_mem_next_cell(dt_root_addr_cells, &prop);
	}

	/* Need adjust the alignment to satisfy the CMA requirement
	 * 需要调整对齐以满足CMA要求
	 */

	/* 如果定义了CMA,然后
	 * 检查到dts中有compatible匹配(CMA这里为“shared-dma-pool”)
	 * device tree中可以包含reserved-memory node,在该节点的child node中,可以定义各种保留内存的信息。
	 * compatible属性是shared-dma-pool的那个节点是专门用于建立 global CMA area的.
	 *
	 * 对于reusable属性,其有reserved memory这样的属性,当驱动程序不使用这些内存的时候,OS可以使用这些内存;
	 * 而当驱动程序从这个CMA area分配memory的时候,OS可以释放这些内存,让驱动可以使用它.
	 *
	 * no-map属性与地址映射有关,如果没有no-map属性,那么OS就会为这段memory创建地址映射,象其他普通内存一样.
	 * 但是对于no-map属性,往往是专用
	 */
	if (IS_ENABLED(CONFIG_CMA)
	    && of_flat_dt_is_compatible(node, "shared-dma-pool")
	    && of_get_flat_dt_prop(node, "reusable", NULL)
	    && !of_get_flat_dt_prop(node, "no-map", NULL)) {
		/* 如果是CMA区域,那么取pageblock_order和MAX_ORDER - 1的最大值 */
		unsigned long order =
			max_t(unsigned long, MAX_ORDER - 1, pageblock_order);

		/* align就为刚刚order个PAGE */
		align = max(align, (phys_addr_t)PAGE_SIZE << order);
	}

	/* 这里是去找alloc-ranges的prop */
	prop = of_get_flat_dt_prop(node, "alloc-ranges", &len);
	if (prop) {

		if (len % t_len != 0) {
			pr_err("invalid alloc-ranges property in '%s', skipping node.\n",
			       uname);
			return -EINVAL;
		}

		base = 0;

		while (len > 0) {
			/* 拿到该prop的start地址 */
			start = dt_mem_next_cell(dt_root_addr_cells, &prop);
			/* 通过start + size 等到end地址 */
			end = start + dt_mem_next_cell(dt_root_size_cells,
						       &prop);

			/* 去分配内存作为reserves_memory */
			ret = early_init_dt_alloc_reserved_memory_arch(size,
					align, start, end, nomap, &base);
			if (ret == 0) {
				pr_debug("allocated memory for '%s' node: base %pa, size %ld MiB\n",
					uname, &base,
					(unsigned long)size / SZ_1M);
				break;
			}
			len -= t_len;
		}

	} else {
		/* 如果没有分配区域,那么设置去end = memblock.current_limit里面去分配 */
		ret = early_init_dt_alloc_reserved_memory_arch(size, align,
							0, 0, nomap, &base);
		if (ret == 0)
			pr_debug("allocated memory for '%s' node: base %pa, size %ld MiB\n",
				uname, &base, (unsigned long)size / SZ_1M);
	}

	if (base == 0) {
		pr_info("failed to allocate memory for node '%s'\n", uname);
		return -ENOMEM;
	}

	*res_base = base;
	*res_size = size;

	return 0;
}

static const struct of_device_id __rmem_of_table_sentinel
	__used __section(__reservedmem_of_table_end);

/**
 * res_mem_init_node() - call region specific reserved memory init code
 *			 调用特定区域的保留内存初始化代码
 */

/* __reserved_mem_init_node会遍历__reservedmem_of_table section中的内容,检查到dts中有compatible匹配(CMA这里为"shared-dma-pool")就进一步执行对应的initfn.
 * 通过RESERVEDMEM_OF_DECLARE定义的都会被链接到__reservedmem_of_table这个section段中,最终会调到使用RESERVEDMEM_OF_DECLARE定义的函数
 */
static int __init __reserved_mem_init_node(struct reserved_mem *rmem)
{
	extern const struct of_device_id __reservedmem_of_table[];
	const struct of_device_id *i;

	for (i = __reservedmem_of_table; i < &__rmem_of_table_sentinel; i++) {
		reservedmem_of_init_fn initfn = i->data;
		const char *compat = i->compatible;

		if (!of_flat_dt_is_compatible(rmem->fdt_node, compat))
			continue;

		if (initfn(rmem) == 0) {
			pr_info("initialized node %s, compatible id %s\n",
				rmem->name, compat);
			return 0;
		}
	}
	return -ENOENT;
}

static int __init __rmem_cmp(const void *a, const void *b)
{
	const struct reserved_mem *ra = a, *rb = b;

	if (ra->base < rb->base)
		return -1;

	if (ra->base > rb->base)
		return 1;

	return 0;
}

static void __init __rmem_check_for_overlap(void)
{
	int i;

	if (reserved_mem_count < 2)
		return;

	sort(reserved_mem, reserved_mem_count, sizeof(reserved_mem[0]),
	     __rmem_cmp, NULL);
	for (i = 0; i < reserved_mem_count - 1; i++) {
		struct reserved_mem *this, *next;

		this = &reserved_mem[i];
		next = &reserved_mem[i + 1];
		if (!(this->base && next->base))
			continue;
		if (this->base + this->size > next->base) {
			phys_addr_t this_end, next_end;

			this_end = this->base + this->size;
			next_end = next->base + next->size;
			pr_err("OVERLAP DETECTED!\n%s (%pa--%pa) overlaps with %s (%pa--%pa)\n",
			       this->name, &this->base, &this_end,
			       next->name, &next->base, &next_end);
		}
	}
}

/**
 * fdt_init_reserved_mem - allocate and init all saved reserved memory regions
 */
void __init fdt_init_reserved_mem(void)
{
	int i;

	/* check for overlapping reserved regions */
	__rmem_check_for_overlap();

	/* 遍历每一个reserved memory region */
	for (i = 0; i < reserved_mem_count; i++) {
		struct reserved_mem *rmem = &reserved_mem[i];
		unsigned long node = rmem->fdt_node;
		int len;
		const __be32 *prop;
		int err = 0;
		/* 每一个需要被其他node引用的node都需要定义"phandle",或者"linux,phandle".
		 * 虽然在实际的device tree source中看不到这个属性,实际上dtc会完美的处理这一切的.
		 */
		prop = of_get_flat_dt_prop(node, "phandle", &len);
		if (!prop)
			prop = of_get_flat_dt_prop(node, "linux,phandle", &len);
		if (prop)
			rmem->phandle = of_read_number(prop, len/4);
		/* size等于0的memory region表示这是一个动态分配region,base address尚未定义,
		 * 因此我们需要通过__reserved_mem_alloc_size函数对节点进行分析(size、alignment等属性),
		 * 然后调用memblock的alloc接口函数进行memory block的分配,最终的结果是确定base address和size,
		 * 并将这段memory region从memory type的数组中移到reserved type的数组中.
		 * 当然,如果定义了no-map属性,那么这段memory会从系统中之间删除(memory type和reserved type数组中都没有这段memory的定义).
		 */
		if (rmem->size == 0)
			err = __reserved_mem_alloc_size(node, rmem->name,
						 &rmem->base, &rmem->size);
		/* 保留内存有两种使用场景,一种是被特定的驱动使用,这时候在特定驱动的初始化函数(probe函数)中自然会进行处理,
		 * 还有一种场景就是被所有驱动或者内核模块使用,例如CMA，per-device Coherent DMA的分配等,这时候,
		 * 我们需要借用device tree的匹配机制进行这段保留内存的初始化动作.
		 * 有兴趣的话可以看看RESERVEDMEM_OF_DECLARE的定义，这里就不再描述了
		 */

		/* 上面的__reserved_mem_alloc_size一切顺利也会返回0 */
		if (err == 0)
			__reserved_mem_init_node(rmem);
	}
}

static inline struct reserved_mem *__find_rmem(struct device_node *node)
{
	unsigned int i;

	if (!node->phandle)
		return NULL;

	for (i = 0; i < reserved_mem_count; i++)
		if (reserved_mem[i].phandle == node->phandle)
			return &reserved_mem[i];
	return NULL;
}

struct rmem_assigned_device {
	struct device *dev;
	struct reserved_mem *rmem;
	struct list_head list;
};

static LIST_HEAD(of_rmem_assigned_device_list);
static DEFINE_MUTEX(of_rmem_assigned_device_mutex);

/**
 * of_reserved_mem_device_init_by_idx() - assign reserved memory region to
 *					  given device
 * @dev:	Pointer to the device to configure
 * @np:		Pointer to the device_node with 'reserved-memory' property
 * @idx:	Index of selected region
 *
 * This function assigns respective DMA-mapping operations based on reserved
 * memory region specified by 'memory-region' property in @np node to the @dev
 * device. When driver needs to use more than one reserved memory region, it
 * should allocate child devices and initialize regions by name for each of
 * child device.
 *
 * Returns error code or zero on success.
 */
int of_reserved_mem_device_init_by_idx(struct device *dev,
				       struct device_node *np, int idx)
{
	struct rmem_assigned_device *rd;
	struct device_node *target;
	struct reserved_mem *rmem;
	int ret;

	if (!np || !dev)
		return -EINVAL;

	target = of_parse_phandle(np, "memory-region", idx);
	if (!target)
		return -ENODEV;

	rmem = __find_rmem(target);
	of_node_put(target);

	if (!rmem || !rmem->ops || !rmem->ops->device_init)
		return -EINVAL;

	rd = kmalloc(sizeof(struct rmem_assigned_device), GFP_KERNEL);
	if (!rd)
		return -ENOMEM;

	ret = rmem->ops->device_init(rmem, dev);
	if (ret == 0) {
		rd->dev = dev;
		rd->rmem = rmem;

		mutex_lock(&of_rmem_assigned_device_mutex);
		list_add(&rd->list, &of_rmem_assigned_device_list);
		mutex_unlock(&of_rmem_assigned_device_mutex);

		dev_info(dev, "assigned reserved memory node %s\n", rmem->name);
	} else {
		kfree(rd);
	}

	return ret;
}
EXPORT_SYMBOL_GPL(of_reserved_mem_device_init_by_idx);

/**
 * of_reserved_mem_device_release() - release reserved memory device structures
 * @dev:	Pointer to the device to deconfigure
 *
 * This function releases structures allocated for memory region handling for
 * the given device.
 */
void of_reserved_mem_device_release(struct device *dev)
{
	struct rmem_assigned_device *rd;
	struct reserved_mem *rmem = NULL;

	mutex_lock(&of_rmem_assigned_device_mutex);
	list_for_each_entry(rd, &of_rmem_assigned_device_list, list) {
		if (rd->dev == dev) {
			rmem = rd->rmem;
			list_del(&rd->list);
			kfree(rd);
			break;
		}
	}
	mutex_unlock(&of_rmem_assigned_device_mutex);

	if (!rmem || !rmem->ops || !rmem->ops->device_release)
		return;

	rmem->ops->device_release(rmem, dev);
}
EXPORT_SYMBOL_GPL(of_reserved_mem_device_release);
