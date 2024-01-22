/*
 * Based on arch/arm/mm/mmu.c
 *
 * Copyright (C) 1995-2005 Russell King
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

#include <linux/cache.h>
#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/libfdt.h>
#include <linux/mman.h>
#include <linux/nodemask.h>
#include <linux/memblock.h>
#include <linux/fs.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <linux/stop_machine.h>

#include <asm/barrier.h>
#include <asm/cputype.h>
#include <asm/fixmap.h>
#include <asm/kasan.h>
#include <asm/kernel-pgtable.h>
#include <asm/sections.h>
#include <asm/setup.h>
#include <asm/sizes.h>
#include <asm/tlb.h>
#include <asm/memblock.h>
#include <asm/mmu_context.h>

u64 idmap_t0sz = TCR_T0SZ(VA_BITS);

u64 kimage_voffset __ro_after_init;
EXPORT_SYMBOL(kimage_voffset);

/*
 * Empty_zero_page is a special page that is used for zero-initialized data
 * and COW.
 */
unsigned long empty_zero_page[PAGE_SIZE / sizeof(unsigned long)] __page_aligned_bss;
EXPORT_SYMBOL(empty_zero_page);

static pte_t bm_pte[PTRS_PER_PTE] __page_aligned_bss;
static pmd_t bm_pmd[PTRS_PER_PMD] __page_aligned_bss __maybe_unused;
static pud_t bm_pud[PTRS_PER_PUD] __page_aligned_bss __maybe_unused;

pgprot_t phys_mem_access_prot(struct file *file, unsigned long pfn,
			      unsigned long size, pgprot_t vma_prot)
{
	if (!pfn_valid(pfn))
		return pgprot_noncached(vma_prot);
	else if (file->f_flags & O_SYNC)
		return pgprot_writecombine(vma_prot);
	return vma_prot;
}
EXPORT_SYMBOL(phys_mem_access_prot);

static phys_addr_t __init early_pgtable_alloc(void)
{
	phys_addr_t phys;
	void *ptr;
	/* 使用 memblock 函数,找到一页空闲的物理内存,地址是phys */
	phys = memblock_alloc(PAGE_SIZE, PAGE_SIZE);

	/*
	 * The FIX_{PGD,PUD,PMD} slots may be in active use, but the FIX_PTE
	 * slot will be free, so we can (ab)use the FIX_PTE slot to initialise
	 * any level of table.
	 *
	 * FIX_{PGD、PUD、PMD}插槽可能处于活动使用状态，但FIX_PTE插槽将是空闲的,
	 * 所以我们可以（ab）使用FIX_PTE插槽初始化任何级别的表。
	 *
	 * fixmap中,pgd pud pmd对应的虚拟地址可能正在被使用,但是pte对应的虚拟地址肯定是可以被覆盖的。
	 * 因为修改地址转换页表时,需要使用虚拟地址,因为已经使能了MMU,CPU 操作的地址都是VA 地址.
	 * 但是修改完成后,MMU工作时,就仅仅依赖页表里面填写的物理地址了。
	 * 所以,FIXMAP中的pte这个VA地址,哪里需要就映射到哪里,然后就可以使用这个VA 地址,填充里面的值。
	 */

	/* 将找到的物理地址,映射到fixmap总pte idx对应的VA 地址处 */
	ptr = pte_set_fixmap(phys);
	/* 使用 memset 函数进行填充为0 */
	memset(ptr, 0, PAGE_SIZE);

	/*
	 * Implicit barriers also ensure the zeroed page is visible to the page
	 * table walker
	 *
	 * 隐式屏障也确保0页对页表 walker是可视的
	 */
	pte_clear_fixmap();
	/* 返回物理地址 */
	return phys;
}

/* PTE页表是4级页表的最后一级,alloc_init_pte配置PTE页表项 */
static void alloc_init_pte(pmd_t *pmd, unsigned long addr,
				  unsigned long end, unsigned long pfn,
				  pgprot_t prot,
				  phys_addr_t (*pgtable_alloc)(void))
{
	pte_t *pte;
	/* 如果pmd是段映射,那么就报个BUG */
	BUG_ON(pmd_sect(*pmd));
	/* 首先判断pmd是否为空,如果为空,说明下一级页表不存在,需要动态分配512个表项,
	 * 然后通过__pmd_populate函数来设置PMD页表项
	 */
	if (pmd_none(*pmd)) {
		phys_addr_t pte_phys;
		BUG_ON(!pgtable_alloc);
		pte_phys = pgtable_alloc();
		pte = pte_set_fixmap(pte_phys);
		__pmd_populate(pmd, pte_phys, PMD_TYPE_TABLE);
		pte_clear_fixmap();
	}
	BUG_ON(pmd_bad(*pmd));
	/* 通过bit[20:12]作为索引,索引到相应的PTE页表项 */
	pte = pte_set_fixmap_offset(pmd, addr);
	do {
		/* 循环设置PTE表项 */
		set_pte(pte, pfn_pte(pfn, prot));
		pfn++;
	} while (pte++, addr += PAGE_SIZE, addr != end);

	pte_clear_fixmap();
}

static void alloc_init_pmd(pud_t *pud, unsigned long addr, unsigned long end,
				  phys_addr_t phys, pgprot_t prot,
				  phys_addr_t (*pgtable_alloc)(void),
				  bool allow_block_mappings)
{
	pmd_t *pmd;
	unsigned long next;

	/*
	 * Check for initial section mappings in the pgd/pud and remove them.
	 */
	/* 如果是段映射
	 * #define pud_sect(pud) ((pud_val(pud) & PUD_TYPE_MASK) == PUD_TYPE_SECT)
	 */
	BUG_ON(pud_sect(*pud));
	/* 首先判断PUD页表项的内容是否为空?
	 * 如果为空,表示PUD指向的下一级页表PMD不存在,需要动态分配PMD页表.
	 * 分配PTRS_PER_PMD个页表项,即512个,然后通过pud_populate来设置pud页表项
	 */
	if (pud_none(*pud)) {
		phys_addr_t pmd_phys;
		BUG_ON(!pgtable_alloc);
		pmd_phys = pgtable_alloc();
		pmd = pmd_set_fixmap(pmd_phys);
		__pud_populate(pud, pmd_phys, PUD_TYPE_TABLE);
		pmd_clear_fixmap();
	}
	BUG_ON(pud_bad(*pud));
	/* 使用bit[29:21]位获取PUD表项 */
	pmd = pmd_set_fixmap_offset(pud, addr);
	do {
		next = pmd_addr_end(addr, end);
		/* try section mapping first */
		/* 段映射,同alloc_init_pud,这是颗粒SECTION_MASK(2MB)有所不同 */
		if (((addr | next | phys) & ~SECTION_MASK) == 0 &&
		      allow_block_mappings) {
			pmd_t old_pmd =*pmd;
			pmd_set_huge(pmd, phys, prot);
			/*
			 * Check for previous table entries created during
			 * boot (__create_page_tables) and flush them.
			 */
			if (!pmd_none(old_pmd)) {
				flush_tlb_all();
				if (pmd_table(old_pmd)) {
					phys_addr_t table = pmd_page_paddr(old_pmd);
					if (!WARN_ON_ONCE(slab_is_available()))
						memblock_free(table, PAGE_SIZE);
				}
			}
		} else {
			/* 如果映射的内存不是和SECTION_MASK对齐的,那么需要通过alloc_init_pte函数来映射下一级PTE页表 */
			alloc_init_pte(pmd, addr, next, __phys_to_pfn(phys),
				       prot, pgtable_alloc);
		}
		phys += next - addr;
	} while (pmd++, addr = next, addr != end);

	pmd_clear_fixmap();
}

static inline bool use_1G_block(unsigned long addr, unsigned long next,
			unsigned long phys)
{
	/* 如果不是4K的大小 返回false */
	if (PAGE_SHIFT != 12)
		return false;

	/* 如果addr、next、phys不是PUD_MASK(也就是说不是1G对齐的),那么返回false */
	if (((addr | next | phys) & ~PUD_MASK) != 0)
		return false;

	return true;
}

static void alloc_init_pud(pgd_t *pgd, unsigned long addr, unsigned long end,
				  phys_addr_t phys, pgprot_t prot,
				  phys_addr_t (*pgtable_alloc)(void),
				  bool allow_block_mappings)
{
	pud_t *pud;
	unsigned long next;
	/* 通过pgd_none判断当前PGD表项内容是否为空.
	 * 如果pgd表项内容为空,说明下一级页表为空,
	 * 那么需要动态分配下一级页表.
	 */
	if (pgd_none(*pgd)) {
		phys_addr_t pud_phys;
		BUG_ON(!pgtable_alloc);
		/* 这里是分配内存,如果是4K的表项,那么分配4K,4096/8 = 512,正好是512个表项
		 * 返回物理地址
		 */
		pud_phys = pgtable_alloc();
		/* 通过pgd_populate把刚刚分配的PUD页表设置到相应的PGD页表项中
		 * 将pud物理地址写到pgd entry，完成pgd entry设置
		 */
		__pgd_populate(pgd, pud_phys, PUD_TYPE_TABLE);
	}
	BUG_ON(pgd_bad(*pgd));
	/* 计算虚拟地址在pud页表中对应的pgd entry的虚拟地址.
	 * (1)读取pgd entry获取pud页表基地址的物理地址
	 * (2)根据虚拟地址与pud相关的域计算pud index
	 * (3)根据(1)(2)的结果获取pud entry的物理地址
	 * (4)利用fixmap中的FIX_PUD映射其虚拟地址,该虚拟地址就是addr虚拟地址对应第一个pud entry的指针,指针进行+1操作会自动跳转到下一个pgd entry指针
	 *
	 * 最终使用虚拟地址的bit[38 ~ 30]位来做索引值
	 */
	pud = pud_set_fixmap_offset(pgd, addr);
	do {
		/* 接下来以PUD_SIZE(即1 << 30，1GB为步长,通过while循坏来设置下一级页表). */
		/* #define pud_addr_end(addr, end)						\
		 * ({	unsigned long __boundary = ((addr) + PUD_SIZE) & PUD_MASK;	\
		 * (__boundary - 1 < (end) - 1)? __boundary: (end);		\
		 * })
		 */
		next = pud_addr_end(addr, end);

		/*
		 * For 4K granule only, attempt to put down a 1GB block
		 * 针对4K颗粒，尝试分配1GB的块
		 */
		/* use_1G_block 函数会判断是否使用1GB大小的block来映射? 当这里要映射的大小内存块正好是PUD_SIZE的时候,
		 * 那么只需要映射到PUD就好了,接下来的PMD和PTE页表等到真正需要使用时在映射,通过set_pud函数来设置相应的PUD表项
		 */
		if (use_1G_block(addr, next, phys) && allow_block_mappings) {
			pud_t old_pud = *pud;
			/* int pud_set_huge(pud_t *pud, phys_addr_t phys, pgprot_t prot)
			 * {
			 * 	BUG_ON(phys & ~PUD_MASK);
			 *	这里就是设置为大小为1G的块映射
			 *	set_pud(pud, __pud(phys | PUD_TYPE_SECT | pgprot_val(mk_sect_prot(prot))));
			 *	return 1;
			 * }
			 */
			pud_set_huge(pud, phys, prot);

			/*
			 * If we have an old value for a pud, it will
			 * be pointing to a pmd table that we no longer
			 * need (from swapper_pg_dir).
			 *
			 * Look up the old pmd table and free it.
			 *
			 * 如果我们有一个pud的旧值，它将指向我们不再需要的pmd表（来自swapper_pg_dir）。
			 *
			 * 查找旧的pmd表并将其释放。
			 */
			/* 如果原来的pud里面有东西 */
			if (!pud_none(old_pud)) {
				/* 由于被替换的old entry内容,可能已被加载到tlb中.
				 * 因此,为了保持tlb和页表内容的一致,需要刷新tlb
				 */
				flush_tlb_all();
				/* 如果是页表映射
				 * #define pud_table(pud)  ((pud_val(pud) & PUD_TYPE_MASK) == PUD_TYPE_TABLE)
				 */
				if (pud_table(old_pud)) {
					/* 拿到物理地址 */
					phys_addr_t table = pud_page_paddr(old_pud);
					/* 释放它 */
					if (!WARN_ON_ONCE(slab_is_available()))
						memblock_free(table, PAGE_SIZE);
				}
			}
		} else {
			/* 如果use_1G_block 函数判断不能通过1GB大小来映射,那么就需要调用alloc_init_pmd函数来进行下一级页表的映射 */
			alloc_init_pmd(pud, addr, next, phys, prot,
				       pgtable_alloc, allow_block_mappings);
		}
		phys += next - addr;
	} while (pud++, addr = next, addr != end);

	pud_clear_fixmap();
}

static void __create_pgd_mapping(pgd_t *pgdir, phys_addr_t phys,
				 unsigned long virt, phys_addr_t size,
				 pgprot_t prot,
				 phys_addr_t (*pgtable_alloc)(void),
				 bool allow_block_mappings)
{
	unsigned long addr, length, end, next;
	pgd_t *pgd = pgd_offset_raw(pgdir, virt);

	/*
	 * If the virtual and physical address don't have the same offset
	 * within a page, we cannot map the region as the caller expects.
	 *
	 * 如果虚拟地址和物理地址在页面内的偏移量不相同,
	 * 我们无法按照调用者期望的方式去映射内存
	 */
	if (WARN_ON((phys ^ virt) & ~PAGE_MASK))
		return;
	/* 把物理地址按照页面对齐 */
	phys &= PAGE_MASK;
	/* 虚拟地址按照页面对齐 */
	addr = virt & PAGE_MASK;
	/* 让虚拟地址按页对齐多出来的部分 + size */
	length = PAGE_ALIGN(size + (virt & ~PAGE_MASK));
	/* 结束地址end = addr + length */
	end = addr + length;
	do {
		/* #define pgd_addr_end(addr, end)		\
		 * ({	unsigned long __boundary = ((addr) + PGDIR_SIZE) & PGDIR_MASK;	\
		 *  (__boundary - 1 < (end) - 1)? __boundary: (end);		\
		 *  })
		 */
		next = pgd_addr_end(addr, end);
		alloc_init_pud(pgd, addr, next, phys, prot, pgtable_alloc,
			       allow_block_mappings);
		phys += next - addr;
	} while (pgd++, addr = next, addr != end);
}

static phys_addr_t pgd_pgtable_alloc(void)
{
	void *ptr = (void *)__get_free_page(PGALLOC_GFP);
	if (!ptr || !pgtable_page_ctor(virt_to_page(ptr)))
		BUG();

	/* Ensure the zeroed page is visible to the page table walker */
	dsb(ishst);
	return __pa(ptr);
}

/*
 * This function can only be used to modify existing table entries,
 * without allocating new levels of table. Note that this permits the
 * creation of new section or page entries.
 */
static void __init create_mapping_noalloc(phys_addr_t phys, unsigned long virt,
				  phys_addr_t size, pgprot_t prot)
{
	if (virt < VMALLOC_START) {
		pr_warn("BUG: not creating mapping for %pa at 0x%016lx - outside kernel range\n",
			&phys, virt);
		return;
	}
	__create_pgd_mapping(init_mm.pgd, phys, virt, size, prot, NULL, true);
}

void __init create_pgd_mapping(struct mm_struct *mm, phys_addr_t phys,
			       unsigned long virt, phys_addr_t size,
			       pgprot_t prot, bool allow_block_mappings)
{
	BUG_ON(mm == &init_mm);

	__create_pgd_mapping(mm->pgd, phys, virt, size, prot,
			     pgd_pgtable_alloc, allow_block_mappings);
}

static void create_mapping_late(phys_addr_t phys, unsigned long virt,
				  phys_addr_t size, pgprot_t prot)
{
	if (virt < VMALLOC_START) {
		pr_warn("BUG: not creating mapping for %pa at 0x%016lx - outside kernel range\n",
			&phys, virt);
		return;
	}

	__create_pgd_mapping(init_mm.pgd, phys, virt, size, prot,
			     NULL, !debug_pagealloc_enabled());
}

static void __init __map_memblock(pgd_t *pgd, phys_addr_t start, phys_addr_t end)
{
	/* 从__text段(内核的代码段)到__init_begin(内核初始化所需的代码和数据) */
	unsigned long kernel_start = __pa(_text);
	unsigned long kernel_end = __pa(__init_begin);

	/*
	 * Take care not to create a writable alias for the
	 * read-only text and rodata sections of the kernel image.
	 */

	/* No overlap with the kernel text/rodata */
	/* 注意不要为内核映像的只读text和rodata段创建可写别名
	 * 不要和内核的text/rodata重叠
	 */
	if (end < kernel_start || start >= kernel_end) {
		__create_pgd_mapping(pgd, start, __phys_to_virt(start),
				     end - start, PAGE_KERNEL,
				     early_pgtable_alloc,
				     !debug_pagealloc_enabled());
		return;
	}

	/*
	 * This block overlaps the kernel text/rodata mappings.
	 * Map the portion(s) which don't overlap.
	 */
	if (start < kernel_start)
		__create_pgd_mapping(pgd, start,
				     __phys_to_virt(start),
				     kernel_start - start, PAGE_KERNEL,
				     early_pgtable_alloc,
				     !debug_pagealloc_enabled());
	if (kernel_end < end)
		__create_pgd_mapping(pgd, kernel_end,
				     __phys_to_virt(kernel_end),
				     end - kernel_end, PAGE_KERNEL,
				     early_pgtable_alloc,
				     !debug_pagealloc_enabled());

	/*
	 * Map the linear alias of the [_text, __init_begin) interval as
	 * read-only/non-executable. This makes the contents of the
	 * region accessible to subsystems such as hibernate, but
	 * protects it from inadvertent modification or execution.
	 */
	__create_pgd_mapping(pgd, kernel_start, __phys_to_virt(kernel_start),
			     kernel_end - kernel_start, PAGE_KERNEL_RO,
			     early_pgtable_alloc, !debug_pagealloc_enabled());
}

static void __init map_mem(pgd_t *pgd)
{
	struct memblock_region *reg;

	/* map all the memory banks */
	for_each_memblock(memory, reg) {
		phys_addr_t start = reg->base;
		phys_addr_t end = start + reg->size;

		if (start >= end)
			break;
		if (memblock_is_nomap(reg))
			continue;

		__map_memblock(pgd, start, end);
	}
}

void mark_rodata_ro(void)
{
	unsigned long section_size;

	section_size = (unsigned long)_etext - (unsigned long)_text;
	create_mapping_late(__pa(_text), (unsigned long)_text,
			    section_size, PAGE_KERNEL_ROX);
	/*
	 * mark .rodata as read only. Use __init_begin rather than __end_rodata
	 * to cover NOTES and EXCEPTION_TABLE.
	 */
	section_size = (unsigned long)__init_begin - (unsigned long)__start_rodata;
	create_mapping_late(__pa(__start_rodata), (unsigned long)__start_rodata,
			    section_size, PAGE_KERNEL_RO);
}

static void __init map_kernel_segment(pgd_t *pgd, void *va_start, void *va_end,
				      pgprot_t prot, struct vm_struct *vma)
{
	phys_addr_t pa_start = __pa(va_start);
	unsigned long size = va_end - va_start;

	BUG_ON(!PAGE_ALIGNED(pa_start));
	BUG_ON(!PAGE_ALIGNED(size));

	__create_pgd_mapping(pgd, pa_start, (unsigned long)va_start, size, prot,
			     early_pgtable_alloc, !debug_pagealloc_enabled());

	vma->addr	= va_start;
	vma->phys_addr	= pa_start;
	vma->size	= size;
	vma->flags	= VM_MAP;
	vma->caller	= __builtin_return_address(0);

	vm_area_add_early(vma);
}

/*
 * Create fine-grained mappings for the kernel.
 */
static void __init map_kernel(pgd_t *pgd)
{
	static struct vm_struct vmlinux_text, vmlinux_rodata, vmlinux_init, vmlinux_data;

	map_kernel_segment(pgd, _text, _etext, PAGE_KERNEL_EXEC, &vmlinux_text);
	map_kernel_segment(pgd, __start_rodata, __init_begin, PAGE_KERNEL, &vmlinux_rodata);
	map_kernel_segment(pgd, __init_begin, __init_end, PAGE_KERNEL_EXEC,
			   &vmlinux_init);
	map_kernel_segment(pgd, _data, _end, PAGE_KERNEL, &vmlinux_data);

	if (!pgd_val(*pgd_offset_raw(pgd, FIXADDR_START))) {
		/*
		 * The fixmap falls in a separate pgd to the kernel, and doesn't
		 * live in the carveout for the swapper_pg_dir. We can simply
		 * re-use the existing dir for the fixmap.
		 */
		set_pgd(pgd_offset_raw(pgd, FIXADDR_START),
			*pgd_offset_k(FIXADDR_START));
	} else if (CONFIG_PGTABLE_LEVELS > 3) {
		/*
		 * The fixmap shares its top level pgd entry with the kernel
		 * mapping. This can really only occur when we are running
		 * with 16k/4 levels, so we can simply reuse the pud level
		 * entry instead.
		 */
		BUG_ON(!IS_ENABLED(CONFIG_ARM64_16K_PAGES));
		set_pud(pud_set_fixmap_offset(pgd, FIXADDR_START),
			__pud(__pa(bm_pmd) | PUD_TYPE_TABLE));
		pud_clear_fixmap();
	} else {
		BUG();
	}

	kasan_copy_shadow(pgd);
}

/*
 * paging_init() sets up the page tables, initialises the zone memory
 * maps and sets up the zero page.
 */
void __init paging_init(void)
{
	phys_addr_t pgd_phys = early_pgtable_alloc();
	pgd_t *pgd = pgd_set_fixmap(pgd_phys);

	map_kernel(pgd);
	map_mem(pgd);

	/*
	 * We want to reuse the original swapper_pg_dir so we don't have to
	 * communicate the new address to non-coherent secondaries in
	 * secondary_entry, and so cpu_switch_mm can generate the address with
	 * adrp+add rather than a load from some global variable.
	 *
	 * To do this we need to go via a temporary pgd.
	 */
	cpu_replace_ttbr1(__va(pgd_phys));
	memcpy(swapper_pg_dir, pgd, PAGE_SIZE);
	cpu_replace_ttbr1(swapper_pg_dir);

	pgd_clear_fixmap();
	memblock_free(pgd_phys, PAGE_SIZE);

	/*
	 * We only reuse the PGD from the swapper_pg_dir, not the pud + pmd
	 * allocated with it.
	 */
	memblock_free(__pa(swapper_pg_dir) + PAGE_SIZE,
		      SWAPPER_DIR_SIZE - PAGE_SIZE);
}

/*
 * Check whether a kernel address is valid (derived from arch/x86/).
 */
int kern_addr_valid(unsigned long addr)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	if ((((long)addr) >> VA_BITS) != -1UL)
		return 0;

	pgd = pgd_offset_k(addr);
	if (pgd_none(*pgd))
		return 0;

	pud = pud_offset(pgd, addr);
	if (pud_none(*pud))
		return 0;

	if (pud_sect(*pud))
		return pfn_valid(pud_pfn(*pud));

	pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd))
		return 0;

	if (pmd_sect(*pmd))
		return pfn_valid(pmd_pfn(*pmd));

	pte = pte_offset_kernel(pmd, addr);
	if (pte_none(*pte))
		return 0;

	return pfn_valid(pte_pfn(*pte));
}
#ifdef CONFIG_SPARSEMEM_VMEMMAP
#if !ARM64_SWAPPER_USES_SECTION_MAPS
int __meminit vmemmap_populate(unsigned long start, unsigned long end, int node)
{
	return vmemmap_populate_basepages(start, end, node);
}
#else	/* !ARM64_SWAPPER_USES_SECTION_MAPS */
int __meminit vmemmap_populate(unsigned long start, unsigned long end, int node)
{
	unsigned long addr = start;
	unsigned long next;
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;

	do {
		next = pmd_addr_end(addr, end);

		pgd = vmemmap_pgd_populate(addr, node);
		if (!pgd)
			return -ENOMEM;

		pud = vmemmap_pud_populate(pgd, addr, node);
		if (!pud)
			return -ENOMEM;

		pmd = pmd_offset(pud, addr);
		if (pmd_none(*pmd)) {
			void *p = NULL;

			p = vmemmap_alloc_block_buf(PMD_SIZE, node);
			if (!p)
				return -ENOMEM;

			set_pmd(pmd, __pmd(__pa(p) | PROT_SECT_NORMAL));
		} else
			vmemmap_verify((pte_t *)pmd, node, addr, next);
	} while (addr = next, addr != end);

	return 0;
}
#endif	/* CONFIG_ARM64_64K_PAGES */
void vmemmap_free(unsigned long start, unsigned long end)
{
}
#endif	/* CONFIG_SPARSEMEM_VMEMMAP */

static inline pud_t * fixmap_pud(unsigned long addr)
{
	pgd_t *pgd = pgd_offset_k(addr);

	BUG_ON(pgd_none(*pgd) || pgd_bad(*pgd));

	return pud_offset_kimg(pgd, addr);
}

static inline pmd_t * fixmap_pmd(unsigned long addr)
{
	pud_t *pud = fixmap_pud(addr);

	BUG_ON(pud_none(*pud) || pud_bad(*pud));

	return pmd_offset_kimg(pud, addr);
}

static inline pte_t * fixmap_pte(unsigned long addr)
{
	return &bm_pte[pte_index(addr)];
}

void __init early_fixmap_init(void)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	unsigned long addr = FIXADDR_START;

	pgd = pgd_offset_k(addr);
	if (CONFIG_PGTABLE_LEVELS > 3 &&
	    !(pgd_none(*pgd) || pgd_page_paddr(*pgd) == __pa(bm_pud))) {
		/*
		 * We only end up here if the kernel mapping and the fixmap
		 * share the top level pgd entry, which should only happen on
		 * 16k/4 levels configurations.
		 */
		BUG_ON(!IS_ENABLED(CONFIG_ARM64_16K_PAGES));
		pud = pud_offset_kimg(pgd, addr);
	} else {
		pgd_populate(&init_mm, pgd, bm_pud);
		pud = fixmap_pud(addr);
	}
	pud_populate(&init_mm, pud, bm_pmd);
	pmd = fixmap_pmd(addr);
	pmd_populate_kernel(&init_mm, pmd, bm_pte);

	/*
	 * The boot-ioremap range spans multiple pmds, for which
	 * we are not prepared:
	 */
	BUILD_BUG_ON((__fix_to_virt(FIX_BTMAP_BEGIN) >> PMD_SHIFT)
		     != (__fix_to_virt(FIX_BTMAP_END) >> PMD_SHIFT));

	if ((pmd != fixmap_pmd(fix_to_virt(FIX_BTMAP_BEGIN)))
	     || pmd != fixmap_pmd(fix_to_virt(FIX_BTMAP_END))) {
		WARN_ON(1);
		pr_warn("pmd %p != %p, %p\n",
			pmd, fixmap_pmd(fix_to_virt(FIX_BTMAP_BEGIN)),
			fixmap_pmd(fix_to_virt(FIX_BTMAP_END)));
		pr_warn("fix_to_virt(FIX_BTMAP_BEGIN): %08lx\n",
			fix_to_virt(FIX_BTMAP_BEGIN));
		pr_warn("fix_to_virt(FIX_BTMAP_END):   %08lx\n",
			fix_to_virt(FIX_BTMAP_END));

		pr_warn("FIX_BTMAP_END:       %d\n", FIX_BTMAP_END);
		pr_warn("FIX_BTMAP_BEGIN:     %d\n", FIX_BTMAP_BEGIN);
	}
}

void __set_fixmap(enum fixed_addresses idx,
			       phys_addr_t phys, pgprot_t flags)
{
	unsigned long addr = __fix_to_virt(idx);
	pte_t *pte;

	BUG_ON(idx <= FIX_HOLE || idx >= __end_of_fixed_addresses);

	pte = fixmap_pte(addr);

	if (pgprot_val(flags)) {
		set_pte(pte, pfn_pte(phys >> PAGE_SHIFT, flags));
	} else {
		pte_clear(&init_mm, addr, pte);
		flush_tlb_kernel_range(addr, addr+PAGE_SIZE);
	}
}

void *__init __fixmap_remap_fdt(phys_addr_t dt_phys, int *size, pgprot_t prot)
{
	const u64 dt_virt_base = __fix_to_virt(FIX_FDT);
	int offset;
	void *dt_virt;

	/*
	 * Check whether the physical FDT address is set and meets the minimum
	 * alignment requirement. Since we are relying on MIN_FDT_ALIGN to be
	 * at least 8 bytes so that we can always access the magic and size
	 * fields of the FDT header after mapping the first chunk, double check
	 * here if that is indeed the case.
	 */
	BUILD_BUG_ON(MIN_FDT_ALIGN < 8);
	if (!dt_phys || dt_phys % MIN_FDT_ALIGN)
		return NULL;

	/*
	 * Make sure that the FDT region can be mapped without the need to
	 * allocate additional translation table pages, so that it is safe
	 * to call create_mapping_noalloc() this early.
	 *
	 * On 64k pages, the FDT will be mapped using PTEs, so we need to
	 * be in the same PMD as the rest of the fixmap.
	 * On 4k pages, we'll use section mappings for the FDT so we only
	 * have to be in the same PUD.
	 */
	BUILD_BUG_ON(dt_virt_base % SZ_2M);

	BUILD_BUG_ON(__fix_to_virt(FIX_FDT_END) >> SWAPPER_TABLE_SHIFT !=
		     __fix_to_virt(FIX_BTMAP_BEGIN) >> SWAPPER_TABLE_SHIFT);

	offset = dt_phys % SWAPPER_BLOCK_SIZE;
	dt_virt = (void *)dt_virt_base + offset;

	/* map the first chunk so we can read the size from the header */
	create_mapping_noalloc(round_down(dt_phys, SWAPPER_BLOCK_SIZE),
			dt_virt_base, SWAPPER_BLOCK_SIZE, prot);

	if (fdt_magic(dt_virt) != FDT_MAGIC)
		return NULL;

	*size = fdt_totalsize(dt_virt);
	if (*size > MAX_FDT_SIZE)
		return NULL;

	if (offset + *size > SWAPPER_BLOCK_SIZE)
		create_mapping_noalloc(round_down(dt_phys, SWAPPER_BLOCK_SIZE), dt_virt_base,
			       round_up(offset + *size, SWAPPER_BLOCK_SIZE), prot);

	return dt_virt;
}

void *__init fixmap_remap_fdt(phys_addr_t dt_phys)
{
	void *dt_virt;
	int size;

	dt_virt = __fixmap_remap_fdt(dt_phys, &size, PAGE_KERNEL_RO);
	if (!dt_virt)
		return NULL;

	memblock_reserve(dt_phys, size);
	return dt_virt;
}

int __init arch_ioremap_pud_supported(void)
{
	/* only 4k granule supports level 1 block mappings */
	return IS_ENABLED(CONFIG_ARM64_4K_PAGES);
}

int __init arch_ioremap_pmd_supported(void)
{
	return 1;
}

int pud_set_huge(pud_t *pud, phys_addr_t phys, pgprot_t prot)
{
	BUG_ON(phys & ~PUD_MASK);
	set_pud(pud, __pud(phys | PUD_TYPE_SECT | pgprot_val(mk_sect_prot(prot))));
	return 1;
}

int pmd_set_huge(pmd_t *pmd, phys_addr_t phys, pgprot_t prot)
{
	BUG_ON(phys & ~PMD_MASK);
	set_pmd(pmd, __pmd(phys | PMD_TYPE_SECT | pgprot_val(mk_sect_prot(prot))));
	return 1;
}

int pud_clear_huge(pud_t *pud)
{
	if (!pud_sect(*pud))
		return 0;
	pud_clear(pud);
	return 1;
}

int pmd_clear_huge(pmd_t *pmd)
{
	if (!pmd_sect(*pmd))
		return 0;
	pmd_clear(pmd);
	return 1;
}
