/*
 * Based on arch/arm/mm/mmap.c
 *
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

#include <linux/elf.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/export.h>
#include <linux/shm.h>
#include <linux/sched.h>
#include <linux/io.h>
#include <linux/personality.h>
#include <linux/random.h>

#include <asm/cputype.h>

/*
 * Leave enough space between the mmap area and the stack to honour ulimit in
 * the face of randomisation.
 */
#define MIN_GAP (SZ_128M + ((STACK_RND_MASK << PAGE_SHIFT) + 1))
#define MAX_GAP	(STACK_TOP/6*5)

/* 内核通过mmap_is_legacy函数来判断进程虚拟内存空间布局采用的是经典布局(返回 1)还是新式布局(返回 0). */
static int mmap_is_legacy(void)
{
	/* 首先内核会判断进程struct task_struct结构中的personality标志位是否设置为ADDR_COMPAT_LAYOUT,
	 * 如果设置了ADDR_COMPAT_LAYOUT标志则表示进程虚拟内存空间布局应该采用经典布局
	 */
	if (current->personality & ADDR_COMPAT_LAYOUT)
		return 1;

	/* 如果栈是无限制增长的 */
	if (rlimit(RLIMIT_STACK) == RLIM_INFINITY)
		return 1;

	/* task_struct->personality如果没有设置ADDR_COMPAT_LAYOUT,则继续判断sysctl_legacy_va_layout内核参数的值,
	 * 如果为1则表示采用经典布局,为0则采用新式布局
	 * 用户可通过设置/proc/sys/vm/legacy_va_layout内核参数来指定sysctl_legacy_va_layout变量的值
	 */
	return sysctl_legacy_va_layout;
}

unsigned long arch_mmap_rnd(void)
{
	unsigned long rnd;

#ifdef CONFIG_COMPAT
	if (test_thread_flag(TIF_32BIT))
		rnd = get_random_long() & ((1UL << mmap_rnd_compat_bits) - 1);
	else
#endif
		rnd = get_random_long() & ((1UL << mmap_rnd_bits) - 1);
	return rnd << PAGE_SHIFT;
}

static unsigned long mmap_base(unsigned long rnd)
{
	unsigned long gap = rlimit(RLIMIT_STACK);

	if (gap < MIN_GAP)
		gap = MIN_GAP;
	else if (gap > MAX_GAP)
		gap = MAX_GAP;

	return PAGE_ALIGN(STACK_TOP - gap - rnd);
}

/*
 * This function, called very early during the creation of a new process VM
 * image, sets up which VM layout function to use:
 *
 * 此函数在创建新进程VM映像的早期调用,用于设置要使用的VM布局函数:
 */
void arch_pick_mmap_layout(struct mm_struct *mm)
{
	unsigned long random_factor = 0UL;

	if (current->flags & PF_RANDOMIZE)
		random_factor = arch_mmap_rnd();

	/*
	 * Fall back to the standard layout if the personality bit is set, or
	 * if the expected stack growth is unlimited:
	 *
	 * 如果设置了个性位,或者如果预期的堆栈增长是无限的，则回退到标准布局：
	 */

	/* 文件映射与匿名映射区的布局分为两种,一种是经典布局,另一种是新布局.
	 * 不同的体系结构可以通过设置HAVE_ARCH_PICK_MMAP_LAYOUT预处理符号,
	 * 并提供arch_pick_mmap_layout函数的实现来在这两种不同布局之间进行选择
	 *
	 * 由于在经典布局下,文件映射与匿名映射区的地址增长方向是从低地址到高地址增长,在新布局下.文件映射与匿名映射区的地址增长方向是从高地址到低地址增长.
	 * 所以当mmap在文件映射与匿名映射区中寻找空闲vma的时候,会受到不同布局的影响,其寻找方向是相反的,因此不同的体系结构需要设置HAVE_ARCH_UNMAPPED_AREA预处理符号,
	 * 并提供arch_get_unmapped_area函数的实现.
	 * 这样一来,如果文件映射与匿名映射区采用的是经典布局,那么mmap就会通过这里的arch_get_unmapped_area来在映射区查找空闲的vma
	 *
	 * 如果文件映射与匿名映射区采用的是新布局,地址增长方向是从高地址到低地址增长.
	 * 因此不同的体系结构需要设置HAVE_ARCH_UNMAPPED_AREA_TOPDOWN预处理符号,并提供arch_get_unmapped_area_topdown函数的实现.
	 * mmap 在新布局下则会通过这里的arch_get_unmapped_area_topdown函数在文件映射与匿名映射区寻找空闲vma
	 * arch_get_unmapped_area和arch_get_unmapped_area_topdown函数,内核都会提供默认的实现,不同体系结构如果没有特殊的定制需求,无需单独实现.
	 * 无论是经典布局下的arch_get_unmapped_area,还是新布局下的arch_get_unmapped_area_topdown都会设置到mm_struct->get_unmapped_area这个函数指针中,
	 * 后续mmap会利用这个get_unmapped_area来在文件映射与匿名映射区中划分虚拟内存区域 vma.
	 */
	if (mmap_is_legacy()) {
		/* 在arm64中,TASK_UNMAPPED_BASE定义如下
		 * #define TASK_UNMAPPED_BASE	(PAGE_ALIGN(TASK_SIZE / 4))
		 * 也就是说从PAGE_ALIGN(TASK_SIZE / 4)往上增长
		 */
		mm->mmap_base = TASK_UNMAPPED_BASE + random_factor;
		mm->get_unmapped_area = arch_get_unmapped_area;
	} else {
		/* 否则就是从栈的顶部
		 * #define STACK_TOP_MAX TASK_SIZE_64
		 * PAGE_ALIGN(STACK_TOP - gap - rnd)
		 * 从这个位置往下增长
		 *
		 * 这个gap实际上就是栈大小
		 */
		mm->mmap_base = mmap_base(random_factor);
		mm->get_unmapped_area = arch_get_unmapped_area_topdown;
	}
}

/*
 * You really shouldn't be using read() or write() on /dev/mem.  This might go
 * away in the future.
 */
int valid_phys_addr_range(phys_addr_t addr, size_t size)
{
	if (addr < PHYS_OFFSET)
		return 0;
	if (addr + size > __pa(high_memory - 1) + 1)
		return 0;

	return 1;
}

/*
 * Do not allow /dev/mem mappings beyond the supported physical range.
 */
int valid_mmap_phys_addr_range(unsigned long pfn, size_t size)
{
	return !(((pfn << PAGE_SHIFT) + size) & ~PHYS_MASK);
}

#ifdef CONFIG_STRICT_DEVMEM

#include <linux/ioport.h>

/*
 * devmem_is_allowed() checks to see if /dev/mem access to a certain address
 * is valid. The argument is a physical page number.  We mimic x86 here by
 * disallowing access to system RAM as well as device-exclusive MMIO regions.
 * This effectively disable read()/write() on /dev/mem.
 */
int devmem_is_allowed(unsigned long pfn)
{
	if (iomem_is_exclusive(pfn << PAGE_SHIFT))
		return 0;
	if (!page_is_ram(pfn))
		return 1;
	return 0;
}

#endif
