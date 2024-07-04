/*
 * Based on arch/arm/mm/context.c
 *
 * Copyright (C) 2002-2003 Deep Blue Solutions Ltd, all rights reserved.
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

#include <linux/bitops.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/mm.h>

#include <asm/cpufeature.h>
#include <asm/mmu_context.h>
#include <asm/smp.h>
#include <asm/tlbflush.h>

static u32 asid_bits;
static DEFINE_RAW_SPINLOCK(cpu_asid_lock);

static atomic64_t asid_generation;
static unsigned long *asid_map;

/*
 * 每处理器变量active_asids保存处理器正在使用的ASID,即处理器正在执行的进程的ASID;
 * 每处理器变量reserved_asids存放保留的ASID,用来在全局ASID版本号加1时保存处理器正在执行的进程的ASID.
 * 处理器给进程分配ASID时,如果ASID分配完了,那么把全局ASID版本号加1,重新从1开始分配ASID,针对每个处理器,使用该处理器的reserved_asids保存该处理器正在执行的进程的ASID,
 * 并且把该处理器的active_asids设置为0.
 */
static DEFINE_PER_CPU(atomic64_t, active_asids);
static DEFINE_PER_CPU(u64, reserved_asids);
static cpumask_t tlb_flush_pending;

#define ASID_MASK		(~GENMASK(asid_bits - 1, 0))
#define ASID_FIRST_VERSION	(1UL << asid_bits)
#define NUM_USER_ASIDS		ASID_FIRST_VERSION

/* Get the ASIDBits supported by the current CPU */
static u32 get_cpu_asid_bits(void)
{
	u32 asid;
	int fld = cpuid_feature_extract_unsigned_field(read_cpuid(ID_AA64MMFR0_EL1),
						ID_AA64MMFR0_ASID_SHIFT);

	switch (fld) {
	default:
		pr_warn("CPU%d: Unknown ASID size (%d); assuming 8-bit\n",
					smp_processor_id(),  fld);
		/* Fallthrough */
	case 0:
		asid = 8;
		break;
	case 2:
		asid = 16;
	}

	return asid;
}

/* Check if the current cpu's ASIDBits is compatible with asid_bits */
void verify_cpu_asid_bits(void)
{
	u32 asid = get_cpu_asid_bits();

	if (asid < asid_bits) {
		/*
		 * We cannot decrease the ASID size at runtime, so panic if we support
		 * fewer ASID bits than the boot CPU.
		 */
		pr_crit("CPU%d: smaller ASID size(%u) than boot CPU (%u)\n",
				smp_processor_id(), asid, asid_bits);
		cpu_panic_kernel();
	}
}

static void flush_context(unsigned int cpu)
{
	int i;
	u64 asid;

	/*
	 * Update the list of reserved ASIDs and the ASID bitmap.
	 * 更新保留的ASIDd和ASID位图.
	 */
	bitmap_clear(asid_map, 0, NUM_USER_ASIDS);

	/*
	 * Ensure the generation bump is observed before we xchg the
	 * active_asids.
	 *
	 * 在我们xchg active_asids之前,确保观察到生成凸块
	 */
	smp_wmb();

	for_each_possible_cpu(i) {
		/* 把每个CPU的active_asids设置为0,这里应该会返回原来的值 */
		asid = atomic64_xchg_relaxed(&per_cpu(active_asids, i), 0);
		/*
		 * If this CPU has already been through a
		 * rollover, but hasn't run another task in
		 * the meantime, we must preserve its reserved
		 * ASID, as this is the only trace we have of
		 * the process it is still running.
		 *
		 * 如果此CPU已经进行了滚动,但尚未运行另一个任务同时,我们必须保留其保留的ASID,因为这是我们有进程仍然在运行的唯一痕迹
		 */

		/* 如果asid == 0,说明我们还在刷新TLB的状态或者刚刷新完
		 * 那我们拿到此时保留的reserved_asids
		 */
		if (asid == 0)
			asid = per_cpu(reserved_asids, i);
		/* 把它在asid_map中置位 */
		__set_bit(asid & ~ASID_MASK, asid_map);
		/* 把其asid设置为reserved_asids */
		per_cpu(reserved_asids, i) = asid;
	}

	/* Queue a TLB invalidate and flush the I-cache if necessary. */
	/* 把所有的CPU都设置到tlb_flush_pending中 */
	cpumask_setall(&tlb_flush_pending);
	/* 如果icache是AIVIVT,
	 * AIVIVT是说具有ASID标志的VIVT
	 * VIVT是用虚拟地址的索引域和虚拟地址的标记域,相当于虚拟高速缓存
	 * 那么还需要去刷新icache
	 */
	if (icache_is_aivivt())
		__flush_icache_all();
}

static bool check_update_reserved_asid(u64 asid, u64 newasid)
{
	int cpu;
	bool hit = false;

	/*
	 * Iterate over the set of reserved ASIDs looking for a match.
	 * If we find one, then we can update our mm to use newasid
	 * (i.e. the same ASID in the current generation) but we can't
	 * exit the loop early, since we need to ensure that all copies
	 * of the old ASID are updated to reflect the mm. Failure to do
	 * so could result in us missing the reserved ASID in a future
	 * generation.
	 *
	 * 在一组保留的ASID上迭代以查找匹配项.
	 * 如果我们找到了一个,那么我们可以更新我们的mm以使用newasid(即当前一代中的相同ASID),但我们不能提前退出循环,
	 * 因为我们需要确保更新旧ASID的所有副本以反映mm.
	 * 如果不这样做，可能会导致我们在未来丢失保留的ASID一代
	 */
	for_each_possible_cpu(cpu) {
		if (per_cpu(reserved_asids, cpu) == asid) {
			hit = true;
			per_cpu(reserved_asids, cpu) = newasid;
		}
	}

	return hit;
}

static u64 new_context(struct mm_struct *mm, unsigned int cpu)
{
	static u32 cur_idx = 1;
	/* 读取mm->context.id */
	u64 asid = atomic64_read(&mm->context.id);
	/* 读取asid_generation */
	u64 generation = atomic64_read(&asid_generation);

	/* 刚创建进程时,mm->context.id值初始化为0,如果这时asid值不为0,说明该进程之前分配过ASID.
	 * 如果原来的ASID还有小,那么只需要再加上新的generation值即可组成一个新的软件ASID.
	 */
	if (asid != 0) {
		u64 newasid = generation | (asid & ~ASID_MASK);

		/*
		 * If our current ASID was active during a rollover, we
		 * can continue to use it and this was just a false alarm.
		 *
		 * 如果我们当前的ASID在转期间处于活动状态,我们可以继续使用它,这只是一个虚惊一场.
		 */

		/* 如果命中了reserved_asids,那么直接返回 */
		if (check_update_reserved_asid(asid, newasid))
			return newasid;

		/*
		 * We had a valid ASID in a previous life, so try to re-use
		 * it if possible.
		 *
		 * 我们前一个周期有一个有效的ASID,所以如果可能的话,尽量重复使用它.
		 */

		/* 这里是取asid */
		asid &= ~ASID_MASK;
		if (!__test_and_set_bit(asid, asid_map))
			return newasid;
	}

	/*
	 * Allocate a free ASID. If we can't find one, take a note of the
	 * currently active ASIDs and mark the TLBs as requiring flushes.
	 * We always count from ASID #1, as we use ASID #0 when setting a
	 * reserved TTBR0 for the init_mm.
	 *
	 * 分配一个free的ASID.
	 * 如果找不到,请记下当前活跃的ASIDs 并将TLB标记为需要刷新.
	 * 我们总是从ASID #1开始计数,因为我们在为init_mm设置保留的TTBR0时使用ASID #0.
	 */

	/* 如果之前的硬件ASID不能使用,那么就从asid_map位图中查找第一个空闲的比特位用在这次的硬件ASID. */
	asid = find_next_zero_bit(asid_map, NUM_USER_ASIDS, cur_idx);
	/* 如果找到了,那么就goto set_asid */
	if (asid != NUM_USER_ASIDS)
		goto set_asid;

	/* We're out of ASIDs, so increment the global generation count */
	/* 如果找不到一个空闲的比特位,说明发生了溢出,那么只能提升generation值,并调用flush_context函数把所有的CPU上的TLB都冲刷掉,同时把位图asid_map清0 */
	generation = atomic64_add_return_relaxed(ASID_FIRST_VERSION,
						 &asid_generation);
	flush_context(cpu);

	/* We have more ASIDs than CPUs, so this will always succeed */
	asid = find_next_zero_bit(asid_map, NUM_USER_ASIDS, 1);

set_asid:
	__set_bit(asid, asid_map);
	cur_idx = asid;
	return asid | generation;
}

/* 在运行进程时,除了cache会缓存进程的数据外,CPU内部还有一个叫做TLB(Translation Lookasid Buffer)的硬件单元,
 * 它为了加快虚拟地址到物理地址的转换速度而将部分的页表项内容缓存起来,避免频繁的访问页表.
 * 当一个prev进程运行时,CPU内部的TLB和cache会缓存prev进程的数据.
 * 如果进程切换到next进程时没有清空(flush)prev进程的数据,那么因TLB和cache缓存了prev进程的数据,有可能导致next进程访问的虚拟地址被翻译成prev进程缓存的数据,
 * 造成数据不一致且系统不稳定,因此进程切换时需要对TLB进行flush操作(在ARM体系结构中也被成为invalidate操作).
 * 但是这种方法显然很粗鲁,对整个TLB进行flush操作后,next进程面对一个空白的TLB,因此刚开始执行时会出现很严重的TLB miss和Cache miss,导致系统性能下降.
 *
 * 如何提高TLB的性能? 这是最近几十年来芯片设计和操作系统设计人员共同努力的方向.从Linux内核角度看,地址空间可以划分为内核地址空间和用户空间,
 * 对于TLB来说可以分为Gobal和Process-Specific.
 * Gloab类型的TLB: 内核空间是所有进程共享的空间,因此这部分空间的虚拟地址到物理地址的翻译是不会变化的,可以理解为Global的.
 * Process-Specific类型的TLB:用户地址空间是每个进程独立的地址空间.
 * Prev进程切换到next进程时,TLB中缓存的prev进程的相关数据对于next进程是无用的,因此可以冲刷掉,这就是所谓的process-specific的TLB.
 *
 * 为了支持Process-Specific类型的TLB,ARM体系结构提出了一种硬件解决方案,叫做ASID(Address Space ID),这样TLB可以识别哪些TLB entry是属于某个进程的.
 * ASID方案让每个TLB entry包含一个ASID号,ASID号用于每个进程分配标识进程地址空间,TLB命中查询的标准由原来的虚拟地址判断再加上ASID条件.
 * 因此有了ASID硬件机制的支持,进程切换不需要flush TLB,即使next进程访问了相同的虚拟地址,prev进程缓存的TLB entry也不会影响到next进程,
 * 因为ASID机制从硬件上保证了prev进程和next进程的TLB不会产生冲突.
 *
 * 当使用short-descriptor格式的页表时,硬件ASID存储在CONTEXTIDR寄存器低8位,也就是说最大支持256个ID.
 * 当系统中所有CPU硬件ASID加起来超过256时会发生溢出,需要把全部TLB冲刷掉,然后重新分配硬件ASID,这个过程还需要软件来协同处理.
 *
 * 硬件ASID号的分配通过位图来管理,分配时通过asid_map位图变量来记录.
 * 另外还有一个全局原子变量asid_generation,其中bit[8~31]用于存放软件管理用的软件generation计数.
 * 软件generation从ASID_FIRST_VERSION开始计数,每当硬件ASID号溢出时,软件generation计数要加上ASID_FIRST_VERSION(ASID_FIRST_VERSION,其实是1 << 8).
 * 硬件ASID: 指存放在CONTEXTIDR寄存器低8位的硬件ASID号.
 * 软件ASID: 这是ARM linux软件提出的概念,存放在进程的mm->context.id中
 *           它包括两个域,低8位是硬件ASID,剩余的比特位是软件generation计数.
 *
 * ASID只有8bit,当这些比特位都分配完毕后需要冲刷TLB,同时增加软件generation计数,然后重新分配ASID. asid_generation存放在mm->context.id的bit[8~31]位中,调度该进程时需要判断asid_generation是否有变化,从而判断mm->context.id存放的ASID是否还有效.
 */
void check_and_switch_context(struct mm_struct *mm, unsigned int cpu)
{
	unsigned long flags;
	u64 asid;

	/* 进程的软件ASID通常存放在mm->context.id变量中,这里通过原子变量的读函数atomic64_read读取软件ASID */
	asid = atomic64_read(&mm->context.id);

	/*
	 * The memory ordering here is subtle. We rely on the control
	 * dependency between the generation read and the update of
	 * active_asids to ensure that we are synchronised with a
	 * parallel rollover (i.e. this pairs with the smp_wmb() in
	 * flush_context).
	 *
	 * 这里的内存顺序是很微妙.
	 * 我们依赖于active_asids的生成读取和更新之间的控制依赖关系,以确保我们与并行翻转(即,这与flush_context中的smp_wmb()配对).
	 */

	/* 软件generation计数相同,说明换入进程的ASID还依然属于同一个批次,
	 * 也就是说还没有发生ASID硬件溢出,因此切换进程不需要任何的TLB冲刷操作,
	 * 直接跳转到cpu_switch_mm函数中进行地址切换,另外还需要通过atomit64_xchg原子交换指令来设置ASID到Per-CPU变量active_asids中
	 */
	if (!((asid ^ atomic64_read(&asid_generation)) >> asid_bits)
	    && atomic64_xchg_relaxed(&per_cpu(active_asids, cpu), asid))
		goto switch_mm_fastpath;

	raw_spin_lock_irqsave(&cpu_asid_lock, flags);
	/* Check that our ASID belongs to the current generation. */
	/* 如果软件generation计数不相同,那么说明至少发生了一次ASID硬件溢出,需要分配一个新的软件ASID,并且设置到mm->context.id中. */
	asid = atomic64_read(&mm->context.id);
	if ((asid ^ atomic64_read(&asid_generation)) >> asid_bits) {
		asid = new_context(mm, cpu);
		atomic64_set(&mm->context.id, asid);
	}

	/*
	 * cpumask_test_and_clear_cpu如果该CPU的位已经在tlb_flush_pending里设置,则清除它,返回原来的位
	 * 硬件ASID发生溢出需要将本地TLB冲刷掉
	 */
	if (cpumask_test_and_clear_cpu(cpu, &tlb_flush_pending))
		local_flush_tlb_all();

	/* 设置本地CPU的active_asids为asid */
	atomic64_set(&per_cpu(active_asids, cpu), asid);
	raw_spin_unlock_irqrestore(&cpu_asid_lock, flags);

switch_mm_fastpath:
	cpu_switch_mm(mm->pgd, mm);
}

static int asids_init(void)
{
	asid_bits = get_cpu_asid_bits();
	/*
	 * Expect allocation after rollover to fail if we don't have at least
	 * one more ASID than CPUs. ASID #0 is reserved for init_mm.
	 */
	WARN_ON(NUM_USER_ASIDS - 1 <= num_possible_cpus());
	atomic64_set(&asid_generation, ASID_FIRST_VERSION);
	asid_map = kzalloc(BITS_TO_LONGS(NUM_USER_ASIDS) * sizeof(*asid_map),
			   GFP_KERNEL);
	if (!asid_map)
		panic("Failed to allocate bitmap for %lu ASIDs\n",
		      NUM_USER_ASIDS);

	pr_info("ASID allocator initialised with %lu entries\n", NUM_USER_ASIDS);
	return 0;
}
early_initcall(asids_init);
