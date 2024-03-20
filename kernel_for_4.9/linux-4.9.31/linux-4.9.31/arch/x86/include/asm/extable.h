#ifndef _ASM_X86_EXTABLE_H
#define _ASM_X86_EXTABLE_H
/*
 * The exception table consists of triples of addresses relative to the
 * exception table entry itself. The first address is of an instruction
 * that is allowed to fault, the second is the target at which the program
 * should continue. The third is a handler function to deal with the fault
 * caused by the instruction in the first field.
 *
 * All the routines below use bits of fixup code that are out of line
 * with the main instruction path.  This means when everything is well,
 * we don't even have to jump over them.  Further, they do not intrude
 * on our cache or tlb entries.
 *
 * 异常表由相对于异常表条目本身的三元组地址组成.
 * 第一个地址是允许fault的指令的地址,第二个地址是程序应该继续的目标地址.
 * 第三个是处理程序函数,用于处理由第一个字段中的指令引起的故障.
 *
 * 下面的所有例程都使用与主指令路径不一致的修复代码位.
 * 这意味着当一切顺利时,我们甚至不必跳过它们.
 * 此外,它们不会侵入我们的cache或tlb条目.
 */

struct exception_table_entry {
	int insn, fixup, handler;
};
struct pt_regs;

#define ARCH_HAS_RELATIVE_EXTABLE

#define swap_ex_entry_fixup(a, b, tmp, delta)			\
	do {							\
		(a)->fixup = (b)->fixup + (delta);		\
		(b)->fixup = (tmp).fixup - (delta);		\
		(a)->handler = (b)->handler + (delta);		\
		(b)->handler = (tmp).handler - (delta);		\
	} while (0)

extern int fixup_exception(struct pt_regs *regs, int trapnr);
extern bool ex_has_fault_handler(unsigned long ip);
extern void early_fixup_exception(struct pt_regs *regs, int trapnr);

#endif
