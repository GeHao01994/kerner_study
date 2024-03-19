/*
 * Derived from arch/ppc/mm/extable.c and arch/i386/mm/extable.c.
 *
 * Copyright (C) 2004 Paul Mackerras, IBM Corp.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/sort.h>
#include <asm/uaccess.h>


/* &x->insn 是异常表项中成员 insn 的地址,也就是宏 _ASM_EXTABLE 中 .long (from) - .;
 * 指令内位置计数器 “.” 对应的值.
 * x->insn 是异常表项中成员insn的值,也就是(from)-.的值.
 * 两者相加，得到的就是 from 的值，也就是异常发生的地址.
 */
#ifndef ARCH_HAS_RELATIVE_EXTABLE
#define ex_to_insn(x)	((x)->insn)
#else
static inline unsigned long ex_to_insn(const struct exception_table_entry *x)
{
	return (unsigned long)&x->insn + x->insn;
}
#endif

#ifndef ARCH_HAS_SORT_EXTABLE
#ifndef ARCH_HAS_RELATIVE_EXTABLE
#define swap_ex		NULL
#else
static void swap_ex(void *a, void *b, int size)
{
	struct exception_table_entry *x = a, *y = b, tmp;
	int delta = b - a;

	tmp = *x;
	x->insn = y->insn + delta;
	y->insn = tmp.insn - delta;

#ifdef swap_ex_entry_fixup
	swap_ex_entry_fixup(x, y, tmp, delta);
#else
	x->fixup = y->fixup + delta;
	y->fixup = tmp.fixup - delta;
#endif
}
#endif /* ARCH_HAS_RELATIVE_EXTABLE */

/*
 * The exception table needs to be sorted so that the binary
 * search that we use to find entries in it works properly.
 * This is used both for the kernel exception table and for
 * the exception tables of modules that get loaded.
 */
static int cmp_ex(const void *a, const void *b)
{
	const struct exception_table_entry *x = a, *y = b;

	/* avoid overflow */
	if (ex_to_insn(x) > ex_to_insn(y))
		return 1;
	if (ex_to_insn(x) < ex_to_insn(y))
		return -1;
	return 0;
}

void sort_extable(struct exception_table_entry *start,
		  struct exception_table_entry *finish)
{
	sort(start, finish - start, sizeof(struct exception_table_entry),
	     cmp_ex, swap_ex);
}

#ifdef CONFIG_MODULES
/*
 * If the exception table is sorted, any referring to the module init
 * will be at the beginning or the end.
 */
void trim_init_extable(struct module *m)
{
	/*trim the beginning*/
	while (m->num_exentries &&
	       within_module_init(ex_to_insn(&m->extable[0]), m)) {
		m->extable++;
		m->num_exentries--;
	}
	/*trim the end*/
	while (m->num_exentries &&
	       within_module_init(ex_to_insn(&m->extable[m->num_exentries - 1]),
				  m))
		m->num_exentries--;
}
#endif /* CONFIG_MODULES */
#endif /* !ARCH_HAS_SORT_EXTABLE */

#ifndef ARCH_HAS_SEARCH_EXTABLE
/*
 * Search one exception table for an entry corresponding to the
 * given instruction address, and return the address of the entry,
 * or NULL if none is found.
 * We use a binary search, and thus we assume that the table is
 * already sorted.
 *
 * 在一个异常向量表中搜索给定指令地址对应的entry,并返回该entry的地址,
 * 如果没有找到,则返回NULL。
 * 我们使用二进制搜索,因此我们假设表已经排序
 */
const struct exception_table_entry *
search_extable(const struct exception_table_entry *first,
	       const struct exception_table_entry *last,
	       unsigned long value)
{
	/* 如果first <= last,也就是说从first一直到last去循环整个异常向量表
	 * 这里其实是用的二分法
	 */
	while (first <= last) {
		const struct exception_table_entry *mid;

		mid = ((last - first) >> 1) + first;
		/*
		 * careful, the distance between value and insn
		 * can be larger than MAX_LONG:
		 *
		 * 小心,value和insn之间的距离可能大于MAX_LONG:
		 */
		if (ex_to_insn(mid) < value)
			first = mid + 1;
		else if (ex_to_insn(mid) > value)
			last = mid - 1;
		else
			return mid;
	}
	return NULL;
}
#endif
