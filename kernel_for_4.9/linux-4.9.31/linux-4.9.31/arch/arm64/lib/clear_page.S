/*
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

#include <linux/linkage.h>
#include <linux/const.h>
#include <asm/assembler.h>
#include <asm/page.h>

/*
 * Clear page @dest
 *
 * Parameters:
 *	x0 - dest
 */
ENTRY(clear_page)
	/* https://developer.arm.com/documentation/ddi0595/2021-12/AArch64-Registers/DCZID-EL0--Data-Cache-Zero-ID-register
	 * 这里要看上面的ARM手册去了解一下该寄存器
	 *
	 */
	/* 将dczid_el0的寄存器的值读入到x1中 */
	mrs	x1, dczid_el0
	/* w1为x1的最低四位 */
	/* 低4位表示Log2 of the block size in words. The maximum size supported is 2KB */
	and	w1, w1, #0xf
	/* 将4赋值给x2 也就是0b100 */
	mov	x2, #4
	/* 上面的单位是word,这里转换为字节 */
	lsl	x1, x2, x1

	/* 清0,把x0(也就是该page的地址) */
1:	dc	zva, x0
	/* x0 = x0 + x1 */
	add	x0, x0, x1
	/* 如果x0 & #(PAGE_SIZE - 1) 不为0,那么跳到1接着弄 */
	tst	x0, #(PAGE_SIZE - 1)
	b.ne	1b
	ret
ENDPROC(clear_page)
