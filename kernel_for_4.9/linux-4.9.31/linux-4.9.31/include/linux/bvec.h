/*
 * bvec iterator
 *
 * Copyright (C) 2001 Ming Lei <ming.lei@canonical.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public Licens
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-
 */
#ifndef __LINUX_BVEC_ITER_H
#define __LINUX_BVEC_ITER_H

#include <linux/kernel.h>
#include <linux/bug.h>

/*
 * was unsigned short, but we might as well be ready for > 64kB I/O pages
 */
/* 在引入聚散(Scatter-Gather) I/O之前，所有对磁盘数据的读/写操作必须在连续的内存区域上进行.
 * 例如，要读取64K的数据,则读请求必须指定一段64K大小的连续内存区域的地址.
 * 也就是说,如果要在离散的内存区域上读取或写入磁盘数据,有两种方式,这两种方式都非常低效:
 * 1、为每个缓冲区进行一次传输
 * 2、采用一个大的中间缓冲区作为周转.在读取时,首先将数据从磁盘上读到该缓冲区,然后执行内存间
 * 复制到目标缓冲区;或者在写入时,首先将目标缓冲区中的数据复制到该缓冲区,然后进行该缓冲区到磁盘的传输
 *
 * 聚散I/O是这样一种输入/输出方法,即一次过程调用将来自多个缓冲区的数据写到一个数据流,或者从
 * 一个数据读取数据到多个缓冲区.缓冲区以缓冲区向量的形式给出.
 * Scattar/Gather是指从多个缓冲区中收集数据,或者向多个缓冲区散发数据的过程.
 * I/O 可以同步或异步执行. 使用矢量I/O的主要原因是有效性和方便性
 *
 * 为了支持聚散I/O,来自上层的单个bio请求在物理扇区上一定是连续的,但是在内存中并不是一定连续,
 * 换句话说,它可以由多个内存中连续的多个部分组成,每个部分被称为一个请求段(segment),表示为数据结构bio_vec.
 */

/*
 *														      pages
 *										    struct bio		             _________
 *										    				    |         | <---bv_page
 *										     —————————————                  |         |
 *                                                                    ————————————> |bi_io_vec[0] |---------------->|         |
 *                    ____________          _______________          |              |             |                 |_________|<-----bv_offset
 *             ————— | bi_sector  | <------|   bi_iter     |         |               —————————————                  |         |
 *            |      |____________|        |______________ |         |              |bi_io_vec[1] |                 |         |<----- bv_len
 *            |      |  bi_size   |        |    ......     |         |              |_____________|                 |________ |
 *            |      |____________|        |               |         |              |bi_io_vec[2] |
 *            |      |  bi_idx    |        |               |         |              |_____________|
 *            |      |____________|        |_______________|         |              |   ......    |
 *            |      |bi_bvec_done|        |  bi_io_vec    | ________|              |_____________|
 *            |      |____________|        |_______________|
 *            |                            |  bi_pool      |
 *            |                            |_______________|
 *            |                            |bi_inline_vecs |
 *            ↓                            |_______________|
 *  __________ _______________________ ________________
 * | ......   |要操作的实际区域       |......          |
 * |          |                       |                |
 *  —————————— ——————————————————————— ————————————————
 *             物理存储设备
struct bio_vec {
	/* 指向该segment对应的页面的page描述符 */
	struct page	*bv_page;
	/* 该segment的长度(以字节为单位) */
	unsigned int	bv_len;
	/* 该segment的数据在页面中的偏移 */
	unsigned int	bv_offset;
};

struct bvec_iter {
	/* I/O 请求的设备起始扇区(512字节) */
	sector_t		bi_sector;	/* device address in 512 byte
						   sectors */
	/* 剩余的I/O数量 */
	unsigned int		bi_size;	/* residual I/O count */
	/* blv_vec中当前的索引 */
	unsigned int		bi_idx;		/* current index into bvl_vec */
	/* 当前bvec中已经处理完成的字节数 */
	unsigned int            bi_bvec_done;	/* number of bytes completed in
						   current bvec */
};

/*
 * various member access, note that bio_data should of course not be used
 * on highmem page vectors
 */
#define __bvec_iter_bvec(bvec, iter)	(&(bvec)[(iter).bi_idx])

#define bvec_iter_page(bvec, iter)				\
	(__bvec_iter_bvec((bvec), (iter))->bv_page)

#define bvec_iter_len(bvec, iter)				\
	min((iter).bi_size,					\
	    __bvec_iter_bvec((bvec), (iter))->bv_len - (iter).bi_bvec_done)

#define bvec_iter_offset(bvec, iter)				\
	(__bvec_iter_bvec((bvec), (iter))->bv_offset + (iter).bi_bvec_done)

#define bvec_iter_bvec(bvec, iter)				\
((struct bio_vec) {						\
	.bv_page	= bvec_iter_page((bvec), (iter)),	\
	.bv_len		= bvec_iter_len((bvec), (iter)),	\
	.bv_offset	= bvec_iter_offset((bvec), (iter)),	\
})

static inline void bvec_iter_advance(const struct bio_vec *bv,
				     struct bvec_iter *iter,
				     unsigned bytes)
{
	WARN_ONCE(bytes > iter->bi_size,
		  "Attempted to advance past end of bvec iter\n");

	while (bytes) {
		unsigned iter_len = bvec_iter_len(bv, *iter);
		unsigned len = min(bytes, iter_len);

		bytes -= len;
		iter->bi_size -= len;
		iter->bi_bvec_done += len;

		if (iter->bi_bvec_done == __bvec_iter_bvec(bv, *iter)->bv_len) {
			iter->bi_bvec_done = 0;
			iter->bi_idx++;
		}
	}
}

#define for_each_bvec(bvl, bio_vec, iter, start)			\
	for (iter = (start);						\
	     (iter).bi_size &&						\
		((bvl = bvec_iter_bvec((bio_vec), (iter))), 1);	\
	     bvec_iter_advance((bio_vec), &(iter), (bvl).bv_len))

#endif /* __LINUX_BVEC_ITER_H */
