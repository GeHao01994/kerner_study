/*
 *	Berkeley style UIO structures	-	Alan Cox 1994.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef __LINUX_UIO_H
#define __LINUX_UIO_H

#include <linux/kernel.h>
#include <uapi/linux/uio.h>

struct page;
struct pipe_inode_info;

struct kvec {
	void *iov_base; /* and that should *never* hold a userland pointer */
	size_t iov_len;
};

enum {
	ITER_IOVEC = 0,
	ITER_KVEC = 2,
	ITER_BVEC = 4,
	ITER_PIPE = 8,
};

/* iov_iter是iovec的迭代,使用iov_iter结构体的本质是用于协助处理用户态缓冲区
 * 数据和页缓存之间的映射关系
 */
struct iov_iter {
	/* 标识读or写，以及其他属性 */
	int type;
	/* 第一个iovec中，数据起始偏移
	 * 多个数据块是存放在一个指针数组的，数组的一个元素指向一个数据块，
	 * 而iov_offset就是数组第一个元素指向的数据块中的偏移。
	 */
	size_t iov_offset;
	/* 数据大小 */
	size_t count;
	union {
		/* 结构与kvec一致，描述用户态的一段空间 */
		const struct iovec *iov;
		/* 述内核态的一段空间 */
		const struct kvec *kvec;
		/* 描述一个内存页中的一段空间 */
		const struct bio_vec *bvec;
		struct pipe_inode_info *pipe;
	};
	union {
		/* iovec数量 */
		unsigned long nr_segs;
		struct {
			int idx;
			int start_idx;
		};
	};
};

/*
 * Total number of bytes covered by an iovec.
 *
 * NOTE that it is not safe to use this function until all the iovec's
 * segment lengths have been validated.  Because the individual lengths can
 * overflow a size_t when added together.
 */
static inline size_t iov_length(const struct iovec *iov, unsigned long nr_segs)
{
	unsigned long seg;
	size_t ret = 0;

	for (seg = 0; seg < nr_segs; seg++)
		ret += iov[seg].iov_len;
	return ret;
}

static inline struct iovec iov_iter_iovec(const struct iov_iter *iter)
{
	return (struct iovec) {
		.iov_base = iter->iov->iov_base + iter->iov_offset,
		.iov_len = min(iter->count,
			       iter->iov->iov_len - iter->iov_offset),
	};
}

#define iov_for_each(iov, iter, start)				\
	if (!((start).type & (ITER_BVEC | ITER_PIPE)))		\
	for (iter = (start);					\
	     (iter).count &&					\
	     ((iov = iov_iter_iovec(&(iter))), 1);		\
	     iov_iter_advance(&(iter), (iov).iov_len))

unsigned long iov_shorten(struct iovec *iov, unsigned long nr_segs, size_t to);

size_t iov_iter_copy_from_user_atomic(struct page *page,
		struct iov_iter *i, unsigned long offset, size_t bytes);
void iov_iter_advance(struct iov_iter *i, size_t bytes);
void iov_iter_revert(struct iov_iter *i, size_t bytes);
int iov_iter_fault_in_readable(struct iov_iter *i, size_t bytes);
size_t iov_iter_single_seg_count(const struct iov_iter *i);
size_t copy_page_to_iter(struct page *page, size_t offset, size_t bytes,
			 struct iov_iter *i);
size_t copy_page_from_iter(struct page *page, size_t offset, size_t bytes,
			 struct iov_iter *i);
size_t copy_to_iter(const void *addr, size_t bytes, struct iov_iter *i);
size_t copy_from_iter(void *addr, size_t bytes, struct iov_iter *i);
size_t copy_from_iter_nocache(void *addr, size_t bytes, struct iov_iter *i);
size_t iov_iter_zero(size_t bytes, struct iov_iter *);
unsigned long iov_iter_alignment(const struct iov_iter *i);
unsigned long iov_iter_gap_alignment(const struct iov_iter *i);
void iov_iter_init(struct iov_iter *i, int direction, const struct iovec *iov,
			unsigned long nr_segs, size_t count);
void iov_iter_kvec(struct iov_iter *i, int direction, const struct kvec *kvec,
			unsigned long nr_segs, size_t count);
void iov_iter_bvec(struct iov_iter *i, int direction, const struct bio_vec *bvec,
			unsigned long nr_segs, size_t count);
void iov_iter_pipe(struct iov_iter *i, int direction, struct pipe_inode_info *pipe,
			size_t count);
ssize_t iov_iter_get_pages(struct iov_iter *i, struct page **pages,
			size_t maxsize, unsigned maxpages, size_t *start);
ssize_t iov_iter_get_pages_alloc(struct iov_iter *i, struct page ***pages,
			size_t maxsize, size_t *start);
int iov_iter_npages(const struct iov_iter *i, int maxpages);

const void *dup_iter(struct iov_iter *new, struct iov_iter *old, gfp_t flags);

static inline size_t iov_iter_count(const struct iov_iter *i)
{
	return i->count;
}

static inline bool iter_is_iovec(const struct iov_iter *i)
{
	return !(i->type & (ITER_BVEC | ITER_KVEC | ITER_PIPE));
}

/*
 * Get one of READ or WRITE out of iter->type without any other flags OR'd in
 * with it.
 *
 * The ?: is just for type safety.
 */
#define iov_iter_rw(i) ((0 ? (struct iov_iter *)0 : (i))->type & RW_MASK)

/*
 * Cap the iov_iter by given limit; note that the second argument is
 * *not* the new size - it's upper limit for such.  Passing it a value
 * greater than the amount of data in iov_iter is fine - it'll just do
 * nothing in that case.
 */
/* 按给定的限额限制iov_iter;
 * 请注意，第二个参数不是new size，它是上限.
 * 给它传递一个大于iov_iter的数据是最好的，他将什么都不会做
 */
static inline void iov_iter_truncate(struct iov_iter *i, u64 count)
{
	/*
	 * count doesn't have to fit in size_t - comparison extends both
	 * operands to u64 here and any value that would be truncated by
	 * conversion in assignement is by definition greater than all
	 * values of size_t, including old i->count.
	 */
	/* count不必适合size_t- comparison(比较) 在这里将两个操作数都扩展到u64，
	 * 任何通过定义分配时通过转换被截断的的任何值都大于size_t的所有值
	 * 包括旧的i->count.
	 */
	if (i->count > count)
		i->count = count;
}

/*
 * reexpand a previously truncated iterator; count must be no more than how much
 * we had shrunk it.
 */
static inline void iov_iter_reexpand(struct iov_iter *i, size_t count)
{
	i->count = count;
}
size_t csum_and_copy_to_iter(const void *addr, size_t bytes, __wsum *csum, struct iov_iter *i);
size_t csum_and_copy_from_iter(void *addr, size_t bytes, __wsum *csum, struct iov_iter *i);

int import_iovec(int type, const struct iovec __user * uvector,
		 unsigned nr_segs, unsigned fast_segs,
		 struct iovec **iov, struct iov_iter *i);

#ifdef CONFIG_COMPAT
struct compat_iovec;
int compat_import_iovec(int type, const struct compat_iovec __user * uvector,
		 unsigned nr_segs, unsigned fast_segs,
		 struct iovec **iov, struct iov_iter *i);
#endif

int import_single_range(int type, void __user *buf, size_t len,
		 struct iovec *iov, struct iov_iter *i);

#endif
