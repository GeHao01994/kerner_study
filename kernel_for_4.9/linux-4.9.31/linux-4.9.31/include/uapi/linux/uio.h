/*
 *	Berkeley style UIO structures	-	Alan Cox 1994.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _UAPI__LINUX_UIO_H
#define _UAPI__LINUX_UIO_H

#include <linux/compiler.h>
#include <linux/types.h>

/* read系统调用只读取数据到一个用户空间缓冲区，而另外还有一个系统调用readv可以一次性读取
 * 数据到多个用户空间缓冲区.
 * 为了同时支持这两个系统调用，引入了数据结构iovec,字面意思为I/O向量，实际上代表的是一个用户空间缓冲区.
 * 这样，I/O请求可以看作是针对I/O 向量数组的，从这个角度，每个I/O向量也可以被看作一个请求段.
 * I/O向量数组的项数也就是请求段的数目.
 * 事实上，readv系统调用就是以指向I/O向量数组的指针，以I/O向量项数为参数而传入的.
 * 对于read系统调用的实现代码则应该显示得构造I/O向量数组，不过也简单，数组只有一项，
 * 并且这一项I/O 向量的缓冲区地址和长度已经作为系统调用参数传入了
 */
struct iovec
{
	/* 用户空间缓冲区地址 */
	void __user *iov_base;	/* BSD uses caddr_t (1003.1g requires void *) */
	/* 缓冲区长度 */
	__kernel_size_t iov_len; /* Must be size_t (1003.1g) */
};

/*
 *	UIO_MAXIOV shall be at least 16 1003.1g (5.4.1.1)
 */
 
#define UIO_FASTIOV	8
#define UIO_MAXIOV	1024


#endif /* _UAPI__LINUX_UIO_H */
