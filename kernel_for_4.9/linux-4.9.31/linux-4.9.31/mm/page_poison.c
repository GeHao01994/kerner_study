#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/page_ext.h>
#include <linux/poison.h>
#include <linux/ratelimit.h>

static bool __page_poisoning_enabled __read_mostly;
static bool want_page_poisoning __read_mostly;

static int early_page_poison_param(char *buf)
{
	if (!buf)
		return -EINVAL;
	return strtobool(buf, &want_page_poisoning);
}
early_param("page_poison", early_page_poison_param);

bool page_poisoning_enabled(void)
{
	return __page_poisoning_enabled;
}

static bool need_page_poisoning(void)
{
	return want_page_poisoning;
}

static void init_page_poisoning(void)
{
	/*
	 * page poisoning is debug page alloc for some arches. If either
	 * of those options are enabled, enable poisoning
	 */
	if (!IS_ENABLED(CONFIG_ARCH_SUPPORTS_DEBUG_PAGEALLOC)) {
		if (!want_page_poisoning && !debug_pagealloc_enabled())
			return;
	} else {
		if (!want_page_poisoning)
			return;
	}

	__page_poisoning_enabled = true;
}

struct page_ext_operations page_poisoning_ops = {
	.need = need_page_poisoning,
	.init = init_page_poisoning,
};

static inline void set_page_poison(struct page *page)
{
	struct page_ext *page_ext;

	page_ext = lookup_page_ext(page);
	if (unlikely(!page_ext))
		return;

	__set_bit(PAGE_EXT_DEBUG_POISON, &page_ext->flags);
}

static inline void clear_page_poison(struct page *page)
{
	struct page_ext *page_ext;

	page_ext = lookup_page_ext(page);
	if (unlikely(!page_ext))
		return;

	__clear_bit(PAGE_EXT_DEBUG_POISON, &page_ext->flags);
}

bool page_is_poisoned(struct page *page)
{
	struct page_ext *page_ext;

	page_ext = lookup_page_ext(page);
	if (unlikely(!page_ext))
		return false;

	return test_bit(PAGE_EXT_DEBUG_POISON, &page_ext->flags);
}

static void poison_page(struct page *page)
{
	void *addr = kmap_atomic(page);
	/* __set_bit(PAGE_EXT_DEBUG_POISON, &page_ext->flags); */
	set_page_poison(page);
	/* 设置该段地址全部为PAGE_POISON */
	memset(addr, PAGE_POISON, PAGE_SIZE);
	kunmap_atomic(addr);
}

static void poison_pages(struct page *page, int n)
{
	int i;
	/* 对于每个page所在的地址空间都进行设置PAGE_POISON的操作，并且设置 __set_bit(PAGE_EXT_DEBUG_POISON, &page_ext->flags); */
	for (i = 0; i < n; i++)
		poison_page(page + i);
}

static bool single_bit_flip(unsigned char a, unsigned char b)
{
	unsigned char error = a ^ b;

	return error && !(error & (error - 1));
}

static void check_poison_mem(unsigned char *mem, size_t bytes)
{
	/* #define RATELIMIT_STATE_INIT_FLAGS(name, interval_init, burst_init, flags_init) { \
	 * .lock		= __RAW_SPIN_LOCK_UNLOCKED(name.lock),		  \
	 * .interval	= interval_init,				  \
	 * .burst		= burst_init,					  \
	 * .flags		= flags_init,					  \
	 * }
	 *
	 * #define RATELIMIT_STATE_INIT(name, interval_init, burst_init) \
	 *	RATELIMIT_STATE_INIT_FLAGS(name, interval_init, burst_init, 0)
	 *
	 * #define DEFINE_RATELIMIT_STATE(name, interval_init, burst_init)		\
	 * struct ratelimit_state name =					\
	 *	RATELIMIT_STATE_INIT(name, interval_init, burst_init)	\
	 *
	 */
	static DEFINE_RATELIMIT_STATE(ratelimit, 5 * HZ, 10);
	unsigned char *start;
	unsigned char *end;

	if (IS_ENABLED(CONFIG_PAGE_POISONING_NO_SANITY))
		return;
	/**
	 * memchr_inv - Find an unmatching character in an area of memory.
	 * @start: The memory area
	 * @c: Find a character other than c
	 * @bytes: The size of the area.
	 *
	 * returns the address of the first character other than @c, or %NULL
	 * if the whole buffer contains just @c.
	 */

	/* page poison,内存毒药,page free时给page填充特定字节0xaa,在page alloc时check page内容是否有非0xaa的字节,
	 * 有的话,代表当前分配的page被其他page盖到,或者说这个page周边的page有发生内存溢出;
	 */

	/* 这里检查这段memory是不是有PAGE_POISON字节
	 *
	 * #ifdef CONFIG_PAGE_POISONING_ZERO
	 * #define PAGE_POISON 0x00
	 * #else
	 * #define PAGE_POISON 0xaa
	 * #endif
	 */
	start = memchr_inv(mem, PAGE_POISON, bytes);
	if (!start)
		return;

	/* 从end开始,到start(这个start是上面的不等于PAGE_POISON的地址)结束
	 * 检查有没有不等于PAGE_POISON的区域
	 */
	for (end = mem + bytes - 1; end > start; end--) {
		if (*end != PAGE_POISON)
			break;
	}

	if (!__ratelimit(&ratelimit))
		return;/* 如果start == end,并且start就是PAGE_POISON,说明是单个自己错误 */
	else if (start == end && single_bit_flip(*start, PAGE_POISON))
		pr_err("pagealloc: single bit error\n");
	else
		pr_err("pagealloc: memory corruption\n");
	/* 那么就dump出来 */
	print_hex_dump(KERN_ERR, "", DUMP_PREFIX_ADDRESS, 16, 1, start,
			end - start + 1, 1);
	dump_stack();
}

static void unpoison_page(struct page *page)
{
	void *addr;

	if (!page_is_poisoned(page))
		return;

	addr = kmap_atomic(page);
	check_poison_mem(addr, PAGE_SIZE);
	/* 清除page_ext->flags的PAGE_EXT_DEBUG_POISON位
	 * __clear_bit(PAGE_EXT_DEBUG_POISON, &page_ext->flags);
	 */
	clear_page_poison(page);
	kunmap_atomic(addr);
}

static void unpoison_pages(struct page *page, int n)
{
	int i;
	/* 对每个page进行unpoison处理 */
	for (i = 0; i < n; i++)
		unpoison_page(page + i);
}

void kernel_poison_pages(struct page *page, int numpages, int enable)
{
	if (!page_poisoning_enabled())
		return;

	/* 在page alloc的时候enable为1,page free的时候enable为0 */
	if (enable)/* 主要是检查该page是不是有非PAGE_POISON的值,如果有那么说明页面被破坏过,那么就dump stack等一系列的信息操作 还会__clear_bit(PAGE_EXT_DEBUG_POISON, &page_ext->flags); */
		unpoison_pages(page, numpages);
	else	/* 这里主要是设置page代表的地址全部为PAGE_POISON,然后设置__set_bit(PAGE_EXT_DEBUG_POISON, &page_ext->flags); */
		poison_pages(page, numpages);
}

#ifndef CONFIG_ARCH_SUPPORTS_DEBUG_PAGEALLOC
void __kernel_map_pages(struct page *page, int numpages, int enable)
{
	/* This function does nothing, all work is done via poison pages */
}
#endif
