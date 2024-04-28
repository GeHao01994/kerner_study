/*
 * mm/rmap.c - physical to virtual reverse mappings
 *
 * Copyright 2001, Rik van Riel <riel@conectiva.com.br>
 * Released under the General Public License (GPL).
 *
 * Simple, low overhead reverse mapping scheme.
 * Please try to keep this thing as modular as possible.
 *
 * Provides methods for unmapping each kind of mapped page:
 * the anon methods track anonymous pages, and
 * the file methods track pages belonging to an inode.
 *
 * Original design by Rik van Riel <riel@conectiva.com.br> 2001
 * File methods by Dave McCracken <dmccr@us.ibm.com> 2003, 2004
 * Anonymous methods by Andrea Arcangeli <andrea@suse.de> 2004
 * Contributions by Hugh Dickins 2003, 2004
 */

/*
 * Lock ordering in mm:
 *
 * inode->i_mutex	(while writing or truncating, not reading or faulting)
 *   mm->mmap_sem
 *     page->flags PG_locked (lock_page)
 *       hugetlbfs_i_mmap_rwsem_key (in huge_pmd_share)
 *         mapping->i_mmap_rwsem
 *           anon_vma->rwsem
 *             mm->page_table_lock or pte_lock
 *               zone_lru_lock (in mark_page_accessed, isolate_lru_page)
 *               swap_lock (in swap_duplicate, swap_info_get)
 *                 mmlist_lock (in mmput, drain_mmlist and others)
 *                 mapping->private_lock (in __set_page_dirty_buffers)
 *                   mem_cgroup_{begin,end}_page_stat (memcg->move_lock)
 *                     mapping->tree_lock (widely used)
 *                 inode->i_lock (in set_page_dirty's __mark_inode_dirty)
 *                 bdi.wb->list_lock (in set_page_dirty's __mark_inode_dirty)
 *                   sb_lock (within inode_lock in fs/fs-writeback.c)
 *                   mapping->tree_lock (widely used, in set_page_dirty,
 *                             in arch-dependent flush_dcache_mmap_lock,
 *                             within bdi.wb->list_lock in __sync_single_inode)
 *
 * anon_vma->rwsem,mapping->i_mutex      (memory_failure, collect_procs_anon)
 *   ->tasklist_lock
 *     pte map lock
 */

#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/ksm.h>
#include <linux/rmap.h>
#include <linux/rcupdate.h>
#include <linux/export.h>
#include <linux/memcontrol.h>
#include <linux/mmu_notifier.h>
#include <linux/migrate.h>
#include <linux/hugetlb.h>
#include <linux/backing-dev.h>
#include <linux/page_idle.h>

#include <asm/tlbflush.h>

#include <trace/events/tlb.h>

#include "internal.h"

static struct kmem_cache *anon_vma_cachep;
static struct kmem_cache *anon_vma_chain_cachep;

static inline struct anon_vma *anon_vma_alloc(void)
{
	struct anon_vma *anon_vma;

	/* 分配anon_vma结构体 */
	anon_vma = kmem_cache_alloc(anon_vma_cachep, GFP_KERNEL);
	if (anon_vma) {
		/* 设置anon->refcount为1 */
		atomic_set(&anon_vma->refcount, 1);
		/* 将degree设置为1 */
		anon_vma->degree = 1;	/* Reference for first vma
					 * 第一个vma的参考
					 */
		anon_vma->parent = anon_vma;
		/*
		 * Initialise the anon_vma root to point to itself. If called
		 * from fork, the root will be reset to the parents anon_vma.
		 *
		 * 初始化anon_vma root以指向其自身.如果从fork调用,则根将重置为父级anon_vma
		 */
		anon_vma->root = anon_vma;
	}

	return anon_vma;
}

static inline void anon_vma_free(struct anon_vma *anon_vma)
{
	/* 如果anon_vma->refcount还有值,那么报个BUG吧 */
	VM_BUG_ON(atomic_read(&anon_vma->refcount));

	/*
	 * Synchronize against page_lock_anon_vma_read() such that
	 * we can safely hold the lock without the anon_vma getting
	 * freed.
	 *
	 * Relies on the full mb implied by the atomic_dec_and_test() from
	 * put_anon_vma() against the acquire barrier implied by
	 * down_read_trylock() from page_lock_anon_vma_read(). This orders:
	 *
	 * page_lock_anon_vma_read()	VS	put_anon_vma()
	 *   down_read_trylock()		  atomic_dec_and_test()
	 *   LOCK				  MB
	 *   atomic_read()			  rwsem_is_locked()
	 *
	 * LOCK should suffice since the actual taking of the lock must
	 * happen _before_ what follows.
	 *
	 * 根据page_lock_anon_vma_read()进行同步,这样我们就可以安全地持有锁,而不会释放anon_vma.
	 *
	 * 依靠put_anon_vma()的atomic_dec_and_test()所暗示的完整mb,对抗page_lock_an_vma_read()的down_read_trylock()所隐含的获取屏障.
	 * 此命令:
	 *
	 * page_lock_anon_vma_read()	VS	put_anon_vma()
	 * 	down_read_trylock()			atomic_dec_and_test（）
	 *	LOCK					MB
	 *	atomic_read()				rwsem_is_locked（）
	 *
	 * LOCK应该足够了,因为锁的实际获取必须在下面的事情之前发生.
	 */
	might_sleep();
	if (rwsem_is_locked(&anon_vma->root->rwsem)) {
		anon_vma_lock_write(anon_vma);
		anon_vma_unlock_write(anon_vma);
	}

	/* 释放anon_vma */
	kmem_cache_free(anon_vma_cachep, anon_vma);
}

static inline struct anon_vma_chain *anon_vma_chain_alloc(gfp_t gfp)
{
	return kmem_cache_alloc(anon_vma_chain_cachep, gfp);
}

static void anon_vma_chain_free(struct anon_vma_chain *anon_vma_chain)
{
	kmem_cache_free(anon_vma_chain_cachep, anon_vma_chain);
}

static void anon_vma_chain_link(struct vm_area_struct *vma,
				struct anon_vma_chain *avc,
				struct anon_vma *anon_vma)
{
	/* 让avc->vma指向vma
	 * 让avc->anon_vma指向我们刚才分配的anon_vma
	 * 把刚才分配的avc添加到vma的anon_vma_chain链表中
	 * 把anon_vma_chain添加到anon_vma->rb_root红黑树中
	 */
	avc->vma = vma;
	avc->anon_vma = anon_vma;
	list_add(&avc->same_vma, &vma->anon_vma_chain);
	anon_vma_interval_tree_insert(avc, &anon_vma->rb_root);
}

/**
 * anon_vma_prepare - attach an anon_vma to a memory region
 * @vma: the memory region in question
 *
 * This makes sure the memory mapping described by 'vma' has
 * an 'anon_vma' attached to it, so that we can associate the
 * anonymous pages mapped into it with that anon_vma.
 *
 * The common case will be that we already have one, but if
 * not we either need to find an adjacent mapping that we
 * can re-use the anon_vma from (very common when the only
 * reason for splitting a vma has been mprotect()), or we
 * allocate a new one.
 *
 * Anon-vma allocations are very subtle, because we may have
 * optimistically looked up an anon_vma in page_lock_anon_vma_read()
 * and that may actually touch the spinlock even in the newly
 * allocated vma (it depends on RCU to make sure that the
 * anon_vma isn't actually destroyed).
 *
 * As a result, we need to do proper anon_vma locking even
 * for the new allocation. At the same time, we do not want
 * to do any locking for the common case of already having
 * an anon_vma.
 *
 * This must be called with the mmap_sem held for reading.
 *
 * anon_vma_prepare - 将anon_vma附加到内存区域
 * @vma: 问题中的内存区域
 *
 * 这确保了"vma"描述的内存映射附加了一个"anon_vm",这样我们就可以将映射到其中的匿名页面与该anon_vm相关联.
 *
 * 常见的情况是,我们已经有了一个,但如果没有,我们要么需要找到一个相邻的映射,我们可以重用来自(非常常见的当拆分vma的原因是mprotect()的VMA),或者我们分配一个新的vma。
 *
 * Anon-vma分配非常微妙,因为我们可能乐观地在page_lock_anon_vma_read()中查找了一个anon_vm,
 * 即使在新分配的vma中,它也可能实际接触到spinlock(这取决于RCU来确保anon_vm没有被实际破坏).
 *
 * 因此,即使对于新的分配,我们也需要进行适当的anon_vma锁定.同时,我们不想对已经具有一个anon_vam的常见情况进行任何锁定
 *
 * 这必须在保持mmap_sem以供读取的情况下调用.
 */

/* anon_vma_prepare函数主要为进程地址空间VMA准备struct anon_vma数据结构和一些管理用的链表.
 * RMAP反向映射系统中有两个重要的数据结构,一个是anon_vma,简称AV;
 * 另一个是anon_vma_chain,检查AVC
 */
int anon_vma_prepare(struct vm_area_struct *vma)
{
	struct anon_vma *anon_vma = vma->anon_vma;
	struct anon_vma_chain *avc;

	might_sleep();
	/* VMA数据结构中有一个成员anon_vma用于指向anon_vma数据结构,如果VMA还没有分配过匿名页面,那么vma->anon_vma就NULL */
	if (unlikely(!anon_vma)) {
		struct mm_struct *mm = vma->vm_mm;
		struct anon_vma *allocated;

		/* 分配anon_vma_chain */
		avc = anon_vma_chain_alloc(GFP_KERNEL);
		if (!avc)
			goto out_enomem;
		/* find_mergeable_anon_vma函数检查是否可以复用当前vma的前继者near_vma和后继者prev_vma的anon_vma.
		 * 能复用的判断条件比较苛刻,例如两个VMA必须相邻,VMA的内存policy也必须相同,有相同的vm_file等
		 */
		anon_vma = find_mergeable_anon_vma(vma);
		allocated = NULL;
		/* 如果相邻的VMA无法复用anon_vma,那么重新分配一个anon_vma数据结构 */
		if (!anon_vma) {
			anon_vma = anon_vma_alloc();
			if (unlikely(!anon_vma))
				goto out_enomem_free_avc;
			allocated = anon_vma;
		}

		anon_vma_lock_write(anon_vma);
		/* page_table_lock to protect against threads */
		spin_lock(&mm->page_table_lock);
		/* 如果vma->anon_vma为NULL */
		if (likely(!vma->anon_vma)) {
			/* 把anon_vma填充给vma->anon_vma */
			vma->anon_vma = anon_vma;
			/* anon_vma_chain_link函数会把刚才分配的avc添加到vma的anon_vma_chain链表中,另外把avc添加到anon_vma->rb_root红黑树中 */
			anon_vma_chain_link(vma, avc, anon_vma);
			/* vma reference or self-parent link for new root
			 * 对新的root的vma引用或者来自父链接
			 */
			anon_vma->degree++;
			allocated = NULL;
			avc = NULL;
		}
		spin_unlock(&mm->page_table_lock);
		anon_vma_unlock_write(anon_vma);

		/* 如果有了就把他们都释放了,因为在上面如果没有的话就会分配,处理完之后就会把allocated和avc都设置为NULL */

		if (unlikely(allocated))
			put_anon_vma(allocated);
		if (unlikely(avc))
			anon_vma_chain_free(avc);
	}
	return 0;

 out_enomem_free_avc:
	anon_vma_chain_free(avc);
 out_enomem:
	return -ENOMEM;
}

/*
 * This is a useful helper function for locking the anon_vma root as
 * we traverse the vma->anon_vma_chain, looping over anon_vma's that
 * have the same vma.
 *
 * Such anon_vma's should have the same root, so you'd expect to see
 * just a single mutex_lock for the whole traversal.
 */
static inline struct anon_vma *lock_anon_vma_root(struct anon_vma *root, struct anon_vma *anon_vma)
{
	struct anon_vma *new_root = anon_vma->root;
	if (new_root != root) {
		if (WARN_ON_ONCE(root))
			up_write(&root->rwsem);
		root = new_root;
		down_write(&root->rwsem);
	}
	return root;
}

static inline void unlock_anon_vma_root(struct anon_vma *root)
{
	if (root)
		up_write(&root->rwsem);
}

/*
 * Attach the anon_vmas from src to dst.
 * Returns 0 on success, -ENOMEM on failure.
 *
 * If dst->anon_vma is NULL this function tries to find and reuse existing
 * anon_vma which has no vmas and only one child anon_vma. This prevents
 * degradation of anon_vma hierarchy to endless linear chain in case of
 * constantly forking task. On the other hand, an anon_vma with more than one
 * child isn't reused even if there was no alive vma, thus rmap walker has a
 * good chance of avoiding scanning the whole hierarchy when it searches where
 * page is mapped.
 *
 * 将anon_vm从src附加到dst.
 * 成功时返回0,失败时返回-ENOMEM.
 *
 * 如果dst->anon_vm为NULL,则此函数将尝试查找并重用现有的没有vmas且只有一个子anon_vma的anon_vma.
 * 这防止了在不断fork task的情况下,将anon_vm层次降级为无尽的线性链.
 *
 * 另一方面,具有多个的anon_vm即使没有活动的vma,child也不会被重用,因此rmap-walker在搜索页面映射的位置时,很有可能避免扫描整个层次结构.
 */
int anon_vma_clone(struct vm_area_struct *dst, struct vm_area_struct *src)
{
	struct anon_vma_chain *avc, *pavc;
	struct anon_vma *root = NULL;

	/* 遍历父进程VMA中的anon_vma_chain链表寻找anon_vma_chain实例.
	 * 父进程在为VMA分配匿名页面时,do_anonymous_page()->anon_vma_prepare函数会分配一个anon_vma_chain实例并挂入到VMA的anon_vma_chain链表中
	 * 因此可以很容易得通过链表找到anon_vma_chain实例,在代码中这个实例叫做pavc.
	 */
	list_for_each_entry_reverse(pavc, &src->anon_vma_chain, same_vma) {
		struct anon_vma *anon_vma;
		/* 分配一个属于子进程的avc数据结构 */
		avc = anon_vma_chain_alloc(GFP_NOWAIT | __GFP_NOWARN);
		if (unlikely(!avc)) {
			unlock_anon_vma_root(root);
			root = NULL;
			avc = anon_vma_chain_alloc(GFP_KERNEL);
			if (!avc)
				goto enomem_failure;
		}
		/* 拿到父进程VMA中的anon_vma */
		anon_vma = pavc->anon_vma;
		root = lock_anon_vma_root(root, anon_vma);
		/* 把属于子进程的avc挂入子进程中VMA的anon_vma_chain链表中,同时也把avc添加到属于父进程的anon_vma->rb_root的红黑树中,
		 * 使子进程和父进程的VMA之间有一个联系的纽带
		 * 这里没有设置dst->anon_vma = anon_vma
		 */
		anon_vma_chain_link(dst, avc, anon_vma);

		/*
		 * Reuse existing anon_vma if its degree lower than two,
		 * that means it has no vma and only one anon_vma child.
		 *
		 * Do not chose parent anon_vma, otherwise first child
		 * will always reuse it. Root anon_vma is never reused:
		 * it has self-parent reference and at least one child.
		 *
		 * 如果现有的anon_vma的阶数低于2,则重用它,这意味着它没有vma,只有一个子级anon_vma
		 *
		 * 不要选择父级anon_vma,否则第一个子级将始终重用它.
		 * root anon_vma从不重用: 它具有自父级引用和至少一个子级.
		 */
		if (!dst->anon_vma && anon_vma != src->anon_vma &&
				anon_vma->degree < 2)
			dst->anon_vma = anon_vma;
	}
	if (dst->anon_vma)
		dst->anon_vma->degree++;
	unlock_anon_vma_root(root);
	return 0;

 enomem_failure:
	/*
	 * dst->anon_vma is dropped here otherwise its degree can be incorrectly
	 * decremented in unlink_anon_vmas().
	 * We can safely do this because callers of anon_vma_clone() don't care
	 * about dst->anon_vma if anon_vma_clone() failed.
	 */
	dst->anon_vma = NULL;
	unlink_anon_vmas(dst);
	return -ENOMEM;
}

/*
 * Attach vma to its own anon_vma, as well as to the anon_vmas that
 * the corresponding VMA in the parent process is attached to.
 * Returns 0 on success, non-zero on failure.
 *
 * 将vma附加到它自己的anon_vma,以及父进程中相应的vma所附加到的anon_vm.成功时返回0,失败时返回非零.
 */
int anon_vma_fork(struct vm_area_struct *vma, struct vm_area_struct *pvma)
{
	struct anon_vma_chain *avc;
	struct anon_vma *anon_vma;
	int error;

	/* Don't bother if the parent process has no anon_vma here.
	 * 如果父进程在此处没有anon_vm,请不要麻烦
	 */

	/* 如果父进程的vma的anon_vma是NULL的,那么直接返回0 */
	if (!pvma->anon_vma)
		return 0;

	/* Drop inherited anon_vma, we'll reuse existing or allocate new.
	 * 删除继承的anon_vm,我们将重用现有的或分配新的.
	 */
	vma->anon_vma = NULL;

	/*
	 * First, attach the new VMA to the parent VMA's anon_vmas,
	 * so rmap can find non-COWed pages in child processes.
	 *
	 * 首先,将新的VMA附加到父VMA的anon_vm,这样rmap就可以在子进程中找到非COWed页面.
	 */
	error = anon_vma_clone(vma, pvma);
	if (error)
		return error;

	/* An existing anon_vma has been reused, all done then.
	 * 已经重用了一个现有的anon_vm,所有这些都在那时完成.
	 */
	/* 如果经过anon_vma_clone已经有anon_vma了,那么直接返回0 */
	if (vma->anon_vma)
		return 0;

	/* Then add our own anon_vma.
	 * 这时添加我们自己的anon_vma
	 */
	/* 因为子进程下面还会fork出进程啊,所以你得形成自己的那套啊 */
	/* 分配一个anon_vma */
	anon_vma = anon_vma_alloc();
	if (!anon_vma)
		goto out_error;
	/* 分配一个avc */
	avc = anon_vma_chain_alloc(GFP_KERNEL);
	if (!avc)
		goto out_error_free_anon_vma;

	/*
	 * The root anon_vma's spinlock is the lock actually used when we
	 * lock any of the anon_vmas in this anon_vma tree.
	 *
	 * root anon_vma的spinlock是当我们锁定此anon_vma树中的任何anon_vma时实际使用的锁.
	 */
	/* 注意这是pvma->anon_vma->root 而不是pvma->anon_vma->rb_root,就这把自己绕进去了好久 */
	anon_vma->root = pvma->anon_vma->root;
	anon_vma->parent = pvma->anon_vma;
	/*
	 * With refcounts, an anon_vma can stay around longer than the
	 * process it belongs to. The root anon_vma needs to be pinned until
	 * this anon_vma is freed, because the lock lives in the root.
	 *
	 * 有了refcounts,一个anon_vma可以比它所属的进程停留更长的时间.
	 * 根anon_vm需要被固定,直到这个anon_vma被释放,因为锁在根中.
	 */

	/*  static inline void get_anon_vma(struct anon_vma *anon_vma)
	 * {
	 *	atomic_inc(&anon_vma->refcount);
	 * }
	 */
	get_anon_vma(anon_vma->root);
	/* Mark this anon_vma as the one where our new (COWed) pages go.
	 * 将此anon_vma标记为我们新(COWed)页面的所在位置.
	 */
	vma->anon_vma = anon_vma;
	anon_vma_lock_write(anon_vma);
	/* static void anon_vma_chain_link(struct vm_area_struct *vma,
	 *			struct anon_vma_chain *avc,
	 *			struct anon_vma *anon_vma)
	 * {
	 *	avc->vma = vma;
	 *	avc->anon_vma = anon_vma;
	 *	list_add(&avc->same_vma, &vma->anon_vma_chain);
	 *	anon_vma_interval_tree_insert(avc, &anon_vma->rb_root);
	 * }
	 */
	anon_vma_chain_link(vma, avc, anon_vma);
	anon_vma->parent->degree++;
	anon_vma_unlock_write(anon_vma);

	return 0;

 out_error_free_anon_vma:
	put_anon_vma(anon_vma);
 out_error:
	unlink_anon_vmas(vma);
	return -ENOMEM;
}

void unlink_anon_vmas(struct vm_area_struct *vma)
{
	struct anon_vma_chain *avc, *next;
	struct anon_vma *root = NULL;

	/*
	 * Unlink each anon_vma chained to the VMA.  This list is ordered
	 * from newest to oldest, ensuring the root anon_vma gets freed last.
	 */
	list_for_each_entry_safe(avc, next, &vma->anon_vma_chain, same_vma) {
		struct anon_vma *anon_vma = avc->anon_vma;

		root = lock_anon_vma_root(root, anon_vma);
		anon_vma_interval_tree_remove(avc, &anon_vma->rb_root);

		/*
		 * Leave empty anon_vmas on the list - we'll need
		 * to free them outside the lock.
		 */
		if (RB_EMPTY_ROOT(&anon_vma->rb_root)) {
			anon_vma->parent->degree--;
			continue;
		}

		list_del(&avc->same_vma);
		anon_vma_chain_free(avc);
	}
	if (vma->anon_vma)
		vma->anon_vma->degree--;
	unlock_anon_vma_root(root);

	/*
	 * Iterate the list once more, it now only contains empty and unlinked
	 * anon_vmas, destroy them. Could not do before due to __put_anon_vma()
	 * needing to write-acquire the anon_vma->root->rwsem.
	 */
	list_for_each_entry_safe(avc, next, &vma->anon_vma_chain, same_vma) {
		struct anon_vma *anon_vma = avc->anon_vma;

		VM_WARN_ON(anon_vma->degree);
		put_anon_vma(anon_vma);

		list_del(&avc->same_vma);
		anon_vma_chain_free(avc);
	}
}

static void anon_vma_ctor(void *data)
{
	struct anon_vma *anon_vma = data;

	init_rwsem(&anon_vma->rwsem);
	atomic_set(&anon_vma->refcount, 0);
	anon_vma->rb_root = RB_ROOT;
}

void __init anon_vma_init(void)
{
	anon_vma_cachep = kmem_cache_create("anon_vma", sizeof(struct anon_vma),
			0, SLAB_DESTROY_BY_RCU|SLAB_PANIC|SLAB_ACCOUNT,
			anon_vma_ctor);
	anon_vma_chain_cachep = KMEM_CACHE(anon_vma_chain,
			SLAB_PANIC|SLAB_ACCOUNT);
}

/*
 * Getting a lock on a stable anon_vma from a page off the LRU is tricky!
 *
 * Since there is no serialization what so ever against page_remove_rmap()
 * the best this function can do is return a locked anon_vma that might
 * have been relevant to this page.
 *
 * The page might have been remapped to a different anon_vma or the anon_vma
 * returned may already be freed (and even reused).
 *
 * In case it was remapped to a different anon_vma, the new anon_vma will be a
 * child of the old anon_vma, and the anon_vma lifetime rules will therefore
 * ensure that any anon_vma obtained from the page will still be valid for as
 * long as we observe page_mapped() [ hence all those page_mapped() tests ].
 *
 * All users of this function must be very careful when walking the anon_vma
 * chain and verify that the page in question is indeed mapped in it
 * [ something equivalent to page_mapped_in_vma() ].
 *
 * Since anon_vma's slab is DESTROY_BY_RCU and we know from page_remove_rmap()
 * that the anon_vma pointer from page->mapping is valid if there is a
 * mapcount, we can dereference the anon_vma after observing those.
 */
struct anon_vma *page_get_anon_vma(struct page *page)
{
	struct anon_vma *anon_vma = NULL;
	unsigned long anon_mapping;

	rcu_read_lock();
	anon_mapping = (unsigned long)READ_ONCE(page->mapping);
	if ((anon_mapping & PAGE_MAPPING_FLAGS) != PAGE_MAPPING_ANON)
		goto out;
	if (!page_mapped(page))
		goto out;

	anon_vma = (struct anon_vma *) (anon_mapping - PAGE_MAPPING_ANON);
	if (!atomic_inc_not_zero(&anon_vma->refcount)) {
		anon_vma = NULL;
		goto out;
	}

	/*
	 * If this page is still mapped, then its anon_vma cannot have been
	 * freed.  But if it has been unmapped, we have no security against the
	 * anon_vma structure being freed and reused (for another anon_vma:
	 * SLAB_DESTROY_BY_RCU guarantees that - so the atomic_inc_not_zero()
	 * above cannot corrupt).
	 */
	if (!page_mapped(page)) {
		rcu_read_unlock();
		put_anon_vma(anon_vma);
		return NULL;
	}
out:
	rcu_read_unlock();

	return anon_vma;
}

/*
 * Similar to page_get_anon_vma() except it locks the anon_vma.
 *
 * Its a little more complex as it tries to keep the fast path to a single
 * atomic op -- the trylock. If we fail the trylock, we fall back to getting a
 * reference like with page_get_anon_vma() and then block on the mutex.
 *
 * 类似于page_get_anon_vma(),只是它锁定了anon_vma.
 *
 * 它有点复杂,因为它试图保持到单个原子操作的快速路径 -- trylock.
 * 如果trylock失败,我们将返回到获取引用,如page_get_an_vma(),然后阻塞互斥体.
 */
struct anon_vma *page_lock_anon_vma_read(struct page *page)
{
	struct anon_vma *anon_vma = NULL;
	struct anon_vma *root_anon_vma;
	unsigned long anon_mapping;

	rcu_read_lock();
	/* 拿到anon_mapping */
	anon_mapping = (unsigned long)READ_ONCE(page->mapping);
	/* 如果不是匿名映射,那么直接goto out */
	if ((anon_mapping & PAGE_MAPPING_FLAGS) != PAGE_MAPPING_ANON)
		goto out;
	/*
	 * page_mapped的作用如下解释:
	 * page_mapped(): Return true if this page is mapped into pagetables.
	 */
	if (!page_mapped(page))
		goto out;

	/* 拿到该page的anon_vma */
	anon_vma = (struct anon_vma *) (anon_mapping - PAGE_MAPPING_ANON);
	/* 拿到该anon_vma的root_anon_vma */
	root_anon_vma = READ_ONCE(anon_vma->root);
	/* 尝试去拿到root_anon_vma->rwsem */
	if (down_read_trylock(&root_anon_vma->rwsem)) {
		/*
		 * If the page is still mapped, then this anon_vma is still
		 * its anon_vma, and holding the mutex ensures that it will
		 * not go away, see anon_vma_free().
		 *
		 * 如果页面仍然被映射,那么这个anon_vma仍然是它的anon_vm,并且拿到mutex可以确保它不会消失,请参见anon_vma _free()
		 */
		/* 如果page已经没有映射进页表了,那么update_read之后把anon_vma设置为NULL之后返回 */
		if (!page_mapped(page)) {
			up_read(&root_anon_vma->rwsem);
			anon_vma = NULL;
		}
		goto out;
	}

	/* trylock failed, we got to sleep
	 * trylock失败,我们准备去睡眠
	 */

	/* 如果anon_vma->refcount不是0,那么就+1
	 * 如果是0,赋值anon_vma = NULL后直接返回
	 */
	if (!atomic_inc_not_zero(&anon_vma->refcount)) {
		anon_vma = NULL;
		goto out;
	}

	/*
	 * page_mapped的作用如下解释:
	 * page_mapped(): Return true if this page is mapped into pagetables.
	 */
	if (!page_mapped(page)) {
		/* 解锁 */
		rcu_read_unlock();
		/* 释放anon_vma */
		put_anon_vma(anon_vma);
		return NULL;
	}

	/* we pinned the anon_vma, its safe to sleep */
	rcu_read_unlock();
	/*
	 *  static inline void anon_vma_lock_read(struct anon_vma *anon_vma)
	 * {
	 *	down_read(&anon_vma->root->rwsem);
	 * }
	 */
	anon_vma_lock_read(anon_vma);

	/* 将anon_vma->refcount -1之后判断它等不等于0 */
	if (atomic_dec_and_test(&anon_vma->refcount)) {
		/*
		 * Oops, we held the last refcount, release the lock
		 * and bail -- can't simply use put_anon_vma() because
		 * we'll deadlock on the anon_vma_lock_write() recursion.
		 *
		 * Oops,我们保留了最后一个refcount,释放了锁和保释 -- 不能简单地使用put_anon_vma(),
		 * 因为我们会在anon_vma_lock_write()递归上死锁.
		 */
		anon_vma_unlock_read(anon_vma);
		/* 释放anon_vma */
		__put_anon_vma(anon_vma);
		anon_vma = NULL;
	}

	/* 返回anon_vma */
	return anon_vma;

out:
	rcu_read_unlock();
	return anon_vma;
}

void page_unlock_anon_vma_read(struct anon_vma *anon_vma)
{
	anon_vma_unlock_read(anon_vma);
}

#ifdef CONFIG_ARCH_WANT_BATCHED_UNMAP_TLB_FLUSH
/*
 * Flush TLB entries for recently unmapped pages from remote CPUs. It is
 * important if a PTE was dirty when it was unmapped that it's flushed
 * before any IO is initiated on the page to prevent lost writes. Similarly,
 * it must be flushed before freeing to prevent data leakage.
 */
void try_to_unmap_flush(void)
{
	struct tlbflush_unmap_batch *tlb_ubc = &current->tlb_ubc;
	int cpu;

	if (!tlb_ubc->flush_required)
		return;

	cpu = get_cpu();

	if (cpumask_test_cpu(cpu, &tlb_ubc->cpumask)) {
		count_vm_tlb_event(NR_TLB_LOCAL_FLUSH_ALL);
		local_flush_tlb();
		trace_tlb_flush(TLB_LOCAL_SHOOTDOWN, TLB_FLUSH_ALL);
	}

	if (cpumask_any_but(&tlb_ubc->cpumask, cpu) < nr_cpu_ids)
		flush_tlb_others(&tlb_ubc->cpumask, NULL, 0, TLB_FLUSH_ALL);
	cpumask_clear(&tlb_ubc->cpumask);
	tlb_ubc->flush_required = false;
	tlb_ubc->writable = false;
	put_cpu();
}

/* Flush iff there are potentially writable TLB entries that can race with IO */
void try_to_unmap_flush_dirty(void)
{
	struct tlbflush_unmap_batch *tlb_ubc = &current->tlb_ubc;

	if (tlb_ubc->writable)
		try_to_unmap_flush();
}

static void set_tlb_ubc_flush_pending(struct mm_struct *mm,
		struct page *page, bool writable)
{
	struct tlbflush_unmap_batch *tlb_ubc = &current->tlb_ubc;

	cpumask_or(&tlb_ubc->cpumask, &tlb_ubc->cpumask, mm_cpumask(mm));
	tlb_ubc->flush_required = true;

	/*
	 * If the PTE was dirty then it's best to assume it's writable. The
	 * caller must use try_to_unmap_flush_dirty() or try_to_unmap_flush()
	 * before the page is queued for IO.
	 */
	if (writable)
		tlb_ubc->writable = true;
}

/*
 * Returns true if the TLB flush should be deferred to the end of a batch of
 * unmap operations to reduce IPIs.
 */
static bool should_defer_flush(struct mm_struct *mm, enum ttu_flags flags)
{
	bool should_defer = false;

	if (!(flags & TTU_BATCH_FLUSH))
		return false;

	/* If remote CPUs need to be flushed then defer batch the flush */
	if (cpumask_any_but(mm_cpumask(mm), get_cpu()) < nr_cpu_ids)
		should_defer = true;
	put_cpu();

	return should_defer;
}
#else
static void set_tlb_ubc_flush_pending(struct mm_struct *mm,
		struct page *page, bool writable)
{
}

static bool should_defer_flush(struct mm_struct *mm, enum ttu_flags flags)
{
	return false;
}
#endif /* CONFIG_ARCH_WANT_BATCHED_UNMAP_TLB_FLUSH */

/*
 * At what user virtual address is page expected in vma?
 * Caller should check the page is actually part of the vma.
 */
unsigned long page_address_in_vma(struct page *page, struct vm_area_struct *vma)
{
	unsigned long address;
	if (PageAnon(page)) {
		struct anon_vma *page__anon_vma = page_anon_vma(page);
		/*
		 * Note: swapoff's unuse_vma() is more efficient with this
		 * check, and needs it to match anon_vma when KSM is active.
		 */
		if (!vma->anon_vma || !page__anon_vma ||
		    vma->anon_vma->root != page__anon_vma->root)
			return -EFAULT;
	} else if (page->mapping) {
		if (!vma->vm_file || vma->vm_file->f_mapping != page->mapping)
			return -EFAULT;
	} else
		return -EFAULT;
	address = __vma_address(page, vma);
	if (unlikely(address < vma->vm_start || address >= vma->vm_end))
		return -EFAULT;
	return address;
}

pmd_t *mm_find_pmd(struct mm_struct *mm, unsigned long address)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd = NULL;
	pmd_t pmde;

	pgd = pgd_offset(mm, address);
	if (!pgd_present(*pgd))
		goto out;

	pud = pud_offset(pgd, address);
	if (!pud_present(*pud))
		goto out;

	pmd = pmd_offset(pud, address);
	/*
	 * Some THP functions use the sequence pmdp_huge_clear_flush(), set_pmd_at()
	 * without holding anon_vma lock for write.  So when looking for a
	 * genuine pmde (in which to find pte), test present and !THP together.
	 */
	pmde = *pmd;
	barrier();
	if (!pmd_present(pmde) || pmd_trans_huge(pmde))
		pmd = NULL;
out:
	return pmd;
}

/*
 * Check that @page is mapped at @address into @mm.
 *
 * If @sync is false, page_check_address may perform a racy check to avoid
 * the page table lock when the pte is not present (helpful when reclaiming
 * highly shared pages).
 *
 * On success returns with pte mapped and locked.
 */
pte_t *__page_check_address(struct page *page, struct mm_struct *mm,
			  unsigned long address, spinlock_t **ptlp, int sync)
{
	pmd_t *pmd;
	pte_t *pte;
	spinlock_t *ptl;

	if (unlikely(PageHuge(page))) {
		/* when pud is not present, pte will be NULL */
		pte = huge_pte_offset(mm, address);
		if (!pte)
			return NULL;

		ptl = huge_pte_lockptr(page_hstate(page), mm, pte);
		goto check;
	}

	pmd = mm_find_pmd(mm, address);
	if (!pmd)
		return NULL;

	pte = pte_offset_map(pmd, address);
	/* Make a quick check before getting the lock */
	if (!sync && !pte_present(*pte)) {
		pte_unmap(pte);
		return NULL;
	}

	ptl = pte_lockptr(mm, pmd);
check:
	spin_lock(ptl);
	if (pte_present(*pte) && page_to_pfn(page) == pte_pfn(*pte)) {
		*ptlp = ptl;
		return pte;
	}
	pte_unmap_unlock(pte, ptl);
	return NULL;
}

/**
 * page_mapped_in_vma - check whether a page is really mapped in a VMA
 * @page: the page to test
 * @vma: the VMA to test
 *
 * Returns 1 if the page is mapped into the page tables of the VMA, 0
 * if the page is not mapped into the page tables of this VMA.  Only
 * valid for normal file or anonymous VMAs.
 */
int page_mapped_in_vma(struct page *page, struct vm_area_struct *vma)
{
	unsigned long address;
	pte_t *pte;
	spinlock_t *ptl;

	address = __vma_address(page, vma);
	if (unlikely(address < vma->vm_start || address >= vma->vm_end))
		return 0;
	pte = page_check_address(page, vma->vm_mm, address, &ptl, 1);
	if (!pte)			/* the page is not in this mm */
		return 0;
	pte_unmap_unlock(pte, ptl);

	return 1;
}

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
/*
 * Check that @page is mapped at @address into @mm. In contrast to
 * page_check_address(), this function can handle transparent huge pages.
 *
 * On success returns true with pte mapped and locked. For PMD-mapped
 * transparent huge pages *@ptep is set to NULL.
 *
 * 检查@page是否在@address映射到@mm.
 * 与page_check_address()不同,此函数可以处理透明的巨大页面.
 *
 * 成功时,pte映射并锁定后返回true.
 * 对于PMD-mapped的透明大页,*@ptep设置为NULL.
 */
bool page_check_address_transhuge(struct page *page, struct mm_struct *mm,
				  unsigned long address, pmd_t **pmdp,
				  pte_t **ptep, spinlock_t **ptlp)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	spinlock_t *ptl;

	/* 这是HUGETLB的case */
	if (unlikely(PageHuge(page))) {
		/* when pud is not present, pte will be NULL */
		pte = huge_pte_offset(mm, address);
		if (!pte)
			return false;

		ptl = huge_pte_lockptr(page_hstate(page), mm, pte);
		pmd = NULL;
		goto check_pte;
	}

	/* 通过mm和address获取pgd */
	pgd = pgd_offset(mm, address);
	/* 如果pgd不在内存中,那么返回false */
	if (!pgd_present(*pgd))
		return false;
	/* 通过pgd和address获取pud */
	pud = pud_offset(pgd, address);
	/* 如果pud不在内存中,那么也返回false */
	if (!pud_present(*pud))
		return false;
	/* 通过pud和address获得pmd */
	pmd = pmd_offset(pud, address);

	/* 如果pmd是块映射,也就是THP */
	if (pmd_trans_huge(*pmd)) {
		/* 获取锁 */
		ptl = pmd_lock(mm, pmd);
		/* 如果pmd没在内存中,那么goto unlock_pmd */
		if (!pmd_present(*pmd))
			goto unlock_pmd;
		/* 如果不是THP,那么解锁之后跳到map_pte处 */
		if (unlikely(!pmd_trans_huge(*pmd))) {
			spin_unlock(ptl);
			goto map_pte;
		}

		/* 如果page不一致,那么也去unlock_pmd */
		if (pmd_page(*pmd) != page)
			goto unlock_pmd;

		/* 否则设置pte为NULL之后goto found */
		pte = NULL;
		goto found;
unlock_pmd:
		/* 解锁之后返回false */
		spin_unlock(ptl);
		return false;
	} else {
		pmd_t pmde = *pmd;

		barrier();
		/* 如果pmd不在内存中,或者说是THP,那么返回false */
		if (!pmd_present(pmde) || pmd_trans_huge(pmde))
			return false;
	}
map_pte:
	/* 通过pmd和address算出pte */
	pte = pte_offset_map(pmd, address);
	/* 如果pte不在内存中 */
	if (!pte_present(*pte)) {
		/* arm64,此处为空函数 */
		pte_unmap(pte);
		/* 返回false */
		return false;
	}

	/* 拿到锁 */
	ptl = pte_lockptr(mm, pmd);
check_pte:
	/* 锁上 */
	spin_lock(ptl);

	/* 如果pte不在内存中 */
	if (!pte_present(*pte)) {
		/* 这边是unlock之后返回NULL */
		pte_unmap_unlock(pte, ptl);
		return false;
	}

	/* THP can be referenced by any subpage
	 * THP能被任何子页引用
	 */
	/* 用pte的页帧号 - page的页帧号大于THP的page,那么不就出去了吗?
	 * 实际上说的就是有THP引用了你的子页面
	 */
	if (pte_pfn(*pte) - page_to_pfn(page) >= hpage_nr_pages(page)) {
		/* unlock之后返回false */
		pte_unmap_unlock(pte, ptl);
		return false;
	}
found:
	*ptep = pte;
	*pmdp = pmd;
	*ptlp = ptl;
	return true;
}
#endif /* CONFIG_TRANSPARENT_HUGEPAGE */

struct page_referenced_arg {
	int mapcount;
	int referenced;
	unsigned long vm_flags;
	struct mem_cgroup *memcg;
};
/*
 * arg: page_referenced_arg will be passed
 *
 * arg: page_referenced_arg将被传递
 */
static int page_referenced_one(struct page *page, struct vm_area_struct *vma,
			unsigned long address, void *arg)
{
	struct mm_struct *mm = vma->vm_mm;
	struct page_referenced_arg *pra = arg;
	pmd_t *pmd;
	pte_t *pte;
	spinlock_t *ptl;
	int referenced = 0;

	/* page_check_address_transhuge: Check that @page is mapped at @address into @mm.
	 * 如果返回false,那么直接返回SWAP_AGAIN
	 */
	if (!page_check_address_transhuge(page, mm, address, &pmd, &pte, &ptl))
		return SWAP_AGAIN;

	/* 如果vma->vm_flags带了VM_LOCKED */
	if (vma->vm_flags & VM_LOCKED) {
		/* 如果有pte,那么调用pte_unmap */
		if (pte)
			pte_unmap(pte);
		/* 解锁 */
		spin_unlock(ptl);
		/* 将pra->vm_flags带上VM_LOCKED */
		pra->vm_flags |= VM_LOCKED;
		/* 返回SWAP_FAIL会跳出循环的 */
		return SWAP_FAIL; /* To break the loop */
	}

	/* 如果是常规page 映射 */
	if (pte) {
		/* 清除pte的YOUNG bit */
		if (ptep_clear_flush_young_notify(vma, address, pte)) {
			/*
			 * Don't treat a reference through a sequentially read
			 * mapping as such.  If the page has been used in
			 * another mapping, we will catch it; if this other
			 * mapping is already gone, the unmap path will have
			 * set PG_referenced or activated the page.
			 *
			 * 不要这样对待通过顺序读取映射的引用.
			 * 如果该页面已在另一个映射中使用,我们将捕获它;
			 * 如果其他映射已经消失,则取消映射路径将设置PG_referenced或将页面放入活跃链表里面.
			 */

			/* 如果vma->vm_flags不是顺序读,那么referenced++ */
			if (likely(!(vma->vm_flags & VM_SEQ_READ)))
				referenced++;
		}
		/* 调用pte_unmap */
		pte_unmap(pte);
		/* 如果定义了THP */
	} else if (IS_ENABLED(CONFIG_TRANSPARENT_HUGEPAGE)) {
		/* 清除pmd的young bit位,referenced++ */
		if (pmdp_clear_flush_young_notify(vma, address, pmd))
			referenced++;
	} else {
		/* unexpected pmd-mapped page?
		 * 不预期的pmd-mapped的页面?
		 */
		WARN_ON_ONCE(1);
	}
	/* 解锁 */
	spin_unlock(ptl);

	/* 如果有referenced,清除PG_idle,PG_idle应该说的是page是idle的,也就是空闲页面 */
	if (referenced)
		clear_page_idle(page);

	/* 这边就是还想清除page的young */
	if (test_and_clear_page_young(page))
		referenced++;

	/* 如果有referenced,那么将pra->referenced++
	 * 然后将pra->vm_flags 并上 vma->vm_flags
	 */
	if (referenced) {
		pra->referenced++;
		pra->vm_flags |= vma->vm_flags;
	}
	/* 将pra->mapcount-- */
	pra->mapcount--;
	/* 如果都走完了,那么就可以跳出循环了 */
	if (!pra->mapcount)
		return SWAP_SUCCESS; /* To break the loop */

	return SWAP_AGAIN;
}

static bool invalid_page_referenced_vma(struct vm_area_struct *vma, void *arg)
{
	struct page_referenced_arg *pra = arg;
	/* 获得mem_cgroup */
	struct mem_cgroup *memcg = pra->memcg;

	/* 判断是不是一样的group */
	if (!mm_match_cgroup(vma->vm_mm, memcg))
		return true;

	return false;
}

/**
 * page_referenced - test if the page was referenced
 * @page: the page to test
 * @is_locked: caller holds lock on the page
 * @memcg: target memory cgroup
 * @vm_flags: collect encountered vma->vm_flags who actually referenced the page
 *
 * Quick test_and_clear_referenced for all mappings to a page,
 * returns the number of ptes which referenced the page.
 *
 * page_referenced - 测试页面是否被引用
 *
 * @page: 要测试的页面
 * @is_locked: 调用方在页面上拿到了锁
 * @memcg: target memory cgroup
 * @vm_flags: 收集遇到的实际引用页面的vma->vm_flags
 *
 * 快速 test_and_clear_referenced 用于指向页面的所有映射,返回引用该页面的pte数.
 */
int page_referenced(struct page *page,
		    int is_locked,
		    struct mem_cgroup *memcg,
		    unsigned long *vm_flags)
{
	int ret;
	int we_locked = 0;
	struct page_referenced_arg pra = {
		/* 拿到page->_mapcount + 1 */
		.mapcount = total_mapcount(page),
		.memcg = memcg,
	};
	struct rmap_walk_control rwc = {
		.rmap_one = page_referenced_one,
		.arg = (void *)&pra,
		.anon_lock = page_lock_anon_vma_read,
	};

	/* 将vm_flags的值设置为0 */
	*vm_flags = 0;
	/* 如果该page没有映射进页表那么返回0 */
	if (!page_mapped(page))
		return 0;

	/* 如果page->mapping指向空,那么也返回0 */
	if (!page_rmapping(page))
		return 0;

	/* 如果is_locked等于0,也就是没有被locked且不是匿名页面或者是ksm页面 */
	if (!is_locked && (!PageAnon(page) || PageKsm(page))) {
		/* 试图获得这个page的锁 */
		we_locked = trylock_page(page);
		if (!we_locked)
			return 1;
	}

	/*
	 * If we are reclaiming on behalf of a cgroup, skip
	 * counting on behalf of references from different
	 * cgroups
	 *
	 * 如果我们代表一个cgroup回收,请跳过代表不同cgroup的引用计数
	 */
	if (memcg) {
		rwc.invalid_vma = invalid_page_referenced_vma;
	}

	/* 这里就是轮询这个page,并调用page_referenced_one
	 */
	ret = rmap_walk(page, &rwc);
	*vm_flags = pra.vm_flags;

	if (we_locked)
		unlock_page(page);
	/* 返回referenced,即引用这个page的进程个数 */
	return pra.referenced;
}

static int page_mkclean_one(struct page *page, struct vm_area_struct *vma,
			    unsigned long address, void *arg)
{
	/* 获得mm_struct */
	struct mm_struct *mm = vma->vm_mm;
	pte_t *pte;
	spinlock_t *ptl;
	int ret = 0;
	int *cleaned = arg;
	/* 获得pte */
	pte = page_check_address(page, mm, address, &ptl, 1);
	if (!pte)
		goto out;
	/* 如果pte是drity的，或者是pte是可写的 */
	if (pte_dirty(*pte) || pte_write(*pte)) {
		pte_t entry;
		/* 刷TLB */
		flush_cache_page(vma, address, pte_pfn(*pte));
		/* 获取页表项内容，保存到pteval中，然后清空页表项 */
		entry = ptep_clear_flush(vma, address, pte);
		/* 清除可写位 */
		entry = pte_wrprotect(entry);
		/* 清除drity位 */
		entry = pte_mkclean(entry);
		/* 设置到相关的页表里面去 */
		set_pte_at(mm, address, pte, entry);
		ret = 1;
	}

	pte_unmap_unlock(pte, ptl);

	if (ret) {
		mmu_notifier_invalidate_page(mm, address);
		(*cleaned)++;
	}
out:
	return SWAP_AGAIN;
}

static bool invalid_mkclean_vma(struct vm_area_struct *vma, void *arg)
{
	if (vma->vm_flags & VM_SHARED)
		return false;

	return true;
}

int page_mkclean(struct page *page)
{
	int cleaned = 0;
	struct address_space *mapping;
	struct rmap_walk_control rwc = {
		.arg = (void *)&cleaned,
		.rmap_one = page_mkclean_one,
		.invalid_vma = invalid_mkclean_vma,
	};
	/* 如果page是locked的，那么报个BUG吧 */
	BUG_ON(!PageLocked(page));
	/* page_mapped: Return true if this page is mapped into pagetables. */
	if (!page_mapped(page))
		return 0;
	/* 得到mapping，如果mapping为空，那么直接返回了
	 * 匿名页面会返回
	 */
	mapping = page_mapping(page);
	if (!mapping)
		return 0;

	rmap_walk(page, &rwc);

	return cleaned;
}
EXPORT_SYMBOL_GPL(page_mkclean);

/**
 * page_move_anon_rmap - move a page to our anon_vma
 * @page:	the page to move to our anon_vma
 * @vma:	the vma the page belongs to
 *
 * When a page belongs exclusively to one process after a COW event,
 * that page can be moved into the anon_vma that belongs to just that
 * process, so the rmap code will not search the parent or sibling
 * processes.
 */
void page_move_anon_rmap(struct page *page, struct vm_area_struct *vma)
{
	struct anon_vma *anon_vma = vma->anon_vma;

	page = compound_head(page);

	VM_BUG_ON_PAGE(!PageLocked(page), page);
	VM_BUG_ON_VMA(!anon_vma, vma);

	anon_vma = (void *) anon_vma + PAGE_MAPPING_ANON;
	/*
	 * Ensure that anon_vma and the PAGE_MAPPING_ANON bit are written
	 * simultaneously, so a concurrent reader (eg page_referenced()'s
	 * PageAnon()) will not see one without the other.
	 */
	WRITE_ONCE(page->mapping, (struct address_space *) anon_vma);
}

/**
 * __page_set_anon_rmap - set up new anonymous rmap
 * @page:	Page to add to rmap	
 * @vma:	VM area to add page to.
 * @address:	User virtual address of the mapping	
 * @exclusive:	the page is exclusively owned by the current process
 */
static void __page_set_anon_rmap(struct page *page,
	struct vm_area_struct *vma, unsigned long address, int exclusive)
{
	struct anon_vma *anon_vma = vma->anon_vma;

	BUG_ON(!anon_vma);
	/* 如果已经设置了anon rmap了,那么就return吧 */
	if (PageAnon(page))
		return;

	/*
	 * If the page isn't exclusively mapped into this vma,
	 * we must use the _oldest_ possible anon_vma for the
	 * page mapping!
	 *
	 * 如果页面不是以独占方式映射到此vma,则必须使用_oldest_可能的anon_vm进行页面映射!
	 */
	if (!exclusive)
		anon_vma = anon_vma->root;
	/* 将anon_vma的指针的值加上PAGE_MAPPING_ANON,然后把指针值赋给page->mapping.
	 * struct page数据结构中的mapping成员用于指定页面所在的地址空间.
	 * 内核中所谓的地址空间通常有两个不同的地址空间,一个用于文件映射页面,另外一个用于匿名映射页面.
	 * mapping指针的最低两位用于判断是否指向匿名映射或KSM页面的地址空间,如果mapping指针最低1位不为0,
	 * 那么mapping指向匿名页面的地址空间数据结构struct anon_vma
	 */
	anon_vma = (void *) anon_vma + PAGE_MAPPING_ANON;
	page->mapping = (struct address_space *) anon_vma;
	/* 算出page->index */
	page->index = linear_page_index(vma, address);
}

/**
 * __page_check_anon_rmap - sanity check anonymous rmap addition
 * @page:	the page to add the mapping to
 * @vma:	the vm area in which the mapping is added
 * @address:	the user virtual address mapped
 */
static void __page_check_anon_rmap(struct page *page,
	struct vm_area_struct *vma, unsigned long address)
{
#ifdef CONFIG_DEBUG_VM
	/*
	 * The page's anon-rmap details (mapping and index) are guaranteed to
	 * be set up correctly at this point.
	 *
	 * We have exclusion against page_add_anon_rmap because the caller
	 * always holds the page locked, except if called from page_dup_rmap,
	 * in which case the page is already known to be setup.
	 *
	 * We have exclusion against page_add_new_anon_rmap because those pages
	 * are initially only visible via the pagetables, and the pte is locked
	 * over the call to page_add_new_anon_rmap.
	 */
	BUG_ON(page_anon_vma(page)->root != vma->anon_vma->root);
	BUG_ON(page_to_pgoff(page) != linear_page_index(vma, address));
#endif
}

/**
 * page_add_anon_rmap - add pte mapping to an anonymous page
 * @page:	the page to add the mapping to
 * @vma:	the vm area in which the mapping is added
 * @address:	the user virtual address mapped
 * @compound:	charge the page as compound or small page
 *
 * The caller needs to hold the pte lock, and the page must be locked in
 * the anon_vma case: to serialize mapping,index checking after setting,
 * and to ensure that PageAnon is not being upgraded racily to PageKsm
 * (but PageKsm is never downgraded to PageAnon).
 */
void page_add_anon_rmap(struct page *page,
	struct vm_area_struct *vma, unsigned long address, bool compound)
{
	do_page_add_anon_rmap(page, vma, address, compound ? RMAP_COMPOUND : 0);
}

/*
 * Special version of the above for do_swap_page, which often runs
 * into pages that are exclusively owned by the current process.
 * Everybody else should continue to use page_add_anon_rmap above.
 */
void do_page_add_anon_rmap(struct page *page,
	struct vm_area_struct *vma, unsigned long address, int flags)
{
	bool compound = flags & RMAP_COMPOUND;
	bool first;

	if (compound) {
		atomic_t *mapcount;
		VM_BUG_ON_PAGE(!PageLocked(page), page);
		VM_BUG_ON_PAGE(!PageTransHuge(page), page);
		mapcount = compound_mapcount_ptr(page);
		first = atomic_inc_and_test(mapcount);
	} else {
		first = atomic_inc_and_test(&page->_mapcount);
	}

	if (first) {
		int nr = compound ? hpage_nr_pages(page) : 1;
		/*
		 * We use the irq-unsafe __{inc|mod}_zone_page_stat because
		 * these counters are not modified in interrupt context, and
		 * pte lock(a spinlock) is held, which implies preemption
		 * disabled.
		 */
		if (compound)
			__inc_node_page_state(page, NR_ANON_THPS);
		__mod_node_page_state(page_pgdat(page), NR_ANON_MAPPED, nr);
	}
	if (unlikely(PageKsm(page)))
		return;

	VM_BUG_ON_PAGE(!PageLocked(page), page);

	/* address might be in next vma when migration races vma_adjust */
	if (first)
		__page_set_anon_rmap(page, vma, address,
				flags & RMAP_EXCLUSIVE);
	else
		__page_check_anon_rmap(page, vma, address);
}

/**
 * page_add_new_anon_rmap - add pte mapping to a new anonymous page
 * @page:	the page to add the mapping to
 * @vma:	the vm area in which the mapping is added
 * @address:	the user virtual address mapped
 * @compound:	charge the page as compound or small page
 *
 * Same as page_add_anon_rmap but must only be called on *new* pages.
 * This means the inc-and-test can be bypassed.
 * Page does not have to be locked.
 *
 * page_add_new_anon_rmap - 将pte映射添加到新的匿名页面
 * @page: 要将映射添加到的页面
 * @vma: 添加映射的vm区域
 * @address: 映射的用户虚拟地址
 * @compound: 按复合页或小页计数
 *
 * 与page_add_anon_rmap相同,但只能在"new"页面上调用.
 * 这意味着可以绕过inc-and-test.
 * 页面不必锁定
 */
void page_add_new_anon_rmap(struct page *page,
	struct vm_area_struct *vma, unsigned long address, bool compound)
{
	/* 算出page数 */
	int nr = compound ? hpage_nr_pages(page) : 1;

	VM_BUG_ON_VMA(address < vma->vm_start || address >= vma->vm_end, vma);
	/* PG_swapbacked:此页可写入swap分区,一般用于表示此页是非文件页 */
	__SetPageSwapBacked(page);
	if (compound) {
		VM_BUG_ON_PAGE(!PageTransHuge(page), page);
		/* increment count (starts at -1) */
		atomic_set(compound_mapcount_ptr(page), 0);
		__inc_node_page_state(page, NR_ANON_THPS);
	} else {
		/* Anon THP always mapped first with PMD */
		VM_BUG_ON_PAGE(PageTransCompound(page), page);
		/* increment count (starts at -1) */
		/* 设置page的_mapcount引用计数为0,_mapcount的初始值为-1 */
		atomic_set(&page->_mapcount, 0);
	}
	/* NR_ANON_MAPPED: Mapped anonymous pages
	 * 映射的匿名页面计数 +1
	 */
	__mod_node_page_state(page_pgdat(page), NR_ANON_MAPPED, nr);
	/* 设置这个页面为匿名映射 */
	__page_set_anon_rmap(page, vma, address, 1);
}

/**
 * page_add_file_rmap - add pte mapping to a file page
 * @page: the page to add the mapping to
 *
 * The caller needs to hold the pte lock.
 */
void page_add_file_rmap(struct page *page, bool compound)
{
	int i, nr = 1;

	VM_BUG_ON_PAGE(compound && !PageTransHuge(page), page);
	lock_page_memcg(page);
	if (compound && PageTransHuge(page)) {
		for (i = 0, nr = 0; i < HPAGE_PMD_NR; i++) {
			if (atomic_inc_and_test(&page[i]._mapcount))
				nr++;
		}
		if (!atomic_inc_and_test(compound_mapcount_ptr(page)))
			goto out;
		VM_BUG_ON_PAGE(!PageSwapBacked(page), page);
		__inc_node_page_state(page, NR_SHMEM_PMDMAPPED);
	} else {
		if (PageTransCompound(page) && page_mapping(page)) {
			VM_WARN_ON_ONCE(!PageLocked(page));

			SetPageDoubleMap(compound_head(page));
			if (PageMlocked(page))
				clear_page_mlock(compound_head(page));
		}
		if (!atomic_inc_and_test(&page->_mapcount))
			goto out;
	}
	__mod_node_page_state(page_pgdat(page), NR_FILE_MAPPED, nr);
	mem_cgroup_update_page_stat(page, MEM_CGROUP_STAT_FILE_MAPPED, nr);
out:
	unlock_page_memcg(page);
}

static void page_remove_file_rmap(struct page *page, bool compound)
{
	int i, nr = 1;
	/* 如果compound为true但是该page不是PageHead,报个BUG吧 */
	VM_BUG_ON_PAGE(compound && !PageHead(page), page);
	lock_page_memcg(page);

	/* Hugepages are not counted in NR_FILE_MAPPED for now. */
	/* 如果是标准大页 */
	if (unlikely(PageHuge(page))) {
		/* hugetlb pages are always mapped with pmds */
		/* atomic(&page[1].compound_mapcount); */
		atomic_dec(compound_mapcount_ptr(page));
		goto out;
	}
	/* 如果是透明大页 */
	/* page still mapped by someone else? */
	if (compound && PageTransHuge(page)) {
		/* 以页为步长来做循环，HPAGE_PMD_NR是看一个大页有多少个PAGE */
		for (i = 0, nr = 0; i < HPAGE_PMD_NR; i++) {
			/* _mapcount引用技术表示这个页面被进程映射的个数，即已经映射了多少个用户pte页表.
			 * 在32位Linux内核中，每个用户进程都拥有3GB的虚拟空间和一份独立的页表，
			 * 所以有可能出现多个进程地址空间同时映射到一个物理页面的情况
			 */
			/* 把原子变量v的值加上i,判断相加后的原子变量值是否为负数,如果为负数返回真 */
			/* 把上面两个注释结合一下，也就是说这个page没其他人使用,nr++ */
			if (atomic_add_negative(-1, &page[i]._mapcount))
				nr++;
		}
		/* 如果atomic_add_negative(-1,&page[1].compound_mapcount) 为负数了，那么就go out */
		if (!atomic_add_negative(-1, compound_mapcount_ptr(page)))
			goto out;
		VM_BUG_ON_PAGE(!PageSwapBacked(page), page);
		/* 将共享内存的NR_SHMEM_PMDMAPPED -1 */
		__dec_node_page_state(page, NR_SHMEM_PMDMAPPED);
	} else {
		/* 如果page 没人用了，那么也go out吧 */
		if (!atomic_add_negative(-1, &page->_mapcount))
			goto out;
	}

	/*
	 * We use the irq-unsafe __{inc|mod}_zone_page_state because
	 * these counters are not modified in interrupt context, and
	 * pte lock(a spinlock) is held, which implies preemption disabled.
	 */
	/* 将pgdat的NR_FILE_MAPPED减去nr */
	__mod_node_page_state(page_pgdat(page), NR_FILE_MAPPED, -nr);
	mem_cgroup_update_page_stat(page, MEM_CGROUP_STAT_FILE_MAPPED, -nr);

	if (unlikely(PageMlocked(page)))
		clear_page_mlock(page);
out:
	unlock_page_memcg(page);
}

static void page_remove_anon_compound_rmap(struct page *page)
{
	int i, nr;
	/* 如果atomic_add_negative(-1,&page[1].compound_mapcount) 为负数了，那么就返回了
	 * 也就是说明没人在用这块了
	 */
	if (!atomic_add_negative(-1, compound_mapcount_ptr(page)))
		return;

	/* Hugepages are not counted in NR_ANON_PAGES for now. */
	/* 如果是传统的hugepage，那么也return */
	if (unlikely(PageHuge(page)))
		return;
	/* 如果没有开透明大页，也返回 */
	if (!IS_ENABLED(CONFIG_TRANSPARENT_HUGEPAGE))
		return;
	/* 将NR_ANON_THPS -1 */
	__dec_node_page_state(page, NR_ANON_THPS);
	/* 大页在进程的页面中间目录 (PMD) 级别具有单个条目。
	 * 相反，各个页面在底部页表条目 (PTE) 级别具有条目，如图所示。但是并没有说必须在所有进程中以相同的方式映射相同的内存；
	 * 一个进程将 2MB 范围视为单个大页面而另一个进程将其映射为 512 个单独的 PTE 是完全合法的。
	 * 如果支持这种类型的不同映射，一个进程可以调用mprotect()来更改大页面一部分的保护（导致映射在该进程的地址空间中被拆分），
	 * 同时不会干扰其他进程中的大页面映射，不受保护变化的影响
	 */
	if (TestClearPageDoubleMap(page)) {
		/*
		 * Subpages can be mapped with PTEs too. Check how many of
		 * themi are still mapped.
		 */
		/* 如果有PageDoubleMap,那么说明子页还映射了PTE，那么看看有多少个子页已经没有映射了 */
		for (i = 0, nr = 0; i < HPAGE_PMD_NR; i++) {
			if (atomic_add_negative(-1, &page[i]._mapcount))
				nr++;
		}
	} else {
		/* 如果没有双重映射，那么nr就等于HPAGE包含的page数目 */
		nr = HPAGE_PMD_NR;
	}

	if (unlikely(PageMlocked(page)))
		clear_page_mlock(page);

	if (nr) {
		/* 修改统计计数 */
		__mod_node_page_state(page_pgdat(page), NR_ANON_MAPPED, -nr);
		/* 当进程munmap大页的一部分时，并不会马上发生同步的大页分裂，因为在进程munmap的上下文进行大页分裂开销很高，现在是在反向映射时进行感知，
		 * 通过deferred_split机制进行。当page发生反向映射时page_remove_rmap发现page的mapcount等于-1即已经没有进程对这个page进行映射。
		 * 就会将此page通过deferred_split_huge_page加入链表中，在下次内存压力紧张时进行shrink拆分回收
		 */
		deferred_split_huge_page(page);
	}
}

/**
 * page_remove_rmap - take down pte mapping from a page
 * @page:	page to remove mapping from
 * @compound:	uncharge the page as compound or small page
 *
 * The caller needs to hold the pte lock.
 */
void page_remove_rmap(struct page *page, bool compound)
{
	//如果是文件页，通过文件页的方式反向映射。主要是mapcount的统计差异
	if (!PageAnon(page))
		return page_remove_file_rmap(page, compound);
	//如果是整体反向映射，整体对大页的mapcount计数进行减1
	if (compound)
		return page_remove_anon_compound_rmap(page);

	/* page still mapped by someone else? */
	/* 对page的mapcount减1后如果不等于-1，即还有进程进行映射，退出 */
	if (!atomic_add_negative(-1, &page->_mapcount))
		return;

	/*
	 * We use the irq-unsafe __{inc|mod}_zone_page_stat because
	 * these counters are not modified in interrupt context, and
	 * pte lock(a spinlock) is held, which implies preemption disabled.
	 */
	/* 走到这里， page已经被进程映射了，计数处理 */
	__dec_node_page_state(page, NR_ANON_MAPPED);
	/* 如果page带mlock标记，清除它 */
	if (unlikely(PageMlocked(page)))
		clear_page_mlock(page);
	/* 如果是thp大页，把page加到deferred_split的链表， 在下次内存紧张shrink时进分裂回收 */
	if (PageTransCompound(page))
		deferred_split_huge_page(compound_head(page));

	/*
	 * It would be tidy to reset the PageAnon mapping here,
	 * but that might overwrite a racing page_add_anon_rmap
	 * which increments mapcount after us but sets mapping
	 * before us: so leave the reset to free_hot_cold_page,
	 * and remember that it's only reliable while mapped.
	 * Leaving it set also helps swapoff to reinstate ptes
	 * faster for those pages still in swapcache.
	 */
}

struct rmap_private {
	enum ttu_flags flags;
	int lazyfreed;
};

/*
 * @arg: enum ttu_flags will be passed to this argument
 */
static int try_to_unmap_one(struct page *page, struct vm_area_struct *vma,
		     unsigned long address, void *arg)
{
	struct mm_struct *mm = vma->vm_mm;
	pte_t *pte;
	pte_t pteval;
	spinlock_t *ptl;
	int ret = SWAP_AGAIN;
	struct rmap_private *rp = arg;
	enum ttu_flags flags = rp->flags;

	/* munlock has nothing to gain from examining un-locked vmas */
	if ((flags & TTU_MUNLOCK) && !(vma->vm_flags & VM_LOCKED))
		goto out;

	if (flags & TTU_SPLIT_HUGE_PMD) {
		split_huge_pmd_address(vma, address,
				flags & TTU_MIGRATION, page);
		/* check if we have anything to do after split */
		if (page_mapcount(page) == 0)
			goto out;
	}

	pte = page_check_address(page, mm, address, &ptl,
				 PageTransCompound(page));
	if (!pte)
		goto out;

	/*
	 * If the page is mlock()d, we cannot swap it out.
	 * If it's recently referenced (perhaps page_referenced
	 * skipped over this mm) then we should reactivate it.
	 */
	if (!(flags & TTU_IGNORE_MLOCK)) {
		if (vma->vm_flags & VM_LOCKED) {
			/* PTE-mapped THP are never mlocked */
			if (!PageTransCompound(page)) {
				/*
				 * Holding pte lock, we do *not* need
				 * mmap_sem here
				 */
				mlock_vma_page(page);
			}
			ret = SWAP_MLOCK;
			goto out_unmap;
		}
		if (flags & TTU_MUNLOCK)
			goto out_unmap;
	}
	if (!(flags & TTU_IGNORE_ACCESS)) {
		if (ptep_clear_flush_young_notify(vma, address, pte)) {
			ret = SWAP_FAIL;
			goto out_unmap;
		}
  	}

	/* Nuke the page table entry. */
	flush_cache_page(vma, address, page_to_pfn(page));
	if (should_defer_flush(mm, flags)) {
		/*
		 * We clear the PTE but do not flush so potentially a remote
		 * CPU could still be writing to the page. If the entry was
		 * previously clean then the architecture must guarantee that
		 * a clear->dirty transition on a cached TLB entry is written
		 * through and traps if the PTE is unmapped.
		 */
		pteval = ptep_get_and_clear(mm, address, pte);

		set_tlb_ubc_flush_pending(mm, page, pte_dirty(pteval));
	} else {
		pteval = ptep_clear_flush(vma, address, pte);
	}

	/* Move the dirty bit to the physical page now the pte is gone. */
	if (pte_dirty(pteval))
		set_page_dirty(page);

	/* Update high watermark before we lower rss */
	update_hiwater_rss(mm);

	if (PageHWPoison(page) && !(flags & TTU_IGNORE_HWPOISON)) {
		if (PageHuge(page)) {
			hugetlb_count_sub(1 << compound_order(page), mm);
		} else {
			dec_mm_counter(mm, mm_counter(page));
		}
		set_pte_at(mm, address, pte,
			   swp_entry_to_pte(make_hwpoison_entry(page)));
	} else if (pte_unused(pteval)) {
		/*
		 * The guest indicated that the page content is of no
		 * interest anymore. Simply discard the pte, vmscan
		 * will take care of the rest.
		 */
		dec_mm_counter(mm, mm_counter(page));
	} else if (IS_ENABLED(CONFIG_MIGRATION) && (flags & TTU_MIGRATION)) {
		swp_entry_t entry;
		pte_t swp_pte;
		/*
		 * Store the pfn of the page in a special migration
		 * pte. do_swap_page() will wait until the migration
		 * pte is removed and then restart fault handling.
		 */
		entry = make_migration_entry(page, pte_write(pteval));
		swp_pte = swp_entry_to_pte(entry);
		if (pte_soft_dirty(pteval))
			swp_pte = pte_swp_mksoft_dirty(swp_pte);
		set_pte_at(mm, address, pte, swp_pte);
	} else if (PageAnon(page)) {
		swp_entry_t entry = { .val = page_private(page) };
		pte_t swp_pte;
		/*
		 * Store the swap location in the pte.
		 * See handle_pte_fault() ...
		 */
		VM_BUG_ON_PAGE(!PageSwapCache(page), page);

		if (!PageDirty(page) && (flags & TTU_LZFREE)) {
			/* It's a freeable page by MADV_FREE */
			dec_mm_counter(mm, MM_ANONPAGES);
			rp->lazyfreed++;
			goto discard;
		}

		if (swap_duplicate(entry) < 0) {
			set_pte_at(mm, address, pte, pteval);
			ret = SWAP_FAIL;
			goto out_unmap;
		}
		if (list_empty(&mm->mmlist)) {
			spin_lock(&mmlist_lock);
			if (list_empty(&mm->mmlist))
				list_add(&mm->mmlist, &init_mm.mmlist);
			spin_unlock(&mmlist_lock);
		}
		dec_mm_counter(mm, MM_ANONPAGES);
		inc_mm_counter(mm, MM_SWAPENTS);
		swp_pte = swp_entry_to_pte(entry);
		if (pte_soft_dirty(pteval))
			swp_pte = pte_swp_mksoft_dirty(swp_pte);
		set_pte_at(mm, address, pte, swp_pte);
	} else
		dec_mm_counter(mm, mm_counter_file(page));

discard:
	page_remove_rmap(page, PageHuge(page));
	put_page(page);

out_unmap:
	pte_unmap_unlock(pte, ptl);
	if (ret != SWAP_FAIL && ret != SWAP_MLOCK && !(flags & TTU_MUNLOCK))
		mmu_notifier_invalidate_page(mm, address);
out:
	return ret;
}

bool is_vma_temporary_stack(struct vm_area_struct *vma)
{
	int maybe_stack = vma->vm_flags & (VM_GROWSDOWN | VM_GROWSUP);

	if (!maybe_stack)
		return false;

	if ((vma->vm_flags & VM_STACK_INCOMPLETE_SETUP) ==
						VM_STACK_INCOMPLETE_SETUP)
		return true;

	return false;
}

static bool invalid_migration_vma(struct vm_area_struct *vma, void *arg)
{
	return is_vma_temporary_stack(vma);
}

static int page_mapcount_is_zero(struct page *page)
{
	return !page_mapcount(page);
}

/**
 * try_to_unmap - try to remove all page table mappings to a page
 * @page: the page to get unmapped
 * @flags: action and flags
 *
 * Tries to remove all the page table entries which are mapping this
 * page, used in the pageout path.  Caller must hold the page lock.
 * Return values are:
 *
 * SWAP_SUCCESS	- we succeeded in removing all mappings
 * SWAP_AGAIN	- we missed a mapping, try again later
 * SWAP_FAIL	- the page is unswappable
 * SWAP_MLOCK	- page is mlocked.
 */
int try_to_unmap(struct page *page, enum ttu_flags flags)
{
	int ret;
	struct rmap_private rp = {
		.flags = flags,
		.lazyfreed = 0,
	};

	struct rmap_walk_control rwc = {
		.rmap_one = try_to_unmap_one,
		.arg = &rp,
		.done = page_mapcount_is_zero,
		.anon_lock = page_lock_anon_vma_read,
	};

	/*
	 * During exec, a temporary VMA is setup and later moved.
	 * The VMA is moved under the anon_vma lock but not the
	 * page tables leading to a race where migration cannot
	 * find the migration ptes. Rather than increasing the
	 * locking requirements of exec(), migration skips
	 * temporary VMAs until after exec() completes.
	 */
	if ((flags & TTU_MIGRATION) && !PageKsm(page) && PageAnon(page))
		rwc.invalid_vma = invalid_migration_vma;

	if (flags & TTU_RMAP_LOCKED)
		ret = rmap_walk_locked(page, &rwc);
	else
		ret = rmap_walk(page, &rwc);

	if (ret != SWAP_MLOCK && !page_mapcount(page)) {
		ret = SWAP_SUCCESS;
		if (rp.lazyfreed && !PageDirty(page))
			ret = SWAP_LZFREE;
	}
	return ret;
}

static int page_not_mapped(struct page *page)
{
	return !page_mapped(page);
};

/**
 * try_to_munlock - try to munlock a page
 * @page: the page to be munlocked
 *
 * Called from munlock code.  Checks all of the VMAs mapping the page
 * to make sure nobody else has this page mlocked. The page will be
 * returned with PG_mlocked cleared if no other vmas have it mlocked.
 *
 * Return values are:
 *
 * SWAP_AGAIN	- no vma is holding page mlocked, or,
 * SWAP_AGAIN	- page mapped in mlocked vma -- couldn't acquire mmap sem
 * SWAP_FAIL	- page cannot be located at present
 * SWAP_MLOCK	- page is now mlocked.
 */
int try_to_munlock(struct page *page)
{
	int ret;
	struct rmap_private rp = {
		.flags = TTU_MUNLOCK,
		.lazyfreed = 0,
	};

	struct rmap_walk_control rwc = {
		.rmap_one = try_to_unmap_one,
		.arg = &rp,
		.done = page_not_mapped,
		.anon_lock = page_lock_anon_vma_read,

	};

	VM_BUG_ON_PAGE(!PageLocked(page) || PageLRU(page), page);

	ret = rmap_walk(page, &rwc);
	return ret;
}

void __put_anon_vma(struct anon_vma *anon_vma)
{
	/* 获得anon_vma的根anon_vma */
	struct anon_vma *root = anon_vma->root;
	/* free掉anon_vma */
	anon_vma_free(anon_vma);
	/* 如果root != anon_vma && 并且把root->refcount - 1 之后等于0,那么也把root个free掉 */
	if (root != anon_vma && atomic_dec_and_test(&root->refcount))
		anon_vma_free(root);
}

static struct anon_vma *rmap_walk_anon_lock(struct page *page,
					struct rmap_walk_control *rwc)
{
	struct anon_vma *anon_vma;

	/* 如果有rwc->anon_lock,那么就调用rwc->anon_lock */
	if (rwc->anon_lock)
		return rwc->anon_lock(page);

	/*
	 * Note: remove_migration_ptes() cannot use page_lock_anon_vma_read()
	 * because that depends on page_mapped(); but not all its usages
	 * are holding mmap_sem. Users without mmap_sem are required to
	 * take a reference count to prevent the anon_vma disappearing
	 *
	 * 注意: remove_migration_ptes() 不能使用page_lock_anon_vma_read().
	 * 因为这取决于page_mapped(); 但并不是所有的用法都拿到mmap_sem.
	 * 没有mmap_sem的用户需要进行拿到引用计数,以防止anon_vma消失.
	 */
	/* 拿到page的anon_vma */
	anon_vma = page_anon_vma(page);
	/* 如果anon_vma为NULL,那么直接返回NULL */
	if (!anon_vma)
		return NULL;
	/* static inline void anon_vma_lock_read(struct anon_vma *anon_vma)
	 * {
	 *	down_read(&anon_vma->root->rwsem);
	 * }
	 */
	anon_vma_lock_read(anon_vma);
	return anon_vma;
}

/*
 * rmap_walk_anon - do something to anonymous page using the object-based
 * rmap method
 * @page: the page to be handled
 * @rwc: control variable according to each walk type
 *
 * Find all the mappings of a page using the mapping pointer and the vma chains
 * contained in the anon_vma struct it points to.
 *
 * When called from try_to_munlock(), the mmap_sem of the mm containing the vma
 * where the page was found will be held for write.  So, we won't recheck
 * vm_flags for that VMA.  That should be OK, because that vma shouldn't be
 * LOCKED.
 *
 * rmap_walk_anon - 使用基于对象的匿名页面执行某些操作
 *
 * rmap方法
 * @page: 要处理的页面
 * @rwc: 根据每种walk类型的控制变量
 *
 * 使用映射指针和它所指向的anon_vm结构中包含的vma chains来查找页面的所有映射.
 *
 * 当从try_to_munlock()调用时,包含找到页面的vma的mm的mmap_sem将被保留以进行写入.
 * 因此,我们不会重新检查VMA的vm_flags.
 * 这应该没问题,因为vma不应该被锁定.
 */
static int rmap_walk_anon(struct page *page, struct rmap_walk_control *rwc,
		bool locked)
{
	struct anon_vma *anon_vma;
	pgoff_t pgoff;
	struct anon_vma_chain *avc;
	int ret = SWAP_AGAIN;

	/* 看传进来的参数locked是否为 true,也就是外面有没有拿到锁 */
	if (locked) {
		/* 拿到该page的anon_vma */
		anon_vma = page_anon_vma(page);
		/* anon_vma disappear under us? */
		VM_BUG_ON_PAGE(!anon_vma, page);
	} else {
		/* 如果没拿到锁,那么调用下面这个去拿到锁且得到它的anon_vma */
		anon_vma = rmap_walk_anon_lock(page, rwc);
	}

	/* 如果anon_vma等于NULL,那么直接返回吧 */
	if (!anon_vma)
		return ret;

	/* 拿到page的index */
	pgoff = page_to_pgoff(page);
	/* 这里就是对每个映射到这个page的vma进行操作
	 * 包括子进程的子进程,因为这里回去循环到subtree
	 */
	anon_vma_interval_tree_foreach(avc, &anon_vma->rb_root, pgoff, pgoff) {
		struct vm_area_struct *vma = avc->vma;
		/* 通过给定vma和page,获取相应的虚拟地址
		 * 很经典哦
		 */
		unsigned long address = vma_address(page, vma);

		cond_resched();

		/* 如果有invalid_vma那么就调用invaild_vma */
		if (rwc->invalid_vma && rwc->invalid_vma(vma, rwc->arg))
			continue;

		/* 调用rwc->rmap_one函数 */
		ret = rwc->rmap_one(page, vma, address, rwc->arg);
		/* 如果返回值不是SWAP_AGAIN,那么直接break */
		if (ret != SWAP_AGAIN)
			break;
		/* 如果有rwc->done,那么调用rwc->done函数 */
		if (rwc->done && rwc->done(page))
			break;
	}

	/* 如果进来的时候没有带锁,我们rmap_walk_anon_lock回去带
	 * 所以这里需要解锁
	 */
	if (!locked)
		anon_vma_unlock_read(anon_vma);
	return ret;
}

/*
 * rmap_walk_file - do something to file page using the object-based rmap method
 * @page: the page to be handled
 * @rwc: control variable according to each walk type
 *
 * Find all the mappings of a page using the mapping pointer and the vma chains
 * contained in the address_space struct it points to.
 *
 * When called from try_to_munlock(), the mmap_sem of the mm containing the vma
 * where the page was found will be held for write.  So, we won't recheck
 * vm_flags for that VMA.  That should be OK, because that vma shouldn't be
 * LOCKED.
 */
static int rmap_walk_file(struct page *page, struct rmap_walk_control *rwc,
		bool locked)
{
	struct address_space *mapping = page_mapping(page);
	pgoff_t pgoff;
	struct vm_area_struct *vma;
	int ret = SWAP_AGAIN;

	/*
	 * The page lock not only makes sure that page->mapping cannot
	 * suddenly be NULLified by truncation, it makes sure that the
	 * structure at mapping cannot be freed and reused yet,
	 * so we can safely take mapping->i_mmap_rwsem.
	 */
	VM_BUG_ON_PAGE(!PageLocked(page), page);

	if (!mapping)
		return ret;

	pgoff = page_to_pgoff(page);
	if (!locked)
		i_mmap_lock_read(mapping);
	vma_interval_tree_foreach(vma, &mapping->i_mmap, pgoff, pgoff) {
		unsigned long address = vma_address(page, vma);

		cond_resched();

		if (rwc->invalid_vma && rwc->invalid_vma(vma, rwc->arg))
			continue;

		ret = rwc->rmap_one(page, vma, address, rwc->arg);
		if (ret != SWAP_AGAIN)
			goto done;
		if (rwc->done && rwc->done(page))
			goto done;
	}

done:
	if (!locked)
		i_mmap_unlock_read(mapping);
	return ret;
}

int rmap_walk(struct page *page, struct rmap_walk_control *rwc)
{
	/* 如果是ksm页面,那么调用rmap_walk_ksm */
	if (unlikely(PageKsm(page)))
		return rmap_walk_ksm(page, rwc);
	else if (PageAnon(page))/* 如果是匿名页面,调用rmap_walk_anon */
		return rmap_walk_anon(page, rwc, false);
	else/* 如果是page cache,那么调用rmap_walk_file */
		return rmap_walk_file(page, rwc, false);
}

/* Like rmap_walk, but caller holds relevant rmap lock */
int rmap_walk_locked(struct page *page, struct rmap_walk_control *rwc)
{
	/* no ksm support for now */
	VM_BUG_ON_PAGE(PageKsm(page), page);
	if (PageAnon(page))
		return rmap_walk_anon(page, rwc, true);
	else
		return rmap_walk_file(page, rwc, true);
}

#ifdef CONFIG_HUGETLB_PAGE
/*
 * The following three functions are for anonymous (private mapped) hugepages.
 * Unlike common anonymous pages, anonymous hugepages have no accounting code
 * and no lru code, because we handle hugepages differently from common pages.
 */
static void __hugepage_set_anon_rmap(struct page *page,
	struct vm_area_struct *vma, unsigned long address, int exclusive)
{
	struct anon_vma *anon_vma = vma->anon_vma;

	BUG_ON(!anon_vma);

	if (PageAnon(page))
		return;
	if (!exclusive)
		anon_vma = anon_vma->root;

	anon_vma = (void *) anon_vma + PAGE_MAPPING_ANON;
	page->mapping = (struct address_space *) anon_vma;
	page->index = linear_page_index(vma, address);
}

void hugepage_add_anon_rmap(struct page *page,
			    struct vm_area_struct *vma, unsigned long address)
{
	struct anon_vma *anon_vma = vma->anon_vma;
	int first;

	BUG_ON(!PageLocked(page));
	BUG_ON(!anon_vma);
	/* address might be in next vma when migration races vma_adjust */
	first = atomic_inc_and_test(compound_mapcount_ptr(page));
	if (first)
		__hugepage_set_anon_rmap(page, vma, address, 0);
}

void hugepage_add_new_anon_rmap(struct page *page,
			struct vm_area_struct *vma, unsigned long address)
{
	BUG_ON(address < vma->vm_start || address >= vma->vm_end);
	atomic_set(compound_mapcount_ptr(page), 0);
	__hugepage_set_anon_rmap(page, vma, address, 1);
}
#endif /* CONFIG_HUGETLB_PAGE */
