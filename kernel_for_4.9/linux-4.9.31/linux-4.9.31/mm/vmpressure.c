/*
 * Linux VM pressure
 *
 * Copyright 2012 Linaro Ltd.
 *		  Anton Vorontsov <anton.vorontsov@linaro.org>
 *
 * Based on ideas from Andrew Morton, David Rientjes, KOSAKI Motohiro,
 * Leonid Moiseichuk, Mel Gorman, Minchan Kim and Pekka Enberg.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 */

#include <linux/cgroup.h>
#include <linux/fs.h>
#include <linux/log2.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/vmstat.h>
#include <linux/eventfd.h>
#include <linux/slab.h>
#include <linux/swap.h>
#include <linux/printk.h>
#include <linux/vmpressure.h>

/*
 * The window size (vmpressure_win) is the number of scanned pages before
 * we try to analyze scanned/reclaimed ratio. So the window is used as a
 * rate-limit tunable for the "low" level notification, and also for
 * averaging the ratio for medium/critical levels. Using small window
 * sizes can cause lot of false positives, but too big window size will
 * delay the notifications.
 *
 * As the vmscan reclaimer logic works with chunks which are multiple of
 * SWAP_CLUSTER_MAX, it makes sense to use it for the window size as well.
 *
 * TODO: Make the window size depend on machine size, as we do for vmstat
 * thresholds. Currently we set it to 512 pages (2MB for 4KB pages).
 *
 * 窗口大小(vmpressure_win)是在我们尝试分析scanned/reclaimed比率之前scanned页数.
 * 因此,该窗口被用作"low"级别的通知的可调的rate-limit,也用于平均medium/critical级别的比率.
 * 使用较小的窗口大小可能会导致大量误报,但过大的窗口大小会延迟通知。
 *
 * 由于vmscan回收器逻辑处理的块是SWAP_CLUSTER_MAX的倍数,因此将其用于窗口大小也是有意义的.
 *
 * TODO:使窗口大小取决于机器大小,就像我们对vmstat阈值所做的那样.
 *
 * 目前,我们将其设置为512页(4KB页面为2MB).
 */
static const unsigned long vmpressure_win = SWAP_CLUSTER_MAX * 16;

/*
 * These thresholds are used when we account memory pressure through
 * scanned/reclaimed ratio. The current values were chosen empirically. In
 * essence, they are percents: the higher the value, the more number
 * unsuccessful reclaims there were.
 */
static const unsigned int vmpressure_level_med = 60;
static const unsigned int vmpressure_level_critical = 95;

/*
 * When there are too little pages left to scan, vmpressure() may miss the
 * critical pressure as number of pages will be less than "window size".
 * However, in that case the vmscan priority will raise fast as the
 * reclaimer will try to scan LRUs more deeply.
 *
 * The vmscan logic considers these special priorities:
 *
 * prio == DEF_PRIORITY (12): reclaimer starts with that value
 * prio <= DEF_PRIORITY - 2 : kswapd becomes somewhat overwhelmed
 * prio == 0                : close to OOM, kernel scans every page in an lru
 *
 * Any value in this range is acceptable for this tunable (i.e. from 12 to
 * 0). Current value for the vmpressure_level_critical_prio is chosen
 * empirically, but the number, in essence, means that we consider
 * critical level when scanning depth is ~10% of the lru size (vmscan
 * scans 'lru_size >> prio' pages, so it is actually 12.5%, or one
 * eights).
 */
static const unsigned int vmpressure_level_critical_prio = ilog2(100 / 10);

static struct vmpressure *work_to_vmpressure(struct work_struct *work)
{
	return container_of(work, struct vmpressure, work);
}

static struct vmpressure *vmpressure_parent(struct vmpressure *vmpr)
{
	struct cgroup_subsys_state *css = vmpressure_to_css(vmpr);
	struct mem_cgroup *memcg = mem_cgroup_from_css(css);

	memcg = parent_mem_cgroup(memcg);
	if (!memcg)
		return NULL;
	return memcg_to_vmpressure(memcg);
}

enum vmpressure_levels {
	VMPRESSURE_LOW = 0,
	VMPRESSURE_MEDIUM,
	VMPRESSURE_CRITICAL,
	VMPRESSURE_NUM_LEVELS,
};

static const char * const vmpressure_str_levels[] = {
	[VMPRESSURE_LOW] = "low",
	[VMPRESSURE_MEDIUM] = "medium",
	[VMPRESSURE_CRITICAL] = "critical",
};

static enum vmpressure_levels vmpressure_level(unsigned long pressure)
{
	/* 如果pressure 大于等于vmpressure_level_critical(95)
	 * 也就是说明recaimed / scanned 要小于5%,说明回收的比较少
	 * 返回VMPRESSURE_CRITICAL
	 *
	 * 如果pressure 大于等于vmpressure_level_med(60)
	 * 也就是说明recaimed / scanned 要小于40%,说明回收的比较中等
	 * 返回VMPRESSURE_MEDIUM
	 */
	if (pressure >= vmpressure_level_critical)
		return VMPRESSURE_CRITICAL;
	else if (pressure >= vmpressure_level_med)
		return VMPRESSURE_MEDIUM;
	return VMPRESSURE_LOW;
}

static enum vmpressure_levels vmpressure_calc_level(unsigned long scanned,
						    unsigned long reclaimed)
{
	unsigned long scale = scanned + reclaimed;
	unsigned long pressure = 0;

	/*
	 * reclaimed can be greater than scanned in cases
	 * like THP, where the scanned is 1 and reclaimed
	 * could be 512
	 *
	 * 在THP这样的情况下,回收的可以大于扫描的,其中扫描的是1,回收的可能是512
	 */

	/* 如果回收的大于扫描的不活跃页面数量,那么直接out */
	if (reclaimed >= scanned)
		goto out;
	/*
	 * We calculate the ratio (in percents) of how many pages were
	 * scanned vs. reclaimed in a given time frame (window). Note that
	 * time is in VM reclaimer's "ticks", i.e. number of pages
	 * scanned. This makes it possible to set desired reaction time
	 * and serves as a ratelimit.
	 *
	 * 我们计算在给定的时间段(窗口)内扫描的页面数与回收的页面数的比率(以百分比为单位).
	 * 请注意,时间以vm 回收器的“刻度”为单位,例如扫描的页数.
	 * 这使得可以设置所需的反应时间并用作速率限制。
	 */

	/* preesure = ((scanned + reclaimed) - (reclaimed * (scanned + reclaimed ) / scanned)) * 100 / (scanned + reclaimed) */
	/* preesure = ( 1 - recaimed / scanned ) * 100 */
	pressure = scale - (reclaimed * scale / scanned);
	pressure = pressure * 100 / scale;

out:
	pr_debug("%s: %3lu  (s: %lu  r: %lu)\n", __func__, pressure,
		 scanned, reclaimed);

	return vmpressure_level(pressure);
}

struct vmpressure_event {
	struct eventfd_ctx *efd;
	enum vmpressure_levels level;
	struct list_head node;
};

static bool vmpressure_event(struct vmpressure *vmpr,
			     enum vmpressure_levels level)
{
	struct vmpressure_event *ev;
	bool signalled = false;

	mutex_lock(&vmpr->events_lock);
	/* 这是通过vmpressure_event来注册进来的 */
	/* 看一下这篇博客 https://blog.csdn.net/ds1130071727/article/details/93474431
	 * 想一下android的lmkd的实现
	 */
	list_for_each_entry(ev, &vmpr->events, node) {
		if (level >= ev->level) {
			eventfd_signal(ev->efd, 1);
			signalled = true;
		}
	}

	mutex_unlock(&vmpr->events_lock);

	return signalled;
}

static void vmpressure_work_fn(struct work_struct *work)
{
	struct vmpressure *vmpr = work_to_vmpressure(work);
	unsigned long scanned;
	unsigned long reclaimed;
	enum vmpressure_levels level;

	spin_lock(&vmpr->sr_lock);
	/*
	 * Several contexts might be calling vmpressure(), so it is
	 * possible that the work was rescheduled again before the old
	 * work context cleared the counters. In that case we will run
	 * just after the old work returns, but then scanned might be zero
	 * here. No need for any locks here since we don't care if
	 * vmpr->reclaimed is in sync.
	 *
	 * 几个上下文可能正在调用vmpressure(),
	 * 因此在旧的工作上下文清除计数器之前,可能会再次rescheduled.
	 * 在这种情况下,我们将在旧工作返回后立即运行,但扫描的结果可能为零.
	 * 这里不需要任何锁,因为我们不在乎vmpr->回收的是否同步.
	 */

	/* 获得scanned的数目 */
	scanned = vmpr->tree_scanned;
	if (!scanned) {
		spin_unlock(&vmpr->sr_lock);
		return;
	}

	/* 获得回收的数目 */
	reclaimed = vmpr->tree_reclaimed;
	vmpr->tree_scanned = 0;
	vmpr->tree_reclaimed = 0;
	spin_unlock(&vmpr->sr_lock);

	/* 计算然后得到vmpreesure level */
	level = vmpressure_calc_level(scanned, reclaimed);

	do {
		/* 发送event */
		if (vmpressure_event(vmpr, level))
			break;
		/*
		 * If not handled, propagate the event upward into the
		 * hierarchy.
		 */
	} while ((vmpr = vmpressure_parent(vmpr)));
}

/**
 * vmpressure() - Account memory pressure through scanned/reclaimed ratio
 * @gfp:	reclaimer's gfp mask
 * @memcg:	cgroup memory controller handle
 * @tree:	legacy subtree mode
 * @scanned:	number of pages scanned
 * @reclaimed:	number of pages reclaimed
 *
 * This function should be called from the vmscan reclaim path to account
 * "instantaneous" memory pressure (scanned/reclaimed ratio). The raw
 * pressure index is then further refined and averaged over time.
 *
 * If @tree is set, vmpressure is in traditional userspace reporting
 * mode: @memcg is considered the pressure root and userspace is
 * notified of the entire subtree's reclaim efficiency.
 *
 * If @tree is not set, reclaim efficiency is recorded for @memcg, and
 * only in-kernel users are notified.
 *
 * This function does not return any value.
 *
 * vmpressure（）- 通过scanned/reclaimed 比率计算内存压力
 * @gfp：回收者的gfp mask
 * @memcg: cgroup 内存控制处理
 * @tree: 传统子树模式
 * @scanned：已扫描的页数
 * @reclaimed: 回收的页面数量
 *
 * 应从vmscan回收路径调用此函数,以考虑“瞬时”内存压力(scanned/reclaimed 比率).
 * 然后对原始压力指数进行进一步细化,并随时间进行平均。
 *
 * 如果设置了@tree,则vmpressure处于传统的用户空间报告模式:@memcg被视为压力根,并且用户空间被通知整个子树的回收效率.
 *
 * 如果没有设置@tree,则会记录@memcg的回收效率,并且只通知内核中的用户.
 *
 * 此函数不返回任何值。
 */
void vmpressure(gfp_t gfp, struct mem_cgroup *memcg, bool tree,
		unsigned long scanned, unsigned long reclaimed)
{
	struct vmpressure *vmpr = memcg_to_vmpressure(memcg);

	/*
	 * Here we only want to account pressure that userland is able to
	 * help us with. For example, suppose that DMA zone is under
	 * pressure; if we notify userland about that kind of pressure,
	 * then it will be mostly a waste as it will trigger unnecessary
	 * freeing of memory by userland (since userland is more likely to
	 * have HIGHMEM/MOVABLE pages instead of the DMA fallback). That
	 * is why we include only movable, highmem and FS/IO pages.
	 * Indirect reclaim (kswapd) sets sc->gfp_mask to GFP_KERNEL, so
	 * we account it too.
	 *
	 * 在这里,我们只想说明压力让用户空间能够帮助我们解决.
	 * 例如,假设DMA zone处于压力之下;如果我们将这种压力通知给用户空间,那么这将是一种浪费,因为它将触发用户空间不必要的内存释放
	 * (因为userland更有可能具有HIGHMEM/MOVABLE页面而不是DMA fallback).
	 * 这就是为什么我们只包括movable、highmem和FS/IO页面.
	 * 间接回收(kswapd)将sc->gfp_mask设置为gfp_KERNEL,因此我们也对其进行了说明.
	 */
	if (!(gfp & (__GFP_HIGHMEM | __GFP_MOVABLE | __GFP_IO | __GFP_FS)))
		return;

	/*
	 * If we got here with no pages scanned, then that is an indicator
	 * that reclaimer was unable to find any shrinkable LRUs at the
	 * current scanning depth. But it does not mean that we should
	 * report the critical pressure, yet. If the scanning priority
	 * (scanning depth) goes too high (deep), we will be notified
	 * through vmpressure_prio(). But so far, keep calm.
	 *
	 * 如果我们在没有扫描页面的情况下到达这里,那么表明回收者在当前扫描深度下找不到任何可shrinkable的LRU.
	 * 但这并不意味着我们应该报告critical压力.
	 * 如果扫描优先级(扫描深度)过高(deep),我们将通过vmpressure_prio()通知.
	 * 但到目前为止，请保持冷静。
	 */
	if (!scanned)
		return;

	/* 如果tree = true */
	if (tree) {
		spin_lock(&vmpr->sr_lock);
		/* 将vmpr->tree_scanned + scanned */
		scanned = vmpr->tree_scanned += scanned;
		/* 将vmpr->tree_reclaimed + reclaimed */
		vmpr->tree_reclaimed += reclaimed;
		spin_unlock(&vmpr->sr_lock);
		/* 如果scanned < vmpressure_win,那么直接返回
		 * vmpressure_win见上面的注释
		 */
		if (scanned < vmpressure_win)
			return;
		/* 这边就是调用vmpressure_init的vmpressure_work_fn */
		schedule_work(&vmpr->work);
	} else { /* 如果tree = false */
		enum vmpressure_levels level;

		/* For now, no users for root-level efficiency
		 * 目前，没有用户支持根级别的效率
		 */

		/* 如果memcg为NULL,或者memcg == root_mem_cgroup直接返回 */
		if (!memcg || memcg == root_mem_cgroup)
			return;

		spin_lock(&vmpr->sr_lock);
		/* 将vmpr->tree_scanned + scanned */
		scanned = vmpr->scanned += scanned;
		/* 将vmpr->tree_reclaimed + reclaimed */
		reclaimed = vmpr->reclaimed += reclaimed;
		/* 如果scanned < vmpressure_win,那么直接返回
		 * vmpressure_win见上面的注释
		 */
		if (scanned < vmpressure_win) {
			spin_unlock(&vmpr->sr_lock);
			return;
		}
		/* vmpr->scanned 和 vmpr->reclaimed 初始化为0 */
		vmpr->scanned = vmpr->reclaimed = 0;
		spin_unlock(&vmpr->sr_lock);
		/* 通过reclaimed和scanned 得到vmpressure的level */
		level = vmpressure_calc_level(scanned, reclaimed);

		/* 如果level > VMPRESSURE_LOW */
		if (level > VMPRESSURE_LOW) {
			/*
			 * Let the socket buffer allocator know that
			 * we are having trouble reclaiming LRU pages.
			 *
			 * For hysteresis keep the pressure state
			 * asserted for a second in which subsequent
			 * pressure events can occur.
			 *
			 * 让套接字缓冲区分配器知道我们在回收LRU页面时遇到问题.
			 *
			 * 对于滞后现象,将压力状态保持一秒钟,在这一秒钟内可能会发生后续的压力事件.
			 */
			memcg->socket_pressure = jiffies + HZ;
		}
	}
}

/**
 * vmpressure_prio() - Account memory pressure through reclaimer priority level
 * @gfp:	reclaimer's gfp mask
 * @memcg:	cgroup memory controller handle
 * @prio:	reclaimer's priority
 *
 * This function should be called from the reclaim path every time when
 * the vmscan's reclaiming priority (scanning depth) changes.
 *
 * This function does not return any value.
 */
void vmpressure_prio(gfp_t gfp, struct mem_cgroup *memcg, int prio)
{
	/*
	 * We only use prio for accounting critical level. For more info
	 * see comment for vmpressure_level_critical_prio variable above.
	 */
	if (prio > vmpressure_level_critical_prio)
		return;

	/*
	 * OK, the prio is below the threshold, updating vmpressure
	 * information before shrinker dives into long shrinking of long
	 * range vmscan. Passing scanned = vmpressure_win, reclaimed = 0
	 * to the vmpressure() basically means that we signal 'critical'
	 * level.
	 */
	vmpressure(gfp, memcg, true, vmpressure_win, 0);
}

/**
 * vmpressure_register_event() - Bind vmpressure notifications to an eventfd
 * @memcg:	memcg that is interested in vmpressure notifications
 * @eventfd:	eventfd context to link notifications with
 * @args:	event arguments (used to set up a pressure level threshold)
 *
 * This function associates eventfd context with the vmpressure
 * infrastructure, so that the notifications will be delivered to the
 * @eventfd. The @args parameter is a string that denotes pressure level
 * threshold (one of vmpressure_str_levels, i.e. "low", "medium", or
 * "critical").
 *
 * To be used as memcg event method.
 */
int vmpressure_register_event(struct mem_cgroup *memcg,
			      struct eventfd_ctx *eventfd, const char *args)
{
	struct vmpressure *vmpr = memcg_to_vmpressure(memcg);
	struct vmpressure_event *ev;
	int level;

	for (level = 0; level < VMPRESSURE_NUM_LEVELS; level++) {
		if (!strcmp(vmpressure_str_levels[level], args))
			break;
	}

	if (level >= VMPRESSURE_NUM_LEVELS)
		return -EINVAL;

	ev = kzalloc(sizeof(*ev), GFP_KERNEL);
	if (!ev)
		return -ENOMEM;

	ev->efd = eventfd;
	ev->level = level;

	mutex_lock(&vmpr->events_lock);
	list_add(&ev->node, &vmpr->events);
	mutex_unlock(&vmpr->events_lock);

	return 0;
}

/**
 * vmpressure_unregister_event() - Unbind eventfd from vmpressure
 * @memcg:	memcg handle
 * @eventfd:	eventfd context that was used to link vmpressure with the @cg
 *
 * This function does internal manipulations to detach the @eventfd from
 * the vmpressure notifications, and then frees internal resources
 * associated with the @eventfd (but the @eventfd itself is not freed).
 *
 * To be used as memcg event method.
 */
void vmpressure_unregister_event(struct mem_cgroup *memcg,
				 struct eventfd_ctx *eventfd)
{
	struct vmpressure *vmpr = memcg_to_vmpressure(memcg);
	struct vmpressure_event *ev;

	mutex_lock(&vmpr->events_lock);
	list_for_each_entry(ev, &vmpr->events, node) {
		if (ev->efd != eventfd)
			continue;
		list_del(&ev->node);
		kfree(ev);
		break;
	}
	mutex_unlock(&vmpr->events_lock);
}

/**
 * vmpressure_init() - Initialize vmpressure control structure
 * @vmpr:	Structure to be initialized
 *
 * This function should be called on every allocated vmpressure structure
 * before any usage.
 */
void vmpressure_init(struct vmpressure *vmpr)
{
	spin_lock_init(&vmpr->sr_lock);
	mutex_init(&vmpr->events_lock);
	INIT_LIST_HEAD(&vmpr->events);
	INIT_WORK(&vmpr->work, vmpressure_work_fn);
}

/**
 * vmpressure_cleanup() - shuts down vmpressure control structure
 * @vmpr:	Structure to be cleaned up
 *
 * This function should be called before the structure in which it is
 * embedded is cleaned up.
 */
void vmpressure_cleanup(struct vmpressure *vmpr)
{
	/*
	 * Make sure there is no pending work before eventfd infrastructure
	 * goes away.
	 */
	flush_work(&vmpr->work);
}
