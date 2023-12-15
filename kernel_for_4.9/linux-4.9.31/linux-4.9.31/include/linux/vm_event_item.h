#ifndef VM_EVENT_ITEM_H_INCLUDED
#define VM_EVENT_ITEM_H_INCLUDED

#ifdef CONFIG_ZONE_DMA
#define DMA_ZONE(xx) xx##_DMA,
#else
#define DMA_ZONE(xx)
#endif

#ifdef CONFIG_ZONE_DMA32
#define DMA32_ZONE(xx) xx##_DMA32,
#else
#define DMA32_ZONE(xx)
#endif

#ifdef CONFIG_HIGHMEM
#define HIGHMEM_ZONE(xx) xx##_HIGH,
#else
#define HIGHMEM_ZONE(xx)
#endif

#define FOR_ALL_ZONES(xx) DMA_ZONE(xx) DMA32_ZONE(xx) xx##_NORMAL, HIGHMEM_ZONE(xx) xx##_MOVABLE

enum vm_event_item { PGPGIN, PGPGOUT,
		/* 发生swap in 换入事件的个数 */
		PSWPIN,
		/* 发生swap out 换出事件个数 */
		PSWPOUT,
		/* 每个zone成功申请page的个数 */
		FOR_ALL_ZONES(PGALLOC),
		/* 每个zone分配内存触发进程直接内存回收事件的次数
		 * 也就是当到达min水位的时候
		 */
		FOR_ALL_ZONES(ALLOCSTALL),
		/* 在内存回收流程中，从lru隔离page的时候，记录每个zone不符合隔离条件的page的个数 */
		FOR_ALL_ZONES(PGSCAN_SKIP),
		/* 释放page的个数 */
		PGFREE,
		/* 被移入活跃lru链表的page个数 */
		PGACTIVATE,
		/* 被移入非活跃lru链表的page个数 */
		PGDEACTIVATE,
		/* 整个系统缺页总次数(major+minor) */
		PGFAULT,
		/* major page fault 次数。缺页分配内存page时，若涉及io操作，即统计到pgmajfault，
		 * 比如文件映射，swap in时，需要读写磁盘文件的情况.
		 */
		PGMAJFAULT,
		/* 在内存回收从lru成功隔离符合回收条件的pages后，如果是匿名映射的page并且没有PG_swapbacked的falg，增加一次该事件的计数,
		 * 说明后续是可以直接释放该page，无需swap out的。
		 * 可以通过madvise(MADV_FREE)设置某匿名vma内映射的pages，
		 * 如果系统内存紧张决定回收pages，不用交换，后续直接释放.
		 */
		PGLAZYFREED,
		/* 在内存回收流程中扫描活跃lru链表page的个数。然后这些pages会分别根据每个page的引用情况，
		 * 是移到非活跃lru链表还是继续放在活跃链表
		 */
		PGREFILL,
		/* 这里steal和scan是存在差异，因为内存回收扫描非活跃lru时，会先将符合回收条件的page从lru隔离出来，
		 * 以免影响lru使用的竞争，此时sacn会先被计数，若成功隔离page的个数为0，说明此次扫描完成后未找到符合回收的page，
		 * 若隔离page的个数不为0，即有符合回收条件的page，此时会继续回收page，同时steal才被计数,所以steal 是<= scan的
		 */
		/* 分别是后台内存回收和直接内存会输收扫描非活跃lru时，
		 * 能够成功隔离page的个数，即能够回收page的个数
		 */
		PGSTEAL_KSWAPD,
		PGSTEAL_DIRECT,
		/* 分别是后台和直接内存内存回收扫描非活跃lru时，扫描到的page个数 */
		PGSCAN_KSWAPD,
		PGSCAN_DIRECT,
		/* 成功限制直接回收事件的次数。当前进程在此时收到了SIGKILL信号的话，就没必要再继续直接回收了，
		 * 停止直接回收，同时增加该计数
		 */
		PGSCAN_DIRECT_THROTTLE,
#ifdef CONFIG_NUMA
		/* node 快速回收失败次数。在申请内存流程中，若在fastpath申请内存失败，
		 * 踩到内存水线，会进行非unmap和非writeback的快速回收
		 */
		PGSCAN_ZONE_RECLAIM_FAILED,
#endif
		/* 直接回收slab，并扫描inode lru时，如果文件映射的page是空闲的，该page可以被释放回收，即记录该场景下空闲page的个数 */
		PGINODESTEAL,
		/* 回收slab的时候，扫描slab的总数 */
		SLABS_SCANNED,
		/* 和pginodesteal相似的，在后台回收时的计数. */
		KSWAPD_INODESTEAL,
		/* 可以这样理解，当剩余内存踩到低水线时会唤醒kswapd，启动后台回收，直到剩余内存达到高水线时,
		 * kswapd会有一个时长为HZ/10的过渡期，尝试准备sleep，在这期间如果剩余内存再次低于低水线，则记录一次快速low_wmark事件.
		 * 若在这期间如果剩余内存再次低于高水线，则记录一次快速high_wmark事件
		 */
		/* kswap准备sleep之前，剩余内存再次低于低水线的次数 */
		KSWAPD_LOW_WMARK_HIT_QUICKLY,
		/* kswap准备sleep之前，剩余内存再次低于高水线的次数 */
		KSWAPD_HIGH_WMARK_HIT_QUICKLY,
		/* kswap调用balance_pgdat函数(回收主函数)的次数。可视为后台回收的次数 */
		PAGEOUTRUN,
		/* 被移动到lru链表末尾的page个数 */
		PGROTATED,
		/* echo 1 > /proc/sys/vm/drop_caches 释放空闲pagecache，即drop_pagecache。
		 * echo 2 > /proc/sys/vm/drop_caches 释放各文件系统空闲的detry和inode，即drop_slab。
		 * echo 3 > /proc/sys/vm/drop_caches drop_pagecache和drop_slab
		 */
		/* 从系统启动开始，主动drop cache触发次数 */
		DROP_PAGECACHE,
		/* 主动drop slab触发次数 */
		DROP_SLAB,
#ifdef CONFIG_NUMA_BALANCING
		/* 在标记某个虚拟地址区间不可访问的时候，需要更新的普通page页表的个数。mbind()系统调用可能会触发该事件 */
		NUMA_PTE_UPDATES,
		/* 修改某个内存区间属性的时候，需要更新THP页表的个数。mprotect()系统调用可能会触发该事件 */
		NUMA_HUGE_PTE_UPDATES,
		/* 在缺页时，若pte设置了_PAGE_PROTNONE，会走do_numa_page缺页,其中会进行页迁移，同时增加该事件计数 */
		NUMA_HINT_FAULTS,
		/* 是numa_hint_faults的子集，迁移的page list中page所在node是当前cup所在node，则增加一次该事件计数 */
		NUMA_HINT_FAULTS_LOCAL,
		/* 更新页表时，迁移的page的个数 */
		NUMA_PAGE_MIGRATE,
#endif
#ifdef CONFIG_MIGRATION
		/* 迁移成功的page个数 */
		PGMIGRATE_SUCCESS,
		/* 迁移失败的page个数 */
		PGMIGRATE_FAIL,
#endif
#ifdef CONFIG_COMPACTION
		/* 内存规整扫描地址区间后可迁移的page个数，包括后台规整和直接规整 */
		COMPACTMIGRATE_SCANNED,
		/* 内存规整扫描地址区间后是空闲page个数 */
		COMPACTFREE_SCANNED,
		/* 内存规整中可隔离可迁移page和空闲page的总数，然后再对已经隔离的page进行内存迁移 */
		COMPACTISOLATED,
		/* 直接内存规整次数 */
		COMPACTSTALL,
		/* 直接内存规整失败次数 */
		COMPACTFAIL,
		/* 直接内存规整成功次数 */
		COMPACTSUCCESS,
		/* kcompactd后台规整线程被唤醒次数 */
		KCOMPACTD_WAKE,
#endif
#ifdef CONFIG_HUGETLB_PAGE
		/* 分配hugetlb大页成功的次数 */
		HTLB_BUDDY_PGALLOC,
		/* 分配hugetlb大页失败的次数 */
		HTLB_BUDDY_PGALLOC_FAIL,
#endif
		/* page在添加到lru时，若page满足不可回收条件，会增加一次事件计数，并随后会将page添加到不可回收lru
		 * 这里不可回收条件是page映射的vma是mlocked的(mlock()和mlockall()系统调用可设置)和
		 * page映射的文件是不可回收的(ramfs内存文件系统file和shmctl设置的file)，满足其中一个即不可回收
		 */
		UNEVICTABLE_PGCULLED,	/* culled to noreclaim list */
		/* UNEVICTABLE_PGSCANNED 计数中是通过扫描page所在的链表后才被移出不可回收链表的page个数，就是指通过shmctl系统调用，解锁file映射的page */
		UNEVICTABLE_PGSCANNED,	/* scanned for reclaimability */
		/* 与UNEVICTABLE_PGRESCUED场景对应，若不是不可回收的page，会增加该计数，
		 * 并添加到可回收链表。只要是page被移出不可回收链表，都会增加该事件计数
		 */
		UNEVICTABLE_PGRESCUED,	/* rescued from noreclaim list */
		/* 在page加到lru之前，会先校验一下vma是否是mlocked(是否有VM_LOCKED falg)，
		 * 若有该flags并且page没有设置PG_mlocked，则增加一次计数，
		 * 并设置page为PG_mlocked。可视为系统mlocked page的总数
		 */
		UNEVICTABLE_PGMLOCKED,
		/* munlock系统调用中成功解锁的的page个数 */
		UNEVICTABLE_PGMUNLOCKED,
		/* 内核中调用clear_page_mlock()清除page的PG_mlocked符号的次数，
		 * 这个会在内存迁移，断开内存映射时会去调用
		 */
		UNEVICTABLE_PGCLEARED,	/* on COW, page truncate */
		/* munlock系统调用中未能成功解锁的的page个数 */
		UNEVICTABLE_PGSTRANDED,	/* unable to isolate on unlock */
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
		/* 分配THP透明巨页成功的次数 */
		THP_FAULT_ALLOC,
		/* 未能成功分配THP透明巨页的次数 */
		THP_FAULT_FALLBACK,
		/* khugepaged线程会尝试将符合条件的普通page整合成THP，
		 * 线程会先尝试分配一个THP,再将普通page迁移到THP，该事件记录该线程成功分配THP的个数
		 */
		THP_COLLAPSE_ALLOC,
		/* 同上描述，该事件记录khugepaged线程未成功分配THP的个数 */
		THP_COLLAPSE_ALLOC_FAILED,
		/* 共享内存分配THP的次数 */
		THP_FILE_ALLOC,
		/* 共享内存完成缺页并建立映射的THP次数 */
		THP_FILE_MAPPED,
		/* THP成功拆分成普通page的次数，swap out或者madvise系统调用修改vma属性，都会触发该事件 */
		THP_SPLIT_PAGE,
		/* THP拆分成普通page失败的次数 */
		THP_SPLIT_PAGE_FAILED,
		/* 延迟拆分THP成普通page的个数。在只断开THP部分子页的映射时,
		 * 并不会立刻拆分，当内存紧张时才会调用shrinker去拆分THP成普通page,
		 * 并释放空闲的子页
		 */
		THP_DEFERRED_SPLIT_PAGE,
		/* 调整vma的时候(合并或者分离)，若新的vma的起始和结束地址未对齐,
		 * 并且vma中有THP映射，会记录拆分PMD页表为PTE的次数.
		 */
		THP_SPLIT_PMD,
		/* 缺页时，若地址所在vma是只读，会默认分配THP zero page，
		 * 并且内核只保存一份零页，在其他只读vma缺页时，也会共享这个零页，
		 * 不再重新分配。该事件只记录从伙伴系统成功分配零页的次数
		 */
		THP_ZERO_PAGE_ALLOC,
		/* 该事件只记录从伙伴系统未成功分配零页的次数 */
		THP_ZERO_PAGE_ALLOC_FAILED,
#endif
#ifdef CONFIG_MEMORY_BALLOON
		/* virtio balloo是guest os在运行时可动态调整它所占用的宿主机内存资源的一种机制 */
		/* 填充balloon的次数 */
		BALLOON_INFLATE,
		/* 收缩balloon的次数 */
		BALLOON_DEFLATE,
#ifdef CONFIG_BALLOON_COMPACTION
		/* balloon中的page迁移的次数 */
		BALLOON_MIGRATE,
#endif
#endif
#ifdef CONFIG_DEBUG_TLBFLUSH
#ifdef CONFIG_SMP
		NR_TLB_REMOTE_FLUSH,	/* cpu tried to flush others' tlbs */
		NR_TLB_REMOTE_FLUSH_RECEIVED,/* cpu received ipi for flush */
#endif /* CONFIG_SMP */
		NR_TLB_LOCAL_FLUSH_ALL,
		NR_TLB_LOCAL_FLUSH_ONE,
#endif /* CONFIG_DEBUG_TLBFLUSH */
#ifdef CONFIG_DEBUG_VM_VMACACHE
		VMACACHE_FIND_CALLS,
		VMACACHE_FIND_HITS,
		VMACACHE_FULL_FLUSHES,
#endif
		NR_VM_EVENT_ITEMS
};

#ifndef CONFIG_TRANSPARENT_HUGEPAGE
#define THP_FILE_ALLOC ({ BUILD_BUG(); 0; })
#define THP_FILE_MAPPED ({ BUILD_BUG(); 0; })
#endif

#endif		/* VM_EVENT_ITEM_H_INCLUDED */
