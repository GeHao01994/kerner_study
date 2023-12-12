/*
 * This is <linux/capability.h>
 *
 * Andrew G. Morgan <morgan@kernel.org>
 * Alexander Kjeldaas <astor@guardian.no>
 * with help from Aleph1, Roland Buresund and Andrew Main.
 *
 * See here for the libcap library ("POSIX draft" compliance):
 *
 * ftp://www.kernel.org/pub/linux/libs/security/linux-privs/kernel-2.6/
 */

#ifndef _UAPI_LINUX_CAPABILITY_H
#define _UAPI_LINUX_CAPABILITY_H

#include <linux/types.h>

/* User-level do most of the mapping between kernel and user
   capabilities based on the version tag given by the kernel. The
   kernel might be somewhat backwards compatible, but don't bet on
   it. */

/* Note, cap_t, is defined by POSIX (draft) to be an "opaque" pointer to
   a set of three capability sets.  The transposition of 3*the
   following structure to such a composite is better handled in a user
   library since the draft standard requires the use of malloc/free
   etc.. */

#define _LINUX_CAPABILITY_VERSION_1  0x19980330
#define _LINUX_CAPABILITY_U32S_1     1

#define _LINUX_CAPABILITY_VERSION_2  0x20071026  /* deprecated - use v3 */
#define _LINUX_CAPABILITY_U32S_2     2

#define _LINUX_CAPABILITY_VERSION_3  0x20080522
#define _LINUX_CAPABILITY_U32S_3     2

typedef struct __user_cap_header_struct {
	__u32 version;
	int pid;
} __user *cap_user_header_t;

typedef struct __user_cap_data_struct {
        __u32 effective;
        __u32 permitted;
        __u32 inheritable;
} __user *cap_user_data_t;


#define VFS_CAP_REVISION_MASK	0xFF000000
#define VFS_CAP_REVISION_SHIFT	24
#define VFS_CAP_FLAGS_MASK	~VFS_CAP_REVISION_MASK
#define VFS_CAP_FLAGS_EFFECTIVE	0x000001

#define VFS_CAP_REVISION_1	0x01000000
#define VFS_CAP_U32_1           1
#define XATTR_CAPS_SZ_1         (sizeof(__le32)*(1 + 2*VFS_CAP_U32_1))

#define VFS_CAP_REVISION_2	0x02000000
#define VFS_CAP_U32_2           2
#define XATTR_CAPS_SZ_2         (sizeof(__le32)*(1 + 2*VFS_CAP_U32_2))

#define XATTR_CAPS_SZ           XATTR_CAPS_SZ_2
#define VFS_CAP_U32             VFS_CAP_U32_2
#define VFS_CAP_REVISION	VFS_CAP_REVISION_2

struct vfs_cap_data {
	__le32 magic_etc;            /* Little endian */
	struct {
		__le32 permitted;    /* Little endian */
		__le32 inheritable;  /* Little endian */
	} data[VFS_CAP_U32];
};

#ifndef __KERNEL__

/*
 * Backwardly compatible definition for source code - trapped in a
 * 32-bit world. If you find you need this, please consider using
 * libcap to untrap yourself...
 */
#define _LINUX_CAPABILITY_VERSION  _LINUX_CAPABILITY_VERSION_1
#define _LINUX_CAPABILITY_U32S     _LINUX_CAPABILITY_U32S_1

#endif


/**
 ** POSIX-draft defined capabilities.
 **/

/* In a system with the [_POSIX_CHOWN_RESTRICTED] option defined, this
   overrides the restriction of changing file ownership and group
   ownership. */
/* CAP_CHOWN (容许改变文件的全部权) */
#define CAP_CHOWN            0

/* Override all DAC access, including ACL execute access if
   [_POSIX_ACL] is defined. Excluding DAC access covered by
   CAP_LINUX_IMMUTABLE. */
/* 忽略对文件的全部DAC访问限制 */
#define CAP_DAC_OVERRIDE     1

/* Overrides all DAC restrictions regarding read and search on files
   and directories, including ACL restrictions if [_POSIX_ACL] is
   defined. Excluding DAC access covered by CAP_LINUX_IMMUTABLE. */
/* 忽略全部对读、搜索操做的限制 */
#define CAP_DAC_READ_SEARCH  2

/* Overrides all restrictions about allowed operations on files, where
   file owner ID must be equal to the user ID, except where CAP_FSETID
   is applicable. It doesn't override MAC and DAC restrictions. */
/* 以最后操做的UID,覆盖文件的先前的UID */
#define CAP_FOWNER           3

/* Overrides the following restrictions that the effective user ID
   shall match the file owner ID when setting the S_ISUID and S_ISGID
   bits on that file; that the effective group ID (or one of the
   supplementary group IDs) shall match the file owner ID when setting
   the S_ISGID bit on that file; that the S_ISUID and S_ISGID bits are
   cleared on successful return from chown(2) (not implemented). */
/* CAP_FSETID 4(确保在文件被修改后不修改setuid/setgid位)
 * 原由是当文件被修改后,会清除掉文件的setuid/setgid位,
 * 而设定CAP_FSETID后将保证setuid/setgid位不被清除.但这对chown函数无用.
 */
#define CAP_FSETID           4

/* Overrides the restriction that the real or effective user ID of a
   process sending a signal must match the real or effective user ID
   of the process receiving the signal. */
/* 容许对不属于本身的进程发送信号 */
#define CAP_KILL             5

/* Allows setgid(2) manipulation */
/* Allows setgroups(2) */
/* Allows forged gids on socket credentials passing. */
/* 设定程序容许普通用户使用setgid函数,这与文件的setgid权限位无关 */
#define CAP_SETGID           6

/* Allows set*uid(2) manipulation (including fsuid). */
/* Allows forged pids on socket credentials passing. */
/* 设定程序容许普通用户使用setuid函数,这也文件的setuid权限位无关 */
#define CAP_SETUID           7


/**
 ** Linux-specific capabilities
 **/

/* Without VFS support for capabilities:
 *   Transfer any capability in your permitted set to any pid,
 *   remove any capability in your permitted set from any pid
 * With VFS support for capabilities (neither of above, but)
 *   Add any capability from current's capability bounding set
 *       to the current process' inheritable set
 *   Allow taking bits out of capability bounding set
 *   Allow modification of the securebits for a process
 */
/* 容许向其它进程转移能力以及删除其它进程的任意能力
 * 事实上只有init进程能够设定其它进程的能力,而其它程序无权对进程受权,
 * root用户也不能对其它进程的能力进行修改,
 * 只能对当前进程经过cap_set_proc等函数进行修改,
 * 而子进程也会继承这种能力.
 * 因此即便使用了CAP_SETPCAP能力,也不会起到真正的做用.
 */
#define CAP_SETPCAP          8

/* Allow modification of S_IMMUTABLE and S_APPEND file attributes */
/* 容许修改文件的不可修改(IMMUTABLE)和只添加(APPEND-ONLY)属性)
 * 普通用户不能经过chattr对文件设置IMMUTABLE(chattr +i)和
 * APPEND-ONLY(chattr +a)权限,
 * 而经过CAP_LINUX_IMMUTABLE可使普通用户经过本身增减(immutable/append-only)权限
 */
#define CAP_LINUX_IMMUTABLE  9

/* Allows binding to TCP/UDP sockets below 1024 */
/* Allows binding to ATM VCIs below 32 */
/* 容许绑定到小于1024的端口
 * 普通用户不能经过bind函数绑定小于1024的端口,
 * 而root用户能够作到,CAP_NET_BIND_SERVICE的
 * 做用就是让普通用户也能够绑端口到1024以下.
 */
#define CAP_NET_BIND_SERVICE 10

/* Allow broadcasting, listen to multicast */
/* 容许网络广播和多播访问
 * 事实上它并无被应用,普通用户也可使用ping -b 192.168.0.255也发送广播包
 */
#define CAP_NET_BROADCAST    11

/* Allow interface configuration */
/* Allow administration of IP firewall, masquerading and accounting */
/* Allow setting debug option on sockets */
/* Allow modification of routing tables */
/* Allow setting arbitrary process / process group ownership on
   sockets */
/* Allow binding to any address for transparent proxying (also via NET_RAW) */
/* Allow setting TOS (type of service) */
/* Allow setting promiscuous mode */
/* Allow clearing driver statistics */
/* Allow multicasting */
/* Allow read/write of device-specific registers */
/* Allow activation of ATM control sockets */
/* 容许执行网络管理任务:接口,防火墙和路由等 */
#define CAP_NET_ADMIN        12

/* Allow use of RAW sockets */
/* Allow use of PACKET sockets */
/* Allow binding to any address for transparent proxying (also via NET_ADMIN) */
/* (容许使用原始(raw)套接字)
 * 原始套接字编程能够接收到本机网卡上的数据帧或者数据包,
 * 对监控网络流量和分析是颇有做用的.
 */
#define CAP_NET_RAW          13

/* Allow locking of shared memory segments */
/* Allow mlock and mlockall (which doesn't really have anything to do
   with IPC) */
/* (在容许锁定内存片段)
 * root和普通用户均可以用mlock来锁定内存,
 * 区别是root不受ulimit下的锁定内存大小限制,而普通用户会受到影响.
 */
#define CAP_IPC_LOCK         14

/* Override IPC ownership checks */
/* CAP_IPC_OWNER 15 (忽略IPC全部权检查)
 * 这个能力对普通用户有做用,若是用root用户建立共享内存(shmget),
 * 权限为600,而普通用户不能读取该段共享内存.
 * 经过CAP_IPC_OWNER可让普通用户的程序能够读取/更改共享内存.
 */
#define CAP_IPC_OWNER        15
/* CAP_SYS_MODULE 16 (容许普通用户插入和删除内核模块)
 * 因为普通用户不能插入/删除内核模块,而CAP_SYS_MODULE能够帮助普通用户作到这点
 */
/* Insert and remove kernel modules - modify kernel without limit */
#define CAP_SYS_MODULE       16

/* Allow ioperm/iopl access */
/* Allow sending USB messages to any device via /proc/bus/usb */
/* CAP_SYS_RAWIO 17 (容许用户打开端口,并读取修改端口数据,通常用ioperm/iopl函数)
 * ioperm只有低端的[0-0x3ff] I/O端口可被设置,且普通用户不能使用.
 * iopl能够用于全部的65536个端口,所以ioperm至关于iopl调用的一个子集.
 */
#define CAP_SYS_RAWIO        17

/* Allow use of chroot() */
/* (容许使用chroot()系统调用)
 * 普通用户不能经过chroot系统调用更改程式执行时所参考的根目录位置,
 * 而CAP_SYS_CHROOT能够帮助普通用户作到这一点.
 */
#define CAP_SYS_CHROOT       18

/* Allow ptrace() of any process */
/* (容许跟踪任何进程)
 * 普通用户不能跟踪任何进程,不包括它本身的进程,
 * 而CAP_SYS_PTRACE能够帮助普通用户跟踪任何进程.
 */
#define CAP_SYS_PTRACE       19

/* Allow configuration of process accounting */
/* 容许配置进程记账process accounting */
#define CAP_SYS_PACCT        20

/* Allow configuration of the secure attention key */
/* Allow administration of the random device */
/* Allow examination and configuration of disk quotas */
/* Allow setting the domainname */
/* Allow setting the hostname */
/* Allow calling bdflush() */
/* Allow mount() and umount(), setting up new smb connection */
/* Allow some autofs root ioctls */
/* Allow nfsservctl */
/* Allow VM86_REQUEST_IRQ */
/* Allow to read/write pci config on alpha */
/* Allow irix_prctl on mips (setstacksize) */
/* Allow flushing all cache on m68k (sys_cacheflush) */
/* Allow removing semaphores */
/* Used instead of CAP_CHOWN to "chown" IPC message queues, semaphores
   and shared memory */
/* Allow locking/unlocking of shared memory segment */
/* Allow turning swap on/off */
/* Allow forged pids on socket credentials passing */
/* Allow setting readahead and flushing buffers on block devices */
/* Allow setting geometry in floppy driver */
/* Allow turning DMA on/off in xd driver */
/* Allow administration of md devices (mostly the above, but some
   extra ioctls) */
/* Allow tuning the ide driver */
/* Allow access to the nvram device */
/* Allow administration of apm_bios, serial and bttv (TV) device */
/* Allow manufacturer commands in isdn CAPI support driver */
/* Allow reading non-standardized portions of pci configuration space */
/* Allow DDI debug ioctl on sbpcd driver */
/* Allow setting up serial ports */
/* Allow sending raw qic-117 commands */
/* Allow enabling/disabling tagged queuing on SCSI controllers and sending
   arbitrary SCSI commands */
/* Allow setting encryption key on loopback filesystem */
/* Allow setting zone reclaim policy */
/* 容许执行系统管理任务,如挂载/卸载文件系统,设置磁盘配额,开/关交换设备和文件等 */
#define CAP_SYS_ADMIN        21

/* Allow use of reboot() */
/* (容许普通用使用reboot()函数 */
#define CAP_SYS_BOOT         22

/* Allow raising priority and setting priority on other (different
   UID) processes */
/* Allow use of FIFO and round-robin (realtime) scheduling on own
   processes and setting the scheduling algorithm used by another
   process. */
/* Allow setting cpu affinity on other processes */
/* 容许提高优先级,设置其它进程的优先级 */
#define CAP_SYS_NICE         23

/* Override resource limits. Set resource limits. */
/* Override quota limits. */
/* Override reserved space on ext2 filesystem */
/* Modify data journaling mode on ext3 filesystem (uses journaling
   resources) */
/* NOTE: ext2 honors fsuid when checking for resource overrides, so
   you can override using fsuid too */
/* Override size restrictions on IPC message queues */
/* Allow more than 64hz interrupts from the real-time clock */
/* Override max number of consoles on console allocation */
/* Override max number of keymaps */
/* 忽略资源限制
 * 普通用户不能用setrlimit()来突破ulimit的限制
 */
#define CAP_SYS_RESOURCE     24

/* Allow manipulation of system clock */
/* Allow irix_stime on mips */
/* Allow setting the real-time clock */
/* 容许改变系统时钟
 * 普通用户不能改变系统时钟,以下:
 * date -s 2012-01-01
 * date: cannot set date: Operation not permitted
 * Sun Jan  1 00:00:00 EST 2012
 * CAP_SYS_TIME能够帮助普通用户改变系统时钟,以下:
 * setcap cap_sys_time=eip /bin/date
 * 切换到普通用户再次改变时间,发现已经能够改变了
 * su - test
 * date -s 2012-01-01
 * Sun Jan  1 00:00:00 EST 2012
 * date
 * Sun Jan  1 00:00:02 EST 2012
 */
#define CAP_SYS_TIME         25

/* Allow configuration of tty devices */
/* Allow vhangup() of tty */
/* 容许配置TTY设备 */
#define CAP_SYS_TTY_CONFIG   26

/* Allow the privileged aspects of mknod() */
/* 容许使用mknod系统调用
 * 普通用户不能用mknod()来建立设备文件,而CAP_MKNOD能够帮助普通用户作到这一点
 */
#define CAP_MKNOD            27

/* Allow taking of leases on files */
/* 容许在文件上创建租借锁
 * 与租借锁相关的 cmd 参数的取值有两种：F_SETLEASE 和 F_GETLEASE。其含义以下所示:
 * F_SETLEASE：根据下面所描述的 arg 参数指定的值来创建或者删除租约:
 * F_RDLCK：设置读租约。当文件被另外一个进程以写的方式打开时，拥有该租约的当前进程会收到通知
 * F_WRLCK：设置写租约。当文件被另外一个进程以读或者写的方式打开时，拥有该租约的当前进程会收到通知
 * F_UNLCK：删除之前创建的租约
 * F_GETLEASE：代表调用进程拥有文件上哪一种类型的锁，这须要经过返回值来肯定，返回值有三种：F_RDLCK、F_WRLCK和F_UNLCK，
 * 分别代表调用进程对文件拥有读租借、写租借或者根本没有租借
 * 某个进程可能会对文件执行其余一些系统调用(好比 OPEN() 或者 TRUNCATE())，
 * 若是这些系统调用与该文件上由 F_SETLEASE 所设置的租借锁相冲突，内核就会阻塞这个系统调用;
 * 同时，内核会给拥有这个租借锁的进程发信号，告知此事。拥有此租借锁的进程会对该信号进行反馈，
 * 它可能会删除这个租借锁，也可能会减短这个租借锁的租约，从而可使得该文件能够被其余进程所访问.
 * 若是拥有租借锁的进程不能在给定时间内完成上述操做，那么系统会强制帮它完成.
 * 经过 F_SETLEASE 命令将 arg 参数指定为 F_UNLCK 就能够删除这个租借锁.
 * 无论对该租借锁减短租约或者干脆删除的操做是进程自愿的仍是内核强迫的,
 * 只要被阻塞的系统调用尚未被发出该调用的进程解除阻塞,
 * 那么系统就会容许这个系统调用执行.
 * 即便被阻塞的系统调用由于某些缘由被解除阻塞,
 * 可是上面对租借锁减短租约或者删除这个过程仍是会执行的.
 */
#define CAP_LEASE            28

/* Allow writing the audit log via unicast netlink socket */
#define CAP_AUDIT_WRITE      29

/* Allow configuration of audit via unicast netlink socket */

#define CAP_AUDIT_CONTROL    30

/* 容许在指定的程序上受权能力给其它程序 */
#define CAP_SETFCAP	     31

/* Override MAC access.
   The base kernel enforces no MAC policy.
   An LSM may enforce a MAC policy, and if it does and it chooses
   to implement capability based overrides of that policy, this is
   the capability it should use to do so. */
/* CAP_MAC_OVERRIDE	覆盖 MAC(Mandatory Access Control) */
#define CAP_MAC_OVERRIDE     32

/* Allow MAC configuration or state changes.
   The base kernel requires no MAC configuration.
   An LSM may enforce a MAC policy, and if it does and it chooses
   to implement capability based checks on modifications to that
   policy or the data required to maintain it, this is the
   capability it should use to do so. */

#define CAP_MAC_ADMIN        33

/* Allow configuring the kernel's syslog (printk behaviour) */

#define CAP_SYSLOG           34

/* Allow triggering something that will wake the system */

#define CAP_WAKE_ALARM            35

/* Allow preventing system suspends */

#define CAP_BLOCK_SUSPEND    36

/* Allow reading the audit log via multicast netlink socket */

#define CAP_AUDIT_READ		37


#define CAP_LAST_CAP         CAP_AUDIT_READ

#define cap_valid(x) ((x) >= 0 && (x) <= CAP_LAST_CAP)

/*
 * Bit location of each capability (used by user-space library and kernel)
 */

#define CAP_TO_INDEX(x)     ((x) >> 5)        /* 1 << 5 == bits in __u32 */
#define CAP_TO_MASK(x)      (1 << ((x) & 31)) /* mask for indexed __u32 */


#endif /* _UAPI_LINUX_CAPABILITY_H */
