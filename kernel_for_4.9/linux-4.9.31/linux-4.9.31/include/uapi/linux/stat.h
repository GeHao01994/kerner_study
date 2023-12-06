#ifndef _UAPI_LINUX_STAT_H
#define _UAPI_LINUX_STAT_H


#if defined(__KERNEL__) || !defined(__GLIBC__) || (__GLIBC__ < 2)

/* 常量		声明		对普通文件的影响		对目录的影响
 * S_ISUID	设置用户ID	执行时设置有效用户ID		（未使用）
 *
 * S_ISGID	设置组ID	若组执行位设置，则执行时	将在目录中创建的新文件的
 *				设置有效组ID；否则使强制性	组ID设置为目录的组ID
 *				锁起作用（若支持)
 *
 * S_ISVTX	粘着位		在交换区缓存程序正文（若支持）	阻止在目录中删除和重命名文件
 *
 * S_IRUSER	用户读		许可用户读文件			许可用户读目录项
 *
 * S_IWUSER	用户写		许可用户写文件			许可用户在目录中删除和创建文件
 *
 * S_IXUSR	用户执行	许可用户执行文件		许可用户在目录中搜索给定路径名
 *
 * S_IRGRP	组读		许可组读文件			许可组读目录项
 *
 * S_IWGRP	组写		许可组写文件			许可组在目录中删除和创建文件
 *
 * S_IXGRP	组执行		许可组执行文件			许可组在目录中搜索给定路径名
 *
 * S_IROTH	其他读		许可其他读文件			许可其他读目录项
 *
 * S_IWOTH	其他写		许可其他写文件			许可其他在目录上删除和创建文件
 *
 * S_IXOTH	其他执行	许可其他执行文件		许可其他在目录中搜索给定路径名
 */
#define S_IFMT  00170000
#define S_IFSOCK 0140000
#define S_IFLNK	 0120000
#define S_IFREG  0100000
#define S_IFBLK  0060000
#define S_IFDIR  0040000
#define S_IFCHR  0020000
#define S_IFIFO  0010000
#define S_ISUID  0004000
#define S_ISGID  0002000
/* 在UNIX尚未使用请求分页式技术的早期版本中，S_ISVTX位被称为粘着位（sticky bit）。
 * 如果一个可执行程序文件的这一位被设置了，那么当该程序第一次被执行，在其终止时，程序正文部分的一个副本仍被保存在交换区（程序的正文部分是机器指令）。
 * 这使得下次执行该程序时能较快地将其装载入内存。其原因是：通常的UNIX文件系统中，文件的各数据块很可能是随机存放的，相比较而言，交换区是被作为一个连续文件来处理的。
 * 对于通用的应用程序，如文本编辑程序和C语言编译器，我们常常设置它们所在文件的粘着位。
 * 自然地，对于在交换区中可以同时存放的设置了粘着位的文件数是有限制的，以免过多占用交换区空间，
 * 但无论如何这是一个有用的技术。现今较新的UNIX系统大多数都配置了虚拟存储系统以及快速文件系统，所以不再需要使用这种技术。
 * 现今的系统扩展了粘着位的使用范围，Single UNIX Specification允许针对目录设置粘着位。
 * 如果对一个目录设置了粘着位，只有对该目录具有写权限的用户并且满足下列条件之一，才能删除或重命名该目录下的文件：
 * 1、拥有此文件
 * 2、拥有此目录
 * 3、超级用户
 */
#define S_ISVTX  0001000

#define S_ISLNK(m)	(((m) & S_IFMT) == S_IFLNK)
#define S_ISREG(m)	(((m) & S_IFMT) == S_IFREG)
#define S_ISDIR(m)	(((m) & S_IFMT) == S_IFDIR)
#define S_ISCHR(m)	(((m) & S_IFMT) == S_IFCHR)
#define S_ISBLK(m)	(((m) & S_IFMT) == S_IFBLK)
#define S_ISFIFO(m)	(((m) & S_IFMT) == S_IFIFO)
#define S_ISSOCK(m)	(((m) & S_IFMT) == S_IFSOCK)

#define S_IRWXU 00700
#define S_IRUSR 00400
#define S_IWUSR 00200
#define S_IXUSR 00100

#define S_IRWXG 00070
#define S_IRGRP 00040
#define S_IWGRP 00020
#define S_IXGRP 00010

#define S_IRWXO 00007
#define S_IROTH 00004
#define S_IWOTH 00002
#define S_IXOTH 00001

#endif


#endif /* _UAPI_LINUX_STAT_H */
