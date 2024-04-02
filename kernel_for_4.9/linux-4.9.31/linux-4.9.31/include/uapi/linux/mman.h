#ifndef _UAPI_LINUX_MMAN_H
#define _UAPI_LINUX_MMAN_H

#include <asm/mman.h>

#define MREMAP_MAYMOVE	1
#define MREMAP_FIXED	2

/* overcommit_memory这个参数就是用来控制内核对overcommit的策略.该参数可以设定的值如下:
 *
 * OVERCOMMIT_GUESS:这是linux的缺省值,它允许overcommit,但是它会根据当前的系统可用虚拟内存来判断是否允许虚拟内存的申请.
 * 内核利用__vm_enough_memory判断你的内存申请是否合理,它认为不合理就会拒绝overcommit.
 *
 * OVERCOMMIT_ALWAYS:内核不限制overcommit,无论进程们commit了多少的地址空间的申请都不会拒绝.
 *
 * OVERCOMMIT_NEVER: always的反面,禁止overcommit,不允许超过系统设置的虚拟内存限制.
 */
#define OVERCOMMIT_GUESS		0
#define OVERCOMMIT_ALWAYS		1
#define OVERCOMMIT_NEVER		2

#endif /* _UAPI_LINUX_MMAN_H */
