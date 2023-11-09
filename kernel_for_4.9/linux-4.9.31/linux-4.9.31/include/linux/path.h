#ifndef _LINUX_PATH_H
#define _LINUX_PATH_H

struct dentry;
struct vfsmount;

/* 全局文件系统树上的一个位置就不能由dentry唯一确定
 * 尤其我们一个文件系统可以被装载到不同的装载点上。
 * 所以现在文件系统的位置需要由<vfsmount,dentry>二元组来定
 * 这就是所谓在linux内核中确定文件位置的路径
 */
struct path {
	struct vfsmount *mnt;
	struct dentry *dentry;
};

extern void path_get(const struct path *);
extern void path_put(const struct path *);

static inline int path_equal(const struct path *path1, const struct path *path2)
{
	return path1->mnt == path2->mnt && path1->dentry == path2->dentry;
}

#endif  /* _LINUX_PATH_H */
