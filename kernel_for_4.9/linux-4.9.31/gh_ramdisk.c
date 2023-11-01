#include <linux/module.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/timer.h>
#include <linux/genhd.h>
#include <linux/hdreg.h>
#include <linux/ioport.h>
#include <linux/init.h>
#include <linux/wait.h>
#include <linux/blkdev.h>
#include <linux/mutex.h>
#include <linux/blkpg.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/gfp.h>
#include <asm/system.h>
#include <asm/uaccess.h>
#include <asm/dma.h>
#include<linux/slab.h>
static struct gendisk *ramblock_disk;
static struct request_queue *ramblock_queue;
static DEFINE_SPINLOCK(ramdisk_lock);
static int major;
static unsigned char *ramblock_buf;


static int ramblock_getgeo(struct block_device *bdev, struct hd_geometry *geo)
{
geo->heads = 2; //������
geo->sectors = 32;//һ�������ж��ٻ�
geo->cylinders = BLOCK_SIZE/2/32/512;//һ�������ж���ɢ��


return 0;
}
static const struct block_device_operations ramblock_fops = {
.owner  = THIS_MODULE,
.getgeo = ramblock_getgeo,
};
#define RAMBLOCK_SIZE (1024*1024)


static void do_block_request (struct request_queue * q)
{
struct request *req;
req = blk_fetch_request(q);
while (req) {
/*Դ��Ŀ��*/
unsigned long offset = blk_rq_pos(req) * 512;

// ����
/*����*/
unsigned long len  = blk_rq_cur_bytes(req);


if (rq_data_dir(req) == READ)
memcpy(req->buffer, ramblock_buf+offset, len);
else
memcpy(ramblock_buf+offset, req->buffer, len);
/* wrap up, 0 = success, -errno = fail */
if (!__blk_end_request_cur(req, 0))
req = blk_fetch_request(q);
}


}




static int ramblock_init(void)
{
/*1.����һ��gendisk�ṹ��*/
//����,minors�������������ʹ�õĴα��������һ��Ҳ���Ǵ��̷������������˺�minors���ܱ��޸�
ramblock_disk=alloc_disk(16);
/*2.����*/
/*2.1����/���ö���:�ṩ��д����*/
ramblock_queue = blk_init_queue(do_block_request, &ramdisk_lock);
/*2.2�����������ԣ���������*/
major = register_blkdev(0,"ramblock");
ramblock_disk->major = major;
ramblock_disk->first_minor = 0;
sprintf(ramblock_disk->disk_name, "ramblock");
ramblock_disk->fops = &ramblock_fops;
ramblock_disk->queue = ramblock_queue;
//���豸����С�Ŀ�Ѱַ��Ԫ��������������Сһ����2��������������Ĵ�С��512�ֽڡ������Ĵ�С���豸���������ԣ����������п��豸�Ļ�����Ԫ��
set_capacity(ramblock_disk, RAMBLOCK_SIZE/512);
/*3 Ӳ����صĲ���*/
ramblock_buf = kzalloc(RAMBLOCK_SIZE, GFP_KERNEL);
/*4.ע��*/
add_disk(ramblock_disk);
return 0;
}


static void ramblock_exit(void)
{
unregister_blkdev(major,"ramblock");
del_gendisk(ramblock_disk);
put_disk(ramblock_disk);
blk_cleanup_queue(ramblock_queue);


}
module_init(ramblock_init);
module_exit(ramblock_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("EIGHT");
