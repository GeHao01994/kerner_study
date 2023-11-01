#include <linux/module.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/ioport.h>
#include <linux/platform_device.h>
#include <linux/delay.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/clk.h>
#include <linux/cpufreq.h>


#include <linux/mtd/mtd.h>
#include <linux/mtd/nand.h>
#include <linux/mtd/nand_ecc.h>
#include <linux/mtd/partitions.h>


#include <asm/io.h>


#include <plat/regs-nand.h>
#include <plat/nand.h>


static struct nand_chip *nand;
static struct mtd_info *nand_mtd;
struct s5p_nand_regs{
unsigned long nfconf;
unsigned long nfcont;
unsigned long nfcmmd;
unsigned long nfaddr;
unsigned long nfdata;
unsigned long nfmeccd0;
unsigned long nfmeccd1;
unsigned long nfseccd;
unsigned long nfsblk;
unsigned long nfeblk;
unsigned long nfstat;
unsigned long nfeccerr0;
unsigned long nfeccerr1;
};
static struct s5p_nand_regs *s5p_nand_regs;
struct mtd_partition s5p_partition_info[] = {
{
.name = "uboot",
.offset  = 0,          /* for bootloader */
.size = (1*SZ_1M),
.mask_flags  = MTD_CAP_NANDFLASH,
},


{
.name = "recovery",
.offset  = MTDPART_OFS_APPEND,
.size = (5*SZ_1M),
},


{
.name = "kernel",
.offset  = MTDPART_OFS_APPEND,
.size = (5*SZ_1M),
},


{
.name = "ramdisk",
.offset  = MTDPART_OFS_APPEND,
.size = (3*SZ_1M),
},


{
.name = "root",
.offset  = MTDPART_OFS_APPEND,
.size = MTDPART_SIZ_FULL,
},


};






static void gh_select_chip(struct mtd_info *mtd, int chipnr)
{
if(chipnr == -1)
{
//ȡ��ѡ�� ��NFCONT[1] ����Ϊ1
s5p_nand_regs->nfcont |=(1<<1);
}
else
{
//ѡ�� NFCONT��1������Ϊ0
s5p_nand_regs->nfcont &= ~(1<<1);


}


}


static void gh_cmd_ctrl(struct mtd_info *mtd, int cmd, unsigned int ctrl)
{


if (ctrl & NAND_CLE)
{
//������ NFCMD�Ĵ��� = cmd��ֵ
s5p_nand_regs->nfcmmd = cmd;
}
else
{
//����ַ NFADDR�Ĵ���=cmd��ֵ
s5p_nand_regs->nfaddr = cmd;


}


}


static  int gh_dev_ready(struct mtd_info *mtd)
{
return (s5p_nand_regs->nfstat & (1<<0));
}


static int nand_init(void)
{
struct clk *nand_clk;
/*1.����һ��nand_chip�ṹ��*/
nand = kzalloc(sizeof(struct nand_chip), GFP_KERNEL);
/*2.����*/
s5p_nand_regs = ioremap(0xb0e00000,sizeof(struct s5p_nand_regs));
//����nand_chip�Ǹ�nand_scan_ident�����õģ������֪����ô���ã��ȿ�nand_scan_ident��ôʹ��*/
//��Ӧ���ṩ���������ַ�������ݣ������ݣ��ж�״̬�Ĺ���
nand->select_chip = gh_select_chip; 
nand->cmd_ctrl =gh_cmd_ctrl;
nand->dev_ready = gh_dev_ready;
nand->IO_ADDR_R = &s5p_nand_regs->nfdata;
nand->IO_ADDR_W = &s5p_nand_regs->nfdata;
nand->ecc.mode      = NAND_ECC_SOFT;
/*Ӳ����صĲ���*/


/*3.Ӳ�����*/
/*ʹ��ʱ��*/
nand_clk = clk_get(NULL, "nand");
clk_enable(nand_clk);






/*����ʱ��*/
//hclk��166.75Mhz,����16.675ns
#define TWRPH1    1
#define TWRPH0    1
#define TACLS     1
s5p_nand_regs->nfconf |= (TACLS<<12) | (TWRPH0<<8) | (TWRPH1<<4);


/*
* AddrCycle[1]:1 = ���͵�ַ��Ҫ5������
*/
s5p_nand_regs->nfconf |= 1<<1;
/*
* MODE[0]:1     = ʹ��Nand Flash������
* Reg_nCE0[1]:1 = ȡ��Ƭѡ
*/
s5p_nand_regs->nfcont |= (1<<1)|(1<<0);


/*3.ʹ��*/
nand_mtd=kzalloc(sizeof(struct mtd_info),GFP_KERNEL);


//��mtd_info��nandchip����ϵ����


nand_mtd->owner = THIS_MODULE;
nand_mtd->priv = nand;





nand_scan(nand_mtd, 1);
/*4.��ӷ���*/
add_mtd_partitions(nand_mtd,s5p_partition_info,5);
return 0;
}


static void nand_exit(void)
{
del_mtd_partitions(nand_mtd);
kfree(nand);
iounmap(s5p_nand_regs);
kfree(nand_mtd);
}


module_init(nand_init);
module_exit(nand_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("EIGHT");
