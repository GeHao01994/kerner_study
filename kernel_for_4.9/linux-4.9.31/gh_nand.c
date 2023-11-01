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
//取消选中 将NFCONT[1] 设置为1
s5p_nand_regs->nfcont |=(1<<1);
}
else
{
//选中 NFCONT【1】设置为0
s5p_nand_regs->nfcont &= ~(1<<1);


}


}


static void gh_cmd_ctrl(struct mtd_info *mtd, int cmd, unsigned int ctrl)
{


if (ctrl & NAND_CLE)
{
//发命令 NFCMD寄存器 = cmd的值
s5p_nand_regs->nfcmmd = cmd;
}
else
{
//发地址 NFADDR寄存器=cmd的值
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
/*1.分配一个nand_chip结构体*/
nand = kzalloc(sizeof(struct nand_chip), GFP_KERNEL);
/*2.设置*/
s5p_nand_regs = ioremap(0xb0e00000,sizeof(struct s5p_nand_regs));
//设置nand_chip是给nand_scan_ident函数用的，如果不知道怎么设置，先看nand_scan_ident怎么使用*/
//它应该提供发命令，发地址，发数据，读数据，判断状态的功能
nand->select_chip = gh_select_chip; 
nand->cmd_ctrl =gh_cmd_ctrl;
nand->dev_ready = gh_dev_ready;
nand->IO_ADDR_R = &s5p_nand_regs->nfdata;
nand->IO_ADDR_W = &s5p_nand_regs->nfdata;
nand->ecc.mode      = NAND_ECC_SOFT;
/*硬件相关的操作*/


/*3.硬件相关*/
/*使能时钟*/
nand_clk = clk_get(NULL, "nand");
clk_enable(nand_clk);






/*设置时钟*/
//hclk是166.75Mhz,就是16.675ns
#define TWRPH1    1
#define TWRPH0    1
#define TACLS     1
s5p_nand_regs->nfconf |= (TACLS<<12) | (TWRPH0<<8) | (TWRPH1<<4);


/*
* AddrCycle[1]:1 = 发送地址需要5个周期
*/
s5p_nand_regs->nfconf |= 1<<1;
/*
* MODE[0]:1     = 使能Nand Flash控制器
* Reg_nCE0[1]:1 = 取消片选
*/
s5p_nand_regs->nfcont |= (1<<1)|(1<<0);


/*3.使用*/
nand_mtd=kzalloc(sizeof(struct mtd_info),GFP_KERNEL);


//将mtd_info与nandchip相联系起来


nand_mtd->owner = THIS_MODULE;
nand_mtd->priv = nand;





nand_scan(nand_mtd, 1);
/*4.添加分区*/
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
