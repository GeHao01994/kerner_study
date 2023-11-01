#ifndef _POWERPC_PROM_H
#define _POWERPC_PROM_H
#ifdef __KERNEL__

/*
 * Definitions for talking to the Open Firmware PROM on
 * Power Macintosh computers.
 *
 * Copyright (C) 1996-2005 Paul Mackerras.
 *
 * Updates for PPC64 by Peter Bergner & David Engebretsen, IBM Corp.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */
#include <linux/types.h>
#include <asm/irq.h>
#include <linux/atomic.h>

/* These includes should be removed once implicit includes are cleaned up. */
#include <linux/of.h>
#include <linux/of_fdt.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/platform_device.h>

#define OF_DT_BEGIN_NODE	0x1		/* Start of node, full name */
#define OF_DT_END_NODE		0x2		/* End node */
#define OF_DT_PROP		0x3		/* Property: name off, size,
						 * content */
#define OF_DT_NOP		0x4		/* nop */
#define OF_DT_END		0x9

#define OF_DT_VERSION		0x10

/*
 * This is what gets passed to the kernel by prom_init or kexec
 *
 * The dt struct contains the device tree structure, full pathes and
 * property contents. The dt strings contain a separate block with just
 * the strings for the property names, and is fully page aligned and
 * self contained in a page, so that it can be kept around by the kernel,
 * each property name appears only once in this page (cheap compression)
 *
 * the mem_rsvmap contains a map of reserved ranges of physical memory,
 * passing it here instead of in the device-tree itself greatly simplifies
 * the job of everybody. It's just a list of u64 pairs (base/size) that
 * ends when size is 0
 */
struct boot_param_header {
	//设备树魔数，固定为0xd00dfeed  
	__be32	magic;			/* magic word OF_DT_HEADER */ 
	//整个设备树的大小  
	__be32	totalsize;		/* total size of DT block */
	//保存结构块在整个设备树中的偏移
	__be32	off_dt_struct;		/* offset to structure */
	//保存的字符串块在设备树中的偏移
	__be32	off_dt_strings;		/* offset to strings */
	 //保留内存区，该区保留了不能被内核动态分配的内存空间 
	__be32	off_mem_rsvmap;		/* offset to memory reserve map */
	 //设备树版本 
	__be32	version;		/* format version */
	 //向下兼容版本号
	__be32	last_comp_version;	/* last compatible version */
	/* version 2 fields below */
	//为在多核处理器中用于启动的主cpu的物理id
	__be32	boot_cpuid_phys;	/* Physical CPU id we're booting on */
	/* version 3 fields below */
	//字符串块大小
	__be32	dt_strings_size;	/* size of the DT strings block */
	//结构块大小
	/* version 17 fields below */
	__be32	dt_struct_size;		/* size of the DT structure block */
};
/*结构块
1.2 结构块（struct block）
 设备树结构块是一个线性化的结构体，是设备树的主体，以节点node的形式保存了目标单板上的设备信息。
 在结构块中以宏OF_DT_BEGIN_NODE标志一个节点的开始，以宏OF_DT_END_NODE标识一个节点的结束，整个结构块以宏OF_DT_END结束。一个节点主要由以下几部分组成。
(1)节点开始标志：一般为OF_DT_BEGIN_NODE。
(2)节点路径或者节点的单元名(ersion<3以节点路径表示，version>=0x10以节点单元名表示)
(3)填充字段（对齐到四字节）
(4)节点属性。每个属性以宏OF_DT_PROP开始，后面依次为属性值的字节长度(4字节)、属性名称在字符串块中的偏移量(4字节)、属性值和填充（对齐到四字节）。
(5)如果存在子节点，则定义子节点。
(6)节点结束标志OF_DT_END_NODE。
/*
 * OF address retreival & translation
 */

/* Parse the ibm,dma-window property of an OF node into the busno, phys and
 * size parameters.
 */
void of_parse_dma_window(struct device_node *dn, const __be32 *dma_window,
			 unsigned long *busno, unsigned long *phys,
			 unsigned long *size);

extern void of_instantiate_rtc(void);

extern int of_get_ibm_chip_id(struct device_node *np);

/* The of_drconf_cell struct defines the layout of the LMB array
 * specified in the device tree property
 * ibm,dynamic-reconfiguration-memory/ibm,dynamic-memory
 */
struct of_drconf_cell {
	u64	base_addr;
	u32	drc_index;
	u32	reserved;
	u32	aa_index;
	u32	flags;
};

#define DRCONF_MEM_ASSIGNED	0x00000008
#define DRCONF_MEM_AI_INVALID	0x00000040
#define DRCONF_MEM_RESERVED	0x00000080

/*
 * There are two methods for telling firmware what our capabilities are.
 * Newer machines have an "ibm,client-architecture-support" method on the
 * root node.  For older machines, we have to call the "process-elf-header"
 * method in the /packages/elf-loader node, passing it a fake 32-bit
 * ELF header containing a couple of PT_NOTE sections that contain
 * structures that contain various information.
 */

/* New method - extensible architecture description vector. */

/* Option vector bits - generic bits in byte 1 */
#define OV_IGNORE		0x80	/* ignore this vector */
#define OV_CESSATION_POLICY	0x40	/* halt if unsupported option present*/

/* Option vector 1: processor architectures supported */
#define OV1_PPC_2_00		0x80	/* set if we support PowerPC 2.00 */
#define OV1_PPC_2_01		0x40	/* set if we support PowerPC 2.01 */
#define OV1_PPC_2_02		0x20	/* set if we support PowerPC 2.02 */
#define OV1_PPC_2_03		0x10	/* set if we support PowerPC 2.03 */
#define OV1_PPC_2_04		0x08	/* set if we support PowerPC 2.04 */
#define OV1_PPC_2_05		0x04	/* set if we support PowerPC 2.05 */
#define OV1_PPC_2_06		0x02	/* set if we support PowerPC 2.06 */
#define OV1_PPC_2_07		0x01	/* set if we support PowerPC 2.07 */

/* Option vector 2: Open Firmware options supported */
#define OV2_REAL_MODE		0x20	/* set if we want OF in real mode */

/* Option vector 3: processor options supported */
#define OV3_FP			0x80	/* floating point */
#define OV3_VMX			0x40	/* VMX/Altivec */
#define OV3_DFP			0x20	/* decimal FP */

/* Option vector 4: IBM PAPR implementation */
#define OV4_MIN_ENT_CAP		0x01	/* minimum VP entitled capacity */

/* Option vector 5: PAPR/OF options supported
 * These bits are also used in firmware_has_feature() to validate
 * the capabilities reported for vector 5 in the device tree so we
 * encode the vector index in the define and use the OV5_FEAT()
 * and OV5_INDX() macros to extract the desired information.
 */
#define OV5_FEAT(x)	((x) & 0xff)
#define OV5_INDX(x)	((x) >> 8)
#define OV5_LPAR		0x0280	/* logical partitioning supported */
#define OV5_SPLPAR		0x0240	/* shared-processor LPAR supported */
/* ibm,dynamic-reconfiguration-memory property supported */
#define OV5_DRCONF_MEMORY	0x0220
#define OV5_LARGE_PAGES		0x0210	/* large pages supported */
#define OV5_DONATE_DEDICATE_CPU	0x0202	/* donate dedicated CPU support */
#define OV5_MSI			0x0201	/* PCIe/MSI support */
#define OV5_CMO			0x0480	/* Cooperative Memory Overcommitment */
#define OV5_XCMO		0x0440	/* Page Coalescing */
#define OV5_TYPE1_AFFINITY	0x0580	/* Type 1 NUMA affinity */
#define OV5_PRRN		0x0540	/* Platform Resource Reassignment */
#define OV5_PFO_HW_RNG		0x0E80	/* PFO Random Number Generator */
#define OV5_PFO_HW_842		0x0E40	/* PFO Compression Accelerator */
#define OV5_PFO_HW_ENCR		0x0E20	/* PFO Encryption Accelerator */
#define OV5_SUB_PROCESSORS	0x0F01	/* 1,2,or 4 Sub-Processors supported */

/* Option Vector 6: IBM PAPR hints */
#define OV6_LINUX		0x02	/* Linux is our OS */

/*
 * The architecture vector has an array of PVR mask/value pairs,
 * followed by # option vectors - 1, followed by the option vectors.
 */
extern unsigned char ibm_architecture_vec[];

#endif /* __KERNEL__ */
#endif /* _POWERPC_PROM_H */
