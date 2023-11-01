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
	//�豸��ħ�����̶�Ϊ0xd00dfeed  
	__be32	magic;			/* magic word OF_DT_HEADER */ 
	//�����豸���Ĵ�С  
	__be32	totalsize;		/* total size of DT block */
	//����ṹ���������豸���е�ƫ��
	__be32	off_dt_struct;		/* offset to structure */
	//������ַ��������豸���е�ƫ��
	__be32	off_dt_strings;		/* offset to strings */
	 //�����ڴ��������������˲��ܱ��ں˶�̬������ڴ�ռ� 
	__be32	off_mem_rsvmap;		/* offset to memory reserve map */
	 //�豸���汾 
	__be32	version;		/* format version */
	 //���¼��ݰ汾��
	__be32	last_comp_version;	/* last compatible version */
	/* version 2 fields below */
	//Ϊ�ڶ�˴�������������������cpu������id
	__be32	boot_cpuid_phys;	/* Physical CPU id we're booting on */
	/* version 3 fields below */
	//�ַ������С
	__be32	dt_strings_size;	/* size of the DT strings block */
	//�ṹ���С
	/* version 17 fields below */
	__be32	dt_struct_size;		/* size of the DT structure block */
};
/*�ṹ��
1.2 �ṹ�飨struct block��
 �豸���ṹ����һ�����Ի��Ľṹ�壬���豸�������壬�Խڵ�node����ʽ������Ŀ�굥���ϵ��豸��Ϣ��
 �ڽṹ�����Ժ�OF_DT_BEGIN_NODE��־һ���ڵ�Ŀ�ʼ���Ժ�OF_DT_END_NODE��ʶһ���ڵ�Ľ����������ṹ���Ժ�OF_DT_END������һ���ڵ���Ҫ�����¼�������ɡ�
(1)�ڵ㿪ʼ��־��һ��ΪOF_DT_BEGIN_NODE��
(2)�ڵ�·�����߽ڵ�ĵ�Ԫ��(ersion<3�Խڵ�·����ʾ��version>=0x10�Խڵ㵥Ԫ����ʾ)
(3)����ֶΣ����뵽���ֽڣ�
(4)�ڵ����ԡ�ÿ�������Ժ�OF_DT_PROP��ʼ����������Ϊ����ֵ���ֽڳ���(4�ֽ�)�������������ַ������е�ƫ����(4�ֽ�)������ֵ����䣨���뵽���ֽڣ���
(5)��������ӽڵ㣬�����ӽڵ㡣
(6)�ڵ������־OF_DT_END_NODE��
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
