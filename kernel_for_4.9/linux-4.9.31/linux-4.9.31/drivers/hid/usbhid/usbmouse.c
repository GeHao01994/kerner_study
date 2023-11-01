/*
 *  Copyright (c) 1999-2001 Vojtech Pavlik
 *
 *  USB HIDBP Mouse support
 */

/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 * Should you need to contact me, the author, you can do so either by
 * e-mail - mail your message to <vojtech@ucw.cz>, or by paper mail:
 * Vojtech Pavlik, Simunkova 1594, Prague 8, 182 00 Czech Republic
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/usb/input.h>
#include <linux/hid.h>

/* for apple IDs */
#ifdef CONFIG_USB_HID_MODULE
#include "../hid-ids.h"
#endif

/*
 * Version Information
 */
#define DRIVER_VERSION "v1.6"
#define DRIVER_AUTHOR "Vojtech Pavlik <vojtech@ucw.cz>"
#define DRIVER_DESC "USB HID Boot Protocol mouse driver"
#define DRIVER_LICENSE "GPL"

MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_LICENSE(DRIVER_LICENSE);

struct usb_mouse {
	//鼠标设备的名称，包括生产厂家、产品类型、产品等信息
	char name[128];
	//设备节点名称
	char phys[64];
	//鼠标:鼠标设备结构体
	struct usb_device *usbdev;
	//鼠标同时又是一种输入设备，需要内嵌一个输入设备结构体来描述其属性
	struct input_dev *dev;
	//URB请求包结构体，用于传输数据
	struct urb *irq;
	//普通传输用的地址
	signed char *data;
	//DMA传输用的地址
	dma_addr_t data_dma;
};
//urn回调函数，在完全提交urb后，urb回调函数会被调用
//此函数作为 usb_fill_int_urb 函数的形参，为构建的 urb 制定的回调函数
static void usb_mouse_irq(struct urb *urb)
{
///* urb 中的 context 指针用于为 USB 驱动程序保存一些数据。
//比如在这个回调函数的形参没有传递在 probe中为 mouse 结构体分配的那块内存的地址指针，
//而又需要用到那块内存区域中的数据，context 指针则帮了大忙了！
//在填充 urb 时将 context 指针指向 mouse 结构体数据区，
//在这又创建一个局部 mouse 指针指向在 probe函数中为 mouse 申请的那块内存，
//那块内存保存着非常重要数据。当 urb 通过 USB core 提交给 hc 之后，
//如果结果正常，mouse->data 指向的内存区域将保存着鼠标的按键和移动坐标信息，
//系统则依靠这些信息对鼠标的行为作出反应。mouse 中内嵌的 dev 指针，指向 input_dev 所属于的内存区域*/ 
	struct usb_mouse *mouse = urb->context;
	signed char *data = mouse->data;
	struct input_dev *dev = mouse->dev;
	int status;
/*
* status 值为 0 表示 urb 成功返回，直接跳出循环把鼠标事件报告给输入子系统。 
* ECONNRESET 出错信息表示 urb 被 usb_unlink_urb 函数给 unlink 了，ENOENT 出错信息表示 urb 被  
* usb_kill_urb 函数给 kill 了。usb_kill_urb 表示彻底结束 urb 的生命周期，而 usb_unlink_urb 则 
* 是停止 urb，这个函数不等 urb 完全终止就会返回给回调函数。这在运行中断处理程序时或者等待某自旋锁 
* 时非常有用，在这两种情况下是不能睡眠的，而等待一个 urb 完全停止很可能会出现睡眠的情况。 
* ESHUTDOWN 这种错误表示 USB 主控制器驱动程序发生了严重的错误，或者提交完 urb 的一瞬间设备被拔出。 
* 遇见除了以上三种错误以外的错误，将申请重传 urb。 
*/ 
	switch (urb->status) {
	case 0:			/* success */
		break;
	case -ECONNRESET:	/* unlink */
	case -ENOENT:
	case -ESHUTDOWN:
		return;
	/* -EPIPE:  should clear the halt */
	default:		/* error */
		goto resubmit;
	}
//上报按键类事件
//* data 数组的第0个字节：bit 0、1、2、3、4分别代表左、右、中、SIDE、EXTRA键的按下情况
	input_report_key(dev, BTN_LEFT,   data[0] & 0x01);
	input_report_key(dev, BTN_RIGHT,  data[0] & 0x02);
	input_report_key(dev, BTN_MIDDLE, data[0] & 0x04);
	input_report_key(dev, BTN_SIDE,   data[0] & 0x08);
	input_report_key(dev, BTN_EXTRA,  data[0] & 0x10);
//报告相对位移事件
/* data 数组的第1个字节：表示鼠标的水平位移； 
* data 数组的第2个字节：表示鼠标的垂直位移； 
* data 数组的第3个字节：REL_WHEEL位移*/

	input_report_rel(dev, REL_X,     data[1]);
	input_report_rel(dev, REL_Y,     data[2]);
	input_report_rel(dev, REL_WHEEL, data[3]);
/* 这里是用于事件同步。上面几行是一次完整的鼠标事件，包括按键信息、绝对坐标信息和滚轮信息，
输入子系统正是通过这个同步信号来在多个完整事件报告中区分每一次完整事件报告。示意如下： 
按键信息坐标位移信息滚轮信息 EV_SYC | 按键信息坐标位移信息滚轮信息 EV_SYC ... 
*/ 
	input_sync(dev);
/* 系统需要周期性不断地获取鼠标的事件信息，
 因此在 urb 回调函数的末尾再次提交 urb 请求块，这样又会调用新的回调函数，周而复始。 
 在回调函数中提交 urb 一定只能是 GFP_ATOMIC 优先级的，因为 urb 回调函数运行于中断上下文中，
 在提交 urb 过程中可能会需要申请内存、保持信号量，这些操作或许会导致 USB core 睡眠，一切导致睡眠的行为都是不允许的。 
 */ 
resubmit:
	status = usb_submit_urb (urb, GFP_ATOMIC);
	if (status)
		dev_err(&mouse->usbdev->dev,
			"can't resubmit intr, %s-%s/input0, status %d\n",
			mouse->usbdev->bus->bus_name,
			mouse->usbdev->devpath, status);
}
/* 
 * 打开鼠标设备时，开始提交在 probe 函数中构建的 urb，进入 urb 周期。 
 */
static int usb_mouse_open(struct input_dev *dev)
{
	struct usb_mouse *mouse = input_get_drvdata(dev);

	mouse->irq->dev = mouse->usbdev;
	if (usb_submit_urb(mouse->irq, GFP_KERNEL))
		return -EIO;

	return 0;
}
/* 
 * 关闭鼠标设备时，结束 urb 生命周期。 
 */
 static void usb_mouse_close(struct input_dev *dev)
{
	struct usb_mouse *mouse = input_get_drvdata(dev);

	usb_kill_urb(mouse->irq);
}
/* 
 * 驱动程序的探测函数 
 */

static int usb_mouse_probe(struct usb_interface *intf, const struct usb_device_id *id)
{
/*  
* 接口结构体包含于设备结构体中，interface_to_usbdev 是通过接口结构体获得它的设备结构体。 
* usb_host_interface 是用于描述接口设置的结构体，内嵌在接口结构体 usb_interface 中。 
 * usb_endpoint_descriptor 是端点描述符结构体，内嵌在端点结构体 usb_host_endpoint 中，而端点 
 * 结构体内嵌在接口设置结构体中。 
 */
	struct usb_device *dev = interface_to_usbdev(intf);
	struct usb_host_interface *interface;
//定义USB端点描述符
	struct usb_endpoint_descriptor *endpoint;
//USB鼠标结构体指针
	struct usb_mouse *mouse;
//代表一个输入设备
	struct input_dev *input_dev;
	int pipe, maxp;
	int error = -ENOMEM;
//获取当前正在使用的设置
	interface = intf->cur_altsetting;
//根据HID规范:鼠标只能有一个端点(端点0用于控制除外)，而且这个端点一定要是中断输入端点
//这里判断端点的数量
	if (interface->desc.bNumEndpoints != 1)
		return -ENODEV;
//获取端点描述符
	endpoint = &interface->endpoint[0].desc;
//判断是否是中断输入端点
	if (!usb_endpoint_is_int_in(endpoint))
		return -ENODEV;
/* 
* 返回对应端点能够传输的最大的数据包，鼠标的返回的最大数据包为4个字节，数据包具体内容在 urb 
* 回调函数中有详细说明。 
*/
	pipe = usb_rcvintpipe(dev, endpoint->bEndpointAddress);
	maxp = usb_maxpacket(dev, pipe, usb_pipeout(pipe));
/* 为 mouse 设备结构体分配内存 */
	mouse = kzalloc(sizeof(struct usb_mouse), GFP_KERNEL);
	input_dev = input_allocate_device();
	if (!mouse || !input_dev)
		goto fail1;
/* 申请内存空间用于数据传输，data 为指向该空间的地址，
data_dma 则是这块内存空间的 dma 映射，即这块内存空间对应的 dma 地址。
在使用 dma 传输的情况下，则使用 data_dma 指向的 dma 区域，否则使用 data 指向的普通内存区域进行传输。 
GFP_ATOMIC表示不等待，GFP_KERNEL 是普通的优先级，可以睡眠等待，
由于鼠标使用中断传输方式，不允许睡眠状态，
data又是周期性获取鼠标事件的存储区，因此使用 GFP_ATOMIC 优先级，如果不能分配到内存则立即返回 0。 
*/ 
	mouse->data = usb_alloc_coherent(dev, 8, GFP_ATOMIC, &mouse->data_dma);
	if (!mouse->data)
		goto fail1;
/* 为 urb 结构体申请内存空间，
第一个参数表示等时传输时需要传送包的数量，
其它传输方式则为0。申请的内存将通过下面即将见到的 usb_fill_int_urb 函数进行填充。  
      */ 
	mouse->irq = usb_alloc_urb(0, GFP_KERNEL);
	if (!mouse->irq)
		goto fail2;
/* 填充 usb 设备结构体和输入设备结构体 */
	mouse->usbdev = dev;
	mouse->dev = input_dev;
/* 获取鼠标设备的名称 */
	if (dev->manufacturer)
		strlcpy(mouse->name, dev->manufacturer, sizeof(mouse->name));

	if (dev->product) {
		if (dev->manufacturer)
			strlcat(mouse->name, " ", sizeof(mouse->name));
		strlcat(mouse->name, dev->product, sizeof(mouse->name));
	}

	if (!strlen(mouse->name))
		snprintf(mouse->name, sizeof(mouse->name),
			 "USB HIDBP Mouse %04x:%04x",
			 le16_to_cpu(dev->descriptor.idVendor),
			 le16_to_cpu(dev->descriptor.idProduct));
 /* 
 * 填充鼠标设备结构体中的节点名。usb_make_path 用来获取 USB 设备在 Sysfs 中的路径，格式 
 * 为：usb-usb 总线号-路径名。 
 */
	usb_make_path(dev, mouse->phys, sizeof(mouse->phys));
	strlcat(mouse->phys, "/input0", sizeof(mouse->phys));
/* 将鼠标设备的名称赋给鼠标设备内嵌的输入子系统结构体 */
	input_dev->name = mouse->name;
/* 将鼠标设备的设备节点名赋给鼠标设备内嵌的输入子系统结构体 */
	input_dev->phys = mouse->phys;
/* input_dev 中的 input_id 结构体，用来存储厂商、设备类型和设备的编号，
这个函数是将设备描述符中的编号赋给内嵌的输入子系统结构体 
*/
	usb_to_input_id(dev, &input_dev->id);
 /*设备所属类别（class device） */
	input_dev->dev.parent = &intf->dev;
/* evbit 用来描述事件，EV_KEY 是按键事件，EV_REL 是相对坐标事件 */
	input_dev->evbit[0] = BIT_MASK(EV_KEY) | BIT_MASK(EV_REL);
/* keybit 表示键值，包括左键、右键和中键 */
	input_dev->keybit[BIT_WORD(BTN_MOUSE)] = BIT_MASK(BTN_LEFT) |
		BIT_MASK(BTN_RIGHT) | BIT_MASK(BTN_MIDDLE);
/* relbit 用于表示相对坐标值 */ 
	input_dev->relbit[0] = BIT_MASK(REL_X) | BIT_MASK(REL_Y);
/* 有的鼠标还有其它按键 */
	input_dev->keybit[BIT_WORD(BTN_MOUSE)] |= BIT_MASK(BTN_SIDE) |
		BIT_MASK(BTN_EXTRA);
/* 中键滚轮的滚动值 */ 
	input_dev->relbit[0] |= BIT_MASK(REL_WHEEL);
/* input_dev 的 private 数据项用于表示当前输入设备的种类，这里将鼠标结构体对象赋给它 */
	input_set_drvdata(input_dev, mouse);

	input_dev->open = usb_mouse_open;
	input_dev->close = usb_mouse_close;
/* 填充构建 urb，将刚才填充好的 mouse 结构体的数据填充进 urb 结构体中，
在 open 中递交 urb。当 urb 包含一个即将传输的 DMA 缓冲区时应该设置 URB_NO_TRANSFER_DMA_MAP。
USB核心使用transfer_dma变量所指向的缓冲区，而不是transfer_buffer变量所指向的。
URB_NO_SETUP_DMA_MAP 用于 Setup 包，URB_NO_TRANSFER_DMA_MAP 用于所有 Data 包。 
     */ 
	usb_fill_int_urb(mouse->irq, dev, pipe, mouse->data,
			 (maxp > 8 ? 8 : maxp),
			 usb_mouse_irq, mouse, endpoint->bInterval);
	mouse->irq->transfer_dma = mouse->data_dma;
	mouse->irq->transfer_flags |= URB_NO_TRANSFER_DMA_MAP;
/* 向系统注册输入设备 */ 
	error = input_register_device(mouse->dev);
	if (error)
		goto fail3;
/*  一般在 probe 函数中，都需要将设备相关信息保存在一个 usb_interface 结构体中，
以便以后通过usb_get_intfdata 获取使用。
这里鼠标设备结构体信息将保存在 intf 接口结构体内嵌的设备结构体中的 driver_data 数据成员中，
即 intf->dev->dirver_data = mouse。 
      */
	usb_set_intfdata(intf, mouse);
	return 0;

fail3:	
	usb_free_urb(mouse->irq);
fail2:	
	usb_free_coherent(dev, 8, mouse->data, mouse->data_dma);
fail1:	
	input_free_device(input_dev);
	kfree(mouse);
	return error;
}
/* 
 * 鼠标设备拔出时的处理函数 
 */
static void usb_mouse_disconnect(struct usb_interface *intf)
{
/* 获取鼠标设备结构体 */ 
	struct usb_mouse *mouse = usb_get_intfdata (intf);
/* intf->dev->dirver_data = NULL，将接口结构体中的鼠标设备指针置空。*/
	usb_set_intfdata(intf, NULL);
	if (mouse) {
		 /* 结束 urb 生命周期 */
		usb_kill_urb(mouse->irq);
		  /* 将鼠标设备从输入子系统中注销 */
		input_unregister_device(mouse->dev);
		    /* 释放 urb 存储空间 */
		usb_free_urb(mouse->irq);
		usb_free_coherent(interface_to_usbdev(intf), 8, mouse->data, mouse->data_dma);
		/* 释放存放鼠标结构体的存储空间 */ 
		kfree(mouse);
	}
}
/* 
 * usb_device_id 结构体用于表示该驱动程序所支持的设备，
 USB_INTERFACE_INFO 可以用来匹配特定类型的接口，这个宏的参数意思为 (类别, 子类别, 协议)。
 USB_INTERFACE_CLASS_HID 表示是一种 HID (Human Interface Device)，即人机交互设备类别；
 USB_INTERFACE_SUBCLASS_BOOT 是子类别，表示是一种 boot 阶段使用的 HID； 
 USB_INTERFACE_PROTOCOL_MOUSE 表示是鼠标设备，遵循鼠标的协议。 
 */
static struct usb_device_id usb_mouse_id_table [] = {
//设备的类型是人机交互类设备，子类型是一种boot设备，遵循鼠标协议，那么就支持
	{ USB_INTERFACE_INFO(USB_INTERFACE_CLASS_HID, USB_INTERFACE_SUBCLASS_BOOT,
		USB_INTERFACE_PROTOCOL_MOUSE) },
	{ }	/* Terminating entry */
};

MODULE_DEVICE_TABLE (usb, usb_mouse_id_table);

static struct usb_driver usb_mouse_driver = {
	//驱动的名字
	.name		= "usbmouse",
	 //匹配成功后调用的函数
	.probe		= usb_mouse_probe,
	//移除设备时调用的函数
	.disconnect	= usb_mouse_disconnect,
	//驱动支持的设备列表
	.id_table	= usb_mouse_id_table,
};

module_usb_driver(usb_mouse_driver);
