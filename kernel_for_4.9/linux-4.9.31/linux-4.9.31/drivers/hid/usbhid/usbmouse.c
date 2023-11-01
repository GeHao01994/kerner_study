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
	//����豸�����ƣ������������ҡ���Ʒ���͡���Ʒ����Ϣ
	char name[128];
	//�豸�ڵ�����
	char phys[64];
	//���:����豸�ṹ��
	struct usb_device *usbdev;
	//���ͬʱ����һ�������豸����Ҫ��Ƕһ�������豸�ṹ��������������
	struct input_dev *dev;
	//URB������ṹ�壬���ڴ�������
	struct urb *irq;
	//��ͨ�����õĵ�ַ
	signed char *data;
	//DMA�����õĵ�ַ
	dma_addr_t data_dma;
};
//urn�ص�����������ȫ�ύurb��urb�ص������ᱻ����
//�˺�����Ϊ usb_fill_int_urb �������βΣ�Ϊ������ urb �ƶ��Ļص�����
static void usb_mouse_irq(struct urb *urb)
{
///* urb �е� context ָ������Ϊ USB �������򱣴�һЩ���ݡ�
//����������ص��������β�û�д����� probe��Ϊ mouse �ṹ�������ǿ��ڴ�ĵ�ַָ�룬
//������Ҫ�õ��ǿ��ڴ������е����ݣ�context ָ������˴�æ�ˣ�
//����� urb ʱ�� context ָ��ָ�� mouse �ṹ����������
//�����ִ���һ���ֲ� mouse ָ��ָ���� probe������Ϊ mouse ������ǿ��ڴ棬
//�ǿ��ڴ汣���ŷǳ���Ҫ���ݡ��� urb ͨ�� USB core �ύ�� hc ֮��
//������������mouse->data ָ����ڴ����򽫱��������İ������ƶ�������Ϣ��
//ϵͳ��������Щ��Ϣ��������Ϊ������Ӧ��mouse ����Ƕ�� dev ָ�룬ָ�� input_dev �����ڵ��ڴ�����*/ 
	struct usb_mouse *mouse = urb->context;
	signed char *data = mouse->data;
	struct input_dev *dev = mouse->dev;
	int status;
/*
* status ֵΪ 0 ��ʾ urb �ɹ����أ�ֱ������ѭ��������¼������������ϵͳ�� 
* ECONNRESET ������Ϣ��ʾ urb �� usb_unlink_urb ������ unlink �ˣ�ENOENT ������Ϣ��ʾ urb ��  
* usb_kill_urb ������ kill �ˡ�usb_kill_urb ��ʾ���׽��� urb ���������ڣ��� usb_unlink_urb �� 
* ��ֹͣ urb������������� urb ��ȫ��ֹ�ͻ᷵�ظ��ص����������������жϴ������ʱ���ߵȴ�ĳ������ 
* ʱ�ǳ����ã���������������ǲ���˯�ߵģ����ȴ�һ�� urb ��ȫֹͣ�ܿ��ܻ����˯�ߵ������ 
* ESHUTDOWN ���ִ����ʾ USB �����������������������صĴ��󣬻����ύ�� urb ��һ˲���豸���γ��� 
* ���������������ִ�������Ĵ��󣬽������ش� urb�� 
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
//�ϱ��������¼�
//* data ����ĵ�0���ֽڣ�bit 0��1��2��3��4�ֱ�������ҡ��С�SIDE��EXTRA���İ������
	input_report_key(dev, BTN_LEFT,   data[0] & 0x01);
	input_report_key(dev, BTN_RIGHT,  data[0] & 0x02);
	input_report_key(dev, BTN_MIDDLE, data[0] & 0x04);
	input_report_key(dev, BTN_SIDE,   data[0] & 0x08);
	input_report_key(dev, BTN_EXTRA,  data[0] & 0x10);
//�������λ���¼�
/* data ����ĵ�1���ֽڣ���ʾ����ˮƽλ�ƣ� 
* data ����ĵ�2���ֽڣ���ʾ���Ĵ�ֱλ�ƣ� 
* data ����ĵ�3���ֽڣ�REL_WHEELλ��*/

	input_report_rel(dev, REL_X,     data[1]);
	input_report_rel(dev, REL_Y,     data[2]);
	input_report_rel(dev, REL_WHEEL, data[3]);
/* �����������¼�ͬ�������漸����һ������������¼�������������Ϣ������������Ϣ�͹�����Ϣ��
������ϵͳ����ͨ�����ͬ���ź����ڶ�������¼�����������ÿһ�������¼����档ʾ�����£� 
������Ϣ����λ����Ϣ������Ϣ EV_SYC | ������Ϣ����λ����Ϣ������Ϣ EV_SYC ... 
*/ 
	input_sync(dev);
/* ϵͳ��Ҫ�����Բ��ϵػ�ȡ�����¼���Ϣ��
 ����� urb �ص�������ĩβ�ٴ��ύ urb ����飬�����ֻ�����µĻص��������ܶ���ʼ�� 
 �ڻص��������ύ urb һ��ֻ���� GFP_ATOMIC ���ȼ��ģ���Ϊ urb �ص������������ж��������У�
 ���ύ urb �����п��ܻ���Ҫ�����ڴ桢�����ź�������Щ��������ᵼ�� USB core ˯�ߣ�һ�е���˯�ߵ���Ϊ���ǲ�����ġ� 
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
 * ������豸ʱ����ʼ�ύ�� probe �����й����� urb������ urb ���ڡ� 
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
 * �ر�����豸ʱ������ urb �������ڡ� 
 */
 static void usb_mouse_close(struct input_dev *dev)
{
	struct usb_mouse *mouse = input_get_drvdata(dev);

	usb_kill_urb(mouse->irq);
}
/* 
 * ���������̽�⺯�� 
 */

static int usb_mouse_probe(struct usb_interface *intf, const struct usb_device_id *id)
{
/*  
* �ӿڽṹ��������豸�ṹ���У�interface_to_usbdev ��ͨ���ӿڽṹ���������豸�ṹ�塣 
* usb_host_interface �����������ӿ����õĽṹ�壬��Ƕ�ڽӿڽṹ�� usb_interface �С� 
 * usb_endpoint_descriptor �Ƕ˵��������ṹ�壬��Ƕ�ڶ˵�ṹ�� usb_host_endpoint �У����˵� 
 * �ṹ����Ƕ�ڽӿ����ýṹ���С� 
 */
	struct usb_device *dev = interface_to_usbdev(intf);
	struct usb_host_interface *interface;
//����USB�˵�������
	struct usb_endpoint_descriptor *endpoint;
//USB���ṹ��ָ��
	struct usb_mouse *mouse;
//����һ�������豸
	struct input_dev *input_dev;
	int pipe, maxp;
	int error = -ENOMEM;
//��ȡ��ǰ����ʹ�õ�����
	interface = intf->cur_altsetting;
//����HID�淶:���ֻ����һ���˵�(�˵�0���ڿ��Ƴ���)����������˵�һ��Ҫ���ж�����˵�
//�����ж϶˵������
	if (interface->desc.bNumEndpoints != 1)
		return -ENODEV;
//��ȡ�˵�������
	endpoint = &interface->endpoint[0].desc;
//�ж��Ƿ����ж�����˵�
	if (!usb_endpoint_is_int_in(endpoint))
		return -ENODEV;
/* 
* ���ض�Ӧ�˵��ܹ�������������ݰ������ķ��ص�������ݰ�Ϊ4���ֽڣ����ݰ����������� urb 
* �ص�����������ϸ˵���� 
*/
	pipe = usb_rcvintpipe(dev, endpoint->bEndpointAddress);
	maxp = usb_maxpacket(dev, pipe, usb_pipeout(pipe));
/* Ϊ mouse �豸�ṹ������ڴ� */
	mouse = kzalloc(sizeof(struct usb_mouse), GFP_KERNEL);
	input_dev = input_allocate_device();
	if (!mouse || !input_dev)
		goto fail1;
/* �����ڴ�ռ��������ݴ��䣬data Ϊָ��ÿռ�ĵ�ַ��
data_dma ��������ڴ�ռ�� dma ӳ�䣬������ڴ�ռ��Ӧ�� dma ��ַ��
��ʹ�� dma ���������£���ʹ�� data_dma ָ��� dma ���򣬷���ʹ�� data ָ�����ͨ�ڴ�������д��䡣 
GFP_ATOMIC��ʾ���ȴ���GFP_KERNEL ����ͨ�����ȼ�������˯�ߵȴ���
�������ʹ���жϴ��䷽ʽ��������˯��״̬��
data���������Ի�ȡ����¼��Ĵ洢�������ʹ�� GFP_ATOMIC ���ȼ���������ܷ��䵽�ڴ����������� 0�� 
*/ 
	mouse->data = usb_alloc_coherent(dev, 8, GFP_ATOMIC, &mouse->data_dma);
	if (!mouse->data)
		goto fail1;
/* Ϊ urb �ṹ�������ڴ�ռ䣬
��һ��������ʾ��ʱ����ʱ��Ҫ���Ͱ���������
�������䷽ʽ��Ϊ0��������ڴ潫ͨ�����漴�������� usb_fill_int_urb ����������䡣  
      */ 
	mouse->irq = usb_alloc_urb(0, GFP_KERNEL);
	if (!mouse->irq)
		goto fail2;
/* ��� usb �豸�ṹ��������豸�ṹ�� */
	mouse->usbdev = dev;
	mouse->dev = input_dev;
/* ��ȡ����豸������ */
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
 * �������豸�ṹ���еĽڵ�����usb_make_path ������ȡ USB �豸�� Sysfs �е�·������ʽ 
 * Ϊ��usb-usb ���ߺ�-·������ 
 */
	usb_make_path(dev, mouse->phys, sizeof(mouse->phys));
	strlcat(mouse->phys, "/input0", sizeof(mouse->phys));
/* ������豸�����Ƹ�������豸��Ƕ��������ϵͳ�ṹ�� */
	input_dev->name = mouse->name;
/* ������豸���豸�ڵ�����������豸��Ƕ��������ϵͳ�ṹ�� */
	input_dev->phys = mouse->phys;
/* input_dev �е� input_id �ṹ�壬�����洢���̡��豸���ͺ��豸�ı�ţ�
��������ǽ��豸�������еı�Ÿ�����Ƕ��������ϵͳ�ṹ�� 
*/
	usb_to_input_id(dev, &input_dev->id);
 /*�豸�������class device�� */
	input_dev->dev.parent = &intf->dev;
/* evbit ���������¼���EV_KEY �ǰ����¼���EV_REL ����������¼� */
	input_dev->evbit[0] = BIT_MASK(EV_KEY) | BIT_MASK(EV_REL);
/* keybit ��ʾ��ֵ������������Ҽ����м� */
	input_dev->keybit[BIT_WORD(BTN_MOUSE)] = BIT_MASK(BTN_LEFT) |
		BIT_MASK(BTN_RIGHT) | BIT_MASK(BTN_MIDDLE);
/* relbit ���ڱ�ʾ�������ֵ */ 
	input_dev->relbit[0] = BIT_MASK(REL_X) | BIT_MASK(REL_Y);
/* �е���껹���������� */
	input_dev->keybit[BIT_WORD(BTN_MOUSE)] |= BIT_MASK(BTN_SIDE) |
		BIT_MASK(BTN_EXTRA);
/* �м����ֵĹ���ֵ */ 
	input_dev->relbit[0] |= BIT_MASK(REL_WHEEL);
/* input_dev �� private ���������ڱ�ʾ��ǰ�����豸�����࣬���ｫ���ṹ����󸳸��� */
	input_set_drvdata(input_dev, mouse);

	input_dev->open = usb_mouse_open;
	input_dev->close = usb_mouse_close;
/* ��乹�� urb�����ղ����õ� mouse �ṹ����������� urb �ṹ���У�
�� open �еݽ� urb���� urb ����һ����������� DMA ������ʱӦ������ URB_NO_TRANSFER_DMA_MAP��
USB����ʹ��transfer_dma������ָ��Ļ�������������transfer_buffer������ָ��ġ�
URB_NO_SETUP_DMA_MAP ���� Setup ����URB_NO_TRANSFER_DMA_MAP �������� Data ���� 
     */ 
	usb_fill_int_urb(mouse->irq, dev, pipe, mouse->data,
			 (maxp > 8 ? 8 : maxp),
			 usb_mouse_irq, mouse, endpoint->bInterval);
	mouse->irq->transfer_dma = mouse->data_dma;
	mouse->irq->transfer_flags |= URB_NO_TRANSFER_DMA_MAP;
/* ��ϵͳע�������豸 */ 
	error = input_register_device(mouse->dev);
	if (error)
		goto fail3;
/*  һ���� probe �����У�����Ҫ���豸�����Ϣ������һ�� usb_interface �ṹ���У�
�Ա��Ժ�ͨ��usb_get_intfdata ��ȡʹ�á�
��������豸�ṹ����Ϣ�������� intf �ӿڽṹ����Ƕ���豸�ṹ���е� driver_data ���ݳ�Ա�У�
�� intf->dev->dirver_data = mouse�� 
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
 * ����豸�γ�ʱ�Ĵ����� 
 */
static void usb_mouse_disconnect(struct usb_interface *intf)
{
/* ��ȡ����豸�ṹ�� */ 
	struct usb_mouse *mouse = usb_get_intfdata (intf);
/* intf->dev->dirver_data = NULL�����ӿڽṹ���е�����豸ָ���ÿա�*/
	usb_set_intfdata(intf, NULL);
	if (mouse) {
		 /* ���� urb �������� */
		usb_kill_urb(mouse->irq);
		  /* ������豸��������ϵͳ��ע�� */
		input_unregister_device(mouse->dev);
		    /* �ͷ� urb �洢�ռ� */
		usb_free_urb(mouse->irq);
		usb_free_coherent(interface_to_usbdev(intf), 8, mouse->data, mouse->data_dma);
		/* �ͷŴ�����ṹ��Ĵ洢�ռ� */ 
		kfree(mouse);
	}
}
/* 
 * usb_device_id �ṹ�����ڱ�ʾ������������֧�ֵ��豸��
 USB_INTERFACE_INFO ��������ƥ���ض����͵Ľӿڣ������Ĳ�����˼Ϊ (���, �����, Э��)��
 USB_INTERFACE_CLASS_HID ��ʾ��һ�� HID (Human Interface Device)�����˻������豸���
 USB_INTERFACE_SUBCLASS_BOOT ������𣬱�ʾ��һ�� boot �׶�ʹ�õ� HID�� 
 USB_INTERFACE_PROTOCOL_MOUSE ��ʾ������豸����ѭ����Э�顣 
 */
static struct usb_device_id usb_mouse_id_table [] = {
//�豸���������˻��������豸����������һ��boot�豸����ѭ���Э�飬��ô��֧��
	{ USB_INTERFACE_INFO(USB_INTERFACE_CLASS_HID, USB_INTERFACE_SUBCLASS_BOOT,
		USB_INTERFACE_PROTOCOL_MOUSE) },
	{ }	/* Terminating entry */
};

MODULE_DEVICE_TABLE (usb, usb_mouse_id_table);

static struct usb_driver usb_mouse_driver = {
	//����������
	.name		= "usbmouse",
	 //ƥ��ɹ�����õĺ���
	.probe		= usb_mouse_probe,
	//�Ƴ��豸ʱ���õĺ���
	.disconnect	= usb_mouse_disconnect,
	//����֧�ֵ��豸�б�
	.id_table	= usb_mouse_id_table,
};

module_usb_driver(usb_mouse_driver);
