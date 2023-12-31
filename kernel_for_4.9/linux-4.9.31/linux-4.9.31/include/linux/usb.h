#ifndef __LINUX_USB_H
#define __LINUX_USB_H

#include <linux/mod_devicetable.h>
#include <linux/usb/ch9.h>
//Linux 为USB设备预留的主设备号,如果USB设备没有其他任何 子系统关联，
//就需要在对应的驱动的probe函数里使用usb_register_dev函数来注册并获得主设备号USB_MAJOR
//例子中usb-skeleton.c文件就是属于这种。如果USB设备关联了其他子系统，则需要在对应驱动的probe函数里使用相应的注册函数
#define USB_MAJOR			180
#define USB_DEVICE_MAJOR		189


#ifdef __KERNEL__

#include <linux/errno.h>        /* for -ENODEV */
#include <linux/delay.h>	/* for mdelay() */
#include <linux/interrupt.h>	/* for in_interrupt() */
#include <linux/list.h>		/* for struct list_head */
#include <linux/kref.h>		/* for struct kref */
#include <linux/device.h>	/* for struct device */
#include <linux/fs.h>		/* for struct file_operations */
#include <linux/completion.h>	/* for struct completion */
#include <linux/sched.h>	/* for current && schedule_timeout */
#include <linux/mutex.h>	/* for struct mutex */
#include <linux/pm_runtime.h>	/* for runtime PM */

struct usb_device;
struct usb_driver;
struct wusb_dev;

/*-------------------------------------------------------------------------*/

/*
 * Host-side wrappers for standard USB descriptors ... these are parsed
 * from the data provided by devices.  Parsing turns them from a flat
 * sequence of descriptors into a hierarchy:
 *
 *  - devices have one (usually) or more configs;
 *  - configs have one (often) or more interfaces;
 *  - interfaces have one (usually) or more settings;
 *  - each interface setting has zero or (usually) more endpoints.
 *  - a SuperSpeed endpoint has a companion descriptor
 *
 * And there might be other descriptors mixed in with those.
 *
 * Devices may also have class-specific or vendor-specific descriptors.
 */

struct ep_device;

/**
 * struct usb_host_endpoint - host-side endpoint descriptor and queue
 * @desc: descriptor for this endpoint, wMaxPacketSize in native byteorder
 * @ss_ep_comp: SuperSpeed companion descriptor for this endpoint
 * @ssp_isoc_ep_comp: SuperSpeedPlus isoc companion descriptor for this endpoint
 * @urb_list: urbs queued to this endpoint; maintained by usbcore
 * @hcpriv: for use by HCD; typically holds hardware dma queue head (QH)
 *	with one or more transfer descriptors (TDs) per urb
 * @ep_dev: ep_device for sysfs info
 * @extra: descriptors following this endpoint in the configuration
 * @extralen: how many bytes of "extra" are valid
 * @enabled: URBs may be submitted to this endpoint
 * @streams: number of USB-3 streams allocated on the endpoint
 *
 * USB requests are always queued to a given endpoint, identified by a
 * descriptor within an active interface in a given USB configuration.
 */
struct usb_host_endpoint {
	//端点描述符
	struct usb_endpoint_descriptor		desc;
	struct usb_ss_ep_comp_descriptor	ss_ep_comp;
	struct usb_ssp_isoc_ep_comp_descriptor	ssp_isoc_ep_comp;
	//端点要处理的urb队列，urb是USB通信的主角，包含执行URB传输所需要的所有信息
	struct list_head		urb_list;
	//这是提供给HCD用的
	void				*hcpriv;
	//这个字段是供sysfs用的
	struct ep_device		*ep_dev;	/* For sysfs info */
	//扩展描述符
	unsigned char *extra;   /* Extra descriptors */
	int extralen;
	int enabled;
	int streams;
};

/* host-side wrapper for one interface setting's parsed descriptors */
struct usb_host_interface {
//因为一个接口可以有多个设置，使用不同的设置，描述接口的信息会有所不同
//所以接口描述符并没有放在struct  usb_interface结构体里面
	struct usb_interface_descriptor	desc;

	int extralen;
	unsigned char *extra;   /* Extra descriptors */

	/* array of desc.bNumEndpoints endpoints associated with this
	 * interface setting.  these will be in no particular order.
	 */
	  //一个数组，标明这个设置所用到的端点
	struct usb_host_endpoint *endpoint;
//用来保存从设备里取出来的字符串描述符信息，可有 可无，这个指针可以空
	char *string;		/* iInterface string, if present */
};

enum usb_interface_condition {
	USB_INTERFACE_UNBOUND = 0,
	USB_INTERFACE_BINDING,
	USB_INTERFACE_BOUND,
	USB_INTERFACE_UNBINDING,
};

/**
 * struct usb_interface - what usb device drivers talk to
 * @altsetting: array of interface structures, one for each alternate
 *	setting that may be selected.  Each one includes a set of
 *	endpoint configurations.  They will be in no particular order.
 * @cur_altsetting: the current altsetting.
 * @num_altsetting: number of altsettings defined.
 * @intf_assoc: interface association descriptor
 * @minor: the minor number assigned to this interface, if this
 *	interface is bound to a driver that uses the USB major number.
 *	If this interface does not use the USB major, this field should
 *	be unused.  The driver should set this value in the probe()
 *	function of the driver, after it has been assigned a minor
 *	number from the USB core by calling usb_register_dev().
 * @condition: binding state of the interface: not bound, binding
 *	(in probe()), bound to a driver, or unbinding (in disconnect())
 * @sysfs_files_created: sysfs attributes exist
 * @ep_devs_created: endpoint child pseudo-devices exist
 * @unregistering: flag set when the interface is being unregistered
 * @needs_remote_wakeup: flag set when the driver requires remote-wakeup
 *	capability during autosuspend.
 * @needs_altsetting0: flag set when a set-interface request for altsetting 0
 *	has been deferred.
 * @needs_binding: flag set when the driver should be re-probed or unbound
 *	following a reset or suspend operation it doesn't support.
 * @authorized: This allows to (de)authorize individual interfaces instead
 *	a whole device in contrast to the device authorization.
 * @dev: driver model's view of this device
 * @usb_dev: if an interface is bound to the USB major, this will point
 *	to the sysfs representation for that device.
 * @pm_usage_cnt: PM usage counter for this interface
 * @reset_ws: Used for scheduling resets from atomic context.
 * @resetting_device: USB core reset the device, so use alt setting 0 as
 *	current; needs bandwidth alloc after reset.
 *
 * USB device drivers attach to interfaces on a physical device.  Each
 * interface encapsulates a single high level function, such as feeding
 * an audio stream to a speaker or reporting a change in a volume control.
 * Many USB devices only have one interface.  The protocol used to talk to
 * an interface's endpoints can be defined in a usb "class" specification,
 * or by a product's vendor.  The (default) control endpoint is part of
 * every interface, but is never listed among the interface's descriptors.
 *
 * The driver that is bound to the interface can use standard driver model
 * calls such as dev_get_drvdata() on the dev member of this structure.
 *
 * Each interface may have alternate settings.  The initial configuration
 * of a device sets altsetting 0, but the device driver can change
 * that setting using usb_set_interface().  Alternate settings are often
 * used to control the use of periodic endpoints, such as by having
 * different endpoints use different amounts of reserved USB bandwidth.
 * All standards-conformant USB devices that use isochronous endpoints
 * will use them in non-default settings.
 *
 * The USB specification says that alternate setting numbers must run from
 * 0 to one less than the total number of alternate settings.  But some
 * devices manage to mess this up, and the structures aren't necessarily
 * stored in numerical order anyhow.  Use usb_altnum_to_altsetting() to
 * look up an alternate setting in the altsetting array based on its number.
 */
struct usb_interface {
	/* array of alternate settings for this interface,
	 * stored in no particular order */
	 //可选的设置
	struct usb_host_interface *altsetting;
	//当前正在使用的设置
	struct usb_host_interface *cur_altsetting;	/* the currently
					 * active alternate setting */
	//可选设置的数量				 	
	unsigned num_altsetting;	/* number of alternate settings */

	/* If there is an interface association descriptor then it will list
	 * the associated interfaces */
	struct usb_interface_assoc_descriptor *intf_assoc;
//分配给接口的次设备号，只在USB_MAJOR起作用的时候起作用
	int minor;			/* minor number this interface is
					 * bound to */
//表示接口与驱动的绑定状态
	enum usb_interface_condition condition;		/* state of binding */
	unsigned sysfs_files_created:1;	/* the sysfs attributes exist */
	unsigned ep_devs_created:1;	/* endpoint "devices" exist */
	unsigned unregistering:1;	/* unregistration is in progress */
//与pm_usage_cnt都是关于挂起与唤醒
	//协议里规定，所有的USB设备都必须支持挂起状态，就是说为了达到节电的目的
	//当设备在指定的时间内，如果没有发生总线传输，就要进入挂起状态。
	//当它收到一个no_idle信号的时候，就会被唤醒
	//needs_remote_wakeup表示是否需要打开远程唤醒功能。远程唤醒功能允许挂起的设备给主机发信号
	//通知主机它将从挂起状态恢复，注意如果此时主机处于挂起状态就会唤醒主机，不然主机依然睡觉，设备自己 醒来没什么用
	//协议里并没有要求USB设备一定要实现远程唤醒功能，即使实现了，从主机那边也可以打开或者关闭
	unsigned needs_remote_wakeup:1;	/* driver requires remote wakeup */
	unsigned needs_altsetting0:1;	/* switch to altsetting 0 is pending */
	unsigned needs_binding:1;	/* needs delayed unbind/rebind */
	unsigned resetting_device:1;	/* true: bandwidth alloc after reset */
	unsigned authorized:1;		/* used for interface authorization */

	struct device dev;		/* interface specific device info */
//只有当接口使用USB_MAJOR作为主设备号的时候,usb_dev才会用到，usb_dev指向usb_register_dev函数里面创建的usb classd device
	struct device *usb_dev;
//pm就是电源管理，usage_cnt就是使用计数。当它为0的时候，接口允许autosuspend,就是自动进入休眠
	atomic_t pm_usage_cnt;		/* usage counter for autosuspend */
	struct work_struct reset_ws;	/* for resets in atomic context */
};
#define	to_usb_interface(d) container_of(d, struct usb_interface, dev)

static inline void *usb_get_intfdata(struct usb_interface *intf)
{
	return dev_get_drvdata(&intf->dev);
}

static inline void usb_set_intfdata(struct usb_interface *intf, void *data)
{
	dev_set_drvdata(&intf->dev, data);
}

struct usb_interface *usb_get_intf(struct usb_interface *intf);
void usb_put_intf(struct usb_interface *intf);

/* Hard limit */
#define USB_MAXENDPOINTS	30
/* this maximum is arbitrary */
#define USB_MAXINTERFACES	32
#define USB_MAXIADS		(USB_MAXINTERFACES/2)

/*
 * USB Resume Timer: Every Host controller driver should drive the resume
 * signalling on the bus for the amount of time defined by this macro.
 *
 * That way we will have a 'stable' behavior among all HCDs supported by Linux.
 *
 * Note that the USB Specification states we should drive resume for *at least*
 * 20 ms, but it doesn't give an upper bound. This creates two possible
 * situations which we want to avoid:
 *
 * (a) sometimes an msleep(20) might expire slightly before 20 ms, which causes
 * us to fail USB Electrical Tests, thus failing Certification
 *
 * (b) Some (many) devices actually need more than 20 ms of resume signalling,
 * and while we can argue that's against the USB Specification, we don't have
 * control over which devices a certification laboratory will be using for
 * certification. If CertLab uses a device which was tested against Windows and
 * that happens to have relaxed resume signalling rules, we might fall into
 * situations where we fail interoperability and electrical tests.
 *
 * In order to avoid both conditions, we're using a 40 ms resume timeout, which
 * should cope with both LPJ calibration errors and devices not following every
 * detail of the USB Specification.
 */
#define USB_RESUME_TIMEOUT	40 /* ms */

/**
 * struct usb_interface_cache - long-term representation of a device interface
 * @num_altsetting: number of altsettings defined.
 * @ref: reference counter.
 * @altsetting: variable-length array of interface structures, one for
 *	each alternate setting that may be selected.  Each one includes a
 *	set of endpoint configurations.  They will be in no particular order.
 *
 * These structures persist for the lifetime of a usb_device, unlike
 * struct usb_interface (which persists only as long as its configuration
 * is installed).  The altsetting arrays can be accessed through these
 * structures at any time, permitting comparison of configurations and
 * providing support for the /proc/bus/usb/devices pseudo-file.
 */
struct usb_interface_cache {
	unsigned num_altsetting;	/* number of alternate settings */
	struct kref ref;		/* reference counter */

	/* variable-length array of alternate settings for this interface,
	 * stored in no particular order */
	  //altsetting[0] 是一个可变长数组，按需分配的那种，你对设备说GET_DESCRIPTOR的时候
　 //，内核就根据返回的每个接口可选设置的数目分配给intf_cache
//数组相应的空间，有多少需要多少分配多少，
	struct usb_host_interface altsetting[0];
};
#define	ref_to_usb_interface_cache(r) \
		container_of(r, struct usb_interface_cache, ref)
#define	altsetting_to_usb_interface_cache(a) \
		container_of(a, struct usb_interface_cache, altsetting[0])

/**
 * struct usb_host_config - representation of a device's configuration
 * @desc: the device's configuration descriptor.
 * @string: pointer to the cached version of the iConfiguration string, if
 *	present for this configuration.
 * @intf_assoc: list of any interface association descriptors in this config
 * @interface: array of pointers to usb_interface structures, one for each
 *	interface in the configuration.  The number of interfaces is stored
 *	in desc.bNumInterfaces.  These pointers are valid only while the
 *	the configuration is active.
 * @intf_cache: array of pointers to usb_interface_cache structures, one
 *	for each interface in the configuration.  These structures exist
 *	for the entire life of the device.
 * @extra: pointer to buffer containing all extra descriptors associated
 *	with this configuration (those preceding the first interface
 *	descriptor).
 * @extralen: length of the extra descriptors buffer.
 *
 * USB devices may have multiple configurations, but only one can be active
 * at any time.  Each encapsulates a different operational environment;
 * for example, a dual-speed device would have separate configurations for
 * full-speed and high-speed operation.  The number of configurations
 * available is stored in the device descriptor as bNumConfigurations.
 *
 * A configuration can contain multiple interfaces.  Each corresponds to
 * a different function of the USB device, and all are available whenever
 * the configuration is active.  The USB standard says that interfaces
 * are supposed to be numbered from 0 to desc.bNumInterfaces-1, but a lot
 * of devices get this wrong.  In addition, the interface array is not
 * guaranteed to be sorted in numerical order.  Use usb_ifnum_to_if() to
 * look up an interface entry based on its number.
 *
 * Device drivers should not attempt to activate configurations.  The choice
 * of which configuration to install is a policy decision based on such
 * considerations as available power, functionality provided, and the user's
 * desires (expressed through userspace tools).  However, drivers can call
 * usb_reset_configuration() to reinitialize the current configuration and
 * all its interfaces.
 */
struct usb_host_config {
	struct usb_config_descriptor	desc;
//string，这个字符串保存了配置描述符iConfiguration字段对应的字符串描述信息
	char *string;		/* iConfiguration string, if present */

	/* List of any Interface Association Descriptors in this
	 * configuration. */
	struct usb_interface_assoc_descriptor *intf_assoc[USB_MAXIADS];

	/* the interfaces associated with this configuration,
	 * stored in no particular order */
	  //interface[USB_MAXINTERFACES]，配置所包含的接口。注释里说的很明确，
	//这个数组的顺序未必是按照配置里接口号的顺序
	//所以你要想得到某个接口号对应的struct usb_interface 结构对象
	//就必须使用 usb.c 里定义的 usb_ifnum_to_if 函数。
	//USB_MAXINTERFACES 是 include/linux/usb.h 里定义的一个宏，值为 32，不要说不
	//够用，谁见过有很多接口的设备
	struct usb_interface *interface[USB_MAXINTERFACES];

	/* Interface information available even when this is not the
	 * active configuration */
	  //usb_interface_cache 就是 usb 接口的缓存
	struct usb_interface_cache *intf_cache[USB_MAXINTERFACES];
//后面两个是
	//有关额外扩展的描述符的
	//如果你使用
	//GET_DESCRIPTOR请求从设备里获得配置描述符信息，它们会紧跟在标准的配置描述符
	//后面返回给你
	unsigned char *extra;   /* Extra descriptors */
	int extralen;
};

/* USB2.0 and USB3.0 device BOS descriptor set */
struct usb_host_bos {
	struct usb_bos_descriptor	*desc;

	/* wireless cap descriptor is handled by wusb */
	struct usb_ext_cap_descriptor	*ext_cap;
	struct usb_ss_cap_descriptor	*ss_cap;
	struct usb_ssp_cap_descriptor	*ssp_cap;
	struct usb_ss_container_id_descriptor	*ss_id;
	struct usb_ptm_cap_descriptor	*ptm_cap;
};

int __usb_get_extra_descriptor(char *buffer, unsigned size,
	unsigned char type, void **ptr);
#define usb_get_extra_descriptor(ifpoint, type, ptr) \
				__usb_get_extra_descriptor((ifpoint)->extra, \
				(ifpoint)->extralen, \
				type, (void **)ptr)

/* ----------------------------------------------------------------------- */
/* ----------------------------------------------------------------------- */
//假设unsigend long = 4bytes，那么unsigned long devicemap[128/(8*sizeof(unsigned kong))]就
//等价于unsigend long devicemap[128/(8*4)] 进而等价于unsigned long devicemap[4],而4bytes就是32个bits
//因此这个数组最终表示的就是128个bits,这也对应于一条总线上可以连接128个USB设备
//之所以使用sizeof(unsigned long )，就是为了跨平台应用，不管unsigned long到底是几，总之这个
//devicemap数组最终可以表示为128位，也就是说每天总线上最多可以连上128个设备
/* USB device number allocation bitmap */
/* USB device number allocation bitmap */
struct usb_devmap {
	unsigned long devicemap[128 / (8*sizeof(unsigned long))];
};

/*
 * Allocated per bus (tree of devices) we have:
 */
 //在我们usb_init里已经注册了usb_bus_type，但是那只是让系统知道有那么一个类型的总线
 //一个类型的总线和一条总线是两码事。从硬件上讲，一个host controller就会连出一条usb总线
 //从软件上讲，你有多少host controller，或者说多少条总线，它们通通属于usb_bus_type这么一个类型
 //只是每一条总线对应一个struct usb_bus结构体变量，这个变量在host_controller的驱动程序中去申请
struct usb_bus {
	struct device *controller;	/* host/master side hardware */
	//busnum，总线编号，你的机子里总可以有多个主机控制器吧，自然也就可以有
	//多条 usb 总线了
	int busnum;			/* Bus number (in order of reg) */
	//bus_name，bus 总线，name 名字
	const char *bus_name;		/* stable id (PCI slot_name etc) */
	//uses_dma，表明这个主机控制器支持不支持 DMA
	u8 uses_dma;			/* Does the host controller use DMA? */
	u8 uses_pio_for_control;	/*
					 * Does the host controller use PIO
					 * for control transfers?
					 */
	u8 otg_port;			/* 0, or number of OTG/HNP port */
	unsigned is_b_host:1;		/* true during some HNP roleswitches */
	unsigned b_hnp_enable:1;	/* OTG: did A-Host enable HNP? */
	unsigned no_stop_on_short:1;    /*
					 * Quirk: some controllers don't stop
					 * the ep queue on a short transfer
					 * with the URB_SHORT_NOT_OK flag set.
					 */
	unsigned no_sg_constraint:1;	/* no sg constraint */
	unsigned sg_tablesize;		/* 0 or largest number of sg list entries */
//devnum_next  中记录的就是这张表里下一个为 0 的位，里面为 1 的位都是已经被这条总线上的
	//usb 设备占据了的，名花有主的
	int devnum_next;		/* Next open device number in
					 * round-robin allocation */
	struct mutex devnum_next_mutex; /* devnum_next mutex */
//地址映射表，表示了一条总线上设备的连接情况
	struct usb_devmap devmap;	/* device address allocation map */
	struct usb_device *root_hub;	/* Root hub */
	struct usb_bus *hs_companion;	/* Companion EHCI bus, if any */
	//bandwidth_allocated，表明总线为中断传输和等时传输预留了多少带宽，协议
	//里说了，对于高速来说，最多可以有 80%，对于低速和全速要多点儿，可以达到 90%。
	//它的单位是微妙，表示一帧或微帧内有多少微妙可以留给中断/等时传输用。
	int bandwidth_allocated;	/* on this bus: how much of the time
					 * reserved for periodic (intr/iso)
					 * requests is used, on average?
					 * Units: microseconds/frame.
					 * Limits: Full/low speed reserve 90%,
					 * while high speed reserves 80%.
					 */
	//bandwidth_int_reqs，bandwidth_isoc_reqs，分别表示当前中断传输和等时传输的数量。
	int bandwidth_int_reqs;		/* number of Interrupt requests */
	int bandwidth_isoc_reqs;	/* number of Isoc. requests */

	unsigned resuming_ports;	/* bit array: resuming root-hub ports */

#if defined(CONFIG_USB_MON) || defined(CONFIG_USB_MON_MODULE)
	struct mon_bus *mon_bus;	/* non-null when associated */
	int monitored;			/* non-zero when monitored */
#endif
};

struct usb_dev_state;

/* ----------------------------------------------------------------------- */

struct usb_tt;

enum usb_device_removable {
	USB_DEVICE_REMOVABLE_UNKNOWN = 0,
	USB_DEVICE_REMOVABLE,
	USB_DEVICE_FIXED,
};

enum usb_port_connect_type {
	USB_PORT_CONNECT_TYPE_UNKNOWN = 0,
	USB_PORT_CONNECT_TYPE_HOT_PLUG,
	USB_PORT_CONNECT_TYPE_HARD_WIRED,
	USB_PORT_NOT_USED,
};

/*
 * USB 2.0 Link Power Management (LPM) parameters.
 */
struct usb2_lpm_parameters {
	/* Best effort service latency indicate how long the host will drive
	 * resume on an exit from L1.
	 */
	unsigned int besl;

	/* Timeout value in microseconds for the L1 inactivity (LPM) timer.
	 * When the timer counts to zero, the parent hub will initiate a LPM
	 * transition to L1.
	 */
	int timeout;
};

/*
 * USB 3.0 Link Power Management (LPM) parameters.
 *
 * PEL and SEL are USB 3.0 Link PM latencies for device-initiated LPM exit.
 * MEL is the USB 3.0 Link PM latency for host-initiated LPM exit.
 * All three are stored in nanoseconds.
 */
struct usb3_lpm_parameters {
	/*
	 * Maximum exit latency (MEL) for the host to send a packet to the
	 * device (either a Ping for isoc endpoints, or a data packet for
	 * interrupt endpoints), the hubs to decode the packet, and for all hubs
	 * in the path to transition the links to U0.
	 */
	unsigned int mel;
	/*
	 * Maximum exit latency for a device-initiated LPM transition to bring
	 * all links into U0.  Abbreviated as "PEL" in section 9.4.12 of the USB
	 * 3.0 spec, with no explanation of what "P" stands for.  "Path"?
	 */
	unsigned int pel;

	/*
	 * The System Exit Latency (SEL) includes PEL, and three other
	 * latencies.  After a device initiates a U0 transition, it will take
	 * some time from when the device sends the ERDY to when it will finally
	 * receive the data packet.  Basically, SEL should be the worse-case
	 * latency from when a device starts initiating a U0 transition to when
	 * it will get data.
	 */
	unsigned int sel;
	/*
	 * The idle timeout value that is currently programmed into the parent
	 * hub for this device.  When the timer counts to zero, the parent hub
	 * will initiate an LPM transition to either U1 or U2.
	 */
	int timeout;
};

/**
 * struct usb_device - kernel's representation of a USB device
 * @devnum: device number; address on a USB bus
 * @devpath: device ID string for use in messages (e.g., /port/...)
 * @route: tree topology hex string for use with xHCI
 * @state: device state: configured, not attached, etc.
 * @speed: device speed: high/full/low (or error)
 * @tt: Transaction Translator info; used with low/full speed dev, highspeed hub
 * @ttport: device port on that tt hub
 * @toggle: one bit for each endpoint, with ([0] = IN, [1] = OUT) endpoints
 * @parent: our hub, unless we're the root
 * @bus: bus we're part of
 * @ep0: endpoint 0 data (default control pipe)
 * @dev: generic device interface
 * @descriptor: USB device descriptor
 * @bos: USB device BOS descriptor set
 * @config: all of the device's configs
 * @actconfig: the active configuration
 * @ep_in: array of IN endpoints
 * @ep_out: array of OUT endpoints
 * @rawdescriptors: raw descriptors for each config
 * @bus_mA: Current available from the bus
 * @portnum: parent port number (origin 1)
 * @level: number of USB hub ancestors
 * @can_submit: URBs may be submitted
 * @persist_enabled:  USB_PERSIST enabled for this device
 * @have_langid: whether string_langid is valid
 * @authorized: policy has said we can use it;
 *	(user space) policy determines if we authorize this device to be
 *	used or not. By default, wired USB devices are authorized.
 *	WUSB devices are not, until we authorize them from user space.
 *	FIXME -- complete doc
 * @authenticated: Crypto authentication passed
 * @wusb: device is Wireless USB
 * @lpm_capable: device supports LPM
 * @usb2_hw_lpm_capable: device can perform USB2 hardware LPM
 * @usb2_hw_lpm_besl_capable: device can perform USB2 hardware BESL LPM
 * @usb2_hw_lpm_enabled: USB2 hardware LPM is enabled
 * @usb2_hw_lpm_allowed: Userspace allows USB 2.0 LPM to be enabled
 * @usb3_lpm_u1_enabled: USB3 hardware U1 LPM enabled
 * @usb3_lpm_u2_enabled: USB3 hardware U2 LPM enabled
 * @string_langid: language ID for strings
 * @product: iProduct string, if present (static)
 * @manufacturer: iManufacturer string, if present (static)
 * @serial: iSerialNumber string, if present (static)
 * @filelist: usbfs files that are open to this device
 * @maxchild: number of ports if hub
 * @quirks: quirks of the whole device
 * @urbnum: number of URBs submitted for the whole device
 * @active_duration: total time device is not suspended
 * @connect_time: time device was first connected
 * @do_remote_wakeup:  remote wakeup should be enabled
 * @reset_resume: needs reset instead of resume
 * @port_is_suspended: the upstream port is suspended (L2 or U3)
 * @wusb_dev: if this is a Wireless USB device, link to the WUSB
 *	specific data for the device.
 * @slot_id: Slot ID assigned by xHCI
 * @removable: Device can be physically removed from this port
 * @l1_params: best effor service latency for USB2 L1 LPM state, and L1 timeout.
 * @u1_params: exit latencies for USB3 U1 LPM state, and hub-initiated timeout.
 * @u2_params: exit latencies for USB3 U2 LPM state, and hub-initiated timeout.
 * @lpm_disable_count: Ref count used by usb_disable_lpm() and usb_enable_lpm()
 *	to keep track of the number of functions that require USB 3.0 Link Power
 *	Management to be disabled for this usb_device.  This count should only
 *	be manipulated by those functions, with the bandwidth_mutex is held.
 *
 * Notes:
 * Usbcore drivers should not set usbdev->state directly.  Instead use
 * usb_set_device_state().
 */
struct usb_device {
	int		devnum;
	char		devpath[16];
	u32		route;
	enum usb_device_state	state;
	enum usb_device_speed	speed;

	struct usb_tt	*tt;
	int		ttport;

	unsigned int toggle[2];

	struct usb_device *parent;
	struct usb_bus *bus;
	struct usb_host_endpoint ep0;

	struct device dev;

	struct usb_device_descriptor descriptor;
	struct usb_host_bos *bos;
	struct usb_host_config *config;

	struct usb_host_config *actconfig;
	struct usb_host_endpoint *ep_in[16];
	struct usb_host_endpoint *ep_out[16];

	char **rawdescriptors;

	unsigned short bus_mA;
	u8 portnum;
	u8 level;

	unsigned can_submit:1;
	unsigned persist_enabled:1;
	unsigned have_langid:1;
	unsigned authorized:1;
	unsigned authenticated:1;
	unsigned wusb:1;
	unsigned lpm_capable:1;
	unsigned usb2_hw_lpm_capable:1;
	unsigned usb2_hw_lpm_besl_capable:1;
	unsigned usb2_hw_lpm_enabled:1;
	unsigned usb2_hw_lpm_allowed:1;
	unsigned usb3_lpm_u1_enabled:1;
	unsigned usb3_lpm_u2_enabled:1;
	int string_langid;

	/* static strings from the device */
	char *product;
	char *manufacturer;
	char *serial;

	struct list_head filelist;

	int maxchild;

	u32 quirks;
	atomic_t urbnum;

	unsigned long active_duration;

#ifdef CONFIG_PM
	unsigned long connect_time;

	unsigned do_remote_wakeup:1;
	unsigned reset_resume:1;
	unsigned port_is_suspended:1;
#endif
	struct wusb_dev *wusb_dev;
	int slot_id;
	enum usb_device_removable removable;
	struct usb2_lpm_parameters l1_params;
	struct usb3_lpm_parameters u1_params;
	struct usb3_lpm_parameters u2_params;
	unsigned lpm_disable_count;
};
#define	to_usb_device(d) container_of(d, struct usb_device, dev)

static inline struct usb_device *interface_to_usbdev(struct usb_interface *intf)
{
	return to_usb_device(intf->dev.parent);
}

extern struct usb_device *usb_get_dev(struct usb_device *dev);
extern void usb_put_dev(struct usb_device *dev);
extern struct usb_device *usb_hub_find_child(struct usb_device *hdev,
	int port1);

/**
 * usb_hub_for_each_child - iterate over all child devices on the hub
 * @hdev:  USB device belonging to the usb hub
 * @port1: portnum associated with child device
 * @child: child device pointer
 */
#define usb_hub_for_each_child(hdev, port1, child) \
	for (port1 = 1,	child =	usb_hub_find_child(hdev, port1); \
			port1 <= hdev->maxchild; \
			child = usb_hub_find_child(hdev, ++port1)) \
		if (!child) continue; else

/* USB device locking */
#define usb_lock_device(udev)			device_lock(&(udev)->dev)
#define usb_unlock_device(udev)			device_unlock(&(udev)->dev)
#define usb_lock_device_interruptible(udev)	device_lock_interruptible(&(udev)->dev)
#define usb_trylock_device(udev)		device_trylock(&(udev)->dev)
extern int usb_lock_device_for_reset(struct usb_device *udev,
				     const struct usb_interface *iface);

/* USB port reset for device reinitialization */
extern int usb_reset_device(struct usb_device *dev);
extern void usb_queue_reset_device(struct usb_interface *dev);

#ifdef CONFIG_ACPI
extern int usb_acpi_set_power_state(struct usb_device *hdev, int index,
	bool enable);
extern bool usb_acpi_power_manageable(struct usb_device *hdev, int index);
#else
static inline int usb_acpi_set_power_state(struct usb_device *hdev, int index,
	bool enable) { return 0; }
static inline bool usb_acpi_power_manageable(struct usb_device *hdev, int index)
	{ return true; }
#endif

/* USB autosuspend and autoresume */
#ifdef CONFIG_PM
extern void usb_enable_autosuspend(struct usb_device *udev);
extern void usb_disable_autosuspend(struct usb_device *udev);

extern int usb_autopm_get_interface(struct usb_interface *intf);
extern void usb_autopm_put_interface(struct usb_interface *intf);
extern int usb_autopm_get_interface_async(struct usb_interface *intf);
extern void usb_autopm_put_interface_async(struct usb_interface *intf);
extern void usb_autopm_get_interface_no_resume(struct usb_interface *intf);
extern void usb_autopm_put_interface_no_suspend(struct usb_interface *intf);

static inline void usb_mark_last_busy(struct usb_device *udev)
{
	pm_runtime_mark_last_busy(&udev->dev);
}

#else

static inline int usb_enable_autosuspend(struct usb_device *udev)
{ return 0; }
static inline int usb_disable_autosuspend(struct usb_device *udev)
{ return 0; }

static inline int usb_autopm_get_interface(struct usb_interface *intf)
{ return 0; }
static inline int usb_autopm_get_interface_async(struct usb_interface *intf)
{ return 0; }

static inline void usb_autopm_put_interface(struct usb_interface *intf)
{ }
static inline void usb_autopm_put_interface_async(struct usb_interface *intf)
{ }
static inline void usb_autopm_get_interface_no_resume(
		struct usb_interface *intf)
{ }
static inline void usb_autopm_put_interface_no_suspend(
		struct usb_interface *intf)
{ }
static inline void usb_mark_last_busy(struct usb_device *udev)
{ }
#endif

extern int usb_disable_lpm(struct usb_device *udev);
extern void usb_enable_lpm(struct usb_device *udev);
/* Same as above, but these functions lock/unlock the bandwidth_mutex. */
extern int usb_unlocked_disable_lpm(struct usb_device *udev);
extern void usb_unlocked_enable_lpm(struct usb_device *udev);

extern int usb_disable_ltm(struct usb_device *udev);
extern void usb_enable_ltm(struct usb_device *udev);

static inline bool usb_device_supports_ltm(struct usb_device *udev)
{
	if (udev->speed < USB_SPEED_SUPER || !udev->bos || !udev->bos->ss_cap)
		return false;
	return udev->bos->ss_cap->bmAttributes & USB_LTM_SUPPORT;
}

static inline bool usb_device_no_sg_constraint(struct usb_device *udev)
{
	return udev && udev->bus && udev->bus->no_sg_constraint;
}


/*-------------------------------------------------------------------------*/

/* for drivers using iso endpoints */
extern int usb_get_current_frame_number(struct usb_device *usb_dev);

/* Sets up a group of bulk endpoints to support multiple stream IDs. */
extern int usb_alloc_streams(struct usb_interface *interface,
		struct usb_host_endpoint **eps, unsigned int num_eps,
		unsigned int num_streams, gfp_t mem_flags);

/* Reverts a group of bulk endpoints back to not using stream IDs. */
extern int usb_free_streams(struct usb_interface *interface,
		struct usb_host_endpoint **eps, unsigned int num_eps,
		gfp_t mem_flags);

/* used these for multi-interface device registration */
extern int usb_driver_claim_interface(struct usb_driver *driver,
			struct usb_interface *iface, void *priv);

/**
 * usb_interface_claimed - returns true iff an interface is claimed
 * @iface: the interface being checked
 *
 * Return: %true (nonzero) iff the interface is claimed, else %false
 * (zero).
 *
 * Note:
 * Callers must own the driver model's usb bus readlock.  So driver
 * probe() entries don't need extra locking, but other call contexts
 * may need to explicitly claim that lock.
 *
 */
static inline int usb_interface_claimed(struct usb_interface *iface)
{
	return (iface->dev.driver != NULL);
}

extern void usb_driver_release_interface(struct usb_driver *driver,
			struct usb_interface *iface);
const struct usb_device_id *usb_match_id(struct usb_interface *interface,
					 const struct usb_device_id *id);
extern int usb_match_one_id(struct usb_interface *interface,
			    const struct usb_device_id *id);

extern int usb_for_each_dev(void *data, int (*fn)(struct usb_device *, void *));
extern struct usb_interface *usb_find_interface(struct usb_driver *drv,
		int minor);
extern struct usb_interface *usb_ifnum_to_if(const struct usb_device *dev,
		unsigned ifnum);
extern struct usb_host_interface *usb_altnum_to_altsetting(
		const struct usb_interface *intf, unsigned int altnum);
extern struct usb_host_interface *usb_find_alt_setting(
		struct usb_host_config *config,
		unsigned int iface_num,
		unsigned int alt_num);

/* port claiming functions */
int usb_hub_claim_port(struct usb_device *hdev, unsigned port1,
		struct usb_dev_state *owner);
int usb_hub_release_port(struct usb_device *hdev, unsigned port1,
		struct usb_dev_state *owner);

/**
 * usb_make_path - returns stable device path in the usb tree
 * @dev: the device whose path is being constructed
 * @buf: where to put the string
 * @size: how big is "buf"?
 *
 * Return: Length of the string (> 0) or negative if size was too small.
 *
 * Note:
 * This identifier is intended to be "stable", reflecting physical paths in
 * hardware such as physical bus addresses for host controllers or ports on
 * USB hubs.  That makes it stay the same until systems are physically
 * reconfigured, by re-cabling a tree of USB devices or by moving USB host
 * controllers.  Adding and removing devices, including virtual root hubs
 * in host controller driver modules, does not change these path identifiers;
 * neither does rebooting or re-enumerating.  These are more useful identifiers
 * than changeable ("unstable") ones like bus numbers or device addresses.
 *
 * With a partial exception for devices connected to USB 2.0 root hubs, these
 * identifiers are also predictable.  So long as the device tree isn't changed,
 * plugging any USB device into a given hub port always gives it the same path.
 * Because of the use of "companion" controllers, devices connected to ports on
 * USB 2.0 root hubs (EHCI host controllers) will get one path ID if they are
 * high speed, and a different one if they are full or low speed.
 */
static inline int usb_make_path(struct usb_device *dev, char *buf, size_t size)
{
	int actual;
	actual = snprintf(buf, size, "usb-%s-%s", dev->bus->bus_name,
			  dev->devpath);
	return (actual >= (int)size) ? -1 : actual;
}

/*-------------------------------------------------------------------------*/

#define USB_DEVICE_ID_MATCH_DEVICE \
		(USB_DEVICE_ID_MATCH_VENDOR | USB_DEVICE_ID_MATCH_PRODUCT)
#define USB_DEVICE_ID_MATCH_DEV_RANGE \
		(USB_DEVICE_ID_MATCH_DEV_LO | USB_DEVICE_ID_MATCH_DEV_HI)
#define USB_DEVICE_ID_MATCH_DEVICE_AND_VERSION \
		(USB_DEVICE_ID_MATCH_DEVICE | USB_DEVICE_ID_MATCH_DEV_RANGE)
#define USB_DEVICE_ID_MATCH_DEV_INFO \
		(USB_DEVICE_ID_MATCH_DEV_CLASS | \
		USB_DEVICE_ID_MATCH_DEV_SUBCLASS | \
		USB_DEVICE_ID_MATCH_DEV_PROTOCOL)
#define USB_DEVICE_ID_MATCH_INT_INFO \
		(USB_DEVICE_ID_MATCH_INT_CLASS | \
		USB_DEVICE_ID_MATCH_INT_SUBCLASS | \
		USB_DEVICE_ID_MATCH_INT_PROTOCOL)

/**
 * USB_DEVICE - macro used to describe a specific usb device
 * @vend: the 16 bit USB Vendor ID
 * @prod: the 16 bit USB Product ID
 *
 * This macro is used to create a struct usb_device_id that matches a
 * specific device.
 */
#define USB_DEVICE(vend, prod) \
	.match_flags = USB_DEVICE_ID_MATCH_DEVICE, \
	.idVendor = (vend), \
	.idProduct = (prod)
/**
 * USB_DEVICE_VER - describe a specific usb device with a version range
 * @vend: the 16 bit USB Vendor ID
 * @prod: the 16 bit USB Product ID
 * @lo: the bcdDevice_lo value
 * @hi: the bcdDevice_hi value
 *
 * This macro is used to create a struct usb_device_id that matches a
 * specific device, with a version range.
 */
#define USB_DEVICE_VER(vend, prod, lo, hi) \
	.match_flags = USB_DEVICE_ID_MATCH_DEVICE_AND_VERSION, \
	.idVendor = (vend), \
	.idProduct = (prod), \
	.bcdDevice_lo = (lo), \
	.bcdDevice_hi = (hi)

/**
 * USB_DEVICE_INTERFACE_CLASS - describe a usb device with a specific interface class
 * @vend: the 16 bit USB Vendor ID
 * @prod: the 16 bit USB Product ID
 * @cl: bInterfaceClass value
 *
 * This macro is used to create a struct usb_device_id that matches a
 * specific interface class of devices.
 */
#define USB_DEVICE_INTERFACE_CLASS(vend, prod, cl) \
	.match_flags = USB_DEVICE_ID_MATCH_DEVICE | \
		       USB_DEVICE_ID_MATCH_INT_CLASS, \
	.idVendor = (vend), \
	.idProduct = (prod), \
	.bInterfaceClass = (cl)

/**
 * USB_DEVICE_INTERFACE_PROTOCOL - describe a usb device with a specific interface protocol
 * @vend: the 16 bit USB Vendor ID
 * @prod: the 16 bit USB Product ID
 * @pr: bInterfaceProtocol value
 *
 * This macro is used to create a struct usb_device_id that matches a
 * specific interface protocol of devices.
 */
#define USB_DEVICE_INTERFACE_PROTOCOL(vend, prod, pr) \
	.match_flags = USB_DEVICE_ID_MATCH_DEVICE | \
		       USB_DEVICE_ID_MATCH_INT_PROTOCOL, \
	.idVendor = (vend), \
	.idProduct = (prod), \
	.bInterfaceProtocol = (pr)

/**
 * USB_DEVICE_INTERFACE_NUMBER - describe a usb device with a specific interface number
 * @vend: the 16 bit USB Vendor ID
 * @prod: the 16 bit USB Product ID
 * @num: bInterfaceNumber value
 *
 * This macro is used to create a struct usb_device_id that matches a
 * specific interface number of devices.
 */
#define USB_DEVICE_INTERFACE_NUMBER(vend, prod, num) \
	.match_flags = USB_DEVICE_ID_MATCH_DEVICE | \
		       USB_DEVICE_ID_MATCH_INT_NUMBER, \
	.idVendor = (vend), \
	.idProduct = (prod), \
	.bInterfaceNumber = (num)

/**
 * USB_DEVICE_INFO - macro used to describe a class of usb devices
 * @cl: bDeviceClass value
 * @sc: bDeviceSubClass value
 * @pr: bDeviceProtocol value
 *
 * This macro is used to create a struct usb_device_id that matches a
 * specific class of devices.
 */
#define USB_DEVICE_INFO(cl, sc, pr) \
	.match_flags = USB_DEVICE_ID_MATCH_DEV_INFO, \
	.bDeviceClass = (cl), \
	.bDeviceSubClass = (sc), \
	.bDeviceProtocol = (pr)

/**
 * USB_INTERFACE_INFO - macro used to describe a class of usb interfaces
 * @cl: bInterfaceClass value
 * @sc: bInterfaceSubClass value
 * @pr: bInterfaceProtocol value
 *
 * This macro is used to create a struct usb_device_id that matches a
 * specific class of interfaces.
 */
#define USB_INTERFACE_INFO(cl, sc, pr) \
	.match_flags = USB_DEVICE_ID_MATCH_INT_INFO, \
	//设备的类型
	.bInterfaceClass = (cl), \
	//设备的子类型
	.bInterfaceSubClass = (sc), \
	//设备使用的协议
	.bInterfaceProtocol = (pr)

/**
 * USB_DEVICE_AND_INTERFACE_INFO - describe a specific usb device with a class of usb interfaces
 * @vend: the 16 bit USB Vendor ID
 * @prod: the 16 bit USB Product ID
 * @cl: bInterfaceClass value
 * @sc: bInterfaceSubClass value
 * @pr: bInterfaceProtocol value
 *
 * This macro is used to create a struct usb_device_id that matches a
 * specific device with a specific class of interfaces.
 *
 * This is especially useful when explicitly matching devices that have
 * vendor specific bDeviceClass values, but standards-compliant interfaces.
 */
#define USB_DEVICE_AND_INTERFACE_INFO(vend, prod, cl, sc, pr) \
	.match_flags = USB_DEVICE_ID_MATCH_INT_INFO \
		| USB_DEVICE_ID_MATCH_DEVICE, \
	.idVendor = (vend), \
	.idProduct = (prod), \
	.bInterfaceClass = (cl), \
	.bInterfaceSubClass = (sc), \
	.bInterfaceProtocol = (pr)

/**
 * USB_VENDOR_AND_INTERFACE_INFO - describe a specific usb vendor with a class of usb interfaces
 * @vend: the 16 bit USB Vendor ID
 * @cl: bInterfaceClass value
 * @sc: bInterfaceSubClass value
 * @pr: bInterfaceProtocol value
 *
 * This macro is used to create a struct usb_device_id that matches a
 * specific vendor with a specific class of interfaces.
 *
 * This is especially useful when explicitly matching devices that have
 * vendor specific bDeviceClass values, but standards-compliant interfaces.
 */
#define USB_VENDOR_AND_INTERFACE_INFO(vend, cl, sc, pr) \
	.match_flags = USB_DEVICE_ID_MATCH_INT_INFO \
		| USB_DEVICE_ID_MATCH_VENDOR, \
	.idVendor = (vend), \
	.bInterfaceClass = (cl), \
	.bInterfaceSubClass = (sc), \
	.bInterfaceProtocol = (pr)

/* ----------------------------------------------------------------------- */

/* Stuff for dynamic usb ids */
struct usb_dynids {
	spinlock_t lock;
	struct list_head list;
};

struct usb_dynid {
	struct list_head node;
	struct usb_device_id id;
};

extern ssize_t usb_store_new_id(struct usb_dynids *dynids,
				const struct usb_device_id *id_table,
				struct device_driver *driver,
				const char *buf, size_t count);

extern ssize_t usb_show_dynids(struct usb_dynids *dynids, char *buf);

/**
 * struct usbdrv_wrap - wrapper for driver-model structure
 * @driver: The driver-model core driver structure.
 * @for_devices: Non-zero for device drivers, 0 for interface drivers.
 */
  //usb的世界里不得已分成了设备驱动和接口驱
 //动两种，为了区分这两种驱动，就中间加了这么一层，添了个for_devices标志来判断是哪一种
struct usbdrv_wrap {
	struct device_driver driver;
	int for_devices;
};

/**
 * struct usb_driver - identifies USB interface driver to usbcore
 * @name: The driver name should be unique among USB drivers,
 *	and should normally be the same as the module name.
 * @probe: Called to see if the driver is willing to manage a particular
 *	interface on a device.  If it is, probe returns zero and uses
 *	usb_set_intfdata() to associate driver-specific data with the
 *	interface.  It may also use usb_set_interface() to specify the
 *	appropriate altsetting.  If unwilling to manage the interface,
 *	return -ENODEV, if genuine IO errors occurred, an appropriate
 *	negative errno value.
 * @disconnect: Called when the interface is no longer accessible, usually
 *	because its device has been (or is being) disconnected or the
 *	driver module is being unloaded.
 * @unlocked_ioctl: Used for drivers that want to talk to userspace through
 *	the "usbfs" filesystem.  This lets devices provide ways to
 *	expose information to user space regardless of where they
 *	do (or don't) show up otherwise in the filesystem.
 * @suspend: Called when the device is going to be suspended by the
 *	system either from system sleep or runtime suspend context. The
 *	return value will be ignored in system sleep context, so do NOT
 *	try to continue using the device if suspend fails in this case.
 *	Instead, let the resume or reset-resume routine recover from
 *	the failure.
 * @resume: Called when the device is being resumed by the system.
 * @reset_resume: Called when the suspended device has been reset instead
 *	of being resumed.
 * @pre_reset: Called by usb_reset_device() when the device is about to be
 *	reset.  This routine must not return until the driver has no active
 *	URBs for the device, and no more URBs may be submitted until the
 *	post_reset method is called.
 * @post_reset: Called by usb_reset_device() after the device
 *	has been reset
 * @id_table: USB drivers use ID table to support hotplugging.
 *	Export this with MODULE_DEVICE_TABLE(usb,...).  This must be set
 *	or your driver's probe function will never get called.
 * @dynids: used internally to hold the list of dynamically added device
 *	ids for this driver.
 * @drvwrap: Driver-model core structure wrapper.
 * @no_dynamic_id: if set to 1, the USB core will not allow dynamic ids to be
 *	added to this driver by preventing the sysfs file from being created.
 * @supports_autosuspend: if set to 0, the USB core will not allow autosuspend
 *	for interfaces bound to this driver.
 * @soft_unbind: if set to 1, the USB core will not kill URBs and disable
 *	endpoints before calling the driver's disconnect method.
 * @disable_hub_initiated_lpm: if set to 1, the USB core will not allow hubs
 *	to initiate lower power link state transitions when an idle timeout
 *	occurs.  Device-initiated USB 3.0 link PM will still be allowed.
 *
 * USB interface drivers must provide a name, probe() and disconnect()
 * methods, and an id_table.  Other driver fields are optional.
 *
 * The id_table is used in hotplugging.  It holds a set of descriptors,
 * and specialized data may be associated with each entry.  That table
 * is used by both user and kernel mode hotplugging support.
 *
 * The probe() and disconnect() methods are called in a context where
 * they can sleep, but they should avoid abusing the privilege.  Most
 * work to connect to a device should be done when the device is opened,
 * and undone at the last close.  The disconnect code needs to address
 * concurrency issues with respect to open() and close() methods, as
 * well as forcing all pending I/O requests to complete (by unlinking
 * them as necessary, and blocking until the unlinks complete).
 */
struct usb_driver {
//驱动程序的名字，对应了在/sys/bus/usb/drivers/下面的子目录名称
	const char *name;
	// 用来看看这个 usb 驱动是否愿意接受某个接口的函数
	int (*probe) (struct usb_interface *intf,
		      const struct usb_device_id *id);
//当接口失去联系，或使用rmmod卸载驱动将它和接口强行分开时
//这个函数就会被调用
	void (*disconnect) (struct usb_interface *intf);
//ioctl，当你的驱动有通过usbfs和用户空间交流的需要的话，就使用它吧
	int (*unlocked_ioctl) (struct usb_interface *intf, unsigned int code,
			void *buf);
	//suspend，resume，分别在设备被挂起和唤醒时使用。
	int (*suspend) (struct usb_interface *intf, pm_message_t message);
	int (*resume) (struct usb_interface *intf);
	int (*reset_resume)(struct usb_interface *intf);
//pre_reset，post_reset，分别在设备将要复位（reset）和已经复位后使用
	int (*pre_reset)(struct usb_interface *intf);
	int (*post_reset)(struct usb_interface *intf);
//id_table，驱动支持的所有设备的花名册
	const struct usb_device_id *id_table;
//dynids，支持动态 id 的
//即使驱动已经加载了，也可以添加新的 id 给她，只要新 id 代表的设备存在
//怎么添加新的 id？到驱动所在的地方瞅瞅，也就是/sys/bus/usb/drivers 目录下边儿，那
//里列出的每个目录就代表了一个 usb 驱动，随便选一个进去，能够看到一个 new_id 文件
//吧，使用 echo 将厂商和产品 id 写进去就可以了
//例子echo 0557 2008 > /sys/bus/usb/drivers/foo_driver/new_id 
//就可以将 16 进制值 0557 和 2008 写到 foo_driver 驱动的设备 id 表里去
	struct usb_dynids dynids;
//struct usbdrv_wrap 结构的，也在
//include/linux/usb.h 里定义
	struct usbdrv_wrap drvwrap;
//no_dynamic_id，可以用来禁止动态 id 的
	unsigned int no_dynamic_id:1;
//supports_autosuspend，对 autosuspend 的支持，如果设置为 0 的话，就不再允许绑定到这个驱动的接口 autosuspend
	unsigned int supports_autosuspend:1;
	unsigned int disable_hub_initiated_lpm:1;
	unsigned int soft_unbind:1;
};
#define	to_usb_driver(d) container_of(d, struct usb_driver, drvwrap.driver)

/**
 * struct usb_device_driver - identifies USB device driver to usbcore
 * @name: The driver name should be unique among USB drivers,
 *	and should normally be the same as the module name.
 * @probe: Called to see if the driver is willing to manage a particular
 *	device.  If it is, probe returns zero and uses dev_set_drvdata()
 *	to associate driver-specific data with the device.  If unwilling
 *	to manage the device, return a negative errno value.
 * @disconnect: Called when the device is no longer accessible, usually
 *	because it has been (or is being) disconnected or the driver's
 *	module is being unloaded.
 * @suspend: Called when the device is going to be suspended by the system.
 * @resume: Called when the device is being resumed by the system.
 * @drvwrap: Driver-model core structure wrapper.
 * @supports_autosuspend: if set to 0, the USB core will not allow autosuspend
 *	for devices bound to this driver.
 *
 * USB drivers must provide all the fields listed above except drvwrap.
 */
struct usb_device_driver {
	const char *name;

	int (*probe) (struct usb_device *udev);
	void (*disconnect) (struct usb_device *udev);

	int (*suspend) (struct usb_device *udev, pm_message_t message);
	int (*resume) (struct usb_device *udev, pm_message_t message);
	struct usbdrv_wrap drvwrap;
	unsigned int supports_autosuspend:1;
};
#define	to_usb_device_driver(d) container_of(d, struct usb_device_driver, \
		drvwrap.driver)

extern struct bus_type usb_bus_type;

/**
 * struct usb_class_driver - identifies a USB driver that wants to use the USB major number
 * @name: the usb class device name for this driver.  Will show up in sysfs.
 * @devnode: Callback to provide a naming hint for a possible
 *	device node to create.
 * @fops: pointer to the struct file_operations of this driver.
 * @minor_base: the start of the minor range for this driver.
 *
 * This structure is used for the usb_register_dev() and
 * usb_unregister_dev() functions, to consolidate a number of the
 * parameters used for them.
 */
struct usb_class_driver {
	char *name;
	char *(*devnode)(struct device *dev, umode_t *mode);
	const struct file_operations *fops;
	int minor_base;
};

/*
 * use these in module_init()/module_exit()
 * and don't forget MODULE_DEVICE_TABLE(usb, ...)
 */
extern int usb_register_driver(struct usb_driver *, struct module *,
			       const char *);

/* use a define to avoid include chaining to get THIS_MODULE & friends */
#define usb_register(driver) \
	usb_register_driver(driver, THIS_MODULE, KBUILD_MODNAME)

extern void usb_deregister(struct usb_driver *);

/**
 * module_usb_driver() - Helper macro for registering a USB driver
 * @__usb_driver: usb_driver struct
 *
 * Helper macro for USB drivers which do not do anything special in module
 * init/exit. This eliminates a lot of boilerplate. Each module may only
 * use this macro once, and calling it replaces module_init() and module_exit()
 */
#define module_usb_driver(__usb_driver) \
	module_driver(__usb_driver, usb_register, \
		       usb_deregister)

extern int usb_register_device_driver(struct usb_device_driver *,
			struct module *);
extern void usb_deregister_device_driver(struct usb_device_driver *);

extern int usb_register_dev(struct usb_interface *intf,
			    struct usb_class_driver *class_driver);
extern void usb_deregister_dev(struct usb_interface *intf,
			       struct usb_class_driver *class_driver);

extern int usb_disabled(void);

/* ----------------------------------------------------------------------- */

/*
 * URB support, for asynchronous request completions
 */

/*
 * urb->transfer_flags:
 *
 * Note: URB_DIR_IN/OUT is automatically set in usb_submit_urb().
 */
 //这个标记只对用来从 IN 端点读取数据的 urb 有效意思就是说
//如果从一个 IN 端点那里读取了一个比较短的数据包，就可以认为是错误的。
//如果从 IN 端点那儿收到了一个比 wMaxPacketSize 要短的包！
//同时也设置了 URB_SHORT_NOT_OK 这个标志，那么就可以认为传输出错了
#define URB_SHORT_NOT_OK	0x0001	/* report short reads as errors */
//URB_ISO_ASAP，这个标志只是为了方便等时传输用的。
//它的意思就是告诉HCD 啥时候不忙就啥时候开始
#define URB_ISO_ASAP		0x0002	/* iso-only; use the first unexpired
					 * slot in the schedule */
#define URB_NO_TRANSFER_DMA_MAP	0x0004	/* urb->transfer_dma valid on submit */
//URB_NO_FSBR，这是给 UHCI 用的。
#define URB_NO_FSBR		0x0020	/* UHCI-specific */
//URB_ZERO_PACKET，这个标志表示批量的 OUT 传输必须使用一个 short packet 来结束
//当等于wMaxPacketSize 时，如果同时设置了 URB_ZERO_PACKET 标志，就需要再发送一个长
//度为 0 的数据包来结束这次传输，如果小于 wMaxPacketSize 就没必要多此一举了
#define URB_ZERO_PACKET		0x0040	/* Finish bulk OUT with short packet */
//URB_NO_INTERRUPT，这个标志用来告诉 HCD，在 URB 完成后，不要请求一个硬件中
//断，当然这就意味着你的结束处理函数可能不会在 urb 完成后立即被调用，而是在之后的
//某个时间被调用
#define URB_NO_INTERRUPT	0x0080	/* HINT: no non-error interrupt
					 * needed */
#define URB_FREE_BUFFER		0x0100	/* Free transfer buffer with the URB */

/* The following flags are used internally by usbcore and HCDs */
#define URB_DIR_IN		0x0200	/* Transfer from device to host */
#define URB_DIR_OUT		0
#define URB_DIR_MASK		URB_DIR_IN

#define URB_DMA_MAP_SINGLE	0x00010000	/* Non-scatter-gather mapping */
#define URB_DMA_MAP_PAGE	0x00020000	/* HCD-unsupported S-G */
#define URB_DMA_MAP_SG		0x00040000	/* HCD-supported S-G */
#define URB_MAP_LOCAL		0x00080000	/* HCD-local-memory mapping */
#define URB_SETUP_MAP_SINGLE	0x00100000	/* Setup packet DMA mapped */
#define URB_SETUP_MAP_LOCAL	0x00200000	/* HCD-local setup packet */
#define URB_DMA_SG_COMBINED	0x00400000	/* S-G entries were combined */
#define URB_ALIGNED_TEMP_BUFFER	0x00800000	/* Temp buffer was alloc'd */

struct usb_iso_packet_descriptor {
//offset表示transfer_buffer里的偏移位置
	unsigned int offset;
//length是预期的这次等时传输Data包里数据的长度，注意这里说的是预期，
//因为实际传输时因为种种原因可能不会有那么多数据
	unsigned int length;		/* expected length */
//urb结束时，每个struct  usb_iso_packet_descriptor结构体的actual_length就表示了各次等时传输实际传输的
//数据长度
	unsigned int actual_length;
	//status分别记录了它们的状态。
	int status;
};

struct urb;

struct usb_anchor {
	struct list_head urb_list;
	wait_queue_head_t wait;
	spinlock_t lock;
	atomic_t suspend_wakeups;
	unsigned int poisoned:1;
};

static inline void init_usb_anchor(struct usb_anchor *anchor)
{
	memset(anchor, 0, sizeof(*anchor));
	INIT_LIST_HEAD(&anchor->urb_list);
	init_waitqueue_head(&anchor->wait);
	spin_lock_init(&anchor->lock);
}

typedef void (*usb_complete_t)(struct urb *);

/**
 * struct urb - USB Request Block
 * @urb_list: For use by current owner of the URB.
 * @anchor_list: membership in the list of an anchor
 * @anchor: to anchor URBs to a common mooring
 * @ep: Points to the endpoint's data structure.  Will eventually
 *	replace @pipe.
 * @pipe: Holds endpoint number, direction, type, and more.
 *	Create these values with the eight macros available;
 *	usb_{snd,rcv}TYPEpipe(dev,endpoint), where the TYPE is "ctrl"
 *	(control), "bulk", "int" (interrupt), or "iso" (isochronous).
 *	For example usb_sndbulkpipe() or usb_rcvintpipe().  Endpoint
 *	numbers range from zero to fifteen.  Note that "in" endpoint two
 *	is a different endpoint (and pipe) from "out" endpoint two.
 *	The current configuration controls the existence, type, and
 *	maximum packet size of any given endpoint.
 * @stream_id: the endpoint's stream ID for bulk streams
 * @dev: Identifies the USB device to perform the request.
 * @status: This is read in non-iso completion functions to get the
 *	status of the particular request.  ISO requests only use it
 *	to tell whether the URB was unlinked; detailed status for
 *	each frame is in the fields of the iso_frame-desc.
 * @transfer_flags: A variety of flags may be used to affect how URB
 *	submission, unlinking, or operation are handled.  Different
 *	kinds of URB can use different flags.
 * @transfer_buffer:  This identifies the buffer to (or from) which the I/O
 *	request will be performed unless URB_NO_TRANSFER_DMA_MAP is set
 *	(however, do not leave garbage in transfer_buffer even then).
 *	This buffer must be suitable for DMA; allocate it with
 *	kmalloc() or equivalent.  For transfers to "in" endpoints, contents
 *	of this buffer will be modified.  This buffer is used for the data
 *	stage of control transfers.
 * @transfer_dma: When transfer_flags includes URB_NO_TRANSFER_DMA_MAP,
 *	the device driver is saying that it provided this DMA address,
 *	which the host controller driver should use in preference to the
 *	transfer_buffer.
 * @sg: scatter gather buffer list, the buffer size of each element in
 * 	the list (except the last) must be divisible by the endpoint's
 * 	max packet size if no_sg_constraint isn't set in 'struct usb_bus'
 * @num_mapped_sgs: (internal) number of mapped sg entries
 * @num_sgs: number of entries in the sg list
 * @transfer_buffer_length: How big is transfer_buffer.  The transfer may
 *	be broken up into chunks according to the current maximum packet
 *	size for the endpoint, which is a function of the configuration
 *	and is encoded in the pipe.  When the length is zero, neither
 *	transfer_buffer nor transfer_dma is used.
 * @actual_length: This is read in non-iso completion functions, and
 *	it tells how many bytes (out of transfer_buffer_length) were
 *	transferred.  It will normally be the same as requested, unless
 *	either an error was reported or a short read was performed.
 *	The URB_SHORT_NOT_OK transfer flag may be used to make such
 *	short reads be reported as errors.
 * @setup_packet: Only used for control transfers, this points to eight bytes
 *	of setup data.  Control transfers always start by sending this data
 *	to the device.  Then transfer_buffer is read or written, if needed.
 * @setup_dma: DMA pointer for the setup packet.  The caller must not use
 *	this field; setup_packet must point to a valid buffer.
 * @start_frame: Returns the initial frame for isochronous transfers.
 * @number_of_packets: Lists the number of ISO transfer buffers.
 * @interval: Specifies the polling interval for interrupt or isochronous
 *	transfers.  The units are frames (milliseconds) for full and low
 *	speed devices, and microframes (1/8 millisecond) for highspeed
 *	and SuperSpeed devices.
 * @error_count: Returns the number of ISO transfers that reported errors.
 * @context: For use in completion functions.  This normally points to
 *	request-specific driver context.
 * @complete: Completion handler. This URB is passed as the parameter to the
 *	completion function.  The completion function may then do what
 *	it likes with the URB, including resubmitting or freeing it.
 * @iso_frame_desc: Used to provide arrays of ISO transfer buffers and to
 *	collect the transfer status for each buffer.
 *
 * This structure identifies USB transfer requests.  URBs must be allocated by
 * calling usb_alloc_urb() and freed with a call to usb_free_urb().
 * Initialization may be done using various usb_fill_*_urb() functions.  URBs
 * are submitted using usb_submit_urb(), and pending requests may be canceled
 * using usb_unlink_urb() or usb_kill_urb().
 *
 * Data Transfer Buffers:
 *
 * Normally drivers provide I/O buffers allocated with kmalloc() or otherwise
 * taken from the general page pool.  That is provided by transfer_buffer
 * (control requests also use setup_packet), and host controller drivers
 * perform a dma mapping (and unmapping) for each buffer transferred.  Those
 * mapping operations can be expensive on some platforms (perhaps using a dma
 * bounce buffer or talking to an IOMMU),
 * although they're cheap on commodity x86 and ppc hardware.
 *
 * Alternatively, drivers may pass the URB_NO_TRANSFER_DMA_MAP transfer flag,
 * which tells the host controller driver that no such mapping is needed for
 * the transfer_buffer since
 * the device driver is DMA-aware.  For example, a device driver might
 * allocate a DMA buffer with usb_alloc_coherent() or call usb_buffer_map().
 * When this transfer flag is provided, host controller drivers will
 * attempt to use the dma address found in the transfer_dma
 * field rather than determining a dma address themselves.
 *
 * Note that transfer_buffer must still be set if the controller
 * does not support DMA (as indicated by bus.uses_dma) and when talking
 * to root hub. If you have to trasfer between highmem zone and the device
 * on such controller, create a bounce buffer or bail out with an error.
 * If transfer_buffer cannot be set (is in highmem) and the controller is DMA
 * capable, assign NULL to it, so that usbmon knows not to use the value.
 * The setup_packet must always be set, so it cannot be located in highmem.
 *
 * Initialization:
 *
 * All URBs submitted must initialize the dev, pipe, transfer_flags (may be
 * zero), and complete fields.  All URBs must also initialize
 * transfer_buffer and transfer_buffer_length.  They may provide the
 * URB_SHORT_NOT_OK transfer flag, indicating that short reads are
 * to be treated as errors; that flag is invalid for write requests.
 *
 * Bulk URBs may
 * use the URB_ZERO_PACKET transfer flag, indicating that bulk OUT transfers
 * should always terminate with a short packet, even if it means adding an
 * extra zero length packet.
 *
 * Control URBs must provide a valid pointer in the setup_packet field.
 * Unlike the transfer_buffer, the setup_packet may not be mapped for DMA
 * beforehand.
 *
 * Interrupt URBs must provide an interval, saying how often (in milliseconds
 * or, for highspeed devices, 125 microsecond units)
 * to poll for transfers.  After the URB has been submitted, the interval
 * field reflects how the transfer was actually scheduled.
 * The polling interval may be more frequent than requested.
 * For example, some controllers have a maximum interval of 32 milliseconds,
 * while others support intervals of up to 1024 milliseconds.
 * Isochronous URBs also have transfer intervals.  (Note that for isochronous
 * endpoints, as well as high speed interrupt endpoints, the encoding of
 * the transfer interval in the endpoint descriptor is logarithmic.
 * Device drivers must convert that value to linear units themselves.)
 *
 * If an isochronous endpoint queue isn't already running, the host
 * controller will schedule a new URB to start as soon as bandwidth
 * utilization allows.  If the queue is running then a new URB will be
 * scheduled to start in the first transfer slot following the end of the
 * preceding URB, if that slot has not already expired.  If the slot has
 * expired (which can happen when IRQ delivery is delayed for a long time),
 * the scheduling behavior depends on the URB_ISO_ASAP flag.  If the flag
 * is clear then the URB will be scheduled to start in the expired slot,
 * implying that some of its packets will not be transferred; if the flag
 * is set then the URB will be scheduled in the first unexpired slot,
 * breaking the queue's synchronization.  Upon URB completion, the
 * start_frame field will be set to the (micro)frame number in which the
 * transfer was scheduled.  Ranges for frame counter values are HC-specific
 * and can go from as low as 256 to as high as 65536 frames.
 *
 * Isochronous URBs have a different data transfer model, in part because
 * the quality of service is only "best effort".  Callers provide specially
 * allocated URBs, with number_of_packets worth of iso_frame_desc structures
 * at the end.  Each such packet is an individual ISO transfer.  Isochronous
 * URBs are normally queued, submitted by drivers to arrange that
 * transfers are at least double buffered, and then explicitly resubmitted
 * in completion handlers, so
 * that data (such as audio or video) streams at as constant a rate as the
 * host controller scheduler can support.
 *
 * Completion Callbacks:
 *
 * The completion callback is made in_interrupt(), and one of the first
 * things that a completion handler should do is check the status field.
 * The status field is provided for all URBs.  It is used to report
 * unlinked URBs, and status for all non-ISO transfers.  It should not
 * be examined before the URB is returned to the completion handler.
 *
 * The context field is normally used to link URBs back to the relevant
 * driver or request state.
 *
 * When the completion callback is invoked for non-isochronous URBs, the
 * actual_length field tells how many bytes were transferred.  This field
 * is updated even when the URB terminated with an error or was unlinked.
 *
 * ISO transfer status is reported in the status and actual_length fields
 * of the iso_frame_desc array, and the number of errors is reported in
 * error_count.  Completion callbacks for ISO transfers will normally
 * (re)submit URBs to ensure a constant transfer rate.
 *
 * Note that even fields marked "public" should not be touched by the driver
 * when the urb is owned by the hcd, that is, since the call to
 * usb_submit_urb() till the entry into the completion routine.
 */
struct urb {
	/* private: usb core and host controller only fields in the urb */
       //每多一个使用者，它的这个引用计数就加 1，每减少一个使用者，引用计数就减一，如果连最后一个使用者都释放了这个 urb，宣称不再
	//使用它了，那它的生命周期就走到了尽头，会自动的销毁
	//在 include/linux/kref.h 里定义
	//但是我们应该是几乎见不到内核里边儿直接使用上面那几个	
	//函数来给对象计数的，而是每种对象又定义了自己专用的引用计数函数，比如咱们的 urb，
	//在 urb.c 里定义
	struct kref kref;		/* reference count of the URB */
//urb 最终还是要提交给主机控制器驱动的，这个字段就是 urb 里主机控制器驱动的自留地
	void *hcpriv;			/* private data for host controller */
//在usb_core将urb移交给HCD，办理移交手续的时候，插上了那么一脚，每当走到这一步它的值就会�
// 1,在HCD重新将urb的所有权交给驱动程序的时候减一
//注意kref计数减为0的时候，urb对象就会被销毁，但是这个use_count只是用来统计当前这个urb是不是在正在被使用的，即使是0，也只能说明没有HCD在使用它而已                                                                                       
//具体这个有什么用呢，urb驱动也创建了，提交也提交了，HCD正处理，但是驱动返回了，它不想在进行这次通信了
//想把这个urb给终止掉。但是这个分为了两张，第一种是驱动只想通过USB CORE告诉HCD一声，这个urb我想终止掉，它不想在那里等着HCD的处理
//对应的是usb_unlink_urb函数
//还一种就是驱动在那里等着HCD的处理结果，等待urb被终止，对应的函数是usb_kill_urb函数
//而 HCD 将这次通信终止后，同样会将 urb 的所有权移交回驱动。那么驱动通过什么判断 HCD 已经终止了这次通信？就是
//通过这里的 use_count，驱动会在 usb_kill_urb 里面一直等待着这个值变为 0。
	atomic_t use_count;		/* concurrent submissions counter */
//拒接???  只有 usb_kill_urb 函数有特权对它进行修改，那么，显然 reject 就与上面说的 urb 终止有关了。那就看看 urb.c 里定义的这个函数
	atomic_t reject;		/* submissions will fail */
	int unlinked;			/* unlink error code */

	/* public: documented fields in the urb that can be used by drivers */
//每个端点都会有个urb队列，这个队列就是由这里的urb_list一个一个链接起来的
	struct list_head urb_list;	/* list head for use by the urb's
					 * current owner */
	struct list_head anchor_list;	/* the URB may be anchored */
	struct usb_anchor *anchor;
	//它表示的是 urb 要去的那个 usb 设备
	struct usb_device *dev;		/* (in) pointer to associated device */
	struct usb_host_endpoint *ep;	/* (internal) pointer to endpoint */
	//urb 到达端点之前，需要经过一个通往端点的管道，就是这个 pipe
	//bit7 用来表示方向
	//bit8~14 表示设备地址
	//bit15~18 表示端点号bit30~31 表示管道类型
	unsigned int pipe;		/* (in) pipe information */
	unsigned int stream_id;		/* (in) stream ID */
	//status，urb 的当前状态。urb 当然是可以有多种状态的
	int status;			/* (return) non-ISO status */
	//一些标记，可用的值都在 include/linux/usb.h 里有定义
	unsigned int transfer_flags;	/* (in) URB_SHORT_NOT_OK | ...*/
	//transfer_buffer 是使用 kmalloc 分配的缓冲区
	//transfer_dma 是使用usb_buffer_alloc 分配的 dma 缓冲区
	//HCD 不会同时使用它们两个，如果你的 urb 自带
	//了 transfer_dma，就要同时设置 URB_NO_TRANSFER_DMA_MAP 来告诉 HCD 一声，
	//不用它再费心做 DMA 映射了
	//。transfer_buffer 是必须要设置的，因为不是所有的主机控
	//制器都能够使用 DMA 的，万一遇到这样的情况，也好有个备用
	void *transfer_buffer;		/* (in) associated data buffer */
	dma_addr_t transfer_dma;	/* (in) dma addr for transfer_buffer */
	struct scatterlist *sg;		/* (in) scatter gather buffer list */
	int num_mapped_sgs;		/* (internal) mapped sg entries */
	int num_sgs;			/* (in) number of entries in the sg list */
	//。transfer_buffer_length指的就是 transfer_buffer 或 transfer_dma 的长度
	u32 transfer_buffer_length;	/* (in) data buffer length */
	//actual_length，urb 结束之后，会用这个字段告诉你实际上传输了多少数据
	u32 actual_length;		/* (return) actual transfer length */
	//setup_packet，setup_dma，同样是两个缓冲区，一个是kmalloc分
	//配的，一个是用usb_buffer_alloc分配的
	//不过，这两个缓冲区是控制传输专用的
	unsigned char *setup_packet;	/* (in) setup packet (control only) */
	dma_addr_t setup_dma;		/* (in) dma addr for setup_packet */
	//start_frame，如果你没有指定 URB_ISO_ASAP 标志，就必须自己设置
	//start_frame，指定等时传输在哪帧或微帧开�
	//如果指定了 URB_ISO_ASAP，urb 结束时会使用这个值返回实际的开始帧号
	int start_frame;		/* (modify) start frame (ISO) */
	int number_of_packets;		/* (in) number of ISO packets */
	//interval，等时和中断传输专用。interval 间隔时间的意思
	//端点希望主机轮询自己的时间间隔。这个值和端点描述符里的 bInterval 是一
	//样的，你不能随便儿的指定一个
	int interval;			/* (modify) transfer interval
					 * (INT/ISO) */
	int error_count;		/* (return) number of ISO errors */
	//context，驱动设置了给下面的结束处理函数用的。比如可以将自己驱动里描述
	//自己设备的结构体放在里边儿，在结束处理函数里就可以取出来
	void *context;			/* (in) context for completion */
	//complete，一个指向结束处理函数的指针，传输成功完成，或者中间发生错误
	//的时候就会调用它，驱动可以在这里边儿检查 urb 的状态，并做一些处理，比如可以释放
	//这个 urb，或者重新提交给 HCD
	usb_complete_t complete;	/* (in) completion routine */
	//等时传输专用的等时传输与其它传输不一样，可以指定传输多少个packet，
	//每 个 packet 使 用 struct usb_iso_packet_descriptor 结构来描�
	//iso_frame_desc就表示了一个变长的struct usb_iso_packet_descriptor结构体数组
	//要说明的是这里说的packet不是说你在一次等时传输里传输了多个Data packet，而是说
	//你在一个urb里指定了多次的等时传输，每个struct usb_iso_packet_descriptor结构体
	//都代表了一次等时传输。
	//所以对于等时传输来说，在完成了 number_of_packets 次传输之后，会去调用你的结束
	//处理函数，在里面对数据做处理，
	struct usb_iso_packet_descriptor iso_frame_desc[0];
					/* (in) ISO ONLY */
};

/* ----------------------------------------------------------------------- */

/**
 * usb_fill_control_urb - initializes a control urb
 * @urb: pointer to the urb to initialize.
 * @dev: pointer to the struct usb_device for this urb.
 * @pipe: the endpoint pipe
 * @setup_packet: pointer to the setup_packet buffer
 * @transfer_buffer: pointer to the transfer buffer
 * @buffer_length: length of the transfer buffer
 * @complete_fn: pointer to the usb_complete_t function
 * @context: what to set the urb context to.
 *
 * Initializes a control urb with the proper information needed to submit
 * it to a device.
 */
 //初始化刚才创建的控制urb
 //参数里的 setup_packet
//就是之前创建和赋好值的struct usb_ctrlrequest结构体，设备的地址已经在struct 
//usb_ctrlrequest结构体wValue字段里了
//这次控制传输并没有DATA transaction阶段
//也并不需要urb提供什么transfer_buffer缓冲区，所以transfer_buffer应该传递一个NULL，当然transfer_buffer_length也就为 0 了
static inline void usb_fill_control_urb(struct urb *urb,
					struct usb_device *dev,
					unsigned int pipe,
					unsigned char *setup_packet,
					void *transfer_buffer,
					int buffer_length,
					usb_complete_t complete_fn,
					void *context)
{
	urb->dev = dev;
	urb->pipe = pipe;
	urb->setup_packet = setup_packet;
	urb->transfer_buffer = transfer_buffer;
	urb->transfer_buffer_length = buffer_length;
	urb->complete = complete_fn;
	urb->context = context;
}

/**
 * usb_fill_bulk_urb - macro to help initialize a bulk urb
 * @urb: pointer to the urb to initialize.
 * @dev: pointer to the struct usb_device for this urb.
 * @pipe: the endpoint pipe
 * @transfer_buffer: pointer to the transfer buffer
 * @buffer_length: length of the transfer buffer
 * @complete_fn: pointer to the usb_complete_t function
 * @context: what to set the urb context to.
 *
 * Initializes a bulk urb with the proper information needed to submit it
 * to a device.
 */
  //初始化urb     对于批量传输有 usb_fill_bulk_urb 
static inline void usb_fill_bulk_urb(struct urb *urb,
				     struct usb_device *dev,
				     unsigned int pipe,
				     void *transfer_buffer,
				     int buffer_length,
				     usb_complete_t complete_fn,
				     void *context)
{
	urb->dev = dev;
	urb->pipe = pipe;
	urb->transfer_buffer = transfer_buffer;
	urb->transfer_buffer_length = buffer_length;
	urb->complete = complete_fn;
	urb->context = context;
}

/**
 * usb_fill_int_urb - macro to help initialize a interrupt urb
 * @urb: pointer to the urb to initialize.
 * @dev: pointer to the struct usb_device for this urb.
 * @pipe: the endpoint pipe
 * @transfer_buffer: pointer to the transfer buffer
 * @buffer_length: length of the transfer buffer
 * @complete_fn: pointer to the usb_complete_t function
 * @context: what to set the urb context to.
 * @interval: what to set the urb interval to, encoded like
 *	the endpoint descriptor's bInterval value.
 *
 * Initializes a interrupt urb with the proper information needed to submit
 * it to a device.
 *
 * Note that High Speed and SuperSpeed(+) interrupt endpoints use a logarithmic
 * encoding of the endpoint interval, and express polling intervals in
 * microframes (eight per millisecond) rather than in frames (one per
 * millisecond).
 *
 * Wireless USB also uses the logarithmic encoding, but specifies it in units of
 * 128us instead of 125us.  For Wireless USB devices, the interval is passed
 * through to the host controller, rather than being translated into microframe
 * units.
 */
  //中断传输有usb_fill_int_urb，初始化urb	
static inline void usb_fill_int_urb(struct urb *urb,
				    struct usb_device *dev,
				    unsigned int pipe,
				    void *transfer_buffer,
				    int buffer_length,
				    usb_complete_t complete_fn,
				    void *context,
				    int interval)
{
	urb->dev = dev;
	urb->pipe = pipe;
	urb->transfer_buffer = transfer_buffer;
	urb->transfer_buffer_length = buffer_length;
	urb->complete = complete_fn;
	urb->context = context;

	if (dev->speed == USB_SPEED_HIGH || dev->speed >= USB_SPEED_SUPER) {
		/* make sure interval is within allowed range */
		interval = clamp(interval, 1, 16);

		urb->interval = 1 << (interval - 1);
	} else {
		urb->interval = interval;
	}

	urb->start_frame = -1;
}

extern void usb_init_urb(struct urb *urb);
extern struct urb *usb_alloc_urb(int iso_packets, gfp_t mem_flags);
extern void usb_free_urb(struct urb *urb);
#define usb_put_urb usb_free_urb
extern struct urb *usb_get_urb(struct urb *urb);
extern int usb_submit_urb(struct urb *urb, gfp_t mem_flags);
extern int usb_unlink_urb(struct urb *urb);
extern void usb_kill_urb(struct urb *urb);
extern void usb_poison_urb(struct urb *urb);
extern void usb_unpoison_urb(struct urb *urb);
extern void usb_block_urb(struct urb *urb);
extern void usb_kill_anchored_urbs(struct usb_anchor *anchor);
extern void usb_poison_anchored_urbs(struct usb_anchor *anchor);
extern void usb_unpoison_anchored_urbs(struct usb_anchor *anchor);
extern void usb_unlink_anchored_urbs(struct usb_anchor *anchor);
extern void usb_anchor_suspend_wakeups(struct usb_anchor *anchor);
extern void usb_anchor_resume_wakeups(struct usb_anchor *anchor);
extern void usb_anchor_urb(struct urb *urb, struct usb_anchor *anchor);
extern void usb_unanchor_urb(struct urb *urb);
extern int usb_wait_anchor_empty_timeout(struct usb_anchor *anchor,
					 unsigned int timeout);
extern struct urb *usb_get_from_anchor(struct usb_anchor *anchor);
extern void usb_scuttle_anchored_urbs(struct usb_anchor *anchor);
extern int usb_anchor_empty(struct usb_anchor *anchor);

#define usb_unblock_urb	usb_unpoison_urb

/**
 * usb_urb_dir_in - check if an URB describes an IN transfer
 * @urb: URB to be checked
 *
 * Return: 1 if @urb describes an IN transfer (device-to-host),
 * otherwise 0.
 */
static inline int usb_urb_dir_in(struct urb *urb)
{
	return (urb->transfer_flags & URB_DIR_MASK) == URB_DIR_IN;
}

/**
 * usb_urb_dir_out - check if an URB describes an OUT transfer
 * @urb: URB to be checked
 *
 * Return: 1 if @urb describes an OUT transfer (host-to-device),
 * otherwise 0.
 */
static inline int usb_urb_dir_out(struct urb *urb)
{
	return (urb->transfer_flags & URB_DIR_MASK) == URB_DIR_OUT;
}

void *usb_alloc_coherent(struct usb_device *dev, size_t size,
	gfp_t mem_flags, dma_addr_t *dma);
void usb_free_coherent(struct usb_device *dev, size_t size,
	void *addr, dma_addr_t dma);

#if 0
struct urb *usb_buffer_map(struct urb *urb);
void usb_buffer_dmasync(struct urb *urb);
void usb_buffer_unmap(struct urb *urb);
#endif

struct scatterlist;
int usb_buffer_map_sg(const struct usb_device *dev, int is_in,
		      struct scatterlist *sg, int nents);
#if 0
void usb_buffer_dmasync_sg(const struct usb_device *dev, int is_in,
			   struct scatterlist *sg, int n_hw_ents);
#endif
void usb_buffer_unmap_sg(const struct usb_device *dev, int is_in,
			 struct scatterlist *sg, int n_hw_ents);

/*-------------------------------------------------------------------*
 *                         SYNCHRONOUS CALL SUPPORT                  *
 *-------------------------------------------------------------------*/

extern int usb_control_msg(struct usb_device *dev, unsigned int pipe,
	__u8 request, __u8 requesttype, __u16 value, __u16 index,
	void *data, __u16 size, int timeout);
extern int usb_interrupt_msg(struct usb_device *usb_dev, unsigned int pipe,
	void *data, int len, int *actual_length, int timeout);
extern int usb_bulk_msg(struct usb_device *usb_dev, unsigned int pipe,
	void *data, int len, int *actual_length,
	int timeout);

/* wrappers around usb_control_msg() for the most common standard requests */
extern int usb_get_descriptor(struct usb_device *dev, unsigned char desctype,
	unsigned char descindex, void *buf, int size);
extern int usb_get_status(struct usb_device *dev,
	int type, int target, void *data);
extern int usb_string(struct usb_device *dev, int index,
	char *buf, size_t size);

/* wrappers that also update important state inside usbcore */
extern int usb_clear_halt(struct usb_device *dev, int pipe);
extern int usb_reset_configuration(struct usb_device *dev);
extern int usb_set_interface(struct usb_device *dev, int ifnum, int alternate);
extern void usb_reset_endpoint(struct usb_device *dev, unsigned int epaddr);

/* this request isn't really synchronous, but it belongs with the others */
extern int usb_driver_set_configuration(struct usb_device *udev, int config);

/* choose and set configuration for device */
extern int usb_choose_configuration(struct usb_device *udev);
extern int usb_set_configuration(struct usb_device *dev, int configuration);

/*
 * timeouts, in milliseconds, used for sending/receiving control messages
 * they typically complete within a few frames (msec) after they're issued
 * USB identifies 5 second timeouts, maybe more in a few cases, and a few
 * slow devices (like some MGE Ellipse UPSes) actually push that limit.
 */
#define USB_CTRL_GET_TIMEOUT	5000
#define USB_CTRL_SET_TIMEOUT	5000


/**
 * struct usb_sg_request - support for scatter/gather I/O
 * @status: zero indicates success, else negative errno
 * @bytes: counts bytes transferred.
 *
 * These requests are initialized using usb_sg_init(), and then are used
 * as request handles passed to usb_sg_wait() or usb_sg_cancel().  Most
 * members of the request object aren't for driver access.
 *
 * The status and bytecount values are valid only after usb_sg_wait()
 * returns.  If the status is zero, then the bytecount matches the total
 * from the request.
 *
 * After an error completion, drivers may need to clear a halt condition
 * on the endpoint.
 */
struct usb_sg_request {
	int			status;
	size_t			bytes;

	/* private:
	 * members below are private to usbcore,
	 * and are not provided for driver access!
	 */
	spinlock_t		lock;

	struct usb_device	*dev;
	int			pipe;

	int			entries;
	struct urb		**urbs;

	int			count;
	struct completion	complete;
};

int usb_sg_init(
	struct usb_sg_request	*io,
	struct usb_device	*dev,
	unsigned		pipe,
	unsigned		period,
	struct scatterlist	*sg,
	int			nents,
	size_t			length,
	gfp_t			mem_flags
);
void usb_sg_cancel(struct usb_sg_request *io);
void usb_sg_wait(struct usb_sg_request *io);


/* ----------------------------------------------------------------------- */

/*
 * For various legacy reasons, Linux has a small cookie that's paired with
 * a struct usb_device to identify an endpoint queue.  Queue characteristics
 * are defined by the endpoint's descriptor.  This cookie is called a "pipe",
 * an unsigned int encoded as:
 *
 *  - direction:	bit 7		(0 = Host-to-Device [Out],
 *					 1 = Device-to-Host [In] ...
 *					like endpoint bEndpointAddress)
 *  - device address:	bits 8-14       ... bit positions known to uhci-hcd
 *  - endpoint:		bits 15-18      ... bit positions known to uhci-hcd
 *  - pipe type:	bits 30-31	(00 = isochronous, 01 = interrupt,
 *					 10 = control, 11 = bulk)
 *
 * Given the device address and endpoint descriptor, pipes are redundant.
 */

/* NOTE:  these are not the standard USB_ENDPOINT_XFER_* values!! */
/* (yet ... they're the values used by usbfs) */
#define PIPE_ISOCHRONOUS		0
#define PIPE_INTERRUPT			1
#define PIPE_CONTROL			2
#define PIPE_BULK			3

#define usb_pipein(pipe)	((pipe) & USB_DIR_IN)
#define usb_pipeout(pipe)	(!usb_pipein(pipe))

#define usb_pipedevice(pipe)	(((pipe) >> 8) & 0x7f)
#define usb_pipeendpoint(pipe)	(((pipe) >> 15) & 0xf)

#define usb_pipetype(pipe)	(((pipe) >> 30) & 3)
#define usb_pipeisoc(pipe)	(usb_pipetype((pipe)) == PIPE_ISOCHRONOUS)
#define usb_pipeint(pipe)	(usb_pipetype((pipe)) == PIPE_INTERRUPT)
#define usb_pipecontrol(pipe)	(usb_pipetype((pipe)) == PIPE_CONTROL)
#define usb_pipebulk(pipe)	(usb_pipetype((pipe)) == PIPE_BULK)

static inline unsigned int __create_pipe(struct usb_device *dev,
		unsigned int endpoint)
{
	return (dev->devnum << 8) | (endpoint << 15);
}

/* Create various pipes... */
#define usb_sndctrlpipe(dev, endpoint)	\
	((PIPE_CONTROL << 30) | __create_pipe(dev, endpoint))
#define usb_rcvctrlpipe(dev, endpoint)	\
	((PIPE_CONTROL << 30) | __create_pipe(dev, endpoint) | USB_DIR_IN)
#define usb_sndisocpipe(dev, endpoint)	\
	((PIPE_ISOCHRONOUS << 30) | __create_pipe(dev, endpoint))
#define usb_rcvisocpipe(dev, endpoint)	\
	((PIPE_ISOCHRONOUS << 30) | __create_pipe(dev, endpoint) | USB_DIR_IN)
#define usb_sndbulkpipe(dev, endpoint)	\
	((PIPE_BULK << 30) | __create_pipe(dev, endpoint))
#define usb_rcvbulkpipe(dev, endpoint)	\
	((PIPE_BULK << 30) | __create_pipe(dev, endpoint) | USB_DIR_IN)
#define usb_sndintpipe(dev, endpoint)	\
	((PIPE_INTERRUPT << 30) | __create_pipe(dev, endpoint))
#define usb_rcvintpipe(dev, endpoint)	\
	((PIPE_INTERRUPT << 30) | __create_pipe(dev, endpoint) | USB_DIR_IN)

static inline struct usb_host_endpoint *
usb_pipe_endpoint(struct usb_device *dev, unsigned int pipe)
{
	struct usb_host_endpoint **eps;
	eps = usb_pipein(pipe) ? dev->ep_in : dev->ep_out;
	return eps[usb_pipeendpoint(pipe)];
}

/*-------------------------------------------------------------------------*/

static inline __u16
usb_maxpacket(struct usb_device *udev, int pipe, int is_out)
{
	struct usb_host_endpoint	*ep;
	unsigned			epnum = usb_pipeendpoint(pipe);

	if (is_out) {
		WARN_ON(usb_pipein(pipe));
		ep = udev->ep_out[epnum];
	} else {
		WARN_ON(usb_pipeout(pipe));
		ep = udev->ep_in[epnum];
	}
	if (!ep)
		return 0;

	/* NOTE:  only 0x07ff bits are for packet size... */
	return usb_endpoint_maxp(&ep->desc);
}

/* ----------------------------------------------------------------------- */

/* translate USB error codes to codes user space understands */
static inline int usb_translate_errors(int error_code)
{
	switch (error_code) {
	case 0:
	case -ENOMEM:
	case -ENODEV:
	case -EOPNOTSUPP:
		return error_code;
	default:
		return -EIO;
	}
}

/* Events from the usb core */
#define USB_DEVICE_ADD		0x0001
#define USB_DEVICE_REMOVE	0x0002
#define USB_BUS_ADD		0x0003
#define USB_BUS_REMOVE		0x0004
extern void usb_register_notify(struct notifier_block *nb);
extern void usb_unregister_notify(struct notifier_block *nb);

/* debugfs stuff */
extern struct dentry *usb_debug_root;

/* LED triggers */
enum usb_led_event {
	USB_LED_EVENT_HOST = 0,
	USB_LED_EVENT_GADGET = 1,
};

#ifdef CONFIG_USB_LED_TRIG
extern void usb_led_activity(enum usb_led_event ev);
#else
static inline void usb_led_activity(enum usb_led_event ev) {}
#endif

#endif  /* __KERNEL__ */

#endif
