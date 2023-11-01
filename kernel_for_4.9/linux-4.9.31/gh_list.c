static struct _mydrv_wq { 

	struct list_head mydrv_worklist; /* Work List */ 
	spinlock_t lock; /* Protect the list */ 
 	wait_queue_head_t todo; /* Synchronize submitter and worker */
	
} mydrv_wq;

struct _mydrv_work { 
	
	 struct list_head mydrv_workitem; /* The work chain */ 
 	void (*worker_func)(void *); /* Work to perform */ 
	 void *worker_data; /* Argument to worker_func */ 
	 /* ... */ /* Other fields */ 
} mydrv_work;


static int mydrv_worker(void *unused) 
{ 
 	DECLARE_WAITQUEUE(wait, current); 
 	void (*worker_func)(void *); 
 	void *worker_data; 
 	struct _mydrv_work *mydrv_work; 
 	set_current_state(TASK_INTERRUPTIBLE); 
 	/* Spin until asked to die */ 
	 while (!asked_to_die()) { 
	 	
 		add_wait_queue(&mydrv_wq.todo, &wait);
		
 		if (list_empty(&mydrv_wq.mydrv_worklist)) { 
 		schedule(); 
	 	/* Woken up by the submitter */ 
 		} else { 
 		set_current_state(TASK_RUNNING); 
 		}
		
 	remove_wait_queue(&mydrv_wq.todo, &wait);
	/* Protect concurrent access to the list */ 
	 spin_lock(&mydrv_wq.lock); 
	 /* Traverse the list and plough through the work functions 
 	present in each node */
 	
 	while (!list_empty(&mydrv_wq.mydrv_worklist)) { 
	 /* Get the first entry in the list */ 
 	mydrv_work = list_entry(mydrv_wq.mydrv_worklist.next, 
 	struct _mydrv_work, mydrv_workitem);
	 
	 worker_func = mydrv_work->worker_func; 
 	worker_data = mydrv_work->worker_data; 
 	/* This node has been processed. Throw it out of the list */ 
 	list_del(mydrv_wq.mydrv_worklist.next); 
 	kfree(mydrv_work); /* Free the node */ 
 	/* Execute the work function in this node */ 
	 spin_unlock(&mydrv_wq.lock); /* Release lock */ 
 	worker_func(worker_data); 
 	spin_lock(&mydrv_wq.lock); /* Re-acquire lock */ 
 	}
	
 	spin_unlock(&mydrv_wq.lock); 
 	set_current_state(TASK_INTERRUPTIBLE); 
 	} 
 set_current_state(TASK_RUNNING); 
 return 0; 
} 

int submit_work(void (*func)(void *data), void *data) 
{ 

 	struct _mydrv_work *mydrv_work; 
 	/* Allocate the work structure */ 
 	mydrv_work = kmalloc(sizeof(struct _mydrv_work), GFP_ATOMIC); 
 	if (!mydrv_work) return -1;
 	 /* Populate the work structure */ 
	 mydrv_work->worker_func = func; /* Work function */ 
 	mydrv_work->worker_data = data; /* Argument to pass */ 
 	spin_lock(&mydrv_wq.lock); /* Protect the list */ 
 	/* Add your work to the tail of the list */ 
 	list_add_tail(&mydrv_work->mydrv_workitem, &mydrv_wq.mydrv_worklist); 
 	/* Wake up the worker thread */
 	wake_up(&mydrv_wq.todo); 
 	spin_unlock(&mydrv_wq.lock); 
 	return 0; 
} 

static int __init mydrv_init(void) 
{ 
 	/* Initialize the lock to protect against concurrent list access */ 
 	spin_lock_init(&mydrv_wq.lock); 
	 /* Initialize the wait queue for communication 
 	between the submitter and the worker */ 
 	init_waitqueue_head(&mydrv_wq.todo); 
 	/* Initialize the list head */ 
 	INIT_LIST_HEAD(&mydrv_wq.mydrv_worklist); 
	 /* Start the worker thread. See Listing 3.4 */ 
 	kernel_thread(mydrv_worker, NULL,  CLONE_FS | CLONE_FILES | CLONE_SIGHAND | SIGCHLD);
 	return 0; 
} 

module_init(mydrv_init)




















#include <linux/workqueue.h> 
struct workqueue_struct *wq;
static int __init 
mydrv_init(void) 
{ 
 /* ... */ 
 /*创建一个服务于workqueue_struct的内核线程*/
 wq = create_singlethread_workqueue("mydrv"); 
 return 0; 
} 
int 
 submit_work(void (*func)(void *data), void *data) 
 { 
 struct work_struct *hardwork; 
 hardwork = kmalloc(sizeof(struct work_struct), GFP_KERNEL); 
 /* Init the work structure */ 
 INIT_WORK(hardwork, func, data); 
 /* Enqueue Work */ 
 queue_work(wq, hardwork); 
 return 0; 
} 









#include <linux/notifier.h> 
#include <asm/kdebug.h> 
#include <linux/netdevice.h> 
#include <linux/inetdevice.h> 


/* Die Notifier Definition */ 
static struct notifier_block my_die_notifier = { 
 .notifier_call = my_die_event_handler, 
}; 

/* Die notification event handler */ 
int  my_die_event_handler(struct notifier_block *self, 
 unsigned long val, void *data) 
{ 
 struct die_args *args = (struct die_args *)data; 
 if (val == 1) { /* '1' corresponds to an "oops" */ 
 printk("my_die_event: OOPs! at EIP=%lx\n", args->regs->eip); 
 } /* else ignore */ 
 return 0; 
} 

/* Net Device notifier definition */ 
static struct notifier_block my_dev_notifier = { 
 .notifier_call = my_dev_event_handler, 
}; 

/* Net Device notification event handler */ 
int my_dev_event_handler(struct notifier_block *self, 
 unsigned long val, void *data) 
{ 
 printk("my_dev_event: Val=%ld, Interface=%s\n", val, 
 ((struct net_device *) data)->name); 
 return 0; 
} 

/* User-defined notifier chain implementation */ 
static BLOCKING_NOTIFIER_HEAD(my_noti_chain); 
static struct notifier_block my_notifier = { 
 .notifier_call = my_event_handler, 
}; 


int my_event_handler(struct notifier_block *self, unsigned long val, void *data) 
{ 
 printk("my_event: Val=%ld\n", val); 
 return 0; 
} 

/* Driver Initialization */ 
static int __init  my_init(void) 
{ 

 	/* ... */ 
	 /* Register Die Notifier */ 
 	register_die_notifier(&my_die_notifier); 
 	/* Register Net Device Notifier */ 
 	register_netdevice_notifier(&my_dev_notifier); 
 	/* Register a user-defined Notifier */ 
 	blocking_notifier_chain_register(&my_noti_chain, &my_notifier); 
 	/* ... */
 
} 





#include <linux/fs.h> 
#include <linux/cdev.h> 
#include <linux/types.h> 
#include <linux/slab.h> 
#include <asm/uaccess.h> 
#include <linux/pci.h> 

#define NUM_CMOS_BANKS 2

/* Per-device (per-bank) structure */ 
struct cmos_dev { 
 unsigned short current_pointer; /* Current pointer within the bank */ 
 unsigned int size; /* Size of the bank */ 
 int bank_number; /* CMOS bank number */ 
 struct cdev cdev; /* The cdev structure */ 
 char name[10]; /* Name of I/O region */ 
 /* ... */ /* Mutexes, spinlocks, wait queues, .. */ 
} *cmos_devp[NUM_CMOS_BANKS]; 

/* File operations structure. Defined in linux/fs.h */ 
static struct file_operations cmos_fops = { 
 .owner = THIS_MODULE, /* Owner */ 
 .open = cmos_open, /* Open method */ 
 .release = cmos_release, /* Release method */ 
 .read = cmos_read, /* Read method */ 
 .write = cmos_write, /* Write method */ 
 .llseek = cmos_llseek, /* Seek method */ 
 .ioctl =  cmos_ioctl, /* Ioctl method */ 
}; 


static dev_t cmos_dev_number; /* Allotted device number */ 
struct class *cmos_class; /* Tie with the device model */ 
//255 * 8
#define CMOS_BANK_SIZE (0xFF*8) 

#define DEVICE_NAME "cmos" 

/**********************************************
CMOS_BANK0_INDEX_PORT  此寄存器中指定了待访问的CMOS存储体0的偏移
CMOS_BANK0_DATA_PORT   对CMOS_BANK0_DATA_PORT 指定的地址读取/写入数据
CMOS_BANK1_INDEX_PORT  此寄存器中指定了待访问的CMOS存储体1的偏移
CMOS_BANK1_DATA_PORT   对CMOS_BANK1_DATA_PORT 指定的地址读取/写入数据
***********************************************/

#define CMOS_BANK0_INDEX_PORT 0x70 
#define CMOS_BANK0_DATA_PORT 0x71 
#define CMOS_BANK1_INDEX_PORT 0x72 
#define CMOS_BANK1_DATA_PORT 0x73 

unsigned char addrports[NUM_CMOS_BANKS] = {CMOS_BANK0_INDEX_PORT, 
 CMOS_BANK1_INDEX_PORT,}; 
unsigned char dataports[NUM_CMOS_BANKS] = {CMOS_BANK0_DATA_PORT, 
 CMOS_BANK1_DATA_PORT,}; 

ssize_t  cmos_read(struct file *file, char *buf, size_t count, loff_t *ppos) 
{ 
 	struct cmos_dev *cmos_devp = file->private_data; 
	 char data[CMOS_BANK_SIZE]; 
 	unsigned char mask; 
 	int xferred = 0, i = 0, l, zero_out; 
 	int start_byte = cmos_devp->current_pointer/8; 
 	int start_bit = cmos_devp->current_pointer%8; 
 	if (cmos_devp->current_pointer >= cmos_devp->size) { 
 		return 0; /*EOF*/ 
 	} 
 	/* Adjust count if it edges past the end of the CMOS bank */ 
 	if (cmos_devp->current_pointer + count > cmos_devp->size) { 
 		count = cmos_devp->size - cmos_devp->current_pointer; 
 	} 
 	/* Get the specified number of bits from the CMOS */ 
	 while (xferred < count) { 
		 data[i] = port_data_in(start_byte, cmos_devp->bank_number) >> start_bit; 
 	 	 xferred += (8 - start_bit); 
 		 if ((start_bit) && (count + start_bit > 8)) { 
 			 data[i] |= (port_data_in (start_byte + 1, cmos_devp->bank_number) << (8 - start_bit)); 
 			 xferred += start_bit; 
 		} 
 		start_byte++; 
 		i++; 
	 } 
 	if (xferred > count) { 
 	/* Zero out (xferred-count) bits from the MSB of the last data byte */ 
 	zero_out = xferred - count; 
 	mask = 1 << (8 - zero_out); 
 	for (l=0; l < zero_out; l++) { 
 	data[i-1] &= ~mask; mask <<= 1; 
 	} 
 	xferred = count; 
 	} 
 	if (!xferred) return -EIO; 
 	/* Copy the read bits to the user buffer */ 
	 if (copy_to_user(buf, (void *)data, ((xferred/8)+1)) != 0) { 
	 return -EIO; 
 	} 
 	/* Increment the file pointer by the number of xferred bits */ 
 	cmos_devp->current_pointer += xferred; 
 	return xferred; /* Number of bits read */ 
} 


/* 
 * Write to a CMOS bank at bit-level granularity. 'count' holds the 
 * number of bits to be written. 
 */ 
ssize_t cmos_write(struct file *file, const char *buf, size_t count, loff_t *ppos) 
{ 
	 struct cmos_dev *cmos_devp = file->private_data; 
 	int xferred = 0, i = 0, l, end_l, start_l; 
 	char *kbuf, tmp_kbuf; 
 	unsigned char tmp_data = 0, mask; 
 	int start_byte = cmos_devp->current_pointer/8; 
 	int start_bit = cmos_devp->current_pointer%8;
 	if (cmos_devp->current_pointer >= cmos_devp->size) { 
 	return 0; /* EOF */ 
 	} 
 	/* Adjust count if it edges past the end of the CMOS bank */ 
	 if (cmos_devp->current_pointer + count > cmos_devp->size) { 
 	count = cmos_devp->size - cmos_devp->current_pointer; 
 	} 
 	kbuf = kmalloc((count/8)+1,GFP_KERNEL); 
 	if (kbuf==NULL) 
 	return -ENOMEM; 
 	/* Get the bits from the user buffer */ 
	 if (copy_from_user(kbuf,buf,(count/8)+1)) { 
	 kfree(kbuf); 
	 return -EFAULT; 
 	} 
 	/* Write the specified number of bits to the CMOS bank */ 
	 while (xferred < count) { 
	 tmp_data = port_data_in(start_byte, cmos_devp->bank_number); 
	 mask = 1 << start_bit; 
 	end_l = 8; 
	 if ((count-xferred) < (8 - start_bit)) { 
 	end_l = (count - xferred) + start_bit; 
 	} 
	 for (l = start_bit; l < end_l; l++) { 
 	tmp_data &= ~mask; mask <<= 1; 
 	} 
 	tmp_kbuf = kbuf[i]; 
 	mask = 1 << end_l; 
 	for (l = end_l; l < 8; l++) { 
 	tmp_kbuf &= ~mask; 
 	mask <<= 1; 
 	} 
 	port_data_out(start_byte, tmp_data |(tmp_kbuf << start_bit), cmos_devp->bank_number); 
 	xferred += (end_l - start_bit); 
	 if ((xferred < count) && (start_bit) && (count + start_bit > 8)) { 
 	tmp_data = port_data_in(start_byte+1, cmos_devp->bank_number); 
 	start_l = ((start_bit + count) % 8); 
	 mask = 1 << start_l; 
 	for (l=0; l < start_l; l++) { 
 	mask >>= 1; 
 	tmp_data &= ~mask; 
 	} 
 	port_data_out((start_byte+1), tmp_data |(kbuf[i] >> (8 - start_bit)), cmos_devp->bank_number); 
 	xferred += start_l; 
	 } 
 	start_byte++; 
	 i++; 
	 } 
 	if (!xferred) return -EIO; 
 	/* Push the offset pointer forward */ 
 	cmos_devp->current_pointer += xferred; 
 	return xferred; /* Return the number of written bits */ 
} 
/* 
 * Read data from specified CMOS bank 
 */ 
unsigned char port_data_in(unsigned char offset, int bank) 
{ 
	 unsigned char data; 
	 
 	if (unlikely(bank >= NUM_CMOS_BANKS)) { 
 		printk("Unknown CMOS Bank\n"); 
 		return 0; 
 	} 
	else { 
		 outb(offset, addrports[bank]); /* Read a byte */ 
 		 data = inb(dataports[bank]); 
 	}
	
 	return data; 
} 
/* 
 * Write data to specified CMOS bank 
 */ 
void port_data_out(unsigned char offset, unsigned char data, int bank) 
{ 
 	if (unlikely(bank >= NUM_CMOS_BANKS)) { 
 		printk("Unknown CMOS Bank\n"); 
 		return; 
 	}
	else { 
		 outb(offset, addrports[bank]); /* Output a byte */ 
 	 	outb(data, dataports[bank]); 
 	}
	
 	return; 
} 





/* 
 * Open CMOS bank 
 */ 
int cmos_open(struct inode *inode, struct file *file) 
{ 
 	struct cmos_dev *cmos_devp; 
 	/* Get the per-device structure that contains this cdev */ 
 	cmos_devp = container_of(inode->i_cdev, struct cmos_dev, cdev); 
 	/* Easy access to cmos_devp from rest of the entry points */ 
 	file->private_data = cmos_devp; 
 	/* Initialize some fields */ 
 	cmos_devp->size = CMOS_BANK_SIZE; 
 	cmos_devp->current_pointer = 0; 
 	return 0; 
} 

/* 
 * Release CMOS bank 
 */ 
int cmos_release(struct inode *inode, struct file *file) 
{ 
 	struct cmos_dev *cmos_devp = file->private_data; 
 	/* Reset file pointer */ 
 	cmos_devp->current_pointer = 0; 
 	return 0; 
} 

/* 
 * Driver Initialization 
 */ 
int __init cmos_init(void) 
{ 
 	int i, ret; 
 	/* Request dynamic allocation of a device major number */ 
 	if (alloc_chrdev_region(&cmos_dev_number, 0, NUM_CMOS_BANKS, DEVICE_NAME) < 0) { 
 		printk(KERN_DEBUG "Can't register device\n"); return -1; 
 	} 
 	/* Populate sysfs entries */ 
	 cmos_class = class_create(THIS_MODULE, DEVICE_NAME); 
	 for (i=0; i<NUM_CMOS_BANKS; i++) { 
	 /* Allocate memory for the per-device structure */ 
		 cmos_devp[i] = kmalloc(sizeof(struct cmos_dev), GFP_KERNEL); 
 		if (!cmos_devp[i]) { 
 			printk("Bad Kmalloc\n"); return -ENOMEM; 
		} 
 	/* Request I/O region */ 
	 sprintf(cmos_devp[i]->name, "cmos%d", i); 
 	if (!(request_region(addrports[i], 2, cmos_devp[i]->name))) { 
		 printk("cmos: I/O port 0x%x is not free.\n", addrports[i]); 
		 return -EIO; 
 		} 
	 /* Fill in the bank number to correlate this device 
	 with the corresponding CMOS bank */ 
 	cmos_devp[i]->bank_number = i; 
	 /* Connect the file operations with the cdev */ 
	 cdev_init(&cmos_devp[i]->cdev, &cmos_fops); 
	 cmos_devp[i]->cdev.owner = THIS_MODULE; 
 	/* Connect the major/minor number to the cdev */ 
 	ret = cdev_add(&cmos_devp[i]->cdev, (cmos_dev_number + i), 1); 
 	if (ret) { 
		 printk("Bad cdev\n"); 
 	return ret; 
 	} 
	 /* Send uevents to udev, so it'll create /dev nodes */ 
	 device_create(cmos_class, NULL, MKDEV(MAJOR(cmos_dev_number), i), "cmos%d", i); 
	 } 
	 printk("CMOS Driver Initialized.\n"); 
 	return 0; 
} 


/* Driver Exit */ 
void __exit cmos_cleanup(void) 
{ 
 	int i; 
 	/* Release the major number */ 
	 unregister_chrdev_region((cmos_dev_number), NUM_CMOS_BANKS); 
 	/* Release I/O region */ 
 	for (i=0; i<NUM_CMOS_BANKS; i++) { 
 		device_destroy (cmos_class, MKDEV(MAJOR(cmos_dev_number), i)); 
 		release_region(addrports[i], 2); 
 		cdev_del(&cmos_devp[i]->cdev); 
 		kfree(cmos_devp[i]); 
 	} 
 	/* Destroy cmos_class */ 
 	class_destroy(cmos_class); 
	 return(); 
} 
module_init(cmos_init); 
module_exit(cmos_cleanup); 













































#include <linux/module.h>  
#include <linux/notifier.h>  
#include <linux/export.h>  
static BLOCKING_NOTIFIER_HEAD(test_chain_head);  
  
int register_test_notifier(struct notifier_block *nb)  
{  
    return blocking_notifier_chain_register(&test_chain_head, nb);  
}  
EXPORT_SYMBOL(register_test_notifier);  
  
int unregister_test_notifier(struct notifier_block *nb)  
{  
    return blocking_notifier_chain_unregister(&test_chain_head, nb);  
}  
EXPORT_SYMBOL(unregister_test_notifier);  
  
int test_notifier_call_chain(unsigned long val)  
{  
    int ret;  
    ret = blocking_notifier_call_chain(&test_chain_head, val, NULL);  
    return notifier_to_errno(ret);  
}  
EXPORT_SYMBOL(test_notifier_call_chain);  
  
MODULE_LICENSE("Dual BSD/GPL");



#include <linux/module.h>  
#include <linux/delay.h>  
#include "notifier_chain.h"  
  
static int producer_init(void)   
{   
    printk(KERN_INFO "%s\n",__FUNCTION__);  
    test_notifier_call_chain(1);  
    msleep(1000);  
    test_notifier_call_chain(1000);  
    return 0;   
}   
       
static void producer_exit(void)   
{        
    printk(KERN_INFO "%s\n",__FUNCTION__);  
}   
       
module_init(producer_init);   
module_exit(producer_exit);   
MODULE_LICENSE("Dual BSD/GPL");  



#include <linux/module.h>  
#include "notifier_chain.h"  
  
static int test_notify(struct notifier_block *self, unsigned long action, void *dev)  
{  
    switch (action) {  
    case 1:  
            printk("action=%ld\n",action);  
              
        break;  
    case 1000:  
            printk("action=%ld\n",action);  
        break;  
    }  
    return NOTIFY_OK;  
}  
  
static struct notifier_block test_nb = {  
    .notifier_call = test_notify,  
};  
  
static int consumer_init(void)   
{   
    printk(KERN_INFO "%s\n",__FUNCTION__);  
    register_test_notifier(&test_nb);  
    return 0;  
}  
static void consumer_exit(void)   
{        
    printk(KERN_INFO "%s\n",__FUNCTION__);  
    unregister_test_notifier(&test_nb);  
}   
       
module_init(consumer_init);   
module_exit(consumer_exit);    
MODULE_LICENSE("Dual BSD/GPL");  















#include <linux/fs.h> 
#include <linux/cdev.h> 
#include <linux/parport.h> 
#include <asm/uaccess.h> 
#include <linux/platform_device.h> 
#define DEVICE_NAME "led" 
static dev_t dev_number; /* Allotted device number */ 
static struct class *led_class; /* Class to which this device belongs */ 
struct cdev led_cdev; /* Associated cdev */ 
struct pardevice *pdev; /* Parallel port device */

/* LED open */ 
int led_open(struct inode *inode, struct file *file) 
{ 
	 return 0; 
} 

/* Write to the LED */ 
ssize_t led_write(struct file *file, const char *buf, size_t count, loff_t *ppos) 
{ 
 	char kbuf; 
 	if (copy_from_user(&kbuf, buf, 1)) return -EFAULT; 
 	/* Claim the port */ 
 	parport_claim_or_block(pdev); 
 	/* Write to the device */ 
 	parport_write_data(pdev->port, kbuf); 
 	/* Release the port */ 
 	parport_release(pdev); 
 	return count; 
} 

/* Release the device */ 
int led_release(struct inode *inode, struct file *file) 
{ 
 	return 0; 
}

/* File Operations */ 
static struct file_operations led_fops = { 
	 .owner = THIS_MODULE, 
 	.open = led_open, 
 	.write = led_write, 
 	.release = led_release, 
}; 

static int led_preempt(void *handle) 
{ 
 	return 1; 
} 

/* Parport attach method */ 
static void led_attach(struct parport *port) 
{ 	
	/* Register the parallel LED device with parport */ 
 	pdev = parport_register_device(port, DEVICE_NAME, led_preempt, NULL, NULL, 0, NULL); 
 	if (pdev == NULL) printk("Bad register\n"); 
} 

/* Parport detach method */ 
static void led_detach(struct parport *port) 
{ 
 /* Do nothing */ 
} 

/* Parport driver operations */ 
static struct parport_driver led_driver = { 
 	.name = "led", 
 	.attach = led_attach, 
 	.detach = led_detach, 
}; 

/* Driver Initialization */ 
int __init led_init(void) 
{ 
	 /* Request dynamic allocation of a device major number */ 
 	if (alloc_chrdev_region(&dev_number, 0, 1, DEVICE_NAME) < 0) { 
 	printk(KERN_DEBUG "Can't register device\n"); 
 	return -1; 
 	} 
	 /* Create the led class */ 
 	led_class = class_create(THIS_MODULE, DEVICE_NAME); 
	if (IS_ERR(led_class)) printk("Bad class create\n");
	/* Connect the file operations with the cdev */ 
      cdev_init(&led_cdev, &led_fops);
      led_cdev.owner = THIS_MODULE; 
     /* Connect the major/minor number to the cdev */ 
     if (cdev_add(&led_cdev, dev_number, 1)) { 
      printk("Bad cdev add\n"); 
     return 1; 
     } 
	 
    class_device_create(led_class, NULL, dev_number, NULL, DEVICE_NAME); 
    /* Register this driver with parport */ 
   if (parport_register_driver(&led_driver)) { 
    printk(KERN_ERR "Bad Parport Register\n"); 
    return -EIO; 
    }
    printk("LED Driver Initialized.\n"); 
    return 0; 
} 
/* Driver Exit */ 
void __exit led_cleanup(void) 
{ 
 	unregister_chrdev_region(dev_number, 1); 
 	class_device_destroy(led_class, dev_number); 
 	class_destroy(led_class); 
 	return; 
} 
module_init(led_init); 
module_exit(led_cleanup); 
MODULE_LICENSE("GPL");






#include <linux/console.h> 
#include <linux/platform_device.h> 
#include <linux/tty.h> 
#include <linux/tty_flip.h> 
#include <linux/serial_core.h> 
#include <linux/serial.h> 
#include <asm/irq.h> 
#include <asm/io.h> 

#define USB_UART_MAJOR 200 /* You've to get this assigned */ 
#define USB_UART_MINOR_START 70 /* Start minor numbering here */ 
#define USB_UART_PORTS 2 /* The phone has 2 USB_UARTs */ 
#define PORT_USB_UART 30 /* UART type. Add this to include/linux/serial_core.h */

/* Each USB_UART has a 3-byte register set consisting of 
 UU_STATUS_REGISTER at offset 0, UU_READ_DATA_REGISTER at
  offset 1, and UU_WRITE_DATA_REGISTER at offset 2 as shown 
 in Table 6.1 */ 
#define USB_UART1_BASE 0xe8000000 /* Memory base for USB_UART1 */ 
#define USB_UART2_BASE 0xe9000000 /* Memory base for USB_UART2 */ 
#define USB_UART_REGISTER_SPACE 0x3 

/* Semantics of bits in the status register */ 
#define USB_UART_TX_FULL 0x20 /* TX FIFO is full */ 
#define USB_UART_RX_EMPTY 0x10 /* TX FIFO is empty */ 
#define USB_UART_STATUS 0x0F /* Parity/frame/overruns? */ 

#define USB_UART1_IRQ 3 /* USB_UART1 IRQ */ 
#define USB_UART2_IRQ 4 /* USB_UART2 IRQ */ 
#define USB_UART_FIFO_SIZE 32 /* FIFO size */ 
#define USB_UART_CLK_FREQ 16000000 

static struct uart_port usb_uart_port[]; /* Defined later on */ 

/* Write a character to the USB_UART port */ 
static void  usb_uart_putc(struct uart_port *port, unsigned char c) 
{ 
 /* Wait until there is space in the TX FIFO of the USB_UART. 
 Sense this by looking at the USB_UART_TX_FULL bit in the 
 status register */ 
 while (__raw_readb(port->membase) & USB_UART_TX_FULL); 
 /* Write the character to the data port*/ 
 __raw_writeb(c, (port->membase+1)); 
} 

/* Read a character from the USB_UART */ 
static unsigned char usb_uart_getc(struct uart_port *port) 
{ 
 /* Wait until data is available in the RX_FIFO */ 
 while (__raw_readb(port->membase) & USB_UART_RX_EMPTY); 
 /* Obtain the data */ 
 return(__raw_readb(port->membase+2)); 
} 

/* Obtain USB_UART status */ 
static unsigned char usb_uart_status(struct uart_port *port) 
{ 
 return(__raw_readb(port->membase) & USB_UART_STATUS); 
} 
/* 
 * Claim the memory region attached to USB_UART port. Called 
 * when the driver adds a USB_UART port via uart_add_one_port(). 
 */ 
static int usb_uart_request_port(struct uart_port *port) 
{ 
	 if (!request_mem_region(port->mapbase, USB_UART_REGISTER_SPACE,  "usb_uart")) { 
 	return -EBUSY; 
	 } 
 	return 0; 
} 

/* Release the memory region attached to a USB_UART port. 
 * Called when the driver removes a USB_UART port via 
 * uart_remove_one_port(). 
 */ 
static void usb_uart_release_port(struct uart_port *port) 
{ 
 	release_mem_region(port->mapbase, USB_UART_REGISTER_SPACE); 
} 
/* 
 * Configure USB_UART. Called when the driver adds a USB_UART port. 
 */ 
static void usb_uart_config_port(struct uart_port *port, int flags) 
{ 
	 if (flags & UART_CONFIG_TYPE && usb_uart_request_port(port) == 0) 
	 { 
 	port->type = PORT_USB_UART; 
 	}	 
} 

/* Receive interrupt handler */ 
static irqreturn_t usb_uart_rxint(int irq, void *dev_id) 
{ 
 	struct uart_port *port = (struct uart_port *) dev_id; 
	 struct tty_struct *tty = port->info->tty; 
 	unsigned int status, data; 
 	/* ... */ 
 	do { 
	 /* ... */ 
 	/* Read data */ 
 	data = usb_uart_getc(port); 
	 /* Normal, overrun, parity, frame error? */ 
 	status = usb_uart_status(port); 
 	/* Dispatch to the tty layer */ 
 	tty_insert_flip_char(tty, data, status); 
 	/* ... */ 
	 } while (more_chars_to_be_read()); /* More chars */ 
 	/* ... */ 
 	tty_flip_buffer_push(tty); 
 	return IRQ_HANDLED; 
}

/* Called when an application opens a USB_UART */ 
static int usb_uart_startup(struct uart_port *port) 
{ 
	 int retval = 0; 
	 /* ... */ 
	 /* Request IRQ */ 
	 if ((retval = request_irq(port->irq, usb_uart_rxint, 0,  "usb_uart", (void *)port))) { 
	 return retval; 
 	} 
	 /* ... */ 
	 return retval; 
} 
/* Called when an application closes a USB_UART */ 
static void usb_uart_shutdown(struct uart_port *port) 
{ 
 	/* ... */ 
 	/* Free IRQ */ 
	 free_irq(port->irq, port); 
 	/* Disable interrupts by writing to appropriate 
	 registers */ 
 	/* ... */ 
} 


/* Set UART type to USB_UART */ 
static const char *usb_uart_type(struct uart_port *port) 
{ 
 	return port->type == PORT_USB_UART ? "USB_UART" : NULL; 
} 
/* Start transmitting bytes */ 
static void usb_uart_start_tx(struct uart_port *port) 
{ 
	 while (1) { 
 	/* Get the data from the UART circular buffer and 
	 write it to the USB_UART's WRITE_DATA register */ 
	 usb_uart_putc(port, port->info->xmit.buf[port->info->xmit.tail]); 
 	/* Adjust the tail of the UART buffer */ 
	port->info->xmit.tail = (port->info->xmit.tail + 1) &  (UART_XMIT_SIZE - 1); 
	 /* Statistics */ 
	 port->icount.tx++; 
	 /* Finish if no more data available in the UART buffer */ 
	 if (uart_circ_empty(&port->info->xmit)) break; 
	 } 
 /* ... */ 

} 

 
/* The UART operations structure */ 
static struct uart_ops usb_uart_ops = { 
 	.start_tx = usb_uart_start_tx, /* Start transmitting */ 
 	.startup = usb_uart_startup, /* App opens USB_UART */ 
	 .shutdown = usb_uart_shutdown, /* App closes USB_UART */ 
 	.type = usb_uart_type, /* Set UART type */ 
 	.config_port = usb_uart_config_port, /* Configure when driver 
	 adds a USB_UART port */ 
	 .request_port = usb_uart_request_port,/* Claim resources associated with a 
	 USB_UART port */ 
	 .release_port = usb_uart_release_port,/* Release resources associated with a 
 	USB_UART port */ 
	#if 0 /* Left unimplemented for the USB_UART */ 
 	.tx_empty = usb_uart_tx_empty, /* Transmitter busy? */ 
	 .set_mctrl = usb_uart_set_mctrl, /* Set modem control */ 
	 .get_mctrl = usb_uart_get_mctrl, /* Get modem control 
	 .stop_tx = usb_uart_stop_tx, /* Stop transmission */ 
	 .stop_rx = usb_uart_stop_rx, /* Stop reception */ 
	 .enable_ms = usb_uart_enable_ms, /* Enable modem status signals */ 
	 .set_termios = usb_uart_set_termios, /* Set termios */ 
	#endif 
}; 

static struct uart_driver usb_uart_reg = { 
	 .owner = THIS_MODULE, /* Owner */ 
	 .driver_name = "usb_uart", /* Driver name */ 
	 .dev_name = "ttyUU", /* Node name */ 
	 .major = USB_UART_MAJOR, /* Major number */ 
	 .minor = USB_UART_MINOR_START, /* Minor number start */ 
	 .nr = USB_UART_PORTS, /* Number of UART ports */ 
	 .cons = &usb_uart_console, /* Pointer to the console 
 	structure. Discussed in Chapter 
	 12, "Video Drivers" */ 
};

/* Called when the platform driver is unregistered */ 
static int usb_uart_remove(struct platform_device *dev) 
{ 
	 platform_set_drvdata(dev, NULL); 
	 /* Remove the USB_UART port from the serial core */ 
	 uart_remove_one_port(&usb_uart_reg, &usb_uart_port[dev->id]); 
	 return 0; 
} 

/* Suspend power management event */ 
static int usb_uart_suspend(struct platform_device *dev, pm_message_t state) 
{ 
 	uart_suspend_port(&usb_uart_reg, &usb_uart_port[dev->id]); 
 	return 0; 
}

/* Resume after a previous suspend */ 
static int usb_uart_resume(struct platform_device *dev) 
{ 
 	uart_resume_port(&usb_uart_reg, &usb_uart_port[dev->id]); 
 	return 0; 
} 

/* Parameters of each supported USB_UART port */ 
static struct uart_port usb_uart_port[] = { 
 	{ 
 		.mapbase = (unsigned int) USB_UART1_BASE, 
 		.iotype = UPIO_MEM, /* Memory mapped */ 
 		.irq = USB_UART1_IRQ, /* IRQ */ 
 		.uartclk = USB_UART_CLK_FREQ, /* Clock HZ */ 
 		.fifosize = USB_UART_FIFO_SIZE, /* Size of the FIFO */ 
 		.ops = &usb_uart_ops, /* UART operations */ 
 		.flags = UPF_BOOT_AUTOCONF, /* UART port flag */ 
 		.line = 0, /* UART port number */ 
 	}, 
 	{ 
	 	.mapbase = (unsigned int)USB_UART2_BASE, 
	 .iotype = UPIO_MEM, /* Memory mapped */ 
 	.irq = USB_UART2_IRQ, /* IRQ */ 
	 .uartclk = USB_UART_CLK_FREQ, /* CLock HZ */ 
 	.fifosize = USB_UART_FIFO_SIZE, /* Size of the FIFO */ 
	 .ops = &usb_uart_ops, /* UART operations */ 
	 .flags = UPF_BOOT_AUTOCONF, /* UART port flag */ 
 	.line = 1, /* UART port number */ 
	 } 
}; 

/* Platform driver probe */ 
static int __init usb_uart_probe(struct platform_device *dev) 
{ 
	 /* ... */ 
	 /* Add a USB_UART port. This function also registers this device 
 	with the tty layer and triggers invocation of the config_port() 
 	entry point */ 
 	uart_add_one_port(&usb_uart_reg, &usb_uart_port[dev->id]); 
 	platform_set_drvdata(dev, &usb_uart_port[dev->id]); 
 	return 0; 
} 

struct platform_device *usb_uart_plat_device1; /* Platform device for USB_UART 1 */ 
struct platform_device *usb_uart_plat_device2; /* Platform device for USB_UART 2 */ 
static struct platform_driver usb_uart_driver = { 
	 .probe = usb_uart_probe, /* Probe method */ 
	  .remove = __exit_p(usb_uart_remove), /* Detach method */
	 .suspend = usb_uart_suspend, /* Power suspend */ 
 	.resume = usb_uart_resume, /* Resume after a suspend */ 
	 .driver = { 
		 .name = "usb_uart", /* Driver name */ 
 	}, 
}; 
/* Driver Initialization */ 
static int __init usb_uart_init(void) 
{ 
 	int retval; 
	 /* Register the USB_UART driver with the serial core */ 	
	 if ((retval = uart_register_driver(&usb_uart_reg))) { 
 	return retval; 
 	} 
 	/* Register platform device for USB_UART 1. Usually called 
 	during architecture-specific setup */ 
	 usb_uart_plat_device1 =  platform_device_register_simple("usb_uart", 0, NULL, 0); 
	 if (IS_ERR(usb_uart_plat_device1)) { 
		 uart_unregister_driver(&usb_uart_reg); 
	 return PTR_ERR(usb_uart_plat_device1); 
 	} 
 	/* Register platform device for USB_UART 2. Usually called 
	 during architecture-specific setup */ 
	 usb_uart_plat_device2 =  platform_device_register_simple("usb_uart", 1, NULL, 0); 
	 if (IS_ERR(usb_uart_plat_device2)) { 
	 	uart_unregister_driver(&usb_uart_reg); 
 	platform_device_unregister(usb_uart_plat_device1); 
	 return PTR_ERR(usb_uart_plat_device2); 
 	} 
	 /* Announce a matching driver for the platform 
	 devices registered above */ 
 	if ((retval = platform_driver_register(&usb_uart_driver))) { 
 	uart_unregister_driver(&usb_uart_reg); 
 	platform_device_unregister(usb_uart_plat_device1); 
 	platform_device_unregister(usb_uart_plat_device2); 
 	} 
	 return 0; 
}

/* Driver Exit */ 
static void __exit usb_uart_exit(void) 
{ 
 	/* The order of unregistration is important. Unregistering the 
	 UART driver before the platform driver will crash the system */
 	 /* Unregister the platform driver */ 
	 platform_driver_unregister(&usb_uart_driver); 
	 /* Unregister the platform devices */ 
	 platform_device_unregister(usb_uart_plat_device1); 
	 platform_device_unregister(usb_uart_plat_device2); 
	 /* Unregister the USB_UART driver */ 
	 uart_unregister_driver(&usb_uart_reg); 
} 
module_init(usb_uart_init); 
module_exit(usb_uart_exit);








/* Driver entry points */ 
static struct file_operations eep_fops = { 
 .owner = THIS_MODULE, 
 .llseek = eep_llseek, 
 .read = eep_read, 
 .ioctl = eep_ioctl, 
 .open = eep_open, 
 .release = eep_release, 
 .write = eep_write, 
}; 
static dev_t dev_number; /* Allotted Device Number */ 
static struct class *eep_class; /* Device class */ 

/* Per-device client data structure for each 
 * memory bank supported by the driver 
 */

struct eep_bank { 
 struct i2c_client *client; /* I2
C client for this bank */ 
 unsigned int addr; /* Slave address of this bank */ 
 unsigned short current_pointer; /* File pointer */ 
 int bank_number; /* Actual memory bank number */ 
 /* ... */ /* Spinlocks, data cache for slow devices,.. */ 
}; 
#define NUM_BANKS 2 /* Two supported banks */ 
#define BANK_SIZE 2048 /* Size of each bank */ 
struct ee_bank *ee_bank_list; /* List of private data 
 structures, one per bank */ 

/* 
 * Device Initialization 
*/


static struct i2c_driver eep_driver = 
{ 
 .driver = { 
 .name = "EEP", /* Name */ 
 }, 
 .id = I2C_DRIVERID_EEP, /* ID */ 
 .attach_adapter = eep_probe, /* Probe Method */ 
 .detach_client = eep_detach, /* Detach Method */ 
}; 
 

int __init eep_init(void) 
{ 

 		int err, i; 
 		/* Allocate the per-device data structure, ee_bank */ 
		//this can use kzalloc because of kzalloc can clear this memory
		//ee_bank_list = kzalloc(sizeof(struct ee_bank)*NUM_BANKS,GFP_KERNEL);
		//kzalloc
 		ee_bank_list = kmalloc(sizeof(struct ee_bank)*NUM_BANKS, GFP_KERNEL); 
	 	memset(ee_bank_list, 0, sizeof(struct ee_bank)*NUM_BANKS); 
	 	/* Register and create the /dev interfaces to access the EEPROM 
 		banks. Refer back to Chapter 5, "Character Drivers" for more details */ 
 		if (alloc_chrdev_region(&dev_number, 0, NUM_BANKS, "eep") < 0)
		{ 
 			printk(KERN_DEBUG "Can't register device\n"); 
 			return -1; 
 		} 
  		eep_class = class_create(THIS_MODULE, DEVICE_NAME); 
 		for (i=0; i < NUM_BANKS;i++) 
		{ 
 			/* Connect the file operations with cdev */ 
 			cdev_init(&ee_bank[i].cdev, &ee_fops); 
 			/* Connect the major/minor number to the cdev */ 
 			if (cdev_add(&ee_bank[i].cdev, (dev_number + i), 1)) { 
 			printk("Bad kmalloc\n"); 
 			return 1; 
 			} 
 			device_create(eep_class, NULL, MKDEV (MAJOR) (dev_number),i), "eeprom%d", i); 
 		} 
	 	/* Inform the I2
		C core about our existence. See the section 
 		"Probing the Device" for the definition of eep_driver */ 
 		err = i2c_add_driver(&eep_driver); 
 		if (err) { 
 		printk("Registering I2C driver failed, errno is %d\n", err); 
 		return err; 
 		} 
 		printk("EEPROM Driver Initialized.\n"); 
	 	return 0; 
} 













 #include <linux/fb.h> 
#include <linux/dma-mapping.h> 
#include <linux/platform_device.h> 
/* Address map of LCD controller registers */ 
#define LCD_CONTROLLER_BASE 0x01000D00 
#define SIZE_REG (*(volatile u32 *)(LCD_CONTROLLER_BASE)) 
#define HSYNC_REG (*(volatile u32 *)(LCD_CONTROLLER_BASE + 4)) 
#define VSYNC_REG (*(volatile u32 *)(LCD_CONTROLLER_BASE + 8)) 
#define CONF_REG (*(volatile u32 *)(LCD_CONTROLLER_BASE + 12)) 
#define CTRL_REG (*(volatile u32 *)(LCD_CONTROLLER_BASE + 16)) 
#define DMA_REG (*(volatile u32 *)(LCD_CONTROLLER_BASE + 20)) 
#define STATUS_REG (*(volatile u32 *)(LCD_CONTROLLER_BASE + 24)) 
#define CONTRAST_REG (*(volatile u32 *)(LCD_CONTROLLER_BASE + 28)) 
#define LCD_CONTROLLER_SIZE 32 
/* Resources for the LCD controller platform device */ 
static struct resource myfb_resources[] = { 
 [0] = { 
 .start = LCD_CONTROLLER_BASE, 
 .end = LCD_CONTROLLER_SIZE, 
 .flags = IORESOURCE_MEM, 
 }, 
}; 
/* Platform device definition */ 
static struct platform_device myfb_device = { 
 .name = "myfb", 
 .id = 0, 
 .dev = { 
 .coherent_dma_mask = 0xffffffff, 
 }, 
 .num_resources = ARRAY_SIZE(myfb_resources), 
 .resource = myfb_resources, 
}; 
/* Set LCD controller parameters */ 
static int 
myfb_set_par(struct fb_info *info) 
{ 
 unsigned long adjusted_fb_start; 
 struct fb_var_screeninfo *var = &info->var; 
 struct fb_fix_screeninfo *fix = &info->fix; 
 /* Top 16 bits of HSYNC_REG hold HSYNC duration, next 8 contain 
 the left margin, while the bottom 8 house the right margin */ 
 HSYNC_REG = (var->hsync_len << 16) | 
 (var->left_margin << 8)| 
 (var->right_margin); 
 /* Top 16 bits of VSYNC_REG hold VSYNC duration, next 8 contain 
 the upper margin, while the bottom 8 house the lower margin */ 
 VSYNC_REG = (var->vsync_len << 16) | 
 (var->upper_margin << 8)| 
 (var->lower_margin); 
 /* Top 16 bits of SIZE_REG hold xres, bottom 16 hold yres */ 
 SIZE_REG = (var->xres << 16) | (var->yres); 
 /* Set bits per pixel, pixel polarity, clock dividers for 
 the pixclock, and color/monochrome mode in CONF_REG */ 
 /* ... */ 
 /* Fill DMA_REG with the start address of the frame buffer 
 coherently allocated from myfb_probe(). Adjust this address 
 to account for any offset to the start of screen area */ 
 adjusted_fb_start = fix->smem_start + 
 (var->yoffset * var->xres_virtual + var->xoffset) * 
 (var->bits_per_pixel) / 8; 
 __raw_writel(adjusted_fb_start, (unsigned long *)DMA_REG); 
 /* Set the DMA burst length and watermark sizes in DMA_REG */ 
 /* ... */ 
 /* Set fixed information */ 
 fix->accel = FB_ACCEL_NONE; /* No hardware acceleration */ 
 fix->visual = FB_VISUAL_TRUECOLOR; /* True color mode */ 
 fix->line_length = var->xres_virtual * var->bits_per_pixel/8; 
 return 0; 
} 
/* Enable LCD controller */ 
static void 
myfb_enable_controller(struct fb_info *info) 
{ 
 /* Enable LCD controller, start DMA, enable clocks and power 
 by writing to CTRL_REG */ 
 /* ... */ 
} 
/* Disable LCD controller */ 
static void 
myfb_disable_controller(struct fb_info *info) 
{ 
 /* Disable LCD controller, stop DMA, disable clocks and power 
 by writing to CTRL_REG */ 
 /* ... */ 
} 
/* Sanity check and adjustment of variables */ 
static int 
myfb_check_var(struct fb_var_screeninfo *var, struct fb_info *info) 
{ 
 /* Round up to the minimum resolution supported by 
 the LCD controller */ 
 if (var->xres < 64) var->xres = 64; 
 if (var->yres < 64) var->yres = 64; 
 /* ... */ 
 /* This hardware supports the RGB565 color format. 
 See the section "Color Modes" for more details */ 
 if (var->bits_per_pixel == 16) { 
 /* Encoding Red */ 
 var->red.length = 5; 
 var->red.offset = 11; 
 /* Encoding Green */ 
 var->green.length = 6; 
 var->green.offset = 5; 
 /* Encoding Blue */ 
 var->blue.length = 5; 
 var->blue.offset = 0; 
 /* No hardware support for alpha blending */ 
 var->transp.length = 0; 
 var->transp.offset = 0; 
 } 
 return 0; 
} 
/* Blank/unblank screen */ 
static int 
myfb_blank(int blank_mode, struct fb_info *info) 
{ 
 switch (blank_mode) { 
 case FB_BLANK_POWERDOWN: 
 case FB_BLANK_VSYNC_SUSPEND: 
 case FB_BLANK_HSYNC_SUSPEND: 
 case FB_BLANK_NORMAL: 
 myfb_disable_controller(info); 
 break; 
 case FB_BLANK_UNBLANK: 
 myfb_enable_controller(info); 
 break; 
 } 
 return 0; 
} 
/* Configure pseudo color palette map */ 
static int 
myfb_setcolreg(u_int color_index, u_int red, u_int green, 
 u_int blue, u_int transp, struct fb_info *info) 
{ 
 if (info->fix.visual == FB_VISUAL_TRUECOLOR) { 
 /* Do any required translations to convert red, blue, green and 
 transp, to values that can be directly fed to the hardware */ 
 /* ... */ 
 ((u32 *)(info->pseudo_palette))[color_index] = 
(red << info->var.red.offset) | 
 (green << info->var.green.offset) | 
 (blue << info->var.blue.offset) | 
 (transp << info->var.transp.offset); 
 } 
 return 0; 
} 
/* Device-specific ioctl definition */ 
#define MYFB_SET_BRIGHTNESS _IOW('M', 3, int8_t) 
/* Device-specific ioctl */ 
static int 
myfb_ioctl(struct fb_info *info, unsigned int cmd, 
 unsigned long arg) 
{ 
 u32 blevel ; 
 switch (cmd) { 
 case MYFB_SET_BRIGHTNESS : 
 copy_from_user((void *)&blevel, (void *)arg, 
 sizeof(blevel)) ; 
 /* Write blevel to CONTRAST_REG */ 
 /* ... */ 
 break; 
 default: 
 return –EINVAL; 
 } 
 return 0; 
} 
/* The fb_ops structure */ 
static struct fb_ops myfb_ops = { 
 .owner = THIS_MODULE, 
 .fb_check_var = myfb_check_var,/* Sanity check */ 
 .fb_set_par = myfb_set_par, /* Program controller registers */ 
 .fb_setcolreg = myfb_setcolreg,/* Set color map */ 
 .fb_blank = myfb_blank, /* Blank/unblank display */ 
 .fb_fillrect = cfb_fillrect, /* Generic function to fill rectangle */ 
 .fb_copyarea = cfb_copyarea, /* Generic function to copy area */ 
 .fb_imageblit = cfb_imageblit, /* Generic function to draw */ 
 .fb_ioctl = myfb_ioctl, /* Device-specific ioctl */ 
}; 
/* Platform driver's probe() routine */ 
static int __init 
myfb_probe(struct platform_device *pdev) 
{ 
 struct fb_info *info; 
 struct resource *res; 
 info = framebuffer_alloc(0, &pdev->dev); 
 /* ... */ 
 /* Obtain the associated resource defined while registering the 
 corresponding platform_device */ 
 res = platform_get_resource(pdev, IORESOURCE_MEM, 0); 
 /* Get the kernel's sanction for using the I/O memory chunk 
 starting from LCD_CONTROLLER_BASE and having a size of 
 LCD_CONTROLLER_SIZE bytes */ 
 res = request_mem_region(res->start, res->end - res->start + 1, pdev->name); 
 /* Fill the fb_info structure with fixed (info->fix) and variable 
 (info->var) values such as frame buffer length, xres, yres, 
 bits_per_pixel, fbops, cmap, etc */ 
initialize_fb_info(info, pdev); /* Not expanded */ 
 info->fbops = &myfb_ops; 
 fb_alloc_cmap(&info->cmap, 16, 0); 
 /* DMA-map the frame buffer memory coherently. info->screen_base 
 holds the CPU address of the mapped buffer, 
 info->fix.smem_start carries the associated hardware address */ 
 info->screen_base = dma_alloc_coherent(0, info->fix.smem_len, 
 (dma_addr_t *)&info->fix.smem_start, 
 GFP_DMA | GFP_KERNEL); 
 /* Set the information in info->var to the appropriate 
 LCD controller registers */ 
 myfb_set_par(info); 
 /* Register with the frame buffer core */ 
 register_framebuffer(info); 
 return 0; 
} 
/* Platform driver's remove() routine */ 
static int 
myfb_remove(struct platform_device *pdev) 
{ 
 struct fb_info *info = platform_get_drvdata(pdev); 
 struct resource *res; 
 /* Disable screen refresh, turn off DMA,.. */ 
 myfb_disable_controller(info); 
 /* Unregister frame buffer driver */ 
 unregister_framebuffer(info); 
 /* Deallocate color map */ 
 fb_dealloc_cmap(&info->cmap); 
 kfree(info->pseudo_palette); 
 /* Reverse of framebuffer_alloc() */ 
 framebuffer_release(info); 
 /* Release memory region */ 
 res = platform_get_resource(pdev, IORESOURCE_MEM, 0); 
 release_mem_region(res->start, res->end - res->start + 1); 
 platform_set_drvdata(pdev, NULL); 
 return 0; 
} 
/* The platform driver structure */ 
static struct platform_driver myfb_driver = { 
 .probe = myfb_probe, 
 .remove = myfb_remove, 
 .driver = { 
 .name = "myfb", 
 }, 
}; 
/* Module Initialization */ 
int __init 
myfb_init(void) 
{ 
 platform_device_add(&myfb_device); 
 return platform_driver_register(&myfb_driver); 
} 
/* Module Exit */ 
void __exit 
myfb_exit(void) 
{ 
 platform_driver_unregister(&myfb_driver); 
 platform_device_unregister(&myfb_device); 
} 
module_init(myfb_init); 
module_exit(myfb_exit); 
 
