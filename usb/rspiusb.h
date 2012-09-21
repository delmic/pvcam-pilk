/* piusb.h */

#include <linux/ioctl.h>
#include <linux/version.h>


#define to_pi_dev(d) container_of( d, struct device_extension, kref )

#define PIUSB_MAGIC     'm'
#define PIUSB_IOCTL_BASE    192
#define PIUSB_GETVNDCMD     _IOR( PIUSB_MAGIC, PIUSB_IOCTL_BASE + 1, ioctl_struct  )
#define PIUSB_SETVNDCMD     _IOW( PIUSB_MAGIC, PIUSB_IOCTL_BASE + 2, ioctl_struct  )
#define PIUSB_WRITEPIPE     _IOW( PIUSB_MAGIC, PIUSB_IOCTL_BASE + 3, ioctl_struct  )
#define PIUSB_READPIPE      _IOR( PIUSB_MAGIC, PIUSB_IOCTL_BASE + 4, ioctl_struct  )
#define PIUSB_SETFRAMESIZE  _IOW( PIUSB_MAGIC, PIUSB_IOCTL_BASE + 5, ioctl_struct  )
#define PIUSB_WHATCAMERA    _IO( PIUSB_MAGIC,  PIUSB_IOCTL_BASE + 6 )
#define PIUSB_USERBUFFER    _IOW( PIUSB_MAGIC, PIUSB_IOCTL_BASE + 7, ioctl_struct  )
#define PIUSB_ISHIGHSPEED   _IO( PIUSB_MAGIC,  PIUSB_IOCTL_BASE + 8 )
#define PIUSB_UNMAP_USERBUFFER  _IOW( PIUSB_MAGIC, PIUSB_IOCTL_BASE + 9, ioctl_struct  )

/* Version Information */
#define DRIVER_VERSION "V1.0.2"
#define DRIVER_AUTHOR  "Princeton Instruments"
#define DRIVER_DESC    "PI USB2.0 Device Driver for Linux"
/* Define these values to match your devices */
#define VENDOR_ID   0x0BD7
#define ST133_PID   0xA010
#define PIXIS_PID   0xA026
/* Get a minor range for your devices from the usb maintainer */
#ifdef CONFIG_USB_DYNAMIC_MINORS
#define PIUSB_MINOR_BASE    0
#else
#define PIUSB_MINOR_BASE    192
#endif
/* prevent races between open() and disconnect() */
static DECLARE_MUTEX (disconnect_sem);
/* local function prototypes */
/* Structure to hold all of our device specific stuff */
struct device_extension {
    struct usb_device*      udev;           /* save off the usb device pointer */
    struct usb_interface*   interface;      /* the interface for this device */
    unsigned char           minor;          /* the starting minor number for this device */
    size_t                  bulk_in_size_returned;
    int                     bulk_in_byte_trk;
    struct urb***           PixelUrb;
    int                     frameIdx;
    int                     urbIdx;
    unsigned int*           maplist_numPagesMapped;
    int                     open;           /* if the port is open or not */
    int                     present;        /* if the device is not disconnected */
    int                     userBufMapped;      /* has the user buffer been mapped? */
    struct scatterlist**    sgl;            /* scatter-gather list for user buffer */
    unsigned int*           sgEntries;
    struct  kref            kref;
    int                     gotPixelData;
    int                     pendingWrite;
    char**                  pendedPixelUrbs;
    int                     iama;           /*PIXIS or ST133 */
    int                     num_frames;     /* the number of frames that will fit in the user buffer */
    int                     active_frame;
    unsigned long           frameSize;
    struct semaphore        sem;
    //FX2 specific endpoints
    unsigned int        hEP[8];
};
typedef struct IOCTL_STRUCT
{
    unsigned char       cmd;
    unsigned long       numbytes;
    unsigned char       dir;//1=out;0=in
    int         endpoint;
    int         numFrames;
    unsigned char *     pData;
}ioctl_struct;

static int 	piusb_ioctl			(struct inode *inode, struct file *file, unsigned int cmd, unsigned long arg);
static int 	piusb_open			(struct inode *inode, struct file *file);
static int 	piusb_release			(struct inode *inode, struct file *file);
static int 	piusb_probe			(struct usb_interface *interface, const struct usb_device_id *id);
static void 	piusb_disconnect		(struct usb_interface *interface);
int		piusb_output			(struct IOCTL_STRUCT*, unsigned char *,int, struct device_extension * );

/*
 * File operations needed when we register this driver.
 * This assumes that this driver NEEDS file operations,
 * of course, which means that the driver is expected
 * to have a node in the /dev directory. If the USB
 * device were for a network interface then the driver
 * would use "struct net_driver" instead, and a serial
 * device would use "struct tty_driver".
 */
static struct file_operations piusb_fops = {
	/*
	 * The owner field is part of the module-locking
	 * mechanism. The idea is that the kernel knows
	 * which module to increment the use-counter of
	 * BEFORE it calls the device's open() function.
	 * This also means that the kernel can decrement
	 * the use-counter again before calling release()
	 * or should the open() function fail.
	 */
	.owner =	THIS_MODULE,
	.ioctl =	piusb_ioctl,
	.open =		piusb_open,
	.release =	piusb_release,
};

/* 
 * usb class driver info in order to get a minor number from the usb core,
 * and to have the device registered with devfs and the driver core
 */
static struct usb_class_driver piusb_class = {
	.name =		"usb/rspiusb%d",
	.fops =		&piusb_fops,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,15)
	.mode =		S_IFCHR | S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH,
#endif
	.minor_base =	PIUSB_MINOR_BASE,
};

/* table of devices that work with this driver */
static struct usb_device_id pi_device_table [] = {
	{ USB_DEVICE( VENDOR_ID, ST133_PID ) },
	{ USB_DEVICE( VENDOR_ID, PIXIS_PID ) },
	{ }					/* Terminating entry */
};
MODULE_DEVICE_TABLE (usb, pi_device_table);
/* usb specific object needed to register this driver with the usb subsystem */
static struct usb_driver piusb_driver = {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,16)
	.owner =	    THIS_MODULE,
#endif
	.name =		    "RSPIUSB",
	.probe =	    piusb_probe,
	.disconnect =	    piusb_disconnect,
	.id_table =	    pi_device_table,
};


