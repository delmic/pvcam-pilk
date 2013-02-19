/* piusb.h */

#include <linux/ioctl.h>
#include <linux/kernel.h>

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


/* Define these values to match your devices */
#define APA_VID   0x0BD7
#define ST133_PID   0xA010
#define PIXIS_PID   0xA026

/* Get a minor range for your devices from the usb maintainer */
#ifdef CONFIG_USB_DYNAMIC_MINORS
#define PIUSB_MINOR_BASE    0
#else
#define PIUSB_MINOR_BASE    192
#endif

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
    unsigned char **		user_buffer;
    int                     iama;           /*PIXIS or ST133 */
    int                     num_frames;     /* the number of frames that will fit in the user buffer */
    int                     active_frame;
    unsigned long           frameSize;
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
} ioctl_struct;


