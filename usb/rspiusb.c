#include <linux/vmalloc.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/smp_lock.h>
#include <linux/completion.h>
#include <asm/uaccess.h>
#include <linux/usb.h>
#include <asm/scatterlist.h>
#include <linux/mm.h>
#include <linux/pci.h> //for scatterlist macros
#include <linux/pagemap.h>
#include "rspiusb.h"

/*
 * rspiusb.c
 *
 * Copyright (C) 2005, 2006 Princeton Instruments
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation version 2 of the License
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */


#ifdef CONFIG_USB_DEBUG
	static int debug = 1;
#else
	static int debug;
#endif
/* Use our own dbg macro */
#undef dbg
#define dbg(format, arg...) do { if (debug) printk(KERN_DEBUG __FILE__ ": " format "\n" , ## arg); } while (0)


/* Module parameters */
module_param(debug, int, 0 );
MODULE_PARM_DESC(debug, "Debug enabled or not");

static void piusb_delete (struct kref *kref);
int MapUserBuffer( struct IOCTL_STRUCT*, struct device_extension * );
int UnMapUserBuffer( struct device_extension * );
static void piusb_write_bulk_callback(struct urb *, struct pt_regs *);
static void piusb_readPIXEL_callback ( struct urb *, struct pt_regs * );

static int lastErr = 0;
static int errCnt=0;


/**
 *	piusb_probe
 *
 *	Called by the usb core when a new device is connected that it thinks
 *	this driver might be interested in.
 */
static int piusb_probe(struct usb_interface *interface, const struct usb_device_id *id)
{
    struct device_extension *pdx = NULL;
    struct usb_host_interface *iface_desc;
    struct usb_endpoint_descriptor *endpoint;
    int i;
    int retval = -ENOMEM;
    dbg("%s - Looking for PI USB Hardware", __FUNCTION__ );
    
    pdx = kmalloc( sizeof( struct device_extension ), GFP_KERNEL );
    if( pdx == NULL )
    {
        err("Out of memory" );
        goto error;
    }
    memset( pdx, 0x00, sizeof( *pdx ) );
    kref_init( &pdx->kref );
    pdx->udev = usb_get_dev( interface_to_usbdev(interface));
    pdx->interface = interface;
    iface_desc = interface->cur_altsetting;
    
    /* See if the device offered us matches what we can accept */
    if ((pdx->udev->descriptor.idVendor != VENDOR_ID) || ((pdx->udev->descriptor.idProduct != PIXIS_PID) && 
        (pdx->udev->descriptor.idProduct != ST133_PID ))) 
        {
        return -ENODEV;
    }
    pdx->iama = pdx->udev->descriptor.idProduct;
    
    if( debug )
    {
        if( pdx->udev->descriptor.idProduct == PIXIS_PID )
            dbg("PIUSB:Pixis Camera Found" );
        else
            dbg("PIUSB:ST133 USB Controller Found" );
        if( pdx->udev->speed  == USB_SPEED_HIGH )
            dbg("Highspeed(USB2.0) Device Attached" );
        else
            dbg("Lowspeed (USB1.1) Device Attached" );
            
        dbg( "NumEndpoints in Configuration: %d", iface_desc->desc.bNumEndpoints );
    }
    for (i = 0; i < iface_desc->desc.bNumEndpoints; ++i) 
    {
        endpoint = &iface_desc->endpoint[i].desc;
        if( debug )
        {
    		dbg( "Endpoint[%d]->bDescriptorType = %d", i, endpoint->bDescriptorType );
            dbg( "Endpoint[%d]->bEndpointAddress = 0x%02X", i, endpoint->bEndpointAddress );
    		dbg( "Endpoint[%d]->bbmAttributes = %d", i, endpoint->bmAttributes );
    		dbg( "Endpoint[%d]->MaxPacketSize = %d\n", i, endpoint->wMaxPacketSize );
        }
        if( ( endpoint->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK ) == USB_ENDPOINT_XFER_BULK )
        {
            if( endpoint->bEndpointAddress & USB_DIR_IN )
                pdx->hEP[i] = usb_rcvbulkpipe( pdx->udev, endpoint->bEndpointAddress );
            else
                pdx->hEP[i] = usb_sndbulkpipe( pdx->udev, endpoint->bEndpointAddress );
        }
    }
    usb_set_intfdata( interface, pdx );
    retval = usb_register_dev( interface, &piusb_class );
    if( retval )
    {
        err( "Not able to get a minor for this device." );
        usb_set_intfdata( interface, NULL );
        goto error;
    }
    pdx->present = 1;
    
    /* we can register the device now, as it is ready */
    pdx->minor = interface->minor;
    /* let the user know what node this device is now attached to */
    dbg ("PI USB2.0 device now attached to piusb-%d", pdx->minor);
    return 0;

error:
    if( pdx )
        kref_put( &pdx->kref, piusb_delete );
    return retval;
}

/**
 *	piusb_delete
 */
static void piusb_delete (struct kref *kref)
{
    struct device_extension *pdx = to_pi_dev( kref );
    
    dbg( "piusb_delete()" );
    usb_put_dev( pdx->udev );
    kfree( pdx );  
}


/**
 *	piusb_open
 */
static int piusb_open (struct inode *inode, struct file *file)
{
    struct device_extension *pdx = NULL;
    struct usb_interface *interface;
    int subminor;
    int retval = 0;
    
    dbg( "Piusb_Open()" );
    subminor = iminor(inode);
    interface = usb_find_interface (&piusb_driver, subminor);
    if (!interface) 
    {
        err ("%s - error, can't find device for minor %d", __FUNCTION__, subminor);
        retval = -ENODEV;
        goto exit_no_device;
    }
    
    pdx = usb_get_intfdata(interface);
    if (!pdx) 
    {
        retval = -ENODEV;
        goto exit_no_device;
    }
    dbg( "Alternate Setting = %d", interface->num_altsetting );
    
    pdx->frameIdx = pdx->urbIdx = 0;
    pdx->gotPixelData = 0;
    pdx->pendingWrite = 0;
    pdx->frameSize = 0;
    pdx->num_frames = 0;
    pdx->active_frame = 0;
    pdx->bulk_in_byte_trk = 0;
    pdx->userBufMapped = 0;
    pdx->pendedPixelUrbs = NULL;
    pdx->sgEntries = NULL;
    pdx->sgl = NULL;
    pdx->maplist_numPagesMapped = NULL;
    pdx->PixelUrb = NULL;
    pdx->bulk_in_size_returned = 0;
    /* increment our usage count for the device */
    kref_get(&pdx->kref);
    /* save our object in the file's private structure */
    file->private_data = pdx;
    exit_no_device:
    return retval;
}

/**
 *	piusb_release
 */
static int piusb_release (struct inode *inode, struct file *file)
{
    struct device_extension *pdx;
    int retval = 0;
    
    dbg( "Piusb_Release()" );
    pdx = (struct device_extension *)file->private_data;
    if (pdx == NULL) 
    {
        dbg ("%s - object is NULL", __FUNCTION__ );
        return -ENODEV;
    }
	/* decrement the count on our device */
    kref_put(&pdx->kref, piusb_delete);
    return retval;
}


/**
 *	piusb_ioctl
 */
static int piusb_ioctl (struct inode *inode, struct file *file, unsigned int cmd, unsigned long arg)
{
    struct device_extension *pdx;
    char dummyCtlBuf[] = {0,0,0,0,0,0,0,0};
    unsigned long devRB=0;
    int i = 0;
    int err = 0;
    int retval = 0;
    ioctl_struct ctrl;
    unsigned char *uBuf;
    int numbytes = 0;
    unsigned short controlData = 0;
    
    pdx = (struct device_extension *)file->private_data;
    /* verify that the device wasn't unplugged */
    if (!pdx->present) 
        {
        dbg( "No Device Present\n" );
        return -ENODEV;
    }
	/* fill in your device specific stuff here */
    if( _IOC_DIR( cmd ) & _IOC_READ )
        err = !access_ok( VERIFY_WRITE, (void __user *) arg, _IOC_SIZE( cmd ) );
    else if (_IOC_DIR(cmd) & _IOC_WRITE)
        err =  !access_ok(VERIFY_READ, (void __user *)arg, _IOC_SIZE(cmd));
    if( err )
    {
        printk( KERN_INFO "return with error = %d\n", err );
        return -EFAULT;
    }
    switch( cmd )
	{
        case PIUSB_GETVNDCMD:
            if( copy_from_user( &ctrl, (void __user*)arg, sizeof( ioctl_struct ) ) )
                info( "copy_from_user failed\n" );
            dbg( "%s %x\n", "Get Vendor Command = ",ctrl.cmd );
            retval = usb_control_msg( pdx->udev, usb_rcvctrlpipe( pdx->udev, 0 ), ctrl.cmd, 
                            USB_DIR_IN, 0, 0, &devRB,  ctrl.numbytes, HZ*10 );
            if( ctrl.cmd == 0xF1 )
            {
                dbg( "FW Version returned from HW = %ld.%ld", (devRB>>8),(devRB&0xFF) );
            }
            return devRB;
        case PIUSB_SETVNDCMD:
            if( copy_from_user( &ctrl, (void __user*)arg, sizeof( ioctl_struct ) ) )
                info( "copy_from_user failed\n" );
//            dbg( "%s %x", "Set Vendor Command = ",ctrl.cmd );
            controlData = ctrl.pData[0];
            controlData |= ( ctrl.pData[1] << 8 );
//            dbg( "%s %d", "Vendor Data =",controlData );
            retval = usb_control_msg( pdx->udev, 
                            usb_sndctrlpipe( pdx->udev, 0 ),
                            ctrl.cmd, 
                            (USB_DIR_OUT | USB_TYPE_VENDOR ),/* | USB_RECIP_ENDPOINT), */
                            controlData, 
                            0, 
                            &dummyCtlBuf, 
                            ctrl.numbytes, 
                            HZ*10 );
            return retval;
            break;
        case PIUSB_ISHIGHSPEED:
            return ( ( pdx->udev->speed == USB_SPEED_HIGH ) ? 1 : 0 );
            break;
        case PIUSB_WRITEPIPE:
            if( copy_from_user( &ctrl, (void __user*)arg, _IOC_SIZE( cmd ) ) )
                info( "copy_from_user WRITE_DUMMY failed\n" );
            if( !access_ok( VERIFY_READ, ctrl.pData, ctrl.numbytes ) )
            {
                dbg("can't access pData" );
                return 0;
            }
            piusb_output( &ctrl, ctrl.pData/*uBuf*/, ctrl.numbytes, pdx );
            return ctrl.numbytes;
            break;
        case PIUSB_USERBUFFER:
            if( copy_from_user( &ctrl, (void __user*)arg, sizeof( ioctl_struct ) ) )
                info( "copy_from_user failed\n" );
            return (MapUserBuffer( (ioctl_struct *) &ctrl, pdx ) );
            break;
        case PIUSB_UNMAP_USERBUFFER:
            UnMapUserBuffer( pdx );
            return 0;
            break;
        case PIUSB_READPIPE:
            if( copy_from_user( &ctrl, (void __user*)arg, sizeof( ioctl_struct ) ) )
                info( "copy_from_user failed\n" );
            switch( ctrl.endpoint )
            {
                case 0://ST133 Pixel Data or PIXIS IO
                    if( pdx->iama == PIXIS_PID )
                    {
                        unsigned int numToRead = 0;
                        unsigned int totalRead = 0;
                        uBuf = kmalloc( ctrl.numbytes, GFP_KERNEL );
                        if( !uBuf )
                        {
                            dbg("Alloc for uBuf failed" );
                            return 0;
                        }
                        numbytes = ctrl.numbytes;
                        numToRead = numbytes;
                        dbg( "numbytes to read = %d", numbytes );
                        dbg( "endpoint # %d", ctrl.endpoint );
                        if( copy_from_user( uBuf, ctrl.pData, numbytes ) )
                            dbg("copying ctrl.pData to dummyBuf failed" );
                        do
                        {
                            i = usb_bulk_msg( pdx->udev, pdx->hEP[ctrl.endpoint],(uBuf + totalRead ), 
                                            (numToRead > 64)?64:numToRead,&numbytes, HZ*10 ); //EP0 can only handle 64 bytes at a time
                            if( i )
                            {
                                dbg( "CMD = %s, Address = 0x%02X",((uBuf[3] == 0x02) ? "WRITE":"READ" ), uBuf[1] );
                                dbg( "Number of bytes Attempted to read = %d", (int)ctrl.numbytes );
                                dbg( "Blocking ReadI/O Failed with status %d", i );
                                kfree( uBuf );
                                return -1;
                            }
                            else
                            {
                                dbg( "Pixis EP0 Read %d bytes", numbytes );
                                totalRead += numbytes;
                                numToRead -= numbytes;
                            }
                        }
                        while( numToRead );
                        memcpy( ctrl.pData, uBuf, totalRead );
                        dbg( "Total Bytes Read from PIXIS EP0 = %d", totalRead );
                        ctrl.numbytes = totalRead;
                        if( copy_to_user( (ioctl_struct *)arg, &ctrl, sizeof( ioctl_struct ) ) )
                            dbg("copy_to_user failed in IORB" );
                        kfree( uBuf );
                        return ctrl.numbytes;
                    }
                    else //ST133 Pixel Data
                    {
                        if( !pdx->gotPixelData )
                            return 0;
                        else
                        {
                            pdx->gotPixelData = 0;
                            ctrl.numbytes = pdx->bulk_in_size_returned;
                            pdx->bulk_in_size_returned -= pdx->frameSize;
                            for( i=0; i < pdx->maplist_numPagesMapped[pdx->active_frame]; i++ )
                                SetPageDirty( pdx->sgl[pdx->active_frame][i].page );
                            pdx->active_frame = ( ( pdx->active_frame + 1 ) % pdx->num_frames );
                            return ctrl.numbytes;
                        }
                    }
                    break;
                case 1://ST133IO
                case 4://PIXIS IO
                    uBuf = kmalloc( ctrl.numbytes, GFP_KERNEL );
                    if( !uBuf )
                    {
                        dbg("Alloc for uBuf failed" );
                        return 0;
                    }
                    numbytes = ctrl.numbytes;
//					dbg( "numbytes to read = %d", numbytes );
                    if( copy_from_user( uBuf, ctrl.pData, numbytes ) )
                        dbg("copying ctrl.pData to dummyBuf failed" );
                    i = usb_bulk_msg( pdx->udev, pdx->hEP[ctrl.endpoint],uBuf,
                                numbytes,&numbytes, HZ*10 );
                    if( i )
                    {
                        dbg( "Blocking ReadI/O Failed with status %d", i );
                        kfree( uBuf );
                        return -1;
                    }
                    else
                    {
                        ctrl.numbytes = numbytes;
                        memcpy( ctrl.pData, uBuf, numbytes );
                        if( copy_to_user( (ioctl_struct *)arg, &ctrl, sizeof( ioctl_struct ) ) )
                            dbg("copy_to_user failed in IORB" );
                        kfree( uBuf );
                        return ctrl.numbytes;
                    }
                    break;
		
                case 2://PIXIS Ping
                case 3://PIXIS Pong
                        if( !pdx->gotPixelData )
                            return 0;
                        else
                        {
                            pdx->gotPixelData = 0;
                            ctrl.numbytes = pdx->bulk_in_size_returned;
                            pdx->bulk_in_size_returned -= pdx->frameSize;
                            for( i=0; i < pdx->maplist_numPagesMapped[pdx->active_frame]; i++ )
                                SetPageDirty( pdx->sgl[pdx->active_frame][i].page );
                            pdx->active_frame = ( ( pdx->active_frame + 1 ) % pdx->num_frames );
                            return ctrl.numbytes;
                        }
                        break;
            }
            break;
        case PIUSB_WHATCAMERA:
            return pdx->iama;
        case PIUSB_SETFRAMESIZE:
            dbg("PIUSB_SETFRAMESIZE");
            if( copy_from_user( &ctrl, (void __user*)arg, sizeof( ioctl_struct ) ) )
                info( "copy_from_user failed\n" );
            pdx->frameSize = ctrl.numbytes;
            pdx->num_frames = ctrl.numFrames;
            if( !pdx->sgl )
                pdx->sgl = kmalloc( sizeof ( struct scatterlist *) * pdx->num_frames, GFP_KERNEL );
            if( !pdx->sgEntries )
                pdx->sgEntries = kmalloc( sizeof( unsigned int ) * pdx->num_frames, GFP_KERNEL );
            if( !pdx->PixelUrb )
                pdx->PixelUrb = kmalloc( sizeof( struct urb **) * pdx->num_frames, GFP_KERNEL );
            if( !pdx->maplist_numPagesMapped )
                pdx->maplist_numPagesMapped = vmalloc( sizeof( unsigned int ) * pdx->num_frames );
            if( !pdx->pendedPixelUrbs )
                pdx->pendedPixelUrbs = kmalloc( sizeof( char *) * pdx->num_frames, GFP_KERNEL );
            return 0;
        default:
            dbg( "%s\n", "No IOCTL found" );
            break;
            
    }
    /* return that we did not understand this ioctl call */
    dbg( "Returning -ENOTTY" );
    return -ENOTTY;
}



/**
 *	piusb_disconnect
 *
 *	Called by the usb core when the device is removed from the system.
 *
 *	This routine guarantees that the driver will not submit any more urbs
 *	by clearing pdx->udev.  It is also supposed to terminate any currently
 *	active urbs.  Unfortunately, usb_bulk_msg(), used in piusb_read(), does
 *	not provide any way to do this.  But at least we can cancel an active
 *	write.
 */
static void piusb_disconnect(struct usb_interface *interface)
{
    struct device_extension *pdx;
    int minor = interface->minor;
    lock_kernel( );
    pdx = usb_get_intfdata (interface);
    usb_set_intfdata (interface, NULL);
    /* give back our minor */
    usb_deregister_dev (interface, &piusb_class);
    unlock_kernel( );
    /* prevent device read, write and ioctl */
    pdx->present = 0;
    kref_put( &pdx->kref, piusb_delete );
    dbg("PI USB2.0 device #%d now disconnected\n", minor);
}

/**
 *	piusb_init
 */
static int __init piusb_init(void)
{
    int result;
    /* register this driver with the USB subsystem */
    result = usb_register(&piusb_driver);
    if (result) 
        {
        err("usb_register failed. Error number %d", result);
        return result;
    }
    info("%s: %s",DRIVER_DESC,DRIVER_VERSION);
    return 0;
}

/**
 *	piusb_exit
 */
static void __exit piusb_exit(void)
{
    /* deregister this driver with the USB subsystem */
    usb_deregister(&piusb_driver);
}

int piusb_output( ioctl_struct *io, unsigned char *uBuf,int len, struct device_extension *pdx )
{
    struct urb *urb = NULL;
    int err = 0;
    unsigned char *kbuf = NULL;
	
    urb = usb_alloc_urb( 0, GFP_KERNEL );
    if( urb != NULL )
    {
        kbuf = usb_buffer_alloc( pdx->udev, len, GFP_KERNEL, &urb->transfer_dma );
        if( !kbuf)
        {
            info( "buffer_alloc failed\n" );
            return -ENOMEM;
        }
        memcpy( kbuf, uBuf, len );
        usb_fill_bulk_urb( urb, pdx->udev, pdx->hEP[io->endpoint], kbuf, len, piusb_write_bulk_callback, pdx );
        urb->transfer_flags |= URB_NO_TRANSFER_DMA_MAP;
        err = usb_submit_urb( urb, GFP_KERNEL );
        if( err )
        {
            printk( KERN_INFO "%s %d\n", "WRITE ERROR:submit urb error =", err );
        }
        pdx->pendingWrite = 1;
        usb_free_urb( urb );
    }
    return -EINPROGRESS;
}
int UnMapUserBuffer( struct device_extension *pdx )
{
    int i = 0;
    int k = 0;
    unsigned int epAddr;
    for( k = 0; k < pdx->num_frames; k++ )
    {
        dbg("Killing Urbs for Frame %d", k );
        for( i = 0; i < pdx->sgEntries[k]; i++ )
        {
            usb_kill_urb( pdx->PixelUrb[k][i] );
            usb_free_urb( pdx->PixelUrb[k][i] );
            pdx->pendedPixelUrbs[k][i] = 0;
        }
        dbg( "Urb error count = %d", errCnt );
        errCnt = 0;
        dbg( "Urbs free'd and Killed for Frame %d", k );
    }
    
    for( k = 0; k < pdx->num_frames; k++ )
    {
        if( pdx->iama == PIXIS_PID ) //if so, which EP should we map this frame to
        {
            if( k % 2 )//check to see if this should use EP4(PONG)
            {
                epAddr = pdx->hEP[3];//PONG, odd frames
            }
            else
            {
                epAddr = pdx->hEP[2];//PING, even frames and zero
            }
        }
        else //ST133 only has 1 endpoint for Pixel data transfer
        {
            epAddr = pdx->hEP[0];
        }
        usb_buffer_unmap_sg( pdx->udev, epAddr, pdx->sgl[k], pdx->maplist_numPagesMapped[k] );
        for( i = 0; i < pdx->maplist_numPagesMapped[k]; i++ )
        {
            page_cache_release( pdx->sgl[k][i].page );
        }
        kfree( pdx->sgl[k] );
        kfree( pdx->PixelUrb[k] );
        kfree( pdx->pendedPixelUrbs[k] );
        pdx->sgl[k] = NULL;
        pdx->PixelUrb[k] = NULL;
        pdx->pendedPixelUrbs[k] = NULL;
    }
    kfree( pdx->sgEntries );
    vfree( pdx->maplist_numPagesMapped );
    pdx->sgEntries = NULL;
    pdx->maplist_numPagesMapped = NULL;
    kfree( pdx->sgl );
    kfree( pdx->pendedPixelUrbs );
    kfree( pdx->PixelUrb );
    pdx->sgl = NULL;
    pdx->pendedPixelUrbs = NULL;
    pdx->PixelUrb = NULL;
    return 0;
}
/* MapUserBuffer(
	inputs:
	ioctl_struct *io - structure containing user address, frame #, and size
	struct device_extension *pdx - the PIUSB device extension
	returns:
	int - status of the task
	Notes:
	MapUserBuffer maps a buffer passed down through an ioctl.  The user buffer is Page Aligned by the app
	and then passed down.  The function get_free_pages(...) does the actual mapping of the buffer from user space to 
	kernel space.  From there a scatterlist is created from all the pages.  The next function called is to usb_buffer_map_sg
	which allocated DMA addresses for each page, even coalescing them if possible.  The DMA address is placed in the scatterlist
	structure.  The function returns the number of DMA addresses.  This may or may not be equal to the number of pages that 
	the user buffer uses.  We then build an URB for each DMA address and then submit them.
*/
//int MapUserBuffer( unsigned long uaddr, unsigned long numbytes, unsigned long frameInfo, struct device_extension *pdx )
int MapUserBuffer( struct IOCTL_STRUCT *io, struct device_extension *pdx )
{
    unsigned long uaddr;
    unsigned long numbytes;
    int frameInfo; //which frame we're mapping
    unsigned int epAddr = 0;
    unsigned long count =0;
    int i = 0;
    int k = 0;
    int err = 0;
    struct page **maplist_p;
    int numPagesRequired;
    frameInfo = io->numFrames;
    uaddr = (unsigned long) io->pData;
    numbytes = io->numbytes;
    
    if( pdx->iama == PIXIS_PID ) //if so, which EP should we map this frame to
    {
        if( frameInfo % 2 )//check to see if this should use EP4(PONG)
        {
            epAddr = pdx->hEP[3];//PONG, odd frames
        }
        else
        {
            epAddr = pdx->hEP[2];//PING, even frames and zero
        }
        dbg("Pixis Frame #%d: EP=%d",frameInfo, (epAddr==pdx->hEP[2]) ? 2 : 4 );
    }
    else //ST133 only has 1 endpoint for Pixel data transfer
    {
        epAddr = pdx->hEP[0];
        dbg("ST133 Frame #%d: EP=2",frameInfo );
    }
    count = numbytes;
    dbg("UserAddress = 0x%08lX", uaddr );
    dbg("numbytes = %d", (int)numbytes );
    //number of pages to map the entire user space DMA buffer
    numPagesRequired = ((uaddr & ~PAGE_MASK) + count + ~PAGE_MASK) >> PAGE_SHIFT;
    dbg("Number of pages needed = %d", numPagesRequired );
    maplist_p = vmalloc( numPagesRequired * sizeof(struct page));//, GFP_ATOMIC);
    if (!maplist_p)
    {
        dbg( "Can't Allocate Memory for maplist_p" );
        return -ENOMEM;
    }
	//map the user buffer to kernel memory
    down_write( &current->mm->mmap_sem );	
    pdx->maplist_numPagesMapped[frameInfo] = get_user_pages( current,
                                                            current->mm,
                                                            (uaddr & PAGE_MASK), 
                                                            numPagesRequired,
                                                            WRITE, 
                                                            0, //Don't Force
                                                            maplist_p, 
                                                            NULL );
    up_write(&current->mm->mmap_sem );
    dbg( "Number of pages mapped = %d", pdx->maplist_numPagesMapped[frameInfo] );
    for( i=0; i < pdx->maplist_numPagesMapped[frameInfo]; i++ )
        flush_dcache_page(maplist_p[i]);
    if( !pdx->maplist_numPagesMapped[frameInfo] )
    {
        dbg( "get_user_pages() failed" );
        vfree( maplist_p );
        return -ENOMEM;
    }
	//need to create a scatterlist that spans each frame that can fit into the mapped buffer
    pdx->sgl[frameInfo] = kmalloc( ( pdx->maplist_numPagesMapped[frameInfo] * sizeof( struct scatterlist ) ), GFP_ATOMIC );
    if( !pdx->sgl[frameInfo] )
    {
        vfree( maplist_p );
        dbg("can't allocate mem for sgl");
        return -ENOMEM;
    }
    pdx->sgl[frameInfo][0].page = maplist_p[0];
    pdx->sgl[frameInfo][0].offset = uaddr & ~PAGE_MASK;
    if (pdx->maplist_numPagesMapped[frameInfo] > 1)
    {
        pdx->sgl[frameInfo][0].length = PAGE_SIZE - pdx->sgl[frameInfo][0].offset;
        count -= pdx->sgl[frameInfo][0].length;
        for (k=1; k < pdx->maplist_numPagesMapped[frameInfo] ; k++)
        {
            pdx->sgl[frameInfo][k].offset = 0;
            pdx->sgl[frameInfo][k].page = maplist_p[k];
            pdx->sgl[frameInfo][k].length = ( count < PAGE_SIZE ) ? count : PAGE_SIZE;
            count -= PAGE_SIZE; //example had PAGE_SIZE here;
        }
    }
    else
    {
        pdx->sgl[frameInfo][0].length = count;
    }
    pdx->sgEntries[frameInfo] = usb_buffer_map_sg( pdx->udev, epAddr, pdx->sgl[frameInfo], pdx->maplist_numPagesMapped[frameInfo] );
    dbg("number of sgEntries = %d", pdx->sgEntries[frameInfo] );
    pdx->userBufMapped = 1;
    vfree( maplist_p );
	//Create and Send the URB's for each s/g entry	
    pdx->PixelUrb[frameInfo] = kmalloc( pdx->sgEntries[frameInfo] * sizeof( struct urb *), GFP_KERNEL);
    if( !pdx->PixelUrb[frameInfo] )
    {
        dbg( "Can't Allocate Memory for Urb" );
        return -ENOMEM;
    }
    for( i = 0; i < pdx->sgEntries[frameInfo]; i++ )
    {
        pdx->PixelUrb[frameInfo][i] = usb_alloc_urb( 0, GFP_KERNEL );//0 because we're using BULK transfers
        usb_fill_bulk_urb( pdx->PixelUrb[frameInfo][i], 
                    pdx->udev, 
                    epAddr,
                    (dma_addr_t*)sg_dma_address( &pdx->sgl[frameInfo][i] ), 
                    sg_dma_len( &pdx->sgl[frameInfo][i] ), 
                    piusb_readPIXEL_callback, 
                    (void *)pdx );
        pdx->PixelUrb[frameInfo][i]->transfer_dma = sg_dma_address( &pdx->sgl[frameInfo][i] );
        pdx->PixelUrb[frameInfo][i]->transfer_flags = URB_NO_TRANSFER_DMA_MAP | URB_NO_INTERRUPT;
    }
    pdx->PixelUrb[frameInfo][--i]->transfer_flags &= ~URB_NO_INTERRUPT;  //only interrupt when last URB completes
    pdx->pendedPixelUrbs[frameInfo] = kmalloc( ( pdx->sgEntries[frameInfo] * sizeof( char ) ), GFP_KERNEL );
    if( !pdx->pendedPixelUrbs[frameInfo] )
        dbg( "Can't allocate Memory for pendedPixelUrbs" );
    for( i = 0; i < pdx->sgEntries[frameInfo]; i++ )
    {
        err = usb_submit_urb( pdx->PixelUrb[frameInfo][i], GFP_ATOMIC );
        if( err )
        {
            dbg( "%s %d\n", "submit urb error =", err );
            pdx->pendedPixelUrbs[frameInfo][i] = 0;
            return err;
        }
        else
            pdx->pendedPixelUrbs[frameInfo][i] = 1;;
    }
    return 0;
}

/**
 *	piusb_write_bulk_callback
 */
static void piusb_write_bulk_callback (struct urb *urb, struct pt_regs *regs)
{
    struct device_extension *pdx = (struct device_extension *)urb->context;
    
    /* sync/async unlink faults aren't errors */
    if (urb->status && !(urb->status == -ENOENT || urb->status == -ECONNRESET)) 
        {
        dbg("%s - nonzero write bulk status received: %d",
            __FUNCTION__, urb->status);
    }
    pdx->pendingWrite = 0;
    usb_buffer_free( urb->dev, urb->transfer_buffer_length, urb->transfer_buffer, urb->transfer_dma );
}

static void piusb_readPIXEL_callback ( struct urb *urb, struct pt_regs *regs )
{
    int i=0;
    struct device_extension *pdx  = ( struct device_extension *) urb->context;
    if( urb->status && !( urb->status == -ENOENT || urb->status == -ECONNRESET ) )
    {
        dbg("%s - nonzero read bulk status received: %d", __FUNCTION__, urb->status);
        dbg( "Error in read EP2 callback" );
        dbg( "FrameIndex = %d", pdx->frameIdx );
        dbg( "Bytes received before problem occurred = %d", pdx->bulk_in_byte_trk );
        dbg( "Urb Idx = %d", pdx->urbIdx );
        pdx->pendedPixelUrbs[pdx->frameIdx][pdx->urbIdx] = 0;
    }
    else
    {
        pdx->bulk_in_byte_trk += urb->actual_length;
        {
            i = usb_submit_urb( urb, GFP_ATOMIC ); //resubmit the URB
            if( i )
            {
                errCnt++;
                if( i != lastErr )
                {
                    dbg("submit urb in callback failed with error code %d", i );
                    lastErr = i;
                }
            }
            else
            {
                pdx->urbIdx++;  //point to next URB when we callback
                if( pdx->bulk_in_byte_trk >= pdx->frameSize )
                {
                    pdx->bulk_in_size_returned = pdx->bulk_in_byte_trk;
                    pdx->bulk_in_byte_trk = 0;
                    pdx->gotPixelData = 1;
                    pdx->frameIdx = ( ( pdx->frameIdx + 1 ) % pdx->num_frames );
                    pdx->urbIdx = 0;
                }
            }
        }
    }
} 

module_init ( piusb_init );
module_exit ( piusb_exit );

MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_LICENSE("GPL v2");

