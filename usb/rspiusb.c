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

#include <linux/vmalloc.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/completion.h>
#include <linux/mutex.h>
#include <asm/uaccess.h>
#include <linux/usb.h>
#include <asm/scatterlist.h>
#include <linux/mm.h>
#include <linux/pci.h> //for scatterlist macros
#include <linux/pagemap.h>
#include "rspiusb.h"

#ifdef CONFIG_USB_DEBUG
  static int debug = 1;
#else
  static int debug;
#endif
/* Use our own dbg macro */
#undef dbg
#define dbg(format, arg...) do { if (debug) printk(KERN_DEBUG "rspiusb: " format "\n" , ## arg); } while (0)

/* Version Information */
#define DRIVER_VERSION "V1.0.3"
#define DRIVER_DESC    "PI USB2.0 Device Driver for Linux"

static void piusb_readPIXEL_callback ( struct urb * );
static struct usb_driver piusb_driver;

static int lastErr;
static int errCnt;

static DEFINE_MUTEX(ioctl_mutex); // FIXME: should be per device (-> device extension)

/**
 *  piusb_write_bulk_callback
 *  called when the urb submitted by piusb_write_bulk is done writing.
 */
static void piusb_write_bulk_callback (struct urb *urb)
{
    struct device_extension *pdx = urb->context;
    int status = urb->status;

    /* sync/async unlink faults aren't errors */
    if (status) {
    	if (status == -ENOENT || status == -ECONNRESET || status == -ESHUTDOWN) {
    		dev_dbg(&urb->dev->dev,
    					"%s - nonzero write bulk early end, status: %d",
    					__func__, -status);
    	} else {
    		dev_dbg(&urb->dev->dev,
    					"%s - nonzero write bulk status received: %d",
    					__func__, -status);
    	}
    }
    pdx->pendingWrite = 0;
    kfree(urb->transfer_buffer);
}

/**
 * Called from user-space (via the IOCTL) to send some data to one of the output
 * bulk endpoints (eg: 1 or 8).
 */
int piusb_write_bulk( ioctl_struct *io, unsigned char *uBuf, int len, struct device_extension *pdx )
{
    struct urb *urb = NULL;
    int err = 0;
    unsigned char *kbuf = NULL;

    // TODO: return the number of bytes submitted or the error?
    urb = usb_alloc_urb( 0, GFP_KERNEL );
    if( urb != NULL )
    {        
        kbuf = kmalloc(len, GFP_KERNEL);                                  
        if (kbuf == NULL) 
        {                                                      
        	dev_err(&pdx->udev->dev, "buffer_alloc failed\n");
            return -ENOMEM;                                           
        }                                                                 
        if (copy_from_user(kbuf, uBuf, len))
        {                           
        	dev_err(&pdx->udev->dev, "copy_from_user failed\n");
            return -EFAULT;                                           
        }                                                                 
              
        usb_fill_bulk_urb( urb, pdx->udev, pdx->hEP[io->endpoint], kbuf, len, piusb_write_bulk_callback, pdx );
        
        err = usb_submit_urb( urb, GFP_KERNEL );
        if (err) {
			dev_err(&pdx->udev->dev, "WRITE ERROR:submit urb error = %d\n", err);
        }
        pr_info("sending %d bytes to pipe %d\n", len, io->endpoint);
        pdx->pendingWrite = 1;
        usb_free_urb( urb );
    }
    return -EINPROGRESS;
}

// Next 2 functions are directly from core/usb.c, where they have been
// disabled because there is no user in-kernel.
// A possibility would be to use directly dma_(un)map_sg. (pipe is always IN)

/**
 * usb_buffer_map_sg - create scatterlist DMA mapping(s) for an endpoint
 * @dev: device to which the scatterlist will be mapped
 * @is_in: mapping transfer direction
 * @sg: the scatterlist to map
 * @nents: the number of entries in the scatterlist
 *
 * Return value is either < 0 (indicating no buffers could be mapped), or
 * the number of DMA mapping array entries in the scatterlist.
 *
 * The caller is responsible for placing the resulting DMA addresses from
 * the scatterlist into URB transfer buffer pointers, and for setting the
 * URB_NO_TRANSFER_DMA_MAP transfer flag in each of those URBs.
 *
 * Top I/O rates come from queuing URBs, instead of waiting for each one
 * to complete before starting the next I/O.   This is particularly easy
 * to do with scatterlists.  Just allocate and submit one URB for each DMA
 * mapping entry returned, stopping on the first error or when all succeed.
 * Better yet, use the usb_sg_*() calls, which do that (and more) for you.
 *
 * This call would normally be used when translating scatterlist requests,
 * rather than usb_buffer_map(), since on some hardware (with IOMMUs) it
 * may be able to coalesce mappings for improved I/O efficiency.
 *
 * Reverse the effect of this call with usb_buffer_unmap_sg().
 */
int usb_buffer_map_sg(const struct usb_device *dev, int is_in,
		      struct scatterlist *sg, int nents)
{
	struct usb_bus		*bus;
	struct device		*controller;

	if (!dev
			|| !(bus = dev->bus)
			|| !(controller = bus->controller)
			|| !controller->dma_mask)
		return -EINVAL;
	pr_info( "usb_buffer_map_sg: controller=%p, sg=%p, nents=%d, is_in=%d",
			controller, sg, nents, is_in);

	/* FIXME generic api broken like pci, can't report errors */
	return dma_map_sg(controller, sg, nents,
			is_in ? DMA_FROM_DEVICE : DMA_TO_DEVICE) ? : -ENOMEM;
}

/**
 * usb_buffer_unmap_sg - free DMA mapping(s) for a scatterlist
 * @dev: device to which the scatterlist will be mapped
 * @is_in: mapping transfer direction
 * @sg: the scatterlist to unmap
 * @n_hw_ents: the positive return value from usb_buffer_map_sg
 *
 * Reverses the effect of usb_buffer_map_sg().
 */
void usb_buffer_unmap_sg(const struct usb_device *dev, int is_in,
			 struct scatterlist *sg, int n_hw_ents)
{
	struct usb_bus		*bus;
	struct device		*controller;

	if (!dev
			|| !(bus = dev->bus)
			|| !(controller = bus->controller)
			|| !controller->dma_mask)
		return;

	dma_unmap_sg(controller, sg, n_hw_ents,
			is_in ? DMA_FROM_DEVICE : DMA_TO_DEVICE);
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
        usb_buffer_unmap_sg( pdx->udev, usb_pipein(epAddr), pdx->sgl[k], pdx->maplist_numPagesMapped[k] );
        //dma_unmap_sg( pdx->udev->bus->controller, pdx->sgl[k], pdx->maplist_numPagesMapped[k], DMA_FROM_DEVICE);
        for( i = 0; i < pdx->maplist_numPagesMapped[k]; i++ )
        {
            page_cache_release( sg_page(&(pdx->sgl[k][i])) );
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
int MapUserBuffer(ioctl_struct *io, struct device_extension *pdx )
{
    unsigned long uaddr;
    unsigned long numbytes;
    int frameInfo; //which frame we're mapping
    unsigned int epAddr = 0;
    unsigned long count =0;
    int i = 0;
    int k = 0;
    int err = 0;
    int ret;
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
    maplist_p = vmalloc( numPagesRequired * sizeof(struct page*));//, GFP_ATOMIC);
    if (!maplist_p)
    {
        dbg( "Can't Allocate Memory for maplist_p" );
        return -ENOMEM;
    }
    // Note: this is similar to videobuf2-dma-contig.c vb2_dc_get_userptr()
  //map the user buffer to kernel memory
    down_write( &current->mm->mmap_sem ); 
    ret = get_user_pages(current, current->mm, (uaddr & PAGE_MASK),
                         numPagesRequired, WRITE, 0, //Don't Force
                         maplist_p, NULL);
    up_write(&current->mm->mmap_sem );
    if( numPagesRequired != ret )
    {
        dbg( "get_user_pages() failed with %d", ret);
        vfree( maplist_p );
        // TODO: put_page
        return -ENOMEM;
    }
    pdx->maplist_numPagesMapped[frameInfo] = ret;
    dbg( "Number of pages mapped = %d", pdx->maplist_numPagesMapped[frameInfo] );
    for( i=0; i < pdx->maplist_numPagesMapped[frameInfo]; i++ )
        flush_dcache_page(maplist_p[i]);
    //need to create a scatterlist that spans each frame that can fit into the mapped buffer
    pdx->sgl[frameInfo] = kmalloc( ( pdx->maplist_numPagesMapped[frameInfo] * sizeof( struct scatterlist ) ), GFP_ATOMIC );
    if( !pdx->sgl[frameInfo] )
    {
        vfree( maplist_p );
        dbg("can't allocate mem for sgl");
        return -ENOMEM;
    }
    
    sg_init_table( pdx->sgl[frameInfo], pdx->maplist_numPagesMapped[frameInfo] );    
    sg_assign_page(&(pdx->sgl[frameInfo][0]), maplist_p[0]);    
    pdx->sgl[frameInfo][0].offset = uaddr & ~PAGE_MASK;
    if (pdx->maplist_numPagesMapped[frameInfo] > 1)
    {
        pdx->sgl[frameInfo][0].length = PAGE_SIZE - pdx->sgl[frameInfo][0].offset;
        count -= pdx->sgl[frameInfo][0].length;
        for (k=1; k < pdx->maplist_numPagesMapped[frameInfo] ; k++)
        {
            sg_assign_page(&(pdx->sgl[frameInfo][k]), maplist_p[k]);
            pdx->sgl[frameInfo][k].offset = 0;            
            pdx->sgl[frameInfo][k].length = ( count < PAGE_SIZE ) ? count : PAGE_SIZE;
            count -= PAGE_SIZE; //example had PAGE_SIZE here;            
        }
    }
    else
    {
        pdx->sgl[frameInfo][0].length = count;
    }
    // TODO use usb_sg_init()? usb_buffer_alloc()?
    // cf ff9c895f07d36193c75533bda8193bde8ca99d02

    //ret = dma_map_sg( pdx->udev->bus->controller, pdx->sgl[frameInfo], pdx->maplist_numPagesMapped[frameInfo], DMA_FROM_DEVICE);
    // + check for ret == 0
    ret = usb_buffer_map_sg( pdx->udev, usb_pipein(epAddr), pdx->sgl[frameInfo], pdx->maplist_numPagesMapped[frameInfo] );
	if (ret < 0) {
		vfree(maplist_p);
		pr_info( "usb_buffer_map_sg failed" );
		return -EINVAL;
	}

	pdx->sgEntries[frameInfo] = ret;
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
                    (void*) (unsigned long) sg_dma_address( &pdx->sgl[frameInfo][i] ), 
                    sg_dma_len( &pdx->sgl[frameInfo][i] ), 
                    piusb_readPIXEL_callback, 
                    (void *)pdx );
        pdx->PixelUrb[frameInfo][i]->transfer_dma = sg_dma_address( &pdx->sgl[frameInfo][i] );
        pdx->PixelUrb[frameInfo][i]->transfer_flags = URB_NO_TRANSFER_DMA_MAP | URB_NO_INTERRUPT;
    }
    pdx->PixelUrb[frameInfo][i-1]->transfer_flags &= ~URB_NO_INTERRUPT;  //only interrupt when last URB completes
    pdx->pendedPixelUrbs[frameInfo] = kmalloc( ( pdx->sgEntries[frameInfo] * sizeof( char ) ), GFP_KERNEL );
    if( !pdx->pendedPixelUrbs[frameInfo] )
        dbg( "Can't allocate Memory for pendedPixelUrbs" );
    for( i = 0; i < pdx->sgEntries[frameInfo]; i++ )
    {
        //err = usb_submit_urb( pdx->PixelUrb[frameInfo][i], GFP_ATOMIC );
        err = usb_submit_urb( pdx->PixelUrb[frameInfo][i], GFP_KERNEL );
        if( err )
        {
            dbg( "submit urb for entry %d error = %d\n", i, err);
            pdx->pendedPixelUrbs[frameInfo][i] = 0;
            return err;
        }
        else
            pdx->pendedPixelUrbs[frameInfo][i] = 1;
    }
    return 0;
}


/**
 * DEBUG: equivalent of UnMapUserBuffer
 */
int FreeFrameBuffer( struct device_extension *pdx )
{
    int i = 0;
    int k = 0;
    unsigned int epAddr;

    for( k = 0; k < pdx->num_frames; k++ )
    {
        for (i = 0; i < pdx->sgEntries[k]; i++) {
//			dbg("Killing Urbs %d for Frame %d", i, k );
			usb_kill_urb( pdx->PixelUrb[k][i] );
			usb_free_coherent(pdx->udev, pdx->PixelUrb[k][i]->transfer_buffer_length,
					pdx->PixelUrb[k][i]->transfer_buffer, pdx->PixelUrb[k][i]->transfer_dma);
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
        kfree( pdx->PixelUrb[k] );
        kfree( pdx->pendedPixelUrbs[k] );
        pdx->PixelUrb[k] = NULL;
        pdx->pendedPixelUrbs[k] = NULL;
    }
    kfree(pdx->user_buffer);
    pdx->user_buffer = NULL;

    kfree( pdx->sgEntries );
    vfree( pdx->maplist_numPagesMapped );
    pdx->sgEntries = NULL;
    pdx->maplist_numPagesMapped = NULL;
    kfree( pdx->pendedPixelUrbs );
    kfree( pdx->PixelUrb );
    pdx->pendedPixelUrbs = NULL;
    pdx->PixelUrb = NULL;
    return 0;
}

/* DEBUG:
 * Same as MapUserBuffer, but doesn't actually map the user buffer, just allocates
 * our own urbs.
 */

/*
 * Maximum size for each allocation block, if it's too big, it might have some
 * fail being allocated. So we use 100 Kb. 1Mb seemed to work fine too, but at
 * least we are sure to test multiple URBs.
 */
#define MAX_BUFFER_SIZE (102400)
int AllocateFrameBuffer(ioctl_struct *io, struct device_extension *pdx )
{
    unsigned long numbytes = io->numbytes; // length of the buffer
    int frameInfo = io->numFrames; // which frame we're mapping
    unsigned int epAddr;
    int i = 0;
    int err = 0;
    int retval = 0;
    struct urb *urb = NULL;
    void *buf = NULL;
    unsigned int buf_size, size_last;
    int numurb;

    pdx->user_buffer[frameInfo] = io->pData; // address of the user buffer, to copy it back

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
    dbg("UserAddress = %p", io->pData );

    buf_size = min((int)numbytes, MAX_BUFFER_SIZE);
    numurb = ((int)numbytes / buf_size);
    size_last = ((int)numbytes % buf_size);
    if (size_last)
    	numurb++;
    dbg("numbytes = %d => %d urbs of %d bytes", (int)numbytes, numurb, buf_size);
    pdx->sgEntries[frameInfo] = numurb;

	pdx->PixelUrb[frameInfo] = kmalloc( numurb * sizeof( struct urb *), GFP_KERNEL);
	if( !pdx->PixelUrb[frameInfo] )
	{
		dbg( "Can't Allocate Memory for Urb" );
		return -ENOMEM;
	}

	pdx->pendedPixelUrbs[frameInfo] = kmalloc(numurb * ( sizeof( char ) ), GFP_KERNEL );
	if( !pdx->pendedPixelUrbs[frameInfo] ) {
		dbg( "Can't allocate Memory for pendedPixelUrbs" );
		retval = -ENOMEM;
		goto error;
	}

    for (i=0; i < numurb; i++) {
    	int size = buf_size;
    	if (size_last && i == (numurb -1))
    		size = size_last;

		urb = usb_alloc_urb( 0, GFP_KERNEL );
		if (!urb) {
			retval = -ENOMEM;
			goto error;
		}

		buf = usb_alloc_coherent(pdx->udev, size, GFP_KERNEL, &urb->transfer_dma);
		if (!buf) {
			retval = -ENOMEM;
			goto error;
		}

		usb_fill_bulk_urb(urb, pdx->udev, epAddr, buf, size,
				          piusb_readPIXEL_callback, (void *)pdx);
		urb->transfer_flags = URB_NO_TRANSFER_DMA_MAP;
		pdx->PixelUrb[frameInfo][i] = urb;
    }
    /* Old version used to only activate interrupt for the last URB. It might
     * work, but piusb_readPIXEL_callback() need some changes for that.
     */
//    pdx->PixelUrb[frameInfo][numurb-1]->transfer_flags &= ~URB_NO_INTERRUPT;

	for (i=0; i < numurb; i++) {
		err = usb_submit_urb( pdx->PixelUrb[frameInfo][i], GFP_KERNEL );
		if (err) {
			dbg( "submit urb for entry %d error = %d", i, err);
			pdx->pendedPixelUrbs[frameInfo][i] = 0;
			retval = err;
			goto error_kill;
		}

		pdx->pendedPixelUrbs[frameInfo][i] = 1;
	}
	return 0;

error_kill:
error:
	// FIXME: need to unfree every single urb already allocated
	if (urb) {
		usb_free_coherent(pdx->udev, numbytes, buf, urb->transfer_dma);
		usb_free_urb(urb);
	}
    return retval;
}




static void piusb_readPIXEL_callback ( struct urb *urb )
{
    struct device_extension *pdx = urb->context;
    int status = urb->status;

    if (status &&
    	// for these 3 errors -> we might have still received something
    	!(status == -ENOENT || status == -ECONNRESET || status == -ESHUTDOWN)) {
		dbg("%s - nonzero read bulk status received: %d", __func__, urb->status);
		dbg( "Error in read EP2 callback" );
		dbg( "FrameIndex = %d", pdx->frameIdx );
		dbg( "Bytes received before problem occurred = %d", pdx->bulk_in_byte_trk );
		dbg( "Urb Idx = %d", pdx->urbIdx );
		pdx->pendedPixelUrbs[pdx->frameIdx][pdx->urbIdx] = 0;
		return;
    }

	pdx->bulk_in_byte_trk += urb->actual_length;

	pdx->urbIdx++;  //point to next URB when we callback
	if( pdx->bulk_in_byte_trk >= pdx->frameSize )
	{
		pdx->bulk_in_size_returned = pdx->bulk_in_byte_trk;
		pdx->bulk_in_byte_trk = 0;
		pdx->gotPixelData = 1;
		pdx->frameIdx = ( ( pdx->frameIdx + 1 ) % pdx->num_frames );
		pdx->urbIdx = 0;
	}

	// You cannot submit it here if using the in-kernel buffer, because the data hasn't been copied yet

	// Apparently the user interface expects us to keep listening to the
	// camera until the buffer is unmapped. So resubmit the same URB to
	// keep filling the cyclic buffer. (Unless it has been trying to stop)
	// eg urb->status == -ENOENT means UnMapBuffer has been called
//	if (!urb->status) {
//      int err=0;
//		err = usb_submit_urb( urb, GFP_ATOMIC ); //resubmit the URB
//		if( err && err != -EPERM )
//		{
//			errCnt++;
//			if( err != lastErr )
//			{
//				dbg("submit urb in callback failed with error code %d", -err );
//				lastErr = err;
//			}
//			return;
//		} else if (err == -EPERM)
//			dbg("submit urb in callback failed, due to shutdown" );
} 


static int piusb_read_io(ioctl_struct *ctrl, struct device_extension *pdx,
		ioctl_struct *arg)
{
	struct usb_host_endpoint *ep;
	unsigned int numToRead, maxPacketSize;
	unsigned int totalRead = 0;
	unsigned char *uBuf;
	int numbytes;
	int ret;

	// TODO: see if it is needed to cut it in small pieces, usb_bulk_msg is
	// supposed to automatically do this
	ep = usb_pipe_endpoint(pdx->udev, pdx->hEP[ctrl->endpoint]);
	if (!ep)
		return -ENOENT;
	maxPacketSize = usb_endpoint_maxp(&ep->desc);

	uBuf = kmalloc(ctrl->numbytes, GFP_KERNEL);
	if (!uBuf) {
		dbg("Alloc for uBuf failed");
		return -ENOMEM;
	}
	numbytes = (int) ctrl->numbytes;
	numToRead = (unsigned int) ctrl->numbytes;
	dbg("numbytes to read = %d", numbytes);
	dbg("endpoint # %d", ctrl->endpoint);

	if (copy_from_user(uBuf, ctrl->pData, numbytes)) {
		dbg("copying ctrl->pData to dummyBuf failed");
		kfree(uBuf);
		return -EFAULT;
	}
#if 0
	do {
		ret = usb_bulk_msg(pdx->udev, pdx->hEP[ctrl->endpoint],
				(uBuf + totalRead),
				/* EP0 can only handle 64 bytes at a time */
				min(numToRead, maxPacketSize),
				&numbytes, HZ * 10);
		if (ret) {
			dbg("CMD = %s, Address = 0x%02X",
					((uBuf[3] == 0x02) ? "WRITE" : "READ"),
					uBuf[1]);
			dbg("Number of bytes Attempted to read = %d",
					(int)ctrl->numbytes);
			dbg("Blocking ReadI/O Failed with status %d", ret);
			kfree(uBuf);
			return ret;
		}
		dbg("EP Read %d bytes", numbytes);
		totalRead += numbytes;
		numToRead -= numbytes;
	} while (numToRead);
#else
	ret = usb_bulk_msg(pdx->udev, pdx->hEP[ctrl->endpoint],
			uBuf,
			numToRead,
			&numbytes, HZ * 10);
	if (ret) {
		dbg("CMD = %s, Address = 0x%02X",
				((uBuf[3] == 0x02) ? "WRITE" : "READ"),
				uBuf[1]);
		dbg("Number of bytes Attempted to read = %lu", ctrl->numbytes);
		dbg("Blocking ReadI/O Failed with status %d", ret);
		kfree(uBuf);
		return ret;
	}
	dbg("EP Read %d bytes", numbytes);
	totalRead = numbytes;
#endif

	memcpy(ctrl->pData, uBuf, totalRead);
	dbg("Total Bytes Read from EP[%d] = %d", ctrl->endpoint, totalRead);
	ctrl->numbytes = totalRead;

	if (copy_to_user(arg, ctrl, sizeof(ioctl_struct))) {
		dbg("copy_to_user failed in IORB");
		kfree(uBuf);
		return -EFAULT;
	}

	kfree(uBuf);
	return ctrl->numbytes;
}

#if 0
static int get_pixel_data(struct device_extension *pdx)
{
	int i;
	unsigned long numbytes;

	if (!pdx->gotPixelData)
		return 0;

	pdx->gotPixelData = 0;
	numbytes = pdx->bulk_in_size_returned;
	pdx->bulk_in_size_returned -= pdx->frameSize;

	for (i = 0; i < pdx->maplist_numPagesMapped[pdx->active_frame]; i++)
		SetPageDirty(sg_page(&pdx->sgl[pdx->active_frame][i]));

	pdx->active_frame = ((pdx->active_frame + 1) % pdx->num_frames);

	return numbytes;
}
#else
static int get_pixel_data(struct device_extension *pdx)
{
	struct urb **urbs = pdx->PixelUrb[pdx->active_frame];
	unsigned char *to_buf = pdx->user_buffer[pdx->active_frame];
	unsigned long numbytes;
	int i, err;

	if (!pdx->gotPixelData)
		return 0; /* not yet */

	pdx->gotPixelData = 0;
	numbytes = pdx->bulk_in_size_returned;
	pdx->bulk_in_size_returned -= pdx->frameSize;

	for (i=0; i<pdx->sgEntries[pdx->active_frame]; i++){
		u16 *buf = (urbs[i]->transfer_buffer);
		unsigned int length = urbs[i]->actual_length;

		dbg("Got pixel data of urb %d = %x", i, buf[length/2]);
		if (copy_to_user(to_buf, buf, length))
			dbg("failed to copy pixel data of urb %d to user", i);
		to_buf += length;

		/* try to resubmitting the urb (will fail if buffer is unmapped */
		err = usb_submit_urb(urbs[i], GFP_KERNEL);
		if (err && err != -EPERM) {
			errCnt++;
			if(err != lastErr) {
				dbg("submit urb failed with error code %d", -err);
				lastErr = err;
			}
		} else if (err == -EPERM)
			dbg("submit urb cancelled");
	}

	pdx->active_frame = ((pdx->active_frame + 1) % pdx->num_frames);
	dbg("return %lu bytes of data", numbytes);
	return numbytes;
}
#endif

static long piusb_ioctl (struct file *file, unsigned int cmd, unsigned long arg)
{
    struct device_extension *pdx;
    char dummyCtlBuf[] = {0,0,0,0,0,0,0,0};
    u16 devRB=0;
    int err = 0;
    long retval = 0;
    ioctl_struct ctrl;
    unsigned short controlData;

    pdx = (struct device_extension *)file->private_data;
    mutex_lock(&ioctl_mutex);
    /* verify that the device wasn't unplugged */
    if (!pdx->present) {
        dbg( "No Device Present\n" );
        retval = -ENODEV;
        goto done;
    }

  /* check the ioctl struct can be read/written */
    if(_IOC_DIR(cmd) & _IOC_READ)
        err = !access_ok(VERIFY_WRITE, (void __user *)arg, _IOC_SIZE(cmd));
    else if (_IOC_DIR(cmd) & _IOC_WRITE)
        err = !access_ok(VERIFY_READ, (void __user *)arg, _IOC_SIZE(cmd));
    if( err ) {
    	dev_err(&pdx->udev->dev, "fail to access ioctl data. error = %d\n", err);
        retval = -EFAULT;
        goto done;
    }

    switch (cmd) {
        case PIUSB_GETVNDCMD:
            if (copy_from_user(&ctrl, (void __user*)arg, sizeof(ioctl_struct))) {
                pr_info("copy_from_user failed\n");
				retval = -EFAULT;
				goto done;
    		}
            dbg("Get Vendor Command = %x, pData = %p", ctrl.cmd, ctrl.pData);
            if (ctrl.numbytes != sizeof(devRB)) {
            	dev_err(&pdx->udev->dev, "GETVNDCMD numbytes should be 2, but is %lu\n", ctrl.numbytes);
            	mutex_unlock(&ioctl_mutex);
            	return -EINVAL;
            }
            retval = usb_control_msg(pdx->udev, usb_rcvctrlpipe(pdx->udev, 0),
            			ctrl.cmd, USB_DIR_IN, 0, 0, &devRB, ctrl.numbytes, HZ*10);
            if (ctrl.cmd == 0xF1)
                dbg( "FW Version returned from HW = %d.%d", (devRB>>8), (devRB&0xFF) );
            // FIXME: the user-space lib doesn't seem much happy with the value
            // returned for the FW version (states it's unsupported). Maybe it's
            // a sign that it's not behaving well. Should it return 0 and copy
            // the return value in ctrl.pData (it seems it's a valid pointer)?
            retval = devRB;
            break;

        case PIUSB_SETVNDCMD:
            if (copy_from_user(&ctrl, (void __user*)arg, sizeof(ioctl_struct))) {
                pr_info("copy_from_user failed\n");
                retval = -EFAULT;
				goto done;
    		}
            controlData = (ctrl.pData[1] << 8) | ctrl.pData[0];
            dbg( "Set Vendor Command = %x -> %d",ctrl.cmd, controlData);

            // TODO: not clear whether ctrl.numbytes is supposed to be the size of
            // ctrl.pData of the amount of extra (null) data to send. My guess
            // is that it's related to ctrl.pData (and no data at all can be sent)
            // but for safety, keep sending null data.
            if (ctrl.numbytes > ARRAY_SIZE(dummyCtlBuf)) {
            	dev_err(&pdx->udev->dev, "SETVNDCMD numbytes bigger than possible: %lu\n", ctrl.numbytes);
            	mutex_unlock(&ioctl_mutex);
            	return -EINVAL;
            }

            retval = usb_control_msg(pdx->udev, usb_sndctrlpipe(pdx->udev, 0),
                            ctrl.cmd,
                            (USB_DIR_OUT | USB_TYPE_VENDOR ),/* | USB_RECIP_ENDPOINT), */
                            controlData, 0, dummyCtlBuf, ctrl.numbytes, HZ*10);
            mutex_unlock(&ioctl_mutex);
            dbg( "control msg returned %ld", retval);
            break;

        case PIUSB_ISHIGHSPEED:
            retval = (pdx->udev->speed == USB_SPEED_HIGH) ? 1 : 0;
            break;

        case PIUSB_WRITEPIPE:
        	dbg("PIUSB_WRITEPIPE");
            if (copy_from_user(&ctrl, (void __user*)arg, sizeof(ioctl_struct))) {
                pr_info("copy_from_user failed\n");
                retval = -EFAULT;
				goto done;
            }
            if( !access_ok(VERIFY_READ, ctrl.pData, ctrl.numbytes)) {
                dbg("can't access pData" );
                retval = -EFAULT;
				goto done;
            }
            // TODO: shall we care about pendingWrite?
            piusb_write_bulk(&ctrl, ctrl.pData, ctrl.numbytes, pdx);
            retval = ctrl.numbytes;
            break;

        case PIUSB_USERBUFFER:
            if (copy_from_user(&ctrl, (void __user*)arg, sizeof(ioctl_struct))) {
                pr_info("copy_from_user failed\n");
                retval = -EFAULT;
				goto done;
            }
//            err = MapUserBuffer( (ioctl_struct *) &ctrl, pdx );
            retval = AllocateFrameBuffer( (ioctl_struct *) &ctrl, pdx );
            break;

        case PIUSB_UNMAP_USERBUFFER:
        	dbg("unmapping buffer");
        	retval = FreeFrameBuffer( pdx );
//            UnMapUserBuffer( pdx );
            break;

        case PIUSB_READPIPE:
        	/* Called to receive data from the camera */
            if (copy_from_user(&ctrl, (void __user*)arg, sizeof(ioctl_struct))) {
                pr_info("copy_from_user failed\n");
                retval = -EFAULT;
				goto done;
    		}
        	dbg("PIUSB_READPIPE %d", ctrl.endpoint);

        	/* Depending on the camera, endpoints have different meanings */
        	if (pdx->iama == PIXIS_PID) {
        		switch(ctrl.endpoint) {
				case 0: // PIXIS IO EP0
                case 4: // PIXIS IO EP4
					retval = piusb_read_io(&ctrl, pdx, (ioctl_struct *)arg);
					break;
                case 2://PIXIS Ping
				case 3://PIXIS Pong
					retval = get_pixel_data(pdx);
					break;
				default:
                	retval = -EINVAL;
                	break;
        		}
        	} else { /* ST133 */
        		switch(ctrl.endpoint) {
				case 0://ST133 Pixel Data
					retval = get_pixel_data(pdx);
					break;
				case 1://ST133 IO
					retval = piusb_read_io(&ctrl, pdx, (ioctl_struct *)arg);
					break;
				default:
                	retval = -EINVAL;
                	break;
        		}
        	}
        	break;

        case PIUSB_WHATCAMERA:
            retval = pdx->iama;
            break;

        case PIUSB_SETFRAMESIZE:
            if (copy_from_user(&ctrl, (void __user*)arg, sizeof(ioctl_struct))) {
                pr_info("copy_from_user failed\n");
                retval = -EFAULT;
				goto done;
    		}
            /* don't allow to change it after it has already been allocated */
            if (pdx->PixelUrb) {
            	dev_err(&pdx->udev->dev, "SETFRAMESIZE called while buffer is still mapped\n");
            	retval = -EINVAL;
            	goto done;
            }
            pdx->frameSize = ctrl.numbytes;
            pdx->num_frames = ctrl.numFrames;
            dbg("PIUSB_SETFRAMESIZE to %dx%lu", ctrl.numFrames, ctrl.numbytes);

            /* the checks shouldn't be necessary, but it makes sure there is no leak */
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
            if( !pdx->user_buffer)
                pdx->user_buffer = kmalloc( sizeof(unsigned char *) * pdx->num_frames, GFP_KERNEL );
            break;

        default:
			/* return that we did not understand this ioctl call */
            dbg( "%s\n", "No IOCTL found" );
            retval = -ENOTTY;
            break;
    }

done:
    mutex_unlock(&ioctl_mutex);
    return retval;
}

static void piusb_delete (struct kref *kref)
{
    struct device_extension *pdx = to_pi_dev(kref);

	dev_dbg(&pdx->udev->dev, "%s\n", __func__);
    usb_put_dev(pdx->udev);
    kfree(pdx);
}

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
    pdx->pendingWrite = 0; // FIXME: never read
    pdx->frameSize = 0;
    pdx->num_frames = 0;
    pdx->active_frame = 0;
    pdx->bulk_in_byte_trk = 0;
    pdx->userBufMapped = 0; // FIXME: never read
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
 *  piusb_release
 */
static int piusb_release (struct inode *inode, struct file *file)
{
    struct device_extension *pdx;
    int retval = 0;

    dbg( "Piusb_Release()" );
    pdx = (struct device_extension *)file->private_data;
    if (pdx == NULL)
    {
        dbg ("%s - object is NULL", __func__);
        return -ENODEV;
    }
  /* decrement the count on our device */
    kref_put(&pdx->kref, piusb_delete);
    return retval;
}

/*
 * File operations needed when we register this driver.
 * This assumes that this driver NEEDS file operations,
 * of course, which means that the driver is expected
 * to have a node in the /dev directory. This is for the
 * IOCTL interface.
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
	.unlocked_ioctl =	piusb_ioctl,
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
	.minor_base =	PIUSB_MINOR_BASE,
};

/* table of devices that work with this driver */
static struct usb_device_id pi_device_table [] = {
	{ USB_DEVICE( APA_VID, ST133_PID ) },
	{ USB_DEVICE( APA_VID, PIXIS_PID ) },
	{ }					/* Terminating entry */
};
MODULE_DEVICE_TABLE (usb, pi_device_table);

/**
 *  piusb_probe
 *
 *  Called by the usb core when a new device is connected that it thinks
 *  this driver might be interested in.
 */
static int piusb_probe(struct usb_interface *interface, const struct usb_device_id *id)
{
    struct device_extension *pdx = NULL;
    struct usb_host_interface *iface_desc;
    struct usb_endpoint_descriptor *endpoint;
    int i;
    int retval = -ENOMEM;

    dev_dbg(&interface->dev, "%s - Looking for PI USB Hardware", __func__);

    pdx = kzalloc( sizeof( struct device_extension ), GFP_KERNEL );
    if( pdx == NULL )
    {
    	dev_err(&interface->dev, "Out of memory\n");
        goto error;
    }
    kref_init( &pdx->kref );
    pdx->udev = usb_get_dev( interface_to_usbdev(interface));
    pdx->interface = interface;
    iface_desc = interface->cur_altsetting;

    /* See if the device offered us matches what we can accept */
    if ((pdx->udev->descriptor.idVendor != APA_VID) ||
    	((pdx->udev->descriptor.idProduct != PIXIS_PID) &&
         (pdx->udev->descriptor.idProduct != ST133_PID )))
        return -ENODEV;

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
    for (i = 0; i < iface_desc->desc.bNumEndpoints; i++) {
        endpoint = &iface_desc->endpoint[i].desc;
        if( debug )
        {
        dbg( "Endpoint[%d]->bDescriptorType = %d", i, endpoint->bDescriptorType );
            dbg( "Endpoint[%d]->bEndpointAddress = 0x%02X", i, endpoint->bEndpointAddress );
        dbg( "Endpoint[%d]->bbmAttributes = %d", i, endpoint->bmAttributes );
        dbg( "Endpoint[%d]->MaxPacketSize = %d\n", i, endpoint->wMaxPacketSize );
        }
        if (usb_endpoint_xfer_bulk(endpoint)) {
            if(usb_endpoint_dir_in(endpoint))
                pdx->hEP[i] = usb_rcvbulkpipe( pdx->udev, endpoint->bEndpointAddress );
            else
                pdx->hEP[i] = usb_sndbulkpipe( pdx->udev, endpoint->bEndpointAddress );
        }
    }
    usb_set_intfdata( interface, pdx );
    retval = usb_register_dev( interface, &piusb_class );
    if( retval ) {
        pr_err( "Not able to get a minor for this device." );
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
 *  piusb_disconnect
 *
 *  Called by the usb core when the device is removed from the system.
 *
 *  This routine guarantees that the driver will not submit any more urbs
 *  by clearing pdx->udev.  It is also supposed to terminate any currently
 *  active urbs.  Unfortunately, usb_bulk_msg(), used in piusb_read(), does
 *  not provide any way to do this.  But at least we can cancel an active
 *  write.
 */
static void piusb_disconnect(struct usb_interface *interface)
{
    struct device_extension *pdx;
    int minor = interface->minor;

    mutex_lock(&ioctl_mutex);
    pdx = usb_get_intfdata (interface);
    usb_set_intfdata (interface, NULL);
    /* give back our minor */
    usb_deregister_dev (interface, &piusb_class);
    /* prevent device read, write and ioctl */
    pdx->present = 0;
    mutex_unlock(&ioctl_mutex);

    kref_put(&pdx->kref, piusb_delete);
    dbg("PI USB2.0 device #%d now disconnected\n", minor);
}

static struct usb_driver piusb_driver = {
	.name =		    "rspiusb",
	.probe =	    piusb_probe,
	.disconnect =	    piusb_disconnect,
	.id_table =	    pi_device_table,
};


static int __init piusb_init(void)
{
	int result;

	lastErr = 0;
	errCnt = 0;

	/* register this driver with the USB subsystem */
	result = usb_register(&piusb_driver);
	if (result)
		printk(KERN_ERR KBUILD_MODNAME
				": usb_register failed. Error number %d\n",
				result);
	else
		printk(KERN_INFO KBUILD_MODNAME ": %s %s\n", DRIVER_DESC, DRIVER_VERSION);
	return result;
}

static void __exit piusb_exit(void)
{
    /* deregister this driver with the USB subsystem */
    usb_deregister(&piusb_driver);
}

module_init ( piusb_init );
module_exit ( piusb_exit );

/* Module parameters */
module_param(debug, int, 0 );
MODULE_PARM_DESC(debug, "Debug enabled or not");

MODULE_AUTHOR("Princeton Instruments");
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_LICENSE("GPL v2");

