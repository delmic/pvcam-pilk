

	#ifndef PIDRIVER_H
	#define PIDRIVER_H
	
	#include <linux/ioctl.h>
	
	
	#define TABLE_ORDER 	4    	/* get 16 pages for scatter gather table 	*/
	#define TABLE_PAGES 	16  	/* 2 ^ TABLE_ORDER 							*/
	#define TABLE_SIZE		8192		/* scatter gather table for 128 meg images  */
								/* (TABLE_PAGES * PAGE_SIZE) / 8 			*/
	
	#define PI_PCI_VENDOR		0x10e8
	#define PI_PCI_DEVICE		0x801d
	#define PI_MAX_CARDS 		0x0c
	
	#define MAJOR_NUM 		177
	#define DEVICE_FILE_NAME	"rspipci"
	#define DEVICE_NAME		"pipci"
	
	typedef unsigned char 	uns8, *uns8_ptr;
	typedef short		  	int16, *int16_ptr;
	typedef unsigned short	uint16, *uint16_ptr;
	typedef unsigned long	uns32, *uns32_ptr;
	typedef unsigned long   DWORD;
	
	
	struct pi_dma_node {
		void *virtaddr;
		void *physaddr;
		DWORD physsize;
		struct pi_dma_node *next;
	};
	
	struct pi_dma_frames {
		long nodecount;
		long startindex;
		long offset;
		struct pi_dma_node *node;
		long framenumber;
		struct pi_dma_frames *next;
	};
	
	struct pi_userdma_info {
		DWORD numberofentries;
		DWORD size;
		struct pi_dma_node nodes[1024];
	};
	
	struct pi_userptr {
		void *address;
		DWORD size;
		DWORD nodecount;
		DWORD nodestart;
		DWORD offset;
		struct pi_dma_frames *xfernodes;
		DWORD sizeofnodes;
	};

	struct pi_irqs {
		DWORD triggers;
		DWORD eofs;
		DWORD bofs;
		DWORD interrupt_counter;
		DWORD avail;
		DWORD nframe_count;
		DWORD error_occurred;
		DWORD violations;
		DWORD fifo_full;
	};
	struct extension {
		struct mutex mutex; /* acquire it before accessing the device */

		unsigned long base_address0;
		unsigned long base_address1;
		unsigned long base_address2;
		unsigned int irq;		
		unsigned char state;
		
		/* Dma Buffer Information */
		struct pi_userdma_info dmainfo;	
		unsigned int bufferflag;
		struct pi_irqs irqs;
		unsigned int mem_mapped;
	};
	
	struct pi_pci_info {
	
		unsigned long base_address0;
		unsigned long base_address1;
		unsigned long base_address2;
		unsigned irq;	
		unsigned short number_of_cards;	
	};
	
	struct pi_pci_io {
		unsigned long port;
		union {
			unsigned long  dword_data;
			unsigned short word_data;
			unsigned char  byte_data;
		} data;			
	};
	
	
	
	#define STATE_CLOSED 0
	#define STATE_OPEN 	 1
	
	#define PIDD_SUCCESS 0
	#define PIDD_FAILURE 1
	
	/* Get General Info about the Interface Card... */
	#define IOCTL_PCI_GET_PI_INFO  _IOR(MAJOR_NUM, 1, int)
	
	/* Reading And Writing Out Ports */
	#define IOCTL_PCI_READ_BYTE	    _IOR(MAJOR_NUM, 2, int)
	#define IOCTL_PCI_READ_WORD		_IOR(MAJOR_NUM, 3, int)
	#define IOCTL_PCI_READ_DWORD	_IOR(MAJOR_NUM, 4, int)
	#define IOCTL_PCI_WRITE_BYTE	_IOW(MAJOR_NUM, 5, int)
	#define IOCTL_PCI_WRITE_WORD	_IOW(MAJOR_NUM, 6, int)
	#define IOCTL_PCI_WRITE_DWORD	_IOW(MAJOR_NUM, 7, int)

	/* Get the Dma Information */
	#define IOCTL_PCI_ALLOCATE_SG_TABLE _IOWR(MAJOR_NUM, 8, int)
	#define IOCTL_PCI_TRANSFER_DATA     _IOWR(MAJOR_NUM, 9, int)
	#define IOCTL_PCI_GET_IRQS          _IOWR(MAJOR_NUM, 10, int)
	

	
	
	#endif
