TARGET = rspiusb

# Special variable for the kernel makefile
obj-m := $(TARGET).o
# Special variable that get overriden by DKMS if building for a different kernel
KERNELRELEASE := $(shell uname -r)

all:
	make -C /lib/modules/$(KERNELRELEASE)/build M=$(PWD) modules
clean:
	test ! -d /lib/modules/$(KERNELRELEASE) || make -C /lib/modules/$(KERNELRELEASE)/build M=$(PWD) clean

