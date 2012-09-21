KERVER=`uname -r`
NCAMPI=`lspci -vv | grep 801d | wc -l` 
NDRIVERPI=`grep pipci /proc/modules | wc -l`
NALIASESPI=`grep pipci /etc/modprobe.conf | wc -l`

echo PI PCI Driver Installation: $NCAMPI Princeton Instruments type cameras found.

x=0
while [ $x -lt $NCAMPI ]
do
  mknod /dev/rspipci$x c 177 $x
  x=`expr $x + 1`
done  

if [ $NCAMPI ]
then
  install -d /lib/modules/$KERVER/kernel/drivers/misc/pi/
  install pipci.ko /lib/modules/$KERVER/kernel/drivers/misc/pi/
  depmod -a
  modprobe pipci
fi

echo Princeton Instruments Device Driver for Linux installation complete.




