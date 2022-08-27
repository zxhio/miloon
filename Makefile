obj-m := hook.o
 
CROSS_COMPILE=''
KDIR := /lib/modules/$(shell uname -r)/build
all:
	make -C $(KDIR) M=$(PWD) modules
clean:
	rm -f *.ko *.o *.mod.o *.mod.c .*.cmd *.symvers  modul* *.mod

install: all uninstall
	insmod hook.ko
uninstall:
	rmmod hook