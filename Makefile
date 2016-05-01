ifneq ($(KERNELRELEASE),)

obj-m := demo_genetlink_kern.o

else
	
KDIR := /home/apple/raspberry/build/linux-rpi-4.1.y
all:prepare
	make -C $(KDIR) M=$(PWD) modules ARCH=arm CROSS_COMPILE=arm-bcm2708-linux-gnueabi-
	$(CROSS_COMPILE)gcc -o demo_genetlink_user demo_genetlink_user.c
	cp *.ko ./release/	
	cp demo_genetlink_user ./release/
prepare:
	cp /home/apple/win_share/netlink_test/* ./
modules_install:
	make -C $(KDIR) M=$(PWD) modules_install ARCH=arm CROSS_COMPILE=arm-bcm2708-linux-gnueabi-
clean:
	rm -f *.ko *.o *.mod.o *.mod.c *.symvers  modul*
	rm -f ./release/*

endif
