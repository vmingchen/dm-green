obj-m += dm-green.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	gcc -o user_disk_spin user_disk_spin.c

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -rf user_disk_spin

install: 
	insmod dm-green.ko

remove: 
	rmmod dm-green
