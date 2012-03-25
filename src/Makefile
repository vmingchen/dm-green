obj-m += dm-green.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

install: 
	insmod dm-green.ko

remove: 
	rmmod dm-green
