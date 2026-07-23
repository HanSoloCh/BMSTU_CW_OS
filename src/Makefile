CONFIG_MODULE_SIG=0
PWD := $(shell pwd)
KDIR_PATH ?= /lib/modules/$(shell uname -r)/build

obj-m += my_module.o
my_module-objs := main.o rootkit.o

ccflags-y := -Wall -Wno-unused-result -Wno-unused-function -Wno-unused-variable

all:
	$(MAKE) -C $(KDIR_PATH) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR_PATH) M=$(PWD) clean