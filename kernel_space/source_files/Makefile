INSTALL_DIR=modules
ifneq (${KERNELRELEASE},)


        obj-m :=cdd107.o
cdd107-objs := kfw_kernel.o kfw_kernel_functions.o




else
        KERNELDIR ?= /lib/modules/$(shell uname -r)/build
        PWD := $(shell pwd)
default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
	@rm -rf ${INSTALL_DIR}
	@mkdir ${INSTALL_DIR}
	@mv -f *.o *.ko *.mod.c .*.cmd ${INSTALL_DIR}
clean:
	rm -rf ${INSTALL_DIR}
endif