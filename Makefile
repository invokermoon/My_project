KVER = $(shell uname -r)
out_dir=$(PWD)/out

obj-m :=qeexo.o

.PHONY : all clean kernel_modules

all:kernel_modules

kernel_modules:
	mkdir -p $(out_dir)
	make -C /lib/modules/$(KVER)/build  M=$(PWD) modules
	mv *.ko *.mod.c *.o .*.cmd modules.order  Module.symvers  $(out_dir)/
	rm .tmp_versions/ -rf
clean:
	make -C /lib/modules/$(KVER)/build  M=$(PWD) clean
	rm -rf $(out_dir)
