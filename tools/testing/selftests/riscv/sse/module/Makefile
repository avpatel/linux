ifneq ($(CONFIG_RISCV_SBI_SSE),)
obj-m += riscv_sse_test.o
endif

ifndef KERNELRELEASE

TESTMODS_DIR := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
KDIR ?= /lib/modules/$(shell uname -r)/build

# Ensure that KDIR exists, otherwise skip the compilation
modules:
ifneq ("$(wildcard $(KDIR))", "")
	$(Q)$(MAKE) -C $(KDIR) modules KBUILD_EXTMOD=$(TESTMODS_DIR)
endif

# Ensure that KDIR exists, otherwise skip the clean target
clean:
ifneq ("$(wildcard $(KDIR))", "")
	$(Q)$(MAKE) -C $(KDIR) clean KBUILD_EXTMOD=$(TESTMODS_DIR)
endif

endif
