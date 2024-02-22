#
# Copyright 2022, Technology Innovation Institute
#
# SPDX-License-Identifier: GPL-2.0-only

prefix ?= /usr/local
includedir = $(prefix)/include

ifneq ($(KERNELRELEASE),)
sel4_virt := sel4_core.o \
	     sel4_vmm.o \
	     sel4_mmap.o \
	     sel4_ioeventfd.o \
	     sel4_irqfd.o
sel4_pci := pci/sel4_pci.o pci/sel4_vmm_pool.o

obj-m := sel4_virt.o # sel4_virt_test.o
sel4_virt-y := $(sel4_virt) $(sel4_pci)
sel4_virt_test-y := $(sel4_virt) test/kmod/sel4_virt_test.o

ccflags-y := -I$(src)/include/uapi -I$(src)
else

PUB_HEADERS := include/uapi/sel4/sel4_virt.h \
	       include/uapi/sel4/sel4_virt_types.h \
	       include/uapi/sel4/rpc.h \
	       include/uapi/sel4/rpc_queue.h

DEPS := $(PUB_HEADERS) \
	sel4_virt_drv.h \
	pci/sel4_vmm_pool.h \
	test/kmod/sel4_virt_test.h
KERNEL_SRC ?= /lib/modules/`uname -r`/build
SRC := $(shell pwd)

# Testing stuff
CFLAGS ?= -Wall -Wextra -std=gnu17 -pedantic-errors -g -rdynamic
CPPFLAGS ?= -I$(SRC)/include/uapi -I$(SRC) -I$(SRC)/test/kmod
TEST_DEPS ?= $(DEPS) test/test_utils.h
OBJS = test/test_sel4.o test/test_utils.o

# Check user to avoid accidental test runs
TEST_USER ?= vagrant
export TEST_USER

default: $(DEPS)
	$(MAKE) -C $(KERNEL_SRC) M=$(SRC) $(MAKEFLAGS)

modules_install:
	$(MAKE) -C $(KERNEL_SRC) M=$(SRC) $(MAKEFLAGS) modules_install

headers_install: $(PUB_HEADERS)
	install -m 0644 -D -t $(INSTALL_HDR_PATH)/$(includedir)/sel4 \
		$(PUB_HEADERS)

test: test_run

test_run: test/test_sel4
	@scripts/test-prepare.sh
	test/test_sel4

test/test_sel4: default $(OBJS)
	$(CC) -o $@ $(OBJS) $(CFLAGS)

test/test_queue:  test/test_queue.o test/test_utils.o
	$(CC) -o $@ $^ $(CFLAGS)

test/%.o: test/%.c $(TEST_DEPS)
	$(CC) -c -o $@ $< $(CPPFLAGS) $(CFLAGS)

vagrant:
	vagrant up

test_vagrant: vagrant
	vagrant ssh -c "cd sel4 && make test"

clean:
	$(MAKE) -C $(KERNEL_SRC) M=$(SRC) clean
	rm -f test/test_sel4

.PHONY: default modules_install headers_install clean test test_run vagrant test_vagrant

endif
