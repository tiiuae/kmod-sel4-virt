// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright 2022, Technology Innovation Institute
 *
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <stdbool.h>

#include "test_utils.h"

#include "sel4/sel4_virt.h"
#include "sel4_virt_test.h"

#define TEST
#include "sel4_vmm_rpc.h"


#define atomic_load(ptr) __atomic_load_n(ptr, __ATOMIC_SEQ_CST)

#define VM_RAM_SIZE (2 << 20)

static int create_vm(void)
{
	int sel4, vm = -1;
	struct sel4_vm_params params = {
		.ram_size = VM_RAM_SIZE,
	};

	sel4 = open("/dev/sel4", O_RDWR);
	assert_ne(sel4, -1);

	do {
		vm = ioctl(sel4, SEL4_CREATE_VM, &params);
	} while (vm == -EINTR);

	assert_gte(vm, 0);

	assert_ne(close(sel4), -1);

	return vm;
}

static int start_vm(int vm)
{
	return ioctl(vm, SEL4_START_VM, 0);
}

static int create_vpci_device(int vm, struct sel4_vpci_device *device)
{
	return ioctl(vm, SEL4_CREATE_VPCI_DEVICE, device);
}

static int destroy_vpci_device(int vm, struct sel4_vpci_device *device)
{
	return ioctl(vm, SEL4_DESTROY_VPCI_DEVICE, device);
}

static int set_irqline(int vm, uint32_t irq)
{
	struct sel4_irqline req = {
		.irq = irq,
		.op = SEL4_IRQ_OP_SET,

	};
	return ioctl(vm, SEL4_SET_IRQLINE, &req);
}

static int clear_irqline(int vm, uint32_t irq)
{
	struct sel4_irqline req = {
		.irq = irq,
		.op = SEL4_IRQ_OP_CLR,

	};

	return ioctl(vm, SEL4_SET_IRQLINE, &req);
}

static int create_iohandler(int vm)
{
	return ioctl(vm, SEL4_CREATE_IO_HANDLER, 0);
}

static int wait_io(int vm)
{
	return ioctl(vm, SEL4_WAIT_IO);
}

static int notify_io_handled(int vm, __u64 slot)
{
	return ioctl(vm, SEL4_NOTIFY_IO_HANDLED, slot);
}

static int inject_ioreq(int vm, struct sel4_test_ioreq *inject)
{
	return ioctl(vm, SEL4_TEST_IOREQ_ADD, inject);
}

static int inject_upcall(int vm)
{
	return ioctl(vm, SEL4_TEST_INJECT_UPCALL, 0);
}

static int consume_sent(int vm)
{
	return ioctl(vm, SEL4_TEST_CONSUME_SENT, 0);
}

static bool mmio_ioreqs_equal(struct sel4_ioreq_mmio *lhs, struct sel4_ioreq_mmio *rhs)
{
	return ((lhs->direction == rhs->direction) &&
		(lhs->vcpu	== rhs->vcpu) &&
		(lhs->addr	== rhs->addr) &&
		(lhs->len	== rhs->len) &&
		(lhs->data	== rhs->data));
}

static bool pci_ioreqs_equal(struct sel4_ioreq_pci *lhs, struct sel4_ioreq_pci *rhs)
{
	return ((lhs->direction == rhs->direction) &&
		(lhs->pcidev	== rhs->pcidev) &&
		(lhs->addr	== rhs->addr) &&
		(lhs->len	== rhs->len) &&
		(lhs->data	== rhs->data));
}
static bool ioreqs_equal(struct sel4_ioreq *lhs, struct sel4_ioreq *rhs)
{
	return ((lhs->type == rhs->type) &&
		(lhs->type == SEL4_IOREQ_TYPE_MMIO) ?
		mmio_ioreqs_equal(&lhs->req.mmio, &rhs->req.mmio) :
		pci_ioreqs_equal(&lhs->req.pci, &rhs->req.pci));
}

static int test_vm_create(void)
{
	int vm;
	vm = create_vm();
	assert_ne(close(vm), -1);

	return 0;
}

static int test_vm_create_many(void)
{
	int vm[5];
	for (size_t i = 0; i < ARRAY_SIZE(vm); i++) {
		vm[i] = create_vm();
		assert_ne(vm[i], -1);
	}

	for (size_t i = 0; i < ARRAY_SIZE(vm); i++) {
		assert_ne(close(vm[i]), -1);
	}

	return 0;
}

int test_char_unknown_ioctl(void)
{
	int sel4;

	sel4 = open("/dev/sel4", O_RDWR);
	assert_ne(sel4, -1);
	assert_eq(ioctl(sel4, _IOR(SEL4_IOCTL, 0x01, __u64), 0), -1);
	assert_eq(errno, EINVAL);
	assert_ne(close(sel4), -1);

	return 0;
}

static int test_vm_unknown_ioctl(void)
{
	int vm = create_vm();

	assert_eq(ioctl(vm, SEL4_CREATE_VM, 0), -1);
	assert_eq(errno, EINVAL);

	assert_ne(close(vm), -1);

	return 0;
}

static int test_create_iohandler(void)
{
	struct sel4_iohandler_buffer *buf;

	int vm = create_vm();
	int iohandler = create_iohandler(vm);
	assert_gte(iohandler, 0);

	buf = mmap(NULL, sizeof(*buf), PROT_READ | PROT_WRITE, MAP_SHARED, iohandler, 0);
	assert_ne(buf, MAP_FAILED);

	buf->request_slots[1].type = 1;

	assert_eq(munmap(buf, sizeof(*buf)), 0);
	assert_ne(close(iohandler), -1);
	assert_ne(close(vm), -1);
	return 0;
}

static int test_one_iohandler_allowed(void)
{
	int rc;
	int vm = create_vm();
	int iohandler = create_iohandler(vm);
	assert_gte(iohandler, 0);

	rc = create_iohandler(vm);
	assert_eq(rc, -1);
	assert_eq(errno, EEXIST);

	assert_ne(close(iohandler), -1);
	assert_ne(close(vm), -1);

	return 0;
}

static int test_start_vm(void)
{
	int vm = create_vm();
	int iohandler = create_iohandler(vm);
	assert_gte(iohandler, 0);

	assert_eq(start_vm(vm), 0);
	assert_eq(consume_sent(vm), QEMU_OP_START_VM);

	// ensure no excess messages
	assert_eq(consume_sent(vm), -1);
	assert_eq(errno, ENOMSG);

	assert_ne(close(iohandler), -1);
	assert_ne(close(vm), -1);

	return 0;
}

static int test_start_vm_requires_iohandler(void)
{
	int vm = create_vm();

	assert_eq(start_vm(vm), -1);
	assert_eq(errno, EBADFD);

	// ensure no messages sent
	assert_eq(consume_sent(vm), -1);
	assert_eq(errno, ENOMSG);

	assert_ne(close(vm), -1);

	return 0;
}

static int test_create_vpci_device(void)
{
	struct sel4_vpci_device vpcidev = {
		.pcidev = 0,
	};
	int vm = create_vm();

	assert_eq(create_vpci_device(vm, &vpcidev), 0);
	assert_eq(consume_sent(vm), QEMU_OP_REGISTER_PCI_DEV);

	// ensure no excess messages
	assert_eq(consume_sent(vm), -1);
	assert_eq(errno, ENOMSG);

	assert_ne(close(vm), -1);

	return 0;
}

static int test_destroy_vpci_device(void)
{
	struct sel4_vpci_device vpcidev = {
		.pcidev = 0,
	};
	int vm = create_vm();

	assert_eq(destroy_vpci_device(vm, &vpcidev), -1);
	assert_eq(errno, ENOSYS);

	assert_eq(consume_sent(vm), -1);
	assert_eq(errno, ENOMSG);

	assert_ne(close(vm), -1);

	return 0;
}

static int test_set_irqline(void)
{
	int vm = create_vm();

	assert_eq(set_irqline(vm, 10), 0);
	assert_eq(consume_sent(vm), QEMU_OP_SET_IRQ);

	// ensure no excess messages
	assert_eq(consume_sent(vm), -1);
	assert_eq(errno, ENOMSG);

	assert_ne(close(vm), -1);

	return 0;
}

static int test_clear_irqline(void)
{
	int vm = create_vm();

	assert_eq(clear_irqline(vm, 10), 0);
	assert_eq(consume_sent(vm), QEMU_OP_CLR_IRQ);

	// ensure no excess messages
	assert_eq(consume_sent(vm), -1);
	assert_eq(errno, ENOMSG);

	assert_ne(close(vm), -1);

	return 0;
}

static struct sel4_ioreq *iohandler_inject_ioreq(int vm,
						 struct sel4_iohandler_buffer *buf,
						 unsigned slot,
						 struct sel4_test_ioreq *inject)
{
	struct sel4_ioreq *ioreq;
	if (!buf) {
		return NULL;
	}

	ioreq = &buf->request_slots[slot];

	// ensure state is free
	assert_eq(atomic_load(&ioreq->state), SEL4_IOREQ_STATE_FREE);

	assert_eq(inject_ioreq(vm, inject), 0);
	assert_eq(inject_upcall(vm), 0);

	return ioreq;
}

static void wait_ioreq(int vm, struct sel4_ioreq *ioreq)
{
	assert_eq(wait_io(vm), 0);

	// ensure we have pending request
	assert_eq(atomic_load(&ioreq->state), SEL4_IOREQ_STATE_PROCESSING);
}

static int test_ioreq_pci_op_read(void)
{
	struct sel4_iohandler_buffer *buf;
	struct sel4_ioreq *ioreq;
	struct sel4_test_ioreq inject = {
		.ioreq = {
			.type = SEL4_IOREQ_TYPE_PCI,
			.req.pci.direction = SEL4_IO_DIR_READ,
			.req.pci.pcidev = 0x1,
			.req.pci.addr = 0x123,
			.req.pci.len = 1,
			.req.pci.data = 0x0,
		},
	};
	unsigned slot = 0;

	int vm = create_vm();
	int iohandler = create_iohandler(vm);
	assert_gte(iohandler, 0);

	buf = mmap(NULL, sizeof(*buf), PROT_READ | PROT_WRITE, MAP_SHARED, iohandler, 0);
	assert_ne(buf, MAP_FAILED);

	ioreq = iohandler_inject_ioreq(vm, buf, slot, &inject);
	assert_true(ioreq);

	// wait for ioreq and assert it matches the injected one
	wait_ioreq(vm, ioreq);
	assert_true(ioreqs_equal(&inject.ioreq, ioreq));

	// ensure no messages sent before notify_io_handled
	assert_eq(consume_sent(vm), -1);
	assert_eq(errno, ENOMSG);

	// reply data
	ioreq->req.pci.data = 0xFF;

	assert_eq(notify_io_handled(vm, slot), 0);

	// ensure processed
	assert_eq(atomic_load(&ioreq->state), SEL4_IOREQ_STATE_FREE);
	assert_eq(consume_sent(vm), QEMU_OP_READ);

	// ensure no excess messages
	assert_eq(consume_sent(vm), -1);
	assert_eq(errno, ENOMSG);

	assert_eq(munmap(buf, sizeof(*buf)), 0);
	assert_ne(close(iohandler), -1);
	assert_ne(close(vm), -1);

	return 0;
}

static int test_ioreq_pci_op_write(void)
{
	struct sel4_iohandler_buffer *buf;
	struct sel4_ioreq *ioreq;
	struct sel4_test_ioreq inject = {
		.ioreq = {
			.type = SEL4_IOREQ_TYPE_PCI,
			.req.pci.direction = SEL4_IO_DIR_WRITE,
			.req.pci.pcidev = 0x1,
			.req.pci.addr = 0x123,
			.req.pci.len = 1,
			.req.pci.data = 0xAB
		},
	};
	unsigned slot = 0;

	int vm = create_vm();
	int iohandler = create_iohandler(vm);
	assert_gte(iohandler, 0);

	buf = mmap(NULL, sizeof(*buf), PROT_READ | PROT_WRITE, MAP_SHARED, iohandler, 0);
	assert_ne(buf, MAP_FAILED);

	ioreq = iohandler_inject_ioreq(vm, buf, slot, &inject);
	assert_true(ioreq);

	// wait for ioreq and assert it matches the injected one
	wait_ioreq(vm, ioreq);
	assert_true(ioreqs_equal(&inject.ioreq, ioreq));

	// ensure no messages sent before notify_io_handled
	assert_eq(consume_sent(vm), -1);
	assert_eq(errno, ENOMSG);

	assert_eq(notify_io_handled(vm, slot), 0);

	// ensure processed
	assert_eq(atomic_load(&ioreq->state), SEL4_IOREQ_STATE_FREE);
	assert_eq(consume_sent(vm), QEMU_OP_WRITE);

	// ensure no excess messages
	assert_eq(consume_sent(vm), -1);
	assert_eq(errno, ENOMSG);

	assert_eq(munmap(buf, sizeof(*buf)), 0);
	assert_ne(close(iohandler), -1);
	assert_ne(close(vm), -1);

	return 0;
}

static int test_ioreq_pci_many(void)
{
	struct sel4_iohandler_buffer *buf;
	struct sel4_ioreq *ioreq[2];
	struct sel4_test_ioreq inject[2] = {{
		.ioreq = {
			.req.pci.direction = SEL4_IO_DIR_WRITE,
			.req.pci.pcidev = 0x1,
			.req.pci.addr = 0x123,
			.req.pci.len = 1,
			.req.pci.data = 0xAB
		},
	}, {
		.ioreq = {
			.req.pci.direction = SEL4_IO_DIR_READ,
			.req.pci.pcidev = 0x1,
			.req.pci.addr = 0x123,
			.req.pci.len = 1,
			.req.pci.data = 0xAB
		},
	}};
	unsigned slot;

	int vm = create_vm();
	int iohandler = create_iohandler(vm);
	assert_gte(iohandler, 0);

	buf = mmap(NULL, sizeof(*buf), PROT_READ | PROT_WRITE, MAP_SHARED, iohandler, 0);
	assert_ne(buf, MAP_FAILED);

	for (slot = 0; slot < ARRAY_SIZE(inject); slot++) {
		int retry = 10;

		ioreq[slot] = iohandler_inject_ioreq(vm, buf, slot, &inject[slot]);
		assert_true(ioreq[slot]);

		// wait for ioreq
		do {
			assert_eq(wait_io(vm), 0);

			// testing for multiple ioreqs requires polling for
			// state, because wait returns immediately when there's
			// one available for processing.
			if (atomic_load(&ioreq[slot]->state) == SEL4_IOREQ_STATE_PROCESSING)
				break;

			usleep(100);
			retry--;
		} while (retry);

		assert_true(ioreqs_equal(&inject[slot].ioreq, ioreq[slot]));
	}

	for (slot = 0; slot < ARRAY_SIZE(inject); slot++) {
		// ensure no messages sent before notify_io_handled
		assert_eq(consume_sent(vm), -1);
		assert_eq(errno, ENOMSG);

		assert_eq(notify_io_handled(vm, slot), 0);

		// ensure processed
		assert_eq(atomic_load(&ioreq[slot]->state), SEL4_IOREQ_STATE_FREE);

		assert_eq(consume_sent(vm), (ioreq[slot]->req.pci.direction == SEL4_IO_DIR_WRITE) ? QEMU_OP_WRITE : QEMU_OP_READ);
	}

	// ensure no excess messages
	assert_eq(consume_sent(vm), -1);
	assert_eq(errno, ENOMSG);

	assert_eq(munmap(buf, sizeof(*buf)), 0);
	assert_ne(close(iohandler), -1);
	assert_ne(close(vm), -1);

	return 0;
}

static int test_mmap_ram(void)
{
	int vm = create_vm();
	uint64_t *buf = mmap(NULL, VM_RAM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, vm, 0);
	assert_ne(buf, MAP_FAILED);
	buf[10] = 0xabbabaab;
	buf[4097] = 0xabbabaab;
	assert_eq(munmap(buf, sizeof(*buf)), 0);
	assert_ne(close(vm), -1);

	return 0;
}

int main(void)
{
	const struct test_case tests[] = {
		declare_test(test_vm_create),
		declare_test(test_vm_create_many),
		declare_test(test_char_unknown_ioctl),
		declare_test(test_vm_unknown_ioctl),
		declare_test(test_create_iohandler),
		declare_test(test_one_iohandler_allowed),
		declare_test(test_start_vm),
		declare_test(test_start_vm_requires_iohandler),
		declare_test(test_create_vpci_device),
		declare_test(test_destroy_vpci_device),
		declare_test(test_set_irqline),
		declare_test(test_clear_irqline),
		declare_test(test_ioreq_pci_op_read),
		declare_test(test_ioreq_pci_op_write),
		declare_test(test_ioreq_pci_many),
		declare_test(test_mmap_ram),
	};
	return run_tests(tests);
}

