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
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/eventfd.h>
#include <stdbool.h>

#include "test_utils.h"

#include "sel4/sel4_virt.h"
#include "sel4_virt_test.h"

#define TEST
#include "sel4_vmm_rpc.h"


#define atomic_load(_ptr) __atomic_load_n((_ptr), __ATOMIC_ACQUIRE)
#define atomic_store(_ptr, _data)  __atomic_store_n((_ptr), (_data), __ATOMIC_RELEASE);

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

static int ioeventfd_config(int vm, struct sel4_ioeventfd_config *config)
{
	return ioctl(vm, SEL4_IOEVENTFD, config);
}

static int irqfd_config(int vm, struct sel4_irqfd_config *config)
{
	return ioctl(vm, SEL4_IRQFD, config);
}

static int inject_ioreq(int vm, struct sel4_test_ioreq *inject)
{
	return ioctl(vm, SEL4_TEST_IOREQ_ADD, inject);
}

static int inject_upcall(int vm)
{
	return ioctl(vm, SEL4_TEST_INJECT_UPCALL, 0);
}

static int consume_msg(int vm, rpcmsg_t *msg)
{
	return ioctl(vm, SEL4_TEST_CONSUME_MSG, msg);
}

#define msg_type(msg) QEMU_OP(msg.mr0)

static int consume_sent(int vm)
{
	rpcmsg_t msg;
	return (!consume_msg(vm, &msg)) ? (int) msg_type(msg) : -1;
}

static bool ioreqs_equal(struct sel4_ioreq *lhs, struct sel4_ioreq *rhs)
{
	return ((lhs->direction  == rhs->direction) &&
		(lhs->addr_space == rhs->addr_space) &&
		(lhs->addr	 == rhs->addr) &&
		(lhs->len	 == rhs->len) &&
		(lhs->data	 == rhs->data));
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

	buf->request_slots[1].addr_space = AS_GLOBAL;

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

static void complete_ioreq(struct sel4_iohandler_buffer *buf, unsigned slot)
{
	struct sel4_ioreq *ioreq;
	assert_true(buf);
	ioreq = &buf->request_slots[slot];
	atomic_store(&ioreq->state, SEL4_IOREQ_STATE_FREE);
}

static int test_ioreq_pci_op_read(void)
{
	struct sel4_iohandler_buffer *buf;
	struct sel4_ioreq *ioreq;
	struct sel4_test_ioreq inject = {
		.slot = 0,
		.ioreq = {
			.state = SEL4_IOREQ_STATE_PENDING,
			.direction = SEL4_IO_DIR_READ,
			.addr_space = AS_PCIDEV(0x1),
			.addr = 0x123,
			.len = 1,
			.data = 0x0,
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
	ioreq->data = 0xFF;

	assert_eq(notify_io_handled(vm, slot), 0);

	// ensure processed
	assert_eq(atomic_load(&ioreq->state), SEL4_IOREQ_STATE_FREE);
	assert_eq(consume_sent(vm), QEMU_OP_IO_HANDLED);

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
		.slot = 0,
		.ioreq = {
			.state = SEL4_IOREQ_STATE_PENDING,
			.direction = SEL4_IO_DIR_WRITE,
			.addr_space = AS_PCIDEV(0x1),
			.addr = 0x123,
			.len = 1,
			.data = 0xAB
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
	assert_eq(consume_sent(vm), QEMU_OP_IO_HANDLED);

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
		.slot = 0,
		.ioreq = {
			.state = SEL4_IOREQ_STATE_PENDING,
			.direction = SEL4_IO_DIR_WRITE,
			.addr_space = AS_PCIDEV(0x1),
			.addr = 0x123,
			.len = 1,
			.data = 0xAB
		},
	}, {
		.slot = 1,
		.ioreq = {
			.state = SEL4_IOREQ_STATE_PENDING,
			.direction = SEL4_IO_DIR_READ,
			.addr_space = AS_PCIDEV(0x1),
			.addr = 0x123,
			.len = 1,
			.data = 0xAB
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

		assert_eq(consume_sent(vm), QEMU_OP_IO_HANDLED);
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

static int test_ioeventfd_assign_wildcard(void)
{
	struct sel4_ioeventfd_config config[] = {
		{ .addr_space = AS_GLOBAL, .len = 1, },
		{ .addr_space = AS_GLOBAL, .len = 2, },
		{ .addr_space = AS_GLOBAL, .len = 4, },
		{ .addr_space = AS_GLOBAL, .len = 8, },
	};
	int vm = create_vm();

	for (unsigned i = 0; i < ARRAY_SIZE(config); i++) {
		config[i].fd = eventfd(0, EFD_CLOEXEC);
		assert_ne(config[i].fd, -1);

		config[i].addr = (i * 8);

		/* assign */
		assert_eq(ioeventfd_config(vm, config + i), 0);
	}

	for (unsigned i = 0; i < ARRAY_SIZE(config); i++) {
		/* deassign */
		config[i].flags |= SEL4_IOEVENTFD_FLAG_DEASSIGN;
		assert_eq(ioeventfd_config(vm, config + i), 0);

		assert_ne(close(config[i].fd), -1);
	}

	assert_ne(close(vm), -1);

	return 0;
}

static int test_ioeventfd_assign_datamatch(void)
{
	struct sel4_ioeventfd_config config[] = {
		{ .addr_space = AS_GLOBAL, .len = 1, .data = 0, .flags = SEL4_IOEVENTFD_FLAG_DATAMATCH, },
		{ .addr_space = AS_GLOBAL, .len = 2, .data = 1, .flags = SEL4_IOEVENTFD_FLAG_DATAMATCH, },
		{ .addr_space = AS_GLOBAL, .len = 4, .data = 2, .flags = SEL4_IOEVENTFD_FLAG_DATAMATCH, },
		{ .addr_space = AS_GLOBAL, .len = 8, .data = 3, .flags = SEL4_IOEVENTFD_FLAG_DATAMATCH, },
	};
	int vm = create_vm();

	for (unsigned i = 0; i < ARRAY_SIZE(config); i++) {
		config[i].fd = eventfd(0, EFD_CLOEXEC);
		assert_ne(config[i].fd, -1);

		config[i].addr = (i * 8);

		/* assign */
		assert_eq(ioeventfd_config(vm, config + i), 0);
	}

	for (unsigned i = 0; i < ARRAY_SIZE(config); i++) {
		/* deassign */
		config[i].flags |= SEL4_IOEVENTFD_FLAG_DEASSIGN;
		assert_eq(ioeventfd_config(vm, config + i), 0);

		assert_ne(close(config[i].fd), -1);
	}

	assert_ne(close(vm), -1);

	return 0;
}

static int test_ioeventfd_assign_invalid_len(void)
{
	uint32_t invalid[] = { 0, 3, 5, 6, 7, 9 };
	int vm = create_vm();

	for (unsigned i = 0; i < ARRAY_SIZE(invalid); i++) {
		struct sel4_ioeventfd_config config = {
			.addr_space = AS_GLOBAL,
			.addr = 0xabbabaab,
			.len = invalid[i],
		};
		config.fd = eventfd(0, EFD_CLOEXEC);
		assert_ne(config.fd, -1);

		assert_eq(ioeventfd_config(vm, &config), -1);
		assert_eq(errno, EINVAL);

		assert_ne(close(config.fd), -1);
	}

	assert_ne(close(vm), -1);
	return 0;
}

static int test_ioeventfd_assign_overflow(void)
{
	struct sel4_ioeventfd_config config = {
		.addr_space = AS_GLOBAL,
		.addr = -1,
		.len = 1,
	};
	int vm = create_vm();

	config.fd = eventfd(0, EFD_CLOEXEC);
	assert_ne(config.fd, -1);

	assert_eq(ioeventfd_config(vm, &config), -1);
	assert_eq(errno, EINVAL);

	assert_ne(close(config.fd), -1);
	assert_ne(close(vm), -1);

	return 0;
}

static int test_ioeventfd_assign_conflict_wildcard(void)
{
	struct sel4_ioeventfd_config config[] = {
		{ .addr_space = AS_GLOBAL, .addr = 0x4, .len = 1, .flags = 0 },
		{ .addr_space = AS_GLOBAL, .addr = 0x4, .len = 1, .flags = SEL4_IOEVENTFD_FLAG_DATAMATCH },
	};
	int vm = create_vm();

	config[0].fd = eventfd(0, EFD_CLOEXEC);
	assert_ne(config[0].fd, -1);

	config[1].fd = config[0].fd;

	/* Given wildcard registered with fd and addr, */
	assert_eq(ioeventfd_config(vm, &config[0]), 0);

	/* Then duplicate with the same fd and addr is not allowed */
	for (unsigned i = 0; i < ARRAY_SIZE(config); i++) {
		assert_eq(ioeventfd_config(vm, &config[i]), -1);
		assert_eq(errno, EEXIST);
	}

	/* Teardown */
	config[0].flags |= SEL4_IOEVENTFD_FLAG_DEASSIGN;
	assert_eq(ioeventfd_config(vm, &config[0]), 0);
	assert_ne(close(config[0].fd), -1);
	assert_ne(close(vm), -1);

	return 0;
}

static int test_ioeventfd_assign_conflict_datamatch(void)
{
	struct sel4_ioeventfd_config config[] = {
		{ .addr_space = AS_GLOBAL, .addr = 0x4, .len = 1, .data = 1, .flags = SEL4_IOEVENTFD_FLAG_DATAMATCH },
		{ .addr_space = AS_GLOBAL, .addr = 0x4, .len = 1, },
	};
	int vm = create_vm();

	config[0].fd = eventfd(0, EFD_CLOEXEC);
	assert_ne(config[0].fd, -1);

	config[1].fd = config[0].fd;

	/* Given datamatch registered with fd, addr and datamatch, */
	assert_eq(ioeventfd_config(vm, &config[0]), 0);
	/* Then duplicate with the same fd, addr, datamatch or wildcard is not allowed */
	for (unsigned i = 0; i < ARRAY_SIZE(config); i++) {
		assert_eq(ioeventfd_config(vm, &config[i]), -1);
		assert_eq(errno, EEXIST);
	}

	/* Teardown */
	config[0].flags |= SEL4_IOEVENTFD_FLAG_DEASSIGN;
	assert_eq(ioeventfd_config(vm, &config[0]), 0);
	assert_ne(close(config[0].fd), -1);
	assert_ne(close(vm), -1);

	return 0;
}

static int test_ioeventfd_allow_datamatch_different_data(void)
{
	struct sel4_ioeventfd_config config[] = {
		{ .addr_space = AS_GLOBAL, .addr = 0x4, .len = 1, .data = 1, .flags = SEL4_IOEVENTFD_FLAG_DATAMATCH },
		{ .addr_space = AS_GLOBAL, .addr = 0x4, .len = 1, .data = 2, .flags = SEL4_IOEVENTFD_FLAG_DATAMATCH },
	};
	int vm = create_vm();

	config[0].fd = eventfd(0, EFD_CLOEXEC);
	assert_ne(config[0].fd, -1);
	config[1].fd = config[0].fd;
	/* Different datamatch values are allowed. */
	for (unsigned i = 0; i < ARRAY_SIZE(config); i++) {
		assert_eq(ioeventfd_config(vm, &config[i]), 0);
	}

	/* Teardown */
	for (unsigned i = 0; i < ARRAY_SIZE(config); i++) {
		config[i].flags |= SEL4_IOEVENTFD_FLAG_DEASSIGN;
		assert_eq(ioeventfd_config(vm, &config[i]), 0);
	}
	assert_ne(close(config[0].fd), -1);
	assert_ne(close(vm), -1);

	return 0;
}

static int test_ioeventfd_assign_invalid_fd(void)
{
	struct sel4_ioeventfd_config config = {
		.fd = 10,
		.addr_space = AS_GLOBAL,
		.addr = 0xabbabaab,
		.len = 1,
	};
	int vm = create_vm();

	assert_eq(ioeventfd_config(vm, &config), -1);
	assert_eq(errno, EBADF);

	assert_ne(close(vm), -1);

	return 0;
}

static int test_ioeventfd_deassign_invalid_fd(void)
{
	struct sel4_ioeventfd_config config = {
		.fd = 10,
		.addr_space = AS_GLOBAL,
		.addr = 0xabbabaab,
		.len = 1,
		.flags = SEL4_IOEVENTFD_FLAG_DEASSIGN,
	};
	int vm = create_vm();

	assert_eq(ioeventfd_config(vm, &config), -1);
	assert_eq(errno, EBADF);

	assert_ne(close(vm), -1);

	return 0;
}

struct ioeventfd_test_ctx {
	int vm;
	int iohandler;
	struct sel4_iohandler_buffer *buf;
	struct sel4_ioeventfd_config config;
};

static int setup_ioeventfd_test(struct ioeventfd_test_ctx *ctx)
{
	assert_true(ctx);

	ctx->vm = create_vm();
	ctx->iohandler = create_iohandler(ctx->vm);
	assert_gte(ctx->iohandler, 0);

	ctx->buf = mmap(NULL, sizeof(*ctx->buf), PROT_READ | PROT_WRITE, MAP_SHARED, ctx->iohandler, 0);
	assert_ne(ctx->buf, MAP_FAILED);

	ctx->config.fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	assert_ne(ctx->config.fd, -1);
	assert_eq(ioeventfd_config(ctx->vm, &ctx->config), 0);

	return 0;
}

static int teardown_ioeventfd_test(struct ioeventfd_test_ctx *ctx)
{
	assert_true(ctx);

	ctx->config.flags |= SEL4_IOEVENTFD_FLAG_DEASSIGN;
	assert_eq(ioeventfd_config(ctx->vm, &ctx->config), 0);
	assert_eq(close(ctx->config.fd), 0);
	assert_eq(munmap(ctx->buf, sizeof(*ctx->buf)), 0);
	assert_eq(close(ctx->iohandler), 0);
	assert_eq(close(ctx->vm), 0);

	return 0;
}

static void construct_ioeventfd_inject(struct sel4_ioeventfd_config *config,
				      struct sel4_test_ioreq *inject,
				      uint64_t data,
				      bool is_write)
{
	assert_true(config && inject);
	uint32_t direction = (is_write) ? SEL4_IO_DIR_WRITE : SEL4_IO_DIR_READ;

	inject->slot = 0;
	inject->ioreq.state = SEL4_IOREQ_STATE_PENDING;
	inject->ioreq.direction = direction;

	inject->ioreq.addr = config->addr;
	inject->ioreq.addr_space = config->addr_space;
	inject->ioreq.len = config->len;
	inject->ioreq.data = data;
}

static int do_test_ioeventfd_wildcard(struct sel4_ioeventfd_config *config)
{
	struct ioeventfd_test_ctx ctx;
	struct sel4_test_ioreq inject;
	uint64_t data;
	struct pollfd pfd = { .events = POLLIN };

	assert_true(config);

	/* Setup */
	ctx.config = *config;
	setup_ioeventfd_test(&ctx);

	/* Exercise */
	/* should block first */
	assert_eq(read(ctx.config.fd, &data, sizeof(data)), -1);
	assert_eq(errno, EWOULDBLOCK);

	/* inject event to address */
	construct_ioeventfd_inject(&ctx.config, &inject, 0, true);
	assert_true(iohandler_inject_ioreq(ctx.vm, ctx.buf, 0, &inject));

	/* Poll for eventfd */
	pfd.fd = ctx.config.fd;
	assert_eq(poll(&pfd, 1, 5000), 1);
	assert_eq(pfd.revents, POLLIN);

	/* Read the event */
	assert_eq(read(ctx.config.fd, &data, sizeof(data)), (int) sizeof(data));
	assert_eq(data, 1LU);

	/* Ensure kernel completed the ioreq */
	assert_eq(consume_sent(ctx.vm), QEMU_OP_IO_HANDLED);

	/* Ensure event is cleared */
	assert_eq(read(ctx.config.fd, &data, sizeof(data)), -1);
	assert_eq(errno, EWOULDBLOCK);

	/* Teardown */
	teardown_ioeventfd_test(&ctx);

	return 0;
}

static int do_test_ioeventfd_datamatch(struct sel4_ioeventfd_config *config)
{
	struct ioeventfd_test_ctx ctx;
	struct sel4_test_ioreq inject;
	uint64_t data;
	struct pollfd pfd = { .events = POLLIN };

	assert_true(config);

	/* Setup */
	ctx.config = *config;
	setup_ioeventfd_test(&ctx);

	/* Exercise */
	/* should block first */
	assert_eq(read(ctx.config.fd, &data, sizeof(data)), -1);
	assert_eq(errno, EWOULDBLOCK);

	/* inject event without data match to address */
	construct_ioeventfd_inject(&ctx.config, &inject, 0, true);
	assert_true(iohandler_inject_ioreq(ctx.vm, ctx.buf, 0, &inject));

	/* Poll for eventfd - should timeout */
	pfd.fd = ctx.config.fd;
	assert_eq(poll(&pfd, 1, 1000), 0);

	/* Ensure kernel left ioreq untouched */
	assert_eq(consume_sent(ctx.vm), -1);
	complete_ioreq(ctx.buf, 0);

	/* Inject event with datamatch and poll - we should get event */
	construct_ioeventfd_inject(&ctx.config, &inject, ctx.config.data, true);
	assert_true(iohandler_inject_ioreq(ctx.vm, ctx.buf, 0, &inject));

	pfd.fd = ctx.config.fd;
	assert_eq(poll(&pfd, 1, 1000), 1);
	assert_eq(pfd.revents, POLLIN);

	/* Read the event */
	assert_eq(read(ctx.config.fd, &data, sizeof(data)), (int) sizeof(data));
	assert_eq(data, 1LU);

	/* Ensure kernel completed the ioreq */
	assert_eq(consume_sent(ctx.vm), QEMU_OP_IO_HANDLED);

	/* Ensure event is cleared */
	assert_eq(read(ctx.config.fd, &data, sizeof(data)), -1);
	assert_eq(errno, EWOULDBLOCK);

	/* Teardown */
	teardown_ioeventfd_test(&ctx);

	return 0;
}

static int test_ioeventfd_wait_wildcard_pci(void)
{
	struct sel4_ioeventfd_config config = {
		.addr_space = AS_PCIDEV(1),
		.addr = 0xabbabaab,
		.len = 4,
		.data = 0xbaadcafe,
		.flags = 0,
	};

	assert_eq(do_test_ioeventfd_wildcard(&config), 0);

	return 0;
}

static int test_ioeventfd_wait_datamatch_pci(void)
{
	struct sel4_ioeventfd_config config = {
		.addr_space = AS_PCIDEV(1),
		.addr = 0xabbabaab,
		.len = 4,
		.data = 0xbaadcafe,
		.flags = SEL4_IOEVENTFD_FLAG_DATAMATCH,
	};
	assert_eq(do_test_ioeventfd_datamatch(&config), 0);

	return 0;
}

static int test_ioeventfd_wait_wildcard_mmio(void)
{
	struct sel4_ioeventfd_config config = {
		.addr_space = AS_GLOBAL,
		.addr = 0xabbabaab,
		.len = 4,
		.data = 0xbaadcafe,
	};

	assert_eq(do_test_ioeventfd_wildcard(&config), 0);

	return 0;
}

static int test_ioeventfd_wait_datamatch_mmio(void)
{
	struct sel4_ioeventfd_config config = {
		.addr_space = AS_GLOBAL,
		.addr = 0xabbabaab,
		.len = 4,
		.data = 0xbaadcafe,
		.flags = SEL4_IOEVENTFD_FLAG_DATAMATCH,
	};
	assert_eq(do_test_ioeventfd_datamatch(&config), 0);

	return 0;
}

static int do_test_ioeventfd_read(struct sel4_ioeventfd_config *config)
{
	struct ioeventfd_test_ctx ctx;
	struct sel4_test_ioreq inject;
	struct pollfd pfd = { .events = POLLIN };

	assert_true(config);

	/* Setup */
	ctx.config = *config;
	setup_ioeventfd_test(&ctx);

	/* Exercise */
	/* inject event with read operation */
	construct_ioeventfd_inject(&ctx.config, &inject, ctx.config.data, false);
	assert_true(iohandler_inject_ioreq(ctx.vm, ctx.buf, 0, &inject));

	/* Poll for eventfd - should timeout */
	pfd.fd = ctx.config.fd;
	assert_eq(poll(&pfd, 1, 1000), 0);

	/* Ensure kernel did not complete the ioreq */
	assert_eq(consume_sent(ctx.vm), -1);

	complete_ioreq(ctx.buf, 0);

	/* Teardown */
	teardown_ioeventfd_test(&ctx);

	return 0;
}

static int test_ioeventfd_wildcard_ignore_read(void)
{
	struct sel4_ioeventfd_config mmio_config = {
		.addr_space = AS_GLOBAL,
		.addr = 0xabbabaab,
		.len = 4,
		.flags = 0,
	};
	struct sel4_ioeventfd_config pci_config = {
		.addr_space = AS_PCIDEV(1),
		.addr = 0xabbabaab,
		.len = 4,
		.flags = 0,
	};


	assert_eq(do_test_ioeventfd_read(&mmio_config), 0);
	assert_eq(do_test_ioeventfd_read(&pci_config), 0);

	return 0;
}

static int test_ioeventfd_datamatch_ignore_read(void)
{
	struct sel4_ioeventfd_config mmio_config = {
		.addr_space = AS_GLOBAL,
		.addr = 0xabbabaab,
		.len = 4,
		.data = 0xbaadcafe,
		.flags = SEL4_IOEVENTFD_FLAG_DATAMATCH,
	};
	struct sel4_ioeventfd_config pci_config = {
		.addr_space = AS_PCIDEV(1),
		.addr = 0xabbabaab,
		.len = 4,
		.data = 0xbaadcafe,
		.flags = SEL4_IOEVENTFD_FLAG_DATAMATCH,
	};

	assert_eq(do_test_ioeventfd_read(&mmio_config), 0);
	assert_eq(do_test_ioeventfd_read(&pci_config), 0);

	return 0;
}

struct irqfd_test_ctx {
	int vm;
	int iohandler;
	struct sel4_iohandler_buffer *buf;
	struct sel4_irqfd_config config;
};

static int setup_irqfd_test(struct irqfd_test_ctx *ctx)
{
	assert_true(ctx);

	ctx->vm = create_vm();
	ctx->iohandler = create_iohandler(ctx->vm);
	assert_gte(ctx->iohandler, 0);

	ctx->buf = mmap(NULL, sizeof(*ctx->buf), PROT_READ | PROT_WRITE, MAP_SHARED, ctx->iohandler, 0);
	assert_ne(ctx->buf, MAP_FAILED);

	ctx->config.fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	assert_ne(ctx->config.fd, -1);
	assert_eq(irqfd_config(ctx->vm, &ctx->config), 0);

	return 0;
}

static int teardown_irqfd_test(struct irqfd_test_ctx *ctx)
{
	assert_true(ctx);
	ctx->config.flags |= SEL4_IRQFD_FLAG_DEASSIGN;

	assert_eq(irqfd_config(ctx->vm, &ctx->config), 0);
	assert_eq(close(ctx->config.fd), 0);
	assert_eq(munmap(ctx->buf, sizeof(*ctx->buf)), 0);
	assert_eq(close(ctx->iohandler), 0);
	assert_eq(close(ctx->vm), 0);

	return 0;
}

static int test_irqfd_assign(void)
{
	struct irqfd_test_ctx ctx = {
		.config = {
			.virq = 1,
		}
	};
	uint64_t val = 1;
	rpcmsg_t msg;

	setup_irqfd_test(&ctx);

	// We expect to receive SET_IRQ followed by CLR_IRQ
	memset(&msg, 0, sizeof(msg));
	assert_eq(write(ctx.config.fd, &val, sizeof(val)), 8);
	assert_eq(consume_msg(ctx.vm, &msg), 0);
	assert_eq(msg_type(msg), (unsigned int) QEMU_OP_SET_IRQ);
	assert_eq(msg.mr1, ctx.config.virq);

	memset(&msg, 0, sizeof(msg));
	assert_eq(consume_msg(ctx.vm, &msg), 0);
	assert_eq(msg_type(msg), (unsigned int) QEMU_OP_CLR_IRQ);
	assert_eq(msg.mr1, ctx.config.virq);

	/* Ensure messages consumed */
	assert_eq(consume_sent(ctx.vm), -1);

	teardown_irqfd_test(&ctx);
	return 0;
}

static int test_irqfd_assign_invalid_fd(void)
{

	struct sel4_irqfd_config config = {
		.fd = 10,
		.virq = 1,
	};
	int vm = create_vm();

	assert_eq(irqfd_config(vm, &config), -1);
	assert_eq(errno, EBADF);

	assert_ne(close(vm), -1);

	return 0;
}

static int test_irqfd_deassign_invalid_fd(void)
{

	struct sel4_irqfd_config config = {
		.fd = 10,
		.flags = SEL4_IRQFD_FLAG_DEASSIGN,
		.virq = 1,
	};
	int vm = create_vm();

	assert_eq(irqfd_config(vm, &config), -1);
	assert_eq(errno, EBADF);

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
		declare_test(test_ioeventfd_assign_wildcard),
		declare_test(test_ioeventfd_assign_datamatch),
		declare_test(test_ioeventfd_assign_invalid_len),
		declare_test(test_ioeventfd_assign_overflow),
		declare_test(test_ioeventfd_assign_conflict_wildcard),
		declare_test(test_ioeventfd_assign_conflict_datamatch),
		declare_test(test_ioeventfd_allow_datamatch_different_data),
		declare_test(test_ioeventfd_assign_invalid_fd),
		declare_test(test_ioeventfd_deassign_invalid_fd),
		declare_test(test_ioeventfd_wait_wildcard_pci),
		declare_test(test_ioeventfd_wait_datamatch_pci),
		declare_test(test_ioeventfd_wait_wildcard_mmio),
		declare_test(test_ioeventfd_wait_datamatch_mmio),
		declare_test(test_ioeventfd_wildcard_ignore_read),
		declare_test(test_ioeventfd_datamatch_ignore_read),
		declare_test(test_irqfd_assign),
		declare_test(test_irqfd_assign_invalid_fd),
		declare_test(test_irqfd_deassign_invalid_fd),
	};
	return run_tests(tests);
}

