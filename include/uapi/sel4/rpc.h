/*
 * Copyright 2022, 2023, 2024, Technology Innovation Institute
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <assert.h>
#include <inttypes.h>
#endif

#include "rpc_queue.h"

typedef enum rpcmsg_iobuf_id {
	iobuf_id_driver = 0,
	iobuf_id_driver_fwd, /* kernel -> user */
	iobuf_id_device,
	iobuf_id_last,
} rpcmsg_iobuf_id_t;

typedef struct rpcmsg_iobuf {
	rpcmsg_buffer_t buffers[iobuf_id_last];
	rpcmsg_queue_t queues[iobuf_id_last];
} rpcmsg_iobuf_t;

#define IOBUF_NUM_PAGES 2
#define iobuf_queue(_addr, _id, _type)			\
	({						\
	 rpcmsg_iobuf_t *_iobuf = (void *)(_addr);	\
	 _type _q = {					\
		.buffer = &_iobuf->buffers[(_id)],	\
		.queue = &_iobuf->queues[(_id)],        \
	 };						\
	 _q;						\
	 })

#define driver_tx_queue(_addr) iobuf_queue((_addr), iobuf_id_driver, rpcmsg_event_queue_t)
#define driver_rx_queue(_addr) iobuf_queue((_addr), iobuf_id_device, rpcmsg_event_queue_t)

#define device_km_tx_queue(_addr) iobuf_queue((_addr), iobuf_id_device, rpcmsg_event_queue_t)
#define device_km_rx_queue(_addr) iobuf_queue((_addr), iobuf_id_driver, rpcmsg_event_queue_t)

#define device_tx_queue(_addr) iobuf_queue((_addr), iobuf_id_device, rpcmsg_event_queue_t)
#define device_rx_queue(_addr) iobuf_queue((_addr), iobuf_id_driver_fwd, rpcmsg_event_queue_t)

static_assert(sizeof(rpcmsg_iobuf_t) < 4096 * IOBUF_NUM_PAGES,
	      "Not enough of iobuf memory");

#ifndef MASK
#define MASK(_n)                        ((1UL << (_n)) - 1)
#endif

#define BIT_FIELD_MASK(_name)           (MASK(_name ## _WIDTH) << (_name ## _SHIFT))

#define BIT_FIELD_CLR_ALL(_v, _name)    ((_v) & ~BIT_FIELD_MASK(_name))
#define BIT_FIELD_SET_ALL(_v, _name)    ((_v) | BIT_FIELD_MASK(_name))

#define BIT_FIELD_GET(_v, _name)        (((_v) >> (_name ## _SHIFT)) & MASK(_name ## _WIDTH))
#define BIT_FIELD_SET(_v, _name, _n)    ((BIT_FIELD_CLR_ALL(_v, _name)) | ((((seL4_Word)(_n)) << (_name ## _SHIFT)) & BIT_FIELD_MASK(_name)))

#define RPC_MR0_OP_WIDTH                6
#define RPC_MR0_OP_SHIFT                0

/* from driver to device */
#define QEMU_OP_MMIO        0
#define QEMU_OP_PUTC_LOG    2

/* from device to driver */
#define QEMU_OP_SET_IRQ     16
#define QEMU_OP_CLR_IRQ     17
#define QEMU_OP_START_VM    18
#define QEMU_OP_REGISTER_PCI_DEV    19
#define QEMU_OP_MMIO_REGION_CONFIG  20

#define QEMU_OP(_mr0)       BIT_FIELD_GET(_mr0, RPC_MR0_OP)

#define RPC_MR0_COMMON_WIDTH            (RPC_MR0_OP_WIDTH + RPC_MR0_OP_SHIFT)
#define RPC_MR0_COMMON_SHIFT            0

/************************* defines for QEMU_OP_MMIO *************************/

#define RPC_MR0_MMIO_SLOT_WIDTH         6
#define RPC_MR0_MMIO_SLOT_SHIFT         (RPC_MR0_COMMON_WIDTH + RPC_MR0_COMMON_SHIFT)

#define RPC_MR0_MMIO_DIRECTION_WIDTH    1
#define RPC_MR0_MMIO_DIRECTION_SHIFT    (RPC_MR0_MMIO_SLOT_WIDTH + RPC_MR0_MMIO_SLOT_SHIFT)

#define RPC_MR0_MMIO_DIRECTION_READ     0
#define RPC_MR0_MMIO_DIRECTION_WRITE    1

#define SEL4_IO_DIR_READ                RPC_MR0_MMIO_DIRECTION_READ
#define SEL4_IO_DIR_WRITE               RPC_MR0_MMIO_DIRECTION_WRITE

#define RPC_MR0_MMIO_ADDR_SPACE_WIDTH   8
#define RPC_MR0_MMIO_ADDR_SPACE_SHIFT   (RPC_MR0_MMIO_DIRECTION_WIDTH + RPC_MR0_MMIO_DIRECTION_SHIFT)

#define AS_GLOBAL                       MASK(RPC_MR0_MMIO_ADDR_SPACE_WIDTH)
#define AS_PCIDEV(__pcidev)             (__pcidev)

#define RPC_MR0_MMIO_LENGTH_WIDTH       4
#define RPC_MR0_MMIO_LENGTH_SHIFT       (RPC_MR0_MMIO_ADDR_SPACE_WIDTH + RPC_MR0_MMIO_ADDR_SPACE_SHIFT)

/*****************************************************************************/

typedef struct sel4_rpc {
	rpcmsg_event_queue_t tx_queue;
	rpcmsg_event_queue_t rx_queue;

	void (*doorbell)(void *doorbell_cookie);
	void *doorbell_cookie;
} sel4_rpc_t;

static inline
int rpcmsg_queue_iterate(rpcmsg_event_queue_t *q,
			 int (*fn)(rpcmsg_t *msg, void *cookie),
			 void *cookie)
{
	rpcmsg_t msg;
	int ret = 0;

	while (!rpcmsg_event_rx(q, &msg))
	{
		ret = fn(&msg, cookie);
		if (ret < 0) {
			break;
		}
	}

	return ret;
}

static inline int sel4_rpc_rx_process(sel4_rpc_t *rpc,
				      int (*fn)(rpcmsg_t *msg, void *cookie),
				      void *cookie)
{
	return rpcmsg_queue_iterate(&rpc->rx_queue, fn, cookie);
}

static inline int sel4_rpc_doorbell(sel4_rpc_t *rpc)
{
	if (!rpc || !rpc->tx_queue.queue || !rpc->tx_queue.buffer || !rpc->doorbell) {
		return -1;
	}

	if (!rpcmsg_queue_empty(rpc->tx_queue.queue)) {
		rpc->doorbell(rpc->doorbell_cookie);
	}

	return 0;
}

static inline int rpcmsg_send(sel4_rpc_t *rpc, unsigned int op,
			      seL4_Word mr0, seL4_Word mr1,
			      seL4_Word mr2, seL4_Word mr3)
{
	mr0 = BIT_FIELD_SET(mr0, RPC_MR0_OP, op);

	rpcmsg_event_tx(&rpc->tx_queue, mr0, mr1, mr2, mr3);

	return sel4_rpc_doorbell(rpc);
}

static inline int driver_req_start_vm(sel4_rpc_t *rpc)
{
	return rpcmsg_send(rpc, QEMU_OP_START_VM, 0, 0, 0, 0);
}

static inline int driver_req_create_vpci_device(sel4_rpc_t *rpc,
						seL4_Word pcidev)
{
	return rpcmsg_send(rpc, QEMU_OP_REGISTER_PCI_DEV, 0, pcidev, 0, 0);
}

static inline int driver_req_set_irqline(sel4_rpc_t *rpc, seL4_Word irq)
{
	return rpcmsg_send(rpc, QEMU_OP_SET_IRQ, 0, irq, 0, 0);
}

static inline int driver_req_clear_irqline(sel4_rpc_t *rpc, seL4_Word irq)
{
	return rpcmsg_send(rpc, QEMU_OP_CLR_IRQ, 0, irq, 0, 0);
}

static inline int driver_ack_mmio_finish(sel4_rpc_t *rpc, unsigned int slot, seL4_Word data)
{
	seL4_Word mr0 = 0;

	mr0 = BIT_FIELD_SET(mr0, RPC_MR0_MMIO_SLOT, slot);

	return rpcmsg_send(rpc, QEMU_OP_MMIO, mr0, 0, data, 0);
}

static inline int driver_req_mmio_region_config(sel4_rpc_t *rpc, uintptr_t gpa,
						size_t size,
						unsigned long flags)
{
	return rpcmsg_send(rpc, QEMU_OP_MMIO_REGION_CONFIG, 0, gpa, size, flags);
}

static inline int device_req_mmio_start(sel4_rpc_t *rpc, unsigned int direction,
					unsigned int addr_space, unsigned int slot,
					seL4_Word addr, seL4_Word len, seL4_Word data)
{
	seL4_Word mr0 = 0;
	seL4_Word mr1 = 0;
	seL4_Word mr2 = 0;

	mr0 = BIT_FIELD_SET(mr0, RPC_MR0_MMIO_DIRECTION, direction);
	mr0 = BIT_FIELD_SET(mr0, RPC_MR0_MMIO_ADDR_SPACE, addr_space);
	mr0 = BIT_FIELD_SET(mr0, RPC_MR0_MMIO_LENGTH, len);
	mr0 = BIT_FIELD_SET(mr0, RPC_MR0_MMIO_SLOT, slot);
	mr1 = addr;
	mr2 = data;

	return rpcmsg_send(rpc, QEMU_OP_MMIO, mr0, mr1, mr2, 0);
}

static inline int sel4_rpc_init(sel4_rpc_t *rpc,
				rpcmsg_event_queue_t rx,
				rpcmsg_event_queue_t tx,
				void (*doorbell)(void *doorbell_cookie),
				void *doorbell_cookie)
{
	if (!rpc || !rx.queue || !rx.buffer || !tx.queue || !tx.buffer || !doorbell) {
		return -1;
	}

	rpc->rx_queue = rx;
	rpc->tx_queue = tx;
	rpc->doorbell = doorbell;
	rpc->doorbell_cookie = doorbell_cookie;

	/* note that we do not initialize the queues themselves -- they are
	 * initialized statically on boot and dynamically on VM reboot
	 */

	return 0;
}
