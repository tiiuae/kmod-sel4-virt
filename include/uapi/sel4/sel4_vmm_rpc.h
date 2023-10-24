/*
 * Copyright 2022, 2023, Technology Innovation Institute
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#ifdef __KERNEL__
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/compiler_attributes.h>
#else
#include <string.h>
#include <stdio.h>
#include <stddef.h>
#include <assert.h>
#include <inttypes.h>

#define __maybe_unused __attribute__ ((unused))
#endif

typedef unsigned long seL4_Word;

#ifndef smp_wmb
#define smp_wmb() do { asm volatile("dmb ishst" ::: "memory"); } while (0)
#endif

#if defined(__KERNEL__)
#define rpc_assert(_cond) BUG_ON(!(_cond))
#else
#define rpc_assert(_cond) assert(_cond)
#endif

#define IOBUF_PAGE_DRIVER_RX     1
#define IOBUF_PAGE_DRIVER_TX     0

#define IOBUF_PAGE_DEVICE_RX     IOBUF_PAGE_DRIVER_TX
#define IOBUF_PAGE_DEVICE_TX     IOBUF_PAGE_DRIVER_RX

#define iobuf_page(_iobuf, _page) (((uintptr_t)(_iobuf)) + (4096 * (_page)))

#define device_tx_queue(_iobuf) ((rpcmsg_queue_t *)iobuf_page((_iobuf), IOBUF_PAGE_DEVICE_TX))
#define device_rx_queue(_iobuf) ((rpcmsg_queue_t *)iobuf_page((_iobuf), IOBUF_PAGE_DEVICE_RX))

#define driver_tx_queue(_iobuf) ((rpcmsg_queue_t *)iobuf_page((_iobuf), IOBUF_PAGE_DRIVER_TX))
#define driver_rx_queue(_iobuf) ((rpcmsg_queue_t *)iobuf_page((_iobuf), IOBUF_PAGE_DRIVER_RX))

#ifndef MASK
#define MASK(_n)                        ((1UL << (_n)) - 1)
#endif

#define BIT_FIELD_MASK(_name)           (MASK(_name ## _WIDTH) << (_name ## _SHIFT))

#define BIT_FIELD_CLR_ALL(_v, _name)    ((_v) & ~BIT_FIELD_MASK(_name))
#define BIT_FIELD_SET_ALL(_v, _name)    ((_v) | BIT_FIELD_MASK(_name))

#define BIT_FIELD_GET(_v, _name)        (((_v) >> (_name ## _SHIFT)) & MASK(_name ## _WIDTH))
#define BIT_FIELD_SET(_v, _name, _n)    ((BIT_FIELD_CLR_ALL(_v, _name)) | (((_n) << (_name ## _SHIFT)) & BIT_FIELD_MASK(_name)))

#define RPC_MR0_OP_WIDTH                6
#define RPC_MR0_OP_SHIFT                0

/* start/finish MMIO access */
#define RPC_MR0_OP_MMIO                 0

/* tell other side our status */
#define RPC_MR0_OP_NOTIFY_STATUS        1

/* from device to driver */
#define RPC_MR0_OP_SET_IRQ              16
#define RPC_MR0_OP_CLR_IRQ              17
#define RPC_MR0_OP_START_VM             18
#define RPC_MR0_OP_REGISTER_PCI_DEV     19

#define RPC_MR0_STATE_WIDTH             2
#define RPC_MR0_STATE_SHIFT             (RPC_MR0_OP_WIDTH + RPC_MR0_OP_SHIFT)

#define RPC_MR0_STATE_COMPLETE          0
#define RPC_MR0_STATE_RESERVED          1
#define RPC_MR0_STATE_PENDING           2
#define RPC_MR0_STATE_PROCESSING        3

#define RPC_MR0_COMMON_WIDTH            (RPC_MR0_STATE_WIDTH + RPC_MR0_STATE_SHIFT)
#define RPC_MR0_COMMON_SHIFT            0

/* defines for RPC_MR0_OP field */

/************************ defines for RPC_MR0_OP_MMIO ************************/

#define RPC_MR0_MMIO_SLOT_WIDTH         6
#define RPC_MR0_MMIO_SLOT_SHIFT         (RPC_MR0_COMMON_WIDTH + RPC_MR0_COMMON_SHIFT)

#define RPC_MR0_MMIO_DIRECTION_WIDTH    1
#define RPC_MR0_MMIO_DIRECTION_SHIFT    (RPC_MR0_MMIO_SLOT_WIDTH + RPC_MR0_MMIO_SLOT_SHIFT)

#define RPC_MR0_MMIO_DIRECTION_READ     0
#define RPC_MR0_MMIO_DIRECTION_WRITE    1

/* 256 should be enough for one global space and PCI devices */
#define RPC_MR0_MMIO_ADDR_SPACE_WIDTH   8
#define RPC_MR0_MMIO_ADDR_SPACE_SHIFT   (RPC_MR0_MMIO_DIRECTION_WIDTH + RPC_MR0_MMIO_DIRECTION_SHIFT)

/* for 64-bit archs 8 is maximum fault data length */
#define RPC_MR0_MMIO_LENGTH_WIDTH       3
#define RPC_MR0_MMIO_LENGTH_SHIFT       (RPC_MR0_MMIO_ADDR_SPACE_WIDTH + RPC_MR0_MMIO_ADDR_SPACE_SHIFT)

/* currently there are 26 bits in mr0 for RPC_MR0_OP_MMIO */

/* for RPC_MR0_OP_MMIO, mr1 and mr2 contain address and data, respectively */

/*********************** defines for RPC_MR0_OP_STATUS ***********************/

/* for RPC_MR0_OP_NOTIFY_STATUS, mr1 contains the status */

#define RPC_MR1_NOTIFY_STATUS_OFF       0
#define RPC_MR1_NOTIFY_STATUS_READY     1

/*****************************************************************************/

#define RPCMSG_BUFFER_SIZE  32

typedef struct {
    seL4_Word mr0;
    seL4_Word mr1;
    seL4_Word mr2;
    seL4_Word mr3;
} rpcmsg_t;

typedef struct {
    rpcmsg_t data[RPCMSG_BUFFER_SIZE];
    seL4_Word head;
    seL4_Word tail;
} rpcmsg_queue_t;

typedef struct sel4_rpc {
    rpcmsg_queue_t *tx_queue;
    rpcmsg_queue_t *rx_queue;
    void (*doorbell)(void *doorbell_cookie);
    void *doorbell_cookie;
} sel4_rpc_t;

#define QUEUE_NEXT(_i) (((_i) + 1) & (RPCMSG_BUFFER_SIZE - 1))

__maybe_unused static
void rpcmsg_queue_init(rpcmsg_queue_t *q)
{
    memset(q, 0, sizeof(*q));
}

static inline
bool rpcmsg_queue_full(rpcmsg_queue_t *q)
{
    return QUEUE_NEXT(q->tail) == q->head;
}

static inline
bool rpcmsg_queue_empty(rpcmsg_queue_t *q)
{
    return q->tail == q->head;
}

static inline
rpcmsg_t *rpcmsg_queue_head(rpcmsg_queue_t *q)
{
    return rpcmsg_queue_empty(q) ? NULL : (q->data + q->head);
}

static inline
rpcmsg_t *rpcmsg_queue_tail(rpcmsg_queue_t *q)
{

    return rpcmsg_queue_full(q) ? NULL : (q->data + q->tail);
}

static inline
rpcmsg_t *rpcmsg_queue_peek_next(rpcmsg_queue_t *q, rpcmsg_t *msg)
{
    unsigned int next;

    if (!q || !msg) {
        return NULL;
    }

    next = QUEUE_NEXT(msg - q->data);
    if (next == q->head) {
        return NULL;
    }

    return q->data + next;
}

static inline
rpcmsg_t *rpcmsg_queue_iterate(rpcmsg_queue_t *q, rpcmsg_t *msg)
{
    if (msg) {
        return rpcmsg_queue_peek_next(q, msg);
    } else {
        return rpcmsg_queue_head(q);
    }
}

static inline
rpcmsg_t *rpcmsg_queue_advance_head(rpcmsg_queue_t *q)
{
    rpc_assert(!rpcmsg_queue_empty(q));
    q->head = QUEUE_NEXT(q->head);
    return rpcmsg_queue_head(q);
}

static inline
rpcmsg_t *rpcmsg_queue_advance_tail(rpcmsg_queue_t *q)
{
    rpc_assert((!rpcmsg_queue_full(q)));
    q->tail = QUEUE_NEXT(q->tail);
    return rpcmsg_queue_tail(q);
}

static inline
int sel4_rpc_doorbell(sel4_rpc_t *rpc)
{
    if (!rpc) {
        return -1;
    }

    rpc_assert(rpc->tx_queue && rpc->doorbell);

    if (!rpcmsg_queue_empty(rpc->tx_queue)) {
        rpc->doorbell(rpc->doorbell_cookie);
    }

    return 0;
}

/* TODO: ensure this is really atomic */
static inline
rpcmsg_t *rpcmsg_new(sel4_rpc_t *rpc)
{
    rpcmsg_t *msg;

    if (!rpc || !rpc->tx_queue) {
        return NULL;
    }

    for (;;) {
        msg = rpcmsg_queue_tail(rpc->tx_queue);
        if (!msg) {
            rpc_assert(!"tx queue full");
        }

        switch (BIT_FIELD_GET(msg->mr0, RPC_MR0_STATE)) {
        case RPC_MR0_STATE_COMPLETE:
            msg->mr0 = BIT_FIELD_SET(msg->mr0, RPC_MR0_STATE, RPC_MR0_STATE_RESERVED);
            rpcmsg_queue_advance_tail(rpc->tx_queue);
            return msg;
        case RPC_MR0_STATE_RESERVED:
            /* tail changed, let's retry */
	    /* TODO: should we do seL4_Yield() here? */
            break;
        default:
            rpc_assert(!"logic error");
            break;
        }
    }

    return msg;
}

static inline
sel4_rpc_t *rpcmsg_commit(sel4_rpc_t *rpc, rpcmsg_t *msg)
{
    msg->mr0 = BIT_FIELD_SET(msg->mr0, RPC_MR0_STATE, RPC_MR0_STATE_PENDING);

    return rpc;
}

static inline
sel4_rpc_t *rpcmsg_compose(sel4_rpc_t *rpc, unsigned int op, seL4_Word mr0,
                        seL4_Word mr1, seL4_Word mr2, seL4_Word mr3)
{
    rpcmsg_t *msg = rpcmsg_new(rpc);

    rpc_assert(msg);
    rpc_assert(BIT_FIELD_GET(msg->mr0, RPC_MR0_STATE) == RPC_MR0_STATE_RESERVED);

    msg->mr0 = BIT_FIELD_SET(mr0, RPC_MR0_OP, op);
    msg->mr1 = mr1;
    msg->mr2 = mr2;
    msg->mr3 = mr3;

    return rpcmsg_commit(rpc, msg);
}

/******************** message constructors for both sides ********************/

static inline
sel4_rpc_t *ntfn_status(sel4_rpc_t *rpc, unsigned int status)
{
    return rpcmsg_compose(rpc, RPC_MR0_OP_NOTIFY_STATUS, 0, status, 0, 0);
}

/************ message constructors for device (sending to driver) ************/

static inline
sel4_rpc_t *driver_ntfn_device_status(sel4_rpc_t *rpc, unsigned int status)
{
    return ntfn_status(rpc, status);
}

static inline
sel4_rpc_t *driver_req_create_vpci_device(sel4_rpc_t *rpc, seL4_Word pcidev)
{
    return rpcmsg_compose(rpc, RPC_MR0_OP_REGISTER_PCI_DEV, 0, pcidev, 0, 0);
}

static inline
sel4_rpc_t *driver_req_set_irqline(sel4_rpc_t *rpc, seL4_Word irq)
{
    return rpcmsg_compose(rpc, RPC_MR0_OP_SET_IRQ, 0, irq, 0, 0);
}

static inline
sel4_rpc_t *driver_req_clear_irqline(sel4_rpc_t *rpc, seL4_Word irq)
{
    return rpcmsg_compose(rpc, RPC_MR0_OP_CLR_IRQ, 0, irq, 0, 0);
}

static inline
sel4_rpc_t *driver_ack_mmio_finish(sel4_rpc_t *rpc, unsigned int slot, seL4_Word data)
{
    seL4_Word mr0 = 0;

    mr0 = BIT_FIELD_SET(mr0, RPC_MR0_MMIO_SLOT, slot);

    return rpcmsg_compose(rpc, RPC_MR0_OP_MMIO, mr0, 0, data, 0);
}

/************ message constructors for driver (sending to device) ************/

static inline
sel4_rpc_t *device_ntfn_driver_status(sel4_rpc_t *rpc, unsigned int status)
{
    return ntfn_status(rpc, status);
}

static inline
sel4_rpc_t *device_req_mmio_start(sel4_rpc_t *rpc, unsigned int direction,
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

    return rpcmsg_compose(rpc, RPC_MR0_OP_MMIO, mr0, mr1, mr2, 0);
}

/*****************************************************************************/

static inline
int sel4_rpc_init(sel4_rpc_t *rpc, rpcmsg_queue_t *rx, rpcmsg_queue_t *tx,
                  void (*doorbell)(void *doorbell_cookie),
                  void *doorbell_cookie)
{
    if (!rpc || !rx || !tx || !doorbell) {
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
