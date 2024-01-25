/*
 * Copyright 2022, 2023, 2024, Technology Innovation Institute
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#ifdef __KERNEL__
#include <linux/atomic.h>
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
#include <stdbool.h>

#define __maybe_unused __attribute__ ((unused))
#endif

typedef unsigned long seL4_Word;

#define atomic_load_acquire(ptr) __atomic_load_n(ptr, __ATOMIC_ACQUIRE)
#define atomic_store_release(ptr, i)  __atomic_store_n(ptr, i, __ATOMIC_RELEASE)

#ifndef __KERNEL__
#define atomic_compare_and_swap(_p, _o, _n) __sync_bool_compare_and_swap(_p, _o, _n)
#else
#define atomic_compare_and_swap(_p, _o, _n) (arch_cmpxchg((_p), (_o), (_n)) == (_o))
#endif

#if defined(__KERNEL__)
#define rpc_assert(_cond) BUG_ON(!(_cond))
#else
#define rpc_assert assert
#endif

#define IOBUF_NUM_PAGES             2

#define IOBUF_PAGE_DRIVER_RX        1
#define IOBUF_PAGE_DRIVER_TX        0

#define IOBUF_PAGE_DEVICE_RX        IOBUF_PAGE_DRIVER_TX
#define IOBUF_PAGE_DEVICE_TX        IOBUF_PAGE_DRIVER_RX

#define iobuf_page(_iobuf, _page)   (((uintptr_t)(_iobuf)) + (4096 * (_page)))

#define driver_tx_queue(_iobuf)     ((rpcmsg_queue_t *)iobuf_page((_iobuf), IOBUF_PAGE_DRIVER_TX))
#define driver_rx_queue(_iobuf)     ((rpcmsg_queue_t *)iobuf_page((_iobuf), IOBUF_PAGE_DRIVER_RX))

#define device_tx_queue(_iobuf)     ((rpcmsg_queue_t *)iobuf_page((_iobuf), IOBUF_PAGE_DEVICE_TX))
#define device_rx_queue(_iobuf)     ((rpcmsg_queue_t *)iobuf_page((_iobuf), IOBUF_PAGE_DEVICE_RX))

#ifndef MASK
#define MASK(_n)                        ((1UL << (_n)) - 1)
#endif

#define BIT_FIELD_MASK(_name)           (MASK(_name ## _WIDTH) << (_name ## _SHIFT))

#define BIT_FIELD_CLR_ALL(_v, _name)    ((_v) & ~BIT_FIELD_MASK(_name))
#define BIT_FIELD_SET_ALL(_v, _name)    ((_v) | BIT_FIELD_MASK(_name))

#define BIT_FIELD_GET(_v, _name)        (((_v) >> (_name ## _SHIFT)) & MASK(_name ## _WIDTH))
#define BIT_FIELD_SET(_v, _name, _n)    ((BIT_FIELD_CLR_ALL(_v, _name)) | ((((seL4_Word)(_n)) << (_name ## _SHIFT)) & BIT_FIELD_MASK(_name)))

#define RPCMSG_STATE_FREE               0
#define RPCMSG_STATE_DRIVER             1
#define RPCMSG_STATE_DEVICE_KERNEL      2
#define RPCMSG_STATE_DEVICE_USER        3
#define RPCMSG_STATE_ERROR              ~0U

#define rpcmsg_state_ptr(_msg_ptr)          ((uint32_t *)&(_msg_ptr)->mr0)
#define rpcmsg_state_get(_msg_ptr)          atomic_load_acquire(rpcmsg_state_ptr(_msg_ptr))
#define rpcmsg_state_set(_msg_ptr, _state)  atomic_store_release(rpcmsg_state_ptr(_msg_ptr), _state)

#define RPC_MR0_STATE_WIDTH             32
#define RPC_MR0_STATE_SHIFT             0

#define RPC_MR0_OP_WIDTH                6
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define RPC_MR0_OP_SHIFT                32
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define RPC_MR0_OP_SHIFT                0
#else
#error Cannot determinate endianness
#endif

/* from VMM to QEMU */
#define QEMU_OP_MMIO        0
#define QEMU_OP_PUTC_LOG    2

/* from QEMU to VMM */
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
    /* the message state this is hooked to */
    unsigned int my_state;
    void (*doorbell)(void *doorbell_cookie);
    void *doorbell_cookie;
} sel4_rpc_t;

#define QUEUE_NEXT(_i) (((_i) + 1) & (RPCMSG_BUFFER_SIZE - 1))

__maybe_unused static void rpcmsg_queue_init(rpcmsg_queue_t *q)
{
    memset(q, 0, sizeof(*q));
}

static inline
int rpcmsg_queue_iterate(rpcmsg_queue_t *q,
                         unsigned int handler_state,
                         unsigned int (*fn)(rpcmsg_t *msg, void *cookie),
                         void *cookie)
{
    rpcmsg_t *msg;
    unsigned int state;
    unsigned int head;

    do {
        head = atomic_load_acquire(&q->head);
        if (head == q->tail) {
            break;
        }

        msg = q->data + head;

        state = rpcmsg_state_get(msg);
        if (state != RPCMSG_STATE_FREE) {
            if (state != handler_state) {
                break;
            }

            state = fn(msg, cookie);
            if (state == RPCMSG_STATE_ERROR) {
                return -1;
            }
        }

        rpcmsg_state_set(msg, state);
        if (state == RPCMSG_STATE_FREE) {
            head = QUEUE_NEXT(head);
        }

        atomic_store_release(&q->head, head);
    } while (state == RPCMSG_STATE_FREE);

    return 0;
}

static inline int sel4_rpc_rx_process(sel4_rpc_t *rpc,
                                      unsigned int (*fn)(rpcmsg_t *msg, void *cookie),
                                      void *cookie)
{
    return rpcmsg_queue_iterate(rpc->rx_queue, rpc->my_state, fn, cookie);
}

static inline void plat_yield(void)
{
    /* TODO */
}

static inline rpcmsg_t *rpcmsg_new(rpcmsg_queue_t *q, unsigned int state)
{
    unsigned int tail, next;

    rpc_assert(q);

    do {
        for (;;) {
            tail = q->tail;
            next = QUEUE_NEXT(tail);

            if (next != q->head) {
                break;
            }

            /* messages are produced faster than they are consumed */
            plat_yield();
        }

        /* if there are multiple writers, only one of those will succeed doing
         * CAS on state below -- the others will keep looping until queue's tail
         * is updated by that specific writer which broke out of loop -- the
         * process will repeat inductively until only one writer is left.
         */
    } while (!atomic_compare_and_swap(rpcmsg_state_ptr(q->data + tail),
                                      RPCMSG_STATE_FREE,
                                      state));

    /* since we modified state of message pointed by tail, we want that
     * store to finish before updating tail.
     */
    atomic_store_release(&q->tail, next);

    return q->data + tail;
}

static inline bool rpcmsg_queue_full(rpcmsg_queue_t *q)
{
    return QUEUE_NEXT(q->tail) == q->head;
}

static inline bool rpcmsg_queue_empty(rpcmsg_queue_t *q)
{
    return q->tail == q->head;
}

static inline int sel4_rpc_doorbell(sel4_rpc_t *rpc)
{
    if (!rpc || !rpc->tx_queue || !rpc->doorbell) {
        return -1;
    }

    if (!rpcmsg_queue_empty(rpc->tx_queue)) {
        rpc->doorbell(rpc->doorbell_cookie);
    }

    return 0;
}

static inline int rpcmsg_send(sel4_rpc_t *rpc, unsigned int op,
                              seL4_Word mr0, seL4_Word mr1,
                              seL4_Word mr2, seL4_Word mr3)
{
    rpcmsg_t *msg = rpcmsg_new(rpc->tx_queue, rpc->my_state);

    rpc_assert(msg);
    rpc_assert(rpcmsg_state_get(msg) == rpc->my_state);

    mr0 = BIT_FIELD_SET(mr0, RPC_MR0_STATE, rpcmsg_state_get(msg));
    mr0 = BIT_FIELD_SET(mr0, RPC_MR0_OP, op);

    msg->mr0 = mr0;
    msg->mr1 = mr1;
    msg->mr2 = mr2;
    msg->mr3 = mr3;

    if (rpc->my_state == RPCMSG_STATE_DRIVER) {
        rpcmsg_state_set(msg, RPCMSG_STATE_DEVICE_KERNEL);
    } else {
        rpcmsg_state_set(msg, RPCMSG_STATE_DRIVER);
    }

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

static inline int sel4_rpc_init(sel4_rpc_t *rpc, rpcmsg_queue_t *rx,
                                rpcmsg_queue_t *tx,
                                unsigned int handler_state,
                                void (*doorbell)(void *doorbell_cookie),
                                void *doorbell_cookie)
{
    if (!rpc || !rx || !tx || !doorbell) {
        return -1;
    }

    rpc->rx_queue = rx;
    rpc->tx_queue = tx;
    rpc->my_state = handler_state;
    rpc->doorbell = doorbell;
    rpc->doorbell_cookie = doorbell_cookie;

    /* note that we do not initialize the queues themselves -- they are
     * initialized statically on boot and dynamically on VM reboot
     */

    return 0;
}
