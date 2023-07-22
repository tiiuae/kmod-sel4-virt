/*
 * Copyright 2022, Technology Innovation Institute
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

#if !defined(SEL4_VMM)
typedef unsigned long seL4_Word;
#endif

#if defined(__KERNEL__)
#define rpc_assert(_cond) BUG_ON(!(_cond))
#else
#define rpc_assert assert
#endif

#ifdef SEL4_VMM
#define IOBUF_PAGE_RECV 2
#define IOBUF_PAGE_SEND 1
#else
#define IOBUF_PAGE_RECV 1
#define IOBUF_PAGE_SEND 2
#endif
#define IOBUF_PAGE_MMIO 0

#define iobuf_page(_iobuf, _page) (((uintptr_t)(_iobuf)) + (4096 * (_page)))

#define tx_queue(_iobuf) ((rpcmsg_queue_t *)iobuf_page((_iobuf), IOBUF_PAGE_SEND))
#define rx_queue(_iobuf) ((rpcmsg_queue_t *)iobuf_page((_iobuf), IOBUF_PAGE_RECV))
#define mmio_reqs(_iobuf) ((struct sel4_iohandler_buffer *)iobuf_page((_iobuf), IOBUF_PAGE_MMIO))

/* from VMM to QEMU */
#define QEMU_OP_IO_HANDLED  0
#define QEMU_OP_PUTC_LOG    2

/* from QEMU to VMM */
#define QEMU_OP_SET_IRQ     16
#define QEMU_OP_CLR_IRQ     17
#define QEMU_OP_START_VM    18
#define QEMU_OP_REGISTER_PCI_DEV    19

#define QEMU_OP_MASK        0xffULL
#define QEMU_OP_SHIFT       0
#define QEMU_OP(__x__)      ((unsigned int)(((__x__) & QEMU_OP_MASK) >> QEMU_OP_SHIFT))

#define RPCMSG_BUFFER_SIZE  32

typedef struct {
    seL4_Word mr0;
    seL4_Word mr1;
    seL4_Word mr2;
    seL4_Word mr3;
} rpcmsg_t;

typedef struct {
    uint32_t head;
    uint32_t tail;
    uint32_t rsvd[2];
    rpcmsg_t data[RPCMSG_BUFFER_SIZE];
} rpcmsg_queue_t;

#define QUEUE_NEXT(_i) (((_i) + 1) & (RPCMSG_BUFFER_SIZE - 1))

__maybe_unused static void rpcmsg_queue_init(rpcmsg_queue_t *q)
{
    memset(q, 0, sizeof(*q));
}

static inline bool rpcmsg_queue_full(rpcmsg_queue_t *q)
{
    return QUEUE_NEXT(q->tail) == q->head;
}

static inline bool rpcmsg_queue_empty(rpcmsg_queue_t *q)
{
    return q->tail == q->head;
}

static inline rpcmsg_t *rpcmsg_queue_head(rpcmsg_queue_t *q)
{
    return rpcmsg_queue_empty(q) ? NULL : (q->data + q->head);
}

static inline rpcmsg_t *rpcmsg_queue_tail(rpcmsg_queue_t *q)
{

    return rpcmsg_queue_full(q) ? NULL : (q->data + q->tail);
}

static inline void rpcmsg_queue_advance_head(rpcmsg_queue_t *q)
{
    rpc_assert(!rpcmsg_queue_empty(q));
    q->head = QUEUE_NEXT(q->head);
}

static inline void rpcmsg_queue_advance_tail(rpcmsg_queue_t *q)
{
    rpc_assert((!rpcmsg_queue_full(q)));
    q->tail = QUEUE_NEXT(q->tail);
}

static inline void rpcmsg_queue_enqueue(rpcmsg_queue_t *q, rpcmsg_t *msg)
{
    rpc_assert(!rpcmsg_queue_full(q));
    memcpy(q->data + q->tail, msg, sizeof(*msg));
    q->tail = QUEUE_NEXT(q->tail);
}
