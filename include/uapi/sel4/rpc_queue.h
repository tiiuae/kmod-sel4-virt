/*
 * Copyright 2024, Technology Innovation Institute
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#ifdef __KERNEL__
#include <linux/atomic.h>
#include <linux/string.h>
#include <linux/bitmap.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/compiler_attributes.h>
#else
#include <string.h>
#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>

#define __maybe_unused __attribute__ ((unused))
#endif

typedef unsigned long seL4_Word;

#define atomic_load_acquire(ptr) __atomic_load_n(ptr, __ATOMIC_ACQUIRE)
#define atomic_store_release(ptr, i)  __atomic_store_n(ptr, i, __ATOMIC_RELEASE)

#ifndef __KERNEL__
#define atomic_compare_and_swap(_p, _o, _n) __atomic_compare_exchange_n(_p, _o, _n, false, __ATOMIC_ACQUIRE, __ATOMIC_ACQUIRE)
#else
#define atomic_compare_and_swap(_p, _o, _n) (arch_cmpxchg((_p), *(_o), (_n)) == *(_o))
#endif

#if defined(__KERNEL__)
#define rpc_assert(_cond) BUG_ON(!(_cond))
#else
#define rpc_assert assert
#endif

#ifndef DECLARE_BITMAP
#define DECLARE_BITMAP(name, bits)	\
	unsigned long name[((bits) + (8 * sizeof(unsigned long)) - 1) / (8 * sizeof(unsigned long))]
#endif

#ifndef min
#define min(_a, _b) ((_a) < (_b) ? (_a) : (_b))
#endif

#if !defined(__KERNEL__)
#define find_first_zero_bit _find_first_zero_bit
static inline
unsigned long _find_first_zero_bit(const unsigned long *addr,
				   unsigned long size)
{
	unsigned long i, v, n = size;
	unsigned long n_bits = (8 * sizeof(unsigned long));

	for (i = 0; i * n_bits < n; i++) {
		v = ~addr[i];
		if (v) {
			n = min(i * n_bits + __builtin_ctzl(v), n);
			break;
		}
	}
	return n;
}
#endif

#if !defined(__KERNEL__)
#define set_bit _set_bit

static inline
void _set_bit(unsigned long nr, volatile unsigned long *addr)
{
	unsigned long n_bits = (8 * sizeof(unsigned long));
	unsigned long mask = (1UL << (nr % n_bits));

	addr += nr / n_bits;

	__sync_fetch_and_or(addr, mask);
}
#endif

#if !defined(__KERNEL__)
#define clear_bit _clear_bit

static inline
void _clear_bit(unsigned long nr, volatile unsigned long *addr)
{
	unsigned long n_bits = (8 * sizeof(unsigned long));
	unsigned long mask = (1UL << (nr % n_bits));

	addr += nr / n_bits;

	__sync_fetch_and_and(addr, ~mask);
}
#endif

/*****************************************************************************/

#define RPCMSG_BUFFER_SIZE 32
#define RPCMSG_BUFFER_MASK (RPCMSG_BUFFER_SIZE - 1)
#define RPCMSG_HTD_MAX ((RPCMSG_BUFFER_SIZE) / 4)

static_assert(RPCMSG_BUFFER_SIZE != 0 ||
	      (RPCMSG_BUFFER_SIZE & RPCMSG_BUFFER_MASK) == 0,
	      "message buffer size must be power of two");

typedef struct {
	seL4_Word mr0;
	seL4_Word mr1;
	seL4_Word mr2;
	seL4_Word mr3;
} rpcmsg_t;

typedef struct rpcmsg_buffer {
	rpcmsg_t messages[RPCMSG_BUFFER_SIZE];
} rpcmsg_buffer_t;

struct _rpcmsg_marker {
	uint32_t pos;
	uint32_t count;
};

typedef union rpcmsg_marker {
	uint64_t raw  __attribute__ ((aligned (8)));
	uint32_t val;
	struct _rpcmsg_marker marker;
} rpcmsg_marker_t;

typedef struct rpcmsg_queue_bound {
	volatile rpcmsg_marker_t tail;
	volatile rpcmsg_marker_t head;
} rpcmsg_queue_bound_t;

typedef struct rpcmsg_queue_t {
	volatile rpcmsg_queue_bound_t prod;
	volatile rpcmsg_queue_bound_t cons;
	uint16_t ring[RPCMSG_BUFFER_SIZE];
} rpcmsg_queue_t;

typedef void rpcmsg_enqueue_elem_fn_t(rpcmsg_queue_t *q,
				      rpcmsg_buffer_t *b,
				      uint32_t ring_index,
				      void const * const tx_data);
typedef void rpcmsg_dequeue_elem_fn_t(rpcmsg_queue_t *q,
				      rpcmsg_buffer_t *b,
				      uint32_t ring_index,
				      void * const rx_data);

__maybe_unused static void rpcmsg_queue_init(rpcmsg_queue_t * const q)
{
	memset(q, 0, sizeof(*q));
}

__maybe_unused static void rpcmsg_buffer_init(rpcmsg_buffer_t * const b)
{
	memset(b, 0, sizeof(*b));
}

static inline
bool rpcmsg_queue_full(rpcmsg_queue_t const * const q)
{
	rpc_assert(q);

	return (RPCMSG_BUFFER_SIZE + q->cons.tail.val - q->prod.tail.val) == 0;
}

static inline
bool rpcmsg_queue_empty(rpcmsg_queue_t *q)
{
	rpc_assert(q);

	return q->prod.head.val == q->cons.head.val;
}

static inline
uint16_t rpcmsg_msg_to_id(rpcmsg_buffer_t *buffer, rpcmsg_t *msg)
{
	uint16_t id;

	rpc_assert(buffer);
	rpc_assert(msg);

	id = msg - buffer->messages;
	rpc_assert(id < RPCMSG_BUFFER_SIZE);

	return id;
}

static inline
rpcmsg_t *rpcmsg_id_to_msg(rpcmsg_buffer_t * const buffer, uint16_t id)
{
	rpc_assert(buffer);
	rpc_assert(id < RPCMSG_BUFFER_SIZE);

	return &buffer->messages[id];
}

static inline
void rpcmsg_plat_yield(void)
{
	/* FIXME: sleep/yield/schedule */
}

static inline
void rpcmsg_tail_wait(volatile const rpcmsg_queue_bound_t *bound,
		      rpcmsg_marker_t *tail)
{
	while (tail->marker.pos - bound->head.marker.pos > RPCMSG_HTD_MAX) {
		rpcmsg_plat_yield();
		tail->raw = atomic_load_acquire(&bound->tail.raw);
	}
}

static inline
int rpcmsg_acquire_prod_entry(rpcmsg_queue_t *q, uint32_t *entry)
{
	rpcmsg_marker_t ot, nt;
	uint32_t entries;
	int ret = 0;

	ot.raw = atomic_load_acquire(&q->prod.tail.raw);

	do {
		/* wait for producer head/tail distance */
		rpcmsg_tail_wait(&q->prod, &ot);

		/* check size */
		entries = RPCMSG_BUFFER_SIZE + q->cons.head.marker.pos - ot.marker.pos;
		if (!entries) {
			ret = -1;
			break;
		}

		nt.marker.pos = ot.marker.pos + 1;
		nt.marker.count = ot.marker.count + 1;
	} while (!atomic_compare_and_swap(&q->prod.tail.raw, (uint64_t *)(uintptr_t)&ot.raw, nt.raw));

	*entry = ot.marker.pos;

	return ret;
}

static inline
int rpcmsg_acquire_cons_entry(rpcmsg_queue_t *q, uint32_t *entry)
{
	rpcmsg_marker_t ot, nt;
	uint32_t entries;
	int ret = 0;

	ot.raw = atomic_load_acquire(&q->cons.tail.raw);

	do {
		/* wait for consumer head/tail distance */
		rpcmsg_tail_wait(&q->cons, &ot);

		entries = q->prod.head.marker.pos - ot.marker.pos;
		if (!entries) {
			/* empty */
			ret = -1;
			break;
		}

		nt.marker.pos = ot.marker.pos + 1;
		nt.marker.count = ot.marker.count + 1;

	} while (!atomic_compare_and_swap(&q->cons.tail.raw, (uint64_t *)(uintptr_t)&ot.raw, nt.raw));

	*entry = ot.marker.pos;

	return ret;
}

static inline
void rpcmsg_commit_update(volatile rpcmsg_queue_bound_t *bound)
{
	rpcmsg_marker_t t, oh, nh;

	/*
	 * If there are other enqueues/dequeues in progress that
	 * might preceded us, then don't update marker position, just updater
	 * count.
	 */
	oh.raw = atomic_load_acquire(&bound->head.raw);

	do {
		t.raw = atomic_load_acquire(&bound->tail.raw);

		nh.raw = oh.raw;
		if (++nh.marker.count == t.marker.count)
			nh.marker.pos = t.marker.pos;

	} while (!atomic_compare_and_swap(&bound->head.raw, (uint64_t *)(uintptr_t)&oh.raw, nh.raw));
}

static inline
int rpcmsg_enqueue(rpcmsg_queue_t *q, rpcmsg_buffer_t *b,
		   rpcmsg_enqueue_elem_fn_t enqueue_fn, void const * const data)
{
	uint32_t entry;

	rpc_assert(q);
	rpc_assert(b);
	rpc_assert(enqueue_fn);
	rpc_assert(data);

	if (rpcmsg_acquire_prod_entry(q, &entry)) {
		/* full */
		return -1;
	}

	/* enqueue entry */
	enqueue_fn(q, b, entry & RPCMSG_BUFFER_MASK, data);
	rpcmsg_commit_update(&q->prod);

	return 0;
}

static inline
int rpcmsg_dequeue(rpcmsg_queue_t *q, rpcmsg_buffer_t *b,
		   rpcmsg_dequeue_elem_fn_t dequeue_fn, void * const data)
{
	uint32_t entry;

	rpc_assert(q);
	rpc_assert(b);
	rpc_assert(dequeue_fn);
	rpc_assert(data);

	if (rpcmsg_acquire_cons_entry(q, &entry)) {
		/* empty */
		return -1;
	}

	/* dequeue entry */
	dequeue_fn(q, b, entry & RPCMSG_BUFFER_MASK, data);
	rpcmsg_commit_update(&q->cons);

	return 0;
}

#define RPCMSG_F_INIT_BUFFER	1
#define RPCMSG_F_INIT_QUEUE	2
#define RPCMSG_F_INIT_ALL	(~0)

#define _rpcmsg_queue_init(_ptr, _b, _q, _flags)	\
	do {						\
		(_ptr)->buffer = (_b);			\
		(_ptr)->queue = (_q);			\
		if ((_flags) & RPCMSG_F_INIT_BUFFER)	\
			rpcmsg_buffer_init((_b));	\
		if ((_flags) & RPCMSG_F_INIT_QUEUE)	\
			rpcmsg_queue_init((_q));	\
	} while(0)

/* Event queue is for fire-and-forget send semantics */
typedef struct rpcmsg_event_queue {
	rpcmsg_buffer_t *buffer;
	rpcmsg_queue_t *queue;
} rpcmsg_event_queue_t;

#define rpcmsg_event_txq_init(_ptr, _b, _q)	\
	_rpcmsg_queue_init((_ptr), (_b), (_q), RPCMSG_F_INIT_ALL)
#define rpcmsg_event_rxq_init(_ptr, _b, _q)	\
	_rpcmsg_queue_init((_ptr), (_b), (_q), 0)

static inline
void rpcmsg_event_enqueue_fn(rpcmsg_queue_t * const q,
			     rpcmsg_buffer_t * const b,
			     uint32_t ring_index,
			     void const * const data)
{
	rpcmsg_t *msg;

	rpc_assert(data);

	/* pointer to message buffer */
	msg = rpcmsg_id_to_msg(b, ring_index);

	/* copy data to message */
	memcpy(msg, data, sizeof(*msg));

	/* id to ring */
	q->ring[ring_index] = rpcmsg_msg_to_id(b, msg);
}

static inline
int rpcmsg_event_tx(rpcmsg_event_queue_t *eq,
		    seL4_Word mr0, seL4_Word mr1,
		    seL4_Word mr2, seL4_Word mr3)
{
	rpcmsg_t msg;

	rpc_assert(eq);

	msg.mr0 = mr0;
	msg.mr1 = mr1;
	msg.mr2 = mr2;
	msg.mr3 = mr3;

	return rpcmsg_enqueue(eq->queue, eq->buffer, rpcmsg_event_enqueue_fn, &msg);
}

static inline
void rpcmsg_event_dequeue_fn(rpcmsg_queue_t *q,
			     rpcmsg_buffer_t *b,
			     uint32_t ring_index,
			     void * const data)
{
	rpcmsg_t *msg;

	rpc_assert(data);

	/* pointer to received message */
	msg = rpcmsg_id_to_msg(b, q->ring[ring_index]);

	/* copy message to given pointer */
	memcpy(data, msg, sizeof(*msg));
}

static inline
int rpcmsg_event_rx(rpcmsg_event_queue_t *eq, rpcmsg_t *msg)
{
	rpc_assert(eq);

	return rpcmsg_dequeue(eq->queue, eq->buffer, rpcmsg_event_dequeue_fn, msg);
}

/* RPC queue is a mpmc queue that together with one or more reply queues
 * establish a request-reply communication pattern.
 *
 * When sending a message through a request queue, a message buffer is
 * lent for the request-reply sequence. A response is received through a reply
 * queue. A reply uses the same message buffer as the request. A Message ID
 * (index in the message buffer table) is used to match the request and the
 * reply together. When the response is received and processed, the message
 * buffer is explicitly reclaimed.
 *
 * On a given request-reply communication chain, there can be
 * - one request queue,
 * - optional forwarding queues, and
 * - one or more reply queue.
 *
 * A message contents may be changed *only* when the message is not queued.
 * The ownership to the message is passed on once the message is enqueued, and
 * the message buffer shouldn't be tampered with afterwards.
 *
 * Replies may be received out-of-order and it is up to the receiver keep
 * a receive buffer for unhandled messages.
 */
typedef struct rpcmsg_rpc_queue {
	rpcmsg_buffer_t *buffer;
	rpcmsg_queue_t *queue;
} rpcmsg_rpc_queue_t;

#define rpcmsg_call_queue_init(_ptr, _b, _q) \
	_rpcmsg_queue_init((_ptr), (_b), (_q), RPCMSG_F_INIT_ALL)
#define rpcmsg_recv_queue_init(_ptr, _b, _q) \
	_rpcmsg_queue_init((_ptr), (_b), (_q), 0)
#define rpcmsg_fwd_queue_init(_ptr, _b, _q) \
	_rpcmsg_queue_init((_ptr), (_b), (_q), RPCMSG_F_INIT_QUEUE)
#define rpcmsg_reply_queue_init(_ptr, _b, _q) \
	_rpcmsg_queue_init((_ptr), (_b), (_q), RPCMSG_F_INIT_QUEUE)

typedef DECLARE_BITMAP(rpcmsg_buffer_state_t, RPCMSG_BUFFER_SIZE);

#define rpcmsg_buffer_state_init(_buf_state)		\
	do {						\
		memset((_buf_state), 0,			\
		       sizeof(rpcmsg_buffer_state_t));	\
	} while(0)


static inline
rpcmsg_t *rpcmsg_lend_buffer(rpcmsg_rpc_queue_t *rpc,
			     rpcmsg_buffer_state_t state)
{
	uint16_t id;

	rpc_assert(rpc);

	id = find_first_zero_bit(state, RPCMSG_BUFFER_SIZE);
	if (id >= RPCMSG_BUFFER_SIZE) {
		/* all messages in use */
		return NULL;
	}

	set_bit(id, state);
	return rpcmsg_id_to_msg(rpc->buffer, id);
}

static inline
void rpcmsg_reclaim_buffer(rpcmsg_rpc_queue_t *rpc,
			   rpcmsg_buffer_state_t state,
			   rpcmsg_t *msg)
{
	rpc_assert(rpc);
	rpc_assert(state);
	rpc_assert(msg);

	clear_bit(rpcmsg_msg_to_id(rpc->buffer, msg), state);
}

static inline
void rpcmsg_rpc_enqueue_fn(rpcmsg_queue_t *q,
			   rpcmsg_buffer_t *b,
			   uint32_t ring_index,
			   void const * const data)
{
	rpc_assert(q);
	rpc_assert(b);
	rpc_assert(data);

	/* id to ring */
	q->ring[ring_index] = rpcmsg_msg_to_id(b, (rpcmsg_t *) data);
}

static inline
int rpcmsg_request(rpcmsg_rpc_queue_t *rpc,
		   rpcmsg_buffer_state_t state,
		   seL4_Word mr0, seL4_Word mr1,
		   seL4_Word mr2, seL4_Word mr3)
{
	rpcmsg_t *msg;

	rpc_assert(rpc);
	rpc_assert(state);

	/* find next available buffer for rpc */
	msg = rpcmsg_lend_buffer(rpc, state);

	msg->mr0 = mr0;
	msg->mr1 = mr1;
	msg->mr2 = mr2;
	msg->mr3 = mr3;

	if (rpcmsg_enqueue(rpc->queue, rpc->buffer, rpcmsg_rpc_enqueue_fn, msg)) {
		rpcmsg_reclaim_buffer(rpc, state, msg);
		return -1;
	}

	return (int) rpcmsg_msg_to_id(rpc->buffer, msg);
}

static inline
void rpcmsg_rpc_dequeue_fn(rpcmsg_queue_t *q,
			   rpcmsg_buffer_t *b,
			   uint32_t ring_index,
			   void * const data)
{
	rpcmsg_t **msg = data;

	rpc_assert(q);
	rpc_assert(b);
	rpc_assert(msg);

	/* pointer to received message */
	*msg = rpcmsg_id_to_msg(b, q->ring[ring_index]);
}

static inline
rpcmsg_t *rpcmsg_receive(rpcmsg_rpc_queue_t *rpc)
{
	rpcmsg_t *msg;

	rpc_assert(rpc);

	if (!rpcmsg_dequeue(rpc->queue, rpc->buffer, rpcmsg_rpc_dequeue_fn, &msg)) {
		return msg;
	}

	return NULL;
}

static inline
int rpcmsg_reply(rpcmsg_rpc_queue_t *rpc, rpcmsg_t *msg)
{
	rpc_assert(rpc);
	rpc_assert(msg);

	return rpcmsg_enqueue(rpc->queue, rpc->buffer, rpcmsg_rpc_enqueue_fn, msg);
}

static inline
rpcmsg_t *rpcmsg_receive_response(rpcmsg_rpc_queue_t *rpc,
				  uint16_t *transaction_id)
{
	rpcmsg_t *msg = NULL;

	rpc_assert(rpc);

	if (!rpcmsg_dequeue(rpc->queue, rpc->buffer, rpcmsg_rpc_dequeue_fn, &msg)) {
		if (transaction_id) {
			*transaction_id = rpcmsg_msg_to_id(rpc->buffer, msg);
		}
	}

	return msg;
}

static inline
int rpcmsg_forward(rpcmsg_rpc_queue_t *rpc, rpcmsg_t *msg)
{
	rpc_assert(rpc);
	rpc_assert(msg);

	return rpcmsg_enqueue(rpc->queue, rpc->buffer, rpcmsg_rpc_enqueue_fn, msg);
}

