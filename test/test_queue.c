// SPDX-License-Identifier: GPL-2.0-only

#define _GNU_SOURCE
#include "test_utils.h"

#include "sel4/rpc_queue.h"

#define assert_msg_eq(_l, _r)						\
	do {								\
		rpcmsg_t *__l = (_l), *__r = (_r);			\
		assert_eq(memcmp(__l, __r, sizeof(rpcmsg_t)), 0);	\
	} while (0)
#define assert_msg_fields_eq(_msg, _mr0, _mr1, _mr2, _mr3)	\
	do {							\
		rpcmsg_t _val = {				\
			.mr0 = (_mr0),				\
			.mr1 = (_mr1),				\
			.mr2 = (_mr2),				\
			.mr3 = (_mr3),				\
		};						\
		assert_msg_eq((_msg), &_val);			\
	} while (0)


static int test_id_to_msg(void)
{
	rpcmsg_buffer_t b;
	rpcmsg_t *msg;

	rpcmsg_buffer_init(&b);

	msg = rpcmsg_id_to_msg(&b, 2);
	assert_eq(msg, &b.messages[2]);

	msg = rpcmsg_id_to_msg(&b, 5);
	assert_eq(msg, &b.messages[5]);

	return 0;
}

static int test_msg_to_id(void)
{
	rpcmsg_buffer_t b;
	rpcmsg_t *msg;

	rpcmsg_buffer_init(&b);

	msg = &b.messages[2];
	assert_eq(rpcmsg_msg_to_id(&b, msg), 2);

	msg = &b.messages[5];
	assert_eq(rpcmsg_msg_to_id(&b, msg), 5);

	return 0;
}

static int test_queue_enqueue(void)
{
	rpcmsg_queue_t q;
	rpcmsg_buffer_t b;
	rpcmsg_t *msg;

	rpcmsg_queue_init(&q);
	rpcmsg_buffer_init(&b);

	assert_true(rpcmsg_queue_empty(&q));

	msg = rpcmsg_id_to_msg(&b, 2);
	assert_eq(rpcmsg_enqueue(&q, &b, rpcmsg_rpc_enqueue_fn, msg), 0);
	assert_eq(q.prod.tail.val, 1U);
	assert_eq(q.prod.head.val, 1U);
	assert_eq(q.ring[0], 2);

	msg = rpcmsg_id_to_msg(&b, 5);
	assert_eq(msg, &b.messages[5]);
	assert_eq(rpcmsg_enqueue(&q, &b, rpcmsg_rpc_enqueue_fn, msg), 0);
	assert_eq(q.prod.tail.val, 2U);
	assert_eq(q.prod.head.val, 2U);
	assert_eq(q.ring[1], 5);
	return 0;
}

static int test_queue_dequeue(void)
{
	rpcmsg_queue_t q;
	rpcmsg_buffer_t b;
	rpcmsg_t *msg = NULL;

	rpcmsg_queue_init(&q);
	rpcmsg_buffer_init(&b);

	q.prod.tail.val = 2;
	q.prod.head.val = 2;
	q.ring[0] = 2;
	q.ring[1] = 5;

	assert_false(rpcmsg_queue_empty(&q));

	assert_eq(rpcmsg_dequeue(&q, &b, rpcmsg_rpc_dequeue_fn, &msg), 0);
	assert_eq(rpcmsg_msg_to_id(&b, msg), 2);
	assert_eq(rpcmsg_dequeue(&q, &b, rpcmsg_rpc_dequeue_fn, &msg), 0);
	assert_eq(rpcmsg_msg_to_id(&b, msg), 5);

	assert_true(rpcmsg_queue_empty(&q));
	assert_eq(rpcmsg_dequeue(&q, &b, rpcmsg_rpc_dequeue_fn, &msg), -1);

	return 0;
}

static int test_enqueue_dequeue(void)
{
	rpcmsg_queue_t q;
	rpcmsg_buffer_t b;
	rpcmsg_t *msg;
	rpcmsg_t msg1 = {
		0x11223344,
		0x55667788,
		0x99AABBCC,
		0xDDEEFF00,
	};
	rpcmsg_queue_init(&q);
	rpcmsg_buffer_init(&b);

	msg = rpcmsg_id_to_msg(&b, 5);
	*msg = msg1;

	assert_eq(rpcmsg_enqueue(&q, &b, rpcmsg_rpc_enqueue_fn, msg), 0);
	assert_eq(rpcmsg_dequeue(&q, &b, rpcmsg_rpc_dequeue_fn, &msg), 0);

	assert_ne(msg, NULL);
	assert_msg_eq(msg, &msg1);

	return 0;
}

static int test_event_queue(void)
{
	rpcmsg_queue_t q;
	rpcmsg_buffer_t b;
	rpcmsg_event_queue_t eq;
	rpcmsg_t msg;

	rpcmsg_event_txq_init(&eq, &b, &q);

	assert_eq(rpcmsg_event_tx(&eq, 1, 2, 3, 4), 0);
	assert_eq(rpcmsg_event_tx(&eq, 5, 6, 7, 8), 0);

	assert_eq(rpcmsg_event_rx(&eq, &msg), 0);
	assert_msg_fields_eq(&msg, 1, 2, 3, 4);
	assert_eq(rpcmsg_event_rx(&eq, &msg), 0);
	assert_msg_fields_eq(&msg, 5, 6, 7, 8);

	assert_eq(rpcmsg_event_rx(&eq, &msg), -1);

	return 0;
}

#define bm_sz 72UL

static int test_find_first_zero_bit(void)
{
	DECLARE_BITMAP(bm, bm_sz);
	memset(bm, 0, sizeof(bm));

	assert_eq(find_first_zero_bit(bm, bm_sz), 0UL);
	bm[0] = ~(1UL << 35);
	assert_eq(find_first_zero_bit(bm, bm_sz), 35UL);
	bm[0] = ~(0UL);
	assert_eq(find_first_zero_bit(bm, bm_sz), 64UL);
	bm[1] = ~(1UL << ((72 - 64) - 1));
	assert_eq(find_first_zero_bit(bm, bm_sz), 71UL);
	bm[1] = ~(1UL << (72 - 64));
	assert_eq(find_first_zero_bit(bm, bm_sz), bm_sz);
	bm[1] = ~(0UL);
	assert_eq(find_first_zero_bit(bm, bm_sz), bm_sz);

	return 0;
}

static int test_set_bit(void)
{
	DECLARE_BITMAP(bm, bm_sz);
	memset(bm, 0, sizeof(bm));

	set_bit(33, bm);
	assert_eq(bm[0], (1UL << 33));

	set_bit(65, bm);
	assert_eq(bm[1], (1UL << 1));

	return 0;
}

static int test_clear_bit(void)
{
	DECLARE_BITMAP(bm, bm_sz);
	memset(bm, 0, sizeof(bm));

	bm[0] = 3UL << 33;
	clear_bit(33, bm);
	assert_eq(bm[0], (1UL << 34));

	bm[1] = 0xFF;
	clear_bit(71, bm);
	assert_eq(bm[1], 0x7FUL);

	clear_bit(66, bm);
	assert_eq(bm[1], 0x7BUL);

	return 0;
}

typedef struct caller {
	rpcmsg_rpc_queue_t request;
	rpcmsg_rpc_queue_t response;
	rpcmsg_buffer_state_t s;
} caller_t;

typedef struct callee {
	rpcmsg_rpc_queue_t request;
	rpcmsg_rpc_queue_t response;
} callee_t;

static void init_caller(caller_t *caller,
			rpcmsg_buffer_t *buffer,
			rpcmsg_queue_t *request,
			rpcmsg_queue_t *response)
{
	rpcmsg_call_queue_init(&caller->request, buffer, request);
	rpcmsg_recv_queue_init(&caller->response, buffer, response);
	rpcmsg_buffer_state_init(caller->s);
}

static void init_callee(callee_t *callee,
			rpcmsg_buffer_t *buffer,
			rpcmsg_queue_t *request,
			rpcmsg_queue_t *response)
{
	rpcmsg_recv_queue_init(&callee->request, buffer, request);
	rpcmsg_reply_queue_init(&callee->response, buffer, response);
}

static int test_request_reply(void)
{
	rpcmsg_queue_t req;
	rpcmsg_queue_t resp;
	rpcmsg_buffer_t b;
	caller_t caller;
	callee_t callee;
	rpcmsg_t *msg1;
	rpcmsg_t *msg2;
	uint16_t id = ~0;


	init_caller(&caller, &b, &req, &resp);
	init_callee(&callee, &b, &req, &resp);

	/* caller: queue transaction 1 */
	assert_eq(rpcmsg_request(&caller.request, caller.s, 1, 2, 3, 4), 0);
	assert_eq(caller.s[0], 0x1UL);

	/* caller: queue transaction 2 */
	assert_eq(rpcmsg_request(&caller.request, caller.s, 5, 6, 7, 8), 1);

	/* caller: ensure buffers lent */
	assert_eq(caller.s[0], 0x3UL);

	/* callee: dequeue requests */
	msg1 = rpcmsg_receive(&callee.request);
	assert_ne(msg1, NULL);
	assert_msg_fields_eq(msg1, 1, 2, 3, 4);

	msg2 = rpcmsg_receive(&callee.request);
	assert_ne(msg2, NULL);
	assert_msg_fields_eq(msg2, 5, 6, 7, 8);

	/* callee: queue reply in reverse order */
	assert_eq(rpcmsg_reply(&callee.response, msg2), 0);
	assert_eq(rpcmsg_reply(&callee.response, msg1), 0);

	/* caller: dequeue transaction 2 */
	msg1 = rpcmsg_receive_response(&caller.response, &id);
	assert_ne(msg1, NULL);
	assert_eq(id, 1);
	assert_msg_eq(msg1, msg2);

	/* caller: reclaim buffer for transaction 2 */
	assert_eq(caller.s[0], 0x3UL);
	rpcmsg_reclaim_buffer(&caller.response, caller.s, msg1);
	assert_eq(caller.s[0], 0x1UL);

	/* caller: dequeue transaction 1 */
	msg1 = rpcmsg_receive_response(&caller.response, NULL);
	assert_ne(msg1, NULL);
	assert_msg_fields_eq(msg1, 1, 2, 3, 4);

	/* caller: reclaim buffer for transaction 1 */
	rpcmsg_reclaim_buffer(&caller.response, caller.s, msg1);
	assert_eq(caller.s[0], 0x0UL);

	return 0;
}

int main(void)
{
	const struct test_case tests[] = {
		declare_test(test_id_to_msg),
		declare_test(test_msg_to_id),
		declare_test(test_queue_enqueue),
		declare_test(test_queue_dequeue),
		declare_test(test_enqueue_dequeue),
		declare_test(test_event_queue),
		declare_test(test_find_first_zero_bit),
		declare_test(test_set_bit),
		declare_test(test_clear_bit),
		declare_test(test_request_reply),
	};

	return run_tests(tests);
}

