// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright 2022, Technology Innovation Institute
 *
 */
#include <linux/errno.h>
#include <linux/slab.h>

#include "sel4/sel4_virt.h"

struct sel4_rpc *sel4_rpc_create(rpcmsg_queue_t *tx,
				 rpcmsg_queue_t *rx,
				 void (*doorbell)(void *),
				 void *private)
{
	struct sel4_rpc *rpc;
	int err;

	BUG_ON(!tx || !rx || !doorbell);

	rpc = kzalloc(sizeof(struct sel4_rpc), GFP_KERNEL);
	if (!rpc) {
		return ERR_PTR(-ENOMEM);
	}

	err = sel4_rpc_init(rpc, rx, tx, doorbell, private);
	if (err) {
		kfree(rpc);
		return ERR_PTR(-EINVAL);
	}

	return rpc;
}

void sel4_rpc_destroy(struct sel4_rpc *rpc)
{
	BUG_ON(!rpc);

	rpc->tx_queue = NULL;
	rpc->rx_queue = NULL;
	rpc->doorbell = NULL;
	rpc->doorbell_cookie = NULL;

	kfree(rpc);
}
