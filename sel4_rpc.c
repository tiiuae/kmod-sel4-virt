// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright 2022, Technology Innovation Institute
 *
 */
#include <linux/errno.h>
#include <linux/slab.h>

#include "sel4_rpc.h"
#include "sel4/sel4_virt.h"

static void sel4_rpc_doorbell_ring(struct sel4_rpc *rpc)
{
	BUG_ON(!rpc || !rpc->doorbell);
	rpc->doorbell(rpc->private);
}

static int sel4_rpc_send_msg(struct sel4_rpc *rpc, const rpcmsg_t *msg)
{
	rpcmsg_t *new;

	BUG_ON(!rpc || !rpc->tx_queue || !msg);

	spin_lock(&rpc->tx_lock);
	new = rpcmsg_queue_tail(rpc->tx_queue);
	if (!new) {
		pr_err("TX queue full\n");
		spin_unlock(&rpc->tx_lock);
		return -EBUSY;
	}

	*new = *msg;
	smp_mb();	// smb_wmb?
	rpcmsg_queue_advance_tail(rpc->tx_queue);
	sel4_rpc_doorbell_ring(rpc);
	spin_unlock(&rpc->tx_lock);

	return 0;
}

int sel4_rpc_start_vm(struct sel4_rpc *rpc)
{
	rpcmsg_t msg = {
		.mr0 = QEMU_OP_START_VM,
	};

	BUG_ON(!rpc);

	return sel4_rpc_send_msg(rpc, &msg);
}

int sel4_rpc_create_vpci_device(struct sel4_rpc *rpc, u32 pcidev)
{
	rpcmsg_t msg = {
		.mr0 = QEMU_OP_REGISTER_PCI_DEV | (pcidev << QEMU_PCIDEV_SHIFT),
	};

	BUG_ON(!rpc);

	return sel4_rpc_send_msg(rpc, &msg);
}

int sel4_rpc_set_irqline(struct sel4_rpc *rpc, u32 irq)
{
	rpcmsg_t msg = {
		.mr0 = QEMU_OP_SET_IRQ,
		.mr1 = irq,
	};

	BUG_ON(!rpc);

	return sel4_rpc_send_msg(rpc, &msg);
}

int sel4_rpc_clear_irqline(struct sel4_rpc *rpc, u32 irq)
{
	rpcmsg_t msg = {
		.mr0 = QEMU_OP_CLR_IRQ,
		.mr1 = irq,
	};

	BUG_ON(!rpc);

	return sel4_rpc_send_msg(rpc, &msg);
}

int sel4_rpc_notify_io_handled(struct sel4_rpc *rpc,
			       struct sel4_ioreq *ioreq)
{
	rpcmsg_t msg;
	int rc;

	BUG_ON(!rpc);

	rc = sel4_rpc_ioreq_to_msg(ioreq, &msg);
	if (rc)
		return rc;

	smp_store_release(&ioreq->state, SEL4_IOREQ_STATE_FREE);

	return sel4_rpc_send_msg(rpc, &msg);
}

struct sel4_rpc *sel4_rpc_create(rpcmsg_queue_t *tx,
				 rpcmsg_queue_t *rx,
				 void (*doorbell)(void *),
				 void *private)
{
	struct sel4_rpc *rpc;

	BUG_ON(!tx || !rx || !doorbell);

	rpc = kzalloc(sizeof(struct sel4_rpc), GFP_KERNEL);
	if (!rpc) {
		return ERR_PTR(-ENOMEM);
	}

	spin_lock_init(&rpc->tx_lock);

	rpc->tx_queue = tx;
	rpc->rx_queue = rx;
	rpc->doorbell = doorbell;
	rpc->private = private;

	rpcmsg_queue_init(rpc->tx_queue);
	rpcmsg_queue_init(rpc->rx_queue);

	return rpc;
}

void sel4_rpc_destroy(struct sel4_rpc *rpc)
{
	BUG_ON(!rpc);

	rpc->tx_queue = NULL;
	rpc->rx_queue = NULL;
	rpc->doorbell = NULL;
	rpc->private = NULL;

	kfree(rpc);
}

