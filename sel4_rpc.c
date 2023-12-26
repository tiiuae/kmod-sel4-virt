// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright 2022, Technology Innovation Institute
 *
 */
#include <linux/errno.h>
#include <linux/slab.h>

#include "sel4_rpc.h"
#include "sel4/sel4_virt.h"

static int sel4_rpc_send_msg(struct sel4_rpc *rpc, const rpcmsg_t *msg)
{
	int err;

	BUG_ON(!rpc || !rpc->tx_queue || !msg);

	rpc = rpcmsg_compose(rpc, msg->mr0, 0, msg->mr1, msg->mr2, msg->mr3);
	if (!rpc) {
		pr_err("rpcmsg_compose() failed");
		return -EBUSY;
	}

	err = sel4_rpc_doorbell(rpc);
	if (err) {
		pr_err("sel4_rpc_doorbell() failed");
		return -EBUSY;
	}

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
		.mr0 = QEMU_OP_REGISTER_PCI_DEV,
		.mr1 = pcidev,
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

int sel4_rpc_notify_io_handled(struct sel4_rpc *rpc, u32 slot)
{
	rpcmsg_t msg = {
		.mr0 = QEMU_OP_IO_HANDLED,
		.mr1 = slot,
	};


	BUG_ON(!rpc);

	return sel4_rpc_send_msg(rpc, &msg);
}

int sel4_rpc_set_mmio_region(struct sel4_rpc *rpc,
			     struct sel4_mmio_region_config *config)
{
	rpcmsg_t msg = {
		.mr0 = QEMU_OP_MMIO_REGION_CONFIG,
		.mr1 = config->gpa,
		.mr2 = config->len,
		.mr3 = config->flags,

	};

	BUG_ON(!rpc);

	return sel4_rpc_send_msg(rpc, &msg);
}

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
		pr_err("sel4_rpc_init() failed");
		kfree(rpc);
		return ERR_PTR(-EINVAL);
	}

	return rpc;
}

void sel4_rpc_destroy(struct sel4_rpc *rpc)
{
	BUG_ON(!rpc);

	kfree(rpc);
}
