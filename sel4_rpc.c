// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright 2022, Technology Innovation Institute
 *
 */
#include <linux/errno.h>
#include <linux/slab.h>

#include "sel4_rpc.h"
#include "sel4/sel4_virt.h"

int sel4_rpc_start_vm(struct sel4_rpc *rpc)
{
	return driver_req_start_vm(rpc);
}

int sel4_rpc_create_vpci_device(struct sel4_rpc *rpc, u32 pcidev)
{
	return driver_req_create_vpci_device(rpc, pcidev);
}

int sel4_rpc_set_irqline(struct sel4_rpc *rpc, u32 irq)
{
	return driver_req_set_irqline(rpc, irq);
}

int sel4_rpc_clear_irqline(struct sel4_rpc *rpc, u32 irq)
{
	return driver_req_clear_irqline(rpc, irq);
}

int sel4_rpc_notify_io_handled(struct sel4_rpc *rpc, u32 slot)
{
	return driver_ack_mmio_finish(rpc, slot);
}

int sel4_rpc_set_mmio_region(struct sel4_rpc *rpc,
			     struct sel4_mmio_region_config *config)
{
	return driver_req_mmio_region_config(rpc, config->gpa, config->len,
					     config->flags);
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
