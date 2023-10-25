/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright 2022, Technology Innovation Institute
 *
 */
#ifndef __SEL4_RPC_H
#define __SEL4_RPC_H

#include <linux/types.h>

#include "sel4_virt_drv.h"

int sel4_rpc_start_vm(struct sel4_rpc *rpc);
int sel4_rpc_create_vpci_device(struct sel4_rpc *rpc, u32 pcidev);
int sel4_rpc_set_irqline(struct sel4_rpc *rpc, u32 irq);
int sel4_rpc_clear_irqline(struct sel4_rpc *rpc, u32 irq);

struct sel4_rpc *sel4_rpc_create(rpcmsg_queue_t *tx, rpcmsg_queue_t *rx,
				 void (*doorbell)(void *), void *private);
void sel4_rpc_destroy(struct sel4_rpc *rpc);

static inline int sel4_rpc_op_start_vm(struct sel4_vmm *vmm)
{
	return sel4_rpc_doorbell(driver_ntfn_device_status(vmm->rpc, RPC_MR1_NOTIFY_STATUS_READY));
}

static inline int sel4_rpc_op_create_vpci_device(struct sel4_vmm *vmm, u32 device)
{
	return sel4_rpc_doorbell(driver_req_create_vpci_device(vmm->rpc, device));
}

static inline int sel4_rpc_op_destroy_vpci_device(struct sel4_vmm *vmm, u32 device)
{
	return -ENOSYS;
}

static inline int sel4_rpc_op_set_irqline(struct sel4_vmm *vmm, u32 irq, u32 op)
{
	int rc = -EINVAL;

	switch (op) {
	case SEL4_IRQ_OP_SET:
		rc = sel4_rpc_doorbell(driver_req_set_irqline(vmm->rpc, irq));
		break;
	case SEL4_IRQ_OP_CLR:
		rc = sel4_rpc_doorbell(driver_req_clear_irqline(vmm->rpc, irq));
		break;
	default:
		break;
	}

	return rc;
}

#endif /* __SEL4_RPC_H */
