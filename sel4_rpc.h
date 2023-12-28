/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright 2022, Technology Innovation Institute
 *
 */
#ifndef __SEL4_RPC_H
#define __SEL4_RPC_H

#include <linux/types.h>
#include "sel4/sel4_vmm_rpc.h"
#include "sel4_virt_drv.h"

static inline int sel4_rpc_op_start_vm(struct sel4_vmm *vmm)
{
	return driver_req_start_vm(&vmm->rpc);
}

static inline int sel4_rpc_op_create_vpci_device(struct sel4_vmm *vmm,
						 u32 device)
{
	return driver_req_create_vpci_device(&vmm->rpc, pcidev);
}

static inline int sel4_rpc_op_destroy_vpci_device(struct sel4_vmm *vmm,
						  u32 device)
{
	// Not implemented
	return -ENOSYS;
}


static inline int sel4_rpc_op_set_irqline(struct sel4_vmm *vmm, u32 irq, u32 op)
{
	int rc = -EINVAL;

	switch (op) {
	case SEL4_IRQ_OP_SET:
		rc = driver_req_set_irqline(&vmm->rpc, irq);
		break;
	case SEL4_IRQ_OP_CLR:
		rc = driver_req_clear_irqline(&vmm->rpc, irq);
		break;
	default:
		break;
	}

	return rc;
}

static inline int sel4_rpc_op_set_mmio_region(struct sel4_vmm *vmm,
					      struct sel4_mmio_region_config *config)
{
	if (!config) {
		return -EINVAL;
	}

	return driver_req_mmio_region_config(rpc, config->gpa, config->len,
					     config->flags);
}

static inline int sel4_rpc_op_notify_io_handled(struct sel4_vmm *vmm, u32 slot)
{
	return driver_ack_mmio_finish(&vmm->rpc, slot);
}

#endif /* __SEL4_RPC_H */
