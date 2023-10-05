/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright 2022, Technology Innovation Institute
 *
 */
#ifndef __SEL4_RPC_H
#define __SEL4_RPC_H

#include <linux/types.h>
#include <linux/spinlock.h>
#include "sel4/sel4_vmm_rpc.h"
#include "sel4_virt_drv.h"

struct sel4_rpc {
	spinlock_t tx_lock;
	rpcmsg_queue_t *tx_queue;
	rpcmsg_queue_t *rx_queue;
	void (*doorbell)(void *private);
	void *private;
};

#define mr0(_vcpu, _dir, _pcidev) \
	((((_dir) == SEL4_IO_DIR_WRITE) ? QEMU_OP_WRITE : QEMU_OP_READ) | \
	((_vcpu) << QEMU_VCPU_SHIFT) | \
	((_pcidev)  << QEMU_PCIDEV_SHIFT))

int sel4_rpc_start_vm(struct sel4_rpc *rpc);
int sel4_rpc_create_vpci_device(struct sel4_rpc *rpc, u32 pcidev);
int sel4_rpc_set_irqline(struct sel4_rpc *rpc, u32 irq);
int sel4_rpc_clear_irqline(struct sel4_rpc *rpc, u32 irq);
int sel4_rpc_notify_io_handled(struct sel4_rpc *rpc, u32 slot);
int sel4_rpc_set_mmio_region(struct sel4_rpc *rpc,
			     struct sel4_mmio_region_config *config);

struct sel4_rpc *sel4_rpc_create(rpcmsg_queue_t *tx, rpcmsg_queue_t *rx,
				 void (*doorbell)(void *), void *private);
void sel4_rpc_destroy(struct sel4_rpc *rpc);

static inline int sel4_rpc_op_start_vm(struct sel4_vmm *vmm)
{
	struct sel4_rpc *rpc = (struct sel4_rpc *) vmm->private;
	if (!rpc) {
		return -EINVAL;
	}
	return sel4_rpc_start_vm(rpc);
}

static inline int sel4_rpc_op_create_vpci_device(struct sel4_vmm *vmm,
						 u32 device)
{
	struct sel4_rpc *rpc = (struct sel4_rpc *) vmm->private;
	if (!rpc) {
		return -EINVAL;
	}
	return sel4_rpc_create_vpci_device(rpc, device);
}

static inline int sel4_rpc_op_destroy_vpci_device(struct sel4_vmm *vmm,
						  u32 device)
{
	struct sel4_rpc *rpc = (struct sel4_rpc *) vmm->private;
	if (!rpc) {
		return -EINVAL;
	}
	// Not implemented
	return -ENOSYS;
}


static inline int sel4_rpc_op_set_irqline(struct sel4_vmm *vmm, u32 irq, u32 op)
{
	int rc = -EINVAL;

	struct sel4_rpc *rpc = (struct sel4_rpc *) vmm->private;
	if (!rpc) {
		return -EINVAL;
	}
	switch (op) {
	case SEL4_IRQ_OP_SET:
		rc = sel4_rpc_set_irqline(rpc, irq);
		break;
	case SEL4_IRQ_OP_CLR:
		rc = sel4_rpc_clear_irqline(rpc, irq);
		break;
	default:
		break;
	}

	return rc;
}

static inline int sel4_rpc_op_set_mmio_region(struct sel4_vmm *vmm,
					      struct sel4_mmio_region_config *config)
{
	struct sel4_rpc *rpc = (struct sel4_rpc *) vmm->private;
	if (!rpc || !config) {
		return -EINVAL;
	}
	return sel4_rpc_set_mmio_region(rpc, config);
}

static inline int sel4_rpc_op_notify_io_handled(struct sel4_vmm *vmm, u32 slot)
{
	struct sel4_rpc *rpc = (struct sel4_rpc *) vmm->private;
	if (!rpc) {
		return -EINVAL;
	}

	return sel4_rpc_notify_io_handled(rpc, slot);
}

#endif /* __SEL4_RPC_H */
