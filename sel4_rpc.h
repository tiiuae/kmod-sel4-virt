/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright 2022, Technology Innovation Institute
 *
 */
#ifndef __SEL4_RPC_H
#define __SEL4_RPC_H

#include <linux/types.h>
#include <linux/spinlock.h>
#include "sel4_vmm_rpc.h"
#include "sel4_virt_drv.h"

struct sel4_ioreq;

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
int sel4_rpc_notify_io_handled(struct sel4_rpc *rpc, struct sel4_ioreq *ioreq);

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

static inline int sel4_rpc_op_notify_io_handled(struct sel4_vmm *vmm,
						struct sel4_ioreq *ioreq)
{
	struct sel4_rpc *rpc = (struct sel4_rpc *) vmm->private;
	if (!rpc || !ioreq) {
		return -EINVAL;
	}

	return sel4_rpc_notify_io_handled(rpc, ioreq);
}

static inline u32 sel4_ioreq_dir(struct sel4_ioreq *ioreq)
{
	return ioreq->type == SEL4_IOREQ_TYPE_MMIO ?
		ioreq->req.mmio.direction :
		ioreq->req.pci.direction;
}

static inline int sel4_rpc_msg_to_mmio(rpcmsg_t *msg, struct sel4_ioreq_mmio *mmio)
{
	if (!msg || !mmio) {
		return -EINVAL;
	}

	switch (QEMU_OP(msg->mr0)) {
	case QEMU_OP_READ:
		mmio->direction = SEL4_IO_DIR_READ;
		break;
	case QEMU_OP_WRITE:
		mmio->direction = SEL4_IO_DIR_WRITE;
		break;
	default:
		return -EINVAL;
	}

	mmio->vcpu = QEMU_VCPU(msg->mr0);
	mmio->addr = msg->mr1;
	mmio->len = msg->mr2;
	mmio->data = 0;
	memcpy(&mmio->data, &msg->mr3, mmio->len);

	return 0;
}

static inline int sel4_rpc_msg_to_pci(rpcmsg_t *msg, struct sel4_ioreq_pci *pci)
{
	if (!msg || !pci) {
		return -EINVAL;
	}

	switch (QEMU_OP(msg->mr0)) {
	case QEMU_OP_READ:
		pci->direction = SEL4_IO_DIR_READ;
		break;
	case QEMU_OP_WRITE:
		pci->direction = SEL4_IO_DIR_WRITE;
		break;
	default:
		return -EINVAL;
	}

	pci->pcidev = QEMU_PCIDEV(msg->mr0);
	pci->addr = msg->mr1;
	pci->len = msg->mr2;
	pci->data = 0;
	memcpy(&pci->data, &msg->mr3, pci->len);

	return 0;
}

static inline int sel4_rpc_msg_to_ioreq(rpcmsg_t *msg, struct sel4_ioreq *ioreq)
{
	if (!msg || !ioreq) {
		return -EINVAL;
	}

	if (QEMU_VCPU(msg->mr0) == QEMU_VCPU_NONE) {
		ioreq->type = SEL4_IOREQ_TYPE_PCI;
		return sel4_rpc_msg_to_pci(msg, &ioreq->req.pci);
	} else {
		ioreq->type = SEL4_IOREQ_TYPE_MMIO;
		return sel4_rpc_msg_to_mmio(msg, &ioreq->req.mmio);
	}
}

static inline int sel4_rpc_pci_to_msg(struct sel4_ioreq_pci *pci,
				      rpcmsg_t *msg)
{
	if (!pci || !msg) {
		return -EINVAL;
	}

	msg->mr0 = mr0(0xFF, pci->direction, pci->pcidev);
	msg->mr1 = pci->addr;
	msg->mr2 = pci->len;
	msg->mr3 = pci->data;

	return 0;
}
static inline int sel4_rpc_mmio_to_msg(struct sel4_ioreq_mmio *mmio,
				       rpcmsg_t *msg)
{
	if (!mmio || !msg) {
		return -EINVAL;
	}

	msg->mr0 = mr0(mmio->vcpu, mmio->direction, 0xFF);
	msg->mr1 = mmio->addr;
	msg->mr2 = mmio->len;
	msg->mr3 = mmio->data;

	return 0;
}

static inline int sel4_rpc_ioreq_to_msg(struct sel4_ioreq *ioreq,
					rpcmsg_t *msg)
{
	if (!ioreq || !msg) {
		return -EINVAL;
	}

	if (ioreq->type == SEL4_IOREQ_TYPE_PCI) {
		return sel4_rpc_pci_to_msg(&ioreq->req.pci, msg);
	} else {
		return sel4_rpc_mmio_to_msg(&ioreq->req.mmio, msg);
	}
}

static inline int sel4_rpc_op_ioreqhandler(struct sel4_vmm *vmm,
					   struct sel4_ioreq *ioreq)
{
	struct sel4_rpc *rpc = (struct sel4_rpc *) vmm->private;
	int rc = SEL4_IOREQ_NONE;
	rpcmsg_t *msg = rpcmsg_queue_head(rpc->rx_queue);

	if (msg) {
		rc = sel4_rpc_msg_to_ioreq(msg, ioreq);
		if (rc < 0) {
			return SEL4_IOREQ_NONE;
		}

		ioreq->state = SEL4_IOREQ_STATE_PENDING;
		rpcmsg_queue_advance_head(rpc->rx_queue);

		rc = SEL4_IOREQ_HANDLED;
		if (rpcmsg_queue_head(rpc->rx_queue))
			rc |= SEL4_IOREQ_AGAIN;
	}

	return rc;
}

#endif /* __SEL4_RPC_H */
