/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright 2022, 2023, 2024, Technology Innovation Institute
 *
 */
#ifndef __SEL4_VIRT_DRV_H
#define __SEL4_VIRT_DRV_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/errno.h>
#include <linux/refcount.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/wait.h>

#include "sel4/sel4_virt.h"
#include <sel4/rpc.h>

#define SEL4_MEM_IOVA		0
#define SEL4_MEM_LOGICAL	1
#define SEL4_MEM_VIRTUAL	2

/* vm_server is interface implements vmm create/destroy calls. The vm-server
 * is responsible for resource management. It is up tho the driver to either
 * implement the resource management mechanisms, or pass the calls to
 * hypervisor. */
struct sel4_vm_server {
	struct sel4_vmm *(*create_vm)(struct sel4_vm_params params);
	int (*destroy_vm)(struct sel4_vmm *vmm);
	void *private;
};

struct sel4_vmm;

struct sel4_mem_map {
	int		type;
	phys_addr_t	paddr;
	void		*addr;
	resource_size_t	size;
	struct sel4_vmm	*vmm;
};

struct sel4_vmm_ops {
	/* irq handler */
	irqreturn_t (*upcall_irqhandler)(int irq, struct sel4_vmm *);
};

/* Use this to indicate that the VMM uses some other upcall mechanism,
 * thus skipping irq_request/free. The driver should call
 * sel4_vm_upcall_notify directly. */
#define SEL4_IRQ_NONE		0

struct sel4_vmm {
	int			id;
	int			irq;
	unsigned long		irq_flags;
	struct sel4_vmm_ops	ops;
	struct sel4_mem_map	maps[NUM_SEL4_MEM_MAP];
	struct sel4_vm		*vm;
	sel4_rpc_t		rpc;
	rpcmsg_event_queue_t	device_rx;
};

/* Indicates whether ioeventfd processed the ioreq */
#define SEL4_IOEVENTFD_PROCESSED	(1)
#define SEL4_IOEVENTFD_NONE		(0)

struct sel4_vm {
	struct list_head	vm_list;
	spinlock_t		lock;
	refcount_t		refcount;

	wait_queue_head_t	ioreq_wait;

	struct list_head	ioeventfds;
	struct list_head	irqfds;

	struct sel4_vmm		*vmm;
};

static inline void sel4_vmm_mem_map_set(struct sel4_vmm *vmm,
					unsigned int index,
					struct sel4_mem_map *map)
{
	BUG_ON(index >= NUM_SEL4_MEM_MAP);
	vmm->maps[index] = *map;
	vmm->maps[index].vmm = vmm;
}

static inline __must_check unsigned long sel4_vm_lock(struct sel4_vm *vm)
{
	unsigned long irqflags;
	spin_lock_irqsave(&vm->lock, irqflags);

	return irqflags;
}

static inline void sel4_vm_unlock(struct sel4_vm *vm, unsigned long irqflags)
{
	spin_unlock_irqrestore(&vm->lock, irqflags);
}

static inline int sel4_start_vm(struct sel4_vm *vm)
{
	if (WARN_ON(!vm))
		return -EINVAL;

	if (WARN_ON(!vm->vmm)) {
		return -ENODEV;
	}

	return driver_req_start_vm(&vm->vmm->rpc);
}

static inline int sel4_vm_create_vpci(struct sel4_vm *vm,
				      struct sel4_vpci_device *vpci)
{
	if (WARN_ON(!vm || !vpci))
		return -EINVAL;

	if (WARN_ON(!vm->vmm)) {
		return -ENODEV;
	}

	return driver_req_create_vpci_device(&vm->vmm->rpc, vpci->pcidev);
}

static inline int sel4_vm_destroy_vpci(struct sel4_vm *vm,
				       struct sel4_vpci_device *vpci)
{
	if (WARN_ON(!vm || !vpci))
		return -EINVAL;

	if (WARN_ON(!vm->vmm)) {
		return -ENODEV;
	}

	/* Not implemented */
	return -ENOSYS;
}

static inline int sel4_vm_set_irqline(struct sel4_vm *vm, u32 irq, u32 op)
{
	int rc;

	if (WARN_ON(!vm))
		return -EINVAL;

	if (WARN_ON(!vm->vmm)) {
		return -ENODEV;
	}

	switch (op) {
	case SEL4_IRQ_OP_SET:
		rc = driver_req_set_irqline(&vm->vmm->rpc, irq);
		break;
	case SEL4_IRQ_OP_CLR:
		rc = driver_req_clear_irqline(&vm->vmm->rpc, irq);
		break;
	default:
		rc = -EINVAL;
		break;
	}

	return rc;
}

static inline irqreturn_t sel4_vm_call_irqhandler(struct sel4_vm *vm, int irq)
{
	if (WARN_ON(!vm))
		return IRQ_NONE;

	if (WARN_ON(!vm->vmm || !vm->vmm->ops.upcall_irqhandler)) {
		return IRQ_NONE;
	}

	return vm->vmm->ops.upcall_irqhandler(irq, vm->vmm);
}

static inline int sel4_vm_mmio_region_config(struct sel4_vm *vm,
					     struct sel4_mmio_region_config *config)
{
	if (WARN_ON(!vm) || WARN_ON(!config))
		return -EINVAL;

	if (WARN_ON(!vm->vmm)) {
		return -ENODEV;
	}

	return driver_req_mmio_region_config(&vm->vmm->rpc, config->gpa,
					     config->len, config->flags);
}

void sel4_vm_upcall_notify(struct sel4_vm *vm);

int sel4_irqfd_init(void);
void sel4_irqfd_exit(void);

int sel4_vm_irqfd_config(struct sel4_vm *vm,
			 struct sel4_irqfd_config *config);

int sel4_vm_ioeventfd_config(struct sel4_vm *vm,
			     struct sel4_ioeventfd_config *config);

int rpc_process_mmio(struct sel4_vm *vm, rpcmsg_t *req);

int sel4_init(struct sel4_vm_server *vm_server, struct module *module);
void sel4_exit(void);

/* Called when vmm is killed/about to be killed and still used by VM. */
int sel4_notify_vmm_dying(int id);

/* For driver modules with custom ioctls */
long sel4_module_ioctl(struct file *filp, unsigned int ioctl,
		       unsigned long arg);

int sel4_vm_mmap(struct file *filp, struct vm_area_struct *vma);

struct sel4_vmm *sel4_vmm_alloc(struct sel4_vmm_ops ops);
bool sel4_vmm_valid(struct sel4_vmm *vmm);

#endif /* __SEL4_VIRT_DRV_H */
