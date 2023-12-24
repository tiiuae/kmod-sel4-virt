/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright 2022, Technology Innovation Institute
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

struct sel4_mem_map {
	int		type;
	phys_addr_t	paddr;
	void		*addr;
	resource_size_t	size;
};

struct sel4_vmm;

struct sel4_vmm_ops {
	int (*start_vm)(struct sel4_vmm *);
	int (*create_vpci_device)(struct sel4_vmm *, u32 device);
	int (*destroy_vpci_device)(struct sel4_vmm *, u32 device);
	int (*set_irqline)(struct sel4_vmm *, u32 irq, u32 op);
	int (*set_mmio_region)(struct sel4_vmm *, struct sel4_mmio_region_config *config);

	/* enable/disable irq */
	int (*upcall_control)(struct sel4_vmm *, s32 upcall_on);
	/* irq handler */
	irqreturn_t (*upcall_irqhandler)(int irq, struct sel4_vmm *);

	int (*notify_io_handled)(struct sel4_vmm *, u32 slot);
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
	struct sel4_mem_map	iobuf;
	struct sel4_mem_map	ram;
	struct sel4_vm		*vm;
	void			*private;
};

/* Indicates whether ioeventfd processed the ioreq */
#define SEL4_IOEVENTFD_PROCESSED	(1)
#define SEL4_IOEVENTFD_NONE		(0)

struct sel4_vm {
	struct list_head	vm_list;
	spinlock_t		lock;
	refcount_t		refcount;

	wait_queue_head_t	ioreq_wait;
	struct sel4_ioreq	*mmio_reqs;
	DECLARE_BITMAP(ioreq_map, SEL4_MAX_IOREQS);

	struct list_head	ioeventfds;
	struct list_head	irqfds;

	struct sel4_vmm		*vmm;
};

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
	int rc;
	unsigned long irqflags;

	if (WARN_ON(!vm))
		return -EINVAL;

	irqflags = sel4_vm_lock(vm);
	if (WARN_ON(!vm->vmm || !vm->vmm->ops.start_vm)) {
		rc = -ENODEV;
		goto out_unlock;
	}

	if (!vm->mmio_reqs) {
		pr_notice("no ioreq handler");
		rc = -EBADFD;
		goto out_unlock;
	}

	rc = vm->vmm->ops.start_vm(vm->vmm);

out_unlock:
	sel4_vm_unlock(vm, irqflags);

	return rc;
}

static inline int sel4_vm_create_vpci(struct sel4_vm *vm,
				      struct sel4_vpci_device *vpci)
{
	int rc;
	unsigned long irqflags;

	if (WARN_ON(!vm || !vpci))
		return -EINVAL;

	irqflags = sel4_vm_lock(vm);
	if (WARN_ON(!vm->vmm || !vm->vmm->ops.create_vpci_device)) {
		sel4_vm_unlock(vm, irqflags);
		return -ENODEV;
	}

	rc =  vm->vmm->ops.create_vpci_device(vm->vmm, vpci->pcidev);
	sel4_vm_unlock(vm, irqflags);

	return rc;
}

static inline int sel4_vm_destroy_vpci(struct sel4_vm *vm,
				       struct sel4_vpci_device *vpci)
{
	int rc;
	unsigned long irqflags;

	if (WARN_ON(!vm || !vpci))
		return -EINVAL;

	irqflags = sel4_vm_lock(vm);
	if (WARN_ON(!vm->vmm || !vm->vmm->ops.destroy_vpci_device)) {
		sel4_vm_unlock(vm, irqflags);
		return -ENODEV;
	}

	rc = vm->vmm->ops.destroy_vpci_device(vm->vmm, vpci->pcidev);
	sel4_vm_unlock(vm, irqflags);

	return rc;
}

static inline int sel4_vm_set_irqline(struct sel4_vm *vm, u32 irq, u32 op)
{
	int rc;
	unsigned long irqflags;

	if (WARN_ON(!vm))
		return -EINVAL;

	irqflags = sel4_vm_lock(vm);
	if (WARN_ON(!vm->vmm || !vm->vmm->ops.set_irqline)) {
		sel4_vm_unlock(vm, irqflags);
		return -ENODEV;
	}

	rc = vm->vmm->ops.set_irqline(vm->vmm, irq, op);
	sel4_vm_unlock(vm, irqflags);

	return rc;
}

static inline int sel4_vm_notify_io_handled(struct sel4_vm *vm, u32 slot)
{
	int rc;

	if (WARN_ON(!vm || !SEL4_IOREQ_SLOT_VALID(slot)))
		return -EINVAL;

	lockdep_assert_held(&vm->lock);

	if (WARN_ON(!vm->vmm || !vm->vmm->ops.notify_io_handled)) {
		return -ENODEV;
	}

	rc = vm->vmm->ops.notify_io_handled(vm->vmm, slot);

	return rc;
}

static inline irqreturn_t sel4_vm_call_irqhandler(struct sel4_vm *vm, int irq)
{
	irqreturn_t rc;
	unsigned long irqflags;

	if (WARN_ON(!vm))
		return IRQ_NONE;

	irqflags = sel4_vm_lock(vm);
	if (WARN_ON(!vm->vmm || !vm->vmm->ops.upcall_irqhandler)) {
		rc = IRQ_NONE;
		goto unlock;
	}

	rc = vm->vmm->ops.upcall_irqhandler(irq, vm->vmm);

unlock:
	sel4_vm_unlock(vm, irqflags);

	return rc;
}

static inline int sel4_vm_mmio_region_config(struct sel4_vm *vm,
					     struct sel4_mmio_region_config *config)
{
	int rc;
	unsigned long irqflags;

	if (WARN_ON(!vm))
		return -EINVAL;

	irqflags = sel4_vm_lock(vm);
	if (WARN_ON(!vm->vmm || !vm->vmm->ops.set_mmio_region)) {
		sel4_vm_unlock(vm, irqflags);
		return -ENODEV;
	}

	rc = vm->vmm->ops.set_mmio_region(vm->vmm, config);
	sel4_vm_unlock(vm, irqflags);

	return rc;
}

void sel4_vm_upcall_notify(struct sel4_vm *vm);

int sel4_irqfd_init(void);
void sel4_irqfd_exit(void);

int sel4_vm_irqfd_config(struct sel4_vm *vm,
			 struct sel4_irqfd_config *config);

int sel4_vm_ioeventfd_config(struct sel4_vm *vm,
			     struct sel4_ioeventfd_config *config);

/* Returns SEL4_IOEVENTFD_PROCESSED or SEL4_IOEVENTFD_NONE to indicate whether
 * ioeventfd processed the ioreq.
 *
 * On errors a negative value is returned.
 */
int sel4_vm_ioeventfd_process(struct sel4_vm *vm, int slot);

int sel4_init(struct sel4_vm_server *vm_server, struct module *module);
void sel4_exit(void);

/* Called when vmm is killed/about to be killed and still used by VM. */
int sel4_notify_vmm_dying(int id);

/* For driver modules with custom ioctls */
long sel4_module_ioctl(struct file *filp, unsigned int ioctl,
		       unsigned long arg);

int sel4_iohandler_mmap(struct file *filp, struct vm_area_struct *vma);
int sel4_vm_mmap_ram(struct file *filp, struct vm_area_struct *vma);

struct sel4_vmm *sel4_vmm_alloc(struct sel4_vmm_ops ops);
bool sel4_vmm_valid(struct sel4_vmm *vmm);

#endif /* __SEL4_VIRT_DRV_H */
