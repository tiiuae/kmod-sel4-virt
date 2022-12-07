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
	phys_addr_t	addr;
	void		*service_vm_va;
	resource_size_t	size;
};

struct sel4_vmm;

struct sel4_vmm_ops {
	int (*start_vm)(struct sel4_vmm *);
	int (*create_vpci_device)(struct sel4_vmm *, u32 device);
	int (*destroy_vpci_device)(struct sel4_vmm *, u32 device);
	int (*set_irqline)(struct sel4_vmm *, u32 irq, u32 op);

	/* enable/disable irq */
	int (*upcall_control)(struct sel4_vmm *, s32 upcall_on);
	/* irq handler */
	irqreturn_t (*upcall_irqhandler)(int irq, struct sel4_vmm *);

	/* bit masks for ioreqhanbler returns. When ioreq was received and
	 * placed to 'ioreq', the handler should return with
	 * SEL4_IOREQ_HANDLED mask set. If the handler has received additional
	 * ioreqr that it wants to have processed, OR the return with
	 * SEL4_IOREQ_AGAIN.
	 */
#define SEL4_IOREQ_NONE		(0 << 0)
#define SEL4_IOREQ_HANDLED	(1 << 1)
#define SEL4_IOREQ_AGAIN	(1 << 2)
	/* workqueue handler for processing: ioreq allocated by the caller. */
	int (*upcall_ioreqhandler)(struct sel4_vmm *, struct sel4_ioreq *ioreq);
	int (*notify_io_handled)(struct sel4_vmm *, struct sel4_ioreq *);
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
	struct sel4_mem_map	ram;
	struct sel4_vm		*vm;
	void			*private;
};

struct sel4_vm {
	struct list_head	vm_list;
	spinlock_t		lock;
	refcount_t		refcount;

	// FIXME: move to own file.
	// FIXME: consider ioeventfds
	wait_queue_head_t	ioreq_wait;
	struct sel4_iohandler_buffer *ioreq_buffer;
	DECLARE_BITMAP(ioreq_map, SEL4_MAX_IOREQS);
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
		sel4_vm_unlock(vm, irqflags);
		return -ENODEV;
	}

	rc = vm->vmm->ops.start_vm(vm->vmm);
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

static inline int sel4_vm_notify_io_handled(struct sel4_vm *vm, struct sel4_ioreq *ioreq)
{
	int rc;

	if (WARN_ON(!vm || !ioreq))
		return -EINVAL;

	lockdep_assert_held(&vm->lock);

	if (WARN_ON(!vm->vmm || !vm->vmm->ops.notify_io_handled)) {
		return -ENODEV;
	}

	rc = vm->vmm->ops.notify_io_handled(vm->vmm, ioreq);

	return rc;
}

static inline int sel4_vm_ioeventfd_config(struct sel4_vm *vm,
					   struct sel4_ioeventfd *ioeventfd)
{
	unsigned long irqflags;

	if (WARN_ON(!vm || !ioeventfd))
		return -EINVAL;

	irqflags = sel4_vm_lock(vm);
	if (WARN_ON(!vm->vmm)) {
		sel4_vm_unlock(vm, irqflags);
		return -ENODEV;
	}
	sel4_vm_unlock(vm, irqflags);

	return -ENOSYS;
}

static inline int sel4_vm_irqfd_config(struct sel4_vm *vm,
				       struct sel4_irqfd *irqfd)
{
	unsigned long irqflags;

	if (WARN_ON(!vm || !irqfd))
		return -EINVAL;

	irqflags = sel4_vm_lock(vm);
	if (WARN_ON(!vm->vmm)) {
		sel4_vm_unlock(vm, irqflags);
		return -ENODEV;
	}
	sel4_vm_unlock(vm, irqflags);

	return -ENOSYS;
}

static inline int sel4_vm_call_ioreqhandler(struct sel4_vm *vm,
					    struct sel4_ioreq *out_ioreq)
{
	int rc;

	if (WARN_ON(!vm || !out_ioreq))
		return -EINVAL;

	lockdep_assert_held(&vm->lock);

	if (WARN_ON(!vm->vmm || !vm->vmm->ops.upcall_ioreqhandler)) {
		return -ENODEV;
	}

	rc = vm->vmm->ops.upcall_ioreqhandler(vm->vmm, out_ioreq);

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

void sel4_vm_upcall_notify(struct sel4_vm *vm);

int sel4_init(struct sel4_vm_server *vm_server, struct module *module);
void sel4_exit(void);

/* Called when vmm is killed/about to be killed and still used by VM. */
int sel4_notify_vmm_dying(int id);

/* For driver modules with custom ioctls */
long sel4_module_ioctl(struct file *filp, unsigned int ioctl,
		       unsigned long arg);

struct sel4_vmm *sel4_vmm_alloc(struct sel4_vmm_ops ops);

#endif /* __SEL4_VIRT_DRV_H */
