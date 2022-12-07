// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright 2022, Technology Innovation Institute
 *
 */

#include "linux/atomic.h"
#include "linux/types.h"
#include "linux/slab.h"

#include "sel4_virt_drv.h"

static atomic_t id = ATOMIC_INIT(0);

bool vmm_ops_valid(struct sel4_vmm_ops ops)
{
	return (ops.start_vm &&
		ops.create_vpci_device &&
		ops.set_irqline &&
		ops.upcall_ioreqhandler &&
		ops.notify_io_handled);
}

struct sel4_vmm *sel4_vmm_alloc(struct sel4_vmm_ops ops)
{
	struct sel4_vmm *vmm;

	if (!vmm_ops_valid(ops)) {
		return ERR_PTR(-EINVAL);
	}

	vmm = kzalloc(sizeof(struct sel4_vmm), GFP_KERNEL);
	if (!vmm) {
		return ERR_PTR(-ENOMEM);
	}

	vmm->ops = ops;
	vmm->id = atomic_inc_return(&id);

	return vmm;
}

