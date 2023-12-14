// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright 2022, Technology Innovation Institute
 *
 */
#include "linux/mm.h"
#include "linux/atomic.h"
#include "linux/types.h"
#include "linux/slab.h"

#include "sel4_virt_drv.h"

static atomic_t id = ATOMIC_INIT(0);

static bool vmm_ops_valid(struct sel4_vmm_ops ops)
{
	return (ops.start_vm &&
		ops.create_vpci_device &&
		ops.set_irqline &&
		ops.notify_io_handled);
}

static bool sel4_mem_map_valid(struct sel4_mem_map *mem)
{
	if (WARN_ON(IS_ERR_OR_NULL(mem))) {
		return false;
	}

	return (mem->size &&
		mem->addr &&
		PAGE_ALIGNED(mem->addr));
}

bool sel4_vmm_valid(struct sel4_vmm *vmm)
{
	if (WARN_ON(IS_ERR_OR_NULL(vmm))) {
		return false;
	}

	return (sel4_mem_map_valid(&vmm->ram) &&
		sel4_mem_map_valid(&vmm->iobuf) &&
		vmm_ops_valid(vmm->ops));
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

