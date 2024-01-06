// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright 2022, 2023, 2024, Technology Innovation Institute
 *
 */
#include "linux/mm.h"
#include "linux/atomic.h"
#include "linux/types.h"
#include "linux/slab.h"

#include "sel4_virt_drv.h"

static atomic_t id = ATOMIC_INIT(0);

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
	int i;

	if (WARN_ON(IS_ERR_OR_NULL(vmm))) {
		return false;
	}

	for (i = 0; i < NUM_SEL4_MEM_MAP; i++) {
		if (!sel4_mem_map_valid(&vmm->maps[i]))
			return false;
	}

	return true;
}

struct sel4_vmm *sel4_vmm_alloc(struct sel4_vmm_ops ops)
{
	struct sel4_vmm *vmm;

	vmm = kzalloc(sizeof(struct sel4_vmm), GFP_KERNEL);
	if (!vmm) {
		return ERR_PTR(-ENOMEM);
	}

	vmm->ops = ops;
	vmm->id = atomic_inc_return(&id);

	return vmm;
}

