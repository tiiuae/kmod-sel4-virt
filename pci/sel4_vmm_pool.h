/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright 2022, Technology Innovation Institute
 *
 */
#ifndef __SEL4_VMM_POOL_H
#define __SEL4_VMM_POOL_H

#define VMID_DONT_CARE -1

int sel4_vmmpool_add(struct sel4_vmm *vmm);
struct sel4_vmm *sel4_vmmpool_remove(int id);
struct sel4_vmm *sel4_vmmpool_get(int id, resource_size_t ram_size);

#endif /* __SEL4_VMM_POOL_H */
