// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright 2023, 2024, Technology Innovation Institute
 *
 */

#include <linux/mm.h>
#include <linux/version.h>

#include "sel4_virt_drv.h"

static int sel4_find_mem_index(struct vm_area_struct *vma)
{
	return (vma->vm_pgoff) ? -1 : (int) vma->vm_pgoff;
}

static vm_fault_t sel4_handle_vma_fault(struct vm_fault *vmf)
{
	struct sel4_mem_map *map = vmf->vma->vm_private_data;
	struct page *page;
	unsigned long offset;
	void *paddr;
	vm_fault_t rc = 0;
	int index;
	unsigned long irqflags;

	BUG_ON(!map || !map->vmm || !map->vmm->vm);

	irqflags = sel4_vm_lock(map->vmm->vm);

	index = sel4_find_mem_index(vmf->vma);
	if (index < 0) {
		rc = VM_FAULT_SIGBUS;
		goto out_unlock;
	}

	offset = (vmf->pgoff - index) << PAGE_SHIFT;

	paddr = (void *)(unsigned long)map->paddr + offset;
	if (map->type == SEL4_MEM_LOGICAL)
		page = virt_to_page(paddr);
	else
		page = vmalloc_to_page(paddr);
	get_page(page);
	vmf->page = page;

out_unlock:
	sel4_vm_unlock(map->vmm->vm, irqflags);

	return rc;
}

static const struct vm_operations_struct sel4_mmap_logical_vm_ops = {
	.fault = sel4_handle_vma_fault,
};

static inline void sel4_set_vm_flags(struct vm_area_struct *vma, vm_flags_t flags)
{
#if LINUX_VERSION_CODE <= KERNEL_VERSION(6,3,0)
       vma->vm_flags |= flags;
#else
       vm_flags_set(vma, flags);
#endif
}

static int sel4_mmap_logical(struct vm_area_struct *vma)
{
	sel4_set_vm_flags(vma, VM_DONTEXPAND | VM_DONTDUMP);
	vma->vm_ops = &sel4_mmap_logical_vm_ops;

	return 0;
}

static const struct vm_operations_struct sel4_mmap_physical_vm_ops = {
#ifdef CONFIG_HAVE_IOREMAP_PROT
	.access = generic_access_phys,
#endif
};

static int sel4_mmap_physical(struct vm_area_struct *vma, struct sel4_mem_map *map)
{
	if (!vma || !map)
		return -EINVAL;

	if (sel4_find_mem_index(vma))
		return -EINVAL;

	if (map->paddr & ~PAGE_MASK)
		return -ENODEV;

	if (vma->vm_end - vma->vm_start > map->size)
		return -EINVAL;

	vma->vm_ops = &sel4_mmap_physical_vm_ops;

	return remap_pfn_range(vma,
			       vma->vm_start,
			       map->paddr >> PAGE_SHIFT,
			       vma->vm_end - vma->vm_start,
			       vma->vm_page_prot);
}

int sel4_vm_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct sel4_mem_map *map = filp->private_data;
	unsigned long requested_pages, actual_pages;
	int rc = 0;
	unsigned long irqflags;

	BUG_ON(!map || !map->vmm || !map->vmm->vm);

	if (vma->vm_end < vma->vm_start)
		return -EINVAL;

	vma->vm_private_data = map;

	irqflags = sel4_vm_lock(map->vmm->vm);
	if (sel4_find_mem_index(vma) < 0) {
		rc = -EINVAL;
		goto out_unlock;
	}

	requested_pages = vma_pages(vma);
	actual_pages = ((map->paddr & ~PAGE_MASK) +
			map->size + PAGE_SIZE - 1) >> PAGE_SHIFT;
	if (requested_pages > actual_pages) {
		rc = -EINVAL;
		goto out_unlock;
	}

	switch (map->type) {
	case SEL4_MEM_IOVA:	/* shared memory with guest vmm */
		rc = sel4_mmap_physical(vma, map);
		break;
	case SEL4_MEM_LOGICAL:	/* kmalloc'd */
	case SEL4_MEM_VIRTUAL:	/* vmalloc'd */
		rc = sel4_mmap_logical(vma);
		break;
	default:
		rc = -EINVAL;
	}

out_unlock:
	sel4_vm_unlock(map->vmm->vm, irqflags);
	return rc;
}
