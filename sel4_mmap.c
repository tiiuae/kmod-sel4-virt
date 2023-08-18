// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright 2023, Technology Innovation Institute
 *
 */

#include <linux/mm.h>
#include <linux/version.h>

#include "sel4_virt_drv.h"

#define SEL4_MMAP_RAM	(0)
#define SEL4_MMAP_IOBUF (1)

static inline struct sel4_mem_map *sel4_get_map(struct sel4_vm *vm, unsigned region)
{
	struct sel4_mem_map *map = NULL;
	switch (region) {
	case SEL4_MMAP_RAM:
		map = &vm->vmm->ram;
		break;
	case SEL4_MMAP_IOBUF:
		map = &vm->vmm->iobuf;
		break;
	default:
		WARN(1, "Invalid mmap region");
		break;
	}

	return map;
}

static int sel4_find_mem_index(struct vm_area_struct *vma)
{
	return (vma->vm_pgoff) ? -1 : (int) vma->vm_pgoff;
}

static vm_fault_t sel4_handle_vma_fault(struct vm_fault *vmf, unsigned region)
{
	struct sel4_vm *vm = vmf->vma->vm_private_data;
	struct sel4_mem_map *map;
	struct page *page;
	unsigned long offset;
	void *addr;
	vm_fault_t rc = 0;
	int index;
	unsigned long irqflags;

	irqflags = sel4_vm_lock(vm);
	if (!vm->vmm) {
		rc = VM_FAULT_SIGBUS;
		goto out_unlock;
	}

	map = sel4_get_map(vm, region);

	index = sel4_find_mem_index(vmf->vma);
	if (index < 0) {
		rc = VM_FAULT_SIGBUS;
		goto out_unlock;
	}

	offset = (vmf->pgoff - index) << PAGE_SHIFT;

	addr = (void *)(unsigned long) map->addr + offset;
	if (vm->vmm->ram.type == SEL4_MEM_LOGICAL)
		page = virt_to_page(addr);
	else
		page = vmalloc_to_page(addr);
	get_page(page);
	vmf->page = page;

out_unlock:
	sel4_vm_unlock(vm, irqflags);

	return rc;
}

static vm_fault_t sel4_iohandler_vma_fault(struct vm_fault *vmf)
{
	return sel4_handle_vma_fault(vmf, SEL4_MMAP_IOBUF);
}

static const struct vm_operations_struct sel4_iohandler_logical_vm_ops = {
	.fault = sel4_iohandler_vma_fault,
};

static vm_fault_t sel4_ram_vma_fault(struct vm_fault *vmf)
{
	return sel4_handle_vma_fault(vmf, SEL4_MMAP_RAM);
}

static const struct vm_operations_struct sel4_ram_logical_vm_ops = {
	.fault = sel4_ram_vma_fault,
};

static const struct vm_operations_struct *sel4_get_vm_ops(unsigned region)
{
	const struct vm_operations_struct *vms = NULL;
	switch (region) {
	case SEL4_MMAP_RAM:
		vms = &sel4_ram_logical_vm_ops;
		break;
	case SEL4_MMAP_IOBUF:
		vms = &sel4_iohandler_logical_vm_ops;
		break;
	default:
		WARN(1, "Invalid mmap region");
		break;
	}
	return vms;
}

static inline void sel4_set_vm_flags(struct vm_area_struct *vma, vm_flags_t flags)
{
#if LINUX_VERSION_CODE <= KERNEL_VERSION(6,3,0)
       vma->vm_flags |= flags;
#else
       vm_flags_set(vma, flags);
#endif
}

static int sel4_mmap_logical(struct vm_area_struct *vma, unsigned region)
{
	sel4_set_vm_flags(vma, VM_DONTEXPAND | VM_DONTDUMP);
	vma->vm_ops = sel4_get_vm_ops(region);

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

	if (map->addr & ~PAGE_MASK)
		return -ENODEV;

	if (vma->vm_end - vma->vm_start > map->size)
		return -EINVAL;

	vma->vm_ops = &sel4_mmap_physical_vm_ops;

	return remap_pfn_range(vma,
			       vma->vm_start,
			       map->addr >> PAGE_SHIFT,
			       vma->vm_end - vma->vm_start,
			       vma->vm_page_prot);
}

static int sel4_do_mmap(struct file *filp, struct vm_area_struct *vma, unsigned region)
{
	struct sel4_vm *vm = filp->private_data;
	struct sel4_mem_map *map;
	unsigned long requested_pages, actual_pages;
	int rc = 0;
	unsigned long irqflags;

	BUG_ON(!vm);

	if (vma->vm_end < vma->vm_start)
		return -EINVAL;

	vma->vm_private_data = vm;

	irqflags = sel4_vm_lock(vm);
	if (sel4_find_mem_index(vma) < 0) {
		rc = -EINVAL;
		goto out_unlock;
	}

	map = sel4_get_map(vm, region);

	requested_pages = vma_pages(vma);
	actual_pages = ((map->addr & ~PAGE_MASK) +
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
		rc = sel4_mmap_logical(vma, region);
		break;
	default:
		rc = -EINVAL;
	}

out_unlock:
	sel4_vm_unlock(vm, irqflags);
	return rc;
}

int sel4_iohandler_mmap(struct file *filp, struct vm_area_struct *vma)
{
	return sel4_do_mmap(filp, vma, SEL4_MMAP_IOBUF);
}

int sel4_vm_mmap_ram(struct file *filp, struct vm_area_struct *vma)
{
	return sel4_do_mmap(filp, vma, SEL4_MMAP_RAM);
}

