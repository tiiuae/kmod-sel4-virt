// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright 2022, Technology Innovation Institute
 *
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/file.h>
#include <linux/anon_inodes.h>
#include <linux/wait.h>
#include <linux/errno.h>
#include <linux/compiler.h>
#include <linux/interrupt.h>
#include <linux/mm.h>
#include <linux/mm_types.h>

#include "sel4/sel4_virt.h"
#include "sel4_virt_drv.h"

/* Large enough to hold huge number with sign and null character */
#define ITOA_MAX_LEN	(12)

static void sel4_vm_upcall_work(struct work_struct *work);

DEFINE_RWLOCK(vm_list_lock);
LIST_HEAD(vm_list);

static struct sel4_vm_server *vm_server;

static struct workqueue_struct *sel4_ioreq_wq;
static DECLARE_WORK(sel4_ioreq_work, sel4_vm_upcall_work);

// FIXME: To be moved to vmm
static int sel4_next_avail_slot(struct sel4_vm *vm)
{
	return find_first_zero_bit(vm->ioreq_map, SEL4_MAX_IOREQS);
}

static int sel4_vm_process_ioreq(struct sel4_vm *vm)
{
	struct sel4_ioreq *ioreq;
	struct sel4_ioreq incoming;
	int slot;
	int rc;
	unsigned long irqflags;

	irqflags = sel4_vm_lock(vm);

	slot = sel4_next_avail_slot(vm);
	if (WARN_ON(slot >= SEL4_MAX_IOREQS)) {
		/* Slots full, unable to process now. */
		rc = SEL4_IOREQ_NONE;
		goto out_unlock;
	}

	rc = sel4_vm_call_ioreqhandler(vm, &incoming);
	if (rc < 0)
		goto out_unlock;

	if (rc & SEL4_IOREQ_HANDLED && vm->ioreq_buffer &&
	    incoming.state == SEL4_IOREQ_STATE_PENDING) {
		ioreq = vm->ioreq_buffer->request_slots + slot;
		*ioreq = incoming;

		smp_store_release(&ioreq->state,
				  SEL4_IOREQ_STATE_PROCESSING);
		set_bit(slot, vm->ioreq_map);

		wake_up_interruptible(&vm->ioreq_wait);
	}

out_unlock:
	sel4_vm_unlock(vm, irqflags);

	return rc;
}


static void sel4_vm_process_ioreqs(struct sel4_vm *vm)
{
	int rc;

	do {
		rc = sel4_vm_process_ioreq(vm);
		if (rc < 0)
			break;

	} while(rc & SEL4_IOREQ_AGAIN);
}

static void sel4_vm_upcall_work(struct work_struct *work)
{
	struct sel4_vm *vm;

	read_lock(&vm_list_lock);
	list_for_each_entry(vm, &vm_list, vm_list) {
		sel4_vm_process_ioreqs(vm);
	}
	read_unlock(&vm_list_lock);
}

void sel4_vm_upcall_notify(struct sel4_vm *vm)
{
	queue_work(sel4_ioreq_wq, &sel4_ioreq_work);
}

static irqreturn_t sel4_vm_interrupt(int irq, void *private)
{
	struct sel4_vm *vm = (struct sel4_vm *) private;

	irqreturn_t rc = sel4_vm_call_irqhandler(vm, irq);

	if (rc == IRQ_HANDLED)
		sel4_vm_upcall_notify(vm);

	return rc;
}

static struct sel4_vm *sel4_vm_create(struct sel4_vm_params vm_params)
{
	struct sel4_vm *vm;
	int rc = 0;

	vm = kzalloc(sizeof(*vm), GFP_KERNEL);
	if (!vm)
		return ERR_PTR(-ENOMEM);

	vm->vmm = vm_server->create_vm(vm_params);
	if (IS_ERR_OR_NULL(vm->vmm)) {
		rc = (!vm->vmm) ? -ENOMEM : PTR_ERR(vm->vmm);
		kfree(vm);
		return ERR_PTR(rc);
	}
	vm->vmm->vm = vm;

	spin_lock_init(&vm->lock);

	refcount_set(&vm->refcount, 1);

	/* FIXME: to own file */
	init_waitqueue_head(&vm->ioreq_wait);

	write_lock_bh(&vm_list_lock);
	list_add(&vm->vm_list, &vm_list);
	write_unlock_bh(&vm_list_lock);

	if (vm->vmm->ops.upcall_irqhandler && vm->vmm->irq != SEL4_IRQ_NONE) {
		rc = request_irq(vm->vmm->irq, sel4_vm_interrupt,
				 vm->vmm->irq_flags, "sel4", vm);
		if (rc) {
			write_lock_bh(&vm_list_lock);
			list_del(&vm->vm_list);
			write_unlock_bh(&vm_list_lock);

			vm_server->destroy_vm(vm->vmm);
			kfree(vm);
			return ERR_PTR(rc);
		}
	}

	return vm;
}

static void sel4_destroy_vm(struct sel4_vm *vm)
{
	unsigned long irqflags;

	BUG_ON(!vm);

	if (vm->vmm->irq != SEL4_IRQ_NONE)
		free_irq(vm->vmm->irq, vm);

	write_lock_bh(&vm_list_lock);
	list_del(&vm->vm_list);
	write_unlock_bh(&vm_list_lock);

	irqflags = sel4_vm_lock(vm);
	if (vm->ioreq_buffer) {
		free_page((unsigned long)vm->ioreq_buffer);
		vm->ioreq_buffer = NULL;
	}
	vm_server->destroy_vm(vm->vmm);
	sel4_vm_unlock(vm, irqflags);

	kfree(vm);
}

static void sel4_vm_get(struct sel4_vm *vm)
{
	BUG_ON(!vm);

	refcount_inc(&vm->refcount);
}

static void sel4_vm_put(struct sel4_vm *vm)
{
	BUG_ON(!vm);

	if (refcount_dec_and_test(&vm->refcount))
		sel4_destroy_vm(vm);
}

/*
 * Used when file descriptor installation fail. This is to prevent freeing
 * memory while caller still is using the struct. See virt/kvm/kvm_main.c
 * for the explanation.
 */
void sel4_put_no_destroy(struct sel4_vm *vm)
{
	BUG_ON(!vm);
	WARN_ON(refcount_dec_and_test(&vm->refcount));
}

static int sel4_find_mem_index(struct vm_area_struct *vma)
{
	return (vma->vm_pgoff) ? -1 : (int) vma->vm_pgoff;
}

static vm_fault_t sel4_iohandler_fault(struct vm_fault *vmf)
{
	struct sel4_vm *vm = vmf->vma->vm_file->private_data;
	struct page *page;
	int rc = 0;
	unsigned long irqflags;

	irqflags = sel4_vm_lock(vm);
	if (sel4_find_mem_index(vmf->vma)) {
		rc = VM_FAULT_SIGBUS;
		goto out_unlock;
	}
	page = virt_to_page(vm->ioreq_buffer);
	get_page(page);
	vmf->page = page;

out_unlock:
	sel4_vm_unlock(vm, irqflags);

	return rc;
}

static const struct vm_operations_struct sel4_iohandler_vm_ops = {
	.fault = sel4_iohandler_fault,
};

static int sel4_iohandler_mmap(struct file *file, struct vm_area_struct *vma)
{
	vma->vm_flags |= VM_DONTEXPAND | VM_DONTDUMP;
	vma->vm_ops = &sel4_iohandler_vm_ops;
	return 0;
}

static int sel4_iohandler_release(struct inode *inode, struct file *filp)
{
	struct sel4_vm *vm = filp->private_data;

	sel4_vm_put(vm);
	return 0;
}

static struct file_operations sel4_iohandler_fops = {
	.release        = sel4_iohandler_release,
	.mmap           = sel4_iohandler_mmap,
	.llseek		= noop_llseek,
};

static int sel4_vm_create_iohandler(struct sel4_vm *vm)
{
	int rc;
	int i;
	struct page *page;
	unsigned long irqflags;

	if (vm->ioreq_buffer) {
		return -EEXIST;
	}

	page = alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (!page) {
		return -ENOMEM;
	}

	irqflags = sel4_vm_lock(vm);
	vm->ioreq_buffer = page_address(page);
	for (i = 0; i < SEL4_MAX_IOREQS; i++) {
		vm->ioreq_buffer->request_slots[i].state = SEL4_IOREQ_STATE_FREE;
	}
	sel4_vm_unlock(vm, irqflags);


	/* new fd for iohandler */
	sel4_vm_get(vm);
	rc = anon_inode_getfd("sel4-vm-iohandler", &sel4_iohandler_fops, vm,
			      O_RDWR | O_CLOEXEC);
	if (rc < 0)
		goto error;

	return rc;

error:
	irqflags = sel4_vm_lock(vm);
	free_page((unsigned long)vm->ioreq_buffer);
	vm->ioreq_buffer = NULL;
	sel4_vm_unlock(vm, irqflags);

	sel4_put_no_destroy(vm);

	return rc;
}

static int sel4_vm_ioreq_complete(struct sel4_vm *vm, u16 slot)
{
	struct sel4_ioreq *ioreq;
	int rc = 0;
	unsigned long irqflags;

	if (slot >= SEL4_MAX_IOREQS) {
		return -EINVAL;
	}
	irqflags = sel4_vm_lock(vm);
	if (vm->ioreq_buffer) {
		clear_bit(slot, vm->ioreq_map);
		ioreq = vm->ioreq_buffer->request_slots + slot;
		smp_store_release(&ioreq->state, SEL4_IOREQ_STATE_COMPLETE);
		rc = sel4_vm_notify_io_handled(vm, ioreq);
	} else {
		rc = -ENODEV;
	}
	sel4_vm_unlock(vm, irqflags);

	return rc;
}

static inline bool sel4_ioreq_pending(struct sel4_vm *vm)
{
	return !bitmap_empty(vm->ioreq_map, SEL4_MAX_IOREQS);
}

static int sel4_vm_wait_io(struct sel4_vm *vm)
{
	if (!vm->ioreq_buffer) {
		return -ENODEV;
	}

	if (wait_event_interruptible(vm->ioreq_wait, sel4_ioreq_pending(vm))) {
		return -ERESTARTSYS;
	}

	return 0;
}

static long sel4_vm_ioctl(struct file *filp, unsigned int ioctl,
			  unsigned long arg)
{
	struct sel4_vm *vm = filp->private_data;
	int rc = -EINVAL;

	BUG_ON(!vm);

	switch (ioctl) {
	case SEL4_START_VM: {
		rc = sel4_start_vm(vm);
		break;
	}
	case SEL4_CREATE_VPCI_DEVICE: {
		struct sel4_vpci_device vpci;

		if (copy_from_user(&vpci, (void __user *) arg, sizeof(vpci)))
			return -EFAULT;

		rc = sel4_vm_create_vpci(vm, &vpci);
		break;
	}
	case SEL4_DESTROY_VPCI_DEVICE: {
		struct sel4_vpci_device vpci;

		if (copy_from_user(&vpci, (void __user *) arg, sizeof(vpci)))
			return -EFAULT;

		rc = sel4_vm_destroy_vpci(vm, &vpci);
		break;
	}
	case SEL4_SET_IRQLINE: {
		struct sel4_irqline irq;

		if (copy_from_user(&irq, (void __user *) arg, sizeof(irq)))
			return -EFAULT;

		rc = sel4_vm_set_irqline(vm, irq.irq, irq.op);
		break;
	}


	case SEL4_IOEVENTFD: {
		struct sel4_ioeventfd ioeventfd;
		if (copy_from_user(&ioeventfd, (void __user *) arg,
				   sizeof(ioeventfd)))
			return -EFAULT;

		rc = sel4_vm_ioeventfd_config(vm, &ioeventfd);
		break;
	}
	case SEL4_IRQFD: {
		struct sel4_irqfd irqfd;
		if (copy_from_user(&irqfd, (void __user *) arg, sizeof(irqfd)))
			return -EFAULT;

		rc = sel4_vm_irqfd_config(vm, &irqfd);
		break;
	}
	case SEL4_CREATE_IO_HANDLER: {
		rc = sel4_vm_create_iohandler(vm);
		break;
	}
	case SEL4_WAIT_IO: {
		rc = sel4_vm_wait_io(vm);
		break;
	}
	case SEL4_NOTIFY_IO_HANDLED: {
		rc = sel4_vm_ioreq_complete(vm, arg);
		break;
	}

	default:
		rc = sel4_module_ioctl(filp, ioctl, arg);
		break;
	}

	return rc;
}

static vm_fault_t sel4_ram_vma_fault(struct vm_fault *vmf)
{
	struct sel4_vm *vm = vmf->vma->vm_private_data;
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

	index = sel4_find_mem_index(vmf->vma);
	if (index < 0) {
		rc = VM_FAULT_SIGBUS;
		goto out_unlock;
	}

	offset = (vmf->pgoff - index) << PAGE_SHIFT;

	addr = (void *)(unsigned long)vm->vmm->ram.addr + offset;
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

static const struct vm_operations_struct sel4_ram_logical_vm_ops = {
	.fault = sel4_ram_vma_fault,
};

static int sel4_ram_mmap_logical(struct vm_area_struct *vma)
{
	vma->vm_flags |= VM_DONTEXPAND | VM_DONTDUMP;
	vma->vm_ops = &sel4_ram_logical_vm_ops;
	return 0;
}

static const struct vm_operations_struct sel4_ram_physical_vm_ops = {
#ifdef CONFIG_HAVE_IOREMAP_PROT
	.access = generic_access_phys,
#endif
};

static int sel4_ram_mmap_physical(struct vm_area_struct *vma)
{
	struct sel4_vm *vm = vma->vm_private_data;

	if (sel4_find_mem_index(vma))
		return -EINVAL;

	if (vm->vmm->ram.addr & ~PAGE_MASK)
		return -ENODEV;

	if (vma->vm_end - vma->vm_start > vm->vmm->ram.size)
		return -EINVAL;

	vma->vm_ops = &sel4_ram_physical_vm_ops;

	return remap_pfn_range(vma,
			       vma->vm_start,
			       vm->vmm->ram.addr >> PAGE_SHIFT,
			       vma->vm_end - vma->vm_start,
			       vma->vm_page_prot);
}

static int sel4_vm_mmap_ram(struct file *filp, struct vm_area_struct *vma)
{
	struct sel4_vm *vm = filp->private_data;
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

	requested_pages = vma_pages(vma);
	actual_pages = ((vm->vmm->ram.addr & ~PAGE_MASK)
			+ vm->vmm->ram.size + PAGE_SIZE - 1) >> PAGE_SHIFT;
	if (requested_pages > actual_pages) {
		rc = -EINVAL;
		goto out_unlock;
	}

	switch (vm->vmm->ram.type) {
	case SEL4_MEM_IOVA:	/* shared memory with guest vmm */
		rc = sel4_ram_mmap_physical(vma);
		break;
	case SEL4_MEM_LOGICAL:	/* kmalloc'd */
	case SEL4_MEM_VIRTUAL:	/* vmalloc'd */
		rc = sel4_ram_mmap_logical(vma);
		break;
	default:
		rc = -EINVAL;
	}

out_unlock:
	sel4_vm_unlock(vm, irqflags);
	return rc;

}

static int sel4_vm_release(struct inode *inode, struct file *filp)
{
	struct sel4_vm *vm = filp->private_data;

	BUG_ON(!vm);

	sel4_vm_put(vm);
	return 0;
}

static struct file_operations sel4_vm_fops = {
	.mmap		= sel4_vm_mmap_ram,
	.release        = sel4_vm_release,
	.unlocked_ioctl = sel4_vm_ioctl,
	.llseek		= noop_llseek,
};

/* char device functions */
static int sel4_dev_ioctl_create_vm(struct sel4_vm_params params)
{
	int rc;
	struct file *file;

	struct sel4_vm *vm = sel4_vm_create(params);
	if (IS_ERR(vm)) {
		return PTR_ERR(vm);
	}

	/* new fd for VM */
	rc = get_unused_fd_flags(O_CLOEXEC);
	if (rc < 0)
		goto put;

	file = anon_inode_getfile("sel4-vm", &sel4_vm_fops, vm, O_RDWR);
	if (IS_ERR(file)) {
		put_unused_fd(rc);
		rc = PTR_ERR(file);
		goto put;
	}
	/* expose to userspace */
	fd_install(rc, file);

	return rc;

put:
	sel4_vm_put(vm);
	return rc;
}

static long sel4_dev_ioctl(struct file *filp,
			  unsigned int ioctl, unsigned long arg)
{
	long rc = -EINVAL;
	struct sel4_vm_params vm_params;

	switch (ioctl) {
	case SEL4_CREATE_VM:
		if (copy_from_user(&vm_params, (void __user *) arg, sizeof(vm_params)))
			return -EFAULT;
		rc = sel4_dev_ioctl_create_vm(vm_params);
		break;
	default:
		break;
	}
	return rc;
}

static struct file_operations sel4_chardev_ops = {
	.unlocked_ioctl = sel4_dev_ioctl,
	.llseek		= noop_llseek,
};

static struct miscdevice sel4_dev = {
	MISC_DYNAMIC_MINOR,
	"sel4",
	&sel4_chardev_ops,
};

int sel4_notify_vmm_dying(int id)
{
	struct sel4_vm *vm, *tmp, *found = NULL;
	int rc = -ENOENT;

	write_lock_bh(&vm_list_lock);
	list_for_each_entry_safe(vm, tmp, &vm_list, vm_list) {
		if (vm->vmm->id == id) {
			found = vm;
			list_del(&found->vm_list);
			break;
		}
	}
	write_unlock_bh(&vm_list_lock);

	if (found) {
		unsigned long irqflags = sel4_vm_lock(vm);
		vm_server->destroy_vm(vm->vmm);
		vm->vmm = NULL;
		sel4_vm_unlock(vm, irqflags);
		rc = 0;
	}

	return rc;
}

long __weak sel4_module_ioctl(struct file *filp,
			      unsigned int ioctl,
			      unsigned long arg)
{
	return -EINVAL;
}

int sel4_init(struct sel4_vm_server *server, struct module *module)
{
	int err;

	BUG_ON(!server || !server->create_vm || !server->destroy_vm || !module);

	vm_server = server;
	sel4_ioreq_wq = alloc_workqueue("sel4_ioreq_wq",
				       WQ_HIGHPRI | WQ_MEM_RECLAIM | WQ_UNBOUND, 1);
	if (!sel4_ioreq_wq) {
		pr_err("sel4: workqueue allocation failed\n");
		return -ENOMEM;
	}

	// Create misc char device
	sel4_chardev_ops.owner = module;
	sel4_vm_fops.owner = module;

	err = misc_register(&sel4_dev);
	if (err) {
		pr_err("sel4: misc device register failed\n");
		destroy_workqueue(sel4_ioreq_wq);
		return err;
	}

	return err;
}

void sel4_exit(void)
{
	misc_deregister(&sel4_dev);
	destroy_workqueue(sel4_ioreq_wq);
	vm_server = NULL;
}

