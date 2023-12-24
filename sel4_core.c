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
#include <linux/eventfd.h>

#include "sel4/sel4_virt.h"
#include "sel4_virt_drv.h"
#include "sel4/sel4_vmm_rpc.h"

/* Large enough to hold huge number with sign and null character */
#define ITOA_MAX_LEN	(12)

static void sel4_vm_upcall_work(struct work_struct *work);

DEFINE_RWLOCK(vm_list_lock);
LIST_HEAD(vm_list);

static struct sel4_vm_server *vm_server;

static struct workqueue_struct *sel4_ioreq_wq;
static DECLARE_WORK(sel4_ioreq_work, sel4_vm_upcall_work);

static void sel4_vm_process_ioreqs(struct sel4_vm *vm)
{
	struct sel4_ioreq *ioreq;
	int slot;
	unsigned long irqflags;

	irqflags = sel4_vm_lock(vm);

	if (!vm->mmio_reqs)
		goto out_unlock;

	for (slot = 0; slot < SEL4_MAX_IOREQS; slot++) {
		ioreq = vm->mmio_reqs + slot;
		if (smp_load_acquire(&ioreq->state) == SEL4_IOREQ_STATE_PENDING) {
			if (sel4_vm_ioeventfd_process(vm, slot) == SEL4_IOEVENTFD_PROCESSED)
				continue;

			smp_store_release(&ioreq->state,
					  SEL4_IOREQ_STATE_PROCESSING);
			set_bit(slot, vm->ioreq_map);

			wake_up_interruptible(&vm->ioreq_wait);
		}
	}

out_unlock:
	sel4_vm_unlock(vm, irqflags);
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
		goto err_free_vm;
	}

	if (!sel4_vmm_valid(vm->vmm)) {
		rc = -EINVAL;
		goto err_destroy_vm;
	}

	vm->vmm->vm = vm;

	spin_lock_init(&vm->lock);

	refcount_set(&vm->refcount, 1);

	/* FIXME: to own file */
	vm->mmio_reqs = NULL;
	init_waitqueue_head(&vm->ioreq_wait);

	INIT_LIST_HEAD(&vm->ioeventfds);
	INIT_LIST_HEAD(&vm->irqfds);

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

			goto err_destroy_vm;
		}
	}

	return vm;

err_destroy_vm:
	vm_server->destroy_vm(vm->vmm);
err_free_vm:
	kfree(vm);

	return ERR_PTR(rc);
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
	vm->mmio_reqs = NULL;
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
	unsigned long irqflags;


	irqflags = sel4_vm_lock(vm);
	if (vm->mmio_reqs) {
		sel4_vm_unlock(vm, irqflags);
		return -EEXIST;
	}

	vm->mmio_reqs = device_mmio_reqs(vm->vmm->iobuf.addr);
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
	vm->mmio_reqs = NULL;
	sel4_vm_unlock(vm, irqflags);

	sel4_put_no_destroy(vm);

	return rc;
}

static int sel4_vm_ioreq_complete(struct sel4_vm *vm, u32 slot)
{
	struct sel4_ioreq *ioreq;
	int rc = 0;
	unsigned long irqflags;

	if (!SEL4_IOREQ_SLOT_VALID(slot)) {
		return -EINVAL;
	}

	irqflags = sel4_vm_lock(vm);
	if (vm->mmio_reqs) {
		clear_bit(slot, vm->ioreq_map);
		ioreq = vm->mmio_reqs + slot;
		smp_store_release(&ioreq->state, SEL4_IOREQ_STATE_COMPLETE);
		rc = sel4_vm_notify_io_handled(vm, slot);
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
	if (!vm->mmio_reqs) {
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
		struct sel4_ioeventfd_config ioeventfd;
		if (copy_from_user(&ioeventfd, (void __user *) arg,
				   sizeof(ioeventfd)))
			return -EFAULT;

		rc = sel4_vm_ioeventfd_config(vm, &ioeventfd);
		break;
	}
	case SEL4_IRQFD: {
		struct sel4_irqfd_config irqfd;
		if (copy_from_user(&irqfd, (void __user *) arg, sizeof(irqfd)))
			return -EFAULT;

		rc = sel4_vm_irqfd_config(vm, &irqfd);
		break;
	}
	case SEL4_MMIO_REGION: {
		struct sel4_mmio_region_config mmio_region;
		if (copy_from_user(&mmio_region, (void __user *) arg, sizeof(mmio_region)))
			return -EFAULT;

		rc = sel4_vm_mmio_region_config(vm, &mmio_region);
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

	if (sel4_irqfd_init()) {
		pr_err("sel4: irqfd init failed\n");
		destroy_workqueue(sel4_ioreq_wq);
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
	sel4_irqfd_exit();
	destroy_workqueue(sel4_ioreq_wq);
	vm_server = NULL;
}

