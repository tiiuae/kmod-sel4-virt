// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright 2022, 2023, Technology Innovation Institute
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/fs.h>

#include "sel4_virt_drv.h"
#include "sel4_rpc.h"

#include "sel4_virt_test.h"

#define SEL4_TEST_RPCBUF_SIZE 0x100000

/* Functions for injecting ioreqs from user space */
static int sel4_test_inject_ioreq(struct sel4_vm *vm,
				  struct sel4_test_ioreq *inject)
{
	int rc = 0;
	unsigned long irqflags;

	if (WARN_ON(!vm || !inject || !SEL4_IOREQ_SLOT_VALID(inject->slot)))
		return -EINVAL;

	irqflags = sel4_vm_lock(vm);

	if (WARN_ON(!vm->mmio_reqs)) {
		rc = -ENODEV;
		goto out_unlock;
	}

	vm->mmio_reqs[inject->slot] = inject->ioreq;
	smp_mb();

out_unlock:
	sel4_vm_unlock(vm, irqflags);

	return rc;
}

static int sel4_test_inject_upcall(struct sel4_vm *vm)
{
	sel4_vm_upcall_notify(vm);

	return 0;
}

static int sel4_test_consume_sent(struct sel4_vm *vm, rpcmsg_t __user *to_user)
{
	struct sel4_vmm *vmm;
	struct sel4_rpc *rpc;
	rpcmsg_t *msg;
	int rc = 0;
	unsigned long irqflags;

	irqflags = sel4_vm_lock(vm);

	vmm = vm->vmm;
	if (!vmm || !vmm->private) {
		rc = -ENODEV;
		goto out_unlock;
	}
	rpc = vmm->private;

	msg = rpcmsg_queue_head(rpc->tx_queue);
	if (!msg) {
		rc = -ENOMSG;
		goto out_unlock;
	}
	rc = copy_to_user(to_user, msg, sizeof(*to_user)) ? -EFAULT : 0;
	rpcmsg_queue_advance_head(rpc->tx_queue);

out_unlock:
	sel4_vm_unlock(vm, irqflags);

	return rc;

}

/* mostly for debugging */
static void sel4_test_doorbell(void *private)
{
	struct sel4_vmm *vmm = private;
	struct sel4_rpc *rpc;
	rpcmsg_t *msg;

	if (!vmm || !vmm->private) {
		pr_err("doorbell: private data null\n");
		return;
	}

	rpc = (struct sel4_rpc *) vmm->private;
	msg = rpcmsg_queue_head(rpc->tx_queue);
	if (!msg) {
		pr_err("no message?");
		return;
	}

	switch (QEMU_OP(msg->mr0)) {
	case QEMU_OP_START_VM:
		pr_info("QEMU_OP_START_VM sent\n");
		break;
	case QEMU_OP_REGISTER_PCI_DEV:
		pr_info("QEMU_OP_REGISTER_PCI_DEV sent\n");
		break;
	case QEMU_OP_SET_IRQ:
		pr_info("QEMU_OP_SET_IRQ sent\n");
		break;
	case QEMU_OP_CLR_IRQ:
		pr_info("QEMU_OP_CLR_IRQ sent\n");
		break;
	case QEMU_OP_IO_HANDLED: {
		struct sel4_ioreq *mmio_reqs = device_mmio_reqs(vmm->iobuf.addr);

		pr_info("QEMU_OP_IO_HANDLED sent\n");

		if (WARN_ON(!SEL4_IOREQ_SLOT_VALID(msg->mr1))) {
			break;
		}

		smp_store_release(&mmio_reqs[msg->mr1].state,
				  SEL4_IOREQ_STATE_FREE);
		break;
	}
	default:
		pr_info("unknown message\n");
		break;
	}
}

static int sel4_test_mem_alloc(struct sel4_mem_map *mem, resource_size_t size)
{
	if (!mem || !size)
		return -EINVAL;

	mem->type = SEL4_MEM_VIRTUAL;
	mem->addr = vzalloc(size);
	if (!mem->addr)
		return -ENOMEM;

	mem->paddr = (phys_addr_t) mem->addr;
	mem->size = size;

	return 0;
}

static void sel4_test_mem_free(struct sel4_mem_map *mem)
{
	BUG_ON(!mem);
	vfree(mem->addr);
	mem->addr = NULL;
	mem->size = 0;
	mem->paddr = 0;
}

struct sel4_vmm_ops sel4_test_vmm_ops = {
	.start_vm = sel4_rpc_op_start_vm,
	.create_vpci_device = sel4_rpc_op_create_vpci_device,
	.destroy_vpci_device = sel4_rpc_op_destroy_vpci_device,
	.set_irqline = sel4_rpc_op_set_irqline,
	.notify_io_handled = sel4_rpc_op_notify_io_handled,
};

static struct sel4_vmm *sel4_test_vmm_create(struct sel4_vm_params params)
{
	struct sel4_vmm *vmm;
	struct sel4_rpc *rpc;
	void *rpc_buffer;
	int rc = 0;

	vmm = sel4_vmm_alloc(sel4_test_vmm_ops);
	if (IS_ERR_OR_NULL(vmm)) {
		/* pass on the error */
		return vmm;
	}

	vmm->irq = SEL4_IRQ_NONE;

	rpc_buffer = vmalloc(SEL4_TEST_RPCBUF_SIZE);
	if (!rpc_buffer) {
		rc = -EINVAL;
		goto free_vmm;
	}

	rc = sel4_test_mem_alloc(&vmm->iobuf, PAGE_SIZE * 3);
	if (rc)
		goto free_rpcbuf;

	rc = sel4_test_mem_alloc(&vmm->ram, params.ram_size);
	if (rc)
		goto free_iobuf;

	rpc = sel4_rpc_create(device_tx_queue(rpc_buffer),
			      device_rx_queue(rpc_buffer),
			      sel4_test_doorbell,
			      vmm);
	if (IS_ERR(rpc)) {
		rc = PTR_ERR(rpc);
		goto free_ram;
	}

	vmm->private = rpc;

	return vmm;

free_ram:
	sel4_test_mem_free(&vmm->ram);
free_iobuf:
	sel4_test_mem_free(&vmm->iobuf);
free_rpcbuf:
	vfree(rpc_buffer);
free_vmm:
	kfree(vmm);

	return ERR_PTR(rc);
}

static int sel4_test_vmm_destroy(struct sel4_vmm *vmm)
{
	struct sel4_rpc *rpc;
	if (WARN_ON(IS_ERR_OR_NULL(vmm))) {
		return -EINVAL;
	}

	rpc = vmm->private;

	if (rpc) {
		vfree(rpc->rx_queue);
		sel4_rpc_destroy(rpc);
		vmm->private = NULL;
	}

	sel4_test_mem_free(&vmm->iobuf);
	sel4_test_mem_free(&vmm->ram);

	kfree(vmm);

	return 0;
}

long sel4_module_ioctl(struct file *filp, unsigned int ioctl,
		       unsigned long arg)
{
	struct sel4_vm *vm = filp->private_data;
	int rc = 0;

	BUG_ON(!vm);

	switch (ioctl) {
	case SEL4_TEST_IOREQ_ADD: {
		struct sel4_test_ioreq inject;

		if (copy_from_user(&inject, (void __user *) arg, sizeof(inject)))
			return -EFAULT;

		rc = sel4_test_inject_ioreq(vm, &inject);
		break;
	}
	case SEL4_TEST_INJECT_UPCALL: {
		rc = sel4_test_inject_upcall(vm);
		break;
	}
	case SEL4_TEST_CONSUME_MSG: {
		rc = sel4_test_consume_sent(vm, (rpcmsg_t __user *) arg);
		break;
	}
	default:
		rc = -EINVAL;
		break;
	}

	return rc;
}

static struct sel4_vm_server vm_server = {
	.create_vm = sel4_test_vmm_create,
	.destroy_vm = sel4_test_vmm_destroy,
};

static int __init sel4_test_init(void)
{
	int rc;

	rc = sel4_init(&vm_server, THIS_MODULE);
	if (rc) {
		pr_err("sel4_init failed!\n");
		return rc;
	}

	return rc;
}
module_init(sel4_test_init);

static void __exit sel4_test_exit(void)
{
	sel4_exit();
}
module_exit(sel4_test_exit);

MODULE_AUTHOR("Technology Innovation Institute");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Module for testing seL4 VM module");
