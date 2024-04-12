// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright 2023, Technology Innovation Institute
 *
 */

#include <linux/mutex.h>
#include <linux/file.h>
#include <linux/wait.h>
#include <linux/workqueue.h>
#include <linux/poll.h>
#include <linux/eventfd.h>
#include <linux/list.h>
#include <linux/slab.h>

#include "sel4_virt_drv.h"

struct sel4_irqfd {
	struct sel4_vm		*vm;
	struct list_head	list;
	struct eventfd_ctx	*eventfd;
	wait_queue_entry_t	wait;
	struct work_struct	cleanup;
	poll_table		pt;
	u32 virq;
};

static struct workqueue_struct *irqfd_cleanup_wq;

static void sel4_irqfd_inject(struct sel4_irqfd *irqfd)
{
	u64 cnt;
	eventfd_ctx_do_read(irqfd->eventfd, &cnt);

	/* Pulse irq */
	sel4_vm_set_irqline(irqfd->vm, irqfd->virq, SEL4_IRQ_OP_PULSE);
}

/* Called with wqh->lock held and interrupts disabled */
static int sel4_irqfd_wakeywakey(wait_queue_entry_t *wait,
				 unsigned int mode,
				 int sync, void *key)
{
	struct sel4_irqfd *irqfd;
	unsigned long poll_bits = (unsigned long)key;

	irqfd = container_of(wait, struct sel4_irqfd, wait);
	if (poll_bits & POLLIN)
		/* An event has been signaled, inject an interrupt */
		sel4_irqfd_inject(irqfd);

	if (poll_bits & POLLHUP)
		/* Do shutdown work in thread to hold wqh->lock */
		queue_work(irqfd_cleanup_wq , &irqfd->cleanup);

	return 0;
}

static void sel4_irqfd_poll(struct file *file, wait_queue_head_t *wqh, poll_table *pt)
{
	struct sel4_irqfd *irqfd = container_of(pt, struct sel4_irqfd, pt);
	add_wait_queue_priority(wqh, &irqfd->wait);
}

static void sel4_irqfd_cleanup(struct sel4_irqfd *irqfd)
{
	u64 cnt;

	lockdep_assert_held(&irqfd->vm->lock);

	/* remove from wait queue */
	list_del_init(&irqfd->list);
	eventfd_ctx_remove_wait_queue(irqfd->eventfd, &irqfd->wait, &cnt);
	eventfd_ctx_put(irqfd->eventfd);
	kfree(irqfd);
}

static void sel4_irqfd_cleanup_work(struct work_struct *work)
{
	struct sel4_irqfd *irqfd;
	unsigned long irqflags;

	irqfd = container_of(work, struct sel4_irqfd, cleanup);

	irqflags = sel4_vm_lock(irqfd->vm);
	if (!list_empty(&irqfd->list))
		sel4_irqfd_cleanup(irqfd);
	sel4_vm_unlock(irqfd->vm, irqflags);
}

static int sel4_irqfd_assign(struct sel4_vm *vm,
			     struct sel4_irqfd_config *config)
{
	struct sel4_irqfd *irqfd, *tmp;
	struct fd fd;
	__poll_t events;
	unsigned long irqflags;
	int rc = 0;

	irqfd = kzalloc(sizeof(*irqfd), GFP_KERNEL);
	if (!irqfd)
		return -ENOMEM;

	irqfd->vm = vm;

	irqfd->virq = config->virq;
	INIT_LIST_HEAD(&irqfd->list);
	INIT_WORK(&irqfd->cleanup, sel4_irqfd_cleanup_work);
	fd = fdget(config->fd);
	if (!fd.file) {
		rc = -EBADF;
		goto err_free;
	}

	irqfd->eventfd = eventfd_ctx_fileget(fd.file);
	if (IS_ERR(irqfd->eventfd )) {
		rc = PTR_ERR(irqfd->eventfd);
		goto err_put;
	}

	init_waitqueue_func_entry(&irqfd->wait, sel4_irqfd_wakeywakey);
	init_poll_funcptr(&irqfd->pt, sel4_irqfd_poll);

	irqflags = sel4_vm_lock(vm);
	list_for_each_entry(tmp, &vm->irqfds, list) {
		if (irqfd->eventfd != tmp->eventfd)
			continue;
		rc = -EBUSY;
		sel4_vm_unlock(vm, irqflags);
		goto err_put;
	}
	list_add_tail(&irqfd->list, &vm->irqfds);
	sel4_vm_unlock(vm, irqflags);

	/* Check the pending event in this stage */
	events = vfs_poll(fd.file, &irqfd->pt);

	if (events & EPOLLIN)
		sel4_irqfd_inject(irqfd);

	fdput(fd);

	return rc;

err_put:
	if (irqfd->eventfd  && !IS_ERR(irqfd->eventfd))
		eventfd_ctx_put(irqfd->eventfd);

	fdput(fd);
err_free:
	kfree(irqfd);

	return rc;
}

static int sel4_irqfd_deassign(struct sel4_vm *vm,
			       struct sel4_irqfd_config *config)
{
	struct sel4_irqfd *irqfd, *tmp;
	struct eventfd_ctx *eventfd;
	unsigned long irqflags;

	eventfd = eventfd_ctx_fdget(config->fd);
	if (IS_ERR(eventfd))
		return PTR_ERR(eventfd);

	irqflags = sel4_vm_lock(vm);
	list_for_each_entry_safe(irqfd, tmp, &vm->irqfds, list) {
		if (irqfd->eventfd == eventfd) {
			sel4_irqfd_cleanup(irqfd);
			break;
		}
	}
	sel4_vm_unlock(vm, irqflags);

	eventfd_ctx_put(eventfd);

	return 0;
}

int sel4_vm_irqfd_config(struct sel4_vm *vm,
			 struct sel4_irqfd_config *config)
{
	if (WARN_ON(!vm || !config))
		return -EINVAL;

	if (config->flags & SEL4_IRQFD_FLAG_DEASSIGN)
		return sel4_irqfd_deassign(vm, config);

	return sel4_irqfd_assign(vm, config);
}

int sel4_irqfd_init(void)
{
	irqfd_cleanup_wq = alloc_workqueue("sel4-irqfd-cleanup", 0, 0);
	if (!irqfd_cleanup_wq)
		return -ENOMEM;

	return 0;
}

void sel4_irqfd_exit(void)
{
	destroy_workqueue(irqfd_cleanup_wq);
}

