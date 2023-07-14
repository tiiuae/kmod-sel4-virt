// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright 2023, Technology Innovation Institute
 *
 */

#include <linux/slab.h>
#include <linux/list.h>
#include <linux/eventfd.h>

#include "sel4_virt_drv.h"

struct sel4_ioeventfd {
	struct list_head	list;
	struct eventfd_ctx	*eventfd;
	u64	addr;
	u64	data;
	u32	len;
	u32	addr_space;
	bool	wildcard;
};

static bool sel4_ioeventfd_config_valid(struct sel4_ioeventfd_config *config)
{
	if (!config)
		return false;

	/* overflow */
	if (config->addr + config->len < config->addr)
		return false;

	/* vhost supported lengths */
	if (!(config->len == 1 || config->len == 2 ||
	      config->len == 4 || config->len == 8))
		return false;

	return true;
}

static bool sel4_ioeventfd_conflict(struct sel4_vm *vm,
				    struct sel4_ioeventfd *ioeventfd)
{
	struct sel4_ioeventfd *entry;

	lockdep_assert_held(&vm->lock);

	list_for_each_entry(entry, &vm->ioeventfds, list) {
		if (entry->eventfd == ioeventfd->eventfd &&
		    entry->addr == ioeventfd->addr &&
		    entry->addr_space == ioeventfd->addr_space &&
		    (entry->wildcard || ioeventfd->wildcard ||
			entry->data == ioeventfd->data)) {
			return true;
		}
	}

	return false;
}

static struct sel4_ioeventfd *sel4_ioeventfd_match(struct sel4_vm *vm,
						   u32 addr_space, u64 addr,
						   u64 len, u64 data)
{
	struct sel4_ioeventfd *entry = NULL;
	if (WARN_ON(!vm))
		return NULL;

	lockdep_assert_held(&vm->lock);

	list_for_each_entry(entry, &vm->ioeventfds, list) {
		if (entry->addr == addr &&
		    entry->addr_space == addr_space &&
		    entry->len >= len &&
		    (entry->wildcard || entry->data == data)) {
			return entry;
		}
	}

	return NULL;
}

static int sel4_ioeventfd_assign(struct sel4_vm *vm,
				 struct sel4_ioeventfd_config *config)
{
	struct eventfd_ctx *eventfd;
	struct sel4_ioeventfd *new;
	unsigned long irqflags;
	int rc = 0;

	if (!sel4_ioeventfd_config_valid(config)) {
		return -EINVAL;
	}

	eventfd = eventfd_ctx_fdget(config->fd);
	if (IS_ERR(eventfd))
		return PTR_ERR(eventfd);

	new = kzalloc(sizeof(*new), GFP_KERNEL);
	if (!new) {
		rc = -ENOMEM;
		goto err;
	}

	INIT_LIST_HEAD(&new->list);
	new->addr = config->addr;
	new->addr_space = config->addr_space;
	new->len = config->len;
	new->eventfd = eventfd;

	if (config->flags & SEL4_IOEVENTFD_FLAG_DATAMATCH)
		new->data = config->data;
	else
		new->wildcard = true;

	irqflags = sel4_vm_lock(vm);
	if (sel4_ioeventfd_conflict(vm, new)) {
		rc = -EEXIST;
		goto err_unlock;
	}

	list_add_tail(&new->list, &vm->ioeventfds);
	sel4_vm_unlock(vm, irqflags);

	return rc;

err_unlock:
	sel4_vm_unlock(vm, irqflags);
	kfree(new);
err:
	eventfd_ctx_put(eventfd);
	return rc;
}

static int sel4_ioeventfd_deassign(struct sel4_vm *vm,
				 struct sel4_ioeventfd_config *config)
{
	struct sel4_ioeventfd *entry, *tmp;
	struct eventfd_ctx *eventfd;
	unsigned long irqflags;

	eventfd = eventfd_ctx_fdget(config->fd);
	if (IS_ERR(eventfd))
		return PTR_ERR(eventfd);

	irqflags = sel4_vm_lock(vm);

	list_for_each_entry_safe(entry, tmp, &vm->ioeventfds, list) {
		if (entry->eventfd != eventfd)
			continue;

		eventfd_ctx_put(entry->eventfd);
		list_del(&entry->list);
		kfree(entry);
		break;
	}

	sel4_vm_unlock(vm, irqflags);

	eventfd_ctx_put(eventfd);

	return 0;
}

int sel4_vm_ioeventfd_process(struct sel4_vm *vm, int slot)
{
	struct sel4_ioreq *ioreq = vm->ioreq_buffer->request_slots + slot;
	struct sel4_ioeventfd *ioeventfd;
	int rc = SEL4_IOEVENTFD_NONE;

	lockdep_assert_held(&vm->lock);

	if (WARN_ON(!SEL4_IOREQ_SLOT_VALID(slot))) {
		return -EINVAL;
	}

	if (ioreq->direction == SEL4_IO_DIR_READ) {
		/* let userspace process reads */
		return SEL4_IOEVENTFD_NONE;
	}

	ioeventfd = sel4_ioeventfd_match(vm, ioreq->addr_space, ioreq->addr,
					 ioreq->len, ioreq->data);
	if (ioeventfd) {
		/* signal the eventfd and mark request as complete */
		eventfd_signal(ioeventfd->eventfd, 1);
		smp_store_release(&ioreq->state, SEL4_IOREQ_STATE_COMPLETE);

		rc = sel4_vm_notify_io_handled(vm, slot);
		if (rc)
			return rc;

		return SEL4_IOEVENTFD_PROCESSED;
	}

	return rc;
}

int sel4_vm_ioeventfd_config(struct sel4_vm *vm,
			     struct sel4_ioeventfd_config *config)
{
	if (WARN_ON(!vm || !config))
		return -EINVAL;

	if (config->flags & SEL4_IOEVENTFD_FLAG_DEASSIGN)
		return sel4_ioeventfd_deassign(vm, config);

	return sel4_ioeventfd_assign(vm, config);
}

