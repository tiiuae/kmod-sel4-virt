// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright 2023, 2024, Technology Innovation Institute
 *
 */

#include <linux/slab.h>
#include <linux/list.h>
#include <linux/eventfd.h>
#include <linux/version.h>

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

static inline void sel4_ioeventfd_signal(struct sel4_ioeventfd *ioeventfd)
{
#if LINUX_VERSION_CODE <= KERNEL_VERSION(6,8,0) || LINUX_VERSION_CODE <= KERNEL_VERSION(6,7,12)
	eventfd_signal(ioeventfd->eventfd, 1);
#else
	eventfd_signal(ioeventfd->eventfd);
#endif
}

static bool sel4_ioeventfd_config_valid(struct sel4_ioeventfd_config *config)
{
	if (!config)
		return false;

	/* vhost supported lengths: 0 matches all lengths. */
	switch (config->len) {
	case 0:
	case 1:
	case 2:
	case 4:
	case 8:
		break;
	default:
		return false;
	}

	/* overflow */
	if (config->addr + config->len < config->addr)
		return false;

	/* ioeventfd with no length can't be combined with DATAMATCH */
	if (!config->len && (config->flags & SEL4_IOEVENTFD_FLAG_DATAMATCH))
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
		    (!entry->len || !ioeventfd->len ||
		     (entry->len == ioeventfd->len &&
		      (entry->wildcard || ioeventfd->wildcard ||
			entry->data == ioeventfd->data)))) {
			return true;
		}
	}

	return false;
}

static bool sel4_ioeventfd_in_range(struct sel4_ioeventfd *e, u32 addr_space,
				    u64 addr, u64 len, u64 data)
{
	if (e->addr != addr)
		return false;

	if (e->addr_space != addr_space)
		return false;

	if (!e->len)
		return true;

	if (e->len != len)
		return false;

	if (e->wildcard)
		return true;

	return e->data == data;
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
		if (sel4_ioeventfd_in_range(entry, addr_space,
					    addr, len, data)) {
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

int rpc_process_mmio(struct sel4_vm *vm, rpcmsg_t *req)
{
	struct sel4_ioeventfd *ioeventfd;
	unsigned int direction;
	unsigned int addr_space;
	unsigned int len;
	unsigned int slot;
	seL4_Word addr;
	seL4_Word data;
	int err;
	unsigned long irqflags;

	direction = BIT_FIELD_GET(req->mr0, RPC_MR0_MMIO_DIRECTION);
	addr_space = BIT_FIELD_GET(req->mr0, RPC_MR0_MMIO_ADDR_SPACE);
	len = BIT_FIELD_GET(req->mr0, RPC_MR0_MMIO_LENGTH);
	slot = BIT_FIELD_GET(req->mr0, RPC_MR0_MMIO_SLOT);
	addr = req->mr1;
	data = req->mr2;

	if (direction == SEL4_IO_DIR_READ) {
		/* let userspace process reads */
		return -1;
	}

	irqflags = sel4_vm_lock(vm);
	ioeventfd = sel4_ioeventfd_match(vm, addr_space, addr, len, data);
	if (!ioeventfd) {
		sel4_vm_unlock(vm, irqflags);
		return -1;
	}

	/* signal the eventfd and mark request as complete */
	sel4_ioeventfd_signal(ioeventfd);
	sel4_vm_unlock(vm, irqflags);

	err = driver_rpc_ack_mmio_finish(&vm->vmm->rpc, req, data);
	if (err) {
		// FIXME: Wait and retry
		return -1;
	}

	return 0;
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

