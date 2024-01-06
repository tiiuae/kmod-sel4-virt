/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright 2022, 2023, 2024, Technology Innovation Institute
 *
 */
#ifndef __SEL4_VIRT_H
#define __SEL4_VIRT_H

#include <linux/types.h>

#include "sel4_virt_types.h"

#define SEL4_IOEVENTFD_FLAG_DATAMATCH	(1 << 1)
#define SEL4_IOEVENTFD_FLAG_DEASSIGN	(1 << 2)

enum {
	SEL4_MEM_MAP_RAM,
	SEL4_MEM_MAP_IOBUF,
	SEL4_MEM_MAP_EVENT_BAR,
	NUM_SEL4_MEM_MAP
};

struct sel4_ioeventfd_config {
	__s32	fd;
	__u32	flags;
	__u64	addr;
	__u32	len;
	__u32	addr_space;
	__u64	data;
};

#define SEL4_IRQFD_FLAG_DEASSIGN	(1)

struct sel4_irqfd_config {
	__s32	fd;
	__u32	flags;
	__u32	virq;
};

#define SEL4_IOCTL 0xAF

/* Returns fd to VM or negative error code.
 *
 * RAM is accessed by mmap'ing the returned fd with sel4_vm_params.ram_size. */
#define SEL4_CREATE_VM			_IOW(SEL4_IOCTL, 0x20, struct sel4_vm_params)

#define SEL4_START_VM			_IO(SEL4_IOCTL,  0x21)
#define SEL4_CREATE_VPCI_DEVICE		_IOW(SEL4_IOCTL, 0x22, struct sel4_vpci_device)
#define SEL4_DESTROY_VPCI_DEVICE	_IOW(SEL4_IOCTL, 0x23, struct sel4_vpci_device)
#define SEL4_SET_IRQLINE		_IOW(SEL4_IOCTL, 0x24, struct sel4_irqline)

#define SEL4_IOEVENTFD          	_IOW(SEL4_IOCTL, 0x25, struct sel4_ioeventfd_config)
#define SEL4_IRQFD			_IOW(SEL4_IOCTL, 0x26, struct sel4_irqfd_config)

#define SEL4_MMIO_REGION		_IOW(SEL4_IOCTL, 0x27, struct sel4_mmio_region_config)

#define SEL4_CREATE_IO_HANDLER	_IOW(SEL4_IOCTL, 0x30, __u64)
#define SEL4_WAIT_IO		_IO(SEL4_IOCTL, 0x31)
#define SEL4_NOTIFY_IO_HANDLED	_IOW(SEL4_IOCTL, 0x32, __u64)

#endif /* __SEL4_VIRT_H */
