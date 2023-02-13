/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright 2022, Technology Innovation Institute
 *
 */
#ifndef __SEL4_VIRT_H
#define __SEL4_VIRT_H

#include <linux/types.h>

#include "sel4_virt_types.h"

#define SEL4_IOEVENTFD_FLAG_PIO		0x01
#define SEL4_IOEVENTFD_FLAG_DATAMATCH	0x02
#define SEL4_IOEVENTFD_FLAG_DEASSIGN	0x04

struct sel4_ioeventfd {
	__s32	fd;
	__u32	flags;
	__u64	addr;
	__u32	len;
	__u32	reserved;
	__u64	data;
};

#define SEL4_IRQFD_FLAG_DEASSIGN	0x01

struct sel4_irqfd {
	__s32	fd;
	__u32	flags;
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

#define SEL4_IOEVENTFD          	_IOW(SEL4_IOCTL, 0x25, struct sel4_ioeventfd)
#define SEL4_IRQFD			_IOW(SEL4_IOCTL, 0x26, struct sel4_irqfd)

/* Returns fd which is to be mmap'd with size SEL4_IOREQ_MMAP_SIZE. */
#define SEL4_CREATE_IO_HANDLER	_IO(SEL4_IOCTL, 0x30)
#define SEL4_WAIT_IO		_IO(SEL4_IOCTL, 0x31)
#define SEL4_NOTIFY_IO_HANDLED	_IOW(SEL4_IOCTL, 0x32, __u64)

#endif /* __SEL4_VIRT_H */
