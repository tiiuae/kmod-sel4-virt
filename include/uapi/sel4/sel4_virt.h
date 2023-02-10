/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright 2022, Technology Innovation Institute
 *
 */
#ifndef __SEL4_VIRT_H
#define __SEL4_VIRT_H

#include <linux/types.h>

struct sel4_vm_params {
	__u64	ram_size;
};

#define SEL4_MAX_IOREQS			32
#define SEL4_MAX_VCPUS			(SEL4_MAX_IOREQS)
#define SEL4_IOREQ_MMAP_SIZE		4096

#define SEL4_IO_DIR_READ		0U
#define SEL4_IO_DIR_WRITE		1U

#define SEL4_IOREQ_STATE_FREE		0U
#define SEL4_IOREQ_STATE_PENDING	1U
#define SEL4_IOREQ_STATE_PROCESSING	2U
#define SEL4_IOREQ_STATE_COMPLETE	3U

#define SEL4_IOREQ_TYPE_MMIO		0U
#define SEL4_IOREQ_TYPE_PCI		1U

struct sel4_ioreq_mmio {
	__u32	direction;
	__u32   vcpu;
	__u64	addr;
	__u64	len;
	__u64	data;
};

struct sel4_ioreq_pci {
	__u32	direction;
	__u32	pcidev;
	__u32	addr;
	__u32	len;
	__u32	data;
	__u32   reserved0;
};

struct sel4_ioreq {
	__u32   state;
	__u32   type;
	union {
		struct sel4_ioreq_mmio	mmio;
		struct sel4_ioreq_pci	pci;
		__u64			data[8];
	} req;
} __attribute__((aligned(128)));


#define SEL4_IOREQ_SLOT_VALID(_slot) \
	((_slot) >= 0 && (_slot) < (SEL4_MAX_IOREQS))

struct sel4_iohandler_buffer {
	union {
		struct sel4_ioreq	request_slots[SEL4_MAX_IOREQS];
		__u8			reserved[SEL4_IOREQ_MMAP_SIZE];
	};
};

struct sel4_vpci_device {
	__u32	pcidev;
};

#define SEL4_IRQ_OP_CLR	0
#define SEL4_IRQ_OP_SET	1

struct sel4_irqline {
	__u32	irq;
	__u32	op;
};

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
