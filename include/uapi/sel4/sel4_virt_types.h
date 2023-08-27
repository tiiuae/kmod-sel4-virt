/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright 2023, Technology Innovation Institute
 *
 */
#ifndef __SEL4_VIRT_TYPES_H
#define __SEL4_VIRT_TYPES_H

struct sel4_vm_params {
	__u64	ram_size;
	__u64   id;
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

#define AS_GLOBAL           ~0
#define AS_PCIDEV(__pcidev) (__pcidev)

struct sel4_ioreq {
	__u16   state;
	__u16	direction;
	__u32   addr_space;
	__u64	addr;
	__u64	len;
	__u64	data;
} __attribute__((packed, aligned(128)));


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

#endif /* __SEL4_VIRT_TYPES_H */

