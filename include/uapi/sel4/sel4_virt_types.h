/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright 2023, Technology Innovation Institute
 *
 */
#ifndef __SEL4_VIRT_TYPES_H
#define __SEL4_VIRT_TYPES_H

#include "sel4/sel4_vmm_rpc.h"

struct sel4_vm_params {
	__u64	ram_size;
	__u64   id;
};

#define SEL4_MMIO_MAX_VCPU		32
#define SEL4_MMIO_NATIVE_BASE		SEL4_MMIO_MAX_VCPU
#define SEL4_MMIO_MAX_NATIVE		32

#define SEL4_IO_DIR_READ		RPC_MR0_MMIO_DIRECTION_READ
#define SEL4_IO_DIR_WRITE		RPC_MR0_MMIO_DIRECTION_WRITE

#define AS_GLOBAL			MASK(RPC_MR0_MMIO_ADDR_SPACE_WIDTH)
#define AS_PCIDEV(__pcidev)		(__pcidev)

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

