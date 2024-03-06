/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright 2023, 2024, Technology Innovation Institute
 *
 */
#ifndef __SEL4_VIRT_TYPES_H
#define __SEL4_VIRT_TYPES_H

#include "sel4/rpc.h"

struct sel4_vm_params {
	__u64	ram_size;
	__u64   id;
};

struct sel4_vpci_device {
	__u32	pcidev;
};

#define SEL4_IO_DIR_READ	RPC_MR0_MMIO_DIRECTION_READ
#define SEL4_IO_DIR_WRITE	RPC_MR0_MMIO_DIRECTION_WRITE

#define SEL4_IRQ_OP_CLR		RPC_IRQ_CLR
#define SEL4_IRQ_OP_SET		RPC_IRQ_SET
#define SEL4_IRQ_OP_PULSE	RPC_IRQ_PULSE

struct sel4_irqline {
	__u32	irq;
	__u32	op;
};

#define SEL4_MMIO_REGION_FREE	(1U)

struct sel4_mmio_region_config {
	__u64	gpa;
	__u64	len;
	__u64	flags;
};

#endif /* __SEL4_VIRT_TYPES_H */

