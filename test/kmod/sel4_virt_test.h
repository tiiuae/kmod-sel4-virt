/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright 2022, Technology Innovation Institute
 *
 */
#ifndef __SEL4_TEST_KMOD_H
#define __SEL4_TEST_KMOD_H

#include "sel4/sel4_virt.h"
#define TEST
#include "sel4/rpc.h"

struct sel4_test_ioreq {
	__u64 slot;
	struct sel4_ioreq ioreq;
};

#define SEL4_TEST_IOREQ_ADD	_IOW(SEL4_IOCTL, 0x80, struct sel4_test_ioreq)
#define SEL4_TEST_INJECT_UPCALL	_IO(SEL4_IOCTL, 0x81)
#define SEL4_TEST_CONSUME_MSG	_IOR(SEL4_IOCTL, 0x82, rpcmsg_t)

#endif /* __SEL4_TEST_KMOD_H */

