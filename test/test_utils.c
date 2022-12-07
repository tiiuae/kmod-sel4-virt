// SPDX-License-Identifier: GPL-2.0-only
/*
 * Some parts of the file, namely test_dump_backtrace() from Linux
 * kernel: tools/testing/selftests/kvm/lib/assert.c
 *
 * Copyright (C) 2018, Google LLC.
 * Copyright 2022, Technology Innovation Institute
 *
 */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <execinfo.h>
#include <unistd.h>

#include "test_utils.h"

void __attribute__((noinline)) test_dump_backtrace()
{
	size_t i;
	size_t n = 20;
	void *stack[n];
	const char *addr2line = "addr2line -s -e /proc/$PPID/exe -fpai";
	const char *pipeline = "|cat -n 1>&2";
	char cmd[strlen(addr2line) + strlen(pipeline) +
		 /* N bytes per addr * 2 digits per byte + 1 space per addr: */
		 n * (((sizeof(void *)) * 2) + 1) +
		 /* Null terminator: */
		 1];
	char *c;

	n = backtrace(stack, n);
	c = &cmd[0];
	c += sprintf(c, "%s", addr2line);
	/*
	 * Skip the first 3 frames: backtrace, test_dump_stack, and
	 * test_assert. We hope that backtrace isn't inlined and the other two
	 * we've declared noinline.
	 */
	for (i = 2; i < n; i++)
		c += sprintf(c, " %lx", ((unsigned long) stack[i]) - 1);
	c += sprintf(c, "%s", pipeline);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-result"
	system(cmd);
#pragma GCC diagnostic pop
}

void __attribute__((noinline)) _test_assert(bool exp,
					    const char *exp_str,
					    const char *file,
					    unsigned int line,
					    const char *fmt, ...)
{
	va_list args;
	if (!(exp)) {
		fprintf(stderr, "  %s:%u: ", file, line);
		if (fmt) {
			va_start(args, fmt);
			fputs("  ", stderr);
			vfprintf(stderr, fmt, args);
			fputs("\n", stderr);
			va_end(args);
		}

		if (exp_str) {
			fprintf(stderr, "  %s\n", exp_str);
		}

		if (errno) {
			fprintf(stderr, "  %s\n", strerror(errno));
		}
		test_dump_backtrace();

		exit(254);
	}

	return;
}

int _run_tests(const test_function tests[], const size_t n_tests) {
	int rc = 0;
	size_t i;

	for (i = 0; i < n_tests; i++) {
		if ((tests[i])()) {
			rc++;
		}
	}

	return rc;
}

