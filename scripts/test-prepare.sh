#!/bin/sh
#
# Copyright 2022, Technology Innovation Institute
#
# SPDX-License-Identifier: GPL-2.0-only

if [ -n "$TEST_USER" ] && [ "$TEST_USER" != "$(whoami)" ]; then
	>&2 cat << EOF
error: Invalid test user

The tests may crash your computer or worse. You'd normally would run
the tests in a VM, not in your dev machine.

If you still want to run the tests on this machine, set TEST_USER empty.

Consider yourself warned.
EOF
	exit 22
fi

# unload
if grep -q sel4_virt_test /proc/modules; then
	echo "unload modules"
	sudo rmmod sel4_virt_test
fi

sudo insmod sel4_virt_test.ko
sudo chmod a+r+w /dev/sel4
