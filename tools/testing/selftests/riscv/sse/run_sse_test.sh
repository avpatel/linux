#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2025 Rivos Inc.

MODULE_NAME=riscv_sse_test
DRIVER="./module/${MODULE_NAME}.ko"

check_test_failed_prefix() {
	if dmesg | grep -q "${MODULE_NAME}: FAILED:";then
		echo "${MODULE_NAME} failed, please check dmesg"
		exit 1
	fi
}

# Kselftest framework requirement - SKIP code is 4.
ksft_skip=4

check_test_requirements()
{
	uid=$(id -u)
	if [ $uid -ne 0 ]; then
		echo "$0: Must be run as root"
		exit $ksft_skip
	fi

	if ! which insmod > /dev/null 2>&1; then
		echo "$0: You need insmod installed"
		exit $ksft_skip
	fi

	if [ ! -f $DRIVER ]; then
		echo "$0: You need to compile ${MODULE_NAME} module"
		exit $ksft_skip
	fi
}

check_test_requirements

insmod $DRIVER > /dev/null 2>&1
rmmod $MODULE_NAME
check_test_failed_prefix

exit 0
