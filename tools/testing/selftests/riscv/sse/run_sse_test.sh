#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2025 Rivos Inc.

MODULE_NAME=riscv_sse_test
DRIVER="./module/${MODULE_NAME}.ko"
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

	if [ ! -f "$DRIVER" ]; then
		echo "$0: SSE is disabled or ${MODULE_NAME} is not built"
		exit $ksft_skip
	fi
}

check_test_requirements
run_id="$$-$(date +%s)"

if ! insmod "$DRIVER" run_id="$run_id" "$@" > /dev/null 2>&1; then
	echo "${MODULE_NAME}: failed to load, please check dmesg"
	exit 1
fi

if ! rmmod "$MODULE_NAME"; then
	echo "${MODULE_NAME}: failed to unload, please check dmesg"
	exit 1
fi

run_log=$(dmesg | sed -n \
	"/${MODULE_NAME}: RUN ${run_id} BEGIN/,/${MODULE_NAME}: RUN ${run_id} END/p")
if [ -z "$run_log" ]; then
	echo "${MODULE_NAME}: unable to find log for run ${run_id}"
	exit 1
fi

if echo "$run_log" | grep -q "${MODULE_NAME}: FAILED:"; then
	echo "${MODULE_NAME} failed, please check dmesg"
	exit 1
fi

if echo "$run_log" | grep -q "${MODULE_NAME}: SKIP:"; then
	echo "${MODULE_NAME}: no injectable SSE event"
	exit $ksft_skip
fi

exit 0
