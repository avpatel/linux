# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2021 ARM Limited
# Originally tools/testing/arm64/abi/Makefile

CFLAGS += -I$(top_srcdir)/tools/include

TEST_GEN_PROGS := breakpoint_test

include ../../lib.mk

$(OUTPUT)/breakpoint_test: breakpoint_test.c
	$(CC) -static -o$@ $(CFLAGS) $(LDFLAGS) $^
