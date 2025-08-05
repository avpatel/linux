/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2024 Ventana Micro Systems Inc.
 */

#ifndef __RISCV_HW_BREAKPOINT_H
#define __RISCV_HW_BREAKPOINT_H

struct task_struct;

#ifdef CONFIG_HAVE_HW_BREAKPOINT

#include <uapi/linux/hw_breakpoint.h>

#if __riscv_xlen == 64
#define cpu_to_le cpu_to_le64
#define le_to_cpu le64_to_cpu
#elif __riscv_xlen == 32
#define cpu_to_le cpu_to_le32
#define le_to_cpu le32_to_cpu
#else
#error "Unexpected __riscv_xlen"
#endif

struct arch_hw_breakpoint {
	unsigned long address;
	unsigned long len;

	/* Callback info */
	unsigned long next_addr;
	bool in_callback;

	/* Trigger configuration data */
	unsigned long tdata1;
	unsigned long tdata2;
	unsigned long tdata3;
};

/* Maximum number of hardware breakpoints supported */
#define RV_MAX_TRIGGERS 32

struct perf_event_attr;
struct notifier_block;
struct perf_event;
struct pt_regs;

int hw_breakpoint_slots(int type);
int arch_check_bp_in_kernelspace(struct arch_hw_breakpoint *hw);
int hw_breakpoint_arch_parse(struct perf_event *bp,
			     const struct perf_event_attr *attr,
			     struct arch_hw_breakpoint *hw);
int hw_breakpoint_exceptions_notify(struct notifier_block *unused,
				    unsigned long val, void *data);
int arch_install_hw_breakpoint(struct perf_event *bp);
void arch_uninstall_hw_breakpoint(struct perf_event *bp);
void hw_breakpoint_pmu_read(struct perf_event *bp);

#endif /* CONFIG_HAVE_HW_BREAKPOINT */
#endif /* __RISCV_HW_BREAKPOINT_H */
