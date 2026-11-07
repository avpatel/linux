/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2026 Qualcomm Technologies, Inc.
 */

#ifndef __RISCV_HW_BREAKPOINT_H
#define __RISCV_HW_BREAKPOINT_H

struct task_struct;

#ifdef CONFIG_HAVE_HW_BREAKPOINT

#include <uapi/linux/hw_breakpoint.h>

/* Maximum number of hardware breakpoints supported */
#define RISCV_MAX_BP		16

enum riscv_hw_bp_step_method {
	RISCV_HW_BP_STEP_DISABLED,
	RISCV_HW_BP_STEP_ICOUNT,
	RISCV_HW_BP_STEP_SW,
};

struct arch_hw_breakpoint {
	unsigned long address;
	unsigned long len;
	unsigned int type;

	/*
	 * Single-step callback state.  While step_method is enabled, the
	 * hardware slot is temporarily programmed as either an icount trigger
	 * or an execute trigger at next_addr, and the original trigger config
	 * is restored when that temporary trigger fires.
	 */
	unsigned long next_addr;
	enum riscv_hw_bp_step_method step_method;
	bool pending_perf_event;
	unsigned int match;
	unsigned int chain;
	unsigned int select;
	unsigned int time;

	/* Trigger configuration data */
	unsigned long tdata1;
	unsigned long tdata2;
	unsigned long tdata3;
};

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

void arch_enable_hw_breakpoint(struct perf_event *bp);
void arch_update_hw_breakpoint(struct perf_event *bp);
void arch_disable_hw_breakpoint(struct perf_event *bp);
int arch_install_hw_breakpoint(struct perf_event *bp);
void arch_uninstall_hw_breakpoint(struct perf_event *bp);
void hw_breakpoint_pmu_read(struct perf_event *bp);
void clear_ptrace_hw_breakpoint(struct task_struct *tsk);
void flush_ptrace_hw_breakpoint(struct task_struct *tsk);
void ptrace_hw_copy_thread(struct task_struct *task);

#else

static inline void flush_ptrace_hw_breakpoint(struct task_struct *task) { }
static inline void ptrace_hw_copy_thread(struct task_struct *task) { }

#endif /* CONFIG_HAVE_HW_BREAKPOINT */
#endif /* __RISCV_HW_BREAKPOINT_H */
