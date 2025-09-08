/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2024 Rivos Inc.
 */
#ifndef __ASM_SSE_H
#define __ASM_SSE_H

#include <asm/sbi.h>

#ifdef CONFIG_RISCV_SBI_SSE

struct sse_event_interrupted_state {
	unsigned long a6;
	unsigned long a7;
};

struct sse_event_arch_data {
	void *stack;
	void *shadow_stack;
	unsigned long tmp;
	struct sse_event_interrupted_state interrupted;
	unsigned long interrupted_phys;
	u32 evt_id;
	unsigned int hart_id;
	unsigned int cpu_id;
};

static inline bool sse_event_is_global(u32 evt)
{
	return !!(evt & SBI_SSE_EVENT_GLOBAL);
}

void arch_sse_event_update_cpu(struct sse_event_arch_data *arch_evt, int cpu);
int arch_sse_init_event(struct sse_event_arch_data *arch_evt, u32 evt_id,
			int cpu);
void arch_sse_free_event(struct sse_event_arch_data *arch_evt);
int arch_sse_register_event(struct sse_event_arch_data *arch_evt);

void sse_handle_event(struct sse_event_arch_data *arch_evt,
		      struct pt_regs *regs);
asmlinkage void handle_sse(void);
asmlinkage void do_sse(struct sse_event_arch_data *arch_evt,
		       struct pt_regs *reg);

#endif

#endif
