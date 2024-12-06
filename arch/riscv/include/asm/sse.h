/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2024 Rivos Inc.
 */
#ifndef __ASM_SSE_H
#define __ASM_SSE_H

#ifdef CONFIG_RISCV_SSE

struct sse_event_interrupted_state {
	unsigned long a6;
	unsigned long a7;
};

struct sse_event_arch_data {
	void *stack;
	void *shadow_stack;
	unsigned long tmp;
	struct sse_event_interrupted_state interrupted;
	unsigned long interrupted_state_phys;
	u32 evt_id;
};

struct sse_registered_event;
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
