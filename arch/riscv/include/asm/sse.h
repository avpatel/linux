/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2024 Rivos Inc.
 */
#ifndef __ASM_SSE_H
#define __ASM_SSE_H

#include <linux/printk.h>
#include <linux/types.h>

#include <asm/sbi.h>

static inline bool riscv_sse_available(void)
{
#ifdef CONFIG_RISCV_SBI
	return sbi_probe_extension(SBI_EXT_SSE) > 0;
#else
	return false;
#endif
}

static inline void riscv_sse_mask_current_hart(void)
{
#ifdef CONFIG_RISCV_SBI
	struct sbiret ret;

	if (!riscv_sse_available())
		return;

	ret = sbi_ecall(SBI_EXT_SSE, SBI_SSE_HART_MASK, 0, 0, 0, 0, 0, 0);
	if (ret.error && ret.error != SBI_ERR_ALREADY_STOPPED)
		pr_emerg("SSE hart mask failed: %ld\n", ret.error);
#endif
}

#ifdef CONFIG_RISCV_SBI_SSE

struct sse_event_interrupted_state {
	unsigned long a6;
	unsigned long a7;
};

struct sse_event_arch_data {
	void *stack;
	void *shadow_stack;
	unsigned long tmp;
	struct sse_event_interrupted_state *interrupted;
	phys_addr_t interrupted_phys;
	u32 evt_id;
	unsigned long hart_id;
	unsigned int cpu_id;
};

struct riscv_sse_interrupted_context {
	struct pt_regs *regs;
	unsigned long hstatus;
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
void arch_sse_init_cpu(void);

void sse_handle_event(struct sse_event_arch_data *arch_evt,
		      struct pt_regs *regs);
asmlinkage void handle_sse(void);
asmlinkage void noinstr do_sse(struct sse_event_arch_data *arch_evt,
			       struct pt_regs *regs, unsigned long hstatus);

const struct riscv_sse_interrupted_context *
riscv_sse_get_interrupted_context(void);

#endif

#endif
