/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2018 SiFive
 * Copyright (C) 2018 Andes Technology Corporation
 *
 */

#ifndef _ASM_RISCV_PERF_EVENT_H
#define _ASM_RISCV_PERF_EVENT_H

#ifdef CONFIG_PERF_EVENTS
/* Use sstatus bit 2 to convey whether an epc in the sample is precise or not */
#define PERF_SR_PRECISE	_AC(0x00000004, UL)

struct pt_regs;
extern unsigned long perf_arch_misc_flags(struct pt_regs *regs);
#define perf_arch_misc_flags(regs)	perf_arch_misc_flags(regs)
#define perf_arch_instruction_pointer(regs)	instruction_pointer(regs)

#include <linux/perf_event.h>
#define perf_arch_bpf_user_pt_regs(regs) (struct user_regs_struct *)regs

#define perf_arch_fetch_caller_regs(regs, __ip) { \
	(regs)->epc = (__ip); \
	(regs)->s0 = (unsigned long) __builtin_frame_address(0); \
	(regs)->sp = current_stack_pointer; \
	(regs)->status = SR_PP; \
}

#ifdef CONFIG_RISCV_SBI_SSE
/*
 * Raw user-stack sampling can run in the NMI-like SSE context. Route it
 * through an implementation that does not fault on a non-resident page.
 */
unsigned long riscv_perf_out_copy_user(void *dst, const void *src,
				       unsigned long n);
#define arch_perf_out_copy_user riscv_perf_out_copy_user
#endif
#endif

#endif /* _ASM_RISCV_PERF_EVENT_H */
