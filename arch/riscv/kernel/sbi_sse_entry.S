/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2024 Rivos Inc.
 */

#include <linux/init.h>
#include <linux/linkage.h>

#include <asm/asm.h>
#include <asm/csr.h>
#include <asm/scs.h>

/* When entering handle_sse, the following registers are set:
 * a6: contains the hartid
 * a7: contains a sse_event_arch_data struct pointer
 */
SYM_CODE_START(handle_sse)
	/* Save stack temporarily */
	REG_S sp, SSE_REG_EVT_TMP(a7)
	/* Set entry stack */
	REG_L sp, SSE_REG_EVT_STACK(a7)

	addi sp, sp, -(PT_SIZE_ON_STACK)
	REG_S ra, PT_RA(sp)
	REG_S s0, PT_S0(sp)
	REG_S s1, PT_S1(sp)
	REG_S s2, PT_S2(sp)
	REG_S s3, PT_S3(sp)
	REG_S s4, PT_S4(sp)
	REG_S s5, PT_S5(sp)
	REG_S s6, PT_S6(sp)
	REG_S s7, PT_S7(sp)
	REG_S s8, PT_S8(sp)
	REG_S s9, PT_S9(sp)
	REG_S s10, PT_S10(sp)
	REG_S s11, PT_S11(sp)
	REG_S tp, PT_TP(sp)
	REG_S t0, PT_T0(sp)
	REG_S t1, PT_T1(sp)
	REG_S t2, PT_T2(sp)
	REG_S t3, PT_T3(sp)
	REG_S t4, PT_T4(sp)
	REG_S t5, PT_T5(sp)
	REG_S t6, PT_T6(sp)
	REG_S gp, PT_GP(sp)
	REG_S a0, PT_A0(sp)
	REG_S a1, PT_A1(sp)
	REG_S a2, PT_A2(sp)
	REG_S a3, PT_A3(sp)
	REG_S a4, PT_A4(sp)
	REG_S a5, PT_A5(sp)

	/* Retrieve entry sp */
	REG_L a4, SSE_REG_EVT_TMP(a7)
	/* Save CSRs */
	csrr a0, CSR_EPC
	csrr a1, CSR_SSTATUS
	csrr a2, CSR_STVAL
	csrr a3, CSR_SCAUSE

	REG_S a0, PT_EPC(sp)
	REG_S a1, PT_STATUS(sp)
	REG_S a2, PT_BADADDR(sp)
	REG_S a3, PT_CAUSE(sp)
	REG_S a4, PT_SP(sp)

	/* Disable user memory access and floating/vector computing */
	li t0, SR_SUM | SR_FS_VS
	csrc CSR_STATUS, t0

	load_global_pointer
	scs_load_sse_stack a7

#ifdef CONFIG_SMP
	lw t4, SSE_REG_HART_ID(a7)
	lw t3, SSE_REG_CPU_ID(a7)

	bne t4, a6, .Lfind_hart_id_slowpath

.Lcpu_id_found:
#else
	mv t3, zero
#endif

	asm_per_cpu_with_cpu t2 __sbi_sse_entry_task t1 t3
	REG_L tp, 0(t2)

	mv a1, sp /* pt_regs on stack */

	/*
	 * Save sscratch for restoration since we might have interrupted the
	 * kernel in early exception path and thus, we don't know the content of
	 * sscratch.
	 */
	csrrw s4, CSR_SSCRATCH, x0

	mv a0, a7

	call do_sse

	csrw CSR_SSCRATCH, s4

	REG_L a0, PT_STATUS(sp)
	REG_L a1, PT_EPC(sp)
	REG_L a2, PT_BADADDR(sp)
	REG_L a3, PT_CAUSE(sp)
	csrw CSR_SSTATUS, a0
	csrw CSR_EPC, a1
	csrw CSR_STVAL, a2
	csrw CSR_SCAUSE, a3

	REG_L ra, PT_RA(sp)
	REG_L s0, PT_S0(sp)
	REG_L s1, PT_S1(sp)
	REG_L s2, PT_S2(sp)
	REG_L s3, PT_S3(sp)
	REG_L s4, PT_S4(sp)
	REG_L s5, PT_S5(sp)
	REG_L s6, PT_S6(sp)
	REG_L s7, PT_S7(sp)
	REG_L s8, PT_S8(sp)
	REG_L s9, PT_S9(sp)
	REG_L s10, PT_S10(sp)
	REG_L s11, PT_S11(sp)
	REG_L tp, PT_TP(sp)
	REG_L t0, PT_T0(sp)
	REG_L t1, PT_T1(sp)
	REG_L t2, PT_T2(sp)
	REG_L t3, PT_T3(sp)
	REG_L t4, PT_T4(sp)
	REG_L t5, PT_T5(sp)
	REG_L t6, PT_T6(sp)
	REG_L gp, PT_GP(sp)
	REG_L a0, PT_A0(sp)
	REG_L a1, PT_A1(sp)
	REG_L a2, PT_A2(sp)
	REG_L a3, PT_A3(sp)
	REG_L a4, PT_A4(sp)
	REG_L a5, PT_A5(sp)

	REG_L sp, PT_SP(sp)

	li a7, SBI_EXT_SSE
	li a6, SBI_SSE_EVENT_COMPLETE
	ecall

#ifdef CONFIG_SMP
.Lfind_hart_id_slowpath:

	/* Restore current task struct from __sbi_sse_entry_task */
	li t1, ASM_NR_CPUS
	/* Slowpath to find the CPU id associated to the hart id */
	la t0, __cpuid_to_hartid_map

.Lhart_id_loop:
	REG_L t2, 0(t0)
	beq t2, a6, .Lcpu_id_found

	/* Increment pointer and CPU number */
	addi t3, t3, 1
	addi t0, t0, RISCV_SZPTR
	bltu t3, t1, .Lhart_id_loop

	/*
	 * This should never happen since we expect the hart_id to match one
	 * of our CPU, but better be safe than sorry
	 */
	la tp, init_task
	la a0, sse_hart_id_panic_string
	la t0, panic
	jalr t0
#endif

SYM_CODE_END(handle_sse)

SYM_DATA_START_LOCAL(sse_hart_id_panic_string)
    .ascii "Unable to match hart_id with cpu\0"
SYM_DATA_END(sse_hart_id_panic_string)
