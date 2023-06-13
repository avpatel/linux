// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2024 Rivos Inc.
 */
#include <linux/nmi.h>
#include <linux/scs.h>
#include <linux/bitfield.h>
#include <linux/riscv_sse.h>

#include <asm/asm-prototypes.h>
#include <asm/irq_stack.h>
#include <asm/sbi.h>
#include <asm/sse.h>

#define SSE_PRIVILEGE_MODE_BIT			BIT(0)
#define SSE_SPIE_BIT				BIT(2)

#define sse_privilege_mode(exec_mode)	FIELD_GET(SSE_PRIVILEGE_MODE_BIT, exec_mode)
#define sse_spie(exec_mode)		FIELD_GET(SSE_SPIE_BIT, exec_mode)

struct sse_registered_event;

extern asmlinkage void handle_sse(void);

void do_sse(struct sse_registered_event *reg_evt, struct pt_regs *regs)
{
	nmi_enter();

	/* Retrieve missing GPRs from SBI */
	sbi_ecall(SBI_EXT_SSE, SBI_SSE_EVENT_ATTR_READ, reg_evt->evt_id,
		  SBI_SSE_ATTR_INTERRUPTED_A6,
		  (SBI_SSE_ATTR_INTERRUPTED_A7 - SBI_SSE_ATTR_INTERRUPTED_A6) + 1,
		  reg_evt->interrupted_state_phys, 0, 0);

	memcpy(&regs->a6, &reg_evt->interrupted, sizeof(reg_evt->interrupted));

	sse_handle_event(reg_evt, regs);

	/* The SSE delivery path does not uses the "standard" exception path and
	 * thus does not process any pending signal/softirqs. Some drivers might
	 * enqueue pending work that needs to be handled as soon as possible.
	 * For that purpose, set the software interrupt pending bit
	 */
	csr_set(CSR_IP, IE_SIE);

	nmi_exit();
}

#ifdef CONFIG_VMAP_STACK
static unsigned long *sse_stack_alloc(unsigned int cpu, unsigned int size)
{
	return arch_alloc_vmap_stack(size, cpu_to_node(cpu));
}

static void sse_stack_free(unsigned long *stack)
{
	vfree(stack);
}
#else /* CONFIG_VMAP_STACK */

static unsigned long *sse_stack_alloc(unsigned int cpu, unsigned int size)
{
	return kmalloc(size, GFP_KERNEL);
}

static void sse_stack_free(unsigned long *stack)
{
	kfree(stack);
}

#endif /* CONFIG_VMAP_STACK */

static int sse_init_scs(int cpu, struct sse_registered_event *reg_evt)
{
	void *stack;

	if (!scs_is_enabled())
		return 0;

	stack = scs_alloc(cpu_to_node(cpu));
	if (!stack)
		return 1;

	reg_evt->shadow_stack = stack;

	return 0;
}

int sse_init_event(int cpu, struct sse_registered_event *reg_evt)
{
	void *stack;

	stack = sse_stack_alloc(cpu, SSE_STACK_SIZE);
	if (!stack)
		return -ENOMEM;

	reg_evt->stack = stack + SSE_STACK_SIZE;

	if (sse_init_scs(cpu, reg_evt))
		goto free_stack;

	reg_evt->entry.pc = (unsigned long)handle_sse;
	reg_evt->entry.arg = (unsigned long)reg_evt;

	return 0;

free_stack:
	sse_stack_free(reg_evt->stack - SSE_STACK_SIZE);

	return -ENOMEM;
}

void sse_free_event(struct sse_registered_event *reg_evt)
{
	scs_free(reg_evt->shadow_stack);
	sse_stack_free(reg_evt->stack - SSE_STACK_SIZE);
}
