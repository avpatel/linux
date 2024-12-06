// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2024 Rivos Inc.
 */
#include <linux/nmi.h>
#include <linux/scs.h>
#include <linux/bitfield.h>
#include <linux/riscv_sse.h>
#include <linux/percpu-defs.h>

#include <asm/asm-prototypes.h>
#include <asm/switch_to.h>
#include <asm/irq_stack.h>
#include <asm/sbi.h>
#include <asm/sse.h>

DEFINE_PER_CPU(struct task_struct *, __sse_entry_task);

void __weak sse_handle_event(struct sse_event_arch_data *arch_evt, struct pt_regs *regs)
{
}

void do_sse(struct sse_event_arch_data *arch_evt, struct pt_regs *regs)
{
	nmi_enter();

	/* Retrieve missing GPRs from SBI */
	sbi_ecall(SBI_EXT_SSE, SBI_SSE_EVENT_ATTR_READ, arch_evt->evt_id,
		  SBI_SSE_ATTR_INTERRUPTED_A6,
		  (SBI_SSE_ATTR_INTERRUPTED_A7 - SBI_SSE_ATTR_INTERRUPTED_A6) + 1,
		  arch_evt->interrupted_state_phys, 0, 0);

	memcpy(&regs->a6, &arch_evt->interrupted, sizeof(arch_evt->interrupted));

	sse_handle_event(arch_evt, regs);

	/*
	 * The SSE delivery path does not uses the "standard" exception path and
	 * thus does not process any pending signal/softirqs. Some drivers might
	 * enqueue pending work that needs to be handled as soon as possible.
	 * For that purpose, set the software interrupt pending bit which will
	 * be serviced once interrupts are reenabled
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

static int sse_init_scs(int cpu, struct sse_event_arch_data *arch_evt)
{
	void *stack;

	if (!scs_is_enabled())
		return 0;

	stack = scs_alloc(cpu_to_node(cpu));
	if (!stack)
		return 1;

	arch_evt->shadow_stack = stack;

	return 0;
}

int arch_sse_init_event(struct sse_event_arch_data *arch_evt, u32 evt_id, int cpu)
{
	void *stack;

	arch_evt->evt_id = evt_id;
	stack = sse_stack_alloc(cpu, SSE_STACK_SIZE);
	if (!stack)
		return -ENOMEM;

	arch_evt->stack = stack + SSE_STACK_SIZE;

	if (sse_init_scs(cpu, arch_evt))
		goto free_stack;

	if (is_kernel_percpu_address((unsigned long)&arch_evt->interrupted)) {
		arch_evt->interrupted_state_phys =
				per_cpu_ptr_to_phys(&arch_evt->interrupted);
	} else {
		arch_evt->interrupted_state_phys =
				virt_to_phys(&arch_evt->interrupted);
	}

	return 0;

free_stack:
	sse_stack_free(arch_evt->stack - SSE_STACK_SIZE);

	return -ENOMEM;
}

void arch_sse_free_event(struct sse_event_arch_data *arch_evt)
{
	scs_free(arch_evt->shadow_stack);
	sse_stack_free(arch_evt->stack - SSE_STACK_SIZE);
}

int arch_sse_register_event(struct sse_event_arch_data *arch_evt)
{
	struct sbiret sret;

	sret = sbi_ecall(SBI_EXT_SSE, SBI_SSE_EVENT_REGISTER, arch_evt->evt_id,
			 (unsigned long) handle_sse, (unsigned long) arch_evt,
			 0, 0, 0);

	return sbi_err_map_linux_errno(sret.error);
}
