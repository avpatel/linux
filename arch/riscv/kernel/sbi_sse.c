// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2024 Rivos Inc.
 */
#include <linux/nmi.h>
#include <linux/scs.h>
#include <linux/bitfield.h>
#include <linux/percpu-defs.h>

#include <asm/asm-prototypes.h>
#include <asm/switch_to.h>
#include <asm/irq_stack.h>
#include <asm/sbi.h>
#include <asm/sse.h>

DEFINE_PER_CPU(struct task_struct *, __sbi_sse_entry_task);

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
		  arch_evt->interrupted_phys, 0, 0);

	memcpy(&regs->a6, &arch_evt->interrupted, sizeof(arch_evt->interrupted));

	sse_handle_event(arch_evt, regs);

	/*
	 * The SSE delivery path does not uses the "standard" exception path
	 * (see sse_entry.S) and does not process any pending signal/softirqs
	 * due to being similar to a NMI.
	 * Some drivers (PMU, RAS) enqueue pending work that needs to be handled
	 * as soon as possible by bottom halves. For that purpose, set the SIP
	 * software interrupt pending bit which will force a software interrupt
	 * to be serviced once interrupts are reenabled in the interrupted
	 * context if they were masked or directly if unmasked.
	 */
	csr_set(CSR_IP, IE_SIE);

	nmi_exit();
}

static void *alloc_to_stack_pointer(void *alloc)
{
	return alloc ? alloc + SSE_STACK_SIZE : NULL;
}

static void *stack_pointer_to_alloc(void *stack)
{
	return stack - SSE_STACK_SIZE;
}

#ifdef CONFIG_VMAP_STACK
static void *sse_stack_alloc(unsigned int cpu)
{
	void *stack = arch_alloc_vmap_stack(SSE_STACK_SIZE, cpu_to_node(cpu));

	return alloc_to_stack_pointer(stack);
}

static void sse_stack_free(void *stack)
{
	vfree(stack_pointer_to_alloc(stack));
}

static void arch_sse_stack_cpu_sync(struct sse_event_arch_data *arch_evt)
{
	void *p_stack = arch_evt->stack;
	unsigned long stack = (unsigned long) stack_pointer_to_alloc(p_stack);
	unsigned long stack_end = stack + SSE_STACK_SIZE;

	/*
	 * Flush the tlb to avoid taking any exception when accessing the
	 * vmapped stack inside the SSE handler
	 */
	if (sse_event_is_global(arch_evt->evt_id))
		flush_tlb_kernel_range(stack, stack_end);
	else
		local_flush_tlb_kernel_range(stack, (unsigned long) stack_end);
}
#else /* CONFIG_VMAP_STACK */
static void *sse_stack_alloc(unsigned int cpu)
{
	void *stack = kmalloc(SSE_STACK_SIZE, GFP_KERNEL);

	return alloc_to_stack_pointer(stack);
}

static void sse_stack_free(void *stack)
{
	kfree(stack_pointer_to_alloc(stack));
}

static void arch_sse_stack_cpu_sync(struct sse_event_arch_data *arch_evt) {}
#endif /* CONFIG_VMAP_STACK */

static int sse_init_scs(int cpu, struct sse_event_arch_data *arch_evt)
{
	void *stack;

	if (!scs_is_enabled())
		return 0;

	stack = scs_alloc(cpu_to_node(cpu));
	if (!stack)
		return -ENOMEM;

	arch_evt->shadow_stack = stack;

	return 0;
}

void arch_sse_event_update_cpu(struct sse_event_arch_data *arch_evt, int cpu)
{
	arch_evt->cpu_id = cpu;
	arch_evt->hart_id = cpuid_to_hartid_map(cpu);
}

int arch_sse_init_event(struct sse_event_arch_data *arch_evt, u32 evt_id,
			int cpu)
{
	void *stack;

	arch_evt->evt_id = evt_id;
	stack = sse_stack_alloc(cpu);
	if (!stack)
		return -ENOMEM;

	arch_evt->stack = stack;

	if (sse_init_scs(cpu, arch_evt)) {
		sse_stack_free(arch_evt->stack);
		return -ENOMEM;
	}

	if (sse_event_is_global(evt_id)) {
		arch_evt->interrupted_phys =
					virt_to_phys(&arch_evt->interrupted);
	} else {
		arch_evt->interrupted_phys =
				per_cpu_ptr_to_phys(&arch_evt->interrupted);
	}

	arch_sse_event_update_cpu(arch_evt, cpu);

	return 0;
}

void arch_sse_free_event(struct sse_event_arch_data *arch_evt)
{
	scs_free(arch_evt->shadow_stack);
	sse_stack_free(arch_evt->stack);
}

int arch_sse_register_event(struct sse_event_arch_data *arch_evt)
{
	struct sbiret sret;

	arch_sse_stack_cpu_sync(arch_evt);

	sret = sbi_ecall(SBI_EXT_SSE, SBI_SSE_EVENT_REGISTER, arch_evt->evt_id,
			 (unsigned long)handle_sse, (unsigned long)arch_evt, 0,
			 0, 0);

	return sbi_err_map_linux_errno(sret.error);
}
