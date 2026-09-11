// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2025 Rivos Inc.
 */
#include <linux/nmi.h>
#include <linux/sched.h>
#include <linux/scs.h>
#include <linux/bitfield.h>
#include <linux/percpu-defs.h>
#include <linux/string.h>

#include <asm/asm-prototypes.h>
#include <asm/switch_to.h>
#include <asm/irq_stack.h>
#include <asm/sbi.h>
#include <asm/sse.h>
#include <asm/tlbflush.h>

DEFINE_PER_CPU(struct task_struct *, __sbi_sse_entry_task);
static DEFINE_PER_CPU(struct riscv_sse_interrupted_context *,
			      riscv_sse_interrupted_context);

const struct riscv_sse_interrupted_context *
riscv_sse_get_interrupted_context(void)
{
	return this_cpu_read(riscv_sse_interrupted_context);
}

void __weak sse_handle_event(struct sse_event_arch_data *arch_evt, struct pt_regs *regs)
{
}

void noinstr do_sse(struct sse_event_arch_data *arch_evt,
		    struct pt_regs *regs, unsigned long hstatus)
{
	struct riscv_sse_interrupted_context context = { regs, hstatus };
	struct riscv_sse_interrupted_context *previous;
	struct sbiret sret;

	nmi_enter();
	instrumentation_begin();

	/* Retrieve missing GPRs from SBI */
	sret = sbi_ecall(SBI_EXT_SSE, SBI_SSE_EVENT_ATTR_READ, arch_evt->evt_id,
			 SBI_SSE_ATTR_INTERRUPTED_A6,
			 (SBI_SSE_ATTR_INTERRUPTED_A7 -
			  SBI_SSE_ATTR_INTERRUPTED_A6) + 1,
			 (unsigned long)arch_evt->interrupted_phys, 0, 0);
	if (sret.error) {
		pr_warn("Failed to read interrupted registers for event %x: %ld\n",
			arch_evt->evt_id, sret.error);
		/* Let the client quiesce its source without using incomplete regs. */
		sse_handle_event(arch_evt, NULL);
		goto out;
	}

	memcpy(&regs->a6, arch_evt->interrupted,
	       sizeof(*arch_evt->interrupted));

	/* Make the interrupted frame visible while clients handle this event. */
	previous = this_cpu_read(riscv_sse_interrupted_context);
	this_cpu_write(riscv_sse_interrupted_context, &context);
	sse_handle_event(arch_evt, regs);
	this_cpu_write(riscv_sse_interrupted_context, previous);

	if (memcmp(&regs->a6, arch_evt->interrupted,
		   sizeof(*arch_evt->interrupted))) {
		memcpy(arch_evt->interrupted, &regs->a6,
		       sizeof(*arch_evt->interrupted));
		sret = sbi_ecall(SBI_EXT_SSE, SBI_SSE_EVENT_ATTR_WRITE,
				 arch_evt->evt_id, SBI_SSE_ATTR_INTERRUPTED_A6,
				 (SBI_SSE_ATTR_INTERRUPTED_A7 -
				  SBI_SSE_ATTR_INTERRUPTED_A6) + 1,
				 (unsigned long)arch_evt->interrupted_phys, 0, 0);
		/*
		 * If writeback fails, COMPLETE resumes with firmware's original
		 * a6/a7 rather than treating the shared buffer as committed.
		 */
		if (sret.error)
			pr_warn("Failed to write interrupted registers for event %x: %ld\n",
				arch_evt->evt_id, sret.error);
	}

out:
	instrumentation_end();
	nmi_exit();
}

static void *alloc_to_stack_pointer(void *alloc)
{
	return alloc ? alloc + SSE_STACK_SIZE : NULL;
}

static void *stack_pointer_to_alloc(void *stack)
{
	return stack ? stack - SSE_STACK_SIZE : NULL;
}

static void arch_sse_flush_tlb_range(struct sse_event_arch_data *arch_evt,
				     unsigned long start, unsigned long size)
{
	unsigned long end = start + size;

	if (sse_event_is_global(arch_evt->evt_id))
		flush_tlb_kernel_range(start, end);
	else
		local_flush_tlb_kernel_range(start, end);
}

static void arch_sse_shadow_stack_cpu_sync(struct sse_event_arch_data *arch_evt)
{
#ifdef CONFIG_SHADOW_CALL_STACK
	if (arch_evt->shadow_stack)
		arch_sse_flush_tlb_range(arch_evt,
					 (unsigned long)arch_evt->shadow_stack,
					 SCS_SIZE);
#endif
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
	unsigned long stack = (unsigned long)stack_pointer_to_alloc(p_stack);

	/*
	 * Flush the tlb to avoid taking any exception when accessing the
	 * vmapped stack inside the SSE handler
	 */
	arch_sse_flush_tlb_range(arch_evt, stack, SSE_STACK_SIZE);

	arch_sse_shadow_stack_cpu_sync(arch_evt);
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

static void arch_sse_stack_cpu_sync(struct sse_event_arch_data *arch_evt)
{
	arch_sse_shadow_stack_cpu_sync(arch_evt);
}
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

void arch_sse_init_cpu(void)
{
	__this_cpu_write(__sbi_sse_entry_task, current);
}

int arch_sse_init_event(struct sse_event_arch_data *arch_evt, u32 evt_id,
			int cpu)
{
	void *stack;

	arch_evt->interrupted = kmalloc_obj(*arch_evt->interrupted, GFP_KERNEL);
	if (!arch_evt->interrupted)
		return -ENOMEM;

	arch_evt->evt_id = evt_id;
	stack = sse_stack_alloc(cpu);
	if (!stack)
		goto err_free_interrupted;

	arch_evt->stack = stack;

	if (sse_init_scs(cpu, arch_evt)) {
		sse_stack_free(arch_evt->stack);
		goto err_free_interrupted;
	}

	/* kmalloc keeps the two adjacent SBI attribute words contiguous. */
	arch_evt->interrupted_phys = virt_to_phys(arch_evt->interrupted);

	arch_sse_event_update_cpu(arch_evt, cpu);

	return 0;

err_free_interrupted:
	kfree(arch_evt->interrupted);
	arch_evt->interrupted = NULL;
	return -ENOMEM;
}

void arch_sse_free_event(struct sse_event_arch_data *arch_evt)
{
	scs_free(arch_evt->shadow_stack);
	sse_stack_free(arch_evt->stack);
	kfree(arch_evt->interrupted);
}

int arch_sse_register_event(struct sse_event_arch_data *arch_evt)
{
	struct sbiret sret;

	arch_sse_stack_cpu_sync(arch_evt);

	sret = sbi_ecall(SBI_EXT_SSE, SBI_SSE_EVENT_REGISTER, arch_evt->evt_id,
			 (unsigned long)handle_sse, (unsigned long)arch_evt, 0,
			 0, 0);
	if (sret.error == SBI_ERR_NOT_SUPPORTED)
		return -EOPNOTSUPP;

	return sbi_err_map_linux_errno(sret.error);
}
