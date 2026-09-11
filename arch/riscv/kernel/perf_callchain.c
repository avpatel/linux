// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2019 Hangzhou C-SKY Microsystems co.,ltd. */

#include <linux/kallsyms.h>
#include <linux/mm.h>
#include <linux/perf_event.h>
#include <linux/sched/task_stack.h>
#include <linux/thread_info.h>
#include <linux/uaccess.h>

#include <asm/csr.h>
#include <asm/sse.h>
#include <asm/stacktrace.h>

static bool fill_callchain(void *entry, unsigned long pc)
{
	return perf_callchain_store(entry, pc) == 0;
}

#ifdef CONFIG_RISCV_SBI_SSE
static bool sse_addr_on_task_stack(unsigned long addr, unsigned long size)
{
	unsigned long end = addr + size;
	unsigned long stack;

	if (end < addr)
		return false;

	stack = (unsigned long)task_stack_page(current);
	if (addr >= stack && end <= stack + THREAD_SIZE)
		return true;

	return false;
}

static bool sse_kernel_regs_safe(struct pt_regs *regs)
{
	unsigned long fp = frame_pointer(regs);
	unsigned long pc = instruction_pointer(regs);
	unsigned long sp = user_stack_pointer(regs);

	if (!__kernel_text_address(pc))
		return false;
	if (!sse_addr_on_task_stack(sp, sizeof(unsigned long)))
		return false;
	if (fp < sizeof(struct stackframe))
		return false;

	return sse_addr_on_task_stack(fp - sizeof(struct stackframe),
				      sizeof(struct stackframe));
}

static bool sse_callchain_is_guest(const struct riscv_sse_interrupted_context *context)
{
	return context && (context->hstatus & HSTATUS_SPV);
}

static bool sse_callchain_kernel(struct perf_callchain_entry_ctx *entry,
				 struct pt_regs *regs)
{
	const struct riscv_sse_interrupted_context *context;
	unsigned long pc;

	context = riscv_sse_get_interrupted_context();
	if (!context || context->regs != regs)
		return false;

	/* A guest stack cannot be walked using the host kernel address space. */
	if (sse_callchain_is_guest(context))
		return true;

	if (user_mode(regs))
		return true;

	if (sse_kernel_regs_safe(regs)) {
		walk_stackframe(NULL, regs, fill_callchain, entry);
		return true;
	}

	/*
	 * Keep the sample useful for sensitive entry paths and IRQ stacks. The
	 * generic walker does not take explicit IRQ stack bounds, and its
	 * THREAD_SIZE alignment assumption fails for non-vmapped IRQ stacks.
	 * Conservatively avoid walking IRQ stacks in every configuration.
	 */
	pc = instruction_pointer(regs);
	if (__kernel_text_address(pc))
		perf_callchain_store(entry, pc);

	return true;
}

unsigned long riscv_perf_out_copy_user(void *dst, const void *src,
				       unsigned long n)
{
	unsigned long addr = (unsigned long)src;
	unsigned long copied = 0;

	/* Keep the generic fast path unchanged outside an SSE handler. */
	if (!riscv_sse_get_interrupted_context()) {
		unsigned long ret;

		pagefault_disable();
		ret = __copy_from_user_inatomic(dst, src, n);
		pagefault_enable();
		return ret;
	}

	if (!access_ok(src, n))
		return n;

	/* Do not sample user memory through an unrelated active page table. */
	if (!current->mm ||
	    (csr_read(CSR_SATP) & SATP_PPN) != virt_to_pfn(current->mm->pgd))
		return n;

	while (copied < n) {
		unsigned long offset = offset_in_page(addr);
		unsigned long chunk = min(n - copied, PAGE_SIZE - offset);
		struct page *page;

		/*
		 * Fast-only GUP cannot fault. This follows perf_virt_to_phys():
		 * local interrupts remain disabled throughout SSE processing, so a
		 * concurrent unmap cannot complete its TLB teardown before this
		 * temporary reference is put.
		 */
		if (!get_user_page_fast_only(addr, 0, &page))
			break;

		memcpy((char *)dst + copied,
		       (char *)page_address(page) + offset, chunk);
		put_page(page);
		addr += chunk;
		copied += chunk;
	}

	return n - copied;
}
#endif

/*
 * This will be called when the target is in user mode
 * This function will only be called when we use
 * "PERF_SAMPLE_CALLCHAIN" in
 * kernel/events/core.c:perf_prepare_sample()
 *
 * How to trigger perf_callchain_[user/kernel] :
 * $ perf record -e cpu-clock --call-graph fp ./program
 * $ perf report --call-graph
 *
 * On RISC-V platform, the program being sampled and the C library
 * need to be compiled with -fno-omit-frame-pointer, otherwise
 * the user stack will not contain function frame.
 */
void perf_callchain_user(struct perf_callchain_entry_ctx *entry,
			 struct pt_regs *regs)
{
#ifdef CONFIG_RISCV_SBI_SSE
	const struct riscv_sse_interrupted_context *context;

	context = riscv_sse_get_interrupted_context();
	/* A guest stack cannot be walked using the host address space. */
	if (sse_callchain_is_guest(context))
		return;
#endif

	if (perf_guest_state()) {
		/* TODO: We don't support guest os callchain now */
		return;
	}

	arch_stack_walk_user(fill_callchain, entry, regs);
}

void perf_callchain_kernel(struct perf_callchain_entry_ctx *entry,
			   struct pt_regs *regs)
{
#ifdef CONFIG_RISCV_SBI_SSE
	if (sse_callchain_kernel(entry, regs))
		return;
#endif

	if (perf_guest_state()) {
		/* TODO: We don't support guest os callchain now */
		return;
	}

	walk_stackframe(NULL, regs, fill_callchain, entry);
}
