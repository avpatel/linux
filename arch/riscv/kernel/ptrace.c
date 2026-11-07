// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright 2010 Tilera Corporation. All Rights Reserved.
 * Copyright 2015 Regents of the University of California
 * Copyright 2017 SiFive
 *
 * Copied from arch/tile/kernel/ptrace.c
 */

#include <asm/vector.h>
#include <asm/ptrace.h>
#include <asm/syscall.h>
#include <asm/thread_info.h>
#include <asm/switch_to.h>
#include <linux/audit.h>
#include <linux/compat.h>
#include <linux/ptrace.h>
#include <linux/elf.h>
#include <linux/regset.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/task_stack.h>
#include <asm/usercfi.h>
#include <linux/hw_breakpoint.h>

enum riscv_regset {
	REGSET_X,
#ifdef CONFIG_FPU
	REGSET_F,
#endif
#ifdef CONFIG_RISCV_ISA_V
	REGSET_V,
#endif
#ifdef CONFIG_RISCV_ISA_SUPM
	REGSET_TAGGED_ADDR_CTRL,
#endif
#ifdef CONFIG_RISCV_USER_CFI
	REGSET_CFI,
#endif
};

static int riscv_gpr_get(struct task_struct *target,
			 const struct user_regset *regset,
			 struct membuf to)
{
	return membuf_write(&to, task_pt_regs(target),
			    sizeof(struct user_regs_struct));
}

static int riscv_gpr_set(struct task_struct *target,
			 const struct user_regset *regset,
			 unsigned int pos, unsigned int count,
			 const void *kbuf, const void __user *ubuf)
{
	struct pt_regs *regs;

	regs = task_pt_regs(target);
	return user_regset_copyin(&pos, &count, &kbuf, &ubuf, regs, 0, -1);
}

#ifdef CONFIG_FPU
static int riscv_fpr_get(struct task_struct *target,
			 const struct user_regset *regset,
			 struct membuf to)
{
	struct __riscv_d_ext_state *fstate = &target->thread.fstate;

	if (target == current)
		fstate_save(current, task_pt_regs(current));

	membuf_write(&to, fstate, offsetof(struct __riscv_d_ext_state, fcsr));
	membuf_store(&to, fstate->fcsr);
	return membuf_zero(&to, 4);	// explicitly pad
}

static int riscv_fpr_set(struct task_struct *target,
			 const struct user_regset *regset,
			 unsigned int pos, unsigned int count,
			 const void *kbuf, const void __user *ubuf)
{
	int ret;
	struct __riscv_d_ext_state *fstate = &target->thread.fstate;

	ret = user_regset_copyin(&pos, &count, &kbuf, &ubuf, fstate, 0,
				 offsetof(struct __riscv_d_ext_state, fcsr));
	if (!ret) {
		ret = user_regset_copyin(&pos, &count, &kbuf, &ubuf, fstate, 0,
					 offsetof(struct __riscv_d_ext_state, fcsr) +
					 sizeof(fstate->fcsr));
	}

	return ret;
}
#endif

#ifdef CONFIG_RISCV_ISA_V
static int riscv_vr_get(struct task_struct *target,
			const struct user_regset *regset,
			struct membuf to)
{
	struct __riscv_v_ext_state *vstate = &target->thread.vstate;
	struct __riscv_v_regset_state ptrace_vstate;

	if (!(has_vector() || has_xtheadvector()))
		return -EINVAL;

	if (!riscv_v_vstate_query(task_pt_regs(target)))
		return -ENODATA;

	/*
	 * Ensure the vector registers have been saved to the memory before
	 * copying them to membuf.
	 */
	if (target == current) {
		get_cpu_vector_context();
		riscv_v_vstate_save(&current->thread.vstate, task_pt_regs(current));
		put_cpu_vector_context();
	}

	ptrace_vstate.vstart = vstate->vstart;
	ptrace_vstate.vl = vstate->vl;
	ptrace_vstate.vtype = vstate->vtype;
	ptrace_vstate.vcsr = vstate->vcsr;
	ptrace_vstate.vlenb = vstate->vlenb;

	/* Copy vector header from vstate. */
	membuf_write(&to, &ptrace_vstate, sizeof(struct __riscv_v_regset_state));

	/* Copy all the vector registers from vstate. */
	return membuf_write(&to, vstate->datap, riscv_v_vsize);
}

static int invalid_ptrace_v_csr(struct __riscv_v_ext_state *vstate,
				struct __riscv_v_regset_state *ptrace)
{
	unsigned long vsew, vlmul, vfrac, vl;
	unsigned long elen, vlen;
	unsigned long sew, lmul;
	unsigned long reserved;

	vlen = vstate->vlenb * 8;
	if (vstate->vlenb != ptrace->vlenb)
		return 1;

	/* do not allow to set vcsr/vxrm/vxsat reserved bits */
	reserved = ~(CSR_VXSAT_MASK | (CSR_VXRM_MASK << CSR_VXRM_SHIFT));
	if (ptrace->vcsr & reserved)
		return 1;

	if (has_vector()) {
		/* do not allow to set vtype reserved bits and vill bit */
		reserved = ~(VTYPE_VSEW | VTYPE_VLMUL | VTYPE_VMA | VTYPE_VTA);
		if (ptrace->vtype & reserved)
			return 1;

		elen = riscv_has_extension_unlikely(RISCV_ISA_EXT_ZVE64X) ? 64 : 32;
		vsew = (ptrace->vtype & VTYPE_VSEW) >> VTYPE_VSEW_SHIFT;
		sew = 8 << vsew;

		if (sew > elen)
			return 1;

		vfrac = (ptrace->vtype & VTYPE_VLMUL_FRAC);
		vlmul = (ptrace->vtype & VTYPE_VLMUL);

		/* RVV 1.0 spec 3.4.2: VLMUL(0x4) reserved */
		if (vlmul == 4)
			return 1;

		/* RVV 1.0 spec 3.4.2: (LMUL < SEW_min / ELEN) reserved */
		if (vlmul == 5 && elen == 32)
			return 1;

		/* for zero vl verify that at least one element is possible */
		vl = ptrace->vl ? ptrace->vl : 1;

		if (vfrac) {
			/* integer 1/LMUL: VL =< VLMAX = VLEN / SEW / LMUL */
			lmul = 2 << (3 - (vlmul - vfrac));
			if (vlen < vl * sew * lmul)
				return 1;
		} else {
			/* integer LMUL: VL =< VLMAX = LMUL * VLEN / SEW */
			lmul = 1 << vlmul;
			if (vl * sew > lmul * vlen)
				return 1;
		}
	}

	if (has_xtheadvector()) {
		/* do not allow to set vtype reserved bits and vill bit */
		reserved = ~(VTYPE_VSEW_THEAD | VTYPE_VLMUL_THEAD | VTYPE_VEDIV_THEAD);
		if (ptrace->vtype & reserved)
			return 1;

		/*
		 * THead ISA Extension spec chapter 16:
		 * divided element extension ('Zvediv') is not part of XTheadVector
		 */
		if (ptrace->vtype & VTYPE_VEDIV_THEAD)
			return 1;

		vsew = (ptrace->vtype & VTYPE_VSEW_THEAD) >> VTYPE_VSEW_THEAD_SHIFT;
		sew = 8 << vsew;

		vlmul = (ptrace->vtype & VTYPE_VLMUL_THEAD);
		lmul = 1 << vlmul;

		/* for zero vl verify that at least one element is possible */
		vl = ptrace->vl ? ptrace->vl : 1;

		if (vl * sew > lmul * vlen)
			return 1;
	}

	return 0;
}

static int riscv_vr_set(struct task_struct *target,
			const struct user_regset *regset,
			unsigned int pos, unsigned int count,
			const void *kbuf, const void __user *ubuf)
{
	int ret;
	struct __riscv_v_ext_state *vstate = &target->thread.vstate;
	struct __riscv_v_regset_state ptrace_vstate;

	if (!(has_vector() || has_xtheadvector()))
		return -EINVAL;

	if (!riscv_v_vstate_query(task_pt_regs(target)))
		return -ENODATA;

	/* Copy rest of the vstate except datap */
	memset(&ptrace_vstate, 0, sizeof(ptrace_vstate));
	ret = user_regset_copyin(&pos, &count, &kbuf, &ubuf, &ptrace_vstate, 0,
				 sizeof(struct __riscv_v_regset_state));
	if (unlikely(ret))
		return ret;

	if (invalid_ptrace_v_csr(vstate, &ptrace_vstate))
		return -EINVAL;

	vstate->vstart = ptrace_vstate.vstart;
	vstate->vl = ptrace_vstate.vl;
	vstate->vtype = ptrace_vstate.vtype;
	vstate->vcsr = ptrace_vstate.vcsr;

	/* Copy all the vector registers. */
	pos = 0;
	ret = user_regset_copyin(&pos, &count, &kbuf, &ubuf, vstate->datap,
				 0, riscv_v_vsize);
	return ret;
}

static int riscv_vr_active(struct task_struct *target, const struct user_regset *regset)
{
	if (!(has_vector() || has_xtheadvector()))
		return -ENODEV;

	if (!riscv_v_vstate_query(task_pt_regs(target)))
		return 0;

	return regset->n;
}
#endif

#ifdef CONFIG_RISCV_ISA_SUPM
static int tagged_addr_ctrl_get(struct task_struct *target,
				const struct user_regset *regset,
				struct membuf to)
{
	long ctrl = get_tagged_addr_ctrl(target);

	if (IS_ERR_VALUE(ctrl))
		return ctrl;

	return membuf_write(&to, &ctrl, sizeof(ctrl));
}

static int tagged_addr_ctrl_set(struct task_struct *target,
				const struct user_regset *regset,
				unsigned int pos, unsigned int count,
				const void *kbuf, const void __user *ubuf)
{
	int ret;
	long ctrl;

	ret = user_regset_copyin(&pos, &count, &kbuf, &ubuf, &ctrl, 0, -1);
	if (ret)
		return ret;

	return set_tagged_addr_ctrl(target, ctrl);
}
#endif

#ifdef CONFIG_RISCV_USER_CFI
static int riscv_cfi_get(struct task_struct *target,
			 const struct user_regset *regset,
			 struct membuf to)
{
	struct user_cfi_state user_cfi;
	struct pt_regs *regs;

	if (!is_user_lpad_enabled() && !is_user_shstk_enabled())
		return -EINVAL;

	memset(&user_cfi, 0, sizeof(user_cfi));
	regs = task_pt_regs(target);

	if (is_indir_lp_enabled(target)) {
		user_cfi.cfi_status.cfi_state |= PTRACE_CFI_BRANCH_LANDING_PAD_EN_STATE;
		user_cfi.cfi_status.cfi_state |= is_indir_lp_locked(target) ?
						 PTRACE_CFI_BRANCH_LANDING_PAD_LOCK_STATE : 0;
		user_cfi.cfi_status.cfi_state |= (regs->status & SR_ELP) ?
						PTRACE_CFI_BRANCH_EXPECTED_LANDING_PAD_STATE : 0;
	}

	if (is_shstk_enabled(target)) {
		user_cfi.cfi_status.cfi_state |= (PTRACE_CFI_SHADOW_STACK_EN_STATE |
						  PTRACE_CFI_SHADOW_STACK_PTR_STATE);
		user_cfi.cfi_status.cfi_state |= is_shstk_locked(target) ?
						 PTRACE_CFI_SHADOW_STACK_LOCK_STATE : 0;
		user_cfi.shstk_ptr = get_active_shstk(target);
	}

	return membuf_write(&to, &user_cfi, sizeof(user_cfi));
}

/*
 * Does it make sense to allow enable / disable of cfi via ptrace?
 * We don't allow enable / disable / locking control via ptrace for now.
 * Setting the shadow stack pointer is allowed. GDB might use it to unwind or
 * some other fixup. Similarly gdb might want to suppress elp and may want
 * to reset elp state.
 */
static int riscv_cfi_set(struct task_struct *target,
			 const struct user_regset *regset,
			 unsigned int pos, unsigned int count,
			 const void *kbuf, const void __user *ubuf)
{
	int ret;
	struct user_cfi_state user_cfi;
	struct pt_regs *regs;

	if (!is_user_lpad_enabled() && !is_user_shstk_enabled())
		return -EINVAL;

	regs = task_pt_regs(target);

	memset(&user_cfi, 0, sizeof(user_cfi));
	ret = user_regset_copyin(&pos, &count, &kbuf, &ubuf, &user_cfi, 0, -1);
	if (ret)
		return ret;

	/*
	 * Not allowing enabling or locking shadow stack or landing pad
	 * There is no disabling of shadow stack or landing pad via ptrace
	 * rsvd field should be set to zero so that if those fields are needed in future
	 */
	if ((user_cfi.cfi_status.cfi_state &
	     (PTRACE_CFI_BRANCH_LANDING_PAD_EN_STATE | PTRACE_CFI_BRANCH_LANDING_PAD_LOCK_STATE |
	      PTRACE_CFI_SHADOW_STACK_EN_STATE | PTRACE_CFI_SHADOW_STACK_LOCK_STATE)) ||
	     (user_cfi.cfi_status.cfi_state & PTRACE_CFI_STATE_INVALID_MASK))
		return -EINVAL;

	/* If lpad is enabled on target and ptrace requests to set / clear elp, do that */
	if (is_indir_lp_enabled(target)) {
		if (user_cfi.cfi_status.cfi_state &
		    PTRACE_CFI_BRANCH_EXPECTED_LANDING_PAD_STATE) /* set elp state */
			regs->status |= SR_ELP;
		else
			regs->status &= ~SR_ELP; /* clear elp state */
	}

	/* If shadow stack enabled on target, set new shadow stack pointer */
	if (is_shstk_enabled(target) &&
	    (user_cfi.cfi_status.cfi_state & PTRACE_CFI_SHADOW_STACK_PTR_STATE))
		set_active_shstk(target, user_cfi.shstk_ptr);

	return 0;
}
#endif

#ifdef CONFIG_HAVE_HW_BREAKPOINT
enum riscv_hbp_type {
	RISCV_HBP_BREAK,
	RISCV_HBP_WATCH,
};

/*
 * Handle hitting a HW-breakpoint.
 */
static void riscv_ptrace_hbptriggered(struct perf_event *bp,
				      struct perf_sample_data *data,
				      struct pt_regs *regs)
{
	struct arch_hw_breakpoint *bkpt = counter_arch_bp(bp);

	force_sig_fault(SIGTRAP, TRAP_HWBKPT, (void __user *)bkpt->address);
}

/*
 * Unregister breakpoints from this task and reset the pointers in
 * the thread_struct.
 */
void flush_ptrace_hw_breakpoint(struct task_struct *tsk)
{
	int i;
	struct thread_struct *t = &tsk->thread;

	for (i = 0; i < RISCV_MAX_BP; i++) {
		if (t->debug.hbp_break[i]) {
			unregister_hw_breakpoint(t->debug.hbp_break[i]);
			t->debug.hbp_break[i] = NULL;
		}
	}

	for (i = 0; i < RISCV_MAX_BP; i++) {
		if (t->debug.hbp_watch[i]) {
			unregister_hw_breakpoint(t->debug.hbp_watch[i]);
			t->debug.hbp_watch[i] = NULL;
		}
	}
}

void ptrace_hw_copy_thread(struct task_struct *tsk)
{
	memset(&tsk->thread.debug, 0, sizeof(struct debug_info));
}

static struct perf_event *ptrace_hbp_get_event(enum riscv_hbp_type hbp_type,
					       struct task_struct *tsk,
					       unsigned long idx)
{
	struct perf_event *bp = ERR_PTR(-EINVAL);

	switch (hbp_type) {
	case RISCV_HBP_BREAK:
		if (idx >= RISCV_MAX_BP)
			goto out;
		idx = array_index_nospec(idx, RISCV_MAX_BP);
		bp = tsk->thread.debug.hbp_break[idx];
		break;
	case RISCV_HBP_WATCH:
		if (idx >= RISCV_MAX_BP)
			goto out;
		idx = array_index_nospec(idx, RISCV_MAX_BP);
		bp = tsk->thread.debug.hbp_watch[idx];
		break;
	}

out:
	return bp;
}

static int ptrace_hbp_set_event(enum riscv_hbp_type hbp_type,
				struct task_struct *tsk,
				unsigned long idx,
				struct perf_event *bp)
{
	int err = -EINVAL;

	switch (hbp_type) {
	case RISCV_HBP_BREAK:
		if (idx >= RISCV_MAX_BP)
			goto out;
		idx = array_index_nospec(idx, RISCV_MAX_BP);
		tsk->thread.debug.hbp_break[idx] = bp;
		err = 0;
		break;
	case RISCV_HBP_WATCH:
		if (idx >= RISCV_MAX_BP)
			goto out;
		idx = array_index_nospec(idx, RISCV_MAX_BP);
		tsk->thread.debug.hbp_watch[idx] = bp;
		err = 0;
		break;
	}

out:
	return err;
}

static struct perf_event *ptrace_hbp_create(enum riscv_hbp_type hbp_type,
					    struct task_struct *tsk,
					    unsigned long idx)
{
	struct perf_event *bp;
	struct perf_event_attr attr;
	int err, type;

	switch (hbp_type) {
	case RISCV_HBP_BREAK:
		type = HW_BREAKPOINT_X;
		break;
	case RISCV_HBP_WATCH:
		type = HW_BREAKPOINT_RW;
		break;
	default:
		return ERR_PTR(-EINVAL);
	}

	ptrace_breakpoint_init(&attr);

	/*
	 * Initialise fields to sane defaults
	 * (i.e. values that will pass validation).
	 */
	attr.bp_addr	= 0;
	attr.bp_len	= HW_BREAKPOINT_LEN_4;
	attr.bp_type	= type;
	attr.disabled	= 1;

	bp = register_user_hw_breakpoint(&attr, riscv_ptrace_hbptriggered, NULL, tsk);
	if (IS_ERR(bp))
		return bp;

	err = ptrace_hbp_set_event(hbp_type, tsk, idx, bp);
	if (err) {
		/* Drop the event if it cannot be published in the task slot. */
		unregister_hw_breakpoint(bp);
		return ERR_PTR(err);
	}

	return bp;
}

#endif	/* CONFIG_HAVE_HW_BREAKPOINT */

static struct user_regset riscv_user_regset[] __ro_after_init = {
	[REGSET_X] = {
		USER_REGSET_NOTE_TYPE(PRSTATUS),
		.n = ELF_NGREG,
		.size = sizeof(elf_greg_t),
		.align = sizeof(elf_greg_t),
		.regset_get = riscv_gpr_get,
		.set = riscv_gpr_set,
	},
#ifdef CONFIG_FPU
	[REGSET_F] = {
		USER_REGSET_NOTE_TYPE(PRFPREG),
		.n = ELF_NFPREG,
		.size = sizeof(elf_fpreg_t),
		.align = sizeof(elf_fpreg_t),
		.regset_get = riscv_fpr_get,
		.set = riscv_fpr_set,
	},
#endif
#ifdef CONFIG_RISCV_ISA_V
	[REGSET_V] = {
		USER_REGSET_NOTE_TYPE(RISCV_VECTOR),
		.align = 16,
		.size = sizeof(__u32),
		.regset_get = riscv_vr_get,
		.set = riscv_vr_set,
		.active = riscv_vr_active,
	},
#endif
#ifdef CONFIG_RISCV_ISA_SUPM
	[REGSET_TAGGED_ADDR_CTRL] = {
		USER_REGSET_NOTE_TYPE(RISCV_TAGGED_ADDR_CTRL),
		.n = 1,
		.size = sizeof(long),
		.align = sizeof(long),
		.regset_get = tagged_addr_ctrl_get,
		.set = tagged_addr_ctrl_set,
	},
#endif
#ifdef CONFIG_RISCV_USER_CFI
	[REGSET_CFI] = {
		USER_REGSET_NOTE_TYPE(RISCV_USER_CFI),
		.align = sizeof(__u64),
		.n = sizeof(struct user_cfi_state) / sizeof(__u64),
		.size = sizeof(__u64),
		.regset_get = riscv_cfi_get,
		.set = riscv_cfi_set,
	},
#endif
};

static const struct user_regset_view riscv_user_native_view = {
	.name = "riscv",
	.e_machine = EM_RISCV,
	.regsets = riscv_user_regset,
	.n = ARRAY_SIZE(riscv_user_regset),
};

#ifdef CONFIG_RISCV_ISA_V
void __init update_regset_vector_info(unsigned long size)
{
	riscv_user_regset[REGSET_V].n = (size + sizeof(struct __riscv_v_regset_state)) /
					sizeof(__u32);
}
#endif

struct pt_regs_offset {
	const char *name;
	int offset;
};

#define REG_OFFSET_NAME(r) {.name = #r, .offset = offsetof(struct pt_regs, r)}
#define REG_OFFSET_END {.name = NULL, .offset = 0}

static const struct pt_regs_offset regoffset_table[] = {
	REG_OFFSET_NAME(epc),
	REG_OFFSET_NAME(ra),
	REG_OFFSET_NAME(sp),
	REG_OFFSET_NAME(gp),
	REG_OFFSET_NAME(tp),
	REG_OFFSET_NAME(t0),
	REG_OFFSET_NAME(t1),
	REG_OFFSET_NAME(t2),
	REG_OFFSET_NAME(s0),
	REG_OFFSET_NAME(s1),
	REG_OFFSET_NAME(a0),
	REG_OFFSET_NAME(a1),
	REG_OFFSET_NAME(a2),
	REG_OFFSET_NAME(a3),
	REG_OFFSET_NAME(a4),
	REG_OFFSET_NAME(a5),
	REG_OFFSET_NAME(a6),
	REG_OFFSET_NAME(a7),
	REG_OFFSET_NAME(s2),
	REG_OFFSET_NAME(s3),
	REG_OFFSET_NAME(s4),
	REG_OFFSET_NAME(s5),
	REG_OFFSET_NAME(s6),
	REG_OFFSET_NAME(s7),
	REG_OFFSET_NAME(s8),
	REG_OFFSET_NAME(s9),
	REG_OFFSET_NAME(s10),
	REG_OFFSET_NAME(s11),
	REG_OFFSET_NAME(t3),
	REG_OFFSET_NAME(t4),
	REG_OFFSET_NAME(t5),
	REG_OFFSET_NAME(t6),
	REG_OFFSET_NAME(status),
	REG_OFFSET_NAME(badaddr),
	REG_OFFSET_NAME(cause),
	REG_OFFSET_NAME(orig_a0),
	REG_OFFSET_END,
};

/**
 * regs_query_register_offset() - query register offset from its name
 * @name:	the name of a register
 *
 * regs_query_register_offset() returns the offset of a register in struct
 * pt_regs from its name. If the name is invalid, this returns -EINVAL;
 */
int regs_query_register_offset(const char *name)
{
	const struct pt_regs_offset *roff;

	for (roff = regoffset_table; roff->name != NULL; roff++)
		if (!strcmp(roff->name, name))
			return roff->offset;
	return -EINVAL;
}

/**
 * regs_within_kernel_stack() - check the address in the stack
 * @regs:      pt_regs which contains kernel stack pointer.
 * @addr:      address which is checked.
 *
 * regs_within_kernel_stack() checks @addr is within the kernel stack page(s).
 * If @addr is within the kernel stack, it returns true. If not, returns false.
 */
static bool regs_within_kernel_stack(struct pt_regs *regs, unsigned long addr)
{
	return (addr & ~(THREAD_SIZE - 1))  ==
		(kernel_stack_pointer(regs) & ~(THREAD_SIZE - 1));
}

/**
 * regs_get_kernel_stack_nth() - get Nth entry of the stack
 * @regs:	pt_regs which contains kernel stack pointer.
 * @n:		stack entry number.
 *
 * regs_get_kernel_stack_nth() returns @n th entry of the kernel stack which
 * is specified by @regs. If the @n th entry is NOT in the kernel stack,
 * this returns 0.
 */
unsigned long regs_get_kernel_stack_nth(struct pt_regs *regs, unsigned int n)
{
	unsigned long *addr = (unsigned long *)kernel_stack_pointer(regs);

	addr += n;
	if (regs_within_kernel_stack(regs, (unsigned long)addr))
		return *addr;
	else
		return 0;
}

void ptrace_disable(struct task_struct *child)
{
}

#ifdef CONFIG_HAVE_HW_BREAKPOINT
static int riscv_ptrace_bp_type_to_hbp(u64 type, enum riscv_hbp_type *hbp_type)
{
	switch (type) {
	case HW_BREAKPOINT_X:
		*hbp_type = RISCV_HBP_BREAK;
		return 0;
	case HW_BREAKPOINT_R:
	case HW_BREAKPOINT_W:
	case HW_BREAKPOINT_RW:
		*hbp_type = RISCV_HBP_WATCH;
		return 0;
	default:
		return -EINVAL;
	}
}

static int riscv_ptrace_bp_clear_event(struct task_struct *child,
				       enum riscv_hbp_type hbp_type,
				       unsigned long idx)
{
	struct perf_event *bp = ptrace_hbp_get_event(hbp_type, child, idx);

	if (IS_ERR(bp))
		return PTR_ERR(bp);
	if (!bp)
		return 0;

	unregister_hw_breakpoint(bp);
	return ptrace_hbp_set_event(hbp_type, child, idx, NULL);
}

static int riscv_ptrace_bp_get(struct task_struct *child, unsigned long idx,
			       struct __riscv_hwdebug_state *state)
{
	struct perf_event *bp;

	if (idx >= RISCV_MAX_BP)
		return -EINVAL;

	idx = array_index_nospec(idx, RISCV_MAX_BP);

	/*
	 * PTRACE_GETHBPREGS is a compact view keyed only by index.  The real
	 * storage is split by type, so search both arrays.
	 */
	bp = ptrace_hbp_get_event(RISCV_HBP_BREAK, child, idx);
	if (IS_ERR(bp))
		return PTR_ERR(bp);
	if (!bp) {
		bp = ptrace_hbp_get_event(RISCV_HBP_WATCH, child, idx);
		if (IS_ERR(bp))
			return PTR_ERR(bp);
	}
	if (!bp)
		return -ENOENT;

	state->addr = bp->attr.bp_addr;
	state->len  = bp->attr.bp_len;
	state->type = bp->attr.bp_type;
	state->ctrl = bp->attr.disabled == 1;

	return 0;
}

static int riscv_ptrace_bp_set(struct task_struct *child, unsigned long idx,
			       struct __riscv_hwdebug_state *state)
{
	struct perf_event *bp;
	struct perf_event_attr attr;
	enum riscv_hbp_type hbp_type, other_hbp_type;
	int ret;
	bool created = false;

	if (idx >= RISCV_MAX_BP)
		return -EINVAL;

	idx = array_index_nospec(idx, RISCV_MAX_BP);

	ret = riscv_ptrace_bp_type_to_hbp(state->type, &hbp_type);
	if (ret)
		return ret;

	/* The legacy request exposes ctrl as a disabled/enabled boolean. */
	if (state->ctrl > 1)
		return -EINVAL;

	other_hbp_type = hbp_type == RISCV_HBP_BREAK ?
			 RISCV_HBP_WATCH : RISCV_HBP_BREAK;

	bp = ptrace_hbp_get_event(hbp_type, child, idx);
	if (IS_ERR(bp))
		return PTR_ERR(bp);
	if (!bp) {
		bp = ptrace_hbp_create(hbp_type, child, idx);
		if (IS_ERR(bp))
			return PTR_ERR(bp);
		created = true;
	}

	attr = bp->attr;

	attr.bp_addr = state->addr;
	attr.bp_len  = state->len;
	attr.bp_type = state->type;
	/* Enable or disable as requested by ctrl (0 = enabled, 1 = disabled) */
	attr.disabled = state->ctrl == 1;
	ret = modify_user_hw_breakpoint(bp, &attr);
	if (ret) {
		/* Drop only events allocated by this failed request. */
		if (created)
			riscv_ptrace_bp_clear_event(child, hbp_type, idx);
		return ret;
	}

	/*
	 * If the same index changed from breakpoint to watchpoint, or back,
	 * clear the old opposite-type slot after the new event is valid so a
	 * failed update does not destroy the previous state.
	 */
	return riscv_ptrace_bp_clear_event(child, other_hbp_type, idx);
}

static long riscv_ptrace_gethbpregs(struct task_struct *child, unsigned long idx,
				    unsigned long __user *datap)
{
	struct __riscv_hwdebug_state state;
	long ret;

	ret = riscv_ptrace_bp_get(child, idx, &state);
	if (ret)
		return ret;
	if (copy_to_user(datap, &state, sizeof(state)))
		return -EFAULT;

	return 0;
}

static long riscv_ptrace_sethbpregs(struct task_struct *child, unsigned long idx,
				    unsigned long __user *datap)
{
	struct __riscv_hwdebug_state state;

	if (copy_from_user(&state, datap, sizeof(state)))
		return -EFAULT;

	return riscv_ptrace_bp_set(child, idx, &state);
}
#endif /* CONFIG_HAVE_HW_BREAKPOINT */

long arch_ptrace(struct task_struct *child, long request,
		 unsigned long addr, unsigned long data)
{
	long ret = -EIO;
#ifdef CONFIG_HAVE_HW_BREAKPOINT
	unsigned long __user *datap = (unsigned long __user *)data;
#endif

	switch (request) {
#ifdef CONFIG_HAVE_HW_BREAKPOINT
	case PTRACE_GETHBPREGS:
		ret = riscv_ptrace_gethbpregs(child, addr, datap);
		break;
	case PTRACE_SETHBPREGS:
		ret = riscv_ptrace_sethbpregs(child, addr, datap);
		break;
#endif
	default:
		ret = ptrace_request(child, request, addr, data);
		break;
	}

	return ret;
}

#ifdef CONFIG_COMPAT
static int compat_riscv_gpr_get(struct task_struct *target,
				const struct user_regset *regset,
				struct membuf to)
{
	struct compat_user_regs_struct cregs;

	regs_to_cregs(&cregs, task_pt_regs(target));

	return membuf_write(&to, &cregs,
			    sizeof(struct compat_user_regs_struct));
}

static int compat_riscv_gpr_set(struct task_struct *target,
				const struct user_regset *regset,
				unsigned int pos, unsigned int count,
				const void *kbuf, const void __user *ubuf)
{
	int ret;
	struct compat_user_regs_struct cregs;

	ret = user_regset_copyin(&pos, &count, &kbuf, &ubuf, &cregs, 0, -1);
	if (!ret)
		cregs_to_regs(&cregs, task_pt_regs(target));

	return ret;
}

static const struct user_regset compat_riscv_user_regset[] = {
	[REGSET_X] = {
		USER_REGSET_NOTE_TYPE(PRSTATUS),
		.n = ELF_NGREG,
		.size = sizeof(compat_elf_greg_t),
		.align = sizeof(compat_elf_greg_t),
		.regset_get = compat_riscv_gpr_get,
		.set = compat_riscv_gpr_set,
	},
#ifdef CONFIG_FPU
	[REGSET_F] = {
		USER_REGSET_NOTE_TYPE(PRFPREG),
		.n = ELF_NFPREG,
		.size = sizeof(elf_fpreg_t),
		.align = sizeof(elf_fpreg_t),
		.regset_get = riscv_fpr_get,
		.set = riscv_fpr_set,
	},
#endif
};

static const struct user_regset_view compat_riscv_user_native_view = {
	.name = "riscv",
	.e_machine = EM_RISCV,
	.regsets = compat_riscv_user_regset,
	.n = ARRAY_SIZE(compat_riscv_user_regset),
};

long compat_arch_ptrace(struct task_struct *child, compat_long_t request,
			compat_ulong_t caddr, compat_ulong_t cdata)
{
	long ret = -EIO;
#ifdef CONFIG_HAVE_HW_BREAKPOINT
	/* cdata is a compat user pointer for the legacy HBP requests. */
	unsigned long __user *datap = compat_ptr(cdata);
#endif

	switch (request) {
#ifdef CONFIG_HAVE_HW_BREAKPOINT
	case PTRACE_GETHBPREGS:
		ret = riscv_ptrace_gethbpregs(child, caddr, datap);
		break;
	case PTRACE_SETHBPREGS:
		ret = riscv_ptrace_sethbpregs(child, caddr, datap);
		break;
#endif
	default:
		ret = compat_ptrace_request(child, request, caddr, cdata);
		break;
	}

	return ret;
}
#else
static const struct user_regset_view compat_riscv_user_native_view = {};
#endif /* CONFIG_COMPAT */

const struct user_regset_view *task_user_regset_view(struct task_struct *task)
{
	if (is_compat_thread(&task->thread_info))
		return &compat_riscv_user_native_view;
	else
		return &riscv_user_native_view;
}
