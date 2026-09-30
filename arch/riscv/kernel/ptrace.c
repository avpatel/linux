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
#ifdef CONFIG_HAVE_HW_BREAKPOINT
	REGSET_RISCV_HW_BREAK,
	REGSET_RISCV_HW_WATCH,
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

	regs = task_pt_regs(target);

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

static struct perf_event *ptrace_hbp_get_event(unsigned int note_type,
					       struct task_struct *tsk,
					       unsigned long idx)
{
	struct perf_event *bp = ERR_PTR(-EINVAL);

	switch (note_type) {
	case NT_RISCV_HW_BREAK:
		if (idx >= RISCV_MAX_BP)
			goto out;
		idx = array_index_nospec(idx, RISCV_MAX_BP);
		bp = tsk->thread.debug.hbp_break[idx];
		break;
	case NT_RISCV_HW_WATCH:
		if (idx >= RISCV_MAX_BP)
			goto out;
		idx = array_index_nospec(idx, RISCV_MAX_BP);
		bp = tsk->thread.debug.hbp_watch[idx];
		break;
	}

out:
	return bp;
}

static int ptrace_hbp_set_event(unsigned int note_type,
				struct task_struct *tsk,
				unsigned long idx,
				struct perf_event *bp)
{
	int err = -EINVAL;

	switch (note_type) {
	case NT_RISCV_HW_BREAK:
		if (idx >= RISCV_MAX_BP)
			goto out;
		idx = array_index_nospec(idx, RISCV_MAX_BP);
		tsk->thread.debug.hbp_break[idx] = bp;
		err = 0;
		break;
	case NT_RISCV_HW_WATCH:
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

static struct perf_event *ptrace_hbp_create(unsigned int note_type,
					    struct task_struct *tsk,
					    unsigned long idx)
{
	struct perf_event *bp;
	struct perf_event_attr attr;
	int err, type;

	switch (note_type) {
	case NT_RISCV_HW_BREAK:
		type = HW_BREAKPOINT_X;
		break;
	case NT_RISCV_HW_WATCH:
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

	err = ptrace_hbp_set_event(note_type, tsk, idx, bp);
	if (err)
		return ERR_PTR(err);

	return bp;
}

static int ptrace_hbp_fill_attr_ctrl(unsigned int note_type,
				     struct arch_hw_breakpoint *bpctrl,
				     struct perf_event_attr *attr)
{
	int len, type;

	attr->disabled = 0;
	type = bpctrl->type;
	len = bpctrl->len;

	switch (note_type) {
	case NT_RISCV_HW_BREAK:
		if ((type & HW_BREAKPOINT_X) != type)
			return -EINVAL;
		break;
	case NT_RISCV_HW_WATCH:
		if ((type & HW_BREAKPOINT_RW) != type)
			return -EINVAL;
		break;
	default:
		return -EINVAL;
	}

	attr->bp_len	= len;
	attr->bp_type	= type;
	attr->bp_addr	= bpctrl->address;

	return 0;
}

static int ptrace_hbp_get_resource_info(unsigned int note_type, u32 *info)
{
	u8 num;

	switch (note_type) {
	case NT_RISCV_HW_BREAK:
		num = hw_breakpoint_slots(TYPE_INST);
		break;
	case NT_RISCV_HW_WATCH:
		num = hw_breakpoint_slots(TYPE_DATA);
		break;
	default:
		return -EINVAL;
	}

	*info = num;

	return 0;
}

static u32 encode_ctrl_reg(struct perf_event *bp)
{
	struct arch_hw_breakpoint *bpctrl = counter_arch_bp(bp);
	u32 ctrl = 0;

	/* Expose the generic UAPI bp_type values in ptrace control bits. */
	ctrl |= HWDEBUG_MK_TYPE(bp->attr.bp_type);
	ctrl |= HWDEBUG_MK_MATCH(bpctrl->match);
	ctrl |= HWDEBUG_MK_SELECT(bpctrl->select);
	ctrl |= HWDEBUG_MK_WHEN(bpctrl->time);
	ctrl |= HWDEBUG_MK_SIZE(bp->attr.bp_len);
	ctrl |= HWDEBUG_MK_CHAIN(bpctrl->chain);

	return ctrl;
}

static int ptrace_hbp_get_ctrl(unsigned int note_type,
			       struct task_struct *tsk,
			       unsigned long idx,
			       u32 *ctrl)
{
	struct perf_event *bp = ptrace_hbp_get_event(note_type, tsk, idx);

	if (IS_ERR(bp))
		return PTR_ERR(bp);

	*ctrl = bp ? encode_ctrl_reg(bp) : 0;
	return 0;
}

static int ptrace_hbp_get_addr(unsigned int note_type,
			       struct task_struct *tsk,
			       unsigned long idx,
			       u64 *addr)
{
	struct perf_event *bp = ptrace_hbp_get_event(note_type, tsk, idx);

	if (IS_ERR(bp))
		return PTR_ERR(bp);

	*addr = bp ? counter_arch_bp(bp)->address : 0;
	return 0;
}

static struct perf_event *ptrace_hbp_get_initialised_bp(unsigned int note_type,
							struct task_struct *tsk,
							unsigned long idx)
{
	struct perf_event *bp = ptrace_hbp_get_event(note_type, tsk, idx);

	if (!bp)
		bp = ptrace_hbp_create(note_type, tsk, idx);

	return bp;
}

static void decode_ctrl_reg(u32 uctrl, struct arch_hw_breakpoint *bpctrl)
{
	bpctrl->type = HWDEBUG_TYPE(uctrl);
	bpctrl->match = HWDEBUG_MATCH(uctrl);
	bpctrl->select = HWDEBUG_SELECT(uctrl);
	bpctrl->time = HWDEBUG_WHEN(uctrl);
	bpctrl->len = HWDEBUG_SIZE(uctrl);
	bpctrl->chain = HWDEBUG_CHAIN(uctrl);
}

static int ptrace_hbp_set_ctrl(unsigned int note_type,
			       struct task_struct *tsk,
			       unsigned long idx,
			       u32 uctrl)
{
	int err;
	struct perf_event *bp;
	struct perf_event_attr attr;
	struct arch_hw_breakpoint bpctrl;

	bp = ptrace_hbp_get_initialised_bp(note_type, tsk, idx);
	if (IS_ERR(bp)) {
		err = PTR_ERR(bp);
		return err;
	}

	attr = bp->attr;
	decode_ctrl_reg(uctrl, &bpctrl);
	bpctrl.address = attr.bp_addr;
	err = ptrace_hbp_fill_attr_ctrl(note_type, &bpctrl, &attr);
	if (err)
		return err;

	return modify_user_hw_breakpoint(bp, &attr);
}

static int ptrace_hbp_set_addr(unsigned int note_type,
			       struct task_struct *tsk,
			       unsigned long idx,
			       u64 addr)
{
	int err;
	struct perf_event *bp;
	struct perf_event_attr attr;

	bp = ptrace_hbp_get_initialised_bp(note_type, tsk, idx);
	if (IS_ERR(bp)) {
		err = PTR_ERR(bp);
		return err;
	}

	attr = bp->attr;
	attr.bp_addr = addr;
	err = modify_user_hw_breakpoint(bp, &attr);
	return err;
}

#define PTRACE_HBP_ADDR_SZ	sizeof(u64)
#define PTRACE_HBP_CTRL_SZ	sizeof(u32)
#define PTRACE_HBP_PAD_SZ	sizeof(u32)

static int riscv_hw_break_get(struct task_struct *target,
			const struct user_regset *regset,
			struct membuf to)
{
	unsigned int note_type = regset->core_note_type;
	int ret, idx, num_slots;
	u32 info, ctrl;
	u64 addr;

	/* Resource info: number of available slots */
	ret = ptrace_hbp_get_resource_info(note_type, &info);
	if (ret)
		return ret;

	membuf_write(&to, &info, sizeof(info));
	membuf_zero(&to, sizeof(u32));

	/* Emit one (address, ctrl, pad) entry per available slot */
	num_slots = (int)info;
	for (idx = 0; idx < num_slots; idx++) {
		ret = ptrace_hbp_get_addr(note_type, target, idx, &addr);
		if (ret)
			return ret;
		ret = ptrace_hbp_get_ctrl(note_type, target, idx, &ctrl);
		if (ret)
			return ret;
		membuf_store(&to, addr);
		membuf_store(&to, ctrl);
		membuf_zero(&to, sizeof(u32));
	}
	return 0;
}

static int riscv_hw_break_set(struct task_struct *target,
			const struct user_regset *regset,
			unsigned int pos, unsigned int count,
			const void *kbuf, const void __user *ubuf)
{
	unsigned int note_type = regset->core_note_type;
	int ret, idx = 0, offset, limit;
	u32 ctrl;
	u64 addr;

	/* Resource info and pad */
	offset = offsetof(struct user_hwdebug_state, dbg_regs);
	user_regset_copyin_ignore(&pos, &count, &kbuf, &ubuf, 0, offset);

	/* (address, ctrl) registers */
	limit = regset->n * regset->size;
	while (count && offset < limit) {
		if (count < PTRACE_HBP_ADDR_SZ)
			return -EINVAL;

		ret = user_regset_copyin(&pos, &count, &kbuf, &ubuf, &addr,
					 offset, offset + PTRACE_HBP_ADDR_SZ);
		if (ret)
			return ret;

		ret = ptrace_hbp_set_addr(note_type, target, idx, addr);
		if (ret)
			return ret;

		offset += PTRACE_HBP_ADDR_SZ;

		if (!count)
			break;

		ret = user_regset_copyin(&pos, &count, &kbuf, &ubuf, &ctrl,
					 offset, offset + PTRACE_HBP_CTRL_SZ);
		if (ret)
			return ret;

		ret = ptrace_hbp_set_ctrl(note_type, target, idx, ctrl);
		if (ret)
			return ret;

		offset += PTRACE_HBP_CTRL_SZ;

		user_regset_copyin_ignore(&pos, &count, &kbuf, &ubuf,
					  offset, offset + PTRACE_HBP_PAD_SZ);
		offset += PTRACE_HBP_PAD_SZ;
		idx++;
	}

	return 0;
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
#ifdef CONFIG_HAVE_HW_BREAKPOINT
	[REGSET_RISCV_HW_BREAK] = {
		USER_REGSET_NOTE_TYPE(RISCV_HW_BREAK),
		.n = sizeof(struct user_hwdebug_state) / sizeof(u32),
		.size = sizeof(u32),
		.align = sizeof(u32),
		.regset_get = riscv_hw_break_get,
		.set = riscv_hw_break_set,
	},
	[REGSET_RISCV_HW_WATCH] = {
		USER_REGSET_NOTE_TYPE(RISCV_HW_WATCH),
		.n = sizeof(struct user_hwdebug_state) / sizeof(u32),
		.size = sizeof(u32),
		.align = sizeof(u32),
		.regset_get = riscv_hw_break_get,
		.set = riscv_hw_break_set,
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
static int riscv_ptrace_bp_get(struct task_struct *child, unsigned long idx,
			  struct __riscv_hwdebug_state *state)
{
	struct perf_event *bp;

	if (idx >= RISCV_HW_BP_NUM_MAX)
		return -EINVAL;

	bp = child->thread.ptrace_bps[idx];
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

	if (idx >= RISCV_HW_BP_NUM_MAX)
		return -EINVAL;

	bp = child->thread.ptrace_bps[idx];
	if (bp)
		attr = bp->attr;
	else
		ptrace_breakpoint_init(&attr);

	attr.bp_addr = state->addr;
	attr.bp_len  = state->len;
	attr.bp_type = state->type;
	/* Always register disabled; enable below if requested */
	attr.disabled = 1;

	if (!bp) {
		bp = register_user_hw_breakpoint(&attr, riscv_ptrace_hbptriggered, NULL, child);
		if (IS_ERR(bp))
			return PTR_ERR(bp);
		child->thread.ptrace_bps[idx] = bp;
	}

	/* Enable or disable as requested by ctrl (0 = enabled, 1 = disabled) */
	attr.disabled = state->ctrl == 1;
	return modify_user_hw_breakpoint(bp, &attr);
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

	switch (request) {
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
