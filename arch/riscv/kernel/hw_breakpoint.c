// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2024 Ventana Micro Systems Inc.
 */

#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <linux/spinlock.h>
#include <linux/percpu.h>
#include <linux/kdebug.h>
#include <linux/bitops.h>
#include <linux/bitfield.h>
#include <linux/cpu.h>
#include <linux/cpuhotplug.h>

#include <asm/insn.h>
#include <asm/sbi.h>

#define DBTR_TDATA1_TYPE_SHIFT		(__riscv_xlen - 4)
#define DBTR_TDATA1_DMODE		BIT_UL(__riscv_xlen - 5)

#define DBTR_TDATA1_TYPE_MCONTROL	(2UL << DBTR_TDATA1_TYPE_SHIFT)
#define DBTR_TDATA1_TYPE_ICOUNT		(3UL << DBTR_TDATA1_TYPE_SHIFT)
#define DBTR_TDATA1_TYPE_MCONTROL6	(6UL << DBTR_TDATA1_TYPE_SHIFT)

#define DBTR_TDATA1_MCONTROL6_LOAD		BIT(0)
#define DBTR_TDATA1_MCONTROL6_STORE		BIT(1)
#define DBTR_TDATA1_MCONTROL6_EXECUTE		BIT(2)
#define DBTR_TDATA1_MCONTROL6_U			BIT(3)
#define DBTR_TDATA1_MCONTROL6_S			BIT(4)
#define DBTR_TDATA1_MCONTROL6_M			BIT(6)
#define DBTR_TDATA1_MCONTROL6_SIZE_FIELD	GENMASK(18, 16)
#define DBTR_TDATA1_MCONTROL6_SELECT		BIT(21)
#define DBTR_TDATA1_MCONTROL6_VU		BIT(23)
#define DBTR_TDATA1_MCONTROL6_VS		BIT(24)

#define DBTR_TDATA1_MCONTROL6_SIZE_8BIT		1
#define DBTR_TDATA1_MCONTROL6_SIZE_16BIT	2
#define DBTR_TDATA1_MCONTROL6_SIZE_32BIT	3
#define DBTR_TDATA1_MCONTROL6_SIZE_64BIT	5

#define TDATA1_MCTRL6_SZ(sz) \
	FIELD_PREP(DBTR_TDATA1_MCONTROL6_SIZE_FIELD, sz)

#define DBTR_TDATA1_MCONTROL_LOAD		BIT(0)
#define DBTR_TDATA1_MCONTROL_STORE		BIT(1)
#define DBTR_TDATA1_MCONTROL_EXECUTE		BIT(2)
#define DBTR_TDATA1_MCONTROL_U			BIT(3)
#define DBTR_TDATA1_MCONTROL_S			BIT(4)
#define DBTR_TDATA1_MCONTROL_M			BIT(6)
#define DBTR_TDATA1_MCONTROL_SIZELO_FIELD	GENMASK(17, 16)
#define DBTR_TDATA1_MCONTROL_SELECT		BIT(19)
#define DBTR_TDATA1_MCONTROL_SIZEHI_FIELD	GENMASK(22, 21)

#define DBTR_TDATA1_MCONTROL_SIZELO_8BIT	1
#define DBTR_TDATA1_MCONTROL_SIZELO_16BIT	2
#define DBTR_TDATA1_MCONTROL_SIZELO_32BIT	3
/* value of 5 split across HI and LO */
#define DBTR_TDATA1_MCONTROL_SIZELO_64BIT	1
#define DBTR_TDATA1_MCONTROL_SIZEHI_64BIT	1

#define TDATA1_MCTRL_SZ(lo, hi) \
	(FIELD_PREP(DBTR_TDATA1_MCONTROL_SIZELO_FIELD, lo) | \
	 FIELD_PREP(DBTR_TDATA1_MCONTROL_SIZEHI_FIELD, hi))

#define DBTR_TDATA1_ICOUNT_U			BIT(6)
#define DBTR_TDATA1_ICOUNT_S			BIT(7)
#define DBTR_TDATA1_ICOUNT_PENDING		BIT(8)
#define DBTR_TDATA1_ICOUNT_M			BIT(9)
#define DBTR_TDATA1_ICOUNT_COUNT_FIELD		GENMASK(23, 10)
#define DBTR_TDATA1_ICOUNT_VU			BIT(25)
#define DBTR_TDATA1_ICOUNT_VS			BIT(26)

enum dbtr_mode {
	DBTR_MODE_U = 0,
	DBTR_MODE_S,
	DBTR_MODE_VS,
	DBTR_MODE_VU,
};

/* Registered per-cpu bp/wp */
static DEFINE_PER_CPU(struct perf_event *, pcpu_hw_bp_events[RV_MAX_TRIGGERS]);
static DEFINE_PER_CPU(unsigned long, ecall_lock_flags);
static DEFINE_PER_CPU(raw_spinlock_t, ecall_lock);

/* Per-cpu shared memory between S and M mode */
static DEFINE_PER_CPU(union sbi_dbtr_shmem_entry, sbi_dbtr_shmem);

/* number of debug triggers on this cpu . */
static int dbtr_total_num __ro_after_init;
static bool have_icount __ro_after_init;
static unsigned long dbtr_type __ro_after_init;
static unsigned long dbtr_init __ro_after_init;

static int arch_smp_setup_sbi_shmem(unsigned int cpu)
{
	union sbi_dbtr_shmem_entry *dbtr_shmem;
	unsigned long shmem_pa;
	struct sbiret ret;
	int rc;

	dbtr_shmem = per_cpu_ptr(&sbi_dbtr_shmem, cpu);
	if (!dbtr_shmem) {
		pr_err("Invalid per-cpu shared memory for debug triggers\n");
		return -ENODEV;
	}

	shmem_pa = virt_to_phys(dbtr_shmem);

	ret = sbi_ecall(SBI_EXT_DBTR, SBI_EXT_DBTR_SETUP_SHMEM,
#ifdef CONFIG_32BIT
			SBI_SHMEM_LO(shmem_pa), SBI_SHMEM_HI(shmem_pa), 0, 0, 0, 0);
#else
			shmem_pa, 0, 0, 0, 0, 0);
#endif
	if (ret.error) {
		pr_warn("%s: failed to setup shared memory. error: %ld\n", __func__, ret.error);
		return sbi_err_map_linux_errno(ret.error);
	}

	pr_debug("CPU %d: HW Breakpoint shared memory registered.\n", cpu);

	return rc;
}

static int arch_smp_teardown_sbi_shmem(unsigned int cpu)
{
	struct sbiret ret;

	/* Disable shared memory */
	ret = sbi_ecall(SBI_EXT_DBTR, SBI_EXT_DBTR_SETUP_SHMEM,
			SBI_SHMEM_DISABLE, SBI_SHMEM_DISABLE, 0, 0, 0, 0);
	if (ret.error) {
		pr_warn("%s: failed to teardown shared memory. error: %ld\n", __func__, ret.error);
		return sbi_err_map_linux_errno(ret.error);
	}

	pr_debug("CPU %d: HW Breakpoint shared memory disabled.\n", cpu);

	return 0;
}

static void init_sbi_dbtr(void)
{
	struct sbiret ret;
	unsigned long dbtr_count = 0;

	/*
	 * Called by hw_breakpoint_slots and arch_hw_breakpoint_init.
	 * Only proceed if this is the first CPU to reach this code.
	 */
	if (test_and_set_bit(0, &dbtr_init))
		return;

	if (sbi_probe_extension(SBI_EXT_DBTR) <= 0) {
		pr_debug("%s: SBI_EXT_DBTR is not supported\n", __func__);
		dbtr_total_num = 0;
		return;
	}

	ret = sbi_ecall(SBI_EXT_DBTR, SBI_EXT_DBTR_NUM_TRIGGERS,
		DBTR_TDATA1_TYPE_ICOUNT, 0, 0, 0, 0, 0);
	if (ret.error) {
		pr_warn("%s: failed to detect icount triggers. error: %ld.\n",
			__func__, ret.error);
	} else if (!ret.value) {
		if (IS_ENABLED(CONFIG_HW_BREAKPOINT_COMPUTE_STEP)) {
			pr_warn("%s: No icount triggers available. "
				"Falling-back to computing single step address.\n", __func__);
		} else {
			pr_err("%s: No icount triggers available.\n", __func__);
			dbtr_total_num = 0;
			return;
		}
	} else {
		dbtr_count = ret.value;
		have_icount = true;
	}

	ret = sbi_ecall(SBI_EXT_DBTR, SBI_EXT_DBTR_NUM_TRIGGERS,
			DBTR_TDATA1_TYPE_MCONTROL6, 0, 0, 0, 0, 0);
	if (ret.error) {
		pr_warn("%s: failed to detect mcontrol6 triggers. error: %ld.\n",
			__func__, ret.error);
	} else if (!ret.value) {
		pr_warn("%s: No mcontrol6 triggers available.\n", __func__);
	} else {
		dbtr_total_num = min_not_zero((unsigned long)ret.value, dbtr_count);
		dbtr_type = DBTR_TDATA1_TYPE_MCONTROL6;
		return;
	}

	/* Fallback to legacy mcontrol triggers if mcontrol6 is not available */
	ret = sbi_ecall(SBI_EXT_DBTR, SBI_EXT_DBTR_NUM_TRIGGERS,
			DBTR_TDATA1_TYPE_MCONTROL, 0, 0, 0, 0, 0);
	if (ret.error) {
		pr_warn("%s: failed to detect mcontrol triggers. error: %ld.\n",
			__func__, ret.error);
	} else if (!ret.value) {
		pr_err("%s: No mcontrol triggers available.\n", __func__);
		dbtr_total_num = 0;
	} else {
		dbtr_total_num = min_not_zero((unsigned long)ret.value, dbtr_count);
		dbtr_type = DBTR_TDATA1_TYPE_MCONTROL;
	}
}

int hw_breakpoint_slots(int type)
{
	/*
	 * We can be called early, so don't rely on
	 * static variables being initialised.
	 */
	init_sbi_dbtr();

	return dbtr_total_num;
}

int arch_check_bp_in_kernelspace(struct arch_hw_breakpoint *hw)
{
	unsigned int len;
	unsigned long va;

	va = hw->address;
	len = hw->len;

	return (va >= TASK_SIZE) && ((va + len - 1) >= TASK_SIZE);
}

static int rv_init_mcontrol_trigger(const struct perf_event_attr *attr,
				    struct arch_hw_breakpoint *hw, enum dbtr_mode mode)
{
	unsigned long tdata1 = DBTR_TDATA1_TYPE_MCONTROL;

	switch (attr->bp_type) {
	case HW_BREAKPOINT_X:
		tdata1 |= DBTR_TDATA1_MCONTROL_EXECUTE;
		break;
	case HW_BREAKPOINT_R:
		tdata1 |= DBTR_TDATA1_MCONTROL_LOAD;
		break;
	case HW_BREAKPOINT_W:
		tdata1 |= DBTR_TDATA1_MCONTROL_STORE;
		break;
	case HW_BREAKPOINT_RW:
		tdata1 |= DBTR_TDATA1_MCONTROL_STORE | DBTR_TDATA1_MCONTROL_LOAD;
		break;
	default:
		return -EINVAL;
	}

	switch (attr->bp_len) {
	case HW_BREAKPOINT_LEN_1:
		hw->len = 1;
		tdata1 |= TDATA1_MCTRL_SZ(DBTR_TDATA1_MCONTROL_SIZELO_8BIT, 0);
		break;
	case HW_BREAKPOINT_LEN_2:
		hw->len = 2;
		tdata1 |= TDATA1_MCTRL_SZ(DBTR_TDATA1_MCONTROL_SIZELO_16BIT, 0);
		break;
	case HW_BREAKPOINT_LEN_4:
		hw->len = 4;
		tdata1 |= TDATA1_MCTRL_SZ(DBTR_TDATA1_MCONTROL_SIZELO_32BIT, 0);
		break;
#if __riscv_xlen >= 64
	case HW_BREAKPOINT_LEN_8:
		hw->len = 8;
		tdata1 |= TDATA1_MCTRL_SZ(DBTR_TDATA1_MCONTROL_SIZELO_64BIT,
					  DBTR_TDATA1_MCONTROL_SIZEHI_64BIT);
		break;
#endif
	default:
		return -EINVAL;
	}

	switch (mode) {
	case DBTR_MODE_U:
		tdata1 |= DBTR_TDATA1_MCONTROL_U;
		break;
	case DBTR_MODE_S:
		tdata1 |= DBTR_TDATA1_MCONTROL_S;
		break;
	default:
		return -EINVAL;
	}

	hw->tdata1 = tdata1;

	return 0;
}

static int rv_init_mcontrol6_trigger(const struct perf_event_attr *attr,
				     struct arch_hw_breakpoint *hw, enum dbtr_mode mode)
{
	unsigned long tdata1 = DBTR_TDATA1_TYPE_MCONTROL;

	switch (attr->bp_type) {
	case HW_BREAKPOINT_X:
		tdata1 |= DBTR_TDATA1_MCONTROL6_EXECUTE;
		break;
	case HW_BREAKPOINT_R:
		tdata1 |= DBTR_TDATA1_MCONTROL6_LOAD;
		break;
	case HW_BREAKPOINT_W:
		tdata1 |= DBTR_TDATA1_MCONTROL6_STORE;
		break;
	case HW_BREAKPOINT_RW:
		tdata1 |= DBTR_TDATA1_MCONTROL6_STORE | DBTR_TDATA1_MCONTROL6_LOAD;
		break;
	default:
		return -EINVAL;
	}

	switch (attr->bp_len) {
	case HW_BREAKPOINT_LEN_1:
		hw->len = 1;
		tdata1 |= TDATA1_MCTRL6_SZ(DBTR_TDATA1_MCONTROL6_SIZE_8BIT);
		break;
	case HW_BREAKPOINT_LEN_2:
		hw->len = 2;
		tdata1 |= TDATA1_MCTRL6_SZ(DBTR_TDATA1_MCONTROL6_SIZE_16BIT);
		break;
	case HW_BREAKPOINT_LEN_4:
		hw->len = 4;
		tdata1 |= TDATA1_MCTRL6_SZ(DBTR_TDATA1_MCONTROL6_SIZE_32BIT);
		break;
	case HW_BREAKPOINT_LEN_8:
		hw->len = 8;
		tdata1 |= TDATA1_MCTRL6_SZ(DBTR_TDATA1_MCONTROL6_SIZE_64BIT);
		break;
	default:
		return -EINVAL;
	}

	switch (mode) {
	case DBTR_MODE_U:
		tdata1 |= DBTR_TDATA1_MCONTROL6_U;
		break;
	case DBTR_MODE_S:
		tdata1 |= DBTR_TDATA1_MCONTROL6_S;
		break;
	case DBTR_MODE_VS:
		tdata1 |= DBTR_TDATA1_MCONTROL6_VS;
		break;
	case DBTR_MODE_VU:
		tdata1 |= DBTR_TDATA1_MCONTROL6_VU;
		break;
	default:
		return -EINVAL;
	}

	hw->tdata1 = tdata1;

	return 0;
}

static int rv_init_icount_trigger(struct arch_hw_breakpoint *hw, enum dbtr_mode mode)
{
	unsigned long tdata1 = DBTR_TDATA1_TYPE_ICOUNT;

	/* Step one instruction */
	tdata1 |= FIELD_PREP(DBTR_TDATA1_ICOUNT_COUNT_FIELD, 1);

	switch (mode) {
	case DBTR_MODE_U:
		tdata1 |= DBTR_TDATA1_ICOUNT_U;
		break;
	case DBTR_MODE_S:
		tdata1 |= DBTR_TDATA1_ICOUNT_S;
		break;
	case DBTR_MODE_VS:
		tdata1 |= DBTR_TDATA1_ICOUNT_VS;
		break;
	case DBTR_MODE_VU:
		tdata1 |= DBTR_TDATA1_ICOUNT_VU;
		break;
	default:
		return -EINVAL;
	}

	hw->tdata1 = tdata1;
	hw->tdata2 = 0;

	return 0;
}

int hw_breakpoint_arch_parse(struct perf_event *bp,
			     const struct perf_event_attr *attr,
			     struct arch_hw_breakpoint *hw)
{
	int ret;

	/* Breakpoint address */
	hw->address = attr->bp_addr;
	hw->tdata2 = attr->bp_addr;
	hw->tdata3 = 0x0;
	hw->next_addr = 0x0;
	hw->in_callback = false;

	switch (dbtr_type) {
	case DBTR_TDATA1_TYPE_MCONTROL:
		ret = rv_init_mcontrol_trigger(attr, hw, DBTR_MODE_U);
		break;
	case DBTR_TDATA1_TYPE_MCONTROL6:
		ret = rv_init_mcontrol6_trigger(attr, hw, DBTR_MODE_U);
		break;
	default:
		pr_warn("Unsupported trigger type %lu.\n", dbtr_type >> DBTR_TDATA1_TYPE_SHIFT);
		ret = -EOPNOTSUPP;
		break;
	}

	return ret;
}

/**
 * setup_singlestep - Update breakpoint to next instruction after breakpoint.
 * @event: Perf event to change
 * @regs: regs at breakpoint
 *
 * Update breakpoint to next instruction that would have
 * executed after the current breakpoint.
 *
 * This allows for single-stepping the instruction being debugged.
 * Then restoring the original breakpoint.
 *
 * Returns Zero on success, negative on failure
 */
static int setup_singlestep(struct perf_event *event, struct pt_regs *regs)
{
	struct arch_hw_breakpoint *bp = counter_arch_bp(event);
	struct perf_event_attr bp_insn;
	unsigned long insn, next_addr = 0;
	int ret;

	/* Remove breakpoint even if return error as not to loop */
	arch_uninstall_hw_breakpoint(event);

	if (have_icount) {
		rv_init_icount_trigger(bp, DBTR_MODE_U);
	} else {
		ret = get_insn_nofault(regs, regs->epc, &insn);
		if (ret < 0)
			return ret;

		next_addr = get_step_address(regs, insn);

		ret = get_insn_nofault(regs, next_addr, &insn);
		if (ret < 0)
			return ret;

		bp_insn.bp_type = HW_BREAKPOINT_X;
		bp_insn.bp_addr = next_addr;
		/* Get the size of the intruction */
		bp_insn.bp_len = GET_INSN_LENGTH(insn);

		ret = hw_breakpoint_arch_parse(NULL, &bp_insn, bp);
		if (ret)
			return ret;
	}

	ret = arch_install_hw_breakpoint(event);
	if (ret)
		return ret;

	bp->in_callback = true;
	bp->next_addr = next_addr;
	return 0;
}

/**
 * icount_triggered - Check if event's icount was triggered.
 * @event: Perf event to check
 *
 * Check the given perf event's icount breakpoint was triggered.
 *
 * Returns:	1 if icount was triggered.
 *		0 if icount was not triggered.
 *		negative on failure.
 */
static int icount_triggered(struct perf_event *event)
{
	union sbi_dbtr_shmem_entry *shmem = this_cpu_ptr(&sbi_dbtr_shmem);
	struct sbiret ret;
	struct perf_event **slot;
	unsigned long tdata1;
	int i;

	for (i = 0; i < dbtr_total_num; i++) {
		slot = this_cpu_ptr(&pcpu_hw_bp_events[i]);

		if (*slot == event)
			break;
	}

	if (i == dbtr_total_num) {
		pr_warn("%s: Breakpoint not installed.\n", __func__);
		return -ENOENT;
	}

	raw_spin_lock_irqsave(this_cpu_ptr(&ecall_lock),
			      *this_cpu_ptr(&ecall_lock_flags));

	ret = sbi_ecall(SBI_EXT_DBTR, SBI_EXT_DBTR_TRIG_READ,
			i, 1, 0, 0, 0, 0);
	tdata1 = shmem->data.tdata1;

	raw_spin_unlock_irqrestore(this_cpu_ptr(&ecall_lock),
				   *this_cpu_ptr(&ecall_lock_flags));
	if (ret.error) {
		pr_warn("%s: failed to read trigger. error: %ld\n", __func__, ret.error);
		return sbi_err_map_linux_errno(ret.error);
	}

	/*
	 * The RISC-V Debug Specification
	 * Tim Newsome, Paul Donahue (Ventana Micro Systems)
	 * Version 1.0, Revised 2025-02-21: Ratified
	 * 5.7.13. Instruction Count (icount, at 0x7a1)
	 * When count is 1 and the trigger matches, then pending becomes set.
	 * In addition count will become 0 unless it is hard-wired to 1.
	 * When pending is set, the trigger fires just before any further
	 * instructions are executed in a mode where the trigger is enabled.
	 * As the trigger fires, pending is cleared. In addition, if count is
	 * hard-wired to 1 then m, s, u, vs, and vu are all cleared.
	 */
	if (FIELD_GET(DBTR_TDATA1_ICOUNT_COUNT_FIELD, tdata1) == 0)
		return 1;

	if (FIELD_GET(DBTR_TDATA1_ICOUNT_COUNT_FIELD, tdata1) != 1)
		return 0;

	if (tdata1 & DBTR_TDATA1_ICOUNT_U)
		return 0;
	if (tdata1 & DBTR_TDATA1_ICOUNT_S)
		return 0;
	if (tdata1 & DBTR_TDATA1_ICOUNT_VU)
		return 0;
	if (tdata1 & DBTR_TDATA1_ICOUNT_VU)
		return 0;
	return 1;
}

/*
 * HW Breakpoint/watchpoint handler
 */
static int hw_breakpoint_handler(struct pt_regs *regs)
{
	int i, ret = 0, bp_ret = NOTIFY_DONE;
	bool expecting_callback = false;
	struct arch_hw_breakpoint *bp;
	struct perf_event *event;

	for (i = 0; i < dbtr_total_num; i++) {
		event = this_cpu_read(pcpu_hw_bp_events[i]);
		if (!event)
			continue;

		bp = counter_arch_bp(event);
		switch (event->attr.bp_type) {
		/* Breakpoint */
		case HW_BREAKPOINT_X:
			if (event->attr.bp_addr == regs->epc) {
				perf_bp_event(event, regs);
				ret = setup_singlestep(event, regs);
				if (ret < 0) {
					pr_err("%s: setup_singlestep failed %d.\n", __func__, ret);
					goto exit;
				}

				bp_ret = NOTIFY_STOP;
				goto exit;
			}
			break;

		/* Watchpoint */
		case HW_BREAKPOINT_W:
		case HW_BREAKPOINT_R:
		case HW_BREAKPOINT_RW:
			/* Watchpoints will trigger on smaller loads than the given type.
			 * To allow for this, check if the load was within the size of
			 * the type. Cast badaddr to the type of bp_addr.
			 */
			if (abs_diff(event->attr.bp_addr, (__u64)regs->badaddr) < bp->len) {
				perf_bp_event(event, regs);
				ret = setup_singlestep(event, regs);
				if (ret < 0) {
					pr_err("%s: setup_singlestep failed %d.\n", __func__, ret);
					goto exit;
				}

				bp_ret = NOTIFY_STOP;
				goto exit;
			}
			break;

		default:
			pr_warn("%s: Unknown type: %u\n", __func__, event->attr.bp_type);
			goto exit;
		}

		if (bp->in_callback) {
			expecting_callback = true;
			if (have_icount) {
				if (icount_triggered(event) != 1)
					continue;
			} else if (regs->epc != bp->next_addr) {
				continue;
			}

			arch_uninstall_hw_breakpoint(event);
			/* Restore original breakpoint */
			if (hw_breakpoint_arch_parse(NULL, &event->attr, bp))
				goto exit;
			if (arch_install_hw_breakpoint(event))
				goto exit;

			bp_ret = NOTIFY_STOP;
			goto exit;
		}

	}

	if (expecting_callback && have_icount) {
		pr_err("%s: in_callback was set, but icount was not triggered, epc (%lx).\n",
		       __func__, regs->epc);
	} else if (expecting_callback) {
		pr_err("%s: in_callback was set, but epc (%lx) was not at next address(%lx).\n",
		       __func__, regs->epc, bp->next_addr);
	}
exit:
	return bp_ret;

}

int hw_breakpoint_exceptions_notify(struct notifier_block *unused,
				    unsigned long val, void *data)
{
	struct die_args *args = data;

	if (val != DIE_DEBUG)
		return NOTIFY_DONE;

	return hw_breakpoint_handler(args->regs);
}

/* atomic: counter->ctx->lock is held */
int arch_install_hw_breakpoint(struct perf_event *event)
{
	struct arch_hw_breakpoint *bp = counter_arch_bp(event);
	union sbi_dbtr_shmem_entry *shmem = this_cpu_ptr(&sbi_dbtr_shmem);
	struct sbi_dbtr_data_msg *xmit;
	struct sbi_dbtr_id_msg *recv;
	struct perf_event **slot;
	unsigned long idx;
	struct sbiret ret;
	int err = 0;

	raw_spin_lock_irqsave(this_cpu_ptr(&ecall_lock),
			      *this_cpu_ptr(&ecall_lock_flags));

	xmit = &shmem->data;
	recv = &shmem->id;
	xmit->tdata1 = cpu_to_le(bp->tdata1);
	xmit->tdata2 = cpu_to_le(bp->tdata2);
	xmit->tdata3 = cpu_to_le(bp->tdata3);

	ret = sbi_ecall(SBI_EXT_DBTR, SBI_EXT_DBTR_TRIG_INSTALL,
			1, 0, 0, 0, 0, 0);

	if (ret.error) {
		pr_warn("%s: failed to install trigger. error: %ld\n", __func__, ret.error);
		err = sbi_err_map_linux_errno(ret.error);
		goto done;
	}

	idx = le_to_cpu(recv->idx);
	if (idx >= dbtr_total_num) {
		pr_warn("%s: invalid trigger index %lu\n", __func__, idx);
		err = -EINVAL;
		goto done;
	}

	slot = this_cpu_ptr(&pcpu_hw_bp_events[idx]);
	if (*slot) {
		pr_warn("%s: slot %lu is in use\n", __func__, idx);
		err = -EBUSY;
		goto done;
	}

	pr_debug("Trigger 0x%lx installed at index 0x%lx\n", bp->tdata2, idx);

	/* Save the event - to be looked up in handler */
	*slot = event;

done:
	raw_spin_unlock_irqrestore(this_cpu_ptr(&ecall_lock),
				   *this_cpu_ptr(&ecall_lock_flags));
	return err;
}

void arch_uninstall_hw_breakpoint(struct perf_event *event)
{
	struct perf_event **slot;
	struct sbiret ret;
	int i;

	for (i = 0; i < dbtr_total_num; i++) {
		slot = this_cpu_ptr(&pcpu_hw_bp_events[i]);

		if (*slot == event) {
			*slot = NULL;
			break;
		}
	}

	if (i == dbtr_total_num) {
		pr_warn("%s: Breakpoint not installed.\n", __func__);
		return;
	}

	ret = sbi_ecall(SBI_EXT_DBTR, SBI_EXT_DBTR_TRIG_UNINSTALL,
			i, 1, 0, 0, 0, 0);
	if (ret.error)
		pr_warn("%s: Failed to uninstall trigger %d. error: %ld\n", __func__, i, ret.error);
}

/*
 * Release the user breakpoints used by ptrace
 */
void flush_ptrace_hw_breakpoint(struct task_struct *tsk)
{
	int i;
	struct thread_struct *t = &tsk->thread;

	for (i = 0; i < dbtr_total_num; i++) {
		unregister_hw_breakpoint(t->ptrace_bps[i]);
		t->ptrace_bps[i] = NULL;
	}
}

void hw_breakpoint_pmu_read(struct perf_event *bp) { }

static int __init arch_hw_breakpoint_init(void)
{
	unsigned int cpu;
	int rc = 0;

	for_each_possible_cpu(cpu)
		raw_spin_lock_init(&per_cpu(ecall_lock, cpu));

	init_sbi_dbtr();

	if (dbtr_total_num) {
		pr_debug("%s: total number of type %lu triggers: %u\n",
			__func__, dbtr_type >> DBTR_TDATA1_TYPE_SHIFT, dbtr_total_num);
	} else {
		pr_debug("%s: No hardware triggers available\n", __func__);
		return rc;
	}

	/* Hotplug handler to register/unregister shared memory with SBI */
	rc = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN,
			       "riscv/hw_breakpoint:prepare",
			       arch_smp_setup_sbi_shmem,
			       arch_smp_teardown_sbi_shmem);

	if (rc < 0)
		pr_warn("%s: Failed to setup CPU hotplug state\n", __func__);

	return rc;
}
arch_initcall(arch_hw_breakpoint_init);
