// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 Qualcomm Technologies, Inc.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

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

#define RISCV_HW_BP_NUM_MAX	32

#if __riscv_xlen == 64
#define cpu_to_le		cpu_to_le64
#define le_to_cpu		le64_to_cpu
#elif __riscv_xlen == 32
#define cpu_to_le		cpu_to_le32
#define le_to_cpu		le32_to_cpu
#else
#error "Unexpected __riscv_xlen"
#endif

enum {
	RISCV_DBTR_TRIG_NONE = 0,
	RISCV_DBTR_TRIG_LEGACY,
	RISCV_DBTR_TRIG_MCONTROL,
	RISCV_DBTR_TRIG_ICOUNT,
	RISCV_DBTR_TRIG_ITRIGGER,
	RISCV_DBTR_TRIG_ETRIGGER,
	RISCV_DBTR_TRIG_MCONTROL6,
};

#define RISCV_DBTR_TDATA1_TYPE_MASK	GENMASK(__riscv_xlen - 1, __riscv_xlen - 4)

#define RISCV_DBTR_MC_LOAD		BIT(0)
#define RISCV_DBTR_MC_STORE		BIT(1)
#define RISCV_DBTR_MC_EXEC		BIT(2)
#define RISCV_DBTR_MC_U		BIT(3)
#define RISCV_DBTR_MC_S		BIT(4)
#define RISCV_DBTR_MC_HIT		BIT(20)
#define RISCV_DBTR_MC_SIZELO_MASK	GENMASK(17, 16)
#if __riscv_xlen >= 64
#define RISCV_DBTR_MC_SIZEHI_MASK	GENMASK(22, 21)
#endif

#define RISCV_DBTR_MC6_LOAD		BIT(0)
#define RISCV_DBTR_MC6_STORE		BIT(1)
#define RISCV_DBTR_MC6_EXEC		BIT(2)
#define RISCV_DBTR_MC6_U		BIT(3)
#define RISCV_DBTR_MC6_S		BIT(4)
#define RISCV_DBTR_MC6_SIZE_MASK	GENMASK(19, 16)
#define RISCV_DBTR_MC6_HIT		BIT(22)
#define RISCV_DBTR_MC6_HIT1		BIT(25)
#define RISCV_DBTR_MC6_HIT_MASK	(RISCV_DBTR_MC6_HIT | RISCV_DBTR_MC6_HIT1)

#define RISCV_DBTR_ICOUNT_U		BIT(6)
#define RISCV_DBTR_ICOUNT_COUNT_MASK	GENMASK(23, 10)

#define RISCV_DBTR_MC6_HIT_FALSE	0
#define RISCV_DBTR_MC6_HIT_BEFORE	1
#define RISCV_DBTR_MC6_HIT_AFTER	2
#define RISCV_DBTR_MC6_HIT_IMM_AFTER	3

/* Registered per-cpu bp/wp */
static DEFINE_PER_CPU(struct perf_event *, pcpu_hw_bp_events[RISCV_HW_BP_NUM_MAX]);
static DEFINE_PER_CPU(raw_spinlock_t, ecall_lock);

/* Per-cpu shared memory between S and M mode */
static union sbi_dbtr_shmem_entry __percpu *sbi_dbtr_shmem;

/* number of debug triggers on this cpu . */
static int dbtr_total_num __ro_after_init;
static int dbtr_type __ro_after_init;
static bool dbtr_icount_available __ro_after_init;
static unsigned long dbtr_init __ro_after_init;

#define MEM_HI(_m)		\
	(IS_ENABLED(CONFIG_32BIT) ? upper_32_bits((u64)(_m)) : 0UL)
#define MEM_LO(_m)		((unsigned long)(_m))

static unsigned long dbtr_tdata1_type(unsigned int type)
{
	return FIELD_PREP(RISCV_DBTR_TDATA1_TYPE_MASK, type);
}

static unsigned long dbtr_mcontrol_size(unsigned int lo, unsigned int hi)
{
	unsigned long tdata1 = FIELD_PREP(RISCV_DBTR_MC_SIZELO_MASK, lo);

#if __riscv_xlen >= 64
	tdata1 |= FIELD_PREP(RISCV_DBTR_MC_SIZEHI_MASK, hi);
#else
	(void)hi;
#endif
	return tdata1;
}

static unsigned long dbtr_mcontrol6_size(unsigned int size)
{
	return FIELD_PREP(RISCV_DBTR_MC6_SIZE_MASK, size);
}

static unsigned int dbtr_mcontrol6_hit(unsigned long tdata1)
{
	return ((tdata1 & RISCV_DBTR_MC6_HIT1) ? 2 : 0) |
	       ((tdata1 & RISCV_DBTR_MC6_HIT) ? 1 : 0);
}

static bool ranges_overlap(unsigned long start1, unsigned long len1,
			   unsigned long start2, unsigned long len2)
{
	unsigned long end1 = start1 + len1 - 1;
	unsigned long end2 = start2 + len2 - 1;

	if (end1 < start1)
		end1 = ~0UL;
	if (end2 < start2)
		end2 = ~0UL;

	return start1 <= end2 && start2 <= end1;
}

static int arch_smp_setup_sbi_shmem(unsigned int cpu)
{
	union sbi_dbtr_shmem_entry *dbtr_shmem;
	phys_addr_t shmem_pa;
	struct sbiret ret;

	dbtr_shmem = per_cpu_ptr(sbi_dbtr_shmem, cpu);

	shmem_pa = per_cpu_ptr_to_phys(dbtr_shmem);

	ret = sbi_ecall(SBI_EXT_DBTR, SBI_EXT_DBTR_SETUP_SHMEM,
			MEM_LO(shmem_pa), MEM_HI(shmem_pa), 0, 0, 0, 0);

	if (ret.error) {
		pr_warn("%s: failed to setup shared memory. error: %ld\n",
			__func__, ret.error);
		return sbi_err_map_linux_errno(ret.error);
	}

	pr_info("CPU %d: HW Breakpoint shared memory registered.\n", cpu);

	return 0;
}

static int arch_smp_teardown_sbi_shmem(unsigned int cpu)
{
	struct sbiret ret;

	/* Disable shared memory */
	ret = sbi_ecall(SBI_EXT_DBTR, SBI_EXT_DBTR_SETUP_SHMEM,
			SBI_SHMEM_DISABLE, SBI_SHMEM_DISABLE, 0, 0, 0, 0);

	if (ret.error)
		pr_warn("%s: failed to disable shared memory. error: %ld\n",
			__func__, ret.error);
	else
		pr_info("CPU %d: HW Breakpoint shared memory disabled.\n", cpu);

	return 0;
}

static void init_sbi_dbtr(void)
{
	unsigned long tdata1;
	struct sbiret ret;

	/*
	 * Called by hw_breakpoint_slots() and arch_hw_breakpoint_init().
	 * Only the first caller should run SBI discovery; later callers may
	 * arrive after __ro_after_init data is read-only, so avoid a locked
	 * write if the bit is already set.
	 */
	if (test_bit(0, &dbtr_init) || test_and_set_bit(0, &dbtr_init))
		return;

	if (sbi_probe_extension(SBI_EXT_DBTR) <= 0) {
		pr_warn("SBI_EXT_DBTR is not supported\n");
		dbtr_total_num = 0;
		return;
	}

	ret = sbi_ecall(SBI_EXT_DBTR, SBI_EXT_DBTR_NUM_TRIGGERS,
			0, 0, 0, 0, 0, 0);
	if (ret.error) {
		pr_warn("Failed to detect triggers\n");
		dbtr_total_num = 0;
		return;
	}

	tdata1 = dbtr_tdata1_type(RISCV_DBTR_TRIG_ICOUNT);

	ret = sbi_ecall(SBI_EXT_DBTR, SBI_EXT_DBTR_NUM_TRIGGERS,
			tdata1, 0, 0, 0, 0, 0);
	if (ret.error) {
		pr_warn("Failed to detect icount triggers\n");
	} else if (ret.value) {
		dbtr_icount_available = 1;
		pr_warn("Icount trigger available.\n");
	}

	tdata1 = dbtr_tdata1_type(RISCV_DBTR_TRIG_MCONTROL6);

	ret = sbi_ecall(SBI_EXT_DBTR, SBI_EXT_DBTR_NUM_TRIGGERS,
			tdata1, 0, 0, 0, 0, 0);
	if (ret.error) {
		pr_warn("Failed to detect mcontrol6 triggers\n");
	} else if (!ret.value) {
		pr_warn("Type 6 triggers not available\n");
	} else {
		dbtr_total_num = min_t(unsigned long, ret.value,
				       RISCV_HW_BP_NUM_MAX);
		dbtr_type = RISCV_DBTR_TRIG_MCONTROL6;
		pr_warn("Mcontrol6 trigger available.\n");
		return;
	}

	/* fallback to type 2 triggers if type 6 is not available */

	tdata1 = dbtr_tdata1_type(RISCV_DBTR_TRIG_MCONTROL);

	ret = sbi_ecall(SBI_EXT_DBTR, SBI_EXT_DBTR_NUM_TRIGGERS,
			tdata1, 0, 0, 0, 0, 0);
	if (ret.error) {
		pr_warn("Failed to detect mcontrol triggers\n");
	} else if (!ret.value) {
		pr_warn("Type 2 triggers not available\n");
	} else {
		dbtr_total_num = min_t(unsigned long, ret.value,
				       RISCV_HW_BP_NUM_MAX);
		dbtr_type = RISCV_DBTR_TRIG_MCONTROL;
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
	unsigned long va, len, end;

	va = hw->address;
	/* Execute breakpoints encode "match any instruction size" as len 0. */
	len = hw->len ?: 1;
	end = va + len - 1;

	if (end < va)
		end = ~0UL;

	return (va >= TASK_SIZE) || (end >= TASK_SIZE);
}

static int rv_init_mcontrol_trigger(const struct perf_event_attr *attr,
				    struct arch_hw_breakpoint *hw)
{
	unsigned long tdata1 = dbtr_tdata1_type(RISCV_DBTR_TRIG_MCONTROL);

	switch (attr->bp_type) {
	case HW_BREAKPOINT_X:
		tdata1 |= RISCV_DBTR_MC_EXEC;
		break;
	case HW_BREAKPOINT_R:
		tdata1 |= RISCV_DBTR_MC_LOAD;
		break;
	case HW_BREAKPOINT_W:
		tdata1 |= RISCV_DBTR_MC_STORE;
		break;
	case HW_BREAKPOINT_RW:
		tdata1 |= RISCV_DBTR_MC_LOAD | RISCV_DBTR_MC_STORE;
		break;
	default:
		return -EINVAL;
	}

	if (attr->bp_type == HW_BREAKPOINT_X) {
		/*
		 * Userspace debuggers can request execute breakpoints with
		 * bp_len == 2 for compressed/non-aligned instruction
		 * addresses. Program execute triggers with "match any size"
		 * to avoid missing valid instruction fetches.
		 */
		hw->len = 0;
	} else {
		switch (attr->bp_len) {
		case HW_BREAKPOINT_LEN_1:
			hw->len = 1;
			tdata1 |= dbtr_mcontrol_size(1, 0);
			break;
		case HW_BREAKPOINT_LEN_2:
			hw->len = 2;
			tdata1 |= dbtr_mcontrol_size(2, 0);
			break;
		case HW_BREAKPOINT_LEN_4:
			hw->len = 4;
			tdata1 |= dbtr_mcontrol_size(3, 0);
			break;
#if __riscv_xlen >= 64
		case HW_BREAKPOINT_LEN_8:
			hw->len = 8;
			tdata1 |= dbtr_mcontrol_size(1, 1);
			break;
#endif
		/* Set to match any size */
		default:
			hw->len = 0;
			break;
		}
	}

	/*
	 * Match only the trigger's actual privilege-mode target. Setting
	 * both bits makes the kernel's own S-mode uaccess (e.g. SUM-enabled
	 * loads in strncpy_from_user()) spuriously fire a user-space watch.
	 */
	if (arch_check_bp_in_kernelspace(hw))
		tdata1 |= RISCV_DBTR_MC_S;
	else
		tdata1 |= RISCV_DBTR_MC_U;

	hw->tdata1 = tdata1;
	return 0;
}

static int rv_init_mcontrol6_trigger(const struct perf_event_attr *attr,
				     struct arch_hw_breakpoint *hw)
{
	unsigned long tdata1 = dbtr_tdata1_type(RISCV_DBTR_TRIG_MCONTROL6);

	switch (attr->bp_type) {
	case HW_BREAKPOINT_X:
		tdata1 |= RISCV_DBTR_MC6_EXEC;
		break;
	case HW_BREAKPOINT_R:
		tdata1 |= RISCV_DBTR_MC6_LOAD;
		break;
	case HW_BREAKPOINT_W:
		tdata1 |= RISCV_DBTR_MC6_STORE;
		break;
	case HW_BREAKPOINT_RW:
		tdata1 |= RISCV_DBTR_MC6_STORE | RISCV_DBTR_MC6_LOAD;
		break;
	default:
		return -EINVAL;
	}

	if (attr->bp_type == HW_BREAKPOINT_X) {
		/* See rv_init_mcontrol_trigger() for rationale. */
		hw->len = 0;
	} else {
		switch (attr->bp_len) {
		case HW_BREAKPOINT_LEN_1:
			hw->len = 1;
			tdata1 |= dbtr_mcontrol6_size(1);
			break;
		case HW_BREAKPOINT_LEN_2:
			hw->len = 2;
			tdata1 |= dbtr_mcontrol6_size(2);
			break;
		case HW_BREAKPOINT_LEN_4:
			hw->len = 4;
			tdata1 |= dbtr_mcontrol6_size(3);
			break;
#if __riscv_xlen >= 64
		case HW_BREAKPOINT_LEN_8:
			hw->len = 8;
			tdata1 |= dbtr_mcontrol6_size(5);
			break;
#endif
		/* Set to match any size */
		default:
			hw->len = 0;
		}
	}

	/* See rv_init_mcontrol_trigger() for rationale. */
	if (arch_check_bp_in_kernelspace(hw))
		tdata1 |= RISCV_DBTR_MC6_S;
	else
		tdata1 |= RISCV_DBTR_MC6_U;

	hw->tdata1 = tdata1;
	return 0;
}

int hw_breakpoint_arch_parse(struct perf_event *bp,
			     const struct perf_event_attr *attr,
			     struct arch_hw_breakpoint *hw)
{
	int ret;

	/* Breakpoint address */
	hw->address = attr->bp_addr;
	hw->tdata1 = 0;
	hw->tdata2 = attr->bp_addr;
	hw->tdata3 = 0x0;
	hw->next_addr = 0x0;
	hw->step_method = RISCV_HW_BP_STEP_DISABLED;
	hw->pending_perf_event = false;

	switch (dbtr_type) {
	case RISCV_DBTR_TRIG_MCONTROL:
		ret = rv_init_mcontrol_trigger(attr, hw);
		break;
	case RISCV_DBTR_TRIG_MCONTROL6:
		ret = rv_init_mcontrol6_trigger(attr, hw);
		break;
	default:
		pr_warn("Unsupported trigger type\n");
		ret = -EOPNOTSUPP;
		break;
	}

	return ret;
}

static ulong get_step_address(struct pt_regs *regs, ulong insn)
{
	return get_next_insn_address(regs, insn, regs->epc);
}

static int dbtr_update_event_tdata(struct perf_event *event,
				   unsigned long tdata1,
				   unsigned long tdata2,
				   unsigned long tdata3, bool wait);

static bool hw_breakpoint_event_active(struct perf_event *event)
{
	return READ_ONCE(event->state) == PERF_EVENT_STATE_ACTIVE;
}

static void clear_singlestep_state(struct arch_hw_breakpoint *bp)
{
	bp->step_method = RISCV_HW_BP_STEP_DISABLED;
	bp->next_addr = 0;
	bp->pending_perf_event = false;
}

static void disable_unhandled_singlestep(struct perf_event *event,
					 struct pt_regs *regs, bool deliver_event,
					 int err)
{
	struct arch_hw_breakpoint *bp = counter_arch_bp(event);

	/*
	 * If the temporary step trigger cannot be installed or restored, leave
	 * the CPU with no active trigger instead of re-entering the same debug
	 * exception forever.
	 */
	pr_warn("single-step setup failed for bp_addr=0x%lx epc=0x%lx: %d; disabling event\n",
		bp->address, regs->epc, err);
	clear_singlestep_state(bp);
	if (deliver_event && hw_breakpoint_event_active(event))
		perf_bp_event(event, regs);
	if (hw_breakpoint_event_active(event))
		perf_event_disable_inatomic(event);
}

static unsigned long icount_step_tdata1(void)
{
	return dbtr_tdata1_type(RISCV_DBTR_TRIG_ICOUNT) |
	       FIELD_PREP(RISCV_DBTR_ICOUNT_COUNT_MASK, 1) |
	       RISCV_DBTR_ICOUNT_U;
}

static int restore_original_breakpoint(struct perf_event *event)
{
	struct arch_hw_breakpoint *bp = counter_arch_bp(event);
	int ret;

	/*
	 * Rebuild the original trigger from the perf attributes instead of
	 * keeping a second copy of the trigger data.  Do not update the
	 * temporary trigger in place when changing back from icount/software-step
	 * mode: uninstall/install gives the original breakpoint a fresh hardware
	 * slot and clears any transient hit state.
	 */
	arch_uninstall_hw_breakpoint(event);

	ret = hw_breakpoint_arch_parse(NULL, &event->attr, bp);
	if (ret)
		return ret;

	return arch_install_hw_breakpoint(event);
}

/*
 * setup_singlestep - Set the breakpoint to next instruction after current breakpoint.
 */
static int setup_singlestep(struct perf_event *event, struct pt_regs *regs)
{
	struct arch_hw_breakpoint *bp = counter_arch_bp(event);
	unsigned long insn, next_addr = 0;
	int ret;
	struct arch_hw_breakpoint tmp = {};

	clear_singlestep_state(bp);

	if (dbtr_icount_available && !arch_check_bp_in_kernelspace(bp)) {
		/*
		 * User breakpoints can use an icount trigger to retire exactly
		 * one instruction.  The sdtrig icount path reports EPC after the
		 * counted instruction, so the callback sees the post-step PC
		 * without decoding the original instruction here.
		 */
		tmp.tdata1 = icount_step_tdata1();

		ret = dbtr_update_event_tdata(event, tmp.tdata1, 0, 0, false);
		if (ret)
			return ret;

		bp->step_method = RISCV_HW_BP_STEP_ICOUNT;
		bp->next_addr = 0;
		return 0;
	}

	if (!event->hw.target) {
		/*
		 * A CPU-wide software-step trigger follows one task's decoded
		 * next PC.  If that task migrates, the per-CPU slot may wait
		 * forever for an address the CPU will not execute.
		 */
		return -EOPNOTSUPP;
	}

	ret = get_insn_safe(regs, regs->epc, &insn);
	if (ret < 0)
		return ret;

	next_addr = get_step_address(regs, insn);
	if (next_addr == regs->epc) {
		/*
		 * Some control transfers, notably SRET, cannot be represented
		 * as an execute breakpoint at a different decoded PC.  Refuse
		 * the software step rather than programming the same address
		 * and looping on the original breakpoint.
		 */
		return -EOPNOTSUPP;
	}

	/*
	 * Software path: update the trigger in-place to an execute
	 * breakpoint at next_addr.  Build the tdata directly without
	 * calling hw_breakpoint_arch_parse() so that bp->len and bp->address
	 * remain valid for the handler's matching logic after restore.
	 */
	tmp.tdata2 = next_addr;
	tmp.tdata3 = 0;
	switch (dbtr_type) {
	case RISCV_DBTR_TRIG_MCONTROL6:
		tmp.tdata1 = dbtr_tdata1_type(RISCV_DBTR_TRIG_MCONTROL6) |
			     RISCV_DBTR_MC6_EXEC;
		if (user_mode(regs))
			tmp.tdata1 |= RISCV_DBTR_MC6_U;
		else
			tmp.tdata1 |= RISCV_DBTR_MC6_S;
		break;
	case RISCV_DBTR_TRIG_MCONTROL:
		tmp.tdata1 = dbtr_tdata1_type(RISCV_DBTR_TRIG_MCONTROL) |
			     RISCV_DBTR_MC_EXEC;
		if (user_mode(regs))
			tmp.tdata1 |= RISCV_DBTR_MC_U;
		else
			tmp.tdata1 |= RISCV_DBTR_MC_S;
		break;
	default:
		return -EOPNOTSUPP;
	}

	ret = dbtr_update_event_tdata(event, tmp.tdata1, next_addr, 0, false);
	if (ret)
		return ret;

	bp->step_method = RISCV_HW_BP_STEP_SW;
	bp->next_addr = next_addr;
	return 0;
}

static void dbtr_encode_update(union sbi_dbtr_shmem_entry *shmem,
			       unsigned long idx, unsigned long tdata1,
			       unsigned long tdata2, unsigned long tdata3)
{
	struct sbi_dbtr_id_msg *id = &shmem->id;
	struct sbi_dbtr_data_msg *data = &shmem->data;

	/*
	 * SBI_EXT_DBTR_TRIG_UPDATE takes the number of entries in a0.  The
	 * trigger index for each entry lives in the first shared-memory word;
	 * that word is named tstate only when the same union is used for
	 * TRIG_READ replies.
	 */
	id->idx = cpu_to_le(idx);
	data->tdata1 = cpu_to_le(tdata1);
	data->tdata2 = cpu_to_le(tdata2);
	data->tdata3 = cpu_to_le(tdata3);
}

static struct sbiret dbtr_update_trigger_locked(unsigned long idx,
						unsigned long tdata1,
						unsigned long tdata2,
						unsigned long tdata3)
{
	union sbi_dbtr_shmem_entry *shmem = this_cpu_ptr(sbi_dbtr_shmem);

	dbtr_encode_update(shmem, idx, tdata1, tdata2, tdata3);

	return sbi_ecall(SBI_EXT_DBTR, SBI_EXT_DBTR_TRIG_UPDATE,
			 1, 0, 0, 0, 0, 0);
}

static int dbtr_update_event_tdata(struct perf_event *event,
				   unsigned long tdata1,
				   unsigned long tdata2,
				   unsigned long tdata3, bool wait)
{
	struct perf_event **slot;
	unsigned long flags;
	struct sbiret ret;
	int i;

	if (wait)
		raw_spin_lock_irqsave(this_cpu_ptr(&ecall_lock), flags);
	else if (!raw_spin_trylock_irqsave(this_cpu_ptr(&ecall_lock), flags))
		return -EBUSY;

	for (i = 0; i < dbtr_total_num; i++) {
		slot = this_cpu_ptr(&pcpu_hw_bp_events[i]);

		if (*slot == event)
			break;
	}

	if (i == dbtr_total_num) {
		raw_spin_unlock_irqrestore(this_cpu_ptr(&ecall_lock), flags);
		return -ENOENT;
	}

	ret = dbtr_update_trigger_locked(i, tdata1, tdata2, tdata3);
	raw_spin_unlock_irqrestore(this_cpu_ptr(&ecall_lock), flags);

	if (ret.error)
		return sbi_err_map_linux_errno(ret.error);

	return 0;
}

static struct sbiret dbtr_uninstall_trigger_locked(unsigned long idx)
{
	return sbi_ecall(SBI_EXT_DBTR, SBI_EXT_DBTR_TRIG_UNINSTALL,
			 idx, 1, 0, 0, 0, 0);
}

static bool mc_read_and_clear_hit(int idx)
{
	union sbi_dbtr_shmem_entry *shmem = this_cpu_ptr(sbi_dbtr_shmem);
	unsigned long flags, tdata1, tdata2, tdata3;
	struct sbiret ret;
	bool hit;

	/*
	 * This runs from DIE_DEBUG.  If the exception interrupted another DBTR
	 * SBI call on this CPU, blocking on the same raw spinlock would deadlock;
	 * the handler can still fall back to address-based matching.
	 */
	if (!raw_spin_trylock_irqsave(this_cpu_ptr(&ecall_lock), flags))
		return false;

	ret = sbi_ecall(SBI_EXT_DBTR, SBI_EXT_DBTR_TRIG_READ,
			idx, 1, 0, 0, 0, 0);
	if (ret.error) {
		pr_warn("Failed to read trigger %d. error: %ld\n",
			idx, ret.error);
		hit = false;
		goto out;
	}

	tdata1 = le_to_cpu(shmem->data.tdata1);
	hit = !!(tdata1 & RISCV_DBTR_MC_HIT);
	if (!hit)
		goto out;

	tdata2 = le_to_cpu(shmem->data.tdata2);
	tdata3 = le_to_cpu(shmem->data.tdata3);
	tdata1 &= ~RISCV_DBTR_MC_HIT;

	ret = dbtr_update_trigger_locked(idx, tdata1, tdata2, tdata3);
	if (ret.error)
		pr_warn("Failed to clear hit bit on trigger %d. error: %ld\n",
			idx, ret.error);

out:
	raw_spin_unlock_irqrestore(this_cpu_ptr(&ecall_lock), flags);
	return hit;
}

/*
 * Read mcontrol6's hit1:hit0 field for trigger @idx. If either bit is set,
 * clear it in hardware (the Debug spec requires the trigger user to do
 * this; hardware only ever sets it). Returns the RISCV_DBTR_MC6_HIT_*
 * value read (RISCV_DBTR_MC6_HIT_FALSE if unimplemented or unfired).
 */
static unsigned int mc6_read_and_clear_hit(int idx)
{
	union sbi_dbtr_shmem_entry *shmem = this_cpu_ptr(sbi_dbtr_shmem);
	unsigned long flags, tdata1, tdata2, tdata3;
	struct sbiret ret;
	unsigned int hit;

	/* See mc_read_and_clear_hit() for the trylock rationale. */
	if (!raw_spin_trylock_irqsave(this_cpu_ptr(&ecall_lock), flags))
		return RISCV_DBTR_MC6_HIT_FALSE;

	ret = sbi_ecall(SBI_EXT_DBTR, SBI_EXT_DBTR_TRIG_READ, idx, 1, 0, 0, 0, 0);
	if (ret.error) {
		pr_warn("Failed to read trigger %d. error: %ld\n", idx, ret.error);
		hit = RISCV_DBTR_MC6_HIT_FALSE;
		goto out;
	}

	tdata1 = le_to_cpu(shmem->data.tdata1);
	hit = dbtr_mcontrol6_hit(tdata1);
	if (hit == RISCV_DBTR_MC6_HIT_FALSE)
		goto out;

	tdata2 = le_to_cpu(shmem->data.tdata2);
	tdata3 = le_to_cpu(shmem->data.tdata3);
	tdata1 &= ~RISCV_DBTR_MC6_HIT_MASK;

	ret = dbtr_update_trigger_locked(idx, tdata1, tdata2, tdata3);
	if (ret.error)
		pr_warn("Failed to clear hit bits on trigger %d. error: %ld\n",
			idx, ret.error);

out:
	raw_spin_unlock_irqrestore(this_cpu_ptr(&ecall_lock), flags);
	return hit;
}

static int handle_triggered_breakpoint(struct perf_event *event,
				       struct pt_regs *regs)
{
	struct arch_hw_breakpoint *bp = counter_arch_bp(event);
	bool defer_perf;
	int ret;

	/*
	 * Report user breakpoints after the temporary step trigger advances
	 * past the armed instruction.  Otherwise signal delivery can re-enter
	 * the same execute trigger before the PC has moved.
	 */
	defer_perf = !arch_check_bp_in_kernelspace(bp);
	if (!defer_perf) {
		perf_bp_event(event, regs);
		if (!hw_breakpoint_event_active(event))
			return NOTIFY_STOP;
	}

	ret = setup_singlestep(event, regs);
	if (ret < 0) {
		disable_unhandled_singlestep(event, regs, defer_perf, ret);
		return NOTIFY_STOP;
	}

	bp->pending_perf_event = defer_perf;
	return NOTIFY_STOP;
}

/*
 * HW Breakpoint/watchpoint handler
 */
static int hw_breakpoint_handler(struct die_args *args)
{
	int i, ret = 0, bp_ret = NOTIFY_DONE;
	struct perf_event *deferred_step_event = NULL;
	struct arch_hw_breakpoint *deferred_step_bp = NULL;
	struct arch_hw_breakpoint *bp;
	struct perf_event *event;

	for (i = 0; i < dbtr_total_num; i++) {
		event = this_cpu_read(pcpu_hw_bp_events[i]);
		if (!event)
			continue;

		bp = counter_arch_bp(event);

		if (bp->step_method != RISCV_HW_BP_STEP_DISABLED) {
			bool pending_perf_event;

			/*
			 * This trap is for the temporary trigger installed by
			 * setup_singlestep().  Software stepping must match the
			 * decoded next_addr; icount already reports the post-step
			 * PC and can restore the original trigger immediately.
			 */
			if (bp->step_method == RISCV_HW_BP_STEP_SW &&
			    args->regs->epc != bp->next_addr) {
				/*
				 * A nested breakpoint can fire before this
				 * event reaches its decoded next_addr, for
				 * example when perf delivers a signal handler
				 * with its own breakpoint.  Let the later slot
				 * handle that trap and keep this temporary step
				 * armed.  If nobody handles the trap, restore
				 * below so a real divergence does not lose the
				 * original breakpoint indefinitely.
				 */
				deferred_step_event = event;
				deferred_step_bp = bp;
				continue;
			}

			if (bp->step_method == RISCV_HW_BP_STEP_ICOUNT &&
			    args->regs->epc == bp->address) {
				unsigned long tdata1 = icount_step_tdata1();

				/*
				 * A trap can be observed before the original
				 * user instruction retires, leaving EPC on the
				 * armed breakpoint.  Delivering the deferred
				 * perf event here would account the same
				 * breakpoint twice, so rearm icount and wait for
				 * a callback with a post-instruction EPC.
				 */
				ret = dbtr_update_event_tdata(event, tdata1, 0, 0, false);
				if (ret) {
					disable_unhandled_singlestep(event,
								     args->regs,
								     bp->pending_perf_event,
								     ret);
					bp_ret = NOTIFY_STOP;
					goto exit;
				}
				bp_ret = NOTIFY_STOP;
				goto exit;
			}

			pending_perf_event = bp->pending_perf_event;

			ret = restore_original_breakpoint(event);
			if (ret) {
				clear_singlestep_state(bp);
				perf_event_disable_inatomic(event);
				bp_ret = NOTIFY_STOP;
				goto exit;
			}

			clear_singlestep_state(bp);
			if (pending_perf_event && hw_breakpoint_event_active(event))
				perf_bp_event(event, args->regs);
			bp_ret = NOTIFY_STOP;
			goto exit;
		}

		switch (event->attr.bp_type) {
		/* Breakpoint */
		case HW_BREAKPOINT_X:
			{
				bool hit = bp->address == args->regs->epc;

				if (dbtr_type == RISCV_DBTR_TRIG_MCONTROL)
					hit |= mc_read_and_clear_hit(i);
				else if (dbtr_type == RISCV_DBTR_TRIG_MCONTROL6)
					hit |= mc6_read_and_clear_hit(i) !=
					       RISCV_DBTR_MC6_HIT_FALSE;

				if (hit) {
					bp_ret = handle_triggered_breakpoint(event, args->regs);
					goto exit;
				}
			}
			break;

		/* Watchpoint */
		case HW_BREAKPOINT_W:
		case HW_BREAKPOINT_R:
		case HW_BREAKPOINT_RW:
			{
				unsigned long stval = args->regs->badaddr;
				unsigned long bp_start = bp->address;
				unsigned long bp_len = bp->len ?: 1;
				bool hit = false;

				/*
				 * Prefer tdata1.hit from SBI trigger readout whenever
				 * possible. Fall back to address-based matching if HIT
				 * isn't observed/supported.
				 */
				if (dbtr_type == RISCV_DBTR_TRIG_MCONTROL)
					hit = mc_read_and_clear_hit(i);
				else if (dbtr_type == RISCV_DBTR_TRIG_MCONTROL6)
					hit = mc6_read_and_clear_hit(i) !=
					      RISCV_DBTR_MC6_HIT_FALSE;

				/*
				 * Sdtrig may report STVAL as the lowest accessed
				 * address while the watchpoint can match a higher byte
				 * in the same access.  Check for full range overlap
				 * rather than comparing only the two start addresses.
				 */
				hit |= ranges_overlap(bp_start, bp_len, stval,
						      sizeof(long));
				if (hit) {
					bp_ret = handle_triggered_breakpoint(event, args->regs);
					goto exit;
				}
			}
			break;

		default:
			pr_warn("Unknown type: %u\n", event->attr.bp_type);
			goto exit;
		}
	}

	if (deferred_step_event) {
		bp = deferred_step_bp;
		ret = restore_original_breakpoint(deferred_step_event);
		if (ret)
			perf_event_disable_inatomic(deferred_step_event);
		clear_singlestep_state(bp);
		bp_ret = NOTIFY_STOP;
	}

exit:
	return bp_ret;
}

int hw_breakpoint_exceptions_notify(struct notifier_block *unused,
				    unsigned long val, void *data)
{
	if (val != DIE_DEBUG)
		return NOTIFY_DONE;

	return hw_breakpoint_handler(data);
}

/* atomic: counter->ctx->lock is held */
int arch_install_hw_breakpoint(struct perf_event *event)
{
	struct arch_hw_breakpoint *bp = counter_arch_bp(event);
	union sbi_dbtr_shmem_entry *shmem = this_cpu_ptr(sbi_dbtr_shmem);
	struct sbi_dbtr_data_msg *xmit;
	struct sbi_dbtr_id_msg *recv;
	struct perf_event **slot;
	unsigned long idx;
	unsigned long flags;
	struct sbiret ret;
	int err = 0;

	raw_spin_lock_irqsave(this_cpu_ptr(&ecall_lock), flags);

	xmit = &shmem->data;
	recv = &shmem->id;
	/* Avoid sending stale union contents from a previous id reply. */
	xmit->tstate = cpu_to_le(0UL);
	xmit->tdata1 = cpu_to_le(bp->tdata1);
	xmit->tdata2 = cpu_to_le(bp->tdata2);
	xmit->tdata3 = cpu_to_le(bp->tdata3);

	ret = sbi_ecall(SBI_EXT_DBTR, SBI_EXT_DBTR_TRIG_INSTALL,
			1, 0, 0, 0, 0, 0);

	if (ret.error) {
		pr_warn("Failed to install trigger\n");
		err = sbi_err_map_linux_errno(ret.error);
		goto done;
	}

	idx = le_to_cpu(recv->idx);
	if (idx >= dbtr_total_num) {
		pr_warn("Invalid trigger index %lu\n", idx);
		ret = dbtr_uninstall_trigger_locked(idx);
		if (ret.error)
			pr_warn("Failed to unwind trigger %lu. error: %ld\n",
				idx, ret.error);
		err = -EINVAL;
		goto done;
	}

	slot = this_cpu_ptr(&pcpu_hw_bp_events[idx]);
	if (*slot) {
		pr_warn("Slot %lu is in use\n", idx);
		ret = dbtr_uninstall_trigger_locked(idx);
		if (ret.error)
			pr_warn("Failed to unwind trigger %lu. error: %ld\n",
				idx, ret.error);
		err = -EBUSY;
		goto done;
	}

	/* Save the event - to be looked up in handler */
	*slot = event;

done:
	raw_spin_unlock_irqrestore(this_cpu_ptr(&ecall_lock), flags);
	return err;
}

/* atomic: counter->ctx->lock is held */
void arch_uninstall_hw_breakpoint(struct perf_event *event)
{
	struct perf_event **slot = NULL;
	unsigned long flags;
	struct sbiret ret;
	int i;

	raw_spin_lock_irqsave(this_cpu_ptr(&ecall_lock), flags);

	for (i = 0; i < dbtr_total_num; i++) {
		struct perf_event **candidate;

		candidate = this_cpu_ptr(&pcpu_hw_bp_events[i]);
		if (*candidate == event) {
			slot = candidate;
			break;
		}
	}

	if (i == dbtr_total_num) {
		pr_warn("Breakpoint not installed.\n");
		goto out;
	}

	/*
	 * Keep the software slot populated until the hardware trigger is gone;
	 * otherwise a last debug exception would look unhandled.
	 */
	ret = dbtr_uninstall_trigger_locked(i);

	if (ret.error) {
		pr_warn("Failed to uninstall trigger %d.\n", i);
		goto out;
	}

	*slot = NULL;

 out:
	raw_spin_unlock_irqrestore(this_cpu_ptr(&ecall_lock), flags);
}

void arch_enable_hw_breakpoint(struct perf_event *event)
{
	struct sbiret ret;
	int i;
	struct perf_event **slot;
	unsigned long flags;

	raw_spin_lock_irqsave(this_cpu_ptr(&ecall_lock), flags);

	for (i = 0; i < dbtr_total_num; i++) {
		slot = this_cpu_ptr(&pcpu_hw_bp_events[i]);

		if (*slot == event)
			break;
	}

	if (i == dbtr_total_num) {
		pr_warn("Breakpoint not installed.\n");
		goto out;
	}

	ret = sbi_ecall(SBI_EXT_DBTR, SBI_EXT_DBTR_TRIG_ENABLE,
			i, 1, 0, 0, 0, 0);

	if (ret.error) {
		pr_warn("Failed to install trigger %d\n", i);
		goto out;
	}

 out:
	raw_spin_unlock_irqrestore(this_cpu_ptr(&ecall_lock), flags);
}
EXPORT_SYMBOL_GPL(arch_enable_hw_breakpoint);

void arch_update_hw_breakpoint(struct perf_event *event)
{
	struct arch_hw_breakpoint *bp = counter_arch_bp(event);
	int ret;

	ret = dbtr_update_event_tdata(event, bp->tdata1, bp->tdata2, bp->tdata3,
				      true);
	if (ret)
		pr_warn("Failed to update trigger. error: %d\n", ret);
}
EXPORT_SYMBOL_GPL(arch_update_hw_breakpoint);

void arch_disable_hw_breakpoint(struct perf_event *event)
{
	struct perf_event **slot;
	struct sbiret ret;
	int i;

	for (i = 0; i < dbtr_total_num; i++) {
		slot = this_cpu_ptr(&pcpu_hw_bp_events[i]);

		if (*slot == event)
			break;
	}

	if (i == dbtr_total_num) {
		pr_warn("Breakpoint not installed.\n");
		return;
	}

	ret = sbi_ecall(SBI_EXT_DBTR, SBI_EXT_DBTR_TRIG_DISABLE,
			i, 1, 0, 0, 0, 0);

	if (ret.error) {
		pr_warn("Failed to uninstall trigger %d.\n", i);
		return;
	}
}
EXPORT_SYMBOL_GPL(arch_disable_hw_breakpoint);

void hw_breakpoint_pmu_read(struct perf_event *bp) { }

static int __init arch_hw_breakpoint_init(void)
{
	unsigned int cpu;
	int rc = 0;

	for_each_possible_cpu(cpu)
		raw_spin_lock_init(&per_cpu(ecall_lock, cpu));

	init_sbi_dbtr();

	if (dbtr_total_num) {
		pr_info("Total number of type %d triggers: %u\n",
			dbtr_type, dbtr_total_num);
	} else {
		pr_info("No hardware triggers available\n");
		goto out;
	}

	/* Allocate per-cpu shared memory */
	sbi_dbtr_shmem = __alloc_percpu(sizeof(*sbi_dbtr_shmem) * dbtr_total_num,
					PAGE_SIZE);

	if (!sbi_dbtr_shmem) {
		pr_warn("Failed to allocate shared memory.\n");
		rc = -ENOMEM;
		goto out;
	}

	/* Hotplug handler to register/unregister shared memory with SBI */
	rc = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN,
			       "riscv/hw_breakpoint:prepare",
			       arch_smp_setup_sbi_shmem,
			       arch_smp_teardown_sbi_shmem);

	if (rc < 0) {
		pr_warn("Failed to setup CPU hotplug state\n");
		free_percpu(sbi_dbtr_shmem);
		sbi_dbtr_shmem = NULL;
		dbtr_total_num = 0;
		dbtr_type = RISCV_DBTR_TRIG_NONE;
		return rc;
	}
	rc = 0;
 out:
	return rc;
}
arch_initcall(arch_hw_breakpoint_init);
