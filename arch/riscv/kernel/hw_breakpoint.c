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
#include <linux/cpu.h>
#include <linux/cpuhotplug.h>

#include <asm/sbi.h>

/* Registered per-cpu bp/wp */
static DEFINE_PER_CPU(struct perf_event *, pcpu_hw_bp_events[RISCV_HW_BP_NUM_MAX]);
static DEFINE_PER_CPU(unsigned long, ecall_lock_flags);
static DEFINE_PER_CPU(raw_spinlock_t, ecall_lock);

/* Per-cpu shared memory between S and M mode */
static union sbi_dbtr_shmem_entry __percpu *sbi_dbtr_shmem;

/* number of debug triggers on this cpu . */
static int dbtr_total_num __ro_after_init;
static int dbtr_type __ro_after_init;
static int dbtr_init __ro_after_init;

#define MEM_HI(_m)	((unsigned long)upper_32_bits(_m))
#define MEM_LO(_m)	((unsigned long)lower_32_bits(_m))

static int arch_smp_setup_sbi_shmem(unsigned int cpu)
{
	union sbi_dbtr_shmem_entry *dbtr_shmem;
	phys_addr_t shmem_pa;
	struct sbiret ret;

	dbtr_shmem = per_cpu_ptr(sbi_dbtr_shmem, cpu);
	if (!dbtr_shmem) {
		pr_err("Invalid per-cpu shared memory for debug triggers\n");
		return -ENODEV;
	}

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

	if (sbi_probe_extension(SBI_EXT_DBTR) <= 0) {
		pr_warn("SBI_EXT_DBTR is not supported\n");
		dbtr_total_num = 0;
		goto done;
	}

	ret = sbi_ecall(SBI_EXT_DBTR, SBI_EXT_DBTR_NUM_TRIGGERS,
			0, 0, 0, 0, 0, 0);
	if (ret.error) {
		pr_warn("Failed to detect triggers\n");
		dbtr_total_num = 0;
		goto done;
	}

	tdata1 = 0;
	tdata1 = RISCV_DBTR_SET_TDATA1_TYPE(tdata1, RISCV_DBTR_TRIG_MCONTROL6);

	ret = sbi_ecall(SBI_EXT_DBTR, SBI_EXT_DBTR_NUM_TRIGGERS,
			tdata1, 0, 0, 0, 0, 0);
	if (ret.error) {
		pr_warn("Failed to detect mcontrol6 triggers\n");
	} else if (!ret.value) {
		pr_warn("Type 6 triggers not available\n");
	} else {
		dbtr_total_num = ret.value;
		dbtr_type = RISCV_DBTR_TRIG_MCONTROL6;
		pr_warn("Mcontrol6 trigger available.\n");
		goto done;
	}

	/* fallback to type 2 triggers if type 6 is not available */

	tdata1 = 0;
	tdata1 = RISCV_DBTR_SET_TDATA1_TYPE(tdata1, RISCV_DBTR_TRIG_MCONTROL);

	ret = sbi_ecall(SBI_EXT_DBTR, SBI_EXT_DBTR_NUM_TRIGGERS,
			tdata1, 0, 0, 0, 0, 0);
	if (ret.error) {
		pr_warn("Failed to detect mcontrol triggers\n");
	} else if (!ret.value) {
		pr_warn("Type 2 triggers not available\n");
	} else {
		dbtr_total_num = ret.value;
		dbtr_type = RISCV_DBTR_TRIG_MCONTROL;
		goto done;
	}

done:
	dbtr_init = 1;
}

int hw_breakpoint_slots(int type)
{
	/*
	 * We can be called early, so don't rely on
	 * static variables being initialised.
	 */

	if (!dbtr_init)
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
				    struct arch_hw_breakpoint *hw)
{
	switch (attr->bp_type) {
	case HW_BREAKPOINT_X:
		hw->type = RISCV_DBTR_EXEC;
		RISCV_DBTR_SET_MC_EXEC_BIT(hw->tdata1);
		break;
	case HW_BREAKPOINT_R:
		hw->type = RISCV_DBTR_LOAD;
		RISCV_DBTR_SET_MC_LOAD_BIT(hw->tdata1);
		break;
	case HW_BREAKPOINT_W:
		hw->type = RISCV_DBTR_STORE;
		RISCV_DBTR_SET_MC_STORE_BIT(hw->tdata1);
		break;
	case HW_BREAKPOINT_RW:
		hw->type = RISCV_DBTR_LDST;
		RISCV_DBTR_SET_MC_LOAD_BIT(hw->tdata1);
		RISCV_DBTR_SET_MC_STORE_BIT(hw->tdata1);
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
		hw->tdata1 = RISCV_DBTR_SET_MC_SIZELO(hw->tdata1, 0);
		hw->tdata1 = RISCV_DBTR_SET_MC_SIZEHI(hw->tdata1, 0);
	} else {
		switch (attr->bp_len) {
		case HW_BREAKPOINT_LEN_1:
			hw->len = 1;
			hw->tdata1 = RISCV_DBTR_SET_MC_SIZELO(hw->tdata1, 1);
			break;
		case HW_BREAKPOINT_LEN_2:
			hw->len = 2;
			hw->tdata1 = RISCV_DBTR_SET_MC_SIZELO(hw->tdata1, 2);
			break;
		case HW_BREAKPOINT_LEN_4:
			hw->len = 4;
			hw->tdata1 = RISCV_DBTR_SET_MC_SIZELO(hw->tdata1, 3);
			break;
#if __riscv_xlen >= 64
		case HW_BREAKPOINT_LEN_8:
			hw->len = 8;
			hw->tdata1 = RISCV_DBTR_SET_MC_SIZELO(hw->tdata1, 1);
			hw->tdata1 = RISCV_DBTR_SET_MC_SIZEHI(hw->tdata1, 1);
			break;
#endif
		/* Set to match any size */
		default:
			hw->len = 0;
			hw->tdata1 = RISCV_DBTR_SET_MC_SIZELO(hw->tdata1, 0);
			hw->tdata1 = RISCV_DBTR_SET_MC_SIZEHI(hw->tdata1, 0);
			break;
		}
	}

	hw->tdata1 = RISCV_DBTR_SET_MC_TYPE(hw->tdata1, RISCV_DBTR_TRIG_MCONTROL);

	CLEAR_DBTR_BIT(hw->tdata1, RISCV_DBTR_MC_DMODE_BIT);
	CLEAR_DBTR_BIT(hw->tdata1, RISCV_DBTR_MC_TIMING_BIT);
	CLEAR_DBTR_BIT(hw->tdata1, RISCV_DBTR_MC_SELECT_BIT);
	CLEAR_DBTR_BIT(hw->tdata1, RISCV_DBTR_MC_ACTION_BIT);
	CLEAR_DBTR_BIT(hw->tdata1, RISCV_DBTR_MC_CHAIN_BIT);
	CLEAR_DBTR_BIT(hw->tdata1, RISCV_DBTR_MC_MATCH_BIT);
	CLEAR_DBTR_BIT(hw->tdata1, RISCV_DBTR_MC_M_BIT);

	SET_DBTR_BIT(hw->tdata1, RISCV_DBTR_MC_S_BIT);
	SET_DBTR_BIT(hw->tdata1, RISCV_DBTR_MC_U_BIT);

	return 0;
}

static int rv_init_mcontrol6_trigger(const struct perf_event_attr *attr,
				     struct arch_hw_breakpoint *hw)
{
	switch (attr->bp_type) {
	case HW_BREAKPOINT_X:
		hw->type = RISCV_DBTR_EXEC;
		RISCV_DBTR_SET_MC6_EXEC_BIT(hw->tdata1);
		break;
	case HW_BREAKPOINT_R:
		hw->type = RISCV_DBTR_LOAD;
		RISCV_DBTR_SET_MC6_LOAD_BIT(hw->tdata1);
		break;
	case HW_BREAKPOINT_W:
		hw->type = RISCV_DBTR_STORE;
		RISCV_DBTR_SET_MC6_STORE_BIT(hw->tdata1);
		break;
	case HW_BREAKPOINT_RW:
		hw->type = RISCV_DBTR_LDST;
		RISCV_DBTR_SET_MC6_STORE_BIT(hw->tdata1);
		RISCV_DBTR_SET_MC6_LOAD_BIT(hw->tdata1);
		break;
	default:
		return -EINVAL;
	}

	if (attr->bp_type == HW_BREAKPOINT_X) {
		/* See rv_init_mcontrol_trigger() for rationale. */
		hw->len = 0;
		hw->tdata1 = RISCV_DBTR_SET_MC6_SIZE(hw->tdata1, 0);
	} else {
		switch (attr->bp_len) {
		case HW_BREAKPOINT_LEN_1:
			hw->len = 1;
			hw->tdata1 = RISCV_DBTR_SET_MC6_SIZE(hw->tdata1, 1);
			break;
		case HW_BREAKPOINT_LEN_2:
			hw->len = 2;
			hw->tdata1 = RISCV_DBTR_SET_MC6_SIZE(hw->tdata1, 2);
			break;
		case HW_BREAKPOINT_LEN_4:
			hw->len = 4;
			hw->tdata1 = RISCV_DBTR_SET_MC6_SIZE(hw->tdata1, 3);
			break;
#if __riscv_xlen >= 64
		case HW_BREAKPOINT_LEN_8:
			hw->len = 8;
			hw->tdata1 = RISCV_DBTR_SET_MC6_SIZE(hw->tdata1, 5);
			break;
#endif
		/* Set to match any size */
		default:
			hw->len = 0;
			hw->tdata1 = RISCV_DBTR_SET_MC6_SIZE(hw->tdata1, 0);
		}
	}

	hw->tdata1 = RISCV_DBTR_SET_MC6_TYPE(hw->tdata1, RISCV_DBTR_TRIG_MCONTROL6);

	CLEAR_DBTR_BIT(hw->tdata1, RISCV_DBTR_MC6_DMODE_BIT);
	CLEAR_DBTR_BIT(hw->tdata1, RISCV_DBTR_MC6_TIMING_BIT);
	CLEAR_DBTR_BIT(hw->tdata1, RISCV_DBTR_MC6_SELECT_BIT);
	CLEAR_DBTR_BIT(hw->tdata1, RISCV_DBTR_MC6_ACTION_BIT);
	CLEAR_DBTR_BIT(hw->tdata1, RISCV_DBTR_MC6_CHAIN_BIT);
	CLEAR_DBTR_BIT(hw->tdata1, RISCV_DBTR_MC6_MATCH_BIT);
	CLEAR_DBTR_BIT(hw->tdata1, RISCV_DBTR_MC6_M_BIT);
	CLEAR_DBTR_BIT(hw->tdata1, RISCV_DBTR_MC6_VS_BIT);
	CLEAR_DBTR_BIT(hw->tdata1, RISCV_DBTR_MC6_VU_BIT);

	SET_DBTR_BIT(hw->tdata1, RISCV_DBTR_MC6_S_BIT);
	SET_DBTR_BIT(hw->tdata1, RISCV_DBTR_MC6_U_BIT);

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

/*
 * HW Breakpoint/watchpoint handler
 */
static int hw_breakpoint_handler(struct die_args *args)
{
	int ret = NOTIFY_DONE;
	struct arch_hw_breakpoint *bp;
	struct perf_event *event;
	int i;

	for (i = 0; i < dbtr_total_num; i++) {
		event = this_cpu_read(pcpu_hw_bp_events[i]);
		if (!event)
			continue;

		bp = counter_arch_bp(event);
		switch (bp->type) {
		/* Breakpoint */
		case RISCV_DBTR_EXEC:
			if (bp->address == args->regs->epc) {
				perf_bp_event(event, args->regs);
				ret = NOTIFY_STOP;
			}
			break;

		/* Watchpoint */
		case RISCV_DBTR_LOAD:
		case RISCV_DBTR_STORE:
		case RISCV_DBTR_LDST:
		{
			unsigned long stval = args->regs->badaddr;
			unsigned long bp_start = bp->address;
			unsigned long bp_len = bp->len ?: 1;
			unsigned long bp_end = bp_start + bp_len - 1;
			unsigned long stval_end = stval + sizeof(long) - 1;
			unsigned long tdata1;
			bool hit = false;
			struct sbiret sret;
			union sbi_dbtr_shmem_entry *shmem;

			if (bp_end < bp_start)
				bp_end = ~0UL;
			if (stval_end < stval)
				stval_end = ~0UL;

			/*
			 * Prefer tdata1.hit from SBI trigger readout whenever
			 * possible. Fall back to address-based matching if HIT
			 * isn't observed/supported.
			 */
			raw_spin_lock_irqsave(this_cpu_ptr(&ecall_lock),
					      *this_cpu_ptr(&ecall_lock_flags));
			shmem = this_cpu_ptr(sbi_dbtr_shmem);
			sret = sbi_ecall(SBI_EXT_DBTR, SBI_EXT_DBTR_TRIG_READ,
					 i, 1, 0, 0, 0, 0);
			if (!sret.error) {
				tdata1 = le_to_cpu(shmem->data.tdata1);

				if (dbtr_type == RISCV_DBTR_TRIG_MCONTROL)
					hit = !!(tdata1 & RISCV_DBTR_MC_HIT_BIT_MASK);
				else if (dbtr_type == RISCV_DBTR_TRIG_MCONTROL6)
					hit = !!(tdata1 & RISCV_DBTR_MC6_HIT_BIT_MASK);
			}
			raw_spin_unlock_irqrestore(this_cpu_ptr(&ecall_lock),
						   *this_cpu_ptr(&ecall_lock_flags));

			/*
			 * Sdtrig may report STVAL as the lowest accessed
			 * address while the watchpoint can match a higher byte
			 * in the same access.
			 */
			if (hit ||
			    (stval >= bp_start && stval <= bp_end) ||
			    (bp_start >= stval && bp_start <= stval_end)) {
				perf_bp_event(event, args->regs);
				ret = NOTIFY_STOP;
			}
			break;
		}

		default:
			pr_warn("Unknown type: %u\n", bp->type);
			break;
		}
	}

	return ret;
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
		pr_warn("Failed to install trigger\n");
		err = sbi_err_map_linux_errno(ret.error);
		goto done;
	}

	idx = le_to_cpu(recv->idx);
	if (idx >= dbtr_total_num) {
		pr_warn("Invalid trigger index %lu\n", idx);
		err = -EINVAL;
		goto done;
	}

	slot = this_cpu_ptr(&pcpu_hw_bp_events[idx]);
	if (*slot) {
		pr_warn("Slot %lu is in use\n", idx);
		err = -EBUSY;
		goto done;
	}

	/* Save the event - to be looked up in handler */
	*slot = event;

done:
	raw_spin_unlock_irqrestore(this_cpu_ptr(&ecall_lock),
				   *this_cpu_ptr(&ecall_lock_flags));
	return err;
}

/* atomic: counter->ctx->lock is held */
void arch_uninstall_hw_breakpoint(struct perf_event *event)
{
	struct sbiret ret;
	int i;

	raw_spin_lock_irqsave(this_cpu_ptr(&ecall_lock),
			      *this_cpu_ptr(&ecall_lock_flags));

	for (i = 0; i < dbtr_total_num; i++) {
		struct perf_event **slot = this_cpu_ptr(&pcpu_hw_bp_events[i]);

		if (*slot == event) {
			*slot = NULL;
			break;
		}
	}

	if (i == dbtr_total_num) {
		pr_warn("Breakpoint not installed.\n");
		goto out;
	}

	ret = sbi_ecall(SBI_EXT_DBTR, SBI_EXT_DBTR_TRIG_UNINSTALL,
			i, 1, 0, 0, 0, 0);

	if (ret.error) {
		pr_warn("Failed to uninstall trigger %d.\n", i);
		goto out;
	}

 out:
	raw_spin_unlock_irqrestore(this_cpu_ptr(&ecall_lock),
				   *this_cpu_ptr(&ecall_lock_flags));
}

void arch_enable_hw_breakpoint(struct perf_event *event)
{
	struct sbiret ret;
	int i;
	struct perf_event **slot;

	raw_spin_lock_irqsave(this_cpu_ptr(&ecall_lock),
			      *this_cpu_ptr(&ecall_lock_flags));

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
	raw_spin_unlock_irqrestore(this_cpu_ptr(&ecall_lock),
				   *this_cpu_ptr(&ecall_lock_flags));
}
EXPORT_SYMBOL_GPL(arch_enable_hw_breakpoint);

void arch_update_hw_breakpoint(struct perf_event *event)
{
	struct arch_hw_breakpoint *bp = counter_arch_bp(event);
	union sbi_dbtr_shmem_entry *shmem = this_cpu_ptr(sbi_dbtr_shmem);
	struct sbi_dbtr_data_msg *xmit;
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

	raw_spin_lock_irqsave(this_cpu_ptr(&ecall_lock),
			      *this_cpu_ptr(&ecall_lock_flags));

	xmit = &shmem->data;
	xmit->tdata1 = cpu_to_le(bp->tdata1);
	xmit->tdata2 = cpu_to_le(bp->tdata2);
	xmit->tdata3 = cpu_to_le(bp->tdata3);

	ret = sbi_ecall(SBI_EXT_DBTR, SBI_EXT_DBTR_TRIG_UPDATE,
			i, 1, 0, 0, 0, 0);
	if (ret.error)
		pr_warn("Failed to update trigger %d.\n", i);

	raw_spin_unlock_irqrestore(this_cpu_ptr(&ecall_lock),
				   *this_cpu_ptr(&ecall_lock_flags));
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

void flush_ptrace_hw_breakpoint(struct task_struct *tsk) { }

static int __init arch_hw_breakpoint_init(void)
{
	unsigned int cpu;
	int rc = 0;

	for_each_possible_cpu(cpu)
		raw_spin_lock_init(&per_cpu(ecall_lock, cpu));

	if (!dbtr_init)
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
		return rc;
	}
 out:
	return rc;
}
arch_initcall(arch_hw_breakpoint_init);
