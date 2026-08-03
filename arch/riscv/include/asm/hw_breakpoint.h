/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2026 Qualcomm Technologies, Inc.
 */

#ifndef __RISCV_HW_BREAKPOINT_H
#define __RISCV_HW_BREAKPOINT_H

struct task_struct;

#ifdef CONFIG_HAVE_HW_BREAKPOINT

#include <uapi/linux/hw_breakpoint.h>

/* Maximum number of hardware breakpoints supported */
#define RISCV_HW_BP_NUM_MAX 32
#define RISCV_MAX_BP		16

#if __riscv_xlen == 64
#define cpu_to_le cpu_to_le64
#define le_to_cpu le64_to_cpu
#elif __riscv_xlen == 32
#define cpu_to_le cpu_to_le32
#define le_to_cpu le32_to_cpu
#else
#error "Unexpected __riscv_xlen"
#endif

#define CLEAR_DBTR_BIT(_target, _bit)	((_target) &= ~BIT(_bit))
#define SET_DBTR_BIT(_target, _bit)	((_target) |= BIT(_bit))

#define RISCV_DBTR_EXEC		BIT(0)
#define RISCV_DBTR_LOAD		BIT(1)
#define RISCV_DBTR_STORE	BIT(2)
#define RISCV_DBTR_LDST		(RISCV_DBTR_LOAD | RISCV_DBTR_STORE)

enum {
	RISCV_DBTR_TRIG_NONE = 0,
	RISCV_DBTR_TRIG_LEGACY,
	RISCV_DBTR_TRIG_MCONTROL,
	RISCV_DBTR_TRIG_ICOUNT,
	RISCV_DBTR_TRIG_ITRIGGER,
	RISCV_DBTR_TRIG_ETRIGGER,
	RISCV_DBTR_TRIG_MCONTROL6,
};

/* Trigger Data 1 */
#define RISCV_DBTR_TDATA1_DATA_BIT	0
#if __riscv_xlen == 64
#define RISCV_DBTR_TDATA1_DMODE_BIT	59
#define RISCV_DBTR_TDATA1_TYPE_BIT	60
#elif __riscv_xlen == 32
#define RISCV_DBTR_TDATA1_DMODE_BIT	27
#define RISCV_DBTR_TDATA1_TYPE_BIT	28
#else
#error "Unknown __riscv_xlen"
#endif

#if __riscv_xlen == 64
#define RISCV_DBTR_TDATA1_DATA_BIT_MASK		GENMASK(58, RISCV_DBTR_TDATA1_DATA_BIT)
#elif __riscv_xlen == 32
#define RISCV_DBTR_TDATA1_DATA_BIT_MASK		GENMASK(26, RISCV_DBTR_TDATA1_DATA_BIT)
#else
#error "Unknown __riscv_xlen"
#endif
#define RISCV_DBTR_TDATA1_DMODE_BIT_MASK	BIT(RISCV_DBTR_TDATA1_DMODE_BIT)
#define RISCV_DBTR_TDATA1_TYPE_BIT_MASK		\
	GENMASK(RISCV_DBTR_TDATA1_TYPE_BIT + 3, RISCV_DBTR_TDATA1_TYPE_BIT)

/* MC - Match Control Type Register */
#define RISCV_DBTR_MC_LOAD_BIT		0
#define RISCV_DBTR_MC_STORE_BIT		1
#define RISCV_DBTR_MC_EXEC_BIT		2
#define RISCV_DBTR_MC_U_BIT		3
#define RISCV_DBTR_MC_S_BIT		4
#define RISCV_DBTR_MC_RES2_BIT		5
#define RISCV_DBTR_MC_M_BIT		6
#define RISCV_DBTR_MC_MATCH_BIT		7
#define RISCV_DBTR_MC_CHAIN_BIT		11
#define RISCV_DBTR_MC_ACTION_BIT	12
#define RISCV_DBTR_MC_SIZELO_BIT	16
#define RISCV_DBTR_MC_TIMING_BIT	18
#define RISCV_DBTR_MC_SELECT_BIT	19
#define RISCV_DBTR_MC_HIT_BIT		20
#if __riscv_xlen >= 64
#define RISCV_DBTR_MC_SIZEHI_BIT	21
#endif
#if __riscv_xlen == 64
#define RISCV_DBTR_MC_MASKMAX_BIT	53
#define RISCV_DBTR_MC_DMODE_BIT		59
#define RISCV_DBTR_MC_TYPE_BIT		60
#elif __riscv_xlen == 32
#define RISCV_DBTR_MC_MASKMAX_BIT	21
#define RISCV_DBTR_MC_DMODE_BIT		27
#define RISCV_DBTR_MC_TYPE_BIT		28
#else
#error "Unknown riscv xlen"
#endif

#define RISCV_DBTR_MC_LOAD_BIT_MASK	BIT(RISCV_DBTR_MC_LOAD_BIT)
#define RISCV_DBTR_MC_STORE_BIT_MASK	BIT(RISCV_DBTR_MC_STORE_BIT)
#define RISCV_DBTR_MC_EXEC_BIT_MASK	BIT(RISCV_DBTR_MC_EXEC_BIT)
#define RISCV_DBTR_MC_U_BIT_MASK	BIT(RISCV_DBTR_MC_U_BIT)
#define RISCV_DBTR_MC_S_BIT_MASK	BIT(RISCV_DBTR_MC_S_BIT)
#define RISCV_DBTR_MC_RES2_BIT_MASK	BIT(RISCV_DBTR_MC_RES2_BIT)
#define RISCV_DBTR_MC_M_BIT_MASK	BIT(RISCV_DBTR_MC_M_BIT)
#define RISCV_DBTR_MC_MATCH_BIT_MASK	\
	GENMASK(RISCV_DBTR_MC_MATCH_BIT + 3, RISCV_DBTR_MC_MATCH_BIT)
#define RISCV_DBTR_MC_CHAIN_BIT_MASK	BIT(RISCV_DBTR_MC_CHAIN_BIT)
#define RISCV_DBTR_MC_ACTION_BIT_MASK	\
	GENMASK(RISCV_DBTR_MC_ACTION_BIT + 3, RISCV_DBTR_MC_ACTION_BIT)
#define RISCV_DBTR_MC_SIZELO_BIT_MASK	\
	GENMASK(RISCV_DBTR_MC_SIZELO_BIT + 1, RISCV_DBTR_MC_SIZELO_BIT)
#define RISCV_DBTR_MC_TIMING_BIT_MASK	BIT(RISCV_DBTR_MC_TIMING_BIT)
#define RISCV_DBTR_MC_SELECT_BIT_MASK	BIT(RISCV_DBTR_MC_SELECT_BIT)
#define RISCV_DBTR_MC_HIT_BIT_MASK	BIT(RISCV_DBTR_MC_HIT_BIT)
#if __riscv_xlen >= 64
#define RISCV_DBTR_MC_SIZEHI_BIT_MASK	\
	GENMASK(RISCV_DBTR_MC_SIZEHI_BIT + 1, RISCV_DBTR_MC_SIZEHI_BIT)
#endif
#define RISCV_DBTR_MC_MASKMAX_BIT_MASK	\
	GENMASK(RISCV_DBTR_MC_MASKMAX_BIT + 5, RISCV_DBTR_MC_MASKMAX_BIT)
#define RISCV_DBTR_MC_DMODE_BIT_MASK	BIT(RISCV_DBTR_MC_DMODE_BIT)
#define RISCV_DBTR_MC_TYPE_BIT_MASK	GENMASK(RISCV_DBTR_MC_TYPE_BIT + 3, RISCV_DBTR_MC_TYPE_BIT)

/* MC6 - Match Control 6 Type Register */
#define RISCV_DBTR_MC6_LOAD_BIT		0
#define RISCV_DBTR_MC6_STORE_BIT	1
#define RISCV_DBTR_MC6_EXEC_BIT		2
#define RISCV_DBTR_MC6_U_BIT		3
#define RISCV_DBTR_MC6_S_BIT		4
#define RISCV_DBTR_MC6_RES2_BIT		5
#define RISCV_DBTR_MC6_M_BIT		6
#define RISCV_DBTR_MC6_MATCH_BIT	7
#define RISCV_DBTR_MC6_CHAIN_BIT	11
#define RISCV_DBTR_MC6_ACTION_BIT	12
#define RISCV_DBTR_MC6_SIZE_BIT		16
#define RISCV_DBTR_MC6_TIMING_BIT	20
#define RISCV_DBTR_MC6_SELECT_BIT	21
#define RISCV_DBTR_MC6_HIT_BIT		22
#define RISCV_DBTR_MC6_VU_BIT		23
#define RISCV_DBTR_MC6_VS_BIT		24
#if __riscv_xlen == 64
#define RISCV_DBTR_MC6_DMODE_BIT	59
#define RISCV_DBTR_MC6_TYPE_BIT		60
#elif __riscv_xlen == 32
#define RISCV_DBTR_MC6_DMODE_BIT	27
#define RISCV_DBTR_MC6_TYPE_BIT		28
#else
#error "Unknown riscv xlen"
#endif

#define RISCV_DBTR_MC6_LOAD_BIT_MASK	BIT(RISCV_DBTR_MC6_LOAD_BIT)
#define RISCV_DBTR_MC6_STORE_BIT_MASK	BIT(RISCV_DBTR_MC6_STORE_BIT)
#define RISCV_DBTR_MC6_EXEC_BIT_MASK	BIT(RISCV_DBTR_MC6_EXEC_BIT)
#define RISCV_DBTR_MC6_U_BIT_MASK	BIT(RISCV_DBTR_MC6_U_BIT)
#define RISCV_DBTR_MC6_S_BIT_MASK	BIT(RISCV_DBTR_MC6_S_BIT)
#define RISCV_DBTR_MC6_RES2_BIT_MASK	BIT(RISCV_DBTR_MC6_RES2_BIT)
#define RISCV_DBTR_MC6_M_BIT_MASK	BIT(RISCV_DBTR_MC6_M_BIT)
#define RISCV_DBTR_MC6_MATCH_BIT_MASK	\
	GENMASK(RISCV_DBTR_MC6_MATCH_BIT + 3, RISCV_DBTR_MC6_MATCH_BIT)
#define RISCV_DBTR_MC6_CHAIN_BIT_MASK	BIT(RISCV_DBTR_MC6_CHAIN_BIT)
#define RISCV_DBTR_MC6_ACTION_BIT_MASK	\
	GENMASK(RISCV_DBTR_MC6_ACTION_BIT + 3, RISCV_DBTR_MC6_ACTION_BIT)
#define RISCV_DBTR_MC6_SIZE_BIT_MASK	\
	GENMASK(RISCV_DBTR_MC6_SIZE_BIT + 3, RISCV_DBTR_MC6_SIZE_BIT)
#define RISCV_DBTR_MC6_TIMING_BIT_MASK	BIT(RISCV_DBTR_MC6_TIMING_BIT)
#define RISCV_DBTR_MC6_SELECT_BIT_MASK	BIT(RISCV_DBTR_MC6_SELECT_BIT)
#define RISCV_DBTR_MC6_HIT_BIT_MASK	BIT(RISCV_DBTR_MC6_HIT_BIT)
#define RISCV_DBTR_MC6_VU_BIT_MASK	BIT(RISCV_DBTR_MC6_VU_BIT)
#define RISCV_DBTR_MC6_VS_BIT_MASK	BIT(RISCV_DBTR_MC6_VS_BIT)
#define RISCV_DBTR_MC6_DMODE_BIT_MASK	BIT(RISCV_DBTR_MC6_DMODE_BIT)
#define RISCV_DBTR_MC6_TYPE_BIT_MASK	\
	GENMASK(RISCV_DBTR_MC6_TYPE_BIT + 3, RISCV_DBTR_MC6_TYPE_BIT)

#define RISCV_DBTR_SET_TDATA1_TYPE(_t1, _type)				\
	({								\
		typeof(_t1) (td1t1) = (_t1);				\
		(td1t1) &= ~RISCV_DBTR_TDATA1_TYPE_BIT_MASK;		\
		(td1t1) |= (((unsigned long)(_type)			\
			     << RISCV_DBTR_TDATA1_TYPE_BIT)		\
			    & RISCV_DBTR_TDATA1_TYPE_BIT_MASK);		\
		(td1t1);						\
	})

#define RISCV_DBTR_SET_MC_TYPE(_t1, _type)				\
	({								\
		typeof(_t1) (mct1) = (_t1);				\
		(mct1) &= ~RISCV_DBTR_MC_TYPE_BIT_MASK;			\
		(mct1) |= (((unsigned long)(_type)			\
			    << RISCV_DBTR_MC_TYPE_BIT)			\
			   & RISCV_DBTR_MC_TYPE_BIT_MASK);		\
		(mct1);							\
	})

#define RISCV_DBTR_SET_MC6_TYPE(_t1, _type)				\
	({								\
		typeof(_t1) (mc6t1) = (_t1);				\
		(mc6t1) &= ~RISCV_DBTR_MC6_TYPE_BIT_MASK;		\
		(mc6t1) |= (((unsigned long)(_type)			\
			     << RISCV_DBTR_MC6_TYPE_BIT)		\
			    & RISCV_DBTR_MC6_TYPE_BIT_MASK);		\
		(mc6t1);						\
	})

#define RISCV_DBTR_SET_MC_EXEC_BIT(_t1)			\
	SET_DBTR_BIT(_t1, RISCV_DBTR_MC_EXEC_BIT)

#define RISCV_DBTR_SET_MC_LOAD_BIT(_t1)			\
	SET_DBTR_BIT(_t1, RISCV_DBTR_MC_LOAD_BIT)

#define RISCV_DBTR_SET_MC_STORE_BIT(_t1)		\
	SET_DBTR_BIT(_t1, RISCV_DBTR_MC_STORE_BIT)

#define RISCV_DBTR_SET_MC_SIZELO(_t1, _val)				\
	({								\
		typeof(_t1) (mcslt1) = (_t1);				\
		mcslt1 &= ~RISCV_DBTR_MC_SIZELO_BIT_MASK;		\
		mcslt1 |= (((_val) << RISCV_DBTR_MC_SIZELO_BIT)		\
			   & RISCV_DBTR_MC_SIZELO_BIT_MASK);		\
		(mcslt1);						\
	})

#if __riscv_xlen >= 64
#define RISCV_DBTR_SET_MC_SIZEHI(_t1, _val)				\
	({								\
		typeof(_t1) (mcsht1) = (_t1);				\
		mcsht1 &= ~RISCV_DBTR_MC_SIZEHI_BIT_MASK;		\
		mcsht1 |= (((_val) << RISCV_DBTR_MC_SIZEHI_BIT)		\
			   & RISCV_DBTR_MC_SIZEHI_BIT_MASK);		\
		(mcsht1);						\
	})
#else
/* SIZEHI does not exist in the rv32 mcontrol layout; nothing to set. */
#define RISCV_DBTR_SET_MC_SIZEHI(_t1, _val) ((void)(_val), (_t1))
#endif

#define RISCV_DBTR_SET_MC6_EXEC_BIT(_t1)		\
	SET_DBTR_BIT(_t1, RISCV_DBTR_MC6_EXEC_BIT)

#define RISCV_DBTR_SET_MC6_LOAD_BIT(_t1)		\
	SET_DBTR_BIT(_t1, RISCV_DBTR_MC6_LOAD_BIT)

#define RISCV_DBTR_SET_MC6_STORE_BIT(_t1)		\
	SET_DBTR_BIT(_t1, RISCV_DBTR_MC6_STORE_BIT)

#define RISCV_DBTR_SET_MC6_SIZE(_t1, _val)				\
	({								\
		typeof(_t1) (mc6szt1) = (_t1);				\
		(mc6szt1) &= ~RISCV_DBTR_MC6_SIZE_BIT_MASK;		\
		(mc6szt1) |= (((_val) << RISCV_DBTR_MC6_SIZE_BIT)	\
			      & RISCV_DBTR_MC6_SIZE_BIT_MASK);		\
		(mc6szt1);						\
	})

struct arch_hw_breakpoint {
	unsigned long address;
	unsigned long len;
	unsigned int type;
	unsigned int match;
	unsigned int chain;
	unsigned int select;
	unsigned int time;

	/* Trigger configuration data */
	unsigned long tdata1;
	unsigned long tdata2;
	unsigned long tdata3;
};

struct perf_event_attr;
struct notifier_block;
struct perf_event;
struct pt_regs;

int hw_breakpoint_slots(int type);
int arch_check_bp_in_kernelspace(struct arch_hw_breakpoint *hw);
int hw_breakpoint_arch_parse(struct perf_event *bp,
			     const struct perf_event_attr *attr,
			     struct arch_hw_breakpoint *hw);
int hw_breakpoint_exceptions_notify(struct notifier_block *unused,
				    unsigned long val, void *data);

void arch_enable_hw_breakpoint(struct perf_event *bp);
void arch_update_hw_breakpoint(struct perf_event *bp);
void arch_disable_hw_breakpoint(struct perf_event *bp);
int arch_install_hw_breakpoint(struct perf_event *bp);
void arch_uninstall_hw_breakpoint(struct perf_event *bp);
void hw_breakpoint_pmu_read(struct perf_event *bp);
void clear_ptrace_hw_breakpoint(struct task_struct *tsk);
void flush_ptrace_hw_breakpoint(struct task_struct *tsk);
void ptrace_hw_copy_thread(struct task_struct *task);

#else

static inline void ptrace_hw_copy_thread(struct task_struct *task) { }

#endif /* CONFIG_HAVE_HW_BREAKPOINT */
#endif /* __RISCV_HW_BREAKPOINT_H */
