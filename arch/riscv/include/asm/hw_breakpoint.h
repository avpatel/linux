// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2024 Ventana Micro Systems Inc.
 */

#ifndef __RISCV_HW_BREAKPOINT_H
#define __RISCV_HW_BREAKPOINT_H

struct task_struct;

#ifdef CONFIG_HAVE_HW_BREAKPOINT

#include <uapi/linux/hw_breakpoint.h>

#if __riscv_xlen == 64
#define cpu_to_le cpu_to_le64
#define le_to_cpu le64_to_cpu
#elif __riscv_xlen == 32
#define cpu_to_le cpu_to_le32
#define le_to_cpu le32_to_cpu
#else
#error "Unexpected __riscv_xlen"
#endif

#define RV_DBTR_BIT(_prefix, _name)		\
	RV_DBTR_##_prefix##_##_name##_BIT

#define RV_DBTR_BIT_MASK(_prefix, _name)	\
	RV_DBTR_##_prefix##_name##_BIT_MASK

#define RV_DBTR_DECLARE_BIT(_prefix, _name, _val)	\
	RV_DBTR_BIT(_prefix, _name) = _val

#define RV_DBTR_DECLARE_BIT_MASK(_prefix, _name, _width)		\
	RV_DBTR_BIT_MASK(_prefix, _name) =				\
		(((1UL << _width) - 1) << RV_DBTR_BIT(_prefix, _name))

#define CLEAR_DBTR_BIT(_target, _prefix, _bit_name)	\
	__clear_bit(RV_DBTR_BIT(_prefix, _bit_name), &_target)

#define SET_DBTR_BIT(_target, _prefix, _bit_name)	\
	__set_bit(RV_DBTR_BIT(_prefix, _bit_name), &_target)

enum {
	RV_DBTR_BP	= 0,
	RV_DBTR_WP	= 1,
};

enum {
	RV_DBTR_TRIG_NONE = 0,
	RV_DBTR_TRIG_LEGACY,
	RV_DBTR_TRIG_MCONTROL,
	RV_DBTR_TRIG_ICOUNT,
	RV_DBTR_TRIG_ITRIGGER,
	RV_DBTR_TRIG_ETRIGGER,
	RV_DBTR_TRIG_MCONTROL6,
};

/* Trigger Data 1 */
enum {
	RV_DBTR_DECLARE_BIT(TDATA1, DATA,   0),
#if __riscv_xlen == 64
	RV_DBTR_DECLARE_BIT(TDATA1, DMODE,  59),
	RV_DBTR_DECLARE_BIT(TDATA1, TYPE,   60),
#elif __riscv_xlen == 32
	RV_DBTR_DECLARE_BIT(TDATA1, DMODE,  27),
	RV_DBTR_DECLARE_BIT(TDATA1, TYPE,   28),
#else
	#error "Unknown __riscv_xlen"
#endif
};

enum {
#if __riscv_xlen == 64
	RV_DBTR_DECLARE_BIT_MASK(TDATA1, DATA,  59),
#elif __riscv_xlen == 32
	RV_DBTR_DECLARE_BIT_MASK(TDATA1, DATA,  27),
#else
	#error "Unknown __riscv_xlen"
#endif
	RV_DBTR_DECLARE_BIT_MASK(TDATA1, DMODE, 1),
	RV_DBTR_DECLARE_BIT_MASK(TDATA1, TYPE,  4),
};

/* MC - Match Control Type Register */
enum {
	RV_DBTR_DECLARE_BIT(MC, LOAD,    0),
	RV_DBTR_DECLARE_BIT(MC, STORE,   1),
	RV_DBTR_DECLARE_BIT(MC, EXEC,    2),
	RV_DBTR_DECLARE_BIT(MC, U,       3),
	RV_DBTR_DECLARE_BIT(MC, S,       4),
	RV_DBTR_DECLARE_BIT(MC, RES2,    5),
	RV_DBTR_DECLARE_BIT(MC, M,       6),
	RV_DBTR_DECLARE_BIT(MC, MATCH,   7),
	RV_DBTR_DECLARE_BIT(MC, CHAIN,   11),
	RV_DBTR_DECLARE_BIT(MC, ACTION,  12),
	RV_DBTR_DECLARE_BIT(MC, SIZELO,  16),
	RV_DBTR_DECLARE_BIT(MC, TIMING,  18),
	RV_DBTR_DECLARE_BIT(MC, SELECT,  19),
	RV_DBTR_DECLARE_BIT(MC, HIT,     20),
#if __riscv_xlen >= 64
	RV_DBTR_DECLARE_BIT(MC, SIZEHI,  21),
#endif
#if __riscv_xlen == 64
	RV_DBTR_DECLARE_BIT(MC, MASKMAX, 53),
	RV_DBTR_DECLARE_BIT(MC, DMODE,   59),
	RV_DBTR_DECLARE_BIT(MC, TYPE,    60),
#elif __riscv_xlen == 32
	RV_DBTR_DECLARE_BIT(MC, MASKMAX, 21),
	RV_DBTR_DECLARE_BIT(MC, DMODE,   27),
	RV_DBTR_DECLARE_BIT(MC, TYPE,    28),
#else
	#error "Unknown riscv xlen"
#endif
};

enum {
	RV_DBTR_DECLARE_BIT_MASK(MC, LOAD,    1),
	RV_DBTR_DECLARE_BIT_MASK(MC, STORE,   1),
	RV_DBTR_DECLARE_BIT_MASK(MC, EXEC,    1),
	RV_DBTR_DECLARE_BIT_MASK(MC, U,       1),
	RV_DBTR_DECLARE_BIT_MASK(MC, S,       1),
	RV_DBTR_DECLARE_BIT_MASK(MC, RES2,    1),
	RV_DBTR_DECLARE_BIT_MASK(MC, M,       1),
	RV_DBTR_DECLARE_BIT_MASK(MC, MATCH,   4),
	RV_DBTR_DECLARE_BIT_MASK(MC, CHAIN,   1),
	RV_DBTR_DECLARE_BIT_MASK(MC, ACTION,  4),
	RV_DBTR_DECLARE_BIT_MASK(MC, SIZELO,  2),
	RV_DBTR_DECLARE_BIT_MASK(MC, TIMING,  1),
	RV_DBTR_DECLARE_BIT_MASK(MC, SELECT,  1),
	RV_DBTR_DECLARE_BIT_MASK(MC, HIT,     1),
#if __riscv_xlen >= 64
	RV_DBTR_DECLARE_BIT_MASK(MC, SIZEHI,  2),
#endif
	RV_DBTR_DECLARE_BIT_MASK(MC, MASKMAX, 6),
	RV_DBTR_DECLARE_BIT_MASK(MC, DMODE,   1),
	RV_DBTR_DECLARE_BIT_MASK(MC, TYPE,    4),
};

/* MC6 - Match Control 6 Type Register */
enum {
	RV_DBTR_DECLARE_BIT(MC6, LOAD,   0),
	RV_DBTR_DECLARE_BIT(MC6, STORE,  1),
	RV_DBTR_DECLARE_BIT(MC6, EXEC,   2),
	RV_DBTR_DECLARE_BIT(MC6, U,      3),
	RV_DBTR_DECLARE_BIT(MC6, S,      4),
	RV_DBTR_DECLARE_BIT(MC6, RES2,   5),
	RV_DBTR_DECLARE_BIT(MC6, M,      6),
	RV_DBTR_DECLARE_BIT(MC6, MATCH,  7),
	RV_DBTR_DECLARE_BIT(MC6, CHAIN,  11),
	RV_DBTR_DECLARE_BIT(MC6, ACTION, 12),
	RV_DBTR_DECLARE_BIT(MC6, SIZE,   16),
	RV_DBTR_DECLARE_BIT(MC6, TIMING, 20),
	RV_DBTR_DECLARE_BIT(MC6, SELECT, 21),
	RV_DBTR_DECLARE_BIT(MC6, HIT,    22),
	RV_DBTR_DECLARE_BIT(MC6, VU,     23),
	RV_DBTR_DECLARE_BIT(MC6, VS,     24),
#if __riscv_xlen == 64
	RV_DBTR_DECLARE_BIT(MC6, DMODE,  59),
	RV_DBTR_DECLARE_BIT(MC6, TYPE,   60),
#elif __riscv_xlen == 32
	RV_DBTR_DECLARE_BIT(MC6, DMODE,  27),
	RV_DBTR_DECLARE_BIT(MC6, TYPE,   28),
#else
	#error "Unknown riscv xlen"
#endif
};

enum {
	RV_DBTR_DECLARE_BIT_MASK(MC6, LOAD,   1),
	RV_DBTR_DECLARE_BIT_MASK(MC6, STORE,  1),
	RV_DBTR_DECLARE_BIT_MASK(MC6, EXEC,   1),
	RV_DBTR_DECLARE_BIT_MASK(MC6, U,      1),
	RV_DBTR_DECLARE_BIT_MASK(MC6, S,      1),
	RV_DBTR_DECLARE_BIT_MASK(MC6, RES2,   1),
	RV_DBTR_DECLARE_BIT_MASK(MC6, M,      1),
	RV_DBTR_DECLARE_BIT_MASK(MC6, MATCH,  4),
	RV_DBTR_DECLARE_BIT_MASK(MC6, CHAIN,  1),
	RV_DBTR_DECLARE_BIT_MASK(MC6, ACTION, 4),
	RV_DBTR_DECLARE_BIT_MASK(MC6, SIZE,   4),
	RV_DBTR_DECLARE_BIT_MASK(MC6, TIMING, 1),
	RV_DBTR_DECLARE_BIT_MASK(MC6, SELECT, 1),
	RV_DBTR_DECLARE_BIT_MASK(MC6, HIT,    1),
	RV_DBTR_DECLARE_BIT_MASK(MC6, VU,     1),
	RV_DBTR_DECLARE_BIT_MASK(MC6, VS,     1),
#if __riscv_xlen == 64
	RV_DBTR_DECLARE_BIT_MASK(MC6, DMODE,  1),
	RV_DBTR_DECLARE_BIT_MASK(MC6, TYPE,   4),
#elif __riscv_xlen == 32
	RV_DBTR_DECLARE_BIT_MASK(MC6, DMODE,  1),
	RV_DBTR_DECLARE_BIT_MASK(MC6, TYPE,   4),
#else
	#error "Unknown riscv xlen"
#endif
};

#define RV_DBTR_SET_TDATA1_TYPE(_t1, _type)				\
	do {								\
		_t1 &= ~RV_DBTR_BIT_MASK(TDATA1, TYPE);			\
		_t1 |= (((unsigned long)_type				\
			 << RV_DBTR_BIT(TDATA1, TYPE))			\
			& RV_DBTR_BIT_MASK(TDATA1, TYPE));		\
	}while (0);

#define RV_DBTR_SET_MC_TYPE(_t1, _type)				\
	do {							\
		_t1 &= ~RV_DBTR_BIT_MASK(MC, TYPE);		\
		_t1 |= (((unsigned long)_type			\
			 << RV_DBTR_BIT(MC, TYPE))		\
			& RV_DBTR_BIT_MASK(MC, TYPE));		\
	}while (0);

#define RV_DBTR_SET_MC6_TYPE(_t1, _type)			\
	do {							\
		_t1 &= ~RV_DBTR_BIT_MASK(MC6, TYPE);		\
		_t1 |= (((unsigned long)_type			\
			 << RV_DBTR_BIT(MC6, TYPE))		\
			& RV_DBTR_BIT_MASK(MC6, TYPE));		\
	}while (0);

#define RV_DBTR_SET_MC_EXEC(_t1)		\
	SET_DBTR_BIT(_t1, MC, EXEC)

#define RV_DBTR_SET_MC_LOAD(_t1)		\
	SET_DBTR_BIT(_t1, MC, LOAD)

#define RV_DBTR_SET_MC_STORE(_t1)		\
	SET_DBTR_BIT(_t1, MC, STORE)

#define RV_DBTR_SET_MC_SIZELO(_t1, _val)			\
	do {							\
		_t1 &= ~RV_DBTR_BIT_MASK(MC, SIZELO);		\
		_t1 |= ((_val << RV_DBTR_BIT(MC, SIZELO))	\
			& RV_DBTR_BIT_MASK(MC, SIZELO));	\
	} while(0);

#define RV_DBTR_SET_MC_SIZEHI(_t1, _val)			\
	do {							\
		_t1 &= ~RV_DBTR_BIT_MASK(MC, SIZEHI);		\
		_t1 |= ((_val << RV_DBTR_BIT(MC, SIZEHI))	\
			& RV_DBTR_BIT_MASK(MC, SIZEHI));	\
	} while(0);

#define RV_DBTR_SET_MC6_EXEC(_t1)		\
	SET_DBTR_BIT(_t1, MC6, EXEC)

#define RV_DBTR_SET_MC6_LOAD(_t1)		\
	SET_DBTR_BIT(_t1, MC6, LOAD)

#define RV_DBTR_SET_MC6_STORE(_t1)		\
	SET_DBTR_BIT(_t1, MC6, STORE)

#define RV_DBTR_SET_MC6_SIZE(_t1, _val)				\
	do {							\
		_t1 &= ~RV_DBTR_BIT_MASK(MC6, SIZE);		\
		_t1 |= ((_val << RV_DBTR_BIT(MC6, SIZE))	\
			& RV_DBTR_BIT_MASK(MC6, SIZE));		\
	} while(0);

typedef unsigned long riscv_dbtr_tdata1_mcontrol_t;
typedef unsigned long riscv_dbtr_tdata1_mcontrol6_t;

struct arch_hw_breakpoint {
	unsigned long address;
	unsigned long len;
	unsigned int type;

	/* Trigger configuration data */
	unsigned long tdata1;
	unsigned long tdata2;
	unsigned long tdata3;
};

/* Maximum number of hardware breakpoints supported */
#define HW_BP_NUM_MAX 32

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

#else

int hw_breakpoint_slots(int type)
{
	return 0;
}

static inline void clear_ptrace_hw_breakpoint(struct task_struct *tsk)
{
}

static inline void flush_ptrace_hw_breakpoint(struct task_struct *tsk)
{
}

void arch_enable_hw_breakpoint(struct perf_event *bp)
{
}

void arch_update_hw_breakpoint(struct perf_event *bp)
{
}

void arch_disable_hw_breakpoint(struct perf_event *bp)
{
}

#endif /* CONFIG_HAVE_HW_BREAKPOINT */
#endif /* __RISCV_HW_BREAKPOINT_H */
