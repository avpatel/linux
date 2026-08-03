/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
/*
 * Copyright (C) 2012 Regents of the University of California
 */

#ifndef _UAPI_ASM_RISCV_PTRACE_H
#define _UAPI_ASM_RISCV_PTRACE_H

#ifndef __ASSEMBLER__

#include <linux/types.h>
#include <linux/const.h>
#include <linux/bits.h>

#define PTRACE_GETFDPIC		33

#define PTRACE_GETFDPIC_EXEC	0
#define PTRACE_GETFDPIC_INTERP	1
#define PTRACE_GETHBPREGS	0x4210
#define PTRACE_SETHBPREGS	0x4211

/*
 * User-mode register state for core dumps, ptrace, sigcontext
 *
 * This decouples struct pt_regs from the userspace ABI.
 * struct user_regs_struct must form a prefix of struct pt_regs.
 */
struct user_regs_struct {
	unsigned long pc;
	unsigned long ra;
	unsigned long sp;
	unsigned long gp;
	unsigned long tp;
	unsigned long t0;
	unsigned long t1;
	unsigned long t2;
	unsigned long s0;
	unsigned long s1;
	unsigned long a0;
	unsigned long a1;
	unsigned long a2;
	unsigned long a3;
	unsigned long a4;
	unsigned long a5;
	unsigned long a6;
	unsigned long a7;
	unsigned long s2;
	unsigned long s3;
	unsigned long s4;
	unsigned long s5;
	unsigned long s6;
	unsigned long s7;
	unsigned long s8;
	unsigned long s9;
	unsigned long s10;
	unsigned long s11;
	unsigned long t3;
	unsigned long t4;
	unsigned long t5;
	unsigned long t6;
};

struct __riscv_f_ext_state {
	__u32 f[32];
	__u32 fcsr;
};

struct __riscv_d_ext_state {
	__u64 f[32];
	__u32 fcsr;
};

struct __riscv_q_ext_state {
	__u64 f[64] __attribute__((aligned(16)));
	__u32 fcsr;
	/*
	 * Reserved for expansion of sigcontext structure.  Currently zeroed
	 * upon signal, and must be zero upon sigreturn.
	 */
	__u32 reserved[3];
};

struct __riscv_ctx_hdr {
	__u32 magic;
	__u32 size;
};

struct __riscv_extra_ext_header {
	__u32 __padding[129] __attribute__((aligned(16)));
	/*
	 * Reserved for expansion of sigcontext structure.  Currently zeroed
	 * upon signal, and must be zero upon sigreturn.
	 */
	__u32 reserved;
	struct __riscv_ctx_hdr hdr;
};

union __riscv_fp_state {
	struct __riscv_f_ext_state f;
	struct __riscv_d_ext_state d;
	struct __riscv_q_ext_state q;
};

struct __riscv_v_ext_state {
	unsigned long vstart;
	unsigned long vl;
	unsigned long vtype;
	unsigned long vcsr;
	unsigned long vlenb;
	void *datap;
	/*
	 * In signal handler, datap will be set a correct user stack offset
	 * and vector registers will be copied to the address of datap
	 * pointer.
	 */
};

struct __riscv_v_regset_state {
	unsigned long vstart;
	unsigned long vl;
	unsigned long vtype;
	unsigned long vcsr;
	unsigned long vlenb;
	char vreg[];
};

/*
 * According to spec: The number of bits in a single vector register,
 * VLEN >= ELEN, which must be a power of 2, and must be no greater than
 * 2^16 = 65536bits = 8192bytes
 */
#define RISCV_MAX_VLENB (8192)

struct __sc_riscv_cfi_state {
	unsigned long ss_ptr;   /* shadow stack pointer */
};

#define PTRACE_CFI_BRANCH_LANDING_PAD_EN_BIT		0
#define PTRACE_CFI_BRANCH_LANDING_PAD_LOCK_BIT		1
#define PTRACE_CFI_BRANCH_EXPECTED_LANDING_PAD_BIT	2
#define PTRACE_CFI_SHADOW_STACK_EN_BIT			3
#define PTRACE_CFI_SHADOW_STACK_LOCK_BIT		4
#define PTRACE_CFI_SHADOW_STACK_PTR_BIT			5

#define PTRACE_CFI_BRANCH_LANDING_PAD_EN_STATE		_BITUL(PTRACE_CFI_BRANCH_LANDING_PAD_EN_BIT)
#define PTRACE_CFI_BRANCH_LANDING_PAD_LOCK_STATE	\
	_BITUL(PTRACE_CFI_BRANCH_LANDING_PAD_LOCK_BIT)
#define PTRACE_CFI_BRANCH_EXPECTED_LANDING_PAD_STATE	\
	_BITUL(PTRACE_CFI_BRANCH_EXPECTED_LANDING_PAD_BIT)
#define PTRACE_CFI_SHADOW_STACK_EN_STATE		_BITUL(PTRACE_CFI_SHADOW_STACK_EN_BIT)
#define PTRACE_CFI_SHADOW_STACK_LOCK_STATE		_BITUL(PTRACE_CFI_SHADOW_STACK_LOCK_BIT)
#define PTRACE_CFI_SHADOW_STACK_PTR_STATE		_BITUL(PTRACE_CFI_SHADOW_STACK_PTR_BIT)

#define PTRACE_CFI_STATE_INVALID_MASK	~(PTRACE_CFI_BRANCH_LANDING_PAD_EN_STATE | \
					  PTRACE_CFI_BRANCH_LANDING_PAD_LOCK_STATE | \
					  PTRACE_CFI_BRANCH_EXPECTED_LANDING_PAD_STATE | \
					  PTRACE_CFI_SHADOW_STACK_EN_STATE | \
					  PTRACE_CFI_SHADOW_STACK_LOCK_STATE | \
					  PTRACE_CFI_SHADOW_STACK_PTR_STATE)

struct __cfi_status {
	__u64 cfi_state;
};

struct user_cfi_state {
	struct __cfi_status	cfi_status;
	__u64 shstk_ptr;
};

/*
 * bit[3:0]        Match
 * bit[8:4]        Size
 * bit[11:9]       When
 * bit[12]         Select
 * bit[13]         Chain
 * bit[16:14]      Type
 * bit[XLEN-1:17]  Reserved
*/
#define HWDEBUG_MATCH_MASK	__GENMASK(3, 0)
#define HWDEBUG_SIZE_MASK	__GENMASK(8, 4)
#define HWDEBUG_WHEN_MASK	__GENMASK(11, 9)
#define HWDEBUG_SELECT_MASK	_BITUL(12)
#define HWDEBUG_CHAIN_MASK	_BITUL(13)
#define HWDEBUG_TYPE_MASK	__GENMASK(16, 14)

#define HWDEBUG_MATCH(_ctrl)	(((_ctrl) & HWDEBUG_MATCH_MASK) >> 0)
#define HWDEBUG_SIZE(_ctrl)	(((_ctrl) & HWDEBUG_SIZE_MASK) >> 4)
#define HWDEBUG_WHEN(_ctrl)	(((_ctrl) & HWDEBUG_WHEN_MASK) >> 9)
#define HWDEBUG_SELECT(_ctrl)	(((_ctrl) & HWDEBUG_SELECT_MASK) >> 12)
#define HWDEBUG_CHAIN(_ctrl)	(((_ctrl) & HWDEBUG_CHAIN_MASK) >> 13)
#define HWDEBUG_TYPE(_ctrl)	(((_ctrl) & HWDEBUG_TYPE_MASK) >> 14)

#define HWDEBUG_MK_MATCH(_match)	((_match << 0) & HWDEBUG_MATCH_MASK)
#define HWDEBUG_MK_SIZE(_sz)		((_sz << 4) & HWDEBUG_SIZE_MASK)
#define HWDEBUG_MK_WHEN(_when)		((_when << 9) & HWDEBUG_WHEN_MASK)
#define HWDEBUG_MK_SELECT(_sel)		((_sel << 12) & HWDEBUG_SELECT_MASK)
#define HWDEBUG_MK_CHAIN(_chain)	((_chain << 13) & HWDEBUG_CHAIN_MASK)
#define HWDEBUG_MK_TYPE(_type)		((_type << 14) & HWDEBUG_TYPE_MASK)

struct user_hwdebug_state {
	__u32 info;
	__u32 pad;
	struct {
		__u64 addr;
		__u32 control;
		__u32 pad;
	} dbg_regs[16];
};

struct __riscv_hwdebug_state {
	unsigned long addr;
	unsigned long type;
	unsigned long len;
	unsigned long ctrl;
} __packed;

#endif /* __ASSEMBLER__ */

#endif /* _UAPI_ASM_RISCV_PTRACE_H */
