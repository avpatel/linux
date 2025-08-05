// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright 2025 Rivos, Inc
 */

#include <linux/uaccess.h>

#include <asm/insn.h>
#include <asm/ptrace.h>
#include <asm/uaccess.h>

#define __read_insn(regs, insn, insn_addr, type)	\
({							\
	int __ret;					\
							\
	if (user_mode(regs)) {				\
		__ret = get_user(insn, (type __user *) insn_addr); \
	} else {					\
		insn = *(type *)insn_addr;		\
		__ret = 0;				\
	}						\
							\
	__ret;						\
})

/*
 * Update a set of two instructions (U-type + I-type) with an immediate value.
 *
 * Used for example in auipc+jalrs pairs the U-type instructions contains
 * a 20bit upper immediate representing bits[31:12], while the I-type
 * instruction contains a 12bit immediate representing bits[11:0].
 *
 * This also takes into account that both separate immediates are
 * considered as signed values, so if the I-type immediate becomes
 * negative (BIT(11) set) the U-type part gets adjusted.
 *
 * @regs: pointer to the utype instruction of the pair
 * @epc: pointer to the itype instruction of the pair
 * @r_insn: the immediate to insert into the two instructions
 * Return: combined immediate
 */
int get_insn(struct pt_regs *regs, ulong epc, ulong *r_insn)
{
	ulong insn = 0;

	if (epc & 0x2) {
		ulong tmp = 0;

		if (__read_insn(regs, insn, epc, u16))
			return -EFAULT;
		/* __get_user() uses regular "lw" which sign extend the loaded
		 * value make sure to clear higher order bits in case we "or" it
		 * below with the upper 16 bits half.
		 */
		insn &= RVC_MASK_C;
		if (riscv_insn_is_c(insn)) {
			*r_insn = insn;
			return 0;
		}
		epc += sizeof(u16);
		if (__read_insn(regs, tmp, epc, u16))
			return -EFAULT;
		*r_insn = (tmp << 16) | insn;

		return 0;
	} else {
		if (__read_insn(regs, insn, epc, u32))
			return -EFAULT;
		if (!riscv_insn_is_c(insn)) {
			*r_insn = insn;
			return 0;
		}
		insn &= RVC_MASK_C;
		*r_insn = insn;

		return 0;
	}
}

int get_insn_nofault(struct pt_regs *regs, ulong epc, ulong *r_insn)
{
	int ret;

	pagefault_disable();
	ret = get_insn(regs, epc, r_insn);
	pagefault_enable();

	return ret;
}

/* Calculate the new address for after a step */
unsigned long get_step_address(struct pt_regs *regs, u32 code)
{
	unsigned long pc = regs->epc;
	unsigned int rs1_num, rs2_num;

	if ((code & __INSN_LENGTH_MASK) != __INSN_LENGTH_GE_32) {
		if (riscv_insn_is_c_jalr(code) ||
		    riscv_insn_is_c_jr(code)) {
			rs1_num = riscv_insn_extract_rs1_reg(code);
			return regs_get_register(regs, rs1_num);
		} else if (riscv_insn_is_c_j(code) ||
			   riscv_insn_is_c_jal(code)) {
			return RVC_EXTRACT_JTYPE_IMM(code) + pc;
		} else if (riscv_insn_is_c_beqz(code)) {
			rs1_num = riscv_insn_extract_rs1_reg(code);
			if (!rs1_num || regs_get_register(regs, rs1_num) == 0)
				return RVC_EXTRACT_BTYPE_IMM(code) + pc;
			else
				return pc + 2;
		} else if (riscv_insn_is_c_bnez(code)) {
			rs1_num = riscv_insn_extract_rs1_reg(RVC_C1_RS1_OPOFF);
			if (rs1_num && regs_get_register(regs, rs1_num) != 0)
				return RVC_EXTRACT_BTYPE_IMM(code) + pc;
			else
				return pc + 2;
		} else {
			return pc + 2;
		}
	} else {
		if ((code & __INSN_OPCODE_MASK) == __INSN_BRANCH_OPCODE) {
			bool result = false;
			long imm = RV_EXTRACT_BTYPE_IMM(code);
			unsigned long rs1_val = 0, rs2_val = 0;

			rs1_num = riscv_insn_extract_rs1_reg(code);
			rs2_num = riscv_insn_extract_rs2_reg(code);
			if (rs1_num)
				rs1_val = regs_get_register(regs, rs1_num);
			if (rs2_num)
				rs2_val = regs_get_register(regs, rs2_num);

			if (riscv_insn_is_beq(code))
				result = (rs1_val == rs2_val) ? true : false;
			else if (riscv_insn_is_bne(code))
				result = (rs1_val != rs2_val) ? true : false;
			else if (riscv_insn_is_blt(code))
				result =
				    ((long)rs1_val <
				     (long)rs2_val) ? true : false;
			else if (riscv_insn_is_bge(code))
				result =
				    ((long)rs1_val >=
				     (long)rs2_val) ? true : false;
			else if (riscv_insn_is_bltu(code))
				result = (rs1_val < rs2_val) ? true : false;
			else if (riscv_insn_is_bgeu(code))
				result = (rs1_val >= rs2_val) ? true : false;
			if (result)
				return imm + pc;
			else
				return pc + 4;
		} else if (riscv_insn_is_jal(code)) {
			return RV_EXTRACT_JTYPE_IMM(code) + pc;
		} else if (riscv_insn_is_jalr(code)) {
			rs1_num = riscv_insn_extract_rs1_reg(code);
			return RV_EXTRACT_ITYPE_IMM(code) +
			       (rs1_num ? regs_get_register(regs, rs1_num) : 0);
		} else if (riscv_insn_is_sret(code)) {
			return pc;
		} else {
			return pc + 4;
		}
	}
}
