// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright 2026 Qualcomm Technologies, Inc.
 */

#include <linux/uaccess.h>

#include <asm/insn.h>
#include <asm/ptrace.h>

/*
 * fetch_insn_u16() - Fetch a 16-bit RISC-V instruction parcel from memory
 * @regs: Register state used to determine the access context
 * @insn: Pointer receiving the instruction value
 * @insn_addr: Address from which to read the instruction parcel
 *
 * Fetches an instruction parcel from user or kernel memory, depending on the
 * execution context indicated by @regs. RISC-V instruction parcels are
 * stored in little-endian byte order, so the fetched value is converted from
 * little-endian to the native CPU representation before being stored in @insn.
 *
 * The conversion is a no-op on little-endian targets and performs the
 * required byte swap on big-endian targets.
 *
 * Return: 0 on success, or a negative error code if reading user memory
 *         fails.
 */
static int fetch_insn_u16(struct pt_regs *regs, u16 *insn,
			  unsigned long insn_addr)
{
	u16 val;
	int ret;

	if (user_mode(regs))
		ret = get_user(val, (u16 __user *)insn_addr);
	else
		ret = get_kernel_nofault(val, (u16 *)insn_addr);

	if (!ret)
		*insn = le16_to_cpu((__force __le16)val);

	return ret;
}

static int fetch_insn_u32(struct pt_regs *regs, u32 *insn,
			  unsigned long insn_addr)
{
	u32 val;
	int ret;

	if (user_mode(regs))
		ret = get_user(val, (u32 __user *)insn_addr);
	else
		ret = get_kernel_nofault(val, (u32 *)insn_addr);

	if (!ret)
		*insn = le32_to_cpu((__force __le32)val);

	return ret;
}

/**
 * get_insn() - Fetch and decode a RISC-V instruction
 * @regs: Register state used for instruction access
 * @epc: Address of the instruction to fetch
 * @r_insn: Pointer to store the fetched instruction encoding
 *
 * Fetches the instruction at @epc and stores its encoding in @r_insn.
 * Both standard 32-bit instructions and compressed 16-bit instructions are
 * supported. If a 32-bit instruction is split across two 16-bit instruction
 * accesses, the halfwords are combined into a single instruction encoding.
 *
 * Return: 0 on success, or %-EFAULT if instruction access fails.
 */
int get_insn(struct pt_regs *regs, ulong epc, ulong *r_insn)
{
	u32 insn;
	u16 half, tmp;

	if (!(epc & 0x2)) {
		if (fetch_insn_u32(regs, &insn, epc))
			return -EFAULT;

		if (riscv_insn_is_compressed(insn))
			insn &= RVC_MASK_INSN;

		*r_insn = insn;
		return 0;
	}

	if (fetch_insn_u16(regs, &half, epc))
		return -EFAULT;

	insn = half & RVC_MASK_INSN;
	if (riscv_insn_is_compressed(insn)) {
		*r_insn = insn;
		return 0;
	}

	if (fetch_insn_u16(regs, &tmp, epc + sizeof(u16)))
		return -EFAULT;

	*r_insn = ((u32)tmp << 16) | insn;

	return 0;
}

int get_insn_safe(struct pt_regs *regs, ulong epc, ulong *r_insn)
{
	int ret;

	pagefault_disable();
	ret = get_insn(regs, epc, r_insn);
	pagefault_enable();

	return ret;
}

/**
 * riscv_get_reg_value() - Get the value stored the given RISC-V register number
 * @regs: Register state containing the saved register values
 * @regno: RISC-V register number
 *
 * Returns the value of the RISC-V register identified by @regno. Register
 * x0 always returns zero, as required by the RISC-V ISA.
 *
 * Return: The register value, or zero if @regno is zero.
 */
static unsigned long riscv_get_reg_value(struct pt_regs *regs, unsigned int regno)
{
	return regno ? regs_get_register(regs, regno * sizeof(unsigned long)) : 0;
}

static unsigned long riscv_jalr_target(unsigned long base, long offset)
{
	/* JALR, C.JR, and C.JALR clear bit 0 of the computed target address. */
	return (base + offset) & ~1UL;
}

/**
 * get_next_insn_address_compressed() - Calculate the next address for a compressed
 * RISC-V instruction
 * @regs: Register state used to evaluate indirect jumps and conditional
 *        branches
 * @insn: Compressed RISC-V instruction encoding
 * @pc: Current program counter
 *
 * Determines the address at which execution should continue after processing
 * the compressed instruction in @insn. Indirect jumps use the value of the
 * instruction's source register, unconditional jumps use the encoded
 * immediate, and conditional branches evaluate the relevant register value.
 *
 * For a branch that is not taken, or for an unsupported compressed
 * instruction, the address of the following 16-bit instruction is returned.
 *
 * Return: The next instruction address.
 */
static unsigned long get_next_insn_address_compressed(struct pt_regs *regs, u32 insn,
						      unsigned long pc)
{
	unsigned int rs1_num;

	if (riscv_insn_is_c_jalr(insn) || riscv_insn_is_c_jr(insn)) {
		rs1_num = RV_X(insn, RVC_C2_RS1_OPOFF, 5);
		return riscv_jalr_target(riscv_get_reg_value(regs, rs1_num), 0);
	}

	if (riscv_insn_is_c_j(insn) || riscv_insn_is_c_jal(insn))
		return RVC_EXTRACT_JTYPE_IMM(insn) + pc;

	if (riscv_insn_is_c_beqz(insn)) {
		rs1_num = RV_X(insn, RVC_C1_RS1_OPOFF, 3) + 8;
		if (!rs1_num || riscv_get_reg_value(regs, rs1_num) == 0)
			return RVC_EXTRACT_BTYPE_IMM(insn) + pc;
		return pc + 2;
	}

	if (riscv_insn_is_c_bnez(insn)) {
		rs1_num = RV_X(insn, RVC_C1_RS1_OPOFF, 3) + 8;
		if (rs1_num && riscv_get_reg_value(regs, rs1_num) != 0)
			return RVC_EXTRACT_BTYPE_IMM(insn) + pc;
		return pc + 2;
	}

	return pc + 2;
}

/**
 * riscv_branch_taken() - Determine whether a RISC-V conditional branch is taken
 * @regs: Register state used to obtain the source operand values
 * @insn: RISC-V branch instruction encoding
 *
 * Evaluates the branch condition encoded in @insn using the values of its
 * source registers from @regs. Signed comparisons are used for BLT and BGE,
 * while unsigned comparisons are used for BLTU and BGEU.
 *
 * Return: %true if the branch condition is satisfied, or %false otherwise.
 *         Unsupported branch instructions also return %false.
 */
static bool riscv_branch_taken(struct pt_regs *regs, u32 insn)
{
	unsigned int rs1_num = RV_X(insn, RVG_RS1_OPOFF, 5);
	unsigned int rs2_num = RV_X(insn, RVG_RS2_OPOFF, 5);
	unsigned long rs1_val = riscv_get_reg_value(regs, rs1_num);
	unsigned long rs2_val = riscv_get_reg_value(regs, rs2_num);

	if (riscv_insn_is_beq(insn))
		return rs1_val == rs2_val;
	if (riscv_insn_is_bne(insn))
		return rs1_val != rs2_val;
	if (riscv_insn_is_blt(insn))
		return (long)rs1_val < (long)rs2_val;
	if (riscv_insn_is_bge(insn))
		return (long)rs1_val >= (long)rs2_val;
	if (riscv_insn_is_bltu(insn))
		return rs1_val < rs2_val;
	if (riscv_insn_is_bgeu(insn))
		return rs1_val >= rs2_val;

	return false;
}

/**
 * get_next_insn_address_standard() - Compute the next PC for standard RISC-V
 * control-flow instructions
 *
 * @regs: Register state of the current context.
 * @insn: Instruction located at @pc.
 * @pc: Address of the current instruction.
 *
 * Determine the address of the next instruction to be executed after @insn.
 * The function evaluates control-flow instructions whose target cannot be
 * obtained by simply advancing the program counter:
 *
 * - Conditional branches: returns either the branch target or @pc + 4
 * depending on the branch outcome.
 * - JAL: returns the jump target encoded in the instruction.
 * - JALR: returns the computed indirect jump target using the instruction
 * immediate and the value of the source register.
 * - SRET: returns @pc, as control transfer is handled by the trap return
 * mechanism.
 *
 * For all other instructions, execution is assumed to continue at the next
 * sequential 32-bit instruction and @pc + 4 is returned.
 *
 * Return: Address of the next instruction to be executed.
 */
static unsigned long get_next_insn_address_standard(struct pt_regs *regs, u32 insn,
						    unsigned long pc)
{
	unsigned int rs1_num;

	if ((insn & __INSN_OPCODE_MASK) == __INSN_BRANCH_OPCODE)
		return riscv_branch_taken(regs, insn) ?
			RV_EXTRACT_BTYPE_IMM(insn) + pc : pc + 4;

	if (riscv_insn_is_jal(insn))
		return RV_EXTRACT_JTYPE_IMM(insn) + pc;

	if (riscv_insn_is_jalr(insn)) {
		rs1_num = RV_X(insn, RVG_RS1_OPOFF, 5);
		return riscv_jalr_target(riscv_get_reg_value(regs, rs1_num),
					 RV_EXTRACT_ITYPE_IMM(insn));
	}

	if (riscv_insn_is_sret(insn))
		return pc;

	return pc + 4;
}

/* Calculate the new address for after a step */
unsigned long get_next_insn_address(struct pt_regs *regs, ulong insn, ulong pc)
{
	if (riscv_insn_is_compressed(insn))
		return get_next_insn_address_compressed(regs, insn, pc);

	return get_next_insn_address_standard(regs, insn, pc);
}
