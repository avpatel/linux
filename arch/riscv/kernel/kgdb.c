// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2020 SiFive
 */

#include <linux/ptrace.h>
#include <linux/kdebug.h>
#include <linux/bug.h>
#include <linux/kgdb.h>
#include <linux/irqflags.h>
#include <linux/string.h>
#include <asm/cacheflush.h>
#include <asm/gdb_xml.h>
#include <asm/insn.h>

enum {
	NOT_KGDB_BREAK = 0,
	KGDB_SW_BREAK,
	KGDB_COMPILED_BREAK,
	KGDB_SW_SINGLE_STEP
};

static unsigned long stepped_address;
static unsigned int stepped_opcode;

static int do_single_step(struct pt_regs *regs)
{
	/* Determine where the target instruction will send us to */
	unsigned long addr, insn;
	int error = get_insn(regs, regs->epc, &insn);

	if (error)
		return error;

	addr = get_step_address(regs, insn);

	/* Store the op code in the stepped address */
	error = get_insn(regs, addr, stepped_opcode);
	if (error)
		return error;

	stepped_address = addr;

	/* Replace the op code with the break instruction */
	error = copy_to_kernel_nofault((void *)stepped_address,
				   arch_kgdb_ops.gdb_bpt_instr,
				   BREAK_INSTR_SIZE);
	/* Flush and return */
	if (!error) {
		flush_icache_range(addr, addr + BREAK_INSTR_SIZE);
		kgdb_single_step = 1;
		atomic_set(&kgdb_cpu_doing_single_step,
			   raw_smp_processor_id());
	} else {
		stepped_address = 0;
		stepped_opcode = 0;
	}
	return error;
}

/* Undo a single step */
static void undo_single_step(struct pt_regs *regs)
{
	if (stepped_opcode != 0) {
		copy_to_kernel_nofault((void *)stepped_address,
				   (void *)&stepped_opcode, BREAK_INSTR_SIZE);
		flush_icache_range(stepped_address,
				   stepped_address + BREAK_INSTR_SIZE);
	}
	stepped_address = 0;
	stepped_opcode = 0;
	kgdb_single_step = 0;
	atomic_set(&kgdb_cpu_doing_single_step, -1);
}

struct dbg_reg_def_t dbg_reg_def[DBG_MAX_REG_NUM] = {
	{DBG_REG_ZERO, GDB_SIZEOF_REG, -1},
	{DBG_REG_RA, GDB_SIZEOF_REG, offsetof(struct pt_regs, ra)},
	{DBG_REG_SP, GDB_SIZEOF_REG, offsetof(struct pt_regs, sp)},
	{DBG_REG_GP, GDB_SIZEOF_REG, offsetof(struct pt_regs, gp)},
	{DBG_REG_TP, GDB_SIZEOF_REG, offsetof(struct pt_regs, tp)},
	{DBG_REG_T0, GDB_SIZEOF_REG, offsetof(struct pt_regs, t0)},
	{DBG_REG_T1, GDB_SIZEOF_REG, offsetof(struct pt_regs, t1)},
	{DBG_REG_T2, GDB_SIZEOF_REG, offsetof(struct pt_regs, t2)},
	{DBG_REG_FP, GDB_SIZEOF_REG, offsetof(struct pt_regs, s0)},
	{DBG_REG_S1, GDB_SIZEOF_REG, offsetof(struct pt_regs, a1)},
	{DBG_REG_A0, GDB_SIZEOF_REG, offsetof(struct pt_regs, a0)},
	{DBG_REG_A1, GDB_SIZEOF_REG, offsetof(struct pt_regs, a1)},
	{DBG_REG_A2, GDB_SIZEOF_REG, offsetof(struct pt_regs, a2)},
	{DBG_REG_A3, GDB_SIZEOF_REG, offsetof(struct pt_regs, a3)},
	{DBG_REG_A4, GDB_SIZEOF_REG, offsetof(struct pt_regs, a4)},
	{DBG_REG_A5, GDB_SIZEOF_REG, offsetof(struct pt_regs, a5)},
	{DBG_REG_A6, GDB_SIZEOF_REG, offsetof(struct pt_regs, a6)},
	{DBG_REG_A7, GDB_SIZEOF_REG, offsetof(struct pt_regs, a7)},
	{DBG_REG_S2, GDB_SIZEOF_REG, offsetof(struct pt_regs, s2)},
	{DBG_REG_S3, GDB_SIZEOF_REG, offsetof(struct pt_regs, s3)},
	{DBG_REG_S4, GDB_SIZEOF_REG, offsetof(struct pt_regs, s4)},
	{DBG_REG_S5, GDB_SIZEOF_REG, offsetof(struct pt_regs, s5)},
	{DBG_REG_S6, GDB_SIZEOF_REG, offsetof(struct pt_regs, s6)},
	{DBG_REG_S7, GDB_SIZEOF_REG, offsetof(struct pt_regs, s7)},
	{DBG_REG_S8, GDB_SIZEOF_REG, offsetof(struct pt_regs, s8)},
	{DBG_REG_S9, GDB_SIZEOF_REG, offsetof(struct pt_regs, s9)},
	{DBG_REG_S10, GDB_SIZEOF_REG, offsetof(struct pt_regs, s10)},
	{DBG_REG_S11, GDB_SIZEOF_REG, offsetof(struct pt_regs, s11)},
	{DBG_REG_T3, GDB_SIZEOF_REG, offsetof(struct pt_regs, t3)},
	{DBG_REG_T4, GDB_SIZEOF_REG, offsetof(struct pt_regs, t4)},
	{DBG_REG_T5, GDB_SIZEOF_REG, offsetof(struct pt_regs, t5)},
	{DBG_REG_T6, GDB_SIZEOF_REG, offsetof(struct pt_regs, t6)},
	{DBG_REG_EPC, GDB_SIZEOF_REG, offsetof(struct pt_regs, epc)},
	{DBG_REG_STATUS, GDB_SIZEOF_REG, offsetof(struct pt_regs, status)},
	{DBG_REG_BADADDR, GDB_SIZEOF_REG, offsetof(struct pt_regs, badaddr)},
	{DBG_REG_CAUSE, GDB_SIZEOF_REG, offsetof(struct pt_regs, cause)},
};

char *dbg_get_reg(int regno, void *mem, struct pt_regs *regs)
{
	if (regno >= DBG_MAX_REG_NUM || regno < 0)
		return NULL;

	if (dbg_reg_def[regno].offset != -1)
		memcpy(mem, (void *)regs + dbg_reg_def[regno].offset,
		       dbg_reg_def[regno].size);
	else
		memset(mem, 0, dbg_reg_def[regno].size);
	return dbg_reg_def[regno].name;
}

int dbg_set_reg(int regno, void *mem, struct pt_regs *regs)
{
	if (regno >= DBG_MAX_REG_NUM || regno < 0)
		return -EINVAL;

	if (dbg_reg_def[regno].offset != -1)
		memcpy((void *)regs + dbg_reg_def[regno].offset, mem,
		       dbg_reg_def[regno].size);
	return 0;
}

void
sleeping_thread_to_gdb_regs(unsigned long *gdb_regs, struct task_struct *task)
{
	/* Initialize to zero */
	memset((char *)gdb_regs, 0, NUMREGBYTES);

	gdb_regs[DBG_REG_SP_OFF] = task->thread.sp;
	gdb_regs[DBG_REG_FP_OFF] = task->thread.s[0];
	gdb_regs[DBG_REG_S1_OFF] = task->thread.s[1];
	gdb_regs[DBG_REG_S2_OFF] = task->thread.s[2];
	gdb_regs[DBG_REG_S3_OFF] = task->thread.s[3];
	gdb_regs[DBG_REG_S4_OFF] = task->thread.s[4];
	gdb_regs[DBG_REG_S5_OFF] = task->thread.s[5];
	gdb_regs[DBG_REG_S6_OFF] = task->thread.s[6];
	gdb_regs[DBG_REG_S7_OFF] = task->thread.s[7];
	gdb_regs[DBG_REG_S8_OFF] = task->thread.s[8];
	gdb_regs[DBG_REG_S9_OFF] = task->thread.s[10];
	gdb_regs[DBG_REG_S10_OFF] = task->thread.s[11];
	gdb_regs[DBG_REG_EPC_OFF] = task->thread.ra;
}

void kgdb_arch_set_pc(struct pt_regs *regs, unsigned long pc)
{
	regs->epc = pc;
}

noinline void arch_kgdb_breakpoint(void)
{
	asm(".global kgdb_compiled_break\n"
	    "kgdb_compiled_break: ebreak\n");
}

void kgdb_arch_handle_qxfer_pkt(char *remcom_in_buffer,
				char *remcom_out_buffer)
{
	if (!strncmp(remcom_in_buffer, gdb_xfer_read_target,
		     sizeof(gdb_xfer_read_target)))
		strcpy(remcom_out_buffer, riscv_gdb_stub_target_desc);
	else if (!strncmp(remcom_in_buffer, gdb_xfer_read_cpuxml,
			  sizeof(gdb_xfer_read_cpuxml)))
		strcpy(remcom_out_buffer, riscv_gdb_stub_cpuxml);
}

static inline void kgdb_arch_update_addr(struct pt_regs *regs,
					 char *remcom_in_buffer)
{
	unsigned long addr;
	char *ptr;

	ptr = &remcom_in_buffer[1];
	if (kgdb_hex2long(&ptr, &addr))
		regs->epc = addr;
}

int kgdb_arch_handle_exception(int vector, int signo, int err_code,
			       char *remcom_in_buffer, char *remcom_out_buffer,
			       struct pt_regs *regs)
{
	int err = 0;

	undo_single_step(regs);

	switch (remcom_in_buffer[0]) {
	case 'c':
	case 'D':
	case 'k':
		if (remcom_in_buffer[0] == 'c')
			kgdb_arch_update_addr(regs, remcom_in_buffer);
		break;
	case 's':
		kgdb_arch_update_addr(regs, remcom_in_buffer);
		err = do_single_step(regs);
		break;
	default:
		err = -1;
	}
	return err;
}

static int kgdb_riscv_kgdbbreak(unsigned long addr)
{
	if (stepped_address == addr)
		return KGDB_SW_SINGLE_STEP;
	if (atomic_read(&kgdb_setting_breakpoint))
		if (addr == (unsigned long)&kgdb_compiled_break)
			return KGDB_COMPILED_BREAK;

	return kgdb_has_hit_break(addr);
}

static int kgdb_riscv_notify(struct notifier_block *self, unsigned long cmd,
			     void *ptr)
{
	struct die_args *args = (struct die_args *)ptr;
	struct pt_regs *regs = args->regs;
	unsigned long flags;
	int type;

	if (user_mode(regs))
		return NOTIFY_DONE;

	type = kgdb_riscv_kgdbbreak(regs->epc);
	if (type == NOT_KGDB_BREAK && cmd == DIE_TRAP)
		return NOTIFY_DONE;

	local_irq_save(flags);

	if (kgdb_handle_exception(type == KGDB_SW_SINGLE_STEP ? 0 : 1,
				  args->signr, cmd, regs))
		return NOTIFY_DONE;

	if (type == KGDB_COMPILED_BREAK)
		regs->epc += 4;

	local_irq_restore(flags);

	return NOTIFY_STOP;
}

static struct notifier_block kgdb_notifier = {
	.notifier_call = kgdb_riscv_notify,
};

int kgdb_arch_init(void)
{
	register_die_notifier(&kgdb_notifier);

	return 0;
}

void kgdb_arch_exit(void)
{
	unregister_die_notifier(&kgdb_notifier);
}

/*
 * Global data
 */
#ifdef CONFIG_RISCV_ISA_C
const struct kgdb_arch arch_kgdb_ops = {
	.gdb_bpt_instr = {0x02, 0x90},	/* c.ebreak */
};
#else
const struct kgdb_arch arch_kgdb_ops = {
	.gdb_bpt_instr = {0x73, 0x00, 0x10, 0x00},	/* ebreak */
};
#endif
