// SPDX-License-Identifier: GPL-2.0
/*
 * Control transfer records extension Helpers.
 *
 * Copyright (C) 2024 Rivos Inc.
 *
 * Author: Rajnesh Kanwal <rkanwal@rivosinc.com>
 */

#define pr_fmt(fmt) "CTR: " fmt

#include <linux/bitfield.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/perf_event.h>
#include <linux/perf/riscv_pmu.h>
#include <linux/cpufeature.h>
#include <asm/hwcap.h>
#include <asm/csr_indirect.h>
#include <asm/csr.h>

#define CTR_BRANCH_FILTERS_INH  (CTRCTL_EXCINH       | \
				 CTRCTL_INTRINH      | \
				 CTRCTL_TRETINH      | \
				 CTRCTL_TKBRINH      | \
				 CTRCTL_INDCALL_INH  | \
				 CTRCTL_DIRCALL_INH  | \
				 CTRCTL_INDJUMP_INH  | \
				 CTRCTL_DIRJUMP_INH  | \
				 CTRCTL_CORSWAP_INH  | \
				 CTRCTL_RET_INH      | \
				 CTRCTL_INDOJUMP_INH | \
				 CTRCTL_DIROJUMP_INH)

#define CTR_BRANCH_ENABLE_BITS (CTRCTL_KERNEL_ENABLE | CTRCTL_U_ENABLE)

/* Branch filters not-supported by CTR extension. */
#define CTR_EXCLUDE_BRANCH_FILTERS (PERF_SAMPLE_BRANCH_ABORT_TX	        | \
				    PERF_SAMPLE_BRANCH_IN_TX		| \
				    PERF_SAMPLE_BRANCH_PRIV_SAVE        | \
				    PERF_SAMPLE_BRANCH_NO_TX            | \
				    PERF_SAMPLE_BRANCH_COUNTERS)

/* Branch filters supported by CTR extension. */
#define CTR_ALLOWED_BRANCH_FILTERS (PERF_SAMPLE_BRANCH_USER		| \
				    PERF_SAMPLE_BRANCH_KERNEL		| \
				    PERF_SAMPLE_BRANCH_HV		| \
				    PERF_SAMPLE_BRANCH_ANY		| \
				    PERF_SAMPLE_BRANCH_ANY_CALL	        | \
				    PERF_SAMPLE_BRANCH_ANY_RETURN	| \
				    PERF_SAMPLE_BRANCH_IND_CALL	        | \
				    PERF_SAMPLE_BRANCH_COND		| \
				    PERF_SAMPLE_BRANCH_IND_JUMP	        | \
				    PERF_SAMPLE_BRANCH_HW_INDEX	        | \
				    PERF_SAMPLE_BRANCH_NO_FLAGS	        | \
				    PERF_SAMPLE_BRANCH_NO_CYCLES	| \
				    PERF_SAMPLE_BRANCH_CALL_STACK       | \
				    PERF_SAMPLE_BRANCH_CALL		| \
				    PERF_SAMPLE_BRANCH_TYPE_SAVE)

#define CTR_PERF_BRANCH_FILTERS    (CTR_ALLOWED_BRANCH_FILTERS	        | \
				    CTR_EXCLUDE_BRANCH_FILTERS)

static u64 allowed_filters __read_mostly;

struct ctr_regset {
	unsigned long src;
	unsigned long target;
	unsigned long ctr_data;
};

enum {
	CTR_STATE_NONE,
	CTR_STATE_VALID,
};

/* Head is the idx of the next available slot. The slot may be already populated
 * by an old entry which will be lost on new writes.
 */
struct riscv_perf_task_context {
	int callstack_users;
	int stack_state;
	unsigned int num_entries;
	u32 ctr_status;
	u64 ctr_control;
	struct ctr_regset store[MAX_BRANCH_RECORDS];
};

static inline u64 get_ctr_src_reg(unsigned int ctr_idx)
{
	return csr_indirect_read(CSR_SIREG, CTR_ENTRIES_FIRST, ctr_idx);
}

static inline void set_ctr_src_reg(unsigned int ctr_idx, u64 value)
{
	return csr_indirect_write(CSR_SIREG, CTR_ENTRIES_FIRST, ctr_idx, value);
}

static inline u64 get_ctr_tgt_reg(unsigned int ctr_idx)
{
	return csr_indirect_read(CSR_SIREG2, CTR_ENTRIES_FIRST, ctr_idx);
}

static inline void set_ctr_tgt_reg(unsigned int ctr_idx, u64 value)
{
	return csr_indirect_write(CSR_SIREG2, CTR_ENTRIES_FIRST, ctr_idx, value);
}

static inline u64 get_ctr_data_reg(unsigned int ctr_idx)
{
	return csr_indirect_read(CSR_SIREG3, CTR_ENTRIES_FIRST, ctr_idx);
}

static inline void set_ctr_data_reg(unsigned int ctr_idx, u64 value)
{
	return csr_indirect_write(CSR_SIREG3, CTR_ENTRIES_FIRST, ctr_idx, value);
}

static inline bool ctr_record_valid(u64 ctr_src)
{
	return !!FIELD_GET(CTRSOURCE_VALID, ctr_src);
}

static inline int ctr_get_mispredict(u64 ctr_target)
{
	return FIELD_GET(CTRTARGET_MISP, ctr_target);
}

static inline unsigned int ctr_get_cycles(u64 ctr_data)
{
	const unsigned int cce = FIELD_GET(CTRDATA_CCE_MASK, ctr_data);
	const unsigned int ccm = FIELD_GET(CTRDATA_CCM_MASK, ctr_data);

	if (ctr_data & CTRDATA_CCV)
		return 0;

	/* Formula to calculate cycles from spec: (2^12 + CCM) << CCE-1 */
	if (cce > 0)
		return (4096 + ccm) << (cce - 1);

	return FIELD_GET(CTRDATA_CCM_MASK, ctr_data);
}

static inline unsigned int ctr_get_type(u64 ctr_data)
{
	return FIELD_GET(CTRDATA_TYPE_MASK, ctr_data);
}

static inline unsigned int ctr_get_depth(u64 ctr_depth)
{
	/* Depth table from CTR Spec: 2.4 sctrdepth.
	 *
	 * sctrdepth.depth       Depth
	 * 000			- 16
	 * 001			- 32
	 * 010			- 64
	 * 011			- 128
	 * 100			- 256
	 *
	 * Depth = 16 * 2 ^ (ctrdepth.depth)
	 * or
	 * Depth = 16 << ctrdepth.depth.
	 */
	return 16 << FIELD_GET(SCTRDEPTH_MASK, ctr_depth);
}

static inline struct riscv_perf_task_context *task_context(void *ctx)
{
	return (struct riscv_perf_task_context *)ctx;
}

/* Reads CTR entry at idx and stores it in entry struct. */
static bool get_ctr_regset(struct ctr_regset *entry, unsigned int idx)
{
	entry->src = get_ctr_src_reg(idx);

	if (!ctr_record_valid(entry->src))
		return false;

	entry->src = entry->src;
	entry->target = get_ctr_tgt_reg(idx);
	entry->ctr_data = get_ctr_data_reg(idx);

	return true;
}

static void set_ctr_regset(struct ctr_regset *entry, unsigned int idx)
{
	set_ctr_src_reg(idx, entry->src);
	set_ctr_tgt_reg(idx, entry->target);
	set_ctr_data_reg(idx, entry->ctr_data);
}

static u64 branch_type_to_ctr(int branch_type)
{
	u64 config = CTR_BRANCH_FILTERS_INH | CTRCTL_LCOFIFRZ;

	if (branch_type & PERF_SAMPLE_BRANCH_USER)
		config |= CTRCTL_U_ENABLE;

	if (branch_type & PERF_SAMPLE_BRANCH_KERNEL)
		config |= CTRCTL_KERNEL_ENABLE;

	if (branch_type & PERF_SAMPLE_BRANCH_HV) {
		if (riscv_isa_extension_available(NULL, H))
			config |= CTRCTL_KERNEL_ENABLE;
	}

	if (branch_type & PERF_SAMPLE_BRANCH_ANY) {
		config &= ~CTR_BRANCH_FILTERS_INH;
		return config;
	}

	if (branch_type & PERF_SAMPLE_BRANCH_ANY_CALL) {
		config &= ~CTRCTL_INDCALL_INH;
		config &= ~CTRCTL_DIRCALL_INH;
		config &= ~CTRCTL_EXCINH;
		config &= ~CTRCTL_INTRINH;
	}

	if (branch_type & PERF_SAMPLE_BRANCH_ANY_RETURN)
		config &= ~(CTRCTL_RET_INH | CTRCTL_TRETINH);

	if (branch_type & PERF_SAMPLE_BRANCH_IND_CALL)
		config &= ~CTRCTL_INDCALL_INH;

	if (branch_type & PERF_SAMPLE_BRANCH_COND)
		config &= ~CTRCTL_TKBRINH;

	if (branch_type & PERF_SAMPLE_BRANCH_CALL_STACK)
		config |= CTRCTL_RASEMU;

	if (branch_type & PERF_SAMPLE_BRANCH_IND_JUMP) {
		config &= ~CTRCTL_INDJUMP_INH;
		config &= ~CTRCTL_INDOJUMP_INH;
	}

	if (branch_type & PERF_SAMPLE_BRANCH_CALL)
		config &= ~CTRCTL_DIRCALL_INH;

	return config;
}

static const int ctr_perf_map[] = {
	[CTRDATA_TYPE_NONE]			= PERF_BR_UNKNOWN,
	[CTRDATA_TYPE_EXCEPTION]		= PERF_BR_SYSCALL,
	[CTRDATA_TYPE_INTERRUPT]		= PERF_BR_IRQ,
	[CTRDATA_TYPE_TRAP_RET]			= PERF_BR_ERET,
	[CTRDATA_TYPE_NONTAKEN_BRANCH]		= PERF_BR_COND,
	[CTRDATA_TYPE_TAKEN_BRANCH]		= PERF_BR_COND,
	[CTRDATA_TYPE_RESERVED_6]		= PERF_BR_UNKNOWN,
	[CTRDATA_TYPE_RESERVED_7]		= PERF_BR_UNKNOWN,
	[CTRDATA_TYPE_INDIRECT_CALL]		= PERF_BR_IND_CALL,
	[CTRDATA_TYPE_DIRECT_CALL]		= PERF_BR_CALL,
	[CTRDATA_TYPE_INDIRECT_JUMP]		= PERF_BR_IND,
	[CTRDATA_TYPE_DIRECT_JUMP]		= PERF_BR_UNCOND,
	[CTRDATA_TYPE_CO_ROUTINE_SWAP]		= PERF_BR_UNKNOWN,
	[CTRDATA_TYPE_RETURN]			= PERF_BR_RET,
	[CTRDATA_TYPE_OTHER_INDIRECT_JUMP]	= PERF_BR_IND,
	[CTRDATA_TYPE_OTHER_DIRECT_JUMP]	= PERF_BR_UNCOND,
};

static void ctr_set_perf_entry_type(struct perf_branch_entry *entry,
				    u64 ctr_data)
{
	int ctr_type = ctr_get_type(ctr_data);

	entry->type = ctr_perf_map[ctr_type];
	if (entry->type == PERF_BR_UNKNOWN)
		pr_warn("%d - unknown branch type captured\n", ctr_type);
}

static void capture_ctr_flags(struct perf_branch_entry *entry,
			      struct perf_event *event, u64 ctr_data,
			      u64 ctr_target)
{
	if (branch_sample_type(event))
		ctr_set_perf_entry_type(entry, ctr_data);

	if (!branch_sample_no_cycles(event))
		entry->cycles = ctr_get_cycles(ctr_data);

	if (!branch_sample_no_flags(event)) {
		entry->abort = 0;
		entry->mispred = ctr_get_mispredict(ctr_target);
		entry->predicted = !entry->mispred;
	}

	if (branch_sample_priv(event))
		entry->priv = PERF_BR_PRIV_UNKNOWN;
}

static void ctr_regset_to_branch_entry(struct cpu_hw_events *cpuc,
				       struct perf_event *event,
				       struct ctr_regset *regset,
				       unsigned int idx)
{
	struct perf_branch_entry *entry = &cpuc->branches->branch_entries[idx];

	*entry = (struct perf_branch_entry){ };
	entry->from = regset->src & (~CTRSOURCE_VALID);
	entry->to = regset->target & (~CTRTARGET_MISP);
	capture_ctr_flags(entry, event, regset->ctr_data, regset->target);
}

static void ctr_read_entries(struct cpu_hw_events *cpuc,
			     struct perf_event *event,
			     unsigned int depth)
{
	struct ctr_regset entry = {};
	u64 ctr_ctl;
	int i;

	ctr_ctl = csr_read_clear(CSR_CTRCTL, CTR_BRANCH_ENABLE_BITS);

	for (i = 0; i < depth; i++) {
		if (!get_ctr_regset(&entry, i))
			break;

		ctr_regset_to_branch_entry(cpuc, event, &entry, i);
	}

	csr_set(CSR_CTRCTL, ctr_ctl & CTR_BRANCH_ENABLE_BITS);

	cpuc->branches->branch_stack.nr = i;
	cpuc->branches->branch_stack.hw_idx = 0;
}

bool riscv_pmu_ctr_valid(struct perf_event *event)
{
	u64 branch_type = event->attr.branch_sample_type;

	if (branch_type & ~allowed_filters) {
		pr_debug_once("Requested branch filters not supported 0x%llx\n",
			      branch_type & ~allowed_filters);
		return false;
	}

	return true;
}

void riscv_pmu_ctr_consume(struct cpu_hw_events *cpuc, struct perf_event *event)
{
	unsigned int depth = to_riscv_pmu(event->pmu)->ctr_depth;

	ctr_read_entries(cpuc, event, depth);

	/* Clear frozen bit. */
	csr_clear(CSR_SCTRSTATUS, SCTRSTATUS_FROZEN);
}

static void riscv_pmu_ctr_reset(void)
{
	/* FIXME: Replace with sctrclr instruction once support is merged
	 * into toolchain.
	 */
	asm volatile(".4byte 0x10400073\n" ::: "memory");
	csr_write(CSR_SCTRSTATUS, 0);
}

static void __riscv_pmu_ctr_restore(void *ctx)
{
	struct riscv_perf_task_context *task_ctx = ctx;
	unsigned int i;

	csr_write(CSR_SCTRSTATUS, task_ctx->ctr_status);

	for (i = 0; i < task_ctx->num_entries; i++)
		set_ctr_regset(&task_ctx->store[i], i);
}

static void riscv_pmu_ctr_restore(void *ctx)
{
	if (task_context(ctx)->stack_state == CTR_STATE_NONE ||
	    task_context(ctx)->callstack_users == 0) {
		return;
	}

	riscv_pmu_ctr_reset();
	__riscv_pmu_ctr_restore(ctx);

	task_context(ctx)->stack_state = CTR_STATE_NONE;
}

static void __riscv_pmu_ctr_save(void *ctx, unsigned int depth)
{
	struct riscv_perf_task_context *task_ctx = ctx;
	struct ctr_regset *dst;
	unsigned int i;

	for (i = 0; i < depth; i++) {
		dst = &task_ctx->store[i];
		if (!get_ctr_regset(dst, i))
			break;
	}

	task_ctx->num_entries = i;

	task_ctx->ctr_status = csr_read(CSR_SCTRSTATUS);
}

static void riscv_pmu_ctr_save(void *ctx, unsigned int depth)
{
	if (task_context(ctx)->stack_state == CTR_STATE_VALID)
		return;

	if (task_context(ctx)->callstack_users == 0) {
		task_context(ctx)->stack_state = CTR_STATE_NONE;
		return;
	}

	__riscv_pmu_ctr_save(ctx, depth);

	task_context(ctx)->stack_state = CTR_STATE_VALID;
}

/*
 * On context switch in, we need to make sure no samples from previous tasks
 * are left in the CTR.
 *
 * On ctxswin, sched_in = true, called after the PMU has started
 * On ctxswout, sched_in = false, called before the PMU is stopped
 */
void riscv_pmu_ctr_sched_task(struct perf_event_pmu_context *pmu_ctx, struct task_struct *task,
			      bool sched_in)
{
	struct riscv_pmu *rvpmu = to_riscv_pmu(pmu_ctx->pmu);
	struct cpu_hw_events *cpuc = this_cpu_ptr(rvpmu->hw_events);
	void *task_ctx;

	if (!cpuc->ctr_users)
		return;

	/* Save branch records in task_ctx on sched out */
	task_ctx = pmu_ctx ? task->perf_ctx_data : NULL;
	if (task_ctx) {
		if (sched_in)
			riscv_pmu_ctr_restore(task_ctx);
		else
			riscv_pmu_ctr_save(task_ctx, rvpmu->ctr_depth);
		return;
	}

	/* Reset branch records on sched in */
	if (sched_in)
		riscv_pmu_ctr_reset();
}

static inline bool branch_user_callstack(unsigned int br_type)
{
	return (br_type & PERF_SAMPLE_BRANCH_USER) &&
		(br_type & PERF_SAMPLE_BRANCH_CALL_STACK);
}

void riscv_pmu_ctr_add(struct perf_event *event)
{
	struct riscv_pmu *rvpmu = to_riscv_pmu(event->pmu);
	struct cpu_hw_events *cpuc = this_cpu_ptr(rvpmu->hw_events);

	if (branch_user_callstack(event->attr.branch_sample_type) &&
	    event->ctx->task->perf_ctx_data)
		task_context(event->ctx->task->perf_ctx_data)->callstack_users++;

	perf_sched_cb_inc(event->pmu);

	if (!cpuc->ctr_users++)
		riscv_pmu_ctr_reset();
}

void riscv_pmu_ctr_del(struct perf_event *event)
{
	struct riscv_pmu *rvpmu = to_riscv_pmu(event->pmu);
	struct cpu_hw_events *cpuc = this_cpu_ptr(rvpmu->hw_events);

	if (branch_user_callstack(event->attr.branch_sample_type) &&
	    event->ctx->task->perf_ctx_data)
		task_context(event->ctx->task->perf_ctx_data)->callstack_users--;

	perf_sched_cb_dec(event->pmu);
	cpuc->ctr_users--;
	WARN_ON_ONCE(cpuc->ctr_users < 0);
}

void riscv_pmu_ctr_enable(struct perf_event *event)
{
	u64 branch_type = event->attr.branch_sample_type;
	u64 ctr;

	ctr = branch_type_to_ctr(branch_type);
	csr_write(CSR_CTRCTL, ctr);
}

void riscv_pmu_ctr_disable(struct perf_event *event)
{
	/* Clear CTRCTL to disable the recording. */
	csr_write(CSR_CTRCTL, 0);
}

/*
 * Check for hardware supported perf filters here. To avoid missing
 * any new added filter in perf, we do a BUILD_BUG_ON check, so make sure
 * to update CTR_ALLOWED_BRANCH_FILTERS or CTR_EXCLUDE_BRANCH_FILTERS
 * defines when adding support for it in below function.
 */
static void __init check_available_filters(void)
{
	u64 ctr_ctl;

	/*
	 * Ensure both perf branch filter allowed and exclude
	 * masks are always in sync with the generic perf ABI.
	 */
	BUILD_BUG_ON(CTR_PERF_BRANCH_FILTERS != (PERF_SAMPLE_BRANCH_MAX - 1));

	allowed_filters = PERF_SAMPLE_BRANCH_USER      |
			  PERF_SAMPLE_BRANCH_KERNEL    |
			  PERF_SAMPLE_BRANCH_ANY       |
			  PERF_SAMPLE_BRANCH_HW_INDEX  |
			  PERF_SAMPLE_BRANCH_NO_FLAGS  |
			  PERF_SAMPLE_BRANCH_NO_CYCLES |
			  PERF_SAMPLE_BRANCH_TYPE_SAVE;

	csr_write(CSR_CTRCTL, ~0);
	ctr_ctl = csr_read(CSR_CTRCTL);
	csr_write(CSR_CTRCTL, 0);

	if (riscv_isa_extension_available(NULL, H))
		allowed_filters |= PERF_SAMPLE_BRANCH_HV;

	if (ctr_ctl & (CTRCTL_INDCALL_INH | CTRCTL_DIRCALL_INH))
		allowed_filters |= PERF_SAMPLE_BRANCH_ANY_CALL;

	if (ctr_ctl & (CTRCTL_RET_INH | CTRCTL_TRETINH))
		allowed_filters |= PERF_SAMPLE_BRANCH_ANY_RETURN;

	if (ctr_ctl & CTRCTL_INDCALL_INH)
		allowed_filters |= PERF_SAMPLE_BRANCH_IND_CALL;

	if (ctr_ctl & CTRCTL_TKBRINH)
		allowed_filters |= PERF_SAMPLE_BRANCH_COND;

	if (ctr_ctl & CTRCTL_RASEMU)
		allowed_filters |= PERF_SAMPLE_BRANCH_CALL_STACK;

	if (ctr_ctl & (CTRCTL_INDOJUMP_INH | CTRCTL_INDJUMP_INH))
		allowed_filters |= PERF_SAMPLE_BRANCH_IND_JUMP;

	if (ctr_ctl & CTRCTL_DIRCALL_INH)
		allowed_filters |= PERF_SAMPLE_BRANCH_CALL;
}

void riscv_pmu_ctr_starting_cpu(void)
{
	if (!riscv_isa_extension_available(NULL, SxCTR) ||
	    !riscv_isa_extension_available(NULL, SSCOFPMF))
		return;

	/* Set depth to maximum. */
	csr_write(CSR_SCTRDEPTH, SCTRDEPTH_MASK);
}

void riscv_pmu_ctr_dying_cpu(void)
{
	if (!riscv_isa_extension_available(NULL, SxCTR) ||
	    !riscv_isa_extension_available(NULL, SSCOFPMF))
		return;

	/* Clear and reset CTR CSRs. */
	csr_write(CSR_SCTRDEPTH, 0);
	csr_write(CSR_CTRCTL, 0);
	riscv_pmu_ctr_reset();
}

int riscv_pmu_ctr_init(struct riscv_pmu *riscv_pmu)
{
	size_t size = sizeof(struct riscv_perf_task_context);

	if (!riscv_isa_extension_available(NULL, SxCTR) ||
	    !riscv_isa_extension_available(NULL, SSCOFPMF))
		return 0;

	riscv_pmu->pmu.task_ctx_cache =
		kmem_cache_create("ctr_task_ctx", size, sizeof(u64), 0, NULL);
	if (!riscv_pmu->pmu.task_ctx_cache)
		return -ENOMEM;

	check_available_filters();

	/* Set depth to maximum. */
	csr_write(CSR_SCTRDEPTH, SCTRDEPTH_MASK);
	riscv_pmu->ctr_depth = ctr_get_depth(csr_read(CSR_SCTRDEPTH));

	pr_info("Perf CTR available, with %d depth\n", riscv_pmu->ctr_depth);

	return 0;
}

void riscv_pmu_ctr_finish(struct riscv_pmu *riscv_pmu)
{
	if (!riscv_pmu_ctr_supported(riscv_pmu))
		return;

	riscv_pmu->ctr_depth = 0;
	csr_write(CSR_SCTRDEPTH, 0);
	csr_write(CSR_CTRCTL, 0);
	riscv_pmu_ctr_reset();

	kmem_cache_destroy(riscv_pmu->pmu.task_ctx_cache);
}
