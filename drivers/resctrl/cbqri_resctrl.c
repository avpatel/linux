// SPDX-License-Identifier: GPL-2.0-only

#define pr_fmt(fmt) "%s:%s: " fmt, KBUILD_MODNAME, __func__

#include <linux/bitfield.h>
#include <linux/cacheinfo.h>
#include <linux/cleanup.h>
#include <linux/riscv_cbqri.h>
#include <linux/cpu.h>
#include <linux/cpufeature.h>
#include <linux/cpuhotplug.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/rculist.h>
#include <linux/resctrl.h>
#include <linux/slab.h>
#include <linux/types.h>

#include <asm/csr.h>
#include <asm/qos.h>

#include "cbqri_internal.h"

struct cbqri_resctrl_res {
	struct cbqri_controller *ctrl;
	struct rdt_resource     resctrl_res;
	bool                    cdp_enabled;
};

struct cbqri_resctrl_dom {
	struct rdt_ctrl_domain  resctrl_ctrl_dom;
	struct cbqri_controller *hw_ctrl;
};

static struct cbqri_resctrl_res cbqri_resctrl_resources[RDT_NUM_RESOURCES];

static bool exposed_alloc_capable;

/* Protects ctrl_domain list mutations across CPU hotplug. */
static DEFINE_MUTEX(cbqri_domain_list_lock);

static struct rdt_ctrl_domain *
cbqri_find_ctrl_domain(struct list_head *h, int id)
{
	struct rdt_domain_hdr *hdr = resctrl_find_domain(h, id, NULL);

	return hdr ? container_of(hdr, struct rdt_ctrl_domain, hdr) : NULL;
}

/* Map a hardware cache level to its resctrl resource id, or -ENODEV. */
static int cbqri_cache_level_to_rid(u32 cache_level)
{
	switch (cache_level) {
	case 2:
		return RDT_RESOURCE_L2;
	case 3:
		return RDT_RESOURCE_L3;
	default:
		return -ENODEV;
	}
}

static int cbqri_apply_cache_config_dom(struct cbqri_resctrl_dom *hw_dom,
					struct rdt_resource *r,
					u32 closid, enum resctrl_conf_type t,
					u64 cbm)
{
	struct cbqri_resctrl_res *hw_res =
		container_of(r, struct cbqri_resctrl_res, resctrl_res);
	struct cbqri_cc_config cfg = {
		.cbm = cbm,
		.at = (t == CDP_CODE) ? CBQRI_CONTROL_REGISTERS_AT_CODE :
					CBQRI_CONTROL_REGISTERS_AT_DATA,
		.cdp_enabled = hw_res->cdp_enabled,
	};

	return cbqri_apply_cache_config(hw_dom->hw_ctrl, closid, &cfg);
}

bool resctrl_arch_alloc_capable(void)
{
	return exposed_alloc_capable;
}

bool resctrl_arch_mon_capable(void)
{
	return false;
}

bool resctrl_arch_get_cdp_enabled(enum resctrl_res_level rid)
{
	if (rid != RDT_RESOURCE_L2 && rid != RDT_RESOURCE_L3)
		return false;
	return cbqri_resctrl_resources[rid].cdp_enabled;
}

int resctrl_arch_set_cdp_enabled(enum resctrl_res_level rid, bool enable)
{
	struct cbqri_resctrl_res *cbqri_res;

	if (rid != RDT_RESOURCE_L2 && rid != RDT_RESOURCE_L3)
		return -ENODEV;

	cbqri_res = &cbqri_resctrl_resources[rid];
	if (!cbqri_res->resctrl_res.cdp_capable)
		return -ENODEV;

	cbqri_res->cdp_enabled = enable;
	return 0;
}

struct rdt_resource *resctrl_arch_get_resource(enum resctrl_res_level l)
{
	if (l >= RDT_NUM_RESOURCES)
		return NULL;

	return &cbqri_resctrl_resources[l].resctrl_res;
}

bool resctrl_arch_is_evt_configurable(enum resctrl_event_id evt)
{
	return false;
}

void *resctrl_arch_mon_ctx_alloc(struct rdt_resource *r,
				 enum resctrl_event_id evtid)
{
	return NULL;
}

void resctrl_arch_mon_ctx_free(struct rdt_resource *r,
			       enum resctrl_event_id evtid, void *arch_mon_ctx)
{
}

void resctrl_arch_config_cntr(struct rdt_resource *r, struct rdt_l3_mon_domain *d,
			      enum resctrl_event_id evtid, u32 rmid, u32 closid,
			      u32 cntr_id, bool assign)
{
}

int resctrl_arch_cntr_read(struct rdt_resource *r, struct rdt_l3_mon_domain *d,
			   u32 unused, u32 rmid, int cntr_id,
			   enum resctrl_event_id eventid, u64 *val)
{
	return -EOPNOTSUPP;
}

bool resctrl_arch_mbm_cntr_assign_enabled(struct rdt_resource *r)
{
	return false;
}

int resctrl_arch_mbm_cntr_assign_set(struct rdt_resource *r, bool enable)
{
	return -EOPNOTSUPP;
}

void resctrl_arch_reset_cntr(struct rdt_resource *r, struct rdt_l3_mon_domain *d,
			     u32 unused, u32 rmid, int cntr_id,
			     enum resctrl_event_id eventid)
{
}

bool resctrl_arch_get_io_alloc_enabled(struct rdt_resource *r)
{
	return false;
}

int resctrl_arch_io_alloc_enable(struct rdt_resource *r, bool enable)
{
	return -EOPNOTSUPP;
}

void resctrl_arch_mon_event_config_read(void *info)
{
}

void resctrl_arch_mon_event_config_write(void *info)
{
}

void resctrl_arch_reset_rmid_all(struct rdt_resource *r, struct rdt_l3_mon_domain *d)
{
}

void resctrl_arch_reset_rmid(struct rdt_resource *r, struct rdt_l3_mon_domain *d,
			     u32 unused, u32 rmid, enum resctrl_event_id eventid)
{
}

int resctrl_arch_rmid_read(struct rdt_resource *r, struct rdt_domain_hdr *hdr,
			   u32 closid, u32 rmid, enum resctrl_event_id eventid,
			   void *arch_priv, u64 *val, void *arch_mon_ctx)
{
	return -ENODATA;
}

/*
 * Note about terminology between x86 (Intel RDT/AMD QoS) and RISC-V:
 *   CLOSID on x86 is RCID on RISC-V
 *     RMID on x86 is MCID on RISC-V
 */
u32 resctrl_arch_get_num_closid(struct rdt_resource *res)
{
	struct cbqri_resctrl_res *hw_res;

	hw_res = container_of(res, struct cbqri_resctrl_res, resctrl_res);

	if (!hw_res->ctrl)
		return 0;

	return hw_res->ctrl->rcid_count;
}

u32 resctrl_arch_system_num_rmid_idx(void)
{
	return 1;
}

u32 resctrl_arch_rmid_idx_encode(u32 closid, u32 rmid)
{
	return rmid;
}

void resctrl_arch_rmid_idx_decode(u32 idx, u32 *closid, u32 *rmid)
{
	*closid = RISCV_RESCTRL_EMPTY_CLOSID;
	*rmid = idx;
}

void resctrl_arch_set_cpu_default_closid_rmid(int cpu, u32 closid, u32 rmid)
{
	u32 srmcfg = FIELD_PREP(SRMCFG_RCID_MASK, closid) |
		     FIELD_PREP(SRMCFG_MCID_MASK, rmid);

	WRITE_ONCE(per_cpu(cpu_srmcfg_default, cpu), srmcfg);
}

void resctrl_arch_sched_in(struct task_struct *tsk)
{
	__switch_to_srmcfg(tsk);
}

void resctrl_arch_set_closid_rmid(struct task_struct *tsk, u32 closid, u32 rmid)
{
	u32 srmcfg = FIELD_PREP(SRMCFG_RCID_MASK, closid) |
		     FIELD_PREP(SRMCFG_MCID_MASK, rmid);

	WRITE_ONCE(tsk->thread.srmcfg, srmcfg);
}

void resctrl_arch_sync_cpu_closid_rmid(void *info)
{
	struct resctrl_cpu_defaults *r = info;

	lockdep_assert_preemption_disabled();

	if (r) {
		resctrl_arch_set_cpu_default_closid_rmid(smp_processor_id(),
							 r->closid, r->rmid);
	}

	resctrl_arch_sched_in(current);
}

bool resctrl_arch_match_closid(struct task_struct *tsk, u32 closid)
{
	return FIELD_GET(SRMCFG_RCID_MASK, READ_ONCE(tsk->thread.srmcfg)) == closid;
}

bool resctrl_arch_match_rmid(struct task_struct *tsk, u32 closid, u32 rmid)
{
	return FIELD_GET(SRMCFG_MCID_MASK, READ_ONCE(tsk->thread.srmcfg)) == rmid;
}

void resctrl_arch_pre_mount(void)
{
	/* All controllers discovered at boot via late_initcall. Nothing to do. */
}

int resctrl_arch_update_one(struct rdt_resource *r, struct rdt_ctrl_domain *d,
			    u32 closid, enum resctrl_conf_type t, u32 cfg_val)
{
	struct cbqri_resctrl_dom *dom;

	dom = container_of(d, struct cbqri_resctrl_dom, resctrl_ctrl_dom);

	if (!r->alloc_capable)
		return -EINVAL;

	switch (r->rid) {
	case RDT_RESOURCE_L2:
	case RDT_RESOURCE_L3:
		return cbqri_apply_cache_config_dom(dom, r, closid, t, cfg_val);
	default:
		return -EINVAL;
	}
}

int resctrl_arch_update_domains(struct rdt_resource *r, u32 closid)
{
	struct resctrl_staged_config *cfg;
	enum resctrl_conf_type t;
	struct rdt_ctrl_domain *d;
	int err = 0;

	/* Walking r->ctrl_domains, ensure it can't race with cpuhp */
	lockdep_assert_cpus_held();

	list_for_each_entry(d, &r->ctrl_domains, hdr.list) {
		for (t = 0; t < CDP_NUM_TYPES; t++) {
			cfg = &d->staged_config[t];
			if (!cfg->have_new_ctrl)
				continue;
			err = resctrl_arch_update_one(r, d, closid, t, cfg->new_ctrl);
			if (err)
				return err;
		}
	}
	return err;
}

u32 resctrl_arch_get_config(struct rdt_resource *r, struct rdt_ctrl_domain *d,
			    u32 closid, enum resctrl_conf_type type)
{
	struct cbqri_resctrl_dom *hw_dom;
	struct cbqri_controller *ctrl;
	u32 at;
	u32 val;
	int err;

	hw_dom = container_of(d, struct cbqri_resctrl_dom, resctrl_ctrl_dom);
	ctrl = hw_dom->hw_ctrl;
	val = resctrl_get_default_ctrl(r);

	if (!r->alloc_capable)
		return val;

	switch (r->rid) {
	case RDT_RESOURCE_L2:
	case RDT_RESOURCE_L3:
		at = (type == CDP_CODE) ? CBQRI_CONTROL_REGISTERS_AT_CODE :
					  CBQRI_CONTROL_REGISTERS_AT_DATA;
		err = cbqri_read_cache_config(ctrl, closid, at, &val);
		if (err < 0)
			val = resctrl_get_default_ctrl(r);
		break;
	default:
		break;
	}

	return val;
}

void resctrl_arch_reset_all_ctrls(struct rdt_resource *r)
{
	struct cbqri_resctrl_res *hw_res;
	struct rdt_ctrl_domain *d;
	enum resctrl_conf_type t;
	u32 default_ctrl;
	int i;

	lockdep_assert_cpus_held();

	hw_res = container_of(r, struct cbqri_resctrl_res, resctrl_res);
	default_ctrl = resctrl_get_default_ctrl(r);

	if (!hw_res->ctrl)
		return;

	list_for_each_entry(d, &r->ctrl_domains, hdr.list) {
		for (i = 0; i < hw_res->ctrl->rcid_count; i++) {
			for (t = 0; t < CDP_NUM_TYPES; t++) {
				int rerr;

				rerr = resctrl_arch_update_one(r, d, i, t, default_ctrl);
				if (rerr)
					pr_err_ratelimited("rid=%d reset RCID %u type %u failed (%d)\n",
							   r->rid, i, t, rerr);
			}
		}
	}
}

static struct rdt_ctrl_domain *cbqri_new_domain(struct cbqri_controller *ctrl)
{
	struct cbqri_resctrl_dom *hw_dom;
	struct rdt_ctrl_domain *domain;

	hw_dom = kzalloc_obj(*hw_dom, GFP_KERNEL);
	if (!hw_dom)
		return NULL;

	hw_dom->hw_ctrl = ctrl;
	domain = &hw_dom->resctrl_ctrl_dom;

	INIT_LIST_HEAD(&domain->hdr.list);

	return domain;
}

static int cbqri_init_domain_ctrlval(struct rdt_resource *r, struct rdt_ctrl_domain *d)
{
	struct cbqri_resctrl_dom *hw_dom;
	enum resctrl_conf_type t;
	int err = 0;
	int i;

	hw_dom = container_of(d, struct cbqri_resctrl_dom, resctrl_ctrl_dom);

	for (i = 0; i < hw_dom->hw_ctrl->rcid_count; i++) {
		/*
		 * Seed both DATA and CODE staged slots so a later mount
		 * with -o cdp does not see stale CODE values.
		 * On non-AT controllers cbqri_cc_alloc_op() masks AT to 0
		 * so all three iterations land on the same hardware state.
		 * The redundant writes are harmless.
		 */
		for (t = 0; t < CDP_NUM_TYPES; t++) {
			err = resctrl_arch_update_one(r, d, i, t,
						      resctrl_get_default_ctrl(r));
			if (err)
				return err;
		}
	}
	return 0;
}

/*
 * Two capacity controllers at the same cache level are interchangeable to
 * resctrl only if they expose identical caps, since resctrl publishes one
 * set of caps per rid but any of the level's controllers may service a
 * given RCID.
 */
static bool cbqri_cc_caps_agree(const struct cbqri_controller *a,
				const struct cbqri_controller *b)
{
	return a->rcid_count == b->rcid_count &&
	       a->cc.ncblks == b->cc.ncblks &&
	       a->cc.supports_alloc_at_code == b->cc.supports_alloc_at_code &&
	       a->alloc_capable == b->alloc_capable;
}

/*
 * Walk cbqri_controllers and pick one capacity controller (CC) per cache
 * level (L2/L3) to back the corresponding RDT_RESOURCE_L*. When more than
 * one CC sits at the same level (e.g. one per socket), they must agree on
 * rcid_count / ncblks / supports_alloc_at_code / alloc_capable. A level
 * whose controllers disagree is dropped, since resctrl exposes a single
 * set of caps per rid, but the other level is still picked. The first
 * matching controller wins.
 */
static void cbqri_resctrl_pick_caches(void)
{
	struct cbqri_controller *ctrl, *pick;
	int rid;

	guard(mutex)(&cbqri_controllers_lock);

	for (rid = 0; rid < RDT_NUM_RESOURCES; rid++) {
		pick = NULL;

		list_for_each_entry(ctrl, &cbqri_controllers, list) {
			if (ctrl->type != CBQRI_CONTROLLER_TYPE_CAPACITY ||
			    !ctrl->alloc_capable ||
			    cbqri_cache_level_to_rid(ctrl->cache.cache_level) != rid)
				continue;

			if (!pick) {
				pick = ctrl;
			} else if (!cbqri_cc_caps_agree(pick, ctrl)) {
				pr_err("L%u controllers have mismatched capabilities, skipping this level\n",
				       ctrl->cache.cache_level);
				pick = NULL;
				break;
			}
		}

		cbqri_resctrl_resources[rid].ctrl = pick;
	}
}

/*
 * Fill the rdt_resource fields for one picked rid. An rid with no picked
 * controller is left untouched so it stays out of resctrl_arch_get_resource().
 */
static void cbqri_resctrl_control_init(struct cbqri_resctrl_res *cbqri_res)
{
	struct cbqri_controller *ctrl = cbqri_res->ctrl;
	struct rdt_resource *res = &cbqri_res->resctrl_res;

	if (!ctrl)
		return;

	switch (res->rid) {
	case RDT_RESOURCE_L2:
	case RDT_RESOURCE_L3:
		res->name = (res->rid == RDT_RESOURCE_L2) ? "L2" : "L3";
		res->schema_fmt = RESCTRL_SCHEMA_BITMAP;
		res->ctrl_scope = (res->rid == RDT_RESOURCE_L2) ?
				    RESCTRL_L2_CACHE : RESCTRL_L3_CACHE;
		res->cache.cbm_len = ctrl->cc.ncblks;
		res->cache.shareable_bits = 0;
		res->cache.min_cbm_bits = 1;
		res->cache.arch_has_sparse_bitmasks = false;
		res->cdp_capable = ctrl->cc.supports_alloc_at_code;
		res->alloc_capable = ctrl->alloc_capable;
		INIT_LIST_HEAD(&res->ctrl_domains);
		INIT_LIST_HEAD(&res->mon_domains);
		break;
	default:
		break;
	}
}

static void cbqri_resctrl_accumulate_caps(void)
{
	int rid;

	for (rid = 0; rid < RDT_NUM_RESOURCES; rid++) {
		struct cbqri_resctrl_res *hw_res = &cbqri_resctrl_resources[rid];

		if (!hw_res->ctrl)
			continue;
		if (hw_res->ctrl->alloc_capable)
			exposed_alloc_capable = true;
	}
}

/*
 * Create, list-insert, and online a fresh ctrl_domain backing ctrl on
 * resource res, seeded with cpu and identified by dom_id. Caller must
 * hold cbqri_domain_list_lock and must have already verified that no
 * existing ctrl_domain on res carries this id.
 */
static struct rdt_ctrl_domain *cbqri_create_ctrl_domain(struct cbqri_controller *ctrl,
							struct rdt_resource *res,
							unsigned int cpu, int dom_id)
{
	struct rdt_ctrl_domain *domain;
	struct list_head *pos = NULL;
	int err;

	domain = cbqri_new_domain(ctrl);
	if (!domain)
		return ERR_PTR(-ENOMEM);

	cpumask_set_cpu(cpu, &domain->hdr.cpu_mask);
	domain->hdr.id = dom_id;
	domain->hdr.type = RESCTRL_CTRL_DOMAIN;
	domain->hdr.rid = res->rid;

	err = cbqri_init_domain_ctrlval(res, domain);
	if (err)
		goto free;

	err = resctrl_online_ctrl_domain(res, domain);
	if (err)
		goto free;

	/*
	 * Publish only after the domain is fully initialized and online, so a
	 * reader walking the RCU list never sees a half-built domain.
	 */
	resctrl_find_domain(&res->ctrl_domains, dom_id, &pos);
	list_add_tail_rcu(&domain->hdr.list, pos);

	return domain;
free:
	kfree(container_of(domain, struct cbqri_resctrl_dom, resctrl_ctrl_dom));
	return ERR_PTR(err);
}

/*
 * Remove a CPU from the domain at each level whose cache it shares. The
 * domain is looked up by the CPU's own cache id and the lookup returns NULL
 * if it is already gone, so this is idempotent and undoes a partial online
 * attach as well as a full offline. Caller holds cbqri_domain_list_lock.
 */
static void cbqri_detach_cpu_from_all_ctrls(unsigned int cpu)
{
	static const u32 levels[] = { 2, 3 };
	struct cbqri_resctrl_res *hw_res;
	struct rdt_ctrl_domain *d;
	struct rdt_resource *res;
	struct cacheinfo *ci;
	int i, rid;

	lockdep_assert_held(&cbqri_domain_list_lock);

	for (i = 0; i < ARRAY_SIZE(levels); i++) {
		ci = get_cpu_cacheinfo_level(cpu, levels[i]);
		if (!ci)
			continue;

		rid = cbqri_cache_level_to_rid(levels[i]);
		hw_res = &cbqri_resctrl_resources[rid];
		if (!hw_res->ctrl)
			continue;

		res = &hw_res->resctrl_res;
		d = cbqri_find_ctrl_domain(&res->ctrl_domains, ci->id);
		if (!d)
			continue;

		cpumask_clear_cpu(cpu, &d->hdr.cpu_mask);
		if (cpumask_empty(&d->hdr.cpu_mask)) {
			list_del_rcu(&d->hdr.list);
			synchronize_rcu();
			resctrl_offline_ctrl_domain(res, d);
			kfree(container_of(d, struct cbqri_resctrl_dom,
					   resctrl_ctrl_dom));
		}
	}
}

/*
 * Attach a CPU to the capacity controller at each cache level whose cache
 * the CPU shares. On failure, detach the CPU from everything attached so
 * far: the cpuhp core does not run this state's offline teardown when its
 * startup fails, so a partial attach would otherwise leak into the domain
 * cpu_masks. Caller holds cbqri_domain_list_lock.
 */
static int cbqri_attach_cpu_to_all_ctrls(unsigned int cpu)
{
	static const u32 levels[] = { 2, 3 };
	struct cbqri_controller *ctrl, *c;
	struct cbqri_resctrl_res *hw_res;
	struct rdt_ctrl_domain *d;
	struct cacheinfo *ci;
	int i, rid;

	lockdep_assert_held(&cbqri_domain_list_lock);

	/*
	 * Hold cbqri_controllers_lock across the walk so a controller
	 * registered after boot cannot corrupt it. The register path takes
	 * it as a leaf and never cbqri_domain_list_lock, so this nesting
	 * cannot invert.
	 */
	guard(mutex)(&cbqri_controllers_lock);

	for (i = 0; i < ARRAY_SIZE(levels); i++) {
		ci = get_cpu_cacheinfo_level(cpu, levels[i]);
		if (!ci)
			continue;

		rid = cbqri_cache_level_to_rid(levels[i]);
		hw_res = &cbqri_resctrl_resources[rid];
		if (!hw_res->ctrl)
			continue;

		/* The controller backing this CPU's cache at this level. */
		ctrl = NULL;
		list_for_each_entry(c, &cbqri_controllers, list) {
			if (c->type == CBQRI_CONTROLLER_TYPE_CAPACITY &&
			    c->alloc_capable &&
			    c->cache.cache_level == levels[i] &&
			    c->cache.cache_id == ci->id) {
				ctrl = c;
				break;
			}
		}
		if (!ctrl)
			continue;

		d = cbqri_find_ctrl_domain(&hw_res->resctrl_res.ctrl_domains,
					   ci->id);
		if (d) {
			cpumask_set_cpu(cpu, &d->hdr.cpu_mask);
			continue;
		}

		d = cbqri_create_ctrl_domain(ctrl, &hw_res->resctrl_res, cpu,
					     ci->id);
		if (IS_ERR(d)) {
			cbqri_detach_cpu_from_all_ctrls(cpu);
			return PTR_ERR(d);
		}
	}

	return 0;
}

static bool cbqri_resctrl_inited;

static void cbqri_resctrl_teardown(void)
{
	int rid;

	if (!cbqri_resctrl_inited)
		return;

	resctrl_exit();

	for (rid = 0; rid < RDT_NUM_RESOURCES; rid++) {
		struct cbqri_resctrl_res *hw_res = &cbqri_resctrl_resources[rid];

		hw_res->ctrl = NULL;
		hw_res->cdp_enabled = false;
	}
	exposed_alloc_capable = false;
	cbqri_resctrl_inited = false;
}

static int cbqri_resctrl_setup(void)
{
	int rid;
	int err;

	for (rid = 0; rid < RDT_NUM_RESOURCES; rid++)
		cbqri_resctrl_resources[rid].resctrl_res.rid = rid;

	cbqri_resctrl_pick_caches();

	for (rid = 0; rid < RDT_NUM_RESOURCES; rid++)
		cbqri_resctrl_control_init(&cbqri_resctrl_resources[rid]);

	cbqri_resctrl_accumulate_caps();

	if (!exposed_alloc_capable) {
		pr_debug("no resctrl-capable CBQRI controllers found\n");
		return -ENODEV;
	}

	err = resctrl_init();
	if (err)
		return err;

	cbqri_resctrl_inited = true;
	return 0;
}

static int cbqri_resctrl_online_cpu(unsigned int cpu)
{
	int err;

	mutex_lock(&cbqri_domain_list_lock);
	err = cbqri_attach_cpu_to_all_ctrls(cpu);
	mutex_unlock(&cbqri_domain_list_lock);
	if (err)
		return err;

	/*
	 * Seed the per-CPU default RCID/MCID to the reserved (0, 0) pair and
	 * notify the resctrl core so it tracks this CPU in the default group.
	 */
	resctrl_arch_set_cpu_default_closid_rmid(cpu, 0, 0);
	resctrl_online_cpu(cpu);
	return 0;
}

static int cbqri_resctrl_offline_cpu(unsigned int cpu)
{
	resctrl_offline_cpu(cpu);

	mutex_lock(&cbqri_domain_list_lock);
	cbqri_detach_cpu_from_all_ctrls(cpu);
	mutex_unlock(&cbqri_domain_list_lock);
	return 0;
}

static int __init cbqri_arch_late_init(void)
{
	int err;

	if (!riscv_isa_extension_available(NULL, SSQOSID))
		return -ENODEV;

	err = cbqri_resctrl_setup();
	if (err)
		return err;

	err = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "cbqri:online",
				cbqri_resctrl_online_cpu,
				cbqri_resctrl_offline_cpu);
	if (err < 0) {
		cbqri_resctrl_teardown();
		return err;
	}

	return 0;
}
late_initcall(cbqri_arch_late_init);
