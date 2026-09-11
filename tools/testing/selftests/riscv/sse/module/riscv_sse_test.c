// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2025 Rivos Inc.
 */

#define pr_fmt(fmt) "riscv_sse_test: " fmt

#include <linux/array_size.h>
#include <linux/atomic.h>
#include <linux/completion.h>
#include <linux/cpu.h>
#include <linux/cpuhplock.h>
#include <linux/delay.h>
#include <linux/err.h>
#include <linux/hrtimer.h>
#include <linux/io.h>
#include <linux/jiffies.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/riscv_sbi_sse.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include <linux/workqueue.h>

#include <asm/sbi.h>
#include <asm/sse.h>

#define RUN_LOOP_COUNT		1000
#define SSE_FAILED_PREFIX	"FAILED: "
#define SSE_SKIP_PREFIX		"SKIP: "
#define STRESS_DURATION_MS	3000
#define STRESS_INJECT_NS	10000
#define STRESS_REINJECT_DEPTH	10
#define sse_err(...)		pr_err(SSE_FAILED_PREFIX __VA_ARGS__)
#define sse_skip(...)		pr_info(SSE_SKIP_PREFIX __VA_ARGS__)

enum sse_stress_mode {
	SSE_STRESS_OFF,
	SSE_STRESS_AFTER_SMOKE,
	SSE_STRESS_ONLY,
};

static int stress;
module_param(stress, int, 0444);
MODULE_PARM_DESC(stress, "Stress mode: 0=off, 1=after smoke, 2=stress only");

static char *run_id = "unknown";
module_param(run_id, charp, 0444);
MODULE_PARM_DESC(run_id, "Unique identifier used to delimit one test run");

/* Do not report PASS for a capability-only run that handled no event. */
static atomic_t sse_test_handler_count = ATOMIC_INIT(0);
static bool sse_stress_event_can_inject;

struct sse_event_desc {
	u32 evt_id;
	const char *name;
	bool can_inject;
};

static struct sse_event_desc sse_event_descs[] = {
	{
		.evt_id = SBI_SSE_EVENT_LOCAL_HIGH_PRIO_RAS,
		.name = "local_high_prio_ras",
	},
	{
		.evt_id = SBI_SSE_EVENT_LOCAL_DOUBLE_TRAP,
		.name = "local_double_trap",
	},
	{
		.evt_id = SBI_SSE_EVENT_GLOBAL_HIGH_PRIO_RAS,
		.name = "global_high_prio_ras",
	},
	{
		.evt_id = SBI_SSE_EVENT_LOCAL_PMU_OVERFLOW,
		.name = "local_pmu_overflow",
	},
	{
		.evt_id = SBI_SSE_EVENT_LOCAL_LOW_PRIO_RAS,
		.name = "local_low_prio_ras",
	},
	{
		.evt_id = SBI_SSE_EVENT_GLOBAL_LOW_PRIO_RAS,
		.name = "global_low_prio_ras",
	},
	{
		.evt_id = SBI_SSE_EVENT_LOCAL_SOFTWARE_INJECTED,
		.name = "local_software_injected",
	},
	{
		.evt_id = SBI_SSE_EVENT_GLOBAL_SOFTWARE_INJECTED,
		.name = "global_software_injected",
	}
};

static DEFINE_MUTEX(sse_test_cleanup_lock);
/* Firmware permits only one registration for each event ID. */
static struct sse_event *sse_test_cleanup_events[ARRAY_SIZE(sse_event_descs)];

static void sse_test_cleanup_workfn(struct work_struct *work);
static DECLARE_DELAYED_WORK(sse_test_cleanup_work, sse_test_cleanup_workfn);

static void sse_test_queue_cleanup(struct sse_event *event)
{
	int i, free_slot = -1;

	mutex_lock(&sse_test_cleanup_lock);
	for (i = 0; i < ARRAY_SIZE(sse_test_cleanup_events); i++) {
		if (sse_test_cleanup_events[i] == event)
			goto out_schedule;
		if (!sse_test_cleanup_events[i] && free_slot < 0)
			free_slot = i;
	}

	if (WARN_ON_ONCE(free_slot < 0))
		goto out_unlock;

	sse_test_cleanup_events[free_slot] = event;

out_schedule:
	mod_delayed_work(system_wq, &sse_test_cleanup_work,
			 msecs_to_jiffies(100));
out_unlock:
	mutex_unlock(&sse_test_cleanup_lock);
}

static struct sse_event_desc *sse_get_evt_desc(u32 evt)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(sse_event_descs); i++) {
		if (sse_event_descs[i].evt_id == evt)
			return &sse_event_descs[i];
	}

	return NULL;
}

static const char *sse_evt_name(u32 evt)
{
	struct sse_event_desc *desc = sse_get_evt_desc(evt);

	return desc ? desc->name : NULL;
}

static bool sse_test_can_inject_event(u32 evt)
{
	struct sse_event_desc *desc = sse_get_evt_desc(evt);

	return desc ? desc->can_inject : false;
}

/*
 * Firmware can invoke the callback until unregister succeeds. Pin the module
 * so its handler text cannot disappear first.
 */
static struct sse_event *sse_test_event_register(u32 evt, u32 priority,
						 sse_event_handler_fn *handler,
						 void *arg)
{
	struct sse_event *event;

	event = sse_event_register(evt, priority, handler, arg);
	if (!IS_ERR(event))
		__module_get(THIS_MODULE);

	return event;
}

static int sse_test_event_unregister(struct sse_event *event)
{
	int ret;

	ret = sse_event_unregister(event);
	if (!ret)
		module_put(THIS_MODULE);
	else
		sse_test_queue_cleanup(event);

	return ret;
}

static void sse_test_cleanup_workfn(struct work_struct *work)
{
	bool retry = false;
	int i, ret;

	mutex_lock(&sse_test_cleanup_lock);
	for (i = 0; i < ARRAY_SIZE(sse_test_cleanup_events); i++) {
		struct sse_event *event = sse_test_cleanup_events[i];

		if (!event)
			continue;

		ret = sse_event_disable(event);
		if (!ret)
			ret = sse_event_unregister(event);
		if (ret) {
			retry = true;
			continue;
		}

		sse_test_cleanup_events[i] = NULL;
		module_put(THIS_MODULE);
	}
	mutex_unlock(&sse_test_cleanup_lock);

	if (retry)
		mod_delayed_work(system_wq, &sse_test_cleanup_work,
				 msecs_to_jiffies(100));
}

static struct sbiret sbi_sse_ecall(int fid, unsigned long arg0, unsigned long arg1)
{
	return sbi_ecall(SBI_EXT_SSE, fid, arg0, arg1, 0, 0, 0, 0);
}

static int sse_event_attr_read(u32 evt, unsigned long attr_id,
			       unsigned long *attr_buf)
{
	struct sbiret sret;
	phys_addr_t phys;

	phys = virt_to_phys(attr_buf);

	sret = sbi_ecall(SBI_EXT_SSE, SBI_SSE_EVENT_ATTR_READ, evt, attr_id, 1,
			 (unsigned long)phys, 0, 0);
	if (sret.error)
		return sbi_err_map_linux_errno(sret.error);

	return 0;
}

static int sse_event_attr_get(u32 evt, unsigned long attr_id,
			      unsigned long *val)
{
	unsigned long *attr_buf;
	int ret;

	attr_buf = kmalloc_obj(*attr_buf, GFP_KERNEL);
	if (!attr_buf)
		return -ENOMEM;

	ret = sse_event_attr_read(evt, attr_id, attr_buf);
	if (!ret)
		*val = *attr_buf;
	kfree(attr_buf);

	return ret;
}

static int sse_test_signal(u32 evt, unsigned int cpu)
{
	unsigned long hart_id = cpuid_to_hartid_map(cpu);
	struct sbiret ret;

	ret = sbi_sse_ecall(SBI_SSE_EVENT_INJECT, evt, hart_id);
	if (ret.error) {
		sse_err("Failed to signal event %x, error %ld\n", evt, ret.error);
		return sbi_err_map_linux_errno(ret.error);
	}

	return 0;
}

static int sse_test_wait_not_running(u32 evt)
{
	unsigned long timeout = jiffies + HZ;
	unsigned long status;
	int ret;

	do {
		ret = sse_event_attr_get(evt, SBI_SSE_ATTR_STATUS, &status);
		if (ret) {
			sse_err("Failed to get status for evt %x, error %d\n", evt, ret);
			return ret;
		}
		status &= SBI_SSE_ATTR_STATUS_STATE_MASK;
		cpu_relax();
	} while (status == SBI_SSE_STATE_RUNNING && time_before(jiffies, timeout));

	if (status == SBI_SSE_STATE_RUNNING) {
		sse_err("Timed out waiting for event %x to leave RUNNING state\n", evt);
		return -ETIMEDOUT;
	}

	return 0;
}

struct sse_test_wait_status {
	u32 evt;
	unsigned long *attr_buf;
	unsigned long status;
	int ret;
};

static void sse_test_read_status_local(void *info)
{
	struct sse_test_wait_status *wait = info;

	wait->ret = sse_event_attr_read(wait->evt, SBI_SSE_ATTR_STATUS,
					wait->attr_buf);
	if (!wait->ret)
		wait->status = *wait->attr_buf & SBI_SSE_ATTR_STATUS_STATE_MASK;
}

static int sse_test_wait_not_running_on_cpu(u32 evt, unsigned int cpu)
{
	struct sse_test_wait_status wait = { .evt = evt };
	unsigned long timeout;
	int ret = 0;

	if (sse_event_is_global(evt))
		return sse_test_wait_not_running(evt);

	wait.attr_buf = kmalloc_obj(*wait.attr_buf, GFP_KERNEL);
	if (!wait.attr_buf)
		return -ENOMEM;

	timeout = jiffies + HZ;
	do {
		ret = smp_call_function_single(cpu, sse_test_read_status_local,
					       &wait, true);
		if (ret || wait.ret) {
			ret = ret ?: wait.ret;
			break;
		}
		if (wait.status != SBI_SSE_STATE_RUNNING)
			break;
		usleep_range(100, 200);
	} while (time_before(jiffies, timeout));

	if (!ret && wait.status == SBI_SSE_STATE_RUNNING) {
		sse_err("Timed out waiting for event %x on CPU %u\n", evt, cpu);
		ret = -ETIMEDOUT;
	}

	kfree(wait.attr_buf);

	return ret;
}

static int sse_test_inject_event(struct sse_event *event, u32 evt, unsigned int cpu)
{
	int res;

	if (sse_event_is_global(evt)) {
		/*
		 * Due to the fact the completion might happen faster than
		 * the call to SBI_SSE_COMPLETE in the handler, if the event was
		 * running on another CPU, we need to wait for the event status
		 * to be !RUNNING.
		 */
		res = sse_test_wait_not_running(evt);
		if (res)
			return res;

		res = sse_event_set_target_cpu(event, cpu);
		if (res) {
			sse_err("Failed to set cpu for evt %x, error %d\n", evt, res);
			return res;
		}
	}

	return sse_test_signal(evt, cpu);
}

struct fast_test_arg {
	u32 evt;
	int cpu;
	bool args_ready;
	bool completion;
};

/* A failed unregister may leave firmware holding this handler argument. */
static struct fast_test_arg fast_test_arg;

static int sse_test_handler(u32 evt, void *arg, struct pt_regs *regs)
{
	int ret = 0;
	struct fast_test_arg *targ = arg;
	u32 test_evt;
	int cpu;

	atomic_inc(&sse_test_handler_count);

	/* Pairs with the argument publication in sse_run_fast_test_cpu(). */
	if (!smp_load_acquire(&targ->args_ready)) {
		sse_err("Received SSE event %x before its test arguments were published\n",
			evt);
		ret = -EINVAL;
		goto complete;
	}

	test_evt = READ_ONCE(targ->evt);
	cpu = READ_ONCE(targ->cpu);

	if (evt != test_evt) {
		sse_err("Received SSE event id %x instead of %x\n", test_evt, evt);
		ret = -EINVAL;
	}

	if (!sse_event_is_global(evt) && cpu != smp_processor_id()) {
		sse_err("Received SSE event %d on CPU %d instead of %d\n", evt, smp_processor_id(),
			cpu);
		ret = -EINVAL;
	}

complete:
	WRITE_ONCE(targ->args_ready, false);
	/* Publish handler-side checks before waking the waiting CPU. */
	smp_store_release(&targ->completion, true);

	return ret;
}

static int sse_run_fast_test_cpu(struct fast_test_arg *test_arg,
				 struct sse_event *event, u32 evt, int cpu)
{
	unsigned long timeout;
	int ret;

	WRITE_ONCE(test_arg->completion, false);
	WRITE_ONCE(test_arg->args_ready, false);
	WRITE_ONCE(test_arg->evt, evt);
	WRITE_ONCE(test_arg->cpu, cpu);
	/* Publish all arguments before firmware can inject on another hart. */
	smp_store_release(&test_arg->args_ready, true);

	ret = sse_test_inject_event(event, evt, cpu);
	if (ret) {
		sse_err("event %s injection failed, err %d\n",
			sse_evt_name(evt), ret);
		return ret;
	}

	timeout = jiffies + HZ / 100;
	/* We can not use <linux/completion.h> since they are not NMI safe */
	/* Pairs with the handler's completion publication. */
	while (!smp_load_acquire(&test_arg->completion) &&
	       time_before(jiffies, timeout))
		cpu_relax();
	/* Acquire the handler's checks even if the loop observed a timeout. */
	if (!smp_load_acquire(&test_arg->completion)) {
		sse_err("Failed to wait for event %s completion on CPU %d\n",
			sse_evt_name(evt), cpu);
		return -ETIMEDOUT;
	}

	return sse_test_wait_not_running_on_cpu(evt, cpu);
}

static void sse_run_fast_test(struct fast_test_arg *test_arg,
			      struct sse_event *event, u32 evt)
{
	int cpu;

	if (sse_event_is_global(evt)) {
		/* Keep the selected target online through injection and completion. */
		cpu_hotplug_disable();
		for_each_online_cpu(cpu) {
			if (sse_run_fast_test_cpu(test_arg, event, evt, cpu))
				break;
		}
		cpu_hotplug_enable();
		return;
	}

	guard(cpus_read_lock)();
	for_each_online_cpu(cpu) {
		if (sse_run_fast_test_cpu(test_arg, event, evt, cpu))
			return;
	}
}

static void sse_test_injection_fast(void)
{
	int i, ret = 0, j;
	u32 evt;
	struct sse_event *event;

	pr_info("Starting SSE test (fast)\n");

	for (i = 0; i < ARRAY_SIZE(sse_event_descs); i++) {
		evt = sse_event_descs[i].evt_id;
		WRITE_ONCE(fast_test_arg.evt, evt);
		WRITE_ONCE(fast_test_arg.cpu, -1);
		WRITE_ONCE(fast_test_arg.args_ready, false);
		WRITE_ONCE(fast_test_arg.completion, false);

		if (!sse_event_descs[i].can_inject)
			continue;

		event = sse_test_event_register(evt, 0, sse_test_handler,
						(void *)&fast_test_arg);
		if (IS_ERR(event)) {
			if (PTR_ERR(event) == -EEXIST) {
				pr_info("Event %s already registered, skipping\n",
					sse_evt_name(evt));
				continue;
			}
			sse_err("Failed to register event %s, err %ld\n", sse_evt_name(evt),
				PTR_ERR(event));
			continue;
		}

		ret = sse_event_enable(event);
		if (ret) {
			sse_err("Failed to enable event %s, err %d\n", sse_evt_name(evt), ret);
			goto err_disable;
		}

		pr_info("Starting testing event %s\n", sse_evt_name(evt));

		for (j = 0; j < RUN_LOOP_COUNT; j++)
			sse_run_fast_test(&fast_test_arg, event, evt);
		pr_info("Finished testing event %s\n", sse_evt_name(evt));

err_disable:
		ret = sse_event_disable(event);
		if (ret)
			sse_err("Failed to disable event %s, err %d\n",
				sse_evt_name(evt), ret);
		ret = sse_test_event_unregister(event);
		if (ret) {
			sse_err("Failed to unregister event %s, err %d\n",
				sse_evt_name(evt), ret);
			return;
		}
	}
	pr_info("Finished SSE test (fast)\n");
}

struct priority_test_arg {
	unsigned long evt;
	struct sse_event *event;
	bool called;
	bool enable_attempted;
	u32 prio;
	struct priority_test_arg *next_evt_arg;
	void (*check_func)(struct priority_test_arg *arg);
};

/* A failed unregister may leave firmware holding these handler arguments. */
static struct priority_test_arg default_hi_prio_args[] = {
	{ .evt = SBI_SSE_EVENT_GLOBAL_SOFTWARE_INJECTED },
	{ .evt = SBI_SSE_EVENT_LOCAL_SOFTWARE_INJECTED },
	{ .evt = SBI_SSE_EVENT_GLOBAL_LOW_PRIO_RAS },
	{ .evt = SBI_SSE_EVENT_LOCAL_LOW_PRIO_RAS },
	{ .evt = SBI_SSE_EVENT_LOCAL_PMU_OVERFLOW },
	{ .evt = SBI_SSE_EVENT_GLOBAL_HIGH_PRIO_RAS },
	{ .evt = SBI_SSE_EVENT_LOCAL_DOUBLE_TRAP },
	{ .evt = SBI_SSE_EVENT_LOCAL_HIGH_PRIO_RAS },
};

static struct priority_test_arg default_low_prio_args[] = {
	{ .evt = SBI_SSE_EVENT_LOCAL_HIGH_PRIO_RAS },
	{ .evt = SBI_SSE_EVENT_LOCAL_DOUBLE_TRAP },
	{ .evt = SBI_SSE_EVENT_GLOBAL_HIGH_PRIO_RAS },
	{ .evt = SBI_SSE_EVENT_LOCAL_PMU_OVERFLOW },
	{ .evt = SBI_SSE_EVENT_LOCAL_LOW_PRIO_RAS },
	{ .evt = SBI_SSE_EVENT_GLOBAL_LOW_PRIO_RAS },
	{ .evt = SBI_SSE_EVENT_LOCAL_SOFTWARE_INJECTED },
	{ .evt = SBI_SSE_EVENT_GLOBAL_SOFTWARE_INJECTED },
};

static struct priority_test_arg set_prio_args[] = {
	{ .evt = SBI_SSE_EVENT_GLOBAL_SOFTWARE_INJECTED, .prio = 5 },
	{ .evt = SBI_SSE_EVENT_LOCAL_SOFTWARE_INJECTED, .prio = 10 },
	{ .evt = SBI_SSE_EVENT_GLOBAL_LOW_PRIO_RAS, .prio = 15 },
	{ .evt = SBI_SSE_EVENT_LOCAL_LOW_PRIO_RAS, .prio = 20 },
	{ .evt = SBI_SSE_EVENT_LOCAL_PMU_OVERFLOW, .prio = 25 },
	{ .evt = SBI_SSE_EVENT_GLOBAL_HIGH_PRIO_RAS, .prio = 30 },
	{ .evt = SBI_SSE_EVENT_LOCAL_DOUBLE_TRAP, .prio = 35 },
	{ .evt = SBI_SSE_EVENT_LOCAL_HIGH_PRIO_RAS, .prio = 40 },
};

static struct priority_test_arg same_prio_args[] = {
	{ .evt = SBI_SSE_EVENT_LOCAL_PMU_OVERFLOW, .prio = 0 },
	{ .evt = SBI_SSE_EVENT_LOCAL_HIGH_PRIO_RAS, .prio = 10 },
	{ .evt = SBI_SSE_EVENT_LOCAL_SOFTWARE_INJECTED, .prio = 10 },
	{ .evt = SBI_SSE_EVENT_GLOBAL_SOFTWARE_INJECTED, .prio = 10 },
	{ .evt = SBI_SSE_EVENT_GLOBAL_HIGH_PRIO_RAS, .prio = 20 },
};

static int sse_hi_priority_test_handler(u32 evt, void *arg,
					struct pt_regs *regs)
{
	struct priority_test_arg *targ = arg;
	struct priority_test_arg *next = READ_ONCE(targ->next_evt_arg);

	atomic_inc(&sse_test_handler_count);
	WRITE_ONCE(targ->called, 1);

	if (next) {
		sse_test_signal(next->evt, smp_processor_id());
		if (!READ_ONCE(next->called)) {
			sse_err("Higher priority event %s was not handled %s\n",
				sse_evt_name(next->evt), sse_evt_name(evt));
		}
	}

	return 0;
}

static int sse_low_priority_test_handler(u32 evt, void *arg, struct pt_regs *regs)
{
	struct priority_test_arg *targ = arg;
	struct priority_test_arg *next = READ_ONCE(targ->next_evt_arg);

	atomic_inc(&sse_test_handler_count);
	WRITE_ONCE(targ->called, 1);

	if (next) {
		sse_test_signal(next->evt, smp_processor_id());
		if (READ_ONCE(next->called)) {
			sse_err("Lower priority event %s was handle before %s\n",
				sse_evt_name(next->evt), sse_evt_name(evt));
		}
	}

	return 0;
}

static void sse_test_injection_priority_arg(struct priority_test_arg *args, unsigned int args_size,
					    sse_event_handler_fn handler, const char *test_name)
{
	unsigned int i;
	unsigned long timeout;
	int ret;
	int target_cpu;
	struct sse_event *event;
	struct priority_test_arg *arg, *first_arg = NULL, *prev_arg = NULL;

	pr_info("Starting SSE priority test (%s)\n", test_name);
	/* Keep the complete priority chain on one CPU. */
	migrate_disable();
	target_cpu = smp_processor_id();

	for (i = 0; i < args_size; i++) {
		arg = &args[i];

		if (!sse_test_can_inject_event(arg->evt))
			continue;

		WRITE_ONCE(arg->called, false);
		WRITE_ONCE(arg->next_evt_arg, NULL);
		WRITE_ONCE(arg->event, NULL);
		WRITE_ONCE(arg->enable_attempted, false);

		event = sse_test_event_register(arg->evt, arg->prio, handler,
						(void *)arg);
		if (IS_ERR(event)) {
			if (PTR_ERR(event) == -EEXIST) {
				pr_info("Event %s already registered, skipping\n",
					sse_evt_name(arg->evt));
				continue;
			}
			sse_err("Failed to register event %s, err %ld\n", sse_evt_name(arg->evt),
				PTR_ERR(event));
			goto release_events;
		}
		arg->event = event;

		if (sse_event_is_global(arg->evt)) {
			/* Keep the chain on one stable CPU. */
			ret = sse_event_set_target_cpu(event, target_cpu);
			if (ret) {
				sse_err("Failed to set event %s target CPU, err %d\n",
					sse_evt_name(arg->evt), ret);
				goto release_events;
			}
		}

		WRITE_ONCE(arg->enable_attempted, true);
		ret = sse_event_enable(event);
		if (ret) {
			sse_err("Failed to enable event %s, err %d\n", sse_evt_name(arg->evt), ret);
			goto release_events;
		}

		if (prev_arg)
			WRITE_ONCE(prev_arg->next_evt_arg, arg);

		prev_arg = arg;

		if (!first_arg)
			first_arg = arg;
	}

	if (!first_arg) {
		pr_info("No injectable event available for %s priority test\n",
			test_name);
		goto out;
	}

	/* Inject first event, handler should trigger the others in chain. */
	ret = sse_test_inject_event(first_arg->event, first_arg->evt, target_cpu);
	if (ret) {
		sse_err("SSE event %s injection failed\n", sse_evt_name(first_arg->evt));
		goto release_events;
	}

	/* Lower-priority events run after the handler that injected them completes. */
	arg = first_arg;
	while (arg) {
		timeout = jiffies + HZ;
		while (!READ_ONCE(arg->called) && time_before(jiffies, timeout))
			cpu_relax();

		if (!READ_ONCE(arg->called)) {
			sse_err("Event %s handler was not called\n",
				sse_evt_name(arg->evt));
			ret = -EINVAL;
		}

		event = arg->event;
		arg = READ_ONCE(arg->next_evt_arg);
	}

release_events:

	for (i = 0; i < args_size; i++) {
		arg = &args[i];
		event = arg->event;
		if (!event)
			continue;

		ret = sse_test_wait_not_running_on_cpu(arg->evt, target_cpu);
		if (ret)
			sse_err("Event %s did not complete, err %d\n",
				sse_evt_name(arg->evt), ret);

		if (arg->enable_attempted) {
			ret = sse_event_disable(event);
			if (ret) {
				sse_err("Failed to disable event %s, err %d\n",
					sse_evt_name(arg->evt), ret);
				sse_test_queue_cleanup(event);
				WRITE_ONCE(arg->event, NULL);
				WRITE_ONCE(arg->enable_attempted, false);
				continue;
			}
		}

		ret = sse_test_event_unregister(event);
		if (ret) {
			sse_err("Failed to unregister event %s, err %d\n",
				sse_evt_name(arg->evt), ret);
			continue;
		}

		WRITE_ONCE(arg->event, NULL);
		WRITE_ONCE(arg->enable_attempted, false);
	}

	pr_info("Finished SSE priority test (%s)\n", test_name);
out:
	migrate_enable();
}

static void sse_test_injection_priority(void)
{
	sse_test_injection_priority_arg(default_hi_prio_args, ARRAY_SIZE(default_hi_prio_args),
					sse_hi_priority_test_handler, "high");

	sse_test_injection_priority_arg(default_low_prio_args, ARRAY_SIZE(default_low_prio_args),
					sse_low_priority_test_handler, "low");

	sse_test_injection_priority_arg(set_prio_args, ARRAY_SIZE(set_prio_args),
					sse_low_priority_test_handler, "set");

	sse_test_injection_priority_arg(same_prio_args, ARRAY_SIZE(same_prio_args),
					sse_low_priority_test_handler, "same_prio_args");
}

static int sse_get_inject_status(u32 evt, bool *can_inject)
{
	int ret;
	unsigned long val;

	/* Check if injection is supported */
	ret = sse_event_attr_get(evt, SBI_SSE_ATTR_STATUS, &val);
	if (ret == sbi_err_map_linux_errno(SBI_ERR_NOT_SUPPORTED) ||
	    ret == sbi_err_map_linux_errno(SBI_ERR_INVALID_PARAM)) {
		*can_inject = false;
		return 0;
	}
	if (ret)
		return ret;

	*can_inject = !!(val & BIT(SBI_SSE_ATTR_STATUS_INJECT_OFFSET));

	return 0;
}

static int sse_init_events(void)
{
	int i, injectable = 0, ret;

	for (i = 0; i < ARRAY_SIZE(sse_event_descs); i++) {
		struct sse_event_desc *desc = &sse_event_descs[i];

		ret = sse_get_inject_status(desc->evt_id, &desc->can_inject);
		if (ret) {
			sse_err("Failed to read injection status for %s, err %d\n",
				desc->name, ret);
			return ret;
		}

		if (desc->can_inject)
			injectable++;
		else
			pr_info("Can not inject event %s, tests using this event will be skipped\n",
				desc->name);

		if (desc->evt_id == SBI_SSE_EVENT_LOCAL_SOFTWARE_INJECTED)
			sse_stress_event_can_inject = desc->can_inject;
	}

	return injectable;
}

struct stress_test_ctx {
	struct sse_event *event;
	struct hrtimer timer;
	struct hrtimer stop_timer;
	struct task_struct *monitor_task;
	wait_queue_head_t wait_q;
	atomic_t inject_count;
	atomic_t handler_count;
	atomic_t handler_errors;
	u32 evt_id;
	int layer;
	bool running;
	bool test_done;
};

static struct stress_test_ctx stress_ctx;
static DEFINE_PER_CPU(int, stress_reinject_cpu_depth);

static int stress_handler_empty(u32 evt, void *arg, struct pt_regs *regs)
{
	struct stress_test_ctx *ctx = arg;

	atomic_inc(&sse_test_handler_count);
	atomic_inc(&ctx->handler_count);

	return 0;
}

static int stress_handler_ecall(u32 evt, void *arg, struct pt_regs *regs)
{
	struct stress_test_ctx *ctx = arg;
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_BASE, SBI_EXT_BASE_GET_SPEC_VERSION,
			0, 0, 0, 0, 0, 0);
	if (ret.error)
		atomic_inc(&ctx->handler_errors);
	atomic_inc(&sse_test_handler_count);
	atomic_inc(&ctx->handler_count);

	return 0;
}

static int stress_handler_multi_ecall(u32 evt, void *arg, struct pt_regs *regs)
{
	struct stress_test_ctx *ctx = arg;
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_BASE, SBI_EXT_BASE_GET_SPEC_VERSION,
			0, 0, 0, 0, 0, 0);
	if (ret.error)
		atomic_inc(&ctx->handler_errors);
	ret = sbi_ecall(SBI_EXT_BASE, SBI_EXT_BASE_GET_IMP_ID,
			0, 0, 0, 0, 0, 0);
	if (ret.error)
		atomic_inc(&ctx->handler_errors);
	ret = sbi_ecall(SBI_EXT_BASE, SBI_EXT_BASE_GET_IMP_VERSION,
			0, 0, 0, 0, 0, 0);
	if (ret.error)
		atomic_inc(&ctx->handler_errors);
	atomic_inc(&sse_test_handler_count);
	atomic_inc(&ctx->handler_count);

	return 0;
}

static int stress_handler_reinject(u32 evt, void *arg, struct pt_regs *regs)
{
	struct stress_test_ctx *ctx = arg;
	int *depth = this_cpu_ptr(&stress_reinject_cpu_depth);

	(*depth)++;
	if (*depth < STRESS_REINJECT_DEPTH)
		sse_test_signal(evt, smp_processor_id());
	else
		*depth = 0;

	atomic_inc(&sse_test_handler_count);
	atomic_inc(&ctx->handler_count);

	return 0;
}

static sse_event_handler_fn *stress_handlers[] = {
	stress_handler_empty,
	stress_handler_ecall,
	stress_handler_multi_ecall,
	stress_handler_reinject,
};

static const char * const stress_layer_names[] = {
	"empty handler",
	"single SBI ecall in handler",
	"multiple SBI ecalls in handler",
	"self re-inject",
};

static enum hrtimer_restart stress_timer_callback(struct hrtimer *timer)
{
	struct stress_test_ctx *ctx = container_of(timer, struct stress_test_ctx, timer);

	if (!READ_ONCE(ctx->running))
		return HRTIMER_NORESTART;

	if (!sse_test_signal(ctx->evt_id, smp_processor_id()))
		atomic_inc(&ctx->inject_count);
	hrtimer_forward_now(timer, ns_to_ktime(STRESS_INJECT_NS));

	return HRTIMER_RESTART;
}

static enum hrtimer_restart stress_stop_timer_callback(struct hrtimer *timer)
{
	struct stress_test_ctx *ctx;

	ctx = container_of(timer, struct stress_test_ctx, stop_timer);
	WRITE_ONCE(ctx->test_done, true);
	wake_up(&ctx->wait_q);

	return HRTIMER_NORESTART;
}

static int stress_monitor_thread(void *data)
{
	struct stress_test_ctx *ctx = data;
	unsigned long last_inject = 0, last_handler = 0;

	while (!kthread_should_stop()) {
		unsigned long inject = atomic_read(&ctx->inject_count);
		unsigned long handler = atomic_read(&ctx->handler_count);

		pr_info("stress layer %d: inject=%lu (+%lu), handler=%lu (+%lu)\n",
			ctx->layer, inject, inject - last_inject,
			handler, handler - last_handler);

		last_inject = inject;
		last_handler = handler;

		schedule_timeout_interruptible(HZ);
	}

	return 0;
}

static int sse_stress_test_layer(int layer)
{
	struct sse_event *event;
	int inject_count, handler_count;
	int ret, target_cpu, unregister_ret;

	if (layer < 0 || layer >= ARRAY_SIZE(stress_handlers))
		return -EINVAL;

	pr_info("Starting SSE stress layer %d (%s)\n",
		layer, stress_layer_names[layer]);

	memset(&stress_ctx, 0, sizeof(stress_ctx));
	stress_ctx.evt_id = SBI_SSE_EVENT_LOCAL_SOFTWARE_INJECTED;
	stress_ctx.layer = layer;
	WRITE_ONCE(stress_ctx.running, true);
	atomic_set(&stress_ctx.inject_count, 0);
	atomic_set(&stress_ctx.handler_count, 0);
	atomic_set(&stress_ctx.handler_errors, 0);
	init_waitqueue_head(&stress_ctx.wait_q);

	event = sse_test_event_register(stress_ctx.evt_id, 0,
					stress_handlers[layer], &stress_ctx);
	if (IS_ERR(event)) {
		sse_err("Failed to register stress event, err %ld\n",
			PTR_ERR(event));
		return PTR_ERR(event);
	}

	stress_ctx.event = event;

	ret = sse_event_enable(event);
	if (ret) {
		sse_err("Failed to enable stress event, err %d\n", ret);
		goto err_disable;
	}

	stress_ctx.monitor_task = kthread_run(stress_monitor_thread,
					      &stress_ctx, "sse_stress_mon");
	if (IS_ERR(stress_ctx.monitor_task)) {
		ret = PTR_ERR(stress_ctx.monitor_task);
		sse_err("Failed to create stress monitor thread, err %d\n", ret);
		goto err_disable;
	}

	/* Keep the pinned timer and its local event on the selected CPU. */
	cpus_read_lock();
	migrate_disable();
	target_cpu = smp_processor_id();
	hrtimer_setup(&stress_ctx.timer, stress_timer_callback,
		      CLOCK_MONOTONIC, HRTIMER_MODE_PINNED);
	hrtimer_start(&stress_ctx.timer, ns_to_ktime(STRESS_INJECT_NS),
		      HRTIMER_MODE_REL_PINNED);
	migrate_enable();

	hrtimer_setup(&stress_ctx.stop_timer, stress_stop_timer_callback,
		      CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	hrtimer_start(&stress_ctx.stop_timer, ms_to_ktime(STRESS_DURATION_MS),
		      HRTIMER_MODE_REL);

	wait_event(stress_ctx.wait_q, READ_ONCE(stress_ctx.test_done));

	WRITE_ONCE(stress_ctx.running, false);
	hrtimer_cancel(&stress_ctx.timer);
	hrtimer_cancel(&stress_ctx.stop_timer);
	kthread_stop(stress_ctx.monitor_task);

	pr_info("Finished SSE stress layer %d (%s): inject=%d, handler=%d\n",
		layer, stress_layer_names[layer],
		atomic_read(&stress_ctx.inject_count),
		atomic_read(&stress_ctx.handler_count));

	inject_count = atomic_read(&stress_ctx.inject_count);
	handler_count = atomic_read(&stress_ctx.handler_count);
	if (!inject_count || !handler_count) {
		sse_err("Stress layer %d made no progress: inject=%d, handler=%d\n",
			layer, inject_count, handler_count);
		ret = -EIO;
	}
	if (atomic_read(&stress_ctx.handler_errors)) {
		sse_err("Stress layer %d observed %d SBI call errors\n", layer,
			atomic_read(&stress_ctx.handler_errors));
		ret = -EIO;
	}
	if (sse_test_wait_not_running_on_cpu(stress_ctx.evt_id, target_cpu)) {
		sse_err("Stress event did not complete on CPU %d\n", target_cpu);
		if (!ret)
			ret = -ETIMEDOUT;
	}
	cpus_read_unlock();

err_disable:
	if (sse_event_disable(event)) {
		sse_err("Failed to disable stress event\n");
		if (!ret)
			ret = -EIO;
	}
	unregister_ret = sse_test_event_unregister(event);
	if (unregister_ret) {
		sse_err("Failed to unregister stress event\n");
		if (!ret)
			ret = unregister_ret;
	}
	stress_ctx.event = NULL;

	return ret;
}

static void sse_stress_test_all_layers(void)
{
	int i, ret;

	pr_info("Starting SSE stress tests: duration=%d ms, interval=%d ns\n",
		STRESS_DURATION_MS, STRESS_INJECT_NS);

	for (i = 0; i < ARRAY_SIZE(stress_handlers); i++) {
		ret = sse_stress_test_layer(i);
		if (ret) {
			sse_err("Stress layer %d failed, err %d\n", i, ret);
			break;
		}

		msleep(100);
	}

	pr_info("Finished SSE stress tests\n");
}

static int __init sse_test_init(void)
{
	int ret;

	pr_info("RUN %s BEGIN\n", run_id);
	atomic_set(&sse_test_handler_count, 0);

	if (stress < SSE_STRESS_OFF || stress > SSE_STRESS_ONLY) {
		sse_err("Invalid stress mode %d\n", stress);
		pr_info("RUN %s END\n", run_id);
		return -EINVAL;
	}

	ret = sse_init_events();
	if (ret < 0) {
		pr_info("RUN %s END\n", run_id);
		return ret;
	}
	if (!ret) {
		sse_skip("No injectable SSE event is available\n");
		pr_info("RUN %s END\n", run_id);
		return 0;
	}
	if (stress == SSE_STRESS_ONLY && !sse_stress_event_can_inject) {
		sse_skip("Local software-injected event is unavailable for stress\n");
		pr_info("RUN %s END\n", run_id);
		return 0;
	}

	if (stress != SSE_STRESS_ONLY) {
		sse_test_injection_fast();
		sse_test_injection_priority();
	}

	if (stress == SSE_STRESS_AFTER_SMOKE && !sse_stress_event_can_inject)
		sse_skip("Local software-injected event is unavailable for stress\n");
	else if (stress != SSE_STRESS_OFF)
		sse_stress_test_all_layers();
	if (!atomic_read(&sse_test_handler_count))
		sse_skip("No SSE event was handled\n");

	pr_info("RUN %s END\n", run_id);

	return 0;
}

static void __exit sse_test_exit(void)
{
	cancel_delayed_work_sync(&sse_test_cleanup_work);
}

module_init(sse_test_init);
module_exit(sse_test_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Clément Léger <cleger@rivosinc.com>");
MODULE_DESCRIPTION("Test module for SSE");
