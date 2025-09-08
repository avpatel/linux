// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2024 Rivos Inc.
 */

#define pr_fmt(fmt) "riscv_sse_test: " fmt

#include <linux/array_size.h>
#include <linux/completion.h>
#include <linux/err.h>
#include <linux/io.h>
#include <linux/jiffies.h>
#include <linux/module.h>
#include <linux/riscv_sbi_sse.h>
#include <linux/slab.h>
#include <linux/smp.h>

#include <asm/sbi.h>
#include <asm/sse.h>

#define RUN_LOOP_COUNT		1000
#define SSE_FAILED_PREFIX	"FAILED: "
#define sse_err(...)		pr_err(SSE_FAILED_PREFIX __VA_ARGS__)

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

	return desc != NULL ? desc->name : NULL;
}

static bool sse_test_can_inject_event(u32 evt)
{
	struct sse_event_desc *desc = sse_get_evt_desc(evt);

	return desc != NULL ? desc->can_inject : false;
}

static struct sbiret sbi_sse_ecall(int fid, unsigned long arg0, unsigned long arg1)
{
	return sbi_ecall(SBI_EXT_SSE, fid, arg0, arg1, 0, 0, 0, 0);
}

static int sse_event_attr_get(u32 evt, unsigned long attr_id,
			      unsigned long *val)
{
	struct sbiret sret;
	unsigned long *attr_buf, phys;

	attr_buf = kmalloc(sizeof(unsigned long), GFP_KERNEL);
	if (!attr_buf)
		return -ENOMEM;

	phys = virt_to_phys(attr_buf);

	sret = sbi_ecall(SBI_EXT_SSE, SBI_SSE_EVENT_ATTR_READ, evt, attr_id, 1,
			 phys, 0, 0);
	if (sret.error)
		return sbi_err_map_linux_errno(sret.error);

	*val = *attr_buf;

	return 0;
}

static int sse_test_signal(u32 evt, unsigned int cpu)
{
	unsigned int hart_id = cpuid_to_hartid_map(cpu);
	struct sbiret ret;

	ret = sbi_sse_ecall(SBI_SSE_EVENT_INJECT, evt, hart_id);
	if (ret.error) {
		sse_err("Failed to signal event %x, error %ld\n", evt, ret.error);
		return sbi_err_map_linux_errno(ret.error);
	}

	return 0;
}

static int sse_test_inject_event(struct sse_event *event, u32 evt, unsigned int cpu)
{
	int res;
	unsigned long status;

	if (sse_event_is_global(evt)) {
		/*
		 * Due to the fact the completion might happen faster than
		 * the call to SBI_SSE_COMPLETE in the handler, if the event was
		 * running on another CPU, we need to wait for the event status
		 * to be !RUNNING.
		 */
		do {
			res = sse_event_attr_get(evt, SBI_SSE_ATTR_STATUS, &status);
			if (res) {
				sse_err("Failed to get status for evt %x, error %d\n", evt, res);
				return res;
			}
			status = status & SBI_SSE_ATTR_STATUS_STATE_MASK;
		} while (status == SBI_SSE_STATE_RUNNING);

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
	bool completion;
};

static int sse_test_handler(u32 evt, void *arg, struct pt_regs *regs)
{
	int ret = 0;
	struct fast_test_arg *targ = arg;
	u32 test_evt = READ_ONCE(targ->evt);
	int cpu = READ_ONCE(targ->cpu);

	if (evt != test_evt) {
		sse_err("Received SSE event id %x instead of %x\n", test_evt, evt);
		ret = -EINVAL;
	}

	if (cpu != smp_processor_id()) {
		sse_err("Received SSE event %d on CPU %d instead of %d\n", evt, smp_processor_id(),
			cpu);
		ret = -EINVAL;
	}

	WRITE_ONCE(targ->completion, true);

	return ret;
}

static void sse_run_fast_test(struct fast_test_arg *test_arg, struct sse_event *event, u32 evt)
{
	unsigned long timeout;
	int ret, cpu;

	for_each_online_cpu(cpu) {
		WRITE_ONCE(test_arg->completion, false);
		WRITE_ONCE(test_arg->cpu, cpu);
		/* Test arg is used on another CPU */
		smp_wmb();

		ret = sse_test_inject_event(event, evt, cpu);
		if (ret) {
			sse_err("event %s injection failed, err %d\n", sse_evt_name(evt), ret);
			return;
		}

		timeout = jiffies + HZ / 100;
		/* We can not use <linux/completion.h> since they are not NMI safe */
		while (!READ_ONCE(test_arg->completion) &&
			time_before(jiffies, timeout)) {
			cpu_relax();
		}
		if (!time_before(jiffies, timeout)) {
			sse_err("Failed to wait for event %s completion on CPU %d\n",
				sse_evt_name(evt), cpu);
			return;
		}
	}
}

static void sse_test_injection_fast(void)
{
	int i, ret = 0, j;
	u32 evt;
	struct fast_test_arg test_arg;
	struct sse_event *event;

	pr_info("Starting SSE test (fast)\n");

	for (i = 0; i < ARRAY_SIZE(sse_event_descs); i++) {
		evt = sse_event_descs[i].evt_id;
		WRITE_ONCE(test_arg.evt, evt);

		if (!sse_event_descs[i].can_inject)
			continue;

		event = sse_event_register(evt, 0, sse_test_handler,
					   (void *)&test_arg);
		if (IS_ERR(event)) {
			sse_err("Failed to register event %s, err %ld\n", sse_evt_name(evt),
				PTR_ERR(event));
			goto out;
		}

		ret = sse_event_enable(event);
		if (ret) {
			sse_err("Failed to enable event %s, err %d\n", sse_evt_name(evt), ret);
			goto err_unregister;
		}

		pr_info("Starting testing event %s\n", sse_evt_name(evt));

		for (j = 0; j < RUN_LOOP_COUNT; j++)
			sse_run_fast_test(&test_arg, event, evt);

		pr_info("Finished testing event %s\n", sse_evt_name(evt));

		sse_event_disable(event);
err_unregister:
		sse_event_unregister(event);
	}
out:
	pr_info("Finished SSE test (fast)\n");
}

struct priority_test_arg {
	unsigned long evt;
	struct sse_event *event;
	bool called;
	u32 prio;
	struct priority_test_arg *next_evt_arg;
	void (*check_func)(struct priority_test_arg *arg);
};

static int sse_hi_priority_test_handler(u32 evt, void *arg,
					struct pt_regs *regs)
{
	struct priority_test_arg *targ = arg;
	struct priority_test_arg *next = READ_ONCE(targ->next_evt_arg);

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
	int ret;
	struct sse_event *event;
	struct priority_test_arg *arg, *first_arg = NULL, *prev_arg = NULL;

	pr_info("Starting SSE priority test (%s)\n", test_name);
	for (i = 0; i < args_size; i++) {
		arg = &args[i];

		if (!sse_test_can_inject_event(arg->evt))
			continue;

		WRITE_ONCE(arg->called, false);
		WRITE_ONCE(arg->next_evt_arg, NULL);
		if (prev_arg)
			WRITE_ONCE(prev_arg->next_evt_arg, arg);

		prev_arg = arg;

		if (!first_arg)
			first_arg = arg;

		event = sse_event_register(arg->evt, arg->prio, handler, (void *)arg);
		if (IS_ERR(event)) {
			sse_err("Failed to register event %s, err %ld\n", sse_evt_name(arg->evt),
				PTR_ERR(event));
			goto release_events;
		}
		arg->event = event;

		if (sse_event_is_global(arg->evt)) {
			/* Target event at current CPU */
			ret = sse_event_set_target_cpu(event, smp_processor_id());
			if (ret) {
				sse_err("Failed to set event %s target CPU, err %d\n",
					sse_evt_name(arg->evt), ret);
				goto release_events;
			}
		}

		ret = sse_event_enable(event);
		if (ret) {
			sse_err("Failed to enable event %s, err %d\n", sse_evt_name(arg->evt), ret);
			goto release_events;
		}
	}

	if (!first_arg) {
		sse_err("No injectable event available\n");
		return;
	}

	/* Inject first event, handler should trigger the others in chain. */
	ret = sse_test_inject_event(first_arg->event, first_arg->evt, smp_processor_id());
	if (ret) {
		sse_err("SSE event %s injection failed\n", sse_evt_name(first_arg->evt));
		goto release_events;
	}

	/*
	 * Event are injected directly on the current CPU after calling sse_test_inject_event()
	 * so that execution is premmpted right away, no need to wait for timeout.
	 */
	arg = first_arg;
	while (arg) {
		if (!READ_ONCE(arg->called)) {
			sse_err("Event %s handler was not called\n",
			      sse_evt_name(arg->evt));
			ret = -EINVAL;
		}


		event = arg->event;
		arg = READ_ONCE(arg->next_evt_arg);
	}

release_events:

	arg = first_arg;
	while (arg) {
		event = arg->event;
		if (!event)
			break;

		sse_event_disable(event);
		sse_event_unregister(event);
		arg = READ_ONCE(arg->next_evt_arg);
	}

	pr_info("Finished SSE priority test (%s)\n", test_name);
}

static void sse_test_injection_priority(void)
{
	struct priority_test_arg default_hi_prio_args[] = {
		{ .evt = SBI_SSE_EVENT_GLOBAL_SOFTWARE_INJECTED },
		{ .evt = SBI_SSE_EVENT_LOCAL_SOFTWARE_INJECTED },
		{ .evt = SBI_SSE_EVENT_GLOBAL_LOW_PRIO_RAS },
		{ .evt = SBI_SSE_EVENT_LOCAL_LOW_PRIO_RAS },
		{ .evt = SBI_SSE_EVENT_LOCAL_PMU_OVERFLOW },
		{ .evt = SBI_SSE_EVENT_GLOBAL_HIGH_PRIO_RAS },
		{ .evt = SBI_SSE_EVENT_LOCAL_DOUBLE_TRAP },
		{ .evt = SBI_SSE_EVENT_LOCAL_HIGH_PRIO_RAS },
	};

	struct priority_test_arg default_low_prio_args[] = {
		{ .evt = SBI_SSE_EVENT_LOCAL_HIGH_PRIO_RAS },
		{ .evt = SBI_SSE_EVENT_LOCAL_DOUBLE_TRAP },
		{ .evt = SBI_SSE_EVENT_GLOBAL_HIGH_PRIO_RAS },
		{ .evt = SBI_SSE_EVENT_LOCAL_PMU_OVERFLOW },
		{ .evt = SBI_SSE_EVENT_LOCAL_LOW_PRIO_RAS },
		{ .evt = SBI_SSE_EVENT_GLOBAL_LOW_PRIO_RAS },
		{ .evt = SBI_SSE_EVENT_LOCAL_SOFTWARE_INJECTED },
		{ .evt = SBI_SSE_EVENT_GLOBAL_SOFTWARE_INJECTED },

	};
	struct priority_test_arg set_prio_args[] = {
		{ .evt = SBI_SSE_EVENT_GLOBAL_SOFTWARE_INJECTED, .prio = 5 },
		{ .evt = SBI_SSE_EVENT_LOCAL_SOFTWARE_INJECTED, .prio = 10 },
		{ .evt = SBI_SSE_EVENT_GLOBAL_LOW_PRIO_RAS, .prio = 15 },
		{ .evt = SBI_SSE_EVENT_LOCAL_LOW_PRIO_RAS, .prio = 20 },
		{ .evt = SBI_SSE_EVENT_LOCAL_PMU_OVERFLOW, .prio = 25 },
		{ .evt = SBI_SSE_EVENT_GLOBAL_HIGH_PRIO_RAS, .prio = 30 },
		{ .evt = SBI_SSE_EVENT_LOCAL_DOUBLE_TRAP, .prio = 35 },
		{ .evt = SBI_SSE_EVENT_LOCAL_HIGH_PRIO_RAS, .prio = 40 },
	};

	struct priority_test_arg same_prio_args[] = {
		{ .evt = SBI_SSE_EVENT_LOCAL_PMU_OVERFLOW, .prio = 0 },
		{ .evt = SBI_SSE_EVENT_LOCAL_HIGH_PRIO_RAS, .prio = 10 },
		{ .evt = SBI_SSE_EVENT_LOCAL_SOFTWARE_INJECTED, .prio = 10 },
		{ .evt = SBI_SSE_EVENT_GLOBAL_SOFTWARE_INJECTED, .prio = 10 },
		{ .evt = SBI_SSE_EVENT_GLOBAL_HIGH_PRIO_RAS, .prio = 20 },
	};

	sse_test_injection_priority_arg(default_hi_prio_args, ARRAY_SIZE(default_hi_prio_args),
					sse_hi_priority_test_handler, "high");

	sse_test_injection_priority_arg(default_low_prio_args, ARRAY_SIZE(default_low_prio_args),
					sse_low_priority_test_handler, "low");

	sse_test_injection_priority_arg(set_prio_args, ARRAY_SIZE(set_prio_args),
					sse_low_priority_test_handler, "set");

	sse_test_injection_priority_arg(same_prio_args, ARRAY_SIZE(same_prio_args),
					sse_low_priority_test_handler, "same_prio_args");
}


static bool sse_get_inject_status(u32 evt)
{
	int ret;
	unsigned long val;

	/* Check if injection is supported */
	ret = sse_event_attr_get(evt, SBI_SSE_ATTR_STATUS, &val);
	if (ret)
		return false;

	return !!(val & BIT(SBI_SSE_ATTR_STATUS_INJECT_OFFSET));
}

static void sse_init_events(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(sse_event_descs); i++) {
		struct sse_event_desc *desc = &sse_event_descs[i];

		desc->can_inject = sse_get_inject_status(desc->evt_id);
		if (!desc->can_inject)
			pr_info("Can not inject event %s, tests using this event will be skipped\n",
				desc->name);
	}
}

static int __init sse_test_init(void)
{
	sse_init_events();

	sse_test_injection_fast();
	sse_test_injection_priority();

	return 0;
}

static void __exit sse_test_exit(void)
{
}

module_init(sse_test_init);
module_exit(sse_test_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Clément Léger <cleger@rivosinc.com>");
MODULE_DESCRIPTION("Test module for SSE");
