// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2024 Rivos Inc.
 */

#define pr_fmt(fmt) "sse: " fmt

#include <linux/cpu.h>
#include <linux/cpuhotplug.h>
#include <linux/cpu_pm.h>
#include <linux/hardirq.h>
#include <linux/list.h>
#include <linux/percpu-defs.h>
#include <linux/reboot.h>
#include <linux/riscv_sbi_sse.h>
#include <linux/slab.h>

#include <asm/sbi.h>
#include <asm/sse.h>

struct sse_event {
	struct list_head list;
	u32 evt_id;
	u32 priority;
	sse_event_handler_fn *handler;
	void *handler_arg;
	/* Only valid for global events */
	unsigned int cpu;

	union {
		struct sse_registered_event *global;
		struct sse_registered_event __percpu *local;
	};
};

static int sse_hp_state;
static bool sse_available __ro_after_init;
static DEFINE_SPINLOCK(events_list_lock);
static LIST_HEAD(events);
static DEFINE_MUTEX(sse_mutex);

struct sse_registered_event {
	struct sse_event_arch_data arch;
	struct sse_event *event;
	unsigned long attr;
	bool is_enabled;
};

void sse_handle_event(struct sse_event_arch_data *arch_event,
		      struct pt_regs *regs)
{
	int ret;
	struct sse_registered_event *reg_evt =
		container_of(arch_event, struct sse_registered_event, arch);
	struct sse_event *evt = reg_evt->event;

	ret = evt->handler(evt->evt_id, evt->handler_arg, regs);
	if (ret)
		pr_warn("event %x handler failed with error %d\n", evt->evt_id, ret);
}

static struct sse_event *sse_event_get(u32 evt)
{
	struct sse_event *event = NULL;

	scoped_guard(spinlock, &events_list_lock) {
		list_for_each_entry(event, &events, list) {
			if (event->evt_id == evt)
				return event;
		}
	}

	return NULL;
}

static phys_addr_t sse_event_get_attr_phys(struct sse_registered_event *reg_evt)
{
	phys_addr_t phys;
	void *addr = &reg_evt->attr;

	if (sse_event_is_global(reg_evt->event->evt_id))
		phys = virt_to_phys(addr);
	else
		phys = per_cpu_ptr_to_phys(addr);

	return phys;
}

static struct sse_registered_event *sse_get_reg_evt(struct sse_event *event)
{
	if (sse_event_is_global(event->evt_id))
		return event->global;
	else
		return per_cpu_ptr(event->local, smp_processor_id());
}

static int sse_sbi_event_func(struct sse_event *event, unsigned long func)
{
	struct sbiret ret;
	u32 evt = event->evt_id;
	struct sse_registered_event *reg_evt = sse_get_reg_evt(event);

	ret = sbi_ecall(SBI_EXT_SSE, func, evt, 0, 0, 0, 0, 0);
	if (ret.error) {
		pr_warn("Failed to execute func %lx, event %x, error %ld\n",
			func, evt, ret.error);
		return sbi_err_map_linux_errno(ret.error);
	}

	if (func == SBI_SSE_EVENT_DISABLE)
		reg_evt->is_enabled = false;
	else if (func == SBI_SSE_EVENT_ENABLE)
		reg_evt->is_enabled = true;

	return 0;
}

int sse_event_disable_local(struct sse_event *event)
{
	return sse_sbi_event_func(event, SBI_SSE_EVENT_DISABLE);
}
EXPORT_SYMBOL_GPL(sse_event_disable_local);

int sse_event_enable_local(struct sse_event *event)
{
	return sse_sbi_event_func(event, SBI_SSE_EVENT_ENABLE);
}
EXPORT_SYMBOL_GPL(sse_event_enable_local);

static int sse_event_attr_get_no_lock(struct sse_registered_event *reg_evt,
				      unsigned long attr_id, unsigned long *val)
{
	struct sbiret sret;
	u32 evt = reg_evt->event->evt_id;
	unsigned long phys;

	phys = sse_event_get_attr_phys(reg_evt);

	sret = sbi_ecall(SBI_EXT_SSE, SBI_SSE_EVENT_ATTR_READ, evt, attr_id, 1,
			 phys, 0, 0);
	if (sret.error) {
		pr_debug("Failed to get event %x attr %lx, error %ld\n", evt,
			 attr_id, sret.error);
		return sbi_err_map_linux_errno(sret.error);
	}

	*val = reg_evt->attr;

	return 0;
}

static int sse_event_attr_set_nolock(struct sse_registered_event *reg_evt,
				     unsigned long attr_id, unsigned long val)
{
	struct sbiret sret;
	u32 evt = reg_evt->event->evt_id;
	unsigned long phys;

	reg_evt->attr = val;
	phys = sse_event_get_attr_phys(reg_evt);

	sret = sbi_ecall(SBI_EXT_SSE, SBI_SSE_EVENT_ATTR_WRITE, evt, attr_id, 1,
			 phys, 0, 0);
	if (sret.error)
		pr_debug("Failed to set event %x attr %lx, error %ld\n", evt,
			 attr_id, sret.error);

	return sbi_err_map_linux_errno(sret.error);
}

static void sse_global_event_update_cpu(struct sse_event *event,
					unsigned int cpu)
{
	struct sse_registered_event *reg_evt = event->global;

	event->cpu = cpu;
	arch_sse_event_update_cpu(&reg_evt->arch, cpu);
}

static int sse_event_set_target_cpu_nolock(struct sse_event *event,
					   unsigned int cpu)
{
	unsigned long hart_id = cpuid_to_hartid_map(cpu);
	struct sse_registered_event *reg_evt = event->global;
	u32 evt = event->evt_id;
	bool was_enabled;
	int ret;

	if (!sse_event_is_global(evt))
		return -EINVAL;

	was_enabled = reg_evt->is_enabled;
	if (was_enabled)
		sse_event_disable_local(event);

	ret = sse_event_attr_set_nolock(reg_evt, SBI_SSE_ATTR_PREFERRED_HART,
					hart_id);
	if (ret == 0)
		sse_global_event_update_cpu(event, cpu);

	if (was_enabled)
		sse_event_enable_local(event);

	return 0;
}

int sse_event_set_target_cpu(struct sse_event *event, unsigned int cpu)
{
	int ret;

	scoped_guard(mutex, &sse_mutex) {
		scoped_guard(cpus_read_lock) {
			if (!cpu_online(cpu))
				return -EINVAL;

			ret = sse_event_set_target_cpu_nolock(event, cpu);
		}
	}

	return ret;
}
EXPORT_SYMBOL_GPL(sse_event_set_target_cpu);

static int sse_event_init_registered(unsigned int cpu,
				     struct sse_registered_event *reg_evt,
				     struct sse_event *event)
{
	reg_evt->event = event;

	return arch_sse_init_event(&reg_evt->arch, event->evt_id, cpu);
}

static void sse_event_free_registered(struct sse_registered_event *reg_evt)
{
	arch_sse_free_event(&reg_evt->arch);
}

static int sse_event_alloc_global(struct sse_event *event)
{
	int err;
	struct sse_registered_event *reg_evt;

	reg_evt = kzalloc(sizeof(*reg_evt), GFP_KERNEL);
	if (!reg_evt)
		return -ENOMEM;

	event->global = reg_evt;
	err = sse_event_init_registered(smp_processor_id(), reg_evt, event);
	if (err)
		kfree(reg_evt);

	return err;
}

static int sse_event_alloc_local(struct sse_event *event)
{
	int err;
	unsigned int cpu, err_cpu;
	struct sse_registered_event *reg_evt;
	struct sse_registered_event __percpu *reg_evts;

	reg_evts = alloc_percpu(struct sse_registered_event);
	if (!reg_evts)
		return -ENOMEM;

	event->local = reg_evts;

	for_each_possible_cpu(cpu) {
		reg_evt = per_cpu_ptr(reg_evts, cpu);
		err = sse_event_init_registered(cpu, reg_evt, event);
		if (err) {
			err_cpu = cpu;
			goto err_free_per_cpu;
		}
	}

	return 0;

err_free_per_cpu:
	for_each_possible_cpu(cpu) {
		if (cpu == err_cpu)
			break;
		reg_evt = per_cpu_ptr(reg_evts, cpu);
		sse_event_free_registered(reg_evt);
	}

	free_percpu(reg_evts);

	return err;
}

static struct sse_event *sse_event_alloc(u32 evt, u32 priority,
					 sse_event_handler_fn *handler, void *arg)
{
	int err;
	struct sse_event *event;

	event = kzalloc(sizeof(*event), GFP_KERNEL);
	if (!event)
		return ERR_PTR(-ENOMEM);

	event->evt_id = evt;
	event->priority = priority;
	event->handler_arg = arg;
	event->handler = handler;

	if (sse_event_is_global(evt))
		err = sse_event_alloc_global(event);
	else
		err = sse_event_alloc_local(event);

	if (err) {
		kfree(event);
		return ERR_PTR(err);
	}

	return event;
}

static int sse_sbi_register_event(struct sse_event *event,
				  struct sse_registered_event *reg_evt)
{
	int ret;

	ret = sse_event_attr_set_nolock(reg_evt, SBI_SSE_ATTR_PRIO,
					event->priority);
	if (ret)
		return ret;

	return arch_sse_register_event(&reg_evt->arch);
}

static int sse_event_register_local(struct sse_event *event)
{
	int ret;
	struct sse_registered_event *reg_evt;

	reg_evt = per_cpu_ptr(event->local, smp_processor_id());
	ret = sse_sbi_register_event(event, reg_evt);
	if (ret)
		pr_debug("Failed to register event %x: err %d\n", event->evt_id,
			 ret);

	return ret;
}

static int sse_sbi_unregister_event(struct sse_event *event)
{
	return sse_sbi_event_func(event, SBI_SSE_EVENT_UNREGISTER);
}

struct sse_per_cpu_evt {
	struct sse_event *event;
	unsigned long func;
	cpumask_t error;
};

static void sse_event_per_cpu_func(void *info)
{
	int ret;
	struct sse_per_cpu_evt *cpu_evt = info;

	if (cpu_evt->func == SBI_SSE_EVENT_REGISTER)
		ret = sse_event_register_local(cpu_evt->event);
	else
		ret = sse_sbi_event_func(cpu_evt->event, cpu_evt->func);

	if (ret)
		cpumask_set_cpu(smp_processor_id(), &cpu_evt->error);
}

static void sse_event_free(struct sse_event *event)
{
	unsigned int cpu;
	struct sse_registered_event *reg_evt;

	if (sse_event_is_global(event->evt_id)) {
		sse_event_free_registered(event->global);
		kfree(event->global);
	} else {
		for_each_possible_cpu(cpu) {
			reg_evt = per_cpu_ptr(event->local, cpu);
			sse_event_free_registered(reg_evt);
		}
		free_percpu(event->local);
	}

	kfree(event);
}

static int sse_on_each_cpu(struct sse_event *event, unsigned long func,
			   unsigned long revert_func)
{
	struct sse_per_cpu_evt cpu_evt;

	cpu_evt.event = event;
	cpumask_clear(&cpu_evt.error);
	cpu_evt.func = func;
	on_each_cpu(sse_event_per_cpu_func, &cpu_evt, 1);
	/*
	 * If there are some error reported by CPUs, revert event state on the
	 * other ones
	 */
	if (!cpumask_empty(&cpu_evt.error)) {
		cpumask_t revert;

		cpumask_andnot(&revert, cpu_online_mask, &cpu_evt.error);
		cpu_evt.func = revert_func;
		on_each_cpu_mask(&revert, sse_event_per_cpu_func, &cpu_evt, 1);

		return -EIO;
	}

	return 0;
}

int sse_event_enable(struct sse_event *event)
{
	int ret = 0;

	scoped_guard(mutex, &sse_mutex) {
		scoped_guard(cpus_read_lock) {
			if (sse_event_is_global(event->evt_id)) {
				ret = sse_event_enable_local(event);
			} else {
				ret = sse_on_each_cpu(event,
						      SBI_SSE_EVENT_ENABLE,
						      SBI_SSE_EVENT_DISABLE);
			}
		}
	}
	return ret;
}
EXPORT_SYMBOL_GPL(sse_event_enable);

static int sse_events_mask(void)
{
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_SSE, SBI_SSE_HART_MASK, 0, 0, 0, 0, 0, 0);

	return sbi_err_map_linux_errno(ret.error);
}

static int sse_events_unmask(void)
{
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_SSE, SBI_SSE_HART_UNMASK, 0, 0, 0, 0, 0, 0);

	return sbi_err_map_linux_errno(ret.error);
}

static void sse_event_disable_nolock(struct sse_event *event)
{
	struct sse_per_cpu_evt cpu_evt;

	if (sse_event_is_global(event->evt_id)) {
		sse_event_disable_local(event);
	} else {
		cpu_evt.event = event;
		cpu_evt.func = SBI_SSE_EVENT_DISABLE;
		on_each_cpu(sse_event_per_cpu_func, &cpu_evt, 1);
	}
}

void sse_event_disable(struct sse_event *event)
{
	scoped_guard(mutex, &sse_mutex) {
		scoped_guard(cpus_read_lock) {
			sse_event_disable_nolock(event);
		}
	}
}
EXPORT_SYMBOL_GPL(sse_event_disable);

struct sse_event *sse_event_register(u32 evt, u32 priority,
				     sse_event_handler_fn *handler, void *arg)
{
	struct sse_event *event;
	int cpu;
	int ret = 0;

	if (!sse_available)
		return ERR_PTR(-EOPNOTSUPP);

	guard(mutex)(&sse_mutex);
	if (sse_event_get(evt))
		return ERR_PTR(-EEXIST);

	event = sse_event_alloc(evt, priority, handler, arg);
	if (IS_ERR(event))
		return event;

	scoped_guard(cpus_read_lock) {
		if (sse_event_is_global(evt)) {
			unsigned long preferred_hart;

			ret = sse_event_attr_get_no_lock(event->global,
							SBI_SSE_ATTR_PREFERRED_HART,
							&preferred_hart);
			if (ret)
				goto err_event_free;

			cpu = riscv_hartid_to_cpuid(preferred_hart);
			sse_global_event_update_cpu(event, cpu);

			ret = sse_sbi_register_event(event, event->global);
			if (ret)
				goto err_event_free;

		} else {
			ret = sse_on_each_cpu(event, SBI_SSE_EVENT_REGISTER,
					      SBI_SSE_EVENT_DISABLE);
			if (ret)
				goto err_event_free;
		}
	}

	scoped_guard(spinlock, &events_list_lock)
		list_add(&event->list, &events);

	return event;

err_event_free:
	sse_event_free(event);

	return ERR_PTR(ret);
}
EXPORT_SYMBOL_GPL(sse_event_register);

static void sse_event_unregister_nolock(struct sse_event *event)
{
	struct sse_per_cpu_evt cpu_evt;

	if (sse_event_is_global(event->evt_id)) {
		sse_sbi_unregister_event(event);
	} else {
		cpu_evt.event = event;
		cpu_evt.func = SBI_SSE_EVENT_UNREGISTER;
		on_each_cpu(sse_event_per_cpu_func, &cpu_evt, 1);
	}
}

void sse_event_unregister(struct sse_event *event)
{
	scoped_guard(mutex, &sse_mutex) {
		scoped_guard(cpus_read_lock)
			sse_event_unregister_nolock(event);

		scoped_guard(spinlock, &events_list_lock)
			list_del(&event->list);

		sse_event_free(event);
	}
}
EXPORT_SYMBOL_GPL(sse_event_unregister);

static int sse_cpu_online(unsigned int cpu)
{
	struct sse_event *event;

	scoped_guard(spinlock, &events_list_lock) {
		list_for_each_entry(event, &events, list) {
			if (sse_event_is_global(event->evt_id))
				continue;

			sse_event_register_local(event);
			if (sse_get_reg_evt(event))
				sse_event_enable_local(event);
		}
	}

	/* Ready to handle events. Unmask SSE. */
	return sse_events_unmask();
}

static int sse_cpu_teardown(unsigned int cpu)
{
	int ret = 0;
	unsigned int next_cpu;
	struct sse_event *event;
	struct sse_registered_event *reg_evt;

	/* Mask the sse events */
	ret = sse_events_mask();
	if (ret)
		return ret;

	scoped_guard(spinlock, &events_list_lock) {
		list_for_each_entry(event, &events, list) {
			reg_evt = sse_get_reg_evt(event);
			if (!sse_event_is_global(event->evt_id)) {
				if (reg_evt->is_enabled)
					sse_event_disable_local(event);

				sse_sbi_unregister_event(event);
				continue;
			}

			if (event->cpu != smp_processor_id())
				continue;

			/* Update destination hart for global event */
			next_cpu = cpumask_any_but(cpu_online_mask, cpu);
			ret = sse_event_set_target_cpu_nolock(event, next_cpu);
		}
	}

	return ret;
}

static int sse_pm_notifier(struct notifier_block *nb, unsigned long action,
			   void *data)
{
	WARN_ON_ONCE(preemptible());

	switch (action) {
	case CPU_PM_ENTER:
		sse_events_mask();
		break;
	case CPU_PM_EXIT:
	case CPU_PM_ENTER_FAILED:
		sse_events_unmask();
		break;
	default:
		return NOTIFY_DONE;
	}

	return NOTIFY_OK;
}

static struct notifier_block sse_pm_nb = {
	.notifier_call = sse_pm_notifier,
};

/*
 * Mask all CPUs and unregister all events on panic, reboot or kexec.
 */
static int sse_reboot_notifier(struct notifier_block *nb, unsigned long action,
			       void *data)
{
	cpuhp_remove_state(sse_hp_state);

	return NOTIFY_OK;
}

static struct notifier_block sse_reboot_nb = {
	.notifier_call = sse_reboot_notifier,
};

static int __init sse_init(void)
{
	int ret;

	if (sbi_probe_extension(SBI_EXT_SSE) <= 0) {
		pr_err("Missing SBI SSE extension\n");
		return -EOPNOTSUPP;
	}
	pr_info("SBI SSE extension detected\n");

	ret = cpu_pm_register_notifier(&sse_pm_nb);
	if (ret) {
		pr_warn("Failed to register CPU PM notifier...\n");
		return ret;
	}

	ret = register_reboot_notifier(&sse_reboot_nb);
	if (ret) {
		pr_warn("Failed to register reboot notifier...\n");
		goto remove_cpupm;
	}

	ret = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "riscv/sse:online",
				sse_cpu_online, sse_cpu_teardown);
	if (ret < 0)
		goto remove_reboot;

	sse_hp_state = ret;
	sse_available = true;

	return 0;

remove_reboot:
	unregister_reboot_notifier(&sse_reboot_nb);

remove_cpupm:
	cpu_pm_unregister_notifier(&sse_pm_nb);

	return ret;
}
arch_initcall(sse_init);
