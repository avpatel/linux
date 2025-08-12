// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright(C) 2025 Ventanamicro Limited. All rights reserved.
 * Author: Mayuresh Chitale <mchitale@venanamicro.com>
 */

#include <linux/bitfield.h>
#include <linux/cpumask.h>
#include <linux/device.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/init.h>
#include <linux/perf_event.h>
#include <linux/vmalloc.h>
#include <linux/percpu-defs.h>
#include <linux/slab.h>
#include <linux/stringhash.h>
#include <linux/types.h>
#include <linux/workqueue.h>
#include <linux/rvtrace.h>

#define RVTRACE_PMU_NAME "rvtrace"
#define RVTRACE_BUF_LEN (4 * 1024 * 1024)

static struct pmu rvtrace_pmu;
static DEFINE_SPINLOCK(perf_buf_lock);

/**
 * struct rvtrace_event_data - RISC-V trace specific perf event data
 * @work:		Handle to free allocated memory outside IRQ context.
 * @mask:		Hold the CPU(s) this event was set for.
 * @aux_hwid_done:	Whether a CPU has emitted the TraceID packet or not.
 * @path:		An array of path, each slot for one CPU.
 * @buf:		Aux buffer / pages allocated by perf framework.
 */
struct rvtrace_event_data {
	struct work_struct work;
	cpumask_t mask;
	cpumask_t aux_hwid_done;
	struct rvtrace_path * __percpu *path;
	struct rvtrace_perf_auxbuf buf;
};

struct rvtrace_ctxt {
	struct perf_output_handle handle;
	struct rvtrace_event_data *event_data;
};

static DEFINE_PER_CPU(struct rvtrace_ctxt, rvtrace_ctxt);

static void *alloc_event_data(int cpu)
{
	struct rvtrace_event_data *event_data;
	cpumask_t *mask;

	event_data = kzalloc(sizeof(*event_data), GFP_KERNEL);
	if (!event_data)
		return NULL;

	/* Update mask as per selected CPUs */
	mask = &event_data->mask;
	if (cpu != -1)
		cpumask_set_cpu(cpu, mask);
	else
		cpumask_copy(mask, cpu_present_mask);

	event_data->path = alloc_percpu(struct rvtrace_path *);
	return event_data;
}

static void rvtrace_free_aux(void *data)
{
	struct rvtrace_event_data *event_data = data;

	schedule_work(&event_data->work);
}

static struct rvtrace_path **rvtrace_event_cpu_path_ptr(struct rvtrace_event_data *data,
							int cpu)
{
	return per_cpu_ptr(data->path, cpu);
}

static void free_event_data(struct work_struct *work)
{
	struct rvtrace_event_data *event_data;
	struct rvtrace_path *path;
	cpumask_t *mask;
	int cpu;

	event_data = container_of(work, struct rvtrace_event_data, work);
	mask = &event_data->mask;
	for_each_cpu(cpu, mask) {
		path = *rvtrace_event_cpu_path_ptr(event_data, cpu);
		rvtrace_destroy_path(path);
	}
	free_percpu(event_data->path);
	kfree(event_data);
}

static void *rvtrace_setup_aux(struct perf_event *event, void **pages,
			       int nr_pages, bool overwrite)
{
	struct rvtrace_event_data *event_data = NULL;
	struct page **pagelist;
	int cpu = event->cpu, i;
	cpumask_t *mask;

	event_data = alloc_event_data(cpu);
	if (!event_data)
		return NULL;

	INIT_WORK(&event_data->work, free_event_data);
	mask = &event_data->mask;
	/*
	 * Create the path for each CPU in the mask. In case of any failure skip the CPU
	 */
	for_each_cpu(cpu, mask) {
		struct rvtrace_component *src;
		struct rvtrace_path *path;

		src = rvtrace_cpu_source(cpu);
		if (!src)
			continue;

		path = rvtrace_create_path(src, NULL, RVTRACE_COMPONENT_MODE_PERF);
		if (!path)
			continue;

		*rvtrace_event_cpu_path_ptr(event_data, cpu) = path;
	}

	/* If we don't have any CPUs ready for tracing, abort */
	cpu = cpumask_first(&event_data->mask);
	if (cpu >= nr_cpu_ids)
		goto err;

	pagelist = kcalloc(nr_pages, sizeof(*pagelist), GFP_KERNEL);
	if (!pagelist)
		goto err;

	for (i = 0; i < nr_pages; i++)
		pagelist[i] = virt_to_page(pages[i]);

	event_data->buf.base = vmap(pagelist, nr_pages, VM_MAP, PAGE_KERNEL);
	if (!event_data->buf.base) {
		kfree(pagelist);
		goto err;
	}

	event_data->buf.nr_pages = nr_pages;
	event_data->buf.length = nr_pages * PAGE_SIZE;
	event_data->buf.pos = 0;
	return event_data;
err:
	rvtrace_free_aux(event_data);
	return NULL;
}

static void rvtrace_event_read(struct perf_event *event)
{
}

static void rvtrace_event_destroy(struct perf_event *event)
{
}

static int rvtrace_event_init(struct perf_event *event)
{
	if (event->attr.type != rvtrace_pmu.type)
		return -EINVAL;

	event->destroy = rvtrace_event_destroy;
	return 0;
}

static void rvtrace_event_start(struct perf_event *event, int flags)
{
	struct rvtrace_ctxt *ctxt = this_cpu_ptr(&rvtrace_ctxt);
	struct perf_output_handle *handle = &ctxt->handle;
	struct rvtrace_event_data *event_data;
	int cpu = smp_processor_id();
	struct rvtrace_path *path;

	if (WARN_ON(ctxt->event_data))
		goto fail;

	/*
	 * Deal with the ring buffer API and get a handle on the
	 * session's information.
	 */
	event_data = perf_aux_output_begin(handle, event);
	if (!event_data)
		goto fail;

	if (!cpumask_test_cpu(cpu, &event_data->mask))
		goto out;

	event_data->buf.pos = handle->head % event_data->buf.length;
	path = *rvtrace_event_cpu_path_ptr(event_data, cpu);
	if (!path) {
		pr_err("Error. Path not found\n");
		return;
	}

	if (rvtrace_path_start(path)) {
		pr_err("Error. Tracing not started\n");
		return;
	}

	/*
	 * output cpu / trace ID in perf record, once for the lifetime
	 * of the event.
	 */
	if (!cpumask_test_cpu(cpu, &event_data->aux_hwid_done)) {
		cpumask_set_cpu(cpu, &event_data->aux_hwid_done);
		perf_report_aux_output_id(event, cpu);
	}

out:
	/* Tell the perf core the event is alive */
	event->hw.state = 0;
	ctxt->event_data = event_data;
	return;
fail:
	event->hw.state = PERF_HES_STOPPED;
}

static void rvtrace_event_stop(struct perf_event *event, int mode)
{
	struct rvtrace_ctxt *ctxt = this_cpu_ptr(&rvtrace_ctxt);
	struct perf_output_handle *handle = &ctxt->handle;
	struct rvtrace_event_data *event_data;
	int ret, cpu = smp_processor_id();
	struct rvtrace_path *path;
	size_t size;

	if (event->hw.state == PERF_HES_STOPPED)
		return;

	if (handle->event &&
	    WARN_ON(perf_get_aux(handle) != ctxt->event_data))
		return;

	event_data = ctxt->event_data;
	ctxt->event_data = NULL;

	if (WARN_ON(!event_data))
		return;

	if (handle->event && (mode & PERF_EF_UPDATE) && !cpumask_test_cpu(cpu, &event_data->mask)) {
		event->hw.state = PERF_HES_STOPPED;
		perf_aux_output_end(handle, 0);
		return;
	}

	/* stop tracing */
	path = *rvtrace_event_cpu_path_ptr(event_data, cpu);
	if (!path) {
		pr_err("Error. Path not found\n");
		return;
	}

	if (rvtrace_path_stop(path)) {
		pr_err("Error. Tracing not stopped\n");
		return;
	}

	event->hw.state = PERF_HES_STOPPED;
	if (handle->event && (mode & PERF_EF_UPDATE)) {
		if (WARN_ON_ONCE(handle->event != event))
			return;
		spin_lock(&perf_buf_lock);
		ret = rvtrace_path_copyto_auxbuf(path, &event_data->buf, &size);
		spin_unlock(&perf_buf_lock);
		WARN_ON_ONCE(ret);
		if (READ_ONCE(handle->event))
			perf_aux_output_end(handle, size);
		else
			WARN_ON(size);
	}
}

static int rvtrace_event_add(struct perf_event *event, int mode)
{
	struct hw_perf_event *hwc = &event->hw;
	int ret = 0;

	if (mode & PERF_EF_START) {
		rvtrace_event_start(event, 0);
		if (hwc->state & PERF_HES_STOPPED)
			ret = -EINVAL;
	} else {
		hwc->state = PERF_HES_STOPPED;
	}

	return ret;
}

static void rvtrace_event_del(struct perf_event *event, int mode)
{
	rvtrace_event_stop(event, PERF_EF_UPDATE);
}

PMU_FORMAT_ATTR(event, "config:0-0");

static struct attribute *rvtrace_pmu_formats_attr[] = {
	&format_attr_event.attr,
	NULL,
};

static struct attribute_group rvtrace_pmu_format_group = {
	.name = "format",
	.attrs = rvtrace_pmu_formats_attr,
};

static const struct attribute_group *rvtrace_pmu_attr_groups[] = {
	&rvtrace_pmu_format_group,
	NULL,
};

int __init rvtrace_perf_init(void)
{
	rvtrace_pmu.capabilities	= (PERF_PMU_CAP_EXCLUSIVE | PERF_PMU_CAP_ITRACE);
	rvtrace_pmu.attr_groups		= rvtrace_pmu_attr_groups;
	rvtrace_pmu.task_ctx_nr		= perf_sw_context;
	rvtrace_pmu.read		= rvtrace_event_read;
	rvtrace_pmu.event_init		= rvtrace_event_init;
	rvtrace_pmu.setup_aux		= rvtrace_setup_aux;
	rvtrace_pmu.free_aux		= rvtrace_free_aux;
	rvtrace_pmu.start		= rvtrace_event_start;
	rvtrace_pmu.stop		= rvtrace_event_stop;
	rvtrace_pmu.add			= rvtrace_event_add;
	rvtrace_pmu.del			= rvtrace_event_del;
	rvtrace_pmu.module		= THIS_MODULE;

	return perf_pmu_register(&rvtrace_pmu, RVTRACE_PMU_NAME, -1);
}

void __exit rvtrace_perf_exit(void)
{
	perf_pmu_unregister(&rvtrace_pmu);
}
