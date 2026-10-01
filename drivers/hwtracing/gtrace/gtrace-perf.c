// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Qualcomm Technologies, Inc.
 */

#include <linux/bitfield.h>
#include <linux/cpumask.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/init.h>
#include <linux/perf_event.h>
#include <linux/vmalloc.h>
#include <linux/percpu-defs.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/stringhash.h>
#include <linux/types.h>
#include <linux/workqueue.h>
#include <linux/gtrace.h>

#define GTRACE_PMU_NAME "gtrace"
static struct pmu gtrace_pmu;
static struct workqueue_struct *gtrace_wq;

/**
 * struct gtrace_event_data - generic hardware trace perf event data
 * @work:		Handle to free allocated memory outside IRQ context.
 * @mask:		Hold the CPU(s) this event was set for.
 * @aux_hwid_done:	Whether a CPU has emitted the TraceID packet or not.
 * @path:		An array of path, each slot for one CPU.
 * @buf:		Aux buffer / pages allocated by perf framework.
 */
struct gtrace_event_data {
	struct work_struct work;
	cpumask_t mask;
	cpumask_t aux_hwid_done;
	struct gtrace_path * __percpu *path;
	struct gtrace_perf_auxbuf buf;
};

struct gtrace_ctxt {
	struct perf_output_handle handle;
	struct gtrace_event_data *event_data;
};

static DEFINE_PER_CPU(struct gtrace_ctxt, gtrace_ctxt);

static void *alloc_event_data(int cpu)
{
	struct gtrace_event_data *event_data;
	cpumask_t *mask;

	event_data = kzalloc_obj(*event_data);
	if (!event_data)
		return NULL;

	/* Update mask as per selected CPUs */
	mask = &event_data->mask;
	if (cpu != -1)
		cpumask_set_cpu(cpu, mask);
	else
		cpumask_copy(mask, cpu_present_mask);

	event_data->path = alloc_percpu(struct gtrace_path *);
	if (!event_data->path) {
		kfree(event_data);
		return NULL;
	}

	return event_data;
}

static void gtrace_free_aux(void *data)
{
	struct gtrace_event_data *event_data = data;

	queue_work(gtrace_wq, &event_data->work);
}

static struct gtrace_path **gtrace_event_cpu_path_ptr(struct gtrace_event_data *data,
							int cpu)
{
	return per_cpu_ptr(data->path, cpu);
}

static void free_event_data(struct work_struct *work)
{
	struct gtrace_event_data *event_data;
	struct gtrace_path *path;
	cpumask_t *mask;
	int cpu;

	event_data = container_of(work, struct gtrace_event_data, work);
	mask = &event_data->mask;
	for_each_cpu(cpu, mask) {
		path = *gtrace_event_cpu_path_ptr(event_data, cpu);
		gtrace_destroy_path(path);
	}
	if (event_data->buf.base)
		vunmap(event_data->buf.base);
	free_percpu(event_data->path);
	kfree(event_data);
}

static void *gtrace_setup_aux(struct perf_event *event, void **pages,
			       int nr_pages, bool overwrite)
{
	struct gtrace_event_data *event_data = NULL;
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
		struct gtrace_component *src;
		struct gtrace_path *path;

		src = gtrace_cpu_source(cpu);
		if (!src) {
			cpumask_clear_cpu(cpu, mask);
			continue;
		}

		path = gtrace_create_path(src, NULL, GTRACE_COMPONENT_MODE_PERF);
		if (IS_ERR(path)) {
			cpumask_clear_cpu(cpu, mask);
			continue;
		}

		path->owner = task_pid_nr(event->owner);
		*gtrace_event_cpu_path_ptr(event_data, cpu) = path;
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
	kfree(pagelist);
	if (!event_data->buf.base)
		goto err;

	event_data->buf.nr_pages = nr_pages;
	event_data->buf.length = nr_pages * PAGE_SIZE;
	event_data->buf.pos = 0;
	return event_data;
err:
	gtrace_free_aux(event_data);
	return NULL;
}

static u64 gtrace_path_aux_format(struct gtrace_path *path)
{
	struct gtrace_component *src = gtrace_path_source(path);

	switch (src->pdata->format) {
	case GTRACE_FORMAT_ETRACE:
		return PERF_AUX_FLAG_GTRACE_FORMAT_ETRACE;
	case GTRACE_FORMAT_NTRACE:
		return PERF_AUX_FLAG_GTRACE_FORMAT_NTRACE;
	default:
		return PERF_AUX_FLAG_GTRACE_FORMAT_UNKNOWN;
	}
}

static void gtrace_event_read(struct perf_event *event)
{
}

static void gtrace_event_destroy(struct perf_event *event)
{
}

static int gtrace_event_init(struct perf_event *event)
{
	if (event->attr.type != gtrace_pmu.type)
		return -EINVAL;

	event->destroy = gtrace_event_destroy;
	return 0;
}

static void gtrace_event_start(struct perf_event *event, int flags)
{
	struct gtrace_ctxt *ctxt = this_cpu_ptr(&gtrace_ctxt);
	struct perf_output_handle *handle = &ctxt->handle;
	struct gtrace_event_data *event_data;
	int cpu = smp_processor_id();
	struct gtrace_path *path;

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
	path = *gtrace_event_cpu_path_ptr(event_data, cpu);
	if (!path) {
		dev_err_ratelimited(gtrace_pmu.dev, "Error. Path not found on cpu %d\n", cpu);
		goto fail_end;
	}

	if (gtrace_path_start(path)) {
		dev_err_ratelimited(gtrace_pmu.dev, "Error. Tracing not started on cpu %d\n", cpu);
		goto fail_end;
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
fail_end:
	perf_aux_output_end(handle, 0);
fail:
	event->hw.state = PERF_HES_STOPPED;
}

static void gtrace_event_stop(struct perf_event *event, int mode)
{
	struct gtrace_ctxt *ctxt = this_cpu_ptr(&gtrace_ctxt);
	struct perf_output_handle *handle = &ctxt->handle;
	u64 format = PERF_AUX_FLAG_GTRACE_FORMAT_UNKNOWN;
	struct gtrace_event_data *event_data;
	int ret, cpu = smp_processor_id();
	struct gtrace_path *path;
	size_t size = 0;

	if (event->hw.state == PERF_HES_STOPPED)
		return;

	if (handle->event && WARN_ON(perf_get_aux(handle) != ctxt->event_data))
		return;

	event_data = ctxt->event_data;
	ctxt->event_data = NULL;

	if (WARN_ON(!event_data))
		return;

	if (!cpumask_test_cpu(cpu, &event_data->mask))
		goto out_end;

	/* stop tracing */
	path = *gtrace_event_cpu_path_ptr(event_data, cpu);
	if (!path) {
		dev_err_ratelimited(gtrace_pmu.dev, "Error. Path not found on cpu %d\n", cpu);
		goto out_end;
	}

	if (gtrace_path_stop(path)) {
		dev_err_ratelimited(gtrace_pmu.dev, "Error. Tracing not stopped on cpu %d\n", cpu);
		goto out_end;
	}

	event->hw.state = PERF_HES_STOPPED;
	if (handle->event && (mode & PERF_EF_UPDATE)) {
		if (WARN_ON_ONCE(handle->event != event))
			return;
		ret = gtrace_path_copyto_auxbuf(path, &event_data->buf, &size, &format);
		WARN_ON_ONCE(ret);
		format = gtrace_path_aux_format(path);
		if (READ_ONCE(handle->event)) {
			/* Tag the AUX data with the source's trace format. */
			perf_aux_output_flag(handle, format);
			if (size > handle->size) {
				size = handle->size;
				perf_aux_output_flag(handle, PERF_AUX_FLAG_TRUNCATED);
			}
			perf_aux_output_end(handle, size);
		} else
			WARN_ON(size);
	}

	return;

out_end:
	event->hw.state = PERF_HES_STOPPED;
	if (handle->event && (mode & PERF_EF_UPDATE))
		perf_aux_output_end(handle, 0);
}

static int gtrace_event_add(struct perf_event *event, int mode)
{
	struct hw_perf_event *hwc = &event->hw;
	int ret = 0;

	if (mode & PERF_EF_START) {
		gtrace_event_start(event, 0);
		if (hwc->state & PERF_HES_STOPPED)
			ret = -EINVAL;
	} else {
		hwc->state = PERF_HES_STOPPED;
	}

	return ret;
}

static void gtrace_event_del(struct perf_event *event, int mode)
{
	gtrace_event_stop(event, PERF_EF_UPDATE);
}

PMU_FORMAT_ATTR(event, "config:0-0");

static struct attribute *gtrace_pmu_formats_attr[] = {
	&format_attr_event.attr,
	NULL,
};

static struct attribute_group gtrace_pmu_format_group = {
	.name = "format",
	.attrs = gtrace_pmu_formats_attr,
};

static const struct attribute_group *gtrace_pmu_attr_groups[] = {
	&gtrace_pmu_format_group,
	NULL,
};

int __init gtrace_perf_init(void)
{
	int ret;

	gtrace_pmu.capabilities	= (PERF_PMU_CAP_EXCLUSIVE | PERF_PMU_CAP_ITRACE);
	gtrace_pmu.attr_groups		= gtrace_pmu_attr_groups;
	gtrace_pmu.task_ctx_nr		= perf_sw_context;
	gtrace_pmu.read		= gtrace_event_read;
	gtrace_pmu.event_init		= gtrace_event_init;
	gtrace_pmu.setup_aux		= gtrace_setup_aux;
	gtrace_pmu.free_aux		= gtrace_free_aux;
	gtrace_pmu.start		= gtrace_event_start;
	gtrace_pmu.stop		= gtrace_event_stop;
	gtrace_pmu.add			= gtrace_event_add;
	gtrace_pmu.del			= gtrace_event_del;
	gtrace_pmu.module		= THIS_MODULE;

	gtrace_wq = alloc_workqueue(GTRACE_PMU_NAME, WQ_UNBOUND, 0);
	if (!gtrace_wq)
		return -ENOMEM;

	ret = perf_pmu_register(&gtrace_pmu, GTRACE_PMU_NAME, -1);
	if (ret)
		destroy_workqueue(gtrace_wq);

	return ret;
}

void __exit gtrace_perf_exit(void)
{
	perf_pmu_unregister(&gtrace_pmu);
	/* Wait for any pending free_event_data() before the module exits. */
	destroy_workqueue(gtrace_wq);
}
