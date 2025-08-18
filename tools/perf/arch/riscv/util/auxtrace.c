// SPDX-License-Identifier: GPL-2.0
/*
 * Risc-V E-Trace support
 */

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/bitops.h>
#include <linux/log2.h>
#include <linux/zalloc.h>
#include <time.h>

#include <internal/lib.h> // page_size
#include "../../../util/auxtrace.h"
#include "../../../util/cpumap.h"
#include "../../../util/debug.h"
#include "../../../util/event.h"
#include "../../../util/evlist.h"
#include "../../../util/evsel.h"
#include "../../../util/rvtrace.h"
#include "../../../util/pmu.h"
#include "../../../util/record.h"
#include "../../../util/session.h"
#include "../../../util/tsc.h"

#define RVTRACE_PMU_NAME "rvtrace"
#define KiB(x) ((x) * 1024)
#define MiB(x) ((x) * 1024 * 1024)

struct rvtrace_recording {
	struct auxtrace_record	itr;
	struct perf_pmu *rvtrace_pmu;
	struct evlist *evlist;
};

static size_t rvtrace_info_priv_size(struct auxtrace_record *itr __maybe_unused,
				     struct evlist *evlist __maybe_unused)
{
	return RVTRACE_AUXTRACE_PRIV_SIZE;
}

static int rvtrace_info_fill(struct auxtrace_record *itr, struct perf_session *session,
			     struct perf_record_auxtrace_info *auxtrace_info, size_t priv_size)
{
	struct rvtrace_recording *ptr = container_of(itr, struct rvtrace_recording, itr);
	struct perf_pmu *rvtrace_pmu = ptr->rvtrace_pmu;

	if (priv_size != RVTRACE_AUXTRACE_PRIV_SIZE)
		return -EINVAL;

	if (!session->evlist->core.nr_mmaps)
		return -EINVAL;

	auxtrace_info->type = PERF_AUXTRACE_RISCV_TRACE;
	auxtrace_info->priv[0] = rvtrace_pmu->type;

	return 0;
}

static int rvtrace_set_auxtrace_mmap_page(struct record_opts *opts)
{
	bool privileged = perf_event_paranoid_check(-1);

	if (!opts->full_auxtrace)
		return 0;

	if (opts->full_auxtrace && !opts->auxtrace_mmap_pages) {
		if (privileged) {
			opts->auxtrace_mmap_pages = MiB(16) / page_size;
		} else {
			opts->auxtrace_mmap_pages = KiB(128) / page_size;
			if (opts->mmap_pages == UINT_MAX)
				opts->mmap_pages = KiB(256) / page_size;
		}
	}

	/* Validate auxtrace_mmap_pages */
	if (opts->auxtrace_mmap_pages) {
		size_t sz = opts->auxtrace_mmap_pages * (size_t)page_size;
		size_t min_sz = KiB(8);

		if (sz < min_sz || !is_power_of_2(sz)) {
			pr_err("Invalid mmap size : must be at least %zuKiB and a power of 2\n",
			       min_sz / 1024);
			return -EINVAL;
		}
	}

	return 0;
}

static int rvtrace_recording_options(struct auxtrace_record *itr, struct evlist *evlist,
				     struct record_opts *opts)
{
	struct rvtrace_recording *ptr = container_of(itr, struct rvtrace_recording, itr);
	struct perf_pmu *rvtrace_pmu = ptr->rvtrace_pmu;
	struct evsel *evsel, *rvtrace_evsel = NULL;
	struct evsel *tracking_evsel;
	int err;

	ptr->evlist = evlist;
	evlist__for_each_entry(evlist, evsel) {
		if (evsel->core.attr.type == rvtrace_pmu->type) {
			if (rvtrace_evsel) {
				pr_err("There may be only one " RVTRACE_PMU_NAME "x event\n");
				return -EINVAL;
			}
			evsel->core.attr.freq = 0;
			evsel->core.attr.sample_period = 1;
			evsel->needs_auxtrace_mmap = true;
			rvtrace_evsel = evsel;
			opts->full_auxtrace = true;
		}
	}

	err = rvtrace_set_auxtrace_mmap_page(opts);
	if (err)
		return err;
	/*
	 * To obtain the auxtrace buffer file descriptor, the auxtrace event
	 * must come first.
	 */
	evlist__to_front(evlist, rvtrace_evsel);
	evsel__set_sample_bit(rvtrace_evsel, TIME);

	/* Add dummy event to keep tracking */
	err = parse_event(evlist, "dummy:u");
	if (err)
		return err;

	tracking_evsel = evlist__last(evlist);
	evlist__set_tracking_event(evlist, tracking_evsel);

	tracking_evsel->core.attr.freq = 0;
	tracking_evsel->core.attr.sample_period = 1;
	evsel__set_sample_bit(tracking_evsel, TIME);

	return 0;
}

static u64 rvtrace_reference(struct auxtrace_record *itr __maybe_unused)
{
	return rdtsc();
}

static void rvtrace_recording_free(struct auxtrace_record *itr)
{
	struct rvtrace_recording *ptr =
			container_of(itr, struct rvtrace_recording, itr);

	free(ptr);
}

static struct auxtrace_record *rvtrace_recording_init(int *err, struct perf_pmu *rvtrace_pmu)
{
	struct rvtrace_recording *ptr;

	if (!rvtrace_pmu) {
		*err = -ENODEV;
		return NULL;
	}

	ptr = zalloc(sizeof(*ptr));
	if (!ptr) {
		*err = -ENOMEM;
		return NULL;
	}

	ptr->rvtrace_pmu = rvtrace_pmu;
	ptr->itr.recording_options = rvtrace_recording_options;
	ptr->itr.info_priv_size = rvtrace_info_priv_size;
	ptr->itr.info_fill = rvtrace_info_fill;
	ptr->itr.free = rvtrace_recording_free;
	ptr->itr.reference = rvtrace_reference;
	ptr->itr.read_finish = auxtrace_record__read_finish;
	ptr->itr.alignment = 0;

	*err = 0;
	return &ptr->itr;
}

static struct perf_pmu *find_pmu_for_event(struct perf_pmu **pmus,
					   int pmu_nr, struct evsel *evsel)
{
	int i;

	if (!pmus)
		return NULL;

	for (i = 0; i < pmu_nr; i++) {
		if (evsel->core.attr.type == pmus[i]->type)
			return pmus[i];
	}

	return NULL;
}

struct auxtrace_record *auxtrace_record__init(struct evlist *evlist, int *err)
{
	struct perf_pmu	*rvtrace_pmu = NULL;
	struct perf_pmu *found_etm = NULL;
	struct evsel *evsel;

	if (!evlist)
		return NULL;

	rvtrace_pmu = perf_pmus__find(RVTRACE_PMU_NAME);
	evlist__for_each_entry(evlist, evsel) {
		if (rvtrace_pmu && !found_etm)
			found_etm = find_pmu_for_event(&rvtrace_pmu, 1, evsel);
	}

	if (found_etm)
		return rvtrace_recording_init(err, rvtrace_pmu);

	*err = 0;
	return NULL;
}
