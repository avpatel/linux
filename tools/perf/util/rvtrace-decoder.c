// SPDX-License-Identifier: GPL-2.0
/*
 * RISC-V trace Decoder
 */

#include <errno.h>
#include <inttypes.h>
#include "evlist.h"
#include <internal/lib.h>
#include "rvtrace.h"

struct rvtrace_decoder {
	struct auxtrace auxtrace;
	u32 auxtrace_type;
	struct perf_session *session;
	struct machine *machine;
	u32 pmu_type;
};

static int rvtrace_process_event(struct perf_session *session __maybe_unused,
				 union perf_event *event __maybe_unused,
				 struct perf_sample *sample __maybe_unused,
				 const struct perf_tool *tool __maybe_unused)
{
	return 0;
}

static int rvtrace_process_auxtrace_event(struct perf_session *session __maybe_unused,
					  union perf_event *event __maybe_unused,
					  const struct perf_tool *tool __maybe_unused)
{
	return 0;
}

static int rvtrace_flush(struct perf_session *session __maybe_unused,
			 const struct perf_tool *tool __maybe_unused)
{
	return 0;
}

static void rvtrace_free_events(struct perf_session *session __maybe_unused)
{
}

static void rvtrace_free(struct perf_session *session)
{
	struct rvtrace_decoder *ptr = container_of(session->auxtrace, struct rvtrace_decoder,
					    auxtrace);

	session->auxtrace = NULL;
	free(ptr);
}

static bool rvtrace_evsel_is_auxtrace(struct perf_session *session,
				      struct evsel *evsel)
{
	struct rvtrace_decoder *ptr = container_of(session->auxtrace,
						   struct rvtrace_decoder, auxtrace);

	return evsel->core.attr.type == ptr->pmu_type;
}

int rvtrace__process_auxtrace_info(union perf_event *event,
				   struct perf_session *session)
{
	struct perf_record_auxtrace_info *auxtrace_info = &event->auxtrace_info;
	struct rvtrace_decoder *ptr;

	if (auxtrace_info->header.size < RVTRACE_AUXTRACE_PRIV_SIZE +
	    sizeof(struct perf_record_auxtrace_info))
		return -EINVAL;

	ptr = zalloc(sizeof(*ptr));
	if (!ptr)
		return -ENOMEM;

	ptr->session = session;
	ptr->machine = &session->machines.host;
	ptr->auxtrace_type = auxtrace_info->type;
	ptr->pmu_type = auxtrace_info->priv[0];

	ptr->auxtrace.process_event = rvtrace_process_event;
	ptr->auxtrace.process_auxtrace_event = rvtrace_process_auxtrace_event;
	ptr->auxtrace.flush_events = rvtrace_flush;
	ptr->auxtrace.free_events = rvtrace_free_events;
	ptr->auxtrace.free = rvtrace_free;
	ptr->auxtrace.evsel_is_auxtrace = rvtrace_evsel_is_auxtrace;
	session->auxtrace = &ptr->auxtrace;

	return 0;
}
