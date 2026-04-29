// SPDX-License-Identifier: GPL-2.0
/*
 * Generic hardware trace (gtrace) decoder
 * Copyright (c) 2026 Qualcomm Technologies, Inc.
 */

#include <errno.h>
#include <inttypes.h>
#include <internal/lib.h>
#include "evlist.h"
#include "session.h"
#include "gtrace.h"

struct gtrace_decoder {
	struct auxtrace auxtrace;
	u32 auxtrace_type;
	struct perf_session *session;
	struct machine *machine;
	u32 pmu_type;
};

static int gtrace_process_event(struct perf_session *session __maybe_unused,
				 union perf_event *event __maybe_unused,
				 struct perf_sample *sample __maybe_unused,
				 const struct perf_tool *tool __maybe_unused)
{
	return 0;
}

static int gtrace_process_auxtrace_event(struct perf_session *session __maybe_unused,
					  union perf_event *event __maybe_unused,
					  const struct perf_tool *tool __maybe_unused)
{
	return 0;
}

static int gtrace_flush(struct perf_session *session __maybe_unused,
			 const struct perf_tool *tool __maybe_unused)
{
	return 0;
}

static void gtrace_free_events(struct perf_session *session __maybe_unused)
{
}

static void gtrace_free(struct perf_session *session)
{
	struct gtrace_decoder *ptr = container_of(session->auxtrace, struct gtrace_decoder,
					    auxtrace);

	session->auxtrace = NULL;
	free(ptr);
}

static bool gtrace_evsel_is_auxtrace(struct perf_session *session,
				      struct evsel *evsel)
{
	struct gtrace_decoder *ptr = container_of(session->auxtrace,
						   struct gtrace_decoder, auxtrace);

	return evsel->core.attr.type == ptr->pmu_type;
}

int gtrace__process_auxtrace_info(union perf_event *event,
				   struct perf_session *session)
{
	struct perf_record_auxtrace_info *auxtrace_info = &event->auxtrace_info;
	struct gtrace_decoder *ptr;

	if (auxtrace_info->header.size < GTRACE_AUXTRACE_PRIV_SIZE +
	    sizeof(struct perf_record_auxtrace_info))
		return -EINVAL;

	ptr = zalloc(sizeof(*ptr));
	if (!ptr)
		return -ENOMEM;

	ptr->session = session;
	ptr->machine = &session->machines.host;
	ptr->auxtrace_type = auxtrace_info->type;
	ptr->pmu_type = auxtrace_info->priv[0];

	ptr->auxtrace.process_event = gtrace_process_event;
	ptr->auxtrace.process_auxtrace_event = gtrace_process_auxtrace_event;
	ptr->auxtrace.flush_events = gtrace_flush;
	ptr->auxtrace.free_events = gtrace_free_events;
	ptr->auxtrace.free = gtrace_free;
	ptr->auxtrace.evsel_is_auxtrace = gtrace_evsel_is_auxtrace;
	session->auxtrace = &ptr->auxtrace;

	return 0;
}
