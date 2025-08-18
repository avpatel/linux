/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright(C) 2015 Linaro Limited. All rights reserved.
 * Author: Mathieu Poirier <mathieu.poirier@linaro.org>
 */

#ifndef INCLUDE__UTIL_PERF_RVTRACE_H__
#define INCLUDE__UTIL_PERF_RVTRACE_H__

#include "debug.h"
#include "auxtrace.h"
#include "util/event.h"
#include "util/session.h"
#include <linux/bits.h>

#define RVTRACE_AUXTRACE_PRIV_SIZE	sizeof(u64)

int rvtrace__process_auxtrace_info(union perf_event *event, struct perf_session *session);
struct auxtrace_record *rvtrace_record_init(int *err);
#endif
