/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Qualcomm Technologies, Inc.
 */

#ifndef INCLUDE__UTIL_PERF_GTRACE_H__
#define INCLUDE__UTIL_PERF_GTRACE_H__

#define GTRACE_AUXTRACE_PRIV_SIZE      sizeof(u64)

int gtrace__process_auxtrace_info(union perf_event *event, struct perf_session *session);
#endif

