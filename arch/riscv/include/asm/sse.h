/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2024 Rivos Inc.
 */
#ifndef __ASM_SSE_H
#define __ASM_SSE_H

struct sse_registered_event;
int sse_init_event(int cpu, struct sse_registered_event *reg_evt);
void sse_free_event(struct sse_registered_event *reg_evt);

#endif
