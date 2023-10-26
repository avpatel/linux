/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2024 Rivos Inc.
 */

#ifndef __LINUX_RISCV_SSE_H
#define __LINUX_RISCV_SSE_H

#include <linux/types.h>
#include <linux/linkage.h>

struct sse_event;
struct pt_regs;

struct ghes;

typedef int (sse_event_handler)(u32 event_num, void *arg, struct pt_regs *regs);

#ifdef CONFIG_RISCV_SSE

struct sse_event *sse_event_register(u32 event_num, u32 priority,
				     sse_event_handler *handler, void *arg);

void sse_event_unregister(struct sse_event *evt);

int sse_event_set_target_cpu(struct sse_event *sse_evt, unsigned int cpu);

int sse_event_enable(struct sse_event *sse_evt);

void sse_event_disable(struct sse_event *sse_evt);

int sse_register_ghes(struct ghes *ghes, sse_event_handler *lo_cb,
		      sse_event_handler *hi_cb);
int sse_unregister_ghes(struct ghes *ghes);
#else
static inline struct sse_event *sse_event_register(u32 event_num, u32 priority,
						   sse_event_handler *handler,
						   void *arg)
{
	return ERR_PTR(-EOPNOTSUPP);
}

static inline void sse_event_unregister(struct sse_event *evt) {}

static inline int sse_event_set_target_cpu(struct sse_event *sse_evt,
					   unsigned int cpu)
{
	return -EOPNOTSUPP;
}

static inline int sse_event_enable(struct sse_event *sse_evt)
{
	return -EOPNOTSUPP;
}

static inline void sse_event_disable(struct sse_event *sse_evt) {}

static inline int sse_register_ghes(struct ghes *ghes, sse_event_handler *lo_cb,
				    sse_event_handler *hi_cb)
{
	return -EOPNOTSUPP;
}

static inline int sse_unregister_ghes(struct ghes *ghes)
{
	return -EOPNOTSUPP;
}

#endif

#endif /* __LINUX_RISCV_SSE_H */
