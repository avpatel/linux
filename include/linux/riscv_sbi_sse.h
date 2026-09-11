/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2025 Rivos Inc.
 */

#ifndef __LINUX_RISCV_SBI_SSE_H
#define __LINUX_RISCV_SBI_SSE_H

#include <linux/err.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/linkage.h>

struct sse_event;
struct pt_regs;

typedef int (sse_event_handler_fn)(u32 event_num, void *arg,
				   struct pt_regs *regs);

#ifdef CONFIG_RISCV_SBI_SSE

/*
 * The callback and its argument must remain valid until unregister succeeds.
 * The callback runs in NMI context and must not sleep.
 * regs is NULL if firmware cannot provide a complete interrupted context.
 */
struct sse_event *sse_event_register(u32 event_num, u32 priority,
				     sse_event_handler_fn *handler, void *arg);

int sse_event_unregister(struct sse_event *evt);

/*
 * Transfer a retained event to the SSE core for deferred cleanup. The caller
 * must not access the event or its callback data after this function returns.
 */
void sse_event_cleanup(struct sse_event *evt);

int sse_event_set_target_cpu(struct sse_event *sse_evt, unsigned int cpu);

int sse_event_enable(struct sse_event *sse_evt);

int sse_event_disable(struct sse_event *sse_evt);

/* Local events require the caller to remain on the current CPU. */
bool sse_event_is_enabled_local(struct sse_event *sse_evt);
int sse_event_enable_local(struct sse_event *sse_evt);
int sse_event_disable_local(struct sse_event *sse_evt);

#else
static inline struct sse_event *sse_event_register(u32 event_num, u32 priority,
						   sse_event_handler_fn *handler,
						   void *arg)
{
	return ERR_PTR(-EOPNOTSUPP);
}

static inline int sse_event_unregister(struct sse_event *evt)
{
	return -EOPNOTSUPP;
}

static inline void sse_event_cleanup(struct sse_event *evt) { }

static inline int sse_event_set_target_cpu(struct sse_event *sse_evt,
					   unsigned int cpu)
{
	return -EOPNOTSUPP;
}

static inline int sse_event_enable(struct sse_event *sse_evt)
{
	return -EOPNOTSUPP;
}

static inline int sse_event_disable(struct sse_event *sse_evt)
{
	return -EOPNOTSUPP;
}

static inline bool sse_event_is_enabled_local(struct sse_event *sse_evt)
{
	return false;
}

static inline int sse_event_enable_local(struct sse_event *sse_evt)
{
	return -EOPNOTSUPP;
}

static inline int sse_event_disable_local(struct sse_event *sse_evt)
{
	return -EOPNOTSUPP;
}
#endif
#endif /* __LINUX_RISCV_SBI_SSE_H */
