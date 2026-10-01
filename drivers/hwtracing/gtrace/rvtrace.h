/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2026 Qualcomm Technologies, Inc.
 *
 * RISC-V trace component register layout and helpers for the RISC-V backend
 * of the generic trace (gtrace) framework. These definitions are specific to
 * the RISC-V Trace Control Interface and must not be used by the generic core.
 */

#ifndef __LINUX_RVTRACE_H__
#define __LINUX_RVTRACE_H__

#include <linux/gtrace.h>
#include <linux/types.h>

/* Control register common across all RISC-V trace components */
#define RVTRACE_COMPONENT_CTRL_OFFSET		0x000
#define RVTRACE_COMPONENT_CTRL_ACTIVE_MASK	0x1
#define RVTRACE_COMPONENT_CTRL_ACTIVE_SHIFT	0
#define RVTRACE_COMPONENT_CTRL_ENABLE_MASK	0x1
#define RVTRACE_COMPONENT_CTRL_ENABLE_SHIFT	1
#define RVTRACE_COMPONENT_CTRL_EMPTY_SHIFT	3

/* Implementation register common across all RISC-V trace components */
#define RVTRACE_COMPONENT_IMPL_OFFSET		0x004
#define RVTRACE_COMPONENT_IMPL_VERMAJOR_MASK	0xf
#define RVTRACE_COMPONENT_IMPL_VERMAJOR_SHIFT	0
#define RVTRACE_COMPONENT_IMPL_VERMINOR_MASK	0xf
#define RVTRACE_COMPONENT_IMPL_VERMINOR_SHIFT	4
#define RVTRACE_COMPONENT_IMPL_TYPE_MASK	0xf
#define RVTRACE_COMPONENT_IMPL_TYPE_SHIFT	8

/* Component types defined by the RISC-V Trace Control Interface */
enum rvtrace_component_type {
	RVTRACE_COMPONENT_TYPE_RESV0,
	RVTRACE_COMPONENT_TYPE_ENCODER, /* 0x1 */
	RVTRACE_COMPONENT_TYPE_RESV2,
	RVTRACE_COMPONENT_TYPE_RESV3,
	RVTRACE_COMPONENT_TYPE_RESV4,
	RVTRACE_COMPONENT_TYPE_RESV5,
	RVTRACE_COMPONENT_TYPE_RESV6,
	RVTRACE_COMPONENT_TYPE_RESV7,
	RVTRACE_COMPONENT_TYPE_FUNNEL, /* 0x8 */
	RVTRACE_COMPONENT_TYPE_RAMSINK, /* 0x9 */
	RVTRACE_COMPONENT_TYPE_PIBSINK, /* 0xA */
	RVTRACE_COMPONENT_TYPE_RESV11,
	RVTRACE_COMPONENT_TYPE_RESV12,
	RVTRACE_COMPONENT_TYPE_RESV13,
	RVTRACE_COMPONENT_TYPE_ATBBRIDGE, /* 0xE */
	RVTRACE_COMPONENT_TYPE_RESV15,
	RVTRACE_COMPONENT_TYPE_MAX
};

/*
 * Possible component implementation IDs discovered from DT or ACPI
 * shared across the RISC-V trace drivers to infer trace parameters,
 * quirks, and work-arounds. These component implementation IDs are
 * internal to Linux and must not be exposed to user-space.
 *
 * The component implementation ID should be named as follows:
 *    RVTRACE_COMPONENT_IMPID_<vendor>_<part>
 */
enum rvtrace_component_impid {
	RVTRACE_COMPONENT_IMPID_UNKNOWN,
	RVTRACE_COMPONENT_IMPID_MAX
};

#define rvtrace_component_version_major(__version)	\
	(((__version) >> 16) & 0xffff)
#define rvtrace_component_version_minor(__version)	\
	((__version) & 0xffff)
#define rvtrace_component_mkversion(__major, __minor)	\
	((((__major) & 0xffff) << 16) | ((__minor) & 0xffff))

/* Map a RISC-V hardware component type to the global gtrace type */
static inline int rvtrace_type_to_gtrace(enum rvtrace_component_type type)
{
	switch (type) {
	case RVTRACE_COMPONENT_TYPE_ENCODER:
		return GTRACE_RVTRACE_ENCODER;
	case RVTRACE_COMPONENT_TYPE_FUNNEL:
		return GTRACE_RVTRACE_FUNNEL;
	case RVTRACE_COMPONENT_TYPE_RAMSINK:
		return GTRACE_RVTRACE_RAMSINK;
	case RVTRACE_COMPONENT_TYPE_PIBSINK:
		return GTRACE_RVTRACE_PIBSINK;
	case RVTRACE_COMPONENT_TYPE_ATBBRIDGE:
		return GTRACE_RVTRACE_ATBBRIDGE;
	default:
		return -EINVAL;
	}
}

static inline const char *rvtrace_type_name(enum gtrace_component_type type)
{
	switch (type) {
	case GTRACE_RVTRACE_ENCODER:
		return "encoder";
	case GTRACE_RVTRACE_FUNNEL:
		return "funnel";
	case GTRACE_RVTRACE_RAMSINK:
		return "ramsink";
	case GTRACE_RVTRACE_PIBSINK:
		return "pibsink";
	case GTRACE_RVTRACE_ATBBRIDGE:
		return "atbbridge";
	default:
		return NULL;
	}
}

static inline int rvtrace_comp_poll_empty(struct gtrace_component *comp)
{
	return gtrace_poll_bit(comp->pdata, RVTRACE_COMPONENT_CTRL_OFFSET,
			       RVTRACE_COMPONENT_CTRL_EMPTY_SHIFT, 1,
			       comp->pdata->control_poll_timeout_usecs);
}

extern const struct gtrace_hw_ops rvtrace_hw_ops;

#endif /* __LINUX_RVTRACE_H__ */
