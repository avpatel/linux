/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025 Ventana Micro Systems Inc.
 */

#ifndef __LINUX_RVTRACE_H__
#define __LINUX_RVTRACE_H__

#include <linux/device.h>
#include <linux/io.h>
#include <linux/limits.h>
#include <linux/list.h>
#include <linux/platform_device.h>
#include <linux/property.h>
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

/* Possible component types defined by the RISC-V Trace Control Interface */
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

/* Encoding/decoding macros for RISC-V trace component version */
#define rvtrace_component_version_major(__version)	\
	(((__version) >> 16) & 0xffff)
#define rvtrace_component_version_minor(__version)	\
	((__version) & 0xffff)
#define rvtrace_component_mkversion(__major, __minor)	\
	((((__major) & 0xffff) << 16) |	((__minor) & 0xffff))

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

/* Supported usage modes for RISC-V trace components */
enum rvtrace_component_mode {
	RVTRACE_COMPONENT_MODE_PERF,
	RVTRACE_COMPONENT_MODE_MAX
};

/**
 * struct rvtrace_connection - Representation of a physical connection between
 * two RISC-V trace components.
 * @src_port:    A connection's source port number.
 * @src_fwnode:  Source component's fwnode handle..
 * @src_comp:    Source component's pointer.
 * @dest_port:   A connection's destination port number.
 * @dest_fwnode: Destination component's fwnode handle.
 * @dest_comp:   Destination component's pointer.
 */
struct rvtrace_connection {
	int src_port;
	struct fwnode_handle *src_fwnode;
	int dest_port;
	struct fwnode_handle *dest_fwnode;
	struct rvtrace_component *src_comp;
	struct rvtrace_component *dest_comp;
};

/**
 * struct rvtrace_platform_data - Platform-level data for a RISC-V trace component
 * discovered from DT or ACPI.
 * @dev:         Parent device.
 * @impid:       Component implementation ID
 * @io_mem:      Flag showing whether component registers are memory mapped.
 * @base:        If io_mem == true then base address of the memory mapped registers.
 * @read:        If io_mem == false then read register from the given "offset".
 * @write:       If io_mem == false then write register to the given "offset".
 * @bound_cpu:   CPU to which the component is bound. This should be -1 if
 *               the component is not bound to any CPU. For encoder component
 *               type this must not be -1.
 * @nr_inconns:  Number of input connections.
 * @inconns:     Array of pointers to input connections.
 * @nr_outconns: Number of output connections.
 * @outconns:    Array of pointers to output connections.
 */
struct rvtrace_platform_data {
	struct device *dev;

	enum rvtrace_component_impid impid;

	bool io_mem;
	union {
		void __iomem *base;
		struct {
			u32 (*read)(struct rvtrace_platform_data *pdata,
				    u32 offset, bool relaxed);
			void (*write)(struct rvtrace_platform_data *pdata,
				      u32 val, u32 offset, bool relaxed);
		};
	};

	int bound_cpu;

	/* Delay in microseconds when polling control register bits */
	int control_poll_timeout_usecs;

	/*
	 * Platform driver must only populate empty pointer array without
	 * any actual input connections.
	 */
	unsigned int nr_inconns;
	struct rvtrace_connection **inconns;

	/*
	 * Platform driver must fully populate pointer array with individual
	 * array elements pointing to actual output connections. The src_comp
	 * of each output connection is automatically updated at the time of
	 * registering component.
	 */
	unsigned int nr_outconns;
	struct rvtrace_connection **outconns;
};

static inline u32 rvtrace_read32(struct rvtrace_platform_data *pdata, u32 offset)
{
	if (likely(pdata->io_mem))
		return readl(pdata->base + offset);

	return pdata->read(pdata, offset, false);
}

static inline u32 rvtrace_relaxed_read32(struct rvtrace_platform_data *pdata, u32 offset)
{
	if (likely(pdata->io_mem))
		return readl_relaxed(pdata->base + offset);

	return pdata->read(pdata, offset, true);
}

static inline void rvtrace_write32(struct rvtrace_platform_data *pdata, u32 val, u32 offset)
{
	if (likely(pdata->io_mem))
		writel(val, pdata->base + offset);
	else
		pdata->write(pdata, val, offset, false);
}

static inline void rvtrace_relaxed_write32(struct rvtrace_platform_data *pdata,
					   u32 val, u32 offset)
{
	if (likely(pdata->io_mem))
		writel_relaxed(val, pdata->base + offset);
	else
		pdata->write(pdata, val, offset, true);
}

static inline bool rvtrace_is_source(struct rvtrace_platform_data *pdata)
{
	return !pdata->nr_inconns ? true : false;
}

static inline bool rvtrace_is_sink(struct rvtrace_platform_data *pdata)
{
	return !pdata->nr_outconns ? true : false;
}

/**
 * struct rvtrace_component_id - Details to identify or match a RISC-V trace component
 * @type:      Type of the component
 * @version:   Version of the component
 * @data:      Data pointer for driver use
 */
struct rvtrace_component_id {
	enum rvtrace_component_type type;
	u32 version;
	void *data;
};

/**
 * struct rvtrace_component - Representation of a RISC-V trace component
 * pdata:    Pointer to underlying platform data
 * id:       Details to match the component
 * type_idx: Unique number based on component type
 * dev:      Device instance
 * ready:    Flag showing whether RISC-V trace driver was probed successfully
 */
struct rvtrace_component {
	struct rvtrace_platform_data *pdata;
	struct rvtrace_component_id id;
	u32 type_idx;
	struct device dev;
	bool ready;
};

#define to_rvtrace_component(__dev)	container_of_const(__dev, struct rvtrace_component, dev)

static inline void rvtrace_get_component(struct rvtrace_component *comp)
{
	get_device(&comp->dev);
}

static inline void rvtrace_put_component(struct rvtrace_component *comp)
{
	put_device(&comp->dev);
}

const struct rvtrace_component_id *rvtrace_match_id(struct rvtrace_component *comp,
						    const struct rvtrace_component_id *ids);
struct rvtrace_component *rvtrace_find_by_fwnode(struct fwnode_handle *fwnode);

int rvtrace_poll_bit(struct rvtrace_platform_data *pdata, int offset,
		     int bit, int bitval, int timeout);
int rvtrace_enable_component(struct rvtrace_component *comp);
int rvtrace_disable_component(struct rvtrace_component *comp);

int rvtrace_walk_output_components(struct rvtrace_component *comp, void *priv,
				   int (*fn)(struct rvtrace_component *comp, bool *stop,
					     struct rvtrace_connection *stop_conn,
					     void *priv));
struct rvtrace_component *rvtrace_cpu_source(unsigned int cpu);

struct rvtrace_component *rvtrace_register_component(struct rvtrace_platform_data *pdata);
void rvtrace_unregister_component(struct rvtrace_component *comp);

/**
 * struct rvtrace_path - Representation of a RISC-V trace path from source to sink
 * @comp_list: List of RISC-V trace components in the path
 * @mode:      Usage mode for RISC-V trace components
 * @trace_id:  ID of the trace source (typically hart id)
 */
struct rvtrace_path {
	struct list_head		comp_list;
	enum rvtrace_component_mode	mode;
	u32				trace_id;
#define RVTRACE_INVALID_TRACE_ID	0
};

struct rvtrace_component *rvtrace_path_source(struct rvtrace_path *path);
struct rvtrace_component *rvtrace_path_sink(struct rvtrace_path *path);
struct rvtrace_path *rvtrace_create_path(struct rvtrace_component *source,
					 struct rvtrace_component *sink,
					 enum rvtrace_component_mode mode);
void rvtrace_destroy_path(struct rvtrace_path *path);
int rvtrace_path_start(struct rvtrace_path *path);
int rvtrace_path_stop(struct rvtrace_path *path);

/**
 * struct rvtrace_perf_auxbuf - Representation of the perf AUX buffer
 * @length:   size of the AUX buffer
 * @nr_pages: number of pages of the AUX buffer
 * @base:     start address of AUX buffer
 * @pos:      position in the AUX buffer to commit traced data
 */
struct rvtrace_perf_auxbuf {
	size_t length;
	int nr_pages;
	void *base;
	long pos;
};

int rvtrace_path_copyto_auxbuf(struct rvtrace_path *path,
			       struct rvtrace_perf_auxbuf *buf,
			       size_t *bytes_copied);

/**
 * struct rvtrace_driver - Representation of a RISC-V trace driver
 * id_table: Table to match components handled by the driver
 * copyto_auxbuf:Callback to copy data into perf AUX buffer
 * start:        Callback to start tracing
 * stop:         Callback to stop tracing
 * probe:        Driver probe() function
 * remove:       Driver remove() function
 * get_trace_id: Get/allocate a trace ID
 * put_trace_id: Put/free a trace ID
 * driver:   Device driver instance
 */
struct rvtrace_driver {
	const struct rvtrace_component_id *id_table;
	size_t			(*copyto_auxbuf)(struct rvtrace_component *comp,
						 struct rvtrace_perf_auxbuf *buf);
	int			(*start)(struct rvtrace_component *comp);
	int			(*stop)(struct rvtrace_component *comp);
	int			(*probe)(struct rvtrace_component *comp);
	void			(*remove)(struct rvtrace_component *comp);
	int			(*get_trace_id)(struct rvtrace_component *comp,
						enum rvtrace_component_mode mode);
	void			(*put_trace_id)(struct rvtrace_component *comp,
						enum rvtrace_component_mode mode,
						u32 trace_id);
	struct device_driver	driver;
};

#define to_rvtrace_driver(__drv)   \
	((__drv) ? container_of_const((__drv), struct rvtrace_driver, driver) : NULL)

extern struct platform_driver rvtrace_platform_driver;

int __rvtrace_register_driver(struct module *owner, struct rvtrace_driver *rtdrv);
#define rvtrace_register_driver(driver) __rvtrace_register_driver(THIS_MODULE, driver)
static inline void rvtrace_unregister_driver(struct rvtrace_driver *rtdrv)
{
	if (rtdrv)
		driver_unregister(&rtdrv->driver);
}

static inline int rvtrace_comp_is_empty(struct rvtrace_component *comp)
{
	return rvtrace_poll_bit(comp->pdata, RVTRACE_COMPONENT_CTRL_OFFSET,
				RVTRACE_COMPONENT_CTRL_EMPTY_SHIFT, 1,
				comp->pdata->control_poll_timeout_usecs);
}

int rvtrace_perf_init(void);
void rvtrace_perf_exit(void);

#endif
