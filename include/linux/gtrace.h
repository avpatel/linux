/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2026 Qualcomm Technologies, Inc.
 */

#ifndef __LINUX_GTRACE_H__
#define __LINUX_GTRACE_H__

#include <linux/device.h>
#include <linux/io.h>
#include <linux/limits.h>
#include <linux/list.h>
#include <linux/platform_device.h>
#include <linux/property.h>
#include <linux/types.h>

/*
 * Global list of trace component types across all architectures. Each backend
 * uses the entries relevant to it.
 */
enum gtrace_component_type {
	GTRACE_RVTRACE_ENCODER,
	GTRACE_RVTRACE_FUNNEL,
	GTRACE_RVTRACE_RAMSINK,
	GTRACE_RVTRACE_PIBSINK,
	GTRACE_RVTRACE_ATBBRIDGE,
	GTRACE_COMPONENT_TYPE_MAX
};

/* Supported usage modes for trace components */
enum gtrace_component_mode {
	GTRACE_COMPONENT_MODE_PERF,
	GTRACE_COMPONENT_MODE_MAX
};

/**
 * struct gtrace_connection - Physical connection between two trace components.
 * @src_port:    A connection's source port number.
 * @src_fwnode:  Source component's fwnode handle.
 * @src_comp:    Source component's pointer.
 * @dest_port:   A connection's destination port number.
 * @dest_fwnode: Destination component's fwnode handle.
 * @dest_comp:   Destination component's pointer.
 */
struct gtrace_connection {
	int src_port;
	struct fwnode_handle *src_fwnode;
	int dest_port;
	struct fwnode_handle *dest_fwnode;
	struct gtrace_component *src_comp;
	struct gtrace_component *dest_comp;
};

struct gtrace_platform_data;

/**
 * struct gtrace_hw_ops - Architecture-specific low level control of a component.
 * @enable:  Enable the component's hardware block.
 * @disable: Disable the component's hardware block.
 * @reset:   Reset the component's hardware block.
 *
 * These operate on the component's platform data rather than a full
 * gtrace_component so that they can be invoked before the component is
 * registered with the gtrace core (e.g. to reset the hardware during probe).
 *
 * These abstract the register-level programming that differs between
 * architectures (RISC-V Trace Control registers vs ARM CoreSight, etc.). The
 * core never touches component registers directly; it invokes these ops.
 */
struct gtrace_hw_ops {
	int (*enable)(struct gtrace_platform_data *pdata);
	int (*disable)(struct gtrace_platform_data *pdata);
	int (*reset)(struct gtrace_platform_data *pdata);
};

/**
 * struct gtrace_platform_data - Platform-level data for a trace component
 * discovered from DT or ACPI.
 * @dev:         Parent device.
 * @impid:       Opaque, architecture-specific implementation ID.
 * @hw_ops:      Architecture-specific low level control ops.
 * @io_mem:      Flag showing whether component registers are memory mapped.
 * @base:        If io_mem == true then base address of the mapped registers.
 * @read:        If io_mem == false then read register from the given offset.
 * @write:       If io_mem == false then write register to the given offset.
 * @bound_cpu:   CPU to which the component is bound, or -1 if unbound. For a
 *               source component bound to a CPU this must not be -1.
 * @control_poll_timeout_usecs: Delay in usecs when polling control bits.
 * @nr_inconns:  Number of input connections.
 * @inconns:     Array of pointers to input connections.
 * @nr_outconns: Number of output connections.
 * @outconns:    Array of pointers to output connections.
 */
struct gtrace_platform_data {
	struct device *dev;

	u32 impid;

	const struct gtrace_hw_ops *hw_ops;

	bool io_mem;
	union {
		void __iomem *base;
		struct {
			u32 (*read)(struct gtrace_platform_data *pdata,
				    u32 offset, bool relaxed);
			void (*write)(struct gtrace_platform_data *pdata,
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
	struct gtrace_connection **inconns;

	/*
	 * Platform driver must fully populate pointer array with individual
	 * array elements pointing to actual output connections. The src_comp
	 * of each output connection is automatically updated at the time of
	 * registering component.
	 */
	unsigned int nr_outconns;
	struct gtrace_connection **outconns;
};

static inline u32 gtrace_read32(struct gtrace_platform_data *pdata, u32 offset)
{
	if (likely(pdata->io_mem))
		return readl(pdata->base + offset);

	return pdata->read(pdata, offset, false);
}

static inline u32 gtrace_relaxed_read32(struct gtrace_platform_data *pdata, u32 offset)
{
	if (likely(pdata->io_mem))
		return readl_relaxed(pdata->base + offset);

	return pdata->read(pdata, offset, true);
}

static inline void gtrace_write32(struct gtrace_platform_data *pdata, u32 val, u32 offset)
{
	if (likely(pdata->io_mem))
		writel(val, pdata->base + offset);
	else
		pdata->write(pdata, val, offset, false);
}

static inline void gtrace_relaxed_write32(struct gtrace_platform_data *pdata,
					  u32 val, u32 offset)
{
	if (likely(pdata->io_mem))
		writel_relaxed(val, pdata->base + offset);
	else
		pdata->write(pdata, val, offset, true);
}

static inline bool gtrace_is_source(struct gtrace_platform_data *pdata)
{
	return !pdata->nr_inconns ? true : false;
}

static inline bool gtrace_is_sink(struct gtrace_platform_data *pdata)
{
	return !pdata->nr_outconns ? true : false;
}

/**
 * struct gtrace_component_id - Details to identify or match a trace component.
 * @type:    Component type from the global gtrace_component_type list.
 * @version: Architecture-specific version (opaque to the core).
 * @data:    Data pointer for driver use.
 */
struct gtrace_component_id {
	enum gtrace_component_type type;
	u32 version;
	void *data;
};

/**
 * struct gtrace_component - Representation of a trace component.
 * @pdata:    Pointer to underlying platform data.
 * @id:       Details to match the component.
 * @type_idx: Unique number based on component type.
 * @dev:      Device instance.
 * @ready:    Flag showing whether the driver was probed successfully.
 */
struct gtrace_component {
	struct gtrace_platform_data *pdata;
	struct gtrace_component_id id;
	u32 type_idx;
	struct device dev;
	bool ready;
};

#define to_gtrace_component(__dev)	container_of_const(__dev, struct gtrace_component, dev)

static inline void gtrace_get_component(struct gtrace_component *comp)
{
	get_device(&comp->dev);
}

static inline void gtrace_put_component(struct gtrace_component *comp)
{
	put_device(&comp->dev);
}

const struct gtrace_component_id *gtrace_match_id(struct gtrace_component *comp,
						  const struct gtrace_component_id *ids);
struct gtrace_component *gtrace_find_by_fwnode(struct fwnode_handle *fwnode);

int gtrace_poll_bit(struct gtrace_platform_data *pdata, int offset,
		    int bit, int bitval, int timeout);
int gtrace_enable_component(struct gtrace_component *comp);
int gtrace_disable_component(struct gtrace_component *comp);
int gtrace_reset_component(struct gtrace_component *comp);

int gtrace_walk_output_components(struct gtrace_component *comp, void *priv,
				  int (*fn)(struct gtrace_component *comp, bool *stop,
					    struct gtrace_connection *stop_conn,
					    void *priv));
struct gtrace_component *gtrace_cpu_source(unsigned int cpu);

struct gtrace_component *gtrace_register_component(struct gtrace_component_id *id,
						   const char *name,
						   struct gtrace_platform_data *pdata);
void gtrace_unregister_component(struct gtrace_component *comp);

/**
 * struct gtrace_path - Representation of a trace path from source to sink.
 * @comp_list: List of trace components in the path.
 * @mode:      Usage mode for trace components.
 * @trace_id:  ID of the trace source (typically hart/CPU id).
 */
struct gtrace_path {
	struct list_head		comp_list;
	enum gtrace_component_mode	mode;
	u32				trace_id;
#define GTRACE_INVALID_TRACE_ID	0
};

struct gtrace_component *gtrace_path_source(struct gtrace_path *path);
struct gtrace_component *gtrace_path_sink(struct gtrace_path *path);
struct gtrace_path *gtrace_create_path(struct gtrace_component *source,
				       struct gtrace_component *sink,
				       enum gtrace_component_mode mode);
void gtrace_destroy_path(struct gtrace_path *path);
int gtrace_path_start(struct gtrace_path *path);
int gtrace_path_stop(struct gtrace_path *path);

/**
 * struct gtrace_driver - Representation of a trace driver.
 * @id_table:      Table to match components handled by the driver.
 * @start:         Callback to start tracing.
 * @stop:          Callback to stop tracing.
 * @probe:         Driver probe() function.
 * @remove:        Driver remove() function.
 * @get_trace_id:  Get/allocate a trace ID.
 * @put_trace_id:  Put/free a trace ID.
 * @driver:        Device driver instance.
 */
struct gtrace_driver {
	const struct gtrace_component_id *id_table;
	int			(*start)(struct gtrace_component *comp);
	int			(*stop)(struct gtrace_component *comp);
	int			(*probe)(struct gtrace_component *comp);
	void			(*remove)(struct gtrace_component *comp);
	int			(*get_trace_id)(struct gtrace_component *comp,
						enum gtrace_component_mode mode);
	void			(*put_trace_id)(struct gtrace_component *comp,
						enum gtrace_component_mode mode,
						u32 trace_id);
	struct device_driver	driver;
};

#define to_gtrace_driver(__drv)   \
	((__drv) ? container_of_const((__drv), struct gtrace_driver, driver) : NULL)

int __gtrace_register_driver(struct module *owner, struct gtrace_driver *gtdrv);
#define gtrace_register_driver(driver) __gtrace_register_driver(THIS_MODULE, driver)
static inline void gtrace_unregister_driver(struct gtrace_driver *gtdrv)
{
	if (gtdrv)
		driver_unregister(&gtdrv->driver);
}

#endif /* __LINUX_GTRACE_H__ */
