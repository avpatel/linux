// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2025 Ventana Micro Systems Inc.
 */

#include <linux/cpumask.h>
#include <linux/delay.h>
#include <linux/export.h>
#include <linux/idr.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/percpu.h>
#include <linux/rvtrace.h>

/* Mutex to serialize component registration/unregistration */
static DEFINE_MUTEX(rvtrace_mutex);

/* Per-CPU encoder instances */
static DEFINE_PER_CPU(struct rvtrace_component *, rvtrace_cpu_encoder);

/* Component type based id generator */
struct rvtrace_type_idx {
	/* Lock to protect the type ID generator */
	struct mutex lock;
	struct idr idr;
};

/* Array of component type based id generator */
static struct rvtrace_type_idx rvtrace_type_idx_array[RVTRACE_COMPONENT_TYPE_MAX];

static int rvtrace_alloc_type_idx(struct rvtrace_component *comp)
{
	struct rvtrace_type_idx *rvidx = &rvtrace_type_idx_array[comp->id.type];
	int idx;

	mutex_lock(&rvidx->lock);
	idx = idr_alloc(&rvidx->idr, comp, 0, 0, GFP_KERNEL);
	mutex_unlock(&rvidx->lock);
	if (idx < 0)
		return idx;

	comp->type_idx = idx;
	return 0;
}

static void rvtrace_free_type_idx(struct rvtrace_component *comp)
{
	struct rvtrace_type_idx *rvidx = &rvtrace_type_idx_array[comp->id.type];

	mutex_lock(&rvidx->lock);
	idr_remove(&rvidx->idr, comp->type_idx);
	mutex_unlock(&rvidx->lock);
}

static void __init rvtrace_init_type_idx(void)
{
	struct rvtrace_type_idx *rvidx;
	int i;

	for (i = 0; i < RVTRACE_COMPONENT_TYPE_MAX; i++) {
		rvidx = &rvtrace_type_idx_array[i];
		mutex_init(&rvidx->lock);
		idr_init(&rvidx->idr);
	}
}

const struct rvtrace_component_id *rvtrace_match_id(struct rvtrace_component *comp,
						    const struct rvtrace_component_id *ids)
{
	u32 comp_maj, comp_min, id_maj, id_min;
	const struct rvtrace_component_id *id;

	for (id = ids; id->version && id->type; id++) {
		if (comp->id.type != id->type)
			return NULL;

		id_maj = rvtrace_component_version_major(id->version);
		id_min = rvtrace_component_version_minor(id->version);
		comp_maj = rvtrace_component_version_major(comp->id.version);
		comp_min = rvtrace_component_version_minor(comp->id.version);
		if (comp_maj > id_maj)
			continue;

		/* Refer to Ch. 5 'Versioning of components of the Trace Control spec. */
		if (comp_maj < id_maj)
			dev_warn(&comp->dev, "Older component with major version %d\n", comp_maj);
		if (comp_min == 15)
			dev_warn(&comp->dev, "Experimental component\n");
		else if (comp_min > id_min)
			dev_warn(&comp->dev, "Newer component with minor version %d\n", comp_min);

		return id;
	}

	return NULL;
}
EXPORT_SYMBOL_GPL(rvtrace_match_id);

static int rvtrace_match_device(struct device *dev, const struct device_driver *drv)
{
	const struct rvtrace_driver *rtdrv = to_rvtrace_driver(drv);
	struct rvtrace_component *comp = to_rvtrace_component(dev);

	return rvtrace_match_id(comp, rtdrv->id_table) ? 1 : 0;
}

static int rvtrace_probe(struct device *dev)
{
	const struct rvtrace_driver *rtdrv = to_rvtrace_driver(dev->driver);
	struct rvtrace_component *comp = to_rvtrace_component(dev);
	int ret = -ENODEV;

	if (!rtdrv->probe)
		return ret;

	ret = rtdrv->probe(comp);
	if (!ret)
		comp->ready = true;

	return ret;
}

static void rvtrace_remove(struct device *dev)
{
	const struct rvtrace_driver *rtdrv = to_rvtrace_driver(dev->driver);
	struct rvtrace_component *comp = to_rvtrace_component(dev);

	comp->ready = false;
	if (rtdrv->remove)
		rtdrv->remove(comp);
}

const struct bus_type rvtrace_bustype = {
	.name	= "rvtrace",
	.match	= rvtrace_match_device,
	.probe	= rvtrace_probe,
	.remove	= rvtrace_remove,
};

struct rvtrace_fwnode_match_data {
	struct fwnode_handle *fwnode;
	struct rvtrace_component *match;
};

static int rvtrace_match_fwnode(struct device *dev, void *data)
{
	struct rvtrace_component *comp = to_rvtrace_component(dev);
	struct rvtrace_fwnode_match_data *d = data;

	if (device_match_fwnode(&comp->dev, d->fwnode)) {
		d->match = comp;
		return 1;
	}

	return 0;
}

struct rvtrace_component *rvtrace_find_by_fwnode(struct fwnode_handle *fwnode)
{
	struct rvtrace_fwnode_match_data d = { .fwnode = fwnode, .match = NULL };
	int ret;

	ret = bus_for_each_dev(&rvtrace_bustype, NULL, &d, rvtrace_match_fwnode);
	if (ret < 0)
		return ERR_PTR(ret);

	return d.match;
}
EXPORT_SYMBOL_GPL(rvtrace_find_by_fwnode);

int rvtrace_poll_bit(struct rvtrace_platform_data *pdata, int offset,
		     int bit, int bitval, int timeout)
{
	int i = 10;
	u32 val;

	while (i--) {
		val = rvtrace_read32(pdata, offset);
		if (((val >> bit) & 0x1) == bitval)
			break;
		udelay(timeout);
	}

	return (i < 0) ? -ETIMEDOUT : 0;
}
EXPORT_SYMBOL_GPL(rvtrace_poll_bit);

int rvtrace_enable_component(struct rvtrace_component *comp)
{
	u32 val;

	val = rvtrace_read32(comp->pdata, RVTRACE_COMPONENT_CTRL_OFFSET);
	val |= BIT(RVTRACE_COMPONENT_CTRL_ENABLE_SHIFT);
	rvtrace_write32(comp->pdata, val, RVTRACE_COMPONENT_CTRL_OFFSET);
	return rvtrace_poll_bit(comp->pdata, RVTRACE_COMPONENT_CTRL_OFFSET,
				RVTRACE_COMPONENT_CTRL_ENABLE_SHIFT, 1,
				comp->pdata->control_poll_timeout_usecs);
}
EXPORT_SYMBOL_GPL(rvtrace_enable_component);

int rvtrace_disable_component(struct rvtrace_component *comp)
{
	u32 val;

	val = rvtrace_read32(comp->pdata, RVTRACE_COMPONENT_CTRL_OFFSET);
	val &= ~BIT(RVTRACE_COMPONENT_CTRL_ENABLE_SHIFT);
	rvtrace_write32(comp->pdata, val, RVTRACE_COMPONENT_CTRL_OFFSET);
	return rvtrace_poll_bit(comp->pdata, RVTRACE_COMPONENT_CTRL_OFFSET,
				RVTRACE_COMPONENT_CTRL_ENABLE_SHIFT, 0,
				comp->pdata->control_poll_timeout_usecs);
}
EXPORT_SYMBOL_GPL(rvtrace_disable_component);

struct rvtrace_component *rvtrace_cpu_source(unsigned int cpu)
{
	if (!cpu_present(cpu))
		return NULL;

	return per_cpu(rvtrace_cpu_encoder, cpu);
}
EXPORT_SYMBOL_GPL(rvtrace_cpu_source);

static int rvtrace_cleanup_inconn(struct device *dev, void *data)
{
	struct rvtrace_component *comp = to_rvtrace_component(dev);
	struct rvtrace_platform_data *pdata = comp->pdata;
	struct rvtrace_connection *conn = data;
	int i;

	if (device_match_fwnode(&comp->dev, conn->dest_fwnode)) {
		for (i = 0; i < pdata->nr_inconns; i++) {
			if (pdata->inconns[i] != conn)
				continue;
			pdata->inconns[i] = NULL;
			return 1;
		}
	}

	return 0;
}

static void rvtrace_cleanup_inconns_from_outconns(struct rvtrace_component *comp)
{
	struct rvtrace_platform_data *pdata = comp->pdata;
	struct rvtrace_connection *conn;
	int i;

	lockdep_assert_held(&rvtrace_mutex);

	for (i = 0; i < pdata->nr_outconns; i++) {
		conn = pdata->outconns[i];
		bus_for_each_dev(&rvtrace_bustype, NULL, conn, rvtrace_cleanup_inconn);
	}
}

static int rvtrace_setup_inconn(struct device *dev, void *data)
{
	struct rvtrace_component *comp = to_rvtrace_component(dev);
	struct rvtrace_platform_data *pdata = comp->pdata;
	struct rvtrace_connection *conn = data;
	int i;

	if (device_match_fwnode(&comp->dev, conn->dest_fwnode)) {
		for (i = 0; i < pdata->nr_inconns; i++) {
			if (pdata->inconns[i])
				continue;
			pdata->inconns[i] = conn;
			return 1;
		}
	}

	return 0;
}

static int rvtrace_setup_inconns_from_outconns(struct rvtrace_component *comp)
{
	struct rvtrace_platform_data *pdata = comp->pdata;
	struct rvtrace_connection *conn;
	int i, ret;

	lockdep_assert_held(&rvtrace_mutex);

	for (i = 0; i < pdata->nr_outconns; i++) {
		conn = pdata->outconns[i];
		ret = bus_for_each_dev(&rvtrace_bustype, NULL, conn, rvtrace_setup_inconn);
		if (ret < 0) {
			rvtrace_cleanup_inconns_from_outconns(comp);
			return ret;
		}
	}

	return 0;
}

static void rvtrace_component_release(struct device *dev)
{
	struct rvtrace_component *comp = to_rvtrace_component(dev);

	fwnode_handle_put(comp->dev.fwnode);
	rvtrace_free_type_idx(comp);
	kfree(comp);
}

static int rvtrace_component_reset(struct rvtrace_platform_data *pdata)
{
	int ret;

	rvtrace_write32(pdata, 0, RVTRACE_COMPONENT_CTRL_OFFSET);
	ret = rvtrace_poll_bit(pdata, RVTRACE_COMPONENT_CTRL_OFFSET,
			       RVTRACE_COMPONENT_CTRL_ACTIVE_SHIFT, 0,
			       pdata->control_poll_timeout_usecs);
	if (ret)
		return ret;

	rvtrace_write32(pdata, RVTRACE_COMPONENT_CTRL_ACTIVE_MASK,
			RVTRACE_COMPONENT_CTRL_OFFSET);
	return rvtrace_poll_bit(pdata, RVTRACE_COMPONENT_CTRL_OFFSET,
				RVTRACE_COMPONENT_CTRL_ACTIVE_SHIFT, 1,
				pdata->control_poll_timeout_usecs);
}

struct rvtrace_component *rvtrace_register_component(struct rvtrace_platform_data *pdata)
{
	struct rvtrace_connection *conn;
	struct rvtrace_component *comp;
	u32 impl, type, major, minor;
	int i, ret = 0;

	if (!pdata || !pdata->dev) {
		ret = -EINVAL;
		goto err_out;
	}

	for (i = 0; i < pdata->nr_inconns; i++) {
		if (pdata->inconns[i]) {
			ret = -EINVAL;
			goto err_out;
		}
	}

	for (i = 0; i < pdata->nr_outconns; i++) {
		conn = pdata->outconns[i];
		if (!conn || conn->src_port < 0 || conn->src_comp ||
		    !device_match_fwnode(pdata->dev, conn->src_fwnode) ||
		    conn->dest_port < 0 || !conn->dest_fwnode || !conn->dest_comp) {
			ret = -EINVAL;
			goto err_out;
		}
	}

	ret = rvtrace_component_reset(pdata);
	if (ret)
		goto err_out;

	impl = rvtrace_read32(pdata, RVTRACE_COMPONENT_IMPL_OFFSET);
	type = (impl >> RVTRACE_COMPONENT_IMPL_TYPE_SHIFT) &
		RVTRACE_COMPONENT_IMPL_TYPE_MASK;
	major = (impl >> RVTRACE_COMPONENT_IMPL_VERMAJOR_SHIFT) &
		RVTRACE_COMPONENT_IMPL_VERMAJOR_MASK;
	minor = (impl >> RVTRACE_COMPONENT_IMPL_VERMINOR_SHIFT) &
		RVTRACE_COMPONENT_IMPL_VERMINOR_MASK;

	if (pdata->bound_cpu >= 0 && !cpu_present(pdata->bound_cpu)) {
		ret = -EINVAL;
		goto err_out;
	}
	if (type == RVTRACE_COMPONENT_TYPE_ENCODER && pdata->bound_cpu < 0) {
		ret = -EINVAL;
		goto err_out;
	}

	comp = kzalloc(sizeof(*comp), GFP_KERNEL);
	if (!comp) {
		ret = -ENOMEM;
		goto err_out;
	}
	comp->pdata = pdata;
	comp->id.type = type;
	comp->id.version = rvtrace_component_mkversion(major, minor);
	ret = rvtrace_alloc_type_idx(comp);
	if (ret) {
		kfree(comp);
		goto err_out;
	}

	comp->dev.parent = pdata->dev;
	comp->dev.coherent_dma_mask = pdata->dev->coherent_dma_mask;
	comp->dev.release = rvtrace_component_release;
	comp->dev.bus = &rvtrace_bustype;
	comp->dev.fwnode = fwnode_handle_get(dev_fwnode(pdata->dev));
	switch (comp->id.type) {
	case RVTRACE_COMPONENT_TYPE_ENCODER:
		dev_set_name(&comp->dev, "encoder-%d", comp->type_idx);
		break;
	case RVTRACE_COMPONENT_TYPE_FUNNEL:
		dev_set_name(&comp->dev, "funnel-%d", comp->type_idx);
		break;
	case RVTRACE_COMPONENT_TYPE_RAMSINK:
		dev_set_name(&comp->dev, "ramsink-%d", comp->type_idx);
		break;
	case RVTRACE_COMPONENT_TYPE_PIBSINK:
		dev_set_name(&comp->dev, "pibsink-%d", comp->type_idx);
		break;
	case RVTRACE_COMPONENT_TYPE_ATBBRIDGE:
		dev_set_name(&comp->dev, "atbbridge-%d", comp->type_idx);
		break;
	default:
		dev_set_name(&comp->dev, "type%d-%d", comp->id.type, comp->type_idx);
		break;
	}

	mutex_lock(&rvtrace_mutex);

	ret = device_register(&comp->dev);
	if (ret) {
		put_device(&comp->dev);
		goto err_out_unlock;
	}

	for (i = 0; i < pdata->nr_outconns; i++) {
		conn = pdata->outconns[i];
		conn->src_comp = comp;
	}

	ret = rvtrace_setup_inconns_from_outconns(comp);
	if (ret < 0) {
		device_unregister(&comp->dev);
		goto err_out_unlock;
	}

	if (comp->id.type == RVTRACE_COMPONENT_TYPE_ENCODER) {
		rvtrace_get_component(comp);
		per_cpu(rvtrace_cpu_encoder, comp->pdata->bound_cpu) = comp;
	}

	mutex_unlock(&rvtrace_mutex);

	return comp;

err_out_unlock:
	mutex_unlock(&rvtrace_mutex);
err_out:
	return ERR_PTR(ret);
}
EXPORT_SYMBOL_GPL(rvtrace_register_component);

void rvtrace_unregister_component(struct rvtrace_component *comp)
{
	struct rvtrace_component *c;

	mutex_lock(&rvtrace_mutex);

	if (comp->id.type == RVTRACE_COMPONENT_TYPE_ENCODER) {
		c = per_cpu(rvtrace_cpu_encoder, comp->pdata->bound_cpu);
		per_cpu(rvtrace_cpu_encoder, comp->pdata->bound_cpu) = NULL;
		rvtrace_put_component(c);
	}

	rvtrace_cleanup_inconns_from_outconns(comp);
	device_unregister(&comp->dev);

	mutex_unlock(&rvtrace_mutex);
}
EXPORT_SYMBOL_GPL(rvtrace_unregister_component);

int __rvtrace_register_driver(struct module *owner, struct rvtrace_driver *rtdrv)
{
	rtdrv->driver.owner = owner;
	rtdrv->driver.bus = &rvtrace_bustype;

	return driver_register(&rtdrv->driver);
}
EXPORT_SYMBOL_GPL(__rvtrace_register_driver);

static int __init rvtrace_init(void)
{
	int ret;

	rvtrace_init_type_idx();

	ret = bus_register(&rvtrace_bustype);
	if (ret)
		return ret;

	ret = platform_driver_register(&rvtrace_platform_driver);
	if (ret) {
		bus_unregister(&rvtrace_bustype);
		return ret;
	}

	return 0;
}

static void __exit rvtrace_exit(void)
{
	platform_driver_unregister(&rvtrace_platform_driver);
	bus_unregister(&rvtrace_bustype);
}

module_init(rvtrace_init);
module_exit(rvtrace_exit);
