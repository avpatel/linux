// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Qualcomm Technologies, Inc.
 *
 */

#include <linux/cpumask.h>
#include <linux/delay.h>
#include <linux/export.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/percpu.h>
#include <linux/xarray.h>
#include <linux/gtrace.h>

/* Mutex to serialize component registration/unregistration */
static DEFINE_MUTEX(gtrace_mutex);

/* Per-CPU source instances */
static DEFINE_PER_CPU(struct gtrace_component *, gtrace_cpu_source_comp);

/* Component type based id generator */
struct gtrace_type_idx {
	/* Lock to protect the type ID generator */
	struct mutex lock;
	struct xarray xa;
};

/* Array of component type based id generator */
static struct gtrace_type_idx gtrace_type_idx_array[GTRACE_COMPONENT_TYPE_MAX];

static int gtrace_alloc_type_idx(struct gtrace_component *comp)
{
	struct gtrace_type_idx *gidx;
	u32 idx;
	int ret;

	if (comp->id.type >= GTRACE_COMPONENT_TYPE_MAX)
		return -EINVAL;

	gidx = &gtrace_type_idx_array[comp->id.type];
	mutex_lock(&gidx->lock);
	ret = xa_alloc(&gidx->xa, &idx, comp, xa_limit_32b, GFP_KERNEL);
	mutex_unlock(&gidx->lock);
	if (ret)
		return ret;

	comp->type_idx = idx;
	return 0;
}

static void gtrace_free_type_idx(struct gtrace_component *comp)
{
	struct gtrace_type_idx *gidx;

	if (comp->id.type >= GTRACE_COMPONENT_TYPE_MAX)
		return;

	gidx = &gtrace_type_idx_array[comp->id.type];
	mutex_lock(&gidx->lock);
	xa_erase(&gidx->xa, comp->type_idx);
	mutex_unlock(&gidx->lock);
}

static void __init gtrace_init_type_idx(void)
{
	struct gtrace_type_idx *gidx;
	int i;

	for (i = 0; i < GTRACE_COMPONENT_TYPE_MAX; i++) {
		gidx = &gtrace_type_idx_array[i];
		mutex_init(&gidx->lock);
		xa_init_flags(&gidx->xa, XA_FLAGS_ALLOC);
	}
}

const struct gtrace_component_id *gtrace_match_id(struct gtrace_component *comp,
						  const struct gtrace_component_id *ids)
{
	const struct gtrace_component_id *id;

	for (id = ids; id->version; id++) {
		if (comp->id.type != id->type)
			continue;

		return id;
	}

	return NULL;
}
EXPORT_SYMBOL_GPL(gtrace_match_id);

static int gtrace_match_device(struct device *dev, const struct device_driver *drv)
{
	const struct gtrace_driver *gtdrv = to_gtrace_driver(drv);
	struct gtrace_component *comp = to_gtrace_component(dev);

	return gtrace_match_id(comp, gtdrv->id_table) ? 1 : 0;
}

static int gtrace_probe(struct device *dev)
{
	const struct gtrace_driver *gtdrv = to_gtrace_driver(dev->driver);
	struct gtrace_component *comp = to_gtrace_component(dev);
	int ret = 0;

	if (gtdrv->probe)
		ret = gtdrv->probe(comp);

	if (!ret)
		comp->ready = true;

	return ret;
}

static void gtrace_remove(struct device *dev)
{
	const struct gtrace_driver *gtdrv = to_gtrace_driver(dev->driver);
	struct gtrace_component *comp = to_gtrace_component(dev);

	comp->ready = false;
	if (gtdrv->remove)
		gtdrv->remove(comp);
}

static const struct bus_type gtrace_bustype = {
	.name	= "gtrace",
	.match	= gtrace_match_device,
	.probe	= gtrace_probe,
	.remove	= gtrace_remove,
};

struct gtrace_fwnode_match_data {
	struct fwnode_handle *fwnode;
	struct gtrace_component *match;
};

static int gtrace_match_fwnode(struct device *dev, void *data)
{
	struct gtrace_component *comp = to_gtrace_component(dev);
	struct gtrace_fwnode_match_data *d = data;

	if (device_match_fwnode(&comp->dev, d->fwnode)) {
		d->match = comp;
		return 1;
	}

	return 0;
}

struct gtrace_component *gtrace_find_by_fwnode(struct fwnode_handle *fwnode)
{
	struct gtrace_fwnode_match_data d = { .fwnode = fwnode, .match = NULL };
	int ret;

	ret = bus_for_each_dev(&gtrace_bustype, NULL, &d, gtrace_match_fwnode);
	if (ret < 0)
		return ERR_PTR(ret);

	return d.match;
}
EXPORT_SYMBOL_GPL(gtrace_find_by_fwnode);

int gtrace_poll_bit(struct gtrace_platform_data *pdata, int offset,
		    int bit, int bitval, int timeout)
{
	u32 val;

	while (timeout--) {
		val = gtrace_read32(pdata, offset);
		if (((val >> bit) & 0x1) == bitval)
			break;
		udelay(1);
	}

	return (timeout < 0) ? -ETIMEDOUT : 0;
}
EXPORT_SYMBOL_GPL(gtrace_poll_bit);

int gtrace_enable_component(struct gtrace_component *comp)
{
	const struct gtrace_hw_ops *ops = comp->pdata->hw_ops;

	if (!ops || !ops->enable)
		return -EOPNOTSUPP;

	return ops->enable(comp->pdata);
}
EXPORT_SYMBOL_GPL(gtrace_enable_component);

int gtrace_disable_component(struct gtrace_component *comp)
{
	const struct gtrace_hw_ops *ops = comp->pdata->hw_ops;

	if (!ops || !ops->disable)
		return -EOPNOTSUPP;

	return ops->disable(comp->pdata);
}
EXPORT_SYMBOL_GPL(gtrace_disable_component);

int gtrace_reset_component(struct gtrace_component *comp)
{
	const struct gtrace_hw_ops *ops = comp->pdata->hw_ops;

	if (!ops || !ops->reset)
		return -EOPNOTSUPP;

	return ops->reset(comp->pdata);
}
EXPORT_SYMBOL_GPL(gtrace_reset_component);

struct gtrace_component *gtrace_cpu_source(unsigned int cpu)
{
	if (!cpu_present(cpu))
		return NULL;

	return per_cpu(gtrace_cpu_source_comp, cpu);
}
EXPORT_SYMBOL_GPL(gtrace_cpu_source);

static int gtrace_cleanup_inconn(struct device *dev, void *data)
{
	struct gtrace_component *comp = to_gtrace_component(dev);
	struct gtrace_platform_data *pdata = comp->pdata;
	struct gtrace_connection *conn = data;
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

static void gtrace_cleanup_inconns_from_outconns(struct gtrace_component *comp)
{
	struct gtrace_platform_data *pdata = comp->pdata;
	struct gtrace_connection *conn;
	int i;

	lockdep_assert_held(&gtrace_mutex);

	for (i = 0; i < pdata->nr_outconns; i++) {
		conn = pdata->outconns[i];
		bus_for_each_dev(&gtrace_bustype, NULL, conn, gtrace_cleanup_inconn);
	}
}

static int gtrace_setup_inconn(struct device *dev, void *data)
{
	struct gtrace_component *comp = to_gtrace_component(dev);
	struct gtrace_platform_data *pdata = comp->pdata;
	struct gtrace_connection *conn = data;
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

static int gtrace_setup_inconns_from_outconns(struct gtrace_component *comp)
{
	struct gtrace_platform_data *pdata = comp->pdata;
	struct gtrace_connection *conn;
	int i, ret;

	lockdep_assert_held(&gtrace_mutex);

	for (i = 0; i < pdata->nr_outconns; i++) {
		conn = pdata->outconns[i];
		ret = bus_for_each_dev(&gtrace_bustype, NULL, conn, gtrace_setup_inconn);
		if (ret < 0) {
			gtrace_cleanup_inconns_from_outconns(comp);
			return ret;
		}
	}

	return 0;
}

static void gtrace_component_release(struct device *dev)
{
	struct gtrace_component *comp = to_gtrace_component(dev);

	fwnode_handle_put(comp->dev.fwnode);
	gtrace_free_type_idx(comp);
	kfree(comp);
}

struct gtrace_component *gtrace_register_component(struct gtrace_component_id *id,
						   const char *name,
						   struct gtrace_platform_data *pdata)
{
	struct gtrace_connection *conn;
	struct gtrace_component *comp;
	int i, ret = 0;

	if (!id || id->type >= GTRACE_COMPONENT_TYPE_MAX) {
		ret = -EINVAL;
		goto err_out;
	}

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

	if (pdata->bound_cpu >= 0 && !cpu_present(pdata->bound_cpu)) {
		ret = -EINVAL;
		goto err_out;
	}

	comp = kzalloc(sizeof(*comp), GFP_KERNEL);
	if (!comp) {
		ret = -ENOMEM;
		goto err_out;
	}
	comp->pdata = pdata;
	comp->id = *id;
	ret = gtrace_alloc_type_idx(comp);
	if (ret) {
		kfree(comp);
		goto err_out;
	}

	comp->dev.parent = pdata->dev;
	comp->dev.coherent_dma_mask = pdata->dev->coherent_dma_mask;
	comp->dev.release = gtrace_component_release;
	comp->dev.bus = &gtrace_bustype;
	comp->dev.fwnode = fwnode_handle_get(dev_fwnode(pdata->dev));
	dev_set_name(&comp->dev, "%s-%u", name ? name : "comp", comp->type_idx);

	mutex_lock(&gtrace_mutex);

	ret = device_register(&comp->dev);
	if (ret) {
		put_device(&comp->dev);
		goto err_out_unlock;
	}

	for (i = 0; i < pdata->nr_outconns; i++) {
		conn = pdata->outconns[i];
		conn->src_comp = comp;
	}

	ret = gtrace_setup_inconns_from_outconns(comp);
	if (ret < 0) {
		device_unregister(&comp->dev);
		goto err_out_unlock;
	}

	if (comp->pdata->bound_cpu >= 0) {
		gtrace_get_component(comp);
		per_cpu(gtrace_cpu_source_comp, comp->pdata->bound_cpu) = comp;
	}

	mutex_unlock(&gtrace_mutex);

	return comp;

err_out_unlock:
	mutex_unlock(&gtrace_mutex);
err_out:
	return ERR_PTR(ret);
}
EXPORT_SYMBOL_GPL(gtrace_register_component);

void gtrace_unregister_component(struct gtrace_component *comp)
{
	struct gtrace_component *c;

	mutex_lock(&gtrace_mutex);

	if (comp->pdata->bound_cpu >= 0) {
		c = per_cpu(gtrace_cpu_source_comp, comp->pdata->bound_cpu);
		per_cpu(gtrace_cpu_source_comp, comp->pdata->bound_cpu) = NULL;
		gtrace_put_component(c);
	}

	gtrace_cleanup_inconns_from_outconns(comp);
	device_unregister(&comp->dev);

	mutex_unlock(&gtrace_mutex);
}
EXPORT_SYMBOL_GPL(gtrace_unregister_component);

int __gtrace_register_driver(struct module *owner, struct gtrace_driver *gtdrv)
{
	gtdrv->driver.owner = owner;
	gtdrv->driver.bus = &gtrace_bustype;

	return driver_register(&gtdrv->driver);
}
EXPORT_SYMBOL_GPL(__gtrace_register_driver);

static int __init gtrace_init(void)
{
	gtrace_init_type_idx();

	return bus_register(&gtrace_bustype);
}

static void __exit gtrace_exit(void)
{
	bus_unregister(&gtrace_bustype);
}

subsys_initcall(gtrace_init);
module_exit(gtrace_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Generic hardware trace (gtrace) framework core");
