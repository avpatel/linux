// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Qualcomm Technologies, Inc.
 */

#include <linux/device.h>
#include <linux/gtrace.h>
#include <linux/io.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/property.h>
#include <linux/types.h>
#include "rvtrace.h"

static int rvtrace_hw_enable(struct gtrace_platform_data *pdata)
{
	u32 val;

	val = gtrace_read32(pdata, RVTRACE_COMPONENT_CTRL_OFFSET);
	val |= BIT(RVTRACE_COMPONENT_CTRL_ENABLE_SHIFT);
	gtrace_write32(pdata, val, RVTRACE_COMPONENT_CTRL_OFFSET);
	return gtrace_poll_bit(pdata, RVTRACE_COMPONENT_CTRL_OFFSET,
			       RVTRACE_COMPONENT_CTRL_ENABLE_SHIFT, 1,
			       pdata->control_poll_timeout_usecs);
}

static int rvtrace_hw_disable(struct gtrace_platform_data *pdata)
{
	u32 val;

	val = gtrace_read32(pdata, RVTRACE_COMPONENT_CTRL_OFFSET);
	val &= ~BIT(RVTRACE_COMPONENT_CTRL_ENABLE_SHIFT);
	gtrace_write32(pdata, val, RVTRACE_COMPONENT_CTRL_OFFSET);
	return gtrace_poll_bit(pdata, RVTRACE_COMPONENT_CTRL_OFFSET,
			       RVTRACE_COMPONENT_CTRL_ENABLE_SHIFT, 0,
			       pdata->control_poll_timeout_usecs);
}

static int rvtrace_hw_reset(struct gtrace_platform_data *pdata)
{
	int ret;

	gtrace_write32(pdata, 0, RVTRACE_COMPONENT_CTRL_OFFSET);
	ret = gtrace_poll_bit(pdata, RVTRACE_COMPONENT_CTRL_OFFSET,
			      RVTRACE_COMPONENT_CTRL_ACTIVE_SHIFT, 0,
			      pdata->control_poll_timeout_usecs);
	if (ret)
		return ret;

	gtrace_write32(pdata, RVTRACE_COMPONENT_CTRL_ACTIVE_MASK,
		       RVTRACE_COMPONENT_CTRL_OFFSET);
	return gtrace_poll_bit(pdata, RVTRACE_COMPONENT_CTRL_OFFSET,
			       RVTRACE_COMPONENT_CTRL_ACTIVE_SHIFT, 1,
			       pdata->control_poll_timeout_usecs);
}

const struct gtrace_hw_ops rvtrace_hw_ops = {
	.enable		= rvtrace_hw_enable,
	.disable	= rvtrace_hw_disable,
	.reset		= rvtrace_hw_reset,
};

static int rvtrace_platform_probe(struct platform_device *pdev)
{
	struct gtrace_platform_data *pdata;
	struct device *dev = &pdev->dev;
	struct gtrace_component_id id;
	struct gtrace_component *comp;
	u32 impl, type, major, minor;
	struct device_node *node;
	struct resource *res;
	int gtype;
	int ret;

	pdata = devm_kzalloc(dev, sizeof(*pdata), GFP_KERNEL);
	if (!pdata)
		return -ENOMEM;
	pdata->dev = dev;
	pdata->impid = RVTRACE_COMPONENT_IMPID_UNKNOWN;
	pdata->hw_ops = &rvtrace_hw_ops;
	pdata->format = (uintptr_t)device_get_match_data(dev);

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res)
		return -EINVAL;

	pdata->io_mem = true;
	pdata->base = devm_ioremap(&pdev->dev, res->start, resource_size(res));
	if (!pdata->base)
		return dev_err_probe(dev, -ENOMEM, "failed to ioremap %pR\n", res);

	pdata->bound_cpu = -1;
	node = of_parse_phandle(dev_of_node(dev), "cpus", 0);
	if (node) {
		ret = of_cpu_node_to_id(node);
		of_node_put(node);
		if (ret < 0)
			return dev_err_probe(dev, ret, "failed to get CPU id for %pOF\n", node);
		pdata->bound_cpu = ret;
	}

	/* Default control poll timeout */
	pdata->control_poll_timeout_usecs = 10;

	ret = gtrace_of_parse_outconns(pdata);
	if (ret)
		return dev_err_probe(dev, ret, "failed to parse output connections\n");

	ret = gtrace_of_parse_inconns(pdata);
	if (ret)
		return dev_err_probe(dev, ret, "failed to parse input connections\n");

	/* Reset the component before it is registered with the gtrace core. */
	ret = rvtrace_hw_reset(pdata);
	if (ret)
		return dev_err_probe(dev, ret, "failed to reset component\n");

	impl = gtrace_read32(pdata, RVTRACE_COMPONENT_IMPL_OFFSET);
	type = (impl >> RVTRACE_COMPONENT_IMPL_TYPE_SHIFT) &
		RVTRACE_COMPONENT_IMPL_TYPE_MASK;
	major = (impl >> RVTRACE_COMPONENT_IMPL_VERMAJOR_SHIFT) &
		RVTRACE_COMPONENT_IMPL_VERMAJOR_MASK;
	minor = (impl >> RVTRACE_COMPONENT_IMPL_VERMINOR_SHIFT) &
		RVTRACE_COMPONENT_IMPL_VERMINOR_MASK;

	gtype = rvtrace_type_to_gtrace(type);
	if (gtype < 0)
		return dev_err_probe(dev, -ENODEV, "unsupported component type %u\n", type);

	id.type = gtype;
	id.version = rvtrace_component_mkversion(major, minor);

	comp = gtrace_register_component(&id, rvtrace_type_name(gtype), pdata);
	if (IS_ERR(comp))
		return PTR_ERR(comp);

	platform_set_drvdata(pdev, comp);
	return 0;
}

static void rvtrace_platform_remove(struct platform_device *pdev)
{
	struct gtrace_component *comp = platform_get_drvdata(pdev);
	struct gtrace_platform_data *pdata = comp->pdata;
	struct gtrace_connection *conn;
	int i;

	for (i = 0; i < pdata->nr_outconns; i++) {
		conn = pdata->outconns[i];
		if (conn && conn->dest_fwnode)
			fwnode_handle_put(conn->dest_fwnode);
	}

	gtrace_unregister_component(comp);
}

static const struct of_device_id rvtrace_platform_match[] = {
	{ .compatible = "riscv,trace-component", .data = (void *)GTRACE_FORMAT_ETRACE },
	{}
};

static struct platform_driver rvtrace_platform_driver = {
	.driver = {
		.name		= "rvtrace",
		.of_match_table	= rvtrace_platform_match,
	},
	.probe = rvtrace_platform_probe,
	.remove = rvtrace_platform_remove,
};

static int __init rvtrace_platform_init(void)
{
	return platform_driver_register(&rvtrace_platform_driver);
}

static void __exit rvtrace_platform_exit(void)
{
	platform_driver_unregister(&rvtrace_platform_driver);
}

module_init(rvtrace_platform_init);
module_exit(rvtrace_platform_exit);

MODULE_AUTHOR("Anup Patel");
MODULE_DESCRIPTION("RISC-V backend for the generic trace framework");
MODULE_LICENSE("GPL");
