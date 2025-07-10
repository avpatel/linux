// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2025 Ventana Micro Systems Inc.
 */

#include <linux/device.h>
#include <linux/io.h>
#include <linux/of.h>
#include <linux/of_graph.h>
#include <linux/platform_device.h>
#include <linux/property.h>
#include <linux/rvtrace.h>
#include <linux/types.h>

static int rvtrace_of_parse_outconns(struct rvtrace_platform_data *pdata)
{
	struct device_node *parent, *ep_node, *rep_node, *rdev_node;
	struct rvtrace_connection *conn;
	struct of_endpoint ep, rep;
	int ret = 0, i = 0;

	parent = of_get_child_by_name(dev_of_node(pdata->dev), "out-ports");
	if (!parent)
		return 0;

	pdata->nr_outconns = of_graph_get_endpoint_count(parent);
	pdata->outconns = devm_kcalloc(pdata->dev, pdata->nr_outconns,
				       sizeof(*pdata->outconns), GFP_KERNEL);
	if (!pdata->outconns) {
		ret = -ENOMEM;
		goto done;
	}

	for_each_endpoint_of_node(parent, ep_node) {
		conn = devm_kzalloc(pdata->dev, sizeof(*conn), GFP_KERNEL);
		if (!conn) {
			of_node_put(ep_node);
			ret = -ENOMEM;
			break;
		}

		ret = of_graph_parse_endpoint(ep_node, &ep);
		if (ret) {
			of_node_put(ep_node);
			break;
		}

		rep_node = of_graph_get_remote_endpoint(ep_node);
		if (!rep_node) {
			ret = -ENODEV;
			of_node_put(ep_node);
			break;
		}
		rdev_node = of_graph_get_port_parent(rep_node);

		ret = of_graph_parse_endpoint(rep_node, &rep);
		if (ret) {
			of_node_put(ep_node);
			break;
		}

		conn->src_port = ep.port;
		conn->src_fwnode = dev_fwnode(pdata->dev);
		/* The 'src_comp' is set by rvtrace_register_component() */
		conn->src_comp = NULL;
		conn->dest_port = rep.port;
		conn->dest_fwnode = of_fwnode_handle(rdev_node);
		fwnode_handle_get(conn->dest_fwnode);
		conn->dest_comp = rvtrace_find_by_fwnode(conn->dest_fwnode);
		if (!conn->dest_comp) {
			ret = -EPROBE_DEFER;
			of_node_put(ep_node);
			break;
		}

		pdata->outconns[i] = conn;
		i++;
	}

done:
	if (ret) {
		for (i = 0; i < pdata->nr_outconns && pdata->outconns; i++) {
			conn = pdata->outconns[i];
			if (conn && conn->dest_fwnode)
				fwnode_handle_put(conn->dest_fwnode);
		}
	}
	of_node_put(parent);
	return ret;
}

static int rvtrace_of_parse_inconns(struct rvtrace_platform_data *pdata)
{
	struct device_node *parent;
	int ret = 0;

	parent = of_get_child_by_name(dev_of_node(pdata->dev), "in-ports");
	if (!parent)
		return 0;

	pdata->nr_inconns = of_graph_get_endpoint_count(parent);
	pdata->inconns = devm_kcalloc(pdata->dev, pdata->nr_inconns,
				      sizeof(*pdata->inconns), GFP_KERNEL);
	if (!pdata->inconns)
		ret = -ENOMEM;

	of_node_put(parent);
	return ret;
}

static int rvtrace_platform_probe(struct platform_device *pdev)
{
	struct rvtrace_platform_data *pdata;
	struct device *dev = &pdev->dev;
	struct rvtrace_component *comp;
	struct device_node *node;
	struct resource *res;
	int ret;

	pdata = devm_kzalloc(dev, sizeof(*pdata), GFP_KERNEL);
	if (!pdata)
		return -ENOMEM;
	pdata->dev = dev;
	pdata->impid = RVTRACE_COMPONENT_IMPID_UNKNOWN;

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

	ret = rvtrace_of_parse_outconns(pdata);
	if (ret)
		return dev_err_probe(dev, ret, "failed to parse output connections\n");

	ret = rvtrace_of_parse_inconns(pdata);
	if (ret)
		return dev_err_probe(dev, ret, "failed to parse input connections\n");

	comp = rvtrace_register_component(pdata);
	if (IS_ERR(comp))
		return PTR_ERR(comp);

	platform_set_drvdata(pdev, comp);
	return 0;
}

static void rvtrace_platform_remove(struct platform_device *pdev)
{
	struct rvtrace_component *comp = platform_get_drvdata(pdev);
	struct rvtrace_platform_data *pdata = comp->pdata;
	struct rvtrace_connection *conn;
	int i;

	for (i = 0; i < pdata->nr_outconns; i++) {
		conn = pdata->outconns[i];
		if (conn && conn->dest_fwnode)
			fwnode_handle_put(conn->dest_fwnode);
	}

	rvtrace_unregister_component(comp);
}

static const struct of_device_id rvtrace_platform_match[] = {
	{ .compatible = "riscv,trace-component" },
	{}
};

struct platform_driver rvtrace_platform_driver = {
	.driver = {
		.name		= "rvtrace",
		.of_match_table	= rvtrace_platform_match,
	},
	.probe = rvtrace_platform_probe,
	.remove = rvtrace_platform_remove,
};
