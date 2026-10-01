// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Qualcomm Technologies, Inc.
 */

#include <linux/device.h>
#include <linux/export.h>
#include <linux/gtrace.h>
#include <linux/of.h>
#include <linux/of_graph.h>
#include <linux/property.h>

/*
 * Parse the "out-ports" graph of the component's device tree node and fill
 * pdata->outconns.
 * Return: 0 on success or when there are no output ports
 *         -EPROBE_DEFER if a destination is not registered yet
 *         negative error code otherwise.
 */
int gtrace_of_parse_outconns(struct gtrace_platform_data *pdata)
{
	struct device_node *parent, *ep_node, *rep_node, *rdev_node;
	struct gtrace_connection *conn;
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
			of_node_put(rep_node);
			of_node_put(rdev_node);
			break;
		}

		conn->src_port = ep.port;
		conn->src_fwnode = dev_fwnode(pdata->dev);
		/* The 'src_comp' is set by gtrace_register_component() */
		conn->src_comp = NULL;
		conn->dest_port = rep.port;
		conn->dest_fwnode = of_fwnode_handle(rdev_node);
		fwnode_handle_get(conn->dest_fwnode);
		conn->dest_comp = gtrace_find_by_fwnode(conn->dest_fwnode);
		if (!conn->dest_comp) {
			ret = -EPROBE_DEFER;
			of_node_put(ep_node);
			of_node_put(rep_node);
			of_node_put(rdev_node);
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
EXPORT_SYMBOL_GPL(gtrace_of_parse_outconns);

/*
 * Parse the "out-ports" graph of the component's device tree node and allocate
 * pdata->inconns.
 *
 * Return: 0 on success or when there are no input ports, -ENOMEM otherwise.
 */
int gtrace_of_parse_inconns(struct gtrace_platform_data *pdata)
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
EXPORT_SYMBOL_GPL(gtrace_of_parse_inconns);
