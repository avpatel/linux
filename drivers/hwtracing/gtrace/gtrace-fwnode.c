// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Qualcomm Technologies, Inc.
 */

#include <linux/device.h>
#include <linux/export.h>
#include <linux/gtrace.h>
#include <linux/of.h>
#include <linux/property.h>

/*
 * Parse the "out-ports" graph of the component's node and fill
 * pdata->outconns.
 * Return: 0 on success or when there are no output ports
 *         -EPROBE_DEFER if a destination is not registered yet
 *         negative error code otherwise.
 */
int gtrace_parse_outconns(struct gtrace_platform_data *pdata)
{
	struct fwnode_handle *parent, *ep_node, *rep_node, *rdev_node;
	struct fwnode_endpoint ep = { 0 };
	struct fwnode_endpoint rep = { 0 };
	struct gtrace_connection *conn;
	unsigned int nr_outconns;
	int ret = 0, i = 0;

	parent = fwnode_get_named_child_node(dev_fwnode(pdata->dev), "out-ports");
	if (!parent)
		return 0;

	nr_outconns = fwnode_graph_get_endpoint_count(parent, 0);
	pdata->nr_outconns = nr_outconns;
	pdata->outconns = devm_kcalloc(pdata->dev, nr_outconns,
				       sizeof(*pdata->outconns), GFP_KERNEL);
	if (!pdata->outconns) {
		ret = -ENOMEM;
		goto done;
	}

	fwnode_graph_for_each_endpoint(parent, ep_node) {
		conn = devm_kzalloc(pdata->dev, sizeof(*conn), GFP_KERNEL);
		if (!conn) {
			fwnode_handle_put(ep_node);
			ret = -ENOMEM;
			break;
		}

		ret = fwnode_graph_parse_endpoint(ep_node, &ep);
		if (ret) {
			fwnode_handle_put(ep_node);
			break;
		}

		rep_node = fwnode_graph_get_remote_endpoint(ep_node);
		if (!rep_node) {
			ret = -ENODEV;
			fwnode_handle_put(ep_node);
			break;
		}
		rdev_node = fwnode_graph_get_port_parent(rep_node);
		if (!rdev_node) {
			ret = -ENODEV;
			fwnode_handle_put(ep_node);
			fwnode_handle_put(rep_node);
			break;
		}

		ret = fwnode_graph_parse_endpoint(rep_node, &rep);
		if (ret) {
			fwnode_handle_put(ep_node);
			fwnode_handle_put(rep_node);
			fwnode_handle_put(rdev_node);
			break;
		}

		conn->src_port = ep.port;
		conn->src_fwnode = dev_fwnode(pdata->dev);
		/* The 'src_comp' is set by gtrace_register_component() */
		conn->src_comp = NULL;
		conn->dest_port = rep.port;
		conn->dest_fwnode = rdev_node;
		fwnode_handle_get(conn->dest_fwnode);
		conn->dest_comp = gtrace_find_by_fwnode(conn->dest_fwnode);
		if (!conn->dest_comp) {
			ret = -EPROBE_DEFER;
			fwnode_handle_put(ep_node);
			fwnode_handle_put(rep_node);
			fwnode_handle_put(rdev_node);
			break;
		}

		pdata->outconns[i++] = conn;
		fwnode_handle_put(rep_node);
		fwnode_handle_put(rdev_node);
	}

	if (!ret)
		pdata->nr_outconns = i;

done:
	if (ret) {
		for (i = 0; i < pdata->nr_outconns && pdata->outconns; i++) {
			conn = pdata->outconns[i];
			if (conn && conn->dest_fwnode)
				fwnode_handle_put(conn->dest_fwnode);
		}
	}

	fwnode_handle_put(parent);
	return ret;
}
EXPORT_SYMBOL_GPL(gtrace_parse_outconns);

/*
 * Parse the "out-ports" graph of the component's device tree node and allocate
 * pdata->inconns.
 *
 * Return: 0 on success or when there are no input ports, -ENOMEM otherwise.
 */
int gtrace_parse_inconns(struct gtrace_platform_data *pdata)
{
	struct fwnode_handle *parent;
	int ret = 0;

	parent = fwnode_get_named_child_node(dev_fwnode(pdata->dev), "in-ports");
	if (!parent)
		return 0;

	pdata->nr_inconns = fwnode_graph_get_endpoint_count(parent,
							    FWNODE_GRAPH_DEVICE_DISABLED);
	pdata->inconns = devm_kcalloc(pdata->dev, pdata->nr_inconns,
				      sizeof(*pdata->inconns), GFP_KERNEL);
	if (!pdata->inconns)
		ret = -ENOMEM;

	fwnode_handle_put(parent);
	return ret;
}
EXPORT_SYMBOL_GPL(gtrace_parse_inconns);
