// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Qualcomm Technologies, Inc.
 */

#include <linux/acpi.h>
#include <linux/device.h>
#include <linux/io.h>
#include <linux/of.h>
#include <linux/of_graph.h>
#include <linux/platform_device.h>
#include <linux/property.h>
#include <linux/rvtrace.h>
#include <linux/types.h>

static int rvtrace_parse_outconns(struct rvtrace_platform_data *pdata)
{
	struct fwnode_handle *parent, *ep_node, *rep_node, *rdev_node;
	struct fwnode_endpoint ep = { 0 };
	struct fwnode_endpoint rep = { 0 };
	struct rvtrace_connection *conn;
	int ret = 0, i = 0;

	parent = fwnode_get_named_child_node(dev_fwnode(pdata->dev), "out-ports");
	if (!parent)
		return 0;

	pdata->nr_outconns = fwnode_graph_get_endpoint_count(parent, 0);
	pdata->outconns = devm_kcalloc(pdata->dev, pdata->nr_outconns,
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

		ret = fwnode_graph_parse_endpoint(rep_node, &rep);
		if (ret) {
			fwnode_handle_put(ep_node);
			fwnode_handle_put(rep_node);
			fwnode_handle_put(rdev_node);
			break;
		}


		conn->src_port = ep.port;
		conn->src_fwnode = dev_fwnode(pdata->dev);
		/* The 'src_comp' is set by rvtrace_register_component() */
		conn->src_comp = NULL;
		conn->dest_port = rep.port;
		conn->dest_fwnode = rdev_node;
		fwnode_handle_get(conn->dest_fwnode);
		conn->dest_comp = rvtrace_find_by_fwnode(conn->dest_fwnode);
		if (!conn->dest_comp) {
			ret = -EPROBE_DEFER;
			fwnode_handle_put(ep_node);
			fwnode_handle_put(rep_node);
			fwnode_handle_put(rdev_node);
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
	fwnode_handle_put(parent);
	return ret;
}

static int rvtrace_parse_inconns(struct rvtrace_platform_data *pdata)
{
	struct fwnode_handle *parent;
	int ret = 0;

	parent = fwnode_get_named_child_node(dev_fwnode(pdata->dev), "in-ports");
	if (!parent)
		return 0;

	pdata->nr_inconns = fwnode_graph_get_endpoint_count(parent, FWNODE_GRAPH_DEVICE_DISABLED);
	pdata->inconns = devm_kcalloc(pdata->dev, pdata->nr_inconns,
				      sizeof(*pdata->inconns), GFP_KERNEL);
	if (!pdata->inconns)
		ret = -ENOMEM;

	fwnode_handle_put(parent);
	return ret;
}

#ifdef CONFIG_ACPI
#include <acpi/processor.h>

static const struct acpi_device_id rvtrace_platform_acpi_match[] = {
	{ "RSCV0007", 0 },
	{}
};
MODULE_DEVICE_TABLE(acpi, rvtrace_platform_acpi_match);

/*
 * acpi_handle_to_logical_cpuid - Map a given acpi_handle to the
 * logical CPU id of the corresponding CPU device.
 *
 * Returns the logical CPU id when found. Otherwise returns >= nr_cpus_id.
 */
static int
acpi_handle_to_logical_cpuid(acpi_handle handle)
{
	int i;
	struct acpi_processor *pr;

	for_each_possible_cpu(i) {
		pr = per_cpu(processors, i);
		if (pr && pr->handle == handle)
			break;
	}

	return i;
}

static int acpi_rvtrace_get_cpu(struct device *dev)
{
	int cpu;
	acpi_handle cpu_handle;
	acpi_status status;
	struct acpi_device *adev = ACPI_COMPANION(dev);

	if (!adev)
		return -ENODEV;
	status = acpi_get_parent(adev->handle, &cpu_handle);
	if (ACPI_FAILURE(status))
		return -ENODEV;

	cpu = acpi_handle_to_logical_cpuid(cpu_handle);
	if (cpu >= nr_cpu_ids)
		return -ENODEV;
	return cpu;
}
#else
static int acpi_rvtrace_get_cpu(struct device *dev)
{
	return -ENODEV;
}
#endif

#ifdef CONFIG_OF
static int of_rvtrace_get_cpu(struct device *dev)
{
	int cpu;
	struct device_node *dn;

	if (!dev->of_node)
		return -ENODEV;

	dn = of_parse_phandle(dev->of_node, "cpus", 0);
	if (!dn)
		return -ENODEV;

	cpu = of_cpu_node_to_id(dn);
	of_node_put(dn);

	return cpu;
}
#else
static int of_rvtrace_get_cpu(struct device *dev)
{
	return -ENODEV;
}
#endif

/*
 * rvtrace_get_cpu - Find the logical CPU id of the CPU associated
 * with this rvtrace device.
 *
 * Returns the logical CPU id when found. Otherwise returns 0.
 */

static int rvtrace_get_cpu(struct device *dev)
{
	if (is_of_node(dev_fwnode(dev)))
		return of_rvtrace_get_cpu(dev);
	else if (is_acpi_device_node(dev_fwnode(dev)))
		return acpi_rvtrace_get_cpu(dev);

	return -1;
}

static int rvtrace_platform_probe(struct platform_device *pdev)
{
	struct rvtrace_platform_data *pdata;
	struct device *dev = &pdev->dev;
	struct rvtrace_component *comp;
	u32 impl, type, major, minor;
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

	pdata->bound_cpu = rvtrace_get_cpu(dev);
	/* Default control poll timeout */
	pdata->control_poll_timeout_usecs = 10;

	ret = rvtrace_parse_outconns(pdata);
	if (ret)
		return dev_err_probe(dev, ret, "failed to parse output connections\n");

	ret = rvtrace_parse_inconns(pdata);
	if (ret)
		return dev_err_probe(dev, ret, "failed to parse input connections\n");

	ret = rvtrace_reset_component(pdata);
	if (ret)
		return dev_err_probe(dev, ret, "failed to reset component\n");

	impl = rvtrace_read32(pdata, RVTRACE_COMPONENT_IMPL_OFFSET);
	type = (impl >> RVTRACE_COMPONENT_IMPL_TYPE_SHIFT) &
		RVTRACE_COMPONENT_IMPL_TYPE_MASK;
	major = (impl >> RVTRACE_COMPONENT_IMPL_VERMAJOR_SHIFT) &
		RVTRACE_COMPONENT_IMPL_VERMAJOR_MASK;
	minor = (impl >> RVTRACE_COMPONENT_IMPL_VERMINOR_SHIFT) &
		RVTRACE_COMPONENT_IMPL_VERMINOR_MASK;

	comp = rvtrace_register_component(type, rvtrace_component_mkversion(major, minor), pdata);
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
		.acpi_match_table = ACPI_PTR(rvtrace_platform_acpi_match),
	},
	.probe = rvtrace_platform_probe,
	.remove = rvtrace_platform_remove,
};
