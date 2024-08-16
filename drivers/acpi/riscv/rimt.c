// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2024, Ventana Micro Systems Inc
 *	Author: Sunil V L <sunilvl@ventanamicro.com>
 *
 */

#include <linux/acpi.h>
#include <linux/acpi_rimt.h>
#include <linux/iommu.h>
#include <linux/list.h>
#include <linux/pci.h>
#include <linux/platform_device.h>
#include "init.h"

struct rimt_fwnode {
	struct list_head list;
	struct acpi_rimt_node *rimt_node;
	struct fwnode_handle *fwnode;
};

static LIST_HEAD(rimt_fwnode_list);
static DEFINE_SPINLOCK(rimt_fwnode_lock);

typedef acpi_status (*rimt_find_node_callback)
	(struct acpi_rimt_node *node, void *context);

#define RIMT_TYPE_MASK(type)	(1 << (type))
#define RIMT_IOMMU_TYPE		BIT(0)

/* Root pointer to the mapped RIMT table */
static struct acpi_table_header *rimt_table;

/**
 * rimt_set_fwnode() - Create rimt_fwnode and use it to register
 *		       iommu data in the rimt_fwnode_list
 *
 * @rimt_node: RIMT table node associated with the IOMMU
 * @fwnode: fwnode associated with the RIMT node
 *
 * Returns: 0 on success
 *          <0 on failure
 */
static inline int rimt_set_fwnode(struct acpi_rimt_node *rimt_node,
				  struct fwnode_handle *fwnode)
{
	struct rimt_fwnode *np;

	np = kzalloc(sizeof(*np), GFP_ATOMIC);

	if (WARN_ON(!np))
		return -ENOMEM;

	INIT_LIST_HEAD(&np->list);
	np->rimt_node = rimt_node;
	np->fwnode = fwnode;

	spin_lock(&rimt_fwnode_lock);
	list_add_tail(&np->list, &rimt_fwnode_list);
	spin_unlock(&rimt_fwnode_lock);

	return 0;
}

/**
 * rimt_get_fwnode() - Retrieve fwnode associated with an RIMT node
 *
 * @node: RIMT table node to be looked-up
 *
 * Returns: fwnode_handle pointer on success, NULL on failure
 */
static inline struct fwnode_handle *rimt_get_fwnode(struct acpi_rimt_node *node)
{
	struct rimt_fwnode *curr;
	struct fwnode_handle *fwnode = NULL;

	spin_lock(&rimt_fwnode_lock);
	list_for_each_entry(curr, &rimt_fwnode_list, list) {
		if (curr->rimt_node == node) {
			fwnode = curr->fwnode;
			break;
		}
	}
	spin_unlock(&rimt_fwnode_lock);

	return fwnode;
}

/**
 * rimt_delete_fwnode() - Delete fwnode associated with an RIMT node
 *
 * @node: RIMT table node associated with fwnode to delete
 */
static inline void rimt_delete_fwnode(struct acpi_rimt_node *node)
{
	struct rimt_fwnode *curr, *tmp;

	spin_lock(&rimt_fwnode_lock);
	list_for_each_entry_safe(curr, tmp, &rimt_fwnode_list, list) {
		if (curr->rimt_node == node) {
			list_del(&curr->list);
			kfree(curr);
			break;
		}
	}
	spin_unlock(&rimt_fwnode_lock);
}

/**
 * rimt_get_rimt_node() - Retrieve rimt_node associated with an fwnode
 *
 * @fwnode: fwnode associated with device to be looked-up
 *
 * Returns: rimt_node pointer on success, NULL on failure
 */
static inline struct acpi_rimt_node *rimt_get_rimt_node(struct fwnode_handle *fwnode)
{
	struct rimt_fwnode *curr;
	struct acpi_rimt_node *rimt_node = NULL;

	spin_lock(&rimt_fwnode_lock);
	list_for_each_entry(curr, &rimt_fwnode_list, list) {
		if (curr->fwnode == fwnode) {
			rimt_node = curr->rimt_node;
			break;
		}
	}
	spin_unlock(&rimt_fwnode_lock);

	return rimt_node;
}

static struct acpi_rimt_node *rimt_scan_node(enum acpi_rimt_node_type type,
					     rimt_find_node_callback callback,
					     void *context)
{
	struct acpi_rimt_node *rimt_node, *rimt_end;
	struct acpi_table_rimt *rimt;
	int i;

	if (!rimt_table)
		return NULL;

	/* Get the first RIMT node */
	rimt = (struct acpi_table_rimt *)rimt_table;
	rimt_node = ACPI_ADD_PTR(struct acpi_rimt_node, rimt,
				 rimt->node_offset);
	rimt_end = ACPI_ADD_PTR(struct acpi_rimt_node, rimt_table,
				rimt_table->length);

	for (i = 0; i < rimt->node_count; i++) {
		if (WARN_TAINT(rimt_node >= rimt_end, TAINT_FIRMWARE_WORKAROUND,
			       "RIMT node pointer overflows, bad table!\n"))
			return NULL;

		if (rimt_node->type == type &&
		    ACPI_SUCCESS(callback(rimt_node, context)))
			return rimt_node;

		rimt_node = ACPI_ADD_PTR(struct acpi_rimt_node, rimt_node,
					 rimt_node->length);
	}

	return NULL;
}

static acpi_status rimt_match_node_callback(struct acpi_rimt_node *node,
					    void *context)
{
	struct device *dev = context;
	acpi_status status = AE_NOT_FOUND;

	if (node->type == ACPI_RIMT_NODE_PLAT_DEVICE) {
		struct acpi_buffer buf = { ACPI_ALLOCATE_BUFFER, NULL };
		struct acpi_device *adev;
		struct acpi_rimt_platform_device *ncomp;
		struct device *nc_dev = dev;

		/*
		 * Walk the device tree to find a device with an
		 * ACPI companion; there is no point in scanning
		 * RIMT for a device matching a named component if
		 * the device does not have an ACPI companion to
		 * start with.
		 */
		do {
			adev = ACPI_COMPANION(nc_dev);
			if (adev)
				break;

			nc_dev = nc_dev->parent;
		} while (nc_dev);

		if (!adev)
			goto out;

		status = acpi_get_name(adev->handle, ACPI_FULL_PATHNAME, &buf);
		if (ACPI_FAILURE(status)) {
			dev_warn(nc_dev, "Can't get device full path name\n");
			goto out;
		}

		ncomp = (struct acpi_rimt_platform_device *)node->node_data;
		status = !strcmp(ncomp->device_name, buf.pointer) ?
							AE_OK : AE_NOT_FOUND;
		acpi_os_free(buf.pointer);
	} else if (node->type == ACPI_RIMT_NODE_PCI_ROOT_COMPLEX) {
		struct acpi_rimt_root_complex *pci_rc;
		struct pci_bus *bus;

		bus = to_pci_bus(dev);
		pci_rc = (struct acpi_rimt_root_complex *)node->node_data;

		/*
		 * It is assumed that PCI segment numbers maps one-to-one
		 * with root complexes. Each segment number can represent only
		 * one root complex.
		 */
		status = pci_rc->pci_segment_number == pci_domain_nr(bus) ?
							AE_OK : AE_NOT_FOUND;
	} else if (node->type == ACPI_RIMT_NODE_IOMMU) {
		struct acpi_rimt_iommu *iommu_node = (struct acpi_rimt_iommu *)&node->node_data;

		if (dev_is_pci(dev)) {
			struct pci_dev *pdev;
			u16 bdf;

			pdev = to_pci_dev(dev);
			bdf = PCI_DEVID(pdev->bus->number, pdev->devfn);
			if ((pci_domain_nr(pdev->bus) == iommu_node->pci_segment_number) &&
			    bdf == iommu_node->pci_bdf) {
				status = AE_OK;
			} else {
				status = AE_NOT_FOUND;
			}
		} else {
			struct platform_device *pdev = to_platform_device(dev);
			struct resource *res;

			res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
			if (res && res->start == iommu_node->base_address)
				status = AE_OK;
			else
				status = AE_NOT_FOUND;
		}
	}
out:
	return status;
}

static int rimt_iommu_xlate(struct device *dev, struct acpi_rimt_node *node, u32 streamid)
{
	struct fwnode_handle *rimt_fwnode;

	if (!node)
		return -ENODEV;

	rimt_fwnode = rimt_get_fwnode(node);

	/*
	 * The IOMMU drivers may not be probed yet.
	 * Defer the IOMMU configuration
	 */
	if (!rimt_fwnode)
		return -EPROBE_DEFER;

	return acpi_iommu_fwspec_init(dev, streamid, rimt_fwnode);
}

struct rimt_pci_alias_info {
	struct device *dev;
	struct acpi_rimt_node *node;
	const struct iommu_ops *ops;
};

static int rimt_id_map(struct acpi_rimt_id_mapping *map, u8 type, u32 rid_in, u32 *rid_out)
{
	if (rid_in < map->input_base ||
	    (rid_in > map->input_base + map->id_count))
		return -ENXIO;

	*rid_out = map->output_base + (rid_in - map->input_base);
	return 0;
}

static struct acpi_rimt_node *rimt_node_get_id(struct acpi_rimt_node *node,
					       u32 *id_out, int index)
{
	struct acpi_rimt_platform_device *plat_node;
	struct acpi_rimt_root_complex *pci_node;
	u32 id_mapping_offset, num_id_mapping;
	struct acpi_rimt_id_mapping *map;
	struct acpi_rimt_node *parent;

	if (node->type == ACPI_RIMT_NODE_PCI_ROOT_COMPLEX) {
		pci_node = (struct acpi_rimt_root_complex *)&node->node_data;
		id_mapping_offset = pci_node->id_mapping_offset;
		num_id_mapping = pci_node->num_id_mapping;
	} else if (node->type == ACPI_RIMT_NODE_PLAT_DEVICE) {
		plat_node = (struct acpi_rimt_platform_device *)&node->node_data;
		id_mapping_offset = plat_node->id_mapping_offset;
		num_id_mapping = plat_node->num_id_mapping;
	} else {
		return NULL;
	}

	if (!id_mapping_offset || !num_id_mapping || index >= num_id_mapping)
		return NULL;

	map = ACPI_ADD_PTR(struct acpi_rimt_id_mapping, node,
			   id_mapping_offset + index * sizeof(*map));

	/* Firmware bug! */
	if (!map->output_reference) {
		pr_err(FW_BUG "[node %p type %d] ID map has NULL parent reference\n",
		       node, node->type);
		return NULL;
	}

	parent = ACPI_ADD_PTR(struct acpi_rimt_node, rimt_table, map->output_reference);

	if (node->type == ACPI_RIMT_NODE_PLAT_DEVICE ||
	    node->type == ACPI_RIMT_NODE_PCI_ROOT_COMPLEX) {
		*id_out = map->output_base;
		return parent;
	}

	return NULL;
}

static struct acpi_rimt_node *rimt_node_map_id(struct acpi_rimt_node *node,
					       u32 id_in, u32 *id_out,
					       u8 type_mask)
{
	struct acpi_rimt_root_complex *pci_node;
	struct acpi_rimt_platform_device *plat_node;
	u32 id = id_in;
	u32 id_mapping_offset, num_id_mapping;

	/* Parse the ID mapping tree to find specified node type */
	while (node) {
		struct acpi_rimt_id_mapping *map;
		int i, rc = 0;
		u32 map_id = id;

		if (RIMT_TYPE_MASK(node->type) & type_mask) {
			if (id_out)
				*id_out = id;
			return node;
		}

		if (node->type == ACPI_RIMT_NODE_PCI_ROOT_COMPLEX) {
			pci_node = (struct acpi_rimt_root_complex *)&node->node_data;
			id_mapping_offset = pci_node->id_mapping_offset;
			num_id_mapping = pci_node->num_id_mapping;
		} else if (node->type == ACPI_RIMT_NODE_PLAT_DEVICE) {
			plat_node = (struct acpi_rimt_platform_device *)&node->node_data;
			id_mapping_offset = plat_node->id_mapping_offset;
			num_id_mapping = plat_node->num_id_mapping;
		} else {
			goto fail_map;
		}

		if (!id_mapping_offset || !num_id_mapping)
			goto fail_map;

		map = ACPI_ADD_PTR(struct acpi_rimt_id_mapping, node,
				   id_mapping_offset);

		/* Firmware bug! */
		if (!map->output_reference) {
			pr_err(FW_BUG "[node %p type %d] ID map has NULL parent reference\n",
			       node, node->type);
			goto fail_map;
		}

		/* Do the ID translation */
		for (i = 0; i < num_id_mapping; i++, map++) {
			rc = rimt_id_map(map, node->type, map_id, &id);
			if (!rc)
				break;
		}

		if (i == num_id_mapping)
			goto fail_map;

		node = ACPI_ADD_PTR(struct acpi_rimt_node, rimt_table,
				    rc ? 0 : map->output_reference);
	}

fail_map:
	/* Map input ID to output ID unchanged on mapping failure */
	if (id_out)
		*id_out = id_in;

	return NULL;
}

static struct acpi_rimt_node *rimt_node_map_platform_id(struct acpi_rimt_node *node, u32 *id_out,
							u8 type_mask, int index)
{
	struct acpi_rimt_node *parent;
	u32 id;

	parent = rimt_node_get_id(node, &id, index);
	if (!parent)
		return NULL;

	if (!(RIMT_TYPE_MASK(parent->type) & type_mask))
		parent = rimt_node_map_id(parent, id, id_out, type_mask);
	else
		if (id_out)
			*id_out = id;

	return parent;
}

static int rimt_pci_iommu_init(struct pci_dev *pdev, u16 alias, void *data)
{
	struct rimt_pci_alias_info *info = data;
	struct acpi_rimt_node *parent;
	u32 streamid;

	parent = rimt_node_map_id(info->node, alias, &streamid, RIMT_IOMMU_TYPE);
	return rimt_iommu_xlate(info->dev, parent, streamid);
}

/*
 * RISC-V supports IOMMU as a PCI device or a platform device.
 * When it is a platform device, there should be a namespace device as
 * well along with RIMT. To create the link between RIMT information and
 * the platform device, the IOMMU driver should register itself with the
 * RIMT module. This is true for PCI based IOMMU as well.
 */
int rimt_iommu_register(struct device *dev)
{
	struct fwnode_handle *rimt_fwnode;
	struct acpi_rimt_node *node;

	node = rimt_scan_node(ACPI_RIMT_NODE_IOMMU, rimt_match_node_callback, dev);
	if (!node) {
		pr_err("Could not find IOMMU node in RIMT\n");
		return -ENODEV;
	}

	if (dev_is_pci(dev)) {
		rimt_fwnode = acpi_alloc_fwnode_static();
		if (!rimt_fwnode)
			return -ENOMEM;

		rimt_fwnode->dev = dev;
		if (!dev->fwnode)
			dev->fwnode = rimt_fwnode;

		rimt_set_fwnode(node, rimt_fwnode);
	} else {
		rimt_set_fwnode(node, dev->fwnode);
	}

	return 0;
}

#ifdef CONFIG_IOMMU_API

static int rimt_nc_iommu_map(struct device *dev, struct acpi_rimt_node *node)
{
	struct acpi_rimt_node *parent;
	int err = -ENODEV, i = 0;
	u32 streamid = 0;

	do {
		parent = rimt_node_map_platform_id(node, &streamid,
						   RIMT_IOMMU_TYPE,
						   i++);

		if (parent)
			err = rimt_iommu_xlate(dev, parent, streamid);
	} while (parent && !err);

	return err;
}

static int rimt_nc_iommu_map_id(struct device *dev,
				struct acpi_rimt_node *node,
				const u32 *in_id)
{
	struct acpi_rimt_node *parent;
	u32 streamid;

	parent = rimt_node_map_id(node, *in_id, &streamid, RIMT_IOMMU_TYPE);
	if (parent)
		return rimt_iommu_xlate(dev, parent, streamid);

	return -ENODEV;
}

/**
 * rimt_iommu_configure_id - Set-up IOMMU configuration for a device.
 *
 * @dev: device to configure
 * @id_in: optional input id const value pointer
 *
 * Returns: 0 on success, <0 on failure
 */
int rimt_iommu_configure_id(struct device *dev, const u32 *id_in, const struct iommu_ops *ops)
{
	struct acpi_rimt_node *node;
	int err = -ENODEV;

	if (dev_is_pci(dev)) {
		struct iommu_fwspec *fwspec;
		struct pci_bus *bus = to_pci_dev(dev)->bus;
		struct rimt_pci_alias_info info = { .dev = dev };

		node = rimt_scan_node(ACPI_RIMT_NODE_PCI_ROOT_COMPLEX,
				      rimt_match_node_callback, &bus->dev);
		if (!node)
			return -ENODEV;

		info.node = node;
		info.ops = ops;
		err = pci_for_each_dma_alias(to_pci_dev(dev),
					     rimt_pci_iommu_init, &info);

		fwspec = dev_iommu_fwspec_get(dev);
	} else {
		node = rimt_scan_node(ACPI_RIMT_NODE_PLAT_DEVICE,
				      rimt_match_node_callback, dev);
		if (!node)
			return -ENODEV;

		err = id_in ? rimt_nc_iommu_map_id(dev, node, id_in) :
			      rimt_nc_iommu_map(dev, node);
	}

	return err;
}

#else
int rimt_iommu_configure_id(struct device *dev, const u32 *input_id, const struct iommu_ops *ops)
{
	return -ENODEV;
}
#endif

int arch_iommu_configure_id(struct device *dev, const u32 *id_in)
{
	return rimt_iommu_configure_id(dev, id_in, NULL);
}

void __init riscv_acpi_rimt_init(void)
{
	acpi_status status;

	/* rimt_table will be used at runtime after the rimt init,
	 * so we don't need to call acpi_put_table() to release
	 * the RIMT table mapping.
	 */
	status = acpi_get_table(ACPI_SIG_RIMT, 0, &rimt_table);
	if (ACPI_FAILURE(status)) {
		if (status != AE_NOT_FOUND) {
			const char *msg = acpi_format_exception(status);

			pr_err("Failed to get table, %s\n", msg);
		}

		return;
	}
}
