// SPDX-License-Identifier: GPL-2.0-only
/*
 * IOMMU Interrupt Remapping
 *
 * Copyright © 2025 Ventana Micro Systems Inc.
 */
#include <linux/irqchip/riscv-imsic.h>
#include <linux/irqdomain.h>
#include <linux/msi.h>

#include "iommu.h"

static struct irq_chip riscv_iommu_ir_irq_chip = {
	.name			= "IOMMU-IR",
	.irq_ack		= irq_chip_ack_parent,
	.irq_mask		= irq_chip_mask_parent,
	.irq_unmask		= irq_chip_unmask_parent,
	.irq_set_affinity	= irq_chip_set_affinity_parent,
};

static int riscv_iommu_ir_irq_domain_alloc_irqs(struct irq_domain *irqdomain,
						unsigned int irq_base, unsigned int nr_irqs,
						void *arg)
{
	struct irq_data *data;
	int i, ret;

	ret = irq_domain_alloc_irqs_parent(irqdomain, irq_base, nr_irqs, arg);
	if (ret)
		return ret;

	for (i = 0; i < nr_irqs; i++) {
		data = irq_domain_get_irq_data(irqdomain, irq_base + i);
		data->chip = &riscv_iommu_ir_irq_chip;
	}

	return 0;
}

static const struct irq_domain_ops riscv_iommu_ir_irq_domain_ops = {
	.alloc = riscv_iommu_ir_irq_domain_alloc_irqs,
	.free = irq_domain_free_irqs_parent,
};

static const struct msi_parent_ops riscv_iommu_ir_msi_parent_ops = {
	.prefix			= "IR-",
	.supported_flags	= MSI_GENERIC_FLAGS_MASK |
				  MSI_FLAG_PCI_MSIX,
	.required_flags		= MSI_FLAG_USE_DEF_DOM_OPS |
				  MSI_FLAG_USE_DEF_CHIP_OPS |
				  MSI_FLAG_PCI_MSI_MASK_PARENT,
	.chip_flags		= MSI_CHIP_FLAG_SET_ACK,
	.init_dev_msi_info	= msi_parent_init_dev_msi_info,
};

int riscv_iommu_ir_irq_domain_create(struct riscv_iommu_domain *domain,
				     struct device *dev)
{
	struct irq_domain *irqparent = dev_get_msi_domain(dev);
	struct riscv_iommu_device *iommu = dev_to_iommu(dev);
	const struct imsic_global_config *imsic_global;
	struct irq_domain *irqdomain;
	struct fwnode_handle *fn;
	char *fwname;

	if (domain->irqdomain) {
		dev_set_msi_domain(dev, domain->irqdomain);
		return 0;
	}

	if (!(iommu->caps & RISCV_IOMMU_CAPABILITIES_MSI_FLAT))
		return 0;

	imsic_global = imsic_get_global_config();
	if (!imsic_global || !imsic_global->nr_ids)
		return 0;

	fwname = kasprintf(GFP_KERNEL, "IOMMU-IR-%s-%u", dev_name(dev), domain->pscid);
	if (!fwname)
		return -ENOMEM;

	fn = irq_domain_alloc_named_fwnode(fwname);
	kfree(fwname);
	if (!fn) {
		dev_err(iommu->dev, "Couldn't allocate fwnode\n");
		return -ENOMEM;
	}

	irqdomain = irq_domain_create_hierarchy(irqparent, 0, 0, fn,
						&riscv_iommu_ir_irq_domain_ops,
						domain);
	if (!irqdomain) {
		dev_err(iommu->dev, "Failed to create IOMMU irq domain\n");
		irq_domain_free_fwnode(fn);
		return -ENOMEM;
	}

	irqdomain->flags |= IRQ_DOMAIN_FLAG_MSI_PARENT;
	irqdomain->msi_parent_ops = &riscv_iommu_ir_msi_parent_ops;
	irq_domain_update_bus_token(irqdomain, DOMAIN_BUS_MSI_REMAP);

	domain->irqdomain = irqdomain;
	dev_set_msi_domain(dev, irqdomain);

	return 0;
}

void riscv_iommu_ir_irq_domain_remove(struct riscv_iommu_domain *domain)
{
	struct fwnode_handle *fn;

	if (!domain->irqdomain)
		return;

	fn = domain->irqdomain->fwnode;
	irq_domain_remove(domain->irqdomain);
	domain->irqdomain = NULL;
	irq_domain_free_fwnode(fn);
}

void riscv_iommu_ir_irq_domain_unlink(struct riscv_iommu_domain *domain,
				      struct device *dev)
{
	if (!domain || !domain->irqdomain)
		return;

	dev_set_msi_domain(dev, domain->irqdomain->parent);
}
