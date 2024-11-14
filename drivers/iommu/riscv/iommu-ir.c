// SPDX-License-Identifier: GPL-2.0-only
/*
 * IOMMU Interrupt Remapping
 *
 * Copyright © 2024 Ventana Micro Systems Inc.
 */
#include <linux/irqdomain.h>
#include <linux/msi.h>

#include "../iommu-pages.h"
#include "iommu.h"

static size_t riscv_iommu_ir_get_msipte_idx(struct riscv_iommu_domain *domain,
					    phys_addr_t msi_pa)
{
	phys_addr_t addr = msi_pa >> 12;
	size_t idx;

	if (domain->group_index_bits) {
		phys_addr_t group_mask = BIT(domain->group_index_bits) - 1;
		phys_addr_t group_shift = domain->group_index_shift - 12;
		phys_addr_t group = (addr >> group_shift) & group_mask;
		phys_addr_t mask = domain->msiptp.msi_addr_mask & ~(group_mask << group_shift);

		idx = addr & mask;
		idx |= group << fls64(mask);
	} else {
		idx = addr & domain->msiptp.msi_addr_mask;
	}

	return idx;
}

static struct riscv_iommu_msipte *riscv_iommu_ir_get_msipte(struct riscv_iommu_domain *domain,
							    phys_addr_t msi_pa)
{
	size_t idx;

	if (((msi_pa >> 12) & ~domain->msiptp.msi_addr_mask) != domain->msiptp.msi_addr_pattern)
		return NULL;

	idx = riscv_iommu_ir_get_msipte_idx(domain, msi_pa);
	return &domain->msi_root[idx];
}

static size_t riscv_iommu_ir_nr_msiptes(struct riscv_iommu_domain *domain)
{
	phys_addr_t base = domain->msiptp.msi_addr_pattern << 12;
	phys_addr_t max_addr = base | (domain->msiptp.msi_addr_mask << 12);
	size_t max_idx = riscv_iommu_ir_get_msipte_idx(domain, max_addr);

	return max_idx + 1;
}

static struct irq_chip riscv_iommu_irq_chip = {
	.name			= "IOMMU-IR",
	.irq_mask		= irq_chip_mask_parent,
	.irq_unmask		= irq_chip_unmask_parent,
};

static int riscv_iommu_irq_domain_alloc_irqs(struct irq_domain *irqdomain,
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
		data->chip = &riscv_iommu_irq_chip;
	}

	return 0;
}

static const struct irq_domain_ops riscv_iommu_irq_domain_ops = {
	.alloc = riscv_iommu_irq_domain_alloc_irqs,
	.free = irq_domain_free_irqs_parent,
};

static const struct msi_parent_ops riscv_iommu_msi_parent_ops = {
	.prefix			= "IR-",
	.supported_flags	= MSI_GENERIC_FLAGS_MASK |
				  MSI_FLAG_PCI_MSIX,
	.required_flags		= MSI_FLAG_USE_DEF_DOM_OPS |
				  MSI_FLAG_USE_DEF_CHIP_OPS,
	.init_dev_msi_info	= msi_parent_init_dev_msi_info,
};

int riscv_iommu_irq_domain_create(struct riscv_iommu_domain *domain,
				  struct device *dev)
{
	struct riscv_iommu_device *iommu = dev_to_iommu(dev);
	struct fwnode_handle *fn;
	char *fwname;

	if (domain->irqdomain) {
		dev_set_msi_domain(dev, domain->irqdomain);
		return 0;
	}

	if (!(iommu->caps & RISCV_IOMMU_CAPABILITIES_MSI_FLAT)) {
		dev_warn(iommu->dev, "Cannot enable interrupt remapping\n");
		return 0;
	}

	spin_lock_init(&domain->msi_lock);
	/*
	 * TODO: The hypervisor should be in control of this size. For now
	 * we just allocate enough space for 512 VCPUs.
	 */
	domain->msi_order = 1;
	domain->msi_root = iommu_alloc_pages_node(domain->numa_node,
						  GFP_KERNEL_ACCOUNT, domain->msi_order);
	if (!domain->msi_root)
		return -ENOMEM;

	fwname = kasprintf(GFP_KERNEL, "IOMMU-IR-%s", dev_name(dev));
	if (!fwname) {
		iommu_free_pages(domain->msi_root, domain->msi_order);
		return -ENOMEM;
	}

	fn = irq_domain_alloc_named_fwnode(fwname);
	kfree(fwname);
	if (!fn) {
		dev_err(iommu->dev, "Couldn't allocate fwnode\n");
		iommu_free_pages(domain->msi_root, domain->msi_order);
		return -ENOMEM;
	}

	domain->irqdomain = irq_domain_create_hierarchy(dev_get_msi_domain(dev),
							0, 0, fn,
							&riscv_iommu_irq_domain_ops,
							domain);
	if (!domain->irqdomain) {
		dev_err(iommu->dev, "Failed to create IOMMU irq domain\n");
		iommu_free_pages(domain->msi_root, domain->msi_order);
		irq_domain_free_fwnode(fn);
		return -ENOMEM;
	}

	domain->irqdomain->flags |= IRQ_DOMAIN_FLAG_MSI_PARENT |
				    IRQ_DOMAIN_FLAG_ISOLATED_MSI;
	domain->irqdomain->msi_parent_ops = &riscv_iommu_msi_parent_ops;
	irq_domain_update_bus_token(domain->irqdomain, DOMAIN_BUS_MSI_REMAP);
	dev_set_msi_domain(dev, domain->irqdomain);

	return 0;
}

void riscv_iommu_ir_get_resv_regions(struct device *dev, struct list_head *head)
{
	struct riscv_iommu_info *info = dev_iommu_priv_get(dev);
	struct riscv_iommu_domain *domain = info->domain;
	struct iommu_resv_region *reg;
	phys_addr_t base, addr;
	size_t nr_pages, i;

	if (!domain || !domain->msiptp.msiptp)
		return;

	base = domain->msiptp.msi_addr_pattern << 12;

	if (domain->group_index_bits) {
		phys_addr_t group_mask = BIT(domain->group_index_bits) - 1;
		phys_addr_t group_shift = domain->group_index_shift - 12;
		phys_addr_t mask = domain->msiptp.msi_addr_mask & ~(group_mask << group_shift);

		nr_pages = mask + 1;
	} else {
		nr_pages = domain->msiptp.msi_addr_mask + 1;
	}

	for (i = 0; i < BIT(domain->group_index_bits); i++) {
		addr = base | (i << domain->group_index_shift);
		reg = iommu_alloc_resv_region(addr, nr_pages * 4096,
					      0, IOMMU_RESV_MSI, GFP_KERNEL);
		if (reg)
			list_add_tail(&reg->list, head);
	}
}

void riscv_iommu_irq_domain_remove(struct riscv_iommu_domain *domain)
{
	struct fwnode_handle *fn;

	if (!domain->irqdomain)
		return;

	iommu_free_pages(domain->msi_root, domain->msi_order);

	fn = domain->irqdomain->fwnode;
	irq_domain_remove(domain->irqdomain);
	irq_domain_free_fwnode(fn);
}

void riscv_iommu_irq_domain_unlink(struct riscv_iommu_domain *domain,
				   struct device *dev)
{
	if (!domain || !domain->irqdomain)
		return;

	dev_set_msi_domain(dev, domain->irqdomain->parent);
}
