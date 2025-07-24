// SPDX-License-Identifier: GPL-2.0-only
/*
 * IOMMU Interrupt Remapping
 *
 * Copyright © 2025 Ventana Micro Systems Inc.
 */
#include <linux/irqchip/riscv-imsic.h>
#include <linux/irqdomain.h>
#include <linux/msi.h>
#include <linux/sizes.h>

#include "../iommu-pages.h"
#include "iommu.h"

static size_t riscv_iommu_ir_group_size(struct riscv_iommu_domain *domain)
{
	phys_addr_t mask = domain->msiptp.msi_addr_mask;

	if (domain->group_index_bits) {
		phys_addr_t group_mask = BIT(domain->group_index_bits) - 1;
		phys_addr_t group_shift = domain->group_index_shift - 12;

		mask &= ~(group_mask << group_shift);
	}

	return (mask + 1) << 12;
}

static int riscv_iommu_ir_map_unmap_imsics(struct riscv_iommu_domain *domain, bool map,
					   gfp_t gfp, size_t *unmapped)
{
	phys_addr_t base = domain->msiptp.msi_addr_pattern << 12, addr;
	size_t stride = domain->imsic_stride, map_size = SZ_4K, size;
	size_t i, j;

	size = riscv_iommu_ir_group_size(domain);

	if (stride == SZ_4K)
		stride = map_size = size;

	for (i = 0; i < BIT(domain->group_index_bits); i++) {
		for (j = 0; j < size; j += stride) {
			addr = (base + j) | (i << domain->group_index_shift);
			if (map) {
				int ret = iommu_map(&domain->domain, addr, addr, map_size,
						    IOMMU_WRITE | IOMMU_NOEXEC | IOMMU_MMIO, gfp);
				if (ret)
					return ret;
			} else {
				*unmapped += iommu_unmap(&domain->domain, addr, map_size);
			}
		}
	}

	return 0;
}

static size_t riscv_iommu_ir_unmap_imsics(struct riscv_iommu_domain *domain)
{
	size_t unmapped = 0;

	riscv_iommu_ir_map_unmap_imsics(domain, false, 0, &unmapped);

	return unmapped;
}

static int riscv_iommu_ir_map_imsics(struct riscv_iommu_domain *domain, gfp_t gfp)
{
	int ret;

	ret = riscv_iommu_ir_map_unmap_imsics(domain, true, gfp, NULL);
	if (ret)
		riscv_iommu_ir_unmap_imsics(domain);

	return ret;
}

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

static size_t riscv_iommu_ir_nr_msiptes(struct riscv_iommu_domain *domain)
{
	phys_addr_t base = domain->msiptp.msi_addr_pattern << 12;
	phys_addr_t max_addr = base | (domain->msiptp.msi_addr_mask << 12);
	size_t max_idx = riscv_iommu_ir_get_msipte_idx(domain, max_addr);

	return max_idx + 1;
}

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
	size_t nr_ptes;
	char *fwname;
	u64 mask;
	int ret;

	if (domain->irqdomain) {
		dev_set_msi_domain(dev, domain->irqdomain);
		return 0;
	}

	if (!(iommu->caps & RISCV_IOMMU_CAPABILITIES_MSI_FLAT))
		return 0;

	imsic_global = imsic_get_global_config();
	if (!imsic_global || !imsic_global->nr_ids)
		return 0;

	mask = 0;
	mask |= (BIT(imsic_global->group_index_bits) - 1) << (imsic_global->group_index_shift - 12);
	mask |= BIT(imsic_global->hart_index_bits + imsic_global->guest_index_bits) - 1;
	domain->msiptp.msi_addr_mask = mask;
	domain->msiptp.msi_addr_pattern = imsic_global->base_addr >> 12;
	domain->group_index_bits = imsic_global->group_index_bits;
	domain->group_index_shift = imsic_global->group_index_shift;
	domain->imsic_stride = BIT(imsic_global->guest_index_bits + 12);

	/*
	 * The RISC-V IOMMU MSI table is checked after the stage1 DMA
	 * page tables. If we don't create identity mappings in the
	 * stage1 table then we'll fault and won't even get a chance
	 * to check the MSI table. Create all the mappings now if
	 * stage1 is in use.
	 */
	if (domain->pgd_mode) {
		ret = riscv_iommu_ir_map_imsics(domain, GFP_KERNEL_ACCOUNT);
		if (ret)
			return ret;
	}

	nr_ptes = riscv_iommu_ir_nr_msiptes(domain);
	spin_lock_init(&domain->msi_lock);
	domain->msi_root = iommu_alloc_pages_node_sz(domain->numa_node, GFP_KERNEL_ACCOUNT,
						     nr_ptes * sizeof(*domain->msi_root));
	if (!domain->msi_root)
		goto nomem;

	fwname = kasprintf(GFP_KERNEL, "IOMMU-IR-%s-%u", dev_name(dev), domain->pscid);
	if (!fwname)
		goto free_msi_root;

	fn = irq_domain_alloc_named_fwnode(fwname);
	kfree(fwname);
	if (!fn) {
		dev_err(iommu->dev, "Couldn't allocate fwnode\n");
		goto free_msi_root;
	}

	irqdomain = irq_domain_create_hierarchy(irqparent, 0, 0, fn,
						&riscv_iommu_ir_irq_domain_ops,
						domain);
	if (!irqdomain) {
		dev_err(iommu->dev, "Failed to create IOMMU irq domain\n");
		goto free_fwnode;
	}

	irqdomain->flags |= IRQ_DOMAIN_FLAG_MSI_PARENT;
	irqdomain->msi_parent_ops = &riscv_iommu_ir_msi_parent_ops;
	irq_domain_update_bus_token(irqdomain, DOMAIN_BUS_MSI_REMAP);

	domain->irqdomain = irqdomain;
	dev_set_msi_domain(dev, irqdomain);

	return 0;

free_fwnode:
	irq_domain_free_fwnode(fn);
free_msi_root:
	iommu_free_pages(domain->msi_root);
nomem:
	return -ENOMEM;
}

void riscv_iommu_ir_irq_domain_remove(struct riscv_iommu_domain *domain)
{
	struct fwnode_handle *fn;

	if (!domain->irqdomain)
		return;

	if (domain->pgd_mode)
		riscv_iommu_ir_unmap_imsics(domain);

	iommu_free_pages(domain->msi_root);

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

void riscv_iommu_ir_get_resv_regions(struct device *dev, struct list_head *head)
{
	const struct imsic_global_config *imsic_global;
	struct iommu_resv_region *reg;
	phys_addr_t addr;
	size_t size, i;

	imsic_global = imsic_get_global_config();
	if (!imsic_global || !imsic_global->nr_ids)
		return;

	size = BIT(imsic_global->hart_index_bits + imsic_global->guest_index_bits + 12);

	for (i = 0; i < BIT(imsic_global->group_index_bits); i++) {
		addr = imsic_global->base_addr | (i << imsic_global->group_index_shift);
		reg = iommu_alloc_resv_region(addr, size, 0, IOMMU_RESV_MSI, GFP_KERNEL);
		if (reg)
			list_add_tail(&reg->list, head);
	}
}
