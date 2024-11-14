// SPDX-License-Identifier: GPL-2.0-only
/*
 * IOMMU Interrupt Remapping
 *
 * Copyright © 2024 Ventana Micro Systems Inc.
 */
#include <linux/irqdomain.h>
#include <linux/msi.h>

#include <asm/irq.h>

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

static void riscv_iommu_ir_msitbl_inval(struct riscv_iommu_domain *domain,
					struct riscv_iommu_msipte *pte)
{
	struct riscv_iommu_bond *bond;
	struct riscv_iommu_device *iommu, *prev;
	struct riscv_iommu_command cmd;
	u64 addr;

	addr = pfn_to_phys(FIELD_GET(RISCV_IOMMU_MSIPTE_PPN, pte->pte));
	riscv_iommu_cmd_inval_gvma(&cmd);
	riscv_iommu_cmd_inval_set_addr(&cmd, addr);

	/* Like riscv_iommu_iotlb_inval(), synchronize with riscv_iommu_bond_link() */
	smp_mb();

	rcu_read_lock();

	prev = NULL;
	list_for_each_entry_rcu(bond, &domain->bonds, list) {
		iommu = dev_to_iommu(bond->dev);

		if (iommu == prev)
			continue;

		riscv_iommu_cmd_send(iommu, &cmd);
		riscv_iommu_cmd_sync(iommu, RISCV_IOMMU_IOTINVAL_TIMEOUT);
		prev = iommu;
	}

	rcu_read_unlock();
}

static void riscv_iommu_ir_msitbl_update(struct riscv_iommu_domain *domain,
					 struct riscv_iommu_msiptp_state *msiptp)
{
	struct riscv_iommu_bond *bond;
	struct riscv_iommu_device *iommu, *prev;
	struct riscv_iommu_command cmd;
	struct iommu_fwspec *fwspec;
	struct riscv_iommu_dc *dc;
	int i;

	/* Like riscv_iommu_ir_msitbl_inval(), synchronize with riscv_iommu_bond_link() */
	smp_mb();
	rcu_read_lock();

	prev = NULL;
	list_for_each_entry_rcu(bond, &domain->bonds, list) {
		iommu = dev_to_iommu(bond->dev);
		fwspec = dev_iommu_fwspec_get(bond->dev);

		for (i = 0; i < fwspec->num_ids; i++) {
			dc = riscv_iommu_get_dc(iommu, fwspec->ids[i]);
			WRITE_ONCE(dc->msiptp, msiptp->msiptp);
			WRITE_ONCE(dc->msi_addr_mask, msiptp->msi_addr_mask);
			WRITE_ONCE(dc->msi_addr_pattern, msiptp->msi_addr_pattern);
		}

		dma_wmb();

		if (iommu == prev)
			continue;

		riscv_iommu_cmd_inval_gvma(&cmd);
		riscv_iommu_cmd_send(iommu, &cmd);
		riscv_iommu_cmd_sync(iommu, RISCV_IOMMU_IOTINVAL_TIMEOUT);
		prev = iommu;
	}

	rcu_read_unlock();
}

static int riscv_iommu_ir_msitbl_init(struct riscv_iommu_domain *domain,
				      struct riscv_iommu_vcpu_info *vcpu_info)
{
	domain->msiptp.msi_addr_pattern = vcpu_info->msi_addr_pattern;
	domain->msiptp.msi_addr_mask = vcpu_info->msi_addr_mask;
	domain->group_index_bits = vcpu_info->group_index_bits;
	domain->group_index_shift = vcpu_info->group_index_shift;

	if (riscv_iommu_ir_nr_msiptes(domain) * sizeof(*domain->msi_root) > PAGE_SIZE * 2)
		return -ENOMEM;

	domain->msiptp.msiptp = virt_to_pfn(domain->msi_root) |
				FIELD_PREP(RISCV_IOMMU_DC_MSIPTP_MODE,
					   RISCV_IOMMU_DC_MSIPTP_MODE_FLAT);

	riscv_iommu_ir_msitbl_update(domain, &domain->msiptp);

	return 0;
}

static int riscv_iommu_irq_set_vcpu_affinity(struct irq_data *data, void *info)
{
	struct riscv_iommu_vcpu_info *vcpu_info = info;
	struct riscv_iommu_domain *domain = data->domain->host_data;
	struct riscv_iommu_msipte *pte;
	int ret = -EINVAL;
	u64 pteval;

	if (WARN_ON(domain->domain.type != IOMMU_DOMAIN_UNMANAGED))
		return ret;

	spin_lock(&domain->msi_lock);

	if (!domain->msiptp.msiptp) {
		if (WARN_ON(!vcpu_info))
			goto out_unlock;

		ret = riscv_iommu_ir_msitbl_init(domain, vcpu_info);
		if (ret)
			goto out_unlock;
	} else if (!vcpu_info) {
		/*
		 * Nothing to do here since we don't track host_irq <=> msipte mappings
		 * nor reference count the ptes. If we did do that tracking then we would
		 * decrement the reference count of the pte for the host_irq and possibly
		 * clear its valid bit if it was the last one mapped.
		 */
		ret = 0;
		goto out_unlock;
	} else if (WARN_ON(vcpu_info->msi_addr_pattern != domain->msiptp.msi_addr_pattern ||
			   vcpu_info->msi_addr_mask != domain->msiptp.msi_addr_mask ||
			   vcpu_info->group_index_bits != domain->group_index_bits ||
			   vcpu_info->group_index_shift != domain->group_index_shift)) {
		goto out_unlock;
	}

	pte = riscv_iommu_ir_get_msipte(domain, vcpu_info->gpa);
	if (!pte)
		goto out_unlock;

	pteval = FIELD_PREP(RISCV_IOMMU_MSIPTE_M, 3) |
		 riscv_iommu_phys_to_ppn(vcpu_info->hpa) |
		 FIELD_PREP(RISCV_IOMMU_MSIPTE_V, 1);

	if (pte->pte != pteval) {
		pte->pte = pteval;
		riscv_iommu_ir_msitbl_inval(domain, pte);
	}

	ret = 0;

out_unlock:
	spin_unlock(&domain->msi_lock);
	return ret;
}

static struct irq_chip riscv_iommu_irq_chip = {
	.name			= "IOMMU-IR",
	.irq_mask		= irq_chip_mask_parent,
	.irq_unmask		= irq_chip_unmask_parent,
	.irq_set_vcpu_affinity	= riscv_iommu_irq_set_vcpu_affinity,
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
