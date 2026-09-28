// SPDX-License-Identifier: GPL-2.0-only
/*
 * IOMMU Interrupt Remapping
 *
 * Copyright (c) 2026 Qualcomm Technologies, Inc.
 */
#include <linux/cleanup.h>
#include <linux/irqchip/riscv-imsic.h>
#include <linux/msi.h>
#include <linux/slab.h>

#include "iommu.h"

static int riscv_iommu_ir_irq_set_affinity(struct irq_data *data,
					   const struct cpumask *mask, bool force)
{
	if (irqd_is_forwarded_to_vcpu(data))
		return -EINVAL;

	return irq_chip_set_affinity_parent(data, mask, force);
}

static int riscv_iommu_ir_activate(struct riscv_iommu_msi_table *msi_table,
				   struct riscv_iommu_ir_vcpu_info *vcpu_info)
{
	return -EOPNOTSUPP;
}

static int riscv_iommu_ir_deactivate(struct riscv_iommu_msi_table *msi_table)
{
	return -EOPNOTSUPP;
}

static int riscv_iommu_ir_update_target(struct riscv_iommu_msi_table *msi_table,
					struct riscv_iommu_ir_vcpu_info *vcpu_info)
{
	return -EOPNOTSUPP;
}

static int riscv_iommu_ir_irq_set_vcpu_affinity_locked(struct irq_data *data,
						       struct riscv_iommu_info *info,
						       struct riscv_iommu_ir_vcpu_info *vcpu_info,
						       struct riscv_iommu_msi_table *msi_table)
{
	int ret;

	if (!vcpu_info) {
		if (WARN_ON_ONCE(!msi_table->nr_forwarded_irqs || !info->nr_forwarded_irqs))
			return -EINVAL;

		if (msi_table->nr_forwarded_irqs == 1) {
			ret = riscv_iommu_ir_deactivate(msi_table);
			if (ret)
				return ret;
		}

		msi_table->nr_forwarded_irqs--;
		info->nr_forwarded_irqs--;
		irqd_clr_forwarded_to_vcpu(data);

		if (!msi_table->nr_forwarded_irqs) {
			msi_table->owner = NULL;
			msi_table->msi_addr_mask = 0;
			msi_table->msi_addr_pattern = 0;
		}

		return 0;
	}

	if (!msi_table->nr_forwarded_irqs) {
		if (vcpu_info->cmd == RISCV_IOMMU_IR_UPDATE_TARGET ||
		    irqd_is_forwarded_to_vcpu(data))
			return -EINVAL;

		ret = riscv_iommu_ir_activate(msi_table, vcpu_info);
		if (ret)
			return ret;

		msi_table->nr_forwarded_irqs++;
		info->nr_forwarded_irqs++;
		irqd_set_forwarded_to_vcpu(data);

		return 0;
	}

	if (msi_table->owner != vcpu_info->owner ||
	    msi_table->msi_addr_mask != vcpu_info->msi_addr_mask ||
	    msi_table->msi_addr_pattern != vcpu_info->msi_addr_pattern)
		return -EOPNOTSUPP;

	if (vcpu_info->cmd == RISCV_IOMMU_IR_FORWARD) {
		if (!irqd_is_forwarded_to_vcpu(data)) {
			msi_table->nr_forwarded_irqs++;
			info->nr_forwarded_irqs++;
			irqd_set_forwarded_to_vcpu(data);
		}
		return 0;
	}

	return riscv_iommu_ir_update_target(msi_table, vcpu_info);
}

static int riscv_iommu_ir_irq_set_vcpu_affinity(struct irq_data *data, void *arg)
{
	struct riscv_iommu_ir_vcpu_info *vcpu_info = arg;
	struct riscv_iommu_msi_table *msi_table;
	struct riscv_iommu_info *info;
	struct msi_desc *desc;
	struct device *dev;
	int ret;

	if (!vcpu_info && !irqd_is_forwarded_to_vcpu(data))
		return 0;

	if (vcpu_info && vcpu_info->cmd != RISCV_IOMMU_IR_FORWARD &&
	    (vcpu_info->cmd != RISCV_IOMMU_IR_UPDATE_TARGET || !irqd_is_forwarded_to_vcpu(data)))
		return -EINVAL;

	desc = irq_data_get_msi_desc(data);
	if (WARN_ON_ONCE(!desc))
		return -EINVAL;

	dev = msi_desc_to_dev(desc);
	info = dev_iommu_priv_get(dev);
	if (WARN_ON_ONCE(!info))
		return -EINVAL;

	scoped_guard(rcu) {
		/*
		 * RCU keeps the table alive, but the device may switch domains before
		 * the table is locked. Recheck the association under the lock.
		 */
		for (;;) {
			msi_table = riscv_iommu_msi_table_rcu(info);
			if (!msi_table || !msi_table->root)
				return -EOPNOTSUPP;

			raw_spin_lock(&msi_table->lock);
			if (msi_table == riscv_iommu_msi_table_rcu(info))
				break;
			raw_spin_unlock(&msi_table->lock);
		}
	}

	ret = riscv_iommu_ir_irq_set_vcpu_affinity_locked(data, info, vcpu_info, msi_table);
	raw_spin_unlock(&msi_table->lock);

	return ret;
}

static struct irq_chip riscv_iommu_ir_irq_chip = {
	.name			= "IOMMU-IR",
	.irq_ack		= irq_chip_ack_parent,
	.irq_mask		= irq_chip_mask_parent,
	.irq_unmask		= irq_chip_unmask_parent,
	.irq_set_affinity	= riscv_iommu_ir_irq_set_affinity,
	.irq_set_vcpu_affinity	= riscv_iommu_ir_irq_set_vcpu_affinity,
};

static int riscv_iommu_ir_irq_domain_alloc_irqs(struct irq_domain *irqdomain,
						unsigned int irq_base, unsigned int nr_irqs,
						void *arg)
{
	int ret;

	ret = irq_domain_alloc_irqs_parent(irqdomain, irq_base, nr_irqs, arg);
	if (ret)
		return ret;

	for (unsigned int i = 0; i < nr_irqs; i++) {
		ret = irq_domain_set_hwirq_and_chip(irqdomain, irq_base + i,
						    irq_base + i,
						    &riscv_iommu_ir_irq_chip, NULL);
		if (ret) {
			irq_domain_free_irqs_parent(irqdomain, irq_base, nr_irqs);
			return ret;
		}
	}

	return 0;
}

static const struct irq_domain_ops riscv_iommu_ir_irq_domain_ops = {
	.alloc			= riscv_iommu_ir_irq_domain_alloc_irqs,
	.free			= irq_domain_free_irqs_parent,
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

static struct irq_domain *riscv_iommu_ir_irq_domain_create(struct riscv_iommu_device *iommu,
							   struct irq_domain *irqparent)
{
	char *fwname __free(kfree) = NULL;
	struct irq_domain *irqdomain;
	struct fwnode_handle *fn;

	fwname = kasprintf(GFP_KERNEL, "IOMMU-IR-%s", dev_name(iommu->dev));
	if (!fwname)
		return ERR_PTR(-ENOMEM);

	fn = irq_domain_alloc_named_fwnode(fwname);
	if (!fn)
		return ERR_PTR(-ENOMEM);

	irqdomain = irq_domain_create_hierarchy(irqparent, 0, 0, fn,
						&riscv_iommu_ir_irq_domain_ops, iommu);
	if (!irqdomain) {
		irq_domain_free_fwnode(fn);
		return ERR_PTR(-ENOMEM);
	}

	/*
	 * The RISC-V IOMMU doesn't validate MSI data, so we can't set
	 * IRQ_DOMAIN_FLAG_ISOLATED_MSI. The means VFIO requires its
	 * allow_unsafe_interrupts module parameter.
	 */
	irqdomain->flags |= IRQ_DOMAIN_FLAG_MSI_PARENT;
	irqdomain->msi_parent_ops = &riscv_iommu_ir_msi_parent_ops;
	irq_domain_update_bus_token(irqdomain, DOMAIN_BUS_MSI_REMAP);

	return irqdomain;
}

void riscv_iommu_ir_irq_domain_remove(struct riscv_iommu_device *iommu)
{
	struct irq_domain *irqdomain = iommu->irqdomain;
	struct fwnode_handle *fn;

	if (!irqdomain)
		return;

	fn = irqdomain->fwnode;
	irq_domain_remove(irqdomain);
	iommu->irqdomain = NULL;
	irq_domain_free_fwnode(fn);
}

int riscv_iommu_ir_probe_device(struct riscv_iommu_device *iommu, struct device *dev,
				struct riscv_iommu_info *info)
{
	struct irq_domain *msi_parent = dev_get_msi_domain(iommu->dev);
	struct irq_domain *irqdomain;

	info->old_msi_parent = NULL;

	if (iommu->fctl & RISCV_IOMMU_FCTL_WSI)
		msi_parent = imsic_get_base_domain();
	else if (!imsic_dev_has_imsic_msi_parent(iommu->dev))
		return 0;

	if (!msi_parent || dev_get_msi_domain(dev) != msi_parent)
		return 0;

	irqdomain = iommu->irqdomain;
	if (!irqdomain) {
		irqdomain = riscv_iommu_ir_irq_domain_create(iommu, msi_parent);
		if (IS_ERR(irqdomain))
			return PTR_ERR(irqdomain);
		iommu->irqdomain = irqdomain;
	} else if (irqdomain->parent != msi_parent) {
		return 0;
	}

	if (!device_link_add(dev, iommu->dev, DL_FLAG_AUTOREMOVE_SUPPLIER))
		return -ENODEV;

	info->old_msi_parent = msi_parent;
	dev_set_msi_domain(dev, irqdomain);

	return 0;
}

void riscv_iommu_ir_release_device(struct device *dev, struct riscv_iommu_info *info)
{
	if (info->old_msi_parent)
		dev_set_msi_domain(dev, info->old_msi_parent);
}
