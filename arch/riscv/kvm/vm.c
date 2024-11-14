// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019 Western Digital Corporation or its affiliates.
 *
 * Authors:
 *     Anup Patel <anup.patel@wdc.com>
 */

#include <linux/errno.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/kvm_host.h>
#include <linux/kvm_irqfd.h>

#include <asm/kvm_aia.h>

const struct _kvm_stats_desc kvm_vm_stats_desc[] = {
	KVM_GENERIC_VM_STATS()
};
static_assert(ARRAY_SIZE(kvm_vm_stats_desc) ==
		sizeof(struct kvm_vm_stat) / sizeof(u64));

const struct kvm_stats_header kvm_vm_stats_header = {
	.name_size = KVM_STATS_NAME_SIZE,
	.num_desc = ARRAY_SIZE(kvm_vm_stats_desc),
	.id_offset =  sizeof(struct kvm_stats_header),
	.desc_offset = sizeof(struct kvm_stats_header) + KVM_STATS_NAME_SIZE,
	.data_offset = sizeof(struct kvm_stats_header) + KVM_STATS_NAME_SIZE +
		       sizeof(kvm_vm_stats_desc),
};

int kvm_arch_init_vm(struct kvm *kvm, unsigned long type)
{
	int r;

	r = kvm_riscv_gstage_alloc_pgd(kvm);
	if (r)
		return r;

	r = kvm_riscv_gstage_vmid_init(kvm);
	if (r) {
		kvm_riscv_gstage_free_pgd(kvm);
		return r;
	}

	kvm_riscv_aia_init_vm(kvm);

	kvm_riscv_guest_timer_init(kvm);

	return 0;
}

void kvm_arch_destroy_vm(struct kvm *kvm)
{
	kvm_destroy_vcpus(kvm);

	kvm_riscv_aia_destroy_vm(kvm);
}

void kvm_arch_start_assignment(struct kvm *kvm)
{
	atomic_inc(&kvm->arch.assigned_device_count);
}
EXPORT_SYMBOL_GPL(kvm_arch_start_assignment);

void kvm_arch_end_assignment(struct kvm *kvm)
{
	atomic_dec(&kvm->arch.assigned_device_count);
}
EXPORT_SYMBOL_GPL(kvm_arch_end_assignment);

bool noinstr kvm_arch_has_assigned_device(struct kvm *kvm)
{
	return arch_atomic_read(&kvm->arch.assigned_device_count);
}
EXPORT_SYMBOL_GPL(kvm_arch_has_assigned_device);

bool kvm_arch_has_irq_bypass(void)
{
	return false;
}

int kvm_arch_irq_bypass_add_producer(struct irq_bypass_consumer *cons,
				     struct irq_bypass_producer *prod)
{
	struct kvm_kernel_irqfd *irqfd =
		container_of(cons, struct kvm_kernel_irqfd, consumer);
	int ret;

	irqfd->producer = prod;
	kvm_arch_start_assignment(irqfd->kvm);
	ret = kvm_arch_update_irqfd_routing(irqfd->kvm, prod->irq, irqfd->gsi, true);
	if (ret)
		kvm_arch_end_assignment(irqfd->kvm);

	return ret;
}

void kvm_arch_irq_bypass_del_producer(struct irq_bypass_consumer *cons,
				      struct irq_bypass_producer *prod)
{
	struct kvm_kernel_irqfd *irqfd =
		container_of(cons, struct kvm_kernel_irqfd, consumer);
	int ret;

	WARN_ON(irqfd->producer != prod);
	irqfd->producer = NULL;

	ret = kvm_arch_update_irqfd_routing(irqfd->kvm, prod->irq, irqfd->gsi, false);
	if (ret)
		pr_info("irq bypass consumer (token %p) unregistration fails: %d\n",
			irqfd->consumer.token, ret);

	kvm_arch_end_assignment(irqfd->kvm);
}

int kvm_vm_ioctl_irq_line(struct kvm *kvm, struct kvm_irq_level *irql,
			  bool line_status)
{
	if (!irqchip_in_kernel(kvm))
		return -ENXIO;

	return kvm_riscv_aia_inject_irq(kvm, irql->irq, irql->level);
}

int kvm_set_msi(struct kvm_kernel_irq_routing_entry *e,
		struct kvm *kvm, int irq_source_id,
		int level, bool line_status)
{
	struct kvm_msi msi;

	if (!level)
		return -1;

	msi.address_lo = e->msi.address_lo;
	msi.address_hi = e->msi.address_hi;
	msi.data = e->msi.data;
	msi.flags = e->msi.flags;
	msi.devid = e->msi.devid;

	return kvm_riscv_aia_inject_msi(kvm, &msi);
}

static int kvm_riscv_set_irq(struct kvm_kernel_irq_routing_entry *e,
			     struct kvm *kvm, int irq_source_id,
			     int level, bool line_status)
{
	return kvm_riscv_aia_inject_irq(kvm, e->irqchip.pin, level);
}

int kvm_riscv_setup_default_irq_routing(struct kvm *kvm, u32 lines)
{
	struct kvm_irq_routing_entry *ents;
	int i, rc;

	ents = kcalloc(lines, sizeof(*ents), GFP_KERNEL);
	if (!ents)
		return -ENOMEM;

	for (i = 0; i < lines; i++) {
		ents[i].gsi = i;
		ents[i].type = KVM_IRQ_ROUTING_IRQCHIP;
		ents[i].u.irqchip.irqchip = 0;
		ents[i].u.irqchip.pin = i;
	}
	rc = kvm_set_irq_routing(kvm, ents, lines, 0);
	kfree(ents);

	return rc;
}

bool kvm_arch_can_set_irq_routing(struct kvm *kvm)
{
	return irqchip_in_kernel(kvm);
}

int kvm_set_routing_entry(struct kvm *kvm,
			  struct kvm_kernel_irq_routing_entry *e,
			  const struct kvm_irq_routing_entry *ue)
{
	int r = -EINVAL;

	switch (ue->type) {
	case KVM_IRQ_ROUTING_IRQCHIP:
		e->set = kvm_riscv_set_irq;
		e->irqchip.irqchip = ue->u.irqchip.irqchip;
		e->irqchip.pin = ue->u.irqchip.pin;
		if ((e->irqchip.pin >= KVM_IRQCHIP_NUM_PINS) ||
		    (e->irqchip.irqchip >= KVM_NR_IRQCHIPS))
			goto out;
		break;
	case KVM_IRQ_ROUTING_MSI:
		e->set = kvm_set_msi;
		e->msi.address_lo = ue->u.msi.address_lo;
		e->msi.address_hi = ue->u.msi.address_hi;
		e->msi.data = ue->u.msi.data;
		e->msi.flags = ue->flags;
		e->msi.devid = ue->u.msi.devid;
		break;
	default:
		goto out;
	}
	r = 0;
out:
	return r;
}

int kvm_arch_set_irq_inatomic(struct kvm_kernel_irq_routing_entry *e,
			      struct kvm *kvm, int irq_source_id, int level,
			      bool line_status)
{
	if (!level)
		return -EWOULDBLOCK;

	switch (e->type) {
	case KVM_IRQ_ROUTING_MSI:
		return kvm_set_msi(e, kvm, irq_source_id, level, line_status);

	case KVM_IRQ_ROUTING_IRQCHIP:
		return kvm_riscv_set_irq(e, kvm, irq_source_id,
					 level, line_status);
	}

	return -EWOULDBLOCK;
}

bool kvm_arch_irqchip_in_kernel(struct kvm *kvm)
{
	return irqchip_in_kernel(kvm);
}

int kvm_vm_ioctl_check_extension(struct kvm *kvm, long ext)
{
	int r;

	switch (ext) {
	case KVM_CAP_IRQCHIP:
		r = kvm_riscv_aia_available();
		break;
	case KVM_CAP_IOEVENTFD:
	case KVM_CAP_USER_MEMORY:
	case KVM_CAP_SYNC_MMU:
	case KVM_CAP_DESTROY_MEMORY_REGION_WORKS:
	case KVM_CAP_ONE_REG:
	case KVM_CAP_READONLY_MEM:
	case KVM_CAP_MP_STATE:
	case KVM_CAP_IMMEDIATE_EXIT:
	case KVM_CAP_SET_GUEST_DEBUG:
		r = 1;
		break;
	case KVM_CAP_NR_VCPUS:
		r = min_t(unsigned int, num_online_cpus(), KVM_MAX_VCPUS);
		break;
	case KVM_CAP_MAX_VCPUS:
		r = KVM_MAX_VCPUS;
		break;
	case KVM_CAP_NR_MEMSLOTS:
		r = KVM_USER_MEM_SLOTS;
		break;
	case KVM_CAP_VM_GPA_BITS:
		r = kvm_riscv_gstage_gpa_bits();
		break;
	default:
		r = 0;
		break;
	}

	return r;
}

int kvm_arch_vm_ioctl(struct file *filp, unsigned int ioctl, unsigned long arg)
{
	return -EINVAL;
}
