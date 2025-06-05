// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2025 Ventana Micro Systems Inc.
 */

#include <linux/kvm_host.h>

int kvm_riscv_vcpu_nested_swtlb_xlate(struct kvm_vcpu *vcpu,
				      const struct kvm_cpu_trap *trap,
				      struct kvm_gstage_mapping *out_map,
				      struct kvm_cpu_trap *out_trap)
{
	/* TODO: */
	return 0;
}

void kvm_riscv_vcpu_nested_swtlb_process(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_nested_swtlb *nst = &vcpu->arch.nested.swtlb;

	WARN_ON(!nst->request.pending);

	/* TODO: */

	nst->request.pending = false;
}

void kvm_riscv_vcpu_nested_swtlb_request(struct kvm_vcpu *vcpu,
					 const struct kvm_gstage_mapping *guest_map,
					 const struct kvm_gstage_mapping *host_map)
{
	struct kvm_vcpu_nested_swtlb *nst = &vcpu->arch.nested.swtlb;

	WARN_ON(nst->request.pending);

	nst->request.pending = true;
	memcpy(&nst->request.guest, guest_map, sizeof(*guest_map));
	memcpy(&nst->request.host, host_map, sizeof(*host_map));

	kvm_make_request(KVM_REQ_NESTED_SWTLB, vcpu);
}

void kvm_riscv_vcpu_nested_swtlb_reset(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_nested_swtlb *nst = &vcpu->arch.nested.swtlb;

	memset(nst, 0, sizeof(*nst));
}

int kvm_riscv_vcpu_nested_swtlb_init(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_nested_swtlb *nst = &vcpu->arch.nested.swtlb;
	struct page *pgd_page;

	pgd_page = alloc_pages(GFP_KERNEL | __GFP_ZERO,
			       get_order(kvm_riscv_gstage_pgd_size));
	if (!pgd_page)
		return -ENOMEM;
	nst->shadow_pgd = page_to_virt(pgd_page);
	nst->shadow_pgd_phys = page_to_phys(pgd_page);

	return 0;
}

void kvm_riscv_vcpu_nested_swtlb_deinit(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_nested_swtlb *nst = &vcpu->arch.nested.swtlb;

	free_pages((unsigned long)nst->shadow_pgd, get_order(kvm_riscv_gstage_pgd_size));
}
