// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2025 Ventana Micro Systems Inc.
 */

#include <linux/kvm_host.h>

DEFINE_STATIC_KEY_FALSE(kvm_riscv_nested_available);

static bool __read_mostly enable_nested_virt = false;
module_param(enable_nested_virt, bool, 0644);

int kvm_riscv_vcpu_nested_gstage_xlate(struct kvm_vcpu *vcpu,
				       const struct kvm_cpu_trap *trap,
				       struct kvm_gstage_mapping *out_map,
				       struct kvm_cpu_trap *out_trap)
{
	/* TODO: */
	return 0;
}

void kvm_riscv_vcpu_nested_swtlb_flush_host(struct kvm_vcpu *vcpu,
					    gpa_t addr, gpa_t size, unsigned long order)
{
	/* TODO: */
}

void kvm_riscv_vcpu_nested_swtlb_process(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_nested *ns = &vcpu->arch.nested;

	WARN_ON(!ns->swtlb_request.pending);

	/* TODO: */

	ns->swtlb_request.pending = false;
}

void kvm_riscv_vcpu_nested_swtlb_request(struct kvm_vcpu *vcpu,
					 const struct kvm_gstage_mapping *guest_map,
					 const struct kvm_gstage_mapping *host_map)
{
	struct kvm_vcpu_nested *ns = &vcpu->arch.nested;

	WARN_ON(ns->swtlb_request.pending);

	ns->swtlb_request.pending = true;
	memcpy(&ns->swtlb_request.guest, guest_map, sizeof(*guest_map));
	memcpy(&ns->swtlb_request.host, host_map, sizeof(*host_map));

	kvm_make_request(KVM_REQ_NESTED_SWTLB, vcpu);
}

void kvm_riscv_vcpu_nested_reset(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_nested *ns = &vcpu->arch.nested;
	struct kvm_vcpu_nested_csr *ncsr = &vcpu->arch.nested.csr;

	ns->virt = false;
	memset(&ns->swtlb_request, 0, sizeof(ns->swtlb_request));
	memset(ncsr, 0, sizeof(*ncsr));
}

void kvm_riscv_nested_init(void)
{
	/*
	 * Nested virtualization uses hvictl CSR hence only
	 * available when AIA is available.
	 */
	if (!kvm_riscv_aia_available())
		return;

	/* Check state of module parameter */
	if (!enable_nested_virt)
		return;

	/* Enable KVM nested virtualization support */
	static_branch_enable(&kvm_riscv_nested_available);
}
