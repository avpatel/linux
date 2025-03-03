// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2025 Ventana Micro Systems Inc.
 */

#include <linux/kvm_host.h>

DEFINE_STATIC_KEY_FALSE(kvm_riscv_nested_available);

static bool __read_mostly enable_nested_virt = false;
module_param(enable_nested_virt, bool, 0644);

void kvm_riscv_vcpu_nested_reset(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_nested *ns = &vcpu->arch.nested;
	struct kvm_vcpu_nested_csr *ncsr = &vcpu->arch.nested.csr;

	ns->virt = false;
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
