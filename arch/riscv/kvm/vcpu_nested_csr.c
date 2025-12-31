// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Qualcomm Technologies, Inc.
 */

#include <linux/kvm_host.h>

void kvm_riscv_vcpu_nested_csr_reset(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_nested_csr *nsc;

	if (!kvm_riscv_nested_available())
		return;

	nsc = vcpu->arch.nested.csr;
	memset(nsc, 0, sizeof(*nsc));
}

int kvm_riscv_vcpu_nested_csr_init(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_nested_csr *nsc;

	if (!kvm_riscv_nested_available())
		return 0;

	nsc = kzalloc_obj(*nsc);
	if (!nsc)
		return -ENOMEM;
	vcpu->arch.nested.csr = nsc;

	return 0;
}

void kvm_riscv_vcpu_nested_csr_deinit(struct kvm_vcpu *vcpu)
{
	if (!kvm_riscv_nested_available())
		return;

	kfree(vcpu->arch.nested.csr);
	vcpu->arch.nested.csr = NULL;
}
