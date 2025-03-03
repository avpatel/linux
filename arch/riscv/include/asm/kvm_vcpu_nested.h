/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025 Ventana Micro Systems Inc.
 */

#ifndef __RISCV_VCPU_NESTED_H__
#define __RISCV_VCPU_NESTED_H__

#include <linux/jump_label.h>
#include <linux/kvm_types.h>

DECLARE_STATIC_KEY_FALSE(kvm_riscv_nested_available);
#define kvm_riscv_nested_available() \
	static_branch_unlikely(&kvm_riscv_nested_available)

struct kvm_vcpu_nested_csr {
	unsigned long hstatus;
	unsigned long hedeleg;
	unsigned long hideleg;
	unsigned long hvip;
	unsigned long hcounteren;
	unsigned long htimedelta;
	unsigned long htimedeltah;
	unsigned long htval;
	unsigned long htinst;
	unsigned long henvcfg;
	unsigned long henvcfgh;
	unsigned long hgatp;
	unsigned long vsstatus;
	unsigned long vsie;
	unsigned long vstvec;
	unsigned long vsscratch;
	unsigned long vsepc;
	unsigned long vscause;
	unsigned long vstval;
	unsigned long vsatp;
};

struct kvm_vcpu_nested {
	/* Nested virt state */
	bool virt;

	/* Nested CSR state */
	struct kvm_vcpu_nested_csr csr;
};

void kvm_riscv_vcpu_nested_reset(struct kvm_vcpu *vcpu);
void kvm_riscv_nested_init(void);

#endif
