// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2025 Ventana Micro Systems Inc.
 */

#include <linux/kvm_host.h>
#include <asm/kvm_nacl.h>

#define KVM_HEDELEG_DEFAULT	(BIT(EXC_INST_MISALIGNED) | \
				 BIT(EXC_INST_ILLEGAL)     | \
				 BIT(EXC_BREAKPOINT)      | \
				 BIT(EXC_SYSCALL)         | \
				 BIT(EXC_INST_PAGE_FAULT) | \
				 BIT(EXC_LOAD_PAGE_FAULT) | \
				 BIT(EXC_STORE_PAGE_FAULT))

#define KVM_HIDELEG_DEFAULT	(BIT(IRQ_VS_SOFT)  | \
				 BIT(IRQ_VS_TIMER) | \
				 BIT(IRQ_VS_EXT))

void kvm_riscv_vcpu_config_init(struct kvm_vcpu *vcpu)
{
	vcpu->arch.cfg.hedeleg = KVM_HEDELEG_DEFAULT;
	vcpu->arch.cfg.hideleg = KVM_HIDELEG_DEFAULT;
}

void kvm_riscv_vcpu_config_guest_debug(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_config *cfg = &vcpu->arch.cfg;

	if (vcpu->guest_debug)
		cfg->hedeleg &= ~BIT(EXC_BREAKPOINT);
	else
		cfg->hedeleg |= BIT(EXC_BREAKPOINT);
}

void kvm_riscv_vcpu_config_ran_once(struct kvm_vcpu *vcpu)
{
	const unsigned long *isa = vcpu->arch.isa;
	struct kvm_vcpu_config *cfg = &vcpu->arch.cfg;

	if (riscv_isa_extension_available(isa, SVPBMT))
		cfg->henvcfg |= ENVCFG_PBMTE;

	if (riscv_isa_extension_available(isa, SSTC))
		cfg->henvcfg |= ENVCFG_STCE;

	if (riscv_isa_extension_available(isa, ZICBOM))
		cfg->henvcfg |= (ENVCFG_CBIE | ENVCFG_CBCFE);

	if (riscv_isa_extension_available(isa, ZICBOZ))
		cfg->henvcfg |= ENVCFG_CBZE;

	if (riscv_isa_extension_available(isa, SVADU) &&
	    !riscv_isa_extension_available(isa, SVADE))
		cfg->henvcfg |= ENVCFG_ADUE;

	if (riscv_has_extension_unlikely(RISCV_ISA_EXT_SMSTATEEN)) {
		cfg->hstateen0 |= SMSTATEEN0_HSENVCFG;
		if (riscv_isa_extension_available(isa, SSAIA))
			cfg->hstateen0 |= SMSTATEEN0_AIA_IMSIC |
					  SMSTATEEN0_AIA |
					  SMSTATEEN0_AIA_ISEL;
		if (riscv_isa_extension_available(isa, SMSTATEEN))
			cfg->hstateen0 |= SMSTATEEN0_SSTATEEN0;
	}

	if (vcpu->guest_debug)
		cfg->hedeleg &= ~BIT(EXC_BREAKPOINT);
}

void kvm_riscv_vcpu_config_load(struct kvm_vcpu *vcpu, bool nested_virt)
{
	struct kvm_vcpu_nested_csr *nsc = &vcpu->arch.nested.csr;
	struct kvm_vcpu_config *cfg = &vcpu->arch.cfg;
	unsigned long hedeleg, hideleg, tmp;
	u64 henvcfg, hstateen0;
	void *nsh;

	if (nested_virt){
		hedeleg = nsc->hedeleg;
		hideleg = 0;
		henvcfg = 0;
		hstateen0 = 0;
	} else {
		hedeleg = cfg->hedeleg;
		hideleg = cfg->hideleg;
		henvcfg = cfg->henvcfg;
		hstateen0 = cfg->hstateen0;
	}

	if (kvm_riscv_nacl_sync_csr_available()) {
		nsh = nacl_shmem();
		nacl_csr_write(nsh, CSR_HEDELEG, hedeleg);
		nacl_csr_write(nsh, CSR_HIDELEG, hideleg);
		nacl_csr_write(nsh, CSR_HENVCFG, henvcfg);
		if (IS_ENABLED(CONFIG_32BIT))
			nacl_csr_write(nsh, CSR_HENVCFGH, henvcfg >> 32);
		if (riscv_has_extension_unlikely(RISCV_ISA_EXT_SMSTATEEN)) {
			nacl_csr_write(nsh, CSR_HSTATEEN0, hstateen0);
			if (IS_ENABLED(CONFIG_32BIT))
				nacl_csr_write(nsh, CSR_HSTATEEN0H, hstateen0 >> 32);
		}
		if (kvm_riscv_aia_available()) {
			tmp = nacl_csr_read(nsh, CSR_HVICTL);
			if (nested_virt)
				tmp |= HVICTL_VTI;
			else
				tmp &= ~HVICTL_VTI;
			nacl_csr_write(nsh, CSR_HVICTL, tmp);
		}
	} else {
		csr_write(CSR_HEDELEG, hedeleg);
		csr_write(CSR_HIDELEG, hideleg);
		csr_write(CSR_HENVCFG, henvcfg);
		if (IS_ENABLED(CONFIG_32BIT))
			csr_write(CSR_HENVCFGH, henvcfg >> 32);
		if (riscv_has_extension_unlikely(RISCV_ISA_EXT_SMSTATEEN)) {
			csr_write(CSR_HSTATEEN0, hstateen0);
			if (IS_ENABLED(CONFIG_32BIT))
				csr_write(CSR_HSTATEEN0H, hstateen0 >> 32);
		}
		if (kvm_riscv_aia_available()) {
			if (nested_virt)
				csr_set(CSR_HVICTL, HVICTL_VTI);
			else
				csr_clear(CSR_HVICTL, HVICTL_VTI);
		}
	}
}
