// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Qualcomm Technologies, Inc.
 */

#include <linux/errno.h>
#include <linux/kvm_host.h>
#include <linux/cpufeature.h>
#include <linux/pgtable.h>
#include <asm/kvm_isa.h>
#include <asm/vector.h>

struct kvm_isa_ext {
	unsigned long ext;
	bool nested;
};

#define KVM_ISA_EXT_ARR(ext, nested)		\
[KVM_RISCV_ISA_EXT_##ext] = { RISCV_ISA_EXT_##ext, nested }

/* Mapping between KVM ISA Extension ID & guest ISA extension ID */
static const struct kvm_isa_ext kvm_isa_ext_arr[] = {
	/* Single letter extensions (alphabetically sorted) */
	[KVM_RISCV_ISA_EXT_A] = { RISCV_ISA_EXT_a, true },
	[KVM_RISCV_ISA_EXT_C] = { RISCV_ISA_EXT_c, true },
	[KVM_RISCV_ISA_EXT_D] = { RISCV_ISA_EXT_d, true },
	[KVM_RISCV_ISA_EXT_F] = { RISCV_ISA_EXT_f, true },
	[KVM_RISCV_ISA_EXT_H] = { RISCV_ISA_EXT_h, true },
	[KVM_RISCV_ISA_EXT_I] = { RISCV_ISA_EXT_i, true },
	[KVM_RISCV_ISA_EXT_M] = { RISCV_ISA_EXT_m, true },
	[KVM_RISCV_ISA_EXT_V] = { RISCV_ISA_EXT_v, true },
	/* Multi letter extensions (alphabetically sorted) */
	KVM_ISA_EXT_ARR(SMNPM, false),
	KVM_ISA_EXT_ARR(SMSTATEEN, false),
	KVM_ISA_EXT_ARR(SSAIA, false),
	KVM_ISA_EXT_ARR(SSCOFPMF, false),
	KVM_ISA_EXT_ARR(SSNPM, false),
	KVM_ISA_EXT_ARR(SSTC, false),
	KVM_ISA_EXT_ARR(SVADE, true),
	KVM_ISA_EXT_ARR(SVADU, true),
	KVM_ISA_EXT_ARR(SVINVAL, false),
	KVM_ISA_EXT_ARR(SVNAPOT, false),
	KVM_ISA_EXT_ARR(SVPBMT, false),
	KVM_ISA_EXT_ARR(SVVPTC, true),
	KVM_ISA_EXT_ARR(ZAAMO, true),
	KVM_ISA_EXT_ARR(ZABHA, true),
	KVM_ISA_EXT_ARR(ZACAS, true),
	KVM_ISA_EXT_ARR(ZALASR, true),
	KVM_ISA_EXT_ARR(ZALRSC, true),
	KVM_ISA_EXT_ARR(ZAWRS, false),
	KVM_ISA_EXT_ARR(ZBA, true),
	KVM_ISA_EXT_ARR(ZBB, true),
	KVM_ISA_EXT_ARR(ZBC, true),
	KVM_ISA_EXT_ARR(ZBKB, true),
	KVM_ISA_EXT_ARR(ZBKC, true),
	KVM_ISA_EXT_ARR(ZBKX, true),
	KVM_ISA_EXT_ARR(ZBS, true),
	KVM_ISA_EXT_ARR(ZCA, true),
	KVM_ISA_EXT_ARR(ZCB, true),
	KVM_ISA_EXT_ARR(ZCD, true),
	KVM_ISA_EXT_ARR(ZCF, true),
	KVM_ISA_EXT_ARR(ZCLSD, true),
	KVM_ISA_EXT_ARR(ZCMOP, true),
	KVM_ISA_EXT_ARR(ZFA, true),
	KVM_ISA_EXT_ARR(ZFBFMIN, true),
	KVM_ISA_EXT_ARR(ZFH, true),
	KVM_ISA_EXT_ARR(ZFHMIN, true),
	KVM_ISA_EXT_ARR(ZICBOM, false),
	KVM_ISA_EXT_ARR(ZICBOP, false),
	KVM_ISA_EXT_ARR(ZICBOZ, false),
	KVM_ISA_EXT_ARR(ZICCRSE, true),
	KVM_ISA_EXT_ARR(ZICNTR, true),
	KVM_ISA_EXT_ARR(ZICOND, true),
	KVM_ISA_EXT_ARR(ZICSR, true),
	KVM_ISA_EXT_ARR(ZIFENCEI, true),
	KVM_ISA_EXT_ARR(ZIHINTNTL, true),
	KVM_ISA_EXT_ARR(ZIHINTPAUSE, true),
	KVM_ISA_EXT_ARR(ZIHPM, true),
	KVM_ISA_EXT_ARR(ZILSD, true),
	KVM_ISA_EXT_ARR(ZIMOP, true),
	KVM_ISA_EXT_ARR(ZKND, true),
	KVM_ISA_EXT_ARR(ZKNE, true),
	KVM_ISA_EXT_ARR(ZKNH, true),
	KVM_ISA_EXT_ARR(ZKR, true),
	KVM_ISA_EXT_ARR(ZKSED, true),
	KVM_ISA_EXT_ARR(ZKSH, true),
	KVM_ISA_EXT_ARR(ZKT, true),
	KVM_ISA_EXT_ARR(ZTSO, true),
	KVM_ISA_EXT_ARR(ZVBB, true),
	KVM_ISA_EXT_ARR(ZVBC, true),
	KVM_ISA_EXT_ARR(ZVFBFMIN, true),
	KVM_ISA_EXT_ARR(ZVFBFWMA, true),
	KVM_ISA_EXT_ARR(ZVFH, true),
	KVM_ISA_EXT_ARR(ZVFHMIN, true),
	KVM_ISA_EXT_ARR(ZVKB, true),
	KVM_ISA_EXT_ARR(ZVKG, true),
	KVM_ISA_EXT_ARR(ZVKNED, true),
	KVM_ISA_EXT_ARR(ZVKNHA, true),
	KVM_ISA_EXT_ARR(ZVKNHB, true),
	KVM_ISA_EXT_ARR(ZVKSED, true),
	KVM_ISA_EXT_ARR(ZVKSH, true),
	KVM_ISA_EXT_ARR(ZVKT, true),
};

unsigned long kvm_riscv_base2isa_ext(unsigned long base_ext)
{
	unsigned long i;

	for (i = 0; i < KVM_RISCV_ISA_EXT_MAX; i++) {
		if (kvm_isa_ext_arr[i].ext == base_ext)
			return i;
	}

	return KVM_RISCV_ISA_EXT_MAX;
}

int __kvm_riscv_isa_check_host(unsigned long ext, unsigned long *base_ext)
{
	unsigned long host_ext;

	if (ext >= KVM_RISCV_ISA_EXT_MAX ||
	    ext >= ARRAY_SIZE(kvm_isa_ext_arr))
		return -ENOENT;

	if (kvm_riscv_nested_available() && !kvm_isa_ext_arr[ext].nested)
		return -ENOENT;

	switch (kvm_isa_ext_arr[ext].ext) {
	case RISCV_ISA_EXT_SMNPM:
		/*
		 * Pointer masking effective in (H)S-mode is provided by the
		 * Smnpm extension, so that extension is reported to the guest,
		 * even though the CSR bits for configuring VS-mode pointer
		 * masking on the host side are part of the Ssnpm extension.
		 */
		host_ext = RISCV_ISA_EXT_SSNPM;
		break;
	default:
		host_ext = kvm_isa_ext_arr[ext].ext;
		break;
	}

	if (!__riscv_isa_extension_available(NULL, host_ext))
		return -ENOENT;

	if (base_ext)
		*base_ext = kvm_isa_ext_arr[ext].ext;

	return 0;
}

bool kvm_riscv_isa_enable_allowed(unsigned long ext)
{
	switch (ext) {
	case KVM_RISCV_ISA_EXT_H:
		return kvm_riscv_nested_available();
	case KVM_RISCV_ISA_EXT_SSCOFPMF:
		/* Sscofpmf depends on interrupt filtering defined in ssaia */
		return !kvm_riscv_isa_check_host(SSAIA);
	case KVM_RISCV_ISA_EXT_SVADU:
		/*
		 * The henvcfg.ADUE is read-only zero if menvcfg.ADUE is zero.
		 * Guest OS can use Svadu only when host OS enable Svadu.
		 */
		return arch_has_hw_pte_young();
	case KVM_RISCV_ISA_EXT_V:
		return riscv_v_vstate_ctrl_user_allowed();
	default:
		break;
	}

	return true;
}

bool kvm_riscv_isa_disable_allowed(unsigned long ext)
{
	switch (ext) {
	/* Extensions which don't have any mechanism to disable */
	case KVM_RISCV_ISA_EXT_A:
	case KVM_RISCV_ISA_EXT_C:
	case KVM_RISCV_ISA_EXT_I:
	case KVM_RISCV_ISA_EXT_M:
	/* There is not architectural config bit to disable sscofpmf completely */
	case KVM_RISCV_ISA_EXT_SSCOFPMF:
	case KVM_RISCV_ISA_EXT_SSNPM:
	case KVM_RISCV_ISA_EXT_SSTC:
	case KVM_RISCV_ISA_EXT_SVINVAL:
	case KVM_RISCV_ISA_EXT_SVNAPOT:
	case KVM_RISCV_ISA_EXT_SVVPTC:
	case KVM_RISCV_ISA_EXT_ZAAMO:
	case KVM_RISCV_ISA_EXT_ZABHA:
	case KVM_RISCV_ISA_EXT_ZACAS:
	case KVM_RISCV_ISA_EXT_ZALASR:
	case KVM_RISCV_ISA_EXT_ZALRSC:
	case KVM_RISCV_ISA_EXT_ZAWRS:
	case KVM_RISCV_ISA_EXT_ZBA:
	case KVM_RISCV_ISA_EXT_ZBB:
	case KVM_RISCV_ISA_EXT_ZBC:
	case KVM_RISCV_ISA_EXT_ZBKB:
	case KVM_RISCV_ISA_EXT_ZBKC:
	case KVM_RISCV_ISA_EXT_ZBKX:
	case KVM_RISCV_ISA_EXT_ZBS:
	case KVM_RISCV_ISA_EXT_ZCA:
	case KVM_RISCV_ISA_EXT_ZCB:
	case KVM_RISCV_ISA_EXT_ZCD:
	case KVM_RISCV_ISA_EXT_ZCF:
	case KVM_RISCV_ISA_EXT_ZCMOP:
	case KVM_RISCV_ISA_EXT_ZFA:
	case KVM_RISCV_ISA_EXT_ZFBFMIN:
	case KVM_RISCV_ISA_EXT_ZFH:
	case KVM_RISCV_ISA_EXT_ZFHMIN:
	case KVM_RISCV_ISA_EXT_ZICBOP:
	case KVM_RISCV_ISA_EXT_ZICCRSE:
	case KVM_RISCV_ISA_EXT_ZICNTR:
	case KVM_RISCV_ISA_EXT_ZICOND:
	case KVM_RISCV_ISA_EXT_ZICSR:
	case KVM_RISCV_ISA_EXT_ZIFENCEI:
	case KVM_RISCV_ISA_EXT_ZIHINTNTL:
	case KVM_RISCV_ISA_EXT_ZIHINTPAUSE:
	case KVM_RISCV_ISA_EXT_ZIHPM:
	case KVM_RISCV_ISA_EXT_ZIMOP:
	case KVM_RISCV_ISA_EXT_ZKND:
	case KVM_RISCV_ISA_EXT_ZKNE:
	case KVM_RISCV_ISA_EXT_ZKNH:
	case KVM_RISCV_ISA_EXT_ZKR:
	case KVM_RISCV_ISA_EXT_ZKSED:
	case KVM_RISCV_ISA_EXT_ZKSH:
	case KVM_RISCV_ISA_EXT_ZKT:
	case KVM_RISCV_ISA_EXT_ZTSO:
	case KVM_RISCV_ISA_EXT_ZVBB:
	case KVM_RISCV_ISA_EXT_ZVBC:
	case KVM_RISCV_ISA_EXT_ZVFBFMIN:
	case KVM_RISCV_ISA_EXT_ZVFBFWMA:
	case KVM_RISCV_ISA_EXT_ZVFH:
	case KVM_RISCV_ISA_EXT_ZVFHMIN:
	case KVM_RISCV_ISA_EXT_ZVKB:
	case KVM_RISCV_ISA_EXT_ZVKG:
	case KVM_RISCV_ISA_EXT_ZVKNED:
	case KVM_RISCV_ISA_EXT_ZVKNHA:
	case KVM_RISCV_ISA_EXT_ZVKNHB:
	case KVM_RISCV_ISA_EXT_ZVKSED:
	case KVM_RISCV_ISA_EXT_ZVKSH:
	case KVM_RISCV_ISA_EXT_ZVKT:
		return false;
	/* Extensions which can be disabled using Smstateen */
	case KVM_RISCV_ISA_EXT_SSAIA:
		return riscv_has_extension_unlikely(RISCV_ISA_EXT_SMSTATEEN);
	case KVM_RISCV_ISA_EXT_SVADE:
		/*
		 * The henvcfg.ADUE is read-only zero if menvcfg.ADUE is zero.
		 * Svade can't be disabled unless we support Svadu.
		 */
		return arch_has_hw_pte_young();
	default:
		break;
	}

	return true;
}
