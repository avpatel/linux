// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2025 Ventana Micro Systems Inc.
 */

#include <linux/kvm_host.h>
#include <asm/kvm_nacl.h>

DEFINE_STATIC_KEY_FALSE(kvm_riscv_nested_available);

static bool __read_mostly enable_nested_virt;
module_param(enable_nested_virt, bool, 0644);

int kvm_riscv_vcpu_nested_gstage_xlate(struct kvm_vcpu *vcpu,
				       const struct kvm_cpu_trap *trap,
				       struct kvm_gstage_mapping *out_map,
				       struct kvm_cpu_trap *out_trap)
{
	/* TODO: */
	return 0;
}

void kvm_riscv_vcpu_nested_vvma_flush_guest(struct kvm_vcpu *vcpu,
					    unsigned long vaddr, unsigned long size,
					    unsigned long order, unsigned long vmid)
{
	struct kvm_vcpu_nested *ns = &vcpu->arch.nested;
	struct kvm_vmid *v = &vcpu->kvm->arch.vmid;

	if (vmid != -1UL && ((ns->csr.hgatp & HGATP_VMID) >> HGATP_VMID_SHIFT) != vmid)
		return;

	vmid = kvm_riscv_gstage_nested_vmid(READ_ONCE(v->vmid));
	if (!vaddr && !size && !order) {
		if (kvm_riscv_nacl_available())
			nacl_hfence_vvma_all(nacl_shmem(), vmid);
		else
			kvm_riscv_local_hfence_vvma_all(vmid);
	} else {
		if (kvm_riscv_nacl_available())
			nacl_hfence_vvma(nacl_shmem(), vmid, vaddr, size, order);
		else
			kvm_riscv_local_hfence_vvma_gva(vmid, vaddr, size, order);
	}
}

void kvm_riscv_vcpu_nested_vvma_flush_guest_asid(struct kvm_vcpu *vcpu,
						 unsigned long vaddr, unsigned long size,
						 unsigned long order, unsigned long vmid,
						 unsigned long asid)
{
	struct kvm_vcpu_nested *ns = &vcpu->arch.nested;
	struct kvm_vmid *v = &vcpu->kvm->arch.vmid;

	if (vmid != -1UL && ((ns->csr.hgatp & HGATP_VMID) >> HGATP_VMID_SHIFT) != vmid)
		return;

	vmid = kvm_riscv_gstage_nested_vmid(READ_ONCE(v->vmid));
	if (!vaddr && !size && !order) {
		if (kvm_riscv_nacl_available())
			nacl_hfence_vvma_asid_all(nacl_shmem(), vmid, asid);
		else
			kvm_riscv_local_hfence_vvma_asid_all(vmid, asid);
	} else {
		if (kvm_riscv_nacl_available())
			nacl_hfence_vvma_asid(nacl_shmem(), vmid, asid,
					      vaddr, size, order);
		else
			kvm_riscv_local_hfence_vvma_asid_gva(vmid, asid, vaddr,
							     size, order);
	}
}

void kvm_riscv_vcpu_nested_gvma_flush_guest(struct kvm_vcpu *vcpu,
					    gpa_t addr, gpa_t size, unsigned long order)
{
	/* TODO: */
}

void kvm_riscv_vcpu_nested_gvma_flush_guest_vmid(struct kvm_vcpu *vcpu,
						 gpa_t addr, gpa_t size, unsigned long order,
						 unsigned long vmid)
{
	struct kvm_vcpu_nested *ns = &vcpu->arch.nested;

	if (vmid != -1UL && ((ns->csr.hgatp & HGATP_VMID) >> HGATP_VMID_SHIFT) != vmid)
		return;

	kvm_riscv_vcpu_nested_gvma_flush_guest(vcpu, addr, size, order);
}

void kvm_riscv_vcpu_nested_gvma_flush_host(struct kvm_vcpu *vcpu,
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

void kvm_riscv_vcpu_nested_set_virt(struct kvm_vcpu *vcpu,
				    enum kvm_vcpu_nested_set_virt_event event,
				    bool virt, bool svpv, bool gva)
{
	/* TODO: */
}

void kvm_riscv_vcpu_nested_vsirq_process(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_nested *ns = &vcpu->arch.nested;

	/* Do nothing if nested virtualization is OFF */
	if (!ns->virt)
		return;

	/* TODO: */
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
