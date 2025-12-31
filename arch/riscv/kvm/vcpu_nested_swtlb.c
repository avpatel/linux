// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Qualcomm Technologies, Inc.
 */

#include <linux/kvm_host.h>
#include <asm/kvm_gstage.h>
#include <asm/kvm_nacl.h>

struct kvm_vcpu_nested_swtlb {
	/* Software TLB request */
	struct {
		bool pending;
		struct kvm_gstage_mapping guest;
		struct kvm_gstage_mapping host;
	} request;

	/* Shadow G-stage page table for guest VS/VU-mode */
	pgd_t *shadow_pgd;
	phys_addr_t shadow_pgd_phys;
	unsigned long shadow_pgd_levels;
};

int kvm_riscv_vcpu_nested_swtlb_xlate(struct kvm_vcpu *vcpu,
				      const struct kvm_cpu_trap *trap,
				      struct kvm_gstage_mapping *out_map,
				      gpa_t *out_addr, struct kvm_cpu_trap *out_trap)
{
	if (!kvm_riscv_nested_available())
		return -ENOENT;

	/* TODO: */
	return 0;
}

void kvm_riscv_vcpu_nested_swtlb_vvma_flush(struct kvm_vcpu *vcpu,
					    unsigned long vaddr, unsigned long size,
					    unsigned long order, unsigned long vmid)
{
	struct kvm_vmid *v = &vcpu->kvm->arch.vmid;
	struct kvm_vcpu_nested_csr *nsc;

	if (!kvm_riscv_nested_available())
		return;

	nsc = vcpu->arch.nested.csr;
	if (vmid != -1UL && ((nsc->hgatp & HGATP_VMID) >> HGATP_VMID_SHIFT) != vmid)
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

void kvm_riscv_vcpu_nested_swtlb_vvma_flush_asid(struct kvm_vcpu *vcpu,
						 unsigned long vaddr, unsigned long size,
						 unsigned long order, unsigned long vmid,
						 unsigned long asid)
{
	struct kvm_vmid *v = &vcpu->kvm->arch.vmid;
	struct kvm_vcpu_nested_csr *nsc;

	if (!kvm_riscv_nested_available())
		return;

	nsc = vcpu->arch.nested.csr;
	if (vmid != -1UL && ((nsc->hgatp & HGATP_VMID) >> HGATP_VMID_SHIFT) != vmid)
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

void kvm_riscv_vcpu_nested_swtlb_gvma_flush(struct kvm_vcpu *vcpu,
					    gpa_t addr, gpa_t size, unsigned long order)
{
	if (!kvm_riscv_nested_available())
		return;

	/* TODO: */
}

void kvm_riscv_vcpu_nested_swtlb_gvma_flush_vmid(struct kvm_vcpu *vcpu,
						 gpa_t addr, gpa_t size, unsigned long order,
						 unsigned long vmid)
{
	struct kvm_vcpu_nested_csr *nsc;

	if (!kvm_riscv_nested_available())
		return;

	nsc = vcpu->arch.nested.csr;
	if (vmid != -1UL && ((nsc->hgatp & HGATP_VMID) >> HGATP_VMID_SHIFT) != vmid)
		return;

	kvm_riscv_vcpu_nested_swtlb_gvma_flush(vcpu, addr, size, order);
}

void kvm_riscv_vcpu_nested_swtlb_host_flush(struct kvm_vcpu *vcpu,
					    gpa_t addr, gpa_t size, unsigned long order)
{
	/* TODO: */
}

void kvm_riscv_vcpu_nested_swtlb_process(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_nested_swtlb *nst;

	if (!kvm_riscv_nested_available())
		return;

	nst = vcpu->arch.nested.swtlb;
	WARN_ON(!nst->request.pending);

	/* TODO: */

	nst->request.pending = false;
}

void kvm_riscv_vcpu_nested_swtlb_request(struct kvm_vcpu *vcpu,
					 const struct kvm_gstage_mapping *guest_map,
					 const struct kvm_gstage_mapping *host_map)
{
	struct kvm_vcpu_nested_swtlb *nst;

	if (!kvm_riscv_nested_available())
		return;

	nst = vcpu->arch.nested.swtlb;
	WARN_ON(nst->request.pending);

	nst->request.pending = true;
	memcpy(&nst->request.guest, guest_map, sizeof(*guest_map));
	memcpy(&nst->request.host, host_map, sizeof(*host_map));

	kvm_make_request(KVM_REQ_NESTED_SWTLB, vcpu);
}

void kvm_riscv_vcpu_nested_swtlb_update_hgatp(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_nested_swtlb *nst;
	unsigned long vmid;

	if (!kvm_riscv_nested_available())
		return;

	nst = vcpu->arch.nested.swtlb;
	vmid = kvm_riscv_gstage_nested_vmid(READ_ONCE(vcpu->kvm->arch.vmid.vmid));
	kvm_riscv_gstage_update_hgatp(nst->shadow_pgd_phys, nst->shadow_pgd_levels, vmid);
}

void kvm_riscv_vcpu_nested_swtlb_reset(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_nested_swtlb *nst;

	if (!kvm_riscv_nested_available())
		return;

	nst = vcpu->arch.nested.swtlb;
	memset(&nst->request, 0, sizeof(nst->request));

	/* Nuke all swtlb mappings upon VCPU reset */
	kvm_riscv_vcpu_nested_swtlb_gvma_flush(vcpu, 0, 0, 0);
}

int kvm_riscv_vcpu_nested_swtlb_init(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_nested_swtlb *nst;
	struct page *pgd_page;

	if (!kvm_riscv_nested_available())
		return 0;

	nst = kzalloc_obj(*nst);
	if (!nst)
		return -ENOMEM;
	vcpu->arch.nested.swtlb = nst;

	pgd_page = alloc_pages(GFP_KERNEL | __GFP_ZERO,
			       get_order(kvm_riscv_gstage_pgd_size));
	if (!pgd_page) {
		kfree(nst);
		return -ENOMEM;
	}
	nst->shadow_pgd = page_to_virt(pgd_page);
	nst->shadow_pgd_phys = page_to_phys(pgd_page);
	nst->shadow_pgd_levels = vcpu->kvm->arch.pgd_levels;

	return 0;
}

void kvm_riscv_vcpu_nested_swtlb_deinit(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_nested_swtlb *nst;

	if (!kvm_riscv_nested_available())
		return;

	nst = vcpu->arch.nested.swtlb;
	free_pages((unsigned long)nst->shadow_pgd, get_order(kvm_riscv_gstage_pgd_size));
	kfree(nst);
	vcpu->arch.nested.swtlb = NULL;
}
