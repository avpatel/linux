// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Qualcomm Technologies, Inc.
 */

#include <linux/kvm_host.h>
#include <linux/pgtable.h>
#include <asm/csr.h>
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

enum riscv_guest_pgtbl_walk_access {
	RISCV_GUEST_PGTBL_WALK_LOAD = 0,
	RISCV_GUEST_PGTBL_WALK_STORE,
	RISCV_GUEST_PGTBL_WALK_FETCH,
};

struct riscv_guest_pgtbl_walk_context {
	/* VCPU for which translation is being done */
	struct kvm_vcpu *vcpu;

	/* Original trap which initiated page table walk */
	const struct kvm_cpu_trap *original_trap;

	/* Number of page table levels */
	u32 pgd_levels;

	/* Additional runtime state */
	bool smode;
	bool sstatus_sum;
	bool sstatus_mxr;
	bool hlvx;

	/* Get PTE index based on input address and page table level */
	u32 (*level_index)(struct riscv_guest_pgtbl_walk_context *context,
			   u32 level, gpa_t in_addr);

	/* Get page size based on page table level */
	unsigned long (*level_size)(struct riscv_guest_pgtbl_walk_context *context,
				    u32 level);

	/* Update output trap details */
	void (*set_trap)(struct riscv_guest_pgtbl_walk_context *context,
			 enum riscv_guest_pgtbl_walk_access access,
			 u32 level, gpa_t in_addr);

	/* Stage specific PTE permission fault checks */
	bool (*perm_fault)(struct riscv_guest_pgtbl_walk_context *context,
			   enum riscv_guest_pgtbl_walk_access access,
			   pte_t *pte);

	/* Translate address before use (Optional) */
	int (*addr_xlate)(struct riscv_guest_pgtbl_walk_context *context,
			  enum riscv_guest_pgtbl_walk_access access,
			  gpa_t in_addr, gpa_t *out_addr);

	/* Output mapping */
	struct kvm_gstage_mapping *out_map;

	/* Output address */
	gpa_t *out_addr;

	/* Output trap details */
	struct kvm_cpu_trap *out_trap;
};

static int riscv_guest_pgtbl_walk(struct riscv_guest_pgtbl_walk_context *context,
				  enum riscv_guest_pgtbl_walk_access access,
				  gpa_t pgtbl_gpa, u32 level, gpa_t in_addr)
{
	struct kvm_gstage_mapping *out_map;
	bool perm_fault = false;
	unsigned long page_size;
	gpa_t *out_addr;
	pte_t pte;
	u32 idx;
	int rc;

	/* Sanity checks on parameters */
	if (!context || !context->vcpu ||
	    !context->original_trap || context->pgd_levels <= level ||
	    !context->level_index || !context->level_size ||
	    !context->set_trap || !context->perm_fault ||
	    !context->out_map || !context->out_addr || !context->out_trap)
		return -EINVAL;

	/* Translate page table base for nested walks */
	if (context->addr_xlate) {
		rc = context->addr_xlate(context, access, pgtbl_gpa, &pgtbl_gpa);
		if (rc)
			return rc;
		if (context->out_trap->scause)
			return 0;
	}

	/* Read the PTE from guest memory */
	idx = context->level_index(context, level, in_addr);
	rc = kvm_vcpu_read_guest(context->vcpu, pgtbl_gpa + idx * sizeof(pte),
				 &pte, sizeof(pte));
	if (rc) {
		context->set_trap(context, access, level, in_addr);
		return 0;
	}

	/* Trap if PTE not present */
	if (!(pte_val(pte) & _PAGE_PRESENT)) {
		context->set_trap(context, access, level, in_addr);
		return 0;
	}

	/* Recursively walk next page table level for non-leaf PTE */
	if (!(pte_val(pte) & _PAGE_LEAF)) {
		if (!level) {
			context->set_trap(context, access, level, in_addr);
			return 0;
		}

		pgtbl_gpa = pte_pfn(pte) << PAGE_SHIFT;
		return riscv_guest_pgtbl_walk(context, access, pgtbl_gpa,
					      level - 1, in_addr);
	}

	/* Check PTE permissions based on access type */
	if (context->perm_fault(context, access, &pte))
		perm_fault = true;
	else if (access == RISCV_GUEST_PGTBL_WALK_LOAD)
		perm_fault = !((pte_val(pte) & _PAGE_READ) ||
			       ((context->sstatus_mxr) && (pte_val(pte) & _PAGE_EXEC))) ||
			     !(pte_val(pte) & _PAGE_ACCESSED);
	else if (access == RISCV_GUEST_PGTBL_WALK_STORE)
		perm_fault = !(pte_val(pte) & _PAGE_READ) ||
			     !(pte_val(pte) & _PAGE_WRITE) ||
			     !(pte_val(pte) & _PAGE_ACCESSED) ||
			     !(pte_val(pte) & _PAGE_DIRTY);
	else if (access == RISCV_GUEST_PGTBL_WALK_FETCH || context->hlvx)
		perm_fault = !(pte_val(pte) & _PAGE_EXEC);
	if (perm_fault) {
		context->set_trap(context, access, level, in_addr);
		return 0;
	}

	/* Update output address and page size */
	page_size = context->level_size(context, level);
	out_addr = context->out_addr;
	*out_addr = (pte_pfn(pte) << PAGE_SHIFT) | (in_addr & (page_size - 1));

	/* Translate output address for nested walks */
	if (context->addr_xlate) {
		rc = context->addr_xlate(context, access, *out_addr, out_addr);
		if (rc)
			return rc;
		if (context->out_trap->scause)
			return 0;
	}

	/* Update output mapping */
	out_map = context->out_map;
	out_map->addr = in_addr & ~((gpa_t)page_size - 1);
	out_map->pte = pte;
	out_map->level = level;
	return 0;
}

static u32 riscv_guest_gstage_pgd_levels(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_nested_csr *nsc = vcpu->arch.nested.csr;
	u32 pgd_levels = 0;

	switch ((nsc->hgatp & HGATP_MODE) >> HGATP_MODE_SHIFT) {
#ifdef CONFIG_32BIT
	case HGATP_MODE_SV32X4:
		pgd_levels = 2;
		break;
#else
	case HGATP_MODE_SV39X4:
		pgd_levels = 3;
		break;
	case HGATP_MODE_SV48X4:
		pgd_levels = 4;
		break;
	case HGATP_MODE_SV57X4:
		pgd_levels = 5;
		break;
#endif
	case HGATP_MODE_OFF:
	default:
		break;
	}

	return pgd_levels;
}

static gpa_t riscv_guest_gstage_pgd_base(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_nested_csr *nsc = vcpu->arch.nested.csr;

	return (nsc->hgatp & HGATP_PPN) << PAGE_SHIFT;
}

static u32 riscv_guest_gstage_level_index(struct riscv_guest_pgtbl_walk_context *context,
					  u32 level, gpa_t in_addr)
{
	return kvm_riscv_gstage_pte_index(context->pgd_levels, in_addr, level);
}

static unsigned long riscv_guest_gstage_level_size(struct riscv_guest_pgtbl_walk_context *context,
						   u32 level)
{
	return kvm_riscv_gstage_level_to_page_size(level);
}

static bool riscv_guest_gstage_perm_fault(struct riscv_guest_pgtbl_walk_context *context,
					  enum riscv_guest_pgtbl_walk_access access,
					  pte_t *pte)
{
	return !(pte_val(*pte) & _PAGE_USER) ? true : false;
}

static void riscv_guest_gstage_set_trap(struct riscv_guest_pgtbl_walk_context *context,
					enum riscv_guest_pgtbl_walk_access access,
					u32 level, gpa_t in_addr)
{
	const struct kvm_cpu_trap *orig_trap = context->original_trap;
	struct kvm_cpu_trap *out_trap = context->out_trap;

	/* We should never have non-zero scause here. */
	BUG_ON(out_trap->scause);

	switch (access) {
	case RISCV_GUEST_PGTBL_WALK_LOAD:
		out_trap->scause = EXC_LOAD_GUEST_PAGE_FAULT;
		break;
	case RISCV_GUEST_PGTBL_WALK_STORE:
		out_trap->scause = RISCV_GUEST_PGTBL_WALK_STORE;
		break;
	case RISCV_GUEST_PGTBL_WALK_FETCH:
		out_trap->scause = EXC_INST_GUEST_PAGE_FAULT;
		break;
	default:
		BUG_ON(1);
	}

	out_trap->sepc = orig_trap->sepc;
	out_trap->stval = orig_trap->stval;
	out_trap->htval = in_addr >> 2;
	out_trap->htinst = orig_trap->htinst;
}

static int riscv_guest_gstage_xlate(struct kvm_vcpu *vcpu, gpa_t in_addr,
				    const struct kvm_cpu_trap *original_trap,
				    enum riscv_guest_pgtbl_walk_access access,
				    struct kvm_gstage_mapping *out_map,
				    gpa_t *out_addr, struct kvm_cpu_trap *out_trap)
{
	struct riscv_guest_pgtbl_walk_context context = { 0 };
	unsigned long page_size;
	u32 pgd_levels;
	int rc;

	pgd_levels = riscv_guest_gstage_pgd_levels(vcpu);
	if (pgd_levels) {
		context.vcpu = vcpu;
		context.original_trap = original_trap;
		context.pgd_levels = pgd_levels;
		context.smode = !!(vcpu->arch.guest_context.sstatus & SR_SPP);
		context.sstatus_sum = !!(vcpu->arch.guest_context.sstatus & SR_SUM);
		context.sstatus_mxr = !!(vcpu->arch.guest_context.sstatus & SR_MXR);
		context.hlvx = false;
		context.level_index = riscv_guest_gstage_level_index;
		context.level_size = riscv_guest_gstage_level_size;
		context.set_trap = riscv_guest_gstage_set_trap;
		context.perm_fault = riscv_guest_gstage_perm_fault;
		context.out_map = out_map;
		context.out_addr = out_addr;
		context.out_trap = out_trap;
		rc = riscv_guest_pgtbl_walk(&context, access,
					    riscv_guest_gstage_pgd_base(vcpu),
					    pgd_levels - 1, in_addr);
		if (rc)
			return rc;
	} else {
		out_map->level = 1;
		page_size = kvm_riscv_gstage_level_to_page_size(out_map->level);
		out_map->addr = in_addr & ~((gpa_t)page_size - 1);
		out_map->pte = pfn_pte(PFN_DOWN(out_map->addr),
				       __pgprot(_PAGE_PRESENT |
						_PAGE_READ |
						_PAGE_WRITE |
						_PAGE_EXEC |
						_PAGE_USER |
						_PAGE_GLOBAL |
						_PAGE_ACCESSED |
						_PAGE_DIRTY));
		*out_addr = in_addr;
	}

	return 0;
}

int kvm_riscv_vcpu_nested_swtlb_xlate(struct kvm_vcpu *vcpu,
				      const struct kvm_cpu_trap *trap,
				      struct kvm_gstage_mapping *out_map,
				      gpa_t *out_addr, struct kvm_cpu_trap *out_trap)
{
	enum riscv_guest_pgtbl_walk_access access;

	if (!kvm_riscv_nested_available())
		return -ENOENT;

	switch (trap->scause) {
	case EXC_INST_GUEST_PAGE_FAULT:
		access = RISCV_GUEST_PGTBL_WALK_FETCH;
		break;
	case EXC_LOAD_GUEST_PAGE_FAULT:
		access = RISCV_GUEST_PGTBL_WALK_LOAD;
		break;
	case EXC_STORE_GUEST_PAGE_FAULT:
		access = RISCV_GUEST_PGTBL_WALK_STORE;
		break;
	default:
		return -EINVAL;
	}

	return riscv_guest_gstage_xlate(vcpu, (trap->htval << 2) | (trap->stval & 0x3),
					trap, access, out_map, out_addr, out_trap);
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
