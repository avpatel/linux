/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2021 Western Digital Corporation or its affiliates.
 * Copyright (C) 2022 Ventana Micro Systems Inc.
 */
#ifndef __LINUX_IRQCHIP_RISCV_IMSIC_H
#define __LINUX_IRQCHIP_RISCV_IMSIC_H

#include <linux/types.h>
#include <linux/bitops.h>
#include <linux/device.h>
#include <linux/fwnode.h>

#define IMSIC_MMIO_PAGE_SHIFT		12
#define IMSIC_MMIO_PAGE_SZ		BIT(IMSIC_MMIO_PAGE_SHIFT)
#define IMSIC_MMIO_PAGE_LE		0x00
#define IMSIC_MMIO_PAGE_BE		0x04

#define IMSIC_MIN_ID			63
#define IMSIC_MAX_ID			2048

#define IMSIC_EIDELIVERY		0x70

#define IMSIC_EITHRESHOLD		0x72

#define IMSIC_EIP0			0x80
#define IMSIC_EIP63			0xbf
#define IMSIC_EIPx_BITS			32

#define IMSIC_EIE0			0xc0
#define IMSIC_EIE63			0xff
#define IMSIC_EIEx_BITS			32

#define IMSIC_FIRST			IMSIC_EIDELIVERY
#define IMSIC_LAST			IMSIC_EIE63

#define IMSIC_MMIO_SETIPNUM_LE		0x00
#define IMSIC_MMIO_SETIPNUM_BE		0x04

struct imsic_local_config {
	phys_addr_t				msi_pa;
	void __iomem				*msi_va;

	/* Number of guest interrupt files per-HART */
	u32					nr_guest_files;
};

struct imsic_global_config {
	/* Device details */
	struct fwnode_handle                    *fwnode;

	/*
	 * MSI Target Address Scheme
	 *
	 * XLEN-1                                                12     0
	 * |                                                     |     |
	 * -------------------------------------------------------------
	 * |xxxxxx|Group Index|xxxxxxxxxxx|HART Index|Guest Index|  0  |
	 * -------------------------------------------------------------
	 */

	/* Bits representing Guest index, HART index, and Group index */
	u32					guest_index_bits;
	u32					hart_index_bits;
	u32					group_index_bits;
	u32					group_index_shift;

	/* Global base address matching all target MSI addresses */
	phys_addr_t				base_addr;

	/* Number of interrupt identities */
	u32					nr_ids;

	/* Number of guest interrupt identities */
	u32					nr_guest_ids;

	/* Number of guest interrupt files across all HARTs */
	u32					nr_guest_files;

	/* Per-CPU IMSIC addresses */
	struct imsic_local_config __percpu	*local;
};

#ifdef CONFIG_RISCV_IMSIC

const struct imsic_global_config *imsic_get_global_config(void);
bool imsic_dev_has_imsic_msi_parent(struct device *dev);

#else

static inline const struct imsic_global_config *imsic_get_global_config(void)
{
	return NULL;
}

static inline bool imsic_dev_has_imsic_msi_parent(struct device *dev)
{
	return false;
}

#endif

#if IS_ENABLED(CONFIG_ACPI) && IS_ENABLED(CONFIG_RISCV_IMSIC)
int imsic_platform_acpi_probe(struct fwnode_handle *fwnode);
struct fwnode_handle *imsic_acpi_get_fwnode(struct device *dev);
#else
static inline struct fwnode_handle *imsic_acpi_get_fwnode(struct device *dev) { return NULL; }
#endif

enum riscv_iommu_ir_cmd {
	RISCV_IOMMU_IR_INVALID_CMD,
	RISCV_IOMMU_IR_FORWARD,
	RISCV_IOMMU_IR_UPDATE_TARGET,
};

enum riscv_iommu_ir_target_type {
	RISCV_IOMMU_IR_TARGET_INVALID,
	RISCV_IOMMU_IR_TARGET_IMSIC,
	RISCV_IOMMU_IR_TARGET_MRIF,
};

struct riscv_iommu_ir_target {
	u64 gpa;
	enum riscv_iommu_ir_target_type type;
	union {
		u64 hpa;
		struct {
			u64 mrif_hpa;
			u64 notice_hpa;
			u32 notice_id;
		};
	};
};

/*
 * FORWARD enables forwarding for one IRQ and provides the complete target array
 * so the first forwarded IRQ can initialize the domain MSI table. UPDATE_TARGET
 * replaces one target without changing per-IRQ forwarding state. The caller
 * must quiesce all MSI producers using the table when changing both words of a
 * live MRIF PTE because the update temporarily invalidates the entry. A NULL
 * vcpu_info disables forwarding for the IRQ.
 *
 * A well-formed request which is incompatible with the producer or current
 * domain configuration returns -EOPNOTSUPP, allowing the caller to fall back
 * to host delivery. Invalid payloads return -EINVAL and operational errors are
 * propagated.
 */
struct riscv_iommu_ir_vcpu_info {
	enum riscv_iommu_ir_cmd cmd;
	const void *owner;
	u64 msi_addr_mask;
	u64 msi_addr_pattern;
	union {
		struct {
			const struct riscv_iommu_ir_target *targets;
			unsigned int nr_targets;
		};
		struct riscv_iommu_ir_target target;
	};
};

#endif
