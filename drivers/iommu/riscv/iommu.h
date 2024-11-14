/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright © 2022-2024 Rivos Inc.
 * Copyright © 2023 FORTH-ICS/CARV
 *
 * Authors
 *	Tomasz Jeznach <tjeznach@rivosinc.com>
 *	Nick Kossifidis <mick@ics.forth.gr>
 */

#ifndef _RISCV_IOMMU_H_
#define _RISCV_IOMMU_H_

#include <linux/iommu.h>
#include <linux/types.h>
#include <linux/iopoll.h>

#include "iommu-bits.h"

/* Timeouts in [us] */
#define RISCV_IOMMU_QCSR_TIMEOUT	150000
#define RISCV_IOMMU_QUEUE_TIMEOUT	150000
#define RISCV_IOMMU_DDTP_TIMEOUT	10000000
#define RISCV_IOMMU_IOTINVAL_TIMEOUT	90000000

struct riscv_iommu_msiptp_state {
	u64 msiptp;
	u64 msi_addr_mask;
	u64 msi_addr_pattern;
};

/* This struct contains protection domain specific IOMMU driver data. */
struct riscv_iommu_domain {
	struct iommu_domain domain;
	struct list_head bonds;
	spinlock_t lock;			/* protect bonds list updates. */
	int pscid;
	int gscid;
	int amo_enabled;
	int numa_node;
	unsigned int pgd_mode;
	unsigned long *pgd_root;
	u32 group_index_bits;
	u32 group_index_shift;
	int msi_order;
	struct riscv_iommu_msipte *msi_root;
	spinlock_t msi_lock;
	struct riscv_iommu_msiptp_state msiptp;
	struct irq_domain *irqdomain;
};

/* Private IOMMU data for managed devices, dev_iommu_priv_* */
struct riscv_iommu_info {
	struct riscv_iommu_domain *domain;
};

struct riscv_iommu_device;

#define dev_to_iommu(dev) \
	iommu_get_iommu_dev(dev, struct riscv_iommu_device, iommu)

struct riscv_iommu_queue {
	atomic_t prod;				/* unbounded producer allocation index */
	atomic_t head;				/* unbounded shadow ring buffer consumer index */
	atomic_t tail;				/* unbounded shadow ring buffer producer index */
	unsigned int mask;			/* index mask, queue length - 1 */
	unsigned int irq;			/* allocated interrupt number */
	struct riscv_iommu_device *iommu;	/* iommu device handling the queue when active */
	void *base;				/* ring buffer kernel pointer */
	dma_addr_t phys;			/* ring buffer physical address */
	u16 qbr;				/* base register offset, head and tail reference */
	u16 qcr;				/* control and status register offset */
	u8 qid;					/* queue identifier, same as RISCV_IOMMU_INTR_XX */
};

struct riscv_iommu_device {
	/* iommu core interface */
	struct iommu_device iommu;

	/* iommu hardware */
	struct device *dev;

	/* hardware control register space */
	void __iomem *reg;

	/* supported and enabled hardware capabilities */
	u64 caps;
	u32 fctl;

	/* available interrupt numbers, MSI or WSI */
	unsigned int irqs[RISCV_IOMMU_INTR_COUNT];
	unsigned int irqs_count;
	unsigned int icvec;

	/* hardware queues */
	struct riscv_iommu_queue cmdq;
	struct riscv_iommu_queue fltq;

	/* device directory */
	unsigned int ddt_mode;
	dma_addr_t ddt_phys;
	u64 *ddt_root;
};

/*
 * Linkage between an iommu_domain and attached devices.
 *
 * Protection domain requiring IOATC and DevATC translation cache invalidations,
 * should be linked to attached devices using a riscv_iommu_bond structure.
 * Devices should be linked to the domain before first use and unlinked after
 * the translations from the referenced protection domain can no longer be used.
 * Blocking and identity domains are not tracked here, as the IOMMU hardware
 * does not cache negative and/or identity (BARE mode) translations, and DevATC
 * is disabled for those protection domains.
 *
 * The device pointer and IOMMU data remain stable in the bond struct after
 * _probe_device() where it's attached to the managed IOMMU, up to the
 * completion of the _release_device() call. The release of the bond structure
 * is synchronized with the device release.
 */
struct riscv_iommu_bond {
	struct list_head list;
	struct rcu_head rcu;
	struct device *dev;
};

int riscv_iommu_init(struct riscv_iommu_device *iommu);
void riscv_iommu_remove(struct riscv_iommu_device *iommu);

struct riscv_iommu_dc *riscv_iommu_get_dc(struct riscv_iommu_device *iommu,
					  unsigned int devid);

void riscv_iommu_cmd_send(struct riscv_iommu_device *iommu,
			  struct riscv_iommu_command *cmd);
void riscv_iommu_cmd_sync(struct riscv_iommu_device *iommu,
			  unsigned int timeout_us);

int riscv_iommu_irq_domain_create(struct riscv_iommu_domain *domain,
				  struct device *dev);
void riscv_iommu_irq_domain_remove(struct riscv_iommu_domain *domain);
void riscv_iommu_irq_domain_unlink(struct riscv_iommu_domain *domain,
				   struct device *dev);
void riscv_iommu_ir_get_resv_regions(struct device *dev,
				     struct list_head *head);

#define riscv_iommu_readl(iommu, addr) \
	readl_relaxed((iommu)->reg + (addr))

#define riscv_iommu_readq(iommu, addr) \
	readq_relaxed((iommu)->reg + (addr))

#define riscv_iommu_writel(iommu, addr, val) \
	writel_relaxed((val), (iommu)->reg + (addr))

#define riscv_iommu_writeq(iommu, addr, val) \
	writeq_relaxed((val), (iommu)->reg + (addr))

#define riscv_iommu_readq_timeout(iommu, addr, val, cond, delay_us, timeout_us) \
	readx_poll_timeout(readq_relaxed, (iommu)->reg + (addr), val, cond, \
			   delay_us, timeout_us)

#define riscv_iommu_readl_timeout(iommu, addr, val, cond, delay_us, timeout_us) \
	readx_poll_timeout(readl_relaxed, (iommu)->reg + (addr), val, cond, \
			   delay_us, timeout_us)

#endif
