// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 Western Digital Corporation or its affiliates.
 * Copyright (C) 2022 Ventana Micro Systems Inc.
 */

#define pr_fmt(fmt) "aclint-swi: " fmt
#include <linux/cpu.h>
#include <linux/cpumask.h>
#include <linux/io.h>
#include <linux/init.h>
#include <linux/irqchip.h>
#include <linux/irqdomain.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/smp.h>
#include <asm/ipi-mux.h>

struct aclint_swi {
	void __iomem *sip_reg;
};

static struct irq_domain *aclint_swi_domain __ro_after_init;
static DEFINE_PER_CPU(struct aclint_swi, aclint_swis);

static void aclint_swi_ipi_send(const struct cpumask *mask)
{
	int cpu;
	struct aclint_swi *swi;

	for_each_cpu(cpu, mask) {
		swi = per_cpu_ptr(&aclint_swis, cpu);
		writel(1, swi->sip_reg);
	}
}

static void aclint_swi_ipi_clear(void)
{
#ifdef CONFIG_RISCV_M_MODE
	struct aclint_swi *swi = this_cpu_ptr(&aclint_swis);

	writel(0, swi->sip_reg);
#else
	csr_clear(CSR_IP, IE_SIE);
#endif
}

static int __init aclint_swi_domain_init(struct device_node *node)
{
	/*
	 * We can have multiple ACLINT SWI devices but we only need
	 * one IRQ domain for providing per-HART (or per-CPU) IPIs.
	 */
	if (aclint_swi_domain)
		return 0;

	aclint_swi_domain = riscv_ipi_mux_create(true, true,
						 aclint_swi_ipi_clear,
						 aclint_swi_ipi_send);
	if (!aclint_swi_domain) {
		pr_err("unable to create ACLINT SWI IRQ domain\n");
		return -ENOMEM;
	}

	return 0;
}

static int __init aclint_swi_init(struct device_node *node,
				  struct device_node *parent)
{
	int rc;
	void __iomem *base;
	struct aclint_swi *swi;
	u32 i, nr_irqs, nr_cpus = 0;

	/* Map the registers */
	base = of_iomap(node, 0);
	if (!base) {
		pr_err("%pOFP: could not map registers\n", node);
		return -ENODEV;
	}

	/* Iterate over each target CPU connected with this ACLINT */
	nr_irqs = of_irq_count(node);
	for (i = 0; i < nr_irqs; i++) {
		struct of_phandle_args parent;
		int cpu, hartid;

		if (of_irq_parse_one(node, i, &parent)) {
			pr_err("%pOFP: failed to parse irq %d.\n",
			       node, i);
			continue;
		}

		if (parent.args[0] != RV_IRQ_SOFT)
			continue;

		hartid = riscv_of_parent_hartid(parent.np);
		if (hartid < 0) {
			pr_warn("failed to parse hart ID for irq %d.\n", i);
			continue;
		}

		cpu = riscv_hartid_to_cpuid(hartid);
		if (cpu < 0) {
			pr_warn("Invalid cpuid for irq %d\n", i);
			continue;
		}

		swi = per_cpu_ptr(&aclint_swis, cpu);
		swi->sip_reg = base + nr_cpus * sizeof(u32);
		writel(0, swi->sip_reg);

		nr_cpus++;
	}

	/* Create the IPI domain for ACLINT SWI device */
	rc = aclint_swi_domain_init(node);
	if (rc) {
		iounmap(base);
		return rc;
	}

	/* Announce the ACLINT SWI device */
	pr_info("%pOFP: providing IPIs for %d CPUs\n", node, nr_cpus);

	return 0;
}

#ifdef CONFIG_RISCV_M_MODE
IRQCHIP_DECLARE(riscv_aclint_swi, "riscv,aclint-mswi", aclint_swi_init);
#else
IRQCHIP_DECLARE(riscv_aclint_swi, "riscv,aclint-sswi", aclint_swi_init);
#endif
