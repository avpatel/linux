/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __IRQ_RISCV_ACLINT_SWI_H
#define __IRQ_RISCV_ACLINT_SWI_H

#include <linux/types.h>

struct device_node;

#ifdef CONFIG_RISCV_ACLINT_SWI
int aclint_swi_init(struct device_node *node, void __iomem *base);
#else
static inline int aclint_swi_init(struct device_node *node,
				  void __iomem *base)
{
	return 0;
}
#endif

#endif /* __IRQ_RISCV_ACLINT_SWI_H */
