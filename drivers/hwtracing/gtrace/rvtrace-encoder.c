// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Qualcomm Technologies, Inc.
 */

#include <linux/cpumask.h>
#include <linux/device.h>
#include <linux/gtrace.h>
#include <linux/log2.h>
#include <linux/minmax.h>
#include <linux/slab.h>
#include <linux/types.h>
#include "rvtrace.h"

#define RVTRACE_COMPONENT_CTRL_ITRACE_SHIFT	2
#define RVTRACE_COMPONENT_CTRL_INSTMODE_MASK	0x7
#define RVTRACE_COMPONENT_CTRL_INSTMODE_SHIFT	4
#define RVTRACE_COMPONENT_CTRL_INSTMODE_OPIT	0x6
#define RVTRACE_COMPONENT_CTRL_INHIBITSRC_SHIFT	15
#define RVTRACE_COMPONENT_CTRL_FORMAT_MASK	0x7
#define RVTRACE_COMPONENT_CTRL_FORMAT_SHIFT	24
#define RVTRACE_COMPONENT_CTRL_FORMAT_ETRACE	0x0
#define RVTRACE_COMPONENT_CTRL_FORMAT_NTRACE	0x1

#define RVTRACE_ENCODER_INSTFEAT_OFFSET		0x8
#define RVTRACE_ENCODER_INSTFEAT_SRCID_MASK	0xfff
#define RVTRACE_ENCODER_INSTFEAT_SRCID_SHIFT	16
#define RVTRACE_ENCODER_INSTFEAT_SRCBITS_MASK	0xf
#define RVTRACE_ENCODER_INSTFEAT_SRCBITS_SHIFT	28
#define RVTRACE_ENCODER_INSTFEAT_SRCBITS_MAX	12

struct rvtrace_encoder_priv {
	u32 srcbits;
};

/*
 * Set the srcid and clear trTeInhibitSrc bit so that the emitted trace messages carry
 * the source id
 */
static void rvtrace_encoder_set_srcid(struct gtrace_platform_data *pdata, u32 srcbits)
{
	u32 val;

	val = gtrace_read32(pdata, RVTRACE_ENCODER_INSTFEAT_OFFSET);
	val &= ~(RVTRACE_ENCODER_INSTFEAT_SRCID_MASK << RVTRACE_ENCODER_INSTFEAT_SRCID_SHIFT);
	val &= ~(RVTRACE_ENCODER_INSTFEAT_SRCBITS_MASK << RVTRACE_ENCODER_INSTFEAT_SRCBITS_SHIFT);
	val |= pdata->bound_cpu << RVTRACE_ENCODER_INSTFEAT_SRCID_SHIFT;
	val |= srcbits << RVTRACE_ENCODER_INSTFEAT_SRCBITS_SHIFT;
	gtrace_write32(pdata, val, RVTRACE_ENCODER_INSTFEAT_OFFSET);

	val = gtrace_read32(pdata, RVTRACE_COMPONENT_CTRL_OFFSET);
	val &= ~BIT(RVTRACE_COMPONENT_CTRL_INHIBITSRC_SHIFT);
	gtrace_write32(pdata, val, RVTRACE_COMPONENT_CTRL_OFFSET);
}

/* Set requested trace format and return 0 if hardware supports that format */
static int rvtrace_encoder_set_format(struct gtrace_platform_data *pdata)
{
	u32 val, fmt;

	switch (pdata->format) {
	case GTRACE_FORMAT_ETRACE:
		fmt = RVTRACE_COMPONENT_CTRL_FORMAT_ETRACE;
		break;
	case GTRACE_FORMAT_NTRACE:
		fmt = RVTRACE_COMPONENT_CTRL_FORMAT_NTRACE;
		break;
	default:
		return -EINVAL;
	}

	val = gtrace_read32(pdata, RVTRACE_COMPONENT_CTRL_OFFSET);
	val &= ~(RVTRACE_COMPONENT_CTRL_FORMAT_MASK << RVTRACE_COMPONENT_CTRL_FORMAT_SHIFT);
	val |= fmt << RVTRACE_COMPONENT_CTRL_FORMAT_SHIFT;
	gtrace_write32(pdata, val, RVTRACE_COMPONENT_CTRL_OFFSET);

	val = gtrace_read32(pdata, RVTRACE_COMPONENT_CTRL_OFFSET);
	val = (val >> RVTRACE_COMPONENT_CTRL_FORMAT_SHIFT) & RVTRACE_COMPONENT_CTRL_FORMAT_MASK;
	return val == fmt ? 0 : -EOPNOTSUPP;
}

static int rvtrace_encoder_probe(struct gtrace_component *comp)
{
	struct gtrace_platform_data *pdata = comp->pdata;
	struct rvtrace_encoder_priv *priv;
	u32 val, hw_srcbits, srcbits;
	int ret;

	if (pdata->bound_cpu < 0) {
		dev_err(&comp->dev, "cpu property missing. Please fix firmware.\n");
		return -EINVAL;
	}

	priv = devm_kzalloc(&comp->dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	ret = rvtrace_encoder_set_format(pdata);
	if (ret) {
		dev_err(&comp->dev, "failed to set format %d\n", pdata->format);
		return ret;
	}

	/* Check if trTeInhibitSrc is hardwired to 1 */
	val = gtrace_read32(pdata, RVTRACE_COMPONENT_CTRL_OFFSET);
	val &= ~BIT(RVTRACE_COMPONENT_CTRL_INHIBITSRC_SHIFT);
	gtrace_write32(pdata, val, RVTRACE_COMPONENT_CTRL_OFFSET);
	val = gtrace_read32(pdata, RVTRACE_COMPONENT_CTRL_OFFSET);
	if (!(val & BIT(RVTRACE_COMPONENT_CTRL_INHIBITSRC_SHIFT))) {
		/* Probe how many bits can trTeSrcID span in the emitted Trace messages */
		val = gtrace_read32(pdata, RVTRACE_ENCODER_INSTFEAT_OFFSET);
		val |= (RVTRACE_ENCODER_INSTFEAT_SRCBITS_MASK <<
			RVTRACE_ENCODER_INSTFEAT_SRCBITS_SHIFT);
		gtrace_write32(pdata, val, RVTRACE_ENCODER_INSTFEAT_OFFSET);
		val = gtrace_read32(pdata, RVTRACE_ENCODER_INSTFEAT_OFFSET);
		hw_srcbits = (val >> RVTRACE_ENCODER_INSTFEAT_SRCBITS_SHIFT) &
			     RVTRACE_ENCODER_INSTFEAT_SRCBITS_MASK;
		/* Determine if there are sufficient bits to hold max cpus */
		hw_srcbits = min_t(u32, hw_srcbits, RVTRACE_ENCODER_INSTFEAT_SRCBITS_MAX);
		srcbits = min_t(u32, hw_srcbits, order_base_2(nr_cpu_ids));
		if (srcbits && pdata->bound_cpu < BIT(srcbits)) {
			rvtrace_encoder_set_srcid(pdata, srcbits);
			priv->srcbits = srcbits;
		}
	}
	if (!priv->srcbits) {
		dev_warn(&comp->dev, "cpu %d trace will not carry source id\n",
			 pdata->bound_cpu);
		val = gtrace_read32(pdata, RVTRACE_COMPONENT_CTRL_OFFSET);
		val |= BIT(RVTRACE_COMPONENT_CTRL_INHIBITSRC_SHIFT);
		gtrace_write32(pdata, val, RVTRACE_COMPONENT_CTRL_OFFSET);
	}
	dev_set_drvdata(&comp->dev, priv);
	return 0;
}

static int rvtrace_encoder_start(struct gtrace_component *comp)
{
	struct rvtrace_encoder_priv *priv = dev_get_drvdata(&comp->dev);
	struct gtrace_platform_data *pdata = comp->pdata;
	int ret;
	u32 val;

	if (priv->srcbits)
		rvtrace_encoder_set_srcid(pdata, priv->srcbits);

	ret = rvtrace_encoder_set_format(pdata);
	if (ret) {
		dev_err(&comp->dev, "failed to set format %d\n", pdata->format);
		return ret;
	}

	ret = gtrace_enable_component(comp);
	if (ret) {
		dev_err(&comp->dev, "failed to enable encoder.\n");
		return ret;
	}

	/* set mode */
	val = gtrace_read32(pdata, RVTRACE_COMPONENT_CTRL_OFFSET);
	val &= ~(RVTRACE_COMPONENT_CTRL_INSTMODE_MASK << RVTRACE_COMPONENT_CTRL_INSTMODE_SHIFT);
	val |= (RVTRACE_COMPONENT_CTRL_INSTMODE_OPIT << RVTRACE_COMPONENT_CTRL_INSTMODE_SHIFT);
	gtrace_write32(pdata, val, RVTRACE_COMPONENT_CTRL_OFFSET);

	val = gtrace_read32(pdata, RVTRACE_COMPONENT_CTRL_OFFSET);
	val |= BIT(RVTRACE_COMPONENT_CTRL_ITRACE_SHIFT);
	gtrace_write32(pdata, val, RVTRACE_COMPONENT_CTRL_OFFSET);
	ret = gtrace_poll_bit(pdata, RVTRACE_COMPONENT_CTRL_OFFSET,
			      RVTRACE_COMPONENT_CTRL_ITRACE_SHIFT, 1,
			      pdata->control_poll_timeout_usecs);
	if (ret) {
		dev_err(&comp->dev, "failed to enable tracing.\n");
		val = gtrace_read32(pdata, RVTRACE_COMPONENT_CTRL_OFFSET);
		val &= ~BIT(RVTRACE_COMPONENT_CTRL_ITRACE_SHIFT);
		gtrace_write32(pdata, val, RVTRACE_COMPONENT_CTRL_OFFSET);
		gtrace_disable_component(comp);
	}

	return ret;
}

static int rvtrace_encoder_stop(struct gtrace_component *comp)
{
	struct gtrace_platform_data *pdata = comp->pdata;
	int ret, err;
	u32 val;

	val = gtrace_read32(pdata, RVTRACE_COMPONENT_CTRL_OFFSET);
	val &= ~BIT(RVTRACE_COMPONENT_CTRL_ITRACE_SHIFT);
	gtrace_write32(pdata, val, RVTRACE_COMPONENT_CTRL_OFFSET);
	ret = gtrace_poll_bit(pdata, RVTRACE_COMPONENT_CTRL_OFFSET,
			      RVTRACE_COMPONENT_CTRL_ITRACE_SHIFT, 0,
			      pdata->control_poll_timeout_usecs);
	if (ret)
		dev_err(&comp->dev, "failed to stop tracing.\n");

	err = gtrace_disable_component(comp);
	if (err)
		dev_err(&comp->dev, "failed to disable encoder.\n");

	return ret ?: err;
}

static const struct gtrace_component_id rvtrace_encoder_ids[] = {
	{ .type = GTRACE_RVTRACE_ENCODER,
	  .version = rvtrace_component_mkversion(1, 0), },
	{},
};

static struct gtrace_driver rvtrace_encoder_driver = {
	.id_table = rvtrace_encoder_ids,
	.probe = rvtrace_encoder_probe,
	.start = rvtrace_encoder_start,
	.stop = rvtrace_encoder_stop,
	.driver = {
		.name = "rvtrace-encoder",
	},
};

static int __init rvtrace_encoder_init(void)
{
	return gtrace_register_driver(&rvtrace_encoder_driver);
}

static void __exit rvtrace_encoder_exit(void)
{
	gtrace_unregister_driver(&rvtrace_encoder_driver);
}

module_init(rvtrace_encoder_init);
module_exit(rvtrace_encoder_exit);

/* Module information */
MODULE_AUTHOR("Mayuresh Chitale");
MODULE_DESCRIPTION("RISC-V Trace Encoder Driver");
MODULE_LICENSE("GPL");
