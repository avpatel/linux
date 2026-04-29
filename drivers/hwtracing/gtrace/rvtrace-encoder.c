// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Qualcomm Technologies, Inc.
 */

#include <linux/device.h>
#include <linux/gtrace.h>
#include <linux/types.h>
#include "rvtrace.h"

#define RVTRACE_COMPONENT_CTRL_ITRACE_SHIFT	2
#define RVTRACE_COMPONENT_CTRL_INSTMODE_SHIFT	4
#define RVTRACE_COMPONENT_CTRL_INSTMODE_OPIT	0x6

static int rvtrace_encoder_start(struct gtrace_component *comp)
{
	struct gtrace_platform_data *pdata = comp->pdata;
	int ret;
	u32 val;

	ret = gtrace_enable_component(comp);
	if (ret) {
		dev_err(&comp->dev, "failed to enable encoder.\n");
		return ret;
	}

	/* set mode */
	val = gtrace_read32(pdata, RVTRACE_COMPONENT_CTRL_OFFSET);
	val |= (RVTRACE_COMPONENT_CTRL_INSTMODE_OPIT << RVTRACE_COMPONENT_CTRL_INSTMODE_SHIFT);
	gtrace_write32(pdata, val, RVTRACE_COMPONENT_CTRL_OFFSET);

	val = gtrace_read32(pdata, RVTRACE_COMPONENT_CTRL_OFFSET);
	val |= BIT(RVTRACE_COMPONENT_CTRL_ITRACE_SHIFT);
	gtrace_write32(pdata, val, RVTRACE_COMPONENT_CTRL_OFFSET);
	ret = gtrace_poll_bit(pdata, RVTRACE_COMPONENT_CTRL_OFFSET,
			      RVTRACE_COMPONENT_CTRL_ITRACE_SHIFT, 1,
			      pdata->control_poll_timeout_usecs);
	if (ret)
		dev_err(&comp->dev, "failed to enable tracing.\n");

	return ret;
}

static int rvtrace_encoder_stop(struct gtrace_component *comp)
{
	struct gtrace_platform_data *pdata = comp->pdata;
	int ret;
	u32 val;

	val = gtrace_read32(pdata, RVTRACE_COMPONENT_CTRL_OFFSET);
	val &= ~BIT(RVTRACE_COMPONENT_CTRL_ITRACE_SHIFT);
	gtrace_write32(pdata, val, RVTRACE_COMPONENT_CTRL_OFFSET);
	ret = gtrace_poll_bit(pdata, RVTRACE_COMPONENT_CTRL_OFFSET,
			      RVTRACE_COMPONENT_CTRL_ITRACE_SHIFT, 0,
			      pdata->control_poll_timeout_usecs);
	if (ret) {
		dev_err(&comp->dev, "failed to stop tracing.\n");
		return ret;
	}

	ret = gtrace_disable_component(comp);
	if (ret)
		dev_err(&comp->dev, "failed to disable encoder.\n");

	return ret;
}

static const struct gtrace_component_id rvtrace_encoder_ids[] = {
	{ .type = GTRACE_RVTRACE_ENCODER,
	  .version = rvtrace_component_mkversion(1, 0), },
	{},
};

static struct gtrace_driver rvtrace_encoder_driver = {
	.id_table = rvtrace_encoder_ids,
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
