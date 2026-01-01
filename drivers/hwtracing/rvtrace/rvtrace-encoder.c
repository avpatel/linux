// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Qualcomm Technologies, Inc.
 */

#include <linux/device.h>
#include <linux/rvtrace.h>
#include <linux/types.h>

#define RVTRACE_COMPONENT_CTRL_ITRACE_SHIFT	2
#define RVTRACE_COMPONENT_CTRL_INSTMODE_SHIFT	4
#define RVTRACE_COMPONENT_CTRL_INSTMODE_OPIT	0x6

static int rvtrace_encoder_start(struct rvtrace_component *comp)
{
	int ret;
	u32 val;

	val = rvtrace_read32(comp->pdata, RVTRACE_COMPONENT_CTRL_OFFSET);
	val |= BIT(RVTRACE_COMPONENT_CTRL_ENABLE_SHIFT);
	rvtrace_write32(comp->pdata, val, RVTRACE_COMPONENT_CTRL_OFFSET);
	ret = rvtrace_poll_bit(comp->pdata, RVTRACE_COMPONENT_CTRL_OFFSET,
			       RVTRACE_COMPONENT_CTRL_ENABLE_SHIFT, 1,
			       comp->pdata->control_poll_timeout_usecs);
	if (ret) {
		dev_err(&comp->dev, "failed to enable encoder.\n");
		return ret;
	}

	/* set mode */
	val = rvtrace_read32(comp->pdata, RVTRACE_COMPONENT_CTRL_OFFSET);
	val |= (RVTRACE_COMPONENT_CTRL_INSTMODE_OPIT << RVTRACE_COMPONENT_CTRL_INSTMODE_SHIFT);
	rvtrace_write32(comp->pdata, val, RVTRACE_COMPONENT_CTRL_OFFSET);

	val = rvtrace_read32(comp->pdata, RVTRACE_COMPONENT_CTRL_OFFSET);
	val |= BIT(RVTRACE_COMPONENT_CTRL_ITRACE_SHIFT);
	rvtrace_write32(comp->pdata, val, RVTRACE_COMPONENT_CTRL_OFFSET);
	ret = rvtrace_poll_bit(comp->pdata, RVTRACE_COMPONENT_CTRL_OFFSET,
			       RVTRACE_COMPONENT_CTRL_ITRACE_SHIFT, 1,
			       comp->pdata->control_poll_timeout_usecs);
	if (ret)
		dev_err(&comp->dev, "failed to enable tracing.\n");

	return ret;
}

static int rvtrace_encoder_stop(struct rvtrace_component *comp)
{
	int ret;
	u32 val;

	val = rvtrace_read32(comp->pdata, RVTRACE_COMPONENT_CTRL_OFFSET);
	val &= ~BIT(RVTRACE_COMPONENT_CTRL_ITRACE_SHIFT);
	rvtrace_write32(comp->pdata, val, RVTRACE_COMPONENT_CTRL_OFFSET);
	ret = rvtrace_poll_bit(comp->pdata, RVTRACE_COMPONENT_CTRL_OFFSET,
			       RVTRACE_COMPONENT_CTRL_ITRACE_SHIFT, 0,
			       comp->pdata->control_poll_timeout_usecs);
	if (ret) {
		dev_err(&comp->dev, "failed to stop tracing.\n");
		return ret;
	}

	val = rvtrace_read32(comp->pdata, RVTRACE_COMPONENT_CTRL_OFFSET);
	val &= ~BIT(RVTRACE_COMPONENT_CTRL_ENABLE_SHIFT);
	rvtrace_write32(comp->pdata, val, RVTRACE_COMPONENT_CTRL_OFFSET);
	ret = rvtrace_poll_bit(comp->pdata, RVTRACE_COMPONENT_CTRL_OFFSET,
			       RVTRACE_COMPONENT_CTRL_ENABLE_SHIFT, 0,
			       comp->pdata->control_poll_timeout_usecs);
	if (ret) {
		dev_err(&comp->dev, "failed to disable encoder.\n");
		return ret;
	}

	return rvtrace_comp_poll_empty(comp);
}

static int rvtrace_encoder_probe(struct rvtrace_component *comp)
{
	int ret;

	ret = rvtrace_enable_component(comp->pdata);
	if (ret)
		return dev_err_probe(&comp->dev, ret, "failed to enable encoder.\n");

	return 0;
}

static void rvtrace_encoder_remove(struct rvtrace_component *comp)
{
	int ret;

	ret = rvtrace_disable_component(comp->pdata);
	if (ret)
		dev_err(&comp->dev, "failed to disable encoder.\n");
}

static struct rvtrace_component_id rvtrace_encoder_ids[] = {
	{ .type = RVTRACE_COMPONENT_TYPE_ENCODER,
	  .version = rvtrace_component_mkversion(1, 0), },
	{},
};

static struct rvtrace_driver rvtrace_encoder_driver = {
	.id_table = rvtrace_encoder_ids,
	.start = rvtrace_encoder_start,
	.stop = rvtrace_encoder_stop,
	.probe = rvtrace_encoder_probe,
	.remove = rvtrace_encoder_remove,
	.driver = {
		.name = "rvtrace-encoder",
	},
};

static int __init rvtrace_encoder_init(void)
{
	return rvtrace_register_driver(&rvtrace_encoder_driver);
}

static void __exit rvtrace_encoder_exit(void)
{
	rvtrace_unregister_driver(&rvtrace_encoder_driver);
}

module_init(rvtrace_encoder_init);
module_exit(rvtrace_encoder_exit);

/* Module information */
MODULE_AUTHOR("Mayuresh Chitale");
MODULE_DESCRIPTION("RISC-V Trace Encoder Driver");
MODULE_LICENSE("GPL");
