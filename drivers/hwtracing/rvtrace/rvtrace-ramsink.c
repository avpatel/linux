// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Qualcomm Technologies, Inc.
 */

#include <linux/device.h>
#include <linux/platform_device.h>
#include <linux/property.h>
#include <linux/dma-mapping.h>
#include <linux/rvtrace.h>
#include <linux/types.h>
#include <linux/sizes.h>

#define RVTRACE_RAMSINK_STARTLOW_OFF		0x010
#define RVTRACE_RAMSINK_STARTHIGH_OFF		0x014
#define RVTRACE_RAMSINK_LIMITLOW_OFF		0x018
#define RVTRACE_RAMSINK_LIMITHIGH_OFF		0x01c
#define RVTRACE_RAMSINK_WPLOW_OFF		0x020
#define RVTRACE_RAMSINK_WPHIGH_OFF		0x024
#define RVTRACE_RAMSINK_WPLOW_WRAP		0x1
#define RVTRACE_RAMSINK_CTRL_MODE_SHIFT		0x4
#define RVTRACE_RAMSINK_CTRL_STP_WRAP_SHIFT	0x8

enum rvtrace_ramsink_mode {
	MODE_SRAM,
	MODE_SMEM
};

struct rvtrace_ramsink_priv {
	size_t size;
	void *va;
	dma_addr_t start;
	dma_addr_t end;
	enum rvtrace_ramsink_mode mode;
	bool stop_on_wrap;
	int mem_acc_width;
	u64 prev_wp;
};

struct trace_buf {
	void *base;
	size_t cur;
	size_t len;
};

static int rvtrace_ramsink_start(struct rvtrace_component *comp)
{
	int ret;
	u32 val;

	val = rvtrace_read32(comp->pdata, RVTRACE_COMPONENT_CTRL_OFFSET);
	val |= BIT(RVTRACE_COMPONENT_CTRL_ENABLE_SHIFT);
	rvtrace_write32(comp->pdata, val, RVTRACE_COMPONENT_CTRL_OFFSET);
	ret = rvtrace_poll_bit(comp->pdata, RVTRACE_COMPONENT_CTRL_OFFSET,
			       RVTRACE_COMPONENT_CTRL_ENABLE_SHIFT, 1,
			       comp->pdata->control_poll_timeout_usecs);
	if (ret)
		dev_err(&comp->dev, "failed to start ramsink.\n");

	return ret;
}

static int rvtrace_ramsink_stop(struct rvtrace_component *comp)
{
	int ret;
	u32 val;

	val = rvtrace_read32(comp->pdata, RVTRACE_COMPONENT_CTRL_OFFSET);
	val &= ~BIT(RVTRACE_COMPONENT_CTRL_ENABLE_SHIFT);
	rvtrace_write32(comp->pdata, val, RVTRACE_COMPONENT_CTRL_OFFSET);
	ret = rvtrace_poll_bit(comp->pdata, RVTRACE_COMPONENT_CTRL_OFFSET,
			       RVTRACE_COMPONENT_CTRL_ENABLE_SHIFT, 0,
			       comp->pdata->control_poll_timeout_usecs);
	if (ret) {
		dev_err(&comp->dev, "failed to stop ramsink.\n");
		return ret;
	}

	return rvtrace_comp_poll_empty(comp);
}

static void tbuf_to_pbuf_copy(struct trace_buf *src, struct trace_buf *dst, size_t size)
{
	int bytes_dst, bytes_src, bytes;
	void *dst_addr, *src_addr;

	/* If destination cannot hold entire source buffer then write only the latest data. */
	if (dst->len < size) {
		src->cur = (src->cur + size - dst->len) % src->len;
		size = dst->len;
	}

	while (size) {
		src_addr = src->base + src->cur;
		dst_addr = dst->base + dst->cur;

		/* Ensure that there are no OOB memory accesses */
		if (dst->len - dst->cur < size)
			bytes_dst = dst->len - dst->cur;
		else
			bytes_dst = size;

		if (src->len - src->cur < size)
			bytes_src = src->len - src->cur;
		else
			bytes_src = size;
		bytes = bytes_dst < bytes_src ? bytes_dst : bytes_src;
		memcpy(dst_addr, src_addr, bytes);
		dst->cur = (dst->cur + bytes) % dst->len;
		src->cur = (src->cur + bytes) % src->len;
		size -= bytes;
	}
}

static size_t rvtrace_ramsink_copyto_auxbuf(struct rvtrace_component *comp,
					    struct rvtrace_perf_auxbuf *buf)
{
	struct rvtrace_ramsink_priv *priv = dev_get_drvdata(&comp->dev);
	struct trace_buf src, dst;
	u32 wp_low, wp_high;
	size_t bytes = 0;
	bool wrap;
	u64 wp;

	dst.base = buf->base;
	dst.len = buf->length;
	dst.cur = buf->pos;
	src.base = priv->va;
	src.len = priv->size;
	wp_low = rvtrace_read32(comp->pdata, RVTRACE_RAMSINK_WPLOW_OFF);
	wp_high = rvtrace_read32(comp->pdata, RVTRACE_RAMSINK_WPHIGH_OFF);
	wp = (u64)(wp_high) << 32 | wp_low;
	wrap = wp & RVTRACE_RAMSINK_WPLOW_WRAP;
	wp &= ~RVTRACE_RAMSINK_WPLOW_WRAP;
	if (wrap) {
		rvtrace_write32(comp->pdata, lower_32_bits(priv->start),
				RVTRACE_RAMSINK_WPLOW_OFF);
		rvtrace_write32(comp->pdata, upper_32_bits(priv->start),
				RVTRACE_RAMSINK_WPHIGH_OFF);
		src.cur = wp - priv->start;
		priv->prev_wp = priv->start;
		/*
		 * There is no way to tell if trRamWp wrapped around more than once. As a
		 * result priv->prev_wp can't be used and the entire buffer must be copied
		 * even though some data might be duplicated.
		 */
		bytes = priv->size;
	} else {
		src.cur =  priv->prev_wp - priv->start;
		bytes = wp - priv->prev_wp;
		priv->prev_wp = wp;
	}

	tbuf_to_pbuf_copy(&src, &dst, bytes);
	dev_dbg(&comp->dev, "Copied %zu bytes\n", bytes);
	return bytes;
}

static int rvtrace_ramsink_setup_buf(struct rvtrace_component *comp,
				     struct rvtrace_ramsink_priv *priv)
{
	struct device *pdev = comp->pdata->dev;
	u64 start_min, limit_max, end;
	u32 low, high;
	int ret;

	/* Probe min and max values for start and limit registers */
	rvtrace_write32(comp->pdata, 0, RVTRACE_RAMSINK_STARTLOW_OFF);
	rvtrace_write32(comp->pdata, 0, RVTRACE_RAMSINK_STARTHIGH_OFF);
	low = rvtrace_read32(comp->pdata, RVTRACE_RAMSINK_STARTLOW_OFF);
	high = rvtrace_read32(comp->pdata, RVTRACE_RAMSINK_STARTHIGH_OFF);
	start_min = (u64)(high) << 32 | low;

	rvtrace_write32(comp->pdata, 0xffffffff, RVTRACE_RAMSINK_LIMITLOW_OFF);
	rvtrace_write32(comp->pdata, 0xffffffff, RVTRACE_RAMSINK_LIMITHIGH_OFF);
	low = rvtrace_read32(comp->pdata, RVTRACE_RAMSINK_LIMITLOW_OFF);
	high = rvtrace_read32(comp->pdata, RVTRACE_RAMSINK_LIMITHIGH_OFF);
	limit_max = (u64)(high) << 32 | low;

	/* Set DMA mask based on the maximum allowed limit address */
	ret = dma_set_mask_and_coherent(pdev, DMA_BIT_MASK(fls64(limit_max)));
	if (ret)
		return ret;

	priv->va = dma_alloc_coherent(pdev, priv->size, &priv->start, GFP_KERNEL);
	if (!priv->va)
		return -ENOMEM;

	priv->end = priv->start + priv->size;
	priv->prev_wp = priv->start;
	if (priv->end <= start_min || priv->start >= limit_max) {
		dma_free_coherent(pdev, priv->size, priv->va, priv->start);
		dev_err(&comp->dev, "DMA memory not addressable by device\n");
		return -EINVAL;
	}

	/* Setup ram sink start addresses */
	if (priv->start < start_min) {
		dev_warn(&comp->dev, "Ramsink start address updated from %pad to %pad\n",
			 &priv->start, &start_min);
		priv->va += start_min - priv->start;
		priv->start = start_min;
	}

	rvtrace_write32(comp->pdata, lower_32_bits(priv->start), RVTRACE_RAMSINK_STARTLOW_OFF);
	rvtrace_write32(comp->pdata, upper_32_bits(priv->start), RVTRACE_RAMSINK_STARTHIGH_OFF);
	rvtrace_write32(comp->pdata, lower_32_bits(priv->start), RVTRACE_RAMSINK_WPLOW_OFF);
	rvtrace_write32(comp->pdata, upper_32_bits(priv->start), RVTRACE_RAMSINK_WPHIGH_OFF);
	/* Setup ram sink limit addresses */
	if (priv->end > limit_max) {
		dev_warn(&comp->dev, "Ramsink limit address updated from %pad to %pad\n",
			 &priv->end, &limit_max);
		priv->end = limit_max;
		priv->size = priv->end - priv->start;
	}

	/* Limit address needs to be set to end - mem_access_width to avoid overflow */
	end = priv->end - priv->mem_acc_width;
	rvtrace_write32(comp->pdata, lower_32_bits(end), RVTRACE_RAMSINK_LIMITLOW_OFF);
	rvtrace_write32(comp->pdata, upper_32_bits(end), RVTRACE_RAMSINK_LIMITHIGH_OFF);
	low = rvtrace_read32(comp->pdata, RVTRACE_RAMSINK_LIMITLOW_OFF);
	high = rvtrace_read32(comp->pdata, RVTRACE_RAMSINK_LIMITHIGH_OFF);
	end = (u64)(high) << 32 | low;
	if (end != (priv->end - 4)) {
		dev_warn(&comp->dev, "Ramsink limit address updated from %pad to %pad\n",
			 &priv->end, &end);
		priv->end = end;
		priv->size = priv->end - priv->start;
	}

	return 0;
}

static int rvtrace_ramsink_setup(struct rvtrace_component *comp)
{
	struct rvtrace_ramsink_priv *priv;
	u32 trram_ctrl;
	int ret;

	priv = devm_kzalloc(&comp->dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	/* Derive RAM sink memory size based on component implementation ID */
	switch (comp->pdata->impid) {
	default:
		priv->size = SZ_1M;
		priv->mode = MODE_SMEM;
		priv->stop_on_wrap = false;
		priv->mem_acc_width = 4;
		break;
	}

	trram_ctrl = rvtrace_read32(comp->pdata, RVTRACE_COMPONENT_CTRL_OFFSET);
	trram_ctrl |= priv->mode << RVTRACE_RAMSINK_CTRL_MODE_SHIFT;
	rvtrace_write32(comp->pdata, trram_ctrl, RVTRACE_COMPONENT_CTRL_OFFSET);
	trram_ctrl = rvtrace_read32(comp->pdata, RVTRACE_COMPONENT_CTRL_OFFSET);
	dev_dbg(&comp->dev, "mode: %s\n", (trram_ctrl >> RVTRACE_RAMSINK_CTRL_MODE_SHIFT) & 0x1 ?
		 "SMEM" : "SRAM");

	trram_ctrl |= priv->stop_on_wrap << RVTRACE_RAMSINK_CTRL_STP_WRAP_SHIFT;
	rvtrace_write32(comp->pdata, trram_ctrl, RVTRACE_COMPONENT_CTRL_OFFSET);

	ret = rvtrace_ramsink_setup_buf(comp, priv);
	if (!ret)
		dev_set_drvdata(&comp->dev, priv);

	return ret;
}

static void rvtrace_ramsink_cleanup(struct rvtrace_component *comp)
{
	struct rvtrace_ramsink_priv *priv = dev_get_drvdata(&comp->dev);

	dma_free_coherent(comp->pdata->dev, priv->size, priv->va, priv->start);
}

static int rvtrace_ramsink_probe(struct rvtrace_component *comp)
{
	int ret;

	ret = rvtrace_ramsink_setup(comp);
	if (ret)
		return dev_err_probe(&comp->dev, ret, "failed to setup ramsink.\n");

	ret = rvtrace_enable_component(comp->pdata);
	if (ret)
		return dev_err_probe(&comp->dev, ret, "failed to enable ramsink.\n");

	return ret;
}

static void rvtrace_ramsink_remove(struct rvtrace_component *comp)
{
	int ret;

	ret = rvtrace_disable_component(comp->pdata);
	if (ret)
		dev_err(&comp->dev, "failed to disable ramsink.\n");

	rvtrace_ramsink_cleanup(comp);
}

static struct rvtrace_component_id rvtrace_ramsink_ids[] = {
	{ .type = RVTRACE_COMPONENT_TYPE_RAMSINK,
	  .version = rvtrace_component_mkversion(1, 0), },
	{},
};

static struct rvtrace_driver rvtrace_ramsink_driver = {
	.id_table = rvtrace_ramsink_ids,
	.copyto_auxbuf = rvtrace_ramsink_copyto_auxbuf,
	.stop = rvtrace_ramsink_stop,
	.start = rvtrace_ramsink_start,
	.probe = rvtrace_ramsink_probe,
	.remove = rvtrace_ramsink_remove,
	.driver = {
		.name = "rvtrace-ramsink",
	},
};

static int __init rvtrace_ramsink_init(void)
{
	return rvtrace_register_driver(&rvtrace_ramsink_driver);
}

static void __exit rvtrace_ramsink_exit(void)
{
	rvtrace_unregister_driver(&rvtrace_ramsink_driver);
}

module_init(rvtrace_ramsink_init);
module_exit(rvtrace_ramsink_exit);

/* Module information */
MODULE_AUTHOR("Mayuresh Chitale");
MODULE_DESCRIPTION("RISC-V Trace Ramsink Driver");
MODULE_LICENSE("GPL");
