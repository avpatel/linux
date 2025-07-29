// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2025 Ventana Micro Systems Inc.
 */

#include <linux/device.h>
#include <linux/io.h>
#include <linux/of.h>
#include <linux/of_graph.h>
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
#define RVTRACE_RAMSINK_RPLOW_OFF		0x028
#define RVTRACE_RAMSINK_RPHIGH_OFF		0x02c

struct rvtrace_ramsink_priv {
	size_t size;
	void *va;
	dma_addr_t start;
	dma_addr_t end;
	/* WP from prev iteration */
	dma_addr_t prev_head;
};

struct trace_buf {
	void *base;
	size_t size;
	int cur, len;
};

static void tbuf_to_pbuf_copy(struct trace_buf *src, struct trace_buf *dst)
{
	int bytes_dst, bytes_src, bytes;
	void *dst_addr, *src_addr;

	while (src->size) {
		src_addr = src->base + src->cur;
		dst_addr = dst->base + dst->cur;

		if (dst->len - dst->cur < src->size)
			bytes_dst = dst->len - dst->cur;
		else
			bytes_dst = src->size;
		if (src->len - src->cur < src->size)
			bytes_src = src->len - src->cur;
		else
			bytes_src = src->size;
		bytes = bytes_dst < bytes_src ? bytes_dst : bytes_src;
		memcpy(dst_addr, src_addr, bytes);
		dst->cur = (dst->cur + bytes) % dst->len;
		src->cur = (src->cur + bytes) % src->len;
		src->size -= bytes;
	}
}

static size_t rvtrace_ramsink_copyto_auxbuf(struct rvtrace_component *comp,
					    struct rvtrace_perf_auxbuf *buf)
{
	struct rvtrace_ramsink_priv *priv = dev_get_drvdata(&comp->dev);
	struct trace_buf src, dst;
	u32 wp_low, wp_high;
	u64 buf_cur_head;
	size_t size;

	wp_low = rvtrace_read32(comp->pdata, RVTRACE_RAMSINK_WPLOW_OFF);
	wp_high = rvtrace_read32(comp->pdata, RVTRACE_RAMSINK_WPHIGH_OFF);
	buf_cur_head = (u64)(wp_high) << 32 | wp_low;

	if (buf_cur_head == priv->prev_head)
		return 0;

	dst.base = buf->base;
	dst.len = buf->length;
	dst.cur = buf->pos;
	dst.size = 0;

	src.base = priv->va;
	src.len = priv->end - priv->start;
	if (buf_cur_head > priv->prev_head) {
		src.size = buf_cur_head - priv->prev_head;
	} else {
		src.size = priv->end - priv->prev_head;
		src.size += buf_cur_head - priv->start;
	}

	src.cur = buf_cur_head - priv->start;
	size = src.size;
	tbuf_to_pbuf_copy(&src, &dst);
	buf->pos = dst.cur;
	priv->prev_head = buf_cur_head;

	return size;
}

static int rvtrace_ramsink_setup(struct rvtrace_component *comp)
{
	struct rvtrace_ramsink_priv *priv;

	priv = devm_kzalloc(&comp->dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;
	dev_set_drvdata(&comp->dev, priv);

	priv->size = SZ_4M;
	priv->va = dma_alloc_coherent(&comp->dev, priv->size, &priv->start, GFP_KERNEL);
	if (!priv->va)
		return -ENOMEM;
	priv->end = priv->start + priv->size;
	priv->prev_head = priv->start;

	/* Setup ram sink addresses */
	rvtrace_write32(comp->pdata, lower_32_bits(priv->start), RVTRACE_RAMSINK_STARTLOW_OFF);
	rvtrace_write32(comp->pdata, upper_32_bits(priv->start), RVTRACE_RAMSINK_STARTHIGH_OFF);
	rvtrace_write32(comp->pdata, lower_32_bits(priv->start), RVTRACE_RAMSINK_WPLOW_OFF);
	rvtrace_write32(comp->pdata, upper_32_bits(priv->start), RVTRACE_RAMSINK_WPHIGH_OFF);
	/* Limit address needs to be set to end - 4 so that HW doesn't cause an overflow. */
	rvtrace_write32(comp->pdata, lower_32_bits(priv->end - 0x4), RVTRACE_RAMSINK_LIMITLOW_OFF);
	rvtrace_write32(comp->pdata, upper_32_bits(priv->end), RVTRACE_RAMSINK_LIMITHIGH_OFF);

	return 0;
}

static void rvtrace_ramsink_cleanup(struct rvtrace_component *comp)
{
	struct rvtrace_ramsink_priv *priv = dev_get_drvdata(&comp->dev);

	dma_free_coherent(&comp->dev, priv->size, priv->va, priv->start);
}

static int rvtrace_ramsink_probe(struct rvtrace_component *comp)
{
	int ret;

	ret = rvtrace_ramsink_setup(comp);
	if (ret)
		return dev_err_probe(&comp->dev, ret, "failed to setup ramsink.\n");

	ret = rvtrace_enable_component(comp);
	if (ret)
		return dev_err_probe(&comp->dev, ret, "failed to enable ramsink.\n");

	return ret;
}

static void rvtrace_ramsink_remove(struct rvtrace_component *comp)
{
	int ret;

	ret = rvtrace_disable_component(comp);
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
MODULE_AUTHOR("Mayuresh Chitale <mchitale@ventanamicro.com>");
MODULE_DESCRIPTION("RISC-V Trace Ramsink Driver");
MODULE_LICENSE("GPL");
