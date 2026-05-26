// SPDX-License-Identifier: GPL-2.0-only
/*
 * Common SBI MPXY access library.
 *
 * Copyright (c) 2026 Qualcomm Technologies, Inc.
 */

#define pr_fmt(fmt) "riscv: " fmt
#include <linux/cpu.h>
#include <linux/init.h>
#include <linux/percpu.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/types.h>
#include <asm/byteorder.h>
#include <asm/sbi.h>

/* SBI MPXY channel IDs data in shared memory */
struct sbi_mpxy_channel_ids_data {
	/* Remaining number of channel ids */
	__le32 remaining;
	/* Returned channel ids in current function call */
	__le32 returned;
	/* Returned channel id array */
	__le32 channel_array[];
};

/* MPXY Per-CPU or local context */
struct mpxy_local {
	/* Shared memory base address */
	void *shmem;
	/* Shared memory physical address */
	phys_addr_t shmem_phys_addr;
	/* Flag representing whether shared memory is active or not */
	bool shmem_active;
};

static DEFINE_PER_CPU(struct mpxy_local, mpxy_local);
static unsigned long mpxy_shmem_size;
static bool mpxy_shmem_init_done;

unsigned long sbi_mpxy_shmem_size(void)
{
	if (!mpxy_shmem_init_done)
		return 0;
	return mpxy_shmem_size;
}
EXPORT_SYMBOL_GPL(sbi_mpxy_shmem_size);

int sbi_mpxy_get_channel_count(u32 *channel_count)
{
	struct mpxy_local *mpxy = this_cpu_ptr(&mpxy_local);
	struct sbi_mpxy_channel_ids_data *sdata = mpxy->shmem;
	u32 remaining, returned;
	struct sbiret sret;

	if (!mpxy->shmem_active)
		return -ENODEV;
	if (!channel_count)
		return -EINVAL;

	get_cpu();

	/* Get the remaining and returned fields to calculate total */
	sret = sbi_ecall(SBI_EXT_MPXY, SBI_EXT_MPXY_GET_CHANNEL_IDS,
			 0, 0, 0, 0, 0, 0);
	if (sret.error)
		goto err_put_cpu;

	remaining = le32_to_cpu(sdata->remaining);
	returned = le32_to_cpu(sdata->returned);
	*channel_count = remaining + returned;

err_put_cpu:
	put_cpu();
	return sbi_err_map_linux_errno(sret.error);
}
EXPORT_SYMBOL_GPL(sbi_mpxy_get_channel_count);

int sbi_mpxy_get_channel_ids(u32 channel_count, u32 *channel_ids)
{
	struct mpxy_local *mpxy = this_cpu_ptr(&mpxy_local);
	struct sbi_mpxy_channel_ids_data *sdata = mpxy->shmem;
	u32 remaining, returned, count, start_index = 0;
	struct sbiret sret;

	if (!mpxy->shmem_active)
		return -ENODEV;
	if (!channel_count || !channel_ids)
		return -EINVAL;

	get_cpu();

	do {
		sret = sbi_ecall(SBI_EXT_MPXY, SBI_EXT_MPXY_GET_CHANNEL_IDS,
				 start_index, 0, 0, 0, 0, 0);
		if (sret.error)
			goto err_put_cpu;

		remaining = le32_to_cpu(sdata->remaining);
		returned = le32_to_cpu(sdata->returned);

		count = returned < (channel_count - start_index) ?
			returned : (channel_count - start_index);
		memcpy_from_le32(&channel_ids[start_index], sdata->channel_array, count);
		start_index += count;
	} while (remaining && start_index < channel_count);

err_put_cpu:
	put_cpu();
	return sbi_err_map_linux_errno(sret.error);
}
EXPORT_SYMBOL_GPL(sbi_mpxy_get_channel_ids);

int sbi_mpxy_read_attrs(u32 channel_id, u32 base_attrid, u32 attr_count,
			u32 *attrs_buf)
{
	struct mpxy_local *mpxy = this_cpu_ptr(&mpxy_local);
	struct sbiret sret;

	if (!mpxy->shmem_active)
		return -ENODEV;
	if (!attr_count || !attrs_buf)
		return -EINVAL;

	get_cpu();

	sret = sbi_ecall(SBI_EXT_MPXY, SBI_EXT_MPXY_READ_ATTRS,
			 channel_id, base_attrid, attr_count, 0, 0, 0);
	if (sret.error)
		goto err_put_cpu;

	memcpy_from_le32(attrs_buf, (__le32 *)mpxy->shmem, attr_count);

err_put_cpu:
	put_cpu();
	return sbi_err_map_linux_errno(sret.error);
}
EXPORT_SYMBOL_GPL(sbi_mpxy_read_attrs);

int sbi_mpxy_write_attrs(u32 channel_id, u32 base_attrid, u32 attr_count,
			 u32 *attrs_buf)
{
	struct mpxy_local *mpxy = this_cpu_ptr(&mpxy_local);
	struct sbiret sret;

	if (!mpxy->shmem_active)
		return -ENODEV;
	if (!attr_count || !attrs_buf)
		return -EINVAL;

	get_cpu();

	memcpy_to_le32((__le32 *)mpxy->shmem, attrs_buf, attr_count);
	sret = sbi_ecall(SBI_EXT_MPXY, SBI_EXT_MPXY_WRITE_ATTRS,
			 channel_id, base_attrid, attr_count, 0, 0, 0);

	put_cpu();
	return sbi_err_map_linux_errno(sret.error);
}
EXPORT_SYMBOL_GPL(sbi_mpxy_write_attrs);

int sbi_mpxy_send_message_with_resp(u32 channel_id, u32 msg_id,
				    void *tx, unsigned long tx_len,
				    void *rx, unsigned long max_rx_len,
				    unsigned long *rx_len)
{
	struct mpxy_local *mpxy = this_cpu_ptr(&mpxy_local);
	unsigned long rx_bytes;
	struct sbiret sret;

	if (!mpxy->shmem_active)
		return -ENODEV;
	if (!tx && tx_len)
		return -EINVAL;

	get_cpu();

	/* Message protocols allowed to have no data in messages */
	if (tx_len)
		memcpy(mpxy->shmem, tx, tx_len);

	sret = sbi_ecall(SBI_EXT_MPXY, SBI_EXT_MPXY_SEND_MSG_WITH_RESP,
			 channel_id, msg_id, tx_len, 0, 0, 0);
	if (rx && !sret.error) {
		rx_bytes = sret.value;
		if (rx_bytes > max_rx_len) {
			put_cpu();
			return -ENOSPC;
		}

		memcpy(rx, mpxy->shmem, rx_bytes);
		if (rx_len)
			*rx_len = rx_bytes;
	}

	put_cpu();
	return sbi_err_map_linux_errno(sret.error);
}
EXPORT_SYMBOL_GPL(sbi_mpxy_send_message_with_resp);

int sbi_mpxy_send_message_without_resp(u32 channel_id, u32 msg_id,
				       void *tx, unsigned long tx_len)
{
	struct mpxy_local *mpxy = this_cpu_ptr(&mpxy_local);
	struct sbiret sret;

	if (!mpxy->shmem_active)
		return -ENODEV;
	if (!tx && tx_len)
		return -EINVAL;

	get_cpu();

	/* Message protocols allowed to have no data in messages */
	if (tx_len)
		memcpy(mpxy->shmem, tx, tx_len);

	sret = sbi_ecall(SBI_EXT_MPXY, SBI_EXT_MPXY_SEND_MSG_WITHOUT_RESP,
			 channel_id, msg_id, tx_len, 0, 0, 0);

	put_cpu();
	return sbi_err_map_linux_errno(sret.error);
}
EXPORT_SYMBOL_GPL(sbi_mpxy_send_message_without_resp);

int sbi_mpxy_get_notifications(u32 channel_id,
			       struct sbi_mpxy_notification_data *notif_data,
			       unsigned long *events_data_len)
{
	struct mpxy_local *mpxy = this_cpu_ptr(&mpxy_local);
	struct sbiret sret;

	if (!mpxy->shmem_active)
		return -ENODEV;
	if (!notif_data || !events_data_len)
		return -EINVAL;

	get_cpu();

	sret = sbi_ecall(SBI_EXT_MPXY, SBI_EXT_MPXY_GET_NOTIFICATION_EVENTS,
			 channel_id, 0, 0, 0, 0, 0);
	if (sret.error)
		goto err_put_cpu;

	memcpy(notif_data, mpxy->shmem, sret.value + 16);
	*events_data_len = sret.value;

err_put_cpu:
	put_cpu();
	return sbi_err_map_linux_errno(sret.error);
}
EXPORT_SYMBOL_GPL(sbi_mpxy_get_notifications);

static int mpxy_get_shmem_size(unsigned long *shmem_size)
{
	struct sbiret sret;

	sret = sbi_ecall(SBI_EXT_MPXY, SBI_EXT_MPXY_GET_SHMEM_SIZE,
			 0, 0, 0, 0, 0, 0);
	if (sret.error)
		return sbi_err_map_linux_errno(sret.error);
	if (shmem_size)
		*shmem_size = sret.value;
	return 0;
}

static int mpxy_setup_shmem(unsigned int cpu)
{
	struct page *shmem_page;
	struct mpxy_local *mpxy;
	struct sbiret sret;

	mpxy = per_cpu_ptr(&mpxy_local, cpu);
	if (mpxy->shmem_active)
		return 0;

	shmem_page = alloc_pages(GFP_KERNEL | __GFP_ZERO, get_order(mpxy_shmem_size));
	if (!shmem_page)
		return -ENOMEM;

	/*
	 * Linux setup of shmem is done in mpxy OVERWRITE mode.
	 * flags[1:0] = 00b
	 */
	sret = sbi_ecall(SBI_EXT_MPXY, SBI_EXT_MPXY_SET_SHMEM,
			 page_to_phys(shmem_page), 0, 0, 0, 0, 0);
	if (sret.error) {
		free_pages((unsigned long)page_to_virt(shmem_page),
			   get_order(mpxy_shmem_size));
		return sbi_err_map_linux_errno(sret.error);
	}

	mpxy->shmem = page_to_virt(shmem_page);
	mpxy->shmem_phys_addr = page_to_phys(shmem_page);
	mpxy->shmem_active = true;

	return 0;
}

static int __init sbi_mpxy_init(void)
{
	int rc;

	/* Skip quietly when MPXY extension is not supported. */
	if (sbi_spec_version < sbi_mk_version(3, 0) ||
	    !sbi_probe_extension(SBI_EXT_MPXY))
		return 0;
	pr_info("SBI MPXY extension detected\n");

	/* Find-out shared memory size */
	rc = mpxy_get_shmem_size(&mpxy_shmem_size);
	if (rc) {
		pr_err("failed to get MPXY shared memory size\n");
		return rc;
	}

	/*
	 * Setup MPXY shared memory on each CPU
	 *
	 * Note: Don't cleanup MPXY shared memory upon CPU power-down
	 * because the RPMI System MSI irqchip driver needs it to be
	 * available when migrating IRQs in CPU power-down path.
	 */
	rc = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "riscv/sbi-mpxy-shmem",
			       mpxy_setup_shmem, NULL);
	if (rc < 0)
		return rc;

	/* Mark as MPXY shared memory initialization done */
	mpxy_shmem_init_done = true;
	return 0;
}
arch_initcall(sbi_mpxy_init);
