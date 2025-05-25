// SPDX-License-Identifier: GPL-2.0-only
/*
 * Implement EINJ FFH helper routines for RISC-V.
 *
 * Copyright (C) 2025 Ventana Micro Systems Inc.
 */

#include <asm/sbi.h>
#include <acpi/apei.h>

#define EINJ_FFH_TYPE_BIT_SHIFT         60
#define EINJ_FFH_TYPE_BIT_MASK          (0xful)
#define EINJ_FFH_CHAN_ID_BIT_SHIFT      8
#define EINJ_FFH_CHAN_ID_BIT_MASK       (0xffffffULL)
#define EINJ_FFH_MSG_ID_BIT_SHIFT       0
#define EINJ_FFH_MSG_ID_BIT_MASK        (0xfful)

#define FFH_ADDR_TO_CHAN(_ffh)		(((uint64_t)_ffh >> EINJ_FFH_CHAN_ID_BIT_SHIFT) \
					 & EINJ_FFH_CHAN_ID_BIT_MASK)
#define FFH_ADDR_TO_MSGID(_ffh)		(((uint64_t)_ffh >> EINJ_FFH_MSG_ID_BIT_SHIFT) \
					 & EINJ_FFH_MSG_ID_BIT_MASK)
#define FFH_ADDR_TO_TYPE(_ffh) 		(((uint64_t)_ffh >> EINJ_FFH_TYPE_BIT_SHIFT) \
					 & EINJ_FFH_TYPE_BIT_MASK)

static bool mpxy_ext_present;

static int mpxy_send_message_without_resp(u32 channel_id, u32 msg_id)
{
	struct sbiret sret;

	sret = sbi_ecall(SBI_EXT_MPXY, SBI_EXT_MPXY_SEND_MSG_WITHOUT_RESP,
			 channel_id, msg_id, 0, 0, 0, 0);

	return sbi_err_map_linux_errno(sret.error);
}

static int __init sbi_einj_init(void)
{
	/* Probe for SBI MPXY extension */
	if (sbi_spec_version < sbi_mk_version(3, 0) ||
	    sbi_probe_extension(SBI_EXT_MPXY) <= 0) {
		printk(KERN_INFO "%s: SBI MPXY extension not available\n", __func__);
		mpxy_ext_present = false;
		return -ENODEV;
	}

	mpxy_ext_present = true;

	return 0;
}
device_initcall(sbi_einj_init);

int arch_apei_ffh_read(u64 reg, u64 *val, u32 access_bit_width)
{
	if (!mpxy_ext_present)
		return -EINVAL;

	/* TODO: */
	return -ENOTSUPP;
}

int arch_apei_ffh_write(u64 reg, u64 val, u32 access_bit_width)
{
	uint64_t mpxy_chan = FFH_ADDR_TO_CHAN(reg);
	uint64_t msg_id = FFH_ADDR_TO_MSGID(reg);

	if (!mpxy_ext_present)
		return -EINVAL;

	/* TODO: */
	mpxy_send_message_without_resp(mpxy_chan, msg_id);

	return 0;
}

bool arch_apei_ffh_supported(void)
{
	return true;
}
