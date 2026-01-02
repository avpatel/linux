// SPDX-License-Identifier: GPL-2.0-only
/*
 * Implement EINJ FFH helper routines for RISC-V.
 *
 * Copyright (C) 2026 Qualcomm Technologies, Inc.
 */

#include <acpi/apei.h>
#include <asm/sbi.h>
#include <asm/byteorder.h>
#include <linux/mailbox/riscv-rpmi-message.h>
#include <linux/mm.h>
#include <linux/percpu.h>

#define EINJ_FFH_TYPE_BIT_SHIFT         60
#define EINJ_FFH_TYPE_BIT_MASK          (0xful)
#define EINJ_FFH_CHAN_ID_BIT_SHIFT      32
#define EINJ_FFH_CHAN_ID_BIT_MASK       (0x0fffffffUL)
#define EINJ_FFH_REG_ID_BIT_SHIFT       0
#define EINJ_FFH_REG_ID_BIT_MASK        (0xffffffffUL)

#define FFH_ADDR_TO_CHAN(_ffh)		(((uint64_t)_ffh >> EINJ_FFH_CHAN_ID_BIT_SHIFT) \
					 & EINJ_FFH_CHAN_ID_BIT_MASK)
#define FFH_ADDR_TO_REGID(_ffh)		(((uint64_t)_ffh >> EINJ_FFH_REG_ID_BIT_SHIFT) \
					 & EINJ_FFH_REG_ID_BIT_MASK)
#define FFH_ADDR_TO_TYPE(_ffh) 		(((uint64_t)_ffh >> EINJ_FFH_TYPE_BIT_SHIFT) \
					 & EINJ_FFH_TYPE_BIT_MASK)

#define EINJ_FFH_TYPE_RPMI_RAS_AGENT	0x0
#define RPMI_RAS_EINJ_READ_REG		0x07
#define RPMI_RAS_EINJ_WRITE_REG		0x08

int arch_apei_ffh_read(u64 reg, u64 *val, u32 access_bit_width)
{
	u32 channel_id = FFH_ADDR_TO_CHAN(reg);
	u32 register_id = FFH_ADDR_TO_REGID(reg);
	__le32 tx_words[1], rx_words[3];
	unsigned long rx_len;
	int ret;

	if (!sbi_mpxy_shmem_size())
		return -EINVAL;

	if (!val || access_bit_width != 64)
		return -EINVAL;

	if (FFH_ADDR_TO_TYPE(reg) != EINJ_FFH_TYPE_RPMI_RAS_AGENT)
		return -EOPNOTSUPP;

	tx_words[0] = cpu_to_le32(register_id);
	ret = sbi_mpxy_send_message_with_resp(channel_id, RPMI_RAS_EINJ_READ_REG,
					      tx_words, sizeof(tx_words),
					      rx_words, sizeof(rx_words),
					      &rx_len);
	if (rx_len != sizeof(rx_words))
		return -EIO;
	if (ret)
		return ret;

	ret = rpmi_to_linux_error(le32_to_cpu(rx_words[0]));
	if (ret)
		return ret;

	*val = ((u64)le32_to_cpu(rx_words[2]) << 32) | le32_to_cpu(rx_words[1]);
	return 0;
}

int arch_apei_ffh_write(u64 reg, u64 val, u32 access_bit_width)
{
	u32 channel_id = FFH_ADDR_TO_CHAN(reg);
	u32 register_id = FFH_ADDR_TO_REGID(reg);
	__le32 tx_words[3], rx_words[1];
	unsigned long rx_len;
	int ret;

	if (!sbi_mpxy_shmem_size())
		return -EINVAL;

	if (access_bit_width != 64)
		return -EINVAL;

	if (FFH_ADDR_TO_TYPE(reg) != EINJ_FFH_TYPE_RPMI_RAS_AGENT)
		return -EOPNOTSUPP;

	tx_words[0] = cpu_to_le32(register_id);
	tx_words[1] = cpu_to_le32(lower_32_bits(val));
	tx_words[2] = cpu_to_le32(upper_32_bits(val));

	ret = sbi_mpxy_send_message_with_resp(channel_id, RPMI_RAS_EINJ_WRITE_REG,
					      tx_words, sizeof(tx_words),
					      rx_words, sizeof(rx_words),
					      &rx_len);
	if (rx_len != sizeof(rx_words))
		return -EIO;
	if (ret)
		return ret;

	return rpmi_to_linux_error(le32_to_cpu(rx_words[0]));
}

bool arch_apei_ffh_supported(void)
{
	return true;
}
