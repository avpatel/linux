// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2025 Ventana Micro Systems Inc.
 */

#include <linux/err.h>
#include <linux/export.h>
#include <linux/types.h>
#include <asm/csr.h>

#define CSR_CUSTOM0_U_RW_BASE		0x800
#define CSR_CUSTOM0_U_RW_COUNT		0x100

#define CSR_CUSTOM1_U_RO_BASE		0xCC0
#define CSR_CUSTOM1_U_RO_COUNT		0x040

#define CSR_CUSTOM2_S_RW_BASE		0x5C0
#define CSR_CUSTOM2_S_RW_COUNT		0x040

#define CSR_CUSTOM3_S_RW_BASE		0x9C0
#define CSR_CUSTOM3_S_RW_COUNT		0x040

#define CSR_CUSTOM4_S_RO_BASE		0xDC0
#define CSR_CUSTOM4_S_RO_COUNT		0x040

#define CSR_CUSTOM5_HS_RW_BASE		0x6C0
#define CSR_CUSTOM5_HS_RW_COUNT		0x040

#define CSR_CUSTOM6_HS_RW_BASE		0xAC0
#define CSR_CUSTOM6_HS_RW_COUNT		0x040

#define CSR_CUSTOM7_HS_RO_BASE		0xEC0
#define CSR_CUSTOM7_HS_RO_COUNT		0x040

#define CSR_CUSTOM8_M_RW_BASE		0x7C0
#define CSR_CUSTOM8_M_RW_COUNT		0x040

#define CSR_CUSTOM9_M_RW_BASE		0xBC0
#define CSR_CUSTOM9_M_RW_COUNT		0x040

#define CSR_CUSTOM10_M_RO_BASE		0xFC0
#define CSR_CUSTOM10_M_RO_COUNT		0x040

unsigned long csr_read_num(unsigned long csr_num, int *out_err)
{
#define switchcase_csr_read(__csr_num)				\
	case (__csr_num):					\
		return csr_read(__csr_num)
#define switchcase_csr_read_2(__csr_num)			\
	switchcase_csr_read(__csr_num + 0);			\
	switchcase_csr_read(__csr_num + 1)
#define switchcase_csr_read_4(__csr_num)			\
	switchcase_csr_read_2(__csr_num + 0);			\
	switchcase_csr_read_2(__csr_num + 2)
#define switchcase_csr_read_8(__csr_num)			\
	switchcase_csr_read_4(__csr_num + 0);			\
	switchcase_csr_read_4(__csr_num + 4)
#define switchcase_csr_read_16(__csr_num)			\
	switchcase_csr_read_8(__csr_num + 0);			\
	switchcase_csr_read_8(__csr_num + 8)
#define switchcase_csr_read_32(__csr_num)			\
	switchcase_csr_read_16(__csr_num + 0);			\
	switchcase_csr_read_16(__csr_num + 16)
#define switchcase_csr_read_64(__csr_num)			\
	switchcase_csr_read_32(__csr_num + 0);			\
	switchcase_csr_read_32(__csr_num + 32)
#define switchcase_csr_read_128(__csr_num)			\
	switchcase_csr_read_64(__csr_num + 0);			\
	switchcase_csr_read_64(__csr_num + 64)
#define switchcase_csr_read_256(__csr_num)			\
	switchcase_csr_read_128(__csr_num + 0);			\
	switchcase_csr_read_128(__csr_num + 128)

	*out_err = 0;
	switch (csr_num) {
	switchcase_csr_read_32(CSR_CYCLE);
	switchcase_csr_read_32(CSR_CYCLEH);
	switchcase_csr_read_256(CSR_CUSTOM0_U_RW_BASE);
	switchcase_csr_read_64(CSR_CUSTOM1_U_RO_BASE);
	switchcase_csr_read_64(CSR_CUSTOM2_S_RW_BASE);
	switchcase_csr_read_64(CSR_CUSTOM3_S_RW_BASE);
	switchcase_csr_read_64(CSR_CUSTOM4_S_RO_BASE);
	switchcase_csr_read_64(CSR_CUSTOM5_HS_RW_BASE);
	switchcase_csr_read_64(CSR_CUSTOM6_HS_RW_BASE);
	switchcase_csr_read_64(CSR_CUSTOM7_HS_RO_BASE);
#ifdef CONFIG_RISCV_M_MODE
	switchcase_csr_read_64(CSR_CUSTOM8_M_RW_BASE);
	switchcase_csr_read_64(CSR_CUSTOM9_M_RW_BASE);
	switchcase_csr_read_64(CSR_CUSTOM10_M_RO_BASE);
#endif
	default:
		*out_err = -EINVAL;
		break;
	}

	return 0;
#undef switchcase_csr_read_256
#undef switchcase_csr_read_128
#undef switchcase_csr_read_64
#undef switchcase_csr_read_32
#undef switchcase_csr_read_16
#undef switchcase_csr_read_8
#undef switchcase_csr_read_4
#undef switchcase_csr_read_2
#undef switchcase_csr_read
}
EXPORT_SYMBOL_GPL(csr_read_num);

void csr_write_num(unsigned long csr_num, unsigned long val, int *out_err)
{
#define switchcase_csr_write(__csr_num, __val)			\
	case (__csr_num):					\
		csr_write(__csr_num, __val);			\
		break
#define switchcase_csr_write_2(__csr_num, __val)		\
	switchcase_csr_write(__csr_num + 0, __val);		\
	switchcase_csr_write(__csr_num + 1, __val)
#define switchcase_csr_write_4(__csr_num, __val)		\
	switchcase_csr_write_2(__csr_num + 0, __val);		\
	switchcase_csr_write_2(__csr_num + 2, __val)
#define switchcase_csr_write_8(__csr_num, __val)		\
	switchcase_csr_write_4(__csr_num + 0, __val);		\
	switchcase_csr_write_4(__csr_num + 4, __val)
#define switchcase_csr_write_16(__csr_num, __val)		\
	switchcase_csr_write_8(__csr_num + 0, __val);		\
	switchcase_csr_write_8(__csr_num + 8, __val)
#define switchcase_csr_write_32(__csr_num, __val)		\
	switchcase_csr_write_16(__csr_num + 0, __val);		\
	switchcase_csr_write_16(__csr_num + 16, __val)
#define switchcase_csr_write_64(__csr_num, __val)		\
	switchcase_csr_write_32(__csr_num + 0, __val);		\
	switchcase_csr_write_32(__csr_num + 32, __val)
#define switchcase_csr_write_128(__csr_num, __val)		\
	switchcase_csr_write_64(__csr_num + 0, __val);		\
	switchcase_csr_write_64(__csr_num + 64, __val)
#define switchcase_csr_write_256(__csr_num, __val)		\
	switchcase_csr_write_128(__csr_num + 0, __val);		\
	switchcase_csr_write_128(__csr_num + 128, __val)

	*out_err = 0;
	switch (csr_num) {
	switchcase_csr_write_256(CSR_CUSTOM0_U_RW_BASE, val);
	switchcase_csr_write_64(CSR_CUSTOM2_S_RW_BASE, val);
	switchcase_csr_write_64(CSR_CUSTOM3_S_RW_BASE, val);
	switchcase_csr_write_64(CSR_CUSTOM5_HS_RW_BASE, val);
	switchcase_csr_write_64(CSR_CUSTOM6_HS_RW_BASE, val);
#ifdef CONFIG_RISCV_M_MODE
	switchcase_csr_write_64(CSR_CUSTOM8_M_RW_BASE, val);
	switchcase_csr_write_64(CSR_CUSTOM9_M_RW_BASE, val);
#endif
	default:
		*out_err = -EINVAL;
		break;
	}
#undef switchcase_csr_write_256
#undef switchcase_csr_write_128
#undef switchcase_csr_write_64
#undef switchcase_csr_write_32
#undef switchcase_csr_write_16
#undef switchcase_csr_write_8
#undef switchcase_csr_write_4
#undef switchcase_csr_write_2
#undef switchcase_csr_write
}
EXPORT_SYMBOL_GPL(csr_write_num);
