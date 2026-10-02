// SPDX-License-Identifier: GPL-2.0
/*
 * RISC-V SBI watchdog driver
 *
 * Copyright (C) 2026 Qualcomm Inc.
 */

#include <linux/device.h>
#include <asm/sbi.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/types.h>
#include <linux/watchdog.h>
#include <linux/msi.h>
#include <linux/kernel.h>
#include <linux/of_irq.h>
#include <linux/irqdomain.h>
#include <linux/irqchip/riscv-imsic.h>

#define DRV_NAME            "riscv-sbi-wdt"
#define DRV_VERSION         "1.0"

/* Watchdog default timeout in seconds */
#define SBI_WDT_DEFAULT_TIMEOUT         60

/* MSI capability mask */
#define SBI_WDT_CAP_MSI_SUPPORT_MASK         BIT(1)

/* Convert second to microsecond */
static inline u32 sec_to_usec(unsigned int sec)
{
	return (u32)(sec * 1000000ULL);
}

/* Convert microsecond to second and ceil the result */
static inline unsigned int usec_to_sec_ceil(u32 usec)
{
	return (unsigned int) DIV_ROUND_UP_ULL(usec, 1000000ULL);
}

/* Convert microsecond to second and floor the result */
static inline unsigned int usec_to_sec(u32 usec)
{
	return (unsigned int) (usec / 1000000ULL);
}

/* SBI watchdog attributes */
struct sbiwdt_attributes {
	/* MSI and SSE capability flags */
	u32 wdt_capability;
	/* Watchdog state */
	u32 wdt_state;
	/* Minimum watchdog timeout supported in us */
	u32 wdt_min_period;
	/* Watchdog timeout period in us */
	u32 wdt_period;
	/* Time left until watchdog expiry in us */
	u32 wdt_time_left;
	/* Watchdog pretimeout in us */
	u32 wdt_notif_time;
	/* MSI target address low 32-bit */
	u32 wdt_notif_msi_addr_low;
	/* MSI target address high 32-bit */
	u32 wdt_notif_msi_addr_high;
	/* MSI data */
	u32 wdt_notif_msi_data;
};

/* SBI watchdog global structure */
struct sbiwdt {
	/* Kernel watchdog instance */
	struct watchdog_device          wdd;
	struct device                   *dev;
	struct sbiwdt_attributes        attrs;
	int                             virq;
};

/* Watchdog pretimeout expiry handler */
static irqreturn_t sbiwdt_pretimeout_handler(int irq, void *dev_id)
{
	struct sbiwdt *wdt = dev_id;

	watchdog_notify_pretimeout(&wdt->wdd);

	return IRQ_HANDLED;
}

/* Read watchdog attribute */
static int sbiwdt_read_attribute(enum sbi_ext_attribute_id attr_id, u32 *attr_val)
{
	struct sbiret sret;

	sret = sbi_ecall(SBI_EXT_WDT, SBI_EXT_WATCHDOG_READ_ATTRIBUTE, attr_id, 0, 0, 0, 0, 0);
	*attr_val = sret.value;

	return sbi_err_map_linux_errno(sret.error);
}

/* Write watchdog attribute */
static int sbiwdt_write_attribute(enum sbi_ext_attribute_id attr_id, u32 val)
{
	struct sbiret sret;

	sret = sbi_ecall(SBI_EXT_WDT, SBI_EXT_WATCHDOG_WRITE_ATTRIBUTE, attr_id, val, 0, 0, 0, 0);

	return sbi_err_map_linux_errno(sret.error);
}

/* Write the MSI address and data attributes in one SBI call*/
static int sbiwdt_write_notif_msi_message(u32 msi_addr_low, u32 msi_addr_high, u32 msi_data)
{
	struct sbiret sret;

	sret = sbi_ecall(SBI_EXT_WDT, SBI_EXT_WATCHDOG_WRITE_NOTIF_MSI_MESSAGE, msi_addr_low,
								msi_addr_high, msi_data, 0, 0, 0);

	return sbi_err_map_linux_errno(sret.error);
}

/* Start the watchdog */
static int sbiwdt_start(struct watchdog_device *wdd)
{
	struct sbiret sret;

	sret = sbi_ecall(SBI_EXT_WDT, SBI_EXT_WATCHDOG_START, 0, 0, 0, 0, 0, 0);

	return sbi_err_map_linux_errno(sret.error);
}

/* Stop the watchdog */
static int sbiwdt_stop(struct watchdog_device *wdd)
{
	struct sbiret sret;

	sret = sbi_ecall(SBI_EXT_WDT, SBI_EXT_WATCHDOG_STOP, 0, 0, 0, 0, 0, 0);

	return sbi_err_map_linux_errno(sret.error);
}

/* Pat the watchdog */
static int sbiwdt_pat(struct watchdog_device *wdd)
{
	struct sbiret sret;

	sret = sbi_ecall(SBI_EXT_WDT, SBI_EXT_WATCHDOG_PAT, 0, 0, 0, 0, 0, 0);

	return sbi_err_map_linux_errno(sret.error);
}

/* Set the watchdog timeout value */
static int sbiwdt_set_timeout(struct watchdog_device *wdd, unsigned int timeout)
{
	struct sbiwdt *wdt = watchdog_get_drvdata(wdd);
	u32 period_usec;
	int ret;

	period_usec = sec_to_usec(timeout);

	ret = sbiwdt_write_attribute(SBI_WDT_PERIOD, period_usec);
	if (ret)
		return ret;

	wdt->attrs.wdt_period = period_usec;
	wdt->wdd.timeout = timeout;

	return 0;
}

/* Set the watchdog pretimeout value*/
static int sbiwdt_set_pretimeout(struct watchdog_device *wdd, unsigned int pretimeout)
{
	struct sbiwdt *wdt = watchdog_get_drvdata(wdd);
	u32 notif_time_usec;
	int ret;

	if (pretimeout >= wdd->timeout)
		return -EINVAL;

	notif_time_usec = sec_to_usec(pretimeout);
	ret = sbiwdt_write_attribute(SBI_WDT_NOTIF_TIME, notif_time_usec);
	if (ret)
		return ret;

	wdt->wdd.pretimeout = pretimeout;
	wdt->attrs.wdt_notif_time = notif_time_usec;

	return ret;
}

/* Get the watchdog timeleft before expiry */
static unsigned int sbiwdt_get_timeleft(struct watchdog_device *wdd)
{
	struct sbiwdt *wdt = watchdog_get_drvdata(wdd);
	unsigned int time_left_usec;
	int ret;

	ret = sbiwdt_read_attribute(SBI_WDT_TIME_LEFT, &time_left_usec);
	if (ret) {
		dev_err(wdt->dev, "Failed to read watchdog time left: %d\n", ret);
		return 0;
	}

	return usec_to_sec(time_left_usec);
}

static const struct watchdog_info sbiwdt_info = {
	.options	=	WDIOF_SETTIMEOUT	|
				WDIOF_KEEPALIVEPING	|
				WDIOF_PRETIMEOUT	|
				WDIOF_MAGICCLOSE,
	.identity	=	DRV_NAME,
};

static const struct watchdog_ops sbiwdt_ops = {
	.owner		= THIS_MODULE,
	.start		= sbiwdt_start,
	.stop		= sbiwdt_stop,
	.ping		= sbiwdt_pat,
	.set_timeout	= sbiwdt_set_timeout,
	.set_pretimeout	= sbiwdt_set_pretimeout,
	.get_timeleft	= sbiwdt_get_timeleft,
};

/* The callback function from IMSIC containing the MSI address and data */
static void sbiwdt_msi_write(struct msi_desc *desc, struct msi_msg *msg)
{
	int ret;
	struct device *dev = msi_desc_to_dev(desc);
	struct sbiwdt *wdt;

	if (!dev || !msg)
		return;

	wdt = dev_get_drvdata(dev);
	if (!wdt) {
		dev_err(dev, "Missing SBI watchdog driver data\n");
		return;
	}

	/* Store MSI info in attributes*/
	wdt->attrs.wdt_notif_msi_addr_low = msg->address_lo;
	wdt->attrs.wdt_notif_msi_addr_high = msg->address_hi;
	wdt->attrs.wdt_notif_msi_data = msg->data;

	/* Pass the MSI attribute values to OpenSBI */
	ret = sbiwdt_write_notif_msi_message(wdt->attrs.wdt_notif_msi_addr_low,
						wdt->attrs.wdt_notif_msi_addr_high,
						wdt->attrs.wdt_notif_msi_data);
	if (ret) {
		dev_err(dev, "Failed to configure watchdog MSI: %d\n", ret);
		return;
	}
}

/* Initialize the watchdog attributes */
static int sbiwdt_init_attributes(struct sbiwdt *wdt)
{
	int ret;
	u32 attr_val;
	u32 timeout_usec;

	/* Read watchdog capability from firmware */
	ret = sbiwdt_read_attribute(SBI_WDT_CAPABILITY, &attr_val);
	if (ret)
		return ret;

	wdt->attrs.wdt_capability = attr_val;

	/* Read watchdog min period supported in firmware */
	ret = sbiwdt_read_attribute(SBI_WDT_MIN_PERIOD, &attr_val);
	if (ret)
		return ret;

	if (!attr_val)
		attr_val = 1;

	wdt->attrs.wdt_min_period = attr_val;
	wdt->wdd.min_timeout = usec_to_sec_ceil(wdt->attrs.wdt_min_period);

	/* Initialize the watchdog timeout to default value */
	timeout_usec = sec_to_usec(SBI_WDT_DEFAULT_TIMEOUT);
	ret = sbiwdt_write_attribute(SBI_WDT_PERIOD, timeout_usec);
	if (ret)
		return ret;

	wdt->attrs.wdt_period = timeout_usec;
	wdt->wdd.timeout = SBI_WDT_DEFAULT_TIMEOUT;

	/* Initialize the pretimeout to default value */
	wdt->attrs.wdt_notif_time = 0;
	wdt->wdd.pretimeout = 0;

	return 0;
}

static int sbiwdt_probe(struct platform_device *pdev)
{
	struct sbiwdt *wdt;
	struct imsic_global_config *imsic_global;
	struct irq_domain *msi_domain;
	struct device *dev = &pdev->dev;
	int rc;

	/* Allocate memory for the global watchdog structure */
	wdt = devm_kzalloc(dev, sizeof(*wdt), GFP_KERNEL);
	if (!wdt)
		return -ENOMEM;

	platform_set_drvdata(pdev, wdt);
	watchdog_set_drvdata(&wdt->wdd, wdt);

	/* Initialiaze watchdog attributes */
	rc = sbiwdt_init_attributes(wdt);
	if (rc) {
		dev_err(dev, "Failed to read SBI watchdog attributes: %d\n", rc);
		return rc;
	}

	wdt->wdd.info = &sbiwdt_info;
	wdt->wdd.ops = &sbiwdt_ops;

	/* Setup MSI if the capability is available */
	if (wdt->attrs.wdt_capability & SBI_WDT_CAP_MSI_SUPPORT_MASK) {
		imsic_global = imsic_get_global_config();
		if (!imsic_global) {
			dev_err(dev, "IMSIC firmware node is unavailable\n");
			return -ENODEV;
		}

		msi_domain = irq_find_matching_fwnode(imsic_global->fwnode,
							DOMAIN_BUS_PLATFORM_MSI);

		if (!msi_domain) {
			dev_err(dev, "IMSIC platform MSI domain is unavailable\n");
			return -ENODEV;
		}

		dev_set_msi_domain(&pdev->dev, msi_domain);

		/* MSI setup*/
		rc = platform_device_msi_init_and_alloc_irqs(dev, 1, sbiwdt_msi_write);
		if (rc) {
			dev_err(dev, "Failed to allocate MSIs\n");
			return rc;
		}

		wdt->virq = msi_get_virq(dev, 0);
		if (!wdt->virq) {
			dev_err(dev, "Failed to get MSI virtual IRQ: %d\n", wdt->virq);
			return wdt->virq;
		}

		rc = devm_request_irq(dev, wdt->virq,
					sbiwdt_pretimeout_handler,
					0, "sbiwdt-pretimeout", wdt);
		if (rc) {
			dev_err(dev, "Failed to request pretimeout IRQ: %d\n", rc);
			return rc;
		}
	}

	rc = devm_watchdog_register_device(dev, &wdt->wdd);
	if (rc) {
		dev_err(dev, "Failed to register RISC-V SBI watchdog device\n");
		return rc;
	}

	dev_info(&pdev->dev, "RISC-V SBI Watchdog registered\n");

	return 0;
}

static struct platform_driver sbiwdt_driver = {
	.probe  = sbiwdt_probe,
	.driver = {
			.name = DRV_NAME,
	},
};

static int __init sbiwdt_init(void)
{
	int ret;
	struct platform_device *pdev;

	/* Probe for SBI WDT extension */
	if (sbi_spec_version < sbi_mk_version(3, 0) ||
		sbi_probe_extension(SBI_EXT_WDT) <= 0) {
		return -ENODEV;
	}

	ret = platform_driver_register(&sbiwdt_driver);
	if (ret)
		return ret;

	pdev = platform_device_register_simple(DRV_NAME, -1, NULL, 0);
	if (IS_ERR(pdev)) {
		platform_driver_unregister(&sbiwdt_driver);
		return PTR_ERR(pdev);
	}

	return 0;
}
late_initcall(sbiwdt_init);
