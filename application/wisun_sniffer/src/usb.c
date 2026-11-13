/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 GARDENA GmbH
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
 * The USB device, with both CDC ACM interfaces: cdc_acm_uart0 for console, log and shell (if00),
 * cdc_acm_uart1 for capture (if02). The board's own CDC ACM serial backend registers only the first
 * instance, so it is disabled in boards/si4467_dongle_nrf52840.conf and replaced by this.
 */

#include <zephyr/device.h>
#include <zephyr/init.h>
#include <zephyr/logging/log.h>
#include <zephyr/usb/usbd.h>

LOG_MODULE_REGISTER(usb, LOG_LEVEL_INF);

/* Nordic's vendor ID and manufacturer name, as the board uses them; see its Kconfig.defconfig. */
#define USB_VID          0x1915
#define USB_MANUFACTURER "Gardena"

/* bMaxPower in 2 mA units */
#define USB_MAX_POWER 50

USBD_DEVICE_DEFINE(sniffer_usbd, DEVICE_DT_GET(DT_NODELABEL(zephyr_udc0)), USB_VID,
		   CONFIG_WISUN_SNIFFER_USB_PID);

USBD_DESC_LANG_DEFINE(sniffer_lang);
USBD_DESC_MANUFACTURER_DEFINE(sniffer_mfr, USB_MANUFACTURER);
USBD_DESC_PRODUCT_DEFINE(sniffer_product, CONFIG_WISUN_SNIFFER_USB_PRODUCT);
/* What /dev/serial/by-id tells two dongles apart by. */
USBD_DESC_SERIAL_NUMBER_DEFINE(sniffer_sn);

USBD_DESC_CONFIG_DEFINE(sniffer_fs_cfg_desc, "FS Configuration");
USBD_CONFIGURATION_DEFINE(sniffer_fs_config, 0, USB_MAX_POWER, &sniffer_fs_cfg_desc);

static int sniffer_usb_init(void)
{
	struct usbd_desc_node *const descs[] = {
		&sniffer_lang,
		&sniffer_mfr,
		&sniffer_product,
		&sniffer_sn,
	};
	int err;

	for (size_t i = 0; i < ARRAY_SIZE(descs); i++) {
		err = usbd_add_descriptor(&sniffer_usbd, descs[i]);
		if (err != 0) {
			LOG_ERR("failed to add descriptor %zu (%d)", i, err);
			return err;
		}
	}

	err = usbd_add_configuration(&sniffer_usbd, USBD_SPEED_FS, &sniffer_fs_config);
	if (err != 0) {
		LOG_ERR("failed to add configuration (%d)", err);
		return err;
	}

	err = usbd_register_all_classes(&sniffer_usbd, USBD_SPEED_FS, 1, NULL);
	if (err != 0) {
		LOG_ERR("failed to register classes (%d)", err);
		return err;
	}

	/* CDC ACM uses an interface association descriptor, which needs this triple. */
	err = usbd_device_set_code_triple(&sniffer_usbd, USBD_SPEED_FS, USB_BCC_MISCELLANEOUS, 0x02,
					  0x01);
	if (err != 0) {
		LOG_ERR("failed to set code triple (%d)", err);
		return err;
	}

	err = usbd_init(&sniffer_usbd);
	if (err != 0) {
		LOG_ERR("failed to initialise USB device (%d)", err);
		return err;
	}

	err = usbd_enable(&sniffer_usbd);
	if (err != 0) {
		LOG_ERR("failed to enable USB device (%d)", err);
	}

	return err;
}

/* Before main(), so that the console exists by the time anything is logged to it. */
SYS_INIT(sniffer_usb_init, APPLICATION, CONFIG_APPLICATION_INIT_PRIORITY);
