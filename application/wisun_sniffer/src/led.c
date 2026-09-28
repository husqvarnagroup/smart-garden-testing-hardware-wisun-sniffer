/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 GARDENA GmbH
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "led.h"

#include <zephyr/devicetree.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/logging/log.h>

#include <errno.h>

LOG_MODULE_REGISTER(led, LOG_LEVEL_INF);

#if !DT_NODE_EXISTS(DT_ALIAS(led0))
#error "the Wi-SUN sniffer needs a board whose devicetree has an led0 alias"
#endif

/*
 * The only LED on the dongle the nRF52840 can drive. The power LED hangs off USB VBUS and the RX/TX
 * pair is wired to the Si4467, so neither is ours. On dongles before hardware revision 0.4.0 this
 * pin is not connected either, and there the calls below simply have nothing to show.
 */
static const struct gpio_dt_spec app_led = GPIO_DT_SPEC_GET(DT_ALIAS(led0), gpios);

/** Whether the pin was configured, so that a board without one is quiet rather than noisy. */
static bool led_ready;

int led_init(void)
{
	int ret;

	if (!gpio_is_ready_dt(&app_led)) {
		LOG_ERR("%s is not ready", app_led.port->name);
		return -ENODEV;
	}

	/* Dark until a capture tool attaches: unlit is the resting state, not an error state. */
	ret = gpio_pin_configure_dt(&app_led, GPIO_OUTPUT_INACTIVE);
	if (ret) {
		LOG_ERR("cannot drive %s pin %u: %d", app_led.port->name, app_led.pin, ret);
		return ret;
	}

	led_ready = true;

	return 0;
}

void led_set_capture_active(bool active)
{
	if (!led_ready) {
		return;
	}

	/*
	 * Nothing rests on this, and the caller is the DTR poll, which has better things to report
	 * than a GPIO write that failed once and would then fail again a quarter of a second later.
	 */
	(void)gpio_pin_set_dt(&app_led, active);
}
