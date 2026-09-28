/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 GARDENA GmbH
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * @file
 *
 * @brief The application LED, which shows whether a capture is running.
 *
 * With Wireshark on another screen, or a capture left running unattended, the dongle otherwise
 * gives no sign of what it is doing. Lit means a capture tool has the capture port open.
 */

#ifndef WISUN_SNIFFER_LED_H_
#define WISUN_SNIFFER_LED_H_

#include <stdbool.h>

/**
 * @brief Claim the LED and leave it dark.
 *
 * @return 0 on success, negative errno if the pin cannot be driven, in which case
 *         @ref led_set_capture_active does nothing rather than failing on every call.
 */
int led_init(void);

/**
 * @brief Light the LED while a capture tool is reading the capture stream.
 *
 * @param active true to light it, false to put it out.
 */
void led_set_capture_active(bool active);

#endif /* WISUN_SNIFFER_LED_H_ */
