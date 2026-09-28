/**
 * SPDX-FileCopyrightText: Copyright (c) 2023 GARDENA GmbH
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <zephyr/init.h>
#include <zephyr/usb/usb_device.h>

#include <hal/nrf_power.h>

static int board_si4467_dongle_nrf52840_init_pre_kernel(void)
{
	/*
	 * If the dongle is powered from USB (high voltage mode), GPIO output voltage is set to 1.8
	 * volts by default, we need 3.3V for Si4467.
	 *
	 * Note: this code is copied from nrf52840dongle_nrf52840 board & adapted for 3.3V.
	 */
	if ((nrf_power_mainregstatus_get(NRF_POWER) == NRF_POWER_MAINREGSTATUS_HIGH) &&
	    ((NRF_UICR->REGOUT0 & UICR_REGOUT0_VOUT_Msk) ==
	     (UICR_REGOUT0_VOUT_DEFAULT << UICR_REGOUT0_VOUT_Pos))) {

		NRF_NVMC->CONFIG = NVMC_CONFIG_WEN_Wen << NVMC_CONFIG_WEN_Pos;
		while (NRF_NVMC->READY == NVMC_READY_READY_Busy) {
			;
		}

		NRF_UICR->REGOUT0 = (NRF_UICR->REGOUT0 & ~((uint32_t)UICR_REGOUT0_VOUT_Msk)) |
				    (UICR_REGOUT0_VOUT_3V3 << UICR_REGOUT0_VOUT_Pos);

		NRF_NVMC->CONFIG = NVMC_CONFIG_WEN_Ren << NVMC_CONFIG_WEN_Pos;
		while (NRF_NVMC->READY == NVMC_READY_READY_Busy) {
			;
		}

		/* a reset is required for changes to take effect */
		NVIC_SystemReset();
	}

	return 0;
}

SYS_INIT(board_si4467_dongle_nrf52840_init_pre_kernel, PRE_KERNEL_1,
	 CONFIG_KERNEL_INIT_PRIORITY_DEFAULT);
