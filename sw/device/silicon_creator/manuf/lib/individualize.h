// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#ifndef OPENTITAN_SW_DEVICE_SILICON_CREATOR_MANUF_LIB_INDIVIDUALIZE_H_
#define OPENTITAN_SW_DEVICE_SILICON_CREATOR_MANUF_LIB_INDIVIDUALIZE_H_

#include "sw/device/lib/base/status.h"
#include "sw/ip/flash_ctrl/dif/dif_flash_ctrl.h"
#include "sw/ip/lc_ctrl/dif/dif_lc_ctrl.h"
#include "sw/ip/otp_ctrl/dif/dif_otp_ctrl.h"

/**
 * Configures the HW_CFG OTP partition.
 *
 * The HW_CFG partition contains:
 * - Unique device identifier (DeviceId), which is a public value used to
 * identify the device during manufacturing.
 * - Manufacturing state information generated by the manufacturer.
 * - Various digital logic configuration settings.
 *
 * Preconditions:
 * - Device is in DEV, PROD, or PROD_END lifecycle stage.
 *
 * Note: The test will skip all programming steps and succeed if the HW_CFG
 * parition is already locked. This is to facilitate test re-runs.
 *
 * The caller should reset the device after calling this function and call
 * `individualize_dev_hw_cfg_end()` afterwards to confirm that the OTP partition
 * was successfully locked.
 *
 * @param lc_ctrl Lifecycle controller instance.
 * @param otp OTP controller instance.
 * @return The result of the operation.
 */
status_t individualize_dev_hw_cfg_start(dif_flash_ctrl_state_t *flash_state,
                                        const dif_lc_ctrl_t *lc_ctrl,
                                        const dif_otp_ctrl_t *otp);

/**
 * Checks the HW_CFG OTP partition end state.
 *
 * @param otp OTP controller interface.
 * @return OK_STATUS if the HW_CFG partition is locked.
 */
status_t individualize_dev_hw_cfg_end(const dif_otp_ctrl_t *otp);

/**
 * Configures the SECRET1 OTP partition.
 *
 * The SECRET1 partition contains the Flash and SRAM scrambling seeds for the
 * device.
 *
 * Preconditions:
 * - Device is in DEV, PROD, or PROD_END lifecycle stage.
 *
 * Note: The test will skip all programming steps and succeed if the SECRET1
 * parition is already locked. This is to facilitate test re-runs.
 *
 * The caller should reset the device after calling this function and call
 * `individualize_dev_secret1_end()` afterwards to confirm that the OTP
 * partition was successfully locked.
 *
 * @param lc_ctrl Lifecycle controller instance.
 * @param otp OTP controller instance.
 * @return The result of the operation.
 */
status_t individualize_dev_secret1_start(const dif_lc_ctrl_t *lc_ctrl,
                                         const dif_otp_ctrl_t *otp);

/**
 * Checks the SECRET1 OTP partition end state.
 *
 * @param otp OTP controller interface.
 * @return OK_STATUS if the SECRET1 partition is locked.
 */
status_t individualize_dev_secret1_end(const dif_otp_ctrl_t *otp);

#endif  // OPENTITAN_SW_DEVICE_SILICON_CREATOR_MANUF_LIB_INDIVIDUALIZE_H_
