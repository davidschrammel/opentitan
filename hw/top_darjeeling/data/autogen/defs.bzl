# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

load("//rules/opentitan:hw.bzl", "opentitan_top")
load("//hw/ip/aes:defs.bzl", "AES")
load("//hw/top_darjeeling/ip_autogen/alert_handler:defs.bzl", "ALERT_HANDLER")
load("//hw/ip/aon_timer:defs.bzl", "AON_TIMER")
load("//hw/top_darjeeling/ip/ast:defs.bzl", "AST")
load("//hw/top_darjeeling/ip_autogen/clkmgr:defs.bzl", "CLKMGR")
load("//hw/ip/csrng:defs.bzl", "CSRNG")
load("//hw/ip/dma:defs.bzl", "DMA")
load("//hw/ip/edn:defs.bzl", "EDN")
load("//hw/ip/gpio:defs.bzl", "GPIO")
load("//hw/ip/hmac:defs.bzl", "HMAC")
load("//hw/ip/i2c:defs.bzl", "I2C")
load("//hw/ip/keymgr_dpe:defs.bzl", "KEYMGR_DPE")
load("//hw/ip/kmac:defs.bzl", "KMAC")
load("//hw/ip/lc_ctrl:defs.bzl", "LC_CTRL")
load("//hw/ip/mbx:defs.bzl", "MBX")
load("//hw/ip/otbn:defs.bzl", "OTBN")
load("//hw/ip/otp_ctrl:defs.bzl", "OTP_CTRL")
load("//hw/top_darjeeling/ip_autogen/pinmux:defs.bzl", "PINMUX")
load("//hw/top_darjeeling/ip_autogen/pwrmgr:defs.bzl", "PWRMGR")
load("//hw/ip/rom_ctrl:defs.bzl", "ROM_CTRL")
load("//hw/top_darjeeling/ip_autogen/rstmgr:defs.bzl", "RSTMGR")
load("//hw/ip/rv_core_ibex:defs.bzl", "RV_CORE_IBEX")
load("//hw/ip/rv_dm:defs.bzl", "RV_DM")
load("//hw/top_darjeeling/ip_autogen/rv_plic:defs.bzl", "RV_PLIC")
load("//hw/ip/rv_timer:defs.bzl", "RV_TIMER")
load("//hw/top_darjeeling/ip/sensor_ctrl:defs.bzl", "SENSOR_CTRL")
load("//hw/top_darjeeling/ip/soc_proxy:defs.bzl", "SOC_PROXY")
load("//hw/ip/spi_device:defs.bzl", "SPI_DEVICE")
load("//hw/ip/spi_host:defs.bzl", "SPI_HOST")
load("//hw/ip/sram_ctrl:defs.bzl", "SRAM_CTRL")
load("//hw/ip/uart:defs.bzl", "UART")

DARJEELING = opentitan_top(
    name = "darjeeling",
    hjson = "//hw/top_darjeeling/data/autogen:top_darjeeling.gen.hjson",
    top_lib = "//hw/top_darjeeling/sw/autogen:top_darjeeling",
    ips = [
        AES,
        ALERT_HANDLER,
        AON_TIMER,
        AST,
        CLKMGR,
        CSRNG,
        DMA,
        EDN,
        GPIO,
        HMAC,
        I2C,
        KEYMGR_DPE,
        KMAC,
        LC_CTRL,
        MBX,
        OTBN,
        OTP_CTRL,
        PINMUX,
        PWRMGR,
        ROM_CTRL,
        RSTMGR,
        RV_CORE_IBEX,
        RV_DM,
        RV_PLIC,
        RV_TIMER,
        SENSOR_CTRL,
        SOC_PROXY,
        SPI_DEVICE,
        SPI_HOST,
        SRAM_CTRL,
        UART,
    ],
)
