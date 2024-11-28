// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
// tl_dbg package generated by `tlgen.py` tool

package tl_dbg_pkg;

  localparam logic [31:0] ADDR_SPACE_RV_DM__DBG         = 32'h 00000000;
  localparam logic [31:0] ADDR_SPACE_MBX_JTAG__SOC      = 32'h 00001000;
  localparam logic [31:0] ADDR_SPACE_LC_CTRL__DMI       = 32'h 00020000;
  localparam logic [31:0] ADDR_SPACE_SOC_DBG_CTRL__JTAG = 32'h 00002300;

  localparam logic [31:0] ADDR_MASK_RV_DM__DBG         = 32'h 000001ff;
  localparam logic [31:0] ADDR_MASK_MBX_JTAG__SOC      = 32'h 0000001f;
  localparam logic [31:0] ADDR_MASK_LC_CTRL__DMI       = 32'h 00000fff;
  localparam logic [31:0] ADDR_MASK_SOC_DBG_CTRL__JTAG = 32'h 00000007;

  localparam int N_HOST   = 1;
  localparam int N_DEVICE = 4;

  typedef enum int {
    TlRvDmDbg = 0,
    TlMbxJtagSoc = 1,
    TlLcCtrlDmi = 2,
    TlSocDbgCtrlJtag = 3
  } tl_device_e;

  typedef enum int {
    TlDbg = 0
  } tl_host_e;

endpackage
