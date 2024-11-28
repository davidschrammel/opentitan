// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
// xbar_peri_bind module generated by `tlgen.py` tool for assertions
module xbar_peri_bind;
`ifndef GATE_LEVEL
  // Host interfaces
  bind xbar_peri tlul_assert #(.EndpointType("Device")) tlul_assert_host_main (
    .clk_i  (clk_peri_i),
    .rst_ni (rst_peri_ni),
    .h2d    (tl_main_i),
    .d2h    (tl_main_o)
  );

  // Device interfaces
  bind xbar_peri tlul_assert #(.EndpointType("Host")) tlul_assert_device_uart0 (
    .clk_i  (clk_peri_i),
    .rst_ni (rst_peri_ni),
    .h2d    (tl_uart0_o),
    .d2h    (tl_uart0_i)
  );
  bind xbar_peri tlul_assert #(.EndpointType("Host")) tlul_assert_device_i2c0 (
    .clk_i  (clk_peri_i),
    .rst_ni (rst_peri_ni),
    .h2d    (tl_i2c0_o),
    .d2h    (tl_i2c0_i)
  );
  bind xbar_peri tlul_assert #(.EndpointType("Host")) tlul_assert_device_gpio (
    .clk_i  (clk_peri_i),
    .rst_ni (rst_peri_ni),
    .h2d    (tl_gpio_o),
    .d2h    (tl_gpio_i)
  );
  bind xbar_peri tlul_assert #(.EndpointType("Host")) tlul_assert_device_spi_host0 (
    .clk_i  (clk_peri_i),
    .rst_ni (rst_peri_ni),
    .h2d    (tl_spi_host0_o),
    .d2h    (tl_spi_host0_i)
  );
  bind xbar_peri tlul_assert #(.EndpointType("Host")) tlul_assert_device_spi_device (
    .clk_i  (clk_peri_i),
    .rst_ni (rst_peri_ni),
    .h2d    (tl_spi_device_o),
    .d2h    (tl_spi_device_i)
  );
  bind xbar_peri tlul_assert #(.EndpointType("Host")) tlul_assert_device_rv_timer (
    .clk_i  (clk_peri_i),
    .rst_ni (rst_peri_ni),
    .h2d    (tl_rv_timer_o),
    .d2h    (tl_rv_timer_i)
  );
  bind xbar_peri tlul_assert #(.EndpointType("Host")) tlul_assert_device_pwrmgr_aon (
    .clk_i  (clk_peri_i),
    .rst_ni (rst_peri_ni),
    .h2d    (tl_pwrmgr_aon_o),
    .d2h    (tl_pwrmgr_aon_i)
  );
  bind xbar_peri tlul_assert #(.EndpointType("Host")) tlul_assert_device_rstmgr_aon (
    .clk_i  (clk_peri_i),
    .rst_ni (rst_peri_ni),
    .h2d    (tl_rstmgr_aon_o),
    .d2h    (tl_rstmgr_aon_i)
  );
  bind xbar_peri tlul_assert #(.EndpointType("Host")) tlul_assert_device_clkmgr_aon (
    .clk_i  (clk_peri_i),
    .rst_ni (rst_peri_ni),
    .h2d    (tl_clkmgr_aon_o),
    .d2h    (tl_clkmgr_aon_i)
  );
  bind xbar_peri tlul_assert #(.EndpointType("Host")) tlul_assert_device_pinmux_aon (
    .clk_i  (clk_peri_i),
    .rst_ni (rst_peri_ni),
    .h2d    (tl_pinmux_aon_o),
    .d2h    (tl_pinmux_aon_i)
  );
  bind xbar_peri tlul_assert #(.EndpointType("Host")) tlul_assert_device_otp_ctrl__core (
    .clk_i  (clk_peri_i),
    .rst_ni (rst_peri_ni),
    .h2d    (tl_otp_ctrl__core_o),
    .d2h    (tl_otp_ctrl__core_i)
  );
  bind xbar_peri tlul_assert #(.EndpointType("Host")) tlul_assert_device_otp_ctrl__prim (
    .clk_i  (clk_peri_i),
    .rst_ni (rst_peri_ni),
    .h2d    (tl_otp_ctrl__prim_o),
    .d2h    (tl_otp_ctrl__prim_i)
  );
  bind xbar_peri tlul_assert #(.EndpointType("Host")) tlul_assert_device_lc_ctrl__regs (
    .clk_i  (clk_peri_i),
    .rst_ni (rst_peri_ni),
    .h2d    (tl_lc_ctrl__regs_o),
    .d2h    (tl_lc_ctrl__regs_i)
  );
  bind xbar_peri tlul_assert #(.EndpointType("Host")) tlul_assert_device_sensor_ctrl (
    .clk_i  (clk_peri_i),
    .rst_ni (rst_peri_ni),
    .h2d    (tl_sensor_ctrl_o),
    .d2h    (tl_sensor_ctrl_i)
  );
  bind xbar_peri tlul_assert #(.EndpointType("Host")) tlul_assert_device_alert_handler (
    .clk_i  (clk_peri_i),
    .rst_ni (rst_peri_ni),
    .h2d    (tl_alert_handler_o),
    .d2h    (tl_alert_handler_i)
  );
  bind xbar_peri tlul_assert #(.EndpointType("Host")) tlul_assert_device_sram_ctrl_ret_aon__regs (
    .clk_i  (clk_peri_i),
    .rst_ni (rst_peri_ni),
    .h2d    (tl_sram_ctrl_ret_aon__regs_o),
    .d2h    (tl_sram_ctrl_ret_aon__regs_i)
  );
  bind xbar_peri tlul_assert #(.EndpointType("Host")) tlul_assert_device_sram_ctrl_ret_aon__ram (
    .clk_i  (clk_peri_i),
    .rst_ni (rst_peri_ni),
    .h2d    (tl_sram_ctrl_ret_aon__ram_o),
    .d2h    (tl_sram_ctrl_ret_aon__ram_i)
  );
  bind xbar_peri tlul_assert #(.EndpointType("Host")) tlul_assert_device_aon_timer_aon (
    .clk_i  (clk_peri_i),
    .rst_ni (rst_peri_ni),
    .h2d    (tl_aon_timer_aon_o),
    .d2h    (tl_aon_timer_aon_i)
  );
  bind xbar_peri tlul_assert #(.EndpointType("Host")) tlul_assert_device_ast (
    .clk_i  (clk_peri_i),
    .rst_ni (rst_peri_ni),
    .h2d    (tl_ast_o),
    .d2h    (tl_ast_i)
  );
  bind xbar_peri tlul_assert #(.EndpointType("Host")) tlul_assert_device_soc_dbg_ctrl__core (
    .clk_i  (clk_peri_i),
    .rst_ni (rst_peri_ni),
    .h2d    (tl_soc_dbg_ctrl__core_o),
    .d2h    (tl_soc_dbg_ctrl__core_i)
  );
`endif
endmodule
