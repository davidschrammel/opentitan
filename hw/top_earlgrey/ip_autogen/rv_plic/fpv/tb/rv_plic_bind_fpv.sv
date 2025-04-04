// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

module rv_plic_bind_fpv;

  import rv_plic_reg_pkg::*;

  bind rv_plic rv_plic_assert_fpv #(
    .NumSrc(rv_plic_reg_pkg::NumSrc),
    .NumTarget(rv_plic_reg_pkg::NumTarget),
    .NumAlerts(rv_plic_reg_pkg::NumAlerts),
    .PRIOW(rv_plic_reg_pkg::PrioWidth)
  ) rv_plic_assert_fpv(
    .clk_i,
    .rst_ni,
    .intr_src_i,
    .alert_rx_i,
    .alert_tx_o,
    .irq_o,
    .irq_id_o,
    .msip_o,
    .ip,
    .ie,
    .claim,
    .complete,
    .prio,
    .threshold,
    .fatal_alert_i (alerts[0])
  );

  bind rv_plic tlul_assert #(
    .EndpointType("Device")
  ) tlul_assert_device (
    .clk_i,
    .rst_ni,
    .h2d  (tl_i),
    .d2h  (tl_o)
  );

  bind rv_plic rv_plic_csr_assert_fpv rv_plic_csr_assert_fpv (
    .clk_i,
    .rst_ni,
    .h2d  (tl_i),
    .d2h  (tl_o)
  );

endmodule : rv_plic_bind_fpv
