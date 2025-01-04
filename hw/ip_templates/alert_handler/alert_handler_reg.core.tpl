CAPI=2:
# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0
name: ${instance_vlnv("lowrisc:ip:alert_handler_reg:0.1")}
description: "Auto-generated alert handler register sources"

filesets:
  files_rtl:
    depend:
      - lowrisc:prim:subreg
      - lowrisc:ip:tlul
      - lowrisc:prim:subreg
      - ${instance_vlnv("lowrisc:ip:alert_handler_pkg")}
    files:
      - rtl/alert_handler_reg_top.sv
    file_type: systemVerilogSource


targets:
  default: &default_target
    filesets:
      - files_rtl
