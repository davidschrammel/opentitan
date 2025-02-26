// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
// xbar_env_pkg__params generated by `tlgen.py` tool


// List of Xbar device memory map
tl_device_t xbar_devices[$] = '{
    '{"rv_dm__dbg", '{
        '{32'h00000000, 32'h000001ff}
    }},
    '{"mbx_jtag__soc", '{
        '{32'h00002200, 32'h0000221f}
    }},
    '{"lc_ctrl__dmi", '{
        '{32'h00003000, 32'h00003fff}
    }},
    '{"soc_dbg_ctrl__jtag", '{
        '{32'h00002300, 32'h0000231f}
}}};

  // List of Xbar hosts
tl_host_t xbar_hosts[$] = '{
    '{"dbg", 0, '{
        "rv_dm__dbg",
        "mbx_jtag__soc",
        "lc_ctrl__dmi",
        "soc_dbg_ctrl__jtag"}}
};
