// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
// Register Top module auto-generated by `reggen`
<%
  from reggen import gen_rtl
  from reggen.access import HwAccess, SwRdAccess, SwWrAccess
  from reggen.lib import get_basename
  from reggen.register import Register
  from reggen.multi_register import MultiRegister
  from reggen.bits import Bits

  alias_impl = "_" + block.alias_impl if block.alias_impl else ""

  num_wins = len(rb.windows)
  num_reg_dsp = 1 if rb.all_regs else 0
  num_dsp  = num_wins + num_reg_dsp
  regs_flat = rb.flat_regs
  max_regs_char = len("{}".format(len(regs_flat) - 1))
  addr_width = rb.get_addr_width()

  # Used for the dev_select_i signal on a tlul_socket_1n with N =
  # num_wins + 1. This needs to be able to represent any value up to
  # N-1.
  steer_msb = ((num_wins).bit_length()) - 1

  lblock = block.name.lower()
  ublock = lblock.upper()

  u_mod_base = mod_base.upper()

  reg2hw_t = gen_rtl.get_iface_tx_type(block, if_name, False)
  hw2reg_t = gen_rtl.get_iface_tx_type(block, if_name, True)

  racl_support = block.bus_interfaces.racl_support[if_name]

  win_array_decl = f'  [{num_wins}]' if num_wins > 1 else ''

  # Calculate whether we're going to need an AW parameter. We use it if there
  # are any registers (obviously). We also use it if there are any windows that
  # don't start at zero and end at 1 << addr_width (see the "addr_checks"
  # calculation below for where that comes from).
  needs_aw = (bool(regs_flat) or
              num_wins > 1 or
              rb.windows and (
                rb.windows[0].offset != 0 or
                rb.windows[0].size_in_bytes != (1 << addr_width)))


  common_data_intg_gen = 0 if rb.has_data_intg_passthru else 1
  adapt_data_intg_gen = 1 if rb.has_data_intg_passthru else 0
  assert common_data_intg_gen != adapt_data_intg_gen

  # declare a fully asynchronous interface
  reg_clk_expr = "clk_i"
  reg_rst_expr = "rst_ni"
  tl_h2d_expr = "tl_i"
  tl_d2h_expr = "tl_o"
  if rb.async_if:
    tl_h2d_expr = "tl_async_h2d"
    tl_d2h_expr = "tl_async_d2h"
    for clock in rb.clocks.values():
      reg_clk_expr = clock.clock
      reg_rst_expr = clock.reset

  # A map from "register" (which might be a multiregister) to a pair (r0, srs)
  # where r0 is the prototype register and srs is a list of single registers
  # corresponding to the original register.
  r0_srs = {}

  # A big map from field to "finst names". These names are a pair (fld_pfx,
  # name), where fld_pfx is the name used to index into hw2reg / reg2hw
  # structures (something like "my_reg.my_field") and name is the name that
  # gets prefixed onto local signals (something like "my_reg_my_field").
  finst_names = {}

  for r in rb.all_regs:
    if isinstance(r, MultiRegister):
      r0 = r.reg
      srs = r.regs
    else:
      r0 = r
      srs = [r]

    r0_srs[r] = (r0, srs)

    reg_name = r0.name.lower()
    fld_count = 0
    for sr_idx, sr in enumerate(srs):
      sr_name = sr.name.lower()
      for fidx, field in enumerate(sr.fields):
        if isinstance(r, MultiRegister):
          sig_idx = fld_count if r.is_homogeneous() else sr_idx
          fsig_pfx = '{}[{}]'.format(reg_name, sig_idx)
        else:
          fsig_pfx = reg_name

        fld_count += 1

        fld_name = field.name.lower()
        if len(sr.fields) == 1:
          finst_name = sr_name
          fsig_name = fsig_pfx
        else:
          finst_name = sr_name + '_' + fld_name
          if isinstance(r, MultiRegister):
            if r.is_homogeneous():
              fsig_name = fsig_pfx
            else:
              fsig_name = '{}.{}'.format(fsig_pfx, get_basename(fld_name))
          else:
            fsig_name = '{}.{}'.format(fsig_pfx, fld_name)

        finst_names[field] = (fsig_name, finst_name)

%>
`include "prim_assert.sv"

module ${mod_name}${' (' if not racl_support else ''}
% if racl_support:
  # (
    parameter bit EnableRacl   = 1'b0,
    parameter bit RaclErrorRsp = 1'b1
  ) (
% endif
  input clk_i,
  input rst_ni,
% if rb.has_internal_shadowed_reg():
  input rst_shadowed_ni,
% endif
% for clock in rb.clocks.values():
  input ${clock.clock},
  input ${clock.reset},
% endfor
  input  tlul_pkg::tl_h2d_t tl_i,
  output tlul_pkg::tl_d2h_t tl_o,
% if num_wins != 0:

  // Output port for window
  output tlul_pkg::tl_h2d_t tl_win_o${win_array_decl},
  input  tlul_pkg::tl_d2h_t tl_win_i${win_array_decl},

% endif
  // To HW
% if rb.get_n_bits(["q","qe","re"]):
  output ${lblock}${alias_impl}_reg_pkg::${reg2hw_t} reg2hw, // Write
% endif
% if rb.get_n_bits(["d","de"]):
  input  ${lblock}${alias_impl}_reg_pkg::${hw2reg_t} hw2reg, // Read
% endif

% if rb.has_internal_shadowed_reg():
  output logic shadowed_storage_err_o,
  output logic shadowed_update_err_o,

%endif
% if racl_support:
  // RACL interface
  input  top_racl_pkg::racl_policy_vec_t racl_policies_i,
  input  integer racl_policy_sel_vec_i[${len(rb.flat_regs)}],
  output logic racl_error_o,
  output top_racl_pkg::racl_error_log_t racl_error_log_o,

% endif
  // Integrity check errors
  output logic intg_err_o
);

  import ${lblock}${alias_impl}_reg_pkg::* ;

% if needs_aw:
  localparam int AW = ${addr_width};
% endif
% if rb.all_regs:
  localparam int DW = ${block.regwidth};
  localparam int DBW = DW/8;                    // Byte Width

  // register signals
  logic           reg_we;
  logic           reg_re;
  logic [AW-1:0]  reg_addr;
  logic [DW-1:0]  reg_wdata;
  logic [DBW-1:0] reg_be;
  logic [DW-1:0]  reg_rdata;
  logic           reg_error;

  logic          addrmiss, wr_err;

  logic [DW-1:0] reg_rdata_next;
  logic reg_busy;

  tlul_pkg::tl_h2d_t tl_reg_h2d;
  tlul_pkg::tl_d2h_t tl_reg_d2h;
% endif

## The clock and reset inputs aren't used if this device interface has no
## registers, only one window and isn't marked asynchronous. In that case, add
## an unused_ signal to avoid lint warnings.
% if not rb.all_regs and num_wins == 1 and not rb.async_if:
  // Add an unloaded flop to make use of clock / reset
  // This is done to specifically address lint complaints of unused clocks/resets
  // Since the flop is unloaded it will be removed during synthesis
  logic unused_reg;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      unused_reg <= '0;
    end else begin
      unused_reg <= tl_i.a_valid;
    end
  end


% endif
% if rb.async_if:
  tlul_pkg::tl_h2d_t tl_async_h2d;
  tlul_pkg::tl_d2h_t tl_async_d2h;
  tlul_fifo_async #(
    .ReqDepth(2),
    .RspDepth(2)
  ) u_if_sync (
    .clk_h_i(clk_i),
    .rst_h_ni(rst_ni),
    .clk_d_i(${reg_clk_expr}),
    .rst_d_ni(${reg_rst_expr}),
    .tl_h_i(tl_i),
    .tl_h_o(tl_o),
    .tl_d_o(${tl_h2d_expr}),
    .tl_d_i(${tl_d2h_expr})
  );
% endif

% if rb.all_regs:
  // incoming payload check
  logic intg_err;
  tlul_cmd_intg_chk u_chk (
    .tl_i(${tl_h2d_expr}),
    .err_o(intg_err)
  );

  // also check for spurious write enables
  logic reg_we_err;
  ## Note that the write-enables are per register.
  ## Hence, we reduce the byte address to a word address here.
  logic [${len(regs_flat)-1}:0] reg_we_check;
  prim_reg_we_check #(
    .OneHotWidth(${len(regs_flat)})
  ) u_prim_reg_we_check (
    .clk_i(${reg_clk_expr}),
    .rst_ni(${reg_rst_expr}),
    .oh_i  (reg_we_check),
    .en_i  (reg_we && !addrmiss),
    .err_o (reg_we_err)
  );

  logic err_q;
<%
  clk_lc_found = False;
  for clock in rb.clocks.values():
    if clock.clock == "clk_lc_i":
      clk_lc_found = True;
    endif
  endfor
%>\
% if clk_lc_found:
  always_ff @(posedge clk_lc_i or negedge rst_lc_ni) begin
    if (!rst_lc_ni) begin
% else:
  always_ff @(posedge ${reg_clk_expr} or negedge ${reg_rst_expr}) begin
    if (!${reg_rst_expr}) begin
% endif
      err_q <= '0;
    end else if (intg_err || reg_we_err) begin
      err_q <= 1'b1;
    end
  end

  // integrity error output is permanent and should be used for alert generation
  // register errors are transactional
  assign intg_err_o = err_q | intg_err | reg_we_err;
% else:
  // Since there are no registers in this block, commands are routed through to windows which
  // can report their own integrity errors.
  assign intg_err_o = 1'b0;
% endif

  // outgoing integrity generation
  tlul_pkg::tl_d2h_t tl_o_pre;
  tlul_rsp_intg_gen #(
    .EnableRspIntgGen(1),
    .EnableDataIntgGen(${common_data_intg_gen})
  ) u_rsp_intg_gen (
    .tl_i(tl_o_pre),
    .tl_o(${tl_d2h_expr})
  );

% if num_dsp <= 1:
  ## Either no windows (and just registers) or no registers and only
  ## one window.
  % if num_wins == 0:
  assign tl_reg_h2d = ${tl_h2d_expr};
  assign tl_o_pre   = tl_reg_d2h;
  % else:
  assign tl_win_o = ${tl_h2d_expr};
  assign tl_o_pre = tl_win_i;
  % endif
% else:
  tlul_pkg::tl_h2d_t tl_socket_h2d [${num_dsp}];
  tlul_pkg::tl_d2h_t tl_socket_d2h [${num_dsp}];

  logic [${steer_msb}:0] reg_steer;

  // socket_1n connection
  % if rb.all_regs:
  assign tl_reg_h2d = tl_socket_h2d[${num_wins}];
  assign tl_socket_d2h[${num_wins}] = tl_reg_d2h;

  % endif
  % for i,t in enumerate(rb.windows):
<%
      win_suff = f'[{i}]' if num_wins > 1 else ''
%>\
  assign tl_win_o${win_suff} = tl_socket_h2d[${i}];
    % if common_data_intg_gen == 0 and rb.windows[i].data_intg_passthru == False:
    ## If there are multiple windows, and not every window has data integrity
    ## passthrough, we must generate data integrity for it here.
  tlul_rsp_intg_gen #(
    .EnableRspIntgGen(0),
    .EnableDataIntgGen(1)
  ) u_win${i}_data_intg_gen (
    .tl_i(tl_win_i${win_suff}),
    .tl_o(tl_socket_d2h[${i}])
  );
    % else:
  assign tl_socket_d2h[${i}] = tl_win_i${win_suff};
    % endif
  % endfor

  // Create Socket_1n
  tlul_socket_1n #(
    .N            (${num_dsp}),
    .HReqPass     (1'b1),
    .HRspPass     (1'b1),
    .DReqPass     ({${num_dsp}{1'b1}}),
    .DRspPass     ({${num_dsp}{1'b1}}),
    .HReqDepth    (4'h0),
    .HRspDepth    (4'h0),
    .DReqDepth    ({${num_dsp}{4'h0}}),
    .DRspDepth    ({${num_dsp}{4'h0}}),
    .ExplicitErrs (1'b0)
  ) u_socket (
    .clk_i  (${reg_clk_expr}),
    .rst_ni (${reg_rst_expr}),
    .tl_h_i (${tl_h2d_expr}),
    .tl_h_o (tl_o_pre),
    .tl_d_o (tl_socket_h2d),
    .tl_d_i (tl_socket_d2h),
    .dev_select_i (reg_steer)
  );

  // Create steering logic
  always_comb begin
    reg_steer =
  % for i,w in enumerate(rb.windows):
<%
      steer_width = steer_msb + 1
      base_addr = w.offset
      limit_addr = w.offset + w.size_in_bytes
      assert (limit_addr-1 >= base_addr)
      addr_test = f"[{base_addr}:{limit_addr-1}]"
%>\
        ${f'{tl_h2d_expr}.a_address[AW-1:0]'} inside {${addr_test}} ? ${steer_width}'d${i} :
  % endfor
        // Default set to register
        ${steer_width}'d${num_dsp-1};

    // Override this in case of an integrity error
    if (intg_err) begin
      reg_steer = ${steer_width}'d${num_dsp-1};
    end
  end
% endif
% if rb.all_regs:

  tlul_adapter_reg #(
    .RegAw(AW),
    .RegDw(DW),
    .EnableDataIntgGen(${adapt_data_intg_gen})
  ) u_reg_if (
    .clk_i  (${reg_clk_expr}),
    .rst_ni (${reg_rst_expr}),

    .tl_i (tl_reg_h2d),
    .tl_o (tl_reg_d2h),

    .en_ifetch_i(prim_mubi_pkg::MuBi4False),
    .intg_error_o(),

    .we_o    (reg_we),
    .re_o    (reg_re),
    .addr_o  (reg_addr),
    .wdata_o (reg_wdata),
    .be_o    (reg_be),
    .busy_i  (reg_busy),
    .rdata_i (reg_rdata),
  % if racl_support:
    // Translate RACL error to TLUL error if enabled
    .error_i (reg_error | (RaclErrorRsp & racl_error_o))
  % else:
    .error_i (reg_error)
  % endif
  );

  // cdc oversampling signals

  % if block.expose_reg_if:
  assign reg2hw.reg_if.reg_we    = reg_we;
  assign reg2hw.reg_if.reg_re    = reg_re;
  assign reg2hw.reg_if.reg_addr  = reg_addr;
  assign reg2hw.reg_if.reg_wdata = reg_wdata;
  assign reg2hw.reg_if.reg_be    = reg_be;

  % endif
  assign reg_rdata = reg_rdata_next ;
  assign reg_error = addrmiss | wr_err | intg_err;

  // Define SW related signals
  // Format: <reg>_<field>_{wd|we|qs}
  //        or <reg>_{wd|we|qs} if field == 1 or 0
  % for r in regs_flat:
${reg_sig_decl(r)}\
    % for f in r.fields:
<%
        fld_suff = '_' + f.name.lower() if len(r.fields) > 1 else ''
        sig_name = r.name.lower() + fld_suff
%>\
${field_sig_decl(f, sig_name, r.hwext, r.shadowed, r.async_clk)}\
    % endfor
  % endfor
  % if len(rb.clocks.values()) > 0:
  // Define register CDC handling.
  // CDC handling is done on a per-reg instead of per-field boundary.
  % endif
  % for r in regs_flat:
    % if r.async_clk:
<%
  base_name = r.async_clk.clock_base_name
  r_name = r.name.lower()
  comb_name = f"{base_name}_{r_name}"
  src_we_expr = f"{r_name}_we" if r.needs_we() else "'0"
  src_wd_expr = f"reg_wdata[{r.get_width()-1}:0]" if r.needs_we() else "'0"
  src_re_expr = f"{r_name}_re" if r.needs_re() else "'0"
  src_regwen_expr = f"{r.regwen.lower()}_qs" if r.regwen else "'0"
  dst_we_expr = f"{comb_name}_we" if r.needs_we() else ""
  dst_wd_expr = f"{comb_name}_wdata" if r.needs_we() else ""
  dst_re_expr = f"{comb_name}_re" if r.needs_re() else ""
  dst_regwen_expr = f"{comb_name}_regwen" if r.regwen else ""
  dst_qe_expr = f"{comb_name}_qe" if r.is_hw_writable() else "'0"
  dst_wr_req = "1" if r.is_hw_writable() else "0"
  dst_ds_expr = f"{comb_name}_ds" if r.is_hw_writable() else "'0"
  reset_val = format(r.resval, "x")
  reset_val_expr = f"{r.get_width()}'h{reset_val}"
%>
      % if len(r.fields) > 1:
        % for f in r.fields:
          % if r.is_hw_writable():
  logic ${str_arr_sv(f.bits)} ${comb_name}_${f.name.lower()}_ds_int;
          % endif
          % if f.swaccess.allows_read():
  logic ${str_arr_sv(f.bits)} ${comb_name}_${f.name.lower()}_qs_int;
          % endif
        % endfor
      % else:
          % if r.is_hw_writable():
  logic ${str_arr_sv(r.fields[0].bits)} ${comb_name}_ds_int;
          % endif
        % if r.fields[0].swaccess.allows_read():
  logic ${str_arr_sv(r.fields[0].bits)} ${comb_name}_qs_int;
        % endif
      % endif
      % if r.is_hw_writable():
  logic [${r.get_width()-1}:0] ${comb_name}_ds;
  logic ${dst_qe_expr};
      % endif
  logic [${r.get_width()-1}:0] ${comb_name}_qs;
      % if r.needs_we():
  logic [${r.get_width()-1}:0] ${comb_name}_wdata;
  logic ${dst_we_expr};
  logic unused_${comb_name}_wdata;
      % endif
      % if r.needs_re():
  logic ${dst_re_expr};
      % endif
      % if r.regwen:
  logic ${dst_regwen_expr};
      % endif

  ## Since prim_reg_cdc operates at the level of the register, the registers
  ## hw writability is used to determine whether the ds is needed.
  always_comb begin
    ${comb_name}_qs = ${reset_val_expr};
    % if r.is_hw_writable():
    ${comb_name}_ds = ${reset_val_expr};
    % endif
      % if len(r.fields) > 1:
        % for f in r.fields:
          % if r.is_hw_writable() and f.swaccess.allows_read():
    ${comb_name}_ds[${str_bits_sv(f.bits)}] = ${comb_name}_${f.name.lower()}_ds_int;
          % endif
          % if f.swaccess.allows_read():
    ${comb_name}_qs[${str_bits_sv(f.bits)}] = ${comb_name}_${f.name.lower()}_qs_int;
          % endif
        % endfor
      % else:
          % if r.is_hw_writable() and r.fields[0].swaccess.allows_read():
    ${comb_name}_ds = ${comb_name}_ds_int;
          % endif
          % if r.fields[0].swaccess.allows_read():
    ${comb_name}_qs = ${comb_name}_qs_int;
          % endif
      % endif
  end

  prim_reg_cdc #(
    .DataWidth(${r.get_width()}),
    .ResetVal(${reset_val_expr}),
    .BitMask(${r.get_width()}'h${r.bitmask()}),
    .DstWrReq(${dst_wr_req})
  ) u_${r_name}_cdc (
    .clk_src_i    (${reg_clk_expr}),
    .rst_src_ni   (${reg_rst_expr}),
    .clk_dst_i    (${r.async_clk.clock}),
    .rst_dst_ni   (${r.async_clk.reset}),
    .src_regwen_i (${src_regwen_expr}),
    .src_we_i     (${src_we_expr}),
    .src_re_i     (${src_re_expr}),
    .src_wd_i     (${src_wd_expr}),
    .src_busy_o   (${r_name}_busy),
    .src_qs_o     (${r_name}_qs), // for software read back
    .dst_update_i (${dst_qe_expr}),
    .dst_ds_i     (${dst_ds_expr}),
    .dst_qs_i     (${comb_name}_qs),
    .dst_we_o     (${dst_we_expr}),
    .dst_re_o     (${dst_re_expr}),
    .dst_regwen_o (${dst_regwen_expr}),
    .dst_wd_o     (${dst_wd_expr})
  );
      % if r.needs_we():
  assign unused_${comb_name}_wdata =
      ^${comb_name}_wdata;
      % endif
    % endif
  % endfor

  // Register instances
  % for r in rb.all_regs:
<%
      r0, srs = r0_srs[r]
      reg_name = r0.name.lower()
%>\
    % for sr_idx, sr in enumerate(srs):
<%
        sr_name = sr.name.lower()

        if isinstance(r, MultiRegister):
          reg_hdr = (f'  // Subregister {sr_idx} of Multireg {reg_name}\n' +
                     f'  // R[{sr_name}]: V({sr.hwext})')
        else:
          reg_hdr = (f'  // R[{sr_name}]: V({sr.hwext})')
        clk_expr = sr.async_clk.clock if sr.async_clk else reg_clk_expr
        rst_expr = sr.async_clk.reset if sr.async_clk else reg_rst_expr
%>\
${reg_hdr}
      % if sr.needs_qe():
  logic ${sr_name}_qe;
      % endif
      % if sr.needs_int_qe():
  logic [${len(sr.fields)-1}:0] ${sr_name}_flds_we;
      % endif
      % if sr.needs_qe():
<%
      flds_no_we = 0
      for f_idx, f in enumerate(sr.fields):
        flds_no_we |= (not f.swaccess.needs_we()) << f_idx
      if flds_no_we != 0:
        flds_we_masked = f"&({sr_name}_flds_we | {len(sr.fields)}'h{flds_no_we:x})"
        unused_flds_we_masked = f"^({sr_name}_flds_we & {len(sr.fields)}'h{flds_no_we:x})"
      else:
        flds_we_masked = f"&{sr_name}_flds_we"
      f"" if flds_no_we != 0 else ""
%>\
        % if sr.hwext and flds_no_we != 2**len(sr.fields)-1:
          % if flds_no_we != 0:
  // This ignores QEs that are set to constant 0 due to read-only fields.
  logic unused_${sr_name}_flds_we;
  assign unused_${sr_name}_flds_we = ${unused_flds_we_masked};
          % endif
  assign ${sr_name}_qe = ${flds_we_masked};
        % elif flds_no_we != 2**len(sr.fields)-1:
  prim_flop #(
    .Width(1),
    .ResetValue(0)
  ) u_${reg_name}${sr_idx}_qe (
    .clk_i(${clk_expr}),
    .rst_ni(${rst_expr}),
    .d_i(${flds_we_masked}),
    .q_o(${sr_name}_qe)
  );
        % else:
  // In case all fields are read-only the aggregated register QE will be zero as well.
  assign ${sr_name}_qe = &${sr_name}_flds_we;
        % endif
      % endif
<%
  # We usually use the REG_we signal, but use REG_re for RC fields
  # (which get updated on a read, not a write)
  clk_base_name = f"{sr.async_clk.clock_base_name}_" if sr.async_clk else ""
  we_suffix = 're' if field.swaccess.swrd() == SwRdAccess.RC else 'we'
  we_signal = f'{clk_base_name}{sr_name}_{we_suffix}'

  if sr.async_clk and sr.regwen:
    we_expr = f'{we_signal} & {clk_base_name}{sr_name}_regwen'
  elif sr.regwen:
    we_expr = f'{we_signal} & {sr.regwen.lower()}_qs'
    for reg in regs_flat:
      if reg.name == sr.regwen and reg.fields[0].mubi:
        we_expr = f'''{we_signal} &
          prim_mubi_pkg::mubi{reg.fields[0].bits.width()}_test_true_strict(prim_mubi_pkg::mubi{reg.fields[0].bits.width()}_t\'({sr.regwen.lower()}_qs))'''
  else:
    we_expr = we_signal

  we_expr_regwen_gated = f'{clk_base_name}{sr_name}_gated_{we_suffix}'
%>\
  % if sr.async_clk and sr.is_hw_writable():
  assign ${clk_base_name}${sr_name}_qe = |${sr_name}_flds_we;
  % endif
  ## Only create this helper signal if there actually is a REGWEN gate.
  ## Otherwise the WE signal is connected directly to the register.
  % if sr.regwen and sr.needs_we():
  // Create REGWEN-gated WE signal
  logic ${we_expr_regwen_gated};
<%
    # Wrap the assignment if the statement is too long
    assignment = f'assign {we_expr_regwen_gated} = {we_expr};'
    if len(assignment) > 100-2:
      assignment = f'assign {we_expr_regwen_gated} =\n    {we_expr};'
%>\
  ${assignment}
  % endif
      % for fidx, field in enumerate(sr.fields):
<%
          fld_name = field.name.lower()
          fsig_name, finst_name = finst_names[field]
%>\
        % if len(sr.fields) > 1:
  //   F[${fld_name}]: ${field.bits.msb}:${field.bits.lsb}
        % endif
${finst_gen(sr, field, finst_name, fsig_name, fidx)}
      % endfor

    % endfor
  % endfor

  logic [${len(regs_flat)-1}:0] addr_hit;
% if racl_support:
  top_racl_pkg::racl_role_vec_t racl_role_vec;
  top_racl_pkg::racl_role_t racl_role;

  logic [${len(regs_flat)-1}:0] racl_addr_hit_read;
  logic [${len(regs_flat)-1}:0] racl_addr_hit_write;

  if (EnableRacl) begin : gen_racl_role_logic
    // Retrieve RACL role from user bits and one-hot encode that for the comparison bitmap
    assign racl_role = top_racl_pkg::tlul_extract_racl_role_bits(tl_i.a_user.rsvd);

    prim_onehot_enc #(
      .OneHotWidth( $bits(prim_onehot_enc) )
    ) u_racl_role_encode (
      .in_i ( racl_role     ),
      .en_i ( 1'b1          ),
      .out_o( racl_role_vec )
    );
  end else begin : gen_no_racl_role_logic
    assign racl_role     = '0;
    assign racl_role_vec = '0;
  end

% endif
  always_comb begin
    addr_hit = '0;
  % if racl_support:
    racl_addr_hit_read  = '0;
    racl_addr_hit_write = '0;
  % endif
    % for i,r in enumerate(regs_flat):
<% slice = '{}'.format(i).rjust(max_regs_char) %>\
    addr_hit[${slice}] = (reg_addr == ${ublock}_${r.name.upper()}_OFFSET);
    % endfor
  % if racl_support:

    if (EnableRacl) begin : gen_racl_hit
    % for i,r in enumerate(regs_flat):
<% slice = '{}'.format(i).rjust(max_regs_char) %>\
      racl_addr_hit_read [${slice}] = addr_hit[${slice}] & (|(racl_policies_i[racl_policy_sel_vec_i[${slice}]].read_perm  & racl_role_vec));
      racl_addr_hit_write[${slice}] = addr_hit[${slice}] & (|(racl_policies_i[racl_policy_sel_vec_i[${slice}]].write_perm & racl_role_vec));
    % endfor
    end else begin : gen_no_racl
      racl_addr_hit_read  = addr_hit;
      racl_addr_hit_write = addr_hit;
    end
  % endif
  end

  assign addrmiss = (reg_re || reg_we) ? ~|addr_hit : 1'b0 ;
% if racl_support:
  // Address hit but failed the RACL check
  assign racl_error_o = (|addr_hit) & ~(|(addr_hit & (racl_addr_hit_read | racl_addr_hit_write)));
  assign racl_error_log_o.racl_role  = racl_role;

  if (EnableRacl) begin : gen_racl_log
    assign racl_error_log_o.ctn_uid        = top_racl_pkg::tlul_extract_ctn_uid_bits(tl_i.a_user.rsvd);
    assign racl_error_log_o.read_not_write = tl_i.a_opcode == tlul_pkg::Get;
  end else begin : gen_no_racl_log
    assign racl_error_log_o.ctn_uid        = '0;
    assign racl_error_log_o.read_not_write = 1'b0;
  end
% endif

  % if regs_flat:
<%
    # We want to signal wr_err if reg_be (the byte enable signal) is true for
    # any bytes that aren't supported by a register. That's true if a
    # addr_hit[i] and a bit is set in reg_be but not in *_PERMIT[i].

    wr_addr_hit = 'racl_addr_hit_write' if racl_support else 'addr_hit'
    wr_err_terms = ['({wr_addr_hit}[{idx}] & (|({mod}_PERMIT[{idx}] & ~reg_be)))'
                    .format(idx=str(i).rjust(max_regs_char),
                            mod=u_mod_base,
                            wr_addr_hit=wr_addr_hit)
                    for i in range(len(regs_flat))]
    wr_err_expr = (' |\n' + (' ' * 15)).join(wr_err_terms)
%>\
  // Check sub-word write is permitted
  always_comb begin
    wr_err = (reg_we &
              (${wr_err_expr}));
  end
  % else:
  assign wr_error = 1'b0;
  % endif\


  // Generate write-enables
  % for i, r in enumerate(regs_flat):
${reg_enable_gen(r, i)}\
    % if len(r.fields) == 1:
${field_wd_gen(r.fields[0], r.name.lower(), r.hwext, r.shadowed, r.async_clk, r.name, i)}\
    % else:
      % for f in r.fields:
${field_wd_gen(f, r.name.lower() + "_" + f.name.lower(), r.hwext, r.shadowed, r.async_clk, r.name, i)}\
      % endfor
    % endif
  % endfor

  // Assign write-enables to checker logic vector.
  always_comb begin
    reg_we_check = '0;
    % for i, r in enumerate(regs_flat):
<%
    # The WE checking logic does NOT protect RC fields.
    if r.needs_we():
      # In case this is an asynchronous register, the WE signal is taken from
      # the CDC primitive input. This could be enhanced in the future to provide
      # more protection for asynchronous registers.
      if r.async_clk or not r.regwen:
        we_expr = f'{r.name.lower()}_we'
      else:
        we_expr = f'{r.name.lower()}_gated_we'
    else:
      we_expr = "1'b0"

    assignment = f'reg_we_check[{i}] = {we_expr};'

    # Wrap the assignment if the statement is too long
    if len(assignment) > 100-4:
      assignment = f'reg_we_check[{i}] =\n        {we_expr};'
%>\
    ${assignment}
    % endfor
  end

  // Read data return
  always_comb begin
    reg_rdata_next = '0;
    unique case (1'b1)
<% read_addr_hit = 'racl_addr_hit_read' if racl_support else 'addr_hit' %>\
  % for i, r in enumerate(regs_flat):
    % if r.async_clk:
      ${read_addr_hit}[${i}]: begin
        reg_rdata_next = DW'(${r.name.lower()}_qs);
      end
    % elif len(r.fields) == 1:
      ${read_addr_hit}[${i}]: begin
${rdata_gen(r.fields[0], r.name.lower())}\
      end

    % else:
      ${read_addr_hit}[${i}]: begin
      % for f in r.fields:
${rdata_gen(f, r.name.lower() + "_" + f.name.lower())}\
      % endfor
      end

    % endif
  % endfor
      default: begin
        reg_rdata_next = '1;
      end
    endcase
  end

  // shadow busy
  logic shadow_busy;
  % if rb.has_internal_shadowed_reg():
  logic rst_done;
  logic shadow_rst_done;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      rst_done <= '0;
    end else begin
      rst_done <= 1'b1;
    end
  end

  always_ff @(posedge clk_i or negedge rst_shadowed_ni) begin
    if (!rst_shadowed_ni) begin
      shadow_rst_done <= '0;
    end else begin
      shadow_rst_done <= 1'b1;
    end
  end

  // both shadow and normal resets have been released
  assign shadow_busy = ~(rst_done & shadow_rst_done);
  % else:
  assign shadow_busy = 1'b0;
  % endif

  % if rb.has_internal_shadowed_reg():
  // Collect up storage and update errors
<%
    shadowed_field_pfxs = []
    for r in rb.all_regs:
      r0, srs = r0_srs[r]

      if not (r0.shadowed and not r0.hwext):
        continue

      for sr in srs:
        for field in sr.fields:
          _, pfx = finst_names[field]
          shadowed_field_pfxs.append(pfx)
%>\
  assign shadowed_storage_err_o = |{
  % for pfx in shadowed_field_pfxs:
    ${pfx}_storage_err${"" if loop.last else ","}
  % endfor
  };
  assign shadowed_update_err_o = |{
  % for pfx in shadowed_field_pfxs:
    ${pfx}_update_err${"" if loop.last else ","}
  % endfor
  };

  % endif
  // register busy
<%
  async_busy_signals = {}
  for i, r in enumerate(regs_flat):
    if r.async_clk:
      async_busy_signals[i] = r.name.lower() + "_busy"
%>\
  % if rb.async_if or not async_busy_signals:
  assign reg_busy = shadow_busy;
  % else:
  logic reg_busy_sel;
  assign reg_busy = reg_busy_sel | shadow_busy;
  always_comb begin
    reg_busy_sel = '0;
    unique case (1'b1)
    % for i, busy_signal in async_busy_signals.items():
      addr_hit[${i}]: begin
        reg_busy_sel = ${busy_signal};
      end
    % endfor
      default: begin
        reg_busy_sel  = '0;
      end
    endcase
  end

  % endif
% endif

  // Unused signal tieoff
% if rb.all_regs:

  // wdata / byte enable are not always fully used
  // add a blanket unused statement to handle lint waivers
  logic unused_wdata;
  logic unused_be;
  assign unused_wdata = ^reg_wdata;
  assign unused_be = ^reg_be;
% endif
% if rb.all_regs:

  // Assertions for Register Interface
  `ASSERT_PULSE(wePulse, reg_we, ${reg_clk_expr}, !${reg_rst_expr})
  `ASSERT_PULSE(rePulse, reg_re, ${reg_clk_expr}, !${reg_rst_expr})

  `ASSERT(reAfterRv, $rose(reg_re || reg_we) |=> tl_o_pre.d_valid, ${reg_clk_expr}, !${reg_rst_expr})

  `ASSERT(en2addrHit, (reg_we || reg_re) |-> $onehot0(addr_hit), ${reg_clk_expr}, !${reg_rst_expr})

  // this is formulated as an assumption such that the FPV testbenches do disprove this
  // property by mistake
  //`ASSUME(reqParity, tl_reg_h2d.a_valid |-> tl_reg_h2d.a_user.chk_en == tlul_pkg::CheckDis)

% endif
endmodule
<%def name="str_bits_sv(bits)">\
% if bits.msb != bits.lsb:
${bits.msb}:${bits.lsb}\
% else:
${bits.msb}\
% endif
</%def>\
<%def name="str_arr_sv(bits)">\
% if bits.msb != bits.lsb:
[${bits.msb-bits.lsb}:0] \
% endif
</%def>\
<%def name="reg_sig_decl(reg)">\
  % if reg.needs_re():
  logic ${reg.name.lower()}_re;
  % endif
  % if reg.needs_we():
  logic ${reg.name.lower()}_we;
  % endif
  % if reg.async_clk:
  logic [${reg.get_width()-1}:0] ${reg.name.lower()}_qs;
  logic ${reg.name.lower()}_busy;
  % endif
</%def>\
<%def name="field_sig_decl(field, sig_name, hwext, shadowed, async_clk)">\
  % if not async_clk and field.swaccess.allows_read():
  logic ${str_arr_sv(field.bits)}${sig_name}_qs;
  % endif
  % if not async_clk and field.swaccess.allows_write():
  logic ${str_arr_sv(field.bits)}${sig_name}_wd;
  % endif
  % if shadowed and not hwext:
  logic ${sig_name}_storage_err;
  logic ${sig_name}_update_err;
  % endif
</%def>\
<%def name="finst_gen(reg, field, finst_name, fsig_name, fidx)">\
<%

    clk_base_name = f"{reg.async_clk.clock_base_name}_" if reg.async_clk else ""
    reg_name = reg.name.lower()
    clk_expr = reg.async_clk.clock if reg.async_clk else reg_clk_expr
    rst_expr = reg.async_clk.reset if reg.async_clk else reg_rst_expr
    re_expr = f'{clk_base_name}{reg_name}_re' if field.swaccess.allows_read() or reg.shadowed else "1'b0"

    # software inputs to field instance, write enable, read enable, write data
    if field.swaccess.allows_write():
      # We usually use the REG_we signal, but use REG_re for RC fields
      # (which get updated on a read, not a write)
      we_suffix = 're' if field.swaccess.swrd() == SwRdAccess.RC else 'we'
      # If this is a REGWEN gated field, need to use the gated WE signal.
      gated_suffix = '_gated' if reg.regwen else ''
      we_expr = f'{clk_base_name}{reg_name}{gated_suffix}_{we_suffix}'

      # when async, pick from the cdc handled data
      wd_expr = f'{finst_name}_wd'
      if reg.async_clk:
        if field.bits.msb == field.bits.lsb:
          bit_sel = f'{field.bits.msb}'
        else:
          bit_sel = f'{field.bits.msb}:{field.bits.lsb}'
        wd_expr = f'{clk_base_name}{reg_name}_wdata[{bit_sel}]'

    else:
      we_expr = "1'b0"
      wd_expr = "'0"

    # hardware inputs to field instance
    if field.hwaccess.allows_write():
      de_expr = f'hw2reg.{fsig_name}.de'
      d_expr = f'hw2reg.{fsig_name}.d'
    else:
      de_expr = "1'b0"
      d_expr = "'0"

    # field instance outputs
    qre_expr = f'reg2hw.{fsig_name}.re' if reg.hwre or reg.shadowed else ""

    if reg.needs_int_qe() or field.hwaccess.allows_read():
      qe_expr = f'{reg_name}_flds_we[{fidx}]' if reg.needs_int_qe() else ''
    else:
      qe_expr = ''

    if field.hwaccess.allows_read():
      qe_reg_expr = f'reg2hw.{fsig_name}.qe'
      q_expr = f'reg2hw.{fsig_name}.q'
    else:
      q_expr = ''

    if field.mubi:
      mubi_expr = "1'b1"
    else:
      mubi_expr = "1'b0"

    # when async, the outputs are aggregated first by the cdc module
    async_suffix = '_int' if reg.async_clk else ''
    qs_expr = f'{clk_base_name}{finst_name}_qs{async_suffix}' if field.swaccess.allows_read() else ''
    ds_expr = f'{clk_base_name}{finst_name}_ds{async_suffix}' if reg.async_clk and reg.is_hw_writable() else ''

%>\
  % if reg.hwext:       ## if hwext, instantiate prim_subreg_ext
<%
    subreg_block = "prim_subreg_ext"
%>\
  ${subreg_block} #(
    .DW    (${field.bits.width()})
  ) u_${finst_name} (
    .re     (${re_expr}),
    .we     (${we_expr}),
    .wd     (${wd_expr}),
    .d      (${d_expr}),
    .qre    (${qre_expr}),
    .qe     (${qe_expr}),
    .q      (${q_expr}),
    .ds     (${ds_expr}),
    .qs     (${qs_expr})
  );
  % else:
<%
      # This isn't a field in a hwext register. Instantiate prim_subreg,
      # prim_subreg_shadow or constant assign.

      resval_expr = f"{field.bits.width()}'h{field.resval or 0:x}"
      is_const_reg = not (field.hwaccess.allows_read() or
                          field.hwaccess.allows_write() or
                          field.swaccess.allows_write() or
                          field.swaccess.swrd() != SwRdAccess.RD)

      subreg_block = 'prim_subreg' + ('_shadow' if reg.shadowed else '')
%>\
    % if is_const_reg:
  // constant-only read
  assign ${finst_name}_qs = ${resval_expr};
    % else:
      % if reg.async_clk and reg.shadowed:
  logic async_${finst_name}_err_update;
  logic async_${finst_name}_err_storage;

  // storage error is persistent and can be sampled at any time
  prim_flop_2sync #(
    .Width(1),
    .ResetValue('0)
  ) u_${finst_name}_err_storage_sync (
    .clk_i,
    .rst_ni,
    .d_i(async_${finst_name}_err_storage),
    .q_o(${finst_name}_storage_err)
  );

  // update error is transient and must be immediately captured
  prim_pulse_sync u_${finst_name}_err_update_sync (
    .clk_src_i(${reg.async_clk.clock}),
    .rst_src_ni(${reg.async_clk.reset}),
    .src_pulse_i(async_${finst_name}_err_update),
    .clk_dst_i(clk_i),
    .rst_dst_ni(rst_ni),
    .dst_pulse_o(${finst_name}_update_err)
  );
      % endif
  ${subreg_block} #(
    .DW      (${field.bits.width()}),
    .SwAccess(prim_subreg_pkg::SwAccess${field.swaccess.value[1].name.upper()}),
    .RESVAL  (${resval_expr}),
    .Mubi    (${mubi_expr})
  ) u_${finst_name} (
      % if reg.sync_clk:
    // sync clock and reset required for this register
    .clk_i   (${reg.sync_clk.clock}),
    .rst_ni  (${reg.sync_clk.reset}),
      % else:
    .clk_i   (${clk_expr}),
    .rst_ni  (${rst_expr}),
      % endif
      % if reg.shadowed and not reg.hwext:
    .rst_shadowed_ni (rst_shadowed_ni),
      % endif

    // from register interface
      % if reg.shadowed:
    .re     (${re_expr}),
      % endif
    .we     (${we_expr}),
    .wd     (${wd_expr}),

    // from internal hardware
    .de     (${de_expr}),
    .d      (${d_expr}),

    // to internal hardware
    .qe     (${qe_expr}),
    .q      (${q_expr}),
    .ds     (${ds_expr}),

    // to register interface (read)
      % if not reg.shadowed:
    .qs     (${qs_expr})
      % else:
    .qs     (${qs_expr}),

    // Shadow register phase. Relevant for hwext only.
    .phase  (),

    // Shadow register error conditions
        % if reg.async_clk:
    .err_update  (async_${finst_name}_err_update),
    .err_storage (async_${finst_name}_err_storage)
        % else:
    .err_update  (${finst_name}_update_err),
    .err_storage (${finst_name}_storage_err)
        % endif
      % endif
  );
    % endif  ## end non-constant prim_subreg
  % endif
  % if field.hwaccess.allows_read() and field.hwqe:
  assign ${qe_reg_expr} = ${reg_name}_qe;
  % endif
</%def>\
<%def name="reg_enable_gen(reg, idx)">\
<% wr_addr_hit = 'racl_addr_hit_write' if racl_support else 'addr_hit'%>\
  % if reg.needs_re():
  assign ${reg.name.lower()}_re = ${wr_addr_hit}[${idx}] & reg_re & !reg_error;
  % endif
  % if reg.needs_we():
  assign ${reg.name.lower()}_we = ${wr_addr_hit}[${idx}] & reg_we & !reg_error;
  % endif
</%def>\
<%def name="field_wd_gen(field, sig_name, hwext, shadowed, async_clk, reg_name, idx)">\
<%
    needs_wd = field.swaccess.allows_write()
    space = '\n' if needs_wd or needs_re else ''
%>\
${space}\
% if needs_wd and not async_clk:
  % if field.swaccess.swrd() == SwRdAccess.RC:
  assign ${sig_name}_wd = '1;
  % else:
  assign ${sig_name}_wd = reg_wdata[${str_bits_sv(field.bits)}];
  % endif
% endif
</%def>\
<%def name="rdata_gen(field, sig_name, rd_name='reg_rdata_next')">\
% if field.swaccess.allows_read():
        ${rd_name}[${str_bits_sv(field.bits)}] = ${sig_name}_qs;
% else:
        ${rd_name}[${str_bits_sv(field.bits)}] = '0;
% endif
</%def>\
<%def name="reg_cdc_gen(field, sig_name, hwext, shadowed, idx)">\
<%
    needs_wd = field.swaccess.allows_write()
    space = '\n' if needs_wd or needs_re else ''
%>\
${space}\
% if needs_wd:
  % if field.swaccess.swrd() == SwRdAccess.RC:
  assign ${sig_name}_wd = '1;
  % else:
  assign ${sig_name}_wd = reg_wdata[${str_bits_sv(field.bits)}];
  % endif
% endif
</%def>\
