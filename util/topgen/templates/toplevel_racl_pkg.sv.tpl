// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
${gencmd}

package top_racl_pkg;
  // Number of RACL policies used
  parameter int unsigned NrRaclPolicies = ${racl_config['nr_policies']};

  // Number of RACL bits transferred
  parameter int unsigned NrRaclBits = 4;

  // Number of CTN UID bits transferred
  parameter int unsigned NrCtnUidBits = 8;

  // RACL role type binary encoded
  typedef logic [NrRaclBits-1:0] racl_role_t;

  // CTN UID assigned the bus originator
  typedef logic [NrCtnUidBits-1:0] ctn_uid_t;

  // RACL permission: A one-hot encoded role vector
  typedef logic [(2**NrRaclBits)-1:0] racl_role_vec_t;

  // RACL policy containing a read and write permission
  typedef struct packed {
    racl_role_vec_t read_perm;
    racl_role_vec_t write_perm;
  } racl_policy_t;

  // RACL policy vector for distributing RACL policies from the RACL widget to the subscribing IP
  typedef racl_policy_t [NrRaclPolicies-1:0] racl_policy_vec_t;

  // Default policy vector for unconnected RACL IPs
  parameter racl_policy_vec_t RACL_POLICY_VEC_DEFAULT = '0;

  // Default ROT Private read policy value
  parameter racl_policy_vec_t RACL_POLICY_ROT_PRIVATE_RD = 16'h${f"{racl_config['rot_private_policy_rd']:x}"};

  // Default ROT Private write policy value
  parameter racl_policy_vec_t RACL_POLICY_ROT_PRIVATE_WR = 16'h${f"{racl_config['rot_private_policy_wr']:x}"};

  // RACL information logged in case of a denial
  typedef struct packed {
    racl_role_t racl_role;
    ctn_uid_t   ctn_uid;
    // 0: Write access, 1: Read access
    logic       access_type;
  } racl_error_log_t;

  // Extract RACL role bits from the TLUL reserved user bits
  function automatic racl_role_t tlul_extract_racl_role_bits(logic [tlul_pkg::RsvdWidth-1:0] rsvd);
    // Waive unused bits
    logic unused_rsvd_bits;
    unused_rsvd_bits = ^{rsvd};

    return racl_role_t'(rsvd[11:8]);
  endfunction

  // Extract CTN UID bits from the TLUL reserved user bits
  function automatic ctn_uid_t tlul_extract_ctn_uid_bits(logic [tlul_pkg::RsvdWidth-1:0] rsvd);
    // Waive unused bits
    logic unused_rsvd_bits;
    unused_rsvd_bits = ^{rsvd};

    return ctn_uid_t'(rsvd[7:0]);
  endfunction

% for racl_group, policies in racl_config['policies'].items():
<% prefix = "" if len(racl_config['policies'].keys()) == 1 else f"{racl_group.upper()}_" %>\
  /**
   * Policies for group ${racl_group}
   */

  % for policy in policies:
  /*
   * Policy ${policy['name']} allowed READ roles:
   *   ${', '.join(policy['allowed_wr'])}
   */
  parameter racl_policy_t RACL_POLICY_${prefix}${policy['name'].upper()}_RD_DEFAULT = 16'h${f"{policy['rd_default']:x}"};

  /**
   * Policy ${policy['name']} allowed WRITE roles:
   *   ${', '.join(policy['allowed_wr'])}
   */
  parameter racl_policy_t RACL_POLICY_${prefix}${policy['name'].upper()}_WR_DEFAULT = 16'h${f"{policy['wr_default']:x}"};

  % endfor
% endfor

<%doc>\
  Note: This template needs to be manually synced between the following files:
        util/raclgen.py
        util/topgen/templates/toplevel_racl_pkg.sv.tpl
</%doc>\
<% import math %>\
% if 'racl' in topcfg:
<% policy_names = [policy['name'] for policy in topcfg['racl']['policies'][racl_group]] %>\
<% policy_name_len = max( (len(name) for name in policy_names) ) %>\
<% policy_idx_len = math.ceil(math.log10(max(1,len(policy_names)+1))) %>\
  /**
   * RACL groups:
% for racl_group in topcfg['racl']['policies']:
   *   ${racl_group}
  % for policy_idx, policy_name in enumerate(policy_names):
   *     ${f"{policy_name}".ljust(policy_name_len)} (Idx ${f"{policy_idx}".rjust(policy_idx_len)})
  % endfor
% endfor
   */

% endif
% for m in topcfg['module']:
  % if 'racl_mappings' in m:
    % for if_name in m['racl_mappings'].keys():
<% register_mapping = m['racl_mappings'][if_name]['register_mapping'] %>\
<% racl_group = m['racl_mappings'][if_name]['racl_group'] %>\
<% group_suffix = f"_{racl_group.upper()}" if racl_group and racl_group != "Null" else "" %>\
<% if_suffix = f"_{if_name.upper()}" if if_name else "" %>\
<% reg_name_len = max( (len(name) for name in register_mapping.keys()) ) %>\
  /**
   * Policy selection vector for ${m["name"]}
   *   TLUL interface name: ${if_name}
   *   RACL group: ${racl_group}
      % if len(register_mapping) > 0:
   *   Register to policy mapping:
        % for reg_name, policy_idx in register_mapping.items():
   *     ${f"{reg_name}:".ljust(reg_name_len+1)} ${policy_names[policy_idx]} (Idx ${f"{policy_idx}".rjust(policy_idx_len)})
        % endfor
      % endif
   */
  parameter int unsigned RACL_POLICY_SEL_${m["name"].upper()}${group_suffix}${if_suffix} [${len(register_mapping)}] = '{${", ".join(map(str, reversed(register_mapping.values())))}};

    % endfor
  % endif
% endfor
endpackage
