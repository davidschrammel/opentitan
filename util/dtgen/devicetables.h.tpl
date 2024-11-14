// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
// Device table API auto-generated by `dtgen`
<%
from topgen.lib import Name, is_top_reggen, is_ipgen

module_types = {m["type"] for m in top["module"]}
module_types = sorted(module_types)

def snake_to_constant_name(s):
    out = ""
    parts = s.split("_")
    for p in parts:
        # If we're about to join two parts which would introduce adjacent
        # numbers, put an underscore between them.
        if out[-1:].isnumeric() and p[:1].isnumeric():
            out += "_" + p
        else:
            out += p.capitalize()
    return out

include_guard = "OPENTITAN_TOP_{}_DEVICETABLES_H_".format(top["name"].upper())
%>\

#ifndef ${include_guard}
#define ${include_guard}

#include "dt_api.h" // Generated.

% for header in sorted(dt_headers):
#include "${header}" // Generated.
% endfor

// Number of instances of each module.
enum {
% for module_name in module_types:
<%
    modules = [m for m in top["module"] if m["type"] == module_name]
%>\
  kDt${snake_to_constant_name(module_name)}Count = ${len(modules)},
% endfor
};

% for module_name in module_types:
// Device tables for ${module_name}
extern const dt_${module_name}_t kDt${snake_to_constant_name(module_name)}[kDt${snake_to_constant_name(module_name)}Count];
% endfor

<%
    # List all muxed pads directly from the top.
    pads = [pad["name"] for pad in top['pinout']['pads'] if pad['connection'] == 'muxed']

    # List direct pads from the pinmux to avoid pins which are not relevant.
    for pad in top['pinmux']['ios']:
        if pad['connection'] == 'muxed':
            continue
        name = pad['name']
        if pad['width'] > 1:
            name += str(pad['idx'])
        pads.append(name)
%>\
// List of pads.
typedef enum dt_pad_index_t {
% for pad in pads:
  kDtPad${snake_to_constant_name(pad)},
% endfor
  kDtPadCount,
} dt_pad_index_t;

// Pad descriptions (indexed by dt_pad_index_t)
extern const dt_pad_t kDtPad[kDtPadCount];

#endif  // ${include_guard}
