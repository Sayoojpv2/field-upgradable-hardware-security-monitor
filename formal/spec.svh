// spec.svh - executable specification used by the formal harnesses.
// Written from docs/RESEARCH_AND_DESIGN.md sections 5 and 6 (rule layout, authority envelopes,
// decision rules). It deliberately does NOT use rtl/hsm_defs.svh, so a mistake there cannot make
// the RTL and the specification agree with each other.
//
// Rule word: [79] valid | [78:75] owner | [74:43] start | [42:11] end (inclusive)
//            [10] privilege required | [9] write | [8] read | [7:0] max burst (beats of 4 bytes)

// A rule lies inside its owner's immutable authority envelope and is structurally sane.
function automatic bit sp_env_ok(input logic [79:0] r);
  logic [31:0] lo, hi;
  logic        may_r, may_w, floor_priv, known;
  logic [7:0]  max_b;
  known = 1'b1; lo = 32'd0; hi = 32'd0; may_r = 1'b0; may_w = 1'b0; floor_priv = 1'b0; max_b = 8'd0;
  case (r[78:75])
    4'd0:    begin lo = 32'h0000_0000; hi = 32'h0000_FFFF; may_r = 1; may_w = 1; max_b = 8'd16; end  // CPU
    4'd1:    begin lo = 32'h1000_0000; hi = 32'h1000_FFFF; may_r = 1; may_w = 1; max_b = 8'd64; end  // DMA
    4'd2:    begin lo = 32'h2000_0000; hi = 32'h2000_FFFF; may_r = 1; floor_priv = 1; max_b = 8'd4; end // DIAG
    default: known = 1'b0;
  endcase
  sp_env_ok = known && r[7:0] != 8'd0 && r[74:43] <= r[42:11] && r[74:43] >= lo && r[42:11] <= hi &&
              (!r[8] || may_r) && (!r[9] || may_w) && (!floor_priv || r[10]) && r[7:0] <= max_b;
endfunction

// Ownership: a slot that holds, or would hold, another owner's rule must be left exactly as it is.
// At boot (root) there is no committed policy to protect, so only the envelope applies.
function automatic bit sp_slot_ok(input logic [79:0] c, input logic [79:0] a, input logic [3:0] req,
                                  input logic root);
  logic foreign;
  foreign = !root && ((a[79] && a[78:75] != req) || (c[79] && c[78:75] != req));
  sp_slot_ok = (!foreign || (a[79] && c[79] && a == c)) && (!c[79] || sp_env_ok(c));
endfunction

// Two valid rules must not overlap (inclusive ranges).
function automatic bit sp_disjoint(input logic [79:0] x, input logic [79:0] y);
  sp_disjoint = !(x[79] && y[79]) || x[42:11] < y[74:43] || y[42:11] < x[74:43];
endfunction

// A rule covers the transaction's start address for this master (the monitor's "match").
function automatic bit sp_hit(input logic [79:0] r, input logic [3:0] m, input logic [31:0] a);
  sp_hit = r[79] && r[78:75] == m && a >= r[74:43] && a <= r[42:11];
endfunction

// A rule permits a transaction (master m, start address a, write w, privileged p, burst b beats).
function automatic bit sp_permits(input logic [79:0] r, input logic [3:0] m, input logic [31:0] a,
                                  input logic w, input logic p, input logic [7:0] b);
  logic [32:0] last;
  last = {1'b0, a} + {23'd0, b, 2'b00} - 33'd1;          // last byte touched; bit 32 = wrap
  sp_permits = r[79] && r[78:75] == m && m <= 4'd2 && a >= r[74:43] && !last[32] && last[31:0] <= r[42:11] &&
               (w ? r[9] : r[8]) && (!r[10] || p) && b != 8'd0 && b <= r[7:0];
endfunction
