`timescale 1ns/1ps
// bus_security_monitor - per-transaction access check against the ACTIVE policy bank.
// One decision per accepted transaction, registered one cycle later. The datapath contains
// no update logic: it only sees the active bank and a `hold` (quiesce) input.
module bus_security_monitor #(
    parameter int NRULES = 8
) (
    input  logic                 clk,
    input  logic                 rst_n,
    input  logic [NRULES*80-1:0] rules,        // active bank, slot k at [k*80 +: 80]
    input  logic                 hold,         // update controller is switching banks
    input  logic                 txn_valid,
    output logic                 txn_ready,
    input  logic [3:0]           txn_master,
    input  logic [31:0]          txn_addr,
    input  logic                 txn_write,
    input  logic                 txn_priv,
    input  logic [7:0]           txn_burst,    // beats of 4 bytes, 1..255 (0 is malformed)
    output logic                 dec_valid,
    output logic                 dec_allow,
    output logic                 dec_violation,
    output logic [3:0]           dec_reason,
    output logic [2:0]           dec_rule,     // matched slot (valid when dec_rule_hit)
    output logic                 dec_rule_hit
);
`include "hsm_defs.svh"

  assign txn_ready = !hold;
  wire accept = txn_valid && txn_ready;

  // 1) Match: a rule covers the transaction if owner == master and start address is in range.
  logic [NRULES-1:0] hit;
  always_comb
    for (int k = 0; k < NRULES; k++)
      hit[k] = r_valid(rules[k*RULE_W +: RULE_W]) &&
               r_owner(rules[k*RULE_W +: RULE_W]) == txn_master &&
               txn_addr >= r_start(rules[k*RULE_W +: RULE_W]) &&
               txn_addr <= r_end(rules[k*RULE_W +: RULE_W]);

  // 2) Deterministic order: lowest slot index wins. (Validated policies never overlap,
  //    so at most one rule can hit; the order matters only for the unbounded baseline.)
  logic        found;
  logic [2:0]  idx;
  logic [79:0] sel;
  always_comb begin
    found = 1'b0; idx = 3'd0;
    for (int k = NRULES - 1; k >= 0; k--)
      if (hit[k]) begin found = 1'b1; idx = k; end
  end
  assign sel = rules[idx*RULE_W +: RULE_W];

  // 3) Last byte touched by the burst; bit 32 catches address wrap-around.
  wire [32:0] last = {1'b0, txn_addr} + {23'd0, txn_burst, 2'b00} - 33'd1;

  // 4) Default deny; first failing check gives the reason.
  logic [3:0] reason;
  always_comb begin
    if (txn_master >= NUM_OWNERS)                          reason = V_BAD_MASTER;
    else if (!found)                                       reason = V_NO_RULE;
    else if (!txn_write && !r_rd(sel))                     reason = V_READ_DENIED;
    else if ( txn_write && !r_wr(sel))                     reason = V_WRITE_DENIED;
    else if (r_priv(sel) && !txn_priv)                     reason = V_PRIV;
    else if (txn_burst == 8'd0 || txn_burst > r_burst(sel)) reason = V_BURST;
    else if (last[32] || last[31:0] > r_end(sel))          reason = V_SPAN;
    else                                                   reason = V_OK;
  end

  always_ff @(posedge clk or negedge rst_n)
    if (!rst_n) begin
      dec_valid <= 1'b0; dec_allow <= 1'b0; dec_reason <= V_OK; dec_rule <= 3'd0; dec_rule_hit <= 1'b0;
    end else begin
      dec_valid <= accept;
      if (accept) begin
        dec_allow    <= (reason == V_OK);
        dec_reason   <= reason;
        dec_rule     <= idx;
        dec_rule_hit <= found;
      end
    end

  assign dec_violation = dec_valid && !dec_allow;

endmodule
