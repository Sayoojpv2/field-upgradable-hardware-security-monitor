`timescale 1ns/1ps
// policy_bank - two rule banks and the single bank-select bit that activates a policy.
// DUAL=1: writes always target the INACTIVE bank (there is no write path to the active one).
// DUAL=0: one live bank written directly (used only for the unbounded baseline design).
module policy_bank #(
    parameter int NRULES = 8,
    parameter int DUAL   = 1
) (
    input  logic                 clk,
    input  logic                 rst_n,
    input  logic                 swap,             // 1-cycle pulse: flip the active bank
    input  logic                 clear_inactive,   // invalidate every slot of the write bank
    input  logic                 we,
    input  logic [2:0]           widx,
    input  logic [1:0]           wfield,           // 0 start, 1 end, 2 attr
    input  logic [31:0]          wdata,
    output logic                 active_sel,
    output logic [NRULES*80-1:0] active_rules,
    output logic [NRULES*80-1:0] inactive_rules
);
`include "hsm_defs.svh"
  localparam int PW = 79;                          // payload = rule[78:0]

  logic                     sel;
  logic [2*NRULES-1:0]      v;                     // valid bits, bank b slot k at [b*NRULES+k]
  logic [2*NRULES*PW-1:0]   p;                     // payloads (owner,start,end,attr)
  wire                      wbank = (DUAL != 0) ? ~sel : 1'b0;

  assign active_sel = sel;

  always_ff @(posedge clk or negedge rst_n)
    if (!rst_n)                       sel <= 1'b0;
    else if (swap && DUAL != 0)       sel <= ~sel;

  // Valid bits are the only bank state that needs reset: an invalid slot never matches.
  always_ff @(posedge clk or negedge rst_n)
    if (!rst_n) v <= '0;
    else
      for (int b = 0; b < 2; b++)
        for (int k = 0; k < NRULES; k++)
          if (wbank == b) begin
            if (clear_inactive)                        v[b*NRULES+k] <= 1'b0;
            else if (we && wfield == 2'd2 && widx == k) v[b*NRULES+k] <= wdata[31];
          end

  always_ff @(posedge clk)
    for (int b = 0; b < 2; b++)
      for (int k = 0; k < NRULES; k++)
        if (we && wbank == b && widx == k)
          case (wfield)
            2'd0: p[(b*NRULES+k)*PW + 43 +: 32] <= wdata;
            2'd1: p[(b*NRULES+k)*PW + 11 +: 32] <= wdata;
            2'd2: begin
                    p[(b*NRULES+k)*PW + 75 +: 4]  <= wdata[19:16];
                    p[(b*NRULES+k)*PW      +: 11] <= wdata[10:0];
                  end
            default: ;
          endcase

  always_comb
    for (int k = 0; k < NRULES; k++) begin
      active_rules[k*80 +: 80]   = sel ? {v[NRULES+k], p[(NRULES+k)*PW +: PW]} : {v[k], p[k*PW +: PW]};
      inactive_rules[k*80 +: 80] = sel ? {v[k], p[k*PW +: PW]} : {v[NRULES+k], p[(NRULES+k)*PW +: PW]};
    end

endmodule
