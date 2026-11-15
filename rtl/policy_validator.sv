`timescale 1ns/1ps
// policy_validator - bounded-authority check of the candidate (inactive) bank before activation.
// Multi-cycle FSM, data-independent schedule for accepted policies:
//   HDR (1) -> SLOT (NRULES, one slot per cycle) -> PAIR (NRULES*(NRULES-1)/2 overlap pairs) -> FINAL (1)
// Stops at the first violation and reports its code and slot.
module policy_validator #(
    parameter int NRULES = 8
) (
    input  logic                 clk,
    input  logic                 rst_n,
    input  logic                 start,
    input  logic [NRULES*80-1:0] cand_rules,      // inactive bank (candidate)
    input  logic [NRULES*80-1:0] act_rules,       // active bank (committed)
    input  logic [3:0]           req_owner,       // authenticated requester (latched by controller)
    input  logic                 root_mode,       // boot restore: no active policy to protect yet
    input  logic [31:0]          cand_version,
    input  logic [31:0]          active_version,
    input  logic [3:0]           declared_count,
    input  logic                 malformed,       // controller saw a malformed rule write
    output logic                 busy,
    output logic                 done,            // 1-cycle pulse
    output logic                 ok,
    output logic [7:0]           err_code,
    output logic [2:0]           err_slot
);
`include "hsm_defs.svh"
  localparam logic [2:0] VS_IDLE = 3'd0, VS_HDR = 3'd1, VS_SLOT = 3'd2, VS_PAIR = 3'd3, VS_FINAL = 3'd4;

  logic [2:0] st, i, j;
  logic [3:0] cnt;
  assign busy = (st != VS_IDLE);

  // Read ports: candidate slot i and j, active slot i (indexed part-selects -> mux trees;
  // 14% fewer generic cells than one-hot AND-OR selection, see docs/EXPERIMENTS.md).
  logic [79:0] ci, cj, ai;
  assign ci = cand_rules[i*80 +: 80];
  assign cj = cand_rules[j*80 +: 80];
  assign ai = act_rules[i*80 +: 80];

  // Per-slot checks for slot i.
  wire [3:0] o = r_owner(ci);
  // Ownership: a slot that holds (or would hold) another owner's rule must be bit-identical.
  wire foreign = !root_mode && ((r_valid(ai) && r_owner(ai) != req_owner) ||
                                (r_valid(ci) && r_owner(ci) != req_owner));
  wire same    = r_valid(ai) && r_valid(ci) && (ai == ci);

  logic [7:0] slot_err;
  always_comb begin
    slot_err = E_NONE;
    if (foreign && !same)                                     slot_err = E_FOREIGN;
    else if (r_valid(ci)) begin
      if (o >= NUM_OWNERS)                                    slot_err = E_OWNER_ID;
      else if (r_burst(ci) == 8'd0)                           slot_err = E_MALFORMED;
      else if (r_start(ci) > r_end(ci))                       slot_err = E_RANGE;
      else if (r_start(ci) < env_lo(o) || r_end(ci) > env_hi(o)) slot_err = E_ADDR_ESCAPE;
      else if ((r_rd(ci) && !env_r(o)) || (r_wr(ci) && !env_w(o))) slot_err = E_PERM_ESC;
      else if (env_pf(o) && !r_priv(ci))                      slot_err = E_PRIV_FLOOR;
      else if (r_burst(ci) > env_burst(o))                    slot_err = E_BURST_ESC;
    end
  end

  wire overlap = r_valid(ci) && r_valid(cj) && r_start(ci) <= r_end(cj) && r_start(cj) <= r_end(ci);

  always_ff @(posedge clk or negedge rst_n)
    if (!rst_n) begin
      st <= VS_IDLE; i <= 3'd0; j <= 3'd0; cnt <= 4'd0;
      done <= 1'b0; ok <= 1'b0; err_code <= E_NONE; err_slot <= 3'd0;
    end else begin
      done <= 1'b0;
      case (st)
        VS_IDLE:
          if (start) begin
            st <= VS_HDR; i <= 3'd0; j <= 3'd0; cnt <= 4'd0;
            ok <= 1'b0; err_code <= E_NONE; err_slot <= 3'd0;
          end
        VS_HDR:
          if (malformed)                          begin done <= 1'b1; st <= VS_IDLE; err_code <= E_MALFORMED; end
          else if (cand_version <= active_version) begin done <= 1'b1; st <= VS_IDLE; err_code <= E_VERSION; end
          else                                         st <= VS_SLOT;
        VS_SLOT:
          if (slot_err != E_NONE) begin
            done <= 1'b1; st <= VS_IDLE; err_code <= slot_err; err_slot <= i;
          end else begin
            cnt <= cnt + {3'd0, r_valid(ci)};
            if (i == NRULES - 1) begin i <= 3'd0; j <= 3'd1; st <= VS_PAIR; end
            else                       i <= i + 3'd1;
          end
        VS_PAIR:
          if (overlap) begin
            done <= 1'b1; st <= VS_IDLE; err_code <= E_OVERLAP; err_slot <= j;
          end else if (j == NRULES - 1) begin
            if (i == NRULES - 2) st <= VS_FINAL;
            else begin i <= i + 3'd1; j <= i + 3'd2; end
          end else j <= j + 3'd1;
        VS_FINAL: begin
          done <= 1'b1; st <= VS_IDLE;
          if (cnt != declared_count) err_code <= E_COUNT;
          else                       ok <= 1'b1;
        end
        default: st <= VS_IDLE;
      endcase
    end

`ifdef FORMAL
`include "validator_props.svh"
`endif

endmodule
