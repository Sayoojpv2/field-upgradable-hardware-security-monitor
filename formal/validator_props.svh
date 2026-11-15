// validator_props.svh - inductive strengthening for policy_validator (included inside the module
// under `ifdef FORMAL`). These invariants describe what the scan has established so far; they are
// themselves checked (assert), not assumed. Valid when the inputs are stable during a run
// (assumption A_stable in fv_validator.sv).
`ifdef FV_VALIDATOR
`include "spec.svh"
  localparam int FV_P = NRULES * (NRULES - 1) / 2;

  logic [NRULES-1:0] fv_slot_ok;
  logic              fv_pre_ok, fv_all_ok, fv_pairs_before_ok, fv_all_pairs_ok;
  logic [3:0]        fv_pre_cnt, fv_all_cnt;
  always @* begin
    fv_pre_ok = 1'b1; fv_all_ok = 1'b1; fv_pre_cnt = 4'd0; fv_all_cnt = 4'd0;
    fv_pairs_before_ok = 1'b1; fv_all_pairs_ok = 1'b1;
    for (int k = 0; k < NRULES; k++) begin
      fv_slot_ok[k] = sp_slot_ok(cand_rules[k*80 +: 80], act_rules[k*80 +: 80], req_owner, root_mode);
      if (k < i) begin fv_pre_ok &= fv_slot_ok[k]; fv_pre_cnt += {3'd0, cand_rules[k*80+79]}; end
      fv_all_ok &= fv_slot_ok[k];
      fv_all_cnt += {3'd0, cand_rules[k*80+79]};
      for (int l = k + 1; l < NRULES; l++) begin
        if (k < i || (k == i && l < j)) fv_pairs_before_ok &= sp_disjoint(cand_rules[k*80 +: 80], cand_rules[l*80 +: 80]);
        fv_all_pairs_ok &= sp_disjoint(cand_rules[k*80 +: 80], cand_rules[l*80 +: 80]);
      end
    end
  end

  // Cycles since start (exact latency of an accepted validation).
  logic [7:0] fv_cyc;
  always_ff @(posedge clk or negedge rst_n)
    if (!rst_n)              fv_cyc <= 8'd0;
    else if (st == VS_IDLE)  fv_cyc <= start ? 8'd1 : 8'd0;
    else                     fv_cyc <= fv_cyc + 8'd1;

  function automatic int fv_pidx(input logic [2:0] a, input logic [2:0] b);
    fv_pidx = a * NRULES - (a * (a + 1)) / 2 + (b - a - 1);
  endfunction

  wire fv_hdr_passed = !malformed && cand_version > active_version;

  always @* if (rst_n) begin
    assert (st <= VS_FINAL);
    if (st != VS_IDLE) assert (!done && !ok && err_code == E_NONE);
    if (st == VS_HDR)  assert (i == 0 && j == 0 && cnt == 0 && fv_cyc == 8'd1);
    if (st == VS_SLOT) assert (i < NRULES && j == 0 && fv_hdr_passed && fv_pre_ok && cnt == fv_pre_cnt &&
                               fv_cyc == 8'd2 + i);
    if (st == VS_PAIR) assert (i < j && j < NRULES && fv_hdr_passed && fv_all_ok && cnt == fv_all_cnt &&
                               fv_pairs_before_ok && fv_cyc == 8'(2 + NRULES + fv_pidx(i, j)));
    if (st == VS_FINAL) assert (fv_hdr_passed && fv_all_ok && cnt == fv_all_cnt && fv_all_pairs_ok &&
                                fv_cyc == 8'(2 + NRULES + FV_P));
  end
`endif
