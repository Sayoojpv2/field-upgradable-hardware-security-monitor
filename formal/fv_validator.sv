`ifndef FV_NR
`define FV_NR 8
`endif
// fv_validator - Property B (bounded policy authority) and version monotonicity on policy_validator,
// with all 8 rule slots. Candidate bank, active bank, requester, versions, count and the malformed
// flag are chosen freely by the solver.
module fv_validator (
    input logic            clk,
    input logic            rst_n,
    input logic            start,
    input logic [`FV_NR*80-1:0] cand,
    input logic [`FV_NR*80-1:0] act,
    input logic [3:0]      req,
    input logic            root,
    input logic [31:0]     cv,
    input logic [31:0]     av,
    input logic [3:0]      dc,
    input logic            mal
);
`ifdef FV_SBY
  initial assume (!rst_n);      // SymbiYosys: start in reset (scripts/run_formal.py uses -set-at 1 rst_n 0)
`endif
`include "spec.svh"
  localparam int N = `FV_NR;

  logic busy, done, ok;
  logic [7:0] err;
  logic [2:0] eslot;
  policy_validator #(.NRULES(N)) dut (
    .clk(clk), .rst_n(rst_n), .start(start), .cand_rules(cand), .act_rules(act), .req_owner(req),
    .root_mode(root), .cand_version(cv), .active_version(av), .declared_count(dc), .malformed(mal),
    .busy(busy), .done(done), .ok(ok), .err_code(err), .err_slot(eslot));

  // ENVIRONMENT ASSUMPTION A_stable: the inputs do not change while the validator is working or
  // reporting. Discharged for the real design by fv_controller (no bank write, clear, swap or
  // configuration change in VALIDATE) and fv_bank (bank contents change only through those).
  logic [N*80-1:0] cand_p, act_p;
  logic [3:0]      req_p, dc_p;
  logic            root_p, mal_p, pv;
  logic [31:0]     cv_p, av_p;
  initial pv = 1'b0;
  always @(posedge clk) begin
    pv <= 1'b1;
    cand_p <= cand; act_p <= act; req_p <= req; dc_p <= dc; root_p <= root; mal_p <= mal; cv_p <= cv; av_p <= av;
  end
  always @* if (pv && (busy || done))
    assume (cand == cand_p && act == act_p && req == req_p && dc == dc_p && root == root_p && mal == mal_p &&
            cv == cv_p && av == av_p);

  // Specification of an acceptable candidate (formal/spec.svh).
  logic slots_ok, pairs_ok, spec_ok, first_bad_ok, earlier_overlap;
  logic [3:0] pop;
  always @* begin
    slots_ok = 1'b1; pairs_ok = 1'b1; pop = 4'd0; first_bad_ok = 1'b1; earlier_overlap = 1'b0;
    for (int k = 0; k < N; k++) begin
      slots_ok &= sp_slot_ok(cand[k*80 +: 80], act[k*80 +: 80], req, root);
      pop += {3'd0, cand[k*80+79]};
      if (k < eslot) first_bad_ok &= sp_slot_ok(cand[k*80 +: 80], act[k*80 +: 80], req, root);
      if (k < eslot) earlier_overlap |= !sp_disjoint(cand[k*80 +: 80], cand[eslot*80 +: 80]);
      for (int l = k + 1; l < N; l++) pairs_ok &= sp_disjoint(cand[k*80 +: 80], cand[l*80 +: 80]);
    end
    spec_ok = !mal && cv > av && slots_ok && pairs_ok && pop == dc;
  end

  always @* if (rst_n) begin
    if (busy) assert (!done && !ok);
    if (done) begin
      assert (ok == spec_ok);                 // B + F: accepted <=> within authority, well-formed, newer version
      assert (ok == (err == 8'd0));
`ifdef FV_DIAG
      // Diagnosis: a per-slot error names the first offending slot; an overlap names a slot that
      // overlaps an earlier one.
      if (err >= 8'd4 && err <= 8'd10)
        assert (!sp_slot_ok(cand[eslot*80 +: 80], act[eslot*80 +: 80], req, root) && first_bad_ok);
      if (err == 8'd11) assert (earlier_overlap);
`endif
    end
  end

  // Reachability witnesses
  (* keep *) logic fv_cov_accept, fv_cov_reject_foreign, fv_cov_reject_escape, fv_cov_last_slot;
  initial begin fv_cov_accept = 0; fv_cov_reject_foreign = 0; fv_cov_reject_escape = 0; fv_cov_last_slot = 0; end
  always @(posedge clk) begin
    fv_cov_accept         <= fv_cov_accept | (rst_n && done && ok && !root && cand[(N-1)*80+79]);   // last slot used
    fv_cov_reject_foreign <= fv_cov_reject_foreign | (rst_n && done && err == 8'd10);
    fv_cov_reject_escape  <= fv_cov_reject_escape | (rst_n && done && err == 8'd6);
    fv_cov_last_slot      <= fv_cov_last_slot | (rst_n && done && err == 8'd11 && eslot == 3'(N-1));
  end
endmodule
