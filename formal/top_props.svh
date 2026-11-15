// top_props.svh - system-level properties on the real security_monitor_top (MODE 2), included in its
// bounded-design generate block under `ifdef FORMAL`. All top-level ports are free.
`ifdef FV_TOP
`include "spec.svh"
  // ENVIRONMENT: an interconnect that registers its outstanding-beat counter, so it learns about a
  // grant one cycle AFTER dec_valid. This is the timing that exposed the bug fixed in d426302; apart
  // from never reporting idle while it knows of outstanding beats, bus_idle is free.
  logic [7:0] fv_acc_burst;
  logic [8:0] fv_beats;
  always @(posedge clk) if (txn_valid && txn_ready) fv_acc_burst <= txn_burst;
  always_ff @(posedge clk or negedge rst_n)
    if (!rst_n)                      fv_beats <= 9'd0;
    else if (dec_valid && dec_allow) fv_beats <= {1'b0, fv_acc_burst};
    else if (fv_beats != 9'd0)       fv_beats <= fv_beats - 9'd1;
  always @* if (fv_beats != 9'd0) assume (!bus_idle);

  always @* if (rst_n) begin
    // D: the bank select never flips while a granted burst is in its data phase (including the
    // grant cycle itself, which the registered interconnect cannot see yet)
    assert (!(swap && (fv_beats != 9'd0 || (dec_valid && dec_allow))));
    if (hold) assert (!txn_ready);
  end
  always @* if (!rst_n)                       // reset: no rule is active, so nothing partial survives
    for (int k = 0; k < NRULES; k++) assert (!act_rules[k*80+79]);

`ifdef FV_E2E
  // End-to-end (bounded): whatever is switched in satisfies the authority specification relative to
  // the policy it replaces. Reverts restore an earlier, already-validated policy and are excluded.
  always @* if (reg_we && reg_addr == A_CMD && reg_wdata[3:0] == C_REVERT) assume (1'b0);
  logic fv_ok_all;
  logic [3:0] fv_pop;
  always @* begin
    fv_ok_all = !vmal && vcand > vact; fv_pop = 4'd0;
    for (int k = 0; k < NRULES; k++) begin
      fv_ok_all &= sp_slot_ok(cand_rules[k*80 +: 80], act_rules[k*80 +: 80], vreq, vroot);
      fv_pop += {3'd0, cand_rules[k*80+79]};
      for (int l = k + 1; l < NRULES; l++) fv_ok_all &= sp_disjoint(cand_rules[k*80 +: 80], cand_rules[l*80 +: 80]);
    end
  end
  always @* if (rst_n && swap) assert (fv_ok_all && fv_pop == vcount);
`endif

  // Reachability witnesses
  (* keep *) logic fv_cov_switch, fv_cov_wait_then_switch, fv_cov_fail_after_switch, fv_waited, fv_switched;
  initial begin fv_cov_switch = 0; fv_cov_wait_then_switch = 0; fv_cov_fail_after_switch = 0; fv_waited = 0; fv_switched = 0; end
  always @(posedge clk) begin
    fv_waited   <= fv_waited | (hold && fv_beats != 9'd0);
    fv_switched <= fv_switched | swap;
    fv_cov_switch            <= fv_cov_switch | (rst_n && swap);
    fv_cov_wait_then_switch  <= fv_cov_wait_then_switch | (rst_n && swap && fv_waited);
    fv_cov_fail_after_switch <= fv_cov_fail_after_switch | (rst_n && fv_switched && vdone && !vok);
  end
`endif
