// monitor_props.svh - Property A on the decision function of bus_security_monitor.
// Included inside the module under `ifdef FORMAL` (Yosys has no `bind`), so the checks see the
// same input signals the RTL uses. The decision computed here is registered unchanged into
// dec_allow/dec_reason/dec_rule; that register-level protocol is checked by formal/fv_monitor.sv.
`ifdef FV_MONITOR
`include "spec.svh"
  logic fv_any_permit, fv_lower_hit;
  logic fv_ok;
  assign fv_ok = (reason == V_OK);
  always @* begin
    fv_any_permit = 1'b0; fv_lower_hit = 1'b0;
    for (int k = 0; k < NRULES; k++) begin
      fv_any_permit |= sp_permits(rules[k*80 +: 80], txn_master, txn_addr, txn_write, txn_priv, txn_burst);
      if (k < idx)
        fv_lower_hit |= rules[k*80+79] && rules[k*80+75 +: 4] == txn_master &&
                        txn_addr >= rules[k*80+43 +: 32] && txn_addr <= rules[k*80+11 +: 32];
    end
  end
  always @* begin
`ifdef FV_A_SOUND
    if (fv_ok) assert (found && sp_permits(sel, txn_master, txn_addr, txn_write, txn_priv, txn_burst)); // grant => permitted
    if (fv_ok) assert (!fv_lower_hit);                                // ... by the lowest matching slot
`endif
`ifdef FV_A_DENY
    if (txn_master > 4'd2) assert (!fv_ok);                           // unknown masters: default deny
    if (!fv_any_permit)    assert (!fv_ok);                           // nothing permits it: default deny
`endif
`ifdef FV_A_PRIORITY
    // Completeness, RTL part 1 (R1): the RTL's match is exactly the specification's, and the lowest
    // matching slot is the one selected. (Specification lemmas G1/G2 are in fv_spec.sv.)
    assert (found == (|hit));
    for (int k = 0; k < NRULES; k++) begin
      assert (hit[k] == sp_hit(rules[k*80 +: 80], txn_master, txn_addr));
      if (hit[k] && (hit & ((NRULES'(1) << k) - NRULES'(1))) == '0) assert (idx == k);
    end
`endif
`ifdef FV_A_GRANT
    // Completeness, RTL part 2 (R2): once a permitting rule is selected, the decision is a grant.
    if (found && sp_permits(sel, txn_master, txn_addr, txn_write, txn_priv, txn_burst)) assert (fv_ok);
`endif
  end
`endif
