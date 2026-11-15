// controller_props.svh - Properties C, D, E, F on policy_update_controller (included inside the
// module under `ifdef FORMAL`, so the checks see the controller's own state).
`ifdef FV_CONTROLLER
  logic        fv_pv, fv_rst_p, fv_bi_p, fv_bw_p, fv_rev_p;
  logic [3:0]  fv_st_p, fv_req_p, fv_cnt_p;
  logic [31:0] fv_av_p, fv_prev_p, fv_cv_p;
  initial fv_pv = 1'b0;
  always @(posedge clk) begin
    fv_pv <= 1'b1; fv_rst_p <= rst_n; fv_st_p <= state; fv_bi_p <= bus_idle; fv_bw_p <= boot_window;
    fv_rev_p <= reverting; fv_req_p <= req_owner; fv_cnt_p <= rule_count;
    fv_av_p <= active_version; fv_prev_p <= prev_version; fv_cv_p <= cand_version;
  end

  // "Validated": the validator accepted the staged candidate and nothing has touched it since.
  logic fv_validated;
  always_ff @(posedge clk or negedge rst_n)
    if (!rst_n)                                        fv_validated <= 1'b0;
    else if (bank_we || bank_clear)                    fv_validated <= 1'b0;
    else if (state == S_VALIDATE && val_done && val_ok) fv_validated <= 1'b1;

  always @* if (rst_n) begin
    assert (state <= S_ERROR);
    assert (hold == (state == S_WAIT_IDLE || state == S_SWITCH));            // D: traffic held exactly while switching
    if (bank_we)    assert (state == S_RECEIVE);                              // C: rule writes only while staging
    if (bank_clear) assert (state == S_IDLE || state == S_ERROR);
    if (bank_swap)  assert (state == S_SWITCH && !bank_we && !bank_clear);    // C: swap never coincides with a write
    if (val_start)  assert (state == S_RECEIVE);
    if (reverting)  assert (state == S_WAIT_IDLE || state == S_SWITCH || state == S_ROLLBACK);
    if (state == S_READY) assert (fv_validated);                              // E: only a validated candidate ...
    if ((state == S_WAIT_IDLE || state == S_SWITCH) && !reverting) assert (fv_validated);   // ... can be switched in
    if ((state == S_RECEIVE || state == S_VALIDATE || state == S_READY) && req_owner == OWNER_ROOT)
      assert (boot_window);                                                   // root mode only in the boot window
  end

  always @* if (rst_n && fv_rst_p && fv_pv) begin
    if (state == S_SWITCH) assert (fv_st_p == S_WAIT_IDLE && fv_bi_p);       // D: switch only after an idle bus cycle
    if (active_version != fv_av_p || prev_version != fv_prev_p)
      assert (fv_st_p == S_SWITCH);                                          // E/F: versions change only at a switch
    if (fv_st_p != S_IDLE && fv_st_p != S_ERROR)                              // configuration frozen during an update
      assert (req_owner == fv_req_p && cand_version == fv_cv_p && rule_count == fv_cnt_p);
    if (!fv_bw_p) assert (!boot_window);                                     // the boot window never reopens
  end

`ifdef FV_CONTROLLER_UNIT
  // ENVIRONMENT ASSUMPTION A_val (validator contract, proved as Property B/F in fv_validator):
  // the validator never accepts a candidate whose version is not newer than the active one.
  always @* if (val_done && val_ok) assume (val_cand_version > val_active_version);

  always @* if (rst_n && (state == S_READY || ((state == S_WAIT_IDLE || state == S_SWITCH) && !reverting)))
    assert (cand_version > active_version);
  always @* if (rst_n && fv_rst_p && fv_pv && fv_st_p == S_SWITCH) begin
    if (!fv_rev_p) assert (active_version == fv_cv_p && active_version > fv_av_p);   // F: activation raises the version
    else           assert (active_version == fv_prev_p);                            // revert: back to the previous one
  end

  // Reachability witnesses
  (* keep *) logic fv_cov_activate, fv_cov_reject, fv_cov_wait, fv_cov_revert;
  logic fv_waited;
  initial begin fv_cov_activate = 0; fv_cov_reject = 0; fv_cov_wait = 0; fv_cov_revert = 0; fv_waited = 0; end
  always @(posedge clk) begin
    fv_waited       <= fv_waited | (state == S_WAIT_IDLE && !bus_idle);
    fv_cov_activate <= fv_cov_activate | (rst_n && state == S_COMPLETE);
    fv_cov_reject   <= fv_cov_reject | (rst_n && state == S_ERROR && last_err == E_FOREIGN);
    fv_cov_wait     <= fv_cov_wait | (rst_n && state == S_SWITCH && fv_waited);
    fv_cov_revert   <= fv_cov_revert | (rst_n && state == S_ROLLBACK && reverting);
  end
`endif
`endif
