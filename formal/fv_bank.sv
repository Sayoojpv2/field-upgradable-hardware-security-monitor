// fv_bank - Property C on policy_bank (dual-bank mode, 8 slots): the active bank cannot be written.
module fv_bank (
    input logic        clk,
    input logic        rst_n,
    input logic        swap,
    input logic        clear_inactive,
    input logic        we,
    input logic [2:0]  widx,
    input logic [1:0]  wfield,
    input logic [31:0] wdata
);
`ifdef FV_SBY
  initial assume (!rst_n);      // SymbiYosys: start in reset (scripts/run_formal.py uses -set-at 1 rst_n 0)
`endif
  localparam int N = 8;
  logic            active_sel;
  logic [N*80-1:0] active_rules, inactive_rules;
  policy_bank #(.NRULES(N), .DUAL(1)) dut (.*);

  // ENVIRONMENT ASSUMPTION A_ctrl: the controller never swaps in a cycle that also writes or clears
  // (proved in fv_controller: bank_swap -> !bank_we && !bank_clear).
  always @* assume (!(swap && (we || clear_inactive)));

  logic            pv, swap_p, rst_p, we_p, sel_p;
  logic [N*80-1:0] act_p, inact_p;
  logic [2:0]      widx_p;
  logic [1:0]      wf_p;
  logic [31:0]     wd_p;
  initial pv = 1'b0;
  always @(posedge clk) begin
    pv <= 1'b1; rst_p <= rst_n; swap_p <= swap; we_p <= we; sel_p <= active_sel;
    act_p <= active_rules; inact_p <= inactive_rules; widx_p <= widx; wf_p <= wfield; wd_p <= wdata;
  end

  always @* if (rst_n && rst_p && pv) begin
    if (!swap_p) assert (active_rules == act_p && active_sel == sel_p);   // C: only a swap changes the active policy
    else         assert (active_rules == inact_p && active_sel != sel_p); // a swap installs exactly the staged bank
    if (we_p && wf_p == 2'd0) assert (inactive_rules[widx_p*80+43 +: 32] == wd_p);   // writes land in the inactive bank
  end
  always @* if (!rst_n)                                                    // reset: no rule of either bank is valid
    for (int k = 0; k < N; k++) assert (!active_rules[k*80+79] && !inactive_rules[k*80+79]);
endmodule
