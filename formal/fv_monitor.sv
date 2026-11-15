// fv_monitor - Property A on bus_security_monitor. Port-level harness: every input (policy,
// transaction, hold) is chosen freely by the solver on every cycle; nothing about the policy is assumed.
module fv_monitor (
    input logic           clk,
    input logic           rst_n,
    input logic [8*80-1:0] rules,
    input logic           hold,
    input logic           txn_valid,
    input logic [3:0]     txn_master,
    input logic [31:0]    txn_addr,
    input logic           txn_write,
    input logic           txn_priv,
    input logic [7:0]     txn_burst
);
`ifdef FV_SBY
  initial assume (!rst_n);      // SymbiYosys: start in reset (scripts/run_formal.py uses -set-at 1 rst_n 0)
`endif
  localparam int N = 8;

  logic txn_ready, dec_valid, dec_allow, dec_violation, dec_rule_hit;
  logic [3:0] dec_reason;
  logic [2:0] dec_rule;
  bus_security_monitor #(.NRULES(N)) dut (.*);

  // Snapshot of what the monitor saw when it accepted the transaction now being reported.
  logic [3:0]      m_q;
  logic [31:0]     a_q;
  logic            w_q, p_q, acc_q;
  logic [7:0]      b_q;
  initial acc_q = 1'b0;
  always @(posedge clk) begin
    acc_q <= rst_n && txn_valid && txn_ready;
    if (txn_valid && txn_ready) begin
      m_q <= txn_master; a_q <= txn_addr; w_q <= txn_write; p_q <= txn_priv; b_q <= txn_burst;
    end
  end

  // Cycle-level protocol of the monitor. The decision function itself (soundness, default deny,
  // completeness) is checked combinationally by formal/monitor_props.svh inside the module.
  always @* if (rst_n) begin
    assert (txn_ready == !hold);                                    // nothing is accepted while held
    assert (dec_valid == acc_q);                                    // one decision per accepted txn, 1 cycle later
    assert (dec_violation == (dec_valid && !dec_allow));
    if (dec_valid && !dec_allow) assert (dec_reason != 4'd0);
    if (dec_valid && dec_allow)  assert (dec_rule_hit && dec_reason == 4'd0);
  end

  // Reachability witnesses (checked by BMC; see scripts/run_formal.py)
  (* keep *) logic fv_cov_grant, fv_cov_deny_known_master;
  initial begin fv_cov_grant = 0; fv_cov_deny_known_master = 0; end
  always @(posedge clk) begin
    fv_cov_grant <= fv_cov_grant | (rst_n && dec_valid && dec_allow);
    fv_cov_deny_known_master <= fv_cov_deny_known_master | (rst_n && dec_valid && !dec_allow && m_q <= 4'd2);
  end
endmodule
