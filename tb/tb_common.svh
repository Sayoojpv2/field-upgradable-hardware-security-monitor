// tb_common.svh - shared testbench infrastructure (included inside each tb module).
// Stimulus discipline: every input changes 1 ns after a rising edge.
`include "hsm_defs.svh"

  logic        clk = 1'b0, rst_n = 1'b0;
  always #5 clk = ~clk;

  logic        txn_valid = 1'b0, txn_write = 1'b0, txn_priv = 1'b0, bus_idle = 1'b1, reg_we = 1'b0;
  logic [3:0]  txn_master = 4'd0;
  logic [31:0] txn_addr = 32'd0, reg_wdata = 32'd0;
  logic [7:0]  txn_burst = 8'd0, reg_addr = 8'd0;
  wire         txn_ready, dec_valid, dec_allow, dec_violation, dec_rule_hit;
  wire  [3:0]  dec_reason;
  wire  [2:0]  dec_rule;
  wire  [31:0] reg_rdata;

  integer checks = 0, errors = 0, cycle = 0;
  always @(posedge clk) cycle <= cycle + 1;

  task automatic check(input bit cond, input string msg);
    checks++;
    if (!cond) begin errors++; $display("ERROR @%0t (cycle %0d): %s", $time, cycle, msg); end
  endtask

  task automatic tick(input int n = 1);
    repeat (n) @(posedge clk);
    #1;
  endtask

  task automatic do_reset();
    rst_n = 1'b0; txn_valid = 1'b0; reg_we = 1'b0;
    tick(2);
    rst_n = 1'b1;
    tick(1);
  endtask

  // ---- MMIO: one write per cycle, combinational read
  task automatic wr(input [7:0] a, input [31:0] d);
    reg_we = 1'b1; reg_addr = a; reg_wdata = d;
    @(posedge clk); #1;
    reg_we = 1'b0;
  endtask

  task automatic rd(input [7:0] a, output [31:0] d);
    reg_addr = a; #1; d = reg_rdata;
  endtask

  task automatic wait_not_busy(output [31:0] s);
    int n = 0;
    rd(A_STATUS, s);
    while (s[4] && n < 20000) begin tick(); rd(A_STATUS, s); n++; end
    check(!s[4], "timeout waiting for STATUS.busy == 0");
  endtask

  function automatic [3:0] st(input [31:0] s); st = s[3:0]; endfunction

  // ---- Policy image (from tools/policy_generator.py hex): requester, version, count, {slot,start,end,attr}*
  logic [31:0] pw [0:34];

  task automatic read_policy(input string f);
    for (int i = 0; i < 35; i++) pw[i] = 32'd0;
    $readmemh(f, pw);
    if (pw[2] == 0 || pw[2] > 8) begin errors++; $display("ERROR: bad policy image %s", f); end
  endtask

  function automatic [7:0] rule_reg(input [31:0] slot, input int field);
    rule_reg = A_RULE_BASE + 8'(slot * 16) + 8'(field * 4);
  endfunction

  // Write config + BEGIN + rules into the inactive bank (MODE 2)
  task automatic stage_pw();
    wr(A_REQ_OWNER, pw[0]); wr(A_CAND_VERSION, pw[1]); wr(A_RULE_COUNT, pw[2]); wr(A_CMD, {28'd0, C_BEGIN});
    for (int i = 0; i < pw[2] && i < 8; i++) begin
      wr(rule_reg(pw[3+4*i], 0), pw[4+4*i]);
      wr(rule_reg(pw[3+4*i], 1), pw[5+4*i]);
      wr(rule_reg(pw[3+4*i], 2), pw[6+4*i]);
    end
  endtask

  // Full MODE 2 install. exp_err == E_NONE expects success; otherwise the given error and slot.
  task automatic install_pw(input [7:0] exp_err, input [2:0] exp_slot, input string tag);
    logic [31:0] s;
    stage_pw();
    rd(A_STATUS, s);
    if (st(s) == S_RECEIVE) begin wr(A_CMD, {28'd0, C_VALIDATE}); wait_not_busy(s); end
    if (exp_err == E_NONE) begin
      check(st(s) == S_READY, $sformatf("%s: expected READY, state %0d err %0d slot %0d", tag, st(s), s[15:8], s[18:16]));
      wr(A_CMD, {28'd0, C_ACTIVATE}); wait_not_busy(s);
      check(st(s) == S_COMPLETE, $sformatf("%s: expected COMPLETE, state %0d", tag, st(s)));
      wr(A_CMD, {28'd0, C_CONFIRM});
    end else begin
      check(st(s) == S_ERROR && s[15:8] == exp_err && s[18:16] == exp_slot,
            $sformatf("%s: expected error %0d slot %0d, got state %0d err %0d slot %0d", tag, exp_err, exp_slot, st(s), s[15:8], s[18:16]));
      wr(A_CMD, {28'd0, C_ABORT});
    end
  endtask

  // MODE 1 (unbounded baseline): write every rule straight into the live bank, invalidate the rest.
  task automatic direct_pw();
    logic [7:0] present = 8'd0;
    for (int i = 0; i < pw[2] && i < 8; i++) begin
      wr(rule_reg(pw[3+4*i], 0), pw[4+4*i]);
      wr(rule_reg(pw[3+4*i], 1), pw[5+4*i]);
      wr(rule_reg(pw[3+4*i], 2), pw[6+4*i]);
      present[pw[3+4*i]] = 1'b1;
    end
    for (int k = 0; k < NRULES; k++) if (!present[k]) wr(rule_reg(k, 2), 32'd0);
  endtask

  // ---- Transactions: drive, wait until accepted, return the registered decision
  task automatic txn(input [3:0] m, input [31:0] a, input w, input p, input [7:0] b,
                     output logic allow, output logic [3:0] reason, output logic [2:0] rule);
    txn_master = m; txn_addr = a; txn_write = w; txn_priv = p; txn_burst = b; txn_valid = 1'b1;
    while (!txn_ready) tick();
    tick();
    txn_valid = 1'b0;
    check(dec_valid, "dec_valid must follow an accepted transaction by one cycle");
    check(dec_violation == !dec_allow, "dec_violation must equal !dec_allow");
    allow = dec_allow; reason = dec_reason; rule = dec_rule;
  endtask

  task automatic expect_txn(input [3:0] m, input [31:0] a, input w, input p, input [7:0] b,
                            input exp_allow, input [3:0] exp_reason, input string tag);
    logic al; logic [3:0] rs; logic [2:0] ru;
    txn(m, a, w, p, b, al, rs, ru);
    check(al == exp_allow && rs == exp_reason,
          $sformatf("%s: m%0d %s 0x%08h x%0d priv%0d -> allow %0d reason %0d, expected %0d/%0d",
                    tag, m, w ? "W" : "R", a, b, p, al, rs, exp_allow, exp_reason));
  endtask

  task automatic finish(input string name);
    $display("TB_RESULT tb=%s checks=%0d errors=%0d %s", name, checks, errors,
             (errors == 0 && checks > 0) ? "PASS" : "FAIL");
    $finish;
  endtask
