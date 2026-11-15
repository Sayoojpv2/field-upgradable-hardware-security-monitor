// tb_security_monitor - transaction datapath tests, trace replay, and update-under-traffic runs.
//   (no plusargs)                      directed datapath tests for the selected MODE
//   +policy=P.hex +vectors=V.hex [+check] [+out=F]   replay a trace; +check compares with the
//                                       Python reference decisions in V.hex
//   +policy=P.hex +attack=A.hex +vectors=V.hex +out=F   try to install attack image A on top of P
//                                       (real requester), report whether it took effect, then replay
//   +policy=OLD.hex +transient=NEW.hex +vectors=V.hex +out=F [+runs=N]
//                                       stream one transaction per cycle while updating OLD -> NEW
`timescale 1ns/1ps
module tb_security_monitor;
  parameter int MODE   = 2;
  parameter int NRULES = 8;
`include "tb_common.svh"

  security_monitor_top #(.NRULES(NRULES), .MODE(MODE)) dut (.*);

  localparam int MAXV = 1024;
  logic [3:0]  vm [MAXV];
  logic [31:0] va [MAXV];
  logic        vw [MAXV], vp [MAXV], ve [MAXV];
  logic [7:0]  vb [MAXV];
  logic [3:0]  vr [MAXV];
  int nv = 0;

  task automatic read_vectors(input string f);
    int fd, r;
    logic [31:0] m, a, w, p, b, e, rr;
    fd = $fopen(f, "r");
    if (fd == 0) begin errors++; $display("ERROR: cannot open %s", f); end  // no `return`: Icarus 12 rejects it in tasks
    else begin
      r = $fscanf(fd, "%h\n", nv);
      for (int i = 0; i < nv && i < MAXV; i++) begin
        r = $fscanf(fd, "%h %h %h %h %h %h %h\n", m, a, w, p, b, e, rr);
        vm[i] = m[3:0]; va[i] = a; vw[i] = w[0]; vp[i] = p[0]; vb[i] = b[7:0]; ve[i] = e[0]; vr[i] = rr[3:0];
      end
      $fclose(fd);
    end
  endtask

  task automatic apply_policy();
    if (MODE == 2) begin pw[0] = {28'd0, OWNER_ROOT}; install_pw(E_NONE, 0, "boot restore"); end
    else if (MODE == 1) direct_pw();
  endtask

  // ------------------------------------------------------------------------------------------
  task automatic directed_mode2();
    logic al; logic [3:0] rs; logic [2:0] ru; logic [31:0] s;
    // Empty banks after reset: default deny for everything.
    expect_txn(0, 32'h0000_1000, 0, 1, 1, 0, V_NO_RULE, "reset default-deny");
    expect_txn(1, 32'h1000_0000, 1, 0, 1, 0, V_NO_RULE, "reset default-deny");
    // Directed test policy (boot restore)
    pw[0] = OWNER_ROOT; pw[1] = 1; pw[2] = 4;
    pw[3]  = 0; pw[4]  = 32'h0000_1000; pw[5]  = 32'h0000_1FFF; pw[6]  = 32'h8000_0104;  // CPU R      burst 4
    pw[7]  = 1; pw[8]  = 32'h0000_2000; pw[9]  = 32'h0000_2FFF; pw[10] = 32'h8000_0708;  // CPU RW priv burst 8
    pw[11] = 2; pw[12] = 32'h1000_0000; pw[13] = 32'h1000_00FF; pw[14] = 32'h8001_0210;  // DMA W      burst 16
    pw[15] = 3; pw[16] = 32'h2000_0000; pw[17] = 32'h2000_0FFF; pw[18] = 32'h8002_0504;  // DIAG R priv burst 4
    install_pw(E_NONE, 0, "directed policy");

    txn(0, 32'h0000_1000, 0, 0, 1, al, rs, ru);
    check(al && rs == V_OK && ru == 0 && dec_rule_hit, "valid read accepted by slot 0");
    expect_txn(0, 32'h0000_1000, 1, 0, 1, 0, V_WRITE_DENIED, "write to read-only rule");
    expect_txn(0, 32'h0000_2000, 0, 0, 1, 0, V_PRIV,         "unprivileged access to privileged rule");
    txn(0, 32'h0000_2000, 1, 1, 8, al, rs, ru);
    check(al && ru == 1, "privileged max-burst write accepted by slot 1");
    expect_txn(0, 32'h0000_2000, 0, 1, 9, 0, V_BURST,        "burst above rule maximum");
    expect_txn(0, 32'h0000_2000, 0, 1, 0, 0, V_BURST,        "zero-length burst");
    expect_txn(0, 32'h0000_1FF8, 0, 0, 2, 1, V_OK,           "burst ending on last byte");
    expect_txn(0, 32'h0000_1FF8, 0, 0, 3, 0, V_SPAN,         "burst crossing rule end");
    expect_txn(1, 32'h1000_0000, 0, 0, 1, 0, V_READ_DENIED,  "read on write-only rule");
    expect_txn(1, 32'h1000_00C0, 1, 0, 16, 1, V_OK,          "DMA max burst to region end");
    expect_txn(1, 32'h1000_00C4, 1, 0, 16, 0, V_SPAN,        "DMA burst leaving region");
    expect_txn(0, 32'h0000_0FFC, 0, 1, 1, 0, V_NO_RULE,      "address below every rule");
    expect_txn(0, 32'h0000_3000, 0, 1, 1, 0, V_NO_RULE,      "address above every rule");
    expect_txn(1, 32'h0000_1000, 0, 1, 1, 0, V_NO_RULE,      "other owner's region");
    expect_txn(3, 32'h0000_1000, 0, 1, 1, 0, V_BAD_MASTER,   "unknown master 3");
    expect_txn(15, 32'h0000_1000, 0, 1, 1, 0, V_BAD_MASTER,  "unknown master 15");
    expect_txn(2, 32'h2000_0FF0, 0, 1, 4, 1, V_OK,           "diagnostics privileged read");
    expect_txn(2, 32'h2000_0000, 1, 1, 1, 0, V_WRITE_DENIED, "diagnostics write");

    // Throughput: three back-to-back transactions -> three decisions on consecutive cycles.
    txn_master = 0; txn_addr = 32'h0000_1000; txn_write = 0; txn_priv = 0; txn_burst = 1; txn_valid = 1;
    tick(); check(dec_valid && dec_allow, "pipelined txn 1");
    txn_addr = 32'h0000_1004; txn_write = 1;
    tick(); check(dec_valid && !dec_allow && dec_reason == V_WRITE_DENIED, "pipelined txn 2");
    txn_addr = 32'h0000_2004; txn_write = 0; txn_priv = 1;
    tick(); check(dec_valid && dec_allow && dec_rule == 1, "pipelined txn 3");
    txn_valid = 0;
    tick(); check(!dec_valid, "dec_valid drops when no transaction");
    rd(A_ACTIVE_VERSION, s); check(s == 1, "active version 1");
  endtask

  task automatic directed_mode1();
    // Unbounded baseline: rules land in the live bank immediately; overlapping rules resolve
    // to the lowest slot; a rule may even reach the top of the address space.
    expect_txn(0, 32'h0000_1000, 0, 0, 1, 0, V_NO_RULE, "baseline reset default-deny");
    wr(rule_reg(3, 0), 32'h0000_0000); wr(rule_reg(3, 1), 32'hFFFF_FFFF); wr(rule_reg(3, 2), 32'h8000_0310);
    expect_txn(0, 32'h0000_1000, 1, 0, 1, 1, V_OK, "live write takes effect immediately");
    wr(rule_reg(1, 0), 32'h0000_1000); wr(rule_reg(1, 1), 32'h0000_1FFF); wr(rule_reg(1, 2), 32'h8000_0110);
    expect_txn(0, 32'h0000_1000, 1, 0, 1, 0, V_WRITE_DENIED, "lowest slot wins on overlap");
    expect_txn(0, 32'hFFFF_FFF8, 0, 0, 2, 1, V_OK, "burst ending at 0xFFFFFFFF");
    expect_txn(0, 32'hFFFF_FFFC, 0, 0, 2, 0, V_SPAN, "burst wrapping past 0xFFFFFFFF");
    expect_txn(1, 32'h0000_1000, 0, 0, 1, 0, V_NO_RULE, "other master");
  endtask

  task automatic directed_mode0();
    // Static monitor with the factory policy (v1) compiled in.
    expect_txn(0, 32'h0000_F000, 1, 0, 1, 1, V_OK, "static v1 allows unprivileged peripheral access");
    expect_txn(1, 32'h1000_8000, 1, 0, 1, 1, V_OK, "static v1 allows DMA into protected window");
    expect_txn(2, 32'h2000_0000, 0, 0, 1, 0, V_PRIV, "static v1 diagnostics need privilege");
    expect_txn(1, 32'h3000_0000, 0, 0, 1, 0, V_NO_RULE, "static v1 default deny");
  endtask

  // ------------------------------------------------------------------------------------------
  task automatic replay_vectors(input bit do_check, input int fd);
    logic al; logic [3:0] rs; logic [2:0] ru;
    int mism = 0;
    for (int i = 0; i < nv; i++) begin
      txn(vm[i], va[i], vw[i], vp[i], vb[i], al, rs, ru);
      if (fd) $fdisplay(fd, "%0d %0d %0d", i, al, rs);
      if (do_check && (al != ve[i] || rs != vr[i])) begin
        mism++;
        if (mism <= 5) $display("  mismatch #%0d: RTL %0d/%0d, reference %0d/%0d", i, al, rs, ve[i], vr[i]);
      end
    end
    if (do_check) check(mism == 0, $sformatf("%0d of %0d RTL decisions differ from the reference model", mism, nv));
  endtask

  task automatic try_attack(input string f);
    logic [31:0] s;
    read_policy(f);
    if (MODE == 1) begin direct_pw(); $display("ATTACK accepted=1 err=0"); end
    else if (MODE == 2) begin
      stage_pw(); rd(A_STATUS, s);
      if (st(s) == S_RECEIVE) begin wr(A_CMD, {28'd0, C_VALIDATE}); wait_not_busy(s); end
      if (st(s) == S_READY) begin
        wr(A_CMD, {28'd0, C_ACTIVATE}); wait_not_busy(s); wr(A_CMD, {28'd0, C_CONFIRM});
        $display("ATTACK accepted=1 err=0");
      end else begin
        $display("ATTACK accepted=0 err=%0d", s[15:8]);
        wr(A_CMD, {28'd0, C_ABORT});
      end
    end
    check(1'b1, "attack attempted");
  endtask

  // One transaction per cycle (when accepted); bus_idle models the data phase of granted bursts.
  bit   streaming = 0;
  int   s_idx = 0, s_run = 0, s_fd = 0, beats = 0, stall = 0;
  always @(posedge clk) if (streaming) begin
    #1;
    if (dec_valid) begin
      $fdisplay(s_fd, "D %0d %0d %0d %0d %0d", s_run, cycle, (s_idx + nv - 1) % nv, dec_allow, dec_reason);
      if (dec_allow && vb[(s_idx + nv - 1) % nv] > beats) beats = vb[(s_idx + nv - 1) % nv];
    end
    if (beats > 0) beats--;
    bus_idle = (beats == 0);
    if (!txn_ready) stall++;
  end
  // Present the next vector whenever the previous one was accepted.
  always @(posedge clk) if (streaming) begin
    #2;
    if (txn_ready) begin
      txn_master = vm[s_idx]; txn_addr = va[s_idx]; txn_write = vw[s_idx]; txn_priv = vp[s_idx];
      txn_burst = vb[s_idx]; txn_valid = 1'b1;
      s_idx = (s_idx + 1) % nv;
    end
  end

  task automatic transient_runs(input string oldf, input string newf, input int runs, input int fd);
    int t0, t1, sw;
    logic [31:0] s;
    for (int r = 0; r < runs; r++) begin
      do_reset();
      read_policy(oldf); apply_policy();
      read_policy(newf);
      s_run = r; s_fd = fd; s_idx = (r * 37) % nv; beats = 0; stall = 0;
      streaming = 1; tick(30);
      t0 = cycle;
      if (MODE == 2) install_pw(E_NONE, 0, "update under traffic");
      else direct_pw();
      t1 = cycle;
      tick(30);
      streaming = 0; txn_valid = 0; bus_idle = 1; tick(2);
      $fdisplay(fd, "U %0d %0d %0d %0d", r, t0, t1, stall);
      if (MODE == 2) begin rd(A_ACTIVE_VERSION, s); check(s == pw[1], "new policy active after update"); end
    end
  endtask

  // ------------------------------------------------------------------------------------------
  initial begin
    string pf, vf, tf, of;
    int runs, fd;
    do_reset();
    if ($value$plusargs("transient=%s", tf)) begin
      void'($value$plusargs("policy=%s", pf)); void'($value$plusargs("vectors=%s", vf));
      void'($value$plusargs("out=%s", of));
      if (!$value$plusargs("runs=%d", runs)) runs = 20;
      read_vectors(vf);
      fd = $fopen(of, "w");
      transient_runs(pf, tf, runs, fd);
      $fclose(fd);
      check(nv > 0, "vectors loaded");
    end else if ($value$plusargs("vectors=%s", vf)) begin
      read_vectors(vf);
      if ($value$plusargs("policy=%s", pf)) begin read_policy(pf); apply_policy(); end
      if ($value$plusargs("attack=%s", tf)) try_attack(tf);
      fd = $value$plusargs("out=%s", of) ? $fopen(of, "w") : 0;
      replay_vectors($test$plusargs("check"), fd);
      if (fd) $fclose(fd);
      check(nv > 0, "vectors loaded");
    end else begin
      if (MODE == 2) directed_mode2();
      else if (MODE == 1) directed_mode1();
      else directed_mode0();
    end
    finish($sformatf("tb_security_monitor[MODE=%0d]", MODE));
  end

endmodule
