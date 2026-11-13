`timescale 1ns/1ps
// security_monitor_top - integrates the monitor with one of three policy back-ends.
//   MODE 0: static monitor   - policy fixed at synthesis time (STATIC_POLICY parameter)
//   MODE 1: configurable     - one live bank written directly over MMIO, no validation (baseline)
//   MODE 2: bounded dual-bank - validated, owner-bounded, atomically switched updates (this project)
// The monitor datapath is the same module in all three modes.
module security_monitor_top #(
    parameter int       NRULES = 8,
    parameter int       MODE   = 2,
    // default: examples/policy_v1.json (slot k at [k*80 +: 80]); tests/test_constants.py checks it
    parameter [639:0]   STATIC_POLICY = {400'd0,
                                         80'h91000000010007FFFD04,    // slot 2 DIAG
                                         80'h88800000008007FFFB40,    // slot 1 DMA
                                         80'h80000000000007FFFB10}    // slot 0 CPU
) (
    input  logic        clk,
    input  logic        rst_n,
    // bus transaction check port
    input  logic        txn_valid,
    output logic        txn_ready,
    input  logic [3:0]  txn_master,
    input  logic [31:0] txn_addr,
    input  logic        txn_write,
    input  logic        txn_priv,
    input  logic [7:0]  txn_burst,
    input  logic        bus_idle,     // no granted burst in its data phase; may lag a grant by <= 1 cycle
    output logic        dec_valid,
    output logic        dec_allow,
    output logic        dec_violation,
    output logic [3:0]  dec_reason,
    output logic [2:0]  dec_rule,
    output logic        dec_rule_hit,
    // MMIO configuration port
    input  logic        reg_we,
    input  logic [7:0]  reg_addr,
    input  logic [31:0] reg_wdata,
    output logic [31:0] reg_rdata
);
`include "hsm_defs.svh"

`ifndef SYNTHESIS
  initial if (NRULES < 2 || NRULES > 8) $fatal(1, "security_monitor_top: NRULES must be 2..8");
`endif

  logic [NRULES*80-1:0] act_rules;
  logic                 hold;
  wire  [31:0]          hw_info = {8'h48, 8'(MODE), 8'(NUM_OWNERS), 8'(NRULES)};

  generate
    if (MODE == 0) begin : g_static
      assign act_rules = STATIC_POLICY[NRULES*80-1:0];
      assign hold      = 1'b0;
      assign reg_rdata = (reg_addr == A_HW_INFO) ? hw_info : 32'd0;

    end else if (MODE == 1) begin : g_config
      wire [7:0] roff = reg_addr - A_RULE_BASE;
      wire       wr   = reg_we && reg_addr >= A_RULE_BASE && reg_addr < (A_RULE_BASE + 8'h80) &&
                        roff[6:4] < NRULES && roff[3:2] != 2'd3;
      logic unused_sel;
      logic [NRULES*80-1:0] unused_inact;
      policy_bank #(.NRULES(NRULES), .DUAL(0)) u_bank (
        .clk(clk), .rst_n(rst_n), .swap(1'b0), .clear_inactive(1'b0),
        .we(wr), .widx(roff[6:4]), .wfield(roff[3:2]), .wdata(reg_wdata),
        .active_sel(unused_sel), .active_rules(act_rules), .inactive_rules(unused_inact));
      assign hold      = 1'b0;
      assign reg_rdata = (reg_addr == A_HW_INFO) ? hw_info : 32'd0;

    end else begin : g_bounded
      logic        sel, swap, clr, bwe, vstart, vroot, vmal, vdone, vok, vbusy;
      logic [2:0]  widx, verr_slot;
      logic [1:0]  wfield;
      logic [31:0] wdata, vcand, vact;
      logic [3:0]  vreq, vcount;
      logic [7:0]  verr;
      logic [NRULES*80-1:0] cand_rules;

      policy_bank #(.NRULES(NRULES), .DUAL(1)) u_bank (
        .clk(clk), .rst_n(rst_n), .swap(swap), .clear_inactive(clr),
        .we(bwe), .widx(widx), .wfield(wfield), .wdata(wdata),
        .active_sel(sel), .active_rules(act_rules), .inactive_rules(cand_rules));

      policy_validator #(.NRULES(NRULES)) u_val (
        .clk(clk), .rst_n(rst_n), .start(vstart), .cand_rules(cand_rules), .act_rules(act_rules),
        .req_owner(vreq), .root_mode(vroot), .cand_version(vcand), .active_version(vact),
        .declared_count(vcount), .malformed(vmal), .busy(vbusy), .done(vdone), .ok(vok),
        .err_code(verr), .err_slot(verr_slot));

      policy_update_controller #(.NRULES(NRULES)) u_ctrl (
        .clk(clk), .rst_n(rst_n), .reg_we(reg_we), .reg_addr(reg_addr), .reg_wdata(reg_wdata),
        // A burst granted this cycle is not yet visible in a registered interconnect's bus_idle:
        // never treat the bus as idle in the grant cycle, or the bank could flip mid-burst.
        .reg_rdata(reg_rdata), .bus_idle(bus_idle && !(dec_valid && dec_allow)), .hold(hold), .active_sel(sel),
        .bank_swap(swap), .bank_clear(clr), .bank_we(bwe), .bank_widx(widx), .bank_wfield(wfield),
        .bank_wdata(wdata), .val_start(vstart), .val_req_owner(vreq), .val_root(vroot),
        .val_cand_version(vcand), .val_active_version(vact), .val_count(vcount),
        .val_malformed(vmal), .val_done(vdone), .val_ok(vok), .val_err(verr), .val_err_slot(verr_slot));
    end
  endgenerate

  bus_security_monitor #(.NRULES(NRULES)) u_mon (
    .clk(clk), .rst_n(rst_n), .rules(act_rules), .hold(hold),
    .txn_valid(txn_valid), .txn_ready(txn_ready), .txn_master(txn_master), .txn_addr(txn_addr),
    .txn_write(txn_write), .txn_priv(txn_priv), .txn_burst(txn_burst),
    .dec_valid(dec_valid), .dec_allow(dec_allow), .dec_violation(dec_violation),
    .dec_reason(dec_reason), .dec_rule(dec_rule), .dec_rule_hit(dec_rule_hit));

endmodule
