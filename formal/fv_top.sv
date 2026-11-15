// fv_top - harness around the real security_monitor_top (MODE 2). All ports are free inputs; the
// properties and the registered-interconnect environment model live in top_props.svh.
`ifndef FV_NR
`define FV_NR 8
`endif
module fv_top (
    input logic        clk,
    input logic        rst_n,
    input logic        txn_valid,
    input logic [3:0]  txn_master,
    input logic [31:0] txn_addr,
    input logic        txn_write,
    input logic        txn_priv,
    input logic [7:0]  txn_burst,
    input logic        bus_idle,
    input logic        reg_we,
    input logic [7:0]  reg_addr,
    input logic [31:0] reg_wdata
);
`ifdef FV_SBY
  initial assume (!rst_n);      // SymbiYosys: start in reset (scripts/run_formal.py uses -set-at 1 rst_n 0)
`endif
  logic        txn_ready, dec_valid, dec_allow, dec_violation, dec_rule_hit;
  logic [3:0]  dec_reason;
  logic [2:0]  dec_rule;
  logic [31:0] reg_rdata;
  security_monitor_top #(.NRULES(`FV_NR), .MODE(2)) dut (.*);
endmodule
