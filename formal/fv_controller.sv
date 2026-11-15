// fv_controller - harness for policy_update_controller. Every input (MMIO bus, bus_idle, bank select,
// validator outputs) is free; the properties live in controller_props.svh inside the module.
module fv_controller (
    input logic        clk,
    input logic        rst_n,
    input logic        reg_we,
    input logic [7:0]  reg_addr,
    input logic [31:0] reg_wdata,
    input logic        bus_idle,
    input logic        active_sel,
    input logic        val_done,
    input logic        val_ok,
    input logic [7:0]  val_err,
    input logic [2:0]  val_err_slot
);
`ifdef FV_SBY
  initial assume (!rst_n);      // SymbiYosys: start in reset (scripts/run_formal.py uses -set-at 1 rst_n 0)
`endif
  logic [31:0] reg_rdata, bank_wdata, val_cand_version, val_active_version;
  logic        hold, bank_swap, bank_clear, bank_we, val_start, val_root, val_malformed;
  logic [2:0]  bank_widx;
  logic [1:0]  bank_wfield;
  logic [3:0]  val_req_owner, val_count;
  policy_update_controller #(.NRULES(8)) dut (.*);
endmodule
