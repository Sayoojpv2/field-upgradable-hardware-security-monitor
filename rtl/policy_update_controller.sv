`timescale 1ns/1ps
// policy_update_controller - MMIO register file + update FSM.
//   IDLE -BEGIN-> RECEIVE (rule writes land in the inactive bank) -VALIDATE-> VALIDATE
//   -> READY -ACTIVATE-> WAIT_IDLE (hold new txns until bus_idle) -> SWITCH (flip bank_sel)
//   -> COMPLETE -CONFIRM-> IDLE            | COMPLETE -REVERT-> WAIT_IDLE -> SWITCH -> ROLLBACK -> IDLE
//   validation failure -> ERROR ; ABORT from RECEIVE/READY/WAIT_IDLE -> ROLLBACK -> IDLE
// The active bank and active version change only in SWITCH.
module policy_update_controller #(
    parameter int NRULES = 8
) (
    input  logic        clk,
    input  logic        rst_n,
    // MMIO: one write per cycle, combinational read
    input  logic        reg_we,
    input  logic [7:0]  reg_addr,
    input  logic [31:0] reg_wdata,
    output logic [31:0] reg_rdata,
    // interconnect: no granted burst is still in its data phase
    input  logic        bus_idle,
    output logic        hold,
    // policy bank
    input  logic        active_sel,
    output logic        bank_swap,
    output logic        bank_clear,
    output logic        bank_we,
    output logic [2:0]  bank_widx,
    output logic [1:0]  bank_wfield,
    output logic [31:0] bank_wdata,
    // validator
    output logic        val_start,
    output logic [3:0]  val_req_owner,
    output logic        val_root,
    output logic [31:0] val_cand_version,
    output logic [31:0] val_active_version,
    output logic [3:0]  val_count,
    output logic        val_malformed,
    input  logic        val_done,
    input  logic        val_ok,
    input  logic [7:0]  val_err,
    input  logic [2:0]  val_err_slot
);
`include "hsm_defs.svh"

  logic [3:0]  state, req_owner, rule_count;
  logic [31:0] cand_version, active_version, prev_version;
  logic        boot_window, reverting, malformed;
  logic [7:0]  last_err;
  logic [2:0]  err_slot;

  // Configuration registers are frozen from BEGIN until the update finishes (no TOCTOU).
  wire cfg_open = (state == S_IDLE) || (state == S_ERROR);
  wire cmd_wr   = reg_we && reg_addr == A_CMD;
  wire [3:0] cmd = reg_wdata[3:0];

  // Rule window 0x40..0xBF
  wire [7:0] roff     = reg_addr - A_RULE_BASE;
  wire       rule_wr  = reg_we && reg_addr >= A_RULE_BASE && reg_addr < (A_RULE_BASE + 8'h80);
  wire [2:0] rslot    = roff[6:4];
  wire [1:0] rfield   = roff[3:2];
  wire       rule_bad = (roff[6:4] >= NRULES) || (rfield == 2'd3) || (reg_addr[1:0] != 2'b00) ||
                        (rfield == 2'd2 && (reg_wdata & ATTR_RSVD_MASK) != 32'd0);

  wire req_ok   = (req_owner < NUM_OWNERS) || (req_owner == OWNER_ROOT && boot_window);
  wire count_ok = (rule_count != 4'd0) && (rule_count <= NRULES);
  wire begin_ok = cfg_open && cmd_wr && cmd == C_BEGIN && req_ok && count_ok;

  assign bank_we     = (state == S_RECEIVE) && rule_wr && !rule_bad;
  assign bank_widx   = rslot;
  assign bank_wfield = rfield;
  assign bank_wdata  = reg_wdata;
  assign bank_clear  = begin_ok;
  assign bank_swap   = (state == S_SWITCH);
  assign hold        = (state == S_WAIT_IDLE) || (state == S_SWITCH);

  assign val_start          = (state == S_RECEIVE) && cmd_wr && cmd == C_VALIDATE;
  assign val_req_owner      = req_owner;
  assign val_root           = (req_owner == OWNER_ROOT);
  assign val_cand_version   = cand_version;
  assign val_active_version = active_version;
  assign val_count          = rule_count;
  assign val_malformed      = malformed;

  always_ff @(posedge clk or negedge rst_n)
    if (!rst_n) begin
      state <= S_IDLE; req_owner <= 4'd0; rule_count <= 4'd0;
      cand_version <= 32'd0; active_version <= 32'd0; prev_version <= 32'd0;
      boot_window <= 1'b1; reverting <= 1'b0; malformed <= 1'b0;
      last_err <= E_NONE; err_slot <= 3'd0;
    end else begin
      if (reg_we && cfg_open)
        case (reg_addr)
          A_REQ_OWNER:    req_owner    <= reg_wdata[3:0];
          A_CAND_VERSION: cand_version <= reg_wdata;
          A_RULE_COUNT:   rule_count   <= reg_wdata[3:0];
          default: ;
        endcase
      if (state == S_RECEIVE && rule_wr && rule_bad) malformed <= 1'b1;

      case (state)
        S_IDLE, S_ERROR:
          if (cmd_wr && cmd == C_BEGIN) begin
            err_slot <= 3'd0;
            if (!req_ok)        begin state <= S_ERROR; last_err <= E_AUTH;  end
            else if (!count_ok) begin state <= S_ERROR; last_err <= E_COUNT; end
            else                begin state <= S_RECEIVE; last_err <= E_NONE; malformed <= 1'b0; end
          end
          else if (cmd_wr && cmd == C_ABORT && state == S_ERROR) state <= S_IDLE;
          else if (cmd_wr && cmd == C_LOCK  && state == S_IDLE)  boot_window <= 1'b0;
        S_RECEIVE:
          if (cmd_wr && cmd == C_VALIDATE)   state <= S_VALIDATE;
          else if (cmd_wr && cmd == C_ABORT) state <= S_ROLLBACK;
        S_VALIDATE:
          if (val_done) begin
            if (val_ok) state <= S_READY;
            else begin state <= S_ERROR; last_err <= val_err; err_slot <= val_err_slot; end
          end
        S_READY:
          if (cmd_wr && cmd == C_ACTIVATE)   state <= S_WAIT_IDLE;
          else if (cmd_wr && cmd == C_ABORT) state <= S_ROLLBACK;
        S_WAIT_IDLE:
          if (cmd_wr && cmd == C_ABORT && !reverting) state <= S_ROLLBACK;
          else if (bus_idle)                          state <= S_SWITCH;
        S_SWITCH:
          if (reverting) begin
            active_version <= prev_version;
            state <= S_ROLLBACK;
          end else begin
            prev_version   <= active_version;
            active_version <= cand_version;
            boot_window    <= 1'b0;          // first activation closes the boot-restore window
            state <= S_COMPLETE;
          end
        S_COMPLETE:
          if (cmd_wr && cmd == C_CONFIRM)     state <= S_IDLE;
          else if (cmd_wr && cmd == C_REVERT) begin reverting <= 1'b1; state <= S_WAIT_IDLE; end
        S_ROLLBACK: begin reverting <= 1'b0; state <= S_IDLE; end
        default: state <= S_IDLE;
      endcase
    end

  wire busy = (state == S_VALIDATE) || (state == S_WAIT_IDLE) || (state == S_SWITCH) || (state == S_ROLLBACK);
  wire [31:0] status = {13'd0, err_slot, last_err, (state == S_COMPLETE), boot_window, active_sel, busy, state};

  always_comb
    case (reg_addr)
      A_STATUS:         reg_rdata = status;
      A_REQ_OWNER:      reg_rdata = {28'd0, req_owner};
      A_CAND_VERSION:   reg_rdata = cand_version;
      A_RULE_COUNT:     reg_rdata = {28'd0, rule_count};
      A_ACTIVE_VERSION: reg_rdata = active_version;
      A_PREV_VERSION:   reg_rdata = prev_version;
      A_HW_INFO:        reg_rdata = {8'h48, 8'd2, 8'(NUM_OWNERS), 8'(NRULES)};
      default:          reg_rdata = 32'd0;
    endcase

endmodule
