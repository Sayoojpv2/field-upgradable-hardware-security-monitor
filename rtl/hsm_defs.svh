// hsm_defs.svh - constants shared by all RTL modules (included inside each module body,
// so there is deliberately no include guard).
// Must match firmware/include/hsm_regs.h and tools/hsm_common.py; tests/test_constants.py checks it.

// ---------------------------------------------------------------------------
// Packed rule (80 bits). Bits [10:0] are identical to bits [10:0] of the MMIO ATTR word.
//   [79] valid | [78:75] owner | [74:43] start | [42:11] end (inclusive)
//   [10] PRIV required | [9] W allowed | [8] R allowed | [7:0] max burst (beats)
// ---------------------------------------------------------------------------
localparam int RULE_W     = 80;
localparam int NUM_OWNERS = 3;

localparam logic [3:0] OWNER_CPU  = 4'd0;
localparam logic [3:0] OWNER_DMA  = 4'd1;
localparam logic [3:0] OWNER_DIAG = 4'd2;
localparam logic [3:0] OWNER_ROOT = 4'hF;   // boot-time restore only (boot window open)

// Monitor violation codes (dec_reason)
localparam logic [3:0] V_OK = 4'd0, V_BAD_MASTER = 4'd1, V_NO_RULE = 4'd2, V_READ_DENIED = 4'd3,
                       V_WRITE_DENIED = 4'd4, V_PRIV = 4'd5, V_BURST = 4'd6, V_SPAN = 4'd7;

// Update / validation error codes (STATUS[15:8])
localparam logic [7:0] E_NONE = 8'd0, E_AUTH = 8'd1, E_COUNT = 8'd2, E_MALFORMED = 8'd3,
                       E_OWNER_ID = 8'd4, E_RANGE = 8'd5, E_ADDR_ESCAPE = 8'd6, E_PERM_ESC = 8'd7,
                       E_PRIV_FLOOR = 8'd8, E_BURST_ESC = 8'd9, E_FOREIGN = 8'd10,
                       E_OVERLAP = 8'd11, E_VERSION = 8'd12;

// Update controller states (STATUS[3:0])
localparam logic [3:0] S_IDLE = 4'd0, S_RECEIVE = 4'd1, S_VALIDATE = 4'd2, S_READY = 4'd3,
                       S_WAIT_IDLE = 4'd4, S_SWITCH = 4'd5, S_COMPLETE = 4'd6,
                       S_ROLLBACK = 4'd7, S_ERROR = 4'd8;

// Commands (written to CMD[3:0])
localparam logic [3:0] C_BEGIN = 4'd1, C_VALIDATE = 4'd2, C_ACTIVATE = 4'd3, C_CONFIRM = 4'd4,
                       C_REVERT = 4'd5, C_ABORT = 4'd6, C_LOCK = 4'd7;

// Register map (byte offsets)
localparam logic [7:0] A_CMD = 8'h00, A_STATUS = 8'h04, A_REQ_OWNER = 8'h08, A_CAND_VERSION = 8'h0C,
                       A_RULE_COUNT = 8'h10, A_ACTIVE_VERSION = 8'h14, A_PREV_VERSION = 8'h18,
                       A_HW_INFO = 8'h1C, A_RULE_BASE = 8'h40;   // slot s: 0x40 + 16*s + {0 start,4 end,8 attr}
localparam logic [31:0] ATTR_RSVD_MASK = 32'h7FF0_F800;           // must be zero in ATTR writes

// ---------------------------------------------------------------------------
// Immutable authority envelopes (synthetic SoC; design assumption, see docs).
// Hard-wired constants: no register, port or command can change them.
// ---------------------------------------------------------------------------
function automatic logic [31:0] env_lo(input logic [3:0] o);
  case (o) 4'd0: env_lo = 32'h0000_0000; 4'd1: env_lo = 32'h1000_0000;
           4'd2: env_lo = 32'h2000_0000; default: env_lo = 32'hFFFF_FFFF; endcase
endfunction
function automatic logic [31:0] env_hi(input logic [3:0] o);
  case (o) 4'd0: env_hi = 32'h0000_FFFF; 4'd1: env_hi = 32'h1000_FFFF;
           4'd2: env_hi = 32'h2000_FFFF; default: env_hi = 32'h0000_0000; endcase
endfunction
function automatic logic env_r(input logic [3:0] o);  env_r = (o <= 4'd2);              endfunction
function automatic logic env_w(input logic [3:0] o);  env_w = (o == 4'd0 || o == 4'd1); endfunction
function automatic logic env_pf(input logic [3:0] o); env_pf = (o == 4'd2);             endfunction // privilege floor
function automatic logic [7:0] env_burst(input logic [3:0] o);
  case (o) 4'd0: env_burst = 8'd16; 4'd1: env_burst = 8'd64; 4'd2: env_burst = 8'd4;
           default: env_burst = 8'd0; endcase
endfunction

// Rule field accessors
function automatic logic        r_valid(input logic [79:0] r); r_valid = r[79];    endfunction
function automatic logic [3:0]  r_owner(input logic [79:0] r); r_owner = r[78:75]; endfunction
function automatic logic [31:0] r_start(input logic [79:0] r); r_start = r[74:43]; endfunction
function automatic logic [31:0] r_end  (input logic [79:0] r); r_end   = r[42:11]; endfunction
function automatic logic        r_priv (input logic [79:0] r); r_priv  = r[10];    endfunction
function automatic logic        r_wr   (input logic [79:0] r); r_wr    = r[9];     endfunction
function automatic logic        r_rd   (input logic [79:0] r); r_rd    = r[8];     endfunction
function automatic logic [7:0]  r_burst(input logic [79:0] r); r_burst = r[7:0];   endfunction
