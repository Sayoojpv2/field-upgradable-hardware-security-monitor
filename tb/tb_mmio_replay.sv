// tb_mmio_replay - replays the register traffic recorded by the C firmware (host backend) into
// the RTL and checks every read-back. This cross-checks the firmware's hardware model against
// the RTL over the whole firmware test suite (installs, rejections, reverts, power losses).
//   +log=build/fw/mmio_tests.log
// Line format "<op> <addr> <data> <mask>": 1 write, 2 read (expect data), 3 poll until
// (reg & mask) == data, 4 reset, 5 marker.
`timescale 1ns/1ps
module tb_mmio_replay;
  localparam int NRULES = 8;
  localparam int MODE   = 2;
`include "tb_common.svh"

  security_monitor_top #(.NRULES(NRULES), .MODE(MODE)) dut (.*);

  initial begin
    string lf;
    int fd, r, n = 0, nw = 0, nr = 0, np = 0, nx = 0, polls, maxpoll = 0, mism = 0;
    logic [31:0] op, a, d, m, got;
    do_reset();
    if (!$value$plusargs("log=%s", lf)) lf = "build/fw/mmio_tests.log";
    fd = $fopen(lf, "r");
    check(fd != 0, {"open ", lf});
    while (fd != 0 && $fscanf(fd, "%h %h %h %h\n", op, a, d, m) == 4) begin
      n++;
      case (op)
        1: begin wr(a[7:0], d); nw++; end
        2: begin
             rd(a[7:0], got); nr++;
             if (got != d) begin
               mism++;
               if (mism <= 10) $display("  line %0d: read 0x%02h = 0x%08h, firmware model expected 0x%08h", n, a[7:0], got, d);
             end
           end
        3: begin
             polls = 0; rd(a[7:0], got);
             while ((got & m) != d && polls < 20000) begin tick(); rd(a[7:0], got); polls++; end
             check((got & m) == d, $sformatf("line %0d: poll 0x%02h timed out", n, a[7:0]));
             if (polls > maxpoll) maxpoll = polls;
             np++;
           end
        4: begin do_reset(); nx++; end
        default: ;
      endcase
    end
    if (fd) $fclose(fd);
    check(mism == 0, $sformatf("%0d of %0d read-backs differ between firmware model and RTL", mism, nr));
    check(nr > 0, "log contained reads");
    $display("REPLAY lines=%0d writes=%0d reads=%0d polls=%0d resets=%0d max_poll_cycles=%0d", n, nw, nr, np, nx, maxpoll);
    finish("tb_mmio_replay");
  end

endmodule
