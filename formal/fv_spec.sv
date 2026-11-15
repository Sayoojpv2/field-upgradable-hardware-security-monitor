// fv_spec - lemmas about the specification functions alone (no RTL). Two arbitrary rule words and
// an arbitrary transaction. Used to compose monitor completeness (formal/README.md).
module fv_spec (
    input logic [79:0] x,
    input logic [79:0] y,
    input logic [3:0]  m,
    input logic [31:0] a,
    input logic        w,
    input logic        p,
    input logic [7:0]  b
);
`include "spec.svh"
  always @* begin
    // G1: a rule that permits a transaction also matches its start address.
    if (sp_permits(x, m, a, w, p, b)) assert (sp_hit(x, m, a));
    // G2: if two rules are disjoint and one permits a transaction, the other cannot match it.
    if (sp_disjoint(x, y) && sp_permits(y, m, a, w, p, b)) assert (!sp_hit(x, m, a));
  end
endmodule
