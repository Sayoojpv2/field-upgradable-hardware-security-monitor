# Progress log

## 2026-11-12 — milestone 1: toolchain, architecture, first implementation pass

- Toolchain inspected. GCC was not installed, so MSYS2 UCRT64 GCC 16.2.0 was unpacked into
  `~/tools/msys2-eda` (19 packages, SHA-256 checked against the official MSYS2 package database).
  Icarus Verilog 13.0 and yowasp-yosys 0.70 were already present. Tool paths go in `local.mk`.
- The project moved out of the app's temporary folder: its ~240-character path broke Icarus
  Verilog (Windows MAX_PATH).
- Monocypher 4.0.2 vendored (C Ed25519 + BLAKE2b); Python signing uses `cryptography`.
- Written: RTL (monitor, dual bank, bounded validator, update controller, top with 3 modes),
  Python tools (generator, signer, trace validator), C firmware (package verify, policy
  manager, persistent store, host hardware model, tests, demo), testbenches, Makefile.
- Python release gate run on the scenario policies: v2/v3/v4 recommended; the over-restrictive
  and the re-opening candidates are flagged.

## 2026-11-12 — milestone 2: verified, measured, documented

- C firmware tests: 1 213 checks pass; 205/205 torn-write runs recover the committed policy.
- RTL: 11/11 testbench runs, 7 891 checks. RTL equals the Python model on the full trace for
  v1–v4 in all modes; 17 720 firmware register operations replayed into the RTL with identical
  read-backs.
- Mutation check added. Its first run caught a real gap (no test for an overlap in the last slot
  pair); the test was added and 20/20 planted bugs are now caught.
- Validator and monitor read muxes rewritten as indexed part-selects (−14% / −10% generic cells).
- Yosys sweep (3 designs × 2/4/6/8 rules), comparative experiments, plots, docs, CI workflow.
- Not done: cross-compiled firmware size (the RISC-V newlib headers are not unpacked locally),
  timing or power analysis, CI execution on GitHub (nothing pushed).
