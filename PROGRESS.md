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

## 2026-11-13 — milestone 3: independent audit and hardening

Issues found and fixed (each with a regression test that fails without the fix):

| Pri | Where | Problem | Fix |
|---|---|---|---|
| P1 | `rtl/security_monitor_top.sv` | With an interconnect that registers its busy state, a burst granted in the ACTIVATE cycle let the bank flip mid-burst | `bus_idle` ignored in the grant cycle; RTL test with a registered interconnect; mutant added |
| P1 | `firmware/src/policy_manager.c`, `pstore.c` | Boot re-checked signatures but not freshness: rewriting the metadata restored an older signed policy | One-way anti-rollback counter (models OTP/RPMB), checked at boot |
| P2 | `firmware/src/policy_manager.c` | Activation timeout left the controller in WAIT_IDLE, holding all bus traffic | ABORT (or REVERT if the switch slipped in late) on timeout |
| P2 | `scripts/mutation_check.py` | A mutant that failed to compile counted as caught | Compile failure now aborts the check |
| P2 | `tools/hsm_common.py` | `"false"` in policy JSON became `True` (permission silently granted); no range checks | Strict types and ranges |
| P2 | `tools/trace_validator.py` | Gate could pass changes no trace exercised | Uncovered changed rules refuse the candidate |
| P2 | `Makefile` demo | an `echo` fallback after each gate call also hid crashes | `--expect recommend/reject`, self-checking |
| P3 | RTL, TB, C, repo | NRULES range unchecked; static-lifetime TB warning; `logf` shadowed libc; line endings | Sim-time guard, TB fix, rename, `.gitattributes`; raw logs untracked |

Also added: envelope ±1 boundary tests for every owner, in-authority permission changes, reset in
SWITCH, owner-relabel test, CI pinned to ubuntu-24.04 with an ASan/UBSan step. Verified unchanged:
all security, latency and recovery results. Bounded design at 8 rules: 11 606 → 11 614 cells.

## 2026-11-15 — milestone 4: formal verification and independent assurance

- `formal/`: an executable specification, property files and harnesses for the monitor, validator,
  bank, controller and top level, checked with Yosys' built-in SAT engine (`make formal`, about
  560 s).
  - Proved: properties A–F.
  - Bounded only: the end-to-end property, 40 cycles on 2 slots.
  - 13 covers reached; 10 planted bugs each give a counterexample.
- The race fixed in d426302 is rediscovered formally when its fix is removed. The trace is kept
  in `formal/cex/`; it reaches the race through REVERT as well as activation.
- `tests/independent_model.py`: an independent monitor and validator model with adversarial
  vectors. The RTL agrees on 10 987 comparisons. Its first run's mismatches were a generator bug
  (values wider than 32 bits), fixed and now rejected by a range check. No RTL defect was found.
- Planted bug added: "controller activates a rejected candidate". The simulation mutation check
  now catches 22/22.
- SymbiYosys configuration and two CI jobs (`formal`, `formal-sby`) added. They have not run:
  there is no SMT solver locally, and nothing has been pushed.
- No RTL behaviour changed. The only RTL edits are `ifdef FORMAL` include lines, and synthesis
  results are identical.

