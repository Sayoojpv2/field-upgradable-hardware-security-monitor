# Results

Every number below comes from a run in this repository: an RTL simulation (Icarus Verilog 13.0),
a Yosys 0.70 run, the firmware test binary (GCC 16.2), or the generated packages. Regenerate them
with `make test` and `make experiments`. Data: `results/*.csv`, `results/summary.json`; per-decision
logs are regenerated in `results/raw/` by `make experiments` and are not committed. Method and caveats: [docs/EXPERIMENTS.md](docs/EXPERIMENTS.md).
These are simulation and generic-synthesis results, not FPGA, ASIC or hardware measurements.

## 1. Test results

| Suite | Result |
|---|---|
| Python (`pytest`, tools + cross-language constant/authority-table checks) | 29 passed |
| C firmware (`test_firmware`) | 1 239 checks, 0 failures |
| C firmware under UBSan (`-fsanitize=undefined -fsanitize-trap=all`, local) | 1 239 checks, no trap |
| C firmware under ASan + UBSan | configured in CI only; not run (MinGW has no ASan runtime) |
| RTL regression (`run_rtl.py`) | 11/11 testbench runs, 7 982 checks, 0 errors |
| Firmware → RTL MMIO replay (C test suite) | 17 852 operations, 2 993 read-backs identical, 431 resets |
| Firmware → RTL MMIO replay (demo) | 381 operations, identical |
| Mutation check (planted RTL security bugs, every mutant must compile) | 21/21 caught |
| Package fuzzing (3 000 random corruptions of a signed package) | 0 accepted |
| Truncation (every length shorter than a valid package) | all rejected as `TRUNCATED` |
| Yosys `check -assert`, latch scan | clean, 0 latches in all 24 configurations |

## 2. The three scenarios on unchanged RTL

Same 477-transaction trace (318 benign, 159 malicious); the RTL decisions match the Python
reference model exactly for every policy.

| Policy | Attacks accepted | Legitimate rejected | FN rate | FP rate | Release gate |
|---|---:|---:|---:|---:|---|
| v1 factory | 104 | 0 | 0.654 | 0 | – |
| v2 (DMA, scenario 1) | 62 | 0 | 0.390 | 0 | recommended |
| v3 (CPU, scenario 2) | 31 | 0 | 0.195 | 0 | recommended |
| v4 (DMA, scenario 3) | **0** | **0** | 0 | 0 | recommended |
| cand_v2_overbroad (within authority) | 57 | **23** | 0.359 | 0.072 | **NOT recommended**: 23 legitimate transactions newly rejected |
| cand_v5_dma_reopen (within authority) | **42** | 0 | 0.264 | 0 | **NOT recommended**: 42 attacks newly accepted |

The two flawed candidates pass the hardware authority check, as they should: they stay inside
DMA's envelope. Only the offline trace gate catches them, which is why contributions A and B
are complementary.

## 3. Design comparison on identical traces

| Design | Policy | Benign accepted | Benign rejected | Malicious accepted | Malicious rejected |
|---|---|---:|---:|---:|---:|
| Static | v1, fixed at synthesis | 318 | 0 | 104 | 55 |
| Configurable (unbounded) | v4 | 318 | 0 | 0 | 159 |
| Bounded dual-bank | v4 | 318 | 0 | 0 | 159 |

The static monitor cannot receive the fixes: its 104 false negatives remain until the silicon is changed.

### Authorised but malicious updates (8 attack images applied on top of v4)

| Design | Updates that took effect | Attacks accepted afterwards (sum) | Legitimate rejected afterwards (sum) |
|---|---:|---:|---:|
| Configurable (unbounded) | 8 / 8 | 99 | 31 |
| Bounded dual-bank | **0 / 8** | **0** | **0** |

| Attack image (signed by a real owner key) | Unbounded: attacks / legit broken | Bounded: hardware error |
|---|---|---|
| atk_dma_expand: DMA widens past 0x1000FFFF | 1 / 0 | ADDR_ESCAPE (slot 3) |
| atk_dma_burst: DMA burst 128 > 64 | 16 / 0 | BURST_ESC (slot 1) |
| atk_diag_write: diagnostics grants itself write | 10 / 0 | PERM_ESC (slot 2) |
| atk_diag_unpriv: diagnostics drops privilege | 10 / 0 | PRIV_FLOOR (slot 2) |
| atk_dma_foreign_modify: DMA re-opens CPU peripheral | 31 / 0 | FOREIGN (slot 0) |
| atk_dma_foreign_delete: DMA deletes CPU rule | 0 / 31 | FOREIGN (slot 4) |
| atk_dma_claim_slot: DMA writes a DIAG rule | 0 / 0 | FOREIGN (slot 5) |
| atk_dma_overlap: DMA shadow rule | 31 / 0 | OVERLAP (slot 5) |

### Updating while one transaction is issued every cycle (20 runs per transition)

| Design | Transition | Decisions | Inconsistent decisions | Update window (cycles) | Held cycles per update |
|---|---|---:|---:|---:|---:|
| Configurable (unbounded) | v1→v2 | 1 500 | 18 | 16.0 | 0 |
| Configurable (unbounded) | v2→v3 | 1 540 | 14 | 18.0 | 0 |
| Configurable (unbounded) | v3→v4 | 1 540 | 2 | 18.0 | 0 |
| Bounded dual-bank | v1→v2 | 2 340 | **0** | 74.2 | 16.2 |
| Bounded dual-bank | v2→v3 | 2 400 | **0** | 75.9 | 14.9 |
| Bounded dual-bank | v3→v4 | 2 400 | **0** | 75.9 | 14.9 |

The unbounded monitor exposes half-written policies. During v1→v2, 15 legitimate DMA buffer
accesses (plus 3 oversized bursts that both policies allow) were denied while slot 1 was already
shrunk and slot 3 not yet written. During v2→v3, 14 legitimate privileged peripheral accesses
were denied while the CPU rule was shrunk but its privileged replacement was not written yet.
During v3→v4 there were 2 decisions where the old burst limit reappeared after the new one had
taken effect. The bounded design never shows an intermediate state. Its cost
is a longer update (validation included) and about 15 cycles in which new transactions are held
while outstanding bursts drain. Under traffic, every run cut over exactly once.

## 4. Latency and update overhead (bounded design, all slots filled)

| Rule slots | Validation cycles | Full update cycles¹ | MMIO writes | Switch hold (idle bus) | Decision latency | Package bytes |
|---:|---:|---:|---:|---:|---:|---:|
| 2 | 6 | 20 | 12 | 2 | 1 | 144 |
| 4 | 13 | 33 | 18 | 2 | 1 | 168 |
| 6 | 24 | 50 | 24 | 2 | 1 | 192 |
| 8 | 39 | 71 | 30 | 2 | 1 | 216 |

¹ From the first configuration write to `COMPLETE`, one register write per cycle, idle bus.
Validation follows N(N+1)/2 + 3 exactly. The transaction decision path is not lengthened by the
update logic: 1 cycle in all three designs.

![update latency](results/plots/update_latency.png)

## 5. Synthesis (Yosys generic, technology-independent)

| Design | Rules | Gate cells | Flip-flops | Generic LUT6 |
|---|---:|---:|---:|---:|
| Static | 2 / 4 / 6 / 8 | 231 / 269 / 284 / 330 | 7 / 8 / 9 / 9 | 34 / 48 / 54 / 61 |
| Configurable (unbounded) | 2 / 4 / 6 / 8 | 1 485 / 2 558 / 3 641 / 4 721 | 167 / 328 / 489 / 649 | 303 / 467 / 681 / 831 |
| Bounded dual-bank | 2 / 4 / 6 / 8 | 4 403 / 6 787 / 8 950 / 11 614 | 470 / 791 / 1 112 / 1 432 | 1 183 / 2 014 / 2 769 / 3 516 |

Per module, bounded design, 8 rules (hierarchy kept):

| Module | Gate cells | Flip-flops |
|---|---:|---:|
| policy_bank | 2 680 | 1 281 |
| bus_security_monitor | 3 496 | 9 |
| policy_update_controller | 635 | 122 |
| policy_validator | 4 775 | 22 |
| security_monitor_top (grant-cycle bus_idle gate) | 2 | 0 |

At 8 rules the bounded design costs 2.5× the cells and 2.2× the flip-flops of the unbounded
configurable monitor. The second bank (640 FFs) and the validator's three 80-bit read ports
dominate. The static monitor is tiny because the policy constant-folds into the logic, which is
also why it cannot be updated. These are generic counts with no technology library, timing or
power, so they are not comparable with the FPGA LUT figures in the referenced preprint.

![module breakdown](results/plots/module_breakdown.png)

## 6. Recovery (firmware + host hardware model)

| Power loss at | Restored version | Correct | Update retry afterwards |
|---|---:|---|---|
| candidate package stored | 2 (committed) | yes | succeeds |
| half the rules loaded | 2 | yes | succeeds |
| during hardware validation | 2 | yes | succeeds |
| candidate validated (READY) | 2 | yes | succeeds |
| switch requested | 2 | yes | succeeds |
| switched, not yet committed | 2 | yes | succeeds |
| committed, not yet confirmed | 3 (new) | yes | – |

- **Torn-write sweep**: a power loss after every possible number of programmed bytes during an
  update gave 205/205 boots restoring exactly the committed policy.
- **Store write failure after the switch**: the hardware reverted to the retained previous bank
  (version 4 active again).
- **Corrupted committed image**: rejected at boot (`DIGEST`). The monitor stays default-deny with
  the boot window locked.
- **Reset in each update state** (RECEIVE, VALIDATE, READY, WAIT_IDLE, SWITCH, COMPLETE), RTL: no
  partial rule ever active, and the committed image restored afterwards.
- **Storage rollback** (metadata rewritten with a valid CRC to point at the older, still signed v2):
  refused at boot by the anti-rollback counter; the monitor stays default-deny. Without the counter,
  the same test restores v2.
- **Activation timeout** (bus never idle): the firmware aborts, the controller leaves WAIT_IDLE so
  traffic flows again, the old policy stays active, and a retry succeeds.
- **Registered interconnect** (bus_idle lags a grant by one cycle), RTL: the bank never flips while
  the burst granted in the ACTIVATE cycle is still transferring. Before the audit fix it did.

## 7. Design iteration

| Change | Before | After |
|---|---:|---:|
| Validator read ports: one-hot AND-OR → indexed part-select | 5 682 cells | 4 860 cells (−14%) |
| Monitor: priority mux → priority-encoded index + indexed select | 3 900 cells | 3 502 cells (−10%) |

Module-level synthesis in isolation; both versions pass the full regression and mutation check.

## 8. Not measured

Timing (Fmax), power, FPGA or ASIC area, signature verification time, firmware code size on a
target CPU, and anything on physical hardware.
