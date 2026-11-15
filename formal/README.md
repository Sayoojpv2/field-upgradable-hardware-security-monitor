# Formal verification

This folder holds the formal harnesses, property files and executable specification for the
security properties of the RTL. `make formal` runs everything (`scripts/run_formal.py`). Exact
results, including solver sizes and run times, are written to [results/formal.md](../results/formal.md).

## Tools and status words

| What | Engine | Where it runs |
|---|---|---|
| `make formal` | Yosys 0.70 built-in `sat` command (MiniSAT) through yowasp-yosys, pinned to 0.70.0.0.post1259 in `requirements.txt`; no external solver | locally (Windows 11) and in the CI job `formal` |
| `formal/hsm.sby` | SymbiYosys, `smtbmc` + yices, k-induction (depth 4, controller 6) | CI job `formal-sby` only (OSS CAD Suite 2026-11-14); this machine has no SMT solver |

| Status | Meaning |
|---|---|
| PROVED (one-step) | The property is checked over one clock step with all inputs **and all register state free**, so it holds in every state, reachable or not |
| PROVED (k-induction) | `sat -tempinduct`: base case from reset plus an induction step from any state satisfying the asserted invariants. Unbounded |
| BOUNDED PASS (N) | Bounded model check from reset: no violation in the first N clock cycles. **Not a proof** |
| REACHED | A cover: the solver produced a trace from reset that reaches the scenario |
| FAILED / UNKNOWN / TIMEOUT / ERROR | Each fails `make formal`; none is ever counted as a pass |

## Method

The checks follow the transaction-checker idea of Nokes et al., *Verifying Hardware Resource Isolation
through Mandatory Access Control Policy* (ISQED 2026, NIST). Hardware accesses are treated as subject-to-object
transactions and checked against an explicit policy, with three stages: translate signals into
transactions, map each transaction to a subject and an object, and verify it against the policy. Here:

- **Subject**: the bus master ID.
- **Object**: an address range.
- **Access mode**: read or write, plus privilege and burst length.
- **Policy**: the active rule bank, which must sit inside the immutable per-owner authority envelopes.

[`spec.svh`](spec.svh) is that policy, written from the design document **without** reusing
`rtl/hsm_defs.svh`. The property files apply it as formal checks, not simulation monitors.

Yosys has no SystemVerilog `bind`, so properties that need a module's internal signals are kept in
separate `*_props.svh` files. Each RTL module includes its file inside `` `ifdef FORMAL ``, which
simulation and synthesis never define, so these include lines do not change synthesis.

## Property matrix

| Property | Module | Job | Method | Result | Limitations |
|---|---|---|---|---|---|
| **A** every grant is permitted by the matched (lowest) rule | `bus_security_monitor` | `A_monitor_sound` | one-step | PROVED | for any 8-rule bank and any transaction |
| **A** unknown masters and unpermitted transactions are denied (default deny) | `bus_security_monitor` | `A_monitor_deny` | one-step | PROVED | |
| **A** no false deny for overlap-free (validated) policies | `bus_security_monitor` + spec | `A_monitor_priority`, `A_monitor_grant`, `A_spec_lemmas` | one-step | PROVED (lemmas) | the three lemmas are machine-checked; combining them (below) is a written argument |
| **A** one decision per accepted transaction, one cycle later; nothing accepted while held | `bus_security_monitor` | `A_monitor_protocol` | k-induction (k=1) | PROVED | |
| **B** accepted ⇔ every rule inside its owner's envelope (range, read/write, privilege floor, burst), no other owner's rule changed, no overlap, count matches; error slot names the first offender | `policy_validator`, all 8 slots | `B_validator` | k-induction (k=1) | PROVED | assumes inputs stable while validating (A_stable, discharged below) |
| **B** exact schedule: the validator reaches FINAL exactly 2 + N + N(N−1)/2 cycles after start (38 for N = 8) | `policy_validator` | `B_validator` (invariant) | k-induction | PROVED | the 39-cycle controller figure in RESULTS.md adds the controller handshake and is measured in simulation |
| **C** only a swap changes the active bank; a swap installs exactly the staged bank; reset invalidates every slot | `policy_bank` | `C_bank` | k-induction (k=1) | PROVED | assumes no swap in a write cycle (A_ctrl, discharged below) |
| **C** rule writes only in RECEIVE; swap never coincides with a write or clear | `policy_update_controller` | `CDEF_controller` | k-induction (k=1) | PROVED | |
| **D** switch only after an idle-bus cycle in WAIT_IDLE; traffic held exactly during WAIT_IDLE/SWITCH | `policy_update_controller` | `CDEF_controller` | k-induction (k=1) | PROVED | |
| **D** the bank never flips while a granted burst is in its data phase, with an interconnect that learns of grants one cycle late | `security_monitor_top` (real top, NRULES=8) | `D_top_registered_bus` | k-induction (k=1) | PROVED | interconnect contract A_bus |
| **E** READY / switch only with a validated candidate untouched since validation; versions and bank change only at SWITCH; config frozen during an update; boot window never reopens; ROOT mode only inside it | `policy_update_controller` | `CDEF_controller` | k-induction (k=1) | PROVED | |
| **F** activation strictly raises `active_version`; revert restores the previous one | `policy_update_controller` + `policy_validator` | `CDEF_controller`, `B_validator` | k-induction | PROVED | controller proof assumes A_val, discharged by `B_validator` |
| **E2E** whatever is switched in satisfies the authority spec relative to the policy it replaces | `security_monitor_top` (NRULES=2) | `E2E_top_n2` | BMC | BOUNDED PASS (40) | bounded; 2 rule slots; reverts excluded |
| Recovery below the committed version is refused | C firmware | not formal | C tests | – | covered by `test_storage_rollback`; **no formal method was applied to the C code** |

## Assumptions and how each is discharged

| Assumption | Used by | Discharged by |
|---|---|---|
| **A_stable**: validator inputs (both banks, requester, versions, count, malformed flag) do not change while it is busy or reporting | `B_validator` | `CDEF_controller`: no bank write, clear or swap and frozen configuration outside IDLE/ERROR; `C_bank`: bank contents change only through those |
| **A_ctrl**: no swap in a cycle that writes or clears | `C_bank` | `CDEF_controller` (`bank_swap → !bank_we && !bank_clear`) |
| **A_val**: the validator never accepts a version that is not newer | `CDEF_controller` (property F) | `B_validator` (accept ⇒ `cand_version > active_version`) |
| **A_bus**: the interconnect never reports idle while it knows of outstanding beats, and learns of a grant at most one cycle late | `D_top_registered_bus` | **not discharged**: interface contract that the SoC must honour |
| Reset is asserted in the first cycle; afterwards reset may occur at any time | all | modelled (`-set-at 1 rst_n 0`; free `rst_n` afterwards) |
| The requester ID written to `REQ_OWNER` is the owner the C policy manager authenticated | system | **trusted**. The hardware does **not** verify Ed25519 signatures |

**Completeness of the monitor** composes three proved lemmas:

1. **G1** (`A_spec_lemmas`): a permitting rule matches the transaction's start address.
2. **G2** (`A_spec_lemmas`): if two rules are disjoint and one permits a transaction, the other cannot match it.
3. **R1** (`A_monitor_priority`) and **R2** (`A_monitor_grant`): the RTL's match is exactly the specification's, the lowest match is selected, and a selected rule that permits produces a grant.

The argument: take an overlap-free policy in which slot *k* permits a transaction. By G1, slot *k* matches. By G2, no lower slot matches. By R1, slot *k* is selected. By R2, the transaction is granted.

## Evidence that the proofs are not vacuous

1. **Covers.** 13 scenarios reached from reset, with traces. Among them:
   - an 8-slot candidate accepted;
   - an overlap found in the last slot pair;
   - a switch waiting for a granted burst;
   - a failed update after an earlier activation.
2. **Planted bugs.** Ten known bugs, each inserted into a temporary copy of the RTL, and each producing a concrete counterexample (FAILED):
   - monitor: privilege check removed, span check removed, highest slot wins;
   - validator: burst check, ownership check and last-pair check skipped;
   - bank: writes reach the active bank;
   - controller: switch without an idle bus, activation of a rejected candidate;
   - the `d426302` race.

   Bugs that only appear after a full update sequence run as BMC on a 2-slot configuration, where a validation takes 6 cycles instead of 39.
3. **Historical counterexample.** [`cex/d426302_switch_race.txt`](cex/d426302_switch_race.txt) and its `.vcd`, regenerated by every `make formal`. With the `d426302` fix removed, the solver finds a 24-cycle trace. A REVERT is accepted in the same cycle a 2-beat burst is granted. The registered interconnect still reports idle, and the bank select flips with 2 beats outstanding. The fixed RTL is proved free of this.

## Second engine: SymbiYosys

`formal/hsm.sby` runs the ten proof jobs again (not the bounded end-to-end check or the covers)
with a different engine: SymbiYosys with `smtbmc` and the yices SMT solver, from a pinned OSS CAD
Suite release. On GitHub Actions (job `formal-sby`), all ten tasks end in `PASS` ("successful
proof by k-induction"). Two of the planted bugs above are also inserted there, and each gives a
`FAIL`:

- "bank writes reach the active bank" (task `bank`);
- "monitor ignores privilege requirement" (task `monitor_sound`).

The PASS results are therefore not vacuous. The two engines agree on every proof job.

The first CI runs of `make formal` showed a reproducibility problem, now fixed. Two or three
jobs died at random points, with logs cut off mid-pass. `make formal` correctly counted them as
ERROR and failed.

The cause was the yowasp runtime, not the designs or the properties. This was identified from
the yowasp-runtime source and the failure pattern; the race was not reproduced locally. The
runtime writes its compiled Yosys module (about 220 MB) to a cache file without locking or an
atomic rename. The first four parallel jobs on a fresh runner each compiled and wrote that file,
and the jobs started after them loaded a half-written copy. `scripts/run_formal.py` now runs
Yosys once before starting the parallel jobs. It also records a non-zero Yosys exit as ERROR,
together with its stderr, so a tool crash can never be read as a result.

The Yosys build is pinned (yowasp-yosys 0.70.0.0.post1259) so that SAT problem sizes and results
match `results/formal.md` exactly.

## What is not formally verified

- The firmware: package parsing, Ed25519 verification, version chain, persistent store and anti-rollback counter. These are tested by the C suite, under UBSan locally and under ASan + UBSan in CI.
- A fully unbounded end-to-end proof of the composed system. The end-to-end property is a bounded check (40 cycles, 2 slots) plus the assume-guarantee argument above.
- Liveness, for example "every update eventually completes". Only the validator's exact latency is proved.
- The static and unbounded baseline designs (`MODE` 0 and 1). The monitor properties apply to them as well, because the datapath is the same module, but they have no update guarantees to prove.
- The specification, the independent Python model and the RTL were all written by the same developer. Formal proof shows the RTL matches `spec.svh`; it cannot show `spec.svh` matches the intent.

## Files

| File | Purpose |
|---|---|
| `spec.svh` | executable specification (envelopes, slot rule, disjointness, match, permit) |
| `monitor_props.svh`, `validator_props.svh`, `controller_props.svh`, `top_props.svh` | properties and inductive invariants, included under `` `ifdef FORMAL `` |
| `fv_monitor.sv`, `fv_validator.sv`, `fv_bank.sv`, `fv_controller.sv`, `fv_top.sv`, `fv_spec.sv` | harnesses (free inputs, environment assumptions) |
| `hsm.sby` | SymbiYosys configuration of the ten proof jobs (CI only) |
| `cex/` | counterexample for the `d426302` bug, regenerated by `make formal` |
