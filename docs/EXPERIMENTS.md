# Experiments: method

All experiments are reproducible with `make experiments` (which also runs `make sim-rtl` and
`make synth`). Results go to `results/` and are summarised in [RESULTS.md](../RESULTS.md).

## Designs compared

`rtl/security_monitor_top.sv`, parameter `MODE`, same `bus_security_monitor` in all three:

| MODE | Design | Policy back-end |
|---|---|---|
| 0 | Static monitor | Rules are the `STATIC_POLICY` parameter (synthesised as constants). Cannot be updated |
| 1 | Runtime-configurable, unbounded | One live bank written directly over MMIO. No authentication in hardware, no validation, no staging |
| 2 | Scope-bounded dual-bank (this project) | Validated inactive bank, atomic switch, revert |

## Workload

`tools/trace_validator.py gen` (seed 2026) produces 477 transactions: 318 benign, 159 malicious.
The benign traffic covers CPU memory and privileged peripheral access, DMA buffers and
diagnostic reads. The malicious traffic covers scenario 1 (DMA into 0x1000_8000–0x1000_8FFF,
including bursts crossing into it), scenario 2 (unprivileged CPU access to 0xF000–0xFFFF),
scenario 3 (DMA bursts of 17–64 beats), and attacks outside every owner's authority (unknown
masters, cross-domain access, diagnostics writes, unassigned space, zero-length and oversized
bursts). There are also 15 boundary cases at region edges. Labels state the intended security
behaviour once all three weaknesses are known. The identical corpus is used for every design and policy.

## Metrics

| Experiment | How it is measured | File |
|---|---|---|
| Decision latency | Cycles from an accepted transaction to `dec_valid` (directed RTL test, back-to-back throughput test) | `latency.csv` |
| Validation cycles | `tb_policy_update +measure`: cycles spent in `VALIDATE` for an N-rule policy with all slots filled, `NRULES` = N | `latency.csv` |
| Full update cycles | Same run: from the first configuration write to `COMPLETE`, one MMIO write per cycle, idle bus | `latency.csv` |
| Package size | 120 + 12 × N bytes, from the packages actually generated | `latency.csv` |
| Security effectiveness / false positives | RTL decisions for the corpus, compared with labels | `design_comparison.csv` |
| Malicious authorised updates | For each of the 8 attack images: install it on top of v4 (MODE 1: direct writes; MODE 2: real requester through the validator), then replay the corpus on the RTL | `malicious_updates.csv` |
| Update under traffic | One transaction per cycle while updating v1→v2, v2→v3, v3→v4, 20 runs each with different stream offsets; a beat counter drives `bus_idle`. Each decision is classified against the old and new policy: an *inconsistent* decision is either a transaction both policies treat the same but which was decided differently mid-update, or old behaviour reappearing after new behaviour had started | `transient.csv` |
| Hold cycles | Cycles with `txn_ready` low during each update | `transient.csv`, `latency.csv` |
| Resources | Yosys 0.70 `synth -flatten` generic cells and flip-flops; `synth -flatten -lut 6` generic 6-input LUTs; `check -assert`; latches rejected | `synth.csv`, `synth_modules.csv` |
| Recovery | C fault-injection tests: 7 fault points + torn-write sweep over every byte of the store writes | `fault_injection.json` |
| Formal verification complexity | `scripts/run_formal.py`: status, induction length or BMC depth, largest SAT instance (variables) and run time of every job, cover and planted-bug run | `formal.json`, `formal.csv`, `formal.md` |
| Independent model agreement | `run_rtl.py`: RTL decisions and validator outcomes compared with `tests/independent_model.py` | testbench output (`VALVEC`, `+check`) |
| Release gate | `trace_validator.compare` on every example policy and candidate. A candidate is refused if the hardware model rejects it, a legitimate transaction becomes rejected, a malicious one becomes accepted, or a changed rule is exercised by no trace | `trace_validation.csv` |

## Caveats

- Yosys numbers are technology-independent gate and LUT counts with no placement, routing or
  timing. They support *relative* comparisons between the three designs and across rule counts
  only. They are not FPGA utilisation, ASIC area, power or Fmax.
- Cycle counts come from RTL simulation with an ideal one-write-per-cycle register master.
  Firmware execution time, bus latency and signature verification time are not included.
  The Ed25519 verification runs on the host in the C tests and is not timed.
- The configurable baseline (MODE 1) is deliberately simple. A real product would add at least
  software checks, so its "malicious update" numbers show what hardware enforcement adds. They
  do not describe any specific commercial part.
- The traces are synthetic and the labels come from the scenario definitions; they measure
  consistency with an intended policy, not real-world detection rates or zero-day detection.
- Per-decision logs (`results/raw/`) are regenerated deterministically and not committed. A run
  from a clean copy reproduced every committed CSV value.
