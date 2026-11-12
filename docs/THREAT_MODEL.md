# Threat model

Scope: the simulated SoC of this repository (three bus masters, one transaction monitor, a
trusted policy manager). This is an academic architecture study, not a certified root of trust.

## Protected assets

1. **Each owner's protection boundary**: the address window, permissions, privilege
   requirement and burst limit that keep one component's resources safe from the others.
2. **The integrity of the enforced policy**: the monitor must enforce exactly a validated,
   authenticated policy, never a partially written or unvalidated one.
3. **Availability of legitimate traffic**: an update must not break or misclassify legitimate
   transactions, either permanently (bad policy) or transiently (non-atomic switch).
4. **The committed policy across power loss** and its version history (anti-rollback).

## Trust boundaries and assumptions

| Component | Trusted? | Assumption |
|---|---|---|
| Authority envelope table (RTL constants) | yes | Correct by design; fixed at synthesis; no write path exists |
| Trusted public-key table and device ID | yes | Provisioned at manufacture, read-only to software |
| C policy manager | yes | Verifies signatures correctly and reports the authenticated requester truthfully to the hardware. This is the largest assumption: a compromised manager could claim any requester, but it still cannot install a rule outside the envelope of the owner it names, or modify another owner's rules without naming that owner |
| Owner signing keys | each key is trusted **only for its own owner** | A key may be stolen or its holder may be careless or malicious: the design must contain the damage to that owner's envelope |
| Policy package in transit / in storage | no | Any byte may be modified, truncated or replayed |
| Persistent store | no (integrity) | May be torn by power loss or corrupted; contents are re-authenticated at boot |
| Bus masters | no | May issue any transaction, including unknown master IDs, oversized bursts, wrap-around bursts |
| Interconnect `bus_idle` signal | yes | Truthfully reports outstanding data-phase activity |
| Offline release tooling and human reviewer | yes, but fallible | The trace gate reduces, not eliminates, the risk of a bad but authorised policy |

## Attacker capabilities considered

- **A1 – Authorised but malicious updater**: holds a valid owner key and signs a policy that
  widens its window, adds permissions, raises its burst, drops a privilege floor, or edits,
  deletes or impersonates another owner's rules.
- **A2 – Package tampering and replay**: modifies headers or rules, swaps signatures, truncates
  packages, sends a package for another device, or replays an older signed policy.
- **A3 – Malicious bus master**: issues transactions outside its permissions, with forged
  master IDs, zero-length, oversized or address-wrapping bursts, or exactly on region boundaries.
- **A4 – Update timing**: issues traffic during an update hoping to hit a half-applied policy;
  tries to change the requester after `BEGIN` or modify the candidate after validation.
- **A5 – Power loss / reset** at any point of an update, including mid-write of the store.

## Attacks addressed (and where)

| Attack | Mechanism | Evidence |
|---|---|---|
| A1 expand address range | envelope containment (`ADDR_ESCAPE`) | `atk_dma_expand`, RTL + C tests |
| A1 add permissions | permission containment (`PERM_ESC`) | `atk_diag_write` |
| A1 drop mandatory privilege | privilege floor (`PRIV_FLOOR`) | `atk_diag_unpriv` |
| A1 raise burst | burst containment (`BURST_ESC`) | `atk_dma_burst` |
| A1 modify / delete / create another owner's rule | slot ownership comparison (`FOREIGN`) | `atk_dma_foreign_modify`, `_delete`, `atk_dma_claim_slot` |
| A1 ambiguous shadow rule | pairwise overlap check (`OVERLAP`) | `atk_dma_overlap` |
| A1 change immutable boundaries | no write path to the authority table; unassigned space can never be covered | RTL structure; envelope tests |
| A2 tampering, wrong key, wrong device, truncation | Ed25519 over header + BLAKE2b digest of payload; length checks first | C tests incl. 3 000-mutation fuzz and every truncation length |
| A2 replay / downgrade | firmware version chain + hardware `VERSION` check | C and RTL tests |
| A3 out-of-policy transactions | default-deny monitor with burst-span and wrap checks | 477-transaction corpus, directed tests |
| A4 half-applied policy | writes only to the inactive bank, one-bit switch at a held, idle boundary | update-under-traffic experiment: 0 inconsistent decisions |
| A4 TOCTOU on requester / candidate | configuration frozen after `BEGIN`; rule writes ignored after `VALIDATE` | RTL tests |
| A5 interruption | A/B store, metadata copies with CRC, re-authentication at boot, revert before confirm | 7 fault points + 205-byte torn-write sweep |

## Attacks not addressed

- An owner **weakening its own protection within its envelope** (for example re-opening a
  window it had closed). That is within its authority by definition; only the offline trace gate
  (`cand_v5_dma_reopen`) and human review catch it.
- A **compromised policy manager** that lies about the requester, or a stolen ROOT key used
  during the boot window.
- Physical attacks: fault injection on the RTL itself, side channels, probing, glitching.
- Denial of service by an owner that never lets the bus go idle (the switch waits; firmware can
  abort), or by repeatedly submitting invalid updates.
- Attacks the monitor cannot see: data contents, timing channels, cache or speculative effects,
  confused-deputy use of a legitimate master.
- Key management: rotation, revocation and secure storage of the signing keys.
- The synthetic vulnerability scenarios are controlled examples. They are **not** real CVEs,
  and nothing here discovers vulnerabilities.
