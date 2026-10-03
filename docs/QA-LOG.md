# QA log

One row per defect found from the `v0.11.0` freeze on (ROADMAP §6). Together
with the coverage table and the hardware matrix in `TESTING.md`, this is the
evaluation chapter's data: what each method found, on a system that did not
change underneath the measurement.

**How it was found** is one of: review, property test, hardware matrix,
dogfooding, user report. **Severity** follows ROADMAP §4 (P0–P3). **Fix
commit** is filled in when the fix is committed.

| Date | What | How it was found | Severity | Fix commit |
|---|---|---|---|---|
| 2026-10-03 | `textsafe` cut skipped an escape and kept appending (`'\x1f0'` at limit 1 came out as `0...`) | property test, unaided | P2 | `ecb6453` |
| 2026-10-03 | The agent's `MSG_CRITICAL` handler told the person "cannot be approved from here. Use the terminal": untrue since CRITICAL devices got the countdown, and the service has no terminal. `AgentLink.notify_critical` had no caller | review | P2 | |
| 2026-10-03 | `SECURITY.md` said an unanswered agent question "times out into the terminal fallback" and that stores are always created `0600`; neither has been true since the service hold and the gate-side trust write | review | P2 | |

## Coverage (privilege boundary)

`coverage.yml`, as root, branch coverage, `HYPOTHESIS_PROFILE=ci`.

| Module | Tests | 0.11.0 | Now |
|---|---|---|---|
| `protocol.py` | test_privsep, test_properties | 97% | 98% |
| `gate_server.py` | test_privsep, test_boundary | 81% | 95% |
| `gate_client.py` | test_privsep, test_boundary | 71% | 94% |
| `privsep.py` | test_privsep, test_boundary | 67% | 98% |
| `securefs.py` | test_privsep, test_trust | 87% | 87% |
| `atomicio.py` | test_trust, test_ledger | 85% | 85% |
| **boundary** | | **80%** | **95%** |
| **total** (without `interrogate.py`, `countdown_dialog.py`) | | 81%¹ | 85% |

¹ Measured with the two modules included.

## Deep property runs (ROADMAP 1.4)

| Date | Version | `HYPOTHESIS_PROFILE=deep` | Result |
|---|---|---|---|
| 2026-10-03 | 0.11.0 + Unreleased (this tree, uncommitted) | 26 property tests, 7500 examples each, Python 3.11 | Clean, 630 s; nothing found |
