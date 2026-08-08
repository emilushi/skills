# Measurements

Every paid run of fp-check, with the number, what it measured, and the raw result.
Written 2026-08-08. **Quote from here rather than from a chat log.**

Raw results are checked in under `tests/fixtures/`, scrubbed with
`tests/scrub_capture.py` — no username, no home directory, no scratch path.
`tracePath` fields survive scrubbing but point at temp dirs that are gone, which
is why `check_ablation_isolation` reports UNVERIFIED rather than passing on them.

> **The tree is 2.6.1 and the last sweep measured 2.6.0.** A review/fix loop
> found six defects after that sweep, one of them in the change the sweep was run
> to evaluate: the reworded `gateReachability` criterion dropped the
> attacker-control requirement for EVERY finding, not only the integration ones it
> was scoped to. That is now conditional on the root cause. **+0.267 describes the
> weaker wording.** Re-sweep before quoting it as 2.6.1's number.

## Sweeps — the seven static cases, n=3, `--ablation with-without`

| version | date | with | without | delta | runs | cost | raw |
|---|---|---|---|---|---|---|---|
| 2.5.0 | 08-07 | 0.868 | 0.656 | **+0.213** | 38/42 ok | $37.65 | `eval-result-2026-08-07-2.5.0-sweep.json` |
| 2.5.1 | 08-08 | 0.908 | 0.700 | **+0.208** | 42/42 | $42.08 | `eval-result-2026-08-08-2.5.1-sweep.json` |
| 2.6.0 | 08-08 | **0.919** | 0.652 | **+0.267** | 42/42 | $52.43 | `eval-result-2026-08-08-2.6.0-sweep.json` |

Earlier, before this series: v1 **+0.170**, v2 **+0.151**. Target to beat, from
concept-prover: **+0.170**.

**Read the with-arm, not the delta.** The baseline loads no plugin, so its
movement is n=3 noise, and it moved 0.656 → 0.700 → 0.652. The with-arm is the
plugin: **0.868 → 0.908 → 0.919**. Real, modest, monotone — a much smaller claim
than the deltas make.

**2.5.0's delta is a reconstruction.** Its `wrong-parameter` lost 4 runs
(including the entire baseline arm) to `exit 1: (no stderr)`, so that case was
re-run separately at 1.000/1.000 and substituted. The CLI reported **+0.279** for
that sweep over a dead arm; +0.213 is the honest figure.

### Per case

| case | 2.5.0 | 2.5.1 | 2.6.0 | discriminates? |
|---|---|---|---|---|
| blocked-attack-path | +0.733 | +0.733 | +0.667 | yes, strongest |
| integration-cap | +0.111 | +0.389 | **+0.667** | yes |
| already-fixed | +0.444 | +0.333 | +0.500 | yes |
| dead-route | +0.200 | 0.000 | +0.200 | weakly |
| inflated-impact | 0.000 | 0.000 | **−0.167** | no / negative |
| should-not-fire | 0.000 | 0.000 | 0.000 | **no** |
| wrong-parameter | 0.000 | 0.000 | 0.000 | **no** |

Three of seven contribute nothing in every sweep. Half the total signal is
`blocked-attack-path` alone.

### The per-case 3/3 gates

The handoff's bar was: mean beats +0.170 **and** these three at 3/3.

| gate | 2.5.0 | 2.5.1 | 2.6.0 |
|---|---|---|---|
| `already-fixed` | ✗ 0.833 | ✗ 0.833 | **✓ 1.000** |
| `integration-cap` | ✗ 0.444 | ✗ 0.722 | **✓ 1.000** |
| `blocked-attack-path` | ✓ 1.000 | ✓ 1.000 | **✗ 0.800** |

**2 of 3 in every sweep, by a different two each time.** At n=3 one run moves a
case by 0.333, so this is as consistent with shuffling as with progress.

## Single-case runs

| what | version | result | cost | raw |
|---|---|---|---|---|
| `wrong-parameter`, n=3 both arms | 2.5.0 | 1.000 / 1.000, **+0.000** | $4.94 | `…-2.5.0-wrong-parameter.json` |
| `integration-cap`, n=3 both arms | 2.6.0 | 0.833 / 0.333, **+0.500** | $13.63 | `…-2.6.0-integration-cap.json` |
| online suite, n=3 both arms | 2.5.0 | 0.889 / 1.000, **−0.111** | $11.51 | `…-2.5.0-online-suite.json` |

The online −0.111 was a grader defect, not behaviour: `actually-went-online`
required `WebFetch` and failed two runs that went online via `Bash`/`gh`. Both
arms found the advisory 6/6. Grader removed; the case does not discriminate.

## Probes — `integration-cap`, n=1, `--ablation none`

Cheap single runs used to decide whether a sweep was worth paying for. **Four for
four found something that would have wasted one.**

| version | score | cost | what it found |
|---|---|---|---|
| 2.3.0 | 0.333 | $5.10 | the dispatch contract forced a fabricated layer |
| 2.4.0 | 0.333 | $2.75 | layer fix held; died at brocard 2 instead |
| 2.4.0 + case fix | 0.167 | $3.12 | brocards passed; the gate conflict surfaced |
| 2.5.0 | **1.000** | $5.54 | first ever pass, after the brocards were removed |

## Free layers at 2.6.0

368 pytest (+25 skipped), 317 node, 36 bats, ruff, shellcheck, shfmt, validator —
all green. Mutation gate **132 run, 0 survived, 0 stale, 12 deferred**.

## What is NOT measured

- **Stage 2 (online)** — its one case does not discriminate; a plain session
  scores 1.000. Never measured as an ablation.
- **Real codebases** — every static case is a synthetic fixture written by a
  `scaffold.sh`.
- **Cost of removing the brocard pre-gate** — Stage 1 dropped 9.33 → 5.44 agents,
  but the no-plugin baseline's cost rose 11.3% over the same interval, so the
  cost data cannot separate the plugin from harness drift.
- **Batch triage and the exploit-chain check** — absent, pinned by live guards in
  `tests/coverage.test.mjs`.

## Traps that cost money, in one place

| trap | consequence |
|---|---|
| Targeting by path, not name | skill never activates; the run is a baseline with a plugin installed |
| Installed cache ≠ working tree | you grade the previous version. `diff -r` proves it |
| Omitting `--tag static` | the online case joins the mean; two different things averaged |
| Reading the CLI mean over a dead arm | 2.5.0 reported +0.279 against a real +0.213 |
| Not passing `--keep-temp` | traces gone exactly when a result needs attributing |
| A foreground timeout on a 3h sweep | one launch was reaped at 62 min with no JSON — the CLI writes results only at the end. Start it detached |
| Running the mutation gate during a sweep | contention stalled it 25 min; the same mutation was caught in 60s alone |
