# Measurements

Every paid run of fp-check, with the number, what it measured, and the raw result.
Written 2026-08-08. **Quote from here rather than from a chat log.**

Raw results are checked in under `tests/fixtures/`, scrubbed with
`tests/scrub_capture.py` — no username, no home directory, no scratch path.
`tracePath` fields survive scrubbing but point at temp dirs that are gone, which
is why `check_ablation_isolation` reports UNVERIFIED rather than passing on them.

**Retention, set 2026-08-10.** Raw JSON is kept only where it is still load-bearing:
the two cross-plugin baselines this merge was justified against (concept-prover,
pre-merge fp-check), the current sweep, and `eval-result-2026-07-30.json`, which
`test_validate_eval_result.py` reads as a real-shaped result so a schema change
cannot pass by agreeing with a mock. Rows marked **not retained** were the
intermediate version ladder and single-case probes; their per-case numbers are in
the tables below and in `tests/README.md`, and ~970 KB of per-run traces nobody had
read since were dropped.

**`scrub_capture.py` cannot scrub an eval result as invoked on the command line.**
It parses line-by-line as JSONL and aborts on the first line of a pretty-printed
document, scrubbing nothing and leaving the machine paths in place — while
reporting a parse error that is easy to read as cosmetic. Import it and call
`scrub(text, username)` over the whole document instead, then assert the file
still parses as JSON and greps clean for the home directory. This bit on the
2.6.1 sweep, which reached `tests/fixtures/` with `/Users/<name>/…` intact on the
first attempt.

> ## ⚠ The +0.281 row does NOT describe the current tree. Read this first.
>
> **Set 2026-08-10.** After the 2.6.1 sweep, an eight-round review/fix loop changed
> the gate logic substantially: a new required `reimplementation` enum decided by
> `artifactProblem`, an ambiguity refusal in all three severity caps, rewritten
> `citedReference` and `capSeverity` rules, `byDesign` gated on an indicator count,
> `uncitedFix`, and roughly 85 defects in total — several of which changed a
> verdict. **None of that is measured.** The number below describes the tree as it
> stood on 2026-08-09, before any of it.
>
> Do not quote +0.281 for the current code. Re-sweep first. A one-case
> `integration-cap` probe at `--ablation none` (~$4) is the cheap way to confirm the
> pipeline still dispatches before committing ~$30 to a full sweep.

> **Resolved 2026-08-09.** 2.6.1 has now been swept. The review/fix loop after
> 2.6.0 had found six defects, one in the change that sweep was run to evaluate:
> the reworded `gateReachability` criterion dropped the attacker-control
> requirement for EVERY finding, not only the integration ones it was scoped to,
> and it is now conditional on the root cause. **+0.267 describes the weaker
> wording; 2.6.1 measures +0.281 with the conditional one**, on a 42/42 clean
> sweep. See the 2.6.1 row below.

## Sweeps — the seven static cases, n=3, `--ablation with-without`

| version | date | with | without | delta | runs | cost | raw |
|---|---|---|---|---|---|---|---|
| 2.5.0 | 08-07 | 0.868 | 0.656 | **+0.213** | 38/42 ok | $37.65 | not retained |
| 2.5.1 | 08-08 | 0.908 | 0.700 | **+0.208** | 42/42 | $42.08 | not retained |
| 2.6.0 | 08-08 | **0.919** | 0.652 | **+0.267** | 42/42 | $52.43 | not retained |
| 2.6.1 | 08-09 | **1.000** | 0.719 | **+0.281** | 42/42 | $29.47 | `eval-result-2026-08-09-2.6.1-sweep.json` |

Earlier, before this series: v1 **+0.170**, v2 **+0.151**. Target to beat, from
concept-prover: **+0.170**.

**Read the with-arm, not the delta.** The baseline loads no plugin, so its
movement is n=3 noise, and it moved 0.656 → 0.700 → 0.652 → 0.719. The with-arm
is the plugin: **0.868 → 0.908 → 0.919 → 1.000**. Real, modest, monotone — a much
smaller claim than the deltas make.

**2.6.1 saturates the suite, and that is now the binding limit.** All 21 with-arm
runs scored exactly 1.000; there is no headroom left to measure an improvement
in. Three of the seven cases have a baseline at 1.000 as well, so the whole
+0.281 comes from four cases and half of it from two. **The next change to this
plugin cannot be evaluated by this suite** — a harder case is owed before the
next sweep is worth paying for, or the sweep will report +0.28 whatever the
change did.

**2.5.0's delta is a reconstruction.** Its `wrong-parameter` lost 4 runs
(including the entire baseline arm) to `exit 1: (no stderr)`, so that case was
re-run separately at 1.000/1.000 and substituted. The CLI reported **+0.279** for
that sweep over a dead arm; +0.213 is the honest figure.

### Per case

| case | 2.5.0 | 2.5.1 | 2.6.0 | 2.6.1 | discriminates? |
|---|---|---|---|---|---|
| blocked-attack-path | +0.733 | +0.733 | +0.667 | **+0.600** | yes, strongest |
| integration-cap | +0.111 | +0.389 | **+0.667** | **+0.667** | yes |
| already-fixed | +0.444 | +0.333 | +0.500 | **+0.500** | yes |
| dead-route | +0.200 | 0.000 | +0.200 | +0.200 | weakly |
| inflated-impact | 0.000 | 0.000 | **−0.167** | 0.000 | no |
| should-not-fire | 0.000 | 0.000 | 0.000 | 0.000 | **no** |
| wrong-parameter | 0.000 | 0.000 | 0.000 | 0.000 | **no** |

Three of seven contribute nothing in every sweep. Half the total signal is
`blocked-attack-path` and `integration-cap`.

At 2.6.1 the three zero rows are zero for a specific reason worth keeping
separate from "the plugin did not help": the **baseline** scores 1.000 on all
three, so the case has nothing left to reward. `should-not-fire` is the one to
keep anyway — it is the over-fire guard, it held 3/3, and it cost $0.28 because
the plugin correctly declined to launch a workflow at all.

### The per-case 3/3 gates

The handoff's bar was: mean beats +0.170 **and** these three at 3/3.

| gate | 2.5.0 | 2.5.1 | 2.6.0 | 2.6.1 |
|---|---|---|---|---|
| `already-fixed` | ✗ 0.833 | ✗ 0.833 | **✓ 1.000** | **✓ 1.000** |
| `integration-cap` | ✗ 0.444 | ✗ 0.722 | **✓ 1.000** | **✓ 1.000** |
| `blocked-attack-path` | ✓ 1.000 | ✓ 1.000 | **✗ 0.800** | **✓ 1.000** |

It was **2 of 3 in every sweep, by a different two each time** — at n=3 one run
moves a case by 0.333, so that pattern was as consistent with shuffling as with
progress. **2.6.1 is the first sweep to hold all three at once**, which is the
handoff's bar. Treat it as one observation, not a trend: the mechanism that took
`blocked-attack-path` from 0.800 back to 1.000 is the `gateReachability` rewording
being made conditional on root cause, and one sweep cannot separate that from the
same n=3 noise that moved it down.

## Against the plugins this one replaces

Measured 2026-08-09. **The comparison is weaker than the numbers look — read the
caveat before quoting any row.**

| | version | with | without | delta | clean runs | cost |
|---|---|---|---|---|---|---|
| **fp-check, merged** | 2.6.1 | **1.000** | 0.719 | **+0.281** | **42/42** | $29.47 |
| concept-prover | 2.1.0 | 0.784 | ~0.614 | +0.170 | 38/42 | $39.96 |
| fp-check, pre-merge | 1.0.3 | — | — | +0.008 | 36/42 | $21.49 |

The merged plugin beats both on delta, on with-arm score, on run integrity and on
cost. It is also the only one of the three with no dead run.

**Caveat 1 — the two archives were measured on different case files.** Since
2026-08-05/06 the suite gained an offline pin on all seven prompts, a
trust-boundary sentence in `integration-cap`, and rewritten graders on
`inflated-impact` and `integration-cap`. These rows are **historical context, not
a head-to-head.** A true comparison requires re-sweeping both parents on the
current suite, ~$100 and ~6h, not done.

**Caveat 2 — concept-prover's +0.170 is a damaged number in both directions.**
Four of its 42 runs were dead: two `inflated-impact` with-arm runs timed out at
900s, dragging that case to −0.444, and two more lost their `outcome` grader to
API 529s. Recomputed, its mean is **+0.151** counting dead runs as zero and
**+0.295** excluding them. The +0.170 the handoff sets as the bar is neither.
**Against the dead-runs-excluded figure of +0.295, 2.6.1's +0.281 does not
clearly win** — it wins on integrity and cost instead.

**Caveat 3 — pre-merge fp-check's 7-case number is mostly void.** Its
`blocked-attack-path` with-arm was 3/3 dead on 900s timeouts and its
`already-fixed` baseline arm was 3/3 dead, two of those overrunning even their own
limit (4012s against 1800s). Only 5 of 7 cases carry data, which is why the
5-case +0.036 is the figure the handoff quotes. Its real `blocked-attack-path`
result comes from the separate re-run: **0.600 with, 0.600 without, delta 0.000.**

All current cases sit at `timeout_seconds: 1800`, so the timeout failure mode
that voided 10 runs across those two archives is closed.

### Per case, against the archives

| case | 2.6.1 Δ | concept-prover Δ | pre-merge fp-check Δ |
|---|---|---|---|
| integration-cap | **+0.667** | +0.667 | 0.000 |
| blocked-attack-path | **+0.600** | +0.600 | 0.000 (re-run) |
| already-fixed | **+0.500** | +0.500 | void |
| dead-route | +0.200 | +0.067 | **+0.400** |
| inflated-impact | 0.000 | −0.444 | −0.222 |
| should-not-fire | 0.000 | 0.000 | 0.000 |
| wrong-parameter | 0.000 | −0.200 | 0.000 |

The merged plugin matches concept-prover exactly on the three cases that were the
merge's stated reason for existing, and loses none of the ground where
concept-prover went negative. `dead-route` remains the one case where pre-merge
fp-check is still ahead.

## Single-case runs

| what | version | result | cost | raw |
|---|---|---|---|---|
| `wrong-parameter`, n=3 both arms | 2.5.0 | 1.000 / 1.000, **+0.000** | $4.94 | not retained |
| `integration-cap`, n=3 both arms | 2.6.0 | 0.833 / 0.333, **+0.500** | $13.63 | not retained |
| online suite, n=3 both arms | 2.5.0 | 0.889 / 1.000, **−0.111** | $11.51 | not retained |

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
| 2.6.1 | 0 | $2.01 | **nothing about the plugin** — killed by a 429 individual spend limit at turn 1. All six gates and the impact agent were correct in the journal up to the kill |
| 2.6.1 (retry) | **1.000** | $4.15 | limit had cleared; `Skill` 2 / `Workflow` 4 / `AskUserQuestion` 0, six gates PASS, `layers: []` with no absence-of-check entry |

**A 429 spend-limit kill is recorded as `exit 1: (no stderr)` with `turns: 1`,**
which is indistinguishable at the result-JSON level from a genuine plugin crash.
The distinguishing evidence is `api_error_status: 429` in the trace's result
event. Check that before attributing such a run to the plugin — the same error
string voided 4 runs in the 2.5.0 sweep.

## Free layers at 2.6.1

381 pytest (+25 skipped), 317 node, 36 bats, ruff, shellcheck, shfmt, validator —
all green, verified 2026-08-09 before the sweep. Mutation gate at 2.6.0 was
**132 run, 0 survived, 0 stale, 12 deferred**; not re-run for 2.6.1.

`make check` also fails `python-tests` in `plugins/constant-time-analysis`
(17 failures), for want of the aarch64 cross sysroot that CI installs. That is
pre-existing and unrelated — this branch touches no file under it — but it means
`make check` exits non-zero, so read the per-directory output rather than the
exit code. Note the runner prints each directory header *before* its results, so
a failure count is attributable to the header above it, not below.

## What is NOT measured

- **Stage 2 (online)** — its one case does not discriminate; a plain session
  scores 1.000. Never measured as an ablation.
- **Real codebases** — every static case is a synthetic fixture written by a
  `scaffold.sh`.
- **Cost of removing the brocard pre-gate** — Stage 1 dropped 9.33 → 5.44 agents,
  but the no-plugin baseline's cost rose 11.3% over the same interval, so the
  cost data cannot separate the plugin from harness drift.
- **Batch triage and the exploit-chain check** — landed in 2.0.0, never
  measured. Their one eval case, `chained-findings`, is tagged `batch` and joins
  a mean only after it discriminates at n=3.
- **Layer 3 (regrade) does not run.** The checked-in capture still records
  `concept-prover:verify-attack-path`, from before the merge, so `test_regrade.py`
  skips on a condition it checks and **12 mutations stay deferred** behind it. One
  paid capture via `tests/capture-runs.sh` re-arms both. This is the only reason
  the mutation gate reports deferrals.

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
