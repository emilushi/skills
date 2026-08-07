# Handoff: measure fp-check 2.2.1, then decide whether the merge is worth keeping

**Written 2026-08-07.** You are picking up a plugin that has been measured twice
and beaten its baseline neither time. Everything free is green, **the §1.1 probe
has been run and acted on**, and the next thing it needs is the sweep in §1.2.

> **The probe was run on 2.2.0 and it failed, which is why this now says 2.2.1.**
> `integration-cap` came back `DISMISSED at Stage 1's pre-gate (Brocard 2)`, with
> the answer stating *"Severity: not reached — the finding was dismissed before
> the impact/severity phase"*. So 2.2.0 fixed the deep-route proof that had been
> killing this case and the cap still never ran, because the last brocard allowed
> to end the stage killed it one step earlier. Brocard 2 now defers to the impact
> stage; brocard 6 is the only one that still short-circuits, and it is the only
> one with no downstream equivalent.
>
> Cost of finding that: **$1.15**. It is the third consecutive time the probe has
> caught something that would have wasted the sweep. Run it again on 2.2.1 before
> §1.2 — the same command, the same four checks.

Read this file, then [tests/README.md](tests/README.md) — that one records every
dead end this plugin has been down, including **five paid sweeps that were invalid
and each produced a plausible-looking number.** Do not skip it.

---

## 0. State in one table

| | |
|---|---|
| Version | **2.2.1**, branch `fp-check-triage-merge` in a worktree off `origin/main` |
| Free layers | 318 node + 324 pytest + 36 bats, all green |
| `make check` | passes except `python-tests`, which fails in `constant-time-analysis` for want of an aarch64 cross sysroot CI installs — **pre-existing, not this branch** (verified on a stashed tree) |
| Mutation gate | **120 run, 0 survived, 0 stale, 12 deferred** |
| Measured | v1 (2026-08-06) mean delta **+0.170**; v2 (2026-08-07) **+0.151** |
| Target to beat | concept-prover's **+0.170**, and 3/3 on `already-fixed`, `integration-cap`, `blocked-attack-path` |
| Verdict so far | **has not beaten its baseline.** concept-prover is NOT retired |

## 1. Do this before spending anything

Two steps, in order. The first is free. **The probe has been run against 2.2.0 and its finding is fixed in 2.2.1; re-run it against 2.2.1.**

### 1.1 Trace probe (~$2, 10 min) — this is not optional

The last probe found two real defects for $0.32 and saved a $39 sweep. The one
before it found that the plugin never activated at all.

```bash
export CLAUDE_CODE_WALNUT_SPIRE=1
claude plugin marketplace add /Users/gros/ToB/tools/tob/skills-wt-fp-check
claude plugin install fp-check@trailofbits
diff -r ~/.claude/plugins/cache/trailofbits/fp-check/2.2.1 plugins/fp-check   # MUST be empty
claude plugin eval fp-check@trailofbits --case integration-cap --runs 1 \
  --ablation none --scaffold --keep-temp \
  --allow-tools Bash Write Skill Workflow Task TaskCreate TaskUpdate TaskList TaskGet \
  --model sonnet --judge-model sonnet --max-cost-usd 8 \
  --output-dir /tmp/probe --json /tmp/probe.json
```

Then read the trace — `tracePath` in the JSON — and confirm **all** of:

| Check | Why |
|---|---|
| `Skill` ≥ 1 and `Workflow` ≥ 1 | A path target does NOT register the skill. Target by NAME. Two probes scored `Skill 0` before this was understood |
| `AskUserQuestion` == 0 | Every case pins both stage answers; if it appears, the pre-supply path is broken and the eval measures Stage 1 only |
| `severityCorrection` appears | **The whole point of this run.** `capSeverity` has fired **0 times in 63 measured runs**. If it is still absent, stop and fix that before the sweep |
| The final answer says Medium, not Critical | `integration-cap` is the 3-point loss |

`integration-cap` is the probe case deliberately: it is the single biggest
shortfall and the one the 2.2.0 changes most directly target.

### 1.2 The sweep

```bash
claude plugin eval fp-check@trailofbits \
  --runs 3 --ablation with-without --scaffold \
  --allow-tools Bash Write Skill Workflow Task TaskCreate TaskUpdate TaskList TaskGet \
  --model sonnet --judge-model sonnet --max-cost-usd 95 \
  --output-dir /tmp/sweep --report /tmp/sweep/report.html --json /tmp/sweep/result.json
```

Expect **~$40 and ~3 hours**, strictly sequential. Every flag is load-bearing;
`tests/README.md` §Layer 4 says why for each. Two that have cost real money:
`--ablation with-without` (a **path** target silently defaults to `none`) and
`--scaffold` (without it the case runs in an empty directory).

**Run it with `--keep-temp`.** Both previous sweeps ran without it, and both times
the traces were gone exactly when a result needed attributing. It costs disk and
nothing else.

### 1.3 Before you read any aggregate

```bash
uv run --no-project python plugins/fp-check/tests/validate_eval_result.py /tmp/sweep/result.json
```

`partial: false` does **not** mean clean. One sweep lost 22 of 30 runs to a usage
limit, still reported `partial: false` and `runsPerCase: 3` for every case, and a
**+0.47** on a case whose entire baseline arm was dead. Check per-run `error`
fields and no-answer runs (`judgeVotes: null` with empty evidence) yourself.

Report the mean **both ways** — as the CLI computes it, and excluding ungradeable
runs. Quote the per-case table, never the mean alone.

## 2. What changed in 2.2.0/2.2.1 and what it should do

Three subagents fixed 17 bugs after v2. The measured problem they were aimed at:

```
case                     cp  old-fp  BEST  v2   what should change
already-fixed             3     0      3    1   retraction now cites the commit
blocked-attack-path       3     0      3    3   (held)
dead-route                1     2      2    3   (exceeds parts)
inflated-impact           1     3      3    2   recovery decides, not brocard 4
integration-cap           3     0      3    0   capSeverity now always runs
should-not-fire           3     3      3    3   (held)
wrong-parameter           2     3      3    3   (held)
TOTAL                    16    11     20   15
```

**best-of-parts 20/21, merged 15/21.** The cause was not a bug in either parent's
logic — the merge added **two gates in first position that neither parent had**,
and they decided the cases the ported machinery existed to decide:

- brocard DISMISS fired **12 times in 63 runs**; a deep-route proof **9**
- `upstreamFixStands`, `capSeverity`, `missingPrecondition`, `decideVerdict`,
  `OUT_OF_SCOPE`, `NOT_VULNERABLE` fired **0 times each**
- **old fp-check's six-gate review ran zero times in 63 runs**

Fixes: `PROOF_SCHEMA.applies` required and read `=== true` so an auxiliary proof
cannot block a question that does not apply; a blocking proof is carried rather
than terminal so `capSeverity` always runs; brocards 2, 4 and 5 defer to the impact,
recovery and history gates (**6 is the only one left that ends the stage**, and the
only one with no downstream equivalent — nothing else evaluates remediation cost);
`upstreamFixStands` moved above the blocking-layer branch; `settledByStageOne`
gives Stage 3 a degraded mode so its refusal reads as a verdict about the finding
rather than a complaint about the caller.

**Monotonicity holds by construction: the softest thing a deferral can reach is
`NEEDS_MORE_INFO`.** No change made it easier to report a finding as real.

## 3. How to read the result

### If the mean beats +0.170 and the three cases hit 3/3

Then the merge is justified. Proceed to step 9 of the original handoff: update the
docs and retire concept-prover. **Carry `tests/fixtures/` over regardless** — those
are the baseline and deleting them destroys the only thing the comparison rests on.

### If it does not

That is the third consecutive answer of "no", and the question stops being *which
gate to fix* and becomes **whether the merge should exist**. The evidence for
splitting it back up is not weak:

- `dead-route` is the only case where the merge exceeds both parents (+1)
- Three of seven cases (`should-not-fire`, `wrong-parameter`, `inflated-impact`)
  do not discriminate at all at n=9–18 per arm — both arms score identically
- concept-prover alone scores 16/21 for $39.96; the merge scores 15/21 for $39.35

A defensible outcome is to keep concept-prover and old fp-check as separate
plugins and take from this branch only what measurably helped: the layer gate's
ordering fixes, the `applies` schema, and the eval-suite invariants.

**Do not keep the merge because it took a long time to build.**

## 4. Traps that have each cost real money

| Trap | Consequence |
|---|---|
| Targeting by **path** instead of name | Skill never activates. `Skill 0 / Workflow 0`; the run is a baseline with a plugin installed |
| Installed cache ≠ working tree | You grade the previous version. `diff -r` proves it; the version must be bumped and the plugin reinstalled |
| Not naming PoC/online in a case prompt | Non-interactive harness has nobody to ask; both defaults are **no**, so the sweep measures Stage 1 and reads as all three stages |
| A grader demanding a false fact | Six correct runs scored 0 because a grader wanted `net/http` to return HTTP 500. **Six runs disagreeing with a grader is the signal to re-read the grader** |
| A grader passable by the plugin's own vocabulary | `names-the-integration-root-cause` accepted the bare token `integration`, which `capSeverity`'s note contains. 0 of 18 baseline runs ever emitted it. Fixed, but the class recurs |
| Running the mutation gate during a sweep | Contention made a mutation's baseline check fail and read as a coverage gap |

## 5. Known gaps — inherit these, do not rediscover them

1. **Layer 3 does not run.** The capture records `concept-prover:verify-attack-path`;
   `test_regrade.py` skips on a condition it checks, and **12 mutations are
   deferred** behind it. One paid capture (`tests/capture-runs.sh`) re-arms both.
2. **Stage 2 (online) has never run in a graded run** — all seven prompts pin
   offline. It needs its own suite built on real public findings, where ground
   truth is free because it is public record. Never mix it into the 7-case numbers.
3. **Three capabilities did not survive the merge**, each now pinned by a live
   guard in `tests/coverage.test.mjs` that fails if anyone claims otherwise:
   - **batch triage** — every workflow takes one `finding`; the batch is the
     orchestrator's loop with no gate behind it. The description advertises
     scanner/agentic triage, which is inherently batch work
   - **the exploit-chain check** — "two `NOT_EXPLOITABLE` results whose blocking
     layers differ" is a comparison no workflow can make. This is a false-negative
     guard, which makes it the more dangerous loss
   - **online-triage's downstream-users census** — the only role in any parent that
     produced evidence about the world rather than the project. Brocard 5's nuance
     still raises a question Stage 2 can no longer answer
   Also gone and not deliberate: the **negative PoC** and the always-required
   **pseudocode PoC**. The hooks and the three agent definitions *were* deliberate.
4. **19 mutations owed to `mutation-gate.sh`** — 10 from the eval-suite invariants,
   9 from the Stage 3 degraded mode. All are proven in sandbox; the selectors are
   recorded in `tests/README.md`. Three of the nine mutate SKILL.md, which no
   existing mutation does, so `run_mutation` will need to checksum it.
5. **`baseDir` is model-supplied and nothing validates it.** SKILL.md now says to
   copy it from the expanded reference links and never reconstruct it, but a wrong
   value still fails silently — every reference read in all three stages resolves
   to nothing. A cheap guard (reject a non-absolute path, or one not ending
   `skills/fp-check`) would have caught the traced `2.0.1`-vs-`2.0.2` guess.

## 6. Housekeeping if you install the plugin

Adding this worktree as a marketplace **replaces** the `trailofbits` entry, which
normally points at `/Users/gros/ToB/tools/tob/skills`. Restore it when done:

```bash
claude plugin uninstall fp-check@trailofbits
claude plugin marketplace add /Users/gros/ToB/tools/tob/skills
```

## 7. Reading order

| File | Why |
|---|---|
| [tests/README.md](tests/README.md) | The most valuable file here. Every invalid sweep, every grader that measured nothing, what each gate enforces |
| [tests/coverage.test.mjs](tests/coverage.test.mjs) | Which parent mechanism is present, reachable, and observed firing |
| `git log --oneline origin/main..HEAD` | Ten commits, each one measurable on its own |
| [skills/fp-check/SKILL.md](skills/fp-check/SKILL.md) | The dispatch contract you will be reading anyway |

**One last warning.** Five of seven paid sweeps in this plugin's history were
invalid, and **every one produced a plausible-looking number**: tools denied,
workflows never dispatched, a usage limit mid-run, graders demanding falsehoods, a
grader passable only by the plugin's own vocabulary. The summary JSON looked fine
in all five. Check the per-run errors and confirm the pipeline dispatched **before**
you believe any delta.
