# Handoff: measure fp-check 2.5.0, then decide whether the merge is worth keeping

**Written 2026-08-07.** You are picking up a plugin that has been measured twice
and beaten its baseline neither time. Everything free is green, §1 has landed, and
**the probe in §2.1 has now been run four times — most recently against 2.3.0,
where it failed and found why `integration-cap` loses all 3 points.** That fix is
2.4.0. The first job is to re-run the probe against it; the second is the sweep.

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
> caught something that would have wasted the sweep. Run it again before §2.2 —
> the same command, the same four checks.
>
> **Then it was run again on 2.3.0, and failed again** — on a different mechanism,
> and this time on the dispatch contract rather than a gate. `missingArgs` rejected
> `layers: []`, so on a fixture with nothing validating the path the orchestrator
> did as its message instructed and passed the ABSENCE of a check as a layer. The
> agent asked to rule on it returned `BLOCKS` with the reason *"I labeled this
> BLOCKS meaning the payload is NOT blocked/validated"*, the finding died before
> the impact agent, and the orchestrator discarded the workflow and reported its
> own uncapped Critical. **$5.10.** Full trace in [tests/README.md](tests/README.md).
>
> **Then 2.5.0 removed the brocard pre-gate entirely**, and `integration-cap`
> scored **1.000** on the next probe — its first ever pass. The four brocard
> agents are guidance in `references/dismissal-grounds.md` now. The cause was not
> which brocard fired: a cheap agent asking a question the fixture cannot answer
> poisons every gate downstream of it, and three probes spent on reordering them
> changed nothing. **The cheap path is no longer cheap** — every finding pays the
> full fan-out — and that trade is the one thing the sweep should be read for.
>
> **The version is 2.5.0.** Layer verdicts are `PAYLOAD_REACHES_SINK` /
> `PAYLOAD_STOPPED_HERE` and deep-route proofs `FINDING_SURVIVES` /
> `FINDING_REFUTED`; `layers: []` is dispatchable with `layersSearched`. The
> `diff -r` in §2.1 is what catches you grading an older build from the cache.

Read this file, then [tests/README.md](tests/README.md) — that one records every
dead end this plugin has been down, including **five paid sweeps that were invalid
and each produced a plausible-looking number.** Do not skip it.

---

## 0. State in one table

| | |
|---|---|
| Version | **2.5.0**, branch `fp-check-triage-merge` in a worktree off `origin/main` |
| Free layers | 313 node + 364 pytest + 36 bats, all green |
| `make check` | passes except `python-tests`, which fails in `constant-time-analysis` for want of an aarch64 cross sysroot CI installs — **pre-existing, not this branch** (verified on a stashed tree) |
| Mutation gate | **128 run, 0 survived, 0 stale, 12 deferred** |
| Measured | v1 (2026-08-06) mean delta **+0.170**; v2 (2026-08-07) **+0.151** |
| Target to beat | concept-prover's **+0.170**, and 3/3 on `already-fixed`, `integration-cap`, `blocked-attack-path` |
| Verdict so far | **has not beaten its baseline.** concept-prover is NOT retired |

## 1. ~~First job: build the downstream-users census~~ — DONE in 2.3.0

**Built. The first job is now §2.1, the probe, against 2.4.0.** Everything below is the record of
what was asked for; the acceptance list is met and the numbers in §0 are stale by
one version. What landed, and the two places it departs from the sketch, is in
[TODO-batch-and-users.md](TODO-batch-and-users.md) item 2 — read that rather than
re-deriving it from this section.

Two departures worth knowing before you touch Stage 2: the reachability agent has
its own `REACHABILITY_SCHEMA` now (it had `SCOPE_SCHEMA`, which required a policy
verdict and clause its prompt never asked for and nothing read), and a census that
cannot reach the network is **reported unperformed rather than halting the stage**,
which is `unsearched`'s shape rather than `offlineProblem`'s. The thing the
instruction protected against — a census that searched nothing reading as "no
users affected" — is prevented by `censusProblem` and by the summary wording.

**Do this before the sweep, and do not expect it to change the sweep.** Those two
statements are both important and they are not in tension — see "what this will
not do" below.

The capability is item 2 of [TODO-batch-and-users.md](TODO-batch-and-users.md);
read that section for the four options and why the recommendation is what it is.
The decision is already made, so you are implementing, not designing:

> **Option C — gate it in code on what Stage 2 already knows.** Not a third
> question at Step 0.

### Why C and not a question

Whether severity depends on downstream usage is a **finding of the reachability
analysis**, not something the user knows when they start. And §5.1a of the
original handoff is emphatic: every extra question is one more thing a
non-interactive harness silently defaults to `no`, so a third toggle would mean
the census never runs in any graded run — which is the failure mode this plugin
has now produced three separate times (`capSeverity`, `upstreamFixStands`,
`decideVerdict`, 0 firings each across 63 runs). Three toggles is also eight
configurations, and the suite already struggles to attribute two.

### What to build

In `workflows/triage-online.js`:

1. **`needsUserCensus(verification, reachability, scope)`** — pure, unit-tested,
   inline (a module const cannot be extracted by `loadFn`; see the same constraint
   on `selectRoute`'s keyword list). It should return true when the bug requires an
   unsafe usage by a client rather than being directly exploitable in the target:
   an `integration` or `external` root cause, a `hardening_gap` in an exported
   surface, or a reachability finding that no in-repo caller drives the sink — and
   the scope verdict is not `out-of-scope`.
2. **A census agent**, dispatched only when that returns true. Its job is the
   parent's: derive the client-side pattern from the reachability findings, find
   the popular public consumers, and keep only **confirmed** hits — a real
   occurrence with a link and enough context to tell it from a string match.
3. **A schema with `result` as an enum** (`no-confirmed-users` /
   `affected-users-found`), the queries actually run, and the coverage. Absence of
   hits is **not** proof no users are affected, and the summary must not read it
   that way.
4. **Log the skip and why.** A silent skip is how `beyondCap` went wrong; that bug
   is already in this file's §5.

### Make it fail closed

The rule this stage already lives by: no claim about the world without having
looked. If the census runs and cannot reach the network, that is the same halt
`offlineProblem` already implements — do not let it degrade into "no users found".

### Acceptance

- `tests/online.test.mjs` — unit tests for `needsUserCensus` on both sides, plus a
  `runScript` test proving the agent is dispatched when it should be and **not**
  when it should not.
- `tests/coverage.test.mjs` — flip the guard
  `[online-triage] the downstream-users census is absent and unadvertised` to
  exercise the capability instead of pinning its absence. **The test tells you so
  itself**, in its own assertion messages.
- `references/brocards.md` line ~119 says outright "Stage 2 has no
  downstream-consumer census". Update it, and close brocard 5's loop while you are
  there: its nuance says downstream usage violating documented guidance is a valid
  finding **against the downstream project**, and until now Stage 1 raised a
  question Stage 2 could not answer.
- `meta.description` may advertise it again **only once the agent exists** — the
  coverage guard fails if you re-advertise without implementing.
- Bump to **2.3.0**: new capability, and `plugin.json` and `marketplace.json` must
  agree or the validator fails.

### What this will not do

**It will not move a single number in the 7-case suite.** Stage 2 has never run in
a graded run — all seven prompts pin "work offline", and the suite cannot measure
it: its premise is public evidence the synthetic fixtures do not have, and its own
rule is to stop when offline, so the correct behaviour would score zero.

That is precisely why it goes first. Doing it *after* the sweep would mean the
measured artifact is not the shipped one; doing it before means the sweep grades
the final shape. Do not let anyone read a flat sweep result as evidence the census
did not work — it is not in the measurement's reach at all. Measuring Stage 2 needs
its own suite on **real public findings**, where ground truth is free because it is
public record and a `GHSA-` id cannot be guessed (§6).

## 2. Then measure — but not before §1 is done

Two steps, in order. §1 has landed and **the probe has now been run against 2.3.0
and failed**, so 2.4.0 is what needs re-probing. The first step is free.

### 2.1 Trace probe (~$5, 16 min) — this is not optional

Four probes, four real defects, four saved sweeps. **The 2.3.0 one cost $5.10 and
found why `integration-cap` loses all 3 points**, which no amount of reading had
turned up: `missingArgs` rejected `layers: []`, so on a fixture with no validation
anywhere the orchestrator did as its message instructed and passed the ABSENCE of
a check as a layer; the agent asked to rule on it answered `BLOCKS` with the reason
*"I labeled this BLOCKS meaning the payload is NOT blocked"*; the finding died
before the impact agent; the orchestrator discarded the workflow and reported its
own uncapped Critical. The full trace is in
[tests/README.md](tests/README.md) under "The 2.3.0 probe". Both defects are fixed
in 2.4.0 — the verdict enums now name their subject, and checkpoint 2.2's "or
confirmed none exist" is reachable via `layersSearched`.

**Re-probe 2.4.0 before the sweep.** The fix is exactly the kind that either works
or moves the failure one step along, and $5 is the cheapest way to find out.

```bash
export CLAUDE_CODE_WALNUT_SPIRE=1
claude plugin marketplace add /Users/gros/ToB/tools/tob/skills-wt-fp-check
claude plugin install fp-check@trailofbits
diff -r ~/.claude/plugins/cache/trailofbits/fp-check/2.5.0 plugins/fp-check   # MUST be empty
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
| `severityCorrection` appears **in a result, not in source text** | **The whole point of this run.** `capSeverity` has fired **0 times in 64 measured runs**. On the 2.3.0 probe all 8 hits were in the workflow source the agent had read — grep the trace for the value, not the word |
| No layer names the absence of a check | The 2.3.0 failure. A `layers[]` entry whose description says "no validation exists" means the orchestrator is still reading a stale contract |
| The final answer says Medium, not Critical | `integration-cap` is the 3-point loss |

`integration-cap` is the probe case deliberately: it is the single biggest
shortfall, and 2.4.0's changes are aimed straight at the mechanism that was losing
it.

### 2.2 The sweep

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

### 2.3 Before you read any aggregate

```bash
uv run --no-project python plugins/fp-check/tests/validate_eval_result.py /tmp/sweep/result.json
```

`partial: false` does **not** mean clean. One sweep lost 22 of 30 runs to a usage
limit, still reported `partial: false` and `runsPerCase: 3` for every case, and a
**+0.47** on a case whose entire baseline arm was dead. Check per-run `error`
fields and no-answer runs (`judgeVotes: null` with empty evidence) yourself.

Report the mean **both ways** — as the CLI computes it, and excluding ungradeable
runs. Quote the per-case table, never the mean alone.

## 3. What changed in 2.2.0/2.2.1 and what it should do

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

## 4. How to read the result

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

## 5. Traps that have each cost real money

| Trap | Consequence |
|---|---|
| Targeting by **path** instead of name | Skill never activates. `Skill 0 / Workflow 0`; the run is a baseline with a plugin installed |
| Installed cache ≠ working tree | You grade the previous version. `diff -r` proves it; the version must be bumped and the plugin reinstalled |
| Not naming PoC/online in a case prompt | Non-interactive harness has nobody to ask; both defaults are **no**, so the sweep measures Stage 1 and reads as all three stages |
| A grader demanding a false fact | Six correct runs scored 0 because a grader wanted `net/http` to return HTTP 500. **Six runs disagreeing with a grader is the signal to re-read the grader** |
| A grader passable by the plugin's own vocabulary | `names-the-integration-root-cause` accepted the bare token `integration`, which `capSeverity`'s note contains. 0 of 18 baseline runs ever emitted it. Fixed, but the class recurs |
| Running the mutation gate during a sweep | Contention made a mutation's baseline check fail and read as a coverage gap |

## 6. Known gaps — inherit these, do not rediscover them

1. **Layer 3 does not run.** The capture records `concept-prover:verify-attack-path`;
   `test_regrade.py` skips on a condition it checks, and **12 mutations are
   deferred** behind it. One paid capture (`tests/capture-runs.sh`) re-arms both.
2. **Stage 2 (online) has never run in a graded run** — all seven static prompts
   pin offline. **The suite it needs now exists in one case and has NOT been run:**
   `online-known-duplicate`, tagged `online`, against a real published advisory in
   python-dotenv where the deterministic grader keys on a `GHSA-` id that cannot
   be guessed. Authored 2026-08-07; invariants green; **no measurement attached,
   and it must not be quoted as if it had one** until it discriminates at n=3.
   The two suites are separated by `--tag` and three invariants enforce it — see
   "The online suite" in [tests/README.md](tests/README.md). Never mix the means.
3. **Two capabilities did not survive the merge** — three, until 2.3.0 closed the
   census — each pinned by a live guard in `tests/coverage.test.mjs` that fails if
   anyone claims otherwise:
   - **batch triage** — every workflow takes one `finding`; the batch is the
     orchestrator's loop with no gate behind it. The description advertises
     scanner/agentic triage, which is inherently batch work
   - **the exploit-chain check** — "two `NOT_EXPLOITABLE` results whose blocking
     layers differ" is a comparison no workflow can make. This is a false-negative
     guard, which makes it the more dangerous loss
   - ~~**online-triage's downstream-users census**~~ — **closed in 2.3.0.** The
     only role in any parent that produced evidence about the world rather than
     the project. Its coverage guard now exercises the capability rather than
     pinning its absence, and three mutations cover the gate
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

## 7. Housekeeping if you install the plugin

Adding this worktree as a marketplace **replaces** the `trailofbits` entry, which
normally points at `/Users/gros/ToB/tools/tob/skills`. Restore it when done:

```bash
claude plugin uninstall fp-check@trailofbits
claude plugin marketplace add /Users/gros/ToB/tools/tob/skills
```

## 8. Reading order

| File | Why |
|---|---|
| [tests/README.md](tests/README.md) | The most valuable file here. Every invalid sweep, every grader that measured nothing, what each gate enforces |
| [tests/coverage.test.mjs](tests/coverage.test.mjs) | Which parent mechanism is present, reachable, and observed firing |
| [TODO-batch-and-users.md](TODO-batch-and-users.md) | §1's design rationale, and the batch/exploit-chain workflow that is the job after the sweep |
| `git log --oneline origin/main..HEAD` | Ten commits, each one measurable on its own |
| [skills/fp-check/SKILL.md](skills/fp-check/SKILL.md) | The dispatch contract you will be reading anyway |

**One last warning.** Five of seven paid sweeps in this plugin's history were
invalid, and **every one produced a plausible-looking number**: tools denied,
workflows never dispatched, a usage limit mid-run, graders demanding falsehoods, a
grader passable only by the plugin's own vocabulary. The summary JSON looked fine
in all five. Check the per-run errors and confirm the pipeline dispatched **before**
you believe any delta.
