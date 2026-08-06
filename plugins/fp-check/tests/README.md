# fp-check tests

**Read this first, because it changes how to read everything below.** Every
measured number in this file was produced by `concept-prover`, the plugin
fp-check was merged from. Those runs graded `verify-attack-path.js`,
`build-poc.js` and `review-poc.js`; this plugin ships `triage-static.js`,
`triage-online.js` and `triage-poc.js`, and the gates were ported rather than
copied. The history is kept **unrewritten and attributed to the scripts that
produced it** — editing a recorded result to name today's files destroys the only
thing it is evidence of, and turns a baseline into a claim.

So: the *operational* sections (the commands, the flags, the traps) apply to
fp-check now and have been re-pointed. The *measured* sections describe
concept-prover, and the numbers in them are the baseline the merged plugin has to
beat — see `tests/fixtures/eval-result-*.json`, which are checked in for exactly
that purpose. **fp-check has not been measured yet.** When it is, add its sweep
below rather than amending theirs.

Two things follow from the merge and are not yet closed:

- **Layer 3 does not run.** The checked-in capture is a recording of
  `concept-prover:verify-attack-path`. `test_regrade.py` skips on a condition it
  checks, with a zero-guard test that fails the build if anyone promotes a new
  capture without re-pointing the constants. Re-capturing costs one paid run.
- **Stage 2 (online) has no eval case and cannot get one from this suite.** Its
  premise is public evidence these synthetic fixtures do not have. See §"Do not
  point this suite at the online stage".

---

Four layers. Three are free and run in CI; only the Layer 3 capture and the
Layer 4 eval cost money.

| Layer | What it covers | Cost | In CI |
|-------|----------------|------|-------|
| 1 — contract | The shipped workflow scripts: parse, `meta`, phases, a schema on every `agent()`, banned non-determinism, fan-out caps | free | yes |
| 2 — logic | The deterministic JS extracted from those scripts: gate decisions, tallying, build acceptance | free | yes |
| 2b — wiring | The whole script body, run against scripted agents: does it *act* on what the helpers decide | free | yes |
| 3 — regrade | Every assertion re-scored against a saved run | free after one capture | yes |
| 4 — eval | The skill wrapper end to end, with an ablation baseline | paid | no |

**Layer 2b exists because Layer 2 was not enough.** Every pure helper was
covered; none was covered *where it is used*. A review disabled twelve call
sites — the `gate.status !== 'PROCEED'` halt, the `impact.result !== 'VERIFIED'`
halt, `isAcceptableBuild`, `alreadyFixedStands`, the confidence band, the
severity cap — and the entire free suite stayed green. Twenty assertions about
`decideGate` could not tell you whether its answer was ever read.
`runScript()` in `extract.mjs` wraps the script body in an async function (the
same trick `test_script_parses` uses for `node --check`) and injects fakes for
`agent`, `parallel`, `phase` and `log`, so `wiring.test.mjs` scripts what each
stage answers and asserts on the status that comes back.

```bash
make check                                       # layers 1-3, what CI runs
make workflow-tests                              # just the node --test half
node --test plugins/fp-check/tests/*.test.mjs
bash plugins/fp-check/tests/mutation-gate.sh   # the gate; see below
```

## Layer 2: what is and is not covered

Workflow scripts have no module system, so pure helpers are defined inline and
`extract.mjs` pulls them out of the source text. `loadFn` throws when a function
is missing — a renamed helper fails loudly rather than silently testing nothing.

Covered: `missingArgs` (three copies), `selectRoute`, `triageBrocards`,
`upstreamFixStands`, `decideGate`, `missingPrecondition`, `capSeverity`,
`decideVerdict`, `selectAttempts`, `isAcceptableBuild`, `artifactProblem`,
`tallyChallenges`, `alreadyFixedStands`, `confidenceBand`, `reportProblem`,
`severityCapViolation`, `offlineProblem`, `scopeHalt`, `summaryProblem`.

`loadFns()` exists because `decideGate` calls `upstreamFixStands`: `loadFn`
evaluates one function alone, so a call to a sibling is a ReferenceError, and the
workaround was to inline the sibling's logic at both call sites. Duplicated logic
in a gate is exactly the drift this suite exists to catch, so the harness gives
way instead of the code.

A helper that reads a module-level `const` cannot be extracted at all, which is
why `selectRoute`'s keyword list, `isAcceptableBuild`'s field list and
`missingArgs`' actionable-status list are all inline. That is a real constraint
the scripts are written around, not an oversight.

**Not applicable to this plugin:** the dedup-against-SEEN and
"N consecutive rounds with nothing new" stop-condition cases. There is no
loop-until-dry stage — the only loop is the PoC stage's bounded retry over at
most `MAX_ATTEMPTS` candidate paths, and that termination *is* tested. No
loop-until-dry logic was invented to satisfy a test.

`tallyChallenges` is the closest analogue and carries the equivalent bug class:
it tallies against the **expected** challenge list, not against whatever came
back. Tallying the returned array instead would let a dead agent shrink the
denominator and silently raise confidence — a result vanishing from the
accounting rather than counting against the finding.

## Layer 3: capture once, regrade forever

```bash
# One capture, promoted to the checked-in fixture:
bash plugins/fp-check/tests/capture-run.sh

# N runs with a pass RATE, each regraded independently (this is the one to use):
RUNS=3 PROMOTE=1 bash plugins/fp-check/tests/capture-runs.sh ./out

# Free, offline, against the saved fixture:
uv run --with pytest --with jsonschema --no-project \
  pytest plugins/fp-check/tests/test_regrade.py
```

`capture-runs.sh` does not stop early on a failure and does not retry until
green — a 2/3 is a result. `--fixtures-dir` regrades any single run of a batch.

**`scrub_capture.py` must not destroy evidence.** A greedy path rule once
replaced an agent's whole `location` with `/SCRATCH`, taking `search.py:27` with
it; the regrade then failed and read as model variance when the plugin had been
correct. `test_scrub.py` pins both halves: identity removed, repo-relative
`file:line` preserved.

**Three assertions in `test_regrade.py` are pinned to the fixture's prose, not
to the plugin**: the `len(evidence) > 80` length floor, the `\bterm\b` search,
and `effectiveImpact.startswith("none")`. Against a frozen fixture they cannot
flake, but they also cannot catch a regression — they only move when the capture
is retaken, at which point they will need rewriting. If one of them fails after
a recapture, that is model variance in the new recording, not a plugin bug.

All stream-format knowledge is quarantined in `stream.py`. No other module
indexes a raw event dict, so a format change breaks one file. `journal.jsonl` is
**not** a documented interface and is isolated behind `Capture.journal_returns`.

`capture-runs.sh` creates the throwaway git worktree itself and refreshes the
fixtures into it on every run — workflow subagents always run `acceptEdits`
regardless of session mode, so file edits are auto-approved and must not land in
your checkout. `capture-run.sh` is now a thin `RUNS=1 PROMOTE=1` wrapper around
it. It used to be a second implementation of the same capture and corrupted the
checked-in fixtures every time it ran: it wrote an unscrubbed stream straight
into `tests/fixtures/`, recorded `"passed": null` (which `test_regrade.py`
asserts against), never wrote `run.journal.jsonl` at all, and echoed
`CAPTURE_MODEL`/`CAPTURE_EFFORT` into the metadata without ever passing them to
`claude`. `CAPTURE_MODEL` is now applied via `--model` before it is recorded;
`CAPTURE_EFFORT` is rejected, because `-p` has no effort flag and recording it
would fabricate provenance.

Promotion requires run 1 to have **passed**, not merely to have produced a
journal — otherwise a failing run 1 alongside passing runs 2–3 became the
checked-in fixture.

**The fixture is a real recorded run** (`synthetic: false`), captured on CLI
2.1.220 for the `blocked-attack-path` case at $1.61. Paths are scrubbed.
`make_synthetic_capture.py` now refuses to overwrite it.

**The capture was taken against the previous `search.py`, and its line numbers
are from that file.** The target's comments have since been rewritten — they
stated the case's own verdict, so both ablation arms scored it by reading rather
than by analysing — and the docstring got shorter, which moved every line below
it. The `search.py:20` / `search.py:27` evidence in the capture, and
`EXPECTED_BLOCKING_LINES` in `test_regrade.py`, therefore describe the file as it
was when recorded: the two blocking checks are now at `search.py:14` and
`search.py:21`. Do **not** renumber the capture to match — it is frozen
provenance, and editing a recorded run to agree with today's source destroys the
only thing it is evidence of.

**A fresh run is graded against derived numbers, not against that constant.**
Pinning both to `EXPECTED_BLOCKING_LINES` was a deadlock: `capture-runs.sh`
copies today's fixtures into the worktree, so every run of a new batch would be
scored against `:20`/`:27`, fail, and never let `PROMOTE` fire — which requires
run 1 to have passed. The constant could therefore only be updated after a
recapture that could never legally happen. So `guard_lines()` locates the two
checks by their code rather than by line number, and the `expected_blocking_lines`
fixture uses the frozen constant for `tests/fixtures` and the derived set for
anything under `--fixtures-dir`. `test_the_guards_can_still_be_located_in_the_current_target`
is the zero guard: `found >= expected` is vacuously true against an empty set, so
a rewrite that broke both patterns would retire the assertion rather than fail it.

The residue is that after a `PROMOTE=1` recapture someone must move
`EXPECTED_BLOCKING_LINES` by hand. `capture-runs.sh` says so, loudly, in a
pre-flight that fails before spending anything if the guards cannot be located,
and again after promotion with the exact edit to make.

Two things the live run corrected in this layer's design:

**Under `-p` the Workflow tool returns on launch.** The session ends at
`num_turns: 1` and the workflow's result never reaches the stream. So the stream
carries the *launch* (namespaced name, no `error`, argument shape) and the
per-stage results come from `run.journal.jsonl`. Assertions are split
accordingly.

**Invoking the skill is a precondition for dispatch.** On the first attempt the
`Skill` tool was denied under default `-p` permissions, the model read `SKILL.md`
by hand, and then correctly refused to call `Workflow` — the opt-in exemption is
"the user invoked a skill whose instructions tell you to call Workflow", and no
skill had been invoked. The capture therefore runs with
`--permission-mode bypassPermissions` (in `capture-runs.sh`, which
`capture-run.sh` now delegates to), and `test_the_skill_was_actually_invoked`
guards the precondition.

## Layer 4: eval

```bash
export CLAUDE_CODE_WALNUT_SPIRE=1
claude plugin eval ./plugins/fp-check \
  --runs 3 --ablation with-without --scaffold \
  --allow-tools Bash Write Skill Workflow Task TaskCreate TaskUpdate TaskList TaskGet \
  --model sonnet --judge-model sonnet \
  --output-dir /tmp/fp-eval --json /tmp/fp-eval/result.json
uv run --no-project python plugins/fp-check/tests/validate_eval_result.py out.json
```

Every flag above is load-bearing, and three of them were learned by paying for a
run that measured the harness instead of the plugin:

- **`--ablation with-without`** defaults to `with-without` only for a plugin
  *name* target; for a **path** target it silently defaults to `none` and you
  get no baseline.
- **`--scaffold`** runs each case's `scaffold_script`. Without it the case runs
  in an empty directory: the eval does **not** run in your repo, so a
  repo-relative path in a prompt resolves to nothing. The first full run scored
  0 with the agent reporting "the target doesn't exist" — correct behaviour,
  zero information.
- **`--output-dir` outside the repo.** The default is
  `./evals/results/<timestamp>/`, which writes machine-absolute paths into the
  plugin tree; the metadata validator then fails on a hardcoded user path.
- **`--allow-tools Bash Write Skill Workflow`** is an *operator* grant.
  Listing them in the case's `allowed_tools` is not enough; gated tools stay
  denied. Without the grant the with-plugin arm cannot produce executed output,
  the skill correctly refuses to finish, and the LLM judge scores that refusal
  as a failure.

  **Every gated tool, not just the ones you remember.** The first attempt at
  this fix granted only `Bash Write` and would have invalidated the re-run for
  exactly the reason it was meant to fix: `Workflow` is gated too, and without
  it the skill cannot dispatch a single phase, so the with-plugin arm degrades
  to a plain session and the ablation measures nothing. `Skill` is granted for
  the same reason — a skill that never activates makes the with-plugin arm
  identical to the baseline by construction.
  `test_the_documented_eval_command_grants_every_tool_the_cases_need` pins the
  documented command against what the cases declare, so this cannot drift
  again.

**Editing the working tree does not change what runs.** Even for a marketplace
whose source is a local `directory`, the plugin is installed into a
version-pinned cache at
`~/.claude/plugins/cache/<marketplace>/<plugin>/<version>/`, and both the `Skill`
tool and `Workflow`'s namespaced `fp-check:<name>` form load from there.
Confirmed the hard way: a dispatch made after all of the fixes below ran the
*previous* version's script. To run edited code:

```bash
claude plugin marketplace update trailofbits-internal
claude plugin update fp-check@trailofbits   # needs the version bumped
```

`plugin update` reports "Restart to apply changes", and it means it — an
in-flight session keeps dispatching the old copy by name until it restarts. To
exercise edited scripts *without* restarting, dispatch by path instead of by
name, which bypasses the cache entirely:

```
Workflow({ scriptPath: 'plugins/fp-check/workflows/triage-static.js', args: {...} })
```

Check which copy actually ran: every invocation persists its script under the
session's `workflows/scripts/` directory, so `diff` that file against the
working tree before trusting a result.

**Target the working tree (`./plugins/fp-check`), not the plugin name.**
A name target resolves to the *installed* copy under
`~/.claude/plugins/cache/`, which is a snapshot taken at install time. Editing
the clone does not update it — the version has to change and the plugin be
reinstalled. Running the eval by name therefore silently grades whatever was
installed, which during this work meant the pre-fix scripts and the old
`prompt.md` eval format. The same applies to invoking the skill interactively.

Cases use `case.yaml`, not `prompt.md` + `graders/`: only `case.yaml` carries
`context.scaffold_script`, and `scaffold_script` is a **path** relative to the
case directory — passing the script body fails with `ENAMETOOLONG`.

| Case | Deterministic pairing |
|------|----------------------|
| `blocked-attack-path` | `regex` (weight 2) requiring the blocking validator be named **in the final answer**. The two `file_exists` graders were removed on 2026-08-04 — see below |
| `inflated-impact` | `regex` requiring the impact be scoped to one connection with the process surviving, `regex` requiring the recovery mechanism be named — both **in the final answer**. Was "the 500 downgrade" until 2026-08-04; net/http returns no 500, so that grader demanded a falsehood. Its replacement then failed 6/6 twice for a *different* reason and was rewritten on 2026-08-06 — see §"The same grader, wrong three times" |
| `should-not-fire` | `tool_used` with `min: 0, max: 0` on Workflow |
| `integration-cap` | `regex` for the balance credited at qty=125, `regex` for the integration root cause — both **in the final answer** |
| `already-fixed` | `regex` for `#412`, plus `tool_used` Bash `min: 1` |
| `dead-route` | `regex` (weight 2) requiring the routing table or the absence of a caller be named **in the final answer** |
| `wrong-parameter` | `regex` (weight 2) requiring the two subprocess call sites be told apart **in the final answer** |

### The two cases that are supposed to reach PROCEED

The first three cases all terminate at or before checkpoint 2.4, which meant
`verify-attack-path` never returned `PROCEED` and **Phases 4, 5 and 6 ran zero
times in the graded suite**: the five independent challenges, the artifact
re-check, `confidenceBand`, `tallyChallenges`, `alreadyFixedStands`,
`severityCapViolation` and `missingPrecondition` — more than half the plugin,
including the mechanism the README calls the flagship — were covered only by the
free layers, never end to end. `integration-cap` and `already-fixed` exist to
carry a finding past that gate.

**`integration-cap`** is a real bug reported at the wrong severity. `charge()`
multiplies an unvalidated rate from the pricing service into an integer cent
amount and passes it to `ledger.debit`, which subtracts it — so a negative rate
credits the account. The correct outcome is a built, executed PoC *and* a Medium:
the attacker does not control the rate, so the root cause is `integration`, the
external precondition has to be stated (`missingPrecondition`, checkpoint 2.4b)
and the severity is capped (`severityCapViolation`, checkpoint 5.2). `charge()`
is deliberately awkward to call — it takes a `BillingContext` built by a factory
that reads two environment variables — so inlining a copy of the arithmetic is
the tempting shortcut and poc-lint rule 6 has something to bite on.

**`already-fixed`** is the only case that can be retracted *after* an exploit has
been built, which makes it the cheapest discriminator in the suite. The
researcher's line is real and is unchanged at HEAD, but `#412` fixed it one layer
up: the caller now reduces both the presented and the stored token to a keyed
HMAC digest, so the `==` runs over two fixed-length digests. Nothing in the sink
file says so. The evidence is in the commit and the CHANGELOG, which is why
`#412` is a usable deterministic grader — a run that never looked at the history
cannot emit it.

**Three scaffolds commit their tree, and that is load-bearing.** `build-poc`
runs its builder with `isolation: 'worktree'`, and a git worktree is cut from
HEAD: a file left uncommitted in the scaffold directory is simply absent from
the directory the builder works in.

`should-not-fire` and `blocked-attack-path` halt before Phase 4 and so never
needed a repository. `inflated-impact` was grouped with them and should not have
been: its panic is real, reachable and in scope, so the gate returns `PROCEED`
and only the *severity* is corrected downward — it reaches Phase 4 like the
other two, and both of its graders read `last_message`, so a build that failed
for want of a repository would not have shown up in the score.

**`integration-cap` carries no `file_exists` grader, deliberately.** The same
worktree isolation puts the PoC outside the eval's working directory, so a
positively-phrased `file_exists` ("a PoC was written") fails the plugin for
having done the right thing. The negative form is still sound and
`blocked-attack-path` still uses it.

Both prompts end with an instruction to state the verdict in the final response.
Without it the plugin's substance lands in `finding-<slug>.md` next to the PoC —
which is where checkpoint 6.1 tells it to put the report, and which no grader can
read.

**A regex grader over the `trace` is usually vacuous.** Both of the ones here
were: `cites-blocking-layer` matched `ALLOWED_TERM` and `_dispatch_search`, and
`names-the-recovery` matched `conn.serve` and "net/http … recover" — all of
which were literal text in the scaffolded target. The trace carries tool results,
so *opening the file* satisfied both, and both passed 6/6 across the with- and
without-plugin arms while contributing exactly nothing to the delta. They now
target `last_message`, which asserts the conclusion rather than which files were
read, and `test_no_regex_grader_is_satisfied_by_the_scaffold_alone` fails any
future grader written the old way.

**The targets no longer state their own verdicts.** Each of the three opened with
a header comment giving the answer away: `ledger.py` announced "a genuine,
reachable bug" in the case whose whole point is that no security review should
start; `search.py` explained that the SQL concatenation "LOOKS injectable but is
not reachable" and cited *Checkpoint 2.2*; `handler.go` stated that the correct
write-up was "a Low/Medium availability issue … not a Critical DoS". Both arms
could reach a passing answer by quoting a comment, and two of the three coached
the no-plugin baseline on the plugin's own methodology. The code is unchanged —
the bugs are exactly as findable as before — but the comments are now the ones a
developer would have written. `test_target_does_not_state_its_own_verdict` greps
each target for verdict and machinery markers (`checkpoint`, `reachable`,
`false positive`, `severity`, `Low/Medium`, `Critical`, `DoS`, `layer N`, …), and
`test_the_giveaway_scan_still_catches_what_it_was_written_for` replays the
pre-fix headers through the same scan so the marker list cannot rot into a
no-op.

Two graders got stronger for free. `names-the-recovery` and `downgrades-to-a-500`
both asked the model for facts — `conn.serve`, the 500 — that `handler.go`'s own
header comment supplied verbatim, so even over `last_message` they could be
satisfied by copying. They now require the model to know how `net/http` handles a
handler panic.

> **Struck, 2026-08-04.** Half of that was wrong. `conn.serve` is a real fact;
> **the 500 is not** — net/http closes the connection and writes no status. The
> grader therefore required a falsehood and scored 0/3 in both arms, and the
> `outcome` criteria stated the same error. Both are fixed and the regex is now
> `downgrades-to-connection-scoped`. Details below under
> "`downgrades-to-a-500` asks for a fact that is not true". Getting a grader to
> demand a *specific* fact is only an improvement if the fact is true, and
> nothing in the free layers can check that — six independent runs disagreeing
> with a grader is the signal to re-read the grader.

**`blocked-attack-path`'s two `file_exists` graders were deleted on 2026-08-04,
and the reasoning generalises.** The stated limit used to be that `build-poc`
runs its builder with `isolation: 'worktree'`, so a pipeline-built PoC lands
outside the working directory where no `file_exists` grader can see it — true,
but they were supposed to still catch the no-plugin baseline. The measured run
showed they catch nothing at all. All six runs, both arms, wrote a PoC into the
working directory; four called it `poc_search_sqli.py` and two
`poc_search_injection.py`; neither matches `test_*.py` or `*ploit*.py`, so both
graders passed 6/6 with the artefact sitting right there.

Widening the pattern to `poc*.py` inverts the bug rather than fixing it. What
those runs wrote was a harness demonstrating that every payload is rejected
before the sink — evidence *for* the case's correct verdict, and not the
"working exploit" the `outcome` criteria forbid. A wider pattern fails all six
runs for doing the right thing.

The general rule: **no filename distinguishes "wrote an exploit" from "wrote a
harness proving there isn't one",** so that judgement cannot be delegated to
`file_exists`. It stays with `outcome`, which already forbids the former.
Constant-pass weight is not harmless either — those 3 of 7 units scored
identically in both arms regardless of behaviour, compressing the very delta the
case exists to produce. `integration-cap` already carries no `file_exists`
grader for a related reason, recorded above.

`test_eval_suite.py` enforces the invariants statically — runs >= 3, an outcome
grader per case rather than only `tool_used`, an LLM grader paired with a
deterministic one, a should-NOT-fire case whose `allowed_tools` still let the
plugin fire, no target that states its own verdict — plus the grader traps
below, each of which cost a full run.

Four were added on 2026-08-06, each of them closing a rule this file already
states in prose and nothing checked. All four were proven to fire by breaking the
input first; the mutations are listed at the end of §"The gate" for whoever
re-points `mutation-gate.sh`.

| test | what it stops |
|---|---|
| `test_no_regex_grader_is_satisfied_by_the_prompt_alone` | The `last_message` twin of the scaffold-echo check. That one inspects only `target: trace` graders, and every regex grader now targets `last_message`, so it inspects **zero graders** and is green by having nothing to look at. Two case comments reason about the prompt-echo trap by hand; this makes it checkable. |
| `test_regex_graders_accept_the_right_answer_and_reject_the_wrong_one` | A grader that can never pass, or never fail. Nothing else in the free suite can establish either half — a pattern that demands a falsehood compiles, has a valid target, and is absent from the prompt and the scaffold. `GRADER_PROBES` keys are compared against the graders on disk, so a new or renamed grader cannot skip it. |
| `test_the_scaffold_writes_nothing_that_is_held_to_no_fixture` | The converse of the byte-identity check. The keys catch an unlisted *case*; a single unlisted *file* was invisible — inlined in the scaffold, shipped to the eval, compared against nothing, and never scanned for a giveaway comment, because that scan reads `evals/fixtures/`. |
| `test_the_deterministic_weight_share_stays_meaningful` | An LLM grader that carries almost all the weight. The pairing invariant only asks that a deterministic grader *exists*; at weight 1 against 9 it exists and decides nothing. `cites-blocking-layer` was raised to weight 2 expressly "so the non-LLM share stays meaningful" — this is that rule as arithmetic. Floor is one third. |

`SCAFFOLD_SOURCES` maps a case to a **list** of (scaffolded path, checked-in
fixture) pairs, and every file a scaffold writes is held byte-identical to its
copy under `evals/fixtures/`. A case that reaches Phase 4 needs a small tree
rather than one file — a caller, a sink, a dependency — because a single-file
target cannot pose the question of whether the PoC drove the real caller or a
copy of it. The keys are also asserted to match the case directories on disk: a
case with no entry would have its targets held to nothing, and the verdict scan
would quietly stop covering it. As of 2026-08-06 all seven scaffolds write
exactly the files they declare, and that is now asserted rather than observed.

### Grader traps

**`tool_used` with `max: 0` needs `min: 0`.** `min` defaults to 1, so `max: 0`
alone asserts the range `1..0`. The plugin correctly called Workflow zero times
and the grader reported *"Workflow called 0x (expected 1..0)"* — a failure, in
both arms, for exactly the behaviour the case rewards.

**`not_contains` on a phrase the right answer must name always fails.** "This is
NOT a process crash" contains "process crash". Assert the positive outcome (the
500) instead of the absence of the wrong one.

**A pattern for the presence of a claim is satisfied by its explicit negation,
and that trap is not confined to graders.** `ONLINE_YES` in `test_eval_suite.py`
listed the bare alternative `go online`, and all seven prompts say *"do not go
online"* — so it matched every case, in the wrong polarity. The assertion is
`yes or no` and `ONLINE_NO` matched too, so the test passed for the right reason
by luck while being unable to tell the two configurations apart; and the
contradiction check that exists for the PoC toggle could not be added for the
online one, because it would have flagged all seven cases. `POC_YES` has the same
latent shape one step out: `POC_NO` contains `do not write (a|an) (poc|exploit)`
and `POC_YES` contains `write (a|the|an) (poc|…|exploit)`, so a prompt phrased
*"do not write a PoC"* would match both and trip a contradiction assertion on a
prompt that is not contradictory at all. No case is phrased that way, which is
the only reason it has not fired. `stage_answers()` now strips the NO phrases
before searching for the YES ones, and the online contradiction check is in.

**A grader keyed on the plugin's own vocabulary measures plumbing, not
reasoning.** `names-the-integration-root-cause` had the bare token `integration`
as its first alternative. That is this plugin's private `rootCause` enum value,
and `capSeverity` emits *"severity lowered from Critical to Medium: a integration
root cause requires an external failure to trigger"* — so relaying that note
passes the grader having reasoned about nothing, while the baseline arm has no
such word to say. Measured across six sweeps: **0 of 18 no-plugin runs ever
emitted it**, and every with-plugin pass sits on a sweep where the pipeline
dispatched. That is the prompt-neutrality rule
(`test_the_workflow_opt_in_is_plugin_neutral`) applied to graders, and nothing
enforced it. Supported rather than proven, because the CLI elides the middle of
each `evidence` string and the deciding text is in there. The token is now
accepted only where it *attributes* — `integration root cause`, `integration
failure`, `integration precondition` — which the cap note still satisfies while a
stray "integration test" does not.

### The same grader, wrong three times (2026-08-06)

`inflated-impact`'s weight-2 deterministic grader has now been wrong in three
different ways, and the third is the instructive one because it looked like the
fix for the second.

| | | measured |
|---|---|---|
| `downgrades-to-a-500` | demanded a fact that is not true | 0/3 both arms — **could never pass** |
| `downgrades-to-connection-scoped` v1 | literal phrasings fitted to 5 recorded runs | 0/3 both arms on the next two sweeps |
| v2 | five semantic branches, emphasis-tolerant seams | 3/3 both arms on the last two sweeps |

v1's own comment claimed it was *"validated against the five clean recorded runs
(5/5 match)"*. It was — and that is not validation, it is memorisation of a
sample. Every subsequent miss was mechanical:

| a later run wrote | v1 wanted |
|---|---|
| the server **process stays alive** | `process (survives\|survived\|is unaffected\|keeps running)` |
| only *that one* connection is torn down | `only (that\|its own\|…) connection` |
| does **not** crash the whole process | `does not crash` |
| the **process does not die** | no branch at all |
| not a full **process kill** | no branch at all |

Two of the five are markdown emphasis landing in the seam between words. **A
literal multi-word phrase is not a safe grader over model prose**: every
inter-word position is a place the model may put `**`, `*`, a backtick or a
hyphen. Both rewritten patterns admit `[-\s*_`]+` at every seam.

Two mistakes made while widening, each caught by regrading rather than by
reading:

- **A bare `only … connection` passes a wrong answer.** "The attacker needs only
  a single TCP connection to crash the server process" is what the *attacker*
  needs, not what is damaged. The branch now requires a demonstrative or
  possessive — `that`, `this`, `their own`, `the attacker's own`.
- **An unbounded filler after a negation inverts the grader.** `not[^.]{0,40}crash`
  passes "this is **not** a false positive: the attacker crashes the server
  process". Filler is capped at three word-only tokens so it cannot cross
  punctuation.

**The discipline, stated as a procedure.** Widen to the semantic family, then
(1) regrade against every recorded answer in `tests/fixtures/`, (2) confirm it
still rejects a set of *wrong* verdicts, and (3) check the prompt and the
scaffold do not satisfy it. Steps 2 and 3 are the ones that catch a widening that
has been fitted to the desired result. The probe corpus from all three is now
checked in as `GRADER_PROBES`, so a future edit that reintroduces literal
matching, or that widens until nothing fails, breaks the free suite instead of a
$30 sweep.

**The regrade is a lower bound and always will be.** The CLI writes each grader's
`evidence` with the middle elided (`[…892 chars elided…]`), so a claim in the
elided span reads as a miss. Three of the four remaining `inflated-impact` misses
are runs that produced no answer at all (`timed out after 900s`, last message
"review-poc is running now — waiting"); the fourth has its survival sentence
inside an elision. For `integration-cap` the elision is load-bearing in the other
direction: the 2026-08-05 with-plugin arm was recorded 3/3 and regrades to 0/3
under *either* pattern, so which alternative fired there cannot be read off the
fixture.

### What this audit found about discrimination (2026-08-06)

Three 2026-08-06 sweeps are checked in and were previously undocumented:

| fixture | CLI | cases x runs | cost | overallScore | meanDelta |
|---|---|---|---|---:|---:|
| `eval-result-2026-08-06-fp-check.json` | 2.1.222 | 7 x 3 x 2 | $21.49 | 0.598 | **+0.008** |
| `eval-result-2026-08-06-fp-check-bap.json` | 2.1.223 | 1 x 3 x 2 | $3.05 | 0.600 | +0.000 |
| `eval-result-2026-08-06-fp-check-v2-7case.json` | 2.1.223 | 7 x 3 x 2 | $31.71 | 0.781 | **+0.170** |

Per-case delta over the three most recent 7-case sweeps (v2 08-06, 08-06, 08-05),
with the count of runs that produced **no answer** in each arm:

| Case | v2 08-06 | 08-06 | 08-05 | mean Δ | no-answer w/wo |
|---|---:|---:|---:|---:|---:|
| already-fixed | +0.72 | +0.28 | +0.50 | **+0.500** | 0 / 4 |
| dead-route | +0.40 | +0.40 | +0.07 | **+0.289** | 0 / 0 |
| integration-cap | +0.00 | +0.00 | +0.67 | +0.222 | 0 / 0 |
| blocked-attack-path | +0.07 | −0.40 | +0.60 | +0.089 | **4 / 0** |
| should-not-fire | +0.00 | +0.00 | +0.00 | **+0.000** | 0 / 0 |
| wrong-parameter | +0.00 | +0.00 | −0.20 | −0.067 | 0 / 0 |
| inflated-impact | +0.00 | −0.22 | −0.44 | −0.222 | 2 / 0 |

**Two cases genuinely discriminate at n=9: `already-fixed` and `dead-route`.**
Both separate on the `outcome` grader in every sweep, in the same direction.

**`should-not-fire` and `wrong-parameter` do not, and neither does
`inflated-impact` after the grader fix.** Per the standard this file already
applies — *a case that cannot separate the arms cannot justify the plugin* — each
is a candidate for the treatment `coerced-to-int` got, and the reasoning differs
per case:

- **`wrong-parameter`**: both graders 9/9 in both arms on the last three sweeps,
  every run in both arms. Nothing about it is broken; the judgement "a list argv
  is not a shell" is simply one a plain session makes. This is the same finding
  the 2026-08-05 sweep recorded as a hypothesis, now confirmed at n=18.
- **`should-not-fire`**: 1.00 vs 1.00 on all three sweeps, both graders 9/9 in
  both arms. It is the cheapest case in the suite (300s, 10 turns) and it is the
  only guard against a plugin that fires on everything, so the argument for
  keeping it is insurance rather than measurement. It should not be counted in a
  mean delta.
- **`inflated-impact`**: before the fix it was capped at 0.667 in both arms; after
  it, `outcome` is 3/3 and the regex is 3/3 in both arms, so it becomes 1.00 vs
  1.00. **The fix raises both arms equally and the delta stays +0.00** — which is
  a finding about the case, not a success. It is kept for now because it holds the
  floor under the impact-downgrade behaviour and because the 0.667 cap was
  corrupting `validate_eval_result.py`'s absolute gate, but it is not evidence
  about the plugin.

**Graders that have never failed, and therefore carry constant weight.** The
README already condemns this for the deleted `file_exists` pair — *"3 of 7 units
scored identically in both arms no matter what happened"* — and three more are in
the same state over the last three sweeps:

| grader | case | weight | last 3 sweeps |
|---|---|---:|---|
| `credited-amount` | integration-cap | 2 of 6 | 9/9 vs 9/9 |
| `distinguishes-the-two-call-sites` | wrong-parameter | 2 of 5 | 9/9 vs 9/9 |
| `no-workflow-launched` | should-not-fire | 2 of 5 | 9/9 vs 9/9 |
| `searched-the-history` | already-fixed | 1 of 6 | 9/9 vs 8/9 |
| `cites-the-missing-route` | dead-route | 2 of 5 | 8/9 vs 9/9 |

None of them is *vacuous* in the `file_exists` sense — each is shown by
`GRADER_PROBES` to reject a wrong answer — so unlike that pair they are a real
floor against regression. But none contributes to a delta either, and
`credited-amount` at weight 2 of 6 dilutes `integration-cap`'s by a third. Left
as measured rather than changed: dropping a grader that can fail is a decision
about what the case asserts, not a defect fix.

**`blocked-attack-path` has a with-plugin reliability problem.** 4 of 9
with-plugin runs on the last three sweeps produced no answer — three 900s
timeouts on the 08-06 sweep and one at the raised 1800s on v2 — against 0 of 9
baseline runs. Its `cites-blocking-layer` grader reads 5/9 with against 9/9
without for that reason alone, not because the baseline names the layer better.
Raising the timeout further is not obviously the fix; the 19% no-answer rate the
2026-08-05 sweep recorded is still live and is a property of fanning out under
`-p`.

### The first run, which measured the harness (CLI 2.1.220)

3 cases x 3 runs x 2 arms, $6.23, 29 minutes.

| Case | with | without | delta |
|------|-----:|--------:|------:|
| blocked-attack-path | 1.00 | 1.00 | +0.00 |
| inflated-impact | 0.61 | 0.78 | -0.17 |
| should-not-fire | 0.60 | 0.60 | +0.00 |
| **mean** | | | **-0.056** |

**This delta does not measure the plugin.** The run predates the `--allow-tools`
grant and both grader fixes, so the with-plugin arm was denied the tools the
skill requires and two graders were scoring the correct behaviour as wrong. It
is recorded because it is what was actually observed, not as evidence about the
plugin.

What it does establish: `blocked-attack-path` is 1.00 in **both** arms, so that
case does not discriminate — a plain session with no plugin handles it just as
well. A case that cannot separate the arms cannot justify the plugin, however
good the finding looks.

### The first valid delta (CLI 2.1.221, 2026-08-04)

5 cases x 3 runs x 2 arms, `partial: false`, $17.90, 81 minutes, run with the
command at the top of this section. Full result checked in at
`fixtures/eval-result-2026-08-04.json` (plugin root and temp paths scrubbed).

| Case | with | without | delta | pass rate with/without |
|------|-----:|--------:|------:|-----------------------:|
| should-not-fire | 1.00 | 0.60 | +0.40 | 3/3 vs 1/3 |
| already-fixed | 0.72 | 0.56 | +0.17 | 2/3 vs 1/3 |
| blocked-attack-path | 1.00 | 0.86 | +0.14 | 3/3 vs 2/3 |
| inflated-impact | 0.78 | 0.78 | +0.00 | 1/3 vs 1/3 |
| integration-cap | 0.67 | 0.72 | -0.06 | 0/3 vs 0/3 |
| **mean** | | | **+0.131** | |

The delta is positive, so `validate_eval_result.py`'s ablation gate passes. The
absolute gate does not: `overallScore` is 0.833 and 2 of 5 cases scored below
full marks, so the validator exits 1.

**The headline number should not be quoted on its own.** Four things below it
each cut into what it means, and three of them are defects in this harness
rather than in the plugin.

**1. The pipeline never ran.** This is the big one. A probe run of
`integration-cap` with `--keep-temp` was traced tool call by tool call:

```
3 Bash   3 Read   1 Grep   1 Skill   1 Write        ← no Workflow, not once
```

`Skill` was called correctly (`concept-prover:concept-prover`) and SKILL.md was
read in full, but the model then declined to dispatch, saying its *"standing
instruction for this session is no workflows unless you ask for them"*. Two of
the three graded `integration-cap` runs say the same thing in their final
answer. So `verify-attack-path`, `build-poc` and `review-poc` — the checkpoint
gates, the five false-positive challenges, `confidenceBand`, `tallyChallenges`,
`poc-lint`, everything the free layers cover and everything the README calls the
flagship — contributed **nothing** to +0.131. What the ablation actually
compared was *SKILL.md read as prose* against *no plugin at all*.

The cause is the `Workflow` tool's own opt-in rule. It lists "the user invoked a
skill whose instructions tell you to call Workflow" as a valid opt-in, but here
*Claude* activated the skill from its description; the user's prompt never named
it. Autonomous skill activation is not user opt-in, so the exemption does not
fire. `--allow-tools Workflow` does not help — this is a policy refusal, not a
permission denial. This is distinct from, and more fundamental than, the
"Phases 5-6 cannot be relied on to complete under `-p`" problem recorded below:
there the workflow is launched and then torn down; here it is never launched.
Until a case prompt opts in explicitly, **no eval run through this harness can
measure the pipeline**, and any delta it reports is a delta on the prose.

**2. `should-not-fire` supplies 61% of the mean and is judge noise.** Its +0.40
is 0.08 of the 0.131. All six answers — both arms — are the same answer: a
two-to-three sentence description of `transfer_balance` plus a note that
`amount` is unchecked for sign, explicitly framed as a documentation
precondition. That is exactly what the case's own criteria call acceptable
("Noting the missing negative-amount check in passing is acceptable"). No run
started a PoC pipeline; `no-workflow-launched` passed 3/3 in both arms. The
judge nonetheless returned unanimous 3-0 verdicts *both ways* on outputs that
cannot be told apart on the criteria. Drop this case and the mean falls to
**+0.063**.

**3. `blocked-attack-path`'s two `file_exists` graders are vacuous.** They carry
3 of the case's 7 weight units and assert that no PoC was written. All six runs
wrote one — `poc_search_sqli.py` in four, `poc_search_injection.py` in two — and
all six passed both graders, because the patterns are `test_*.py` and
`*ploit*.py` and neither filename matches either. The note above about worktree
isolation hiding a pipeline-built PoC is true but was never reached: these
missed a PoC sitting in the working directory. Whether writing a harness that
*demonstrates non-exploitability* should even fail this case is a separate
question — but as written the graders pass regardless of behaviour in both arms,
so the case's entire delta rests on the single `outcome` grader.

**4. `names-the-integration-root-cause` is a lexical near-miss.** It scored 0/3
with the plugin and 1/3 without, and it is the only reason `integration-cap`
lands negative. The pattern wants `integration|third[- ]party|not attacker[-
]controlled|attacker does not control`; the runs wrote "rate is **not
attacker-reachable** through any path" and equivalents. Same conclusion,
unmatched wording. Worth noting separately: every run in both arms independently
found a stronger variant the case does not anticipate — `qty` is equally
unvalidated, is an order field rather than an internal service response, and
`charge(ctx, -125)` at an honest rate mints the identical credit.

**What survives.** At n=3 per arm, `already-fixed` (+0.17) and
`blocked-attack-path` (+0.14) each rest on a one-run difference in a single LLM
grader, which the `should-not-fire` result shows is within this judge's
variance. `already-fixed` also no longer discriminates the way it was designed
to: both arms reached "do not pay" empirically — building the timing attack and
showing it recovers at chance, one run profiling CPython's SIMD `memcmp` into
three plateaus — rather than by finding #412. Good work, wrong mechanism, and
the case cannot tell the two apart.

**Honest summary: the plugin does not yet have evidence that it beats its
baseline.** The first valid delta is positive but is dominated by judge variance
on a case that does not discriminate, is measured against a pipeline that never
executed, and is scored partly by graders that pass unconditionally.

### What was fixed after that run, and what is still owed

Defects 1, 3 and 4 above were fixed on 2026-08-04. Defect 2 is judge variance
and is not fixable by editing the suite.

**1 — the opt-in.** Every case prompt now ends with a paragraph granting
multi-agent orchestration. The wording is deliberately **plugin-neutral**:

> Multi-agent orchestration is authorised here: use a workflow and fan out to
> subagents if the analysis calls for it.

The tempting version — "use the concept-prover skill and run its workflows" —
is a trap, and `test_the_workflow_opt_in_is_plugin_neutral` now fails it. Both
arms receive the *same* prompt, and the baseline has no such skill, so naming it
hands the with-plugin arm a usable instruction and the baseline an impossible
one. That inflates the delta by construction, which is the defect this whole
section is about. Neutral phrasing keeps it fair: both arms may orchestrate,
both have `Workflow` in `allowed_tools`, and the plugin has to earn the delta by
having a *designed* pipeline rather than by being the only arm allowed to fan
out. `test_every_prompt_opts_into_workflow_orchestration` fails any case that
loses the phrase, and both tests were checked against the pre-fix prompts to
confirm they reject them.

This also repairs `should-not-fire`'s `no-workflow-launched` grader, which was
vacuous for the same reason the `file_exists` pair was: it passed 3/3 in both
arms because `Workflow` was uncallable, not because the plugin declined to fire.
It is now a real negative test.

**3 — the vacuous `file_exists` pair.** Deleted; `cites-blocking-layer` goes to
weight 2 to keep the deterministic share meaningful. Reasoning recorded above.

**4 — the near-miss regex.** `names-the-integration-root-cause` now also matches
the negated forms of control / reach / influence / supply, plus "no path from
any attacker". Regraded against the six recorded answers it goes from 0/3 to
1/3 with the plugin and 1/3 to 2/3 without — it did **not** move in the
plugin's favour, which is the check that it was widened to fit the language
rather than to fit the desired result. Runs that stop at "NOT PROVEN" without
saying why still fail, correctly. Caveat: the recorded `evidence` strings are
elided in the middle, so that regrade is a lower bound.

**The neutral opt-in was verified before spending on a re-run** ($1.96, 6
minutes, `integration-cap`, 1 run, `--ablation none --keep-temp`). Counting
`tool_use` names in the kept trace, against the identical probe taken before the
fix:

| | before | after |
|---|---|---|
| `Workflow` calls | **0** | **1** |
| other | Bash 3, Read 3, Grep 1, Skill 1, Write 1 | Bash 4, Read 3, Skill 1, ToolSearch 1, TaskOutput 1 |

So plugin-neutral phrasing is sufficient — the opt-in does **not** have to name
the skill, and the ablation stays fair. `verify-attack-path` dispatched with
proper args and fanned out to 6 agents.

**The orchestrator waited.** It called `TaskOutput` with `block: true,
timeout: 600000` and the workflow reached `completed`. The concern recorded
below — that `Workflow` returns on launch, so a workflow is torn down when the
orchestrator ends its turn — did not materialise here. That was the mechanism
behind "Phases 5-6 cannot be relied on to complete under `-p`", and blocking
`TaskOutput` appears to be the thing that resolves it.

**Superseded by the run below**, which is the first to measure the pipeline.

### The 7-case sweep (2026-08-05) — the firmest numbers to date

CLI 2.1.222, sonnet both arms and judge, 7 cases x 3 runs x 2 arms,
`partial: false`, **40 of 42 runs clean**, $39.96, 204 minutes. Result at
`fixtures/eval-result-2026-08-05-7case.json`.

| Case | with | without | delta | `outcome` |
|------|-----:|--------:|------:|:----------|
| integration-cap | 1.00 | 0.33 | **+0.67** | **3/3 vs 0/3** |
| blocked-attack-path | 1.00 | 0.40 | **+0.60** | **3/3 vs 0/3** |
| already-fixed | 1.00 | 0.50 | **+0.50** | **3/3 vs 0/3** |
| dead-route | 0.47 | 0.40 | +0.07 | 1/3 vs 0/3 |
| should-not-fire | 1.00 | 1.00 | +0.00 | 3/3 vs 3/3 |
| wrong-parameter | 0.80 | 1.00 | −0.20 | 2/3 vs 3/3 |
| inflated-impact | 0.22 | 0.67 | −0.44 | 1/3 vs 3/3 |
| **mean** | | | **+0.170** | |

**The result that needs no caveat: three cases at 3/3 versus 0/3.** Nine
with-plugin runs, nine baseline runs, no exclusions, perfect separation — across
three *different* failure modes:

- `integration-cap` — a real bug reported at inflated severity; the plugin caps
  it, the baseline does not.
- `blocked-attack-path` — a sink with no attacker-reachable path.
- `already-fixed` — a bug already fixed one layer up.

**`integration-cap` went from +0.00 to +0.67, and that is the checkpoint 2.4 fix
paying for itself.** On the previous sweep the impact agent graded a
real-but-downgraded finding `NOT_VERIFIED` and the gate killed it (1/3). With the
enum disambiguated it is 3/3. This is the only change between the two sweeps that
touches that path.

**Four with-plugin runs produced nothing gradeable, and all four were in the
with-plugin arm.** Two `inflated-impact` runs hit the 900s wall; two more
(`dead-route`, `wrong-parameter`) ended with an empty `last_message` — the judge
never voted (`judgeVotes: null`) and the graders scored the absent answer as
zero. Excluding runs that produced no answer, on the same principle the errored-run
guard applies:

| | mean delta |
|---|---:|
| as the CLI reports it | **+0.170** |
| excluding the 2 timeouts | **+0.233** |
| excluding all 4 ungradeable | **+0.295** |

All three are true and they answer different questions. +0.170 counts "produced
no usable answer" as a failure, which is what a user experiences. +0.295 answers
"when it does answer, is it better". **The gap between them is a real reliability
cost: 4 of 21 with-plugin runs — 19% — yielded no answer**, against 0 of 21
baseline runs. That is not a measurement artefact to be waved away; it is the
price of a pipeline that fans out under `-p`.

`inflated-impact`'s timeout is now 1800s, matching the other Phase-4 cases; 900s
was set when the pipeline never dispatched.

**My earlier claim of "4/5 vs 0/5 on unreachable sinks" was overstated, and n=1
is why.** The two new cases were admitted on single-run smoke tests showing +0.60
each. At n=3: `dead-route` +0.07 and `wrong-parameter` **−0.20**. Corrected
tally for that failure mode at n=3 — with **6/9**, without **3/9**, not 4/5 vs
0/5. Two specifics:

- **`wrong-parameter` does not discriminate: the baseline scored 3/3.** Plausibly
  because "a list argv is not a shell" is a much easier judgement than "no code
  path reaches this", so it is not really the same failure mode as the other two.
  That is a hypothesis the data suggests, not something measured.
- **`dead-route`'s 1/3 is substantially my grader's fault.** One run produced no
  output. Another was failed 2-1 by the judges for an answer that is *correct*:
  it returned NOT_EXPLOITABLE, quoted `ROUTES`, and expressly declined to call
  `render_pdf` directly because that "would be exercising code the app itself
  doesn't expose". It then asked whether a registration file existed elsewhere —
  and the criteria clause forbidding "proposing a hypothetical route
  registration" appears to have caught a clarifying question. Over gradeable runs
  the case is 0.70 vs 0.40 (+0.30).

Worth recording about the baseline on `dead-route`, since it went 0/3: all three
runs wrote a PoC calling `render_pdf` directly, **executed real command
injection** (`touch /tmp/poc_evidence` fired despite `wkhtmltopdf` being absent),
and led with "Confirmed command injection" before noting the route does not
exist. They reached the right reachability finding and still framed it as a
confirmed injection — which in a client report is a false positive with a working
exploit attached.

Cost: **with $31.27, without $8.70 — 3.6x**, consistent with the 3.4x of the
5-case sweep.

### The void run: 22 of 30 runs died and the result still said `partial: false`

The first re-run after the opt-in fix (CLI 2.1.221, sonnet judge, $16.48, 84
minutes) is **void**, and the way it failed is worth keeping.

Only **7 of 30 runs completed.** One `already-fixed` baseline run timed out at
1800s; the other 22 exited `1: (no stderr)` at turn 1 having spent **$0.00**
each — the signature of a usage limit reached mid-sweep, not of anything in the
plugin. `claude -p` worked again immediately afterwards, so the window had reset.

What makes it worth recording is that **nothing in the result said so**:

| check | value |
|---|---|
| `partial` | **false** |
| `casesTotal` | 5 |
| `runsPerCase` | 3, for every case |
| `meanDelta` | **+0.127** |
| `blocked-attack-path` delta | **+0.47** |

That +0.47 is entirely an artefact: all three no-plugin runs were dead, and two
with-plugin runs had completed before the wall. **A run that errors is still
scored — as zero — so a dead arm is indistinguishable from an arm that answered
badly, and the delta silently becomes a measure of which arm survived.** Quoted
without looking at the per-run errors, this sweep reads as the plugin's best
result yet.

`validate_eval_result.py` would have rejected it, but only by accident — on
`overallScore != 1`. Every check aimed at run integrity passed. It now counts
errored runs explicitly and refuses the result, with
`test_a_result_with_an_errored_run_is_rejected` pinning it and
`test_the_real_result_carries_the_error_key_the_validator_reads` as the zero
guard, since a reader looking for a key the CLI stopped emitting would inspect
nothing.

Operational notes for the next sweep: a full 5 x 3 x 2 on Opus took 84 minutes
and only got through 1.5 cases before the limit; the `already-fixed` with-plugin
arm alone cost $10.54 for 3 runs (~$3.50/run) once the pipeline actually
dispatched. Run paid sweeps with `--model sonnet`, and check the per-run `error`
fields before reading any aggregate.

### The first run that measured the plugin (2026-08-04, sonnet, pipeline live)

CLI 2.1.221, **sonnet for both arms and for the judge**, 5 cases x 3 runs x
2 arms, `partial: false`, **28 of 30 runs clean**, $28.79, 181 minutes. Full
result at `fixtures/eval-result-2026-08-04-pipeline.json`. This is the first
sweep in which `Workflow` actually dispatched, so it is the first that measures
the plugin rather than its prose.

| Case | with | without | delta | outcome grader |
|------|-----:|--------:|------:|:---------------|
| blocked-attack-path | 0.80 | 0.40 | **+0.40** | 2/3 vs **0/3** |
| already-fixed | 0.83 | 0.50 | **+0.33** | 2/3 vs **0/3** |
| integration-cap | 0.33 | 0.33 | +0.00 | 1/3 vs 0/3 |
| should-not-fire | 1.00 | 1.00 | +0.00 | 3/3 vs 3/3 |
| inflated-impact | 0.44 | 0.67 | −0.22 | 2/3 vs 3/3 |
| **mean** | | | **+0.102** | **10/15 vs 6/15** |

**Both errored runs were in the with-plugin arm** (a 900s timeout on
inflated-impact, one `exit 1` on integration-cap), and an errored run is scored
zero. Excluding them — a run that produced no answer is not evidence about
either arm — the mean delta is **+0.180**, and `inflated-impact` goes to
+0.00 rather than −0.22. So +0.102 is the conservative figure and +0.180 the
like-for-like one. Both are reported; neither is cherry-picked.

**`blocked-attack-path` is the result worth trusting**, because the baseline
fails in exactly the way the case was built to detect and the failure is legible
rather than a grader artefact. All **three** no-plugin runs wrote a working
UNION-injection PoC by calling `run_query()` **directly**, bypassing
`handle_search`, and reported a confirmed SQL injection — one of them dumping
`admin:5f4dcc3b...` from a seeded `users` table. Run 3 explicitly noted that the
entry point's allowlist "happens to block the same payload today" and reported
the finding anyway. That is the canonical false positive: a sink that is
injectable in isolation with no attacker-reachable path. The with-plugin arm
passed 2/3, which is checkpoint 2.2 doing the job the plugin exists to do.

**`should-not-fire` went to 1.00 in both arms**, which retires the largest
caveat on the previous run. Under the haiku judge it had shown a spurious +0.40
on six answers that could not be told apart; under sonnet both arms score 3/3
and the case contributes nothing. The earlier +0.131 was 61% judge noise, as
suspected — and the delta here does not depend on that case at all.

**`already-fixed`'s +0.33 is softer than it looks.** `cites-the-fix` was 3/3 in
*both* arms — the baseline did find #412 unaided. What it lost on was framing:
all three baseline runs hedged ("Confirmed for v1.4.0, but already fixed on
HEAD") and two left a timing PoC in the tree, which the criteria read as
partially validating a bounty that should be retracted outright. One baseline run
even got the mechanism more precisely right than the case's own description,
noting that #412 "never touched `session.py` at all — it changed the caller".
Treat this delta as being about verdict discipline, not about finding the fix.

**Honest summary: this is the first real evidence the plugin beats simple
prompting, and it is suggestive rather than conclusive.** A mean delta of +0.102
(+0.180 like-for-like), driven by 10/15 vs 6/15 on the only grader that measures
correctness, with one case showing a clean mechanism-attributable win and no
case where the plugin is worse once dead runs are excluded. Against that: n=3,
five cases, and one case (`integration-cap`) still at 0.33 in both arms. What
would settle it is n=5 on `blocked-attack-path`-shaped cases — unreachable sinks
reported as exploitable — since that is the one failure mode where the pipeline
demonstrably separates from the baseline three times out of three.

### Two new unreachable-sink cases, and one dropped for measuring nothing

`blocked-attack-path` was the only case where the pipeline demonstrably beat the
baseline, so the whole delta rested on one case's mechanism. Three more cases of
that failure mode — a real sink reported as exploitable with no attacker-reachable
path — were authored to give it independent shapes. Each was smoke-tested at
1-2 runs per arm before being admitted, total $6.99.

| Case | Unreachable because | with | without | delta |
|------|--------------------|-----:|--------:|------:|
| `dead-route` | No call path exists. `app/router.py` maps two paths; `render_pdf` is in no route table and has no caller | 1.00 | 0.40 | **+0.60** |
| `wrong-parameter` | The report joins the wrong sink to the source. `host` reaches `subprocess.run([...])` as argv; the one `shell=True` call takes a fixed string and no request data | 1.00 | 0.40 | **+0.60** |
| ~~`coerced-to-int`~~ | Type coercion — **dropped, see below** | 1.00 | 1.00 | +0.00 |

Both survivors discriminate on the `outcome` grader, with the baseline failing
and the plugin passing, which is the same signature `blocked-attack-path`
produces. `dead-route`'s with-plugin answer was checked by hand rather than
trusted: it quotes `router.py:9-20`, states that `render_pdf` is never
referenced, halts at 2.2, and then flags the shell interpolation as a latent
issue — correct on every count. Its `turns: 1` is the documented artefact of
`Workflow` returning on launch, not a sign it answered without looking; the run
cost $1.54 over 288 seconds.

**`coerced-to-int` was dropped, and the negative result is the point.** SQL
concatenation whose value is `int()`-coerced before the sink. It was measured
twice. The first draft put `int()` one line from the sink in a 17-line file and
scored +0.00. Suspecting the target was simply too small, the coercion was moved
behind a shared typed-params helper in a second module, so disproving the report
required following the value across a module boundary and reading a schema —
precisely the work checkpoint 2.2 does. It scored **+0.00 again**: 6 of 6 runs
across both drafts passed in **both** arms, the baseline solving it in 8 turns
unaided.

So type coercion is not a failure mode this plugin improves on, and by the
standard this file already applies — *a case that cannot separate the arms cannot
justify the plugin, however good the finding looks* — it does not belong in a
graded suite it would cost ~$3 per sweep to run. The files are not in the repo;
the `SCAFFOLD_SOURCES` comment records what they were.

**This makes the case-selection caveat explicit, and it applies to every mean
delta in this file.** The suite is now curated toward failure modes where the
plugin was observed to help. A mean over such a suite is *not* an unbiased
estimate of how much the plugin helps in general — it answers "how much does it
help on the failure modes the suite encodes". `coerced-to-int` is the measured
evidence that those are not the same number, and dropping it raises the headline
delta by removing a true zero. Quote the per-case table, not just the mean.

### `downgrades-to-a-500` asks for a fact that is not true

It scored **0/3 in both arms**, and it is wrong, not the runs. Its pattern is
`\b500\b|internal server error`, but Go's `net/http` does not return 500 on a
handler panic: `conn.serve`'s deferred `recover()` logs the panic and **closes
the connection**, so the client sees a dropped connection, not an HTTP error
status. All six runs said so correctly and in detail — "aborted only their own
connection", "the server kept accepting and correctly answering new requests" —
and all six failed a grader demanding they claim otherwise.

This is the same defect class as the vacuous `file_exists` pair, inverted: that
pair could never fail, this one can never pass. It caps `inflated-impact` at
0.67 in both arms, which is why that case cannot reach full marks however good
the answer is. Because it fails symmetrically it does not bias the delta, only
the absolute score. The fix is to assert what actually happens — the connection
is dropped and the process survives — and the README note claiming this grader
"got stronger for free" by requiring the model to know `net/http`'s behaviour
should be struck: it encoded that behaviour incorrectly.

### Checkpoint 2.4 gates the same finding both ways (found by that probe)

With the pipeline actually running, `integration-cap` — the case whose entire
design is to reach PROCEED and build a PoC — was **halted at checkpoint 2.4**.
The impact agent returned:

```
result: NOT_VERIFIED
impact: "The claimed impact ("CRITICAL: an attacker mints balance") is NOT
         VERIFIED as stated and is downgraded to LOW / defense-in-depth
         trusted-upstream-integrity."
```

`verify-attack-path.js` treats anything other than `VERIFIED` as terminal, so
the run returned `NOT_EXPLOITABLE`, `build-poc` never ran, and the `outcome`
grader failed — its criteria say in as many words that "concluding that the
finding is not exploitable, or reporting no PoC at all, is a failure". The case
scored 0.50, below the 0.67 the prose-only arm averaged.

**The agent did what checkpoint 2.4 asks and then graded itself as failing it.**
The prompt says *"If recovery downgrades it, the verified impact is the
downgraded one, not the original claim"* — the agent performed exactly that
downgrade, then set `result: NOT_VERIFIED` because the claim *as stated* did not
hold. The enum is ambiguous about what it grades: whether **any** impact is
established, or whether **the reported claim** is. The code comment asserts the
former ("NOT_VERIFIED means the impact claim is unsubstantiated"); an impact
that is real but smaller than claimed satisfies neither reading cleanly.

This is not a one-off reading. The end-to-end run recorded further down got
`impact VERIFIED` and `PROCEED` on this same case. Same case, same checkpoint,
opposite gate across two runs — so **findings reported at inflated severity gate
nondeterministically**, and "reported at inflated severity" is the premise of
two of the five cases. Until 2.4's enum says which question it grades,
`integration-cap` measures that coin flip rather than the plugin.

**One case-design question left open, deliberately.** Every `integration-cap`
run in both arms independently found a variant the case does not anticipate:
`qty` is as unvalidated as `rate`, is an order field rather than an internal
service response, and `charge(ctx, -125)` at an honest rate mints the identical
credit. `charge.py:3` asserts the order pipeline finalises quantity, but that
pipeline is not in the repo, so the claim is unverifiable in scope. A model that
argues this pushes severity above Medium is reasoning correctly and the case
penalises it. Closing the variant means adding an in-repo `qty` guard to the
scaffold and its checked-in fixture — a change to what the case *means*, not a
grader fix, so it is left for a decision rather than folded into this one.

### What the two PROCEED-seeking cases actually do (measured, CLI 2.1.220)

Both were run end to end at a cost of $5.78. The design expectation was half
right, and the record is corrected here rather than left as an aspiration.

| Case | Gate status | Phases 4-6 |
|------|-------------|------------|
| `integration-cap` | **PROCEED** (7 agents; 4 layers PASSES, impact VERIFIED, `rootCause: integration`) | build-poc returned **BUILT**; review-poc ran `artifact-check` (lint exit 0, PoC re-ran) and 4 of 5 challenges |
| `already-fixed` | **NOT_EXPLOITABLE**, blocked at checkpoint 2.2 | neither launched |

`already-fixed` does **not** reach PROCEED and never will. A layer agent reads
`auth.py`, sees both operands are replaced by a fixed-length HMAC digest before
the `==`, and returns BLOCKS — quoting *"converting that into an accepted token
requires an HMAC preimage"*. That is the plugin working: the bug is dead at
HEAD, so gating it out at 2.2 is correct, and the case still discriminates
because the graders reward the refusal citing #412. It is simply not a vehicle
for exercising challenge 4. Exercising the retract-after-building path needs a
fix that layer analysis cannot see — a dependency bump, or a partial fix — and
no case does that yet.

**Phases 5-6 cannot be relied on to complete under `claude -p`.** The Workflow
tool returns on launch, so whether review-poc finishes depends on the
orchestrator happening to idle afterwards. In the `integration-cap` run the
orchestrator ended its turn 2.4 seconds after launching review-poc and the
workflow was aborted 140 seconds in, mid-challenge; `already-fixed` idled and
completed. Nothing enforces the wait. **Any harness that grades review-poc
output under `-p` is grading a killed run** — so the severity band, the
confidence band and the report are not measurable this way, only the statuses
that land before review-poc is dispatched.

## The gate

`mutation-gate.sh` breaks each covered behaviour in a sandbox copy and requires
the suite to go red. Anything that survives is testing the model, not the
plugin. It fails if zero mutations run.

Last run, after the merge: **119 run, 0 survived, 0 stale, 12 deferred** (131 total).

The 12 deferrals are the Layer 3 mutations. They break the recorded run that
`test_regrade.py` grades, and that module skips because its capture is a recording
of `concept-prover:verify-attack-path` — a skipped pytest exits 0, which this
harness reads as "the mutation survived". So they are neither run nor dropped:
`defer_mutation` counts and names them, and the summary says what is owed. Leaving
them as `run_mutation` would have reported 13 phantom coverage gaps; deleting them
would have shrunk the gate from 131 to 119 with nothing saying so.

**The re-point after the merge found two real defects, both in the tests.** The
first is the one worth remembering: `decideGate` gained the history verdict as a
fourth positional argument, and `test_every_non_PROCEED_status_carries_a_reason`
passed its cases as 4-tuples. So the layer count landed in the history slot,
`attemptedLayers` was `undefined`, `undefined - 1` is `NaN`, `NaN !== 0` is true,
and all ten rows returned BLOCKED at the mis-attribution branch without ever
reaching the branch each was written for. Ten green assertions, nothing graded.
Nothing but the mutation gate could see it, and what exposed it was a mutation on
a *different* function's fallback. The fix adds a zero guard: the test now asserts
that the rows between them reach six distinct statuses, because ten rows all
returning the same one is what a silently broken argument list looks like.

**Nothing runs this for you.** It is not in `make check` and not in CI — it is
minutes of sandboxed test runs, so it is a thing you run when you change the
scripts, not on every push. The consequence is that the number above is a claim
maintained by hand, and it goes stale the moment the code moves: a review that
changed `isAcceptableBuild`, `decideGate` and five `poc-lint` rules turned 16 of
these mutations into `ERROR — the pattern is stale` across two runs. That is the
harness working (a mutation that no longer applies is not a survivor), but only
if someone re-runs it. Re-run it, re-point what goes stale, and update the count
in the same commit.

**A mutation is only "caught" if its test command passes on UNMUTATED code.**
The harness proves that first, in the pristine sandbox, and memoises the result
per command. Without it, anything that makes a test command fail for an
unrelated reason reads as full coverage, and two such reasons were live:

- `bats` was not installed locally, so the only poc-lint mutation exited 127 and
  had been reported as caught without executing a single assertion. Install
  `bats-core`; the Makefile's `bats` target needs it too.
- `PYTEST` omitted `--with pyyaml` while all eight Layer 4 mutations run
  `test_eval_suite.py`, which imports `yaml` at module scope. It only ever
  worked because pyyaml leaked in from the author's active venv. Run the gate
  under `env -u VIRTUAL_ENV -u PYTHONPATH` to keep it honest.
- A pytest module that **skips** exits 0 too, and the baseline check cannot tell
  a skip from a pass. That is why the Layer 3 mutations are deferred rather than
  run: the baseline would have gone green on a module that asserted nothing.

A third, still latent: `pytest -k renamed_test` exits 5 for "no tests
collected", which would also read as caught. The baseline check covers it.

**A mutation that stops applying is reported as an ERROR, not a survivor.**
`perl -pi` exits 0 when its pattern matches nothing, so a stale mutation used to
read as a coverage gap — sending you to "fix" a test that was fine. The harness
checksums the sandbox and fails the mutation if nothing changed.

Findings from mutation runs so far, all of them holes in the tests rather than
the plugin:

- Deleting a `phase()` call was masked by the `phase:` *option* on an agent call,
  which the same assertion also counted.
- Dropping `.filter(Boolean)` after `parallel()` was masked by a downstream
  `.filter(r => r.verdict)`, because the check accepted any `.filter(`.
- `test_terminal_returns_carry_a_reason` ran its regex over
  `strip_strings_and_comments()` output, which blanks string *contents* — so
  `status: 'NO_CANDIDATES'` could never match. The loop inspected zero returns
  and passed. It now reads the raw source and has a zero-item guard; the moment
  it worked it found a real `DO_NOT_SUBMIT` with no reason.
- The scrubber's leak check lives in `main()`, not in `scrub()`. A unit test
  over `scrub()` alone left the "leak check disagrees with the substitution"
  mutation alive; `test_scrub.py` now runs the script end to end.
- A gate gaining a positional argument silently retires every test that passes
  its arguments positionally — see the `decideGate` case above. Prefer an options
  object for anything that will grow, or expect the gate to find it for you.

### Ten Layer 4 mutations owed to this file (2026-08-06)

The eval-suite audit of 2026-08-06 changed two graders and added four invariants,
and proved each one fires by breaking the input in a sandbox copy — **10
mutations run, 0 survived**, each failing on the specific assertion intended
rather than on a bare non-zero exit. They are not yet in `mutation-gate.sh`, so
the count in §"The gate" is unchanged and this is the outstanding work:

| mutation | must turn red |
|---|---|
| `stage_answers`: search `ONLINE_YES` over the raw prompt instead of the NO-stripped one | `-k pins_both_stage_answers` |
| a case prompt that says both "work offline" and "go online and check their security advisories" | `-k pins_both_stage_answers` |
| append an extra `cat > extra_helper.py` to any scaffold | `-k held_to_no_fixture` |
| prepend `upstream\|` to `names-the-integration-root-cause` | `-k satisfied_by_the_prompt_alone` |
| restore `downgrades-to-connection-scoped` to the literal pattern that failed 6/6 | `-k accept_the_right_answer` |
| restore the bare `integration\|third[- ]party\|` prefix on `names-the-integration-root-cause` | `-k accept_the_right_answer` |
| set `cites-the-fix`'s pattern to `"a\|e\|i\|o\|u\| "` (a grader that cannot fail) | `-k accept_the_right_answer` |
| append a new regex grader to any case without a `GRADER_PROBES` entry | `-k test_every_regex_grader_has_probes` |
| delete one `GRADER_PROBES` entry | `-k test_every_regex_grader_has_probes` |
| `blocked-attack-path`: `outcome` to weight 9, `cites-blocking-layer` to weight 1 | `-k deterministic_weight_share` |

Note for whoever ports these: a stale mutation must read as **survived**, not as
caught. Two of the ten were written with `perl -0pi` patterns that silently
matched nothing on the first attempt, and `perl -pi` exits 0 either way — the
existing `run_mutation` checksums the sandbox for exactly this reason, so port
them into it rather than into a fresh harness.

## What the checkpoint gates actually enforce

Layer 2 covers the decisions, not the prose. Each of these was a checkpoint
that the reference documents state as a hard rule and the scripts left to an
agent's discretion or to the orchestrator's good behaviour:

| Rule | Where it is now enforced |
|------|--------------------------|
| 2.2 needs ≥1 layer inspected — an empty `layers` dispatched zero agents and fell through to PROCEED | `missingArgs`, and `decideGate(attemptedLayers === 0)` |
| 2.3 "checked for recovery (not assumed absent)" — a dead recovery agent proceeded as "not established" | `decideGate(!recoveryVerdict)` |
| 2.4b requires the external precondition when the root cause is not internal | `missingPrecondition` |
| "Only PROCEED justifies building" — failing returns carry a populated `impact`, so a forwarded failure passed the shape check | `verification.status` in both downstream workflows |
| 5.1 challenge 4 overrides the band — a dead agent escaped the one unconditional rule | `alreadyFixedStands(unrebutted)` |
| 2.4b/2.5 severity caps — stated in the report prompt, self-reported by the agent | `severityCapViolation` |
| Destructive operations only at safety levels 1–2 | `missingArgs` in `build-poc` |
| The PoC must be readable by its reviewers — the builder runs in an isolated worktree | `poc.absolutePath`, required by the build gate |

## Provenance

Record model, effort and CLI version with any result; `run.meta.json` and the
eval JSON both carry these fields. Report the pass rate over N runs. Do not
re-run until green.

| | |
|---|---|
| CLI at authoring time | 2.1.220 |
| node | v22.13.1 |
| bats | 1.14.0 (`brew install bats-core`; required, not optional) |
| Layers 1–3 status | 243 pytest (+1 skipped) + 146 node + 36 bats tests passing |
| Mutation gate | 131 mutations, 0 survived, 0 stale, each test command baseline-verified |
| Layer 3 live capture | 3 runs, CLI 2.1.220, `blocked-attack-path` |
| Layer 3 pass rate | **3/3** — all blocked at search.py:20 and :27, no PoC written |
| Layer 4 eval | 8 sweeps. 2026-07-30 $6.23 delta −0.056 **invalid** (tools denied). 2026-08-04 $17.90 delta +0.131 — measured the skill's **prose**, `Workflow` never dispatched. 2026-08-04 $16.48 **void**, 22/30 runs lost to a usage limit. 2026-08-04 sonnet $28.79 5 cases, delta **+0.102**, 28/30 clean — first to measure the pipeline. 2026-08-05 sonnet $39.96 **7 cases, delta +0.170** (+0.295 over gradeable runs), 40/42 clean — three cases at 3/3 vs 0/3. 2026-08-06 CLI 2.1.222 $21.49 7 cases, delta **+0.008** — three `blocked-attack-path` with-plugin runs and three `already-fixed` baseline runs produced no answer. 2026-08-06 CLI 2.1.223 $3.05 `blocked-attack-path` alone, delta +0.000. 2026-08-06 CLI 2.1.223 $31.71 7 cases, delta **+0.170**, `overallScore` 0.781, 41/42 clean — the sweep the 2026-08-06 grader audit was regraded against. See Layer 4. |

The Layer 3 pass rate above predates the checkpoint fixes in the table further
up and has not been re-captured; the assertions it was scored against are
unchanged, but it is a rate for the old scripts. It also predates the rewrite of
`search.py`'s comments, so its `search.py:20` and `:27` are line numbers in the
file as it was captured; the same two checks are at `:14` and `:21` today.
