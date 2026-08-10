# TODO: the two capabilities that did not survive the merge

**Written 2026-08-07**, against fp-check 2.2.0. Two items, independent of each
other and of the measurement work recorded in
[MEASUREMENTS.md](MEASUREMENTS.md).

Both are **capability gaps, not bugs**. The plugin is honest about them today —
`tests/coverage.test.mjs` pins each with a live guard that fails if anyone claims
otherwise, and SKILL.md says plainly that nothing enforces batching or chaining.
So neither is urgent. Item 1 is a clean design with a clear shape; item 2 is a
decision that needs making before any code.

---

# 1. `triage-batch.js` — shared context, fan out, then chain

## What is missing and why it matters

Old fp-check verified several findings in one pass. In the merge **every workflow
destructures a single `finding`**, so the batch is the orchestrator's loop with no
dispatch record and no gate that fails when one is skipped. Two capabilities went
with it:

- **Batch triage** — the description advertises *"triage findings from a scanner,
  a bug bounty submission or an agentic discovery run"*, which is inherently batch
  work. The plugin is weakest at the thing it most loudly claims.
- **The exploit-chain check** — old fp-check's step 4: findings that *individually*
  failed a gate may combine into a viable attack. The shape to look for is **two
  `NOT_EXPLOITABLE` results whose blocking layers differ.** No workflow sees a
  second finding, so that comparison cannot be made anywhere in code.

The chain check is the more dangerous loss because it is a **false-negative**
guard. Everything else in this plugin pushes toward dismissing; this is the one
mechanism that pushes back, and it is gone.

## The shape

```
workflows/triage-batch.js          Stage 0, on request — orchestrates the rest

  phase('Context')   one agent, once, over the whole finding set
                       → the shared facts every finding's Stage 1 would
                         otherwise re-derive: entry points, the routing table,
                         the trust boundaries, the framework and its recovery
                         defaults, the declared scope
  phase('Triage')    pipeline() over findings, each running triage-static via
                       workflow('fp-check:triage-static', {...}) with the shared
                       context folded into its args
  phase('Chains')    one agent per candidate PAIR, bounded — see the gate below
  phase('Summary')   the batch verdict table plus any chain found
```

**`pipeline()`, not `parallel()`.** Finding B's triage should start as soon as A's
does, not wait for a barrier; there is no cross-finding decision until the chain
phase, which is where the barrier genuinely belongs. `Workflow`'s own guidance is
explicit that a barrier is only correct when stage N needs cross-item context from
all of stage N−1 — that is true of `Chains` and false of `Triage`.

**Nesting is one level.** `workflow()` inside a child throws, so `triage-batch`
may call `triage-static` but `triage-static` may not call anything. That is fine:
Stages 2 and 3 stay the orchestrator's decision per finding, exactly as now.

## The gates, which are the point

A batch workflow that returns a list of verdicts is a convenience. The reason to
build it in code is the guarantees prose cannot make:

| Gate | Rule | Why |
|---|---|---|
| `missingArgs` | `findings` is a non-empty array; every entry carries what `triage-static` requires; **at most `MAX_FINDINGS`** | An empty list is the vacuous pass this codebase keeps rediscovering — `layers`, `sources`, and now this |
| `everyFindingAccounted` | The result count equals the dispatch count, matched by id. A finding whose sub-workflow returned nothing is **reported as unverified**, never dropped | This is the whole reason to build it. "Rapid analysis of the remaining bugs" is the first Rationalization row, and it is currently prose arguing with prose |
| `chainCandidates` | Pure. Takes the Stage 1 returns and emits the pairs worth an agent | Bounds the fan-out and makes the selection testable without a model |
| `chainVerdict` | A chain is only reported when the agent names **both** findings' contributions and how one supplies what the other lacks | Stops "these two are both auth bugs" being reported as a chain |

### `chainCandidates` — the interesting one

Naively this is O(n²) agents. It should not be. Pair two findings only when one's
blocking reason plausibly supplies what the other lacks:

- both `NOT_EXPLOITABLE` **and their blocking layers differ** — the shape old
  fp-check named. Same blocking layer means the same wall; different walls may
  compose
- one `NOT_EXPLOITABLE` on reachability + one `TRUE_POSITIVE` whose impact
  includes reaching that component — the classic "you can't get there" plus "here
  is how you get there"
- one `NEEDS_MORE_INFO` whose missing fact is another finding's established impact
- an `ALREADY_FIXED` pairs with nothing — it is dead, and pairing it invites the
  chain agent to argue it back to life

Cap the result at `MAX_CHAINS` and **log what was dropped**. A silent cap reads as
"covered everything", which `triage-online.js` already got wrong once and now
carries `beyondCap` for.

## Cost, which decides whether this is usable

Stage 1 is ~9 agents. Ten findings is ~90 agents before a single chain check —
that is roughly a full sweep's spend on one dispatch. Two things make it viable:

1. **The shared-context phase pays for itself.** Every finding's layer agents
   currently re-read the same router, the same middleware, the same framework
   defaults. Deriving that once and passing it in is the main saving, and it is
   also the main *quality* argument: today ten findings get ten independent and
   possibly inconsistent readings of the same trust boundary.
2. **The brocard pre-gate is the cheap filter it was always meant to be.** In a
   batch its economics finally make sense — dismissing three of ten findings for
   a few cents each before their layer fan-outs is exactly the saving it was
   built for. (Note the tension with 2.2.0, where brocards 4 and 5 now *defer* to
   the specialised gates. The deferral is right for a single finding and should
   stay; batch does not change it.)

Set `MAX_FINDINGS` low to start — 5 is defensible — and let it rise on evidence.

## Testing

`runScript` cannot execute a nested `workflow()` — `tests/extract.mjs` injects a
stub that throws. **Extend the harness first**: inject a `workflow` fake that
returns scripted per-finding results, the way `agent` already is. That is a small
change to `extract.mjs` and it is what makes every gate above testable without a
model. Do it before writing `triage-batch.js`, not after.

Then: unit-test `chainCandidates` against hand-built Stage 1 returns (it is pure),
and wire-test that a finding whose sub-workflow returns `null` is reported as
unverified rather than silently absent.

## Eval

No existing case can measure this — all seven are single-finding. A batch case
needs a target with **two genuinely separate findings that only compose**, and the
correct answer is that each is individually not exploitable *and* together they
are. That is a real case-authoring job, and
[tests/README.md](tests/README.md) is emphatic about proving a new case
discriminates at n=3 before admitting it: two cases were admitted on n=1 smoke
tests showing +0.60 and came in at +0.07 and −0.20.

---

# 2. `triage-online-users` — the downstream-consumer census

> **LANDED in 2.3.0.** Built as option C. `needsUserCensus` and `censusProblem`
> are pure and unit-tested in `tests/online.test.mjs`; the dispatch, the skip and
> the blind-census path are wire-tested there and in `tests/coverage.test.mjs`,
> whose guard now exercises the capability instead of pinning its absence. Three
> mutations cover it — two in the direction that loses it silently.
>
> Two things went differently from the sketch below, both recorded in the script:
>
> - The reachability agent got **its own schema**. It had `SCOPE_SCHEMA`, which is
>   the `inscope` agent's shape — it was forced to answer with a policy `verdict`
>   and a quoted `clause` its prompt never asked for, and nothing read either. So
>   there was no field to gate on. `REACHABILITY_SCHEMA` requires `driver`
>   (`in-repo-caller` / `client-code` / `unknown`), which is the fact the predicate
>   turns on, and requires `eligibilityCaveats`, which two prompts already read.
> - **A blind census is reported, not fatal.** "The same halt `offlineProblem`
>   implements" would kill a completed policy read, scope verdict and past-bug
>   fan-out over one agent that could not reach a code index. `unsearched` is the
>   precedent for this shape and this follows it: `census.state` is `unperformed`,
>   the summary is told downstream usage is UNCHECKED rather than clear, and it
>   belongs in `openQuestions`. What the instruction was protecting against — a
>   census that searched nothing reading as "no users affected" — is what
>   `censusProblem` and the summary wording prevent.
>
> The rest of this section is kept as the record of why C rather than A, B or D.

## What is missing

online-triage's `triage-online-users` role: when severity depends on how
downstream clients consume the target — a misusable API, a pattern clients must
implement — find the popular public consumers and check whether any **actually
exhibits the buggy pattern**. Confirmed hits raise severity; only-theoretical
misuse lowers it.

It was the only role in any parent that produced evidence about **the world**
rather than about the project. `triage-online.js` advertised it in
`meta.description` while dispatching no such agent; that claim is struck as of
2.2.0, so the plugin is honest but poorer.

**There is a loose end it leaves.** Brocard 5's nuance says *"downstream usage
that violates documented guidance is a valid finding against the downstream
project"* — so Stage 1 raises a question that Stage 2 can no longer answer.
Whatever is chosen below should close that loop.

## Four options

### A. Always run it as part of Stage 2

Simplest. One more agent in the History phase.

- **For:** no new question to the user, no new arg. Stage 2 is already opt-in, so
  anyone who got here has accepted the cost and the network.
- **Against:** it is wasted on most findings. It only means something when the
  target is a library or exposes an API *and* the bug needs an unsafe usage by the
  client. For a bug directly exploitable in the target itself, the census answers
  a question nobody asked — the parent skill gated it for exactly this reason.

### B. A third question at Step 0

- **For:** consistent with Q1 and Q2, and the pre-supply path already exists.
- **Against:** the user is the worst-placed party to answer it. Whether severity
  depends on downstream usage is a *finding* of the reachability analysis, not
  something knowable up front. And §5.1a is emphatic: every extra question is
  another thing a non-interactive harness silently defaults to `no`, so it would
  quietly never run in any eval.

**Do not do this.** Three toggles is eight configurations, and the suite already
struggles to attribute two.

### C. Gate it in code on what Stage 2 already knows — **recommended**

The parent gated it on the reachability and scope files indicating the severity
depends on downstream users. That is a decision a pure function can make from the
Stage 1 and Stage 2 payloads:

```js
// Pure, testable, no new user-facing surface.
function needsUserCensus(verification, reachability, scope) {
  // A library or an exposed API, whose bug requires an unsafe usage by the
  // client rather than being directly exploitable in the target.
  //   - verification.impact.rootCause is 'integration' or 'external', OR
  //   - the finding is a hardening_gap in an exported surface, OR
  //   - reachability says no in-repo caller drives the sink
  // AND the scope verdict is not out-of-scope.
}
```

Then dispatch the census agent only when it returns true, and **log when it is
skipped and why** — a silent skip is how `beyondCap` went wrong.

- **For:** no new question; the gate is code and therefore testable; it fires on
  exactly the findings the parent gated it on. It also closes brocard 5's loop
  naturally, because a deferred brocard-5 dismissal is a strong signal that the
  governing document is a *downstream* one.
- **Against:** the predicate needs care and will be wrong at the edges. Mitigate
  by making it fail toward running the census: a false positive costs one agent,
  a false negative loses the capability again.

### D. Fold it into the past-bugs fan-out as another `source`

Let the caller name `{label: 'downstream-users', query: '...'}` and treat it as one
more venue.

- **For:** no new code path at all; the cap, the `beyondCap` accounting and the
  unsearched-venue reporting all come free.
- **Against:** it is not a past-bug search. Its output shape is different (a list
  of confirmed affected consumers with links, not similar reports), its schema
  would have to be loosened to fit, and loosening a schema to fit two jobs is how
  `DO_NOT_SUBMIT` came to carry three outcomes.

## Recommendation

**C, with A as the fallback if the predicate proves unreliable.** The census is
genuinely conditional, and this plugin's whole thesis is that conditions belong in
code rather than in a prompt or a question. Add `needsUserCensus` as a pure
function with unit tests, dispatch on it, and log the skip.

If the predicate turns out to be wrong more often than it is right, collapse to A
— always run it — rather than pushing the decision onto the user. Running one
unnecessary agent inside an already-opt-in stage is a much smaller cost than a
capability that silently never fires, which is the failure this plugin has now
made three times (`capSeverity`, `upstreamFixStands`, `decideVerdict` — 0 firings
each across 63 runs).

## Testing

`triage-online.js` has no eval case and cannot get one from this suite — its
premise is public evidence the synthetic fixtures do not have, and its own rule is
to stop when offline, so the correct behaviour would score zero. Any work here is
covered by `tests/online.test.mjs` and `tests/coverage.test.mjs` until Stage 2
gets its own suite built on **real public findings**, where ground truth is free
because it is public record and a `GHSA-` id cannot be guessed.

When the census lands, flip the guard in `coverage.test.mjs`
(`[online-triage] the downstream-users census is absent and unadvertised`) to
exercise it rather than pin its absence. The test says so itself.
