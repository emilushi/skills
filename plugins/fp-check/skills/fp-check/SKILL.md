---
name: fp-check
description: "Verifies whether a suspected security bug is real, returning TRUE POSITIVE, FALSE POSITIVE or NEEDS MORE INFO with the evidence behind it. Runs a static verification stage always, and adds online policy checks or a built-and-executed PoC on request. Use when asked whether a finding is real, exploitable, in scope, already fixed, or a false positive, or to triage findings from a scanner or an agentic discovery run — not for hunting new bugs."
allowed-tools: Read Grep Glob LSP Bash Write Edit Workflow AskUserQuestion Task TaskCreate TaskUpdate TaskList TaskGet
---

# False Positive Check

Three stages in a fixed order. **Stage 1 always runs and reaches a verdict on its
own.** Stages 2 and 3 run only when the user asks for them, and each can only
narrow or correct what Stage 1 returned.

```text
              ┌─ Stage 1: STATIC  (always) ──────────────────────────┐
  finding ──> │  brocard pre-gate → per-layer reachability →          │
              │  recovery → already-fixed → impact + severity →       │
              │  adversarial → the six gates                          │
              └───────────────────────┬──────────────────────────────┘
                                      │ verdict + severity + open questions
  Q2: online checks? ──yes──> ┌───────▼─ Stage 2: ONLINE ────────────┐
                              │  policy → scope → past bugs → users   │
                              │  may halt: out-of-scope, duplicate    │
                              └───────────────┬──────────────────────┘
  Q1: validate by PoC? ──yes──> ┌─────────────▼─ Stage 3: POC ────────┐
                                │  build → execute → 5 challenges →    │
                                │  confidence band → report            │
                                └──────────────────────────────────────┘
```

The gates in each stage are **code**, not instructions. A workflow script returns
a status you cannot talk it out of; that is the point of the port, and it is where
the measured difference against a linear checklist came from.

## When to Use

- "Is this bug real?", "is this a true positive?", "is this a false positive?"
- "Verify this finding", "check if this is exploitable"
- "Is this already fixed?", "is this in scope for their bounty?"
- Filtering findings from a scanner or an agentic discovery run before human review

## When NOT to Use

- Finding or hunting for bugs ("find bugs", "audit this code") — this verifies a
  finding you already have
- General code review for style, performance, or maintainability
- When the user explicitly asks for a quick look without verification

## Step 0: Ask the two questions, then restate the claim

**Ask both questions before Stage 1 runs**, not between stages. The user should
not be interrupted mid-analysis, and knowing the answers up front lets Stage 1
record the open questions each later stage will resolve.

| Question | Default | Why it is a question and not automatic |
|---|---|---|
| **Q1. Validate by building a PoC?** | **no** | Measured at **$13.34 against $2.15** on the same finding — 6x. Worth it to settle a disputed finding; wasteful when static analysis already answered. |
| **Q2. Run online checks?** | **no** | Needs network access and a real upstream project. Stage 2 fails closed when offline, so defaulting it on makes every offline invocation halt. |

**Read the answers out of the request first, and only fall back to
`AskUserQuestion` when they are genuinely absent.** Phrasings that answer Q1:
*"build a PoC"*, *"prove it"*, *"write an exploit"*, *"demonstrate it"* → yes;
*"static only"*, *"don't write a PoC"*, *"just tell me if it's real"* → no.
Phrasings that answer Q2: *"check their security policy"*, *"is this in scope"*,
*"look for duplicates"*, *"check upstream"* → yes; *"offline"*, *"don't go
online"*, *"work from the code"* → no.

Asking when the answer was already given is not merely rude — under
`claude plugin eval` and any other non-interactive harness there is nobody to
answer, so the question either hangs until the timeout or silently falls through
to the default. Both defaults are **no**, so a plugin that always asks measures
Stage 1 and reports it as though all three stages had run.

Then restate the bug in your own words. **Half of false positives collapse here** —
the claim stops making sense when stated precisely. Establish, and if you cannot,
ask:

- **The claim** — "heap overflow in `parse_header()` when `content_length` > 4096"
- **The alleged root cause** — "no bounds check before the `memcpy` at line 142"
- **The trigger** — "an HTTP request with an oversized Content-Length"
- **The claimed impact** — "RCE via controlled heap corruption"
- **The threat model** — who the attacker is, what capability they already hold,
  how they exploit it, what harm results. A report that cannot answer *"an
  attacker with [capability] can [action] to achieve [impact]"* is dismissible on
  its face, and Stage 1 rejects the dispatch without it.
- **The bug class** — and read
  [bug-class-verification.md]({baseDir}/references/bug-class-verification.md) for
  what that class specifically has to establish
- **The entry point and the layers between it and the sink** — this is the
  dispatch's most important input; see below

## Enumerating the layers

Stage 1 spends one agent per validation layer, and the list you pass is what it
inspects. Walk the path from the entry point to the sink and name every check
between them: authorization, input sanitisation, allowlists, rate limiting, type
checking, bounds checking.

**If you believe nothing validates the path, pass that as one explicit layer.** An
empty list is rejected rather than treated as "no checks exist" — a forgotten
field and a deliberate "nothing guards this" are the same value, and the second
one is a claim that deserves an agent.

At most **4** layers are dispatched. More than that is rejected before anything is
spent: narrow the attack path or split the finding.

## Routing: standard or deep

Stage 1 picks the route itself from the dispatch, and you can override it with
`route: 'deep'` when the user asks for full verification.

**Deep** adds three proofs to the reachability phase — API contracts and
environmental protections, the algebraic bounds proof, and race feasibility — and
runs the full 13 devil's-advocate questions instead of the 7-question spot check.
It fires automatically on 3+ layers, on a concurrency or bounds bug class, and on
`crossComponent: true` or `ambiguous: true`.

**Standard is the default and is doing real work.** Measured: a linear checklist
never escalated on any of seven eval cases and still matched a full pipeline at
2.3x less cost. Do not reach for `deep` to feel thorough.

## Dispatch

Wait for each workflow. `Workflow` returns **on launch**, so the run continues in
the background and ending your turn tears it down: measured, an orchestrator
ended its turn 2.4 seconds after dispatching a review stage and the workflow was
**killed** 140 seconds in, after four of five challenges had finished and before
any report existed. **Do not end your turn until the workflow has returned.** Use
`TaskOutput` with `block: true` and a timeout of at least 600000.

### Stage 1 — always

```text
Workflow({ name: 'fp-check:triage-static', args })

args = {
  baseDir:    the skill directory (references/ and scripts/ resolve under it)
  finding: {
    summary:        one sentence, what the code does wrong
    sink:           file:line of the vulnerable operation
    component:      the module or service it lives in
    claimedImpact:  the impact as reported, before verification
    bugClass:       injection, overflow, race, TOCTOU, authz bypass, crypto, ...
    threatModel:    attacker, capability held, exploit mechanism, harm
  }
  entryPoint: {
    description:  how attacker data enters — the endpoint, RPC, message, upload
    location:     file:line of the entry point itself
    payload:      a concrete example input, not "malicious payload here"
  }
  layers: [ { name, location, checks } ]     at most 4; never empty
  scope:  a STRING describing the declared scope; an object interpolates as
          [object Object] and is rejected
  route:  'standard' | 'deep'                optional; computed when omitted
  crossComponent: true                       optional routing signal
  ambiguous:      true                       optional routing signal
}
```

Returns one of `TRUE_POSITIVE`, `FALSE_POSITIVE`, `DISMISSED`, `NOT_EXPLOITABLE`,
`NOT_VULNERABLE`, `ALREADY_FIXED`, `OUT_OF_SCOPE`, `NEEDS_MORE_INFO`, `BLOCKED` —
each with a `reason`, and with `severity` and `severityCorrection` when it reached
an impact.

### Stage 2 — only if Q2 was yes

```text
Workflow({ name: 'fp-check:triage-online', args })

args = {
  baseDir, finding                  as above
  verification:  triage-static's return value, forwarded VERBATIM
  project: { name, url }            the upstream project to look up
  sources: [ { label, query } ]     at least one public venue, at most 6:
                                    github-issues, github-prs,
                                    github-advisories, mailing-list, immunefi
}
```

Returns `TRIAGED`, `OUT_OF_SCOPE`, `DUPLICATE`, `NEEDS_MORE_INFO`, `BLOCKED`, or
`OFFLINE`. **`OFFLINE` is a correct outcome, not an error** — every claim this
stage makes is about the project's *current* public posture, and it will not make
one from memory.

### Stage 3 — only if Q1 was yes

Only a `TRUE_POSITIVE` justifies building an exploit, and the script enforces
that: `verification.status` is checked, because a failing Stage 1 return carries a
fully populated `impact` and `severity` too, so forwarding one satisfies every
other field and buys a PoC for a finding that failed its own gates.

```text
Workflow({ name: 'fp-check:triage-poc', args })

args = {
  baseDir, finding                  as above
  verification:  triage-static's return value, forwarded VERBATIM
                 (its impact.impact, impact.rootCause, impact.classification,
                  severity, severityCorrection and history.fixed /
                  history.searched are all read)
  envelope: {
    level:        1-5, per safety-guidelines.md
    hosts:        array of permitted targets; [] means local process only
    destructive:  boolean; only permitted at levels 1-2
  }
  candidates: [ { name, description, entryPoint, payload } ]   at most 2 tried
}
```

Returns `REPORTED`, `DO_NOT_SUBMIT`, `BUILD_FAILED`, `NO_CANDIDATES`, or
`BLOCKED`.

## Completion Gate

Before you report anything, check what actually came back.

1. **Did the workflow return at all?** A workflow that was **killed** or
   **aborted** has not failed its gates — it has not finished them. Say so and
   re-dispatch. Never infer a verdict from partial agent output; doing that is the
   exact mistake this skill exists to prevent.
2. **Read `status`, not the shape.** Failing returns carry populated payloads, so
   a result that looks complete may be a `NEEDS_MORE_INFO`.
3. **Relay the `reason` verbatim.** Every terminal status carries one, and it
   names the layer, clause, gate or commit that decided the outcome. That
   specificity is the deliverable.
4. **State the verdict in your final response**, with the severity and the
   evidence. Stage 3 writes its report to a file, and a file is not an answer.
   If Stage 3 ran, state the confidence band and the N/5 challenge tally too.

## Verdicts

Stage statuses collapse onto three user-facing verdicts:

| Verdict | From | Report as |
|---|---|---|
| **TRUE POSITIVE** | `TRUE_POSITIVE`, `REPORTED` | `BUG #N TRUE POSITIVE — <description>`, with severity |
| **FALSE POSITIVE** | `DISMISSED`, `NOT_EXPLOITABLE`, `NOT_VULNERABLE`, `FALSE_POSITIVE`, `DO_NOT_SUBMIT` | `BUG #N FALSE POSITIVE — <the reason, verbatim>` |
| **NEEDS MORE INFO** | `NEEDS_MORE_INFO`, `BLOCKED`, `OFFLINE`, `BUILD_FAILED` | `BUG #N NEEDS MORE INFO — <the missing fact>` |

`ALREADY_FIXED` and `DUPLICATE` are reported as retractions with their reference,
and `OUT_OF_SCOPE` as a scope answer rather than a judgement on the bug.

**NEEDS MORE INFO is not a hedge and must not be rounded to FALSE POSITIVE.**
"The claim as stated is unproven" is not "no vulnerability exists"; conflating the
two killed a real, demonstrable finding in this plugin's own history and scored
the case below the arm that had no plugin at all.

## Batch Triage

1. Run Step 0 for every finding first — restating the claims collapses the
   obvious false positives immediately and costs nothing.
2. Ask the two questions **once**, for the batch.
3. Dispatch Stage 1 per finding. Each is independent; they may run concurrently.
4. After all of them, check for **exploit chains**: findings that individually
   failed a gate may combine into a viable attack. Two `NOT_EXPLOITABLE` results
   whose blocking layers are different is the shape to look for.

## Rationalizations to Reject

| Rationalization | Why it's wrong | Required action |
|---|---|---|
| "Rapid analysis of the remaining bugs" | Every finding gets the same dispatch | Go back and dispatch the next one |
| "This pattern looks dangerous, so it's a vulnerability" | Pattern recognition is not analysis | Let Stage 1 trace the layers |
| "I can see it's unreachable, no need to dispatch" | That judgement is what the per-layer fan-out exists to make independently. It is also the judgement a linear read gets wrong: 6 of 6 measured runs named the blocking guard and only 1 of 6 concluded correctly | Dispatch |
| "The sink is genuinely injectable, so the finding is real" | Attacker control **of the sink** is not control of any reachable entry point. A PoC calling the sink directly is the canonical false positive with an exploit attached | Gate 2 (Reachability) decides this, on the entry point |
| "Similar code was vulnerable elsewhere" | Each context has different validation, callers and protections | Verify this instance |
| "This is clearly critical" | LLMs over-rate severity, and the severity caps are arithmetic | Let Stage 1e apply them |
| "I'll skip the PoC question and just build one" | A PoC costs 6x and the user gets a bill they did not agree to | Ask, or read the answer from the request |

## References

- [checkpoints.md]({baseDir}/references/checkpoints.md) — the pass criteria for
  every checkpoint, and the crosswalk from stages to checkpoints to the six gates
- [brocards.md]({baseDir}/references/brocards.md) — the cheap pre-gate, and the
  guards against wrongly dismissing a valid finding
- [gate-reviews.md]({baseDir}/references/gate-reviews.md) — the six gates and the
  verdict format
- [false-positive-patterns.md]({baseDir}/references/false-positive-patterns.md) —
  the 13-item checklist and the four red-flag lists
- [bug-class-verification.md]({baseDir}/references/bug-class-verification.md) —
  what each bug class specifically has to establish
- [recovery-mechanisms.md]({baseDir}/references/recovery-mechanisms.md) — what
  each runtime does on a panic, and the checklist before claiming a crash
- [validation-dimensions.md]({baseDir}/references/validation-dimensions.md) —
  scope, security model, and design-intent judgement calls
- [evidence-templates.md]({baseDir}/references/evidence-templates.md) — data
  flow, algebraic bounds proofs, attacker control, devil's advocate
- [poc-anti-patterns.md]({baseDir}/references/poc-anti-patterns.md) — PoC
  construction rules, enforced by `scripts/poc-lint.sh`
- [test-integration.md]({baseDir}/references/test-integration.md) — framework
  patterns for a test-integrated PoC
- [safety-guidelines.md]({baseDir}/references/safety-guidelines.md) — the five
  envelope levels
