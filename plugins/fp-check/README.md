# fp-check

Verify whether a suspected security bug is real, and say why — with the gates
enforced in workflow code rather than self-reported by the agent applying them.

## Overview

Three stages in a fixed order, behind two questions asked once up front.

| Stage | When | What it does |
|---|---|---|
| **1 Static** | always | brocard pre-gate → one agent per validation layer → recovery → already-fixed search → impact and severity → adversarial pass → the six gates |
| **2 Online** | on request | the project's published policy, bounty scope, past reports and downstream users. Fails closed when offline |
| **3 PoC** | on request | build the exploit against the real code in an isolated worktree, execute it, then five agents that did not build it try to reject it |

**Stage 1 alone reaches a verdict.** Stages 2 and 3 can only narrow or correct
it, and both default to off: a full PoC pipeline was measured at **$13.34 against
$2.15** on the same finding, which is worth paying to settle a disputed finding
and wasteful when the static analysis already answered.

Every finding gets **TRUE POSITIVE**, **FALSE POSITIVE**, or **NEEDS MORE
INFO** — and the third is not a hedge. Conflating "the claim as stated is
unproven" with "no vulnerability exists" killed a real, demonstrable finding
during this plugin's development, so the schema carries that state explicitly and
the verdict function returns it rather than guessing.

## Installation

```
/plugin install fp-check
```

## Triggers

- "Is this bug real?" / "Is this a true positive?" / "Is this a false positive?"
- "Verify this finding" / "Check if this is exploitable"
- "Is this already fixed?" / "Is this in scope for their bounty?"
- Filtering findings out of a scanner or an agentic discovery run

It does **not** activate for bug hunting ("find bugs", "audit this code").

## What is enforced in code

This is the point of the workflow port. Each rule below was once prose that an
agent was asked to honour; each is now a pure function whose answer the
orchestrator cannot argue with:

| Rule | Enforced by |
|---|---|
| At least one validation layer is inspected — an empty list dispatched zero agents and fell through to a verdict | `missingArgs`, `decideGate` |
| Recovery was *checked*, not assumed absent | `decideGate(!recovery)` |
| An integration or external root cause states the precondition it needs | `missingPrecondition` |
| A fix that exists upstream retracts the finding, and has to cite a commit | `upstreamFixStands`, `alreadyFixedStands` |
| An integration/external root cause, or a hardening gap, caps at Medium | `capSeverity`, `severityCapViolation` |
| All six gates pass before anything is called a TRUE POSITIVE | `decideVerdict` |
| Only a TRUE POSITIVE justifies building an exploit | `verification.status` in Stage 3 |
| A PoC is built, executed and lint-clean, then re-checked by someone else | `isAcceptableBuild`, `artifactProblem` |
| A challenge with no verdict counts *for* the challenge | `tallyChallenges`, `confidenceBand` |
| No scope or severity claim is made from memory when offline | `offlineProblem` |
| Out-of-scope needs a quoted policy clause; "probably" is `unclear` | `scopeHalt` |
| Destructive PoC operations only at safety levels 1–2 | `missingArgs` in Stage 3 |

Two of them carry a measured delta. In a head-to-head over identical cases, the
arm that enforced the already-fixed retraction scored 3/3 against 0/3, and the arm
that enforced the severity cap 3/3 against 0/3. Both had previously been stated in
a prompt and self-reported.

## Components

```
workflows/
  triage-static.js     Stage 1, always
  triage-online.js     Stage 2, on request
  triage-poc.js        Stage 3, on request
skills/fp-check/
  SKILL.md             routing, the two questions, the dispatch contract
  references/          the criteria, the brocards, the runtime lookup tables
  scripts/poc-lint.sh  the PoC quality gate
tests/                 four layers; see tests/README.md
evals/                 7 cases with ablation baselines
```

### Reference files

| File | Purpose |
|------|---------|
| [checkpoints.md](skills/fp-check/references/checkpoints.md) | The pass criteria for every checkpoint, and the crosswalk from stages to checkpoints to the six gates |
| [brocards.md](skills/fp-check/references/brocards.md) | The cheap pre-gate, and the guards against wrongly dismissing a valid finding |
| [gate-reviews.md](skills/fp-check/references/gate-reviews.md) | The six gates and the verdict format |
| [false-positive-patterns.md](skills/fp-check/references/false-positive-patterns.md) | The 13-item checklist and the four red-flag lists |
| [bug-class-verification.md](skills/fp-check/references/bug-class-verification.md) | What each bug class specifically has to establish |
| [recovery-mechanisms.md](skills/fp-check/references/recovery-mechanisms.md) | What each runtime does on a panic, and the checklist before claiming a crash |
| [validation-dimensions.md](skills/fp-check/references/validation-dimensions.md) | Scope, security model, and design-intent judgement calls |
| [evidence-templates.md](skills/fp-check/references/evidence-templates.md) | Data flow, algebraic bounds proofs, attacker control, devil's advocate |
| [poc-anti-patterns.md](skills/fp-check/references/poc-anti-patterns.md) | PoC construction rules, enforced by `scripts/poc-lint.sh` |
| [test-integration.md](skills/fp-check/references/test-integration.md) | Framework patterns for a test-integrated PoC |
| [safety-guidelines.md](skills/fp-check/references/safety-guidelines.md) | The five envelope levels |

## Routing

Stage 1 picks its own route from the dispatch, and **standard is the default
because the cheap path is doing real work**: measured, a linear checklist never
escalated on any of seven eval cases and still matched a full pipeline at 2.3x
less cost.

**Deep** adds three proofs — API contracts and environmental protections, the
algebraic bounds proof, and race feasibility — and runs the full 13
devil's-advocate questions instead of the 7-question spot check. It fires
automatically on 3+ validation layers, on a concurrency or bounds bug class, and
on an explicitly cross-component or ambiguous claim.

## Testing

```bash
make check                                       # what CI runs
bash plugins/fp-check/tests/mutation-gate.sh     # not in CI; run it by hand
```

The mutation gate breaks each covered behaviour in a sandbox copy and requires
the suite to go red. Anything that survives is testing the model, not the plugin.

`tests/README.md` is the file to read before changing anything here. It records
every dead end this plugin has been down — including four paid eval sweeps that
were invalid, each of which produced a plausible-looking number.

## Credits

The brocard pre-gate is adapted from William Woodruff,
["Brocards for vulnerability triage"](https://blog.yossarian.net/2026/04/11/Brocards-for-vulnerability-triage);
`vulnerability-triage-brocards` carries the full worked examples and edge cases.
Stages 1 and 3 graft the checkpoint gates and the five independent
false-positive challenges from the `concept-prover` plugin, and Stage 2 the roles
from `online-triage`.
