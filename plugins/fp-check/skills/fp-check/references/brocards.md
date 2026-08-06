# Brocards: the cheap pre-gate

Seven falsifiable tests applied before any data-flow work. Each is cheap — a
question about the *shape* of the claim, not a trace through the code — and each
can dismiss a finding outright. Stage 1b runs four of them; the rest are folded
into the stages named below so nothing is checked twice.

Adapted from William Woodruff,
["Brocards for vulnerability triage"](https://blog.yossarian.net/2026/04/11/Brocards-for-vulnerability-triage)
(2026). The plugin `vulnerability-triage-brocards` carries the full worked
examples and edge cases; this file carries what Stage 1 enforces.

## Three verdicts, and why the third one exists

| Verdict | Meaning |
|---|---|
| **PASS** | the finding survives this test |
| **DISMISS** | the finding fails this test; the reason is the finding's epitaph |
| **NEEDS-MORE-INFO** | the evidence available cannot decide it; name the missing fact |

**A NEEDS-MORE-INFO does not end the analysis.** Only a DISMISS is terminal here.
An unresolved question is carried into the impact and verdict stages, surfaced to
both, and blocks a TRUE POSITIVE at the verdict — where the call is made by the
agent holding all the evidence rather than by the cheapest one to raise a hand.

That is a correction, and the sweep that forced it is worth knowing about. When a
NEEDS-MORE-INFO could end the stage, aborting did not produce a safe non-answer: it
produced an *unguarded* one. The pre-gate stopped, the PoC stage then refused for
want of a TRUE_POSITIVE, and the orchestrator — still holding a user request for a
PoC — built one outside every gate and reported an uncapped Critical. Fail-closed
at the gate became fail-open one level up, at 4-5x the cost for an identical score.

**The corollary for brocard 5, and the reason it was the one that fired:** if the
document that would settle a test is not in this repository, answer **PASS** and
name the document. A governing spec, an upstream service contract and a downstream
consumer's guidance are all outside the reach of a test about what *this* project
documents. Answering NEEDS-MORE-INFO on an external document makes the test
structurally unanswerable for every finding whose root cause is an integration.

**NEEDS-MORE-INFO is not a soft DISMISS and must never be collapsed into one.**
The most expensive gate bug in this plugin's history was exactly that
conflation: an impact checkpoint read "the claim as stated is unproven" as "no
impact exists" and killed a real, demonstrable finding, scoring the case *below*
the arm that had no plugin at all. `TRUE POSITIVE` / `FALSE POSITIVE` has no room
for "I cannot tell yet", so the schema carries the third state explicitly and
`decideVerdict` returns it rather than guessing.

## Which stage runs which

| # | Brocard | Where |
|---|---|---|
| 1 | No vulnerability without a threat model | Stage 1a — `missingArgs` rejects a finding with no threat model |
| 2 | **No exploit from the heavens** | **Stage 1b** |
| 3 | No vulnerability outside of usage | Stage 1c, as the layer/reachability analysis. Its library rider goes to Stage 2 |
| 4 | **No vulnerability from standard behavior** | **Stage 1b** |
| 5 | **No vulnerability from documented behavior** | **Stage 1b** |
| 6 | **No cure worse than the disease** | **Stage 1b**, and again as a severity input in 1e |
| 7 | The report is neither necessary nor sufficient | Stage 1g, folded into the verdict |

---

## Brocard 2: No exploit from the heavens

Dismiss when the capability the attack *requires* already equals or exceeds the
impact it *grants*. If the attacker must already hold the power the exploit would
give them, the finding is redundant.

**The test:** does triggering this require capabilities that already subsume its
impact?

- Content injection that needs an active MITM — DISMISS; an active MITM can
  already inject content.
- Memory corruption via `ctypes` in CPython — DISMISS; using `ctypes` that way
  already requires arbitrary code execution in the process.
- SSRF from a user-controlled URL — PASS; a string (low capability) buys internal
  network access (high impact).

**Do not misapply it to privilege-escalation chains.** Limited access exploited
into elevated access is valid: the post-exploit capability exceeds the
pre-exploit one. And "the attacker can do X" is not "the attacker can do X *in
this context*" — code execution inside a sandbox is not code execution with the
sandbox's privileges.

## Brocard 4: No vulnerability from standard behavior

Dismiss when the behaviour is a correct implementation of a specification. The
vulnerability, if there is one, is in the standard.

**The test:** does the spec require or permit this? If so, the report targets the
standard, not the code.

- An HTTP server following RFC 7230's robustness principle — DISMISS, and send
  the concern to the standards body.
- "Uses broken MD5" against HMAC-MD5 — DISMISS; HMAC does not rest on collision
  resistance.

**The nuance inverts the test, and dropping it turns this into a false-negative
machine.** An implementation that *voluntarily* claims a stricter posture than
the spec requires **is** vulnerable when that strictness fails. A library
documented as TLS 1.3-only that silently falls back to a 1.2 CBC suite has
broken its own promise, and the spec permitting 1.2 is no defence. Check what the
implementation claims about itself before dismissing on what the standard allows.

## Brocard 5: No vulnerability from documented behavior

Dismiss when the behaviour is explicitly documented, especially where the
documentation carries the security implication or the usage caveat.

**The test:** does the project's own documentation describe this and warn against
the misuse? If so, dismiss the report *against this project*.

**The nuance is a redirection, not a dismissal.** Downstream usage that violates
documented guidance is a valid finding **against the downstream project**. The
answer is not "not a bug", it is "not a bug *here*" — say which project it is a
bug in, or the report is quietly lost. Where the target is a library, that
question is Stage 2's `triage-online-users` job: whether real, popular consumers
actually exhibit the unsafe pattern.

## Brocard 6: No cure worse than the disease

Dismiss, or downgrade, when the remediation would do more harm than the
vulnerability. Weigh three things: severity in practice, the cost and disruption
of the fix, and the blast radius of the remediation across the dependency graph.

**The test:** would fixing this cause more disruption than the bug?

Nothing else in this skill evaluates remediation cost, so this is the only place
a "technically real, not worth the ecosystem breakage" finding gets an honest
hearing. It is also a severity input in Stage 1e, not only a dismissal: a finding
whose only safe fix is a breaking API change is usually reported at a lower
severity with the trade-off stated, rather than dismissed.

## Brocard 7: The report is neither necessary nor sufficient

A CVE ID or a formal report does not prove a vulnerability exists, and the
absence of one does not prove safety.

**The test:** strip the CVE number and the CVSS score. Does the technical
description alone justify action?

---

## Rationalizations to reject, in both directions

fp-check's 13 questions run 11 against the finding and 2 for it. A triage tool
that guards one direction drifts toward it, so the dismissal-side guards below
carry equal weight in Stage 1f.

### Wrongly dismissing a valid finding

- *"It's only reachable in debug mode."* Verify debug mode is truly never enabled
  in production. Plenty of deployments ship with debug flags on.
- *"The attacker would need local access."* Local access is a realistic threat
  model for most containerised services.
- *"Nobody uses that API."* Confirm with usage data, not assumption — integration
  tests, deployment configs, downstream dependents.
- *"The spec allows it."* Check whether the implementation claims stricter
  behaviour than the spec requires (brocard 4's nuance).
- *"The claim as stated is unproven."* That is NEEDS-MORE-INFO, or a smaller
  verified impact. It is not "no impact exists".

### Wrongly accepting an invalid finding

- *"It has a CVE, so it must be real."* Brocard 7 exists for this.
- *"The CVSS score is high."* CVSS is a formula, not a verdict.
- *"Better safe than sorry."* Brocard 6 requires evaluating the fix cost.
- *"We can't prove it's NOT exploitable."* The burden is on the report to
  establish a threat model (brocard 1).
- *"Other projects patched it."* Other projects have different usage patterns
  (brocard 3).
- *"We should include it to pad the report."* A dismissed finding with documented
  reasoning is worth more in a deliverable than a false positive.
