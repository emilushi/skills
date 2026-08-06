# Detailed Checkpoint Reference

The pass criteria for every checkpoint. Each must pass before the next stage
begins; a failure halts the pipeline and is not advisory.

## Which stage runs which checkpoint

Checkpoint numbers are the stable IDs the workflow scripts cite in their gate
code and their prompts, so they are kept rather than renumbered. This table is
the crosswalk between them, the stages in `SKILL.md`, and the six gates in
[gate-reviews.md](gate-reviews.md).

| Stage | Checkpoints | fp-check gate it feeds | Enforced in code by |
|---|---|---|---|
| 1a Intake | 1.1, 1.2, 1.3 | 1 Process | `missingArgs` |
| 1b Cheap pre-gate | brocards 2, 4, 5, 6 — see [brocards.md](brocards.md) | — | `dismissedByBrocard` |
| 1c Reachability | 2.1, 2.2 | 2 Reachability | `decideGate`, `alreadyFixedStands` |
| 1d Recovery | 2.3 | 3 Real Impact | `decideGate(!recovery)` |
| 1e Impact + severity | 2.4, 2.4b, 2.5, 5.2 | 3 Real Impact, 5 Math Bounds | `missingPrecondition`, `capSeverity` |
| 1f Adversarial | 3.1, 3.2, 3.3 + the 13 questions | 6 Environment | — synthesis |
| 1g Verdict | all six gates | all | `decideVerdict` |
| 2 Online | — see the online stage in `SKILL.md` | 2, 3 | `offlineProblem`, scope halt |
| 3 PoC | 4.1, 4.2, 4.3, 5.1, 5.2, 6.1 | 4 PoC Validation | `isAcceptableBuild`, `tallyChallenges`, `confidenceBand`, `alreadyFixedStands`, `severityCapViolation` |

Stages 2 and 3 run only when the user asks for them. **Stage 1 alone must reach
a verdict**, which is why the already-fixed search sits in 1c as well as in
Stage 3's challenge 4: on the cheap path challenge 4 never runs.

This file is the **criteria**. The calibration material — the lookup tables, red
flags and worked examples used to reach a verdict — lives in its siblings and is
not duplicated here:

| For | Read |
|-----|------|
| 2.3 recovery behaviour by runtime | [recovery-mechanisms.md](recovery-mechanisms.md) |
| 2.4b, 2.5, 3.1, 3.3 judgment calls | [validation-dimensions.md](validation-dimensions.md) |
| 1b, and the guards against wrongly dismissing | [brocards.md](brocards.md) |
| 1c, 1e, per bug class | [bug-class-verification.md](bug-class-verification.md) |
| 1f, the 13 questions and the red-flag list | [false-positive-patterns.md](false-positive-patterns.md) |
| 4.2 PoC construction rules | [poc-anti-patterns.md](poc-anti-patterns.md) |
| 4.1 test-integrated PoCs | [test-integration.md](test-integration.md) |

Placeholder, ellipsis, TODO and narration detection is `scripts/poc-lint.sh`'s
job, not a checklist item.

---

## Phase 1: Vulnerability Intake (REQUIRED)

### Checkpoint 1.1: Evidence Collection

**DO NOT PROCEED without source code evidence.**

Record the exact file, line, function and commit/version, how the finding
arrived (source review, user report, scanner, or a hypothesis from
documentation), and the actual code.

**Pass criteria:**

- Exact `file:line` reference, or a publicly accessible code URL
- Actual code shown, not described or paraphrased
- Code accessible for analysis

**If it fails:** request source code access. Mark BLOCKED.

### Checkpoint 1.2: Classification

Name the primary category — input validation bypass, logic error, race
condition/TOCTOU, panic or exception leading to a crash, cryptographic flaw,
access control bypass, resource exhaustion/DoS, state inconsistency, memory
safety — and state in 2-3 sentences what the *code* does wrong.

**Pass criteria:**

- Clear root cause in code terms
- Category matches the root cause
- Not vague: "missing validation" is not a root cause until you say *of what*

**If it fails:** re-analyze until the root cause is clear.

### Checkpoint 1.3: Initial Impact Assessment

State the claimed impact — process crash, data theft, DoS, privilege escalation,
and so on. Checkpoint 2.4 verifies or downgrades it.

**Pass criteria:**

- The claim is specific, not "causes problems"

---

## Phase 2: Attack Path Verification (MANDATORY)

**THIS IS THE PRIMARY QUALITY GATE. DO NOT SKIP.**

**Historical failure rate:** 95% of false positives come from skipping this
phase.

### Checkpoint 2.1: Entry Point Identification

State how attacker-controlled data enters — the RPC/API call, transaction, P2P
message, HTTP endpoint, contract call, file upload — and name the exact entry
package, function and signature. Give a concrete example input, not "malicious
payload goes here".

**Pass criteria:**

- Specific entry point, not "user sends a transaction"
- The attacker can actually call it; it is not internal-only
- The example input is concrete

**If it fails:** find the actual entry point, or mark NOT_EXPLOITABLE.

### Checkpoint 2.2: Validation Layer Enumeration

#### ⚠️ THIS IS THE MOST CRITICAL CHECKPOINT

**Purpose:** verify the attack actually reaches the vulnerable code. Most false
positives fail here.

List **every** validation or check between the entry point and the vulnerable
code. For each, give its type (authorization, input sanitization, rate limiting,
type checking, bounds checking), its `file:line`, what it checks, and whether the
attacker payload passes — with the code as evidence:

- **YES** — explain how the payload survives it
- **NO** — this BLOCKS the attack; stop and mark NOT_EXPLOITABLE
- **UNCERTAIN** — stop; the code must be traced before this can be answered

**Pass criteria:**

- Identified at least 1 layer (or confirmed none exist)
- For each layer, determined pass/fail with evidence
- ZERO "UNCERTAIN" layers — all verified
- If any blocks: mark NOT_EXPLOITABLE
- If all pass: document WHY, with code evidence

**If it fails:** an UNCERTAIN layer requires a code trace and HALTS. Any layer
that blocks means NOT_EXPLOITABLE.

### Checkpoint 2.3: Recovery Mechanism Check

**⚠️ CRITICAL: many "crash" vulnerabilities are actually just errors.**

Determine whether a panic or exception at the vulnerable location is caught
anywhere in the call stack — language-level, framework middleware, or a server
built-in — and state the impact that actually survives.
[recovery-mechanisms.md](recovery-mechanisms.md) carries the per-runtime
defaults, the search primitive to grep for in each, and the checklist to clear
before claiming a process crash.

**Pass criteria:**

- Checked for recovery (not assumed absent)
- If recovery exists: impact updated from crash to error
- If claiming "process crash": proved recovery does not catch it

**If recovery exists and the claim was a process crash:** impact drops to
Low/Informational — this is error handling, not a crash.

### Checkpoint 2.4: Impact Verification with Evidence

Verify each claimed impact against evidence, and grade it
**VERIFIED | NOT VERIFIED | DISPROVEN**.

**The grade is about whether an impact exists, not about whether the reported
one survived intact.** A real bug reported at inflated severity is **VERIFIED**,
carrying the impact the evidence actually supports — downgrading is the work
this checkpoint asks for, not a reason to fail it. Reserve NOT VERIFIED for
"no impact could be established either way", and DISPROVEN for "the evidence
shows there is no impact". Only VERIFIED continues to PoC development, so
grading a real-but-smaller impact as NOT VERIFIED throws away a genuine finding
— which is exactly what happened to a graded eval case before this paragraph
existed.

What counts as evidence depends on the class of impact claimed:

| Claimed impact | Evidence required |
|----------------|-------------------|
| Process/service crash | Panic or exception not caught by recovery; code on a critical execution path; no automatic restart; the crash reproduced |
| Denial of service | Resource exhaustion or infinite loop shown; the service becomes unresponsive; attack complexity is low; impact duration measured |
| Data theft / unauthorized access | The attacker gains access; the access-control bypass shown; sensitive data extracted; scope of exposure identified |
| Privilege escalation | A lower-privileged user gains higher privileges; the authorization check bypassed; elevated actions performed; persistence, where applicable |

**Pass criteria:**

- EVERY claimed impact has evidence
- No "would cause" or "might" — only "does cause", with proof
- If NOT VERIFIED, the claim is removed or marked hypothetical
- An impact smaller than the one claimed is still VERIFIED; record the smaller
  one and let checkpoint 5.2 apply the severity cap

**If it fails:** downgrade severity to match the verified impact only.

### Checkpoint 2.4b: Root Cause Attribution

**Purpose:** distinguish a flaw in our code from a flaw we merely fail to defend
against. This changes both severity and remediation.

State the proximate cause (which line fails) and the root cause (why it fails),
then classify:

| Classification | Meaning | Severity consequence |
|----------------|---------|----------------------|
| **Internal** | Missing validation in our own code | Full exploitability, severity as claimed |
| **Integration** | Missing validation of data from an external source | Requires an external failure to trigger — **cap at Medium** |
| **External** | The flaw is in a dependency; our code lacks defense | Workaround only; report upstream and document — **cap at Medium**, as for Integration |

For Integration or External, answer: is defensive validation required by design
(with evidence), and should this be handled at the integration layer?

**Pass criteria:**

- Classification chosen with code evidence, not asserted
- If Integration/External, the required external precondition is stated
  explicitly

**If it fails:** trace the data to its origin before classifying.

### Checkpoint 2.5: Exploitability Classification

**Purpose:** separate an exploitable vulnerability from a missing hardening
feature. Both are valid findings; they are not the same finding and must not
carry the same severity.

**The test:**

1. Does the code DO something it should not? → **VULNERABILITY**
2. Does the code LACK something it should have? → **HARDENING GAP**

**Tie-breaker when unclear:** "can an external attacker exploit this without user
cooperation?" YES → vulnerability. NO → hardening gap.

**Severity consequence:** a vulnerability is high priority and directly
exploited; a hardening gap is medium priority, defense-in-depth.

**Pass criteria:**

- Classification is justified by the test above, not by how serious it feels
- A hardening gap is not written up as an exploited vulnerability

**If it fails:** reclassify and recalibrate severity before proceeding.

---

## Phase 3: Threat Model Alignment

### Checkpoint 3.1: Scope Verification

Where a scope is defined — a security assessment, a disclosure program — decide
whether the vulnerability is in it: YES, NO (stop), or UNCERTAIN (clarify
first).

**Pass criteria:**

- Verified in-scope against an explicit statement
- Not in an excluded category
- Not already called out as known or accepted

### Checkpoint 3.2: Security Model Verification

Decide whether the finding violates a security property the target claims, or
sits within its stated trust assumptions. Three recurring shapes are usually out
of scope: "an admin can upgrade to malicious code" (centralization risk), an
exploit that requires governance compromise (trust assumption), and behaviour
the documentation states is trusted — cite where.

**Pass criteria:**

- This breaks a security property the target claims
- Not a feature working as intended

Where no documentation exists, proceed but note it.

### Checkpoint 3.3: Design Intent Classification

**Purpose:** privileged access is not a bug when it is intentional. Centralized
control is not by itself a vulnerability.

Check all three indicator classes and report how many fired:

1. **Explicit privilege indicators** — access control identifiers (`isAdmin`,
   `isSuperUser`, `requiresOwner`), function naming (`emergency*`, `override*`,
   `bypass*`, `force*`), or comments saying "intentional", "by design",
   "privileged"
2. **A symmetric pattern** — a guarded path and an unguarded sibling both exist,
   e.g. `withdraw()` requires approval and `emergencyWithdraw()` does not, which
   makes the unguarded sibling an intentional escape hatch rather than a bypass
3. **Documented as normal operation** — the README or architecture docs describe
   the behaviour, or tests cover it as expected

**If 2 or more fire:** search the codebase for usage patterns and check test
coverage. If confirmed intentional → mark NOT_VULNERABLE and STOP.

**Pass criteria:**

- All three indicator classes checked, not assumed absent
- If 2+ indicators fire, the confirmation search was actually performed
- The finding is not "an admin can do admin things"

**If it fails:** mark NOT_VULNERABLE. Do not write a PoC for intended behaviour.

---

## Phase 4: PoC Development (ONLY After 1-3 Pass)

**IF ANY PHASE 1-3 CHECKPOINT FAILED, DO NOT WRITE POC CODE.**

### Checkpoint 4.1: PoC Type Selection

Choose the cheapest form that works, in this order:

1. **Test-integrated** — PREFERRED where a suite exists. Name the framework and
   the tests path. The test must fail while the vulnerability exists and pass
   once it is fixed. See [test-integration.md](test-integration.md).
2. **Standalone script** — name the language and whether it runs against local,
   testnet or a fork.
3. **Testnet demonstration** — record the testnet URL and the transaction hash.

**Pass criteria:**

- An appropriate type selected
- The necessary infrastructure is available

### Checkpoint 4.2: Code Implementation

[poc-anti-patterns.md](poc-anti-patterns.md) carries the construction rules and the
required-structure table. The one that invalidates everything else:

**Real code invocation.** The PoC imports and calls the actual code under test.
Never a copy-pasted or reimplemented vulnerable function. Mocks replace
dependencies only, NEVER the vulnerable component. If the PoC cannot call real
code, document why and get approval.

Beyond that, every PoC carries setup (dependencies and install/run commands), a
concrete payload with every parameter filled, an execution section that actually
calls the vulnerable path — not commented out, not a print statement describing
what would happen — a validation section that asserts on the outcome, and
cleanup where the run was destructive.

### Checkpoint 4.3: Execution and Validation

**REQUIRED: actually run the PoC.** Record the platform and architecture, the
target commit or version, the exact command, and the full output.

**Pass criteria:**

- The PoC actually executed
- The output demonstrates the vulnerability
- Reproducible

**If it fails:** debug until it works, or document why it cannot.

---

## Phase 5: Self-Critical Review (MANDATORY)

**THIS PHASE CANNOT BE SKIPPED.**

### Checkpoint 5.1: Devil's Advocate Analysis

**Assume you are a skeptical auditor reviewing this PoC. Your job is to REJECT
it if possible.** For each challenge below, state the strongest form of the
argument against the finding, then whether the evidence rebuts it. Uncertainty is
not a rebuttal.

| # | Challenge | The argument to make |
|---|-----------|----------------------|
| 1 | Reachable? | The attacker cannot reach the vulnerable code |
| 2 | Recoverable? | The impact is less than claimed, e.g. the panic is caught by defer/recover |
| 3 | By design? | This is intended behaviour, e.g. governance is trusted |
| 4 | Already fixed? | A fix already exists — search the issue tracker, `git log --grep`, and published advisories, and report what you searched |
| 5 | Real deployment? | It is not exploitable in practice — the path is unreachable in a default configuration, real deployments add protections in front of it, or the code path is never used |

**Challenge 4 is not scored like the others.** A fix that exists means
**DO NOT SUBMIT**, and this outcome overrides the confidence band. An incomplete
or partial fix is reported as such.

**Confidence Level — this is the canonical scale for this skill.**

Bands are half-open so that every score carries exactly one label. Derived from
how many of the 5 challenges above were defeated by evidence; a challenge that
cannot be defeated with evidence counts as won by the challenge, not as a tie.

| Band | Range | Derivation | Action |
|------|-------|-----------|--------|
| HIGH | 90-100% | 5 of 5 challenges defeated | Proceed |
| MEDIUM | 50-89% | 3 or 4 defeated | Proceed only with uncertainties documented |
| LOW | 10-49% | 1 or 2 defeated | Do not submit; gather evidence or downgrade |
| NONE | 0-9% | 0 defeated | False positive, DO NOT SUBMIT |

The bands are the only gate. There is no separate percentage threshold: the
derivation is discrete (0-5 challenges), so 3 and 4 defeated both land in
MEDIUM and no run can produce a score that a 70% cut would separate. MEDIUM
means proceed **with the uncertainties documented**; LOW and NONE mean do not
submit.

Any other confidence scale appearing elsewhere in this skill's references is
superseded by this table.

**Pass criteria:**

- All 5 challenges completed honestly
- Evidence-based rebuttals, not speculation
- Confidence matches evidence quality

### Checkpoint 5.2: Severity Calibration

State the original severity and the severity after review, and where they differ,
why — "thought this was a process crash, but recovery makes it an error response
→ Medium, not High".

Justify it on both axes:

- **Impact** — direct loss (amount or TVL%), disruption (permanent, hours,
  minutes, none), who is affected (all, a subset, one) and how many, and the
  cost and time to recover
- **Exploitability** — complexity, privileges required, whether user interaction
  is needed, and attacker cost

**Pass criteria:**

- Severity matches industry standards (CVSS or equivalent)
- The rating is supported by evidence
- Not speculative or inflated

---

## Phase 6: Documentation

### Checkpoint 6.1: Report Completeness

Seven sections, all required:

| Section | Must contain |
|---------|--------------|
| Executive Summary | One paragraph, a clear impact statement, no hyperbole |
| Technical Details | Exact `file:line`, root cause, the attack path trace, the validation layers |
| Proof of Concept | Working executable code, setup instructions, execution output, the impact demonstrated |
| Attack Path Verification | Entry point, validation layers enumerated, recovery checked, impact evidenced |
| False Positive Analysis | The 5 challenges, the confidence assessment, the uncertainties |
| Remediation | A specific fix — NOT "add validation" — as a diff or pseudo-code, why it addresses the root cause, and any breaking changes |
| References | Program URL where applicable, target documentation, similar vulnerabilities, the source repository |

**Pass criteria:**

- All sections complete
- No placeholders (`$XXM`, `$XX`), no TODOs, no "TBD"

---

## Checkpoint Failure Protocol

The output form is in SKILL.md. The rule here is what counts as a failure:

| Failure | Response |
|---------|----------|
| Missing evidence | Request source code, or mark BLOCKED |
| Uncertain validation layer | Code trace required |
| Recovery exists | Downgrade the impact claim |
| A challenge wins | Lower confidence, or mark NOT_EXPLOITABLE |
| Placeholder detected | Complete the code |

In every case: HALT. Do not proceed.
