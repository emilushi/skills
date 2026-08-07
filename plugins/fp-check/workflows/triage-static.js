export const meta = {
  name: 'triage-static',
  description:
    'Stage 1: brocard pre-gate, per-layer reachability, recovery, already-fixed history, impact and severity, then the six gates as code',
  whenToUse:
    'Always, and first. Runs offline against the code in front of you and reaches a TRUE POSITIVE / FALSE POSITIVE / NEEDS MORE INFO verdict on its own. Stages 2 and 3 only narrow or correct what this returns.',
  phases: [
    { title: 'Brocards' },
    { title: 'Layers' },
    { title: 'Impact' },
    { title: 'Verdict' },
  ],
}

// args: { baseDir, finding, entryPoint, layers[], scope, route }
//
// The shape and every defensive habit below is inherited from concept-prover's
// verify-attack-path.js, where each one is a bug that shipped. The comments
// recording why are kept: they are the only reason the next person does not
// re-simplify them away.

// `args || {}`, not `args`. A dispatch with no args at all — a mistyped `arg:`,
// or an omitted block — makes this destructure throw before `missingArgs` can
// report anything, so the run dies with a TypeError instead of returning
// BLOCKED.
const { baseDir, finding, entryPoint, layers = [], scope } = args || {}

const MAX_LAYERS = 4

// `additionalProperties: false` on every schema. It is the only thing stopping
// an agent returning a shape this script never contracted for, and a volunteered
// key is a signal the prompt and the schema have drifted.
// test_every_schema_forbids_extra_keys pins it across all three workflows.

const BROCARD_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['verdict', 'missingFact', 'evidence'],
  properties: {
    verdict: { enum: ['PASS', 'DISMISS', 'NEEDS_MORE_INFO'] },
    // On NEEDS_MORE_INFO this names the fact that would decide it. The whole
    // point of the third state is that it is actionable rather than a hedge.
    // Required rather than optional, and empty for a PASS or a DISMISS.
    // `triageBrocards` branches on it, and `required` is the only thing the
    // runtime validator enforces — a prompt asking for it is a request the model
    // may decline, and a NEEDS_MORE_INFO that does not name the missing fact is
    // the hedge this state exists to replace.
    missingFact: { type: 'string' },
    severityInput: {
      type: 'string',
      description: 'brocard 6 only: what remediation cost does to the severity, if it survives',
    },
    evidence: { type: 'string' },
  },
}

const LAYER_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['verdict', 'evidence'],
  properties: {
    verdict: { enum: ['PASSES', 'BLOCKS', 'UNCERTAIN'] },
    location: { type: 'string', description: 'file:line of the check itself' },
    evidence: { type: 'string', description: 'the code, and why the payload survives or does not' },
    reason: { type: 'string' },
  },
}

// The deep-route proofs. Same verdict enum as a layer, plus the one field that
// tells them apart from one: `applies`.
//
// A layer is ON the attack path and is always applicable — it either stops the
// payload or it does not. A proof is an auxiliary argument, and two of the three
// are asked a question that frequently does not apply at all: there is no
// algebra in a logic bug and no threading model in a synchronous one. The escape
// used to be a line of prompt telling the agent to answer UNCERTAIN in that case,
// and a prompt is not an enforcement mechanism — an agent asked "is concurrent
// access actually possible?" about a finding with no concurrency in it answers
// the question it was asked, truthfully, with BLOCKS.
//
// Measured: `integration-cap` scored 0/3 on the latest sweep, and two of those
// three runs came back NOT_EXPLOITABLE from this path with every one of the other
// twelve sub-agents saying the finding was real and unblocked. One run's answer
// says so in terms — *"the top-line label was self-contradicting against its own
// reasoning text"* — and the orchestrator then discarded the whole workflow and
// reported its own uncapped Critical. The severity cap the case exists to
// exercise never ran.
//
// `applies` is required so the model is asked, and read as `applies === true` so
// an omitted or non-boolean answer cannot block — the same `!== true` idiom
// `upstreamFixStands` uses on `complete`, for the same reason. The direction is
// deliberate: a proof that cannot say it applies fails toward more analysis.
const PROOF_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['applies', 'verdict', 'evidence'],
  properties: {
    applies: {
      type: 'boolean',
      description: 'false when this question is not applicable to this finding at all; a proof that does not apply cannot answer it',
    },
    verdict: { enum: ['PASSES', 'BLOCKS', 'UNCERTAIN'] },
    location: { type: 'string' },
    evidence: { type: 'string' },
    reason: { type: 'string' },
  },
}

const RECOVERY_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['recoveryExists', 'effectiveImpact', 'evidence'],
  properties: {
    recoveryExists: { type: 'boolean' },
    mechanism: { type: 'string', description: 'e.g. net/http per-connection recover in conn.serve' },
    effectiveImpact: { type: 'string', description: 'the impact that survives recovery' },
    evidence: { type: 'string' },
  },
}

const THREAT_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['inScope', 'byDesign', 'byDesignIndicators', 'evidence'],
  properties: {
    inScope: { enum: ['YES', 'NO', 'UNCERTAIN'] },
    byDesign: { type: 'boolean' },
    byDesignIndicators: { type: 'integer', description: 'count of the three indicator classes that fired' },
    evidence: { type: 'string' },
  },
}

// Stage 3's challenge 4 is the only place concept-prover looked for an existing
// fix, and challenge 4 runs only when the user asked for a PoC. On the cheap
// path — which is the default — an already-fixed finding would pass unexamined,
// so the same search runs here.
const HISTORY_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['fixed', 'complete', 'reference', 'searched', 'evidence'],
  properties: {
    fixed: { enum: ['YES', 'NO', 'UNCERTAIN'] },
    // Required, and empty when nothing was found. `upstreamFixStands` branches on
    // it, and `required` is the only thing the runtime validator enforces — so
    // leaving it optional means an omitted field reads as undefined, which is the
    // same as empty here but arrives without the model having been asked. A
    // `fixed: YES` carrying an empty reference is treated as unproven: a
    // retraction has to point at something.
    reference: { type: 'string', description: 'the commit, PR, issue or advisory that fixed it; empty if none' },
    // Required for the same reason `reference` is, and it was optional: the two
    // fields make the same claim about the same retraction. `upstreamFixStands`
    // reads it, and an omitted one was `undefined`, which is not `false`, which is
    // read as a WHOLE fix — so a partial fix nobody flagged retracted the finding
    // entirely. Required makes the model answer instead of the default guessing.
    complete: { type: 'boolean', description: 'false for a partial fix, which is still a finding' },
    searched: { type: 'string', description: 'what was actually searched, so a null result is auditable' },
    evidence: { type: 'string' },
  },
}

const IMPACT_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['result', 'impact', 'rootCause', 'classification', 'severity', 'severityRationale', 'evidence'],
  properties: {
    result: { enum: ['VERIFIED', 'NOT_VERIFIED', 'DISPROVEN'] },
    impact: { type: 'string' },
    rootCause: { enum: ['internal', 'integration', 'external'] },
    externalPrecondition: { type: 'string' },
    classification: { enum: ['vulnerability', 'hardening_gap'] },
    severity: { enum: ['Critical', 'High', 'Medium', 'Low', 'Informational'] },
    severityRationale: { type: 'string' },
    evidence: { type: 'string' },
  },
}

// The six gates from references/gate-reviews.md, flattened. Nested per-gate
// objects would put the fields `decideVerdict` branches on out of reach of
// `required`, which is the only thing the runtime validator enforces.
const VERDICT_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: [
    'gateProcess',
    'gateReachability',
    'gateRealImpact',
    'gatePocValidation',
    'gateMathBounds',
    'gateEnvironment',
    'unresolvedUncertainty',
    'verdictReason',
    'evidence',
  ],
  properties: {
    gateProcess: { enum: ['PASS', 'FAIL'] },
    gateReachability: { enum: ['PASS', 'FAIL'] },
    gateRealImpact: { enum: ['PASS', 'FAIL'] },
    gatePocValidation: { enum: ['PASS', 'FAIL'] },
    // The only gate with an N/A: most bugs are not bounds bugs, and forcing a
    // PASS/FAIL there would make the answer meaningless rather than absent.
    gateMathBounds: { enum: ['PASS', 'FAIL', 'N/A'] },
    gateEnvironment: { enum: ['PASS', 'FAIL'] },
    // fp-check's standard route escalates to deep "if any question produces
    // genuine uncertainty you cannot resolve". This is that signal, and
    // decideVerdict turns it into NEEDS_MORE_INFO rather than a coin-flip
    // verdict.
    unresolvedUncertainty: { type: 'string', description: 'empty when nothing is unresolved' },
    verdictReason: { type: 'string' },
    evidence: { type: 'string' },
  },
}

// Pure. Reject an arg shape this script does not understand BEFORE spending
// agents on it. Every field named here is interpolated into a prompt below, so a
// missing one reaches an agent as the literal text 'undefined' and it spends a
// full turn reasoning about nothing. That is not hypothetical: a live dispatch
// asked the threat-model agent about "Finding: undefined, Component: undefined,
// Declared scope: [object Object]".
//
// maxLayers is a defaulted parameter rather than a reference to MAX_LAYERS
// because the tests extract this function and evaluate it in isolation, where a
// free variable would throw ReferenceError.
// test_the_layer_cap_default_matches_max_layers pins the two together.
function missingArgs(a, maxLayers = 4) {
  const missing = []
  const need = (path, value) => {
    // Whitespace is missing. `finding.summary = '   '` satisfies a `!== ''`
    // check and then reaches every prompt as blank space, which is the
    // `undefined` failure this validator exists to stop wearing a different hat.
    const blank = typeof value === 'string' && value.trim() === ''
    if (value === undefined || value === null || blank) missing.push(path)
  }
  const finding = (a && a.finding) || {}
  const entry = (a && a.entryPoint) || {}

  need('baseDir', a && a.baseDir)
  need('finding.summary', finding.summary)
  need('finding.sink', finding.sink)
  need('finding.component', finding.component)
  need('finding.claimedImpact', finding.claimedImpact)
  need('finding.bugClass', finding.bugClass)
  // Brocard 1, enforced rather than asked: a report that cannot say who the
  // attacker is, what they hold, how they trigger it and what breaks is
  // dismissible on its face, and every downstream stage would be guessing at
  // the threat model it is supposed to align to.
  need('finding.threatModel', finding.threatModel)
  need('entryPoint.description', entry.description)
  need('entryPoint.location', entry.location)
  need('entryPoint.payload', entry.payload)
  // `scope` is the input the threat-model checkpoint is entirely about. Absent,
  // the prompt read "Declared scope: none declared — report UNCERTAIN rather
  // than assuming" and the workflow returned a verdict whenever the agent
  // answered YES anyway. That instruction is a prompt, and a prompt is not an
  // enforcement mechanism.
  need('scope', a && a.scope)
  if (a && a.scope !== undefined && a.scope !== null && typeof a.scope !== 'string') {
    missing.push('scope (must be a string; an object interpolates as [object Object])')
  }
  // `.entries()` on a non-array throws out of the validator, so a wrong shape
  // would kill the run instead of being reported.
  const layers = a && a.layers
  // Checkpoint 2.2 passes on "identified at least 1 layer (or confirmed none
  // exist)". An empty list confirms nothing: `layers` defaults to [] in the
  // destructure, so a forgotten field and a deliberate "nothing validates this
  // path" are the same value. Either way zero layer agents run, the gate has
  // nothing to fail on, and a verdict comes back having inspected nothing. If
  // the sink really is reachable with no check in between, that is a claim —
  // pass it as one explicit layer and let an agent confirm it.
  if (layers === undefined || layers === null || (Array.isArray(layers) && layers.length === 0)) {
    missing.push(
      'layers (Stage 1c needs at least one layer to inspect; if no validation stands between the entry point and the sink, pass that as a single explicit layer so an agent confirms it)',
    )
  }
  // Reject an over-long list HERE rather than after dispatching. Failing closed
  // is only worth anything if it happens before the spend.
  if (Array.isArray(layers) && layers.length > maxLayers) {
    missing.push(
      `layers (${layers.length} supplied, at most ${maxLayers} are dispatched; narrow the attack path or split the finding rather than paying for agents that cannot cover it)`,
    )
  }
  if (layers !== undefined && layers !== null && !Array.isArray(layers)) {
    missing.push('layers (must be an array)')
  } else {
    for (const [i, layer] of (Array.isArray(layers) ? layers : []).entries()) {
      if (!layer || !layer.name) missing.push(`layers[${i}].name`)
      if (!layer || !layer.location) missing.push(`layers[${i}].location`)
    }
  }
  const route = a && a.route
  if (route !== undefined && route !== null && route !== 'standard' && route !== 'deep') {
    missing.push(`route (must be 'standard' or 'deep' when supplied; got '${route}')`)
  }
  return missing
}

// Pure. fp-check's standard/deep routing, decided from the dispatch rather than
// from the orchestrator's mood.
//
// This is the reason Stage 1 is not an unconditional fan-out. Measured:
// fp-check's linear checklist never escalated on any of the seven eval cases and
// still matched a full pipeline at 2.3x less cost, so the cheap path is doing
// real work and replacing it with "always run everything" would spend 3x for no
// measured gain. What deep adds is the three extra proofs listed at the
// dispatch site, not a second opinion on the same questions.
//
// An explicit `route` wins: the user asking for full verification is one of
// fp-check's own escalation criteria.
// Matched with `includes` on a lowercased string rather than with a regex: the
// contract scanner refuses to lex a regex literal in code position, deliberately,
// because reading one wrong blanks the rest of the file and every check below it
// goes green. A keyword list is also easier to extend than an alternation.
//
// The list is inline rather than hoisted: the tests extract this function and
// evaluate it alone, where a free variable is a ReferenceError.
function selectRoute(a) {
  if (a && a.route) return a.route
  const finding = (a && a.finding) || {}
  const layers = (a && Array.isArray(a.layers) && a.layers) || []
  // 3+ trust boundaries in the path. fp-check's first escalation checkpoint.
  if (layers.length >= 3) return 'deep'
  const bugClass = String(finding.bugClass || '').toLowerCase()
  // Keyed on the CLASS NAMES in references/bug-class-verification.md first, then
  // on the ways the same bug gets written by hand. Both halves are needed, and
  // leaving one out was a live defect: SKILL.md sends the orchestrator to that
  // reference for the bug class, so "Memory Corruption" — the heading it reads
  // there — took the cheap route with no algebraic bounds proof, while "buffer
  // overflow" took the deep one. Same finding, opposite route, decided by which
  // words got typed.
  //
  // test_every_bug_class_has_a_routing_decision pins this against the reference's
  // headings, so a class added there has to be routed rather than silently
  // defaulting to standard.
  const escalates = [
    // Memory corruption: the archetypal case for the algebraic bounds proof, and
    // the allocator/API-contract question disposes of whole reports on its own.
    'memory corruption',
    'buffer overflow',
    'heap overflow',
    'stack overflow',
    'out-of-bounds',
    'out of bounds',
    'oob',
    'use-after-free',
    'use after free',
    'double-free',
    'double free',
    'type confusion',
    // Integer arithmetic. Gate 5 wants algebra, which is a separate agent's job
    // rather than a clause in the impact prompt.
    'integer',
    'overflow',
    'underflow',
    'off-by-one',
    'truncation',
    'signedness',
    'bounds',
    // Concurrency in the trigger. A race that cannot be shown to BE a race is
    // the most common false positive in the class, and it needs its own proof.
    'race',
    'racing',
    'toctou',
    'concurren',
    'deadlock',
    'atomic',
    // Denial of service: the amplification ratio and the worst-case input are
    // arithmetic, and "it is O(n^2)" asserted without them is the usual shape of
    // a wrong DoS report.
    'denial of service',
    'dos',
    'algorithmic complexity',
    'resource exhaustion',
  ]
  if (escalates.some((k) => bugClass.includes(k))) return 'deep'
  if (a && a.crossComponent === true) return 'deep'
  if (a && a.ambiguous === true) return 'deep'
  return 'standard'
}

const argProblems = missingArgs(args, MAX_LAYERS)
if (argProblems.length > 0) {
  log(`BLOCKED: dispatch contract violated — ${argProblems.join(', ')}`)
  return {
    status: 'BLOCKED',
    reason: `triage-static received an unusable arg shape: ${argProblems.join(', ')}. See the Dispatch section of SKILL.md for the required fields.`,
  }
}

const route = selectRoute(args)

// ------------------------------------------------------------- Stage 1b
// The cheap pre-gate. Four questions about the shape of the claim, none of which
// needs the code traced, each of which can end the analysis for a few cents.

phase('Brocards')

// `defersTo` names a downstream mechanism that asks the SAME question with more
// evidence and answers it better. A DISMISS from a brocard that has one does not
// end the stage: it is carried, the specialised gate runs, and the specialised
// gate's answer is what the user gets.
//
// This is the fix for the merge's largest measured regression. The brocard
// pre-gate is a first-position gate NEITHER parent had — concept-prover's
// verify-attack-path.js has no brocards at all — and being both cheap and first
// it won the race on findings the specialised gates were built for. Measured
// across 63 with-plugin runs of the seven eval cases: a brocard DISMISS decided
// 12 of them, while `upstreamFixStands`, `capSeverity`, `missingPrecondition`
// and `decideVerdict` fired ZERO times between them. Three of the seven cases
// exist to exercise exactly those four.
//
// The two concrete losses, both readable in the recorded answers:
//   - `already-fixed`: brocard 5 dismissed as "already-fixed/documented
//     behavior" and `upstreamFixStands` never ran, so the answer was a brocard's
//     prose instead of "already fixed by #412 — <commit>. Retract."
//   - `inflated-impact`: brocard 4 dismissed as "no vulnerability from standard
//     behavior" on a case whose grader says in terms that the panic is REAL and
//     must not be dismissed; the recovery agent, whose whole job is to downgrade
//     the impact rather than deny the bug, never decided.
//
// Brocards 2 and 6 keep the short-circuit, and that is deliberate rather than
// timid: nothing downstream tests "the attacker already holds this capability"
// or "the cure is worse than the disease", so deferring them would buy a full
// fan-out and no better answer. The cheap path stays cheap for what the pre-gate
// genuinely disposes of on its own.
//
// A deferred DISMISS is NOT discarded — `decideVerdict` blocks a TRUE_POSITIVE on
// one in code. So the worst this can do is turn a DISMISSED into a
// NEEDS_MORE_INFO that carries the brocard's own reasoning, which is more willing
// to keep analysing and never more willing to report a finding as real.
const BROCARDS = [
  {
    key: 'from-the-heavens',
    title: 'Brocard 2 — no exploit from the heavens',
    // Deferred, on evidence. This brocard was left short-circuiting on the
    // reasoning that nothing downstream asks its question — and that is wrong for
    // one whole class. "The attacker must already control the upstream rate
    // service" IS an integration root cause, which is exactly what
    // `missingPrecondition` and `capSeverity` exist to decide: the finding is
    // real, the precondition has to be stated, and the severity caps at Medium.
    //
    // Measured, at $1.15: a probe of `integration-cap` on 2.2.0 returned
    // "DISMISSED at Stage 1's pre-gate (Brocard 2)" with the answer stating
    // "Severity: not reached — the finding was dismissed before the
    // impact/severity phase". So the gate that was fixed to always run the cap
    // was starved by the one brocard still allowed to end the stage.
    //
    // Its genuine dismissals — an active MITM that can already inject, ctypes
    // that already implies code execution — survive this: the impact stage reaches
    // the same answer with the trace in hand, and a deferred dismissal blocks a
    // TRUE POSITIVE in code either way.
    defersTo:
      'the impact stage, which decides root cause and applies the Medium cap when the capability the attack needs is an external precondition rather than power the attacker already holds',
    prompt: `Do the attacker capabilities this attack REQUIRES already equal or exceed the
impact it GRANTS? If the attacker must already hold the power the exploit would
give them, the finding is redundant and you should DISMISS.

Two traps in the other direction. A privilege-escalation chain does NOT fail this
test: limited access exploited into elevated access is valid, because the
post-exploit capability exceeds the pre-exploit one. And "the attacker can do X"
is not "the attacker can do X in this context" — code execution inside a sandbox
is not code execution with the sandbox's privileges.`,
  },
  {
    key: 'standard-behavior',
    title: 'Brocard 4 — no vulnerability from standard behavior',
    // Overlaps the recovery check and the threat-model agent's design-intent
    // question, and the overlap is where it goes wrong: "the framework recovers
    // this panic" is standard behaviour that DOWNGRADES the impact, not a
    // specification that makes the bug imaginary. Stage 1d states the impact
    // that survives; this test cannot.
    defersTo: 'the recovery check (Stage 1d) and the threat-model agent, which decide impact and design intent on the code rather than on the shape of the claim',
    prompt: `Is this behaviour a correct implementation of a specification? If the spec
requires or permits it, the vulnerability is in the standard, not this code —
DISMISS and say which standard.

The nuance inverts the test, so check it before dismissing: an implementation
that VOLUNTARILY claims a stricter posture than the spec requires IS vulnerable
when that strictness fails. Read what this code documents about itself. A
library documented as TLS 1.3-only that falls back to a 1.2 CBC suite has broken
its own promise, and the spec permitting 1.2 is no defence.`,
  },
  {
    key: 'documented-behavior',
    title: 'Brocard 5 — no vulnerability from documented behavior',
    // Overlaps the already-fixed history search, and the two are told apart by
    // one fact this test does not have: a CHANGELOG entry describing a FIX is
    // not documentation telling you to live with the behaviour. Both dismiss;
    // only the history agent produces the commit reference the retraction needs.
    defersTo: 'the already-fixed history search, which distinguishes documentation you must live with from a fix that landed, and cites the commit',
    prompt: `Does this project's own documentation describe this behaviour, and warn against
the misuse? If so, DISMISS the report against THIS project.

The nuance is a redirection rather than a dismissal: downstream usage that
violates documented guidance is a valid finding against the DOWNSTREAM project.
If that is the situation, say which project it is a bug in — the answer is "not
a bug here", not "not a bug".

**If the document that would settle this is not in this repository, answer PASS
and say which document you would need.** That is not a hedge and it is not
NEEDS_MORE_INFO: this test is only about what THIS project documents, and a
governing spec, an upstream service contract or a downstream consumer's guidance
are all outside its reach. Answering NEEDS_MORE_INFO on an external document makes
this test structurally unanswerable for every finding whose root cause is an
integration — which is measured, not hypothetical: it aborted the whole static
stage on two graded runs, and the finding those runs were meant to cap came back
uncapped because the analysis never ran. The online stage exists for exactly that
question and will pick it up when the user asks for it.`,
  },
  {
    key: 'cure-worse',
    title: 'Brocard 6 — no cure worse than the disease',
    prompt: `Would remediating this cause more harm than the vulnerability? Weigh the
severity in practice, the cost and disruption of the fix, and the blast radius
across the dependency graph.

DISMISS only when the cure is genuinely worse. More often the finding survives at
a lower severity with the trade-off stated: put that in severityInput, which is
carried into the severity decision later. Nothing else in this analysis looks at
remediation cost, so if you leave it blank it is not considered anywhere.`,
  },
]

// The fan-out is written over BROCARDS at the call site rather than over a
// hoisted `brocardChecks` const, so it is visibly bounded by a script-local array
// literal. A hoisted thunk list derived from BROCARDS is bounded too, but nothing
// at the `parallel()` call says so, and test_no_unbounded_fanout is right to
// refuse it: the same shape over a caller-supplied collection is unbounded, and
// the two are indistinguishable at the call.
const brocardRaw = await parallel(BROCARDS.map((b) => () =>
  agent(
    `${b.title}. You are applying ONE cheap triage test to a reported finding,
before anyone traces data flow. Read ${baseDir}/references/brocards.md for the
full statement of this test and the rationalizations to reject.

Finding: ${finding.summary}
Bug class: ${finding.bugClass}
Reported threat model: ${finding.threatModel}
Claimed impact: ${finding.claimedImpact}
Sink: ${finding.sink}
Entry point: ${entryPoint.description} (${entryPoint.location})

${b.prompt}

Answer NEEDS_MORE_INFO if the evidence available cannot decide it, and name the
missing fact. NEEDS_MORE_INFO is a legitimate answer and is not a soft DISMISS:
"the claim as stated is unproven" is NEEDS_MORE_INFO, never "no vulnerability
exists". Conflating those two killed a real finding in this plugin's own history.`,
    { label: `brocard:${b.key}`, phase: 'Brocards', schema: BROCARD_SCHEMA, effort: 'low' },
  ).then((v) => (v ? { ...v, key: b.key, title: b.title } : null)),
))
const brocardVerdicts = brocardRaw.filter(Boolean)

// Pure. Tallies against the EXPECTED list, not against what came back: a
// brocard whose agent died is unevaluated, and an unevaluated test must not read
// as a pass. Tallying the returned array instead lets a dead agent shrink the
// denominator and quietly clear the gate.
//
// Order matters and is the declaration order of BROCARDS: the brocards skill's
// rule is "stop at the first DISMISS", and with the tests running concurrently
// the first in canonical order is what that means. All four still run — four
// low-effort agents cost less than the wall-clock of sequencing them — so a
// DISMISS reported here does not hide the others' verdicts.
//
// `expected` is a list of DESCRIPTORS — `{ key, defersTo }` — not a list of keys.
// A descriptor with a non-empty `defersTo` names a downstream mechanism that
// answers the same question better, and its DISMISS is deferred rather than
// terminal. A malformed entry carrying no `key` matches no verdict and falls
// through to the unevaluated branch, which blocks a TRUE_POSITIVE: a caller that
// gets this wrong fails toward more analysis, not toward a dismissal it did not
// earn.
function triageBrocards(verdicts, expected) {
  const byKey = new Map((verdicts || []).filter(Boolean).map((v) => [v.key, v]))
  const specs = (expected || []).filter(Boolean)

  // A DISMISS from a brocard with no downstream equivalent is the ONLY terminal
  // outcome, and it is read before anything else. Each brocard is an independent
  // falsifiable test and any one dismissing is sufficient, so no later evidence
  // can unmake it and no sibling's silence matters — the same rule `decideGate`
  // applies when a blocking layer outranks a dead recovery agent.
  for (const spec of specs) {
    const v = byKey.get(spec.key)
    if (v && v.verdict === 'DISMISS' && !String(spec.defersTo || '').trim()) {
      return {
        dismissal: {
          status: 'DISMISSED',
          reason: `${v.title}: ${String(v.evidence || '').trim() || 'agent reported DISMISS with no evidence'}`,
        },
        deferred: [],
        unresolved: [],
      }
    }
  }

  // Deferred dismissals. Collected in declaration order, all of them rather than
  // only the first: two brocards dismissing for two different reasons is two
  // things the downstream gates have to answer, and reporting one of them would
  // silently drop the other.
  const deferred = []
  for (const spec of specs) {
    const v = byKey.get(spec.key)
    if (!v || v.verdict !== 'DISMISS') continue
    deferred.push({
      key: spec.key,
      title: v.title || spec.key,
      what: String(v.evidence || '').trim() || 'agent reported DISMISS with no evidence',
      defersTo: String(spec.defersTo || '').trim(),
    })
  }

  // Everything else is CARRIED, not terminal. This is the fix for the most
  // expensive structural defect the first measured sweep found.
  //
  // "This test dismisses the finding" and "this test cannot decide" had the same
  // power to end the stage, and they are not the same statement: the second is
  // precisely what the expensive stages downstream exist to resolve. Worse,
  // aborting did not produce a safe non-answer — it produced an UNGUARDED one. The
  // pre-gate stopped, Stage 3 then refused for want of a TRUE_POSITIVE, and the
  // orchestrator — still holding a user request for a PoC — built one by hand,
  // outside every gate, and reported an uncapped Critical. Fail-closed at the gate
  // became fail-open one level up, at 4-5x the baseline cost for an identical
  // score. Measured on 3 of 18 runs; the DISMISS path was right on 8 of 8.
  //
  // The finding now gets the full analysis — reachability verified, severity
  // capped — and an unresolved brocard is surfaced to the later prompts and
  // blocks a TRUE_POSITIVE in code at the verdict, where the decision is made by
  // the agent holding all the evidence rather than by the cheapest one to raise a
  // hand.
  const unresolved = []
  for (const spec of specs) {
    const v = byKey.get(spec.key)
    if (!v) {
      // A dead agent is unknown, not passed. It is carried rather than fatal so
      // one flaky agent degrades the verdict instead of destroying the run.
      unresolved.push({ key: spec.key, title: spec.key, what: 'the agent returned nothing, so this test never ran' })
    } else if (v.verdict === 'NEEDS_MORE_INFO') {
      const what = String(v.missingFact || '').trim() || String(v.evidence || '').trim()
      unresolved.push({
        key: spec.key,
        title: v.title,
        what: what || 'agent reported NEEDS_MORE_INFO without naming the missing fact',
      })
    }
  }
  return { dismissal: null, deferred, unresolved }
}

const brocardTriage = triageBrocards(
  brocardVerdicts,
  BROCARDS.map((b) => ({ key: b.key, defersTo: b.defersTo || '' })),
)
if (brocardTriage.dismissal) {
  log(`DISMISSED: ${brocardTriage.dismissal.reason}`)
  return {
    status: brocardTriage.dismissal.status,
    reason: brocardTriage.dismissal.reason,
    brocards: brocardVerdicts,
  }
}

// Carried to the impact and verdict prompts, and enforced at the verdict.
const openQuestions = brocardTriage.unresolved
if (openQuestions.length > 0) {
  log(`${openQuestions.length} brocard question(s) unresolved and carried: ${openQuestions.map((q) => q.key).join(', ')}`)
}

// Same channel, different claim: these brocards DID dismiss, and a mechanism
// with more evidence is about to answer the same question. Carried into the
// impact and verdict prompts and enforced at the verdict, exactly as
// openQuestions are.
const deferredDismissals = brocardTriage.deferred
if (deferredDismissals.length > 0) {
  log(
    `${deferredDismissals.length} brocard dismissal(s) deferred to a downstream gate: ${deferredDismissals
      .map((d) => d.key)
      .join(', ')}`,
  )
}

// Brocard 6 may survive as a severity input rather than a dismissal. Carried
// forward explicitly, because a value nothing reads is a value that does not
// exist.
const remediationCost = brocardVerdicts
  .filter((v) => String(v.severityInput || '').trim())
  .map((v) => `${v.key}: ${v.severityInput}`)

log(
  `No brocard ended the stage${
    deferredDismissals.length ? ` (${deferredDismissals.length} dismissal(s) deferred)` : ''
  }. Route: ${route}.`,
)

// ------------------------------------------------------- Stages 1c and 1d

phase('Layers')

// One agent per layer. Checkpoint 2.2's pass criteria are "identified every
// layer, determined pass/block/uncertain for each WITH EVIDENCE, ZERO uncertain
// layers" — a fan-out over an enumerated list, which one agent reading in a
// single pass cannot honestly satisfy.
//
// This is the mechanism the head-to-head measured: on `blocked-attack-path`,
// where the sink is genuinely injectable but no attacker-reachable path exists,
// the arm with per-layer verdicts scored 3/3 and the arm with a linear checklist
// scored 1/3 against a 1/9 pooled baseline. Both arms NAMED the blocking
// allowlist 6/6 — naming it is not the hard part, refusing to call the finding
// real is. Do not collapse this into one agent to save money.
const checks = [
  ...layers.map((layer, i) => () =>
    agent(
      `You are verifying ONE validation layer, independently. Do not reason about the
others.

Finding: ${finding.summary}
Entry point: ${entryPoint.description} (${entryPoint.location})
Attacker payload: ${entryPoint.payload}

Layer under test: ${layer.name} at ${layer.location}
What it checks: ${layer.checks || 'determine this from the code'}

Read the actual code. Decide whether the payload above survives this layer and
reaches the next hop toward ${finding.sink}. Quote the code in your evidence.
Class-specific requirements for a ${finding.bugClass} finding are in
${baseDir}/references/bug-class-verification.md.

Answer UNCERTAIN if you cannot establish it from the code. UNCERTAIN is a
legitimate answer and is preferable to a guess; it halts the pipeline for a
manual trace, which is the intended behaviour.`,
      { label: `layer:${layer.name || i + 1}`, phase: 'Layers', schema: LAYER_SCHEMA, effort: 'low' },
      // This guard is the only thing standing between a dead layer agent and a
      // fail-open, and it is load-bearing rather than defensive: `{...null}` is
      // `{}`, so an unguarded spread yields `{layer, location}` with no
      // `verdict`. That object is truthy, so it survives the `.filter(Boolean)`
      // below, the missing-agent count computes to 0, and the gate reaches a
      // verdict having inspected nothing. Do not simplify it away.
    ).then((v) => (v ? { layer: layer.name || `layer-${i + 1}`, location: layer.location, ...v } : null)),
  ),
]

// Positions are recorded as the list is built rather than computed as
// `layers.length + 1`, `+ 2` and so on. The arithmetic form is what makes the
// deep-route extras dangerous to add: one off-by-one and a recovery verdict is
// read as a threat-model verdict, which was a live fail-open before
// `additionalProperties: false` closed it by accident.
const at = {}
const add = (key, thunk) => {
  at[key] = checks.length
  checks.push(thunk)
}

add('recovery', () =>
  agent(
    `Stage 1d, recovery mechanism check.

Read ${baseDir}/references/recovery-mechanisms.md, in particular the summary
table and the checklist before claiming a process crash.

Finding: ${finding.summary}
Claimed impact: ${finding.claimedImpact}
Vulnerable code: ${finding.sink}

Determine whether a panic/exception at that location is caught by any recovery
in the call stack — language-level, framework middleware, or server built-in —
and state the impact that actually survives.

Do not assume recovery is absent because you did not find it. If the claimed
impact is a process crash, that claim requires positive evidence that nothing
recovers.`,
    { label: 'recovery', phase: 'Layers', schema: RECOVERY_SCHEMA, effort: 'medium' },
  ),
)

add('threat', () =>
  agent(
    `Threat model alignment: scope, security model, and design intent.

Read ${baseDir}/references/validation-dimensions.md.

Finding: ${finding.summary}
Component: ${finding.component}
Declared scope: ${scope}
Reported threat model: ${finding.threatModel}

Answer three things:
  Scope. Is this component explicitly in scope? Ambiguous means UNCERTAIN, not
    YES.
  Security model. Does this violate a security property the target claims, or is
    it within stated trust assumptions?
  Design intent. Check all three indicator classes: privilege identifiers,
    symmetric guarded/unguarded sibling paths, and documentation or tests
    covering it as normal operation. Report how many fired. If two or more fire,
    search usage and test coverage before concluding.

Centralized control is not by itself a vulnerability.`,
    { label: 'threat-model', phase: 'Layers', schema: THREAT_SCHEMA, effort: 'medium' },
  ),
)

add('history', () =>
  agent(
    `Has this already been fixed? Search, do not reason from the file alone.

Finding: ${finding.summary}
Vulnerable code: ${finding.sink}
Entry point: ${entryPoint.location}

Search the git log for the relevant paths (\`git log -p --\` on the sink's file
and its callers, and \`git log --grep\` for the symptom), the issue tracker,
release notes, CHANGELOG, and any published advisories. Report exactly what you
searched in \`searched\`, so a null result is auditable rather than assumed.

The fix is often NOT in the file the finding names. A caller one layer up that
now normalises, encodes or digests the value fixes the sink without touching it,
and nothing in the sink file says so. That is the shape that gets missed.

Report fixed: YES only with a concrete reference — a commit, PR, issue or
advisory ID. YES without one is downgraded to UNCERTAIN, because a retraction has
to point at something. Set complete: false for a partial fix; a partial fix is
still a finding.`,
    { label: 'history', phase: 'Layers', schema: HISTORY_SCHEMA, effort: 'low' },
  ),
)

if (route === 'deep') {
  add('api-contract', () =>
    agent(
      `Deep route only: API contracts and environmental protections.

Finding: ${finding.summary}
Sink: ${finding.sink}
Bug class: ${finding.bugClass}

Two questions, both of which dispose of whole classes of report on their own:

  1. Do the APIs on this path carry built-in protection that prevents the alleged
     issue REGARDLESS of input? Many do — a bounded copy, a managed allocation, a
     validated return value. Read the API's contract, not its name.
  2. Do compiler, runtime, OS or framework protections prevent exploitation
     ENTIRELY, as distinct from raising the bar? Rust's safe type system prevents;
     ASLR and stack canaries raise the bar. Only the former makes this a false
     positive.

Also check whether this pattern exists elsewhere in the codebase and is handled
safely there, and whether tests cover this path. See
${baseDir}/references/false-positive-patterns.md for the API-contract and
context-blind red-flag lists.

Return PASSES if no such protection exists, so the alleged issue is still open
after both questions. BLOCKS if a protection you have READ prevents it entirely.
UNCERTAIN if you cannot establish either from the code. Set applies: false if
neither question bears on this finding — no relevant API contract and no relevant
platform protection — and leave the verdict as UNCERTAIN.

The polarity above is stated because it used to be left to you: the two questions
are phrased so that "yes" means the finding is dead, while the verdict enum is
phrased so that PASSES means it is alive, and an answer given in the wrong
direction reads as a proof that the finding is impossible.`,
      { label: 'api-contract', phase: 'Layers', schema: PROOF_SCHEMA, effort: 'medium' },
    ),
  )

  add('math-bounds', () =>
    agent(
      `Deep route only: the algebraic proof. This is fp-check's Gate 5 and nothing
else in this analysis does it.

Finding: ${finding.summary}
Sink: ${finding.sink}
Validation on the path: ${layers.map((l) => `${l.name} at ${l.location}`).join('; ')}

Write the explicit algebra, using the template in
${baseDir}/references/evidence-templates.md. The form is:

    IF validation_check_passes THEN bounds_guarantee_holds

State each validated relation, then derive whether the vulnerable condition is
reachable. Concretely: if the code checks \`size >= MIN\` and \`MIN >= sizeof(hdr)\`,
then \`size - sizeof(hdr)\` cannot underflow, and the finding is mathematically
impossible rather than merely unlikely.

Return PASSES if the vulnerable condition is algebraically reachable, BLOCKS if
the validation makes it impossible, UNCERTAIN if the relations cannot be pinned
down. If this is not a bounds or arithmetic finding, set applies: false with
verdict UNCERTAIN and say so in the evidence — do not invent algebra for a logic
bug, and do not report BLOCKS to mean "there is no algebra here". Only
applies: true can end the analysis, so mis-setting it is how a logic bug gets
dismissed by an arithmetic argument that was never made.`,
      { label: 'math-bounds', phase: 'Layers', schema: PROOF_SCHEMA, effort: 'high' },
    ),
  )

  add('race-feasibility', () =>
    agent(
      `Deep route only: is concurrent access actually possible?

Finding: ${finding.summary}
Sink: ${finding.sink}
Bug class: ${finding.bugClass}

A race requires proof that the value can change between check and use, by a
second actor that really exists. Establish the threading or task model first:
single-threaded initialisation and synchronised contexts cannot race, however
suggestive the code looks. For a TOCTOU claim specifically, show what modifies
the checked value between the check and the use — if it is read and used in the
same function with no external mutation possible, there is no TOCTOU.

Return PASSES if the race is feasible, BLOCKS if the model rules it out,
UNCERTAIN if the threading model cannot be established. If concurrency is not
part of this finding's trigger, set applies: false with verdict UNCERTAIN and say
so. BLOCKS is reserved for a finding that DOES claim a race and whose threading
model rules it out; answering BLOCKS because there is no concurrency in the
finding at all dismisses it on a question it never asked.`,
      { label: 'race-feasibility', phase: 'Layers', schema: PROOF_SCHEMA, effort: 'medium' },
    ),
  )
}

// parallel() preserves position and substitutes null in place for a dead agent,
// so which thunk produced which result is known from the index. Slice
// positionally out of the UNFILTERED array, and only then drop the nulls.
//
// Disaggregating by shape instead — `.filter(Boolean)` then
// `results.find((r) => r.inScope)` — is a fail-open: the recovery thunk precedes
// the threat thunk, so a recovery agent that volunteered an `inScope: 'YES'` key
// won the threat-model lookup, the real `inScope: 'NO'` verdict was discarded,
// and the workflow returned a verdict on an out-of-scope finding.
//
// The barrier is justified: the gate below is a decision over ALL layers, and a
// blocking layer skips the impact agent and both later stages entirely.
const raw = await parallel(checks)
const layerVerdicts = raw.slice(0, layers.length).filter(Boolean)
const recovery = raw[at.recovery] || null
const threat = raw[at.threat] || null
const history = raw[at.history] || null
const proofs = route === 'deep'
  ? [
      { key: 'api-contract', verdict: raw[at['api-contract']] || null },
      { key: 'math-bounds', verdict: raw[at['math-bounds']] || null },
      { key: 'race-feasibility', verdict: raw[at['race-feasibility']] || null },
    ]
  : []

// Pure. Checkpoint 5.1 challenge 4's rule — Stage 3 enforces the same rule
// over the challenge verdicts, under its original name `alreadyFixedStands` — "a fix exists -> DO NOT SUBMIT, and
// this outcome overrides everything else" — applied at Stage 1c so it also holds
// on the cheap path.
//
// `fixed: YES` with no reference is NOT a retraction. Schema `required` checks
// presence, not content, so `reference: ''` validates; and an unreferenced
// retraction is the one failure mode that silently discards a real finding
// rather than merely reporting a false one.
function upstreamFixStands(historyVerdict) {
  if (!historyVerdict || historyVerdict.fixed !== 'YES') return null
  const ref = String(historyVerdict.reference || '').trim()
  if (!ref) return null
  // `!== true`, not `=== false`. Only an affirmative "this fix is complete"
  // retracts, because the caller treats a non-partial fix as terminal: with
  // `=== false`, an omitted flag was `undefined`, which is not `false`, so a
  // PARTIAL fix that nobody flagged retracted the whole finding — the same
  // silent discard the `reference` check above exists to stop, one field over.
  // A fix flagged partial is not lost: the impact prompt is told about it and the
  // analysis continues against what remains.
  const partial = historyVerdict.complete !== true
  return {
    reference: ref,
    partial,
    evidence: String(historyVerdict.evidence || '').trim() || `fixed by ${ref}`,
  }
}

// Checkpoint 2.2's gate, as a pure function so it can be graded without a model.
//
// attemptedLayers is how many layer agents were dispatched. A verdict list
// shorter than that means agents died, and a gate that inspected nothing must
// not report a verdict.
function decideGate(verdicts, recoveryVerdict, threatVerdict, historyVerdict, attemptedLayers) {
  const where = (ls) => ls.map((l) => `${l.layer} (${l.location})`).join(', ')

  // Zero dispatched layers is the vacuous pass: no BLOCKS to find, no UNCERTAIN
  // to find, so every filter below matches nothing and the function falls
  // through. The arg validator rejects an empty `layers` before any agent is
  // spent; this is the same rule at the gate, where the decision is made.
  if (attemptedLayers === 0) {
    return {
      status: 'BLOCKED',
      reason: 'no validation layers were inspected; Stage 1c cannot pass on zero evidence',
    }
  }

  // Counted, not tested for zero yet: the two signs are two different failures
  // and they do not belong at the same precedence. `> 0` alone was the original
  // defect — a negative difference silently passed a check meant to catch a
  // missing one — and `!== 0` fixed that by promoting BOTH to the same rank,
  // which was the next one.
  const missing = attemptedLayers - verdicts.length

  // MORE verdicts than agents dispatched first, and above everything else: some
  // verdict in this list came from something that is not a layer, so no verdict
  // read out of it can be trusted — including a BLOCKS, which would dismiss a
  // live finding on evidence that was mis-attributed to it.
  if (missing < 0) {
    return {
      status: 'BLOCKED',
      reason: `${-missing} more layer verdict(s) than agents dispatched; results were mis-attributed and Stage 1c cannot be trusted`,
    }
  }

  // The layer verdicts are decided BEFORE every "did that agent run" check, and
  // the order is load-bearing. A blocking layer means the finding is unreachable
  // whatever recovery, the threat model or the git history say, so it outranks a
  // dead sibling agent: putting the liveness checks first turned a firm
  // NOT_EXPLOITABLE into "could not determine" whenever the recovery agent
  // happened to die, which throws away the answer the fan-out had already found.
  //
  // The missing-LAYER-agent count is such a check, and it used to sit above this
  // filter — so the same discarding happened whenever a sibling LAYER agent died,
  // which is the likeliest death of all: there are up to four of them. The layers
  // are conjunctive (a PROCEED needs every one to PASS), so one that BLOCKS
  // settles reachability on its own and the dead sibling cannot overturn it.
  const blocked = verdicts.filter((l) => l.verdict === 'BLOCKS')

  // A referenced, complete upstream fix outranks the blocking layer, and this is
  // a reordering rather than a new rule: both outcomes retract the finding, so
  // nothing here makes a false positive easier to report — only the REASON the
  // orchestrator relays changes, and one of the two reasons is strictly better.
  //
  // The two coincide constantly, because the usual shape of an already-fixed
  // finding is a fix one layer up that a layer agent then correctly reports as
  // BLOCKS. `already-fixed`'s grader asks for the commit — "the reason has to be
  // the fix, cited as evidence" — and `blocked at _digest (auth.py:31)` does not
  // carry it. The blocking layer is named in the reason too, so nothing is lost.
  const fix = upstreamFixStands(historyVerdict)
  if (fix && !fix.partial) {
    return {
      status: 'ALREADY_FIXED',
      reason:
        `already fixed by ${fix.reference} — ${fix.evidence}.` +
        `${blocked.length ? ` The path is also blocked at ${where(blocked)}.` : ''}` +
        ' Retract rather than report at a lowered severity.',
    }
  }

  if (blocked.length > 0) {
    return { status: 'NOT_EXPLOITABLE', reason: `blocked at ${where(blocked)}` }
  }

  // No layer decided the path, so a dead one is the answer: Stage 1c ran on
  // partial evidence and cannot pass.
  if (missing > 0) {
    return {
      status: 'BLOCKED',
      reason: `${missing} layer agent(s) returned nothing; Stage 1c is unverified`,
    }
  }

  // NEEDS_MORE_INFO rather than BLOCKED, and the distinction is the whole reason
  // the third verdict exists. BLOCKED means this analysis could not be RUN — a
  // contract violation, a dead agent. NEEDS_MORE_INFO means it ran and the
  // evidence does not decide. An UNCERTAIN layer is the second: the code is
  // there, it was read, and it could not be traced. Reporting that as a failure
  // of the harness sends the reader to the wrong place, and rounding it to
  // FALSE POSITIVE loses real findings.
  const uncertain = verdicts.filter((l) => l.verdict === 'UNCERTAIN')
  if (uncertain.length > 0) {
    return { status: 'NEEDS_MORE_INFO', reason: `unresolved layers: ${where(uncertain)}` }
  }

  // Read the affirmative value. Grading by exclusion — anything not BLOCKS and
  // not UNCERTAIN — made a pass the fall-through for a verdict this script does
  // not recognise, on the checkpoint that carries the measured delta.
  const passed = verdicts.filter((l) => l.verdict === 'PASSES')
  if (passed.length !== attemptedLayers) {
    return {
      status: 'BLOCKED',
      reason: `${attemptedLayers - passed.length} layer(s) returned no PASSES verdict; Stage 1c is unverified`,
    }
  }

  // Now the "did this agent run at all" checks. Stage 1d passes on "checked for
  // recovery (not assumed absent)", and a dead recovery agent means it was not
  // checked — the impact prompt would say "not established" and carry on,
  // assuming absence by another route.
  if (!recoveryVerdict) {
    return { status: 'BLOCKED', reason: 'recovery agent returned nothing; Stage 1d unverified' }
  }
  if (!threatVerdict) {
    return { status: 'BLOCKED', reason: 'threat-model agent returned nothing; scope and design intent unverified' }
  }
  // The already-fixed search is the cheap path's only guard against reporting a
  // bug that was fixed upstream, so a dead agent there is a blocker rather than a
  // shrug.
  if (!historyVerdict) {
    return { status: 'BLOCKED', reason: 'already-fixed history agent returned nothing; Stage 1c unverified' }
  }

  // The retraction itself is decided above, before the blocking-layer filter,
  // for the reason recorded there. It is gated on a reference existing, so it
  // cannot become a cheap escape hatch, and a `historyVerdict` of null reaches
  // the liveness blocker just above rather than falling through as "nothing was
  // fixed".

  // These reasons are taken straight from an agent, and JSON Schema `required`
  // checks presence, not content — `evidence: ''` validates. Without the
  // fallback the orchestrator relays "OUT_OF_SCOPE:" with nothing after it.
  const why = (fallback) => String(threatVerdict.evidence || '').trim() || fallback
  if (threatVerdict.inScope === 'NO') {
    return { status: 'OUT_OF_SCOPE', reason: why('threat-model agent reported out of scope but gave no evidence') }
  }
  // `!== 'YES'` rather than a list of the two values that block. The rule is
  // "ambiguous means UNCERTAIN, not YES", and grading by exclusion implemented
  // the opposite — anything that was not NO or UNCERTAIN became YES.
  if (threatVerdict.inScope !== 'YES') {
    return { status: 'NEEDS_MORE_INFO', reason: 'scope ambiguous; the declared scope does not settle whether this component is covered' }
  }
  if (threatVerdict.byDesign) {
    return { status: 'NOT_VULNERABLE', reason: why('threat-model agent reported by-design but gave no evidence') }
  }

  return { status: 'PROCEED', reason: '' }
}

const gate = decideGate(layerVerdicts, recovery, threat, history, layers.length)

if (gate.status !== 'PROCEED') {
  log(`${gate.status}: ${gate.reason}`)
  return {
    status: gate.status,
    reason: gate.reason,
    route,
    brocards: brocardVerdicts,
    openQuestions,
    deferredDismissals,
    layers: layerVerdicts,
    recovery,
    threat,
    history,
    proofs,
  }
}

// Pure. Which deep-route proofs actually block the finding.
//
// Two rules, and each of them cost a graded case:
//
// `applies === true`, not merely truthy and not defaulted. A proof that says the
// question does not bear on this finding has not answered it, and an omitted or
// non-boolean flag reads as "did not say", which cannot block. Same `!== true`
// idiom as `upstreamFixStands`' `complete`, in the same direction: unsure means
// keep analysing.
//
// The result is CARRIED rather than terminal. A layer is on the attack path and
// is conjunctive with its siblings — one that BLOCKS settles reachability. A
// proof is an auxiliary argument by a single agent that saw one question, and
// making it terminal put it above the impact stage, the severity cap and the six
// gates, none of which then ran. `gateMathBounds` and `gateEnvironment` are those
// same two questions asked again with all the evidence in view, so routing a
// blocking proof to them produces a verdict that names the gate it failed
// instead of naming the agent that raised its hand first.
//
// This cannot make a false positive easier to report: a blocking proof still
// forbids TRUE_POSITIVE in code at the verdict, so the softest outcome available
// is NEEDS_MORE_INFO carrying the proof's own evidence.
function blockingProofs(proofs) {
  return (proofs || [])
    .filter((p) => p && p.verdict && p.verdict.applies === true && p.verdict.verdict === 'BLOCKS')
    .map((p) => ({
      key: p.key,
      title: p.key,
      what: String(p.verdict.evidence || '').trim() || 'proof reported BLOCKS with no evidence',
    }))
}

const blockingProof = blockingProofs(proofs)
if (blockingProof.length > 0) {
  log(
    `${blockingProof.length} deep-route proof(s) block and are carried to the verdict: ${blockingProof
      .map((p) => p.key)
      .join(', ')}`,
  )
}

// A dead proof agent is the deep route not having run, and it fails closed for
// the same reason decideGate blocks on a dead recovery, threat-model or history
// agent: these three ARE the escalation. Nothing else in this workflow writes the
// algebraic bounds proof or establishes the threading model, so a null read as
// "did not block" pays for the deep route and enforces none of it — the finding
// reaches the six gates with the extra evidence missing and only a line of prose
// telling the gate agent so, which is the self-report this port exists to remove.
//
// UNCERTAIN is not a death — two of the three are asked a question that often does
// not apply and set `applies: false` — so only a missing verdict blocks.
const deadProofs = proofs.filter((p) => !p.verdict).map((p) => p.key)
if (deadProofs.length > 0) {
  const why = `${deadProofs.join(', ')} returned nothing; the deep route was selected for those proofs and they are the only thing it adds`
  log(`BLOCKED: ${why}`)
  return {
    status: 'BLOCKED',
    reason: why,
    route,
    brocards: brocardVerdicts,
    openQuestions,
    deferredDismissals,
    layers: layerVerdicts,
    recovery,
    threat,
    history,
    proofs,
    blockingProofs: blockingProof,
  }
}

// ------------------------------------------------------------- Stage 1e

phase('Impact')

const impact = await agent(
  `Impact verification, root cause attribution, exploitability classification, and
severity.

Finding: ${finding.summary}
Originally claimed impact: ${finding.claimedImpact}
Recovery finding: ${recovery.recoveryExists ? 'recovery EXISTS' : 'no recovery found'} — ${recovery.effectiveImpact}
All ${layerVerdicts.length} validation layers were independently verified as passable.
${history.fixed === 'UNCERTAIN' ? `History search was inconclusive: ${history.searched}` : ''}
${upstreamFixStands(history) ? `A PARTIAL fix exists (${upstreamFixStands(history).reference}); report what remains, not the original claim.` : ''}
${remediationCost.length ? `Remediation cost raised at the pre-gate:\n  ${remediationCost.join('\n  ')}` : ''}
${openQuestions.length ? `Unresolved at the cheap pre-gate, carried rather than fatal — resolve what you can from the code:\n  ${openQuestions.map((q) => `${q.title}: ${q.what}`).join('\n  ')}` : ''}
${deferredDismissals.length ? `Dismissed at the cheap pre-gate and deferred to you, because you hold the evidence\nit did not. Answer it from the code — and note that a framework or specification\nthat contains the damage is a reason to DOWNGRADE the impact, not a reason to say\nthe bug is imaginary:\n  ${deferredDismissals.map((d) => `${d.title}: ${d.what}`).join('\n  ')}` : ''}
${blockingProof.length ? `Deep-route proof(s) reporting that the finding is impossible. They were carried\nrather than made terminal; weigh them against the traced path:\n  ${blockingProof.map((p) => `${p.key}: ${p.what}`).join('\n  ')}` : ''}

Verify the claimed impact against evidence. If recovery downgrades it, the
verified impact is the downgraded one, not the original claim.

  \`result\` grades whether ANY impact is established by evidence. It does NOT
  grade whether the reported claim survived intact:
    VERIFIED     an impact is established. Put the impact the evidence supports
                 in \`impact\` — it may be far smaller than what was claimed. A
                 real bug reported at inflated severity is VERIFIED with the
                 corrected impact. Downgrading is what this asks you to do, not
                 a reason to fail it.
    NOT_VERIFIED no impact could be established either way on the evidence
                 available.
    DISPROVEN    the evidence positively shows there is no impact.
  Only VERIFIED continues, so grading a real-but-smaller impact as NOT_VERIFIED
  discards a genuine finding. That is not hypothetical: it cost a graded case.

Attribute the root cause: internal, integration, or external. If it is not
internal, state the external precondition the attack requires.

Classify: does the code DO something it should not (vulnerability), or LACK
something it should have (hardening gap)?

Then set a severity and justify it on impact and exploitability both. An
integration or external root cause caps severity at Medium, and a hardening gap
is not written up as an exploited vulnerability — those caps are applied in code
after you answer, so a rating above them is corrected rather than accepted.

See ${baseDir}/references/checkpoints.md for the pass criteria of each, and
${baseDir}/references/bug-class-verification.md for what a ${finding.bugClass}
finding specifically has to establish.`,
  { label: 'impact', phase: 'Impact', schema: IMPACT_SCHEMA, effort: 'high' },
)

// The cap is applied HERE, before any early exit, and this position is the fix
// for a defect the first measured sweep exposed. It used to run after the impact
// guard and after `missingPrecondition`, both of which return the `impact` object
// verbatim — so a finding that exited at either one handed the orchestrator the
// agent's own uncapped `severity`, with no correction and no note. The second of
// those exits fires PRECISELY when the root cause is integration or external with
// the precondition unstated, which is the single most likely non-passing outcome
// for exactly the findings the cap exists to bound.
//
// `impact` may be null if the agent died; `capSeverity` is total over that.
const capped = impact
  ? capSeverity(impact.severity, impact.rootCause, impact.classification)
  : { severity: undefined, note: '' }
if (capped.note) log(capped.note)

// Every return below carries the corrected severity, not `impact.severity`. A
// consumer reading `impact.severity` directly is reading the pre-cap number, so
// the corrected one is surfaced under the same keys the passing path uses.
const severityFields = { severity: capped.severity, severityCorrection: capped.note }

// Only VERIFIED is a pass: NOT_VERIFIED means NO impact could be established,
// which is not a licence to spend the rest of the pipeline on it.
//
// "No impact established" is not the same as "the reported severity was too
// high", and conflating the two cost a graded case: the impact agent performed
// exactly the downgrade it was asked for — "NOT VERIFIED as stated and is
// downgraded to LOW" — and then returned NOT_VERIFIED, so the gate killed a
// real, demonstrable bug and the case scored below the arm with no plugin at
// all. NOT_VERIFIED now returns NEEDS_MORE_INFO rather than a false-positive
// verdict, because "could not establish" is not "does not exist".
if (!impact || impact.result !== 'VERIFIED') {
  const stated = impact ? impact.result : 'missing'
  const reason = impact
    ? String(impact.evidence || '').trim() || `impact agent reported ${impact.result} but gave no evidence`
    : 'impact agent returned nothing'
  const status = !impact || impact.result === 'NOT_VERIFIED' ? 'NEEDS_MORE_INFO' : 'NOT_EXPLOITABLE'
  log(`${status}: impact ${stated}. ${reason}`)
  return {
    status,
    reason,
    route,
    brocards: brocardVerdicts,
    openQuestions,
    deferredDismissals,
    layers: layerVerdicts,
    recovery,
    threat,
    history,
    proofs,
    blockingProofs: blockingProof,
    impact,
    ...severityFields,
  }
}

// Checkpoint 2.4b passes only if "the required external precondition is stated
// explicitly" for an integration or external root cause. JSON Schema cannot
// express "required when rootCause is not internal", so the schema marks
// externalPrecondition optional and the rule is applied here. Without it a
// finding that only fires when some upstream system misbehaves reaches the PoC
// stage with the precondition that makes it exploitable left unsaid — and the
// severity cap has nothing to cap against.
function missingPrecondition(verified) {
  if (!verified || verified.rootCause === 'internal') return false
  return !String(verified.externalPrecondition || '').trim()
}

if (missingPrecondition(impact)) {
  const why = `root cause is ${impact.rootCause}, so the external precondition the attack requires must be stated explicitly, and it was not`
  log(`NEEDS_MORE_INFO: ${why}`)
  return {
    status: 'NEEDS_MORE_INFO',
    reason: why,
    route,
    brocards: brocardVerdicts,
    openQuestions,
    deferredDismissals,
    layers: layerVerdicts,
    recovery,
    threat,
    history,
    proofs,
    blockingProofs: blockingProof,
    impact,
    ...severityFields,
  }
}

// Checkpoint 2.4b ("integration -> requires an external failure to trigger, cap
// at Medium", "external -> workaround only") and 2.5 ("hardening gap -> medium
// priority, defense-in-depth") are arithmetic, not judgement. The prompt states
// both, and a prompt is not an enforcement mechanism: what comes back is
// whatever severity the agent chose, and an inflated severity on a finding that
// only fires when a third party misbehaves is exactly the failure this skill
// exists to prevent. Measured: this is why the arm that enforced it scored 3/3
// on `integration-cap` where the arm that asked for it scored 0/3.
//
// It CORRECTS rather than blocks. concept-prover returned BLOCKED here, which is
// right when an agent has already written the severity into a report file — that
// file is now wrong and re-running the workflow will not fix it, so Stage 3
// keeps that behaviour. On the cheap path there is no file, Stage 1 owes the
// user a verdict, and the cap is arithmetic: applying it is strictly better than
// refusing to answer. The correction is reported, never silent.
//
// Self-contained so it can be extracted and graded without the surrounding
// script.
function capSeverity(severity, rootCause, classification) {
  const CAP = 'Medium'
  if (severity !== 'Critical' && severity !== 'High') return { severity, note: '' }
  if (rootCause === 'integration' || rootCause === 'external') {
    return {
      severity: CAP,
      note: `severity lowered from ${severity} to ${CAP}: a ${rootCause} root cause requires an external failure to trigger (checkpoints.md 2.4b)`,
    }
  }
  if (classification === 'hardening_gap') {
    return {
      severity: CAP,
      note: `severity lowered from ${severity} to ${CAP}: a hardening gap is defense-in-depth, not an exploited vulnerability (checkpoints.md 2.5)`,
    }
  }
  return { severity, note: '' }
}


// ------------------------------------------------------- Stages 1f and 1g

phase('Verdict')

const verdictAgent = await agent(
  `The adversarial pass, then the six gates. Everything below was established by
agents that each saw one narrow question; you are the first to see all of it.

Finding: ${finding.summary}
Sink: ${finding.sink}
Bug class: ${finding.bugClass}
Verified impact: ${impact.impact}
Root cause: ${impact.rootCause}${impact.rootCause === 'internal' ? '' : ` (external precondition: ${impact.externalPrecondition})`}
Classification: ${impact.classification}
Severity after the caps: ${capped.severity}${capped.note ? ` — ${capped.note}` : ''}
Recovery: ${recovery.recoveryExists ? `EXISTS, ${recovery.mechanism || 'mechanism not named'}` : 'none found'} — ${recovery.effectiveImpact}
Validation layers, all independently verified as passable:
  ${layerVerdicts.map((l) => `${l.layer} (${l.location}): ${l.evidence}`).join('\n  ')}
Already-fixed search: ${history.fixed} — ${history.searched}
${proofs.length ? `Deep-route proofs:\n  ${proofs.map((p) => `${p.key}: ${p.verdict ? `${p.verdict.applies === true ? p.verdict.verdict : `${p.verdict.verdict} (does not apply to this finding)`} — ${p.verdict.evidence}` : 'agent returned nothing'}`).join('\n  ')}` : ''}
Route: ${route}
${openQuestions.length ? `\nUnresolved at the cheap pre-gate and still open. Resolve each from the code if you\ncan, and put whatever remains into unresolvedUncertainty — an unresolved one blocks\na TRUE POSITIVE whatever the six gates say:\n  ${openQuestions.map((q) => `${q.title}: ${q.what}`).join('\n  ')}\n` : ''}
${deferredDismissals.length ? `\nDismissed at the cheap pre-gate on the shape of the claim alone, then deferred to\nyou because you hold the traced evidence it did not. This is the argument AGAINST\nthe finding, already made — answer it. If it holds, the matching gate below is a\nFAIL and the finding is a FALSE POSITIVE that names which gate; if it does not,\nsay why on the evidence. A deferred dismissal blocks a TRUE POSITIVE in code\neither way, so do not leave it unanswered:\n  ${deferredDismissals.map((d) => `${d.title}: ${d.what}\n    (deferred to ${d.defersTo || 'this review'})`).join('\n  ')}\n` : ''}
${blockingProof.length ? `\nDeep-route proof(s) reporting the finding impossible. They were carried rather\nthan made terminal, because a single auxiliary proof is not above the traced path:\n  ${blockingProof.map((p) => `${p.key}: ${p.what}`).join('\n  ')}\n` : ''}
First, argue against the finding, then for it. Work through
${baseDir}/references/false-positive-patterns.md — the 13-item checklist and the
four red-flag lists. ${route === 'deep' ? 'All 13 devil\'s-advocate questions.' : 'The 7 spot-check questions of the standard route.'}
You are biased toward seeing bugs and toward rating them critical; the questions
exist to work against that.

Then the other direction, which is not optional and carries equal weight. The
guards against wrongly DISMISSING a valid finding are in
${baseDir}/references/brocards.md: "only reachable in debug mode" needs debug
mode proven off in production; "the attacker would need local access" is a real
threat model for containerised services; "nobody uses that API" needs usage
data, not an assumption; and inventing a mitigation you have not read in the
source is the failure mode that loses real findings.

Then apply the six gates and report each as PASS or FAIL. The criteria are here
rather than in a reference file on purpose: they used to be in both, and a gate
criterion that exists in two places is one an agent can read the stale copy of.

  gateProcess         every stage above produced concrete evidence, not assertion
  gateReachability    attacker-controlled data reaches the sink through a path a
                      real caller can drive. A demonstration that constructs
                      state no real caller could reach does NOT pass this gate,
                      however genuine the sink is
  gateRealImpact      RCE, privilege escalation or information disclosure —
                      distinguished from operational robustness, and from a
                      defense-in-depth failure behind intact primary controls
  gatePocValidation   the attack path is demonstrated end to end. On this route
                      that is the traced path and its evidence; a built PoC is
                      Stage 3's job and its absence is not a FAIL here
  gateMathBounds      the algebra permits the vulnerable condition. N/A when this
                      is not a bounds or arithmetic finding
  gateEnvironment     no compiler, runtime, OS or framework protection prevents
                      exploitation ENTIRELY. Raising the bar is not preventing

Put anything you could not resolve with the evidence at hand into
unresolvedUncertainty, and leave it empty when there is nothing. An honest
"unresolved" routes this to NEEDS MORE INFO, which is a supported outcome; a
guess dressed as a verdict is not.

No speculative language in verdictReason: "probably", "likely", "might", "would",
"could bypass" are all disallowed. Say what the evidence shows.`,
  { label: 'gates', phase: 'Verdict', schema: VERDICT_SCHEMA, effort: 'high' },
)

// Pure. fp-check's rule is "all six gate reviews must pass" before anything is
// reported as a vulnerability, and it was prose in a reference file that an
// agent was asked to honour. The six gates are now arithmetic over six enums.
//
// A missing verdict counts AGAINST the finding, and unresolved uncertainty is
// its own outcome rather than being resolved in either direction.
//
// `overruled` is the third input and the one that makes deferral safe: it is the
// list of arguments some earlier, cheaper stage already made FOR dismissing this
// finding — a brocard whose DISMISS was deferred to a specialised gate, a
// deep-route proof that reported the finding impossible. They were carried here
// instead of ending the stage, and the invariant that makes that legal is
// enforced below rather than asked for: nothing on this list can be silently
// dropped, because a non-empty list forbids TRUE_POSITIVE. Deferring is therefore
// only ever a decision to keep analysing, never a decision to report.
function decideVerdict(result, carried, overruled) {
  const open = (carried || []).filter(Boolean)
  const dismissals = (overruled || []).filter(Boolean)
  if (!result) {
    return { status: 'NEEDS_MORE_INFO', reason: 'the gate-review agent returned nothing; no gate was evaluated' }
  }
  const GATES = [
    ['gateProcess', 'Process'],
    ['gateReachability', 'Reachability'],
    ['gateRealImpact', 'Real Impact'],
    ['gatePocValidation', 'PoC Validation'],
    ['gateMathBounds', 'Math Bounds'],
    ['gateEnvironment', 'Environment'],
  ]
  const why = String(result.verdictReason || '').trim() || String(result.evidence || '').trim()

  // FAIL first: a gate that failed is a FALSE POSITIVE and says which one, which
  // is more useful than "something was uncertain".
  const failed = GATES.filter(([key]) => result[key] === 'FAIL').map(([, name]) => name)
  if (failed.length > 0) {
    return {
      status: 'FALSE_POSITIVE',
      reason: `gate ${failed.join(' and ')} failed: ${why || 'agent reported FAIL with no reason'}`,
    }
  }

  const unresolved = String(result.unresolvedUncertainty || '').trim()
  if (unresolved) {
    return { status: 'NEEDS_MORE_INFO', reason: `unresolved after the adversarial pass: ${unresolved}` }
  }

  // Read the affirmative value, per gate, rather than grading by exclusion. Only
  // Math Bounds may be N/A; a gate this script does not recognise on any other
  // must not fall through to TRUE POSITIVE.
  const notPassed = GATES.filter(
    ([key]) => !(result[key] === 'PASS' || (key === 'gateMathBounds' && result[key] === 'N/A')),
  ).map(([, name]) => name)
  if (notPassed.length > 0) {
    return {
      status: 'NEEDS_MORE_INFO',
      reason: `gate ${notPassed.join(' and ')} returned no PASS verdict, so the six-gate review is incomplete`,
    }
  }

  if (!why) {
    return {
      status: 'NEEDS_MORE_INFO',
      reason: 'all six gates passed but the agent gave no reason; a verdict with nothing behind it is not evidence',
    }
  }

  // An unresolved brocard blocks a TRUE POSITIVE, in code. The pre-gate no longer
  // aborts the stage on one — so the finding has been fully analysed by now and the
  // report is useful — but "brocard 4 never answered" is a real gap that nothing
  // downstream tests, and carrying it as prose for an agent to honour is the
  // self-report this whole port exists to remove. Reported with the missing fact,
  // so it is actionable rather than a shrug.
  if (open.length > 0) {
    return {
      status: 'NEEDS_MORE_INFO',
      reason: `all six gates passed, but ${open.length} cheap-pre-gate question(s) remain unresolved: ${open
        .map((q) => `${q.title} — ${q.what}`)
        .join('; ')}`,
    }
  }

  // The other half of deferral. A dismissal that was carried here rather than
  // acted on has to be answered by the six gates, and "answered" means a FAIL
  // that names the gate — which is checked first, above, and returns
  // FALSE_POSITIVE. Six passes with a dismissal still standing means the two
  // disagree and nothing reconciled them, so the finding is not confirmed.
  //
  // The reason quotes the dismissal rather than summarising it: the whole point
  // of deferring was that this argument survives to the reader.
  if (dismissals.length > 0) {
    return {
      status: 'NEEDS_MORE_INFO',
      reason: `all six gates passed, but ${dismissals.length} earlier dismissal(s) were deferred here and none was answered: ${dismissals
        .map((d) => `${d.title} — ${d.what}`)
        .join('; ')}`,
    }
  }
  return { status: 'TRUE_POSITIVE', reason: why }
}

const verdict = decideVerdict(verdictAgent, openQuestions, [...deferredDismissals, ...blockingProof])

const payload = {
  route,
  brocards: brocardVerdicts,
  openQuestions,
  deferredDismissals,
  layers: layerVerdicts,
  recovery,
  threat,
  history,
  proofs,
  blockingProofs: blockingProof,
  impact,
  severity: capped.severity,
  severityCorrection: capped.note,
  gates: verdictAgent,
}

if (verdict.status !== 'TRUE_POSITIVE') {
  log(`${verdict.status}: ${verdict.reason}`)
  return { status: verdict.status, reason: verdict.reason, ...payload }
}

log(`TRUE_POSITIVE at ${capped.severity}. ${verdict.reason}`)
return { status: 'TRUE_POSITIVE', reason: verdict.reason, ...payload }
