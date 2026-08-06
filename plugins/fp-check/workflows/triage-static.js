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
    // `dismissedByBrocard` branches on it, and `required` is the only thing the
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
  required: ['fixed', 'reference', 'searched', 'evidence'],
  properties: {
    fixed: { enum: ['YES', 'NO', 'UNCERTAIN'] },
    // Required, and empty when nothing was found. `upstreamFixStands` branches on
    // it, and `required` is the only thing the runtime validator enforces — so
    // leaving it optional means an omitted field reads as undefined, which is the
    // same as empty here but arrives without the model having been asked. A
    // `fixed: YES` carrying an empty reference is treated as unproven: a
    // retraction has to point at something.
    reference: { type: 'string', description: 'the commit, PR, issue or advisory that fixed it; empty if none' },
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

const BROCARDS = [
  {
    key: 'from-the-heavens',
    title: 'Brocard 2 — no exploit from the heavens',
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
    prompt: `Does this project's own documentation describe this behaviour, and warn against
the misuse? If so, DISMISS the report against THIS project.

The nuance is a redirection rather than a dismissal: downstream usage that
violates documented guidance is a valid finding against the DOWNSTREAM project.
If that is the situation, say which project it is a bug in — the answer is "not
a bug here", not "not a bug".`,
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
function dismissedByBrocard(verdicts, expectedKeys) {
  const byKey = new Map((verdicts || []).filter(Boolean).map((v) => [v.key, v]))

  // A DISMISS is read BEFORE the "did every agent answer" check, and the order is
  // load-bearing — it is the same rule `decideGate` applies when a blocking layer
  // outranks a dead recovery agent, and this function originally got it wrong.
  //
  // Each brocard is an independent falsifiable test and any ONE of them dismissing
  // is sufficient, so a fourth agent dying cannot change an answer another agent
  // has already reached. Checking liveness first threw that answer away: measured,
  // a graded run had brocard 5 return a clean DISMISS, lost one of the other three
  // to a connection error, and returned NEEDS_MORE_INFO about a finding that was
  // already disposed of.
  for (const key of expectedKeys) {
    const v = byKey.get(key)
    if (v && v.verdict === 'DISMISS') {
      return {
        status: 'DISMISSED',
        reason: `${v.title}: ${String(v.evidence || '').trim() || 'agent reported DISMISS with no evidence'}`,
      }
    }
  }

  // Only now does a missing verdict matter: nothing has dismissed the finding, so
  // an unevaluated test is a test whose answer could still have.
  const unevaluated = expectedKeys.filter((k) => !byKey.has(k))
  if (unevaluated.length > 0) {
    return {
      status: 'NEEDS_MORE_INFO',
      reason: `brocard agent(s) returned nothing for ${unevaluated.join(', ')}; an unevaluated test is not a passed one`,
    }
  }
  for (const key of expectedKeys) {
    const v = byKey.get(key)
    if (v.verdict === 'NEEDS_MORE_INFO') {
      const what = String(v.missingFact || '').trim() || String(v.evidence || '').trim()
      return {
        status: 'NEEDS_MORE_INFO',
        reason: `${v.title}: ${what || 'agent reported NEEDS_MORE_INFO without naming the missing fact'}`,
      }
    }
  }
  return null
}

const brocardGate = dismissedByBrocard(brocardVerdicts, BROCARDS.map((b) => b.key))
if (brocardGate) {
  log(`${brocardGate.status}: ${brocardGate.reason}`)
  return { status: brocardGate.status, reason: brocardGate.reason, brocards: brocardVerdicts }
}

// Brocard 6 may survive as a severity input rather than a dismissal. Carried
// forward explicitly, because a value nothing reads is a value that does not
// exist.
const remediationCost = brocardVerdicts
  .filter((v) => String(v.severityInput || '').trim())
  .map((v) => `${v.key}: ${v.severityInput}`)

log(`Brocards 2, 4, 5 and 6 passed. Route: ${route}.`)

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

Answer UNCERTAIN if you cannot establish it from the code.`,
      { label: 'api-contract', phase: 'Layers', schema: LAYER_SCHEMA, effort: 'medium' },
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
down. If this is not a bounds or arithmetic finding, return UNCERTAIN and say so
in the evidence — do not invent algebra for a logic bug.`,
      { label: 'math-bounds', phase: 'Layers', schema: LAYER_SCHEMA, effort: 'high' },
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
part of this finding's trigger, return UNCERTAIN and say so.`,
      { label: 'race-feasibility', phase: 'Layers', schema: LAYER_SCHEMA, effort: 'medium' },
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
  const partial = historyVerdict.complete === false
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

  // `!== 0`, not `> 0`. More verdicts than agents dispatched means the results
  // were mis-attributed — a recovery or threat agent counted as a layer — and a
  // negative difference silently passed a check meant to catch a missing one.
  const missing = attemptedLayers - verdicts.length
  if (missing !== 0) {
    return {
      status: 'BLOCKED',
      reason:
        missing > 0
          ? `${missing} layer agent(s) returned nothing; Stage 1c is unverified`
          : `${-missing} more layer verdict(s) than agents dispatched; results were mis-attributed and Stage 1c cannot be trusted`,
    }
  }

  // The layer verdicts are decided BEFORE the "did the other agents run"
  // checks, and the order is load-bearing. A blocking layer means the finding is
  // unreachable whatever recovery, the threat model or the git history say, so it
  // outranks a dead sibling agent: putting the liveness checks first turned a
  // firm NOT_EXPLOITABLE into "could not determine" whenever the recovery agent
  // happened to die, which throws away the answer the fan-out had already found.
  const blocked = verdicts.filter((l) => l.verdict === 'BLOCKS')
  if (blocked.length > 0) {
    return { status: 'NOT_EXPLOITABLE', reason: `blocked at ${where(blocked)}` }
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

  // Before the threat-model verdicts: a finding fixed upstream is retracted
  // whether or not it is in scope, and the commit reference is the more useful
  // answer. Gated on that reference existing, so this cannot become a cheap
  // escape hatch.
  const fix = upstreamFixStands(historyVerdict)
  if (fix && !fix.partial) {
    return {
      status: 'ALREADY_FIXED',
      reason: `already fixed by ${fix.reference} — ${fix.evidence}. Retract rather than report at a lowered severity.`,
    }
  }

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
    layers: layerVerdicts,
    recovery,
    threat,
    history,
    proofs,
  }
}

// A deep-route proof that BLOCKS is as terminal as a blocking layer: algebra
// showing the condition is impossible, or a threading model that rules the race
// out, disposes of the finding. Checked after decideGate so a dead layer agent
// is still reported as the blocker it is.
const blockingProof = proofs.filter((p) => p.verdict && p.verdict.verdict === 'BLOCKS')
if (blockingProof.length > 0) {
  const why = blockingProof
    .map((p) => `${p.key}: ${String(p.verdict.evidence || '').trim() || 'no evidence given'}`)
    .join('; ')
  log(`NOT_EXPLOITABLE: ${why}`)
  return {
    status: 'NOT_EXPLOITABLE',
    reason: why,
    route,
    brocards: brocardVerdicts,
    layers: layerVerdicts,
    recovery,
    threat,
    history,
    proofs,
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
    layers: layerVerdicts,
    recovery,
    threat,
    history,
    proofs,
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
    layers: layerVerdicts,
    recovery,
    threat,
    history,
    proofs,
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
${proofs.length ? `Deep-route proofs:\n  ${proofs.map((p) => `${p.key}: ${p.verdict ? `${p.verdict.verdict} — ${p.verdict.evidence}` : 'agent returned nothing'}`).join('\n  ')}` : ''}
Route: ${route}

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
function decideVerdict(result) {
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
  return { status: 'TRUE_POSITIVE', reason: why }
}

const verdict = decideVerdict(verdictAgent)

const payload = {
  route,
  brocards: brocardVerdicts,
  layers: layerVerdicts,
  recovery,
  threat,
  history,
  proofs,
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
