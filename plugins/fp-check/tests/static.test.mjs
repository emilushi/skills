/**
 * Layer 2 for the gates Stage 1 added over concept-prover's verify-attack-path:
 * the standard/deep route, the upstream-fix retraction, the severity cap, and the
 * six-gate verdict.
 *
 * The brocard pre-gate was the fifth, and it is gone as of 2.5.0 — its four tests
 * are guidance in references/dismissal-grounds.md, applied by the agents holding
 * the traced path. Its tests are deleted rather than skipped: a suite that keeps
 * grading a mechanism the plugin does not have is the drift this file exists to
 * catch.
 *
 * `gate.test.mjs` covers decideGate and missingPrecondition, which came across
 * unchanged. Everything here is new surface, so it had no tests at all — and the
 * two mechanisms the head-to-head attributed its measured delta to (the
 * already-fixed retraction and the severity cap) are among them.
 */

import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'

import { loadFn, loadFns, runScript, script } from './extract.mjs'

const STATIC = script('triage-static.js')
const selectRoute = loadFn(STATIC, 'selectRoute')
const upstreamFixStands = loadFn(STATIC, 'upstreamFixStands')
const capSeverity = loadFn(STATIC, 'capSeverity')
const decideVerdict = loadFn(STATIC, 'decideVerdict')
const blockingProofs = loadFn(STATIC, 'blockingProofs')

// ------------------------------------------------------------- selectRoute

test('the cheap path is the default', () => {
  assert.equal(selectRoute({ finding: { bugClass: 'SQL injection' }, layers: [{}] }), 'standard')
})

// The escalation criteria are fp-check's own, and the reason the default stays
// cheap is measured: a linear checklist never escalated on any of seven eval
// cases and still matched a full pipeline at 2.3x less cost. A route that
// escalates on everything spends 3x for no measured gain.
test('three or more layers escalates: that is 3+ trust boundaries', () => {
  const layers = [{}, {}, {}]
  assert.equal(selectRoute({ finding: { bugClass: 'injection' }, layers }), 'deep')
  assert.equal(selectRoute({ finding: { bugClass: 'injection' }, layers: [{}, {}] }), 'standard')
})

test('a concurrency or bounds bug class escalates, case-insensitively', () => {
  for (const bugClass of [
    'race condition',
    'TOCTOU',
    'Concurrency bug',
    'deadlock',
    'integer overflow',
    'buffer UNDERFLOW',
    'off-by-one',
    'bounds check missing',
  ]) {
    assert.equal(selectRoute({ finding: { bugClass }, layers: [{}] }), 'deep', bugClass)
  }
})

test('an explicit route wins over every computed criterion', () => {
  // "The user explicitly requests full verification" is one of fp-check's own
  // escalation criteria, and the inverse matters too: an operator who has read
  // the code and wants the cheap path must be able to say so.
  assert.equal(selectRoute({ route: 'deep', finding: { bugClass: 'injection' }, layers: [{}] }), 'deep')
  assert.equal(selectRoute({ route: 'standard', finding: { bugClass: 'race' }, layers: [{}, {}, {}] }), 'standard')
})

test('the cross-component and ambiguous signals escalate', () => {
  const base = { finding: { bugClass: 'injection' }, layers: [{}] }
  assert.equal(selectRoute({ ...base, crossComponent: true }), 'deep')
  assert.equal(selectRoute({ ...base, ambiguous: true }), 'deep')
  // Only `true`, not any truthy value: a stray string from a hand-written
  // dispatch should not silently triple the cost.
  assert.equal(selectRoute({ ...base, crossComponent: 'no' }), 'standard')
})

test('selectRoute never throws on a missing or empty dispatch', () => {
  for (const input of [undefined, {}, { finding: null, layers: null }]) {
    assert.equal(selectRoute(input), 'standard')
  }
})

// --------------------------------------------------------- decideVerdict
//
// The invariant that makes deferral legal, and it is the whole reason a
// deep-route proof is carried here rather than made terminal: everything an
// earlier stage said FOR dismissing the finding reaches this function, and a
// non-empty list forbids TRUE_POSITIVE in code. So the softest outcome a deferral
// can reach is NEEDS_MORE_INFO. Deferring only ever buys more analysis; it can
// never make a false positive easier to report.
//
// This took a third parameter until 2.5.0 — the unresolved brocard questions.
// With the pre-gate gone nothing produces that list, and a parameter that is
// always empty reads as coverage it no longer has, so it was removed rather than
// left to be passed `[]` forever.

test('six passing gates with nothing carried is a TRUE POSITIVE', () => {
  assert.equal(decideVerdict(GATES, []).status, 'TRUE_POSITIVE')
})

test('a blocking deep-route proof blocks a TRUE POSITIVE even with six passing gates', () => {
  const r = decideVerdict(GATES, [
    { key: 'math-bounds', title: 'math-bounds', what: 'qty >= 1 and rate >= 0 make the product non-negative' },
  ])
  assert.equal(r.status, 'NEEDS_MORE_INFO')
  assert.match(r.reason, /math-bounds/)
  // Verbatim, not summarised: the point of carrying it was that this argument
  // survives to the reader.
  assert.match(r.reason, /make the product non-negative/)
})

// A gate that FAILED is the deferral being ANSWERED, and it outranks: naming the
// gate is the better-specified dismissal, which is the whole point of handing the
// question to the six gates rather than letting an auxiliary proof decide it.
test('a gate FAIL outranks a carried proof: the answer beats the question', () => {
  const r = decideVerdict({ ...GATES, gateRealImpact: 'FAIL' }, [
    { key: 'math-bounds', title: 'math-bounds', what: 'the bound holds' },
  ])
  assert.equal(r.status, 'FALSE_POSITIVE')
  assert.match(r.reason, /Real Impact/)
})

test('decideVerdict tolerates a missing or ragged carried list', () => {
  for (const c of [undefined, null, [], [null]]) {
    assert.equal(decideVerdict(GATES, c).status, 'TRUE_POSITIVE', JSON.stringify(c))
  }
})

// The monotonicity property, asserted rather than argued.
test('nothing carried into decideVerdict can be dropped on the way to TRUE POSITIVE', () => {
  const d = { key: 'race-feasibility', title: 'race-feasibility', what: 'the model rules the race out' }
  assert.notEqual(decideVerdict(GATES, [d]).status, 'TRUE_POSITIVE')
  assert.equal(decideVerdict(GATES, []).status, 'TRUE_POSITIVE', 'and the zero guard: nothing carried still passes')
})

// ---------------------------------------------------------- blockingProofs

// `applies === true`, not merely truthy and not defaulted. This is the fix for
// the loss that cost `integration-cap` all three of its outcome points on the
// latest sweep: two of the three runs came back NOT_EXPLOITABLE from a deep-route
// proof while every other sub-agent said the finding was real, and one of those
// runs says so in its own words — "the top-line label was self-contradicting
// against its own reasoning text". The escape hatch for a question that does not
// apply was a line of prompt, and a prompt is not an enforcement mechanism.
test('a proof that does not apply cannot block, whatever verdict it reports', () => {
  for (const applies of [undefined, null, false, 0, '', 'true', 1]) {
    const proofs = [{ key: 'race-feasibility', verdict: { applies, verdict: 'FINDING_REFUTED', evidence: 'no concurrency here' } }]
    assert.deepEqual(
      blockingProofs(proofs),
      [],
      `applies ${JSON.stringify(applies)} is not an affirmative "this question bears on the finding"`,
    )
  }
})

test('an applicable FINDING_REFUTED is returned with its evidence', () => {
  const proofs = [
    { key: 'api-contract', verdict: { applies: true, verdict: 'FINDING_SURVIVES', evidence: 'no built-in bound' } },
    { key: 'math-bounds', verdict: { applies: true, verdict: 'FINDING_REFUTED', evidence: 'MIN >= sizeof(hdr)' } },
    { key: 'race-feasibility', verdict: { applies: false, verdict: 'UNCERTAIN', evidence: 'single-threaded' } },
  ]
  const blocking = blockingProofs(proofs)
  assert.deepEqual(blocking.map((p) => p.key), ['math-bounds'])
  assert.match(blocking[0].what, /sizeof\(hdr\)/)
})

test('an applicable FINDING_REFUTED with no evidence still says something', () => {
  const blocking = blockingProofs([
    { key: 'math-bounds', verdict: { applies: true, verdict: 'FINDING_REFUTED', evidence: '   ' } },
  ])
  assert.equal(blocking.length, 1)
  assert.ok(blocking[0].what.trim())
})

test('blockingProofs never throws on a dead or ragged proof list', () => {
  for (const proofs of [undefined, null, [], [null], [{ key: 'math-bounds', verdict: null }], [undefined]]) {
    assert.deepEqual(blockingProofs(proofs), [], JSON.stringify(proofs))
  }
})

// `required` is the only thing the runtime validator enforces, so `applies` left
// optional is a field the model may simply omit — and `blockingProofs` reads
// `=== true`, so every omission reads as "does not apply". The gate would then be
// silently unable to block anything at all. That direction is safe, which is
// exactly why nothing else would notice.
test('PROOF_SCHEMA requires applies, so a proof cannot decline to say whether it applies', () => {
  const src = readFileSync(STATIC, 'utf8')
  const block = src.match(/const PROOF_SCHEMA = \{[\s\S]*?\n\}\n/)
  assert.ok(block, 'PROOF_SCHEMA not found; this pin is stale')
  const required = block[0].match(/required: \[([^\]]*)\]/)
  assert.ok(required, 'PROOF_SCHEMA declares no required list')
  assert.match(required[1], /'applies'/)
  // And the three deep-route agents are actually given it, rather than the layer
  // schema that has no such field.
  for (const label of ['api-contract', 'math-bounds', 'race-feasibility']) {
    const call = src.match(new RegExp(`label: '${label}'[^}]*schema: (\\w+)`))
    assert.ok(call, `${label} has no schema option`)
    assert.equal(call[1], 'PROOF_SCHEMA', `${label} must use PROOF_SCHEMA, not ${call[1]}`)
  }
})

// ------------------------------------------------------ upstreamFixStands

// `complete: true` is part of the fixture because HISTORY_SCHEMA requires it: a
// retraction has to say it is a WHOLE fix, and a fixture that omits the field is
// not a shape the runtime validator lets through.
const fixed = (over = {}) => ({
  fixed: 'YES',
  reference: '#412',
  complete: true,
  searched: 'git log -p -- auth.py, CHANGELOG',
  evidence: 'the caller now HMACs both operands',
  ...over,
})

test('a referenced complete fix stands', () => {
  const r = upstreamFixStands(fixed())
  assert.equal(r.reference, '#412')
  assert.equal(r.partial, false)
})

// The one failure mode here discards a REAL finding rather than reporting a false
// one, which is why the reference is enforced in code and not asked for in the
// prompt. `required` validates `reference: ''`, so without this check a model
// that answers YES on a hunch retracts a live bug and cites nothing.
test('a fix with no reference does not stand', () => {
  for (const reference of [undefined, null, '', '   ']) {
    assert.equal(upstreamFixStands(fixed({ reference })), null, `reference ${JSON.stringify(reference)}`)
  }
})

test('NO and UNCERTAIN do not stand, whatever else they carry', () => {
  for (const value of ['NO', 'UNCERTAIN', '', undefined]) {
    assert.equal(upstreamFixStands(fixed({ fixed: value })), null, `fixed: ${JSON.stringify(value)}`)
  }
})

test('a partial fix is reported as partial, not as a retraction', () => {
  const r = upstreamFixStands(fixed({ complete: false }))
  assert.equal(r.partial, true)
})

// The retraction is the thing that needs earning, in both fields. `reference` is
// enforced above because "YES with nothing behind it" discards a live finding;
// completeness is the same claim about the same retraction, and reading an omitted
// `complete` as `true` was the more dangerous half — a partial fix (still a
// finding, and the impact prompt has a branch that says so) was retracted whole by
// a field the agent simply never filled in.
//
// `!== true`, so only an affirmative answer retracts. `complete` is in
// HISTORY_SCHEMA's `required` list, which is what makes the answer arrive at all;
// this is what happens if that ever comes off again.
test('an omitted or non-boolean complete flag is not a complete fix', () => {
  for (const complete of [undefined, null, '', 'yes', 1]) {
    const r = upstreamFixStands(fixed({ complete }))
    assert.equal(r.partial, true, `complete ${JSON.stringify(complete)} must not read as a whole fix`)
  }
})

test('a dead history agent does not stand as a fix', () => {
  assert.equal(upstreamFixStands(null), null)
  assert.equal(upstreamFixStands(undefined), null)
})

// ------------------------------------------------------------- capSeverity

test('an internal vulnerability keeps its severity', () => {
  for (const severity of ['Critical', 'High', 'Medium', 'Low', 'Informational']) {
    const r = capSeverity(severity, 'internal', 'vulnerability')
    assert.equal(r.severity, severity)
    assert.equal(r.note, '')
  }
})

// This is one of the two mechanisms the measured head-to-head attributed its
// delta to: 3/3 on `integration-cap` where the arm that merely ASKED for the cap
// in a prompt scored 0/3.
test('an integration or external root cause is capped at Medium', () => {
  for (const rootCause of ['integration', 'external']) {
    for (const severity of ['Critical', 'High']) {
      const r = capSeverity(severity, rootCause, 'vulnerability')
      assert.equal(r.severity, 'Medium', `${severity} / ${rootCause}`)
      assert.match(r.note, new RegExp(rootCause))
      assert.match(r.note, new RegExp(severity))
    }
  }
})

test('a hardening gap is capped at Medium even with an internal root cause', () => {
  const r = capSeverity('Critical', 'internal', 'hardening_gap')
  assert.equal(r.severity, 'Medium')
  assert.match(r.note, /hardening gap/)
})

// The cap lowers; it must never raise. A Low on an integration root cause is a
// Low, and "capped at Medium" read as "set to Medium" would inflate it.
test('the cap never raises a severity below it', () => {
  for (const severity of ['Medium', 'Low', 'Informational']) {
    const r = capSeverity(severity, 'external', 'hardening_gap')
    assert.equal(r.severity, severity, `${severity} must not be raised`)
    assert.equal(r.note, '')
  }
})

test('the correction is always reported, never silent', () => {
  const r = capSeverity('High', 'integration', 'vulnerability')
  assert.ok(r.note.trim(), 'a severity changed without saying so is a silent rewrite of the finding')
})

// ----------------------------------------------------------- decideVerdict

const GATES = {
  gateProcess: 'PASS',
  gateReachability: 'PASS',
  gateRealImpact: 'PASS',
  gatePocValidation: 'PASS',
  gateMathBounds: 'N/A',
  gateEnvironment: 'PASS',
  unresolvedUncertainty: '',
  verdictReason: 'a negative amount reaches ledger.debit unvalidated',
  evidence: 'ledger.py:12',
}
const GATE_NAMES = [
  'gateProcess',
  'gateReachability',
  'gateRealImpact',
  'gatePocValidation',
  'gateMathBounds',
  'gateEnvironment',
]

test('all six passing is a TRUE POSITIVE carrying the reason', () => {
  const r = decideVerdict(GATES)
  assert.equal(r.status, 'TRUE_POSITIVE')
  assert.match(r.reason, /ledger\.debit/)
})

test('any single gate failing is a FALSE POSITIVE that names the gate', () => {
  for (const key of GATE_NAMES) {
    const r = decideVerdict({ ...GATES, [key]: 'FAIL' })
    assert.equal(r.status, 'FALSE_POSITIVE', `${key} FAIL must not pass`)
    assert.ok(r.reason.trim(), `${key} FAIL gave no reason`)
  }
})

test('a FAIL outranks unresolved uncertainty: the specific answer wins', () => {
  const r = decideVerdict({
    ...GATES,
    gateReachability: 'FAIL',
    unresolvedUncertainty: 'could not establish the deployment shape',
  })
  assert.equal(r.status, 'FALSE_POSITIVE')
  assert.match(r.reason, /Reachability/)
})

// fp-check's standard route escalates "if any question produces genuine
// uncertainty you cannot resolve". Six PASSes and an honest unresolved note is
// not a TRUE POSITIVE, and forcing it either way is the coin flip the third
// verdict exists to replace.
test('unresolved uncertainty is NEEDS MORE INFO even with six passes', () => {
  const r = decideVerdict({ ...GATES, unresolvedUncertainty: 'the threading model is unclear' })
  assert.equal(r.status, 'NEEDS_MORE_INFO')
  assert.match(r.reason, /threading model/)
})

test('whitespace in unresolvedUncertainty is not an uncertainty', () => {
  assert.equal(decideVerdict({ ...GATES, unresolvedUncertainty: '   ' }).status, 'TRUE_POSITIVE')
})

// Read the affirmative value per gate. Grading by exclusion — anything not FAIL
// passes — makes TRUE POSITIVE the fall-through for a value this script does not
// recognise, on the decision the whole skill exists to make.
test('a gate value outside the enum does not fall through to TRUE POSITIVE', () => {
  for (const key of GATE_NAMES) {
    for (const value of [undefined, '', 'pass', 'MAYBE', 'N/A']) {
      if (key === 'gateMathBounds' && value === 'N/A') continue
      const r = decideVerdict({ ...GATES, [key]: value })
      assert.equal(
        r.status,
        'NEEDS_MORE_INFO',
        `${key}: ${JSON.stringify(value)} must not reach TRUE_POSITIVE`,
      )
    }
  }
})

test('N/A is accepted on Math Bounds and only there', () => {
  assert.equal(decideVerdict({ ...GATES, gateMathBounds: 'N/A' }).status, 'TRUE_POSITIVE')
  assert.equal(decideVerdict({ ...GATES, gateEnvironment: 'N/A' }).status, 'NEEDS_MORE_INFO')
})

test('a dead gate agent is NEEDS MORE INFO, not a verdict', () => {
  for (const input of [null, undefined]) {
    const r = decideVerdict(input)
    assert.equal(r.status, 'NEEDS_MORE_INFO')
    assert.ok(r.reason.trim())
  }
})

// `required` checks presence, not content, so `verdictReason: ''` validates. Six
// PASSes with nothing behind them is the self-report this port exists to remove.
test('six passes with no reason is not a TRUE POSITIVE', () => {
  for (const blank of ['', '   ']) {
    const r = decideVerdict({ ...GATES, verdictReason: blank, evidence: blank })
    assert.equal(r.status, 'NEEDS_MORE_INFO')
  }
})

test('evidence stands in for a missing verdictReason rather than blocking', () => {
  const r = decideVerdict({ ...GATES, verdictReason: '', evidence: 'ledger.py:12, traced from api.py:8' })
  assert.equal(r.status, 'TRUE_POSITIVE')
  assert.match(r.reason, /api\.py:8/)
})

// -------------------------------------------------- the gates, where used

const WIRING_ARGS = {
  baseDir: '/plugin/skills/fp-check',
  finding: {
    summary: 'unvalidated rate multiplies into a cent amount',
    sink: 'billing/charge.py:20',
    component: 'billing',
    claimedImpact: 'an attacker mints balance',
    bugClass: 'logic error',
    threatModel: 'an order-placing caller supplies a quantity that the pricing service scales',
  },
  entryPoint: { description: 'POST /charge', location: 'billing/charge.py:8', payload: 'qty=125' },
  layers: [{ name: 'qty-check', location: 'billing/charge.py:12', checks: 'quantity is finalised upstream' }],
  scope: 'the billing module',
}

const agents = (over = {}) => ({
  brocard: { verdict: 'PASS', missingFact: '', evidence: 'fine' },
  layer: { verdict: 'PAYLOAD_REACHES_SINK', evidence: 'no guard on rate' },
  recovery: { recoveryExists: false, effectiveImpact: 'balance corrupted', evidence: 'no recover' },
  'threat-model': { inScope: 'YES', byDesign: false, byDesignIndicators: 0, evidence: 'in scope' },
  history: { fixed: 'NO', reference: '', searched: 'git log -p', evidence: 'nothing' },
  impact: {
    result: 'VERIFIED',
    impact: 'a negative rate credits the account',
    rootCause: 'integration',
    externalPrecondition: 'the pricing service returns a negative rate',
    classification: 'vulnerability',
    severity: 'Critical',
    severityRationale: 'full balance control',
    evidence: 'traced',
  },
  gates: GATES,
  ...over,
})

test('an upstream fix retracts before the impact agent is spent', async () => {
  const { result, calls } = await runScript('triage-static.js', {
    args: WIRING_ARGS,
    agents: agents({
      history: {
        fixed: 'YES',
        complete: true,
        reference: '#412',
        searched: 'git log -p',
        evidence: 'fixed in the caller',
      },
    }),
  })
  assert.equal(result.status, 'ALREADY_FIXED')
  assert.match(result.reason, /#412/)
  assert.ok(!calls.some((c) => c.label === 'impact'), 'a dead bug does not need its impact verified')
})

// The other half of that retraction, and the shape the schema used to let through:
// a fix the agent found but never called complete. It retracts nothing, and the
// analysis continues against what the fix left behind.
test('a fix that is not affirmatively complete does not retract the finding', async () => {
  for (const complete of [undefined, false]) {
    const { result, calls } = await runScript('triage-static.js', {
      args: WIRING_ARGS,
      agents: agents({
        history: {
          fixed: 'YES',
          complete,
          reference: '#412',
          searched: 'git log -p',
          evidence: 'the caller normalises one of the two operands',
        },
      }),
    })
    assert.notEqual(result.status, 'ALREADY_FIXED', `complete ${JSON.stringify(complete)}`)
    const impact = calls.find((c) => c.label === 'impact')
    assert.ok(impact, 'a partial fix leaves a finding to verify')
    assert.match(impact.prompt, /PARTIAL fix exists \(#412\)/)
  }
})

test('an unreferenced YES does not retract, and the analysis continues', async () => {
  const { result, calls } = await runScript('triage-static.js', {
    args: WIRING_ARGS,
    agents: agents({
      history: { fixed: 'YES', reference: '', searched: 'git log -p', evidence: 'felt familiar' },
    }),
  })
  assert.notEqual(result.status, 'ALREADY_FIXED')
  assert.ok(calls.some((c) => c.label === 'impact'))
})

test('the standard route dispatches no deep-only proof agents', async () => {
  const { calls } = await runScript('triage-static.js', { args: WIRING_ARGS, agents: agents() })
  for (const label of ['api-contract', 'math-bounds', 'race-feasibility']) {
    assert.ok(!calls.some((c) => c.label === label), `${label} must not run on the cheap path`)
  }
})

// Every deep-route fixture carries `applies`, because PROOF_SCHEMA requires it —
// a fixture that omits it is not a shape the runtime validator lets through, and
// the code reads `applies === true` so an omitted one cannot block.
const proof = (verdict, evidence, applies = true) => ({ applies, verdict, evidence })

test('the deep route dispatches all three', async () => {
  const { calls } = await runScript('triage-static.js', {
    args: { ...WIRING_ARGS, route: 'deep' },
    agents: agents({
      'api-contract': proof('FINDING_SURVIVES', 'no built-in bound'),
      'math-bounds': proof('FINDING_SURVIVES', 'the product is unbounded'),
      'race-feasibility': proof('UNCERTAIN', 'not a concurrency finding', false),
    }),
  })
  for (const label of ['api-contract', 'math-bounds', 'race-feasibility']) {
    assert.ok(calls.some((c) => c.label === label), `${label} must run on the deep route`)
  }
})

// The `integration-cap` loss, reproduced and then fixed. A single auxiliary proof
// used to return NOT_EXPLOITABLE from above the impact stage, the severity cap
// and the six gates — none of which then ran. It is carried now: the analysis
// finishes, the cap is applied, and the proof blocks the confirmation instead of
// replacing it.
test('a blocking proof no longer pre-empts the impact stage and the severity cap', async () => {
  const { result, calls } = await runScript('triage-static.js', {
    args: { ...WIRING_ARGS, route: 'deep' },
    agents: agents({
      'api-contract': proof('FINDING_SURVIVES', 'no built-in bound'),
      'math-bounds': proof('FINDING_REFUTED', 'qty >= 1 and rate >= 0 make the product non-negative'),
      'race-feasibility': proof('UNCERTAIN', 'n/a', false),
    }),
  })
  assert.ok(calls.some((c) => c.label === 'impact'), 'the impact stage must not be pre-empted by one proof')
  assert.equal(result.severity, 'Medium', 'and the cap has to have been applied')
  assert.match(result.severityCorrection, /integration/)
  // Still never a confirmation: the proof blocks TRUE_POSITIVE in code.
  assert.equal(result.status, 'NEEDS_MORE_INFO')
  assert.match(result.reason, /math-bounds/)
  assert.match(result.reason, /non-negative/, 'and the proof reaches the reader verbatim')
})

// The other direction, so the demotion is not a fail-open: the gate agent sees
// the blocking proof and can convert it into a named gate FAIL, which is a
// better-specified dismissal than "math-bounds said no".
test('a blocking proof reaches the gate agent, which can turn it into a FALSE POSITIVE', async () => {
  const { result, calls } = await runScript('triage-static.js', {
    args: { ...WIRING_ARGS, route: 'deep' },
    agents: agents({
      'api-contract': proof('FINDING_SURVIVES', 'no built-in bound'),
      'math-bounds': proof('FINDING_REFUTED', 'MIN >= sizeof(hdr) so the subtraction cannot underflow'),
      'race-feasibility': proof('UNCERTAIN', 'n/a', false),
      gates: { ...GATES, gateMathBounds: 'FAIL', verdictReason: 'the algebra forbids the vulnerable condition' },
    }),
  })
  const gates = calls.find((c) => c.label === 'gates')
  assert.match(gates.prompt, /sizeof\(hdr\)/)
  assert.equal(result.status, 'FALSE_POSITIVE')
  assert.match(result.reason, /Math Bounds/)
})

// An inapplicable deep proof must not be terminal, and `applies` is what makes
// that enforceable rather than requested. Two of the three are asked a question
// that often does not bear on the finding — there is no algebra in a logic bug
// and no threading model in a synchronous one — and the old escape was a line of
// prompt telling the agent to answer UNCERTAIN. An agent asked "is concurrent
// access actually possible?" about a finding with no concurrency in it answers
// the question it was asked, truthfully, with FINDING_REFUTED.
test('an inapplicable deep proof does not block the finding', async () => {
  const { result } = await runScript('triage-static.js', {
    args: { ...WIRING_ARGS, route: 'deep' },
    agents: agents({
      'api-contract': proof('UNCERTAIN', 'no relevant API contract', false),
      'math-bounds': proof('UNCERTAIN', 'not a bounds finding', false),
      'race-feasibility': proof('UNCERTAIN', 'single-threaded', false),
    }),
  })
  assert.equal(result.status, 'TRUE_POSITIVE')
})

test('an inapplicable proof reporting FINDING_REFUTED does not block either', async () => {
  const { result } = await runScript('triage-static.js', {
    args: { ...WIRING_ARGS, route: 'deep' },
    agents: agents({
      'api-contract': proof('UNCERTAIN', 'no relevant API contract', false),
      'math-bounds': proof('UNCERTAIN', 'not a bounds finding', false),
      // The exact shape that cost `integration-cap` its points: a proof asked a
      // question the finding never posed, answering it accurately, in the enum
      // position that means "this finding is impossible".
      'race-feasibility': proof('FINDING_REFUTED', 'this is not a concurrency finding at all', false),
    }),
  })
  assert.equal(result.status, 'TRUE_POSITIVE')
  assert.equal(result.severity, 'Medium')
})

// A dead deep-route proof agent is the deep route not having happened. The three
// proofs ARE the escalation — nothing else in this workflow writes the algebra or
// establishes the threading model — so treating a null as "did not block" spends
// the deep route's money and enforces none of it. `decideGate` blocks on a dead
// recovery, threat-model or history agent for exactly this reason; these were the
// three that were merely mentioned in the gate prompt and left for the agent to
// weigh, which is the self-report the whole port exists to remove.
test('a dead deep-route proof agent blocks rather than passing as non-blocking', async () => {
  const { result } = await runScript('triage-static.js', {
    args: { ...WIRING_ARGS, route: 'deep' },
    // The three proof labels are deliberately unmapped, so their agents return
    // nothing.
    agents: agents(),
  })
  assert.equal(result.status, 'BLOCKED')
  assert.match(result.reason, /api-contract/)
  assert.match(result.reason, /math-bounds/)
  assert.match(result.reason, /race-feasibility/)
})

// A blocking proof no longer outranks a dead sibling, and that is a consequence
// of the demotion rather than a weakening. The old precedence — "a proof that
// decided beats one that died" — was worth having only while a single refutation
// could end the stage. Now it cannot, so a dead sibling means the escalation the
// deep route was paid for did not happen, and BLOCKED is the honest answer.
// What must not happen is the live proof's finding being thrown away, so it is
// still on the payload for whoever re-dispatches.
test('a dead sibling proof blocks even when another proof decided, and the decision survives', async () => {
  const { result } = await runScript('triage-static.js', {
    args: { ...WIRING_ARGS, route: 'deep' },
    agents: agents({
      'math-bounds': proof('FINDING_REFUTED', 'qty >= 1 and rate >= 0 make the product non-negative'),
    }),
  })
  assert.equal(result.status, 'BLOCKED')
  assert.match(result.reason, /api-contract/)
  assert.deepEqual(result.blockingProofs.map((p) => p.key), ['math-bounds'])
  assert.match(result.blockingProofs[0].what, /non-negative/)
})

test('the severity cap is applied to what the workflow returns', async () => {
  const { result } = await runScript('triage-static.js', { args: WIRING_ARGS, agents: agents() })
  assert.equal(result.status, 'TRUE_POSITIVE')
  // The impact agent said Critical; the root cause is integration.
  assert.equal(result.severity, 'Medium')
  assert.match(result.severityCorrection, /Critical/)
})

test('the capped severity, not the agent claim, is what the gate agent is shown', async () => {
  const { calls } = await runScript('triage-static.js', { args: WIRING_ARGS, agents: agents() })
  const gates = calls.find((c) => c.label === 'gates')
  assert.ok(gates, 'the gate agent must be dispatched')
  assert.match(gates.prompt, /Severity after the caps: Medium/)
})

test('a failing gate is reported as a FALSE POSITIVE by the workflow', async () => {
  const { result } = await runScript('triage-static.js', {
    args: WIRING_ARGS,
    agents: agents({
      gates: { ...GATES, gateReachability: 'FAIL', verdictReason: 'no caller drives this path' },
    }),
  })
  assert.equal(result.status, 'FALSE_POSITIVE')
  assert.match(result.reason, /no caller drives this path/)
})

test('the route taken is reported, so a result can be attributed to it', async () => {
  const cheap = await runScript('triage-static.js', { args: WIRING_ARGS, agents: agents() })
  assert.equal(cheap.result.route, 'standard')
  const deep = await runScript('triage-static.js', {
    args: { ...WIRING_ARGS, route: 'deep' },
    agents: agents({
      'api-contract': { verdict: 'UNCERTAIN', evidence: 'n/a' },
      'math-bounds': { verdict: 'UNCERTAIN', evidence: 'n/a' },
      'race-feasibility': { verdict: 'UNCERTAIN', evidence: 'n/a' },
    }),
  })
  assert.equal(deep.result.route, 'deep')
})

test('the layers, recovery, threat and history all dispatch', () => {
  return runScript('triage-static.js', { args: WIRING_ARGS, agents: agents() }).then(({ calls }) => {
    assert.equal(calls.filter((c) => c.label.startsWith('brocard:')).length, 0, 'the brocard pre-gate is gone; nothing may dispatch one')
    assert.equal(calls.filter((c) => c.label.startsWith('layer:')).length, 1)
    for (const label of ['recovery', 'threat-model', 'history', 'impact', 'gates']) {
      assert.ok(calls.some((c) => c.label === label), `${label} must be dispatched`)
    }
  })
})

test('every gate function is extractable: a rename must fail loudly', () => {
  const names = [
    'missingArgs',
    'selectRoute',
    'upstreamFixStands',
    'decideGate',
    'missingPrecondition',
    'capSeverity',
    'blockingProofs',
    'decideVerdict',
  ]
  const loaded = loadFns(STATIC, ...names)
  for (const name of names) {
    assert.equal(typeof loaded[name], 'function', `${name} is not extractable`)
  }
})

// Found by the first measured sweep, via a subagent audit of the logs: the cap
// used to run AFTER both post-impact early exits, each of which returns the
// `impact` object verbatim. So a finding that exited at either one handed the
// orchestrator the agent's own uncapped severity, with no correction and no note —
// and the second exit fires precisely when the root cause is integration or
// external with the precondition unstated, which is the most likely non-passing
// outcome for exactly the findings the cap exists to bound.
test('every post-impact exit carries the capped severity, not the raw one', async () => {
  const INTEGRATION_CRITICAL = {
    result: 'VERIFIED',
    impact: 'an attacker mints balance',
    rootCause: 'integration',
    externalPrecondition: '',        // omitted on purpose: trips missingPrecondition
    classification: 'vulnerability',
    severity: 'Critical',
    severityRationale: 'full balance control',
    evidence: 'traced',
  }
  const cases = [
    ['missingPrecondition exit', INTEGRATION_CRITICAL, 'NEEDS_MORE_INFO'],
    ['NOT_VERIFIED exit', { ...INTEGRATION_CRITICAL, result: 'NOT_VERIFIED' }, 'NEEDS_MORE_INFO'],
    ['DISPROVEN exit', { ...INTEGRATION_CRITICAL, result: 'DISPROVEN' }, 'NOT_EXPLOITABLE'],
  ]
  for (const [label, impact, expected] of cases) {
    const { result } = await runScript('triage-static.js', {
      args: WIRING_ARGS,
      agents: agents({ impact }),
    })
    assert.equal(result.status, expected, label)
    assert.equal(result.severity, 'Medium', `${label}: must carry the CAPPED severity`)
    assert.match(result.severityCorrection, /integration/, `${label}: and say it was corrected`)
    assert.equal(result.impact.severity, 'Critical', `${label}: the raw agent value is still visible`)
  }
})
