/**
 * Layer 2 for the gates Stage 1 added over concept-prover's verify-attack-path:
 * the brocard pre-gate, the standard/deep route, the upstream-fix retraction, the
 * severity cap, and the six-gate verdict.
 *
 * `gate.test.mjs` covers decideGate and missingPrecondition, which came across
 * unchanged. Everything here is new surface, so it had no tests at all — and the
 * two mechanisms the head-to-head attributed its measured delta to (the
 * already-fixed retraction and the severity cap) are among them.
 */

import assert from 'node:assert/strict'
import { test } from 'node:test'

import { loadFn, loadFns, runScript, script } from './extract.mjs'

const STATIC = script('triage-static.js')
const selectRoute = loadFn(STATIC, 'selectRoute')
const triageBrocards = loadFn(STATIC, 'triageBrocards')
// Only a DISMISS is terminal now; everything else is carried. These two shims keep
// the existing assertions readable against the new two-field return.
const dismissalOf = (v, k) => triageBrocards(v, k).dismissal
const unresolvedOf = (v, k) => triageBrocards(v, k).unresolved
const upstreamFixStands = loadFn(STATIC, 'upstreamFixStands')
const capSeverity = loadFn(STATIC, 'capSeverity')
const decideVerdict = loadFn(STATIC, 'decideVerdict')

const KEYS = ['from-the-heavens', 'standard-behavior', 'documented-behavior', 'cure-worse']
const pass = (key) => ({ key, title: `Brocard ${key}`, verdict: 'PASS', missingFact: '', evidence: 'fine' })
const allPass = () => KEYS.map(pass)

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

// ------------------------------------------------------ dismissedByBrocard

test('all four passing returns null so the analysis continues', () => {
  assert.equal(dismissalOf(allPass(), KEYS), null)
})

test('a DISMISS ends the stage and quotes the brocard that did it', () => {
  const verdicts = allPass().map((v) =>
    v.key === 'standard-behavior' ? { ...v, verdict: 'DISMISS', evidence: 'RFC 7230 requires it' } : v,
  )
  const r = dismissalOf(verdicts, KEYS)
  assert.equal(r.status, 'DISMISSED')
  assert.match(r.reason, /standard-behavior/)
  assert.match(r.reason, /RFC 7230/)
})

// The brocards skill's rule is "stop at the first DISMISS". All four agents run
// concurrently, so "first" can only mean first in the declared order — otherwise
// the reported reason depends on which agent happened to finish first, and the
// same finding gets a different epitaph on every run.
test('the reported DISMISS is the first in declaration order, not in return order', () => {
  const verdicts = allPass()
    .map((v) => ({ ...v, verdict: 'DISMISS', evidence: `because ${v.key}` }))
    .reverse()
  assert.match(dismissalOf(verdicts, KEYS).reason, /from-the-heavens/)
})

// A DISMISS is terminal and a NEEDS_MORE_INFO is not, so when both are present
// the terminal one has to win: reporting "I need more information" about a
// finding that another test already disposed of asks the user for evidence
// nobody will use.
test('a DISMISS outranks a NEEDS_MORE_INFO', () => {
  const verdicts = allPass().map((v) => {
    if (v.key === 'from-the-heavens') return { ...v, verdict: 'NEEDS_MORE_INFO', missingFact: 'the deployment shape' }
    if (v.key === 'cure-worse') return { ...v, verdict: 'DISMISS', evidence: 'the fix breaks every consumer' }
    return v
  })
  assert.equal(dismissalOf(verdicts, KEYS).status, 'DISMISSED')
})

// Carried, not terminal — this is the change the first sweep forced. A cheap test
// that cannot decide must not end the analysis, because "the cheapest test could
// not tell" is precisely what the expensive stages exist to resolve. It still has
// to name the missing fact, because an unactionable open question is the hedge the
// third verdict was introduced to replace.
test('NEEDS_MORE_INFO is carried with its missing fact, not made terminal', () => {
  const verdicts = allPass().map((v) =>
    v.key === 'documented-behavior'
      ? { ...v, verdict: 'NEEDS_MORE_INFO', missingFact: 'whether the docs warn about this' }
      : v,
  )
  assert.equal(dismissalOf(verdicts, KEYS), null, 'must not end the stage')
  const open = unresolvedOf(verdicts, KEYS)
  assert.equal(open.length, 1)
  assert.equal(open[0].key, 'documented-behavior')
  assert.match(open[0].what, /whether the docs warn/)
})

test('a carried NEEDS_MORE_INFO with no missing fact still explains itself', () => {
  for (const missingFact of [undefined, '', '   ']) {
    const verdicts = allPass().map((v) =>
      v.key === 'cure-worse' ? { ...v, verdict: 'NEEDS_MORE_INFO', missingFact, evidence: '' } : v,
    )
    const open = unresolvedOf(verdicts, KEYS)
    assert.equal(open.length, 1)
    assert.ok(open[0].what && open[0].what.trim(), `missingFact ${JSON.stringify(missingFact)} gave nothing`)
  }
})

// Tallied against the EXPECTED key list, not against what came back. Reading the
// returned array instead lets a dead agent shrink the denominator: three passes
// out of three returned verdicts clears a gate that was supposed to apply four
// tests, and nothing in the result says a test never ran.
// Tallied against the EXPECTED key list, not against what came back: reading the
// returned array lets a dead agent shrink the denominator, so three passes out of
// three RETURNED verdicts would clear a gate meant to apply four tests.
test('an unevaluated brocard is carried as unknown, never as passed', () => {
  for (const drop of KEYS) {
    const verdicts = allPass().filter((v) => v.key !== drop)
    assert.equal(dismissalOf(verdicts, KEYS), null, 'a dead agent is not a dismissal')
    const open = unresolvedOf(verdicts, KEYS)
    assert.deepEqual(open.map((q) => q.key), [drop], `a missing ${drop} verdict must be carried`)
    assert.match(open[0].what, /never ran|returned nothing/)
  }
})

test('a dead agent yields null and is counted as unevaluated, not skipped', () => {
  const open = unresolvedOf([null, ...allPass().slice(1)], KEYS)
  assert.deepEqual(open.map((q) => q.key), ['from-the-heavens'])
})

// Found by a graded run, not by this suite. Each brocard is an independent
// falsifiable test and any ONE dismissing is sufficient, so a fourth agent dying
// cannot unmake an answer another agent already reached. The gate checked
// liveness first and threw it away: brocard 5 returned a clean DISMISS, one of
// the other three hit a connection error, and the run reported NEEDS_MORE_INFO
// about a finding that was already disposed of — then burned the case's whole
// 1800s budget getting there.
//
// Same rule as `decideGate`'s blocking layer outranking a dead recovery agent.
test('a DISMISS outranks a dead sibling agent, whichever order they land in', () => {
  for (const deadKey of KEYS) {
    for (const dismissKey of KEYS) {
      if (deadKey === dismissKey) continue
      const verdicts = allPass()
        .filter((v) => v.key !== deadKey)
        .map((v) => (v.key === dismissKey ? { ...v, verdict: 'DISMISS', evidence: 'the spec requires it' } : v))
      const r = dismissalOf(verdicts, KEYS)
      assert.equal(
        r.status,
        'DISMISSED',
        `${dismissKey} dismissed and ${deadKey} died: the dismissal must stand`,
      )
      assert.match(r.reason, new RegExp(dismissKey))
    }
  }
})

test('but a dead agent is still carried when nothing dismissed the finding', () => {
  // The inverse, so the fix cannot be over-applied into a fail-open: three PASSes
  // and a corpse is not four PASSes. It no longer ends the stage, but it does reach
  // decideVerdict, which blocks a TRUE POSITIVE on it.
  assert.equal(dismissalOf(allPass().slice(1), KEYS), null)
  assert.equal(unresolvedOf(allPass().slice(1), KEYS).length, 1)
})

test('all four passing carries nothing', () => {
  assert.deepEqual(unresolvedOf(allPass(), KEYS), [])
})

// The enforcement half. The pre-gate no longer vetoes, so this is what stops an
// unresolved cheap test from being lost: six passing gates plus one carried
// question is NEEDS MORE INFO, in code, not a TRUE POSITIVE with a footnote.
test('an unresolved brocard blocks a TRUE POSITIVE at the verdict', () => {
  const carried = [{ key: 'documented-behavior', title: 'Brocard 5', what: 'the upstream contract' }]
  assert.equal(decideVerdict(GATES, []).status, 'TRUE_POSITIVE')
  const r = decideVerdict(GATES, carried)
  assert.equal(r.status, 'NEEDS_MORE_INFO')
  assert.match(r.reason, /Brocard 5/)
  assert.match(r.reason, /upstream contract/)
})

test('a FAIL still outranks a carried question: the specific answer wins', () => {
  const carried = [{ key: 'cure-worse', title: 'Brocard 6', what: 'the fix cost' }]
  const r = decideVerdict({ ...GATES, gateReachability: 'FAIL' }, carried)
  assert.equal(r.status, 'FALSE_POSITIVE')
})

test('decideVerdict tolerates a missing or ragged carried list', () => {
  for (const c of [undefined, null, [], [null]]) {
    assert.equal(decideVerdict(GATES, c).status, 'TRUE_POSITIVE', JSON.stringify(c))
  }
})

test('a DISMISS with no evidence still carries a reason', () => {
  const verdicts = allPass().map((v) =>
    v.key === 'cure-worse' ? { ...v, verdict: 'DISMISS', evidence: '   ' } : v,
  )
  const r = dismissalOf(verdicts, KEYS)
  assert.equal(r.status, 'DISMISSED')
  assert.ok(r.reason.trim().length > 'Brocard cure-worse: '.length)
})

// ------------------------------------------------------ upstreamFixStands

const fixed = (over = {}) => ({
  fixed: 'YES',
  reference: '#412',
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

test('an omitted complete flag is treated as a complete fix', () => {
  // `=== false` rather than falsy, so the field can be left out. The direction is
  // the safe one: asserting "partial" by omission would report a finding that the
  // evidence says is dead.
  assert.equal(upstreamFixStands(fixed()).partial, false)
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
  layer: { verdict: 'PASSES', evidence: 'no guard on rate' },
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

test('a brocard DISMISS stops before any layer agent is dispatched', async () => {
  const { result, calls } = await runScript('triage-static.js', {
    args: WIRING_ARGS,
    agents: agents({ brocard: { verdict: 'DISMISS', missingFact: '', evidence: 'the spec requires it' } }),
  })
  assert.equal(result.status, 'DISMISSED')
  assert.ok(
    !calls.some((c) => c.label.startsWith('layer:')),
    'the whole point of a cheap pre-gate is that it runs before the expensive fan-out',
  )
  assert.ok(!calls.some((c) => c.label === 'impact'))
})

test('an upstream fix retracts before the impact agent is spent', async () => {
  const { result, calls } = await runScript('triage-static.js', {
    args: WIRING_ARGS,
    agents: agents({
      history: { fixed: 'YES', reference: '#412', searched: 'git log -p', evidence: 'fixed in the caller' },
    }),
  })
  assert.equal(result.status, 'ALREADY_FIXED')
  assert.match(result.reason, /#412/)
  assert.ok(!calls.some((c) => c.label === 'impact'), 'a dead bug does not need its impact verified')
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

test('the deep route dispatches all three, and a blocking proof is terminal', async () => {
  const { calls } = await runScript('triage-static.js', {
    args: { ...WIRING_ARGS, route: 'deep' },
    agents: agents({
      'api-contract': { verdict: 'PASSES', evidence: 'no built-in bound' },
      'math-bounds': { verdict: 'PASSES', evidence: 'the product is unbounded' },
      'race-feasibility': { verdict: 'UNCERTAIN', evidence: 'not a concurrency finding' },
    }),
  })
  for (const label of ['api-contract', 'math-bounds', 'race-feasibility']) {
    assert.ok(calls.some((c) => c.label === label), `${label} must run on the deep route`)
  }

  const blocked = await runScript('triage-static.js', {
    args: { ...WIRING_ARGS, route: 'deep' },
    agents: agents({
      'api-contract': { verdict: 'PASSES', evidence: 'no built-in bound' },
      'math-bounds': { verdict: 'BLOCKS', evidence: 'qty >= 1 and rate >= 0 make the product non-negative' },
      'race-feasibility': { verdict: 'UNCERTAIN', evidence: 'n/a' },
    }),
  })
  assert.equal(blocked.result.status, 'NOT_EXPLOITABLE')
  assert.match(blocked.result.reason, /math-bounds/)
  assert.ok(!blocked.calls.some((c) => c.label === 'impact'))
})

// An UNCERTAIN deep proof must not be terminal. Two of the three are asked a
// question that often does not apply — there is no algebra in a logic bug and no
// threading model in a synchronous one — and they are told to answer UNCERTAIN
// and say so. Treating that as a blocker would make the deep route strictly worse
// than the cheap one on every finding that is not a bounds or race bug.
test('an inapplicable deep proof does not block the finding', async () => {
  const { result } = await runScript('triage-static.js', {
    args: { ...WIRING_ARGS, route: 'deep' },
    agents: agents({
      'api-contract': { verdict: 'UNCERTAIN', evidence: 'no relevant API contract' },
      'math-bounds': { verdict: 'UNCERTAIN', evidence: 'not a bounds finding' },
      'race-feasibility': { verdict: 'UNCERTAIN', evidence: 'single-threaded' },
    }),
  })
  assert.equal(result.status, 'TRUE_POSITIVE')
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

// The brocard 6 answer is the only place remediation cost is evaluated, and a
// value nothing reads is a value that does not exist.
test('a brocard 6 severity input reaches the impact agent', async () => {
  const { calls } = await runScript('triage-static.js', {
    args: WIRING_ARGS,
    agents: agents({
      brocard: (prompt) => ({
        verdict: 'PASS',
        missingFact: '',
        severityInput: prompt.includes('Brocard 6') ? 'the only safe fix is a breaking API change' : '',
        evidence: 'fine',
      }),
    }),
  })
  const impact = calls.find((c) => c.label === 'impact')
  assert.ok(impact, 'the impact agent must be dispatched')
  assert.match(impact.prompt, /breaking API change/)
})

test('the four brocards, the layers, recovery, threat and history all dispatch', () => {
  return runScript('triage-static.js', { args: WIRING_ARGS, agents: agents() }).then(({ calls }) => {
    assert.equal(calls.filter((c) => c.label.startsWith('brocard:')).length, 4)
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
    'triageBrocards',
    'upstreamFixStands',
    'decideGate',
    'missingPrecondition',
    'capSeverity',
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
