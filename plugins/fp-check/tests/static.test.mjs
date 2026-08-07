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
import { readFileSync } from 'node:fs'
import { test } from 'node:test'

import { loadFn, loadFns, runScript, script } from './extract.mjs'

const STATIC = script('triage-static.js')
const selectRoute = loadFn(STATIC, 'selectRoute')
const triageBrocards = loadFn(STATIC, 'triageBrocards')
// Only a DISMISS from a brocard with no downstream equivalent is terminal now;
// everything else is carried. These shims keep the existing assertions readable
// against the three-field return.
const dismissalOf = (v, k) => triageBrocards(v, k).dismissal
const unresolvedOf = (v, k) => triageBrocards(v, k).unresolved
const deferredOf = (v, k) => triageBrocards(v, k).deferred
const upstreamFixStands = loadFn(STATIC, 'upstreamFixStands')
const capSeverity = loadFn(STATIC, 'capSeverity')
const decideVerdict = loadFn(STATIC, 'decideVerdict')
const blockingProofs = loadFn(STATIC, 'blockingProofs')

// The descriptor list the workflow passes, not a bare key list: `defersTo` is
// what tells a terminal brocard from a deferring one. Mirroring the shipped
// values here would be a copy that can rot, so
// `the fixtures agree with the shipped BROCARDS about which brocards defer`
// below reads them back out of the script.
const SPECS = [
  // Deferred as of the 2.2.0 probe: "the attacker must already control the
  // upstream service" is an integration root cause, which the impact stage and
  // capSeverity decide. It was the last brocard able to end the stage, and it
  // starved the cap on the one case the cap exists for.
  { key: 'from-the-heavens', defersTo: 'the impact stage' },
  { key: 'standard-behavior', defersTo: 'the recovery check and the threat-model agent' },
  { key: 'documented-behavior', defersTo: 'the already-fixed history search' },
  { key: 'cure-worse', defersTo: '' },
]
const KEYS = SPECS.map((s) => s.key)
// The two that still end the stage on their own, and the two that hand over.
const TERMINAL = SPECS.filter((s) => !s.defersTo).map((s) => s.key)
const DEFERRING = SPECS.filter((s) => s.defersTo).map((s) => s.key)
const pass = (key) => ({ key, title: `Brocard ${key}`, verdict: 'PASS', missingFact: '', evidence: 'fine' })
const allPass = () => KEYS.map(pass)

// The one thing SPECS cannot assert about itself. Every test above and below
// runs against these fixtures, so if the shipped BROCARDS list stopped deferring
// brocard 5 — or started deferring brocard 2 — this whole file would keep
// passing while grading a routing table the plugin no longer has.
//
// Read out of the source rather than imported: workflow scripts have no module
// system, which is why `extract.mjs` exists at all.
test('the fixtures agree with the shipped BROCARDS about which brocards defer', () => {
  const src = readFileSync(STATIC, 'utf8')
  const block = src.match(/const BROCARDS = \[[\s\S]*?\n\]\n/)
  assert.ok(block, 'BROCARDS not found; this pin is stale')
  // Split on the entry boundary so a `defersTo` is attributed to the `key` it
  // shares an object literal with, rather than to whichever key came first.
  const entries = block[0].split(/\n  \{\n/).slice(1)
  assert.equal(entries.length, SPECS.length, `BROCARDS declares ${entries.length} tests, SPECS has ${SPECS.length}`)
  const shipped = entries.map((entry) => {
    const key = entry.match(/^\s*key: '([^']+)'/m)
    assert.ok(key, `a BROCARDS entry has no key: ${entry.slice(0, 60)}`)
    return { key: key[1], defers: /^\s*defersTo:\s*'[^']+'/m.test(entry) }
  })
  assert.deepEqual(
    shipped,
    SPECS.map((s) => ({ key: s.key, defers: Boolean(s.defersTo) })),
    'the fixtures in this file no longer describe the shipped brocard routing',
  )
})

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
  assert.equal(dismissalOf(allPass(), SPECS), null)
})

test('a DISMISS ends the stage and quotes the brocard that did it', () => {
  const verdicts = allPass().map((v) =>
    v.key === 'cure-worse' ? { ...v, verdict: 'DISMISS', evidence: 'RFC 7230 requires it' } : v,
  )
  const r = dismissalOf(verdicts, SPECS)
  assert.equal(r.status, 'DISMISSED')
  assert.match(r.reason, /cure-worse/)
  assert.match(r.reason, /RFC 7230/)
})

// ------------------------------------------------------- deferred dismissals
//
// The merge's largest measured regression, and the reason `defersTo` exists.
// The brocard pre-gate is a first-position gate NEITHER parent had, and being
// cheap and first it won the race on findings the specialised gates were built
// for. Across 63 with-plugin runs of the seven eval cases a brocard DISMISS
// decided 12, while `upstreamFixStands`, `capSeverity`, `missingPrecondition`
// and `decideVerdict` fired zero times between them — and three of the seven
// cases exist to exercise exactly those four.

test('a DISMISS from a brocard with a downstream gate defers rather than ending the stage', () => {
  for (const key of DEFERRING) {
    const verdicts = allPass().map((v) =>
      v.key === key ? { ...v, verdict: 'DISMISS', evidence: 'the CHANGELOG documents this' } : v,
    )
    assert.equal(dismissalOf(verdicts, SPECS), null, `${key} must not end the stage on its own`)
    const deferred = deferredOf(verdicts, SPECS)
    assert.deepEqual(deferred.map((d) => d.key), [key])
    assert.match(deferred[0].what, /CHANGELOG documents this/, 'the dismissal survives verbatim')
    assert.ok(deferred[0].defersTo.trim(), 'and says which mechanism it handed over to')
  }
})

test('a brocard with no downstream gate still ends the stage', () => {
  for (const key of TERMINAL) {
    const verdicts = allPass().map((v) =>
      v.key === key ? { ...v, verdict: 'DISMISS', evidence: 'the attacker already holds it' } : v,
    )
    const r = dismissalOf(verdicts, SPECS)
    assert.ok(r, `${key} has no downstream equivalent; deferring it buys a fan-out and no better answer`)
    assert.equal(r.status, 'DISMISSED')
    assert.match(r.reason, new RegExp(key))
    assert.deepEqual(deferredOf(verdicts, SPECS), [], 'and nothing is left carried once the stage ends')
  }
})

// Precedence, and it is not declaration order: a terminal DISMISS ends the stage
// wherever it sits in the list. Reading the first DISMISS of any kind would let a
// deferring brocard at position 2 suppress a terminal one at position 4 and turn
// a finished analysis into a full fan-out.
test('a terminal DISMISS outranks a deferring one whatever the order', () => {
  const verdicts = allPass().map((v) =>
    v.key === 'standard-behavior' || v.key === 'cure-worse'
      ? { ...v, verdict: 'DISMISS', evidence: `because ${v.key}` }
      : v,
  )
  const r = dismissalOf(verdicts, SPECS)
  assert.equal(r.status, 'DISMISSED')
  assert.match(r.reason, /cure-worse/, 'the terminal brocard decides even though it is declared last')
})

// All of them, not the first. Two brocards dismissing for two different reasons
// is two arguments the downstream gates have to answer, and reporting one drops
// the other silently.
test('every deferred dismissal is carried, not just the first', () => {
  const verdicts = allPass().map((v) =>
    DEFERRING.includes(v.key) ? { ...v, verdict: 'DISMISS', evidence: `because ${v.key}` } : v,
  )
  assert.deepEqual(deferredOf(verdicts, SPECS).map((d) => d.key), DEFERRING)
})

test('a deferred DISMISS with no evidence still says something', () => {
  const verdicts = allPass().map((v) =>
    v.key === 'documented-behavior' ? { ...v, verdict: 'DISMISS', evidence: '   ' } : v,
  )
  const deferred = deferredOf(verdicts, SPECS)
  assert.equal(deferred.length, 1)
  assert.ok(deferred[0].what.trim(), 'a blank evidence string must not become a blank carried reason')
})

// The fail-safe direction. A caller that passes the old bare-key list, or a
// descriptor whose key was renamed, matches no verdict — and that must read as
// "this test never ran" (which blocks a TRUE POSITIVE) rather than as "this test
// passed". A malformed contract cannot be allowed to look like a clean bill.
test('a spec that matches no verdict is carried as unevaluated, never as passed', () => {
  const bare = ['from-the-heavens', 'standard-behavior', 'documented-behavior', 'cure-worse']
  const r = triageBrocards(allPass(), bare)
  assert.equal(r.dismissal, null)
  assert.equal(r.unresolved.length, 4, 'four unmatched specs are four unevaluated tests')
  assert.deepEqual(r.deferred, [])
})

// The brocards skill's rule is "stop at the first DISMISS". All four agents run
// concurrently, so "first" can only mean first in the declared order — otherwise
// the reported reason depends on which agent happened to finish first, and the
// same finding gets a different epitaph on every run.
// The brocards run concurrently, so "stop at the first DISMISS" can only mean
// first in DECLARATION order — otherwise the reported reason depends on which
// agent happened to finish first and the same finding gets a different epitaph
// every run.
//
// Among the ones that can END the stage. A deferring brocard's dismissal is
// carried to the gate that asks its question with the evidence in hand, so it is
// not the epitaph even when it is declared first — and the assertion below is
// deliberately written against the SPECS list rather than a hardcoded key, so it
// keeps testing the ordering property as brocards change which side they are on.
test('the reported DISMISS is the first terminal one in declaration order', () => {
  const verdicts = allPass()
    .map((v) => ({ ...v, verdict: 'DISMISS', evidence: `because ${v.key}` }))
    .reverse()
  const firstTerminal = SPECS.find((spec) => !String(spec.defersTo || '').trim())
  assert.ok(firstTerminal, 'every brocard defers now; this test would grade nothing')
  assert.match(dismissalOf(verdicts, SPECS).reason, new RegExp(firstTerminal.key))
  // And the deferring ones are still carried rather than lost.
  assert.equal(unresolvedOf(verdicts, SPECS).length, 0, 'a terminal dismissal ends it outright')
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
  assert.equal(dismissalOf(verdicts, SPECS).status, 'DISMISSED')
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
  assert.equal(dismissalOf(verdicts, SPECS), null, 'must not end the stage')
  const open = unresolvedOf(verdicts, SPECS)
  assert.equal(open.length, 1)
  assert.equal(open[0].key, 'documented-behavior')
  assert.match(open[0].what, /whether the docs warn/)
})

test('a carried NEEDS_MORE_INFO with no missing fact still explains itself', () => {
  for (const missingFact of [undefined, '', '   ']) {
    const verdicts = allPass().map((v) =>
      v.key === 'cure-worse' ? { ...v, verdict: 'NEEDS_MORE_INFO', missingFact, evidence: '' } : v,
    )
    const open = unresolvedOf(verdicts, SPECS)
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
    assert.equal(dismissalOf(verdicts, SPECS), null, 'a dead agent is not a dismissal')
    const open = unresolvedOf(verdicts, SPECS)
    assert.deepEqual(open.map((q) => q.key), [drop], `a missing ${drop} verdict must be carried`)
    assert.match(open[0].what, /never ran|returned nothing/)
  }
})

test('a dead agent yields null and is counted as unevaluated, not skipped', () => {
  const open = unresolvedOf([null, ...allPass().slice(1)], SPECS)
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
    // TERMINAL, not KEYS: a deferring brocard's DISMISS is carried rather than
    // terminal, so it has no precedence over a dead sibling to assert. Its own
    // half of this rule is the test below.
    for (const dismissKey of TERMINAL) {
      if (deadKey === dismissKey) continue
      const verdicts = allPass()
        .filter((v) => v.key !== deadKey)
        .map((v) => (v.key === dismissKey ? { ...v, verdict: 'DISMISS', evidence: 'the spec requires it' } : v))
      const r = dismissalOf(verdicts, SPECS)
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
  assert.equal(dismissalOf(allPass().slice(1), SPECS), null)
  assert.equal(unresolvedOf(allPass().slice(1), SPECS).length, 1)
})

test('all four passing carries nothing', () => {
  assert.deepEqual(unresolvedOf(allPass(), SPECS), [])
  assert.deepEqual(deferredOf(allPass(), SPECS), [])
})

// The deferring half of the dead-sibling rule. A deferral is a decision to keep
// analysing, so a dead sibling has nothing to overturn — but the dismissal still
// has to survive to the verdict, alongside the dead agent's own open question.
test('a deferred DISMISS and a dead sibling are both carried', () => {
  const verdicts = allPass()
    .filter((v) => v.key !== 'cure-worse')
    .map((v) => (v.key === 'documented-behavior' ? { ...v, verdict: 'DISMISS', evidence: 'documented' } : v))
  assert.equal(dismissalOf(verdicts, SPECS), null)
  assert.deepEqual(deferredOf(verdicts, SPECS).map((d) => d.key), ['documented-behavior'])
  assert.deepEqual(unresolvedOf(verdicts, SPECS).map((q) => q.key), ['cure-worse'])
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
    assert.equal(decideVerdict(GATES, [], c).status, 'TRUE_POSITIVE', `overruled ${JSON.stringify(c)}`)
  }
})

// The invariant that makes deferral legal. Everything a cheaper stage said to
// dismiss the finding is carried here instead of ending the stage — and it is
// enforced in code rather than asked of the gate agent, so the softest outcome a
// deferral can reach is NEEDS_MORE_INFO. Deferring therefore only ever buys more
// analysis; it can never make a false positive easier to report.
test('a deferred dismissal blocks a TRUE POSITIVE even with six passing gates', () => {
  const overruled = [
    { key: 'documented-behavior', title: 'Brocard 5', what: 'the CHANGELOG documents this behaviour' },
  ]
  assert.equal(decideVerdict(GATES, [], []).status, 'TRUE_POSITIVE')
  const r = decideVerdict(GATES, [], overruled)
  assert.equal(r.status, 'NEEDS_MORE_INFO')
  assert.match(r.reason, /Brocard 5/)
  assert.match(r.reason, /CHANGELOG documents this behaviour/, 'the dismissal reaches the reader verbatim')
})

test('a blocking deep-route proof blocks a TRUE POSITIVE through the same channel', () => {
  const r = decideVerdict(GATES, [], [
    { key: 'math-bounds', title: 'math-bounds', what: 'qty >= 1 and rate >= 0 make the product non-negative' },
  ])
  assert.equal(r.status, 'NEEDS_MORE_INFO')
  assert.match(r.reason, /math-bounds/)
})

// A gate that FAILED is the deferral being ANSWERED, and it outranks: naming the
// gate is the better-specified dismissal, which is the whole point of handing the
// question down to the six gates rather than letting the brocard decide it.
test('a gate FAIL outranks a deferred dismissal: the answer beats the question', () => {
  const overruled = [{ key: 'standard-behavior', title: 'Brocard 4', what: 'the spec permits it' }]
  const r = decideVerdict({ ...GATES, gateRealImpact: 'FAIL' }, [], overruled)
  assert.equal(r.status, 'FALSE_POSITIVE')
  assert.match(r.reason, /Real Impact/)
})

// The monotonicity property, asserted rather than argued: over every combination
// of a carried question and a deferred dismissal, a non-empty list of either can
// only ever produce a status that is NOT a confirmation.
test('nothing carried into decideVerdict can be dropped on the way to TRUE POSITIVE', () => {
  const q = { key: 'cure-worse', title: 'Brocard 6', what: 'the fix cost' }
  const d = { key: 'standard-behavior', title: 'Brocard 4', what: 'standard behaviour' }
  for (const [carried, overruled] of [
    [[q], []],
    [[], [d]],
    [[q], [d]],
  ]) {
    assert.notEqual(
      decideVerdict(GATES, carried, overruled).status,
      'TRUE_POSITIVE',
      `carried=${carried.length} overruled=${overruled.length}`,
    )
  }
  assert.equal(decideVerdict(GATES, [], []).status, 'TRUE_POSITIVE', 'and the zero guard: nothing carried still passes')
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
    const proofs = [{ key: 'race-feasibility', verdict: { applies, verdict: 'BLOCKS', evidence: 'no concurrency here' } }]
    assert.deepEqual(
      blockingProofs(proofs),
      [],
      `applies ${JSON.stringify(applies)} is not an affirmative "this question bears on the finding"`,
    )
  }
})

test('an applicable BLOCKS is returned with its evidence', () => {
  const proofs = [
    { key: 'api-contract', verdict: { applies: true, verdict: 'PASSES', evidence: 'no built-in bound' } },
    { key: 'math-bounds', verdict: { applies: true, verdict: 'BLOCKS', evidence: 'MIN >= sizeof(hdr)' } },
    { key: 'race-feasibility', verdict: { applies: false, verdict: 'UNCERTAIN', evidence: 'single-threaded' } },
  ]
  const blocking = blockingProofs(proofs)
  assert.deepEqual(blocking.map((p) => p.key), ['math-bounds'])
  assert.match(blocking[0].what, /sizeof\(hdr\)/)
})

test('an applicable BLOCKS with no evidence still says something', () => {
  const blocking = blockingProofs([
    { key: 'math-bounds', verdict: { applies: true, verdict: 'BLOCKS', evidence: '   ' } },
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

test('a DISMISS with no evidence still carries a reason', () => {
  const verdicts = allPass().map((v) =>
    v.key === 'cure-worse' ? { ...v, verdict: 'DISMISS', evidence: '   ' } : v,
  )
  const r = dismissalOf(verdicts, SPECS)
  assert.equal(r.status, 'DISMISSED')
  assert.ok(r.reason.trim().length > 'Brocard cure-worse: '.length)
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

// The cost half of the deferral, and the reason brocards 2 and 6 keep the
// short-circuit. Nothing downstream tests "the attacker already holds this
// capability", so deferring it would buy a full fan-out and no better answer.
// The measured baseline this protects: a linear checklist matched a full
// pipeline at 2.3x less cost, so the cheap path has to stay cheap for what the
// pre-gate genuinely disposes of on its own.
// Brocard 6 is the only one left that ends the stage: nothing else in the plugin
// evaluates remediation cost, so deferring it would buy a fan-out and no better
// answer. Brocards 2, 4 and 5 all have a downstream gate that asks their question
// with the traced evidence in hand, and all three defer to it.
//
// This is the cost pin. The cheap path has to stay cheap for the one case where
// short-circuiting is still right.
test('the one brocard with no downstream gate still spends nothing after the pre-gate', async () => {
  for (const title of ['Brocard 6']) {
    const { result, calls } = await runScript('triage-static.js', {
      args: WIRING_ARGS,
      agents: agents({
        brocard: (prompt) =>
          prompt.includes(title)
            ? { verdict: 'DISMISS', missingFact: '', evidence: 'the attacker already holds this' }
            : { verdict: 'PASS', missingFact: '', evidence: 'fine' },
      }),
    })
    assert.equal(result.status, 'DISMISSED', title)
    assert.deepEqual(
      calls.filter((c) => !c.label.startsWith('brocard:')).map((c) => c.label),
      [],
      `${title} has no downstream equivalent; not one agent beyond the pre-gate should be spent`,
    )
  }
})

// The wiring half of the deferral, and the one that reproduces the measured
// loss. `already-fixed` scored 1/3 on the latest sweep against concept-prover's
// 3/3, and the two failing runs were both decided at the pre-gate — one of them
// says so verbatim: *"Static triage result: DISMISSED (Brocard 5,
// already-fixed/documented behavior)"*. `upstreamFixStands` was right there,
// with the commit reference the case's grader asks for, and never ran.
test('a brocard 5 DISMISS hands over to the history search instead of ending the stage', async () => {
  const { result, calls } = await runScript('triage-static.js', {
    args: WIRING_ARGS,
    agents: agents({
      brocard: (prompt) =>
        prompt.includes('Brocard 5')
          ? { verdict: 'DISMISS', missingFact: '', evidence: 'the CHANGELOG documents this behaviour' }
          : { verdict: 'PASS', missingFact: '', evidence: 'fine' },
      history: {
        fixed: 'YES',
        complete: true,
        reference: '#412',
        searched: 'git log -p -- auth.py, CHANGELOG',
        evidence: 'the caller now HMACs both operands',
      },
    }),
  })
  assert.ok(calls.some((c) => c.label === 'history'), 'the mechanism it defers to must actually run')
  assert.equal(result.status, 'ALREADY_FIXED')
  assert.match(result.reason, /#412/, 'and its answer is the one the user gets, with the reference')
})

// Same shape on brocard 4, where the specialised mechanism is the recovery check
// and the impact stage. `inflated-impact`'s grader says in terms that the panic
// is REAL and must not be dismissed — only its impact corrected — so "no
// vulnerability from standard behavior" is the one answer the case forbids, and
// it is what the pre-gate returned on 2 of 3 runs.
test('a brocard 4 DISMISS still reaches the impact agent and the severity cap', async () => {
  const { result, calls } = await runScript('triage-static.js', {
    args: WIRING_ARGS,
    agents: agents({
      brocard: (prompt) =>
        prompt.includes('Brocard 4')
          ? { verdict: 'DISMISS', missingFact: '', evidence: 'net/http recovers this by design' }
          : { verdict: 'PASS', missingFact: '', evidence: 'fine' },
    }),
  })
  const impact = calls.find((c) => c.label === 'impact')
  assert.ok(impact, 'the impact stage is the mechanism brocard 4 defers to')
  assert.match(impact.prompt, /net\/http recovers this by design/, 'and it is told what was dismissed')
  assert.equal(result.severity, 'Medium', 'the cap runs, which is the whole point of not stopping short')
  // Never a confirmation while the dismissal stands: it is enforced in code at
  // decideVerdict, so the deferral cannot turn a DISMISSED into a TRUE_POSITIVE.
  assert.equal(result.status, 'NEEDS_MORE_INFO')
  assert.match(result.reason, /net\/http recovers this by design/)
})

test('a deferred dismissal reaches the gate agent as the argument against the finding', async () => {
  const { calls } = await runScript('triage-static.js', {
    args: WIRING_ARGS,
    agents: agents({
      brocard: (prompt) =>
        prompt.includes('Brocard 5')
          ? { verdict: 'DISMISS', missingFact: '', evidence: 'documented in README.md' }
          : { verdict: 'PASS', missingFact: '', evidence: 'fine' },
    }),
  })
  const gates = calls.find((c) => c.label === 'gates')
  assert.ok(gates, 'the gate agent must be dispatched')
  assert.match(gates.prompt, /documented in README\.md/)
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
      'api-contract': proof('PASSES', 'no built-in bound'),
      'math-bounds': proof('PASSES', 'the product is unbounded'),
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
      'api-contract': proof('PASSES', 'no built-in bound'),
      'math-bounds': proof('BLOCKS', 'qty >= 1 and rate >= 0 make the product non-negative'),
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
      'api-contract': proof('PASSES', 'no built-in bound'),
      'math-bounds': proof('BLOCKS', 'MIN >= sizeof(hdr) so the subtraction cannot underflow'),
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
// the question it was asked, truthfully, with BLOCKS.
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

test('an inapplicable proof reporting BLOCKS does not block either', async () => {
  const { result } = await runScript('triage-static.js', {
    args: { ...WIRING_ARGS, route: 'deep' },
    agents: agents({
      'api-contract': proof('UNCERTAIN', 'no relevant API contract', false),
      'math-bounds': proof('UNCERTAIN', 'not a bounds finding', false),
      // The exact shape that cost `integration-cap` its points: a proof asked a
      // question the finding never posed, answering it accurately, in the enum
      // position that means "this finding is impossible".
      'race-feasibility': proof('BLOCKS', 'this is not a concurrency finding at all', false),
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
// decided beats one that died" — was worth having only while a single BLOCKS
// could end the stage. Now it cannot, so a dead sibling means the escalation the
// deep route was paid for did not happen, and BLOCKED is the honest answer.
// What must not happen is the live proof's finding being thrown away, so it is
// still on the payload for whoever re-dispatches.
test('a dead sibling proof blocks even when another proof decided, and the decision survives', async () => {
  const { result } = await runScript('triage-static.js', {
    args: { ...WIRING_ARGS, route: 'deep' },
    agents: agents({
      'math-bounds': proof('BLOCKS', 'qty >= 1 and rate >= 0 make the product non-negative'),
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
