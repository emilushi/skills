import assert from 'node:assert/strict'
import { test } from 'node:test'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { loadFn, loadFns, script } from './extract.mjs'

const STATIC = script('triage-static.js')
// decideGate calls upstreamFixStands, so the two are extracted into one scope.
// Evaluating decideGate alone made every call a ReferenceError, and the
// alternative — inlining the fix check at both call sites — is the duplicated
// gate logic this suite exists to catch.
const { decideGate } = loadFns(STATIC, 'decideGate', 'upstreamFixStands')
const missingPrecondition = loadFn(STATIC, 'missingPrecondition')

const layer = (name, verdict) => ({ layer: name, location: `${name}.go:10`, verdict })
const inScope = { inScope: 'YES', byDesign: false, evidence: 'in scope' }
const checked = { recoveryExists: false, effectiveImpact: 'process exits', evidence: 'no recover in the stack' }
// The already-fixed search ran and found nothing, which is the case every
// pre-existing assertion here was written under. `unfixed` is deliberately not
// a default parameter in decideGate: a caller that forgets it must fail, not
// silently assert that nothing was ever fixed.
const unfixed = { fixed: 'NO', reference: '', searched: 'git log -p, issues, CHANGELOG', evidence: 'nothing found' }

test('extract helper fails loudly when the function is absent', () => {
  assert.throws(() => loadFn(STATIC, 'noSuchFunction'), /not found/)
})

// `^function` is matched with the `m` flag, and `.match()` returns the EARLIEST
// hit. A commented-out copy of a helper therefore shadowed the real definition
// and these tests graded the comment: breaking confidenceBand to always return
// HIGH, with a correct copy left in a `/* ... */` above it, kept all 32
// assertions in review.test.mjs green.
test('a commented-out copy does not shadow the real definition', () => {
  const dir = mkdtempSync(join(tmpdir(), 'cp-extract-'))
  const file = join(dir, 'shadow.js')
  writeFileSync(
    file,
    [
      '/* The correct version, kept for reference:',
      'function pick(n) {',
      "  return 'REAL'",
      '}',
      '*/',
      'function pick(n) {',
      "  return 'BROKEN'",
      '}',
      '',
    ].join('\n'),
  )
  assert.equal(loadFn(file, 'pick')(1), 'BROKEN', 'must extract the live definition, not the comment')
  rmSync(dir, { recursive: true, force: true })
})

test('two live definitions are a hard stop, not a first-wins guess', () => {
  const dir = mkdtempSync(join(tmpdir(), 'cp-extract-'))
  const file = join(dir, 'dup.js')
  writeFileSync(file, "function pick(n) {\n  return 'A'\n}\nfunction pick(n) {\n  return 'B'\n}\n")
  assert.throws(() => loadFn(file, 'pick'), /defined 2 times/)
  rmSync(dir, { recursive: true, force: true })
})

test('all layers passable and threat model clear proceeds', () => {
  const r = decideGate([layer('auth', 'PASSES'), layer('bounds', 'PASSES')], checked, inScope, unfixed, 2, 0)
  assert.equal(r.status, 'PROCEED')
})

test('a blocking layer is NOT_EXPLOITABLE and names where', () => {
  const r = decideGate([layer('auth', 'PASSES'), layer('validate', 'BLOCKS')], checked, inScope, unfixed, 2, 0)
  assert.equal(r.status, 'NOT_EXPLOITABLE')
  assert.match(r.reason, /validate/)
})

test('BLOCKS wins over UNCERTAIN — the stronger verdict decides', () => {
  const r = decideGate([layer('a', 'UNCERTAIN'), layer('b', 'BLOCKS')], checked, inScope, unfixed, 2, 0)
  assert.equal(r.status, 'NOT_EXPLOITABLE')
})

// NEEDS_MORE_INFO, not BLOCKED. BLOCKED means the analysis could not be RUN —
// a contract violation, a dead agent — and NEEDS_MORE_INFO means it ran and the
// evidence does not decide. An UNCERTAIN layer is the second: the code was read
// and could not be traced. Calling that BLOCKED sends the reader to the harness
// instead of to the code.
test('any UNCERTAIN layer needs more info: checkpoint 2.2 requires zero', () => {
  const r = decideGate([layer('a', 'PASSES'), layer('b', 'UNCERTAIN')], checked, inScope, unfixed, 2, 0)
  assert.equal(r.status, 'NEEDS_MORE_INFO')
  assert.match(r.reason, /unresolved/)
})

// The gate reads PASSES rather than "not BLOCKS and not UNCERTAIN". Grading by
// exclusion made PROCEED the fall-through for any verdict the script does not
// recognise — on the checkpoint the phase map calls MOST CRITICAL, and the only
// gate in this pipeline that did not read the value it wanted.
test('a verdict outside the enum blocks rather than falling through to PROCEED', () => {
  for (const verdict of [undefined, '', 'passes', 'BANANA']) {
    const r = decideGate([{ layer: 'a', location: 'a.py:1', verdict }], checked, inScope, unfixed, 1)
    assert.equal(r.status, 'BLOCKED', `verdict ${JSON.stringify(verdict)} must not PROCEED`)
    assert.match(r.reason, /no PASSES verdict/)
  }
})

// Same shape, on checkpoint 3.1, whose stated rule is "Ambiguous means
// UNCERTAIN, not YES". Testing only for NO and UNCERTAIN implemented the
// opposite: anything else became YES.
test('an inScope value outside the enum does not fall through to being read as YES', () => {
  for (const value of [undefined, '', 'yes', 'MAYBE']) {
    const threat = { inScope: value, byDesign: false, evidence: 'e' }
    const r = decideGate([layer('a', 'PASSES')], checked, threat, unfixed, 1)
    assert.equal(r.status, 'NEEDS_MORE_INFO', `inScope ${JSON.stringify(value)} must not PROCEED`)
  }
})

// The bug this function was extracted to expose. Before the refactor the gate
// filtered for BLOCKS and UNCERTAIN over an empty array, matched neither, and
// fell through to PROCEED — reporting success having verified nothing.
test('every layer agent dying BLOCKS rather than proceeding', () => {
  const r = decideGate([], checked, inScope, unfixed, 3, 0)
  assert.equal(r.status, 'BLOCKED')
  assert.match(r.reason, /returned nothing/)
})

test('a partial layer-agent failure blocks', () => {
  const r = decideGate([layer('a', 'PASSES')], checked, inScope, unfixed, 3, 0)
  assert.equal(r.status, 'BLOCKED')
  assert.match(r.reason, /2 layer agent/)
})

// The same bug class one level up, and the one the old assertion here got
// wrong. It read 2.2's "at least 1 layer (or confirmed none exist)" as licence
// to PROCEED on an empty list — but nothing confirms none exist when no agent
// ran. `layers` defaults to [] in the destructure, so a dispatch that simply
// omitted the field was indistinguishable from a deliberate claim, and both
// returned "attack path verified" having dispatched zero agents against the
// checkpoint the phase map marks MOST CRITICAL.
test('zero dispatched layers BLOCKS: 2.2 cannot pass on zero evidence', () => {
  const r = decideGate([], checked, inScope, unfixed, 0, 0)
  assert.equal(r.status, 'BLOCKED')
  assert.match(r.reason, /no validation layers were inspected/)
})

test('MORE verdicts than agents dispatched blocks rather than passing', () => {
  // The results of one parallel() call are disaggregated by shape, so a
  // recovery or threat agent that volunteered a `verdict` key would be counted
  // as a layer verdict. `missing` then goes NEGATIVE, and a `> 0` check reads
  // that as "no agent is missing" while a layer agent is genuinely absent.
  // additionalProperties: false makes it unreachable; this makes it fail loudly
  // if that ever comes off.
  const r = decideGate([layer('a', 'PASSES'), layer('b', 'PASSES')], checked, inScope, unfixed, 1, 0)
  assert.equal(r.status, 'BLOCKED')
  assert.match(r.reason, /mis-attributed/)
})

test('a dead recovery agent blocks: 2.3 requires recovery be checked, not assumed', () => {
  // "Checked for recovery (not assumed absent)" is the pass criterion. A null
  // from a dead agent used to fall through to the impact prompt as "not
  // established" and PROCEED — assuming absence by a different route.
  for (const dead of [undefined, null]) {
    const r = decideGate([layer('a', 'PASSES')], dead, inScope, unfixed, 1, 0)
    assert.equal(r.status, 'BLOCKED')
    assert.match(r.reason, /recovery/)
  }
})

test('a dead threat-model agent blocks rather than proceeding', () => {
  const r = decideGate([layer('a', 'PASSES')], checked, undefined, unfixed, 1, 0)
  assert.equal(r.status, 'BLOCKED')
  assert.match(r.reason, /threat-model/)
})

test('a blocking layer outranks a dead recovery agent', () => {
  // Ordering matters: NOT_EXPLOITABLE is the more informative answer, and it is
  // reached without needing the recovery verdict at all.
  const r = decideGate([layer('validate', 'BLOCKS')], undefined, inScope, unfixed, 1, 0)
  assert.equal(r.status, 'NOT_EXPLOITABLE')
})

test('out of scope halts', () => {
  const r = decideGate([layer('a', 'PASSES')], checked, { inScope: 'NO', evidence: 'infra' }, unfixed, 1, 0)
  assert.equal(r.status, 'OUT_OF_SCOPE')
})

test('ambiguous scope needs more info rather than assuming in-scope', () => {
  const r = decideGate([layer('a', 'PASSES')], checked, { inScope: 'UNCERTAIN', evidence: '?' }, unfixed, 1, 0)
  assert.equal(r.status, 'NEEDS_MORE_INFO')
})

test('by-design halts as NOT_VULNERABLE', () => {
  const threat = { inScope: 'YES', byDesign: true, evidence: 'admin escape hatch' }
  const r = decideGate([layer('a', 'PASSES')], checked, threat, unfixed, 1, 0)
  assert.equal(r.status, 'NOT_VULNERABLE')
})

// Every input shape below has a named test above pinning its EXACT status, so
// there is no separate "returns only known statuses" case: `equal(status,
// 'BLOCKED')` already implies membership. What those tests do not check is that
// a halt explains itself, which is what this asserts.
//
// The last two cases are the only ones that can actually fail it, and they were
// missing. Every other reason here is built from a string literal, so the loop
// could only catch a `reason` key deleted outright — which
// test_terminal_returns_carry_a_reason already catches statically, across all
// three scripts. OUT_OF_SCOPE and NOT_VULNERABLE both return
// `reason: threatVerdict.evidence`, straight from an agent, and THREAT_SCHEMA's
// `required` checks presence and not content: `evidence: ''` is schema-valid and
// yields `{status: 'OUT_OF_SCOPE', reason: ''}`. A halt with no explanation is
// what the orchestrator has to relay to the user.
test('every non-PROCEED status carries a non-empty reason', () => {
  const cases = [
    [[], checked, inScope, 0],
    [[], checked, inScope, 3],
    [[layer('a', 'BLOCKS')], checked, inScope, 1],
    [[layer('a', 'UNCERTAIN')], checked, inScope, 1],
    [[{ layer: 'a', location: 'a.py:1' }], checked, inScope, 1],
    [[layer('a', 'PASSES')], undefined, inScope, 1],
    [[layer('a', 'PASSES')], checked, undefined, 1],
    [[layer('a', 'PASSES')], checked, { inScope: 'UNCERTAIN' }, 1],
    [[layer('a', 'PASSES')], checked, { inScope: 'NO', byDesign: false, evidence: '' }, 1],
    [[layer('a', 'PASSES')], checked, { inScope: 'YES', byDesign: true, evidence: '' }, 1],
  ]
  for (const args of cases) {
    const r = decideGate(...args)
    assert.notEqual(r.status, 'PROCEED')
    assert.ok(r.reason && r.reason.trim(), `${r.status} came back with no reason`)
  }
})

// ------------------------------------------------- checkpoint 2.4b

// "If Integration or External ... the required external precondition is stated
// explicitly" is a pass criterion the JSON Schema cannot express, since it is
// conditional on another field. Unenforced, an integration finding reaches
// Phase 4 without the precondition that makes it exploitable ever being named.

test('an internal root cause needs no external precondition', () => {
  assert.equal(missingPrecondition({ rootCause: 'internal' }), false)
})

test('integration and external without a precondition are caught', () => {
  for (const rootCause of ['integration', 'external']) {
    assert.equal(missingPrecondition({ rootCause }), true, `${rootCause} must require one`)
    assert.equal(
      missingPrecondition({ rootCause, externalPrecondition: '   ' }),
      true,
      'whitespace is not a stated precondition',
    )
    assert.equal(
      missingPrecondition({ rootCause, externalPrecondition: 'the upstream API returns a negative length' }),
      false,
    )
  }
})

test('a dead impact agent does not throw the precondition check', () => {
  for (const dead of [null, undefined]) {
    assert.equal(missingPrecondition(dead), false, 'the VERIFIED gate handles a dead agent first')
  }
})
