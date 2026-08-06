/**
 * Layer 2b: the call sites, not the helpers.
 *
 * `gate.test.mjs`, `build.test.mjs` and `review.test.mjs` test each pure helper
 * in isolation. That leaves the wiring untested, and a review demonstrated how
 * much that hides: disabling twelve separate call sites — the
 * `gate.status !== 'PROCEED'` halt, the `impact.result !== 'VERIFIED'` halt,
 * `isAcceptableBuild`, `alreadyFixedStands`, the band check, the severity cap —
 * left every existing test green. The helpers were covered; none was covered
 * where it is used, so twenty assertions about `decideGate` could not tell you
 * whether `decideGate`'s answer was acted on.
 *
 * These run the real script bodies against scripted agent responses and assert
 * on the status that comes back.
 */

import assert from 'node:assert/strict'
import { test } from 'node:test'

import { runScript } from './extract.mjs'

const BASE = '/plugin/skills/fp-check'

// ------------------------------------------------------------ triage-static

const VERIFY_ARGS = {
  baseDir: BASE,
  finding: {
    summary: 'negative amount reverses a transfer',
    sink: 'ledger.py:12',
    component: 'ledger',
    claimedImpact: 'attacker drains an account',
    bugClass: 'logic error',
    threatModel: 'an authenticated caller of POST /transfer moves a negative amount',
  },
  entryPoint: { description: 'POST /transfer', location: 'api.py:8', payload: '-500' },
  layers: [{ name: 'amount-check', location: 'ledger.py:9', checks: 'sender has funds' }],
  scope: 'the ledger module',
}

const PASSING_LAYER = { verdict: 'PASSES', evidence: 'quoted code' }
const BROCARD_PASS = { verdict: 'PASS', missingFact: '', evidence: 'the capability is lower than the impact' }
const UNFIXED = {
  fixed: 'NO',
  reference: '',
  searched: 'git log -p -- ledger.py, issues, CHANGELOG',
  evidence: 'nothing found',
}
const ALL_GATES_PASS = {
  gateProcess: 'PASS',
  gateReachability: 'PASS',
  gateRealImpact: 'PASS',
  gatePocValidation: 'PASS',
  gateMathBounds: 'N/A',
  gateEnvironment: 'PASS',
  unresolvedUncertainty: '',
  verdictReason: 'a negative amount reaches ledger.debit unvalidated and credits the sender',
  evidence: 'ledger.py:12 with the trace above',
}
const RECOVERY = { recoveryExists: false, effectiveImpact: 'balance corrupted', evidence: 'no recover' }
const IN_SCOPE = { inScope: 'YES', byDesign: false, byDesignIndicators: 0, evidence: 'in scope' }
const VERIFIED = {
  result: 'VERIFIED',
  impact: 'drains an account',
  rootCause: 'internal',
  classification: 'vulnerability',
  severity: 'High',
  severityRationale: 'unauthenticated, no recovery, full balance control',
  evidence: 'ran it',
}

// Keyed by the label PREFIX where labels are per-item: runScript falls back to
// `agents[label.split(':')[0]]`, so one `brocard` entry answers all four and one
// `layer` entry answers every layer agent.
const verifyAgents = (over = {}) => ({
  brocard: BROCARD_PASS,
  layer: PASSING_LAYER,
  recovery: RECOVERY,
  'threat-model': IN_SCOPE,
  history: UNFIXED,
  impact: VERIFIED,
  gates: ALL_GATES_PASS,
  ...over,
})

test('the happy path reaches TRUE_POSITIVE through the impact and gate agents', async () => {
  const { result, calls } = await runScript('triage-static.js', {
    args: VERIFY_ARGS,
    agents: verifyAgents(),
  })
  assert.equal(result.status, 'TRUE_POSITIVE')
  assert.ok(calls.some((c) => c.label === 'impact'), 'checkpoint 2.4 must actually run')
  assert.ok(calls.some((c) => c.label === 'gates'), 'the six-gate review must actually run')
  assert.equal(result.severity, 'High', 'an internal root cause is not capped')
})

test('a BLOCKS verdict halts before the impact agent is ever spent', async () => {
  const { result, calls } = await runScript('triage-static.js', {
    args: VERIFY_ARGS,
    agents: verifyAgents({ layer: { verdict: 'BLOCKS', evidence: 'rejects negatives' } }),
  })
  assert.equal(result.status, 'NOT_EXPLOITABLE')
  assert.ok(
    !calls.some((c) => c.label === 'impact'),
    'a blocked path must not pay for checkpoint 2.4',
  )
})

test('an UNCERTAIN verdict needs more info: the gate decision is acted on', async () => {
  const { result } = await runScript('triage-static.js', {
    args: VERIFY_ARGS,
    agents: verifyAgents({ layer: { verdict: 'UNCERTAIN', evidence: 'could not trace' } }),
  })
  assert.equal(result.status, 'NEEDS_MORE_INFO')
})

test('a dead layer agent blocks rather than proceeding', async () => {
  const { result } = await runScript('triage-static.js', {
    args: VERIFY_ARGS,
    agents: verifyAgents({ layer: null }),
  })
  assert.equal(result.status, 'BLOCKED')
  assert.match(result.reason, /returned nothing/)
})

test('a dead recovery agent blocks: checkpoint 2.3 is not skipped', async () => {
  const { result } = await runScript('triage-static.js', {
    args: VERIFY_ARGS,
    agents: verifyAgents({ recovery: null }),
  })
  assert.equal(result.status, 'BLOCKED')
  assert.match(result.reason, /recovery/)
})

test('an out-of-scope threat verdict halts', async () => {
  const { result } = await runScript('triage-static.js', {
    args: VERIFY_ARGS,
    agents: verifyAgents({ 'threat-model': { inScope: 'NO', byDesign: false, evidence: 'infra' } }),
  })
  assert.equal(result.status, 'OUT_OF_SCOPE')
})

// The results of the one parallel() call used to be disaggregated by SHAPE —
// `.filter(Boolean)` and then `results.find((r) => r.inScope)` — over an array
// whose positions had already been destroyed. The recovery thunk precedes the
// threat thunk, so a recovery agent volunteering an incidental `inScope` key won
// the lookup, the real OUT_OF_SCOPE verdict was silently discarded, and this
// exact input returned PROCEED. Only `additionalProperties: false` stood between
// that and a shipped false positive, and deleting it from all four schemas left
// the whole free suite green, so nothing pinned the guard.
//
// The fix slices positionally out of the UNFILTERED parallel() array. This
// grades that: the threat agent's verdict must win regardless of what any other
// agent volunteers.
test('a recovery agent volunteering inScope cannot displace the threat verdict', async () => {
  const { result } = await runScript('triage-static.js', {
    args: VERIFY_ARGS,
    agents: verifyAgents({
      recovery: { ...RECOVERY, inScope: 'YES' },
      'threat-model': { inScope: 'NO', byDesign: false, byDesignIndicators: 0, evidence: 'infra' },
    }),
  })
  assert.equal(result.status, 'OUT_OF_SCOPE', 'the threat agent decides 3.1, not whoever answers first')
  assert.equal(result.threat.inScope, 'NO', 'the recovery result must not be reported as the threat verdict')
  assert.equal(result.recovery.recoveryExists, false, 'and recovery must still be the recovery result')
})

// The mirror image: a threat agent volunteering a `verdict` key used to be
// counted as a sixth layer verdict, which drove `missing` negative in decideGate.
test('a threat agent volunteering a verdict key is not counted as a layer', async () => {
  const { result } = await runScript('triage-static.js', {
    args: VERIFY_ARGS,
    agents: verifyAgents({ 'threat-model': { ...IN_SCOPE, verdict: 'PASSES' } }),
  })
  assert.equal(result.status, 'TRUE_POSITIVE')
  assert.equal(result.layers.length, 1, 'exactly one layer agent was dispatched')
})

test('by-design halts as NOT_VULNERABLE', async () => {
  const { result } = await runScript('triage-static.js', {
    args: VERIFY_ARGS,
    agents: verifyAgents({
      'threat-model': { inScope: 'YES', byDesign: true, evidence: 'documented escape hatch' },
    }),
  })
  assert.equal(result.status, 'NOT_VULNERABLE')
})

test('NOT_VERIFIED does not reach a positive verdict', async () => {
  // The gate reads `!== 'VERIFIED'`; a two-way check on a three-value enum let
  // NOT_VERIFIED fall through to a verdict, logged as "Verified impact".
  //
  // The two failing values do NOT collapse to one status, and that is deliberate.
  // DISPROVEN is positive evidence that there is no impact — a false positive.
  // NOT_VERIFIED is the absence of evidence either way, which is the conflation
  // that killed a real finding: the impact agent performed the downgrade it was
  // asked for, returned NOT_VERIFIED because the claim AS STATED did not hold,
  // and the run reported a demonstrable bug as not exploitable.
  for (const [bad, status] of [
    ['NOT_VERIFIED', 'NEEDS_MORE_INFO'],
    ['DISPROVEN', 'NOT_EXPLOITABLE'],
  ]) {
    const { result } = await runScript('triage-static.js', {
      args: VERIFY_ARGS,
      agents: verifyAgents({ impact: { ...VERIFIED, result: bad } }),
    })
    assert.equal(result.status, status, `${bad} must not reach a positive verdict`)
  }
})

// IMPACT_SCHEMA requires `evidence`, and JSON Schema `required` checks presence
// rather than content: `evidence: ''` validates. The 2.4 branch relayed it
// verbatim, so SKILL.md's failure protocol rendered as "Reason:" with nothing
// after it — a halt the orchestrator cannot explain to the user. decideGate's
// two agent-sourced reasons already had a `why()` fallback; this sibling did not.
test('an empty-evidence NOT_VERIFIED still explains itself', async () => {
  for (const evidence of ['', '   ']) {
    const { result } = await runScript('triage-static.js', {
      args: VERIFY_ARGS,
      agents: verifyAgents({ impact: { ...VERIFIED, result: 'NOT_VERIFIED', evidence } }),
    })
    assert.equal(result.status, 'NEEDS_MORE_INFO')
    assert.ok(
      result.reason && result.reason.trim(),
      `evidence ${JSON.stringify(evidence)} produced a halt with no reason`,
    )
    assert.match(result.reason, /NOT_VERIFIED/)
  }
})

test('a real evidence string is relayed rather than replaced by the fallback', async () => {
  const { result } = await runScript('triage-static.js', {
    args: VERIFY_ARGS,
    agents: verifyAgents({
      impact: { ...VERIFIED, result: 'DISPROVEN', evidence: 'the sink coerces to unsigned first' },
    }),
  })
  assert.equal(result.reason, 'the sink coerces to unsigned first')
})

test('an integration root cause with no precondition needs more info at 2.4b', async () => {
  const { result } = await runScript('triage-static.js', {
    args: VERIFY_ARGS,
    agents: verifyAgents({ impact: { ...VERIFIED, rootCause: 'integration' } }),
  })
  assert.equal(result.status, 'NEEDS_MORE_INFO')
  assert.match(result.reason, /external precondition/)
})

test('an integration root cause WITH a precondition proceeds', async () => {
  const { result } = await runScript('triage-static.js', {
    args: VERIFY_ARGS,
    agents: verifyAgents({
      impact: {
        ...VERIFIED,
        rootCause: 'integration',
        externalPrecondition: 'the upstream API returns a negative length',
      },
    }),
  })
  assert.equal(result.status, 'TRUE_POSITIVE')
  // And the cap fires: an integration root cause cannot carry the High the
  // impact agent asked for. This is one of the two mechanisms the head-to-head
  // attributed its delta to, so it is asserted where it is USED, not only in
  // capSeverity's unit tests.
  assert.equal(result.severity, 'Medium')
  assert.match(result.severityCorrection, /integration/)
})

test('a bad arg shape returns BLOCKED without spending an agent', async () => {
  const { result, calls } = await runScript('triage-static.js', {
    args: { ...VERIFY_ARGS, layers: [] },
    agents: verifyAgents(),
  })
  assert.equal(result.status, 'BLOCKED')
  assert.equal(calls.length, 0, 'the arg gate must reject before any fan-out')
})

test('no more layer agents are dispatched than the cap allows', async () => {
  const four = Array.from({ length: 4 }, (_, i) => ({ name: `l${i}`, location: `a.py:${i}` }))
  const { calls } = await runScript('triage-static.js', {
    args: { ...VERIFY_ARGS, layers: four },
    agents: verifyAgents(),
  })
  const layerCalls = calls.filter((c) => c.label.startsWith('layer:'))
  assert.equal(layerCalls.length, 4)
})

// --------------------------------------------------------------- triage-poc
//
// Build and review are one script, so a test that scripts only the builder runs
// on into the challenges and the report. Every fixture here therefore supplies
// the whole chain, and the build-phase assertions are about which agents were
// dispatched rather than about the status the build alone produced.

const BUILD_ARGS = {
  baseDir: BASE,
  finding: { summary: 'negative amount reverses a transfer', sink: 'ledger.py:12' },
  verification: {
    status: 'TRUE_POSITIVE',
    impact: { impact: 'drains', rootCause: 'internal', classification: 'vulnerability' },
    severity: 'High',
    history: { fixed: 'NO', searched: 'git log -p -- ledger.py, issues' },
  },
  envelope: { hosts: [], level: 1, destructive: false },
  candidates: [
    { name: 'a', description: 'direct call', entryPoint: 'transfer', payload: '-500' },
    { name: 'b', description: 'via api', entryPoint: 'api', payload: '-500' },
  ],
}

const BUILT_POC = {
  built: true,
  executed: true,
  lintPassed: true,
  pocType: 'standalone',
  path: 'poc/x.py',
  absolutePath: '/wt/poc/x.py',
  command: 'python3 /wt/poc/x.py',
  output: 'AssertionError: alice went negative',
  invokedSymbol: 'ledger.transfer',
}

test('an acceptable build stops retrying and goes straight to the reviewers', async () => {
  const { result, calls } = await runScript('triage-poc.js', {
    args: BUILD_ARGS,
    agents: reviewAgents(),
  })
  assert.equal(result.status, 'REPORTED')
  assert.equal(
    calls.filter((c) => c.label.startsWith('build:')).length,
    1,
    'a successful first attempt must not retry',
  )
  assert.ok(calls.some((c) => c.label === 'artifact-check'))
})

test('a build that failed lint is retried, not accepted', async () => {
  let attempt = 0
  const { result, calls } = await runScript('triage-poc.js', {
    args: BUILD_ARGS,
    agents: reviewAgents({
      build: () => (attempt++ === 0 ? { ...BUILT_POC, lintPassed: false } : BUILT_POC),
    }),
  })
  assert.equal(result.status, 'REPORTED')
  assert.equal(
    calls.filter((c) => c.label.startsWith('build:')).length,
    2,
    'the first attempt must be rejected and retried',
  )
})

test('every attempt failing returns BUILD_FAILED, bounded by the cap', async () => {
  const { result, calls } = await runScript('triage-poc.js', {
    args: BUILD_ARGS,
    agents: { build: { ...BUILT_POC, built: false, failureReason: 'no path' } },
  })
  assert.equal(result.status, 'BUILD_FAILED')
  assert.equal(calls.length, 2, 'MAX_ATTEMPTS bounds the retry loop')
})

// POC_SCHEMA requires these four, and `required` checks presence, not content:
// `output: '   '` is schema-valid. Bare truthiness accepted it, so a builder
// reporting whitespace returned BUILT and that whitespace reached all five
// challenge prompts as the "Captured output" the reviewers judge — and reached
// review-poc's lint command as `--symbol '  '`.
test('a whitespace-only build is rejected, not reported as BUILT', async () => {
  for (const field of ['absolutePath', 'command', 'output', 'invokedSymbol']) {
    const { result } = await runScript('triage-poc.js', {
      args: BUILD_ARGS,
      agents: { build: { ...BUILT_POC, [field]: '   ' } },
    })
    assert.equal(result.status, 'BUILD_FAILED', `whitespace ${field} must not pass the gate`)
    assert.ok(result.reason && result.reason.trim())
  }
})

test('no candidates returns NO_CANDIDATES without throwing', async () => {
  const { result, calls } = await runScript('triage-poc.js', {
    args: { ...BUILD_ARGS, candidates: [] },
    agents: { build: BUILT_POC },
  })
  assert.equal(result.status, 'NO_CANDIDATES')
  assert.equal(calls.length, 0)
})

test('a forwarded failed verification never reaches the builder', async () => {
  const { result, calls } = await runScript('triage-poc.js', {
    args: { ...BUILD_ARGS, verification: { ...BUILD_ARGS.verification, status: 'NOT_EXPLOITABLE' } },
    agents: { build: BUILT_POC },
  })
  assert.equal(result.status, 'BLOCKED')
  assert.equal(calls.length, 0)
})

test('a destructive envelope above level 2 never reaches the builder', async () => {
  const { result, calls } = await runScript('triage-poc.js', {
    args: { ...BUILD_ARGS, envelope: { hosts: [], level: 4, destructive: true } },
    agents: { build: BUILT_POC },
  })
  assert.equal(result.status, 'BLOCKED')
  assert.equal(calls.length, 0, 'the safety contradiction must be caught before an agent runs')
})

// ------------------------------------------------- triage-poc, review half

const CLEAN_ARTIFACT = { fileExists: true, lintExitZero: true, reRunSucceeded: true, evidence: 'ok' }
const rebutted = (key) => ({ challenge: `c:${key}`, rebuttal: 'r', winner: 'REBUTTAL', evidence: 'e' })
const REPORT = {
  severity: 'High',
  severityRationale: 'internal root cause',
  reportPath: '/wt/poc/finding.md',
  unproven: 'no network route was exercised',
}

// The build is scripted too: the reviewers judge whatever the builder returned,
// and BUILT_POC is what supplies the absolutePath and invokedSymbol the artifact
// prompt interpolates. When these were two workflows a `poc` arg stood in for it,
// and that fixture could — and did — carry fields no builder had produced.
const reviewAgents = (over = {}) => ({
  build: BUILT_POC,
  'artifact-check': CLEAN_ARTIFACT,
  challenge: (prompt) => rebutted(prompt.slice(0, 8)),
  report: REPORT,
  ...over,
})

test('five rebuttals and a clean artifact returns REPORTED at HIGH', async () => {
  const { result } = await runScript('triage-poc.js', {
    args: BUILD_ARGS,
    agents: reviewAgents(),
  })
  assert.equal(result.status, 'REPORTED')
  assert.equal(result.band.label, 'HIGH')
})

// Principle 5 — "call real code, never reimplement" — is re-checked exactly
// once by someone who did not build the PoC, and only by poc-lint's --symbol
// rule. Deleting the whole `--symbol '...'` argument from the prompt left 121
// node and 65 pytest assertions green, so nothing covered the one command that
// makes the independent reviewer independent.
test('the artifact prompt re-runs poc-lint with the real symbol', async () => {
  const { calls } = await runScript('triage-poc.js', {
    args: BUILD_ARGS,
    agents: reviewAgents(),
  })
  const artifact = calls.find((c) => c.label === 'artifact-check')
  assert.ok(artifact, 'the artifact check must be dispatched')
  assert.ok(
    artifact.prompt.includes(`--symbol '${BUILT_POC.invokedSymbol}'`),
    `the Principle 5 re-check is missing its symbol; prompt said: ${
      artifact.prompt.split('\n').find((l) => l.includes('poc-lint.sh'))
    }`,
  )
  assert.ok(
    artifact.prompt.includes(`'${BUILT_POC.absolutePath}'`),
    'and it must lint the file the builder actually wrote',
  )
})

// poc-lint.sh exits 2 on an empty --symbol rather than skipping the real-code
// check silently, so a PoC without the field does not weaken the review — it
// breaks it, and returns a BLOCKED that blames the builder's lintPassed claim.
// The build gate is what stops it: a builder that omits invokedSymbol never
// produces a PoC, so no reviewer is ever spent on one.
test('a build with no invokedSymbol never reaches a reviewer', async () => {
  for (const bad of [undefined, '', '   ']) {
    const { result, calls } = await runScript('triage-poc.js', {
      args: BUILD_ARGS,
      agents: reviewAgents({ build: { ...BUILT_POC, invokedSymbol: bad } }),
    })
    assert.equal(result.status, 'BUILD_FAILED', `invokedSymbol ${JSON.stringify(bad)} must fail the gate`)
    assert.ok(
      !calls.some((c) => c.label === 'artifact-check'),
      'no reviewer may be spent on a PoC that cannot be lint-checked',
    )
  }
})

test('a lint failure found by the reviewer blocks, whatever the builder said', async () => {
  const { result, calls } = await runScript('triage-poc.js', {
    args: BUILD_ARGS,
    agents: reviewAgents({
      'artifact-check': { ...CLEAN_ARTIFACT, lintExitZero: false, lintOutput: 'stub-body' },
    }),
  })
  assert.equal(result.status, 'BLOCKED')
  assert.match(result.reason, /poc-lint/)
  assert.ok(!calls.some((c) => c.label === 'report'), 'no report for an unverified artifact')
})

test('a missing PoC file blocks', async () => {
  const { result } = await runScript('triage-poc.js', {
    args: BUILD_ARGS,
    agents: reviewAgents({ 'artifact-check': { ...CLEAN_ARTIFACT, fileExists: false } }),
  })
  assert.equal(result.status, 'BLOCKED')
})

test('a lost already-fixed challenge overrides the band', async () => {
  const { result, calls } = await runScript('triage-poc.js', {
    args: BUILD_ARGS,
    agents: reviewAgents({
      challenge: (prompt) =>
        prompt.includes('ALREADY FIXED')
          ? { challenge: 'patched in 1.2', rebuttal: 'none', winner: 'CHALLENGE', evidence: 'commit abc' }
          : rebutted('x'),
    }),
  })
  assert.equal(result.status, 'DO_NOT_SUBMIT')
  assert.match(result.reason, /already-fixed/)
  assert.ok(!calls.some((c) => c.label === 'report'), 'a patched bug is not written up')
})

test('a dead challenge-4 agent also overrides the band', async () => {
  const { result } = await runScript('triage-poc.js', {
    args: BUILD_ARGS,
    agents: reviewAgents({
      challenge: (prompt) => (prompt.includes('ALREADY FIXED') ? null : rebutted('x')),
    }),
  })
  assert.equal(result.status, 'DO_NOT_SUBMIT')
})

test('LOW confidence does not proceed to a report', async () => {
  const { result, calls } = await runScript('triage-poc.js', {
    args: BUILD_ARGS,
    agents: reviewAgents({
      challenge: (prompt) =>
        prompt.includes('ALREADY FIXED')
          ? rebutted('fixed')
          : { challenge: 'c', rebuttal: 'none', winner: 'CHALLENGE', evidence: 'e' },
    }),
  })
  // already-fixed is rebutted so the unconditional rule does not fire; the four
  // others are lost, so 1/5 defeated lands in LOW and the band alone stops it.
  assert.equal(result.status, 'DO_NOT_SUBMIT')
  assert.equal(result.band.label, 'LOW')
  assert.equal(result.defeated, 1)
  assert.ok(!calls.some((c) => c.label === 'report'))
})

test('a severity above the cap for an integration root cause blocks the report', async () => {
  const { result } = await runScript('triage-poc.js', {
    args: {
      ...BUILD_ARGS,
      verification: {
        ...BUILD_ARGS.verification,
        impact: { impact: 'drains', rootCause: 'integration', classification: 'vulnerability' },
      },
    },
    agents: reviewAgents({ report: { ...REPORT, severity: 'Critical' } }),
  })
  assert.equal(result.status, 'BLOCKED')
  assert.match(result.reason, /Medium cap/)
})

test('an empty unproven field fails checkpoint 6.1', async () => {
  const { result } = await runScript('triage-poc.js', {
    args: BUILD_ARGS,
    agents: reviewAgents({ report: { ...REPORT, unproven: '   ' } }),
  })
  assert.equal(result.status, 'DO_NOT_SUBMIT')
  assert.match(result.reason, /unproven/)
})

// The prompt says "reportPath must be a file you actually wrote, not a path you
// intend to use", and a prompt is a request the model may decline. Nothing gated
// the content: `reportPath: ''` returned REPORTED with no report to point at,
// and the 5.2 block message below rendered as "The report at  carries a
// severity...".
test('an empty reportPath fails checkpoint 6.1', async () => {
  for (const reportPath of ['', '   ']) {
    const { result } = await runScript('triage-poc.js', {
      args: BUILD_ARGS,
      agents: reviewAgents({ report: { ...REPORT, reportPath } }),
    })
    assert.equal(result.status, 'DO_NOT_SUBMIT', `reportPath ${JSON.stringify(reportPath)} must not pass`)
    assert.ok(result.reason && result.reason.trim(), 'a halt must explain itself')
    assert.match(result.reason, /reportPath/)
  }
})

// The severity cap message interpolates report.reportPath, so 6.1 has to run
// first — otherwise the block that tells the user where to correct the severity
// names no file.
test('an empty reportPath is caught before the severity cap names it', async () => {
  const { result } = await runScript('triage-poc.js', {
    args: {
      ...BUILD_ARGS,
      verification: {
        ...BUILD_ARGS.verification,
        impact: { impact: 'drains', rootCause: 'integration', classification: 'vulnerability' },
      },
    },
    agents: reviewAgents({ report: { ...REPORT, severity: 'Critical', reportPath: '' } }),
  })
  assert.equal(result.status, 'DO_NOT_SUBMIT')
  assert.doesNotMatch(result.reason, /The report at\s{2}/)
})

test('a blank severityRationale fails checkpoint 5.2', async () => {
  // Checkpoint 5.2 passes on "the rating is supported by evidence". unproven and
  // reportPath were both trimmed on that reasoning and this one was not, so a
  // Medium asserted with nothing behind it returned REPORTED — and the severity
  // cap below only inspects Critical and High, so nothing else looked.
  for (const severityRationale of ['', '   ']) {
    const { result } = await runScript('triage-poc.js', {
      args: BUILD_ARGS,
      agents: reviewAgents({ report: { ...REPORT, severity: 'Medium', severityRationale } }),
    })
    assert.equal(result.status, 'DO_NOT_SUBMIT')
    assert.match(result.reason, /severityRationale/)
  }
})

// The report prompt was the one stage nothing asserted on. Four separate
// mutations to it — emptying `corrections`, hardcoding the re-run status, and
// deleting either caveat — left the whole suite green. `impactCorrection` is
// the worst of them: it is the channel by which a reviewer's "the true impact
// is weaker than claimed" reaches the report, which is the inflated-impact
// failure this skill exists to prevent.
const reportPrompt = async (over) => {
  const { calls } = await runScript('triage-poc.js', { args: BUILD_ARGS, agents: reviewAgents(over) })
  const call = calls.find((c) => c.label === 'report')
  assert.ok(call, 'the report agent must be dispatched')
  return call.prompt
}

test("a reviewer's impact correction reaches the report agent", async () => {
  const prompt = await reportPrompt({
    challenge: (p) => ({
      ...rebutted(p.slice(0, 8)),
      impactCorrection: p.includes('Challenge 2') ? 'recovery caps this at one 500' : undefined,
    }),
  })
  assert.match(prompt, /recovery caps this at one 500/)
})

test('a re-run the reviewer could not reproduce is stated, not glossed', async () => {
  const failed = { ...CLEAN_ARTIFACT, reRunSucceeded: false, reRunNotes: 'no ES cluster here' }
  const prompt = await reportPrompt({ 'artifact-check': failed })
  assert.match(prompt, /no ES cluster here/)
  assert.match(prompt, /unproven/)

  // And the passing case must not claim the boundary exists.
  assert.doesNotMatch(await reportPrompt({}), /did not reproduce for an independent reviewer/)
})

test('MEDIUM confidence tells the report to document the uncertainties', async () => {
  // Three of five defeated is MEDIUM, which proceeds only with the uncertainties
  // written down. Deleting that instruction changed no assertion.
  const prompt = await reportPrompt({
    challenge: (p) =>
      /Challenge (1|5)\./.test(p)
        ? { challenge: 'unrebutted', rebuttal: 'none', winner: 'CHALLENGE', evidence: 'e' }
        : rebutted(p.slice(0, 8)),
  })
  assert.match(prompt, /Confidence is MEDIUM/)
  assert.match(prompt, /False Positive Analysis section must document the uncertainties/)
})

// ------------------------------------------------------- the dispatch contract

test('a workflow dispatched with no args at all returns BLOCKED, not a TypeError', async () => {
  // The top-of-script destructure ran before missingArgs, so `args` undefined —
  // a mistyped `arg:`, or an omitted block — killed the run with
  // "Cannot destructure property 'baseDir'" and no status came back at all.
  // Every `a && a.finding` guard inside the validators exists for this input
  // and none of them was reachable.
  for (const file of ['triage-static.js', 'triage-poc.js', 'triage-poc.js']) {
    for (const args of [undefined, null]) {
      const { result, calls } = await runScript(file, { args })
      assert.equal(result.status, 'BLOCKED', `${file} with args=${args}`)
      assert.ok(result.reason && result.reason.trim(), `${file} must say why`)
      assert.equal(calls.length, 0, `${file} must not spend an agent`)
    }
  }
})
