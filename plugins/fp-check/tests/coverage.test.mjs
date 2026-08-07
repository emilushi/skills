/**
 * Layer 2c: capability coverage — is each parent plugin's mechanism REACHABLE?
 *
 * fp-check 2.1.0 is a merge of three plugins. `gate.test.mjs` proves each pure
 * helper computes the right answer; `wiring.test.mjs` proves the helper's answer
 * is acted on. Neither answers the question this file exists for: **for every
 * distinct verification mechanism the merge inherited, does some realistic
 * dispatch actually route to it and let it decide?**
 *
 * That is a different failure mode from a wrong answer. A gate can be present,
 * correct and covered, and still never fire — because an earlier gate always
 * decides first, or because nothing in the merged plugin dispatches to it at
 * all. A measured sweep of 18 runs found `upstreamFixStands`, `capSeverity`,
 * `decideVerdict` and `severityCapViolation` with zero firings, and the brocard
 * pre-gate deciding 11 of 18. None of that shows up as a failing assertion
 * anywhere else in this suite.
 *
 * The rule for this file:
 *
 *   - A mechanism that SHOULD be reachable gets a dispatch that provably routes
 *     to it, and an assertion that it — not something upstream of it — decides.
 *   - A mechanism nobody can construct a dispatch for is UNREACHABLE, and the
 *     test FAILS LOUDLY rather than being omitted. An omitted test is how a
 *     capability that did not survive a merge stays invisible.
 *
 * Each test names its parent, so a red run says which plugin lost what.
 */

import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'

import { runScript, script } from './extract.mjs'

const BASE = '/plugin/skills/fp-check'

const STATIC_SRC = readFileSync(script('triage-static.js'), 'utf8')
const ONLINE_SRC = readFileSync(script('triage-online.js'), 'utf8')
const POC_SRC = readFileSync(script('triage-poc.js'), 'utf8')
const SKILL_SRC = readFileSync(
  new URL('../skills/fp-check/SKILL.md', import.meta.url),
  'utf8',
)

// --------------------------------------------------------------- fixtures
//
// One finding shape reused everywhere, so a test that changes the outcome has
// changed exactly one scripted agent answer and the cause is unambiguous.

const finding = {
  summary: 'an unvalidated upstream rate reaches ledger.debit',
  sink: 'billing/charge.py:44',
  component: 'billing',
  claimedImpact: 'an attacker mints balance',
  bugClass: 'input validation',
  threatModel: 'a network attacker who can influence the rate service reaches charge() and credits an account',
}
const entryPoint = {
  description: 'POST /orders',
  location: 'api/orders.py:12',
  payload: 'qty=125 with the rate service returning -1.00',
}

// A dispatch selectRoute must keep on the cheap path: one layer, a bug class
// that is on none of the escalation lists, no crossComponent/ambiguous signal.
const standardArgs = (over = {}) => ({
  baseDir: BASE,
  finding,
  entryPoint,
  scope: 'the billing service and the rate client it calls',
  layers: [{ name: 'sign-check', location: 'billing/charge.py:40' }],
  ...over,
})

const BROCARD_PASS = { verdict: 'PASS', missingFact: '', evidence: 'the test does not apply here' }
const LAYER_PASSES = { verdict: 'PASSES', location: 'billing/charge.py:40', evidence: 'no sign check exists; the payload survives' }
const LAYER_BLOCKS = { verdict: 'BLOCKS', location: 'billing/charge.py:40', evidence: 'rates below zero are rejected here' }
const RECOVERY = { recoveryExists: false, effectiveImpact: 'the balance is inflated', evidence: 'nothing recovers on this path' }
const THREAT_OK = { inScope: 'YES', byDesign: false, byDesignIndicators: 0, evidence: 'billing is named in the declared scope' }
const HISTORY_NONE = { fixed: 'NO', complete: false, reference: '', searched: 'git log -p billing/, CHANGELOG, issues', evidence: 'nothing found' }
const IMPACT_INTERNAL = {
  result: 'VERIFIED',
  impact: 'a negative rate credits the account instead of debiting it',
  rootCause: 'internal',
  classification: 'vulnerability',
  severity: 'High',
  severityRationale: 'direct, silent ledger corruption',
  evidence: 'traced from charge() to ledger.debit()',
}
const GATES_ALL_PASS = {
  gateProcess: 'PASS',
  gateReachability: 'PASS',
  gateRealImpact: 'PASS',
  gatePocValidation: 'PASS',
  gateMathBounds: 'N/A',
  gateEnvironment: 'PASS',
  unresolvedUncertainty: '',
  verdictReason: 'attacker-influenced data reaches ledger.debit unchecked',
  evidence: 'see the layer evidence',
}

const staticAgents = (over = {}) => ({
  brocard: BROCARD_PASS,
  layer: LAYER_PASSES,
  recovery: RECOVERY,
  'threat-model': THREAT_OK,
  history: HISTORY_NONE,
  impact: IMPACT_INTERNAL,
  gates: GATES_ALL_PASS,
  ...over,
})

const labels = (r) => r.calls.map((c) => c.label)
const promptFor = (r, label) => {
  const call = r.calls.find((c) => c.label === label)
  assert.ok(call, `no agent was dispatched with label '${label}'`)
  return call.prompt
}

// A helper that fails the test rather than returning, so an "unreachable"
// verdict cannot be mistaken for a skipped or pending test in the TAP output.
const unreachable = (parent, mechanism, why, wouldFix) => {
  assert.fail(
    `UNREACHABLE CAPABILITY — inherited from ${parent}\n` +
      `  mechanism: ${mechanism}\n` +
      `  why:       ${why}\n` +
      `  to fix:    ${wouldFix}\n` +
      '  This test is failing on purpose. Deleting it hides the gap; the merge\n' +
      '  claims this capability and no dispatch reaches it.',
  )
}

// ===================================================================
// concept-prover
// ===================================================================

test('[concept-prover] per-layer reachability: a blocking layer decides, before impact is spent', async () => {
  const r = await runScript('triage-static.js', {
    args: standardArgs(),
    agents: staticAgents({ layer: LAYER_BLOCKS }),
  })
  assert.equal(r.result.status, 'NOT_EXPLOITABLE')
  assert.match(r.result.reason, /blocked at sign-check/)
  // The mechanism decided: the impact and gate agents were never reached, so
  // nothing downstream can be the thing that produced this status.
  assert.ok(!labels(r).includes('impact'), 'the impact agent ran, so the layer gate did not decide')
  assert.ok(!labels(r).includes('gates'), 'the gate agent ran, so the layer gate did not decide')
})

test('[concept-prover] per-layer reachability: one agent per enumerated layer, capped at 4', async () => {
  const four = [1, 2, 3, 4].map((i) => ({ name: `layer-${i}`, location: `f.py:${i}` }))
  const r = await runScript('triage-static.js', {
    args: standardArgs({ layers: four }),
    agents: staticAgents(),
  })
  const dispatched = labels(r).filter((l) => l.startsWith('layer:'))
  assert.equal(dispatched.length, 4, 'a layer must get its own agent; collapsing them is the mechanism the head-to-head measured')

  const five = [...four, { name: 'layer-5', location: 'f.py:5' }]
  const over = await runScript('triage-static.js', { args: standardArgs({ layers: five }), agents: staticAgents() })
  assert.equal(over.result.status, 'BLOCKED')
  assert.equal(labels(over).length, 0, 'the cap must reject before an agent is spent')
})

test('[concept-prover] the recovery check is a gate: a dead recovery agent blocks', async () => {
  const r = await runScript('triage-static.js', {
    args: standardArgs(),
    agents: staticAgents({ recovery: null }),
  })
  assert.equal(r.result.status, 'BLOCKED')
  assert.match(r.result.reason, /recovery agent returned nothing/)
})

test('[concept-prover] the recovery finding reaches the impact agent, so it can downgrade', async () => {
  const r = await runScript('triage-static.js', {
    args: standardArgs(),
    agents: staticAgents({
      recovery: { recoveryExists: true, mechanism: 'net/http conn.serve', effectiveImpact: 'one connection closes', evidence: 'per-connection recover' },
    }),
  })
  assert.match(promptFor(r, 'impact'), /recovery EXISTS/)
  assert.match(promptFor(r, 'impact'), /one connection closes/)
})

test('[concept-prover] threat-model alignment decides scope and design intent', async () => {
  const out = await runScript('triage-static.js', {
    args: standardArgs(),
    agents: staticAgents({ 'threat-model': { inScope: 'NO', byDesign: false, byDesignIndicators: 0, evidence: 'billing is outside the declared scope' } }),
  })
  assert.equal(out.result.status, 'OUT_OF_SCOPE')
  assert.match(out.result.reason, /outside the declared scope/)

  const design = await runScript('triage-static.js', {
    args: standardArgs(),
    agents: staticAgents({ 'threat-model': { inScope: 'YES', byDesign: true, byDesignIndicators: 3, evidence: 'documented and covered by tests as normal operation' } }),
  })
  assert.equal(design.result.status, 'NOT_VULNERABLE')

  const ambiguous = await runScript('triage-static.js', {
    args: standardArgs(),
    agents: staticAgents({ 'threat-model': { inScope: 'UNCERTAIN', byDesign: false, byDesignIndicators: 0, evidence: 'the scope statement does not name billing' } }),
  })
  assert.equal(ambiguous.result.status, 'NEEDS_MORE_INFO')
})

test('[concept-prover] the external-precondition rule decides an integration finding', async () => {
  const r = await runScript('triage-static.js', {
    args: standardArgs(),
    agents: staticAgents({
      impact: { ...IMPACT_INTERNAL, rootCause: 'integration', externalPrecondition: '   ' },
    }),
  })
  assert.equal(r.result.status, 'NEEDS_MORE_INFO')
  assert.match(r.result.reason, /external precondition/)
  assert.ok(!labels(r).includes('gates'), 'the gate agent ran, so 2.4b did not decide')
})

test('[concept-prover] the severity cap decides on the cheap path, and is reported', async () => {
  const r = await runScript('triage-static.js', {
    args: standardArgs(),
    agents: staticAgents({
      impact: { ...IMPACT_INTERNAL, severity: 'Critical', rootCause: 'integration', externalPrecondition: 'the rate service returns a negative rate' },
    }),
  })
  assert.equal(r.result.severity, 'Medium', 'capSeverity did not decide the severity the workflow returns')
  assert.match(r.result.severityCorrection, /lowered from Critical to Medium/)
  // And the CAPPED number, not the agent's claim, is what the gate agent sees.
  assert.match(promptFor(r, 'gates'), /Severity after the caps: Medium/)
})

test('[concept-prover] the upstream-fix retraction decides, and needs a reference', async () => {
  const fixed = await runScript('triage-static.js', {
    args: standardArgs(),
    agents: staticAgents({
      history: { fixed: 'YES', complete: true, reference: 'commit 99a4704 (#412)', searched: 'git log -p auth.py', evidence: 'the caller now digests the token' },
    }),
  })
  assert.equal(fixed.result.status, 'ALREADY_FIXED')
  assert.match(fixed.result.reason, /99a4704/)
  assert.ok(!labels(fixed).includes('impact'), 'the impact agent ran, so the retraction did not decide')

  const unreferenced = await runScript('triage-static.js', {
    args: standardArgs(),
    agents: staticAgents({
      history: { fixed: 'YES', complete: true, reference: '  ', searched: 'git log', evidence: 'I think it was fixed' },
    }),
  })
  assert.notEqual(unreferenced.result.status, 'ALREADY_FIXED', 'an unreferenced retraction discards a real finding')
})

test('[concept-prover] the five false-positive challenges decide the confidence band', async () => {
  // Challenge 4 is scripted as REBUTTED on purpose: its win overrides the band
  // outright, so leaving it lost would test that rule instead of this one.
  const r = await runScript('triage-poc.js', {
    args: pocArgs(),
    agents: pocAgents({ challenge: CHALLENGE_LOST, 'challenge:already-fixed': CHALLENGE_WON }),
  })
  assert.equal(r.result.status, 'DO_NOT_SUBMIT')
  assert.equal(r.result.defeated, 1)
  assert.equal(r.result.band.label, 'LOW')
  assert.ok(!labels(r).includes('report'), 'a report was written for a finding four reviewers rejected')
  const dispatched = labels(r).filter((l) => l.startsWith('challenge:'))
  assert.deepEqual(
    dispatched.sort(),
    ['challenge:already-fixed', 'challenge:by-design', 'challenge:reachable', 'challenge:real-deployment', 'challenge:recoverable'],
    'all five challenges must be dispatched as independent agents',
  )
})

test('[concept-prover] the already-fixed challenge overrides the band', async () => {
  const r = await runScript('triage-poc.js', {
    args: pocArgs(),
    agents: pocAgents({
      challenge: CHALLENGE_WON,
      'challenge:already-fixed': { ...CHALLENGE_LOST, evidence: 'fixed by 99a4704 (#412)' },
    }),
  })
  assert.equal(r.result.status, 'ALREADY_FIXED', 'four defeated challenges must not carry an already-patched bug through')
  assert.equal(r.result.defeated, 4)
  assert.match(r.result.reason, /99a4704/)
})

test('[concept-prover] the artifact re-check is made by an agent that did not build the PoC', async () => {
  const r = await runScript('triage-poc.js', {
    args: pocArgs(),
    agents: pocAgents({ 'artifact-check': { fileExists: true, lintExitZero: false, lintOutput: 'placeholder on line 4', evidence: 'ran it myself' } }),
  })
  assert.equal(r.result.status, 'BLOCKED')
  assert.match(r.result.reason, /poc-lint\.sh did not exit 0/)
  // The check is worth something only if it re-runs the linter itself.
  assert.match(promptFor(r, 'artifact-check'), /poc-lint\.sh --symbol/)
  assert.match(promptFor(r, 'artifact-check'), /billing\.charge\.charge/)
})

test('[concept-prover] the severity cap on the written report blocks rather than corrects', async () => {
  const r = await runScript('triage-poc.js', {
    args: pocArgs({ verification: { ...VERIFICATION, impact: { ...VERIFICATION.impact, rootCause: 'integration' } } }),
    agents: pocAgents({ report: { ...REPORT, severity: 'Critical' } }),
  })
  assert.equal(r.result.status, 'BLOCKED')
  assert.match(r.result.reason, /exceeds the Medium cap for a integration root cause/)
  assert.match(r.result.reason, /finding-negative-rate\.md/, 'the block must name the file that has to be corrected')
})

// ===================================================================
// old fp-check (git show main:plugins/fp-check/)
// ===================================================================

test('[old fp-check] the six-gate review decides the verdict', async () => {
  const pass = await runScript('triage-static.js', { args: standardArgs(), agents: staticAgents() })
  assert.equal(pass.result.status, 'TRUE_POSITIVE')
  assert.equal(pass.result.reason, GATES_ALL_PASS.verdictReason, 'the verdict must come from decideVerdict, not from an earlier stage')
  assert.ok(labels(pass).includes('gates'), 'the six gates were never dispatched')

  for (const gate of ['gateProcess', 'gateReachability', 'gateRealImpact', 'gatePocValidation', 'gateMathBounds', 'gateEnvironment']) {
    const r = await runScript('triage-static.js', {
      args: standardArgs(),
      agents: staticAgents({ gates: { ...GATES_ALL_PASS, [gate]: 'FAIL' } }),
    })
    assert.equal(r.result.status, 'FALSE_POSITIVE', `${gate} failing did not decide the verdict`)
    assert.match(r.result.reason, /^gate .* failed:/)
  }
})

test('[old fp-check] standard/deep routing is decided from the dispatch', async () => {
  const std = await runScript('triage-static.js', { args: standardArgs(), agents: staticAgents() })
  assert.equal(std.result.route, 'standard')
  for (const extra of ['api-contract', 'math-bounds', 'race-feasibility']) {
    assert.ok(!labels(std).includes(extra), `the standard route dispatched ${extra}; the cheap path is what makes it cheap`)
  }

  const deep = await runScript('triage-static.js', {
    args: standardArgs({ route: 'deep' }),
    agents: staticAgents({ 'api-contract': LAYER_PASSES, 'math-bounds': LAYER_PASSES, 'race-feasibility': LAYER_PASSES }),
  })
  assert.equal(deep.result.route, 'deep')
  for (const extra of ['api-contract', 'math-bounds', 'race-feasibility']) {
    assert.ok(labels(deep).includes(extra), `the deep route did not dispatch ${extra}; those three ARE what deep adds`)
  }
})

test('[old fp-check] bug-class routing escalates the four classes that need a proof', async () => {
  const classes = {
    'memory corruption': 'deep',
    'heap buffer overflow': 'deep',
    'integer truncation': 'deep',
    'TOCTOU race': 'deep',
    'algorithmic complexity DoS': 'deep',
    'input validation': 'standard',
    'injection': 'standard',
  }
  for (const [bugClass, expected] of Object.entries(classes)) {
    const r = await runScript('triage-static.js', {
      args: standardArgs({ finding: { ...finding, bugClass } }),
      agents: staticAgents({ 'api-contract': LAYER_PASSES, 'math-bounds': LAYER_PASSES, 'race-feasibility': LAYER_PASSES }),
    })
    assert.equal(r.result.route, expected, `bug class '${bugClass}' routed to ${r.result.route}`)
  }

  // 3+ trust boundaries in the path is the other escalation, and it fires on a
  // non-escalating bug class.
  const three = await runScript('triage-static.js', {
    args: standardArgs({ layers: [1, 2, 3].map((i) => ({ name: `l${i}`, location: `f.py:${i}` })) }),
    agents: staticAgents({ 'api-contract': LAYER_PASSES, 'math-bounds': LAYER_PASSES, 'race-feasibility': LAYER_PASSES }),
  })
  assert.equal(three.result.route, 'deep')
})

test('[old fp-check] the 13 devil\'s-advocate questions are asked on deep, the 7 spot-checks on standard', async () => {
  const std = await runScript('triage-static.js', { args: standardArgs(), agents: staticAgents() })
  assert.match(promptFor(std, 'gates'), /7 spot-check questions/)

  const deep = await runScript('triage-static.js', {
    args: standardArgs({ route: 'deep' }),
    agents: staticAgents({ 'api-contract': LAYER_PASSES, 'math-bounds': LAYER_PASSES, 'race-feasibility': LAYER_PASSES }),
  })
  assert.match(promptFor(deep, 'gates'), /All 13 devil's-advocate questions/)

  // Both lists have to exist where the prompt sends the agent, or the routing
  // decides between two names for the same thing.
  const fpp = readFileSync(new URL('../skills/fp-check/references/false-positive-patterns.md', import.meta.url), 'utf8')
  const questions = fpp.match(/^\d+\. /gm) || []
  assert.ok(questions.length >= 13, `false-positive-patterns.md lists ${questions.length} numbered questions, expected 13`)
  assert.equal((fpp.match(/^\d+\. ★/gm) || []).length, 7, 'the 7 starred spot-check questions are not marked in the reference')
})

test('[old fp-check] the algebraic bounds proof is written by an agent on the deep route, and cannot vanish', async () => {
  const deepArgs = standardArgs({ finding: { ...finding, bugClass: 'integer overflow' } })
  const deepAgents = (over) =>
    staticAgents({
      'api-contract': LAYER_PASSES,
      'race-feasibility': { verdict: 'UNCERTAIN', evidence: 'concurrency is not part of this trigger' },
      ...over,
    })

  // The proof itself: a dedicated agent, told to write the algebra rather than
  // asked whether it feels bounded. This is old fp-check's Phase 2.2.
  const passes = await runScript('triage-static.js', {
    args: deepArgs,
    agents: deepAgents({ 'math-bounds': { verdict: 'PASSES', evidence: 'no relation bounds the subtraction' } }),
  })
  assert.match(promptFor(passes, 'math-bounds'), /IF validation_check_passes THEN bounds_guarantee_holds/)
  assert.match(promptFor(passes, 'gates'), /math-bounds: PASSES/, 'the algebra never reached the agent that decides gateMathBounds')

  // A BLOCKS must either decide the finding itself or reach the verdict agent.
  // Which of the two is a live design question in this plugin — it was terminal
  // and is being changed to carried — but "neither" is a proof that was paid for
  // and thrown away, and that is what this asserts against.
  const blocks = await runScript('triage-static.js', {
    args: deepArgs,
    agents: deepAgents({ 'math-bounds': { verdict: 'BLOCKS', evidence: 'size >= MIN and MIN >= sizeof(hdr), so size - sizeof(hdr) cannot underflow' } }),
  })
  const decided = blocks.result.status === 'NOT_EXPLOITABLE' && /math-bounds/.test(blocks.result.reason)
  const carried = labels(blocks).includes('gates') && /math-bounds/.test(promptFor(blocks, 'gates'))
  assert.ok(decided || carried, `a blocking algebraic proof neither decided the finding nor reached the verdict agent (status ${blocks.result.status})`)

  // And Gate 5 itself is arithmetic over the verdict agent's answer, on both
  // routes: a FAIL is a FALSE POSITIVE that names the gate.
  const failed = await runScript('triage-static.js', {
    args: standardArgs(),
    agents: staticAgents({ gates: { ...GATES_ALL_PASS, gateMathBounds: 'FAIL' } }),
  })
  assert.equal(failed.result.status, 'FALSE_POSITIVE')
  assert.match(failed.result.reason, /Math Bounds/)
})

test('[old fp-check] on the STANDARD route the bounds proof is only a self-report', async () => {
  // Pinned, not celebrated. The standard route is the default, it dispatches no
  // agent that writes algebra, and `gateMathBounds: 'N/A'` is an accepted pass —
  // so on the cheap path old fp-check's Gate 5 is a question the verdict agent
  // answers about itself. Anything that changes this should change this test.
  const r = await runScript('triage-static.js', { args: standardArgs(), agents: staticAgents() })
  assert.ok(!labels(r).includes('math-bounds'), 'the standard route now dispatches the algebra agent — update this test and the report')
  assert.equal(r.result.status, 'TRUE_POSITIVE', "gateMathBounds: 'N/A' no longer passes on the standard route")
  assert.match(promptFor(r, 'gates'), /gateMathBounds/, 'the verdict agent is not even asked about Gate 5 on the standard route')
})

test('[old fp-check] batch triage is absent, and SKILL.md says so', () => {
  // Every workflow destructures a single `finding`, so the batch is the
  // orchestrator's loop with no gate behind it. That is a real capability old
  // fp-check had and the merge does not.
  //
  // This asserts the HONEST STATE rather than failing forever: the gap is fine,
  // claiming it is not. A test that is permanently red teaches everyone to ignore
  // red, and the next real regression goes with it.
  assert.match(STATIC_SRC, /const \{[^}]*\bfinding\b[^}]*\} = args \|\| \{\}/)
  assert.ok(!/\bfindings\s*[:=]/.test(STATIC_SRC), 'a findings collection exists now — rewrite this to exercise it')
  assert.ok(/## Batch Triage/.test(SKILL_SRC), 'SKILL.md no longer mentions batch triage')
  assert.match(
    SKILL_SRC,
    /Nothing in code enforces any of this/,
    'SKILL.md describes batch triage without saying nothing enforces it. The instruction is fine; ' +
      'presenting it as a guarantee is not, because every workflow takes exactly one finding.',
  )
})

test('[old fp-check] the exploit-chain check is absent, and SKILL.md says so', () => {
  // "Two NOT_EXPLOITABLE results whose blocking layers differ" is a comparison no
  // workflow can make: none of them sees a second finding.
  assert.ok(/exploit chain/i.test(SKILL_SRC), 'SKILL.md no longer mentions exploit chains')
  // Narrowed from /chain/i, which matched "privilege-escalation chain" in a
  // brocard prompt and made this fail on unrelated prose.
  for (const [name, src] of [['triage-static.js', STATIC_SRC], ['triage-online.js', ONLINE_SRC], ['triage-poc.js', POC_SRC]]) {
    assert.ok(!/exploit.chain|chain.check/i.test(src), `${name} implements a chain check now — rewrite this`)
  }
  assert.match(
    SKILL_SRC,
    /also unenforced/,
    'SKILL.md describes the exploit-chain check without saying no workflow can make that comparison',
  )
})

// ===================================================================
// online-triage
// ===================================================================

test('[online-triage] the policy read decides: offline halts before any scope claim', async () => {
  const r = await runScript('triage-online.js', {
    args: onlineArgs(),
    agents: onlineAgents({ policy: { ...POLICY, reachedNetwork: false } }),
  })
  assert.equal(r.result.status, 'OFFLINE')
  assert.ok(!labels(r).includes('inscope'), 'a scope verdict was formed with no document read')
  assert.ok(!labels(r).some((l) => l.startsWith('past-bugs:')), 'the past-bug fan-out was paid for offline')
})

test('[online-triage] the scope verdict halts only with a quoted clause', async () => {
  const clause = await runScript('triage-online.js', {
    args: onlineArgs(),
    agents: onlineAgents({ inscope: { verdict: 'out-of-scope', clause: 'SECURITY.md: "internal services are not in scope"', severity: 'Unknown', evidence: 'clause 3' } }),
  })
  assert.equal(clause.result.status, 'OUT_OF_SCOPE')
  assert.match(clause.result.reason, /internal services are not in scope/)

  const unclaused = await runScript('triage-online.js', {
    args: onlineArgs(),
    agents: onlineAgents({ inscope: { verdict: 'out-of-scope', clause: '   ', severity: 'Unknown', evidence: 'it feels out of scope' } }),
  })
  assert.equal(unclaused.result.status, 'NEEDS_MORE_INFO')
})

test('[online-triage] one past-bug agent per named venue, and a duplicate is terminal', async () => {
  const sources = ['github-issues', 'github-advisories', 'mailing-list'].map((label) => ({ label, query: `${label} query` }))
  const r = await runScript('triage-online.js', {
    args: onlineArgs({ sources }),
    agents: onlineAgents({
      'past-bugs': PAST_NOTHING,
      'past-bugs:github-advisories': { ...PAST_NOTHING, result: 'similar-bugs-found', duplicate: true, links: 'GHSA-xxxx-yyyy-zzzz' },
    }),
  })
  assert.deepEqual(
    labels(r).filter((l) => l.startsWith('past-bugs:')).sort(),
    ['past-bugs:github-advisories', 'past-bugs:github-issues', 'past-bugs:mailing-list'],
  )
  assert.equal(r.result.status, 'DUPLICATE')
  assert.match(r.result.reason, /GHSA-xxxx-yyyy-zzzz/)
})

test('[online-triage] venues beyond the cap are declared unchecked rather than dropped', async () => {
  const sources = [1, 2, 3, 4, 5, 6, 7].map((i) => ({ label: `venue-${i}`, query: `q${i}` }))
  const r = await runScript('triage-online.js', {
    args: onlineArgs({ sources }),
    agents: onlineAgents({ 'past-bugs': PAST_NOTHING }),
  })
  assert.equal(labels(r).filter((l) => l.startsWith('past-bugs:')).length, 6)
  assert.deepEqual(r.result.beyondCap, ['venue-7'])
  assert.match(promptFor(r, 'summary'), /venue-7/)
})

test('[online-triage] the downstream-users census is absent and unadvertised', async () => {
  // The parent's `triage-online-users` role — find the popular public consumers
  // and check whether any exhibits the buggy pattern — is what turns "a misusable
  // API" into a severity. It did not survive the merge.
  //
  // It used to be advertised anyway: meta.description claimed "downstream users"
  // while the script dispatched no such agent, and references/brocards.md said
  // outright that Stage 2 has no census. The description was the stale one.
  assert.ok(
    !/downstream users/i.test(ONLINE_SRC),
    'triage-online.js advertises downstream users again, and no agent implements it',
  )
  const r = await runScript('triage-online.js', { args: onlineArgs(), agents: onlineAgents({ 'past-bugs': PAST_NOTHING }) })
  assert.ok(
    !labels(r).some((l) => /user/i.test(l)),
    'a downstream-users agent now exists — rewrite this to exercise it',
  )
})

// ===================================================================
// the merge itself: ordering, not presence
// ===================================================================

test('[merge] the brocard pre-gate is dispatched ahead of every mechanism the merge inherited', async () => {
  // Not a defect on its own — a cheap test that can end the analysis for cents
  // is the point of a pre-gate. It is pinned here because it decides which
  // mechanism gets to decide: on the measured 7-case sweep the pre-gate returned
  // DISMISSED on findings concept-prover had settled with a blocking layer or an
  // already-fixed retraction, and on those runs neither of those gates ran at
  // all. The ordering is the mechanism-selection rule of the merged plugin.
  const r = await runScript('triage-static.js', { args: standardArgs(), agents: staticAgents() })
  const order = labels(r)
  const lastBrocard = order.reduce((acc, l, i) => (l.startsWith('brocard:') ? i : acc), -1)
  assert.equal(lastBrocard, 3, 'the four brocards are no longer the first four agents dispatched')
  for (const later of ['layer:sign-check', 'recovery', 'threat-model', 'history', 'impact', 'gates']) {
    assert.ok(order.indexOf(later) > lastBrocard, `${later} is dispatched before the pre-gate; the ordering note in this file is stale`)
  }
})

test('[merge] a brocard DISMISS is never silently dropped, whichever brocard raises it', async () => {
  // Brocards 4 and 5 duplicate the recovery/threat-model and already-fixed
  // mechanisms respectively, on strictly less evidence. Whether such a DISMISS
  // ends the stage or is deferred to the gate that knows more is a live design
  // question here. What must not happen either way is that it disappears: the
  // finding comes back TRUE_POSITIVE with no trace of a test that dismissed it.
  const keys = ['from-the-heavens', 'standard-behavior', 'documented-behavior', 'cure-worse']
  for (const key of keys) {
    const marker = `sentinel-dismissal-${key}`
    const r = await runScript('triage-static.js', {
      args: standardArgs(),
      agents: staticAgents({ [`brocard:${key}`]: { verdict: 'DISMISS', missingFact: '', evidence: marker } }),
    })
    const terminal = r.result.status === 'DISMISSED'
    const surfaced = JSON.stringify(r.result).includes(marker)
    const relayedToAGate = labels(r).some((l) => ['impact', 'gates'].includes(l) && promptFor(r, l).includes(marker))
    assert.ok(
      terminal || (surfaced && relayedToAGate),
      `a DISMISS from brocard '${key}' was neither terminal nor carried to a downstream gate (status ${r.result.status})`,
    )
    if (!terminal) {
      assert.notEqual(r.result.status, 'TRUE_POSITIVE', `brocard '${key}' dismissed the finding and it still came back TRUE_POSITIVE`)
    }
  }
})

test('[merge] a carried brocard question blocks a TRUE POSITIVE even with six passing gates', async () => {
  const r = await runScript('triage-static.js', {
    args: standardArgs(),
    agents: staticAgents({
      'brocard:cure-worse': { verdict: 'NEEDS_MORE_INFO', missingFact: 'the dependency graph of the fix', evidence: '' },
    }),
  })
  assert.equal(r.result.status, 'NEEDS_MORE_INFO')
  assert.match(r.result.reason, /all six gates passed/)
  assert.match(r.result.reason, /dependency graph of the fix/)
  // And that is a fact to answer, not a bug to demonstrate: Stage 3 refuses it.
  const poc = await runScript('triage-poc.js', {
    args: pocArgs({ verification: { ...VERIFICATION, status: 'NEEDS_MORE_INFO' } }),
    agents: pocAgents(),
  })
  assert.equal(poc.result.status, 'BLOCKED')
  assert.equal(labels(poc).length, 0, 'a builder was spent on a finding Stage 1 did not confirm')
})

test('[merge] every Stage 1 exit after the impact agent reports the capped severity', async () => {
  // capSeverity is applied before the early exits on purpose. If a later exit
  // returned the agent's own number the cap would be unreachable exactly on the
  // findings it exists to bound.
  const exits = [
    { name: 'missing precondition', over: { impact: { ...IMPACT_INTERNAL, severity: 'Critical', rootCause: 'external', externalPrecondition: '' } } },
    { name: 'failed gate', over: { impact: { ...IMPACT_INTERNAL, severity: 'Critical', rootCause: 'integration', externalPrecondition: 'the rate service misbehaves' }, gates: { ...GATES_ALL_PASS, gateReachability: 'FAIL' } } },
    { name: 'true positive', over: { impact: { ...IMPACT_INTERNAL, severity: 'Critical', rootCause: 'integration', externalPrecondition: 'the rate service misbehaves' } } },
  ]
  for (const { name, over } of exits) {
    const r = await runScript('triage-static.js', { args: standardArgs(), agents: staticAgents(over) })
    assert.equal(r.result.severity, 'Medium', `the ${name} exit returned an uncapped severity`)
    assert.ok(r.result.severityCorrection, `the ${name} exit reported no correction`)
  }
})

// --------------------------------------------------------- shared fixtures
//
// Declared below the tests that use them: function declarations hoist, and
// keeping the const fixtures for one workflow next to the others made the
// static-stage fixtures at the top of the file harder to read than the tests.

const VERIFICATION = {
  status: 'TRUE_POSITIVE',
  impact: {
    impact: 'a negative rate credits the account',
    rootCause: 'internal',
    classification: 'vulnerability',
  },
  severity: 'High',
  severityCorrection: '',
  history: { fixed: 'NO', searched: 'git log -p billing/, CHANGELOG' },
}

const POC_BUILT = {
  built: true,
  pocType: 'test-integrated',
  path: 'tests/test_negative_rate.py',
  absolutePath: '/w/tests/test_negative_rate.py',
  command: 'pytest tests/test_negative_rate.py',
  executed: true,
  output: 'balance 0 -> 12500; VULNERABLE',
  invokedSymbol: 'billing.charge.charge',
  lintPassed: true,
}

const ARTIFACT_OK = { fileExists: true, lintExitZero: true, reRunSucceeded: true, evidence: 'ran it and it reproduces' }
const CHALLENGE_WON = { challenge: 'the path is unreachable', rebuttal: 'the entry point drives it', winner: 'REBUTTAL', evidence: 'see the PoC setup' }
const CHALLENGE_LOST = { challenge: 'the path is unreachable', rebuttal: 'none found', winner: 'CHALLENGE', evidence: 'the fixture constructs state no caller reaches' }
const REPORT = { severity: 'Medium', severityRationale: 'ledger corruption behind an internal trust boundary', reportPath: '/w/finding-negative-rate.md', unproven: 'that the rate service can be made to misbehave' }

function pocArgs(over = {}) {
  return {
    baseDir: BASE,
    finding,
    verification: VERIFICATION,
    envelope: { level: 1, hosts: [], destructive: false },
    candidates: [{ name: 'negative-rate', description: 'drive charge() through POST /orders', entryPoint: 'api/orders.py:12', payload: 'qty=125, rate=-1.00' }],
    ...over,
  }
}

function pocAgents(over = {}) {
  return { build: POC_BUILT, 'artifact-check': ARTIFACT_OK, challenge: CHALLENGE_WON, report: REPORT, ...over }
}

const POLICY = {
  reachedNetwork: true,
  sourcesRead: 'https://example.test/SECURITY.md',
  policyUrl: 'https://example.test/SECURITY.md',
  inScopeClasses: 'authentication, billing integrity',
  outOfScopeClasses: 'self-XSS',
  evidence: 'read the policy',
}
const REACHABILITY = { verdict: 'in-scope', clause: '', severity: 'Medium', eligibilityCaveats: 'requires a compromised rate service', evidence: 'charge() is called from the public order pipeline' }
const INSCOPE = { verdict: 'in-scope', clause: 'SECURITY.md: "billing integrity is in scope"', severity: 'Medium', evidence: 'billing integrity is named' }
const PAST_NOTHING = { result: 'nothing', coverage: 'searched 4 pages of results', duplicate: false, evidence: 'nothing similar' }
const SUMMARY = { finalSeverity: 'Medium', scopeVerdict: 'in-scope', reasoning: 'the policy names billing integrity', confidence: 'medium', openQuestions: 'the rate service is not described in the policy', evidence: 'see above' }

function onlineArgs(over = {}) {
  return {
    baseDir: BASE,
    finding,
    verification: VERIFICATION,
    project: { name: 'example', url: 'https://example.test/example' },
    sources: [{ label: 'github-issues', query: 'repo:example/example negative rate' }],
    ...over,
  }
}

function onlineAgents(over = {}) {
  return { policy: POLICY, reachability: REACHABILITY, inscope: INSCOPE, 'past-bugs': PAST_NOTHING, summary: SUMMARY, ...over }
}
