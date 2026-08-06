import assert from 'node:assert/strict'
import { test } from 'node:test'

import { loadFn, script } from './extract.mjs'

const REVIEW = script('triage-poc.js')
const confidenceBand = loadFn(REVIEW, 'confidenceBand')
const tallyChallenges = loadFn(REVIEW, 'tallyChallenges')
const severityCapViolation = loadFn(REVIEW, 'severityCapViolation')
const alreadyFixedStands = loadFn(REVIEW, 'alreadyFixedStands')
const artifactProblem = loadFn(REVIEW, 'artifactProblem')
const reportProblem = loadFn(REVIEW, 'reportProblem')

const KEYS = ['reachable', 'recoverable', 'by-design', 'already-fixed', 'real-deployment']
const won = (key) => ({ key, winner: 'REBUTTAL', challenge: `c:${key}` })
const lost = (key) => ({ key, winner: 'CHALLENGE', challenge: `c:${key}` })

// ---------------------------------------------------------------- bands

test('bands follow checkpoints.md 5.1 exactly', () => {
  assert.equal(confidenceBand(5).label, 'HIGH')
  assert.equal(confidenceBand(4).label, 'MEDIUM')
  assert.equal(confidenceBand(3).label, 'MEDIUM')
  assert.equal(confidenceBand(2).label, 'LOW')
  assert.equal(confidenceBand(1).label, 'LOW')
  assert.equal(confidenceBand(0).label, 'NONE')
})

test('only HIGH and MEDIUM proceed', () => {
  assert.equal(confidenceBand(5).action, 'PROCEED')
  assert.equal(confidenceBand(3).action, 'PROCEED_WITH_UNCERTAINTIES')
  assert.equal(confidenceBand(2).action, 'DO_NOT_SUBMIT')
  assert.equal(confidenceBand(0).action, 'DO_NOT_SUBMIT')
})

// ------------------------------------------------------------- tallying
//
// The concept-prover analogue of "dedup against SEEN, not CONFIRMED": the tally
// must run against the EXPECTED challenge list, not against whatever came back.
// Counting the returned array instead lets a dead agent shrink the denominator
// and silently raise confidence, which is the same class of bug — a result
// disappearing from the accounting rather than counting against the finding.

test('all five defeated gives HIGH', () => {
  const t = tallyChallenges(KEYS.map(won), KEYS)
  assert.equal(t.defeated, 5)
  assert.equal(t.unrebutted.length, 0)
  assert.equal(confidenceBand(t.defeated).label, 'HIGH')
})

test('a dead agent counts AGAINST the finding, it does not vanish', () => {
  // Four challenges returned, all rebutted. The fifth agent died.
  const returned = KEYS.slice(0, 4).map(won)
  const t = tallyChallenges(returned, KEYS)
  assert.equal(t.defeated, 4, 'the missing challenge must not count as defeated')
  assert.equal(t.missing, 1)
  assert.equal(confidenceBand(t.defeated).label, 'MEDIUM')
  assert.ok(
    t.unrebutted.some((u) => u.key === 'real-deployment'),
    'the unanswered challenge must appear as unrebutted',
  )
})

test('all agents dying yields NONE, never HIGH', () => {
  const t = tallyChallenges([], KEYS)
  assert.equal(t.defeated, 0)
  assert.equal(t.missing, 5)
  assert.equal(confidenceBand(t.defeated).action, 'DO_NOT_SUBMIT')
})

test('nulls from dead agents are filtered, not counted or thrown on', () => {
  const t = tallyChallenges([won('reachable'), null, undefined, won('by-design')], KEYS)
  assert.equal(t.defeated, 2)
  assert.equal(t.unrebutted.length, 3)
})

test('a duplicate key cannot inflate the defeated count', () => {
  const t = tallyChallenges([won('reachable'), won('reachable'), won('reachable')], KEYS)
  assert.equal(t.defeated, 1, 'tally is over expected keys, so duplicates collapse')
})

test('an unknown key is ignored rather than counted', () => {
  const t = tallyChallenges([won('not-a-real-challenge')], KEYS)
  assert.equal(t.defeated, 0)
})

test('a lost challenge is reported with its argument text', () => {
  const others = KEYS.filter((k) => k !== 'recoverable').map(won)
  const t = tallyChallenges([lost('recoverable'), ...others], KEYS)
  assert.equal(t.defeated, 4)
  assert.equal(t.unrebutted.length, 1)
  assert.equal(t.unrebutted[0].key, 'recoverable')
  assert.equal(t.unrebutted[0].challenge, 'c:recoverable')
  assert.equal(confidenceBand(t.defeated).action, 'PROCEED_WITH_UNCERTAINTIES')
})

test('a missing challenge is labelled as having no verdict', () => {
  const t = tallyChallenges([], ['reachable'])
  assert.equal(t.unrebutted[0].challenge, 'no verdict returned')
})

test('empty expected list returns cleanly rather than throwing', () => {
  const t = tallyChallenges([], [])
  assert.equal(t.defeated, 0)
  assert.equal(t.unrebutted.length, 0)
})

test('undefined verdicts array returns cleanly rather than throwing', () => {
  const t = tallyChallenges(undefined, KEYS)
  assert.equal(t.defeated, 0)
  assert.equal(t.unrebutted.length, 5)
})

// ------------------------------------------------- challenge 4 is unconditional

// checkpoints.md 5.1: "Fix exists -> DO NOT SUBMIT (this outcome overrides the
// confidence band)". The script reads that decision off the unrebutted list
// rather than off the returned verdicts, so a dead challenge-4 agent cannot
// escape the one rule the band does not get a vote on. These assertions pin the
// data the script branches on.

test('a DEAD already-fixed agent also appears in the unrebutted list', () => {
  // The gap this closes: `verdicts.find(v => v.key === 'already-fixed' && ...)`
  // matched nothing when the agent died, so the unconditional rule was skipped
  // while every other challenge counted a missing verdict against the finding.
  const returned = KEYS.filter((k) => k !== 'already-fixed').map(won)
  const t = tallyChallenges(returned, KEYS)
  assert.equal(t.defeated, 4)
  assert.ok(
    t.unrebutted.some((u) => u.key === 'already-fixed'),
    'a missing verdict counts as won by the challenge, challenge 4 included',
  )
})

test('the unconditional rule fires whether challenge 4 was lost or never answered', () => {
  const others = KEYS.filter((k) => k !== 'already-fixed').map(won)
  for (const returned of [[lost('already-fixed'), ...others], others]) {
    const t = tallyChallenges(returned, KEYS)
    assert.equal(alreadyFixedStands(t.unrebutted), true)
  }
})

test('a rebutted already-fixed challenge does not trigger the rule', () => {
  const t = tallyChallenges(KEYS.map(won), KEYS)
  assert.equal(alreadyFixedStands(t.unrebutted), false)
})

test('the unconditional rule survives an empty or absent list', () => {
  for (const input of [[], undefined, null, [null, undefined]]) {
    assert.equal(alreadyFixedStands(input), false)
  }
})

test('the rule keys on already-fixed and not on any other lost challenge', () => {
  const t = tallyChallenges([lost('recoverable')], ['recoverable'])
  assert.equal(alreadyFixedStands(t.unrebutted), false)
})

// ------------------------------------------------------------ severity caps

// checkpoints.md 2.4b caps an integration or external root cause at Medium, and
// 2.5 puts a hardening gap at "medium priority, defense-in-depth". The report
// prompt says so, but a prompt is not an enforcement mechanism — what comes back
// is whatever severity the agent chose.

test('an internal vulnerability may carry any severity', () => {
  for (const s of ['Critical', 'High', 'Medium', 'Low', 'Informational']) {
    assert.equal(severityCapViolation(s, 'internal', 'vulnerability'), null, `${s} is allowed`)
  }
})

test('integration and external root causes are capped at Medium', () => {
  for (const rootCause of ['integration', 'external']) {
    for (const s of ['Critical', 'High']) {
      const v = severityCapViolation(s, rootCause, 'vulnerability')
      assert.ok(v, `${s} on a ${rootCause} root cause must be caught`)
      assert.match(v, /2\.4b/)
      assert.match(v, new RegExp(s), 'the message must name the severity it rejected')
    }
    for (const s of ['Medium', 'Low', 'Informational']) {
      assert.equal(severityCapViolation(s, rootCause, 'vulnerability'), null)
    }
  }
})

test('a hardening gap is capped at Medium even with an internal root cause', () => {
  const v = severityCapViolation('High', 'internal', 'hardening_gap')
  assert.ok(v)
  assert.match(v, /2\.5/)
  assert.equal(severityCapViolation('Medium', 'internal', 'hardening_gap'), null)
})

test('the root-cause cap is reported ahead of the classification cap', () => {
  // Both apply; the message names the root cause, which is the stronger reason
  // and the one that drives remediation.
  const v = severityCapViolation('Critical', 'integration', 'hardening_gap')
  assert.match(v, /integration/)
})

test('an unrecognised severity is not silently treated as capped', () => {
  // The schema constrains severity to the five names; anything else means the
  // enum moved and this function must not start rejecting valid reports.
  assert.equal(severityCapViolation(undefined, 'integration', 'vulnerability'), null)
  assert.equal(severityCapViolation('', 'integration', 'vulnerability'), null)
})


// ------------------------------------------------- checkpoint 4.3, re-checked

// build-poc gates on `built`, `executed` and `lintPassed` — three booleans the
// builder fills in itself, in a script with no Bash to verify them. SKILL.md
// nonetheless says placeholders are "enforced by poc-lint.sh, not by good
// intentions". This is what makes that true: an independent agent re-runs the
// linter against poc.absolutePath and this decides what its answer means.

const cleanCheck = { fileExists: true, lintExitZero: true, reRunSucceeded: true, evidence: 'ran it' }

test('a clean artifact check does not block', () => {
  assert.equal(artifactProblem(cleanCheck), null)
})

test('a dead artifact agent blocks: 4.3 unverified is not 4.3 passed', () => {
  for (const dead of [null, undefined]) {
    const problem = artifactProblem(dead)
    assert.ok(problem, 'a missing answer must not read as a passing one')
    assert.match(problem, /returned nothing/)
  }
})

test('a missing PoC file blocks', () => {
  const problem = artifactProblem({ ...cleanCheck, fileExists: false })
  assert.ok(problem)
  assert.match(problem, /no PoC file/)
})

test('a lint failure blocks even though the builder reported lintPassed', () => {
  // The whole point: the builder said it passed, the reviewer ran it and it
  // did not. The reviewer wins.
  const problem = artifactProblem({ ...cleanCheck, lintExitZero: false, lintOutput: 'stub-body' })
  assert.ok(problem)
  assert.match(problem, /did not exit 0/)
  assert.match(problem, /stub-body/, 'the linter output belongs in the reason')
})

test('a lint failure with no captured output still reports a reason', () => {
  const problem = artifactProblem({ fileExists: true, lintExitZero: false })
  assert.match(problem, /no output captured/)
})

test('a failed re-run does NOT block', () => {
  // A testnet or service-dependent PoC can legitimately fail to reproduce on
  // the reviewer's machine. That is a boundary for the report's "unproven"
  // section, not evidence the finding is wrong.
  assert.equal(artifactProblem({ ...cleanCheck, reRunSucceeded: false }), null)
})

test('file existence is checked before lint, so the reason is the useful one', () => {
  const problem = artifactProblem({ fileExists: false, lintExitZero: false })
  assert.match(problem, /no PoC file/, 'a missing file explains the lint failure')
})

// ------------------------------------------------------- checkpoint 6.1
//
// REPORT_SCHEMA requires all four fields, and JSON Schema `required` checks
// presence and not content: `unproven: ''` and `reportPath: ''` both validate.
// `unproven` was gated with .trim(); `reportPath` was not gated at all, despite
// the prompt saying "reportPath must be a file you actually wrote, not a path
// you intend to use" — a prompt is a request the model may decline. An empty one
// returned REPORTED with no report to point at, and reached the severity-cap
// block message as "The report at  carries a severity...".

const goodReport = {
  severity: 'High',
  severityRationale: 'internal root cause, unauthenticated',
  reportPath: '/tmp/wf-worktree-3/finding-negative-transfer.md',
  unproven: 'no network route was exercised',
}

test('a complete report does not block', () => {
  assert.equal(reportProblem(goodReport), null)
})

test('a dead report agent blocks: 6.1 unverified is not 6.1 passed', () => {
  for (const dead of [null, undefined]) {
    const problem = reportProblem(dead)
    assert.ok(problem, 'a missing answer must not read as a passing one')
    assert.match(problem, /returned nothing/)
  }
})

test('an empty or whitespace unproven blocks — every PoC has a boundary', () => {
  for (const unproven of [undefined, '', '   ', '\n\t']) {
    const problem = reportProblem({ ...goodReport, unproven })
    assert.ok(problem, `unproven ${JSON.stringify(unproven)} must block`)
    assert.match(problem, /unproven/)
  }
})

test('an empty or whitespace reportPath blocks, and the reason names the field', () => {
  for (const reportPath of [undefined, '', '   ', '\n']) {
    const problem = reportProblem({ ...goodReport, reportPath })
    assert.ok(problem, `reportPath ${JSON.stringify(reportPath)} must block`)
    assert.match(problem, /reportPath/)
    assert.ok(problem.trim(), 'a halt must explain itself')
  }
})

test('unproven is reported ahead of reportPath when both are blank', () => {
  // Ordering is not arbitrary: a report agent that filled in neither has not
  // written a report at all, and "what remains unproven" is the checkpoint the
  // Completion Gate lists.
  const problem = reportProblem({ ...goodReport, unproven: '', reportPath: '' })
  assert.match(problem, /unproven/)
})
