/**
 * Layer 2 and 2b for Stage 2, which had no tests at all: online-triage shipped as
 * prose with no suite, and the 7-case eval suite cannot measure it — its premise
 * is evidence synthetic fixtures do not have, and its own rule is to stop when
 * offline, so the correct behaviour would score zero.
 *
 * The gates here are therefore the only thing standing behind it, and the one
 * that matters most is `offlineProblem`: as prose, "stop when offline rather than
 * triaging from memory" inverts under pressure, because an agent with no network
 * still has a prompt asking it for a scope verdict and the most likely completion
 * is a plausible one.
 */

import assert from 'node:assert/strict'
import { test } from 'node:test'

import { loadFn, loadFns, runScript, script } from './extract.mjs'

const ONLINE = script('triage-online.js')
const missingArgs = loadFn(ONLINE, 'missingArgs')
const offlineProblem = loadFn(ONLINE, 'offlineProblem')
const scopeHalt = loadFn(ONLINE, 'scopeHalt')
const summaryProblem = loadFn(ONLINE, 'summaryProblem')

const GOOD = {
  baseDir: '/plugin/skills/fp-check',
  finding: {
    summary: 'unauthenticated read of arbitrary tables',
    sink: 'search.py:34',
    component: 'the search module',
    claimedImpact: 'database contents disclosed',
  },
  verification: {
    status: 'TRUE_POSITIVE',
    impact: { impact: 'reads arbitrary tables', rootCause: 'internal', classification: 'vulnerability' },
    severity: 'High',
  },
  project: { name: 'example-app', url: 'https://github.com/example/app' },
  sources: [{ label: 'github-advisories', query: 'repo:example/app SQL' }],
}

// ------------------------------------------------------------- missingArgs

test('a well-formed dispatch has no problems', () => {
  assert.deepEqual(missingArgs(GOOD), [])
})

test('the project must be identified: there is nothing to look up without it', () => {
  for (const field of ['name', 'url']) {
    const problems = missingArgs({ ...GOOD, project: { ...GOOD.project, [field]: undefined } })
    assert.ok(problems.includes(`project.${field}`), `project.${field} must be required`)
  }
  // A missing project object must be reported, not thrown on: `project.name` is a
  // nested access in the prompt.
  const problems = missingArgs({ ...GOOD, project: undefined })
  assert.ok(Array.isArray(problems) && problems.length > 0)
})

// Zero sources means the past-bug fan-out is skipped entirely and the summary is
// written as though nothing similar had ever been reported — the same vacuous pass
// an empty `layers` list is in Stage 1.
test('an empty source list is rejected rather than treated as nothing to find', () => {
  const problems = missingArgs({ ...GOOD, sources: [] })
  assert.ok(problems.some((p) => p.startsWith('sources')))
  assert.match(problems.find((p) => p.startsWith('sources')), /duplicate check/)
})

test('a source without a label or a query is rejected', () => {
  for (const field of ['label', 'query']) {
    const sources = [{ ...GOOD.sources[0], [field]: undefined }]
    assert.ok(missingArgs({ ...GOOD, sources }).includes(`sources[0].${field}`))
  }
})

test('a non-array sources list is reported, not thrown on', () => {
  for (const bad of [{ label: 'x' }, 'github', 7]) {
    const problems = missingArgs({ ...GOOD, sources: bad })
    assert.ok(Array.isArray(problems), 'must return, not throw')
    assert.ok(problems.some((p) => p.startsWith('sources')))
  }
})

// A finding already dismissed on the code does not need a policy check, and
// running one anyway invites the online evidence to argue a dead finding back to
// life. NEEDS_MORE_INFO and OUT_OF_SCOPE are the two that Stage 2 can still move.
test('only an actionable Stage 1 status is accepted', () => {
  for (const status of ['TRUE_POSITIVE', 'NEEDS_MORE_INFO', 'OUT_OF_SCOPE']) {
    const problems = missingArgs({ ...GOOD, verification: { ...GOOD.verification, status } })
    assert.deepEqual(problems, [], `${status} must be accepted`)
  }
  for (const status of ['DISMISSED', 'NOT_EXPLOITABLE', 'NOT_VULNERABLE', 'FALSE_POSITIVE', 'ALREADY_FIXED', 'BLOCKED', '', undefined]) {
    const problems = missingArgs({ ...GOOD, verification: { ...GOOD.verification, status } })
    assert.ok(
      problems.some((p) => p.startsWith('verification.status')),
      `${JSON.stringify(status)} must be rejected`,
    )
  }
})

test('the validator returns an array and never throws on empty input', () => {
  for (const input of [{}, undefined, { finding: null, verification: null, project: null }]) {
    const out = missingArgs(input)
    assert.ok(Array.isArray(out) && out.length > 0)
  }
})

// ---------------------------------------------------------- offlineProblem

const READ = {
  reachedNetwork: true,
  sourcesRead: 'https://github.com/example/app/blob/main/SECURITY.md',
  inScopeClasses: 'injection, authz bypass',
  outOfScopeClasses: 'DoS, self-XSS',
  evidence: 'read the policy',
}

test('a live fetch with a named source is not a problem', () => {
  assert.equal(offlineProblem(READ), null)
})

test('reachedNetwork false halts, and names where it looked', () => {
  const r = offlineProblem({ ...READ, reachedNetwork: false, sourcesRead: 'tried SECURITY.md, DNS failed' })
  assert.ok(r)
  assert.match(r, /DNS failed/)
})

// Read the affirmative value. Grading by exclusion — anything not `false` counts
// as online — makes an omitted field a successful fetch, which is the exact
// failure this gate exists to stop.
test('anything other than true is offline', () => {
  for (const value of [undefined, null, '', 0, 'yes', 'true', 1]) {
    assert.ok(offlineProblem({ ...READ, reachedNetwork: value }), `reachedNetwork ${JSON.stringify(value)}`)
  }
})

// A dead agent read nothing, which is the same thing as being offline, so the
// failure direction has to be the same.
test('a dead policy agent halts exactly as an offline one does', () => {
  for (const input of [null, undefined]) {
    const r = offlineProblem(input)
    assert.ok(r && r.trim())
  }
})

// "I reached the network" with no citable source is worse than being offline: it
// looks like evidence. `required` validates `sourcesRead: ''`.
test('an uncitable policy claim halts even when the network was reached', () => {
  for (const sourcesRead of [undefined, '', '   ']) {
    const r = offlineProblem({ ...READ, sourcesRead })
    assert.ok(r, `sourcesRead ${JSON.stringify(sourcesRead)} must not pass`)
    assert.match(r, /uncitable|named no source/)
  }
})

// A project that publishes nothing is a DIFFERENT answer from a project that
// could not be reached, and collapsing them would make the halt fire on every
// project without a SECURITY.md.
test('a project that publishes nothing is not the same as being offline', () => {
  const r = offlineProblem({
    ...READ,
    inScopeClasses: '',
    outOfScopeClasses: '',
    sourcesRead: 'checked SECURITY.md (404), the wiki (empty), and the docs site: no policy published',
  })
  assert.equal(r, null)
})

// --------------------------------------------------------------- scopeHalt

const IN_SCOPE = {
  verdict: 'in-scope',
  clause: '"injection in the query layer is in scope"',
  severity: 'High',
  evidence: 'matches the in-scope list',
}

test('in-scope and unclear both continue', () => {
  assert.equal(scopeHalt(IN_SCOPE), null)
  assert.equal(scopeHalt({ ...IN_SCOPE, verdict: 'unclear', clause: '' }), null)
})

test('out-of-scope with a quoted clause halts and quotes it', () => {
  const r = scopeHalt({
    ...IN_SCOPE,
    verdict: 'out-of-scope',
    clause: '"self-XSS is explicitly excluded"',
  })
  assert.equal(r.status, 'OUT_OF_SCOPE')
  assert.match(r.reason, /self-XSS/)
})

// The asymmetry is the whole safety property: out-of-scope is the one verdict
// here that ends the work, so it is the one that has to be earned. "It's probably
// out of scope" is `unclear`, and `unclear` does not stop anything.
test('out-of-scope with no clause is NEEDS MORE INFO, not a halt', () => {
  for (const clause of [undefined, '', '   ']) {
    const r = scopeHalt({ ...IN_SCOPE, verdict: 'out-of-scope', clause })
    assert.equal(r.status, 'NEEDS_MORE_INFO', `clause ${JSON.stringify(clause)} must not close the finding`)
    assert.match(r.reason, /unclear/)
  }
})

test('a dead scope agent blocks rather than continuing on no verdict', () => {
  const r = scopeHalt(null)
  assert.equal(r.status, 'BLOCKED')
  assert.ok(r.reason.trim())
})

// ---------------------------------------------------------- summaryProblem

const SUMMARY = {
  finalSeverity: 'High',
  scopeVerdict: 'in-scope',
  reasoning: 'matches the in-scope list and no past report covers it',
  confidence: 'medium',
  openQuestions: 'the rubric does not say how it rates unauthenticated reads',
  evidence: 'the policy and three searches',
}

test('a complete summary is not a problem', () => {
  assert.equal(summaryProblem(SUMMARY), null)
})

test('an empty openQuestions is rejected: an omitted gap reads as a settled question', () => {
  for (const openQuestions of [undefined, '', '   ']) {
    assert.ok(summaryProblem({ ...SUMMARY, openQuestions }), JSON.stringify(openQuestions))
  }
})

test('an empty reasoning is rejected', () => {
  for (const reasoning of [undefined, '', '   ']) {
    assert.ok(summaryProblem({ ...SUMMARY, reasoning }))
  }
})

test('a dead summary agent is a problem', () => {
  assert.ok(summaryProblem(null))
})

// --------------------------------------------------- the gates, where used

const agents = (over = {}) => ({
  policy: READ,
  reachability: { ...IN_SCOPE, verdict: 'unclear', clause: '', evidence: 'reachable from /search' },
  inscope: IN_SCOPE,
  'past-bugs': {
    result: 'nothing',
    coverage: 'searched all 3 pages of the advisory list',
    recommendedSeverity: 'Unknown',
    duplicate: false,
    evidence: 'no similar advisory',
  },
  summary: SUMMARY,
  ...over,
})

test('the happy path reaches TRIAGED through every role', async () => {
  const { result, calls } = await runScript('triage-online.js', { args: GOOD, agents: agents() })
  assert.equal(result.status, 'TRIAGED')
  for (const label of ['policy', 'reachability', 'inscope', 'summary']) {
    assert.ok(calls.some((c) => c.label === label), `${label} must be dispatched`)
  }
  assert.ok(calls.some((c) => c.label === 'past-bugs:github-advisories'))
})

// The measured failure this whole stage is built against: without the gate, an
// offline agent still has a prompt asking for a scope verdict, and it answers.
test('an offline policy agent halts before a single scope claim is made', async () => {
  const { result, calls } = await runScript('triage-online.js', {
    args: GOOD,
    agents: agents({ policy: { ...READ, reachedNetwork: false, sourcesRead: 'no network' } }),
  })
  assert.equal(result.status, 'OFFLINE')
  assert.ok(
    !calls.some((c) => c.label === 'inscope'),
    'no scope verdict may be formed without a document to form it from',
  )
  assert.ok(!calls.some((c) => c.label === 'summary'))
})

test('a dead policy agent halts the same way', async () => {
  const { result } = await runScript('triage-online.js', { args: GOOD, agents: agents({ policy: null }) })
  assert.equal(result.status, 'OFFLINE')
})

test('an out-of-scope verdict halts before the past-bug fan-out is paid for', async () => {
  const { result, calls } = await runScript('triage-online.js', {
    args: GOOD,
    agents: agents({
      inscope: { ...IN_SCOPE, verdict: 'out-of-scope', clause: '"the search module is out of scope"' },
    }),
  })
  assert.equal(result.status, 'OUT_OF_SCOPE')
  assert.ok(!calls.some((c) => c.label.startsWith('past-bugs:')))
})

test('an unclaused out-of-scope does not halt the finding', async () => {
  const { result } = await runScript('triage-online.js', {
    args: GOOD,
    agents: agents({ inscope: { ...IN_SCOPE, verdict: 'out-of-scope', clause: '' } }),
  })
  assert.equal(result.status, 'NEEDS_MORE_INFO')
  assert.match(result.reason, /unclear/)
})

test('a confirmed public duplicate is reported as one', async () => {
  const { result } = await runScript('triage-online.js', {
    args: GOOD,
    agents: agents({
      'past-bugs': {
        result: 'similar-bugs-found',
        coverage: 'all pages',
        links: 'GHSA-xxxx-yyyy-zzzz',
        similarity: 'same trigger, same actor, same component',
        recommendedSeverity: 'High',
        duplicate: true,
        evidence: 'identical report',
      },
    }),
  })
  assert.equal(result.status, 'DUPLICATE')
  assert.match(result.reason, /GHSA-/)
})

// A source whose agent died was NOT searched, and "not searched" summarised as
// "nothing found there" is how an absent duplicate check becomes a clean bill of
// health. Reported rather than fatal: the other sources are still evidence.
test('a dead source agent is reported to the summary as unchecked', async () => {
  const sources = [
    { label: 'github-advisories', query: 'a' },
    { label: 'mailing-list', query: 'b' },
  ]
  const { result, calls } = await runScript('triage-online.js', {
    args: { ...GOOD, sources },
    agents: agents({
      'past-bugs': (prompt) =>
        prompt.includes('mailing-list')
          ? null
          : {
              result: 'nothing',
              coverage: 'all pages',
              recommendedSeverity: 'Unknown',
              duplicate: false,
              evidence: 'none',
            },
    }),
  })
  assert.equal(result.status, 'TRIAGED')
  assert.deepEqual(result.unsearched, ['mailing-list'])
  const summary = calls.find((c) => c.label === 'summary')
  assert.match(summary.prompt, /NOT searched/)
  assert.match(summary.prompt, /mailing-list/)
})

test('the past-bug fan-out is capped, and what was dropped is logged', async () => {
  const sources = Array.from({ length: 9 }, (_, i) => ({ label: `src-${i}`, query: `q${i}` }))
  const { calls, logs } = await runScript('triage-online.js', {
    args: { ...GOOD, sources },
    agents: agents(),
  })
  const searched = calls.filter((c) => c.label.startsWith('past-bugs:'))
  assert.equal(searched.length, 6, 'MAX_SOURCES bounds the fan-out')
  // A silent cap reads as "covered everything".
  assert.ok(logs.some((l) => l.includes('NOT searched')), `the drop must be logged; logs were: ${logs}`)
})

test('a bad arg shape returns BLOCKED without spending an agent', async () => {
  const { result, calls } = await runScript('triage-online.js', {
    args: { ...GOOD, sources: [] },
    agents: agents(),
  })
  assert.equal(result.status, 'BLOCKED')
  assert.equal(calls.length, 0)
})

test('an incomplete summary is NEEDS MORE INFO, not a triage result', async () => {
  const { result } = await runScript('triage-online.js', {
    args: GOOD,
    agents: agents({ summary: { ...SUMMARY, openQuestions: '' } }),
  })
  assert.equal(result.status, 'NEEDS_MORE_INFO')
})

test('every gate function is extractable: a rename must fail loudly', () => {
  const names = ['missingArgs', 'offlineProblem', 'scopeHalt', 'summaryProblem']
  const loaded = loadFns(ONLINE, ...names)
  for (const name of names) {
    assert.equal(typeof loaded[name], 'function', `${name} is not extractable`)
  }
})
