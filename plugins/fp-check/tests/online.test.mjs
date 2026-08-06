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
// life. NEEDS_MORE_INFO is the one Stage 2 can still move: Stage 1 reaches it both
// before and after the impact agent, so its payload sometimes carries the impact
// this stage requires.
test('only an actionable Stage 1 status is accepted', () => {
  for (const status of ['TRUE_POSITIVE', 'NEEDS_MORE_INFO']) {
    const problems = missingArgs({ ...GOOD, verification: { ...GOOD.verification, status } })
    assert.deepEqual(problems, [], `${status} must be accepted`)
  }
  for (const status of ['DISMISSED', 'NOT_EXPLOITABLE', 'NOT_VULNERABLE', 'FALSE_POSITIVE', 'ALREADY_FIXED', 'OUT_OF_SCOPE', 'BLOCKED', '', undefined]) {
    const problems = missingArgs({ ...GOOD, verification: { ...GOOD.verification, status } })
    assert.ok(
      problems.some((p) => p.startsWith('verification.status')),
      `${JSON.stringify(status)} must be rejected`,
    )
  }
})

// Stage 1's own OUT_OF_SCOPE payload, run through Stage 2's validator. Not a
// hand-built fixture: the two scripts have to agree about a value one of them
// produces and the other consumes, and a fixture can be written to agree with
// either.
//
// The status was on the actionable list on the reasoning that "a DECLARED scope is
// exactly what a published policy can overturn" — but Stage 1 decides OUT_OF_SCOPE
// in `decideGate`, before the impact agent is ever dispatched, so the payload it
// returns has no `impact` and no `severity` and Stage 2 requires both. Every
// dispatch the list invited was therefore rejected by the next four lines of the
// same function, and the rejection listed OUT_OF_SCOPE among the statuses it
// accepts.
test('a Stage 1 OUT_OF_SCOPE payload is rejected coherently, not invited and then refused', async () => {
  const staticRun = await runScript('triage-static.js', {
    args: {
      baseDir: '/plugin/skills/fp-check',
      finding: {
        summary: 'unauthenticated read of arbitrary tables',
        sink: 'search.py:34',
        component: 'the search module',
        claimedImpact: 'database contents disclosed',
        bugClass: 'injection',
        threatModel: 'an unauthenticated caller supplies a crafted filter',
      },
      entryPoint: { description: 'GET /search', location: 'search.py:8', payload: "f=1' OR 1=1--" },
      layers: [{ name: 'filter-allowlist', location: 'search.py:14', checks: 'the filter is matched' }],
      scope: 'the API surface, excluding internal tooling',
    },
    agents: {
      brocard: { verdict: 'PASS', missingFact: '', evidence: 'fine' },
      layer: { verdict: 'PASSES', evidence: 'the filter reaches the query' },
      recovery: { recoveryExists: false, effectiveImpact: 'rows disclosed', evidence: 'no recover' },
      'threat-model': {
        inScope: 'NO',
        byDesign: false,
        byDesignIndicators: 0,
        evidence: 'internal tooling is excluded by the declared scope',
      },
      history: { fixed: 'NO', complete: false, reference: '', searched: 'git log -p', evidence: 'nothing' },
    },
  })
  assert.equal(staticRun.result.status, 'OUT_OF_SCOPE', 'the fixture must actually be a Stage 1 OUT_OF_SCOPE')
  assert.equal(staticRun.result.severity, undefined, 'and it is decided before any severity exists')

  const problems = missingArgs({ ...GOOD, verification: staticRun.result })
  const rejection = problems.find((p) => p.startsWith('verification.status'))
  assert.ok(rejection, 'Stage 2 must not offer a status whose only possible payload it rejects')
  // The accepted list, not the whole message: naming the status it RECEIVED is the
  // useful half of the rejection. Listing it as acceptable is the incoherent half.
  const accepted = rejection.slice(0, rejection.indexOf('; got'))
  assert.ok(
    !accepted.includes('OUT_OF_SCOPE'),
    `the rejection lists the status it just refused as acceptable: ${accepted}`,
  )
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

// The one agent result in this script that nothing guarded. `policy` has
// offlineProblem, `scope` has scopeHalt, `summary` has summaryProblem — and
// `reachability.evidence` is interpolated straight into the scope prompt, so a dead
// reachability agent threw a TypeError out of the workflow instead of returning a
// status. An exception is not a fail-closed outcome: the orchestrator is left
// holding a user request with no verdict, which is the documented shape of this
// plugin's worst measured failure (the gate stops, the orchestrator triages by
// hand outside it).
test('a dead reachability agent returns BLOCKED rather than throwing', async () => {
  for (const dead of [null, undefined]) {
    const { result, calls } = await runScript('triage-online.js', {
      args: GOOD,
      agents: agents({ reachability: dead }),
    })
    assert.equal(result.status, 'BLOCKED', `reachability ${JSON.stringify(dead)}`)
    assert.match(result.reason, /reachability/)
    assert.ok(
      !calls.some((c) => c.label === 'inscope'),
      'no scope verdict may be formed against a reachability finding that does not exist',
    )
  }
})

// A duplicate is a fact one of the past-bug agents established, with a link. The
// summary's job is to write it up; its failure cannot unmake it. Ordered the other
// way round, a summary that left openQuestions empty — the single most likely
// summary defect, which is why the gate exists — turned "this is already publicly
// reported at GHSA-x" into "needs more info", and the next reader pays for the
// whole stage again to be told the same thing.
test('a confirmed duplicate survives a summary that fails its own gate', async () => {
  for (const summary of [{ ...SUMMARY, openQuestions: '' }, null]) {
    const { result } = await runScript('triage-online.js', {
      args: GOOD,
      agents: agents({
        summary,
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
    assert.equal(result.status, 'DUPLICATE', `summary ${JSON.stringify(summary)}`)
    assert.match(result.reason, /GHSA-/)
  }
})

// The citation a retraction is relayed with, and `required` checks presence and not
// content: `links: '   '` is schema-valid and truthy, so it displaced the `evidence`
// it was meant to fall back to and DUPLICATE came back citing blank space.
test('a whitespace links field falls back to the evidence, not to nothing', async () => {
  const { result } = await runScript('triage-online.js', {
    args: GOOD,
    agents: agents({
      'past-bugs': {
        result: 'similar-bugs-found',
        coverage: 'all pages',
        links: '   ',
        similarity: 'same trigger, same actor',
        recommendedSeverity: 'High',
        duplicate: true,
        evidence: 'filed as issue 1204 in 2019',
      },
    }),
  })
  assert.equal(result.status, 'DUPLICATE')
  assert.match(result.reason, /issue 1204/)
})

// Over-cap sources are dropped silently as far as every consumer is concerned: the
// cap is logged, and the log is not evidence anyone downstream reads. The summary
// agent is handed "N of M sources returned a result" with the dropped venues absent
// from both numbers, so an unsearched venue reads as a searched one — the same
// "absent duplicate check becomes a clean bill of health" the dead-agent list above
// exists to prevent, arriving by a different route.
test('sources dropped by the cap are declared unchecked, not silently omitted', async () => {
  const sources = Array.from({ length: 8 }, (_, i) => ({ label: `src-${i}`, query: `q${i}` }))
  const { result, calls } = await runScript('triage-online.js', {
    args: { ...GOOD, sources },
    agents: agents(),
  })
  assert.equal(result.status, 'TRIAGED')
  assert.deepEqual(result.beyondCap, ['src-6', 'src-7'], 'the payload must name what was never dispatched')
  const summary = calls.find((c) => c.label === 'summary')
  assert.match(summary.prompt, /src-6/)
  assert.match(summary.prompt, /src-7/)
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
