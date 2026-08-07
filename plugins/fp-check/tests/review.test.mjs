import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

import { loadFn, runScript, script } from './extract.mjs'

const REVIEW = script('triage-poc.js')
const confidenceBand = loadFn(REVIEW, 'confidenceBand')
const tallyChallenges = loadFn(REVIEW, 'tallyChallenges')
const severityCapViolation = loadFn(REVIEW, 'severityCapViolation')
const alreadyFixedStands = loadFn(REVIEW, 'alreadyFixedStands')
const artifactProblem = loadFn(REVIEW, 'artifactProblem')
const reportProblem = loadFn(REVIEW, 'reportProblem')
const settledByStageOne = loadFn(REVIEW, 'settledByStageOne')

const REVIEW_SRC = readFileSync(REVIEW, 'utf8')
const SKILL_MD = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), '..', 'skills', 'fp-check', 'SKILL.md'),
  'utf8',
)

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

// `confidenceBand` hardcoded `defeated === 5` for HIGH while every other consumer
// used CHALLENGES.length. Correct today and silently wrong the moment a sixth
// challenge is added: HIGH becomes unreachable and every perfect review reports
// MEDIUM. `total` is a defaulted parameter rather than a reference to the const,
// because the tests evaluate this function alone where a free variable throws.
test('the band scales with the challenge count instead of hardcoding it', () => {
  assert.equal(confidenceBand(5, 5).label, 'HIGH')
  assert.equal(confidenceBand(6, 6).label, 'HIGH', 'a sixth challenge must not make HIGH unreachable')
  assert.equal(confidenceBand(5, 6).label, 'MEDIUM', 'and one lost is no longer HIGH')
  assert.equal(confidenceBand(5).label, 'HIGH', 'the default still matches todays five')
})

// ------------------------------------- Stage 1 settled it: no exploit is owed
//
// The measured failure this covers is not a code bug. Stage 3 refused correctly;
// the orchestrator, still holding a user request for a PoC, then built the
// exploit by hand and its final answer hedged — reproducing, verbatim, the
// sentence the no-plugin baseline arm produces on the same case. Refusal has no
// degraded mode, so when the user has asked for a PoC the model sides with the
// user and reverts to unguarded behaviour wholesale.
//
// Nothing below relaxes the gate. The exploit is refused exactly as before; what
// changed is that the refusal now reads as an ANSWER ABOUT THE FINDING rather
// than as a complaint about the caller's arguments, and it names the deliverable
// that replaces the PoC.

const SETTLED = [
  'FALSE_POSITIVE',
  'DISMISSED',
  'NOT_EXPLOITABLE',
  'NOT_VULNERABLE',
  'ALREADY_FIXED',
  'OUT_OF_SCOPE',
]

// Read out of the script rather than trusted: this list is the join between the
// gate and the reporting table in SKILL.md, and a status added to one of the
// three without the other two is exactly the drift that produces a verdict with
// no documented way to say it.
test('the settled list these tests grade is the list the script branches on', () => {
  const literal = /const settled = \[([\s\S]*?)\]/.exec(REVIEW_SRC)
  assert.ok(literal, 'settledByStageOne no longer declares a `settled` array; this section is stale')
  const inScript = [...literal[1].matchAll(/'([A-Z_]+)'/g)].map((m) => m[1])
  assert.ok(inScript.length > 0, 'the array literal is empty; this test is grading nothing')
  assert.deepEqual(new Set(inScript), new Set(SETTLED))
})

test('every terminal Stage 1 verdict is recognised as settled, with its reason', () => {
  for (const status of SETTLED) {
    const s = settledByStageOne({ verification: { status, reason: 'blocked at the allowlist' } })
    assert.ok(s, `${status} is a verdict and must be recognised as one`)
    assert.equal(s.status, status)
    assert.equal(s.reason, 'blocked at the allowlist')
  }
})

test('TRUE_POSITIVE is not settled — it is the one status that builds', () => {
  assert.equal(settledByStageOne({ verification: { status: 'TRUE_POSITIVE' } }), null)
})

// The distinction the whole section rests on. NEEDS_MORE_INFO is a fact still to
// establish and BLOCKED is an analysis that could not run; neither is an answer,
// and SKILL.md's own history records that rounding either to FALSE POSITIVE
// killed a real finding. They must keep the arg gate's "go back and fix it"
// message rather than acquiring a reporting template.
test('NEEDS_MORE_INFO and BLOCKED are not settled: they are re-run, not reported', () => {
  for (const status of ['NEEDS_MORE_INFO', 'BLOCKED']) {
    assert.equal(
      settledByStageOne({ verification: { status } }),
      null,
      `${status} is not a verdict and must not be reportable as one`,
    )
  }
})

test('an unrecognised status falls through to the arg gate rather than settling', () => {
  for (const status of ['', 'PROCEED', 'REPORTED', 'not_exploitable', 'TRIAGED', 'anything']) {
    assert.equal(
      settledByStageOne({ verification: { status } }),
      null,
      `${JSON.stringify(status)} must not be treated as a verdict`,
    )
  }
})

test('a surrounding-whitespace status is still the verdict it names', () => {
  const s = settledByStageOne({ verification: { status: '  ALREADY_FIXED\n' } })
  assert.ok(s)
  assert.equal(s.status, 'ALREADY_FIXED', 'the trimmed name is what SKILL.md is keyed on')
})

test('an absent verification neither throws nor settles', () => {
  for (const a of [undefined, null, {}, { verification: null }, { verification: {} }, 'nonsense']) {
    assert.equal(settledByStageOne(a), null)
  }
})

// Trimmed for the reason every other relayed string in this script is trimmed:
// `reason: '   '` is truthy and would reach the orchestrator as a verdict that
// explains itself with blank space.
test('a whitespace reason becomes empty rather than being relayed as one', () => {
  for (const reason of [undefined, '', '   ', '\n\t']) {
    assert.equal(settledByStageOne({ verification: { status: 'DISMISSED', reason } }).reason, '')
  }
})

// ------------------------------------------------- the same gate, wired up

const SETTLED_ARGS = {
  baseDir: '/plugin/skills/fp-check',
  finding: { summary: '`==` on session tokens is a timing oracle', sink: 'session.py:88' },
  verification: {
    status: 'ALREADY_FIXED',
    reason: 'already fixed by #412 — the caller reduces both operands to a keyed HMAC digest',
    impact: { impact: 'token forgery', rootCause: 'internal', classification: 'vulnerability' },
    severity: 'High',
    history: { fixed: 'YES', searched: 'git log -p -- session.py auth.py, CHANGELOG' },
  },
  envelope: { hosts: [], level: 1, destructive: false },
  candidates: [{ description: 'timing oracle', entryPoint: 'POST /login', payload: 'a'.repeat(32) }],
}

const BUILT_POC = {
  built: true,
  executed: true,
  lintPassed: true,
  pocType: 'standalone',
  path: 'poc/x.py',
  absolutePath: '/wt/poc/x.py',
  command: 'python3 /wt/poc/x.py',
  output: 'forged',
  invokedSymbol: 'SessionStore.validate',
}

test('a settled finding spends nothing and is not reported as a bad dispatch', async () => {
  for (const status of SETTLED) {
    const { result, calls } = await runScript('triage-poc.js', {
      args: { ...SETTLED_ARGS, verification: { ...SETTLED_ARGS.verification, status } },
      agents: { build: BUILT_POC },
    })
    assert.equal(result.status, 'BLOCKED', `${status} must not buy a build`)
    assert.equal(calls.length, 0, 'nothing may be spent on a finding Stage 1 already settled')
    assert.equal(result.settledBy, status, 'the orchestrator branches on this field')
    assert.match(result.reason, new RegExp(status), 'the reason must name the verdict it relays')
    // The old message. It sent the orchestrator back to correct a dispatch that
    // was correct, and when that failed it built the exploit by hand instead.
    assert.doesNotMatch(
      result.reason,
      /unusable arg shape|forward triage-static/i,
      'a settled finding is not a defective dispatch and must not be described as one',
    )
    assert.ok(result.deliverable && result.deliverable.trim(), 'the refusal must name what replaces the PoC')
  }
})

test('the relayed reason carries Stage 1s own evidence, not just its status', async () => {
  const { result } = await runScript('triage-poc.js', { args: SETTLED_ARGS, agents: {} })
  assert.match(result.reason, /#412/, "Stage 1's reason is the deciding evidence and must survive")
})

// A dispatch carrying only a settled verification is the shape the arg gate
// handles worst: it answers with a dozen field names and buries the one fact
// that matters. The verdict outranks them because nothing below it runs either
// way.
test('a settled verdict outranks a malformed dispatch', async () => {
  const { result, calls } = await runScript('triage-poc.js', {
    args: { verification: { status: 'NOT_EXPLOITABLE', reason: 'blocked at ALLOWED_TERM' } },
    agents: { build: BUILT_POC },
  })
  assert.equal(result.settledBy, 'NOT_EXPLOITABLE')
  assert.match(result.reason, /ALLOWED_TERM/)
  assert.equal(calls.length, 0)
})

// The converse, and the guard that the new branch did not swallow the arg gate:
// a status that is NOT a verdict must still get the message that sends the
// caller back.
test('a malformed dispatch Stage 1 did not settle still reports its missing fields', async () => {
  for (const status of ['TRUE_POSITIVE', 'NEEDS_MORE_INFO']) {
    const { result, calls } = await runScript('triage-poc.js', {
      args: { verification: { status } },
      agents: { build: BUILT_POC },
    })
    assert.equal(result.status, 'BLOCKED')
    assert.equal(result.settledBy, undefined, 'this one IS a bad dispatch')
    assert.match(result.reason, /unusable arg shape/)
    assert.equal(calls.length, 0)
  }
})

// --------------------------------------------- SKILL.md has to be able to say it
//
// A gate that produces a verdict the orchestrator has no documented way to
// report is a gate that gets talked around. These tie the prose to the code.

function skillSection(titleMatcher) {
  const section = SKILL_MD.split(/^## /m).find((part) => titleMatcher.test(part.split('\n')[0]))
  assert.ok(section, `SKILL.md has no "## " section whose heading matches ${titleMatcher}`)
  return section
}

test('SKILL.md documents every status triage-poc can return', () => {
  const returned = new Set([...REVIEW_SRC.matchAll(/status: '([A-Z_]+)'/g)].map((m) => m[1]))
  assert.ok(returned.size >= 5, `only found ${returned.size} returned statuses; this scan is stale`)
  for (const status of returned) {
    assert.ok(
      SKILL_MD.includes(`\`${status}\``),
      `triage-poc can return ${status} and SKILL.md never mentions it, so the orchestrator ` +
        `has no documented way to report it. ALREADY_FIXED and NEEDS_MORE_INFO were both live ` +
        `and both absent from the Stage 3 returns list.`,
    )
  }
})

test('SKILL.md gives every settled verdict an opening line to report it with', () => {
  const section = skillSection(/asked for a PoC/i)
  for (const status of SETTLED) {
    assert.ok(
      section.includes(`\`${status}\``),
      `Stage 3 refuses on ${status} and the refusal section does not say how to report it`,
    )
  }
})

test('the refusal section forbids hand-building and bounds the negative PoC', () => {
  const section = skillSection(/asked for a PoC/i)
  assert.match(section, /by hand/i, 'hand-building after a refusal is the failure mode; name it')
  assert.match(section, /negative PoC/i, 'the legitimate alternative has to be named to be used')
  assert.match(
    section,
    /entry point/i,
    'an unbounded negative PoC is an exploit; it has to be pinned to the entry point',
  )
  assert.match(section, /settledBy/, 'the field the orchestrator branches on must be documented')
})

test('the retraction wording leaves no room to hedge', () => {
  const section = skillSection(/asked for a PoC/i)
  assert.match(section, /do not pay/i)
  // The measured hedge, kept as the counter-example. It is verbatim what the arm
  // with no plugin answers, and three runs that had FOUND the fix still wrote it.
  // Seam-tolerant, per this suite's own lesson about literal multi-word phrases:
  // every inter-word position in prose is a place a line wrap or an emphasis
  // marker can land, and the first draft of this assertion failed on a newline.
  assert.match(
    section,
    /already[-\s*_`]+fixed[-\s*_`]+on[-\s*_`]+current[-\s*_`]+HEAD/i,
    'the baseline sentence is the thing being ruled out; deleting the example deletes the rule',
  )
})
