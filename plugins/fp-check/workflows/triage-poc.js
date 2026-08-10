export const meta = {
  name: 'triage-poc',
  description:
    'Stage 3: build a working PoC against the real code, execute it, then have five agents that did not build it try to reject it, and derive the confidence band',
  whenToUse:
    'Only when the user asked to validate by PoC, and only after triage-static returned TRUE_POSITIVE. Builds in an isolated worktree; every challenge is judged by an agent that did not build the PoC.',
  phases: [{ title: 'Build' }, { title: 'Challenges' }, { title: 'Report' }],
}

// args: { baseDir, finding, verification, envelope, candidates[] }
//
// `verification` is triage-static's return value, forwarded verbatim.
//
// Build and review are one script rather than two because the PoC is the only
// thing that crosses between them, and as two dispatches that hand-off was a
// standing hazard: build-poc's gate and review-poc's arg validator had to agree
// on eight field names by hand, and twice they did not — a builder returning
// whitespace for `path` or `pocType` returned BUILT and was then rejected
// downstream, discarding a Phase 4 that had already been paid for.

// `args || {}`: an absent args object makes this destructure throw before
// missingArgs can return BLOCKED.
const { baseDir, finding, verification, envelope, candidates = [] } = args || {}

const MAX_ATTEMPTS = 2

const POC_SCHEMA = {
  type: 'object',
  // Extra keys are rejected rather than accepted and ignored: a builder that
  // returns a field this script never contracted for means the prompt and the
  // schema have drifted, and silently dropping it hides which one is stale.
  additionalProperties: false,
  // EVERY field isAcceptableBuild gates on is required. Being named in the
  // prompt is a request; `required` is enforced by the runtime validator, which
  // retries the agent until it complies. Omit one and a PoC that built, executed
  // and linted clean fails the gate, burns the retry, and comes back as
  // BUILD_FAILED. A failed build satisfies these with empty strings, which the
  // gate reads as falsy anyway, so requiring them costs a failure nothing.
  required: [
    'built',
    'pocType',
    'path',
    'absolutePath',
    'executed',
    'lintPassed',
    'command',
    'output',
    'invokedSymbol',
  ],
  properties: {
    built: { type: 'boolean' },
    pocType: { enum: ['test-integrated', 'standalone', 'testnet'] },
    path: { type: 'string', description: 'repo-relative path to the PoC' },
    absolutePath: {
      type: 'string',
      description:
        'absolute path to the PoC file; the builder runs in an isolated worktree, so a repo-relative path does not resolve for the reviewers',
    },
    command: { type: 'string', description: 'exact command that runs it' },
    executed: { type: 'boolean' },
    outputPath: { type: 'string', description: 'file holding the captured run output' },
    output: { type: 'string', description: 'the captured output itself, verbatim' },
    invokedSymbol: { type: 'string', description: 'the real symbol under test that the PoC calls' },
    lintPassed: { type: 'boolean' },
    failureReason: { type: 'string', description: 'set when built is false' },
  },
}

const CHALLENGE_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['challenge', 'rebuttal', 'winner', 'evidence', 'reference', 'complete'],
  properties: {
    challenge: { type: 'string', description: 'the strongest argument against the finding' },
    rebuttal: { type: 'string', description: 'the evidence-based answer, or why there is none' },
    winner: { enum: ['CHALLENGE', 'REBUTTAL'] },
    evidence: { type: 'string' },
    // Challenge 4's win RETRACTS the finding, so it has to point at something —
    // and `evidence` cannot be that something, because every one of the five
    // challenges is required to fill it, so a non-blank check on it is satisfied
    // by any prose at all ("the sink was rewritten during a later refactor").
    // Same field, same rule and same reason as HISTORY_SCHEMA's `reference` one
    // workflow over: required so the model is asked, empty when there is nothing
    // to cite, and `alreadyFixedStands` reads it rather than the prose.
    reference: {
      type: 'string',
      description: 'challenge 4 only: the commit, PR, issue or advisory ID for the fix. Empty for the other four',
    },
    // Required for the same reason `reference` is, and against the same failure:
    // `alreadyFixedStands` retracted on ANY cited award, so a fix that touched
    // one of two sinks discarded a demonstrated, still-live bug whole. The
    // prompt asked for complete-or-partial and the schema had nowhere to put it,
    // so the answer arrived as prose and nothing read it. Required, because an
    // omitted boolean is `undefined`, which is not `false`, and the gate below
    // reads anything but an affirmative `true` as partial — with the field
    // optional that would silently switch the retraction off instead.
    complete: {
      type: 'boolean',
      description: 'challenge 4 only: true only if the fix is WHOLE. false for a partial fix and for the other four',
    },
    impactCorrection: { type: 'string', description: 'set if the true impact is weaker than claimed' },
  },
}

// A workflow script has no Bash, so nothing here can confirm the linter ran or
// the PoC executed — `built`, `executed` and `lintPassed` are three booleans the
// builder fills in itself. This agent is what makes "enforced by poc-lint.sh,
// not by good intentions" true: it has Bash and, because the builder reports
// absolutePath, it has a file it can actually open.
const ARTIFACT_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['fileExists', 'lintExitZero', 'reimplementation', 'evidence'],
  properties: {
    fileExists: { type: 'boolean' },
    lintExitZero: { type: 'boolean', description: 'poc-lint.sh exited 0 when YOU ran it' },
    lintOutput: { type: 'string' },
    // Principle 5, and the ONLY place it is decided. poc-lint.sh's
    // `possible-reimplementation` is a NOTE that exits 0, because a grep cannot
    // tell a façade re-export, a pytest fixture or a local driver from a copy of
    // the target — made fatal it returned BUILD_FAILED on all three. Demoting it
    // without putting the question anywhere left nothing enforcing Principle 5
    // at all: a PoC that pastes the vulnerable function in and exercises the copy
    // passes the note AND rule 8, because the copy's own definition supplies the
    // mention. This agent has Bash and both files, so it is the one reader that
    // can answer it; `artifactProblem` reads the answer.
    //
    // Required, and graded affirmatively below: an omitted or unrecognised value
    // is not a clearance. Three values rather than a boolean because the note
    // names three outcomes and "false" would collapse "no definition at all" with
    // "a definition I checked and cleared".
    reimplementation: {
      enum: ['NOT_DEFINED', 'LOCAL_DRIVER', 'COPY_OF_TARGET'],
      description:
        'does the PoC contain a copy of the code under test, under ANY name? NOT_DEFINED: it holds no copy and calls the imported symbol. LOCAL_DRIVER: it defines that name but the body is not the target\'s logic. COPY_OF_TARGET: the vulnerable logic was pasted in, whatever it was renamed to',
    },
    reRunSucceeded: { type: 'boolean', description: 'the PoC command ran and reproduced the impact' },
    reRunNotes: { type: 'string' },
    evidence: { type: 'string' },
  },
}

const REPORT_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['severity', 'severityRationale', 'reportPath', 'unproven'],
  properties: {
    severity: { enum: ['Critical', 'High', 'Medium', 'Low', 'Informational'] },
    severityRationale: { type: 'string' },
    reportPath: { type: 'string' },
    unproven: { type: 'string', description: 'what this PoC does not establish' },
  },
}

// Checkpoint 5.1 asks the author to write both the challenge and the rebuttal and
// then declare a winner. The author awards the rebuttal. These five are the same
// questions, judged by agents that never saw the PoC being built, so the verdict
// is a verdict rather than a formality.
const CHALLENGES = [
  {
    key: 'reachable',
    prompt: `Challenge 1. Argue that the attacker CANNOT reach the vulnerable code.
Look for validation, authorization, or routing that the PoC's setup bypasses
artificially — a test fixture that constructs state no real caller could reach is
the usual way this finding is wrong.

This is the challenge that separates a real finding from the most common false
positive there is, so hold it to the entry point rather than to the sink. A PoC
that calls the vulnerable function directly genuinely demonstrates attacker
control OF THE SINK; that is not control of any reachable entry point. Measured:
every baseline run on a case built exactly that PoC, exfiltrated seeded
credentials, and reported a confirmed injection — while the guard at the entry
point rejected the payload outright.`,
  },
  {
    key: 'recoverable',
    prompt: `Challenge 2. Argue that the impact is LESS than claimed.
Read ${baseDir}/references/recovery-mechanisms.md. Check the runtime's actual
recovery behaviour rather than assuming none. Two facts flip a Critical to a Low
more often than any others: Go's net/http recovers per-connection in conn.serve,
so a handler panic closes that one connection and writes no status — it is not a
500 and not a dead server; and recover() does not cross goroutine boundaries. If
the true impact is weaker, set impactCorrection.`,
  },
  {
    key: 'by-design',
    prompt: `Challenge 3. Argue that this is INTENDED behaviour.
Read ${baseDir}/references/validation-dimensions.md. Check privilege indicators,
symmetric guarded/unguarded sibling paths, and whether documentation or tests
cover it as normal operation. Centralized control is not by itself a bug.

Also apply the specified- and documented-behaviour grounds from
${baseDir}/references/dismissal-grounds.md: behaviour a
specification requires, or that the project documents and warns about, is not a
bug in this project. Both carry a nuance that inverts them — an implementation
claiming stricter behaviour than the spec, and downstream code violating
documented guidance — so check those before awarding the challenge.`,
  },
  {
    key: 'already-fixed',
    prompt: `Challenge 4. Argue that this is ALREADY FIXED.
Search the git log for the relevant paths, the issue tracker, release notes, and
published advisories. Report what you searched and what you found. If a fix
exists, set \`complete\`: true only if it closes the finding outright, false if
it leaves any part of it live — a second sink, one caller of two, a narrower
input class.

Stage 1 ran this search too, and its result is quoted above. You are not
repeating it for its own sake: a fix landing one layer up from the sink is the
shape that gets missed, and you are looking at a built, executed PoC that Stage 1
did not have. If the PoC passes against HEAD, that is evidence; say so.

Awarding this challenge on a WHOLE fix retracts the finding outright, so it has
to point at something: put the commit, PR, issue or advisory ID in \`reference\`,
on its own and not merely described in \`evidence\`. Both conditions are enforced
in code and neither is refused quietly. A \`complete\`: true win whose
\`reference\` is not a citation — blank, \`n/a\`, \`see evidence\`, a bare
file:line — ENDS THE STAGE as NEEDS_MORE_INFO, so award it that way only if you
can name the fix. A win on a partial fix does not retract and does not end
anything: the finding is reported, with the partial fix recorded against it.`,
  },
  {
    key: 'real-deployment',
    prompt: `Challenge 5. Argue that this is NOT exploitable in real deployments.
Is the vulnerable path reachable in a default configuration? Do real deployments
add protections in front of it — a proxy, a WAF, a non-default flag? Is the code
path ever actually used?`,
  },
]

// Pure. The Stage 1 statuses that are a SETTLED ANSWER rather than a defective
// dispatch: the finding was analysed and did not survive.
//
// It exists because the arg gate below is right about the outcome and wrong
// about the reason, and the wrong reason is what the plugin's most expensive
// failure mode feeds on. A settled finding used to come back as "triage-poc
// received an unusable arg shape: verification.status (...). Forward
// triage-static's return value verbatim" — a complaint about the CALLER, on a
// dispatch where the caller did everything right. The orchestrator is still
// holding a user request for a PoC, reads that as "your dispatch was wrong, try
// again", finds it cannot be made right, and builds the exploit by hand
// instead. Traced, verbatim: "the downstream PoC-workflow's hard gate then
// refused to run without a literal TRUE_POSITIVE string from that stage, so I
// built and executed the PoC directly instead, per your explicit request."
//
// The behaviour it reverts to is measured, not hypothetical: three no-plugin
// runs on `dead-route` wrote a PoC calling the sink directly, executed real
// command injection, and led with "Confirmed command injection" before noting
// the route does not exist.
//
// So this path builds nothing, spends nothing and relaxes nothing — the exploit
// is refused exactly as before. It states the refusal in terms of the finding
// rather than in terms of the arguments, and names the deliverable that takes
// the PoC's place.
//
// NEEDS_MORE_INFO and BLOCKED are deliberately NOT here. Neither is an answer:
// one is a fact still to establish, the other an analysis that could not run,
// and both are resolved by re-running Stage 1 rather than by writing anything
// up. They keep the arg gate's message, which is the one that tells the caller
// to go back. An unrecognised status is absent for the reason a fall-through
// pass is wrong everywhere else in this plugin.
//
// The list is inline rather than hoisted to a const: the tests extract this
// function and evaluate it alone, where a free variable is a ReferenceError.
// review.test.mjs pins the literal against the statuses SKILL.md tells the
// orchestrator how to report, so the two cannot drift.
function settledByStageOne(a) {
  const verification = (a && a.verification) || {}
  const status = typeof verification.status === 'string' ? verification.status.trim() : ''
  // DISMISSED was here until nothing emitted it: it was the removed brocard
  // pre-gate's status, and SKILL.md went on documenting it as a Stage 1 return for
  // two versions after 2.5.0 deleted the only thing that returned it. A status no
  // workflow can produce reads as coverage this list does not have.
  const settled = [
    'FALSE_POSITIVE',
    'NOT_EXPLOITABLE',
    'NOT_VULNERABLE',
    'ALREADY_FIXED',
    'OUT_OF_SCOPE',
  ]
  if (!settled.includes(status)) return null
  // Trimmed for the same reason every other relayed string in this file is:
  // `reason: '   '` is truthy and would reach the orchestrator as a verdict
  // that explains itself with blank space.
  return { status, reason: String(verification.reason || '').trim() }
}

// Pure. Same guard as triage-static, and here the failure is worse than an
// `undefined` in a prompt: `envelope.hosts.join()` and
// `verification.impact.impact` are nested accesses, so a missing or misnamed arg
// throws a TypeError and kills the run mid-prompt-construction.
function missingArgs(a) {
  const missing = []
  const need = (path, value) => {
    const blank = typeof value === 'string' && value.trim() === ''
    if (value === undefined || value === null || blank) missing.push(path)
  }
  const finding = (a && a.finding) || {}
  const impact = (a && a.verification && a.verification.impact) || {}
  const history = (a && a.verification && a.verification.history) || {}
  const envelope = (a && a.envelope) || {}

  need('baseDir', a && a.baseDir)

  // `baseDir` had its PRESENCE validated and never its SHAPE, and that gap is the
  // largest single source of variance measured on this plugin. On a 3-run sweep of
  // `integration-cap` with identical input, two runs passed the TARGET REPO's path
  // and one passed the plugin's: every read under `${baseDir}/references/` 404'd in
  // first two. The impact agent could not read dismissal-grounds.md, the gate agent
  // could not read false-positive-patterns.md, and those runs scored 0.000 and
  // 0.333 against the third's 1.000. All three impact agents returned the same
  // correct `Medium / integration` — the only difference was which files the
  // agents downstream of them could open.
  //
  // A workflow has no filesystem access, so existence cannot be checked here. The
  // SHAPE can be, and it is exactly what the two failing dispatches got wrong: an
  // absolute path ending in the skill directory. Reported rather than silently
  // tolerated, because the failure is otherwise invisible — an agent that cannot
  // read its reference file carries on and answers from memory.
  //
  // Written without a regex literal on purpose: the Python contract suite lexes
  // these scripts to strip strings and comments, and it REJECTS a regex literal
  // rather than risk mis-lexing one (test_a_regex_literal_is_rejected_rather_than_mis_lexed).
  // Adding one here failed 51 of its tests on unmutated code and took 27 mutations
  // with it, because a mutation whose baseline is red proves nothing.
  // `String(...)`, not a `typeof === 'string'` test. A non-string baseDir cleared
  // `need` — it is neither undefined, null nor a blank string — and then read as
  // '' here, so the shape check below was skipped entirely and every reference
  // path became '[object Object]/references/...'.
  const base = String((a && a.baseDir) ?? '').trim()
  const withoutSlash = base.endsWith('/') ? base.slice(0, -1) : base
  const shaped = withoutSlash.startsWith('/') && withoutSlash.endsWith('/skills/fp-check')
  if (base && !shaped) {
    missing.push(
      `baseDir (must be the skill directory's ABSOLUTE path, ending in skills/fp-check; got '${base}'. Copy it from an expanded reference link rather than reconstructing it — the working directory is the TARGET repo and has no references/ in it)`,
    )
  }
  need('finding.summary', finding.summary)
  need('finding.sink', finding.sink)
  need('verification.impact.impact', impact.impact)
  need('verification.impact.rootCause', impact.rootCause)
  need('verification.impact.classification', impact.classification)
  need('verification.severity', a && a.verification && a.verification.severity)
  // Challenge 4 is told what Stage 1 already searched so it can look somewhere
  // else rather than repeat it. Required rather than optional: a nested access
  // on a missing `history` throws mid-prompt-construction, and forwarding
  // triage-static's return value verbatim always carries it.
  need('verification.history.fixed', history.fixed)
  need('verification.history.searched', history.searched)
  // "Only a TRUE POSITIVE justifies building" was stated in SKILL.md and left to
  // the orchestrator to honour. It is not safe there: triage-static's failing
  // returns carry a fully populated `impact` and `severity`, so forwarding a
  // FAILED verification verbatim — exactly what the orchestrator is told to do
  // with a passing one — satisfies every other field here and buys a PoC for a
  // finding that failed its own gates. A blocking gate the caller can skip by
  // not reading it is not a gate.
  //
  // This is still the only gate on the build path. settledByStageOne runs
  // earlier and reaches the same outcome for the five statuses that are a
  // verdict; what is left here is everything else — NEEDS_MORE_INFO, BLOCKED, a
  // status this script does not recognise, and an absent one — for which "go
  // back and correct the dispatch or re-run Stage 1" is the right instruction.
  // Removing this check would let all of those through.
  const status = (a && a.verification && a.verification.status) || ''
  if (status !== 'TRUE_POSITIVE') {
    // The message says TRUE_POSITIVE and not "cleared all six gates", which is
    // what it used to say and is no longer the same thing: since a carried
    // question blocks a TRUE_POSITIVE in code, Stage 1 can pass all six gates and
    // still return NEEDS_MORE_INFO. The gate is unchanged — an open question is a
    // fact to resolve, not a finding to demonstrate — but a rejection that names a
    // criterion the finding did meet sends the reader looking in the wrong place.
    missing.push(
      `verification.status (must be 'TRUE_POSITIVE'; got ${status ? `'${status}'` : 'nothing'} — only a finding Stage 1 confirmed outright justifies building an exploit. Six passing gates are necessary and not sufficient: an unresolved uncertainty still returns NEEDS_MORE_INFO, and that is a missing fact to answer rather than a bug to demonstrate)`,
    )
  }
  need('envelope.level', envelope.level)
  if (!Array.isArray(envelope.hosts)) missing.push('envelope.hosts (must be an array)')
  if (typeof envelope.destructive !== 'boolean') {
    missing.push('envelope.destructive (must be a boolean)')
  }
  // safety-guidelines.md defines exactly five levels. Anything else reaches the
  // builder as "target level: 9", which reads as authoritative and constrains
  // nothing.
  if (envelope.level !== undefined && envelope.level !== null && envelope.level !== '') {
    if (!Number.isInteger(envelope.level) || envelope.level < 1 || envelope.level > 5) {
      missing.push('envelope.level (must be an integer 1-5, per safety-guidelines.md)')
    }
  }
  // An envelope may not authorise what the level forbids. Level 3 is read-only,
  // 4 is a minimal non-destructive probe on a live system, and 5 is nothing at
  // all without written authorization — so `destructive: true` above level 2 is
  // self-contradictory. Telling the builder it may not widen the envelope does
  // not help when the envelope itself is the thing that is wrong: it would read
  // "destructive operations authorised: yes" against production.
  if (envelope.destructive === true && Number.isInteger(envelope.level) && envelope.level >= 3) {
    missing.push(
      `envelope.destructive (true is not permitted at level ${envelope.level}; safety-guidelines.md allows destructive operations only at levels 1-2)`,
    )
  }
  // A non-array `candidates` must be REPORTED, not thrown on: `.entries()` is
  // undefined on an object or string, and the throw would escape missingArgs
  // itself, killing the run with no BLOCKED result.
  const cands = a && a.candidates
  if (cands !== undefined && cands !== null && !Array.isArray(cands)) {
    missing.push('candidates (must be an array)')
  } else {
    for (const [i, c] of (Array.isArray(cands) ? cands : []).entries()) {
      if (!c || !c.description) missing.push(`candidates[${i}].description`)
      if (!c || !c.entryPoint) missing.push(`candidates[${i}].entryPoint`)
      if (!c || !c.payload) missing.push(`candidates[${i}].payload`)
    }
  }
  return missing
}

// Ahead of the arg gate, deliberately. A settled finding is the more useful
// answer than a list of fields, and it is the same answer whether or not the
// rest of the dispatch is well formed — nothing below this line runs either way.
// Dispatched with only a `verification`, the arg gate buries "Stage 1 already
// decided this" under a dozen field names.
//
// The status stays BLOCKED because BLOCKED means "this stage did not run", which
// is exactly and correctly what happened. What tells a settled finding from a
// malformed dispatch is `settledBy`, a field rather than a prefix of prose:
// DO_NOT_SUBMIT is this plugin's cautionary tale about three outcomes sharing
// one status and being told apart by pattern-matching the `reason`, and the
// documented mapping sent all three to FALSE POSITIVE.
const settled = settledByStageOne(args)
if (settled) {
  log(`BLOCKED: Stage 1 settled this as ${settled.status}; there is no exploit to build.`)
  return {
    status: 'BLOCKED',
    settledBy: settled.status,
    reason: `Stage 1 settled this finding as ${settled.status}${settled.reason ? `: ${settled.reason}` : ''}. No exploit is owed and nothing here is missing — a finding that did not survive Stage 1 has nothing to demonstrate.`,
    deliverable:
      "Report Stage 1's verdict and the evidence behind it as the answer to the PoC request; that verdict IS the deliverable. Do not build an exploit by hand and do not re-dispatch this workflow — see \"When the user asked for a PoC and Stage 1 said no\" in SKILL.md, including what a negative PoC may and may not do.",
  }
}

const argProblems = missingArgs(args)
if (argProblems.length > 0) {
  log(`BLOCKED: dispatch contract violated — ${argProblems.join(', ')}`)
  return {
    status: 'BLOCKED',
    reason: `triage-poc received an unusable arg shape: ${argProblems.join(', ')}. Forward triage-static's return value verbatim as \`verification\`; see the Dispatch section of SKILL.md.`,
  }
}

// Pure, so the cap and the empty case can be graded without a model.
function selectAttempts(all, max) {
  const chosen = Array.isArray(all) ? all.slice(0, max) : []
  return { chosen, heldBack: Array.isArray(all) ? all.length - chosen.length : 0 }
}

// Built, executed, and lint-clean. Anything less is a failure, including a null
// from a dead builder agent.
//
// Trimmed, not merely truthy. JSON Schema `required` checks presence and not
// content, so `output: '   '` is schema-valid: a builder reporting whitespace for
// all of them passed this gate, returned BUILT, and that whitespace reached all
// five challenge prompts as the "Captured output" they are meant to judge.
//
// The string list is inline rather than hoisted to a const: the tests extract
// this function and evaluate it alone, where a free variable is a ReferenceError.
// test_the_build_gate_covers_every_field_the_reviewers_read pins it against the
// fields the challenge and artifact prompts interpolate, so a field this gate
// lets through cannot reach a reviewer as blank.
function isAcceptableBuild(result) {
  if (!result || !result.built || !result.executed || !result.lintPassed) return false
  return ['absolutePath', 'path', 'pocType', 'command', 'output', 'invokedSymbol'].every(
    (f) => typeof result[f] === 'string' && result[f].trim() !== '',
  )
}

// ------------------------------------------------------------------- Build
//
// This deliberately does NOT fan out. PoC construction needs one long context
// with an iterative debug loop; N parallel builders would burn N environments to
// produce one artifact. The retry re-attempts with a different attack path rather
// than taking a second opinion on the same one.

phase('Build')

const { chosen: attempts, heldBack } = selectAttempts(candidates, MAX_ATTEMPTS)
if (heldBack > 0) {
  log(`${heldBack} candidate path(s) held in reserve, not attempted.`)
}
if (attempts.length === 0) {
  log('No candidate attack paths supplied; nothing to build.')
  return { status: 'NO_CANDIDATES', reason: 'no candidate attack paths supplied' }
}

let poc = null
let lastFailure = null

for (let i = 0; i < attempts.length; i++) {
  const candidate = attempts[i]
  const retryContext = lastFailure
    ? `\n\nA previous attempt on a different path failed. Do not repeat it.\nPrevious path: ${lastFailure.candidate}\nWhy it failed: ${lastFailure.failureReason || 'unknown'}`
    : ''

  const result = await agent(
    `Build a working PoC for this finding. It cleared all six gates in Stage 1; your
job is to demonstrate it, and to fail honestly if it cannot be demonstrated.

Finding: ${finding.summary}
Verified impact: ${verification.impact.impact}
Classification: ${verification.impact.classification}
Severity so far: ${verification.severity}
Attack path to use: ${candidate.description}
Entry point: ${candidate.entryPoint}
Payload: ${candidate.payload}

Choose the PoC type, cheapest first:
  1. test-integrated  (PREFERRED when a test suite exists — the project's own
     harness gives you the real-code invocation for free)
  2. standalone script
  3. testnet demonstration
See ${baseDir}/references/test-integration.md for framework patterns. A
test-integrated PoC must FAIL while the vulnerability exists and PASS once it is
fixed; write the docstring to match the assertion, not the other way round.

Implement it. This rule is not negotiable: import and call the real code under
test. Never copy the vulnerable function into the PoC and exercise the copy.
Mocking dependencies is fine; mocking the vulnerable component itself is not.
Record the real symbol you invoke as invokedSymbol. See
${baseDir}/references/poc-anti-patterns.md.

Drive it through the ENTRY POINT, not the sink. A PoC that calls the vulnerable
function directly proves the sink is dangerous in isolation, which was never in
question — an independent reviewer's first challenge is that your setup
constructs state no real caller could reach, and a direct-to-sink PoC hands them
that argument. If reaching the sink through the entry point turns out to be
impossible, that is the finding: set built=false and say so.

Then actually run it and capture the full output to a file. A PoC that has not
been executed does not pass this stage.

You are working in an isolated git worktree, not the session's working tree.
Nothing downstream shares it: the reviewers who judge this PoC, the report that
cites it, and the user who has to run it all sit outside this directory, so a
repo-relative path resolves to nothing for every one of them. Report
absolutePath, and make outputPath absolute too.

Safety envelope, which you may not widen:
  permitted hosts: ${envelope.hosts.length ? envelope.hosts.join(', ') : 'NONE — local process only, no network target'}
  destructive operations authorised: ${envelope.destructive ? 'yes' : 'NO'}
  target level: ${envelope.level}
If the exploit cannot be demonstrated inside this envelope, set built=false and
say so. Do not improvise a broader target.

Before returning, run:
  ${baseDir}/scripts/poc-lint.sh --symbol <the symbol under test> <your poc file>
It must exit 0. Fix what it reports; do not work around it. A
\`possible-reimplementation\` NOTE does not fail it — grep cannot tell your own
driver from a copy of the target — but it is exactly the Principle 5 question,
so satisfy it by importing the real symbol rather than by renaming anything. A
reviewer who can open both files settles it after you — on the logic, under
whatever name — and a copy ends this stage as BLOCKED, so renaming past the note
buys nothing.
Report the outcome as
lintPassed — the build gate reads that field, and an independent reviewer re-runs
this exact command against your absolutePath afterwards, so reporting true
without a clean run is caught rather than believed.

A successful return must carry all of: built, executed, lintPassed, pocType,
path, absolutePath, the exact command that runs it, the captured output verbatim,
and invokedSymbol. The gate rejects a build missing any of them, so omitting one
discards a PoC that actually worked.${retryContext}`,
    {
      label: `build:${candidate.name || i + 1}`,
      phase: 'Build',
      schema: POC_SCHEMA,
      isolation: 'worktree',
      effort: 'high',
    },
  )

  if (isAcceptableBuild(result)) {
    poc = result
    log(`PoC built (${result.pocType}) at ${result.path} and executed.`)
    break
  }

  // Trimmed, not merely truthy, for the same reason isAcceptableBuild trims: a
  // schema-valid `failureReason: '   '` is truthy, and this string is both
  // BUILD_FAILED's `reason` — which SKILL.md tells the orchestrator to relay as the
  // missing fact — and the next attempt's "Why it failed:", which would have read as
  // blank space.
  lastFailure = {
    candidate: candidate.description,
    failureReason: result
      ? String(result.failureReason || '').trim() || 'built/executed/lint gate not satisfied'
      : 'builder agent failed',
  }
  log(`Attempt ${i + 1} failed: ${lastFailure.failureReason}`)
}

if (!poc) {
  log('Every attempted path failed to produce an executed, lint-clean PoC.')
  return {
    status: 'BUILD_FAILED',
    reason: lastFailure.failureReason,
    attempted: attempts.length,
    heldBack,
  }
}

// -------------------------------------------------------------- Challenges

phase('Challenges')

// Hoisted so the parallel() call below stays short enough for
// test_no_unbounded_fanout to see that it fans out over CHALLENGES, a
// script-local array literal, and is therefore bounded by construction.
const ARTIFACT_PROMPT = `Verify the PoC artifact itself. Steps 1, 2 and 4 are facts; step 3 is the one
judgement here, and it is yours because you are the only reader with both files
open.

PoC file: ${poc.absolutePath}
Symbol under test: ${poc.invokedSymbol}
Command the builder says runs it: ${poc.command}

Do these, with Bash:
  1. Confirm the file exists and read it.
  2. Run: ${baseDir}/scripts/poc-lint.sh --symbol '${poc.invokedSymbol}' '${poc.absolutePath}'
     Report its exit code as lintExitZero and paste its output as lintOutput.
     The builder reported that this passes; you are the one who checks.
     If it prints a \`possible-reimplementation\` NOTE, that is not a lint
     failure and must not be reported as one — it is the one Principle 5
     question grep cannot answer, handed to you because you can open both files.
  3. Answer that question in \`reimplementation\`, whether or not the note
     printed. Open the PoC and open ${finding.sink}, and compare the LOGIC, not
     the name:
       NOT_DEFINED      the PoC holds no copy of that logic under ANY name;
                        it imports ${poc.invokedSymbol} and calls the real one
       LOCAL_DRIVER     it defines that name, but the body is setup, a fixture,
                        a façade re-export or a harness — not the target's logic
       COPY_OF_TARGET   the vulnerable logic itself was pasted in, whatever it
                        was renamed to. A copy under a DIFFERENT name is this
                        answer and not NOT_DEFINED: rule 6 keys on the leaf, so
                        it prints no note, and rule 8 is satisfied by a mention
                        in a comment — you are the only check left
     COPY_OF_TARGET ends this stage as BLOCKED, because such a PoC proves the
     copy is broken and nothing about the application. Put the two locations you
     compared in \`evidence\`, whichever of the three you answer; a blank one
     ends this stage as BLOCKED too.
  4. Run the command above and report whether it reproduces the impact.
     Grade the impact, not the exit code: the preferred test-integrated PoC is
     written to FAIL while the vulnerability exists, so a red test there IS a
     reproduction and reRunSucceeded is true.
     If it cannot run here for an environmental reason — a missing service, a
     target that is not this machine — say so in reRunNotes and set
     reRunSucceeded false. That is a boundary to record, not a failure to hide.

Report what you observed. Do not repair the PoC and do not re-run the linter
until it passes; a failing check is the finding.`

// The artifact check runs at `medium`, not `low`. It was three shell facts until
// the Principle 5 verdict moved into it, and that step is a logic comparison
// across two files. The comment sits here rather than beside the call so that
// test_no_unbounded_fanout still sees CHALLENGES inside its window.
const checks = await parallel([
  () => agent(ARTIFACT_PROMPT, { label: 'artifact-check', phase: 'Challenges', schema: ARTIFACT_SCHEMA, effort: 'medium' }),
  ...CHALLENGES.map((c) => () =>
      agent(
        `You are a skeptical auditor reviewing a PoC you did not build. Your job is to
REJECT it if you honestly can.

Finding: ${finding.summary}
Location: ${finding.sink}
Claimed impact: ${verification.impact.impact}
Root cause: ${verification.impact.rootCause}
Severity so far: ${verification.severity}
Stage 1's already-fixed search: ${verification.history.fixed} — ${verification.history.searched}
PoC: ${poc.path} (${poc.pocType})
Read it at: ${poc.absolutePath}
  (it was built in an isolated worktree, so it is NOT under your working
   directory; open that absolute path. Challenge 1 in particular cannot be
   answered from the captured output alone — the PoC's setup is the evidence.)
Command: ${poc.command}
Symbol the PoC invokes: ${poc.invokedSymbol}
Captured output:
${poc.output}

${c.prompt}

State the strongest form of the challenge, then whether the evidence rebuts it.
If you cannot rebut it with evidence, the CHALLENGE wins. Uncertainty is not a
rebuttal.

\`reference\` and \`complete\` are required of all five of you and belong to
challenge 4 alone. Unless you are challenge 4 and are awarding it, return
\`reference\` as an empty string and \`complete\` as false. Omitting either fails
validation, and a challenge whose agent dies is counted as won by the challenge —
so leaving one out costs the finding a band step.`,
        { label: `challenge:${c.key}`, phase: 'Challenges', schema: CHALLENGE_SCHEMA, effort: 'high' },
        // `{...null}` is `{}`, so spreading unconditionally turns a dead agent
        // into a truthy phantom verdict: it survives .filter(Boolean), makes the
        // missing-agent count permanently 0, and reaches the report prompt as
        // "reachable: undefined".
      ).then((v) => (v ? { ...v, key: c.key } : null)),
  ),
])
const artifact = checks[0]
const verdicts = checks.slice(1).filter(Boolean)

// The barrier is justified: the confidence band is a decision over all five.

// Re-decided on what the reviewer observed rather than on what the builder
// claimed. Only the two environment-independent facts gate: the file is there,
// and the linter exits 0. A failed re-run is recorded for the report instead of
// blocking, because a testnet or service-dependent PoC can legitimately fail to
// reproduce on the reviewer's machine — that is a boundary for the "unproven"
// section, not proof the finding is wrong.
function artifactProblem(check) {
  if (!check) return 'the artifact-check agent returned nothing; the PoC was never independently verified'
  if (!check.fileExists) return 'no PoC file exists at the reported absolutePath'
  if (!check.lintExitZero) {
    return `poc-lint.sh did not exit 0 when an independent reviewer ran it, though the builder reported lintPassed: ${check.lintOutput || 'no output captured'}`
  }
  // Principle 5, decided here because it is decidable here and nowhere else.
  // Graded affirmatively — only the two values that CLEAR the PoC clear it — for
  // the reason every other gate in this plugin is: the enum is advisory, the
  // runtime validator enforces `required` alone, and by exclusion an omitted or
  // misspelt answer would read as a clearance. A copy is BLOCKED, not
  // DO_NOT_SUBMIT: the finding was not disproven, the artifact was.
  if (check.reimplementation !== 'NOT_DEFINED' && check.reimplementation !== 'LOCAL_DRIVER') {
    return `the PoC reimplements the code under test rather than importing it (reviewer verdict: ${check.reimplementation || 'none given'}): ${String(check.evidence || '').trim() || 'no evidence given'}. It proves the copy is broken, not that the application is exploitable — see the reimplementation section of references/poc-anti-patterns.md`
  }
  // And the CLEARING path is trimmed too, as every sibling gate in this file is.
  // `required` checks presence, not content, so `evidence: ''` validates: a
  // reviewer could clear Principle 5 having compared nothing and the one check
  // that decides it became a self-report. Both clearing answers are judgements
  // about the two bodies — NOT_DEFINED means no copy under ANY name, not merely
  // no symbol of that name — so both owe the locations they were reached from.
  if (!String(check.evidence || '').trim()) {
    return `the artifact check answered ${check.reimplementation} for Principle 5 without saying what it compared; the two locations opened are what makes that a check rather than an assertion`
  }
  return null
}

// Pure. Tallies against the EXPECTED challenge list, not against whatever came
// back: a challenge with no verdict counts as won by the challenge, which is the
// stated rule. Tallying the returned array instead lets a dead agent raise
// confidence by shrinking the denominator.
function tallyChallenges(challengeVerdicts, expectedKeys) {
  const byKey = new Map((challengeVerdicts || []).filter(Boolean).map((v) => [v.key, v]))
  const unrebutted = []
  let defeated = 0
  for (const key of expectedKeys) {
    const v = byKey.get(key)
    if (v && v.winner === 'REBUTTAL') defeated += 1
    else unrebutted.push({ key, challenge: v ? v.challenge : 'no verdict returned' })
  }
  return { defeated, unrebutted, missing: expectedKeys.length - byKey.size }
}

// checkpoints.md 5.1 challenge 4: "a fix exists -> the band does not get a vote".
// Takes the UNREBUTTED list, not the returned verdicts: every other challenge
// counts a missing verdict as won by the challenge, and the one challenge whose
// win overrides the band must not be the exception that escapes when its agent
// dies.
//
// It then requires the fix to be CITED, and returns that citation or null. This
// is triage-static's `upstreamFixStands` rule — `fixed: YES` with no reference is
// not a retraction — arriving one stage later: an unreferenced retraction is the
// one failure mode that silently discards a real finding, and here it discarded a
// built, executed, lint-clean one on nothing but a dead agent. The missing verdict
// still counts against the finding, in the only place it can honestly count:
// `tallyChallenges` has already lowered the band by it, and the report has to
// address it as unrebutted.
//
// This is one of the two mechanisms the head-to-head attributed the delta to:
// 3/3 on `already-fixed` against 0/3 for the arm with no already-fixed gate.
function alreadyFixedStands(unrebutted, challengeVerdicts) {
  if (!(unrebutted || []).some((v) => v && v.key === 'already-fixed')) return null
  const verdict = (challengeVerdicts || []).find((v) => v && v.key === 'already-fixed')
  // A PARTIAL fix is not a retraction — checkpoints.md 5.1: "an incomplete or
  // partial fix is reported as such". `!== true`, and for the same reason Stage
  // 1's `upstreamFixStands` uses it one workflow over: an omitted flag is
  // `undefined`, which is not `false`, so a fix that closed one of two sinks
  // discarded a demonstrated, still-live bug whole. It falls through from here
  // to the band, which has already counted the challenge against the finding.
  if (!verdict || verdict.complete !== true) return null
  // `reference`, not `evidence`. Every challenge is required to fill `evidence`,
  // so reading the citation out of it made the check unfalsifiable — any argued
  // win retracted. `reference` is the field that exists only to hold the commit,
  // PR, issue or advisory ID, exactly as HISTORY_SCHEMA's is, and `'   '` is
  // schema-valid in both. `citedReference` is the shared test of what counts.
  return citedReference(verdict.reference)
}

// Pure. Duplicated verbatim from triage-static.js — see the reasoning there.
// Two copies because these scripts have no module system; the alternative was
// two different rules for one thing, which is what shipped.
function citedReference(value) {
  // `new RegExp` from strings rather than regex literals: the contract suite
  // lexes these scripts and rejects a bare `/` in code position, because reading
  // a regex as a division silently blanks the rest of the file and turns every
  // check built on that text green.
  //
  // Matched ANYWHERE in the string, bounded by non-identifier characters, rather
  // than split on whitespace with each token anchored. Anchoring rejected every
  // ordinary wrapper a citation arrives in: `openssl/openssl#12345` — the
  // canonical cross-repo form, and the integration case this search exists for —
  // `torvalds/linux@a1b2c3d`, a backticked sha, `<https://...>`, a markdown link,
  // and `PR 4521`. A rejection here is not harmless in either direction: Stage 1
  // writes a note saying no reference was given and reports an already-fixed bug
  // as live, and Stage 3 turns a genuine retraction into NEEDS_MORE_INFO.
  //
  // A BARE number is deliberately not a citation. `4521` is indistinguishable
  // from a line number or a year, and admitting it makes "fixed in 2021" a
  // reference; the keyword form (`PR 4521`, `issue 1234`) carries the context
  // that tells them apart. For the same reason a dotted version needs either a
  // `v` or two dots, so that `v3` and `2.3.1` are citations and `2021.03` is not.
  const bound = '(^|[^0-9a-z])'
  const forms = new RegExp(
    [
      // a commit sha, alone or qualified by the repo it belongs to
      bound + '[0-9a-f]{7,40}([^0-9a-z]|$)',
      // #412, and owner/repo#412
      '[0-9a-z._-]*#[0-9]+',
      // Advisory IDs, recognised by REGISTRY NAME rather than by shape. Every
      // shape rule tried here mis-classified in both directions: "one hyphen and
      // a digit" made `internal-fix-2` and `fixed in a post-2020 refactor`
      // advisory IDs and retracted live findings, "the last segment ends in a
      // digit" threw out about 1 real GHSA ID in 20, and "every segment is four
      // or more characters" then threw out `PYSEC-2021-19`, `OSV-2021-9`,
      // `DSA-4879-1` and `USN-5678-1` — writing "no reference given" over a
      // correct citation and reporting a fixed bug as live. A shape cannot tell
      // an ID from an English phrase because registries did not agree on one. An
      // allowlist is honest about what it knows: a name it has never heard of is
      // not silently promoted, and a name it has is matched against that
      // registry's actual ID grammar.
      //
      // GHSA is its own branch because its shape is documented and unlike the
      // rest: exactly three four-character segments over the alphabet
      // `23456789cfghjmpqrvwx`, in which a digit is common but not guaranteed —
      // `GHSA-vqqm-hhhc-jqhw` carries none at all.
      bound + 'ghsa(-[0-9a-z]{4}){3}',
      // CVE-2024-1234, RUSTSEC-2021-0093, PYSEC-2021-19, OSV-2021-9,
      // GO-2022-0603, DSA-4879-1, USN-5678-1, DLA-2571-1, ZDI-21-1234,
      // ALSA-2021:9106. Each of these numbers its first segment — a year or a
      // bulletin number — which is what separates the ID from the prose: `go` is
      // in the list, and `go-to-market-2` still fails because `to` is not a
      // number.
      bound + '(cve|rustsec|pysec|osv|go|dsa|usn|dla|zdi|mal|alsa|elsa|talos)[-:][0-9]+[-:][0-9a-z]+',
      // v3, v2.3.1, 2.3.1. The trailing lookahead refuses a version that is part
      // of a FILENAME: `src/handlers/auth-v2.go:118` is the bare file:line
      // challenge 4's own prompt names as a non-citation, and `v2` inside it
      // satisfied a consuming boundary group.
      bound + '(v[0-9]+([.][0-9]+)*|[0-9]+([.][0-9]+){2,})(?![0-9a-z]|[.][a-z])',
      // PR 4521, issue #1234, release 3, gh-1234.
      bound + '(pr|pull|issues?|bug|ticket|gh|release)[ #-]+[0-9]+',
      // pull/882 and issues/1234, which is how GitHub shorthand is written. The
      // keyword may NOT be reached through a path separator, and that is the
      // whole difference between this branch and the one above it: with `/` in
      // the shared separator class, `src/bug/12.go` and `tests/issues/42/repro.py`
      // both became citations, contradicting this function's own rule that a bare
      // `file:line` is not one. Inside a full URL the `https?://` branch already
      // matches, so nothing is lost by refusing the path form here.
      '(^|[^0-9a-z/])(pr|pull|issues?|bug|ticket|gh|release)/[0-9]+',
      'https?://[^ ]',
    ].join('|'),
    'i',
  )
  const ref = String(value || '').trim()
  return forms.test(ref) ? ref : null
}

// checkpoints.md 5.1, applied as code rather than self-reported.
// `total` is a defaulted parameter rather than a reference to CHALLENGES.length:
// the tests extract this function and evaluate it alone, where a free variable is a
// ReferenceError. test_the_band_total_matches_the_challenge_count pins the two.
function confidenceBand(defeated, total = 5) {
  if (defeated === total) return { label: 'HIGH', range: '90-100%', action: 'PROCEED' }
  if (defeated >= 3) return { label: 'MEDIUM', range: '50-89%', action: 'PROCEED_WITH_UNCERTAINTIES' }
  if (defeated >= 1) return { label: 'LOW', range: '10-49%', action: 'DO_NOT_SUBMIT' }
  return { label: 'NONE', range: '0-9%', action: 'DO_NOT_SUBMIT' }
}

const tally = tallyChallenges(verdicts, CHALLENGES.map((c) => c.key))
const defeated = tally.defeated
const lost = tally.unrebutted
const band = confidenceBand(defeated, CHALLENGES.length)

if (tally.missing > 0) {
  log(`${tally.missing} challenge agent(s) returned nothing; counted as won by the challenge.`)
}
log(`${defeated}/${CHALLENGES.length} challenges defeated → ${band.label} (${band.range})`)

// The band alone would let 4/5 defeated proceed on an already-patched bug.
//
// FIRST, and ahead of the artifact gate below, because 5.1's rule is that this
// outcome "overrides everything else" and the artifact gate was above it. The two
// are different in kind: the artifact check is a judgement about whether this PoC is
// real, and challenge 4 is a fact about the codebase — a fix, with a reference,
// which no amount of PoC verification makes less true. With the gate first, a dead
// artifact agent or a failing lint turned "already patched, retract it" into
// BLOCKED, which SKILL.md relays as NEEDS MORE INFO and whose completion gate tells
// the orchestrator to re-dispatch, buying the same answer twice for a bug that no
// longer exists.
const fixCitation = alreadyFixedStands(lost, verdicts)
if (fixCitation) {
  log(`ALREADY_FIXED: the already-fixed challenge stands. ${fixCitation}`)
  return {
    // ALREADY_FIXED, not DO_NOT_SUBMIT. The bug was real and a fix landed, so this
    // is a RETRACTION with a reference — and Stage 1 already returns exactly this
    // status for exactly this rule. Under one shared DO_NOT_SUBMIT the orchestrator
    // had to pattern-match the reason prefix to tell a retraction from a false
    // positive from an incomplete report, and the documented mapping sent all three
    // to FALSE POSITIVE. Two of the three were the rounding error this plugin
    // exists to prevent.
    status: 'ALREADY_FIXED',
    reason: `already-fixed challenge unrebutted: ${fixCitation}. Retract rather than report at a lowered severity.`,
    band,
    defeated,
    poc,
    artifact,
    verdicts,
    unrebutted: lost,
  }
}

// Now the artifact, and it outranks everything below it: the band is a tally of
// judgements about a PoC, so it means nothing until someone other than the builder
// has confirmed the PoC is there and lints clean. Only the already-fixed rule above
// escapes it, and only because it is a fact about the code rather than about the
// artifact.
const artifactIssue = artifactProblem(artifact)
if (artifactIssue) {
  log(`PoC validation unsatisfied: ${artifactIssue}`)
  return { status: 'BLOCKED', reason: artifactIssue, poc, artifact, verdicts, band, defeated, unrebutted: lost }
}

if (band.action === 'DO_NOT_SUBMIT') {
  const unrebuttedKeys = lost.map((v) => v.key).join(', ')
  log(`Confidence ${band.label}. Not submitting. Unrebutted: ${unrebuttedKeys}`)
  return {
    status: 'DO_NOT_SUBMIT',
    reason: `confidence ${band.label} (${defeated}/${CHALLENGES.length} defeated); unrebutted: ${unrebuttedKeys}`,
    band,
    defeated,
    poc,
    artifact,
    verdicts,
    unrebutted: lost,
  }
}

// Challenge 4 was AWARDED on a WHOLE fix and cited nothing lookupable.
// `alreadyFixedStands` refuses to retract on that — a retraction has to point at
// something — and the band must not quietly decide instead: at 4/5 it is MEDIUM,
// so a bug a reviewer says is entirely patched came back REPORTED, which SKILL.md
// maps to TRUE POSITIVE. It is neither a retraction nor a clean bill of health;
// it is a fact still to establish.
//
// `complete === true`, so a PARTIAL fix never reaches here whether it cited
// anything or not. checkpoints.md 5.1 and challenge 4's own prompt both say a
// partial fix does not retract — the finding survives it and the report records
// it — and the citation is only load-bearing for the outcome that DISCARDS the
// finding. An uncited partial claim halted the stage on a bug everyone agreed was
// still live. Stage 1's `downgradeUnreferencedFix` is the precedent and it does
// not halt either: it downgrades `fixed` to UNCERTAIN and carries on to a verdict.
//
// A DEAD challenge-4 agent is deliberately not here — it returned no claim to
// establish, and `tallyChallenges` has already counted it against the finding.
//
// AFTER the artifact gate and the band, which is where the two findings this
// answers put it. Ahead of them, a PoC whose file does not exist came back
// NEEDS_MORE_INFO instead of BLOCKED, and one that lost ALL FIVE challenges came
// back NEEDS_MORE_INFO instead of the FALSE POSITIVE that SKILL.md maps
// `confidence NONE (0/5)` to — an uncited claim outranking four independent
// refutations that did not need it.
//
// `winner !== 'REBUTTAL'`, not `=== 'CHALLENGE'`, so that this and
// `tallyChallenges` grade the same field the same way. The enum is advisory —
// `required` is the only thing the runtime validator enforces — and an off-enum
// `winner: 'challenge'` counted AGAINST the finding in the tally while escaping
// this check entirely: 4/5, MEDIUM, REPORTED, on a finding the reviewer said was
// entirely patched. A dead agent is still not here, because it leaves no entry in
// `verdicts` at all.
const uncitedFix = verdicts.find(
  (v) => v.key === 'already-fixed' && v.winner !== 'REBUTTAL' && v.complete === true && !citedReference(v.reference),
)
if (uncitedFix) {
  const claim = String(uncitedFix.evidence || '').trim() || 'no evidence given'
  log(`NEEDS_MORE_INFO: the already-fixed challenge was awarded with nothing cited.`)
  return {
    status: 'NEEDS_MORE_INFO',
    reason: `the already-fixed challenge was awarded on a complete fix with no commit, PR, issue or advisory in \`reference\`: ${claim}. Establish the reference — it retracts if one exists — rather than reporting this as live.`,
    band,
    defeated,
    poc,
    artifact,
    verdicts,
    unrebutted: lost,
  }
}

// ------------------------------------------------------------------ Report

phase('Report')

const corrections = verdicts.filter((v) => v.impactCorrection).map((v) => `${v.key}: ${v.impactCorrection}`)

const report = await agent(
  `Calibrate the severity, then write the report. You did not build this PoC.

Finding: ${finding.summary}
Verified impact from Stage 1: ${verification.impact.impact}
Root cause: ${verification.impact.rootCause}
Classification: ${verification.impact.classification}
Severity Stage 1 arrived at: ${verification.severity}${verification.severityCorrection ? ` (${verification.severityCorrection})` : ''}
PoC: ${poc.path} (${poc.pocType}), readable at ${poc.absolutePath}
Confidence: ${band.label} (${band.range}), ${defeated}/${CHALLENGES.length} challenges defeated
${corrections.length ? `Impact corrections raised by reviewers:\n  ${corrections.join('\n  ')}` : 'No reviewer raised an impact correction.'}
${lost.length ? `Unrebutted challenges you must address in the report:\n  ${lost.map((v) => `${v.key}: ${v.challenge}`).join('\n  ')}` : ''}

Calibrate severity against the challenge verdicts and the corrections above.
Where a reviewer showed the impact is weaker than claimed, the weaker impact is
the one that goes in the report. An integration OR external root cause caps
severity at Medium; a hardening gap is not written up as an exploited
vulnerability. Those caps are checked in code after you answer and a rating above
them is rejected, so the report would have to be corrected by hand — get it right
here.

Write the report with all seven required sections: Executive Summary, Technical
Details, Proof of Concept, Attack Path Verification, False Positive Analysis,
Remediation, References. Remediation must be a specific fix, not "add
validation".

Save it next to the PoC, as finding-<short-slug>.md in the directory holding
${poc.absolutePath}, and return that path as reportPath. reportPath must be a
file you actually wrote, not a path you intend to use.

Independent artifact check (a reviewer re-ran these; the builder self-reported):
  poc-lint.sh exit 0: ${artifact.lintExitZero ? 'yes' : 'no'}
  PoC re-ran and reproduced the impact: ${artifact.reRunSucceeded ? 'yes' : `no — ${artifact.reRunNotes || 'no reason given'}`}
${artifact.reRunSucceeded ? '' : 'A PoC that did not reproduce for an independent reviewer is a boundary: say so in "unproven" rather than omitting it.'}
${band.action === 'PROCEED_WITH_UNCERTAINTIES' ? '\nConfidence is MEDIUM: the False Positive Analysis section must document the uncertainties explicitly, not gloss them.' : ''}

Fill the "unproven" field with what this PoC does not establish. It is not
allowed to be empty — every PoC has a boundary.

No speculative language: "probably", "likely", "might", "would", "could bypass"
are all disallowed. Say what the evidence shows.`,
  { label: 'report', phase: 'Report', schema: REPORT_SCHEMA, effort: 'high' },
)

// The report is unsatisfied if the agent died or left a field the report is
// defined by blank. JSON Schema `required` checks presence, not content, so
// `unproven: ''` and `reportPath: ''` both validate.
//
// Pure, and duplicated from triage-static.js with the cap it serves — see the
// reasoning there. Every DISTINCT rating level a string names, WORD-BOUNDED,
// most severe first: `low` sits inside "Allowlist", `high` inside "highly", and
// an unbounded substring test read both as ratings.
function namedLevels(severity) {
  const LEVELS = ['critical', 'high', 'medium', 'low', 'informational']
  return LEVELS.filter((name) => new RegExp(`\\b${name}\\b`, 'i').test(String(severity)))
}

// Pure, so both branches can be graded without a model.
function reportProblem(result) {
  if (!result) return 'report agent returned nothing'
  if (!String(result.unproven || '').trim()) return 'report omitted what remains unproven'
  if (!String(result.reportPath || '').trim()) {
    return 'report gave no reportPath; the report has to be the path of a file that was written, not one that was planned'
  }
  // The NUMBER, on the same reasoning and against a sharper failure than the
  // rationale below it: `severityCapViolation` names no level in a blank string,
  // so a blank reads as below the cap and returns null, and SKILL.md tells the
  // orchestrator the top-level `severity` is the number the finding ships with.
  // So REPORTED shipped a finding with no rating that no cap had been applied
  // to. Stage 2 has a fallback for that shape (`unknownSeverity`); this has none.
  // EXACTLY ONE of the five levels, which is one check rather than the three
  // separate failures it covers. `required` validates `severity: ''`, the enum is
  // advisory, and SKILL.md tells the orchestrator the top-level `severity` IS the
  // number the finding ships with — so a blank shipped a finding with no rating
  // at all; `Unknown`, `n/a` and `TBD` shipped one that names no level, which
  // `severityCapViolation` reads as below the cap and passes; and `Medium/High`
  // and `Critical (affects low-privilege users)` shipped two ratings at once.
  // Stage 2 falls back to Stage 1's number for the unreadable shapes. This stage
  // has nothing to fall back to, so it refuses and names the fix.
  const stated = String(result.severity || '').trim()
  const levels = namedLevels(stated)
  if (levels.length !== 1) {
    if (!stated) {
      return 'report gave no severity; the top-level severity is the number the finding ships with, and no cap can be applied to a blank one'
    }
    return levels.length === 0
      ? `report gave severity "${stated}", which names none of Critical, High, Medium, Low or Informational; no cap can be applied to a rating that is not one of them`
      : `report gave severity "${stated}", which names ${levels.length} levels (${levels.join(', ')}); state exactly one`
  }
  // Severity passes on "the rating is supported by evidence". The two fields
  // above were trimmed on exactly this reasoning and this one was not, so a
  // blank rationale returned REPORTED — and severityCapViolation below only
  // inspects Critical and High, which leaves a Medium asserted with nothing
  // behind it.
  if (!String(result.severityRationale || '').trim()) {
    return 'report gave no severityRationale; the rating has to be justified, not just stated'
  }
  return null
}

const reportIssue = reportProblem(report)
if (reportIssue) {
  // NEEDS_MORE_INFO, not DO_NOT_SUBMIT. Nothing was disproven here — five
  // challenges were defeated and the PoC ran; the report agent left a field the
  // report is defined by blank. Calling that a false positive discards a finding
  // for a clerical failure.
  log(`NEEDS_MORE_INFO: ${reportIssue}`)
  return { status: 'NEEDS_MORE_INFO', reason: reportIssue, band, defeated, poc, artifact, verdicts, unrebutted: lost }
}

// checkpoints.md 2.4b and 2.5, as arithmetic rather than judgement. Stage 1
// CORRECTS an over-rated severity because it has no artifact to correct; here the
// agent has already written the number into a report file, so correcting the
// return value would leave the file wrong and re-running the workflow would not
// fix it. This blocks and names the file instead.
//
// The second of the two mechanisms the head-to-head attributed the delta to:
// 3/3 on `integration-cap` against 0/3 for the arm whose severity was
// self-reported.
function severityCapViolation(severity, rootCause, classification) {
  // Affirmative, and for the reason `capSeverity` is one workflow over: the
  // REPORT_SCHEMA enum is advisory — `required` is the only thing the runtime
  // validator enforces — so grading by exclusion let 'critical', 'CRITICAL' and
  // 'Critical (RCE)' through the gate that exists to catch exactly them.
  //
  // EXACTLY ONE level named is a rating; more than one is an unusable answer, not
  // a number to pick from. `reportProblem` above refuses those first and with a
  // better message, so this branch is normally unreachable — it is here because
  // the alternative is that a gate whose whole job is to bound a number returns
  // "no violation" for a string it could not read, and this function is called
  // and graded on its own. It cannot be allowed to become a silent pass.
  const named = namedLevels(severity)
  if (named.length > 1) {
    return `severity ${severity} names ${named.length} levels (${named.join(', ')}), so no cap can be checked against it: state exactly one of Critical, High, Medium, Low, Informational`
  }
  const level = named[0] || ''
  if (level !== 'critical' && level !== 'high') return null
  if (rootCause === 'integration' || rootCause === 'external') {
    return `severity ${severity} exceeds the Medium cap for a ${rootCause} root cause (checkpoints.md 2.4b)`
  }
  if (classification === 'hardening_gap') {
    return `severity ${severity} exceeds the Medium cap for a hardening gap (checkpoints.md 2.5)`
  }
  return null
}

const capViolation = severityCapViolation(
  report.severity,
  verification.impact.rootCause,
  verification.impact.classification,
)
if (capViolation) {
  log(`Severity calibration unsatisfied: ${capViolation}`)
  return {
    status: 'BLOCKED',
    reason: `${capViolation}. The report at ${report.reportPath} carries a severity the root cause does not support; correct it there rather than re-running this workflow.`,
    band,
    defeated,
    poc,
    artifact,
    verdicts,
    // As every other Stage 3 return carries it. This was the one omission, and
    // it is reachable at MEDIUM with a challenge still standing — so without it
    // nothing here names the challenge the orchestrator has to report.
    unrebutted: lost,
    report,
  }
}

log(`REPORTED at ${report.severity}, confidence ${band.label} (${defeated}/${CHALLENGES.length}).`)
// Every other terminal status carries a `reason`, and SKILL.md's Completion Gate
// tells the orchestrator to relay it verbatim. This was the one exception.
//
// `unrebutted` too, and this is the only status reachable WITH a challenge still
// standing: at MEDIUM the band proceeds and documents it. A dead agent leaves no
// verdict object, so without this key nothing in the return names the challenge
// that stood, and SKILL.md asks the orchestrator only for the band and the tally.
//
// `severity` at the TOP LEVEL, as Stage 1 and Stage 2 both surface it. This was
// the one successful terminal return without it: SKILL.md tells the orchestrator
// to state the verdict "with the severity", it read `undefined`, and the number
// existed only at `report.severity`, which nothing tells it to look at.
return {
  status: 'REPORTED',
  reason: report.severityRationale,
  severity: report.severity,
  band,
  defeated,
  poc,
  artifact,
  verdicts,
  unrebutted: lost,
  report,
}
