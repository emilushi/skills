export const meta = {
  name: 'triage-online',
  description:
    "Stage 2: check the project's current public posture — disclosure policy, bounty scope, advisories, past reports, and a census of the public downstream users when severity turns on how they consume the target — and correct the scope or severity Stage 1 reached",
  whenToUse:
    'Only when the user asked for online checks, and only after triage-static has produced a verdict. Requires network access to a real upstream project; it fails closed rather than triaging policy from memory.',
  phases: [{ title: 'Policy' }, { title: 'Scope' }, { title: 'History' }, { title: 'Summary' }],
}

// args: { baseDir, finding, verification, project, sources[] }
//
// Every conclusion here rests on a document that could be read today and may say
// something different next month, so the one rule this script enforces above all
// others is that a claim without a citation is not a verdict. The failure it is
// built against is not a wrong answer; it is a confident answer produced from the
// model's memory of a policy that has since changed.

const { baseDir, finding, verification, project, sources = [] } = args || {}

const MAX_SOURCES = 6

const POLICY_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['reachedNetwork', 'sourcesRead', 'inScopeClasses', 'outOfScopeClasses', 'evidence'],
  properties: {
    // The only field in this workflow that can halt it before any judgement is
    // formed. See offlineProblem.
    reachedNetwork: { type: 'boolean', description: 'a live fetch of a project document actually succeeded' },
    sourcesRead: {
      type: 'string',
      description: 'the URLs read, and where you looked and found nothing — both, so a null result is auditable',
    },
    policyUrl: { type: 'string', description: 'the canonical policy document, when one exists' },
    inScopeClasses: { type: 'string' },
    outOfScopeClasses: { type: 'string' },
    severityRubric: { type: 'string', description: "the project's own severity scale, when it publishes one" },
    proofRequirements: { type: 'string' },
    evidence: { type: 'string' },
  },
}

const SCOPE_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['verdict', 'clause', 'severity', 'evidence'],
  properties: {
    verdict: { enum: ['in-scope', 'out-of-scope', 'unclear'] },
    // Out-of-scope requires a clause. "It's probably out of scope" is `unclear`,
    // and `unclear` does not stop the workflow — which is the whole reason this
    // field is required rather than encouraged.
    clause: { type: 'string', description: 'the policy text that controls the verdict, quoted' },
    severity: { enum: ['Critical', 'High', 'Medium', 'Low', 'Informational', 'Unknown'] },
    eligibilityCaveats: { type: 'string' },
    evidence: { type: 'string' },
  },
}

// The reachability agent had SCOPE_SCHEMA, which is the `inscope` agent's shape:
// it was made to answer with a policy `verdict` and a quoted `clause`, and its
// prompt asks it for neither. Nothing read either field. That is the same
// "loosen one schema to fit two jobs" that gave DO_NOT_SUBMIT three outcomes, and
// it is why this stage could not tell whether the sink is driven by the project's
// own code or only by a consumer's — the one fact `needsUserCensus` turns on.
//
// Every field here is required and every field here is read.
const REACHABILITY_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['driver', 'eligibilityCaveats', 'evidence'],
  properties: {
    // Who drives the sink in the PUBLISHED project. `client-code` is the library
    // shape — the bug needs an unsafe usage a consumer writes — and it is what
    // makes the downstream-consumer census worth an agent.
    driver: {
      enum: ['in-repo-caller', 'client-code', 'unknown'],
      description:
        "'in-repo-caller' when the project's own code reaches the sink, 'client-code' when only a consumer's code can, 'unknown' when the published evidence does not settle it",
    },
    // Was optional, and read with a fallback in two prompts. Required for the
    // same reason SUMMARY_SCHEMA requires openQuestions: the prompt asks for the
    // unknowns that would change the verdict, and an omitted gap reads as none.
    eligibilityCaveats: { type: 'string', description: 'the unknowns that would change the verdict, and the mitigating factors' },
    evidence: { type: 'string' },
  },
}

const PAST_BUGS_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['result', 'coverage', 'duplicate', 'evidence'],
  properties: {
    result: { enum: ['nothing', 'similar-bugs-found'] },
    coverage: {
      type: 'string',
      description: 'the query used and the pagination or cursors exhausted; one query is not a source',
    },
    links: { type: 'string' },
    similarity: { type: 'string', description: 'trigger, actor, impact, component and policy match' },
    historicalSeverity: { type: 'string' },
    recommendedSeverity: { enum: ['Critical', 'High', 'Medium', 'Low', 'Informational', 'Unknown'] },
    // Required, because the terminal DUPLICATE outcome branches on it and
    // `required` is the only thing the runtime validator enforces. Omitted, it
    // reads as `undefined` — falsy — so a genuine duplicate the agent found but
    // did not flag is reported as a live finding.
    duplicate: { type: 'boolean', description: 'this exact bug is already publicly reported' },
    evidence: { type: 'string' },
  },
}

// online-triage's `triage-online-users` role: the only role in any parent that
// produced evidence about the WORLD rather than about the project.
//
// `result` is an enum rather than a count because the two answers are not
// symmetrical. `affected-users-found` is a positive claim backed by links;
// `no-confirmed-users` bounds what was looked at and says nothing about what was
// not. `coverage` is required so the second one is auditable, and the summary is
// told in as many words not to read it as proof.
const CENSUS_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['reachedNetwork', 'result', 'pattern', 'coverage', 'confirmed', 'severityEffect', 'evidence'],
  properties: {
    // Same fail-closed rule the policy agent lives by, for the same reason: a
    // census answered from memory is a claim about which projects are vulnerable
    // today, made from a snapshot of a package ecosystem that has since moved.
    reachedNetwork: { type: 'boolean', description: 'a live search of a real code or package index actually succeeded' },
    result: { enum: ['no-confirmed-users', 'affected-users-found'] },
    pattern: {
      type: 'string',
      description: 'the client-side usage that makes the bug exploitable, written as it would appear in a consumer',
    },
    coverage: {
      type: 'string',
      description: 'the queries actually run, the indexes searched, and where you looked and found nothing — one query is not a census',
    },
    confirmed: {
      type: 'string',
      description:
        'each confirmed consumer: name, a link to the exact occurrence, and the context that tells it from a string match. Empty when none was confirmed',
    },
    severityEffect: {
      enum: ['raise', 'lower', 'none'],
      description: 'raise on a confirmed unsafe consumer, lower when the misuse is only theoretical, none when the evidence does not settle it',
    },
    evidence: { type: 'string' },
  },
}

const SUMMARY_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['finalSeverity', 'scopeVerdict', 'reasoning', 'confidence', 'openQuestions', 'evidence'],
  properties: {
    finalSeverity: { enum: ['Critical', 'High', 'Medium', 'Low', 'Informational', 'Unknown'] },
    scopeVerdict: { enum: ['in-scope', 'out-of-scope', 'unclear'] },
    duplicateOf: { type: 'string' },
    reasoning: { type: 'string' },
    confidence: { enum: ['high', 'medium', 'low'] },
    // Required, not optional: this stage's honest answer is often "the policy
    // does not address this", and a summary that omits the gap reads as though
    // the question was settled.
    openQuestions: { type: 'string' },
    evidence: { type: 'string' },
  },
}

// Pure.
function missingArgs(a) {
  const missing = []
  const need = (path, value) => {
    const blank = typeof value === 'string' && value.trim() === ''
    if (value === undefined || value === null || blank) missing.push(path)
  }
  const finding = (a && a.finding) || {}
  const proj = (a && a.project) || {}

  need('baseDir', a && a.baseDir)
  need('finding.summary', finding.summary)
  need('finding.sink', finding.sink)
  need('finding.component', finding.component)
  need('finding.claimedImpact', finding.claimedImpact)
  // Without an identified upstream project there is nothing to look up, and the
  // agents would search for a plausible-sounding project instead of this one.
  // A collision between two projects' analysis directories is the documented way
  // this goes wrong quietly.
  need('project.name', proj.name)
  need('project.url', proj.url)

  // Statuses from triage-static that Stage 2 can still act on. A finding already
  // dismissed on the code does not need a policy check, and running one anyway
  // invites the online evidence to argue a dead finding back to life.
  //
  // OUT_OF_SCOPE was on this list, because a DECLARED scope is exactly what a
  // published policy can overturn. It cannot be honoured: triage-static decides
  // OUT_OF_SCOPE inside `decideGate`, BEFORE the impact agent is dispatched, so the
  // payload it returns carries no `impact` and no `severity` — and the two `need`
  // calls below require both, because all three prompts here interpolate them and a
  // Stage 2 run on an unverified impact would tell its agents "Stage 1 already
  // traced the path in the code" when it did not. So every dispatch the entry
  // invited was refused four lines later by a rejection that named OUT_OF_SCOPE as
  // acceptable. Overturning a declared scope means re-running Stage 1 with the
  // corrected `scope` arg, which is where that input lives.
  //
  // Inline rather than a module const: the tests extract this function and
  // evaluate it alone, where a free variable is a ReferenceError. The alternative
  // — the test carrying its own copy of the list — lets the two disagree silently
  // about which findings Stage 2 will touch.
  const actionable = ['TRUE_POSITIVE', 'NEEDS_MORE_INFO']
  const status = (a && a.verification && a.verification.status) || ''
  if (!actionable.includes(status)) {
    missing.push(
      `verification.status (must be one of ${actionable.join(', ')}; got ${status ? `'${status}'` : 'nothing'} — a finding already dismissed on the code does not need a policy check)`,
    )
  }
  const impact = (a && a.verification && a.verification.impact) || {}
  need('verification.impact.impact', impact.impact)
  need('verification.severity', a && a.verification && a.verification.severity)

  const srcs = a && a.sources
  if (srcs !== undefined && srcs !== null && !Array.isArray(srcs)) {
    missing.push('sources (must be an array)')
  } else {
    const list = Array.isArray(srcs) ? srcs : []
    // Zero sources means the past-bug search is skipped entirely and the summary
    // is written as though nothing similar had ever been reported. That is the
    // same vacuous pass an empty `layers` was in Stage 1.
    if (list.length === 0) {
      missing.push(
        'sources (name at least one public venue to search — github-issues, github-advisories, a mailing list, a bounty platform; with none, the duplicate check silently does not happen)',
      )
    }
    for (const [i, s] of list.entries()) {
      if (!s || !s.label) missing.push(`sources[${i}].label`)
      if (!s || !s.query) missing.push(`sources[${i}].query`)
    }
  }
  return missing
}

const argProblems = missingArgs(args)
if (argProblems.length > 0) {
  log(`BLOCKED: dispatch contract violated — ${argProblems.join(', ')}`)
  return {
    status: 'BLOCKED',
    reason: `triage-online received an unusable arg shape: ${argProblems.join(', ')}. See the Dispatch section of SKILL.md.`,
  }
}

// ------------------------------------------------------------------ Policy

phase('Policy')

const policy = await agent(
  `Determine this project's published threat model and disclosure posture. From
online documentation, not from the code in front of you.

Project: ${project.name} (${project.url})
Finding to be triaged against it: ${finding.summary}
Component: ${finding.component}

Search for and read:
  - SECURITY.md, SECURITY.txt, and any vulnerability disclosure policy
  - the GitHub security/policy page and any wiki pages covering it
  - public documentation outside the repository
  - bug bounty scope and eligibility pages
  - any published severity, impact or vulnerability classification guidance

Use the \`gh\` CLI for GitHub. Record the URL of every material claim; separate
what a source says from what you infer from it.

Set reachedNetwork according to whether a live fetch of one of these documents
actually SUCCEEDED. This is not a formality and it is not about effort: if you
could not reach the network, set it false and stop there. Everything downstream
of this stage is a claim about the project's *current* posture, and policies and
bounty scopes change — answering from memory produces a confident, cited-looking
verdict that may describe a policy that no longer exists. A halt here is the
correct outcome, not a failure.

If you reached the network and the project simply publishes nothing, that is a
different answer: reachedNetwork true, and sourcesRead listing where you looked
and found nothing.`,
  { label: 'policy', phase: 'Policy', schema: POLICY_SCHEMA, effort: 'medium' },
)

// Pure. online-triage's own rule is to stop when offline rather than triage from
// memory, and it was prose in a reference file. As prose it inverts under
// pressure: an agent with no network still has a prompt asking it for a scope
// verdict, and the most likely completion is a plausible one.
//
// A dead agent is treated exactly like an offline one. Both mean the same thing —
// nothing was read — and the failure direction has to be the same.
function offlineProblem(result) {
  if (!result) return 'the policy agent returned nothing, so no project document was read'
  if (result.reachedNetwork !== true) {
    return `no project document could be fetched: ${String(result.sourcesRead || '').trim() || 'the agent did not say where it looked'}`
  }
  if (!String(result.sourcesRead || '').trim()) {
    return 'the policy agent reported reaching the network but named no source it read; an uncitable policy claim is not evidence'
  }
  return null
}

const offline = offlineProblem(policy)
if (offline) {
  log(`OFFLINE: ${offline}`)
  return {
    status: 'OFFLINE',
    reason: `${offline}. Stage 2 makes claims about the project's current public posture and will not make them from memory; re-run it with network access, or rely on Stage 1's verdict alone.`,
  }
}

// ------------------------------------------------------------------- Scope

phase('Scope')

const reachability = await agent(
  `How is this bug reached, according to public evidence rather than the local tree?

Project: ${project.name} (${project.url})
Finding: ${finding.summary}
Sink: ${finding.sink}
Impact established offline: ${verification.impact.impact}
Severity so far: ${verification.severity}

Stage 1 already traced the path in the code. You are answering the questions it
could not: which call sites and entry points exist in the published project, which
actors can reach them, and what preconditions — privileges, configuration, timing,
deployment shape — a real deployment imposes.

State the mitigating factors and the reasons exploitation might fail in practice.
Then state the unknowns that would change the verdict. "It's probably not
reachable" is an open question, not a mitigation: record what would have to be
true rather than quietly downgrading the severity.

Then set \`driver\`, which decides whether anyone needs to look at this project's
consumers at all:
  - in-repo-caller — the project's own published code reaches the sink, so the
    bug is exploitable in the target itself
  - client-code — only code a CONSUMER writes reaches it: an exported API, a
    pattern the docs tell clients to implement, a callback the project never
    calls itself
  - unknown — the published evidence does not settle which

Cite a link for every material claim.`,
  { label: 'reachability', phase: 'Scope', schema: REACHABILITY_SCHEMA, effort: 'medium' },
)

// The only agent result here that was read without a guard, and the reason it needs
// one is not symmetry: `reachability.evidence` is interpolated into the two prompts
// below and into the summary, so a dead agent threw a TypeError out of the workflow
// instead of returning a status. That is not a fail-closed outcome — the
// orchestrator is left holding a user request for a triage with no verdict to
// relay, and this plugin's worst measured failure is exactly that shape: the gate
// stops, and the analysis happens by hand outside it. BLOCKED, matching scopeHalt's
// answer to a dead scope agent: nothing was read, so nothing can be claimed.
if (!reachability) {
  const why = 'the reachability agent returned nothing; public call sites, actors and preconditions are unverified'
  log(`BLOCKED: ${why}`)
  return { status: 'BLOCKED', reason: why, policy }
}

const scope = await agent(
  `Does this finding fit the project's published threat model?

Project: ${project.name} (${project.url})
Finding: ${finding.summary}
Component: ${finding.component}
Claimed impact: ${finding.claimedImpact}
Impact established offline: ${verification.impact.impact}
Severity so far: ${verification.severity}

Read ${baseDir}/references/validation-dimensions.md before you decide. Its scope
red flags are the ones that matter here — infrastructure outside the stated focus,
a shared library spanning several systems, a component that does not match the
declared objectives — and its rule that an ambiguous scope is UNCERTAIN rather
than YES is the same asymmetry this verdict is built on.

The policy, as read in the previous step:
  in scope: ${policy.inScopeClasses}
  out of scope: ${policy.outOfScopeClasses}
  severity rubric: ${policy.severityRubric || 'the project publishes none'}
  proof requirements: ${policy.proofRequirements || 'none stated'}
  sources: ${policy.sourcesRead}

Public reachability findings:
  ${reachability.evidence}
  caveats: ${reachability.eligibilityCaveats || 'none recorded'}

Map the reachability facts onto the policy clauses and return a verdict.

out-of-scope requires a matching clause, quoted in \`clause\`. Without one the
verdict is unclear, not out-of-scope — and unclear does not stop the analysis.
This asymmetry is deliberate: out-of-scope is the one verdict here that ends the
work, so it is the one that has to be earned.

Then set the severity from the project's OWN rubric where it publishes one. A CVE
number or a vendor CVSS is a claim, not evidence; re-derive it from the rubric and
the reachability facts. Use Unknown rather than guessing.`,
  { label: 'inscope', phase: 'Scope', schema: SCOPE_SCHEMA, effort: 'medium' },
)

// Pure. The halt, and the asymmetry that makes it safe: out-of-scope ends the
// analysis, so it needs a quoted clause; `unclear` does not end anything.
function scopeHalt(result) {
  if (!result) {
    return { status: 'BLOCKED', reason: 'the scope agent returned nothing; the policy verdict is unverified' }
  }
  if (result.verdict !== 'out-of-scope') return null
  const clause = String(result.clause || '').trim()
  if (!clause) {
    return {
      status: 'NEEDS_MORE_INFO',
      reason:
        'the scope agent answered out-of-scope but quoted no policy clause, which by its own rule makes the verdict unclear rather than out-of-scope',
    }
  }
  return {
    status: 'OUT_OF_SCOPE',
    reason: `out of scope per ${clause}${String(result.evidence || '').trim() ? ` — ${result.evidence}` : ''}`,
  }
}

const halt = scopeHalt(scope)
if (halt) {
  log(`${halt.status}: ${halt.reason}`)
  return { status: halt.status, reason: halt.reason, policy, reachability, scope }
}

// ----------------------------------------------------------------- History

phase('History')

// Capped at MAX_SOURCES, and one agent per source rather than one agent over all
// of them: the rule each has to honour is "exhaust the pagination for YOUR
// source", and an agent handed six venues satisfies that for none of them.
const pastBugs = await parallel(
  sources.slice(0, MAX_SOURCES).map((source) => () =>
    agent(
      `Find bugs similar to this one in ONE source, and only that source.

Project: ${project.name} (${project.url})
Source you are assigned: ${source.label}
Query or URL to start from: ${source.query}

Finding: ${finding.summary}
Component: ${finding.component}
Impact: ${verification.impact.impact}
Public reachability: ${reachability.evidence}

Search only your assigned source. Exhaust its pagination or API cursors, and try
the obvious alternate terms before concluding there is nothing: one query is not a
source, and "the first search found nothing" is the most common way a duplicate
gets filed. Record what you covered, including the limits you hit, in \`coverage\`.

If you find similar bugs, decide whether they change the severity of THIS bug —
but confirm the trigger, actor, impact and component actually match before
importing a historical severity, and record the differences and your confidence.
A superficially similar bug with a different actor is not a precedent.

Set duplicate: true only when this exact bug is already publicly reported, with
the link.`,
      { label: `past-bugs:${source.label}`, phase: 'History', schema: PAST_BUGS_SCHEMA, effort: 'medium' },
    ).then((v) => (v ? { ...v, source: source.label, query: source.query } : null)),
  ),
)
const searched = pastBugs.filter(Boolean)

const attempted = Math.min(sources.length, MAX_SOURCES)

// The venues the cap dropped, by name and carried rather than logged. A log is not
// something any consumer reads: the summary prompt below is built from `attempted`,
// so a 9-source dispatch told the summary agent about 6 venues and said nothing
// about the other 3, and the agent has no way to tell a venue that was never
// dispatched from one that came back clean. That is the same "an absent duplicate
// check becomes a clean bill of health" that `unsearched` exists to stop, arriving
// by the other route. Kept separate from `unsearched` because they are different
// facts — never dispatched, versus dispatched and dead — and the summary is told
// both.
const beyondCap = sources.slice(MAX_SOURCES).map((s) => s.label)
if (beyondCap.length > 0) {
  log(`${beyondCap.length} source(s) beyond the cap of ${MAX_SOURCES} were NOT searched: ${beyondCap.join(', ')}`)
}

// A source whose agent died was not searched, and "not searched" must never be
// summarised as "nothing found there" — that is how an absent duplicate check
// becomes a clean bill of health. Reported rather than fatal: the remaining
// sources are still evidence, and the summary is told which venues are blind.
const unsearched = sources
  .slice(0, MAX_SOURCES)
  .map((s) => s.label)
  .filter((label) => !searched.some((r) => r.source === label))
if (unsearched.length > 0) {
  log(`${unsearched.length} of ${attempted} source(s) returned nothing at all: ${unsearched.join(', ')}`)
}

// ------------------------------------------------- Downstream-user census

// Pure. online-triage's `triage-online-users` role was gated on the reachability
// and scope files saying severity depends on downstream users, and the parent
// gated it for a reason: for a bug directly exploitable in the target, a census
// of consumers answers a question nobody asked.
//
// A gate in code rather than a third question at Step 0, because whether severity
// turns on downstream usage is a FINDING of the reachability analysis and not
// something the user knows when they start — and because every extra question is
// one more thing a non-interactive harness silently defaults to `no`, which is how
// this plugin has now shipped three capabilities that fired zero times.
//
// The last clause is read by exclusion, and that is deliberate. Everywhere else in
// this stage the affirmative value is the one that counts, because there the risk
// is a claim made on no evidence. Here the risk runs the other way: the measured
// failure is a capability that never fires, and an omitted `driver` reading as "no
// census needed" is exactly that. A false positive costs one agent; a false
// negative loses the role again.
function needsUserCensus(verification, reachability, scope) {
  // Unreachable from the call site below — `scopeHalt` has already returned on an
  // out-of-scope verdict. Kept because the predicate is unit-tested on its own and
  // "census a project's consumers over a finding its policy excludes" must not be
  // something it says yes to when someone reuses it.
  if (scope && scope.verdict === 'out-of-scope') return false

  const impact = (verification && verification.impact) || {}
  // An integration or external root cause means the attack needs a failure
  // outside this project, which is the client's side of the boundary.
  if (impact.rootCause === 'integration' || impact.rootCause === 'external') return true
  // A hardening gap is by definition not exploitable on its own; whether it
  // matters is a question about how it is used. Not narrowed to "in an exported
  // surface" — nothing structural tells us that, and guessing narrows toward the
  // failure that costs the capability.
  if (impact.classification === 'hardening_gap') return true

  const driver = (reachability && reachability.driver) || ''
  return driver !== 'in-repo-caller'
}

const censusWanted = needsUserCensus(verification, reachability, scope)

const census = censusWanted
  ? await agent(
      `Do real, popular public consumers of this project actually exhibit the unsafe
pattern this finding depends on?

Project: ${project.name} (${project.url})
Finding: ${finding.summary}
Component: ${finding.component}
Sink: ${finding.sink}
Impact established offline: ${verification.impact.impact}
Root cause: ${verification.impact.rootCause}
Public reachability: ${reachability.evidence}

First derive the pattern. From the reachability findings above, write down what
the unsafe usage looks like in a CONSUMER's code — the call, the argument, the
missing check, the order of operations — and put it in \`pattern\`. Everything
after this depends on searching for the right thing.

Then look for it. Use the dependents graph, public code search, the package
index's reverse dependencies, and the project's own list of users. Prefer
consumers with real usage over toy repositories and forks.

Keep only CONFIRMED hits: a real occurrence, a link to the exact file and line,
and enough surrounding context to tell it from a string match on the same
identifier. A consumer that calls the API safely is not a hit. Record each one in
\`confirmed\`, with the link.

Record in \`coverage\` the queries you actually ran and the indexes you searched,
including where you looked and found nothing. Finding nothing bounds what you
looked at; it is not evidence that no consumer is affected, and \`coverage\` is
what lets the next reader tell those apart.

severityEffect: raise when a confirmed consumer exhibits the pattern, lower when
the misuse is only theoretical, none when the search does not settle it.

Set reachedNetwork according to whether a live search actually SUCCEEDED. If you
could not reach the network, set it false and stop there. A census answered from
memory is a claim about which projects are vulnerable today, drawn from a snapshot
of an ecosystem that has since moved.`,
      { label: 'downstream-users', phase: 'History', schema: CENSUS_SCHEMA, effort: 'medium' },
    )
  : null

// Pure. The same rule the rest of this stage lives by — no claim about the world
// without having looked — applied to the one agent whose subject IS the world.
// The failure it exists to stop is the census degrading into "no users found",
// which is a positive claim, when what happened is that nothing was searched.
function censusProblem(result) {
  if (!result) return 'the census agent returned nothing, so no consumer was looked at'
  if (result.reachedNetwork !== true) {
    return `no consumer index could be searched: ${String(result.coverage || '').trim() || 'the agent did not say where it looked'}`
  }
  if (!String(result.coverage || '').trim()) {
    return 'the census named no query it ran; an uncitable "no affected consumers" is not evidence'
  }
  if (result.result === 'affected-users-found' && !String(result.confirmed || '').trim()) {
    return 'the census reported affected consumers but named none, so there is nothing to raise the severity on'
  }
  return null
}

const censusIssue = censusWanted ? censusProblem(census) : null

// Carried, not merely logged. `beyondCap` is the precedent and the lesson: a log
// is not something any consumer reads, so a silently skipped step reaches the
// summary as an absence and reads as a clean result. Both the summary prompt and
// every return below get this.
const censusState = !censusWanted ? 'not-applicable' : censusIssue ? 'unperformed' : 'performed'
const censusWhy = !censusWanted
  ? `the bug is exploitable in the target itself — root cause ${verification.impact.rootCause}, classification ${verification.impact.classification}, and the published call sites are driven by ${reachability.driver}`
  : censusIssue
if (censusState !== 'performed') log(`downstream-users census ${censusState}: ${censusWhy}`)

// A blind census is reported to the summary as unchecked rather than halting the
// stage, which is where this departs from `offlineProblem`. The policy read is
// this stage's premise and nothing downstream of it means anything; the census is
// one input, and killing a completed policy read, scope verdict and past-bug
// fan-out over it would throw away evidence that is still good. `unsearched` sets
// the precedent for exactly this shape. What must not happen — a census that
// searched nothing summarised as "no consumer is affected" — is what the wording
// below prevents.
const censusReport =
  censusState === 'performed'
    ? `Downstream-consumer census: ${census.result} (severityEffect ${census.severityEffect}).
  unsafe pattern searched for: ${census.pattern}
  confirmed consumers: ${String(census.confirmed || '').trim() || 'none confirmed'}
  coverage: ${census.coverage}
  A census that confirmed nothing bounds what was looked at. It is NOT proof that no consumer is affected.`
    : censusState === 'unperformed'
      ? `Downstream-consumer census: NOT PERFORMED — ${censusWhy}. Severity here turns on how consumers use this project, and that is UNCHECKED rather than clear; it belongs in openQuestions.`
      : `Downstream-consumer census: not applicable — ${censusWhy}.`

// ----------------------------------------------------------------- Summary

phase('Summary')

const duplicates = searched.filter((r) => r.duplicate)

// What a duplicate is relayed with, in the summary prompt and in the DUPLICATE
// return. Trimmed and in one place: `links` is optional and `required` checks
// presence rather than content, so `links: '   '` is schema-valid AND truthy — it
// displaced the `evidence` it was meant to fall back to, and the retraction went out
// citing blank space. DUPLICATE is terminal, so that citation is the deliverable.
const dupCite = (r) => String(r.links || '').trim() || String(r.evidence || '').trim() || 'no link or evidence given'

const summary = await agent(
  `Write the online triage summary. Everything below was gathered by agents that
each saw one narrow question.

Project: ${project.name} (${project.url})
Finding: ${finding.summary}
Severity Stage 1 arrived at, offline: ${verification.severity}
Impact: ${verification.impact.impact}

Scope: ${scope.verdict}${String(scope.clause || '').trim() ? ` per ${scope.clause}` : ' — no controlling clause quoted'}
Severity the policy rubric implies: ${scope.severity}
Policy sources: ${policy.sourcesRead}

Public reachability: ${reachability.evidence}
Unknowns that would change it: ${reachability.eligibilityCaveats || 'none recorded'}

Past-bug searches, ${searched.length} of ${attempted} dispatched source(s) returned a result:
  ${searched.map((r) => `${r.source}: ${r.result}${r.recommendedSeverity && r.recommendedSeverity !== 'Unknown' ? ` → ${r.recommendedSeverity}` : ''} — ${r.similarity || r.evidence} [coverage: ${r.coverage}]`).join('\n  ')}
${unsearched.length ? `NOT searched, because those agents returned nothing — treat these venues as unchecked, not as clear:\n  ${unsearched.join('\n  ')}` : ''}
${beyondCap.length ? `NOT searched, because they were beyond the cap of ${MAX_SOURCES} and no agent was dispatched — unchecked, not clear:\n  ${beyondCap.join('\n  ')}` : ''}
${duplicates.length ? `Reported as an existing public duplicate:\n  ${duplicates.map((r) => `${r.source}: ${dupCite(r)}`).join('\n  ')}` : 'No source reported this as an existing duplicate.'}

${censusReport}

Give the final severity recommendation and the reasoning that gets you there,
mapping the reachability facts onto the policy clauses. Where the online evidence
contradicts the offline severity, say which one you are following and why.

openQuestions is required and may not be empty. If the policy does not address
this class of bug, if a venue went unsearched, if the consumer census could not be
performed, or if the rubric is ambiguous, that belongs here — a summary that omits
the gap reads as though the question was settled.`,
  { label: 'summary', phase: 'Summary', schema: SUMMARY_SCHEMA, effort: 'high' },
)

// Pure. The two fields the summary is defined by, checked for content rather than
// presence, for the same reason every other schema in this plugin is: `required`
// validates `openQuestions: ''`.
function summaryProblem(result) {
  if (!result) return 'the summary agent returned nothing'
  if (!String(result.reasoning || '').trim()) return 'summary gave no reasoning'
  if (!String(result.openQuestions || '').trim()) {
    return 'summary left openQuestions empty; every online triage has at least one, and an omitted gap reads as a settled question'
  }
  return null
}

// BEFORE the summary's own gate, and the order is load-bearing. A duplicate is a
// fact a past-bug agent established with a link; the summary agent's job is to write
// it up, and its failure to do so cannot unmake it. The other way round, the single
// most likely summary defect — an empty `openQuestions`, which is why that gate
// exists at all — downgraded "already publicly reported at GHSA-x" to
// NEEDS_MORE_INFO, discarding a terminal answer the stage had already paid for and
// sending the next reader to buy it again.
//
// `summary` is still returned, and may be null or incomplete: the duplicate finding
// does not depend on it.
if (duplicates.length > 0) {
  const where = duplicates.map((r) => `${r.source}: ${dupCite(r)}`).join('; ')
  log(`DUPLICATE: already publicly reported — ${where}`)
  return {
    status: 'DUPLICATE',
    reason: `already publicly reported — ${where}`,
    policy,
    reachability,
    scope,
    pastBugs: searched,
    unsearched,
    beyondCap,
    census: { state: censusState, why: censusWhy, result: census },
    summary,
  }
}

const summaryIssue = summaryProblem(summary)
if (summaryIssue) {
  log(`NEEDS_MORE_INFO: ${summaryIssue}`)
  return {
    status: 'NEEDS_MORE_INFO',
    reason: summaryIssue,
    policy,
    reachability,
    scope,
    pastBugs: searched,
    unsearched,
    beyondCap,
    census: { state: censusState, why: censusWhy, result: census },
  }
}

log(`Online triage complete: ${summary.scopeVerdict}, severity ${summary.finalSeverity} (confidence ${summary.confidence}).`)
return {
  status: 'TRIAGED',
  reason: summary.reasoning,
  policy,
  reachability,
  scope,
  pastBugs: searched,
  unsearched,
  beyondCap,
  census: { state: censusState, why: censusWhy, result: census },
  summary,
}
