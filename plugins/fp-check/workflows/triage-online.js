export const meta = {
  name: 'triage-online',
  description:
    "Stage 2: check the project's current public posture — disclosure policy, bounty scope, advisories, past reports, downstream users — and correct the scope or severity Stage 1 reached",
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

const PAST_BUGS_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['result', 'coverage', 'evidence'],
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
    duplicate: { type: 'boolean', description: 'this exact bug is already publicly reported' },
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
  // invites the online evidence to argue a dead finding back to life; OUT_OF_SCOPE
  // is here because a DECLARED scope is exactly what a published policy can
  // overturn.
  //
  // Inline rather than a module const: the tests extract this function and
  // evaluate it alone, where a free variable is a ReferenceError. The alternative
  // — the test carrying its own copy of the list — lets the two disagree silently
  // about which findings Stage 2 will touch.
  const actionable = ['TRUE_POSITIVE', 'NEEDS_MORE_INFO', 'OUT_OF_SCOPE']
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

Cite a link for every material claim.`,
  { label: 'reachability', phase: 'Scope', schema: SCOPE_SCHEMA, effort: 'medium' },
)

const scope = await agent(
  `Does this finding fit the project's published threat model?

Project: ${project.name} (${project.url})
Finding: ${finding.summary}
Component: ${finding.component}
Claimed impact: ${finding.claimedImpact}
Impact established offline: ${verification.impact.impact}
Severity so far: ${verification.severity}

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
if (sources.length > MAX_SOURCES) {
  log(`${sources.length - MAX_SOURCES} source(s) beyond the cap of ${MAX_SOURCES} were NOT searched.`)
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

// ----------------------------------------------------------------- Summary

phase('Summary')

const duplicates = searched.filter((r) => r.duplicate)

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

Past-bug searches, ${searched.length} of ${attempted} source(s) returned a result:
  ${searched.map((r) => `${r.source}: ${r.result}${r.recommendedSeverity && r.recommendedSeverity !== 'Unknown' ? ` → ${r.recommendedSeverity}` : ''} — ${r.similarity || r.evidence} [coverage: ${r.coverage}]`).join('\n  ')}
${unsearched.length ? `NOT searched, because those agents returned nothing — treat these venues as unchecked, not as clear:\n  ${unsearched.join('\n  ')}` : ''}
${duplicates.length ? `Reported as an existing public duplicate:\n  ${duplicates.map((r) => `${r.source}: ${r.links || r.evidence}`).join('\n  ')}` : 'No source reported this as an existing duplicate.'}

Give the final severity recommendation and the reasoning that gets you there,
mapping the reachability facts onto the policy clauses. Where the online evidence
contradicts the offline severity, say which one you are following and why.

openQuestions is required and may not be empty. If the policy does not address
this class of bug, if a venue went unsearched, or if the rubric is ambiguous, that
belongs here — a summary that omits the gap reads as though the question was
settled.`,
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

const summaryIssue = summaryProblem(summary)
if (summaryIssue) {
  log(`NEEDS_MORE_INFO: ${summaryIssue}`)
  return { status: 'NEEDS_MORE_INFO', reason: summaryIssue, policy, reachability, scope, pastBugs: searched, unsearched }
}

if (duplicates.length > 0) {
  const where = duplicates.map((r) => `${r.source}: ${r.links || r.evidence}`).join('; ')
  log(`DUPLICATE: already publicly reported — ${where}`)
  return {
    status: 'DUPLICATE',
    reason: `already publicly reported — ${where}`,
    policy,
    reachability,
    scope,
    pastBugs: searched,
    unsearched,
    summary,
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
  summary,
}
