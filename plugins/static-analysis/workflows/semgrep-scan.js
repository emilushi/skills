export const meta = {
  name: 'semgrep-scan',
  description: 'Fan out approved Semgrep rulesets across detected languages, then merge to one SARIF',
  whenToUse:
    'After the semgrep skill has detected languages, selected rulesets, and the user has approved the plan. This runs the execution half only — it does not ask for approval, so never invoke it on an unapproved plan.',
  phases: [
    { title: 'Prepare', detail: 'clone third-party rule repos once, shared by all scanners' },
    { title: 'Scan', detail: 'one agent per language category' },
    { title: 'Merge', detail: 'combine SARIF and report' },
  ],
}

// --- inputs -----------------------------------------------------------------------
//
// The skill owns detection, ruleset selection, and the approval gate; this owns
// execution. Everything needed crosses the boundary as args:
//
//   target        absolute path to scan
//   outputDir     absolute path, already created, containing raw/ and results/
//   languages     [{ name, rulesets: [...], includeFlags: "--include=\"*.py\"" }]
//   mode          "run-all" | "important-only"
//   proAvailable  boolean
//   thirdPartyRepos ["https://github.com/trailofbits/semgrep-rules", ...]
//   mergeScript   absolute path to merge_sarif.py (optional; located if absent)

const cfg = args || {}

const missing = ['target', 'outputDir', 'languages'].filter((k) => !cfg[k])
if (missing.length) {
  throw new Error(
    `semgrep-scan: missing required args: ${missing.join(', ')}. This workflow runs an ` +
      `already-approved plan; the semgrep skill supplies these from Steps 1-3.`,
  )
}

// A scan over zero language categories writes no SARIF, merges nothing, and reports a
// clean codebase having examined nothing. Refuse it rather than produce that result.
if (!Array.isArray(cfg.languages) || cfg.languages.length === 0) {
  throw new Error(
    'semgrep-scan: `languages` is empty — nothing would be scanned, and the run would ' +
      'report zero findings. Re-run language detection (skill Step 1).',
  )
}

const mode = cfg.mode === 'important-only' ? 'important-only' : 'run-all'
const severityFlags =
  mode === 'important-only' ? '--severity MEDIUM --severity HIGH --severity CRITICAL' : ''
const proFlag = cfg.proAvailable ? '--pro' : ''
const thirdParty = Array.isArray(cfg.thirdPartyRepos) ? cfg.thirdPartyRepos : []
const rawDir = `${cfg.outputDir}/raw`

const SCAN_RESULT = {
  type: 'object',
  required: ['language', 'rulesetsRun', 'sarifFiles', 'findings', 'errors'],
  properties: {
    language: { type: 'string' },
    rulesetsRun: { type: 'integer' },
    sarifFiles: { type: 'array', items: { type: 'string' } },
    findings: { type: 'integer' },
    errors: { type: 'array', items: { type: 'string' } },
  },
  additionalProperties: false,
}

// --- Prepare ----------------------------------------------------------------------
//
// Cloned once here rather than inside each scanner. The prose version had every
// parallel scanner clone into $OUTPUT_DIR/repos and `rm -rf` it when its own scans
// finished — so the first scanner to complete deleted the rules its siblings were
// still reading through --config. Clone once, delete once, after everyone is done.

phase('Prepare')

let localConfigs = []
if (thirdParty.length) {
  const cloned = await agent(
    `Clone these Semgrep rule repositories, shallow, into \`${cfg.outputDir}/repos/\`:

${thirdParty.map((u) => `- ${u}`).join('\n')}

For each: \`git clone --depth 1 <url> ${cfg.outputDir}/repos/<repo-name>\`.

Never pass a GitHub URL to semgrep's --config directly — its URL handling fails on
repos with non-standard YAML, which is why these are cloned at all.

Return the absolute local path of each successful clone. If a clone fails, report it
in \`errors\` and continue with the rest; a missing third-party ruleset degrades
coverage but must not abort the scan.`,
    {
      label: 'clone-rulesets',
      phase: 'Prepare',
      effort: 'low',
      schema: {
        type: 'object',
        required: ['paths', 'errors'],
        properties: {
          paths: { type: 'array', items: { type: 'string' } },
          errors: { type: 'array', items: { type: 'string' } },
        },
        additionalProperties: false,
      },
    },
  )

  localConfigs = (cloned && cloned.paths) || []
  if (cloned && cloned.errors && cloned.errors.length) {
    log(`third-party clone problems: ${cloned.errors.join('; ')}`)
  }
  if (localConfigs.length < thirdParty.length) {
    // Named explicitly: third-party rules are required, not optional, so a silent
    // shortfall here looks identical to a clean scan of well-covered code.
    log(
      `WARNING: ${thirdParty.length - localConfigs.length} of ${thirdParty.length} ` +
        `third-party rule repos unavailable — coverage is reduced for every language.`,
    )
  }
}

// --- Scan -------------------------------------------------------------------------

phase('Scan')

function scanPrompt(lang) {
  const rulesets = Array.isArray(lang.rulesets) ? lang.rulesets : []
  const includeFlags = lang.includeFlags || ''

  return `You are a Semgrep scanner for ${lang.name}.

Scan \`${cfg.target}\` and write results to \`${rawDir}\`.

## Approved rulesets — run exactly these, no additions, no substitutions
${rulesets.map((r) => `- ${r}`).join('\n') || '(none)'}
${localConfigs.length ? `\n## Third-party rule repos, already cloned (use these local paths as --config)\n${localConfigs.map((p) => `- ${p}`).join('\n')}` : ''}

## Command shape, one per ruleset, all launched together with \`&\` then \`wait\`

\`\`\`bash
semgrep ${proFlag} --metrics=off ${severityFlags} [INCLUDE] --config <ruleset> \\
  --json -o ${rawDir}/${lang.name.toLowerCase()}-<ruleset-name>.json \\
  --sarif-output=${rawDir}/${lang.name.toLowerCase()}-<ruleset-name>.sarif \\
  ${cfg.target} &
\`\`\`

## Rules
- \`--metrics=off\` on every invocation. Semgrep sends telemetry by default, and this
  runs against code being audited.
- ${cfg.proAvailable ? 'Pro is available: pass `--pro` for cross-file taint tracking.' : 'Pro is not available: omit `--pro`. Analysis is single-file only.'}
- Scan mode is **${mode}**: ${mode === 'important-only' ? `add \`${severityFlags}\` to every command.` : 'add no severity flags.'}
- Apply \`${includeFlags || '(no --include flags for this category)'}\` to the
  language-specific rulesets only. Do NOT apply --include to cross-language rulesets
  (p/security-audit, p/secrets) or to third-party repos — they carry rules for many
  languages and --include would silence most of them.
- Do not delete \`${cfg.outputDir}/repos\`. It is shared with the other scanners running
  right now and is cleaned up centrally once every scanner has finished.
- If one ruleset fails, capture its stderr, report it, and continue with the others.
  Never drop a failed ruleset silently.

## Return
\`findings\` is the total across your rulesets, \`sarifFiles\` the absolute paths you
actually wrote. Report what happened, not what was supposed to happen: if a ruleset
produced no output file, it belongs in \`errors\`, not in \`sarifFiles\`.`
}

// A barrier is correct here: the merge needs every language's SARIF at once, and the
// zero-output check below only means something across the full set.
const scans = (
  await parallel(
    cfg.languages.map(
      (lang) => () =>
        agent(scanPrompt(lang), {
          label: `scan:${lang.name}`,
          phase: 'Scan',
          effort: 'low',
          schema: SCAN_RESULT,
        }),
    ),
  )
).filter(Boolean)

const written = scans.reduce((n, s) => n + (s.sarifFiles || []).length, 0)
const scanErrors = scans.flatMap((s) => (s.errors || []).map((e) => `${s.language}: ${e}`))

if (scanErrors.length) log(`scan errors: ${scanErrors.join(' | ')}`)

if (scans.length < cfg.languages.length) {
  log(
    `WARNING: ${cfg.languages.length - scans.length} of ${cfg.languages.length} ` +
      `scanners returned nothing — those languages are unscanned, not clean.`,
  )
}

// Same failure this plugin's merge script guards against, one layer earlier: no SARIF
// written is a broken scan, and it is indistinguishable from a clean one downstream.
if (written === 0) {
  throw new Error(
    `semgrep-scan: no SARIF files were produced by any of ${cfg.languages.length} ` +
      `scanner(s). This is a scan failure, not a clean result. ` +
      (scanErrors.length ? `Errors: ${scanErrors.join(' | ')}` : 'No errors were reported.'),
  )
}

log(`${scans.length} language(s) scanned, ${written} SARIF file(s) written`)

// --- Merge ------------------------------------------------------------------------

phase('Merge')

const summary = await agent(
  `Merge the Semgrep SARIF output and report.

1. ${mode === 'important-only' ? `This run is **important-only**. First apply the metadata post-filter from the skill's scan-modes.md reference to each \`${rawDir}/*.json\`, writing \`*-important.json\` beside the originals. Leave the originals untouched.` : 'This run is **run-all**. No post-filtering.'}

2. Merge:
   \`\`\`bash
   ${cfg.mergeScript ? `uv run ${cfg.mergeScript}` : 'uv run "$(find ~/.claude/plugins -path \'*static-analysis/skills/semgrep/scripts/merge_sarif.py\' | head -1)"'} ${rawDir} ${cfg.outputDir}/results/results.sarif
   \`\`\`
   A non-zero exit means the merge failed — report that as a failed scan. Do not
   hand back a finding count from a merge that errored.

3. Remove the shared clone directory now that every scanner is finished:
   \`\`\`bash
   [ -n "${cfg.outputDir}" ] && rm -rf "${cfg.outputDir}/repos"
   \`\`\`

4. Read \`${cfg.outputDir}/results/results.sarif\` and break the findings down by
   severity and by rule.

Report the totals and where the files are. ${scanErrors.length ? `Note in your report that these scan errors occurred and coverage is incomplete: ${scanErrors.join(' | ')}` : ''}`,
  {
    label: 'merge-and-report',
    phase: 'Merge',
    effort: 'low',
    schema: {
      type: 'object',
      required: ['mergedSarif', 'totalFindings', 'bySeverity', 'merged'],
      properties: {
        merged: { type: 'boolean', description: 'false if merge_sarif.py exited non-zero' },
        mergedSarif: { type: 'string' },
        totalFindings: { type: 'integer' },
        bySeverity: { type: 'object', additionalProperties: { type: 'integer' } },
        topRules: { type: 'array', items: { type: 'string' } },
        notes: { type: 'string' },
      },
      additionalProperties: false,
    },
  },
)

if (!summary || summary.merged === false) {
  throw new Error(
    `semgrep-scan: the SARIF merge failed. ${(summary && summary.notes) || ''} ` +
      `Raw per-scanner output is preserved in ${rawDir}.`,
  )
}

return {
  mode,
  target: cfg.target,
  outputDir: cfg.outputDir,
  proEngine: Boolean(cfg.proAvailable),
  languagesScanned: scans.map((s) => s.language),
  sarifFilesWritten: written,
  totalFindings: summary.totalFindings,
  bySeverity: summary.bySeverity,
  topRules: summary.topRules || [],
  results: summary.mergedSarif,
  scanErrors,
  coverageComplete: scanErrors.length === 0 && scans.length === cfg.languages.length,
}
