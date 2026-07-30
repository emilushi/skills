---
name: semgrep
description: >-
  Run Semgrep static analysis scan on a codebase. Supports two scan modes — "run
  all" (full ruleset coverage) and "important only" (high-confidence security
  vulnerabilities). Automatically detects and uses Semgrep Pro for cross-file
  taint analysis when available. Use when asked to scan code for
  vulnerabilities, run a security audit with Semgrep, find bugs, or perform
  static analysis. Plans and gets approval, then hands execution to the
  static-analysis:semgrep-scan workflow.
allowed-tools: Bash Read Glob Grep Agent AskUserQuestion Workflow
---

# Semgrep Security Scan

Detect languages, choose rulesets, get the user's approval, then hand off to the
`semgrep-scan` workflow for execution.

## The split

**This skill plans. The workflow executes.**

| | Owner | Why |
|---|---|---|
| Detect languages, pick rulesets, get approval | this skill | Needs judgment and a conversation with the user |
| Scan N languages, merge SARIF, report | [`semgrep-scan` workflow](../../workflows/semgrep-scan.js) | Same commands over N items — a loop, not a decision |

Approval **cannot** move into the workflow: workflows run in the background and cannot
prompt. Never invoke `semgrep-scan` on a plan the user has not explicitly approved.

## Essential Principles

1. **Always use `--metrics=off`** — Semgrep sends telemetry by default; `--config auto` also phones home. Every `semgrep` command must include it, and this runs against code being audited.
2. **The approval gate is real** — "scan this codebase" is a request, not approval of a plan. Present exact rulesets, target, engine, and mode; wait for explicit consent.
3. **Third-party rulesets are required, not optional** — Trail of Bits, 0xdea, and Decurity rules catch vulnerabilities absent from the official registry. Include them whenever the detected language matches.
4. **Always check for Semgrep Pro before scanning** — Pro enables cross-file taint tracking. Skipping the check means silently missing inter-file vulnerabilities, and the user cannot interpret the results without knowing which engine ran.
5. **Zero of anything is a failure, not a result** — zero languages detected, zero SARIF files written, or zero parseable results means the scan broke. Each is indistinguishable from a clean codebase in the output, so each must be reported as an error.

## When NOT to Use

- Binary analysis → use binary analysis tools
- Semgrep already wired into CI → use the existing pipeline
- Need cross-file analysis but no Pro license → consider CodeQL instead
- Writing custom Semgrep rules → `semgrep-rule-creator` skill
- Porting rules to other languages → `semgrep-rule-variant-creator` skill

## Prerequisites

**Required:** Semgrep CLI (`semgrep --version`). See [installation docs](https://semgrep.dev/docs/getting-started/).

**Optional:** Semgrep Pro — cross-file taint tracking, inter-procedural analysis, and extra
languages (Apex, C#, Elixir):

```bash
semgrep --pro --validate --config p/default 2>/dev/null && echo "Pro available" || echo "OSS only"
```

## Output Directory

Resolved **once**, at the start of Step 1, and used everywhere after.

- User specified one → use it.
- Otherwise → `./static_analysis_semgrep_1`, incrementing the suffix if taken.

Always `mkdir -p`, and always pass the **absolute** path onward — the workflow's scanner
agents cannot resolve a relative one.

```
$OUTPUT_DIR/
├── rulesets.txt          # approved rulesets, logged after Step 3
├── raw/                  # per-scan output, unfiltered
└── results/results.sarif # merged
```

## Scan Modes

| Mode | Coverage | Findings Reported |
|------|----------|-------------------|
| **Run all** | All rulesets, all severity levels | Everything |
| **Important only** | All rulesets, pre- and post-filtered | Security vulns only, medium-high confidence/impact |

**Important only** filters twice: `--severity MEDIUM --severity HIGH --severity CRITICAL`
at scan time, then on JSON metadata (`category=security`, `confidence`/`impact` in
{MEDIUM, HIGH}). See [scan-modes.md](references/scan-modes.md).

## Workflow

Follow [scan-planning.md](references/scan-planning.md) for Steps 1–3, then invoke:

```
Workflow: static-analysis:semgrep-scan
```

with the args documented in that file's Handoff section. The workflow clones third-party
rule repos once, spawns one scanner per language category, merges via
`scripts/merge_sarif.py`, and returns finding counts plus `scanErrors` and
`coverageComplete`.

**Report `coverageComplete: false` to the user.** It means a ruleset or scanner failed and
the finding count is a floor, not a total.

## Rationalizations to Reject

| Shortcut | Why It's Wrong |
|----------|----------------|
| "User asked for a scan, that's approval" | The original request is not plan approval. Present the plan and wait for explicit consent |
| "I already know what they want" | Assumptions scan the wrong directories with the wrong rules. Present the plan for verification |
| "Just use default rulesets" | The user must see and approve the exact list |
| "Add extra rulesets without asking" | Changing an approved list without consent breaks the gate |
| "Third-party rulesets are optional" | Trail of Bits, 0xdea, Decurity catch what the registry misses — required |
| "Use `--config auto`" | Sends metrics, and gives up control over which rules run |
| "Pro is too slow, skip `--pro`" | Cross-file analysis finds what single-file analysis structurally cannot |
| "Semgrep handles GitHub URLs natively" | URL handling fails on repos with non-standard YAML; always clone first |
| "Use `.` or a relative path as target" | Scanner agents cannot resolve relative paths |
| "Zero findings means the code is clean" | It equally means nothing was scanned, or every result failed to parse. Check `coverageComplete` and the exit code before saying "clean" |
| "The merge produced valid JSON, so the scan worked" | An empty `results.sarif` is valid JSON. `merge_sarif.py`'s exit code is what distinguishes a clean scan from a wholly failed one |

## Reference Index

| File | Content |
|------|---------|
| [scan-planning.md](references/scan-planning.md) | Steps 1–3: detection, ruleset selection, approval gate, handoff args |
| [rulesets.md](references/rulesets.md) | Ruleset catalog and selection algorithm |
| [scan-modes.md](references/scan-modes.md) | Pre/post-filter criteria and jq commands |
| [scanner-task-prompt.md](references/scanner-task-prompt.md) | Scanner contract — what the workflow's agents are told |

## Agents

| Agent | Purpose |
|-------|---------|
| `static-analysis:semgrep-scanner` | Executes Semgrep for one language category. Spawned by the workflow, not by this skill |

## Success Criteria

- [ ] Output directory resolved once, absolute, and created
- [ ] Languages detected with file counts; **zero detected reported as an error**
- [ ] Pro status checked and reported
- [ ] Scan mode selected by the user
- [ ] Rulesets include third-party rules for every detected language
- [ ] User explicitly approved the plan; approval quoted
- [ ] Approved rulesets logged to `$OUTPUT_DIR/rulesets.txt`
- [ ] Workflow invoked with absolute paths and the approved ruleset list
- [ ] `results.sarif` exists and `merge_sarif.py` exited zero
- [ ] `coverageComplete` and any `scanErrors` reported to the user
- [ ] Cloned rule repos cleaned up from `$OUTPUT_DIR/repos/`
