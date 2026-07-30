# Scan Planning

Detection, ruleset selection, and the approval gate. Execution is not here — once the
user approves, hand off to the `semgrep-scan` workflow, which fans out one scanner per
language and merges the results.

The split follows what each half is good at. Planning needs judgment and a conversation
with the user; execution is the same three commands over N languages, so it lives in a
script where the loop and the error handling cannot be re-interpreted per run.

---

## Step 1: Resolve Output Directory, Detect Languages and Pro Availability

> **Entry:** User has specified or confirmed the target directory.
> **Exit:** `OUTPUT_DIR` resolved and created; language list with file counts produced; Pro availability determined.

If the user specified an output directory, use it. Otherwise auto-increment. Either way
`mkdir -p` — later steps assume it exists.

```bash
if [ -n "$USER_SPECIFIED_DIR" ]; then
  OUTPUT_DIR="$USER_SPECIFIED_DIR"
else
  BASE="static_analysis_semgrep"
  N=1
  while [ -e "${BASE}_${N}" ]; do
    N=$((N + 1))
  done
  OUTPUT_DIR="${BASE}_${N}"
fi
mkdir -p "$OUTPUT_DIR/raw" "$OUTPUT_DIR/results"
OUTPUT_DIR=$(cd "$OUTPUT_DIR" && pwd)   # absolute — the workflow's agents cannot resolve relative paths
echo "Output directory: $OUTPUT_DIR"
```

**Detect Pro availability:**

```bash
if ! command -v semgrep >/dev/null 2>&1; then
  echo "ERROR: semgrep is not installed. Install from https://semgrep.dev/docs/getting-started/"
  exit 1
fi
semgrep --version
semgrep --pro --validate --config p/default 2>/dev/null && echo "Pro: AVAILABLE" || echo "Pro: NOT AVAILABLE"
```

Pro matters enough to check every time: it enables cross-file taint tracking, and without
it the analysis is single-file only. Report which engine is in play — a reader comparing
two scans needs to know why the finding counts differ.

**Detect languages** using Glob, not Bash. Count matches for:

`**/*.py`, `**/*.js`, `**/*.ts`, `**/*.tsx`, `**/*.jsx`, `**/*.go`, `**/*.rb`, `**/*.java`, `**/*.php`, `**/*.c`, `**/*.cpp`, `**/*.rs`, `**/Dockerfile`, `**/*.tf`

Then Read the framework markers — `package.json`, `pyproject.toml`, `Gemfile`, `go.mod`,
`Cargo.toml`, `pom.xml` — for framework dependencies, since those select extra rulesets
(React and Express in `package.json`; Django, Flask, FastAPI in `pyproject.toml`).

| Detection | Category |
|-----------|----------|
| `.py`, `pyproject.toml` | Python |
| `.js`, `.ts`, `package.json` | JavaScript/TypeScript |
| `.go`, `go.mod` | Go |
| `.rb`, `Gemfile` | Ruby |
| `.java`, `pom.xml` | Java |
| `.php` | PHP |
| `.c`, `.cpp` | C/C++ |
| `.rs`, `Cargo.toml` | Rust |
| `Dockerfile` | Docker |
| `.tf` | Terraform |
| k8s manifests | Kubernetes |

**Detecting zero languages is a failure, not an empty result.** Stop and say so. The
workflow refuses an empty language list for the same reason: a scan of nothing reports no
findings, which reads exactly like a clean codebase.

---

## Step 2: Select Scan Mode and Rulesets

> **Entry:** Step 1 complete — languages detected, Pro status known.
> **Exit:** Mode selected; ruleset list compiled per language.

Select mode with `AskUserQuestion`:

```
header: "Scan Mode"
question: "Which scan mode should be used?"
options:
  - label: "Run all (Recommended)"
    description: "Full coverage — all rulesets, all severity levels"
  - label: "Important only"
    description: "Security vulnerabilities only — medium-high confidence and impact, no code quality"
```

Then follow the **Ruleset Selection Algorithm** in [rulesets.md](rulesets.md): security
baseline, language rulesets, framework rulesets, infrastructure, and the third-party sets
(Trail of Bits, 0xdea, Decurity) — which are required whenever the language matches, not
optional, because they catch what the official registry does not.

---

## Step 3: Present Plan and Get Approval

> **Entry:** Step 2 complete.
> **Exit:** User has explicitly approved. Quote their confirmation.

> **⛔ This gate cannot move into the workflow.** Workflows run in the background with no
> way to prompt. Approval has to happen here, before the handoff — which is also why the
> workflow's own description says never to invoke it on an unapproved plan.

Present the target, output directory, engine, mode, detected languages with file counts,
and **every ruleset listed explicitly** so the user can strike any of them. Invite
modification, then wait.

- **Valid approval:** "yes", "proceed", "approved", "go ahead", "run it"
- **Not approval:** the original "scan this codebase" request, silence, or a question
  about the plan

If the user modifies the ruleset list, re-present it and wait again.

### Log approved rulesets

```bash
cat > "$OUTPUT_DIR/rulesets.txt" << RULESETS
# Semgrep Scan — Approved Rulesets
# Generated: $(date -Iseconds)
# Scan mode: <run-all|important-only>

p/security-audit
p/secrets
<...one per line, exactly as approved...>
RULESETS
```

---

## Handoff

Approval in hand, invoke the workflow:

```
Workflow: static-analysis:semgrep-scan
args: {
  "target": "<absolute path>",
  "outputDir": "<absolute $OUTPUT_DIR>",
  "mode": "run-all" | "important-only",
  "proAvailable": true | false,
  "languages": [
    { "name": "Python", "rulesets": ["p/python", "p/django"], "includeFlags": "--include=\"*.py\"" },
    { "name": "Docker", "rulesets": ["p/dockerfile"], "includeFlags": "" }
  ],
  "thirdPartyRepos": ["https://github.com/trailofbits/semgrep-rules"],
  "mergeScript": "{baseDir}/scripts/merge_sarif.py"
}
```

Two things about that shape:

- **Cross-language rulesets go in their own entry, not into every language.** `p/security-audit`
  and `p/secrets` carry rules for many languages; attaching them to each language entry
  runs them N times over the same tree and inflates the merge with duplicates.
- **`includeFlags` applies to that language's own rulesets only.** The workflow tells its
  scanners not to apply `--include` to cross-language or third-party configs, because
  `--include="*.py"` over a multi-language rule repo silences nearly all of it.

The workflow returns finding counts, a per-severity breakdown, `scanErrors`, and
`coverageComplete`. **Report `coverageComplete: false` to the user.** It means some
ruleset or scanner failed, and the finding count is a floor, not a total.
