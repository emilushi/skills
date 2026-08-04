---
name: c-review
description: Performs comprehensive C/C++ security review for memory corruption, integer overflows, race conditions, and platform-specific vulnerabilities. Use when auditing native C/C++ applications, reviewing daemons or services for memory safety, or hunting integer overflow / use-after-free / race conditions in userspace code.
allowed-tools: Workflow AskUserQuestion Bash Read
---

# C/C++ Security Review

Collects four parameters, then hands the whole review to a workflow script. The
workflow owns concurrency, retries and result collection; this skill only resolves
inputs and returns the report.

## When to Use

Native C/C++ application security review: memory safety, integer overflow, races,
type confusion, Linux/macOS daemons, Windows userspace services.

## When NOT to Use

- Kernel drivers or modules (Linux, Windows, macOS).
- Managed languages (Java, C#, Python, Go, Rust).
- Embedded or bare-metal code with no libc.

---

## Phase 0 — Parameters

Parse any free text on the invocation line (`flamenco only`, `high severity only`,
`use haiku`) and pre-fill what it implies. Then make **one** `AskUserQuestion` call for
whatever is still unresolved. Never silently default a required parameter.

| Parameter | Values | Inferring it from the invocation |
|---|---|---|
| `threat_model` | `REMOTE` / `LOCAL_UNPRIVILEGED` / `BOTH` | "remote", "network", "attacker" → `REMOTE`; "local", "unprivileged" → `LOCAL_UNPRIVILEGED`; otherwise ask |
| `worker_model` | `haiku` / `sonnet` / `opus` / `inherit` | An explicit model name. Otherwise ask. `inherit` uses the session model |
| `severity_filter` | `all` / `medium` / `high` | "all", "every", "noisy" → `all`; "medium and above" → `medium`; "high only" → `high`; otherwise ask |
| `scope_subpath` | repo-relative directory, optional | "X only", "just audit X/" → the matching subdirectory, fuzzy-matched against top-level dirs. Absent → `.`. Ambiguous → ask |

Two scopes stay separate for the whole run:

- **`finding_scope_root`** = `scope_subpath` (default `.`) — a finding must live inside it.
- **`context_roots`** = `.` by default — read freely to establish callers, build flags and
  reachability. Set it to `finding_scope_root` only if the user explicitly forbids wider
  reading, and say that reachability confidence drops when you do.

## Phase 1 — Resolve paths

```bash
# Plugin root. Abort if it does not resolve rather than running with an empty path.
root="${CLAUDE_PLUGIN_ROOT:-}"
[ -n "$root" ] && [ -f "$root/workflows/c-review.js" ] && echo "$root"
# Fallback for a local checkout or a cache layout that does not set the variable:
find ~/.claude . -path '*/c-review/workflows/c-review.js' -print -quit 2>/dev/null
```

```bash
# Output directory. The workflow cannot call Date.now(), so the timestamp is made here.
output_dir="$(pwd)/.c-review-results/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$output_dir"
echo "$output_dir"
```

## Phase 2 — Run the workflow

Invoking this skill **is** the opt-in to multi-agent orchestration — call `Workflow`
without asking again. A review of a real codebase also runs past any default workflow
size guideline; that guideline is advisory and this is the case it exempts. Do not shrink
the fan-out to fit it, and do not substitute hand-spawned `Agent` calls.

One `Workflow` call. `scriptPath` takes the absolute path resolved in Phase 1; `args`
must be a real JSON object, not a JSON-encoded string.

```
Workflow({
  scriptPath: "<plugin_root>/workflows/c-review.js",
  args: {
    outputDir:        "<output_dir>",
    pluginRoot:       "<plugin_root>",
    threatModel:      "REMOTE",
    severityFilter:   "all",
    findingScopeRoot: "expat/lib",
    contextRoots:     ".",
    workerModel:      "sonnet"
  }
})
```

The workflow validates its own arguments and throws with a named field if one is
missing. It runs five phases:

| Phase | Agents | What it does |
|---|---|---|
| Detect | 1 | Language and platform flags **from actual API usage**, plus purpose, entry points, trust boundaries and existing hardening |
| Hunt | 13–18 | One agent per bug-class group, in parallel, returning structured findings and a coverage note |
| Dedup | 0–N | Identical `(file, line, class)` merges happen in the script; an agent runs only for same-function collisions |
| Judge | one per candidate | False-positive verdict, then severity for survivors |
| Persist | 1 | Writes `findings.json`, then runs the SARIF and report generators |

Group count depends on detection: **13** always-on groups, **+2** when C++ translation
units are compiled, **+3** when Win32 APIs are actually used. `LOCAL_UNPRIVILEGED` adds no
groups — it restores two *classes* (privilege-drop, envvar) that `REMOTE` drops, taking the
always-on class count from 47 to 49. Groups whose classes all filter out are dropped.

## Phase 3 — Return the report

`Read <output_dir>/REPORT.md` and return it. Then surface, prominently and separately
from the findings, anything in the workflow result that means the run was partial:

- `groupsFailed` — those bug classes were **not covered**. Do not let a clean report imply
  they were.
- `unjudged` — those findings carry an unvalidated severity.
- `artifactsWritten: false` — `REPORT.md` and `REPORT.sarif` are missing. The workflow
  result still carries `reportedFindings` and `stats`; report from those and say the
  artifacts failed, including `artifactError`.
- `hunterNotes` — a reviewer's own note about what it could not finish.

List the artifacts: `findings.json`, `REPORT.md`, `REPORT.sarif`.

---

## Rationalizations to Reject

- **"The run mostly worked, so I'll just present the report."** A failed hunter group is
  uncovered ground, not a rounding error. Report it next to the findings, not in a
  footnote.
- **"I'll write the findings myself instead of running the workflow."** Hand-orchestrating
  this is what the rewrite removed. It cost nine times a single prompt for worse recall.
- **"Zero findings, so there is nothing to report."** A zero-finding run still produces
  `REPORT.md` and `REPORT.sarif`, and a zero-finding run on real C code is itself worth
  saying out loud.
- **"The workflow returned findings, so I can skip reading REPORT.md."** The tool result is
  capped and carries a summary. The report is the artifact.
- **"I'll re-judge or re-severity a finding the judge already ruled on."** The verdict is in
  the artifact. Overriding it in the chat response makes the two disagree.

## Design notes

Four defects from the measured evaluation are load-bearing here; do not undo them by
"improving" the prompts.

- **No reviewer may clear anything from recalled knowledge.** Every negative conclusion
  rests on the code, and any claimed mitigation cites a `path:line`. A worker previously
  cleared thirteen passes by asserting upstream CVE fixes were present when they were
  not, suppressing two real bugs inside its own remit.
- **Coverage is a note, not a gate.** Nothing validates the coverage rows and nothing
  fails because of them. The previous gate accepted any row whose outcome began with
  "cleared", so it certified that a row had been written, not that a search had happened —
  which turned a fabricated clearance into a clean audit record.
- **Platform gating is on usage, not includes.** A portability shim that includes
  `<windows.h>` is not a Windows codebase; treating it as one previously burned 27% of
  the fan-out on a portable XML parser.
- **Every hunter may report anything.** There is no stay-in-lane rule, and the taxonomy
  carries an explicit logic-and-protocol group, because the classes it omits — injection,
  protocol state machines, encoding invariants, authorization — are where the bugs no
  configuration found were hiding.

The plugin is measured, not argued: `evals/` holds a seven-CVE ground-truth corpus, a
grader, and the note that the full run costs roughly a million tokens.
