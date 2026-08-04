# c-review

C/C++ security code review. Bug-class knowledge based on the
[Trail of Bits Testing Handbook](https://appsec.guide/docs/languages/c-cpp/).

Invoke with `/c-review:c-review`. Artifacts land in
`$(pwd)/.c-review-results/<iso-timestamp>/`.

## What it does

The skill collects four parameters and hands the review to a workflow script
(`workflows/c-review.js`). The workflow owns concurrency, retries and result
collection; agents return **structured data**, not files.

```
/c-review:c-review
└── SKILL.md: collect parameters, resolve paths, one Workflow call
    └── workflows/c-review.js
        ├── Detect   1 agent    language/platform flags from real API usage + codebase context
        ├── Hunt     13-18      one agent per bug-class group, in parallel, structured findings
        ├── Dedup    0-N        exact (file, line, class) merges in script; an agent only for
        │                       same-function collisions
        ├── Judge    1/candidate  false-positive verdict, then severity for survivors
        └── Persist  1 agent    findings.json -> generate_sarif.py + render_report.py
```

| Parameter | Values | Effect |
|---|---|---|
| `threat_model` | `REMOTE` / `LOCAL_UNPRIVILEGED` / `BOTH` | Drives which classes are in scope and the severity table the judge uses |
| `worker_model` | `haiku` / `sonnet` / `opus` / `inherit` | Model for every agent in the workflow |
| `severity_filter` | `all` / `medium` / `high` | What reaches `REPORT.md` and `REPORT.sarif` |
| `scope_subpath` | repo-relative dir, optional | Where findings may live. Context is read from the whole repo regardless |

### Output

```
.c-review-results/<stamp>/
├── findings.json    every finding, including merged duplicates and rejected candidates
├── REPORT.md        severity-grouped, filtered, deterministic render of findings.json
└── REPORT.sarif     SARIF 2.1.0 export of the same reported set
```

`REPORT.md` and `REPORT.sarif` are both generated from `findings.json` by
`scripts/render_report.py` and `scripts/generate_sarif.py`, which share one
definition of "reported" — so the two artifacts cannot describe different sets.

## Bug classes

Sixty-six classes in eighteen groups. Group sizes run from two to five, so no single
agent owns a disproportionate share of the run.

Always on (13 groups, 49 classes; two drop under `REMOTE`):

memory bounds · string handling · format and input APIs · object lifecycle ·
**integer overflow and bounds arithmetic** · conversions, precedence and undefined
behavior · return values and errno · files and sockets · concurrency · ambient state and
DoS · build and declaration hygiene · **library API contract misuse** ·
**logic, protocol and crypto**

Conditional: C++ lifetime and C++ class semantics (`is_cpp`); Windows processes, Windows
filesystem and paths, Windows IPC and crypto (`is_windows`). POSIX-only classes drop when
the code does not use POSIX APIs.

Three grouping choices are deliberate, each answering something the evaluation measured:

- **`logic-and-protocol`** has no equivalent in the previous taxonomy. It covers what
  memory-safety classes do not name — delimiter and namespace injection, protocol state
  machines that skip a check, deserialization that lets input pick a type, an encoding
  invariant enforced at some call sites of a shared macro but not all. Both of the hardest
  bugs in the evaluation corpus fall there, and no configuration found either. It also
  carries `crypto-misuse`, because `windows-crypto` is Windows-gated and a POSIX daemon
  would otherwise get no crypto coverage at all.
- **`integer-safety`** is deliberately small. Four of the seven ground-truth bugs in the
  evaluation corpus were integer overflows, and the arithmetic worker that owned four
  classes at once found one of them. The highest-base-rate class gets its own agent.
- **`library-api-misuse`** is split out from build hygiene. Checking a build flag and
  auditing every comparator for transitivity are not the same kind of work, and pairing
  them let the cheap one crowd out the expensive one.

## Evaluation

`evals/` holds a ground-truth corpus (libexpat at `R_2_4_3`, seven CVEs), a grader, and
deterministic tests for the grader. See `evals/README.md` for how to run a full eval and
what it costs — roughly a million tokens, which is why it is not in `make check`. The
grader refuses to score a run that produced no findings rather than reporting `0/7`.

## Design decisions worth keeping

The v1 architecture was measured against that corpus and found 1 of 7 ground-truth bugs
for 1.07 M tokens — last place on recall, at nine times the cost of a single bare prompt.
Four of its defects are corrected here, and undoing any of them regresses the plugin:

- **No clearing from recalled knowledge.** Every negative conclusion rests on the code in
  front of the reviewer, and a claimed mitigation must cite a `path:line`. The v1 recall
  loss came from one worker clearing thirteen passes by asserting that upstream CVE fixes
  were present when they were not — suppressing two ground-truth bugs inside its own remit
  that three cheaper configurations found by plain reading.
- **Coverage is an audit note, not a gate.** The v1 gate accepted any row whose outcome
  began with `cleared`, so it certified that a row existed rather than that a search
  happened, and laundered the fabricated clearances above into a clean 40/40 record. Rows
  now carry cited evidence and nothing validates or depends on them.
- **Platform gating is on API usage, not on a single include.** v1 fired three Windows
  worker groups at a portable XML parser because a compatibility header included
  `<windows.h>` — 27% of the fan-out, all of it finding nothing.
- **No stay-in-lane rule.** v1 told workers to skip bugs outside their assigned class
  because "another worker covers them", which was false for every class the manifest did
  not enumerate. Hunters now report anything they find and flag it.

Also removed, because a workflow engine subsumes all of it: the cache primer, wave
planning, the task ledger, per-worker index shards, `findings-index.txt`, orphan
reconciliation, retry classification, prefix-space clearing, the report safety net,
`build_run_plan.py` and `validate_artifacts.py`.

## Not for

- Kernel drivers or modules (Linux, Windows, macOS)
- Managed languages (Java, C#, Python, Go, Rust)
- Embedded or bare-metal code with no libc
