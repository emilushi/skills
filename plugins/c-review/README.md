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
        ├── Dedup    0-N        exact (file, line, class) merges in script; agents only for
        │                       same-function collisions, batched by file
        ├── Judge    1/file-group  false-positive verdict, then severity for survivors
        └── Persist  1 agent    findings.json -> generate_sarif.py + render_report.py
```

| Parameter | Values | Effect |
|---|---|---|
| `threat_model` | `REMOTE` / `LOCAL_UNPRIVILEGED` / `BOTH` | Drives which classes are in scope and the severity table the judge uses |
| `worker_model` | `haiku` / `sonnet` / `opus` / `inherit` | Model for every agent in the workflow |
| `severity_filter` | `all` / `medium` / `high` | What reaches `REPORT.md` and `REPORT.sarif` |
| `scope_subpath` | repo-relative dir, optional | Where findings may live. Context is read from the whole repo regardless |

Three workflow arguments are optional and rarely set by hand:

| Argument | Default | Effect |
|---|---|---|
| `judgeMode` | `batched` | `batched` groups candidates by source file; `per-finding` is one agent per candidate, retained so the two can be measured |
| `judgeBatchSize` | `5` | Cap on candidates per judge agent; splits are balanced (12 findings → 4+4+4) |
| `injectFindings` | absent | **Eval-only hook.** Appends synthetic findings before dedup and judging. Never use it in a real review — whatever is passed is reported as if a hunter found it |

### Why the judge batches

The 2026-08-04 libexpat run cost 2.66 M tokens across 34 agents. Per-agent cost was
essentially unchanged from the previous architecture (76 K → 78 K, 1.03×) while agent
count went 14 → 34 (2.43×): **cost is agent count, not per-agent verbosity.** One judge
agent per finding was the single largest contributor, at 13 of those 34 agents.

Batching by source file is not only cheaper. A judge holding four findings from one file
opens it once and judges all four with the same context, which is strictly more than
four separate agents each have. The size cap keeps any one agent from carrying an outlier
share, splits are balanced rather than greedy, and a one-candidate batch takes the
single-candidate prompt unchanged. Dedup batches the same way, and a merge whose members
come from two different collision buckets is discarded in code — so batching cannot merge
findings in different functions.

Same run, batched: 4 judge agents and 1 dedup agent instead of 13 and 3.

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

`bench/` holds the benchmark harness: three corpora whose bugs are **injected by us**, a
grader, an oracle detector, a judge benchmark, and 130 deterministic tests that run in
`make check`. See `bench/README.md`.

The previous corpus — libexpat at a tag with seven public CVEs — has been retired. It
measured whether a reviewer could look the answer up: three of sixteen hunters did,
one identified the tree as byte-identical to a named release, and four of five
ground-truth hits in the headline run came from the contaminated hunter. Every bug in
the new corpora was injected at a site we chose, so no CVE record, commit log or
advisory describes any of them, and the base code of the two real-C corpora is
de-identified so it cannot be lined up against upstream.

Three things the recall number alone cannot tell you, all of which the harness reports:

- **Whether the arm used an oracle.** Transcripts are parsed and only real `tool_use`
  blocks count — the string `WebFetch` appears in almost every transcript as a tool
  *definition*, so a substring scan would flag every arm including the honest ones. An
  arm with a violation is **excluded** from the comparison, not annotated. Consulting
  upstream is still legitimate in a real review and nothing in the review path penalises
  it; only a benchmark cares.
- **What the bugs cost to find.** Tokens, agents and wall time per arm, with the
  estimate printed before the run and the actual after it.
- **Judgement.** Every run so far returned 100% `TRUE_POSITIVE` — 4/4 in v1, 13/13 in v2
  — which cannot distinguish a good judge with nothing to reject from one that accepts
  whatever it is handed. `bench/judge_bench/` seeds eight plausible-but-wrong findings
  and scores retention and rejection separately.

No scorer here will score nothing: each exits non-zero rather than reporting `0/N` or
`0%` from an empty inspection, and the corpus gate fails any check that inspected zero
items.

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
