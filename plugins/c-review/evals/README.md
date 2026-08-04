# c-review evaluation

Measures whether c-review finds bugs, against a corpus where the answer is known.
Before this existed the plugin shipped 56 passing tests, none of which would have
noticed that it found one of seven ground-truth bugs at nine times the cost of a
single prompt.

Two things live here and they cost very different amounts:

| | What it is | Cost | Runs in `make check` |
|---|---|---|---|
| `test_grade.py` | Unit tests for the grader, over JSON fixtures | free, ~0.05 s | yes |
| A full eval run | The real pipeline over the real corpus, then graded | ~0.5–1.5 M tokens | **no** |

## The corpus

libexpat at tag `R_2_4_3` (2022-01-16), `expat/lib/` — 19 files, ~13 K lines of C.

Ground truth is the **seven CVEs fixed in the next three releases** (2.4.4, 2.4.5,
2.4.6), i.e. every bug simultaneously live at that commit. They were selected by
project history, not by c-review's taxonomy, so two of them sit outside classic
memory-safety classes on purpose — those are the ones that test whether a bug-class
checklist helps or anchors.

`ground_truth/libexpat-R_2_4_3.json` is the record. Three tiers: EASY (3), MEDIUM (2),
HARD (2).

## Running the full eval

```sh
cd plugins/c-review/evals

# 1. Fetch the corpus. Needs network; fails loudly with no offline fallback.
#    Version markers are scrubbed by default so a reviewer cannot read the answer
#    off the version number. Prints where each ground-truth function actually is,
#    so anchor drift shows up before it silently deflates recall.
uv run fetch_corpus.py --dest /tmp/c-review-eval/libexpat

# 2. Run c-review against it, from a session whose working directory is the clone.
#    threat_model REMOTE, severity_filter all, scope expat/lib, and pick a model.
#    Do not tell the reviewer that bugs exist, where they are, or which project
#    this is — the first attempt at this measurement was invalidated because
#    reviewers found the git history and diffed against upstream instead of
#    reading the code.

# 3. Grade the run's findings.json.
uv run grade.py \
  --findings /tmp/c-review-eval/libexpat/.c-review-results/<stamp>/findings.json \
  --ground-truth ground_truth/libexpat-R_2_4_3.json \
  --json /tmp/c-review-eval/score.json
```

### Cost

The v1 (hand-orchestrated) architecture measured **1,065,732 tokens** for 1/7 recall.
Reference points from the same experiment: a single bare prompt was 116 K for 2/7, and
a matched-compute generic fan-out was 1.21 M for 3/7. Budget roughly 0.5–1.5 M tokens
for a run depending on the model and how much the hunters read. This is why the full
eval is not wired into `make check`.

## Grading rule

A finding is a **HIT** when it

1. names the correct **file**,
2. places itself at the correct **site** — a matching function name, or a line within
   `grading.line_window` (10) of an anchor — and
3. its text identifies the actual **defect mechanism**.

`functions` is the primary site key; the line window is the fallback for a reviewer
that reports a macro or a file-level location. Mechanism matching is deterministic:
every group in the item's `mechanism_all_of` must contribute at least one substring to
the finding's text.

Four outcomes, not two:

- **HIT** — found and reported.
- **SUPPRESSED** — a reviewer found it and the pipeline dropped it (a judge rejected
  it, or dedup buried it). This is the failure that caused the v1 recall loss, and it
  needs a different fix from a miss. `--scope all` re-scores these as hits, which
  answers "did anyone see it?" rather than "was the user told?".
- **NEAR_MISS** — right site, mechanism keywords did not match. Either the finding
  describes a different bug at that line, or the keyword list has gone stale. Read it
  rather than trusting the number.
- **MISS** — nothing at that site.

Recall counts HITs only.

### `--scope`

- `reported` (default) — what a user actually sees: survivors that pass the severity filter.
- `primaries` — everything that reached a judge.
- `all` — every raw finding, including merged duplicates and rejected candidates.

## The grader refuses to score an empty run

`grade.py` exits **2** when it graded zero ground-truth items or zero findings, and
says which. A checker that inspects nothing must not report success — `0/7` from a run
that produced no findings at all is a pipeline failure, and printing it as a recall
number makes a broken run look like a measured one.

`fixtures/all_seven_found.json` is the fixture that proves the grader still detects its
target: it is a synthetic run in which every ground-truth bug is correctly described,
and `test_all_seven_fixture_scores_full_recall` asserts 7/7. If a mechanism keyword
list stops matching a correct description, that test fails instead of every future run
quietly scoring lower. `fixtures/none_found.json` is the negative half — real findings
in the right files that must all grade MISS, so file-only matching cannot pass.

## Caveats on any number produced here

- **n = 1 corpus, 7 bugs, one run per configuration.** Recall differences of one or two
  bugs are inside the noise. Cost ratios are not.
- **libexpat is famous and these CVEs are public**, so absolute recall is inflated. Only
  between-configuration comparison is meaningful, and only when the blinding held.
- **libexpat is mature, fuzzed and CVE-hardened** — the easy findings are long gone.
  Results on fresh legacy C will look different.
- **Precision is not measured here.** The grader counts findings that match no
  ground-truth bug as `extra_findings`; whether they are real bugs or false positives
  needs a human.
