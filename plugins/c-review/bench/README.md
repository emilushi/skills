# c-review benchmark harness

Answers one question repeatedly: **does a change to this plugin find more bugs, and at
what cost?** Bugs found, false positives, tokens, agents and wall time, per bug class
and per difficulty tier, against ground truth that no CVE database contains.

It exists because the plugin's first real measurement was invalidated three times in one
day. Reviewers found the answers instead of the bugs: one fetched upstream and diffed,
another defeated a version scrub and identified the corpus as "byte-identical to real
expat release R_2_4_3", and four of five ground-truth hits in the headline run came from
the contaminated reviewer. Separately, a result file was read while it was still being
written, and three different recall numbers were published from the same run.

Every design decision below is a response to one of those.

## The measurement loop

```sh
cd plugins/c-review/bench

uv run bench.py corpora                        # what exists
uv run bench.py verify --corpus sigil          # the integrity gate — required first
uv run bench.py plan --tier standard --out /tmp/bench-run-1
# run each packet in /tmp/bench-run-1/packets/ exactly as written
uv run bench.py collect --run /tmp/bench-run-1 --arm bare --corpus sigil \
  --result <result.json> --meta <meta.json> --transcript ~/.claude/projects/<slug>/
uv run bench.py score --run /tmp/bench-run-1
```

The order is enforced, not suggested. `plan` refuses a corpus with no verification stamp.
`collect` refuses a result whose meta file does not say `"complete": true` and refuses one
whose bytes are still changing. `score` excludes any arm whose transcript shows oracle
use, and exits non-zero when it does.

Exit codes: `0` did the thing, `2` inspected nothing or found a disqualifying problem,
`3` unusable input.

## Cheating is made useless rather than forbidden

Telling an agent not to look things up demonstrably does not work — 3 of 16 hunters did
it anyway. So the defence is that there is nothing to find:

1. **The bugs are ours.** Every ground-truth bug is injected by this harness at a site we
   chose. No CVE record, commit message, advisory or changelog describes any of them,
   because none of them has ever existed anywhere else.
2. **The base code is de-identified.** Identifiers, filenames and identifying string
   literals are renamed through one deterministic seeded mapping; comments and banners
   are stripped. An agent that guesses the project family still cannot line a file up
   against upstream to diff it. Renaming reaches inside string literals two ways: whole
   identifiers, and *segment* words that thread through the namespace (a word of five or
   more characters appearing in two or more identifiers), which is what catches
   `"widgetlib: bad slot"` where `widgetlib` is never an identifier on its own. Ordinary
   English in an error message is left alone, and `forbidden_strings` in the recipe is
   the enforcement the gate checks.
3. **Decoys.** Ten no-op mutations per corpus, so a reconstructed diff *against upstream* is
   noise rather than a list of our injections. Note what this does not cover: the decoys are
   applied identically to both variants, which the `variants` gate check proves, so a
   bench-versus-**control** diff shows the bugs and nothing else. The decoys defend the
   upstream diff; the containment and tree-comparison rules defend the control diff.
4. **Detection, then invalidation.** Transcripts are parsed and oracle use is a
   disqualification: the arm's numbers are excluded from the comparison table and a
   banner says so. Not a footnote — a footnote does not survive being copied into a
   summary.
5. **A canary.** Since every bug is ours, a finding that cites a CVE number for one is
   proof of recall or invention. Those are recorded per arm.

**What this does not defend against, stated plainly:** training-data recall of code
*patterns*. A model that has read the base project may still recognise the shape of a
decompression loop or a parser state machine, and de-identification does not change that.
What it cannot recover is *where we put the bugs*, because that exists only in this
harness's private files. Absolute recall numbers are therefore still soft; comparisons
between arms on the same corpus are what the harness is for.

### How the oracle check tells use from mention

The string `WebFetch` appears in nearly every transcript twice over: once in the list of
tools offered to the model, and once in the arm packet telling it not to use them. A
substring grep flags every arm including the honest ones, and a check that always fires
gets switched off. So nothing greps raw text:

- transcripts are parsed as JSON, and **only `{"type": "tool_use"}` content blocks count
  as use**;
- tool definitions are counted separately and reported, never as violations;
- a Bash command is split on shell separators and only the **first token** of each
  segment is matched, so `grep -rn curl src/` and a file named `wget-notes.txt` are clean
  while `FOO=1 wget https://…` and `cc -c a.c && curl …` are not. Runner wrappers are
  stripped, so `uv run python …` presents `python`, and a git subcommand is read past its
  flags, so `git -C /tmp clone` classifies as `git clone`;
- an interpreter is not evidence of anything, but an interpreter **plus a call that opens a
  connection** is: `python3 -c "urllib.request.urlopen(…)"` is a violation, and
  base64-obscuring the host does not help because the call is what matches. A bare URL in a
  script is only an advisory, because a printed recommendation may contain one;
- `git log` is an advisory, `git clone` is a violation;
- a read of the harness's own answer key (`ground_truth`, `maps.json`, a `*-private/` path,
  a `staged/` path) is a violation, including through a glob or a `find -name` prefix;
- **anything under the work root that is not the arm's own tree** is a violation, which is
  the containment rule below;
- **`diff` across the bench and control trees** is a violation on its own, by name, because
  the relative-path form cannot be resolved from a transcript;
- for any arm other than `c-review`, invoking the artifact under test (`Skill` or
  `Workflow` naming c-review) is a violation — a baseline that runs the subject is not a
  baseline — and for `bare` and `taxonomy`, which are *defined* as one agent, invoking
  `Task` is a violation because a fan-out is a different arm;
- an arm's own `external_sources_consulted: true` is a violation on its own, and the number
  of declarations actually inspected is printed, because an absent declaration list and
  sixteen clean ones both fold to `false` and only one of them is evidence.

Both directions are tested (`tests/test_anticheat.py`), and the false-negative half of that
file is named after cases that scored `VALID` on the first version: a glob-obscured
answer-key read, `find -name 'ground_truth*'`, `diff -r bench control`, a read of the cached
pristine upstream, `python3 -c urlopen`, a `/dev/tcp` redirect, `git -C … clone`, an MCP tool
called plainly `fetch`, and the `bare` arm invoking c-review.

### Containment: the oracle is one directory up

`verify` emits, side by side under one work root:

```
<workroot>/<corpus>/bench/            the tree the packet hands the arm
<workroot>/<corpus>/control/          the same code with the bugs removed
<workroot>/<corpus>/bench-private/    ground_truth.json, maps.json, staged/
<workroot>/<corpus>/verified.json
```

and `fetch_base` caches the pristine upstream tarball and its extraction in the parent of
the default work root — `~/.cache/c-review-bench/zstream-<digest>-src/` is un-de-identified
zlib, ChangeLog included.

So `diff -r ../bench ../control` lists every injected bug, and `ls ../..` finds the upstream
that de-identification exists to hide. **De-identification is a real defence against
recalling upstream from training data and no defence at all against upstream being on the
same disk two directories up.** Each arm's packet already says to work only from the tree it
was given; the containment check enforces that instruction rather than adding one, and
`score` needs the cell's tree to do it, which is why it is computed there and not in
`collect`.

Residual gap, stated rather than assumed away: a **relative** path cannot be resolved
without the working directory of that particular tool call, which the harness does not
track. `../bench-private/` is still caught by name, and `diff` across the two trees is
caught by name, but a relative read of `../control/src/x.c` is not.

A third verdict exists: **`UNVERIFIABLE`**, for an arm collected without a transcript.
It is excluded like an invalid one, because "we did not look" and "we looked and it was
clean" are different claims and only one supports a number.

## Corpora

| Corpus | Tier | Base | Lines | Bugs | Decoys | Classes | De-identified | Gate |
|---|---|---|---|---|---|---|---|---|
| `sigil` | small | **written from scratch for this harness** | 893 | 17 | 10 | 17 | not applicable — no upstream exists | **passes, 2.5 s** |
| `zstream` | medium | pinned upstream C library tarball (sha256 in the recipe) | 9,260 | 15 | 10 | 15 | 1,034 identifiers renamed across 25 files | **passes, 6.4 s** |
| `jsengine` | large | pinned upstream C engine tarball (sha256 in the recipe) | 68,746 | 15 | 10 | 15 | 4,939 identifiers renamed across 17 files | **passes, ~2 min** |

`bench.py corpora` is the source of truth for what exists; this table is a summary and
the Status column is the part that will go stale first. Until the medium corpus lands,
`plan --tier standard` **refuses to run** rather than quietly measuring one corpus and
labelling it `standard` — pass `--allow-missing-corpora` to record a deliberately reduced
run, and the plan and the report both say `REDUCED RUN` on every print.

`sigil` carries zero lookup risk by construction: it is a telemetry framing library
written for this harness, with a handshake, a TLV field decoder, an interning table, a
path builder, a recursive group walk, a keyed tag and a spool writer. There is no
upstream to diff against and no history to read. Its 17 bugs span 17 of the catalogue's
22 classes across all three difficulty tiers, which makes it the cheapest corpus that can
still tell a broad regression from a narrow one.

The medium and large corpora are de-identified real C, so they carry realistic scale,
idiom and noise that authored code cannot fake. Their bases are pinned by sha256; the
build refuses a tarball whose digest does not match, because an unpinned base means the
recipe's anchors describe a different tree. The de-identifier, the injector and the gate
are exercised by `sigil` and by unit tests over synthetic trees; the two real-C recipes
are the remaining content work, and each is one `recipe.json` — no code changes.

### Difficulty tiers, frozen at injection time

- **EASY** — visible within one function.
- **MEDIUM** — needs cross-function or data-flow reasoning.
- **HARD** — outside the classic memory-safety taxonomy, or needs an invariant argument
  across macros or callers.

Assigned in the recipe when the bug is written, before any arm runs. Nothing re-tiers a
bug after seeing which arm found it.

### The bug catalogue

Twenty-two classes in `lib/recipe.py`, drawn from real bug *shapes* and never from real
bug *locations*: buffer overflow, OOB read, OOB write, use-after-free, double free,
uninitialised use, signed and unsigned integer overflow, width truncation, off-by-one,
missing NUL termination, unbounded copy, unchecked return value, resource leak, unbounded
recursion, TOCTOU race, delimiter injection, state-machine bypass,
validate-one-copy-use-another, encoding-invariant violation at one call site of a shared
macro, nonce/IV reuse, non-constant-time compare.

`bug_class` is validated against that list rather than free text, because a typo silently
splits a row in the per-class breakdown and nobody notices.

## The corpus integrity gate

`bench.py verify` builds both variants and runs ten checks. **A check that inspects zero
items fails**, and the gate refuses to stamp a corpus on that basis — this repository has
shipped a validator that matched nothing and reported every plugin valid, and a
contamination check that printed "0 of 0 hunter groups flagged" while a hunter was openly
declaring it had fetched upstream.

| Check | What it establishes |
|---|---|
| `compile[bench]`, `compile[control]` | both variants compile, and the object count equals the source count |
| `behaviour[bench]`, `behaviour[control]` | a benign-input smoke test still passes **with every bug applied** — a bug that breaks normal operation is not latent, and any test suite would have caught it |
| `warnings` | `-Wall -Wextra` produces no warning in the bench tree that the control tree does not also produce, so no injection announces itself to an arm that compiles the code |
| `reachability` | every bug has a contiguous syntactic call chain from a declared entry point |
| `decoys` | every decoy is a whitelisted no-op kind with a recorded safety argument, and none shares a function with a bug or sits within 3 lines of one |
| `deidentified` | no original identifier (4+ chars) or filename stem survives, no file is byte-identical to its base, and no recipe-declared forbidden string remains |
| `ground_truth` | every recorded site exists, is non-blank, names a function present in that file, and **its own mechanism description satisfies its own keyword groups** |
| `mechanism_discrim` | for every pair of bugs the grader could confuse, each one's keyword groups **reject** the other's mechanism |
| `variants` | bench and control differ in exactly the files that carry bugs and nowhere else |

Three of those deserve their reasoning spelled out.

**Reachability is syntactic and says so.** The check verifies that each declared edge
exists — the callee is called inside the caller's function body in the source — starting
at a declared entry point and ending at the bug's function. A bug inside an entry point
declares a self-edge, which is checked against the entry-point list. This is weaker than
a proof that an attacker can drive the path and stronger than a recorded assertion, and
the harness does not claim the stronger thing. Function-pointer hops are declared
`indirect` and must cite a file where the callee's address is taken.

**The mechanism self-match is the grader's positive control, wired into the gate.** Each
bug's `mechanism_all_of` keyword groups must be satisfied by the bug's own `mechanism`
sentence. A keyword list that cannot match a correct description of the bug it describes
will not match a reviewer's correct description either, and recall would fall for a
reason that has nothing to do with the reviewer.

**`mechanism_discrim` is the negative control, and it was the missing half.** The grader keys
on the enclosing function, so two bugs in one function are graded against the same findings —
four of `sigil`'s seventeen share a function with another, and four of `zstream`'s fifteen
share `inflate()`. If bug X's groups are loose enough to be satisfied by a description of bug
Y, one finding about Y scores as having found both, and recall rises by one for a bug nothing
in the run describes. Demonstrated on the shipped corpus before the fix: deleting the only
finding that described the state-machine bypass left it scored `HIT` on a finding about a
different bug eleven lines away, on the strength of the words *state*, *before*, *tag*,
*record* and *authentication* appearing somewhere in twelve concatenated fields. The probe is
each bug's own terse `mechanism` sentence, which has less surface for an accidental match
than a reviewer's prose, so passing this check is a floor and not a guarantee — `AMBIGUOUS`
below is the backstop for what gets through.

## Arms

Each is independently runnable, and each has a packet in `arms/` that `plan` fills in
with the corpus, the paths and the cost estimate.

| Arm | What it is | Why it exists |
|---|---|---|
| `c-review` | the plugin as shipped, through its own workflow | the subject under test |
| `bare` | one generic agent, one prompt | the baseline that beat c-review on recall at a ninth of the cost |
| `fanout` | N generic agents partitioned into disjoint contiguous regions, N matched to c-review's real agent count | matched compute without the structure — a deliberately strong baseline, not a strawman |
| `taxonomy` | one generic agent handed c-review's whole class catalogue inline | separates the knowledge from the orchestration |
| patched control | any arm against the `control` variant | every claim of an injected bug there is a false positive by construction |

The patched control is a *variant*, not a fifth arm: `plan --tier full` adds `c-review`
and `bare` cells against the bug-free tree. The two trees differ only in the bug patches
— same code, same decoys — and the `variants` gate check proves it.

The taxonomy arm's catalogue is extracted from the shipped `workflows/c-review.js` at plan
time (49 classes at the time of writing), so it is what the plugin actually uses rather
than a copy that has drifted. Extracting zero classes is a hard error.

## Runtime tiers and cost

```sh
uv run bench.py plan --tier smoke    --out RUN   # 1 cell
uv run bench.py plan --tier standard --out RUN   # 4 arms x small + medium
uv run bench.py plan --tier full     --out RUN   # + large + control cells
```

`plan` prints the estimate before anything runs; `score` prints the actual alongside it
afterwards.

| Tier | Cells | Modelled cost | Measured |
|---|---|---|---|
| `smoke --arm bare` | `bare` on `sigil` | 51 K tokens, 1 agent | **92,478 tokens, 1 agent, 642 s** |
| `smoke` | + c-review on `sigil` | 0.74 M tokens, 21 agents | not yet measured |
| `standard` | 4 arms x `sigil` + `zstream` | 4.33 M tokens, 72 agents | not yet measured |
| `full` | + `jsengine` + 4 control cells | 24.6 M tokens | not yet measured |

Those totals are what `bench.py plan` prints for the corpora as they stand; it prints them
before anything runs, and `score` prints the actual beside the model afterwards.

The one measured cell came in at **1.8x the model**, which is the kind of correction the
model exists to receive. Do not tune `ARM_MODEL` off a single cell; re-measure when a
`standard` run exists.

### Which "tokens"?

There is no single number, and `meta.token_basis` records which one a cell used. For the
measured cell above, the same run reads as **92,478** (the platform's reported
`subagent_tokens`), **246,755** (`tokens_fresh`: input + output + cache creation) or
**2,432,494** (`tokens_total`, including cache reads). `bench.py cost --transcript …`
prints all three from the transcript, so the figure in `meta.json` is measured rather
than remembered.

Mixing bases across cells in one run is refused by `score`, and the basis in force is printed
above the comparison table and stored in `score.json` as `token_basis`. Both of those were
claimed here and not implemented: a run mixing `reported_subagent_tokens` with `tokens_total`
scored fine and summed the two into one "actual tokens" total, comparing 92 K against 2.4 M
as though they were the same scale.

The smoke tier is split deliberately. `--arm bare` answers "does the loop work" for about
50 K tokens and a few minutes, which is the sub-100K budget a smoke test should have.
Adding the c-review cell answers "does the artifact under test still parse and grade",
and that cannot be cheap: c-review spawns roughly twenty agents by design, so no
configuration of it fits in 100 K tokens. The two questions are separated rather than
one of them being quietly dropped.

**These are estimates from a model, not measurements, and the harness labels them that
way everywhere it prints them.** The model is anchored on the one real measurement this
plugin has — a 13 KLOC corpus where a bare agent cost 116 K tokens, a fan-out averaged
110 K per agent and c-review averaged 78 K per agent across 34 agents — scaled by corpus
size with a floor, because an agent pays for its own prompt before it reads a line. No arm
has yet been run against these corpora by this harness, so no measured figure exists to
report. `score` writes both numbers into `score.json`; replace this table with the
measured column after the first `standard` run, and correct `ARM_MODEL` in `lib/plan.py`
if the ratio is off.

The `smoke` tier's purpose is to prove the pipeline end to end, and it is the one tier
whose *harness* cost is already known: everything except the arm itself costs zero
tokens and a few seconds — the gate builds and checks both variants of `sigil` in 2.5 s,
and the whole test suite runs in 8 s.

## What the first real runs showed

Two runs of the same cell exist — `bare` on `sigil`, one agent, same corpus, same grading
rule — and they scored **15/17** and **11/17**. The grader is not the variable: the two
`ground_truth.json` files compare equal and cross-grading both result files against the same
one reproduces 15 and 11 exactly. Scoring one run eight times in eight processes with varying
`PYTHONHASHSEED` produces byte-identical `score.json` and `REPORT.md`. The spread is
**reviewer variance**: the first run filed 18 findings and the second 12, and the four bugs
that separate them (`sgl_scope_copy`, `tags_equal`, `tag_check`, `sgl_spool_write`) had no
finding at their site at all in the second.

That is the number that matters for using this harness: **on `sigil`, two runs of one
configuration differ by 4 of 17 bugs — 23 percentage points.** A single-run difference smaller
than that between two arms means nothing. Either run several times per cell, or use the larger
corpora where 15 bugs are spread over 9 KLOC and 68 KLOC and a lucky reading order matters
less. `sigil`'s job is regression detection — a drop from 15 to 8 is real — not ranking.

The second of those runs is also, on the current harness, **`INVALID`**: its transcript shows
the `bare` agent invoking `Skill(c-review:c-review)` on its second turn, because the packet's
own words are what that skill's description triggers on. It loaded the phase outline, searched
for the `Workflow` tool, did not get it, and reviewed by hand — so it was one agent holding
part of c-review's taxonomy, which is not the `bare` arm. Nothing surfaced that at the time.

Taking the 15/17 run at face value: EASY 5/5, MEDIUM 7/8, HARD 3/4, **zero false positives**,
zero decoys claimed, and findings matching recorded corpus weaknesses. It missed the
encoding-invariant violation and the stale-record reuse.

Read that as a statement about the corpus, not a triumph: **`sigil` is too easy to
discriminate between arms.** One generic agent with one prompt finds seven eighths of it,
because 17 bugs in 893 lines is one per 52 lines and every one of them is inside a
function a reviewer will read. Its job is regression detection — if a change drops sigil
from 15 to 8, something broke, and the run costs 90 K tokens to find that out. Telling
c-review apart from a bare prompt needs `zstream` (one bug per 617 lines) and `jsengine`
(one per 4,583), where most of the code is noise and no single agent can read it all.

That run also paid for itself in defects: it found four in the harness (see Tests below)
and two real weaknesses in the corpus's own toy constructions, now recorded as
`known_extra_findings` so they are neither credited nor charged.

## Scoring

A finding is a **HIT** when it names the right file, places itself at the right site (a
matching function name, or a line within 12 of the recorded site), and its text identifies
the actual defect mechanism. Proximity alone is not a hit.

Five outcomes: `HIT`, `SUPPRESSED` (a reviewer found it and the pipeline dropped it — a
different failure from a miss, and the one that caused the previous recall loss),
`NEAR_MISS` (right site, wrong mechanism — read it, the keyword list may be stale),
`AMBIGUOUS` and `MISS`.

`AMBIGUOUS` means one finding was the **only** mechanism-matching evidence for this bug and
for another bug at the same site, so at most one of them was really found and the grader
cannot say which. It is not counted as recall. A bug with a second, independent matching
finding keeps its `HIT`, which is why applying this rule to the two runs that already exist
changes neither of their numbers — both filed a separate correct finding for the second bug.
The rule exists because without it a single verbose finding can be scored as two discoveries,
and that biases the comparison towards verbose arms, which is the comparison the harness is
for.

The site rule is the documented inclusive OR — a matching function name **or** a line within
the window — and the report now records which arm of the OR fired. On `sigil`, `tags_equal`
and `tag_check` are ten lines apart in different functions, so every finding naming one lands
at the other's site by window; a `line-cross-function` match is weaker evidence than a name
match and is resolved in favour of the name match when both are available. The evidence shown
for a bug is the least contested candidate, not the first in file order: that used to
attribute a bug to a finding about a different bug, in both real runs.

False positives are counted in three buckets rather than one:

- **decoy hits** — a finding at an injected no-op, and only when that finding did not
  already match a real bug. A correct finding is never also charged as a false positive.
- **control hits** — on the patched control, a claim of a bug that is not there. Certain.
- **unmatched** — everything else, counted and listed but **not** called a false positive.
  The base code may hold real bugs nobody injected, and calling those FPs would punish an
  arm for being right.
- **known corpus weaknesses** — findings at a site the recipe's `known_extra_findings`
  documents: real, present in the clean tree, and therefore neither a hit nor a false
  positive. They exist so a repeat run does not re-triage the same findings forever. A
  documented weakness also cannot be charged as a *control* false positive: "certain by
  construction" only holds where there is genuinely nothing to find, and the recipe itself
  says there is.

Two rules keep the FP count honest, both of them written after a real run got them wrong:
a finding that already matches an injected bug is never also charged as a decoy, and a
finding at a decoy's site must actually *describe the mutation* (per-kind claim terms) to
count as falling for it. A duplicate report of a bug another finding already claimed is
attributed too, not counted as unmatched.

## What no tool here can check

- **Whether an unmatched finding is real.** The harness counts them; a human reads them.
- **Whether a HARD bug is *fairly* hard.** The tier is a judgement call frozen before the
  run, which stops it being retrofitted to the result but does not make it right.
- **Whether the model has memorised the base project.** See the honesty note above.
- **Whether a keyword group is too tight for prose nobody has written yet.** The gate proves
  each group matches the bug's own description and rejects its neighbours' — it cannot prove
  it matches every correct sentence a reviewer might write. A `NEAR_MISS` is the signal to
  read the finding and decide.
- **Whether an arm was run as its packet says, in general.** Three specific forms are now
  checked — a non-`c-review` arm invoking c-review, a one-agent arm invoking `Task`, and any
  tool call outside the arm's own tree — but a driver that runs the wrong prompt, or an arm
  that fans out through a mechanism with a different tool name, still leaves no trace the
  harness reads.

## What running it for real cost the harness

Six defects in this harness were found by running it, not by reading it. They are listed
because they are the argument for the vertical slice: every one of them would have
produced a plausible wrong number, and none was visible in 160 passing unit tests.

| Found by | Defect |
|---|---|
| the real `bare` arm | `[-/]private/` in the answer-key patterns matched macOS's `/private/tmp`, where the corpus lives, so the honest arm scored `INVALID` for reading the code it was given |
| the real `bare` arm | duplicate reports of an already-found bug were counted as unmatched findings needing triage |
| the real `bare` arm | a genuine finding was charged as a decoy false positive for sharing a function with one |
| the real `bare` arm | two real weaknesses in the corpus's own toy constructions had nowhere to be recorded, so every run would re-triage them |
| the medium corpus | `_DEF_TAIL`'s nested quantifier backtracked exponentially: **9 minutes of CPU** for a gate that now takes 6 seconds, and a gate that slow is a gate nobody runs |
| the medium corpus | the surviving-identifier check scanned the harness's own generated scripts and message strings, flagging `check`, `done` and `header` |
| the large corpus | every `//` line comment was treated as an unterminated `/* */` block, deleting the rest of the file — invisible in two corpora that use only `/* */` |
| the large corpus | `0x7ff00000` was renamed to `0nexirn`, because `x7ff00000` matches an identifier unless the match is forbidden from starting after a digit |
| the large corpus | one unbalanced paren inside a string literal aborted function indexing for the whole file, so half a real project's functions "did not exist" |

A later validation pass found nine more by attacking the harness rather than running it. Every
one produced a plausible number rather than an error, and none was visible in 165 passing
tests:

| Class | Defect |
|---|---|
| recall inflation | one finding could be the **sole** evidence for two bugs in one function; deleting the only finding that described `SGL-B12` still scored it a `HIT` |
| wrong evidence | the evidence shown for a bug was `hits[0]` in file order, so both real runs attributed a bug to a finding about a different bug |
| vacuous scoring | a ground truth with zero decoys reported zero decoy false positives; an item with zero keyword groups made every nearby finding a `HIT` |
| refused a correct result | zero findings on the patched control — the one perfect outcome there — raised, and took the whole run's report with it |
| undetected oracle | `diff -r bench control` lists every injected bug and matched nothing; the pristine upstream sits two directories above the tree the packet hands out |
| undetected oracle | a glob or `find -name 'ground_truth*'` read the answer key; `python3 -c urlopen`, `/dev/tcp`, `git -C … clone` and MCP tools called plainly `fetch` all passed |
| contaminated baseline | the `bare` arm invoked the artifact under test and was reported as `bare` |
| cost accounting | mixing token bases in one run was accepted and summed, and the basis was printed nowhere |
| unreported partial run | a c-review result whose hunters had all failed scored as though the pipeline ran |

Each has a regression test named after the failure.

## Tests

```sh
cd tests && uv run --no-project --with pytest python3 -m pytest -q --import-mode=importlib .
```

201 deterministic tests over fixtures, all in `make check`. The load-bearing ones:

- `test_grade.py::test_positive_control_perfect_run_scores_full_recall` — a synthetic run
  that describes every bug correctly scores 100%.
- `test_grade.py::test_negative_control_right_site_wrong_mechanism_scores_zero` — findings
  in the right files and the right functions, describing something else, score 0%.
- `test_anticheat.py::test_tool_definitions_and_prose_are_not_use` — the distinction the
  whole gate rests on.
- `test_verify.py::test_a_vacuous_check_fails_the_gate` — a check that inspected nothing
  is a failure, never a pass.
- `test_grade.py::test_one_finding_is_not_the_sole_evidence_for_two_bugs` — the recall
  inflation, and `test_a_bug_with_its_own_second_finding_keeps_its_hit` is the other half:
  the rule must not cost a run a bug two findings both describe.
- `test_verify.py::test_keyword_groups_that_cannot_tell_two_co_located_bugs_apart_fail` —
  the grader's negative control, which failed on `zstream` when it was written.
- `test_anticheat.py::test_reading_the_arms_own_tree_is_never_a_violation` — the case that
  matters most, because an over-triggering integrity check gets switched off.
- `test_result_and_report.py::test_scoring_the_same_run_twice_is_byte_identical` and
  `test_verify.py::test_building_the_same_corpus_twice_emits_the_same_bytes` — without these
  two, no comparison across runs means anything.
- `test_verify.py` also runs the real gate over `sigil` and asserts that a deliberately
  loud injection (one the compiler warns about) and a deliberately obvious one (one that
  breaks the smoke test) both **fail** it.
- `test_result_and_report.py::test_an_invalid_arm_is_excluded_not_annotated` — an arm that
  used an oracle does not appear in the comparison table at all.
- `test_result_and_report.py::test_a_control_result_is_not_collected_as_a_bench_result` — a
  real defect this caught: `collect` keyed on arm and corpus only, so a control result was
  attributed to the bench cell and would have been reported as recall.
- `test_result_and_report.py::test_a_stale_collected_file_is_refused` and
  `test_a_tier_missing_a_corpus_size_is_refused_unless_allowed` — the two ways a run can
  quietly measure something other than what it claims.
- `test_tarball_corpus.py` — the whole fetch/pin/inject/de-identify/gate path over a
  miniature upstream project built as a real tarball and served over `file://`. `sigil`
  is authored, so nothing else exercises digest pinning or renaming end to end. Writing
  it found two live defects: a project name surviving inside a string literal, and
  `#include` being renamed to `#lornfen`.

The three tests that build a corpus need a C compiler and skip without one; every check's
logic is also tested directly on synthetic manifests, and those run everywhere.

What the tests do **not** cover, and cannot: whether an arm was run as its packet says,
whether an unmatched finding is real, and whether a HARD tier assignment is fair. The
first is why `collect` records transcripts and digests; the other two need a human.

## Judging: `judge_bench/`

Separate question, separate scorer. The ground-truth grader answers *did the pipeline find
the bug*; it cannot answer *can the judge tell a real finding from a plausible wrong one*.
Every run so far returned 100% TRUE_POSITIVE (4/4, then 13/13), which is equally consistent
with a good judge that had nothing to reject and one that accepts whatever it is handed.
`judge_bench/` supplies eight seeded false positives with a recorded reason each, and
scores retention against rejection. See its own header comments; it exits non-zero if it
scores zero real items or zero seeded ones.

## Adding a corpus

Write `corpora/<name>/recipe.json` — `lib/recipe.py` is the schema and every rule in it is
enforced. Copy `corpora/sigil/recipe.json`. Anchors and replacements are written as arrays
of lines, so a patch diffs like source rather than like an escaped string. Then iterate
against `bench.py verify` until every check passes; it will tell you exactly which claim
is not yet true.

Three rules the gate cannot state for you:

- **Never inject at a site a real advisory describes.** The injections are ours precisely
  so that looking them up is worthless.
- **Keep the bug latent and silent.** Benign input must still work and `-Wall` must stay
  quiet, or the arm is being tested on whether it runs `make`.
- **Say what the decoy cannot change.** `safe_because` is the argument a reviewer checks;
  "it's fine" is not one.
