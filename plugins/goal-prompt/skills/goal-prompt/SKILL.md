---
name: goal-prompt
description: "Drafts copy-paste-ready /goal commands for goal mode in Claude Code and Codex. Use when the user asks to create, write, rewrite, compress, clean up, or prepare a goal prompt, goal condition, /goal command, goal-mode objective, or copy-ready long-running task objective."
allowed-tools: Bash Read Write
---

# Goal Prompt

`/goal` keeps the agent working until a completion condition is met ([Claude Code docs](https://code.claude.com/docs/en/goal), [Codex docs](https://developers.openai.com/codex/use-cases/follow-goals)). Both harnesses take it as one line, max 4,000 characters. In Claude Code a small model re-judges the condition after each turn from the transcript alone — it cannot run commands. In Codex, older CLIs need `[features] goals = true` in `~/.codex/config.toml`, and slash commands exist only in interactive sessions, not `codex exec`.

Draft a condition that can terminate, then format it. A goal fits work bigger than one turn with a checkable finish line; chain small goals with review between them rather than writing one giant goal.

## Draft

Include, joined with AND — never "or", the loop takes the cheaper branch:

1. **End state, not activity** — "all `legacyAuth()` call sites use `auth.verify()`", not "migrate the auth code". An activity can be claimed; an end state is true or false.
2. **Scope to read first** — the files, issue, logs, or plan to read before acting.
3. **Stated check** — the exact command and its observable result ("`npm test` exits 0"), plus an instruction to run it and show the output; a result that never lands in the transcript does not exist to the evaluator.
4. **Invariants** — what must not change ("without modifying vendor/"), always including "do not weaken, skip, or edit the checks themselves".
5. **Stop bound or blocked clause** — "or stop after 20 turns", "if blocked, stop and report the blocker". Without one, a mis-stated condition loops forever; the formatter warns when it is missing. (Claude Code resets the turn counter on session resume, so a turn bound silently extends across resumes.)

For long goals, also name the final evidence (diff, report, artifact) and require a progress log file — durable state across compaction and resume. If the brief exceeds 4,000 characters, put the details in a `GOAL.md` and reference that file from the objective.

**Never invent missing elements.** Ground every element in the user's request, the conversation, or the repository — look up the real check command (Makefile, package.json, CI config) rather than guessing one. If an element cannot be filled from available information — no measurable threshold stated, no test suite found — still optimize and format what the user provided, leave the element out, and flag it as missing (see Format). A goal with an invented success condition terminates on the wrong contract.

## Security research goals

Harden audit goals against reward hacking:

- Neutral wording: "trigger and validate the issue", not "prove this is exploitable".
- Reference a threat model: what is in and out of scope, attacker powers, baseline severity.
- Demonstrate attacker preconditions in scope, never assume them.
- Check open issues, PRs, and known-findings files before calling a bug new; keep a findings log.
- Stop for human review after each meaningful finding; require a second pass by a fresh agent before a finding counts.

More goal patterns: [trailofbits/codex-config](https://github.com/trailofbits/codex-config/blob/main/README.md#goal).

## Format

Run `python3 {baseDir}/scripts/format_goal_prompt.py --fenced` on the draft (file or stdin). It collapses whitespace to one line, strips `/goal` prefixes, quotes, and fences, warns on a missing stop clause, and rejects output over 4,000 characters — shorten or move detail to a file and rerun.

Return exactly one fenced `text` block, one line:

```text
/goal <single normalized objective>
```

Add no prose around it — except when checklist elements could not be grounded: then follow the block with a `Missing:` list, one line per gap, telling the user what to supply.

## Example

Draft:

```
/goal Migrate the auth module:
  - replace legacyAuth() with auth.verify()
  - make sure the tests still work
```

Redrafted and formatted:

```text
/goal All legacyAuth() call sites use auth.verify(): `rg "legacyAuth\(" -t ts` prints nothing AND `npm test` exits 0 (run both, show the output), without modifying vendor/ or weakening any test. If blocked, stop and report attempted paths and the blocker, or stop after 20 turns.
```

Here `npm test` came from the repo's package.json — not a guess. When nothing grounds an element, format what exists and flag the gaps:

Draft: `make checkout faster`, with no metric or benchmark anywhere in context:

```text
/goal Make checkout faster
```

Missing:
- measurable end state — which metric and threshold count as "faster"
- verification — the benchmark or command that proves it
- stop bound — e.g. "or stop after 20 turns"
