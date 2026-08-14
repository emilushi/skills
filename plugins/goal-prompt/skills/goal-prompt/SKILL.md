---
name: goal-prompt
description: "Drafts copy-paste-ready /goal commands for goal mode in Claude Code and Codex. Use when the user asks to create, write, rewrite, compress, clean up, or prepare a goal prompt, goal condition, /goal command, goal-mode objective, or copy-ready long-running task objective."
allowed-tools: Bash Read Write
---

# Goal Prompt

Goal mode keeps the agent working across turns until a completion condition is met. In Claude Code, a small transcript-only model re-judges the condition after every turn; in Codex, the objective persists on the thread and continuation is evidence-based. Both take `/goal` as a single-line command capped at 4,000 characters. Mechanics and sources: [goal-mode.md](references/goal-mode.md).

This skill has two jobs: draft an objective that can actually terminate, then format it so it pastes cleanly.

A goal fits work that is larger than one turn, has a clear stopping condition, and can be validated by commands or artifacts. Rule of thumb: an instruction you would repeat three turns in a row belongs in the goal. For long efforts, chain smaller goals with review between checkpoints rather than writing one giant goal.

## Draft the objective

Write the condition so a model that only reads the transcript can judge it true or false. Include:

1. **End state, not activity** — "all `legacyAuth()` call sites use `auth.verify()`", not "migrate the auth code". An activity can be claimed; an end state is either true or false.
2. **Scope to read first** — the files, directories, issue, logs, or plan the agent must read before acting. Without it the loop rediscovers context every turn.
3. **A stated check** — the exact command that proves it and the observable result: "`npm test` exits 0", "`rg 'legacyAuth\(' -t ts` prints nothing". Tell the agent to run the check and show the output: the Claude Code evaluator cannot run commands itself, so a result that never lands in the transcript does not exist.
4. **Constraints that must hold** — what must not change on the way there: "without modifying vendor/", "no other test file is modified". Always forbid weakening the check itself; the cheapest way to turn a red gate green is to edit the gate.
5. **A stop bound or blocked clause** — "or stop after 20 turns", or "if blocked, stop and report attempted paths and the blocker". Without one, a mis-stated condition burns turns until someone notices. The formatter warns when this is missing.

Join success criteria with AND, never "or" — given alternatives, the loop takes the cheaper branch.

For goals spanning many checkpoints, also name the final evidence to deliver (diff, report, artifact) and require a short progress log file in the repo — it gives compaction and resumed sessions durable state.

If the brief cannot fit in 4,000 characters, do not compress it into mush: write the details to a `GOAL.md` or `PLAN.md` file and reference that file from the objective. This is the official Codex guidance for oversized goals and works in Claude Code too.

## Security research goals

Audit goals need hardening against reward hacking — a flood of impact-inflated findings reads as a denial-of-service on a maintainer's time. When the objective is finding vulnerabilities, additionally:

- Use neutral wording: "trigger and validate the issue", not "prove this is exploitable".
- Reference a threat model stating what is in and out of scope, what the attacker can and cannot do, and what baseline severity means for this project.
- Require demonstrating attacker preconditions in scope, never assuming them — "attacker already controls an internal caller" is the most common false positive.
- Require checking open issues, PRs, and known-findings files before treating a bug as new, and a findings log file for durable state.
- Stop for human review after each meaningful finding instead of piling up untriaged reports, and require a second pass by a fresh agent before a finding is treated as real.

Field notes and high-signal goal patterns (differential testing, invariant breaking, variant analysis): [trailofbits/codex-config](https://github.com/trailofbits/codex-config/blob/main/README.md#goal).

## Format and return it

Run `python3 {baseDir}/scripts/format_goal_prompt.py --fenced` on a draft file or stdin. The formatter strips duplicate `/goal` prefixes, removes wrapping quotes/fences, collapses all whitespace to single ASCII spaces, warns on a missing stop bound or blocked clause, and rejects a final command longer than 4,000 characters. If it rejects the draft, shorten the objective or move detail into a referenced file and rerun it.

Return exactly one fenced `text` block with one line and no extra prose:

```text
/goal <single normalized objective>
```

## Example

Draft (messy, multiline, no termination contract):

```
/goal Migrate the auth module:
  - replace legacyAuth() with auth.verify()
  - make sure the tests still work
```

Redrafted and formatted:

```text
/goal All legacyAuth() call sites use auth.verify(): `rg "legacyAuth\(" -t ts` prints nothing AND `npm test` exits 0 (run both, show the output), without modifying vendor/ or weakening any test. If blocked, stop and report attempted paths and the blocker, or stop after 20 turns.
```

The redraft turned an activity ("migrate") into a checkable end state, named the proving commands, protected the gate, and bounded the loop.
