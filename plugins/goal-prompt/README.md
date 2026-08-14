# goal-prompt

Drafts copy-paste-ready `/goal` commands for goal mode in Claude Code and Codex: verifiable completion conditions, formatted to a single copy-ready line.

## What It Does

Goal mode keeps the agent working across turns until a completion condition is met. Both harnesses take `/goal` as a single-line command capped at 4,000 characters, and both terminate on the condition you write — so a goal prompt has to satisfy two requirements at once. This plugin handles both:

**Make the prompt optimal.** The skill drafts the objective as a termination contract: a measurable end state (not an activity), the scope to read first, a named command that proves it with transcript-visible output, invariants that must not change (including "don't weaken the check itself"), and an explicit stop bound or blocked clause so a mis-stated condition cannot loop forever. Security-research goals get extra hardening against reward hacking (neutral wording, threat-model scoping, demonstrated preconditions, second-pass validation), following [trailofbits/codex-config](https://github.com/trailofbits/codex-config/blob/main/README.md#goal).

**Make the prompt match requirements.** A deterministic formatter then:

- strips duplicate `/goal` prefixes, wrapping quotes, and code fences
- collapses all whitespace to single ASCII spaces
- warns when no stop bound or blocked clause is present
- rejects output longer than 4,000 characters (the `/goal` cap in both harnesses) instead of silently truncating

## When to Use

Ask for a goal prompt in either Claude Code or Codex: "write a /goal command for refactoring the auth module", "compress this task into a goal prompt", "clean up this goal-mode objective".

## Example

```
User: turn this into a /goal command:
      Migrate the auth module:
        - replace legacyAuth() with auth.verify()
        - make sure the tests still work

Assistant:
/goal All legacyAuth() call sites use auth.verify(): `rg "legacyAuth\(" -t ts` prints nothing AND `npm test` exits 0 (run both, show the output), without modifying vendor/ or weakening any test. If blocked, stop and report attempted paths and the blocker, or stop after 20 turns.
```

## Components

- `skills/goal-prompt/SKILL.md` — drafting checklist and output contract
- `skills/goal-prompt/references/goal-mode.md` — goal-mode mechanics and limits per harness, the Trail of Bits work-order template, with sources
- `skills/goal-prompt/scripts/format_goal_prompt.py` — stdlib-only formatter (`--fenced`, `--objective-only`, `--max-chars`)
