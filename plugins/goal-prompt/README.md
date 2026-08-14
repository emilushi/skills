# goal-prompt

Turns a task description into a copy-paste-ready `/goal` command for goal mode in Claude Code or Codex.

## What It Does

A goal prompt has to do two things at once: fit the format (`/goal` is a single line, max 4,000 characters in both harnesses) and actually terminate (goal mode keeps looping until the condition is judged met — a vague condition burns turns forever).

The skill drafts the objective as a termination contract — a measurable end state, what to read first, the command that proves completion, invariants that must hold, and an explicit stop bound — then a deterministic formatter collapses it to one line, warns if the stop clause is missing, and rejects oversized output instead of truncating. Security-audit goals get extra hardening against reward hacking (neutral wording, threat-model scoping, demonstrated preconditions, second-pass validation), following [trailofbits/codex-config](https://github.com/trailofbits/codex-config/blob/main/README.md#goal).

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
- `skills/goal-prompt/references/goal-mode.md` — per-harness goal-mode mechanics and limits, with sources
- `skills/goal-prompt/scripts/format_goal_prompt.py` — stdlib-only formatter (`--fenced`, `--objective-only`, `--max-chars`)
