# goal-prompt

Drafts copy-paste-ready Codex `/goal` commands with deterministic whitespace normalization.

## What It Does

Codex goal mode takes a single `/goal <objective>` line capped at 4,000 characters. Asking a model to draft one usually yields multiline text with indentation artifacts that is cumbersome to copy-paste. This skill drafts the objective, then runs a deterministic formatter that:

- strips duplicate `/goal` prefixes, wrapping quotes, and code fences
- collapses all whitespace to single ASCII spaces
- rejects output longer than 4,000 characters instead of silently truncating

The result is exactly one fenced line, ready to paste into Codex.

## When to Use

Ask for a goal prompt in either Claude Code or Codex: "write a /goal command for refactoring the auth module", "compress this task into a goal prompt", "clean up this goal-mode objective".

## Example

```
User: turn this into a /goal command:
      Refactor the auth module:
        - replace MD5 password hashing with argon2id
        - add tests for the login flow

Assistant:
/goal Refactor the auth module: - replace MD5 password hashing with argon2id - add tests for the login flow
```

## Components

- `skills/goal-prompt/SKILL.md` — drafting guidance and output contract
- `skills/goal-prompt/scripts/format_goal_prompt.py` — stdlib-only formatter (`--fenced`, `--objective-only`, `--max-chars`)
