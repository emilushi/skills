---
name: goal-prompt
description: "Drafts copy-paste-ready Codex /goal commands. Use when the user asks to create, write, rewrite, compress, clean up, or prepare a goal prompt, /goal command, goal-mode objective, or copy-ready long-running task objective for Codex."
allowed-tools: Bash Read Write
---

# Goal Prompt

Codex goal mode takes a single `/goal <objective>` line capped at 4,000 characters. Drafting one by hand tends to produce multiline text with indentation artifacts that breaks on paste. Draft the objective, then run the formatter — do not normalize whitespace by hand, the formatter is deterministic and enforces the length cap.

Return exactly one fenced `text` block with one line and no extra prose:

```text
/goal <single normalized objective>
```

Run `python3 {baseDir}/scripts/format_goal_prompt.py --fenced` on a draft file or stdin. The formatter strips duplicate `/goal` prefixes, removes wrapping quotes/fences, collapses all whitespace to single ASCII spaces, and rejects a final command longer than 4,000 characters. If it rejects the draft, shorten the objective and rerun it.

## Example

Draft (messy, multiline):

```
/goal Refactor the auth module:
  - replace MD5 password hashing with argon2id
  - add tests for the login flow
```

Formatter output:

```text
/goal Refactor the auth module: - replace MD5 password hashing with argon2id - add tests for the login flow
```
