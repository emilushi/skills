# Goal mode mechanics

Facts below are from official documentation as of 2026-08; both harnesses are evolving, so verify against the sources when a limit matters.

## Claude Code `/goal`

Source: <https://code.claude.com/docs/en/goal>

- `/goal <condition>` sets a completion condition and starts a turn immediately, with the condition as the directive. One goal per session; a new one replaces the active one.
- The condition can be **up to 4,000 characters**.
- After each turn, a small fast model (defaults to Haiku; `ANTHROPIC_DEFAULT_HAIKU_MODEL` overrides) answers yes/no with a short reason. On "no", Claude starts another turn and takes the reason as guidance; on "yes", the goal clears automatically. `/goal` is a wrapper around a session-scoped prompt-based Stop hook.
- **The evaluator does not call tools.** It judges only what is already in the transcript. A condition is judgeable only if the agent runs the check and its output lands in the conversation.
- Official condition recipe: one measurable end state (test result, build exit code, file count, empty queue), a stated check ("`npm test` exits 0", "`git status` is clean"), and constraints that matter ("no other test file is modified"). Bound long runs with a clause like "or stop after 20 turns".
- Lifecycle: bare `/goal` shows status (condition, runtime, turn count, token spend, evaluator's last reason); `/goal clear` removes it (aliases: `stop`, `off`, `reset`, `none`, `cancel`); `/clear` also removes it.
- **Resume caveat:** `--resume`/`--continue` restores an active goal but resets the turn count, timer, and token-spend baseline — a "stop after 20 turns" bound silently extends across resumes.
- A goal does not change permissions; pair with auto mode for unattended runs. Headless: `claude -p "/goal <condition>"` runs the loop to completion (add `--output-format stream-json --verbose` to see progress).
- Requires workspace trust (the evaluator is part of the hooks system); unavailable when `disableAllHooks` or `allowManagedHooksOnly` applies.

## Codex `/goal`

Sources: <https://developers.openai.com/codex/use-cases/follow-goals>, <https://developers.openai.com/cookbook/examples/codex/using_goals_in_codex>

- `/goal <objective>` persists the objective as thread state. Codex continues only when the thread is idle, the goal is active, and budget remains; completion must be checked against concrete evidence (files changed, commands run, test output, artifacts), not the model's belief that it is probably done.
- The stored objective is **hard-capped at 4,000 characters** and the TUI rejects oversized input before sending anything. Official guidance for longer briefs: write the instructions to a file and reference that file from the objective.
- Lifecycle: bare `/goal` shows the current goal; `/goal pause`, `/goal resume`, `/goal clear` control the run. Reaching a budget limit stops substantive work but is not completion.
- Older CLIs gate the feature behind `[features] goals = true` in `config.toml`.
- The cookbook's strong-goal contract names six parts: outcome, verification surface, constraints, boundaries, iteration policy, and a blocked stop condition, with this template:

  ```text
  /goal <desired end state> verified by <specific evidence> while preserving <constraints>. Use <allowed inputs, tools, or boundaries>. Between iterations, <how to choose the next best action>. If blocked or no valid paths remain, <what to report and what would unlock progress>.
  ```

## Shared implications for drafting

- 4,000 characters and a single line are the binding format constraints on both platforms.
- Both platforms' guidance converges on the same termination contract: measurable end state, named verification, invariants, and an explicit stop/blocked clause.
- Both recommend the same escape hatch for large briefs: details in a file, referenced from a short objective.
