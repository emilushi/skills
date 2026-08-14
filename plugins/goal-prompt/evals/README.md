# goal-prompt evals

Ablation evals: every case runs the same bare prompt ("Improve this goal: … Give me the final /goal command
to paste.") with and without the plugin, so the score delta measures what the skill actually adds over an
unassisted model.

```sh
claude plugin eval plugins/goal-prompt --ablation with-without --allow-tools Bash Write --judge-model sonnet
```

(`--allow-tools` grants the gated tools the skill's formatter needs. `--judge-model sonnet` is required:
the default haiku judge cannot follow the graders' scoping instruction — judge only the line inside the
fenced block — and fails correct answers for content in the accompanying `Missing:` list.)

| Case | What it measures |
| --- | --- |
| grounded-migration | Single-line copy-ready output; check command grounded in the fixture's package.json; stop clause. |
| ungrounded-vague | With nothing to ground "faster", the goal must not invent metrics, thresholds, or benchmark commands — gaps are flagged back to the user. |
| easy-out-closed | The user's grep-only success check is satisfiable by deleting the callers; the goal must pair it with the fixture's real test suite. |

Graders judge the artifact (the returned `/goal` line and its accompanying warnings), not the agent's
narration. Regex graders enforce the mechanical parts (a stop clause exists); LLM graders judge grounding,
invention, and easy-out closure against the fixture's actual contents.

Measured on 2026-08-14 (4 runs per arm per case, pooled over two suite runs): the plugin arm passed every
grader in every run; the bare arm was bimodal — the deterministic stop-clause regex alone failed half its
grounded-migration runs (multiline rewrites, no bound).

**Baseline contamination caveat (trailofbits/skills-internal#546).** The eval scaffold does not isolate the
repo: baseline-arm responses from these runs cite the fixture's absolute repo path and reproduce SKILL.md
sentences verbatim ("scope to read first", "terminates on the wrong contract"), meaning the no-plugin arm
found and read the plugin under test off disk. Contaminated baselines imitate the skill, so measured deltas
are lower bounds on the plugin's real effect; the uncontaminated baseline runs scored 0. Until the harness
denies the baseline Read access to the plugin directory, run with `--keep-temp`, and audit baseline traces
and responses for the plugin's path and distinctive SKILL.md phrases before trusting a small delta.
