# goal-prompt evals

Ablation evals: every case runs the same bare prompt ("Improve this goal: … Give me the final /goal command
to paste.") with and without the plugin, so the score delta measures what the skill actually adds over an
unassisted model.

```sh
claude plugin eval goal-prompt --ablation with-without --allow-tools Bash Write
```

(`--allow-tools` grants the gated tools the skill's formatter needs. Target by plugin name; targeting a
path defaults to no ablation arm.)

| Case | What the delta demonstrates |
| --- | --- |
| grounded-migration | Single-line copy-ready output; check command grounded in the fixture's package.json; stop clause. A bare answer tends to return a multiline rewrite with "tests pass" unattached to any command. |
| ungrounded-vague | With nothing to ground "faster", the goal must not invent metrics, thresholds, or benchmark commands — gaps are flagged back to the user. A bare answer tends to fabricate a p95 target and a bench command. |
| easy-out-closed | The user's grep-only success check is satisfiable by deleting the callers; the goal must pair it with the fixture's real test suite. A bare rewrite tends to keep the grep-only condition. |

Graders judge the artifact (the returned `/goal` line and its accompanying warnings), not the agent's
narration. Regex graders enforce the mechanical parts (a stop clause exists); LLM graders judge grounding,
invention, and easy-out closure against the fixture's actual contents.
