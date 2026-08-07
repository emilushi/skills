#!/usr/bin/env python3
"""Gate the eval's own JSON output. Deterministic; no model.

`claude plugin eval ... --json out.json` reports scores. This rejects a result
that only looks green:

  - partial != false        the run did not complete
  - casesTotal < 1          a checker that inspected nothing must not pass
  - passed != total         some case failed
  - score != 1              a case scraped through below full marks
  - ablation delta <= 0     the plugin did not beat the no-plugin baseline,
                            so it is not doing anything

Usage:
    validate_eval_result.py RESULT.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Two suites, and a result JSON belongs to exactly one of them. `--tag static`
# is the seven-case mean quoted against concept-prover; `--tag online` is Stage 2,
# whose ground truth is public record. They are never averaged together — the
# static fixtures carry no public evidence for Stage 2 to read, and Stage 2's own
# rule is to stop when offline, so its correct behaviour scores zero there.
#
# Split rather than unioned so that a run of ONE suite still has a complete-set
# check. A single union would have made every `--tag static` result look like it
# had skipped the online case, and the obvious fix for that — dropping the
# completeness check — is what let this list go stale the first time.
CASE_SUITES = {
    "static": {
        "already-fixed",
        "blocked-attack-path",
        "dead-route",
        "inflated-impact",
        "integration-cap",
        "should-not-fire",
        "wrong-parameter",
    },
    "online": {
        "online-known-duplicate",
    },
}

EXPECTED_CASES = {name for cases in CASE_SUITES.values() for name in cases}

MIN_RUNS = 3


def _get(d: dict, *names, default=None):
    """Read the first present key. The result schema is early access and moves."""
    for name in names:
        if name in d:
            return d[name]
    return default


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: validate_eval_result.py RESULT.json", file=sys.stderr)
        return 2

    path = Path(sys.argv[1])
    try:
        result = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        print(f"error: cannot read eval result {path}: {error}", file=sys.stderr)
        return 1

    problems: list[str] = []

    if _get(result, "partial") is not False:
        problems.append("result is partial; the run did not complete")

    agg = _get(result, "aggregates", "aggregate", default={}) or {}
    total = _get(agg, "casesTotal", "totalCases")
    passed = _get(agg, "casesPassed", "passedCases")
    score = _get(agg, "overallScore", "score")

    if not isinstance(total, int) or total < 1:
        problems.append(f"casesTotal is {total!r}; refusing to report success on zero cases")
    elif passed != total:
        problems.append(f"{passed}/{total} cases passed")

    # Absence is "unknown", not "fine". `score is not None and score != 1` made a
    # renamed key read as full marks: rename `overallScore` to `meanScore` in a
    # passing result, set it to 0.6, and the gate printed `OK: 5/5 cases passed`
    # and exited 0. Every sibling reader above already records a problem when its
    # key is missing, and the ablation-delta read below says the schema has moved
    # before — which is exactly the trigger.
    if score is None:
        problems.append(
            "no overall score under any known key (overallScore, score); "
            "the result schema is early access, and a rename must not read as full marks"
        )
    elif score != 1:
        problems.append(f"overallScore is {score!r}, not 1")

    cases = _get(result, "cases", default=[]) or []
    seen = {_get(c, "name", "case", default="") for c in cases}

    # Which suite this result is, decided by what it contains rather than by a
    # flag the caller could get wrong.
    present = {name: cases_ for name, cases_ in CASE_SUITES.items() if seen & cases_}
    if len(present) > 1:
        problems.append(
            f"this result mixes the {' and '.join(sorted(present))} suites, whose means are "
            f"not comparable and must never be averaged. Re-run with a single --tag"
        )
    elif not present:
        problems.append(
            f"no known case ran: saw {sorted(seen) or 'nothing'}. Every case name is "
            f"unrecognised, so this result cannot be checked for completeness at all"
        )
    else:
        suite, expected = next(iter(present.items()))
        missing = expected - seen
        if missing:
            problems.append(f"the {suite} suite did not run: {', '.join(sorted(missing))}")
    unknown = seen - EXPECTED_CASES - {""}
    if unknown:
        problems.append(
            f"unrecognised case(s) {', '.join(sorted(unknown))}; add them to CASE_SUITES or "
            f"this result is being checked against the wrong expectations"
        )

    # A run that errored produced no answer, but its graders still scored it —
    # as zero. So a dead arm looks like a arm that answered badly, and the
    # ablation delta silently becomes a measure of which arm survived.
    #
    # This is not hypothetical. On 2026-08-04 a sweep lost 22 of 30 runs to
    # `exit 1: (no stderr)` at turn 1 for $0.00 each, most likely a usage limit
    # reached mid-sweep. `partial` was still **false**, every case still
    # reported runsPerCase 3, and blocked-attack-path showed a +0.47 delta
    # purely because all three no-plugin runs were dead while two with-plugin
    # runs had completed before the wall. Nothing above this block noticed:
    # `partial` was false, the case count was 5, and the run counts were 3.
    errored = []
    for case in cases:
        name = _get(case, "name", "case", default="<unnamed>")
        arms = _get(case, "arms", default={}) or {}
        for arm_name, runs in arms.items() if isinstance(arms, dict) else []:
            for i, run in enumerate(runs or [], start=1):
                if isinstance(run, dict) and run.get("error"):
                    errored.append(f"{name}/{arm_name}/run{i}: {str(run['error'])[:60]}")
    if errored:
        problems.append(
            f"{len(errored)} run(s) errored, so their graders scored an absent answer as 0 "
            f"and any delta reflects which arm survived: {'; '.join(errored[:6])}"
            + (f" (+{len(errored) - 6} more)" if len(errored) > 6 else "")
        )

    for case in cases:
        name = _get(case, "name", "case", default="<unnamed>")
        # `runsPerCase` is what the CLI actually emits — see the checked-in
        # fixtures/eval-result-2026-07-30.json. This read the two spellings it
        # does NOT emit, so `runs` was None for every case, `isinstance(None,
        # int)` was False, and the loop checked nothing: a 1-run eval passed the
        # validator that exists to require three.
        runs = _get(case, "runsPerCase", "runs", "runCount")
        if isinstance(runs, list):
            runs = len(runs)
        if not isinstance(runs, int):
            problems.append(
                f"case {name} reports no run count under any known key; "
                f"cannot confirm it ran the {MIN_RUNS} times a pass rate needs"
            )
        elif runs < MIN_RUNS:
            problems.append(f"case {name} ran {runs} time(s); {MIN_RUNS} is the minimum")

    # The ablation delta is the number that says the plugin does anything at all.
    # The CLI reports it as aggregates.meanDelta; the other spellings are kept as
    # fallbacks because the result schema is early access and has moved before.
    delta = _get(agg, "meanDelta", "ablationDelta", "delta")
    if delta is None:
        delta = _get(result, "ablationDelta", "delta")
    if delta is None:
        ablation = _get(result, "ablation", default={}) or {}
        delta = _get(ablation, "delta", "scoreDelta")
    if delta is None:
        problems.append(
            "no ablation delta in the result. Pass --ablation with-without explicitly: "
            "for a PATH target it silently defaults to none and you get no baseline."
        )
    elif delta <= 0:
        problems.append(
            f"ablation delta is {delta}; the plugin did not beat the no-plugin baseline"
        )

    if problems:
        print(f"FAIL: {path}", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1

    print(f"OK: {passed}/{total} cases passed, ablation delta {delta}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
