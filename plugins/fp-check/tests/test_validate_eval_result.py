"""Tests for the eval-result gate.

`validate_eval_result.py` is the only thing standing between a green-looking
eval JSON and a claim in a PR. It shipped with no tests, and the consequence was
the bug pinned by `test_a_one_run_eval_is_rejected`: it read `runs`/`runCount`,
the CLI emits `runsPerCase`, so the minimum-runs loop inspected nothing and a
1-run eval passed.

Every case here is driven from the checked-in real result
(`fixtures/eval-result-2026-07-30.json`) rather than a hand-built dict, so a
schema change breaks these tests rather than quietly making them vacuous.

Run:
    uv run --with pytest --no-project \
        pytest plugins/fp-check/tests/test_validate_eval_result.py
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

HERE = Path(__file__).resolve().parent
VALIDATOR = HERE / "validate_eval_result.py"
REAL_RESULT = HERE / "fixtures" / "eval-result-2026-07-30.json"


def run_validator(payload: dict, tmp_path: Path) -> subprocess.CompletedProcess:
    target = tmp_path / "result.json"
    target.write_text(json.dumps(payload))
    return subprocess.run(
        [sys.executable, str(VALIDATOR), str(target)],
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.fixture(scope="module")
def real() -> dict:
    assert REAL_RESULT.exists(), f"{REAL_RESULT} is missing; these tests would test nothing"
    return json.loads(REAL_RESULT.read_text())


def case_suites() -> dict[str, set[str]]:
    """`CASE_SUITES` as the validator actually defines it.

    Read out of the script rather than duplicated here: the two are the same
    list, and a second copy is the thing that let the first one go stale.
    """
    m = re.search(r"CASE_SUITES = \{(.*?)\n\}", VALIDATOR.read_text(), re.S)
    assert m, "CASE_SUITES not found in the validator"
    suites = {
        name: set(re.findall(r'"([^"]+)"', body))
        for name, body in re.findall(r'"(\w+)":\s*\{(.*?)\},', m.group(1), re.S)
    }
    assert suites, "CASE_SUITES is empty; refusing to report success"
    for name, names in suites.items():
        assert names, f"CASE_SUITES[{name!r}] is empty; refusing to report success"
    return suites


def expected_cases() -> set[str]:
    return {name for names in case_suites().values() for name in names}


def test_expected_cases_matches_the_cases_on_disk():
    """The validator's case list must not drift from evals/.

    It did: the list named three cases while five existed, so a run that
    silently skipped `integration-cap` and `already-fixed` — the only two that
    reach Phases 4-6 — passed the gate that exists to catch exactly that.
    """
    on_disk = {p.parent.name for p in (HERE.parents[0] / "evals").glob("*/case.yaml")}
    assert on_disk, "no eval cases found on disk; refusing to report success"
    assert expected_cases() == on_disk, (
        f"validate_eval_result.py expects {sorted(expected_cases())} but evals/ holds "
        f"{sorted(on_disk)}; a run skipping the difference would validate clean"
    )


def test_the_validator_suites_match_the_tags_on_disk():
    """The split is declared in two places and both are load-bearing.

    `--tag` is what the operator actually runs; `CASE_SUITES` is what decides
    whether the resulting JSON is complete. If they disagree, the validator
    demands a case the tag never selected — or, worse, accepts a static sweep
    that silently lost one.
    """
    suites = case_suites()
    by_tag: dict[str, set[str]] = {name: set() for name in suites}
    for path in (HERE.parents[0] / "evals").glob("*/case.yaml"):
        tags = set(yaml.safe_load(path.read_text()).get("tags") or [])
        for name in suites:
            if name in tags:
                by_tag[name].add(path.parent.name)
    assert by_tag == suites, (
        f"validate_eval_result.py splits the cases {ns(suites)} but the tags on disk split "
        f"them {ns(by_tag)}. `--tag` and the completeness check must select the same sets."
    )
    overlap = suites["static"] & suites["online"]
    assert not overlap, f"{sorted(overlap)} is in both suites, so no result can be complete"


def ns(d: dict[str, set[str]]) -> dict[str, list[str]]:
    return {k: sorted(v) for k, v in d.items()}


def test_a_result_mixing_the_two_suites_is_rejected(tmp_path: Path, passing: dict):
    """The failure the tag split exists to prevent, asserted rather than assumed.

    Stage 2's ground truth is public record and the static cases' is authored
    here; a mean over both answers no question. `claude plugin eval` runs every
    case it finds, so producing this JSON takes nothing more than forgetting
    `--tag` — and the resulting number would look entirely ordinary.
    """
    template = json.loads(json.dumps(passing["cases"][0]))
    template["name"] = sorted(case_suites()["online"])[0]
    passing["cases"].append(template)
    passing["aggregates"]["casesTotal"] = len(passing["cases"])
    passing["aggregates"]["casesPassed"] = len(passing["cases"])
    proc = run_validator(passing, tmp_path)
    assert proc.returncode == 1
    assert "must never be averaged" in proc.stderr


def test_an_unrecognised_case_is_reported_rather_than_ignored(tmp_path: Path, passing: dict):
    """A case the validator has never heard of is checked against nothing.

    Silently ignoring it is how the list went stale the first time: a renamed
    case disappears from the expectations and its absence stops being detectable.
    """
    template = json.loads(json.dumps(passing["cases"][0]))
    template["name"] = "some-case-nobody-registered"
    passing["cases"].append(template)
    passing["aggregates"]["casesTotal"] = len(passing["cases"])
    passing["aggregates"]["casesPassed"] = len(passing["cases"])
    proc = run_validator(passing, tmp_path)
    assert proc.returncode == 1
    assert "some-case-nobody-registered" in proc.stderr


@pytest.fixture
def passing(real: dict) -> dict:
    """The real result, edited to the shape a *good* run would have.

    The recorded run genuinely failed (delta -0.056), so a passing payload has
    to be constructed. It is built by editing the real one, so it keeps every
    key the CLI actually emits.

    The recorded run predates two cases, so the case list is topped up from the
    STATIC suite rather than hardcoded — otherwise adding a case makes this
    fixture, and every assertion built on it, silently wrong.

    The static suite specifically, not every known case: the recorded run is a
    static sweep, and topping it up from the union built a result spanning both
    suites, which the validator now rejects as the un-averageable mix it is.
    """
    payload = json.loads(json.dumps(real))
    payload["partial"] = False
    template = payload["cases"][0]
    static = case_suites()["static"]
    payload["cases"] = [c for c in payload["cases"] if c.get("name", c.get("case")) in static]
    seen = {c.get("name", c.get("case")) for c in payload["cases"]}
    for name in sorted(static - seen):
        extra = json.loads(json.dumps(template))
        extra["name"] = name
        payload["cases"].append(extra)
    agg = payload["aggregates"]
    agg["casesTotal"] = len(payload["cases"])
    agg["casesPassed"] = agg["casesTotal"]
    agg["overallScore"] = 1
    agg["meanDelta"] = 0.5
    return payload


def test_the_recorded_real_result_is_rejected(tmp_path: Path, real: dict):
    """The one run that exists scored a negative delta and must not validate."""
    proc = run_validator(real, tmp_path)
    assert proc.returncode == 1, "a negative-delta run must be rejected"
    assert "ablation delta" in proc.stderr


def test_a_constructed_good_result_is_accepted(tmp_path: Path, passing: dict):
    """Guards against the opposite failure: a validator that rejects everything.

    Without this, every assertion below would pass on a validator hard-coded to
    return 1.
    """
    proc = run_validator(passing, tmp_path)
    assert proc.returncode == 0, f"a good result must be accepted:\n{proc.stderr}"
    assert "OK:" in proc.stdout


def test_a_one_run_eval_is_rejected(tmp_path: Path, passing: dict):
    """The bug: the CLI emits `runsPerCase`, the validator read `runs`."""
    for case in passing["cases"]:
        case["runsPerCase"] = 1
    proc = run_validator(passing, tmp_path)
    assert proc.returncode == 1, "a 1-run eval must not pass; a pass RATE needs 3"
    assert "ran 1 time(s)" in proc.stderr


def test_a_result_with_an_errored_run_is_rejected(tmp_path: Path, passing: dict):
    """A dead run is scored 0, so a dead ARM reads as an arm that answered badly.

    The 2026-08-04 sweep lost 22 of 30 runs to `exit 1: (no stderr)` at turn 1
    for $0.00 each — a usage limit reached mid-sweep. `partial` was still false,
    every case still reported `runsPerCase: 3`, and blocked-attack-path showed a
    +0.47 delta purely because all three no-plugin runs were dead while two
    with-plugin runs had completed before the wall. Every other check in the
    validator was satisfied.
    """
    first = passing["cases"][0]["arms"]["with"][0]
    first["error"] = "exit 1: (no stderr)"
    proc = run_validator(passing, tmp_path)
    assert proc.returncode == 1, "a result containing an errored run must not pass"
    assert "errored" in proc.stderr, proc.stderr


def test_the_real_result_carries_the_error_key_the_validator_reads(real: dict):
    """Zero guard for the check above: if runs never carry `error`, it inspects
    nothing and a sweep full of dead runs sails through."""
    runs = [r for c in real["cases"] for arm in c["arms"].values() for r in arm]
    assert runs, "no runs in the recorded result"
    assert all("error" in r for r in runs), (
        "recorded runs have no `error` key, so the errored-run guard reads nothing. "
        f"Keys present: {sorted(runs[0])}"
    )


def test_the_real_result_uses_the_key_the_validator_reads(real: dict):
    """Pins the schema assumption itself, so a rename fails loudly here."""
    assert real["cases"], "no cases in the recorded result"
    for case in real["cases"]:
        assert "runsPerCase" in case, (
            f"case {case.get('name')} has no runsPerCase; the validator reads that key "
            f"and would silently check nothing. Keys present: {sorted(case)}"
        )


def test_a_case_with_no_run_count_is_rejected_not_skipped(tmp_path: Path, passing: dict):
    """A missing count means "unknown", which must not read as "fine"."""
    for case in passing["cases"]:
        case.pop("runsPerCase", None)
    proc = run_validator(passing, tmp_path)
    assert proc.returncode == 1
    assert "no run count" in proc.stderr


def test_a_missing_score_is_rejected_not_skipped(tmp_path: Path, passing: dict):
    """`score is not None and score != 1` read a renamed key as full marks.

    Measured: renaming `overallScore` to `meanScore` in the passing fixture and
    setting it to 0.6 gave `exit 0` and `OK: 5/5 cases passed`. Every sibling
    reader in the same function — casesTotal, runsPerCase, meanDelta — records a
    problem when its key is absent; this one treated absence as fine, on a
    schema the file's own comments note has moved before.
    """
    agg = passing["aggregates"]
    agg.pop("overallScore", None)
    agg["meanScore"] = 0.6
    proc = run_validator(passing, tmp_path)
    assert proc.returncode == 1, "a result with no readable score must not pass"
    assert "no overall score" in proc.stderr


def test_the_real_result_carries_the_score_key_the_validator_reads(real: dict):
    """Pins the schema assumption, so a rename fails loudly here rather than
    silently retiring the score check."""
    agg = real["aggregates"]
    assert "overallScore" in agg or "score" in agg, (
        f"the recorded result has no overallScore/score; the validator reads those two "
        f"keys and a rename would make its score check dead. Keys present: {sorted(agg)}"
    )


def test_zero_cases_is_rejected(tmp_path: Path, passing: dict):
    passing["cases"] = []
    passing["aggregates"]["casesTotal"] = 0
    passing["aggregates"]["casesPassed"] = 0
    proc = run_validator(passing, tmp_path)
    assert proc.returncode == 1
    assert "zero cases" in proc.stderr


def test_a_missing_case_is_reported_by_name(tmp_path: Path, passing: dict):
    passing["cases"] = [c for c in passing["cases"] if c.get("name") != "should-not-fire"]
    passing["aggregates"]["casesTotal"] = len(passing["cases"])
    passing["aggregates"]["casesPassed"] = len(passing["cases"])
    proc = run_validator(passing, tmp_path)
    assert proc.returncode == 1
    assert "should-not-fire" in proc.stderr


def test_a_partial_run_is_rejected(tmp_path: Path, passing: dict):
    passing["partial"] = True
    proc = run_validator(passing, tmp_path)
    assert proc.returncode == 1
    assert "partial" in proc.stderr


@pytest.mark.parametrize("delta", [0, -0.1, -1])
def test_a_non_positive_delta_is_rejected(tmp_path: Path, passing: dict, delta: float):
    """A plugin that does not beat its baseline is not doing anything."""
    passing["aggregates"]["meanDelta"] = delta
    proc = run_validator(passing, tmp_path)
    assert proc.returncode == 1
    assert "did not beat" in proc.stderr


def test_a_missing_delta_is_rejected_with_the_flag_that_causes_it(tmp_path: Path, passing: dict):
    passing["aggregates"].pop("meanDelta", None)
    proc = run_validator(passing, tmp_path)
    assert proc.returncode == 1
    assert "--ablation with-without" in proc.stderr, (
        "the message must name the flag; for a PATH target it silently defaults to none"
    )


def test_an_unreadable_file_is_an_error_not_a_pass(tmp_path: Path):
    proc = subprocess.run(
        [sys.executable, str(VALIDATOR), str(tmp_path / "nope.json")],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 1
    assert "cannot read" in proc.stderr


def test_no_arguments_is_a_usage_error():
    proc = subprocess.run(
        [sys.executable, str(VALIDATOR)], capture_output=True, text=True, check=False
    )
    assert proc.returncode == 2
