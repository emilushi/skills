#!/usr/bin/env python3
"""Tests for the ground-truth grader.

Two of these matter more than the rest:

- `test_all_seven_fixture_scores_full_recall` is the fixture that proves the
  grader still detects its target. If a mechanism keyword list in the ground
  truth stops matching a correct description of the bug, recall drops here and
  this fails, instead of the grader quietly reporting a lower score for every
  future run.
- `test_empty_run_is_refused_not_scored` is the anti-vacuity guard. A grader
  that inspects nothing must not report success.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
# Both paths explicitly: grade.py adds ../scripts itself, but relying on that makes
# these imports order-dependent, and an import sorter will happily reorder them.
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "scripts"))

from findings_model import load  # noqa: E402
from grade import (  # noqa: E402
    HIT,
    MISS,
    NEAR_MISS,
    SUPPRESSED,
    GradeError,
    file_matches,
    grade,
    load_ground_truth,
    main,
    mechanism_matches,
    site_matches,
)

GROUND_TRUTH = HERE / "ground_truth" / "libexpat-R_2_4_3.json"
FIXTURES = HERE / "fixtures"


@pytest.fixture
def gt():
    return load_ground_truth(GROUND_TRUTH)


def fixture(name):
    return load(FIXTURES / name)


def outcomes(report):
    return {r["cve"]: r["outcome"] for r in report["results"]}


# ----------------------------------------------------- the two load-bearing tests


def test_all_seven_fixture_scores_full_recall(gt):
    report = grade(fixture("all_seven_found.json"), gt)
    assert report["hits"] == 7, outcomes(report)
    assert report["recall"] == 1.0
    assert set(outcomes(report).values()) == {HIT}


def test_empty_run_is_refused_not_scored(gt):
    with pytest.raises(GradeError, match="zero findings"):
        grade(fixture("empty_run.json"), gt)


def test_empty_ground_truth_is_refused(gt):
    gt["items"] = []
    with pytest.raises(GradeError, match="zero items"):
        grade(fixture("all_seven_found.json"), gt)


def test_scope_with_no_members_is_refused(gt):
    # Every finding rejected: the run is not empty, but 'reported' is, so the
    # grader inspected nothing under that scope and must say so.
    doc = fixture("found_then_suppressed.json")
    doc["findings"] = [f for f in doc["findings"] if f["fp_verdict"] != "TRUE_POSITIVE"]
    with pytest.raises(GradeError, match="none in scope"):
        grade(doc, gt, scope="reported")


# ------------------------------------------------------------------- outcomes


def test_unrelated_findings_all_miss(gt):
    report = grade(fixture("none_found.json"), gt)
    assert report["hits"] == 0
    assert set(outcomes(report).values()) == {MISS}
    assert report["extra_findings"] == ["ERR-001", "LEAK-001"]


def test_found_then_rejected_is_suppressed_not_miss(gt):
    report = grade(fixture("found_then_suppressed.json"), gt)
    result = outcomes(report)
    assert result["CVE-2022-25315"] == SUPPRESSED
    assert result["CVE-2022-23852"] == SUPPRESSED
    assert result["CVE-2022-25313"] == HIT
    assert report["hits"] == 1
    assert report["suppressed"] == 2


def test_scope_all_counts_a_rejected_finding_as_found(gt):
    # Same run, different question: 'did any reviewer see it?' rather than 'did
    # the user get told about it?'. Both numbers matter, so both are available.
    report = grade(fixture("found_then_suppressed.json"), gt, scope="all")
    assert report["hits"] == 3
    assert report["suppressed"] == 0


def test_right_site_wrong_mechanism_is_near_miss(gt):
    doc = fixture("all_seven_found.json")
    target = next(f for f in doc["findings"] if f["id"] == "DOS-001")
    scrub = (
        "title",
        "description",
        "code",
        "impact",
        "recommendation",
        "data_flow",
        "reachability",
        "fp_rationale",
        "bug_class",
    )
    for field in scrub:
        target[field] = "the element model is copied here"
    report = grade(doc, gt)
    assert outcomes(report)["CVE-2022-25313"] == NEAR_MISS
    assert report["near_misses"] == 1
    assert report["hits"] == 6


def test_correct_mechanism_at_the_wrong_site_does_not_count(gt):
    doc = fixture("all_seven_found.json")
    target = next(f for f in doc["findings"] if f["id"] == "INT-002")
    target["function"] = "some_unrelated_helper"
    target["line"] = 9999
    report = grade(doc, gt)
    assert outcomes(report)["CVE-2022-25315"] == MISS


def test_correct_mechanism_in_the_wrong_file_does_not_count(gt):
    doc = fixture("all_seven_found.json")
    next(f for f in doc["findings"] if f["id"] == "INT-002")["file"] = "expat/lib/xmltok.c"
    assert outcomes(grade(doc, gt))["CVE-2022-25315"] == MISS


def test_line_window_is_the_fallback_for_a_missing_function_name(gt):
    doc = fixture("all_seven_found.json")
    target = next(f for f in doc["findings"] if f["id"] == "INT-002")
    target["function"] = ""
    target["line"] = 2580  # within the 10-line window of the 2576 anchor
    assert outcomes(grade(doc, gt))["CVE-2022-25315"] == HIT


def test_line_just_outside_the_window_does_not_match(gt):
    doc = fixture("all_seven_found.json")
    target = next(f for f in doc["findings"] if f["id"] == "INT-002")
    target["function"] = ""
    target["line"] = 2587
    assert outcomes(grade(doc, gt))["CVE-2022-25315"] == MISS


def test_recall_counts_only_hits(gt):
    doc = fixture("all_seven_found.json")
    doc["findings"] = [f for f in doc["findings"] if f["id"] in {"INT-002", "DOS-001"}]
    report = grade(doc, gt)
    assert report["hits"] == 2
    assert report["recall"] == pytest.approx(2 / 7)


# ---------------------------------------------------------------- primitives


@pytest.mark.parametrize(
    ("found", "wanted", "expected"),
    [
        ("expat/lib/xmlparse.c", "expat/lib/xmlparse.c", True),
        ("./expat/lib/xmlparse.c", "expat/lib/xmlparse.c", True),
        ("xmlparse.c", "expat/lib/xmlparse.c", True),
        ("src/expat/lib/xmlparse.c", "expat/lib/xmlparse.c", True),
        ("otherlib/xmlparse.c", "lib/xmlparse.c", False),
        ("expat/lib/xmltok.c", "expat/lib/xmlparse.c", False),
        ("", "expat/lib/xmlparse.c", False),
    ],
)
def test_file_matching(found, wanted, expected):
    assert file_matches(found, wanted) is expected


def test_function_matching_ignores_case_and_parentheses():
    item = {"functions": ["(file-level)"], "lines": []}
    assert site_matches({"function": "File-Level"}, item, 10)[0]
    assert site_matches({"function": "(file-level)"}, item, 10)[0]
    assert not site_matches({"function": "build_node"}, item, 10)[0]


def test_mechanism_needs_every_group():
    item = {"mechanism_all_of": [["overflow"], ["bufsize", "namelen"]]}
    assert mechanism_matches({"title": "overflow of bufSize"}, item)[0]
    ok, missing = mechanism_matches({"title": "overflow somewhere"}, item)
    assert not ok and len(missing) == 1


# ------------------------------------------------------------- ground truth


def test_shipped_ground_truth_is_well_formed(gt):
    assert len(gt["items"]) == 7
    assert {i["tier"] for i in gt["items"]} == {"EASY", "MEDIUM", "HARD"}
    assert len({i["cve"] for i in gt["items"]}) == 7


@pytest.mark.parametrize("bad", ["items_not_a_list", "item_missing_file", "item_missing_mechanism"])
def test_malformed_ground_truth_is_rejected(tmp_path, bad):
    payloads = {
        "items_not_a_list": {"items": {}},
        "item_missing_file": {"items": [{"cve": "X"}]},
        "item_missing_mechanism": {"items": [{"cve": "X", "file": "a.c", "functions": ["f"]}]},
    }
    path = tmp_path / "gt.json"
    path.write_text(json.dumps(payloads[bad]), encoding="utf-8")
    with pytest.raises(GradeError):
        load_ground_truth(path)


# --------------------------------------------------------------------- cli


def test_cli_grades_and_writes_json(tmp_path, capsys):
    out = tmp_path / "score.json"
    rc = main(
        [
            "--findings",
            str(FIXTURES / "all_seven_found.json"),
            "--ground-truth",
            str(GROUND_TRUTH),
            "--json",
            str(out),
        ]
    )
    assert rc == 0
    assert "recall: 7/7" in capsys.readouterr().out
    assert json.loads(out.read_text())["hits"] == 7


def test_cli_exits_2_when_it_graded_nothing(capsys):
    rc = main(["--findings", str(FIXTURES / "empty_run.json"), "--ground-truth", str(GROUND_TRUTH)])
    assert rc == 2
    assert "inspected nothing" in capsys.readouterr().err


def test_cli_exits_3_on_bad_input(tmp_path, capsys):
    rc = main(["--findings", str(tmp_path / "missing.json"), "--ground-truth", str(GROUND_TRUTH)])
    assert rc == 3
    assert "grade:" in capsys.readouterr().err


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
