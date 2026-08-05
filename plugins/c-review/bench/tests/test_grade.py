#!/usr/bin/env python3
"""Tests for the ground-truth grader.

Two of these are the controls the harness is judged by:

- `test_positive_control_perfect_run_scores_full_recall` — a synthetic run that
  describes every injected bug correctly must score 100%. If a `mechanism_all_of`
  group stops matching a correct description, this fails instead of every future
  run quietly scoring lower.
- `test_negative_control_right_site_wrong_mechanism_scores_zero` — findings in the
  right files, in the right functions, describing something else entirely must score
  0%. Without this, file-level proximity would pass for a hit and every arm would
  look competent.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from lib import grade  # noqa: E402

FIXTURES = HERE / "fixtures"


def load(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


@pytest.fixture
def gt():
    return load("gt_demo.json")


def arm(name, **extra):
    doc = load(name)
    doc.update({"arm": "bare", "corpus": "demo", "variant": "bench", **extra})
    return doc


def outcomes(scored):
    return {row["id"]: row["outcome"] for row in scored["results"]}


# ------------------------------------------------------------------- controls


def test_positive_control_perfect_run_scores_full_recall(gt):
    scored = grade.grade(arm("result_perfect.json"), gt)
    assert scored["hits"] == 3, outcomes(scored)
    assert scored["recall"] == 1.0
    assert set(outcomes(scored).values()) == {grade.HIT}


def test_negative_control_right_site_wrong_mechanism_scores_zero(gt):
    scored = grade.grade(arm("result_wrong_mechanism.json"), gt)
    assert scored["hits"] == 0
    assert scored["recall"] == 0.0
    assert set(outcomes(scored).values()) == {grade.NEAR_MISS}


# --------------------------------------------------------------------- guards


def test_zero_findings_is_refused_not_scored(gt):
    with pytest.raises(grade.GradeError, match="zero findings"):
        grade.grade({"arm": "bare", "corpus": "demo", "findings": []}, gt)


def test_zero_ground_truth_items_is_refused(gt):
    gt["items"] = []
    with pytest.raises(grade.GradeError, match="zero items"):
        grade.grade(arm("result_perfect.json"), gt)


# ------------------------------------------------------------------- outcomes


def test_found_then_dropped_is_suppressed_not_missed(gt):
    scored = grade.grade(arm("result_suppressed.json"), gt)
    assert outcomes(scored) == {"D-1": grade.HIT, "D-2": grade.SUPPRESSED, "D-3": grade.SUPPRESSED}
    assert scored["hits"] == 1
    assert scored["suppressed"] == 2


def test_wrong_file_is_a_miss_even_with_the_right_mechanism(gt):
    doc = arm("result_perfect.json")
    doc["findings"][0]["file"] = "src/unrelated.c"
    assert outcomes(grade.grade(doc, gt))["D-1"] == grade.MISS


def test_wrong_function_and_distant_line_is_a_miss(gt):
    doc = arm("result_perfect.json")
    doc["findings"][1]["function"] = "some_helper"
    doc["findings"][1]["line"] = 999
    assert outcomes(grade.grade(doc, gt))["D-2"] == grade.MISS


def test_line_window_is_the_fallback_when_no_function_is_named(gt):
    doc = arm("result_perfect.json")
    doc["findings"][1]["function"] = ""
    doc["findings"][1]["line"] = 88  # within the 12-line window of 80
    assert outcomes(grade.grade(doc, gt))["D-2"] == grade.HIT


def test_line_outside_the_window_does_not_match(gt):
    doc = arm("result_perfect.json")
    doc["findings"][1]["function"] = ""
    doc["findings"][1]["line"] = 200
    assert outcomes(grade.grade(doc, gt))["D-2"] == grade.MISS


def test_path_matching_is_segment_anchored():
    assert grade.file_matches("expat/lib/x.c", "lib/x.c")
    assert grade.file_matches("./src/a.c", "src/a.c")
    assert not grade.file_matches("otherlib/x.c", "lib/x.c")
    assert not grade.file_matches("", "lib/x.c")


# -------------------------------------------------------------- false positives


def test_a_finding_at_a_decoy_is_a_certain_false_positive(gt):
    scored = grade.grade(arm("result_wrong_mechanism.json"), gt)
    decoys = scored["false_positives"][grade.DECOY_FP]
    assert [d["decoy"] for d in decoys] == ["DEC-1"]
    assert decoys[0]["decoy_kind"] == "extra-init"


def test_a_finding_that_matched_a_bug_is_not_also_charged_as_a_decoy(gt):
    # The decoy sits in a different function from every bug, but a finding can still
    # fall inside the line window of both. A correct finding must never be counted as
    # a false positive as well.
    gt["decoys"][0]["line"] = 40
    gt["decoys"][0]["function"] = "parse_header"
    scored = grade.grade(arm("result_perfect.json"), gt)
    assert scored["hits"] == 3
    assert scored["false_positives"][grade.DECOY_FP] == []


def test_a_second_report_of_the_same_bug_is_not_counted_as_unmatched(gt):
    # Found on the first real run: an arm filed three bugs twice, and the duplicates
    # were reported as findings needing triage.
    doc = arm("result_perfect.json")
    duplicate = dict(doc["findings"][0])
    duplicate["id"] = "F-1b"
    doc["findings"].append(duplicate)
    scored = grade.grade(doc, gt)
    assert scored["hits"] == 3
    assert scored["false_positives"][grade.UNMATCHED] == []


def test_a_real_finding_at_a_decoy_site_is_not_charged_as_a_decoy(gt):
    # Also from the real run: a genuine key-disclosure finding shared a function with a
    # widened-type decoy and was billed for a decoy it never mentioned.
    gt["decoys"] = [
        {
            "id": "DEC-2",
            "decoy_kind": "widened-type",
            "file": "src/c.c",
            "line": 12,
            "function": "join_path",
            "safe_because": "a wider local cannot narrow any value it holds, so nothing changes",
        }
    ]
    doc = {
        "arm": "bare",
        "corpus": "demo",
        "variant": "bench",
        "findings": [
            {
                "id": "F-1",
                "file": "src/a.c",
                "line": 41,
                "function": "decode_value",
                "title": "Out-of-bounds write",
                "description": (
                    "value_len is unchecked so the memcpy overruns the destination buffer"
                ),
            },
            {
                "id": "F-2",
                "file": "src/c.c",
                "line": 12,
                "function": "join_path",
                "title": "The separator check is missing entirely",
                "description": "a scope carrying the delimiter makes the joined path ambiguous",
            },
        ],
    }
    scored = grade.grade(doc, gt)
    assert scored["false_positives"][grade.DECOY_FP] == []
    assert scored["hits"] == 2


def test_a_finding_that_does_claim_the_decoy_is_charged(gt):
    # DEC-1 lives in parse_header, which holds no bug — the arrangement the gate
    # enforces. A finding there that describes the mutation is a decoy hit.
    doc = {
        "arm": "bare",
        "corpus": "demo",
        "variant": "bench",
        "findings": [
            {
                "id": "F-9",
                "file": "src/a.c",
                "line": 10,
                "function": "parse_header",
                "title": "Dead store",
                "description": "the initialiser is redundant because the value is overwritten",
            }
        ],
    }
    scored = grade.grade(doc, gt)
    assert [d["decoy"] for d in scored["false_positives"][grade.DECOY_FP]] == ["DEC-1"]


def test_a_known_corpus_weakness_is_neither_a_hit_nor_a_false_positive(gt):
    doc = {
        "arm": "bare",
        "corpus": "demo",
        "variant": "bench",
        "findings": [
            {
                "id": "F-1",
                "file": "src/a.c",
                "line": 41,
                "function": "decode_value",
                "title": "Out-of-bounds write",
                "description": (
                    "value_len is unchecked so the memcpy overruns the destination buffer"
                ),
            },
            {
                "id": "F-7",
                "file": "src/b.c",
                "line": 5,
                "function": "helper_hash",
                "title": "The toy hash leaks its key",
                "description": "an empty message returns the key unchanged",
            },
        ],
    }
    scored = grade.grade(doc, gt)
    assert [e["finding"] for e in scored["false_positives"][grade.KNOWN_EXTRA]] == ["F-7"]
    assert scored["false_positives"][grade.UNMATCHED] == []
    assert "known extra" in grade.format_grade(scored)


def test_unmatched_findings_are_counted_but_not_called_false_positives(gt):
    doc = arm("result_perfect.json")
    doc["findings"].append(
        {
            "id": "F-9",
            "file": "src/z.c",
            "line": 5,
            "function": "helper",
            "title": "A real bug nobody injected",
            "description": "the base code may hold its own bugs",
        }
    )
    scored = grade.grade(doc, gt)
    assert scored["false_positives"][grade.UNMATCHED] == ["F-9"]
    assert scored["false_positives"][grade.DECOY_FP] == []
    assert scored["hits"] == 3


def test_control_variant_turns_every_claim_into_a_false_positive(gt):
    gt["variant"] = "control"
    for item in gt["items"]:
        item["present"] = False
    scored = grade.grade(arm("result_perfect.json", variant="control"), gt)
    assert scored["bugs_present"] is False
    assert scored["recall"] is None
    assert len(scored["false_positives"][grade.CONTROL_FP]) == 3


def test_the_control_table_relabels_outcomes_so_a_claim_reads_as_a_claim(gt):
    gt["variant"] = "control"
    for item in gt["items"]:
        item["present"] = False
    text = grade.format_grade(grade.grade(arm("result_perfect.json", variant="control"), gt))
    assert "FP_CLAIMED" in text
    assert "HIT" not in text
    assert "patched control" in text


def test_a_cve_citation_is_recorded_as_a_canary(gt):
    scored = grade.grade(arm("result_canary.json"), gt)
    assert scored["canary_cve_citations"][0]["cves"] == ["CVE-2022-25315"]


# ------------------------------------------------------------------ breakdowns


def test_breakdowns_cover_every_class_and_tier(gt):
    scored = grade.grade(arm("result_suppressed.json"), gt)
    assert scored["by_difficulty"] == {
        "EASY": {"total": 1, "hits": 1, "suppressed": 0, "near": 0},
        "MEDIUM": {"total": 1, "hits": 0, "suppressed": 1, "near": 0},
        "HARD": {"total": 1, "hits": 0, "suppressed": 1, "near": 0},
    }
    assert set(scored["by_class"]) == {"buffer-overflow", "use-after-free", "delimiter-injection"}


def test_report_text_names_the_controls_and_the_canary(gt):
    text = grade.format_grade(grade.grade(arm("result_canary.json"), gt))
    assert "recall: 3/3" in text
    assert "CANARY" in text
    assert "by difficulty: EASY 1/1" in text


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
