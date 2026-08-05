#!/usr/bin/env python3
"""Tests for the judge-benchmark scorer.

Three of these carry the weight:

- `test_credulous_judge_scores_zero_rejection` is the fixture that proves the
  scorer still detects its target. A judge that returns TRUE_POSITIVE for
  everything must score 0% rejection here. If this ever passes with a non-zero
  rejection rate, the matching has broken and every future bench run is noise.
- `test_run_with_no_seeded_items_is_refused` and
  `test_empty_run_is_refused_not_scored` are the anti-vacuity guards. A scorer
  that inspected no seeded false positives has measured nothing the ground-truth
  grader does not already measure, and must not print a score for it.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent.parent / "scripts"))

from score_judge_bench import (  # noqa: E402
    ABSENT,
    MERGED,
    RETAINED,
    UNJUDGED,
    BenchError,
    item_key,
    load_bench,
    main,
    score,
)

BENCH_PATH = HERE / "judge_bench_input.json"
FIXTURES = HERE / "fixtures"

JUDGE_FIELDS = (
    "fp_verdict",
    "fp_rationale",
    "severity",
    "attack_vector",
    "exploitability",
    "severity_rationale",
    "severity_validated",
    "id",
    "merged_into",
)


@pytest.fixture
def bench():
    return load_bench(BENCH_PATH)


def judged(
    bench, real_verdict="TRUE_POSITIVE", seeded_verdict="FALSE_POSITIVE", carry_bench_id=False
):
    """Build a judged findings.json in which the judge behaved as described.

    Built from the shipped bench rather than a checked-in copy of it, so the two
    cannot drift apart: if a bench item's file, line or title changes, these tests
    follow it instead of silently ceasing to match.
    """
    findings = []
    for index, item in enumerate(bench["items"], start=1):
        verdict = real_verdict if item["expected"] == "retain" else seeded_verdict
        finding = {k: v for k, v in item.items() if k not in {"bench_id", "expected", "why_wrong"}}
        finding["id"] = f"X-{index:03d}"
        finding["fp_verdict"] = verdict
        finding["fp_rationale"] = "test"
        finding["severity_validated"] = True
        if verdict in {"TRUE_POSITIVE", "LIKELY_TP"}:
            finding["severity"] = "MEDIUM"
        if carry_bench_id:
            finding["bench_id"] = item["bench_id"]
        findings.append(finding)
    return {
        "run": {"threat_model": "REMOTE", "severity_filter": "all", "judge_mode": "batched"},
        "stats": {"judge_agents": 4},
        "findings": findings,
        "coverage": [],
    }


# ------------------------------------------------- the three load-bearing tests


def test_credulous_judge_scores_zero_rejection(bench):
    report = score(judged(bench, "TRUE_POSITIVE", "TRUE_POSITIVE"), bench)
    assert report["true_positive_retention"]["rate"] == 1.0
    assert report["false_positive_rejection"]["rejected"] == 0
    assert report["false_positive_rejection"]["rate"] == 0.0
    assert report["false_positive_rejection"]["judged"] == 8


def test_run_with_no_seeded_items_is_refused(bench):
    doc = judged(bench)
    seeded_keys = {item_key(i) for i in bench["items"] if i["expected"] == "reject"}
    doc["findings"] = [f for f in doc["findings"] if item_key(f) not in seeded_keys]
    with pytest.raises(BenchError, match="seeded false positive"):
        score(doc, bench)


def test_empty_run_is_refused_not_scored(bench):
    doc = json.loads((FIXTURES / "empty_judged.json").read_text(encoding="utf-8"))
    with pytest.raises(BenchError, match="zero findings"):
        score(doc, bench)


def test_run_with_no_real_findings_is_refused(bench):
    # Retention over an empty denominator is undefined, not 0%.
    doc = judged(bench)
    real_keys = {item_key(i) for i in bench["items"] if i["expected"] == "retain"}
    doc["findings"] = [f for f in doc["findings"] if item_key(f) not in real_keys]
    with pytest.raises(BenchError, match="real bench finding"):
        score(doc, bench)


# --------------------------------------------------------------------- scoring


def test_perfect_judge_scores_full_marks(bench):
    report = score(judged(bench), bench)
    assert report["true_positive_retention"] == {"retained": 13, "judged": 13, "rate": 1.0}
    assert report["false_positive_rejection"] == {"rejected": 8, "judged": 8, "rate": 1.0}
    assert report["unexpected_findings"] == []
    assert report["verdict_distribution"] == {"TRUE_POSITIVE": 13, "FALSE_POSITIVE": 8}


def test_paranoid_judge_loses_retention(bench):
    report = score(judged(bench, "FALSE_POSITIVE", "FALSE_POSITIVE"), bench)
    assert report["true_positive_retention"]["rate"] == 0.0
    assert report["false_positive_rejection"]["rate"] == 1.0


@pytest.mark.parametrize("verdict", ["LIKELY_FP", "OUT_OF_SCOPE", "FALSE_POSITIVE"])
def test_every_rejecting_verdict_counts_as_a_rejection(bench, verdict):
    report = score(judged(bench, "TRUE_POSITIVE", verdict), bench)
    assert report["false_positive_rejection"]["rate"] == 1.0


@pytest.mark.parametrize("verdict", ["TRUE_POSITIVE", "LIKELY_TP"])
def test_every_survivor_verdict_counts_as_retention(bench, verdict):
    report = score(judged(bench, verdict, "FALSE_POSITIVE"), bench)
    assert report["true_positive_retention"]["rate"] == 1.0


def test_matching_survives_renumbered_ids(bench):
    doc = judged(bench)
    for offset, finding in enumerate(doc["findings"]):
        finding["id"] = f"RENUMBERED-{999 - offset}"
    report = score(doc, bench)
    assert report["true_positive_retention"]["retained"] == 13


def test_bench_id_matches_even_when_the_location_moved(bench):
    doc = judged(bench, carry_bench_id=True)
    doc["findings"][0]["line"] = 999999
    doc["findings"][0]["title"] = "a reviewer retitled this"
    report = score(doc, bench)
    assert report["per_item"][0]["outcome"] == RETAINED
    assert report["unexpected_findings"] == []


def test_a_merged_finding_is_reported_as_merged_not_judged(bench):
    doc = judged(bench)
    doc["findings"][0]["merged_into"] = "OTHER-001"
    report = score(doc, bench)
    assert report["per_item"][0]["outcome"] == MERGED
    assert report["true_positive_retention"]["judged"] == 12


def test_an_unjudged_finding_is_not_scored_as_retained(bench):
    doc = judged(bench)
    doc["findings"][0]["fp_rationale"] = "JUDGE DID NOT RUN — verdict and severity are unvalidated"
    report = score(doc, bench)
    assert report["per_item"][0]["outcome"] == UNJUDGED
    assert report["true_positive_retention"] == {"retained": 12, "judged": 12, "rate": 1.0}


def test_a_verdict_without_a_severity_still_counts_as_judged(bench):
    # severity_validated is false in two different situations and only one of them
    # means no judge ran. A judge that ruled TRUE_POSITIVE and forgot the severity
    # has judged the finding.
    doc = judged(bench)
    doc["findings"][0]["severity_validated"] = False
    doc["findings"][0].pop("severity", None)
    report = score(doc, bench)
    assert report["per_item"][0]["outcome"] == RETAINED


def test_merged_duplicates_are_not_reported_as_unexpected(bench):
    doc = judged(bench)
    doc["findings"].append(
        {
            "id": "DUP-001",
            "file": "expat/lib/xmlparse.c",
            "line": 2927,
            "title": "a duplicate the dedup judge absorbed",
            "merged_into": "X-001",
        }
    )
    assert score(doc, bench)["unexpected_findings"] == []


def test_a_missing_bench_item_is_absent_not_rejected(bench):
    doc = judged(bench)
    doc["findings"] = doc["findings"][1:]
    report = score(doc, bench)
    assert report["per_item"][0]["outcome"] == ABSENT
    assert report["true_positive_retention"]["judged"] == 12


def test_findings_outside_the_bench_are_reported_separately(bench):
    doc = judged(bench)
    doc["findings"].append(
        {
            "id": "NEW-001",
            "file": "expat/lib/xmltok.c",
            "line": 42,
            "title": "something the hunters found",
            "fp_verdict": "TRUE_POSITIVE",
            "severity_validated": True,
        }
    )
    report = score(doc, bench)
    assert len(report["unexpected_findings"]) == 1
    assert "xmltok.c:42" in report["unexpected_findings"][0]


def test_run_meta_supplies_the_cost_columns(bench):
    report = score(judged(bench), bench, {"agents": 23, "subagent_tokens": 1_800_000})
    assert report["run"]["agents"] == 23
    assert report["run"]["subagent_tokens"] == 1_800_000
    assert report["run"]["judge_agents"] == 4


def test_missing_run_meta_says_so_rather_than_reporting_zero(bench):
    report = score(judged(bench), bench)
    assert report["run"]["agents"] is None
    assert "not supplied" in _format(report)


def test_a_fooled_judge_is_told_why_it_was_wrong(bench):
    text = _format(score(judged(bench, "TRUE_POSITIVE", "TRUE_POSITIVE"), bench))
    assert "The judge accepted these seeded false positives" in text
    assert "sfp-01" in text
    assert "judge was wrong" in text


def _format(report):
    from score_judge_bench import format_score

    return format_score(report)


# ---------------------------------------------------------------- bench input


def test_shipped_bench_is_well_formed(bench):
    real = [i for i in bench["items"] if i["expected"] == "retain"]
    seeded = [i for i in bench["items"] if i["expected"] == "reject"]
    assert len(real) == 13
    assert 6 <= len(seeded) <= 8
    assert bench["expected_counts"] == {"real": len(real), "seeded": len(seeded)}
    assert all(i.get("why_wrong", "").strip() for i in seeded)
    assert len({item_key(i) for i in bench["items"]}) == len(bench["items"])


def test_no_judge_field_leaked_into_the_bench_input(bench):
    for item in bench["items"]:
        assert not (set(item) & set(JUDGE_FIELDS)), item["bench_id"]


# The seven public-CVE functions this bench was originally checked against. The
# corpus that named them has been retired — a benchmark whose answers sit in a CVE
# database measures whether a reviewer can look things up — but the constraint still
# holds: a seeded false positive must not share a function with a real finding, or no
# verdict can distinguish the two and the score means nothing either way.
RETIRED_GROUND_TRUTH_FUNCTIONS = frozenset(
    {
        "copystring",
        "storerawnames",
        "xml_getbuffer",
        "doprolog",
        "build_node",
        "addbinding",
        "utf8_isname2",
        "utf8_isname3",
        "utf8_isnmstrt2",
        "utf8_isnmstrt3",
    }
)


def test_seeded_findings_share_no_function_with_a_real_finding(bench):
    real = {item["function"].lower() for item in bench["items"] if item["expected"] == "keep"}
    seeded = {item["function"].lower() for item in bench["items"] if item["expected"] == "reject"}
    assert seeded, "the bench holds no seeded false positives, so rejection is unmeasurable"
    assert not (real & seeded), sorted(real & seeded)
    assert not (seeded & RETIRED_GROUND_TRUTH_FUNCTIONS), sorted(
        seeded & RETIRED_GROUND_TRUTH_FUNCTIONS
    )


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(lambda b: b["items"].append(dict(b["items"][0])), id="duplicate-key"),
        pytest.param(lambda b: b["items"][0].pop("bench_id"), id="missing-bench-id"),
        pytest.param(lambda b: b["items"][0].update(expected="maybe"), id="bad-expected"),
        pytest.param(lambda b: b.update(items=[]), id="empty-items"),
    ],
)
def test_malformed_bench_input_is_rejected(tmp_path, bench, mutate):
    mutate(bench)
    path = tmp_path / "bench.json"
    path.write_text(json.dumps(bench), encoding="utf-8")
    with pytest.raises(BenchError):
        load_bench(path)


def test_seeded_item_without_why_wrong_is_rejected(tmp_path, bench):
    for item in bench["items"]:
        if item["expected"] == "reject":
            item["why_wrong"] = ""
            break
    path = tmp_path / "bench.json"
    path.write_text(json.dumps(bench), encoding="utf-8")
    with pytest.raises(BenchError, match="why_wrong"):
        load_bench(path)


# ---------------------------------------------------------------------- cli


def test_cli_scores_and_writes_json(tmp_path, bench, capsys):
    doc_path = tmp_path / "findings.json"
    doc_path.write_text(json.dumps(judged(bench)), encoding="utf-8")
    meta_path = tmp_path / "meta.json"
    meta_path.write_text(json.dumps({"agents": 23, "subagent_tokens": 1234}), encoding="utf-8")
    out = tmp_path / "score.json"
    rc = main(
        [
            "--judged",
            str(doc_path),
            "--bench",
            str(BENCH_PATH),
            "--run-meta",
            str(meta_path),
            "--json",
            str(out),
        ]
    )
    assert rc == 0
    printed = capsys.readouterr().out
    assert "true-positive retention:   13/13 = 100.00%" in printed
    assert "false-positive rejection:  8/8 = 100.00%" in printed
    assert json.loads(out.read_text())["run"]["agents"] == 23


def test_cli_exits_2_when_it_scored_nothing(tmp_path, capsys):
    rc = main(["--judged", str(FIXTURES / "empty_judged.json"), "--bench", str(BENCH_PATH)])
    assert rc == 2
    assert "inspected nothing" in capsys.readouterr().err


def test_cli_exits_3_on_bad_input(tmp_path, capsys):
    rc = main(["--judged", str(tmp_path / "missing.json"), "--bench", str(BENCH_PATH)])
    assert rc == 3
    assert "score_judge_bench:" in capsys.readouterr().err


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
