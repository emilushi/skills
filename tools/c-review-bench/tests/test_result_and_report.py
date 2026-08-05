#!/usr/bin/env python3
"""Tests for collection, planning and reporting.

The collection tests are the D13 regression. A previous measurement read
`findings.json` mid-write, published two conclusions from the partial document, and
saw the same code produce structurally different artifacts on two runs. So: a
completion marker is required, a changing file is refused, and an unexpected shape is
an error rather than something to interpret.

The reporting test that matters is `test_an_invalid_arm_is_excluded_not_annotated`.
An arm that used an oracle must vanish from the comparison table, because a caveat
beside a number does not survive being copied into a summary.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from lib import plan as plan_mod  # noqa: E402
from lib import recipe as recipe_mod  # noqa: E402
from lib import report as report_mod  # noqa: E402
from lib import result as result_mod  # noqa: E402

FIXTURES = HERE / "fixtures"
SIGIL = HERE.parent / "corpora" / "sigil" / "recipe.json"
WORKFLOW = plan_mod.plugin_root() / "workflows" / "c-review.js"


def write(path: Path, obj) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2) + "\n", encoding="utf-8")
    return path


def scaffold(tmp_path: Path, *, variant: str = "bench") -> Path:
    """A run directory with a one-cell plan and a private ground truth beside it."""
    run = tmp_path / "run"
    private = tmp_path / "work" / "sigil" / f"{variant}-private"
    ground_truth = json.loads((FIXTURES / "gt_demo.json").read_text(encoding="utf-8"))
    ground_truth["variant"] = variant
    if variant == "control":
        for item in ground_truth["items"]:
            item["present"] = False
    write(private / "ground_truth.json", ground_truth)
    write(
        run / "plan.json",
        {
            "tier": "standard",
            "cells": [
                {
                    "arm": "bare",
                    "corpus": "sigil",
                    "variant": variant,
                    "tree": str(tmp_path / "work" / "sigil" / variant),
                    "private": str(private),
                    "estimated_tokens": 51_047,
                    "estimated_agents": 1,
                    "lines_of_code": 868,
                    "bugs": 3,
                }
            ],
        },
    )
    return run


# ------------------------------------------------------------------ collection


def test_meta_without_the_completion_marker_is_refused(tmp_path):
    with pytest.raises(result_mod.ResultError, match='"complete": true'):
        result_mod.load_meta(FIXTURES / "meta_incomplete.json", 0.01, 1)


def test_zero_tokens_is_refused(tmp_path):
    with pytest.raises(result_mod.ResultError, match="cannot be compared"):
        result_mod.load_meta(FIXTURES / "meta_zero_tokens.json", 0.01, 1)


def test_a_valid_meta_loads():
    meta = result_mod.load_meta(FIXTURES / "meta_ok.json", 0.01, 1)
    assert meta["tokens"] == 51234 and meta["agents"] == 1


def test_a_file_that_keeps_changing_is_refused(tmp_path, monkeypatch):
    path = tmp_path / "growing.json"
    path.write_text("{}", encoding="utf-8")
    state = {"n": 0}
    real_digest = result_mod._digest

    def growing(target: Path) -> str:
        state["n"] += 1
        target.write_text("{}" + " " * state["n"], encoding="utf-8")
        return real_digest(target)

    monkeypatch.setattr(result_mod, "_digest", growing)
    with pytest.raises(result_mod.ResultError, match="still changing"):
        result_mod.wait_until_settled(path, settle_seconds=0.01, timeout=0.05)


def test_a_settled_file_is_accepted(tmp_path):
    path = write(tmp_path / "still.json", {"findings": []})
    assert result_mod.wait_until_settled(path, 0.01, 1)


def test_a_zero_settle_window_is_refused(tmp_path):
    path = write(tmp_path / "still.json", {"findings": []})
    with pytest.raises(result_mod.ResultError, match="checks nothing"):
        result_mod.wait_until_settled(path, 0, 1)


def test_collect_normalises_a_generic_result(tmp_path):
    run = scaffold(tmp_path)
    collected = result_mod.collect(
        run_dir=run,
        arm="bare",
        corpus="sigil",
        result_path=FIXTURES / "result_perfect.json",
        meta_path=FIXTURES / "meta_ok.json",
        transcripts=[FIXTURES / "transcript_clean.jsonl"],
        settle_seconds=0.01,
        timeout=1,
    )
    assert collected["shape"] == "generic"
    assert len(collected["findings"]) == 3
    assert all(f["reported"] for f in collected["findings"])
    assert (run / "collected" / "bare__sigil__bench.json").is_file()


def test_collect_uses_the_plugins_own_definition_of_reported(tmp_path):
    run = scaffold(tmp_path)
    native = {
        "run": {
            "severity_filter": "high",
            "hunter_external_sources": [
                {"group": "memory-bounds", "consulted": True, "detail": "upstream tarball"}
            ],
            "groups_attempted": ["memory-bounds"],
        },
        "stats": {"raw_findings": 3},
        "coverage": [],
        "findings": [
            {
                "id": "A-1",
                "file": "src/a.c",
                "line": 40,
                "function": "decode_value",
                "title": "t",
                "description": "d",
                "severity": "CRITICAL",
                "fp_verdict": "TRUE_POSITIVE",
            },
            {
                "id": "A-2",
                "file": "src/b.c",
                "line": 80,
                "function": "index_record",
                "title": "t",
                "description": "d",
                "severity": "LOW",
                "fp_verdict": "TRUE_POSITIVE",
            },
            {
                "id": "A-3",
                "file": "src/c.c",
                "line": 12,
                "function": "join_path",
                "title": "t",
                "description": "d",
                "severity": "HIGH",
                "fp_verdict": "FALSE_POSITIVE",
            },
        ],
    }
    path = write(tmp_path / "findings.json", native)
    collected = result_mod.collect(
        run_dir=run,
        arm="bare",
        corpus="sigil",
        result_path=path,
        meta_path=FIXTURES / "meta_ok.json",
        transcripts=[],
        settle_seconds=0.01,
        timeout=1,
    )
    assert collected["shape"] == "c-review"
    reported = {f["id"]: f["reported"] for f in collected["findings"]}
    assert reported == {"A-1": True, "A-2": False, "A-3": False}
    assert collected["external_sources_consulted"] is True


@pytest.mark.parametrize(
    ("mutate", "match"),
    [
        (lambda d: d["findings"][0].pop("file"), "missing required field"),
        (lambda d: d["findings"][0].update(line="not a number"), "not an integer"),
        (lambda d: d["findings"][0].update(line=0), "not a source line"),
        (lambda d: d["findings"].append(dict(d["findings"][0])), "duplicate finding id"),
    ],
)
def test_a_result_with_the_wrong_shape_is_refused(tmp_path, mutate, match):
    run = scaffold(tmp_path)
    doc = json.loads((FIXTURES / "result_perfect.json").read_text(encoding="utf-8"))
    mutate(doc)
    path = write(tmp_path / "broken.json", doc)
    with pytest.raises(result_mod.ResultError, match=match):
        result_mod.collect(
            run_dir=run,
            arm="bare",
            corpus="sigil",
            result_path=path,
            meta_path=FIXTURES / "meta_ok.json",
            transcripts=[],
            settle_seconds=0.01,
            timeout=1,
        )


def test_a_missing_findings_key_is_refused(tmp_path):
    run = scaffold(tmp_path)
    path = write(tmp_path / "nope.json", {"results": []})
    with pytest.raises(result_mod.ResultError, match="'findings' list"):
        result_mod.collect(
            run_dir=run,
            arm="bare",
            corpus="sigil",
            result_path=path,
            meta_path=FIXTURES / "meta_ok.json",
            transcripts=[],
            settle_seconds=0.01,
            timeout=1,
        )


def test_a_control_result_is_not_collected_as_a_bench_result(tmp_path):
    # The defect this test exists for: with both a bench and a control cell in the
    # plan, matching on arm and corpus alone attributed a control result to the bench
    # cell, which would have been reported as recall instead of as false positives.
    run = scaffold(tmp_path)
    plan = json.loads((run / "plan.json").read_text())
    control = dict(plan["cells"][0])
    control["variant"] = "control"
    control["private"] = str(tmp_path / "work" / "sigil" / "control-private")
    plan["cells"].append(control)
    write(run / "plan.json", plan)

    collected = result_mod.collect(
        run_dir=run,
        arm="bare",
        corpus="sigil",
        result_path=FIXTURES / "result_perfect.json",
        meta_path=FIXTURES / "meta_ok.json",
        transcripts=[],
        variant="control",
        settle_seconds=0.01,
        timeout=1,
    )
    assert collected["variant"] == "control"
    assert (run / "collected" / "bare__sigil__control.json").is_file()

    default = result_mod.collect(
        run_dir=run,
        arm="bare",
        corpus="sigil",
        result_path=FIXTURES / "result_perfect.json",
        meta_path=FIXTURES / "meta_ok.json",
        transcripts=[],
        settle_seconds=0.01,
        timeout=1,
    )
    assert default["variant"] == "bench"


def test_an_unknown_variant_is_refused(tmp_path):
    run = scaffold(tmp_path)
    with pytest.raises(result_mod.ResultError, match="variant 'control'"):
        result_mod.collect(
            run_dir=run,
            arm="bare",
            corpus="sigil",
            result_path=FIXTURES / "result_perfect.json",
            meta_path=FIXTURES / "meta_ok.json",
            transcripts=[],
            variant="control",
            settle_seconds=0.01,
            timeout=1,
        )


def test_collecting_a_cell_that_is_not_in_the_plan_is_refused(tmp_path):
    run = scaffold(tmp_path)
    with pytest.raises(result_mod.ResultError, match="no cell for arm"):
        result_mod.collect(
            run_dir=run,
            arm="fanout",
            corpus="sigil",
            result_path=FIXTURES / "result_perfect.json",
            meta_path=FIXTURES / "meta_ok.json",
            transcripts=[],
            settle_seconds=0.01,
            timeout=1,
        )


def test_collecting_without_a_plan_is_refused(tmp_path):
    with pytest.raises(result_mod.ResultError, match="no plan at"):
        result_mod.load_plan(tmp_path)


# --------------------------------------------------------------------- scoring


def collect_into(run: Path, result_name: str, transcript: str | None) -> None:
    result_mod.collect(
        run_dir=run,
        arm="bare",
        corpus="sigil",
        result_path=FIXTURES / result_name,
        meta_path=FIXTURES / "meta_ok.json",
        transcripts=[FIXTURES / transcript] if transcript else [],
        settle_seconds=0.01,
        timeout=1,
    )


def test_a_clean_arm_scores_and_exits_zero(tmp_path):
    run = scaffold(tmp_path)
    collect_into(run, "result_perfect.json", "transcript_clean.jsonl")
    scored = report_mod.score_run(run, workroot=tmp_path / "work")
    assert scored["invalid_arms"] == []
    arm = scored["arms"][0]
    assert arm["verdict"] == "VALID"
    assert arm["grade"]["hits"] == 3
    assert arm["cost"]["tokens_per_bug_found"] == 51234 // 3
    text = report_mod.format_report(scored)
    assert "RESULTS EXCLUDED" not in text
    assert "3/3" in text


def test_an_invalid_arm_is_excluded_not_annotated(tmp_path):
    run = scaffold(tmp_path)
    collect_into(run, "result_perfect.json", "transcript_cheating.jsonl")
    scored = report_mod.score_run(run, workroot=tmp_path / "work")
    assert [a["verdict"] for a in scored["arms"]] == ["INVALID"]
    assert scored["invalid_arms"]
    text = report_mod.format_report(scored)
    assert "RESULTS EXCLUDED" in text
    assert "every arm in this run was excluded" in text
    # the recall figure must not appear in the comparison table
    table = text.split("## Comparison")[1].split("## Cost")[0]
    assert "3/3" not in table


def test_an_arm_with_no_transcript_is_unverifiable(tmp_path):
    run = scaffold(tmp_path)
    collect_into(run, "result_perfect.json", None)
    scored = report_mod.score_run(run, workroot=tmp_path / "work")
    assert scored["arms"][0]["verdict"] == "UNVERIFIABLE"
    assert "no oracle check ran" in scored["arms"][0]["anticheat"]["error"]


def test_a_stale_collected_file_is_refused(tmp_path):
    run = scaffold(tmp_path)
    collect_into(run, "result_perfect.json", "transcript_clean.jsonl")
    canonical = run / "collected" / "bare__sigil__bench.json"
    canonical.rename(run / "collected" / "bare__sigil.json")  # the old naming scheme
    with pytest.raises(report_mod.ReportError, match="does not match its own name"):
        report_mod.score_run(run, workroot=tmp_path / "work")


def test_scoring_a_run_with_no_collected_arms_is_refused(tmp_path):
    run = scaffold(tmp_path)
    with pytest.raises(report_mod.ReportError, match="no collected arm results"):
        report_mod.score_run(run, workroot=tmp_path / "work")


def test_the_control_variant_reports_claims_as_false_positives(tmp_path):
    run = scaffold(tmp_path, variant="control")
    result_mod.collect(
        run_dir=run,
        arm="bare",
        corpus="sigil",
        result_path=FIXTURES / "result_perfect.json",
        meta_path=FIXTURES / "meta_ok.json",
        transcripts=[FIXTURES / "transcript_clean.jsonl"],
        variant="control",
        settle_seconds=0.01,
        timeout=1,
    )
    scored = report_mod.score_run(run, workroot=tmp_path / "work")
    grade = scored["arms"][0]["grade"]
    assert grade["bugs_present"] is False
    assert len(grade["false_positives"]["CONTROL_FP"]) == 3
    assert "control" in report_mod.format_report(scored)


# --------------------------------------------------------------------- planning


def test_the_taxonomy_comes_out_of_the_shipped_workflow():
    classes = plan_mod.extract_taxonomy(WORKFLOW)
    assert len(classes) >= 40
    ids = {c["id"] for c in classes}
    assert {"buffer-overflow", "use-after-free"} <= ids
    assert all(c["brief"] for c in classes)


def test_an_empty_taxonomy_is_refused(tmp_path):
    empty = tmp_path / "workflow.js"
    empty.write_text("const CLASSES = {\n}\n", encoding="utf-8")
    with pytest.raises(plan_mod.PlanError, match="zero bug classes"):
        plan_mod.extract_taxonomy(empty)


def test_a_missing_workflow_is_refused(tmp_path):
    with pytest.raises(plan_mod.PlanError, match="does not exist"):
        plan_mod.extract_taxonomy(tmp_path / "absent.js")


def test_the_partition_is_balanced_and_deterministic(tmp_path):
    tree = tmp_path / "tree"
    (tree / "src").mkdir(parents=True)
    (tree / "src" / "a.c").write_text("x\n" * 300, encoding="utf-8")
    (tree / "src" / "b.c").write_text("y\n" * 100, encoding="utf-8")
    first = plan_mod.partition(tree, 4)
    assert plan_mod.partition(tree, 4) == first
    assert len(first) == 4
    sizes = [sum(b - a + 1 for _, a, b in group) for group in first]
    assert sum(sizes) == 400
    assert max(sizes) <= 2 * min(sizes)


def test_partitioning_an_empty_tree_is_refused(tmp_path):
    (tmp_path / "empty").mkdir()
    with pytest.raises(plan_mod.PlanError, match="nothing to partition"):
        plan_mod.partition(tmp_path / "empty", 3)


def test_the_estimate_scales_with_corpus_size_and_has_a_floor():
    _, small = plan_mod.estimate_tokens("bare", 0.9, None)
    _, reference = plan_mod.estimate_tokens("bare", 13.0, None)
    _, big = plan_mod.estimate_tokens("bare", 86.0, None)
    assert small < reference < big
    assert small > plan_mod.ARM_MODEL["bare"]["per_agent"] * plan_mod.FLOOR_SHARE * 0.99
    assert reference == plan_mod.ARM_MODEL["bare"]["per_agent"]


def test_the_fanout_arm_needs_an_agent_count():
    with pytest.raises(plan_mod.PlanError, match="needs an agent count"):
        plan_mod.estimate_tokens("fanout", 1.0, None)


def test_plan_refuses_a_corpus_with_no_verification_stamp(tmp_path):
    with pytest.raises(plan_mod.PlanError, match="no verification stamp"):
        plan_mod.build_plan(
            tier="smoke",
            recipes={"sigil": recipe_mod.load(SIGIL)},
            workroot=tmp_path / "work",
            run_dir=tmp_path / "run",
            packet_dir=HERE.parent / "arms",
        )


def test_plan_refuses_a_stamp_that_says_unverified(tmp_path):
    write(tmp_path / "work" / "sigil" / "verified.json", {"verified": False})
    with pytest.raises(plan_mod.PlanError, match="verified=false"):
        plan_mod.build_plan(
            tier="smoke",
            recipes={"sigil": recipe_mod.load(SIGIL)},
            workroot=tmp_path / "work",
            run_dir=tmp_path / "run",
            packet_dir=HERE.parent / "arms",
        )


def test_plan_refuses_a_tier_with_no_matching_corpus(tmp_path):
    with pytest.raises(plan_mod.PlanError, match="zero corpora"):
        plan_mod.build_plan(
            tier="full",
            recipes={},
            workroot=tmp_path / "work",
            run_dir=tmp_path / "run",
            packet_dir=HERE.parent / "arms",
        )


def stamped(tmp_path: Path) -> Path:
    workroot = tmp_path / "work"
    write(
        workroot / "sigil" / "verified.json",
        {
            "verified": True,
            "lines_of_code": 868,
            "counts": {"bugs": 3, "decoys": 2, "by_class": {"buffer-overflow": 1}},
            "tree_sha256": {},
        },
    )
    tree = workroot / "sigil" / "bench"
    (tree / "src").mkdir(parents=True)
    (tree / "src" / "a.c").write_text("x\n" * 400, encoding="utf-8")
    (workroot / "sigil" / "control").mkdir(parents=True, exist_ok=True)
    return workroot


def test_a_plan_writes_one_packet_per_cell_with_every_placeholder_filled(tmp_path):
    workroot = stamped(tmp_path)
    plan = plan_mod.build_plan(
        allow_missing=True,
        tier="standard",
        recipes={"sigil": recipe_mod.load(SIGIL)},
        workroot=workroot,
        run_dir=tmp_path / "run",
        packet_dir=HERE.parent / "arms",
        fanout_n=3,
    )
    assert len(plan["cells"]) == 4
    assert plan["estimated_tokens_total"] > 0
    for cell in plan["cells"]:
        text = Path(cell["packet"]).read_text(encoding="utf-8")
        assert "{{" not in text
        assert str(cell["result_path"]) in text
    fanout = next(c for c in plan["cells"] if c["arm"] == "fanout")
    assert "lines 1-" in Path(fanout["packet"]).read_text(encoding="utf-8")
    assert "ESTIMATED TOTAL" in plan_mod.format_plan(plan)


def test_a_tier_missing_a_corpus_size_is_refused_unless_allowed(tmp_path):
    # A "standard" run that quietly covers one corpus instead of two is still labelled
    # standard everywhere downstream.
    workroot = stamped(tmp_path)
    with pytest.raises(plan_mod.PlanError, match="covers corpus size"):
        plan_mod.build_plan(
            tier="standard",
            recipes={"sigil": recipe_mod.load(SIGIL)},
            workroot=workroot,
            run_dir=tmp_path / "run",
            packet_dir=HERE.parent / "arms",
            fanout_n=3,
        )
    plan = plan_mod.build_plan(
        tier="standard",
        recipes={"sigil": recipe_mod.load(SIGIL)},
        workroot=workroot,
        run_dir=tmp_path / "run",
        packet_dir=HERE.parent / "arms",
        fanout_n=3,
        allow_missing=True,
    )
    assert plan["reduced"] is True
    assert "REDUCED RUN" in plan_mod.format_plan(plan)


def test_restricting_to_one_corpus_is_not_treated_as_drift(tmp_path):
    workroot = stamped(tmp_path)
    plan = plan_mod.build_plan(
        tier="standard",
        recipes={"sigil": recipe_mod.load(SIGIL)},
        workroot=workroot,
        run_dir=tmp_path / "run",
        packet_dir=HERE.parent / "arms",
        fanout_n=3,
        corpora=["sigil"],
    )
    assert plan["cells"]


def test_the_full_tier_adds_control_cells(tmp_path):
    workroot = stamped(tmp_path)
    plan = plan_mod.build_plan(
        tier="full",
        recipes={"sigil": recipe_mod.load(SIGIL)},
        workroot=workroot,
        run_dir=tmp_path / "run",
        packet_dir=HERE.parent / "arms",
        fanout_n=3,
        allow_missing=True,
    )
    variants = {(c["arm"], c["variant"]) for c in plan["cells"]}
    assert ("c-review", "control") in variants
    assert ("bare", "control") in variants


def _two_cell_plan(tmp_path: Path, second_variant: str = "bench", second_arm: str = "fanout"):
    """A run with two cells, so cross-cell rules have something to fire on."""
    run = scaffold(tmp_path)
    plan = json.loads((run / "plan.json").read_text(encoding="utf-8"))
    private = tmp_path / "work" / "sigil" / f"{second_variant}-private"
    if second_variant != "bench":
        ground_truth = json.loads((FIXTURES / "gt_demo.json").read_text(encoding="utf-8"))
        ground_truth["variant"] = second_variant
        write(private / "ground_truth.json", ground_truth)
    second = dict(plan["cells"][0])
    second.update(
        {
            "arm": second_arm,
            "variant": second_variant,
            "private": str(private),
            "tree": str(tmp_path / "work" / "sigil" / second_variant),
        }
    )
    plan["cells"].append(second)
    write(run / "plan.json", plan)
    return run


def _collect(run: Path, arm: str, result_name: str, meta: dict, variant: str = "bench"):
    meta_path = run / f"meta_{arm}_{variant}.json"
    write(meta_path, meta)
    return result_mod.collect(
        run_dir=run,
        arm=arm,
        corpus="sigil",
        result_path=FIXTURES / result_name,
        meta_path=meta_path,
        transcripts=[FIXTURES / "transcript_clean.jsonl"],
        variant=variant,
        settle_seconds=0.01,
        timeout=1,
    )


BASE_META = {"complete": True, "agents": 1, "tokens": 51234, "wall_seconds": 640, "model": "sonnet"}


# --------------------------------------------- regressions found by validation


def test_mixing_token_bases_across_cells_in_one_run_is_refused(tmp_path):
    """The README says this is refused; it was not. The same cell reads 92,478 tokens on
    one basis and 2,432,494 on another, and the run total summed one straight into the
    other."""
    run = _two_cell_plan(tmp_path)
    _collect(run, "bare", "result_perfect.json", {**BASE_META, "token_basis": "tokens_total"})
    _collect(
        run,
        "fanout",
        "result_perfect.json",
        {**BASE_META, "token_basis": "reported_subagent_tokens"},
    )
    with pytest.raises(report_mod.ReportError, match="different bases"):
        report_mod.score_run(run, workroot=tmp_path / "work")


def test_the_token_basis_is_named_in_the_report(tmp_path):
    """A TOKENS column with no basis beside it is not a measurement anyone can compare."""
    run = scaffold(tmp_path)
    _collect(run, "bare", "result_perfect.json", {**BASE_META, "token_basis": "tokens_fresh"})
    scored = report_mod.score_run(run, workroot=tmp_path / "work")
    assert scored["token_basis"] == "tokens_fresh"
    assert "`tokens_fresh` basis" in report_mod.format_report(scored)


def test_one_unscoreable_cell_does_not_destroy_the_whole_run(tmp_path):
    """A bench cell with zero findings is a run to investigate, and the guard that says so
    used to raise out of `score_run` — so nothing was written at all, not even for the cells
    that were fine. The arm is excluded by name instead."""
    run = _two_cell_plan(tmp_path)
    empty = run / "empty.json"
    write(empty, {"findings": []})
    meta_path = run / "meta_empty.json"
    write(meta_path, BASE_META)
    result_mod.collect(
        run_dir=run,
        arm="fanout",
        corpus="sigil",
        result_path=empty,
        meta_path=meta_path,
        transcripts=[FIXTURES / "transcript_clean.jsonl"],
        settle_seconds=0.01,
        timeout=1,
    )
    _collect(run, "bare", "result_perfect.json", BASE_META)
    scored = report_mod.score_run(run, workroot=tmp_path / "work")
    verdicts = {a["arm"]: a["verdict"] for a in scored["arms"]}
    assert verdicts == {"bare": "VALID", "fanout": report_mod.UNSCOREABLE}
    text = report_mod.format_report(scored)
    assert "RESULTS EXCLUDED" in text
    assert "3/3" in text  # the good cell still reports
    assert "zero findings" in text


def test_a_clean_control_cell_with_no_findings_scores(tmp_path):
    """Zero findings on the patched control is the one perfect result, and it used to make
    `score` refuse the entire run."""
    run = _two_cell_plan(tmp_path, second_variant="control", second_arm="bare")
    empty = run / "empty.json"
    write(empty, {"findings": []})
    meta_path = run / "meta_empty.json"
    write(meta_path, BASE_META)
    result_mod.collect(
        run_dir=run,
        arm="bare",
        corpus="sigil",
        result_path=empty,
        meta_path=meta_path,
        transcripts=[FIXTURES / "transcript_clean.jsonl"],
        variant="control",
        settle_seconds=0.01,
        timeout=1,
    )
    _collect(run, "bare", "result_perfect.json", BASE_META)
    scored = report_mod.score_run(run, workroot=tmp_path / "work")
    control = next(a for a in scored["arms"] if a["variant"] == "control")
    assert control["verdict"] == "VALID"
    assert control["grade"]["false_positives"]["CONTROL_FP"] == []


def test_scoring_the_same_run_twice_is_byte_identical(tmp_path):
    """The first question asked of this harness was whether the grader is stable, because
    two runs of one cell were scored 15/17 and 11/17. It is — the two result files differed
    — and this is what keeps that true. `run_dir` is the only input-dependent field, so a
    second pass over the same directory must produce the same bytes."""
    run = scaffold(tmp_path)
    _collect(run, "bare", "result_perfect.json", BASE_META)
    first = report_mod.score_run(run, workroot=tmp_path / "work")
    second = report_mod.score_run(run, workroot=tmp_path / "work")
    assert json.dumps(first, indent=2, sort_keys=True) == json.dumps(
        second, indent=2, sort_keys=True
    )
    assert report_mod.format_report(first) == report_mod.format_report(second)


def test_failed_hunter_groups_are_surfaced_in_the_report(tmp_path):
    """A c-review run that lost 13 of 16 hunters still produced findings and still scored,
    and nothing in the report said so."""
    run = scaffold(tmp_path)
    _collect(run, "bare", "result_perfect.json", BASE_META)
    collected = run / "collected" / "bare__sigil__bench.json"
    doc = json.loads(collected.read_text(encoding="utf-8"))
    doc["groups_attempted"] = ["a", "b", "c"]
    doc["groups_failed"] = ["b", "c"]
    write(collected, doc)
    text = report_mod.format_report(report_mod.score_run(run, workroot=tmp_path / "work"))
    assert "PARTIAL RUN: 2 of 3 hunter group(s) failed" in text
    assert "floor, not a" in text


def test_an_unfilled_placeholder_is_refused():
    with pytest.raises(plan_mod.PlanError, match="unfilled placeholder"):
        plan_mod._render("hello {{MISSING}}", {"OTHER": "x"})


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
