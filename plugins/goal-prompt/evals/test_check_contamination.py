"""The contamination checker must catch a leaky baseline and must fail on
empty input — a checker that inspects zero runs must not pass."""

from __future__ import annotations

import json

from check_contamination import find_contamination, main


def _result(without_evidence: str) -> dict:
    return {
        "cases": [
            {
                "name": "c",
                "arms": {
                    "with": [{"graders": [{"evidence": "anything"}]}],
                    "without": [{"graders": [{"evidence": without_evidence}]}],
                },
            }
        ]
    }


def test_detects_skill_phrase_in_baseline() -> None:
    hits = find_contamination(_result("a goal terminates on the wrong contract"))
    assert hits and "terminates on the wrong contract" in hits[0]


def test_detects_plugin_path_in_baseline() -> None:
    hits = find_contamination(_result("read /repo/plugins/goal-prompt/skills/x"))
    assert hits and "plugins/goal-prompt" in hits[0]


def test_clean_baseline_passes(tmp_path, capsys) -> None:
    p = tmp_path / "r.json"
    p.write_text(json.dumps(_result("/goal do the thing, or stop after 20 turns")))
    assert main(["check", str(p)]) == 0
    assert "1 baseline run(s) clean" in capsys.readouterr().out


def test_with_arm_markers_do_not_flag() -> None:
    result = _result("clean text")
    result["cases"][0]["arms"]["with"][0]["graders"][0]["evidence"] = (
        "ran format_goal_prompt.py from plugins/goal-prompt"
    )
    assert find_contamination(result) == []


def test_no_baseline_runs_fails(tmp_path, capsys) -> None:
    p = tmp_path / "r.json"
    p.write_text(json.dumps({"cases": [{"name": "c", "arms": {"with": []}}]}))
    assert main(["check", str(p)]) == 1
    assert "no baseline runs" in capsys.readouterr().err


def test_empty_evidence_fails(tmp_path, capsys) -> None:
    p = tmp_path / "r.json"
    p.write_text(json.dumps(_result("  ")))
    assert main(["check", str(p)]) == 1
    assert "no response text" in capsys.readouterr().err


def test_contaminated_result_exits_nonzero(tmp_path, capsys) -> None:
    p = tmp_path / "r.json"
    p.write_text(json.dumps(_result("I found scope to read first in SKILL.md")))
    assert main(["check", str(p)]) == 1
    assert "read the plugin under test" in capsys.readouterr().err
