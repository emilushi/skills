#!/usr/bin/env python3
"""Tests for the oracle detector.

The load-bearing one is `test_tool_definitions_and_prose_are_not_use`. The string
`WebFetch` appears in nearly every transcript twice over — once in the list of tools
offered to the model, once in the packet text telling it not to use them — so a
substring scan flags every arm including the honest ones, and a check that always
fires gets disabled. This asserts the scanner separates a definition from an
invocation, and `test_a_real_invocation_is_a_violation` asserts it still catches the
real thing.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from lib import anticheat  # noqa: E402

FIXTURES = HERE / "fixtures"


def scan(name):
    return anticheat.scan_transcripts([FIXTURES / name])


# ------------------------------------------------- definitions versus invocations


def test_tool_definitions_and_prose_are_not_use():
    result = scan("transcript_clean.jsonl")
    assert result["violations"] == []
    assert result["tool_definitions_seen"] == 7
    assert result["invocations_seen"] == 3
    assert anticheat.assess(result)["verdict"] == "VALID"


def test_a_real_invocation_is_a_violation():
    result = anticheat.assess(scan("transcript_cheating.jsonl"))
    reasons = [v["why"] for v in result["violations"]]
    assert result["verdict"] == "INVALID"
    assert any("oracle tool `WebFetch`" in r for r in reasons)
    assert any("network binary `curl`" in r for r in reasons)
    assert any("git clone" in r for r in reasons)
    assert any("answer key" in r for r in reasons)


def test_a_transcript_with_only_definitions_is_refused_not_cleared():
    # The zero-inspection guard. "No invocations found" from a file the scanner did
    # not understand must not read as "the arm behaved".
    with pytest.raises(anticheat.AntiCheatError, match="zero tool invocations"):
        scan("transcript_definitions_only.jsonl")


def test_no_transcripts_at_all_is_refused(tmp_path):
    with pytest.raises(anticheat.AntiCheatError, match="no transcripts found"):
        anticheat.scan_transcripts([tmp_path / "nothing.jsonl"])


def test_unparseable_transcript_is_refused(tmp_path):
    path = tmp_path / "broken.jsonl"
    path.write_text("not json\nalso not json\n", encoding="utf-8")
    with pytest.raises(anticheat.AntiCheatError, match="parsed zero JSON records"):
        anticheat.scan_transcripts([path])


# -------------------------------------------------------- command-line precision


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("grep -rn curl src/", []),
        ("cat wget-notes.txt", []),
        ("ls curl", []),
        ("cc -c src/a.c", []),
        ("curl https://example.org", ["violation"]),
        ("sudo curl https://example.org", ["violation"]),
        ("FOO=1 wget https://example.org", ["violation"]),
        ("cc -c a.c && curl https://example.org", ["violation"]),
        ("echo hi | nc host 80", ["violation"]),
        ("git clone https://github.com/x/y", ["violation"]),
        ("gh pr diff 123", ["violation"]),
        ("pip download requests", ["violation"]),
        ("git log --oneline", ["advisory"]),
        ("git status", []),
    ],
)
def test_bash_classification_matches_on_command_position(command, expected):
    assert [severity for severity, _ in anticheat._classify_bash(command)] == expected


def test_a_git_history_read_is_advisory_not_disqualifying():
    result = anticheat.assess(scan("transcript_git_history.jsonl"))
    assert result["verdict"] == "VALID"
    assert [a["why"] for a in result["advisories"]] == [
        "ran `git log`; the corpus tree has no history of its own"
    ]


@pytest.mark.parametrize(
    "payload",
    [
        # The regression: on macOS the corpus itself lives under /private/tmp, and the
        # first real arm run was scored INVALID for reading the code it was given.
        {"file_path": "/private/tmp/claude-501/scratch/work/sigil/bench/src/field.c"},
        {"command": "cd /private/tmp/x/work/sigil/bench && wc -l src/*.c tests/smoke.c"},
        {"file_path": "/private/var/folders/t/work/sigil/bench/tests/smoke.c"},
        {"command": "grep -rn memcpy /tmp/corpus/bench/tests/"},
    ],
)
def test_reading_the_corpus_is_not_an_answer_key_access(payload):
    assert anticheat._classify_tool("Read", json.dumps(payload)) == []


@pytest.mark.parametrize(
    "payload",
    [
        {"file_path": "/w/sigil/bench-private/ground_truth.json"},
        {"file_path": "/w/sigil/control-private/maps.json"},
        {"command": "cat /w/sigil/bench-private/staged/src/field.c"},
        {"file_path": "/repo/plugins/c-review/bench/corpora/sigil/recipe.json"},
        {"command": "sed -n 1,50p /repo/plugins/c-review/bench/lib/grade.py"},
        {"file_path": "/repo/C-REVIEW-EVALUATION.md"},
    ],
)
def test_reading_the_answer_key_is_still_caught(payload):
    hits = anticheat._classify_tool("Read", json.dumps(payload))
    assert [severity for severity, _ in hits] == ["violation"], payload


def test_an_oracle_hostname_in_a_read_is_advisory():
    result = anticheat._classify_tool(
        "Read", json.dumps({"file_path": "notes-from-github.com.txt"})
    )
    assert [severity for severity, _ in result] == ["advisory"]


def test_mcp_search_tools_count_as_oracles():
    result = anticheat._classify_tool(
        "mcp__exa__web_search_exa", json.dumps({"query": "expat cve"})
    )
    assert [severity for severity, _ in result] == ["violation"]


# ------------------------------------------------------------------ declarations


def test_a_self_declared_external_source_invalidates_the_arm():
    result = anticheat.assess(
        scan("transcript_clean.jsonl"),
        {
            "external_sources_consulted": True,
            "external_sources_detail": "read the upstream changelog",
        },
    )
    assert result["verdict"] == "INVALID"
    assert "declared" in result["violations"][0]["why"]


def test_cve_mentions_in_prose_are_surfaced():
    result = anticheat.assess(scan("transcript_cheating.jsonl"))
    text = anticheat.format_assessment(result)
    assert "INVALID" in text
    assert "tool definition(s) seen and not counted as use" in text


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
