"""Regression tests for merge_sarif.py.

The bug these exist to catch: a scan in which every scanner produced garbage yields
zero findings, and so does a genuinely clean codebase. Merging on and exiting 0 reports
the first as the second. `results.sarif` is valid JSON either way, so the skill's own
"is it valid JSON" check cannot tell them apart — only the exit code can.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from merge_sarif import is_parseable, main, merge_sarif_pure_python

SCRIPT = Path(__file__).with_name("merge_sarif.py")


def _sarif(*results: dict, tool: str = "semgrep") -> dict:
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {"driver": {"name": tool, "rules": [{"id": "rule.a"}]}},
                "results": list(results),
            }
        ],
    }


def _result(rule: str = "rule.a", uri: str = "src/app.py", line: int = 10) -> dict:
    return {
        "ruleId": rule,
        "level": "error",
        "message": {"text": f"{rule} at {uri}:{line}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": line},
                }
            }
        ],
    }


def _write(directory: Path, name: str, payload: dict | str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text(payload if isinstance(payload, str) else json.dumps(payload), encoding="utf-8")
    return path


def _run(raw_dir: Path, out: Path) -> int:
    """Invoke main() the way the skill's Step 5 does."""
    argv = [str(SCRIPT), str(raw_dir), str(out)]
    original, sys.argv = sys.argv, argv
    try:
        return main()
    finally:
        sys.argv = original


# --- the silent-pass guard -------------------------------------------------------


def test_all_inputs_corrupt_exits_nonzero(tmp_path: Path) -> None:
    """Every input unparseable must fail, not report a clean scan."""
    raw = tmp_path / "raw"
    _write(raw, "python.sarif", "{ this is not json")
    _write(raw, "go.sarif", "<html>504 Gateway Timeout</html>")

    out = tmp_path / "results" / "results.sarif"
    assert _run(raw, out) != 0, (
        "all-corrupt input exited 0 — a failed scan is being reported as a clean one"
    )


def test_all_inputs_corrupt_writes_no_output(tmp_path: Path) -> None:
    """A downstream reader must not find an empty results.sarif to trust."""
    raw = tmp_path / "raw"
    _write(raw, "python.sarif", "not json")

    out = tmp_path / "results" / "results.sarif"
    _run(raw, out)
    assert not out.exists(), "wrote an empty results.sarif for a wholly failed scan"


def test_empty_directory_exits_nonzero(tmp_path: Path) -> None:
    raw = tmp_path / "raw"
    raw.mkdir()
    assert _run(raw, tmp_path / "out.sarif") != 0


def test_partial_corruption_keeps_good_findings(tmp_path: Path) -> None:
    """One bad file must not discard the findings from the good ones."""
    raw = tmp_path / "raw"
    _write(raw, "good.sarif", _sarif(_result()))
    _write(raw, "bad.sarif", "truncated{")

    out = tmp_path / "results.sarif"
    assert _run(raw, out) == 0
    merged = json.loads(out.read_text())
    assert sum(len(r["results"]) for r in merged["runs"]) == 1


def test_clean_scan_still_succeeds(tmp_path: Path) -> None:
    """Zero findings from parseable input is a legitimate result, not a failure.

    This is the other half of the guard: if it ever fails, someone has "fixed" the
    silent pass by rejecting empty results, which breaks every clean codebase.
    """
    raw = tmp_path / "raw"
    _write(raw, "python.sarif", _sarif())

    out = tmp_path / "results.sarif"
    assert _run(raw, out) == 0
    assert json.loads(out.read_text())["version"] == "2.1.0"


# --- merge semantics -------------------------------------------------------------


def test_identical_findings_across_rulesets_dedupe(tmp_path: Path) -> None:
    """Two rulesets flagging the same line collapse to one finding."""
    merged = merge_sarif_pure_python(
        [
            _write(tmp_path, "a.sarif", _sarif(_result())),
            _write(tmp_path, "b.sarif", _sarif(_result())),
        ]
    )
    assert sum(len(r["results"]) for r in merged["runs"]) == 1


def test_same_basename_different_directories_both_kept(tmp_path: Path) -> None:
    """Dedup keys on the full path, not the basename.

    src/a/util.py:10 and src/b/util.py:10 are distinct findings. A fingerprint that
    hashes only the filename — as sarif_helpers.compute_fingerprint does, correctly,
    for its own cross-environment use case — would silently drop one of them here.
    """
    merged = merge_sarif_pure_python(
        [
            _write(tmp_path, "a.sarif", _sarif(_result(uri="src/a/util.py"))),
            _write(tmp_path, "b.sarif", _sarif(_result(uri="src/b/util.py"))),
        ]
    )
    assert sum(len(r["results"]) for r in merged["runs"]) == 2


def test_distinct_findings_all_survive(tmp_path: Path) -> None:
    """A merge that silently drops everything must not pass."""
    merged = merge_sarif_pure_python(
        [
            _write(tmp_path, "a.sarif", _sarif(_result(rule="rule.a", line=1))),
            _write(tmp_path, "b.sarif", _sarif(_result(rule="rule.b", line=2))),
            _write(tmp_path, "c.sarif", _sarif(_result(rule="rule.c", line=3))),
        ]
    )
    total = sum(len(r["results"]) for r in merged["runs"])
    assert total == 3, f"expected 3 findings, merge produced {total}"


def test_rules_from_every_input_are_preserved(tmp_path: Path) -> None:
    """SARIF consumers resolve ruleId against driver.rules; dropping them breaks that."""
    a = _sarif(_result(rule="rule.a"))
    b = _sarif(_result(rule="rule.b", line=99))
    b["runs"][0]["tool"]["driver"]["rules"] = [{"id": "rule.b"}]

    merged = merge_sarif_pure_python(
        [_write(tmp_path, "a.sarif", a), _write(tmp_path, "b.sarif", b)]
    )
    ids = {r["id"] for r in merged["runs"][0]["tool"]["driver"]["rules"]}
    assert ids == {"rule.a", "rule.b"}


# --- helper -----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        ('{"runs": []}', True),
        ("{ broken", False),
        ("", False),
        ("<html>502</html>", False),
    ],
)
def test_is_parseable(tmp_path: Path, payload: str, expected: bool) -> None:
    assert is_parseable(_write(tmp_path, "x.sarif", payload)) is expected


def test_is_parseable_on_missing_file(tmp_path: Path) -> None:
    assert is_parseable(tmp_path / "absent.sarif") is False


# --- invoked as the skill actually invokes it -------------------------------------


def test_cli_exit_code_on_all_corrupt(tmp_path: Path) -> None:
    """The skill runs this via `uv run`, so the real process exit code is what matters."""
    raw = tmp_path / "raw"
    _write(raw, "python.sarif", "not json at all")

    proc = subprocess.run(
        [sys.executable, str(SCRIPT), str(raw), str(tmp_path / "out.sarif")],
        capture_output=True,
        text=True,
    )
    assert proc.returncode != 0
    assert "scan failure" in proc.stderr
