#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Grade a c-review run against a ground-truth CVE corpus.

Grading rule (from the c-review evaluation):

    A finding is a HIT when it names the correct file, places itself at the
    correct site — a matching function name, or a line within +/- `line_window`
    of an anchor — and its text identifies the actual defect mechanism.

`functions` is the primary site key. The line window is the fallback for a
reviewer that reports a macro or a file-level location instead of an enclosing
function. Mechanism matching is deterministic: every group in `mechanism_all_of`
must contribute at least one substring to the finding's text.

A candidate that matches the site but not the mechanism is reported as NEAR_MISS
rather than folded into either bucket, so a keyword list that has gone stale is
visible instead of quietly deflating recall.

A ground-truth bug matched by a finding the pipeline did NOT report — because a
judge rejected it, or dedup buried it — is SUPPRESSED, not MISS. That distinction
is the whole point of grading the artifact rather than the transcript.

Usage:
    uv run grade.py --findings run/findings.json \\
        --ground-truth ground_truth/libexpat-R_2_4_3.json

Exit codes:
    0  graded
    2  graded nothing (no ground-truth items, or no findings in scope)
    3  bad input
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from findings_model import FindingsError, load, primaries, reported_findings  # noqa: E402

TEXT_FIELDS = (
    "title",
    "description",
    "impact",
    "code",
    "data_flow",
    "reachability",
    "recommendation",
    "bug_class",
    "function",
    "severity_rationale",
    "fp_rationale",
)

HIT = "HIT"
SUPPRESSED = "SUPPRESSED"
NEAR_MISS = "NEAR_MISS"
MISS = "MISS"


class GradeError(Exception):
    """Input the grader cannot work with. Callers exit non-zero."""


def normalize_path(value: Any) -> str:
    text = str(value or "").replace("\\", "/").strip()
    while text.startswith("./"):
        text = text[2:]
    return text


def normalize_function(value: Any) -> str:
    return "".join(ch for ch in str(value or "").lower() if ch.isalnum() or ch == "_")


def file_matches(finding_file: str, gt_file: str) -> bool:
    """Suffix match, anchored on a path segment.

    The pipeline emits paths relative to the repo root, the corpus records them
    the same way, but a reviewer scoped to a subdirectory may emit a shorter
    path. Anchoring on '/' stops 'lib/parse.c' matching 'otherlib/parse.c'.
    """
    a, b = normalize_path(finding_file), normalize_path(gt_file)
    if not a or not b:
        return False
    return a == b or a.endswith("/" + b) or b.endswith("/" + a)


def site_matches(finding: dict[str, Any], item: dict[str, Any], window: int) -> tuple[bool, str]:
    fn = normalize_function(finding.get("function"))
    wanted = {normalize_function(f) for f in item.get("functions", [])}
    if fn and fn in wanted:
        return True, f"function {finding.get('function')}"
    try:
        line = int(finding.get("line", 0))
    except (TypeError, ValueError):
        line = 0
    for anchor in item.get("lines", []):
        if line and abs(line - int(anchor)) <= window:
            return True, f"line {line} within {window} of anchor {anchor}"
    return False, ""


def finding_text(finding: dict[str, Any]) -> str:
    return " ".join(str(finding.get(field, "")) for field in TEXT_FIELDS).lower()


def mechanism_matches(finding: dict[str, Any], item: dict[str, Any]) -> tuple[bool, list[str]]:
    text = finding_text(finding)
    missing = []
    for group in item.get("mechanism_all_of", []):
        if not any(term.lower() in text for term in group):
            missing.append("/".join(group[:3]) + ("/..." if len(group) > 3 else ""))
    return (not missing), missing


def load_ground_truth(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise GradeError(f"ground truth not found: {path}")
    try:
        gt = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise GradeError(f"{path} is not valid JSON: {exc}") from exc
    items = gt.get("items")
    if not isinstance(items, list):
        raise GradeError(f"{path}: 'items' must be a list")
    for item in items:
        if not item.get("cve") or not item.get("file"):
            raise GradeError(f"{path}: every item needs at least 'cve' and 'file'")
        if not item.get("functions") and not item.get("lines"):
            raise GradeError(f"{path}: item {item.get('cve')} has neither 'functions' nor 'lines'")
        if not item.get("mechanism_all_of"):
            raise GradeError(f"{path}: item {item.get('cve')} has no 'mechanism_all_of' groups")
    return gt


def select(doc: dict[str, Any], scope: str) -> list[dict[str, Any]]:
    if scope == "reported":
        return reported_findings(doc)
    if scope == "primaries":
        return primaries(doc)
    return list(doc["findings"])


def grade(doc: dict[str, Any], gt: dict[str, Any], scope: str = "reported") -> dict[str, Any]:
    """Grade one run. Raises GradeError when there is nothing to grade.

    An empty ground truth or an empty finding set means this function inspected
    nothing, and a grader that inspects nothing must not report success — a
    silently-vacuous checker is indistinguishable from a passing one.
    """
    items = gt.get("items", [])
    if not items:
        raise GradeError("ground truth contains zero items — nothing to grade against")

    scoped = select(doc, scope)
    everything = list(doc["findings"])
    if not everything:
        raise GradeError(
            "the run contains zero findings, so the grader inspected nothing. That is a "
            "pipeline failure, not a 0/N result — investigate the run before recording a score."
        )
    if not scoped:
        raise GradeError(
            f"the run has {len(everything)} finding(s) but none in scope '{scope}', so the "
            f"grader inspected nothing. Re-grade with --scope all to see what was rejected."
        )

    window = int(gt.get("grading", {}).get("line_window", 10))
    scoped_ids = {str(f.get("id")) for f in scoped}
    results = []
    matched_ids: set[str] = set()

    for item in items:
        candidates = []
        for finding in everything:
            if not file_matches(finding.get("file"), item["file"]):
                continue
            at_site, why = site_matches(finding, item, window)
            if not at_site:
                continue
            ok, missing = mechanism_matches(finding, item)
            candidates.append(
                {
                    "id": str(finding.get("id", "?")),
                    "in_scope": str(finding.get("id")) in scoped_ids,
                    "mechanism_ok": ok,
                    "missing_mechanism_groups": missing,
                    "site": why,
                    "title": str(finding.get("title", "")),
                    "fp_verdict": str(finding.get("fp_verdict", "")),
                    "severity": str(finding.get("severity", "")),
                }
            )

        hits = [c for c in candidates if c["mechanism_ok"] and c["in_scope"]]
        suppressed = [c for c in candidates if c["mechanism_ok"] and not c["in_scope"]]
        near = [c for c in candidates if not c["mechanism_ok"]]

        if hits:
            outcome, evidence = HIT, hits[0]
        elif suppressed:
            outcome, evidence = SUPPRESSED, suppressed[0]
        elif near:
            outcome, evidence = NEAR_MISS, near[0]
        else:
            outcome, evidence = MISS, None

        if evidence:
            matched_ids.add(evidence["id"])
        results.append(
            {
                "cve": item["cve"],
                "tier": item.get("tier", ""),
                "file": item["file"],
                "outcome": outcome,
                "evidence": evidence,
                "candidates": candidates,
            }
        )

    hit_count = sum(1 for r in results if r["outcome"] == HIT)
    return {
        "corpus": gt.get("id", "unknown"),
        "scope": scope,
        "graded_items": len(items),
        "graded_findings": len(scoped),
        "total_findings": len(everything),
        "hits": hit_count,
        "recall": hit_count / len(items),
        "suppressed": sum(1 for r in results if r["outcome"] == SUPPRESSED),
        "near_misses": sum(1 for r in results if r["outcome"] == NEAR_MISS),
        "misses": sum(1 for r in results if r["outcome"] == MISS),
        "extra_findings": sorted(
            str(f.get("id")) for f in scoped if str(f.get("id")) not in matched_ids
        ),
        "results": results,
    }


def format_report(report: dict[str, Any]) -> str:
    lines = [
        f"corpus: {report['corpus']}   scope: {report['scope']}",
        f"graded {report['graded_findings']} finding(s) of {report['total_findings']} "
        f"against {report['graded_items']} ground-truth bug(s)",
        "",
        f"{'CVE':<20} {'TIER':<7} {'OUTCOME':<11} EVIDENCE",
        f"{'-' * 20} {'-' * 7} {'-' * 11} {'-' * 40}",
    ]
    for r in report["results"]:
        ev = r["evidence"]
        if ev and r["outcome"] == NEAR_MISS:
            missing = ", ".join(ev["missing_mechanism_groups"])
            detail = f"{ev['id']} at {ev['site']}; mechanism missing: {missing}"
        elif ev and r["outcome"] == SUPPRESSED:
            detail = f"{ev['id']} found but not reported ({ev['fp_verdict'] or 'no verdict'})"
        elif ev:
            detail = f"{ev['id']} [{ev['severity'] or '—'}] {ev['site']}"
        else:
            detail = "—"
        lines.append(f"{r['cve']:<20} {r['tier']:<7} {r['outcome']:<11} {detail}")
    lines += [
        "",
        f"recall: {report['hits']}/{report['graded_items']} = {report['recall']:.2%}",
        f"suppressed: {report['suppressed']}   near-miss: {report['near_misses']}   "
        f"miss: {report['misses']}",
        f"findings not matching any ground-truth bug: {len(report['extra_findings'])}",
    ]
    if report["suppressed"]:
        lines.append(
            "NOTE: a SUPPRESSED row means a reviewer found the bug and the pipeline dropped it. "
            "Read the verdict before tuning anything else."
        )
    if report["near_misses"]:
        lines.append(
            "NOTE: a NEAR_MISS row matched the site but not the mechanism keywords. Either the "
            "finding describes a different bug at that line, or the keyword list needs updating."
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Grade a c-review run against ground truth")
    parser.add_argument("--findings", required=True, help="findings.json from a c-review run")
    parser.add_argument("--ground-truth", required=True, type=Path)
    parser.add_argument(
        "--scope",
        choices=["reported", "primaries", "all"],
        default="reported",
        help="which findings count as found; default 'reported' is what a user actually sees",
    )
    parser.add_argument("--json", type=Path, default=None, help="also write the full report here")
    parsed = parser.parse_args(argv)

    try:
        doc = load(parsed.findings)
        gt = load_ground_truth(parsed.ground_truth)
    except (FindingsError, GradeError) as exc:
        print(f"grade: {exc}", file=sys.stderr)
        return 3

    try:
        report = grade(doc, gt, parsed.scope)
    except GradeError as exc:
        print(f"grade: {exc}", file=sys.stderr)
        return 2

    print(format_report(report))
    if parsed.json:
        parsed.json.parent.mkdir(parents=True, exist_ok=True)
        parsed.json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"\nwrote {parsed.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
