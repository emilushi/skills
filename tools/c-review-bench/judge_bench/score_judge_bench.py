#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Score a judge-benchmark run: did the judge keep the real bugs and reject the fakes?

The ground-truth grader answers "did the pipeline find the bug". This answers the
other question, which no run so far has been able to: "can the judge tell a real
finding from a plausible wrong one?" A judge that returns TRUE_POSITIVE for
everything scores full retention here and zero rejection, and those two numbers
together are the only way to distinguish a good judge with nothing to reject from
one that accepts whatever it is handed.

Findings are matched to bench items by `bench_id` when the workflow carried one
through, otherwise by (file, line, title). Ids are deliberately not used: injecting
seeded findings renumbers the ids the workflow assigns.

Usage:
    uv run score_judge_bench.py --judged run/findings.json
    uv run score_judge_bench.py --judged run/findings.json --run-meta meta.json \\
        --json score.json

`--run-meta` is optional JSON carrying `agents` and `subagent_tokens` for the run,
which the workflow does not write into findings.json. Without it the cost columns
say so rather than reporting zero.

Exit codes:
    0  scored
    2  scored nothing (no judged findings, no real items matched, or no seeded
       items matched) — a scorer that inspects nothing must not report success
    3  bad input
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "scripts"))

from findings_model import FindingsError, load  # noqa: E402

SURVIVOR_VERDICTS = frozenset({"TRUE_POSITIVE", "LIKELY_TP"})
REJECTING_VERDICTS = frozenset({"FALSE_POSITIVE", "LIKELY_FP", "OUT_OF_SCOPE"})

# What the workflow writes into fp_rationale when no judge reached a finding. This
# is the only reliable signal for it: `severity_validated` is also false when a
# judge did rule but left the severity unset, which is a judged finding.
UNJUDGED_MARKER = "JUDGE DID NOT RUN"

RETAINED = "RETAINED"
REJECTED = "REJECTED"
MERGED = "MERGED"
UNJUDGED = "UNJUDGED"
ABSENT = "ABSENT"

DEFAULT_BENCH = Path(__file__).resolve().parent / "judge_bench_input.json"


class BenchError(Exception):
    """Input the scorer cannot work with. Callers exit non-zero."""


def normalize_path(value: Any) -> str:
    text = str(value or "").replace("\\", "/").strip()
    while text.startswith("./"):
        text = text[2:]
    return text


def item_key(item: dict[str, Any]) -> tuple[str, int, str]:
    try:
        line = int(item.get("line", 0))
    except (TypeError, ValueError):
        line = 0
    title = " ".join(str(item.get("title", "")).split()).lower()
    return normalize_path(item.get("file")), line, title


def load_bench(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise BenchError(f"bench input not found: {path}")
    try:
        bench = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise BenchError(f"{path} is not valid JSON: {exc}") from exc
    items = bench.get("items")
    if not isinstance(items, list) or not items:
        raise BenchError(f"{path}: 'items' must be a non-empty list")

    keys: dict[tuple[str, int, str], str] = {}
    ids: set[str] = set()
    for item in items:
        if item.get("expected") not in {"retain", "reject"}:
            raise BenchError(f"{path}: every item needs expected 'retain' or 'reject'")
        bench_id = str(item.get("bench_id") or "")
        if not bench_id:
            raise BenchError(f"{path}: every item needs a bench_id")
        if bench_id in ids:
            raise BenchError(f"{path}: duplicate bench_id {bench_id}")
        ids.add(bench_id)
        key = item_key(item)
        if key in keys:
            raise BenchError(
                f"{path}: {bench_id} and {keys[key]} share (file, line, title) "
                f"{key}, so a judged finding cannot be attributed to either"
            )
        keys[key] = bench_id
        if item["expected"] == "reject" and not str(item.get("why_wrong") or "").strip():
            raise BenchError(f"{path}: seeded item {bench_id} has no why_wrong")
    return bench


def outcome_of(finding: dict[str, Any] | None) -> str:
    if finding is None:
        return ABSENT
    if finding.get("merged_into"):
        return MERGED
    if UNJUDGED_MARKER in str(finding.get("fp_rationale", "")):
        return UNJUDGED
    verdict = str(finding.get("fp_verdict", "")).upper()
    if verdict in SURVIVOR_VERDICTS:
        return RETAINED
    if verdict in REJECTING_VERDICTS:
        return REJECTED
    return UNJUDGED


def score(
    doc: dict[str, Any], bench: dict[str, Any], run_meta: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Score one judged run against the bench. Raises BenchError on a vacuous score."""
    findings = list(doc["findings"])
    if not findings:
        raise BenchError(
            "the judged run contains zero findings, so the scorer inspected nothing. That is a "
            "pipeline failure, not a 0% score."
        )

    by_bench_id: dict[str, dict[str, Any]] = {}
    by_key: dict[tuple[str, int, str], dict[str, Any]] = {}
    for finding in findings:
        bench_id = str(finding.get("bench_id") or "")
        if bench_id and bench_id not in by_bench_id:
            by_bench_id[bench_id] = finding
        key = item_key(finding)
        if key not in by_key:
            by_key[key] = finding

    matched_ids: set[int] = set()
    per_item = []
    for item in bench["items"]:
        found = by_bench_id.get(str(item.get("bench_id"))) or by_key.get(item_key(item))
        if found is not None:
            matched_ids.add(id(found))
        per_item.append(
            {
                "bench_id": item["bench_id"],
                "expected": item["expected"],
                "outcome": outcome_of(found),
                "fp_verdict": str((found or {}).get("fp_verdict", "")),
                "severity": str((found or {}).get("severity", "")),
                "fp_rationale": str((found or {}).get("fp_rationale", "")),
                "location": f"{item.get('file')}:{item.get('line')}",
                "title": str(item.get("title", "")),
                "why_wrong": str(item.get("why_wrong", "")),
            }
        )

    real = [r for r in per_item if r["expected"] == "retain"]
    seeded = [r for r in per_item if r["expected"] == "reject"]
    judged_real = [r for r in real if r["outcome"] in {RETAINED, REJECTED}]
    judged_seeded = [r for r in seeded if r["outcome"] in {RETAINED, REJECTED}]

    if not judged_real:
        raise BenchError(
            f"none of the {len(real)} real bench finding(s) reached a verdict in this run "
            f"(matched: {sum(1 for r in real if r['outcome'] != ABSENT)}), so retention is "
            f"undefined rather than 0%."
        )
    if not judged_seeded:
        raise BenchError(
            f"none of the {len(seeded)} seeded false positive(s) reached a verdict in this run "
            f"(matched: {sum(1 for r in seeded if r['outcome'] != ABSENT)}). Without them the "
            f"run measures nothing the ground-truth grader does not already measure — check "
            f"that injectFindings was actually passed."
        )

    retained = sum(1 for r in judged_real if r["outcome"] == RETAINED)
    rejected = sum(1 for r in judged_seeded if r["outcome"] == REJECTED)

    distribution: dict[str, int] = {}
    for finding in findings:
        if finding.get("merged_into"):
            continue
        key = str(finding.get("fp_verdict") or "(none)")
        distribution[key] = distribution.get(key, 0) + 1

    meta = run_meta or {}
    return {
        "bench": str(bench.get("corpus", "unknown")),
        "true_positive_retention": {
            "retained": retained,
            "judged": len(judged_real),
            "rate": retained / len(judged_real),
        },
        "false_positive_rejection": {
            "rejected": rejected,
            "judged": len(judged_seeded),
            "rate": rejected / len(judged_seeded),
        },
        "outcome_counts": {
            "real": _counts(real),
            "seeded": _counts(seeded),
        },
        "verdict_distribution": distribution,
        "run": {
            "agents": meta.get("agents"),
            "subagent_tokens": meta.get("subagent_tokens"),
            "judge_agents": doc.get("stats", {}).get("judge_agents"),
            "judge_mode": doc.get("run", {}).get("judge_mode"),
        },
        # Merged duplicates are excluded: the bench lists primaries, so in any real
        # bench run the hunters' duplicates would otherwise fill this list with
        # findings no judge ever saw.
        "unexpected_findings": sorted(
            f"{normalize_path(f.get('file'))}:{f.get('line')} {f.get('title', '')}"
            for f in findings
            if id(f) not in matched_ids and not f.get("merged_into")
        ),
        "per_item": per_item,
    }


def _counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    out: dict[str, int] = {}
    for row in rows:
        out[row["outcome"]] = out.get(row["outcome"], 0) + 1
    return out


def format_score(report: dict[str, Any]) -> str:
    tp = report["true_positive_retention"]
    fp = report["false_positive_rejection"]
    run = report["run"]
    missing = "not supplied (--run-meta)"
    agents = run["agents"] if run["agents"] is not None else missing
    tokens = run["subagent_tokens"] if run["subagent_tokens"] is not None else missing
    judge_agents = run["judge_agents"] if run["judge_agents"] is not None else "unrecorded"
    lines = [
        f"bench: {report['bench']}",
        "",
        f"{'BENCH ID':<14} {'EXPECTED':<9} {'OUTCOME':<9} {'VERDICT':<15} LOCATION",
        f"{'-' * 14} {'-' * 9} {'-' * 9} {'-' * 15} {'-' * 34}",
    ]
    for row in report["per_item"]:
        wrong = row["expected"] == "retain" and row["outcome"] == REJECTED
        wrong = wrong or (row["expected"] == "reject" and row["outcome"] == RETAINED)
        mark = "  <-- judge was wrong" if wrong else ""
        lines.append(
            f"{row['bench_id']:<14} {row['expected']:<9} {row['outcome']:<9} "
            f"{row['fp_verdict'] or '—':<15} {row['location']}{mark}"
        )
    lines += [
        "",
        f"true-positive retention:   {tp['retained']}/{tp['judged']} = {tp['rate']:.2%}",
        f"false-positive rejection:  {fp['rejected']}/{fp['judged']} = {fp['rate']:.2%}",
        "",
        "verdict distribution (primaries): "
        + ", ".join(f"{k}={v}" for k, v in sorted(report["verdict_distribution"].items())),
        f"outcomes real:   {report['outcome_counts']['real']}",
        f"outcomes seeded: {report['outcome_counts']['seeded']}",
        "",
        f"judge mode: {run['judge_mode'] or 'unrecorded'}   judge agents: {judge_agents}",
        f"run agents: {agents}   subagent tokens: {tokens}",
    ]
    if report["unexpected_findings"]:
        lines += [
            "",
            f"{len(report['unexpected_findings'])} judged finding(s) matched no bench item "
            f"(hunters found something the bench does not list):",
        ]
        lines += [f"  {entry}" for entry in report["unexpected_findings"][:10]]
    fooled = [
        r for r in report["per_item"] if r["expected"] == "reject" and r["outcome"] == RETAINED
    ]
    if fooled:
        lines += ["", "The judge accepted these seeded false positives. Why each is wrong:"]
        for row in fooled:
            lines += [f"  {row['bench_id']}: {row['why_wrong']}"]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Score a c-review judge benchmark run")
    parser.add_argument("--judged", required=True, help="findings.json from the benchmark run")
    parser.add_argument("--bench", type=Path, default=DEFAULT_BENCH)
    parser.add_argument(
        "--run-meta", type=Path, default=None, help="JSON with agents/subagent_tokens"
    )
    parser.add_argument("--json", type=Path, default=None, help="also write the full report here")
    parsed = parser.parse_args(argv)

    try:
        doc = load(parsed.judged)
        bench = load_bench(parsed.bench)
        meta = None
        if parsed.run_meta:
            if not parsed.run_meta.is_file():
                raise BenchError(f"run meta not found: {parsed.run_meta}")
            meta = json.loads(parsed.run_meta.read_text(encoding="utf-8"))
    except (FindingsError, BenchError, json.JSONDecodeError) as exc:
        print(f"score_judge_bench: {exc}", file=sys.stderr)
        return 3

    try:
        report = score(doc, bench, meta)
    except BenchError as exc:
        print(f"score_judge_bench: {exc}", file=sys.stderr)
        return 2

    print(format_score(report))
    if parsed.json:
        parsed.json.parent.mkdir(parents=True, exist_ok=True)
        parsed.json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"\nwrote {parsed.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
