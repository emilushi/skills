"""Grade one arm's findings against a corpus's private ground truth.

The grading rule is inherited from the measured evaluation and unchanged, because
it is the part that survived scrutiny: a finding is a **HIT** when it names the
right file, places itself at the right site (matching function name, or a line
within the window of the recorded site), and its text identifies the actual defect
mechanism. Site proximity alone is not a hit — "there is something wrong around
here" is not a finding.

Four outcomes, not two:

- `HIT` — found and reported to the user.
- `SUPPRESSED` — some reviewer found it and the pipeline dropped it (a judge
  rejected it, dedup buried it, a severity filter ate it). That needs a different
  fix from a miss, and conflating the two is how a recall regression gets
  misdiagnosed as a discovery problem.
- `NEAR_MISS` — right site, mechanism keywords did not match. Read it: either the
  finding describes something else at that line, or the keyword list is stale.
- `MISS` — nothing at that site.

False positives are counted in three buckets, deliberately not one:

- `DECOY_FP` — the finding is at an injected decoy, which is a no-op mutation with
  a recorded safety argument. As close to a certain false positive as this harness
  can get on the bench tree.
- `CONTROL_FP` — on the patched-control corpus, a finding that claims one of the
  injected bugs at the site where that bug *is not present*. Certain by
  construction.
- `UNMATCHED` — everything else. **Not** reported as a false positive: the base code
  may contain real bugs we did not inject, and calling those FPs would punish an arm
  for being right. They are counted and listed for a human.

Every entry point raises rather than returning a zero-denominator score. A recall of
`0/0`, a false-positive rate over no findings, and a breakdown of an empty arm list
are all the same defect: a checker that inspected nothing reporting success.
"""

from __future__ import annotations

import re
from typing import Any

from .recipe import DECOY_CLAIM_TERMS

HIT = "HIT"
SUPPRESSED = "SUPPRESSED"
NEAR_MISS = "NEAR_MISS"
MISS = "MISS"

DECOY_FP = "DECOY_FP"
CONTROL_FP = "CONTROL_FP"
UNMATCHED = "UNMATCHED"
KNOWN_EXTRA = "KNOWN_EXTRA"

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
    "mitigations_checked",
    "severity_rationale",
    "fp_rationale",
)

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{3,7}\b", re.IGNORECASE)
DEFAULT_WINDOW = 12


class GradeError(Exception):
    """Nothing to grade, or nothing to grade against. Callers exit non-zero."""


def normalise_path(value: Any) -> str:
    text = str(value or "").replace("\\", "/").strip()
    while text.startswith("./"):
        text = text[2:]
    return text


def normalise_function(value: Any) -> str:
    return "".join(ch for ch in str(value or "").lower() if ch.isalnum() or ch == "_")


def file_matches(found: Any, wanted: Any) -> bool:
    """Suffix match anchored on a path segment, so `lib/x.c` never matches `other/x.c`."""
    a, b = normalise_path(found), normalise_path(wanted)
    if not a or not b:
        return False
    return a == b or a.endswith("/" + b) or b.endswith("/" + a)


def finding_text_raw(finding: dict[str, Any]) -> str:
    return " ".join(str(finding.get(field, "")) for field in TEXT_FIELDS)


def finding_text(finding: dict[str, Any]) -> str:
    return finding_text_raw(finding).lower()


def site_matches(finding: dict[str, Any], item: dict[str, Any], window: int) -> tuple[bool, str]:
    function = normalise_function(finding.get("function"))
    wanted = normalise_function(item.get("function"))
    if function and wanted and function == wanted:
        return True, f"function {finding.get('function')}"
    try:
        line = int(finding.get("line", 0))
    except (TypeError, ValueError):
        line = 0
    anchor = int(item.get("line", 0))
    if line and anchor and abs(line - anchor) <= window:
        return True, f"line {line} within {window} of {anchor}"
    return False, ""


def mechanism_matches(finding: dict[str, Any], item: dict[str, Any]) -> tuple[bool, list[str]]:
    text = finding_text(finding)
    missing = [
        "/".join(group[:3]) + ("/..." if len(group) > 3 else "")
        for group in item["mechanism_all_of"]
        if not any(term.lower() in text for term in group)
    ]
    return (not missing), missing


def _reported(finding: dict[str, Any]) -> bool:
    return bool(finding.get("reported", True))


def grade(
    result: dict[str, Any],
    ground_truth: dict[str, Any],
    window: int = DEFAULT_WINDOW,
) -> dict[str, Any]:
    """Grade one normalised arm result against one corpus manifest."""
    items = ground_truth.get("items") or []
    findings = result.get("findings") or []
    if not items:
        raise GradeError(
            "the ground truth holds zero items, so grading would compare against nothing and "
            "report every arm as 0/0"
        )
    if not findings:
        raise GradeError(
            f"arm {result.get('arm')!r} on corpus {result.get('corpus')!r} produced zero findings. "
            f"That is a run to investigate, not a recall of 0/{len(items)} — a scorer that "
            f"inspected nothing must not report a score."
        )

    variant = result.get("variant", ground_truth.get("variant", "bench"))
    present = variant != "control"

    matched: set[str] = set()
    rows: list[dict[str, Any]] = []
    for item in items:
        candidates = []
        for finding in findings:
            if not file_matches(finding.get("file"), item["file"]):
                continue
            at_site, why = site_matches(finding, item, window)
            if not at_site:
                continue
            ok, missing = mechanism_matches(finding, item)
            candidates.append(
                {
                    "id": str(finding.get("id", "?")),
                    "reported": _reported(finding),
                    "mechanism_ok": ok,
                    "missing_mechanism_groups": missing,
                    "site": why,
                    "title": str(finding.get("title", "")),
                    "severity": str(finding.get("severity", "")),
                    "fp_verdict": str(finding.get("fp_verdict", "")),
                    "found_by": str(finding.get("found_by", "")),
                }
            )
        hits = [c for c in candidates if c["mechanism_ok"] and c["reported"]]
        suppressed = [c for c in candidates if c["mechanism_ok"] and not c["reported"]]
        near = [c for c in candidates if not c["mechanism_ok"]]
        if hits:
            outcome, evidence = HIT, hits[0]
        elif suppressed:
            outcome, evidence = SUPPRESSED, suppressed[0]
        elif near:
            outcome, evidence = NEAR_MISS, near[0]
        else:
            outcome, evidence = MISS, None
        # Every finding that describes this bug correctly is attributed to it, not only
        # the one that took the HIT slot: an arm that files the same bug twice was not
        # producing a false positive the second time. A NEAR_MISS is deliberately *not*
        # attributed — it is at the right site describing something else, so it stays
        # eligible to be a decoy hit or an unmatched finding.
        matched.update(c["id"] for c in candidates if c["mechanism_ok"])
        rows.append(
            {
                "id": item["id"],
                "bug_class": item["bug_class"],
                "difficulty": item["difficulty"],
                "file": item["file"],
                "function": item["function"],
                "line": item["line"],
                "outcome": outcome,
                "evidence": evidence,
                "candidate_count": len(candidates),
            }
        )

    known = ground_truth.get("known_extra_findings") or []

    def known_extra_for(finding: dict[str, Any]) -> dict[str, Any] | None:
        """A documented weakness of the corpus itself, at that exact function.

        Resolved before the decoy scan, deliberately. A recorded weakness beats the
        coincidence of a decoy living in the same function: the first real run reported
        a genuine key disclosure and was charged for a `widened-type` decoy it never
        mentioned.
        """
        for extra in known:
            if file_matches(finding.get("file"), extra["file"]) and normalise_function(
                finding.get("function")
            ) == normalise_function(extra["function"]):
                return extra
        return None

    decoys = ground_truth.get("decoys") or []
    decoy_hits = []
    for finding in findings:
        # A finding that already matched an injected bug is correct, whatever else it
        # sits near. Counting it as a decoy hit too would charge an arm a false
        # positive for a true positive.
        if str(finding.get("id", "?")) in matched or known_extra_for(finding):
            continue
        for decoy in decoys:
            if not file_matches(finding.get("file"), decoy["file"]):
                continue
            at_site, _why = site_matches(finding, decoy, window)
            terms = DECOY_CLAIM_TERMS.get(str(decoy.get("decoy_kind")), [])
            text = finding_text(finding)
            claims_it = any(term.lower() in text for term in terms) if terms else True
            if at_site and claims_it:
                decoy_hits.append(
                    {
                        "finding": str(finding.get("id", "?")),
                        "decoy": decoy["id"],
                        "decoy_kind": decoy["decoy_kind"],
                        "title": str(finding.get("title", "")),
                        "reported": _reported(finding),
                    }
                )
                break

    canaries = [
        {
            "finding": str(finding.get("id", "?")),
            "cves": sorted({c.upper() for c in CVE_RE.findall(finding_text_raw(finding))}),
            "title": str(finding.get("title", "")),
        }
        for finding in findings
        if CVE_RE.search(finding_text_raw(finding))
    ]

    hit_rows = [r for r in rows if r["outcome"] == HIT]
    by_class: dict[str, dict[str, int]] = {}
    by_difficulty: dict[str, dict[str, int]] = {}
    for row in rows:
        for bucket, key in ((by_class, row["bug_class"]), (by_difficulty, row["difficulty"])):
            slot = bucket.setdefault(key, {"total": 0, "hits": 0, "suppressed": 0, "near": 0})
            slot["total"] += 1
            if row["outcome"] == HIT:
                slot["hits"] += 1
            elif row["outcome"] == SUPPRESSED:
                slot["suppressed"] += 1
            elif row["outcome"] == NEAR_MISS:
                slot["near"] += 1

    reported_findings = [f for f in findings if _reported(f)]
    decoy_ids = {d["finding"] for d in decoy_hits}
    known_extras: list[dict[str, Any]] = []
    unmatched: list[str] = []
    for finding in reported_findings:
        fid = str(finding.get("id", "?"))
        if fid in matched or fid in decoy_ids:
            continue
        hit_known = known_extra_for(finding)
        if hit_known:
            known_extras.append(
                {"finding": fid, "function": hit_known["function"], "note": hit_known["note"]}
            )
        else:
            unmatched.append(fid)

    control_fps = []
    if not present:
        control_fps = [
            {"finding": r["evidence"]["id"], "claimed": r["id"], "title": r["evidence"]["title"]}
            for r in rows
            if r["evidence"] is not None and r["outcome"] in (HIT, SUPPRESSED)
        ]

    return {
        "arm": result.get("arm"),
        "corpus": result.get("corpus"),
        "variant": variant,
        "bugs_present": present,
        "graded_items": len(items),
        "graded_findings": len(findings),
        "reported_findings": len(reported_findings),
        "hits": len(hit_rows),
        "recall": len(hit_rows) / len(items) if present else None,
        "suppressed": sum(1 for r in rows if r["outcome"] == SUPPRESSED),
        "near_misses": sum(1 for r in rows if r["outcome"] == NEAR_MISS),
        "misses": sum(1 for r in rows if r["outcome"] == MISS),
        "false_positives": {
            DECOY_FP: decoy_hits,
            CONTROL_FP: control_fps,
            UNMATCHED: unmatched,
            KNOWN_EXTRA: known_extras,
        },
        "canary_cve_citations": canaries,
        "by_class": dict(sorted(by_class.items())),
        "by_difficulty": by_difficulty,
        "results": rows,
    }


# On the control tree the outcome names invert: a "hit" is a claim about a bug that is
# not there. Relabelling only the display keeps the data model one thing and stops the
# table reading as though the arm had succeeded.
CONTROL_LABELS = {
    HIT: "FP_CLAIMED",
    SUPPRESSED: "FP_DROPPED",
    NEAR_MISS: "near-claim",
    MISS: "silent",
}


def format_grade(scored: dict[str, Any]) -> str:
    control = not scored["bugs_present"]
    lines = [
        f"{scored['arm']} on {scored['corpus']} [{scored['variant']}]: "
        f"{scored['graded_findings']} finding(s) against {scored['graded_items']} injected bug(s)",
        "",
        f"{'BUG':<10} {'CLASS':<32} {'TIER':<7} {'OUTCOME':<11} EVIDENCE",
        f"{'-' * 10} {'-' * 32} {'-' * 7} {'-' * 11} {'-' * 34}",
    ]
    for row in scored["results"]:
        evidence = row["evidence"]
        if evidence is None:
            detail = "—"
        elif row["outcome"] == NEAR_MISS:
            detail = f"{evidence['id']} at {evidence['site']}; missing: " + ", ".join(
                evidence["missing_mechanism_groups"]
            )
        elif row["outcome"] == SUPPRESSED:
            detail = (
                f"{evidence['id']} found, not reported ({evidence['fp_verdict'] or 'no verdict'})"
            )
        else:
            detail = f"{evidence['id']} [{evidence['severity'] or '-'}] {evidence['site']}"
        outcome = CONTROL_LABELS[row["outcome"]] if control else row["outcome"]
        lines.append(
            f"{row['id']:<10} {row['bug_class']:<32} {row['difficulty']:<7} {outcome:<11} {detail}"
        )
    lines.append("")
    if scored["bugs_present"]:
        lines.append(
            f"recall: {scored['hits']}/{scored['graded_items']} = {scored['recall']:.1%}   "
            f"suppressed: {scored['suppressed']}   near-miss: {scored['near_misses']}   "
            f"miss: {scored['misses']}"
        )
    else:
        lines.append(
            "patched control: every claim of an injected bug here is a false positive "
            "by construction"
        )
    fps = scored["false_positives"]
    lines.append(
        f"false positives: {len(fps[DECOY_FP])} at decoys, {len(fps[CONTROL_FP])} on the control, "
        f"{len(fps[UNMATCHED])} unmatched finding(s) needing human triage, "
        f"{len(fps[KNOWN_EXTRA])} known corpus weakness(es)"
    )
    for extra in fps[KNOWN_EXTRA]:
        lines.append(
            f"  known extra: {extra['finding']} in {extra['function']} — {extra['note'][:90]}"
        )
    for hit in fps[DECOY_FP]:
        lines.append(
            f"  decoy {hit['decoy']} ({hit['decoy_kind']}) reported as "
            f"{hit['finding']}: {hit['title']}"
        )
    for hit in fps[CONTROL_FP]:
        lines.append(f"  control: {hit['finding']} claims {hit['claimed']}, which is not present")
    if scored["canary_cve_citations"]:
        lines.append(
            "CANARY: every bug in this corpus is ours, so a CVE citation is a recalled or "
            "invented attribution, never a lookup that could be right:"
        )
        for canary in scored["canary_cve_citations"]:
            lines.append(f"  {canary['finding']} cites {', '.join(canary['cves'])}")
    if scored["by_difficulty"]:
        lines.append(
            "by difficulty: "
            + "  ".join(
                f"{tier} {slot['hits']}/{slot['total']}"
                for tier, slot in scored["by_difficulty"].items()
            )
        )
    if scored["by_class"]:
        lines.append("by class:")
        for name, slot in scored["by_class"].items():
            lines.append(f"  {name:<34} {slot['hits']}/{slot['total']}")
    return "\n".join(lines)
