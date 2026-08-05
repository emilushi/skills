"""Collect one arm's result: wait for it to be finished, then check its shape.

This module exists because of a specific, expensive failure. A previous measurement
read `findings.json` while the workflow was still writing it, drew two conclusions
from the partial document, and separately produced structurally different artifacts
from two runs of identical code (23 survivors with 7 fields once, 31 primaries with
8 fields the next). Three published numbers were wrong.

So collection is deliberately paranoid, in this order:

1. **A completion marker.** `meta.json` must say `"complete": true`. The driver
   writes it *after* the arm returns; there is no way to infer completion from the
   result file itself, and inferring it is what went wrong before.
2. **A settle check.** The result file's digest must be unchanged across two samples
   `settle_seconds` apart. A file still being written fails this.
3. **A schema check.** Every finding must carry the fields the grader reads, with
   the types it expects. An unexpected shape is an error, never something to infer
   meaning from.
4. **Normalisation.** c-review's own `findings.json` is converted through the
   plugin's `findings_model`, the same module that decides what `REPORT.md` shows,
   so "reported" means the same thing here as it does to a user. A generic arm
   supplies the normalised shape directly.

Cost is part of the result, not a footnote: `agents`, `tokens` and `wall_seconds`
are required, and a zero token count is refused. An arm that reports no cost cannot
be compared with one that does.
"""

from __future__ import annotations

import hashlib
import json
import sys
import time
from pathlib import Path
from typing import Any

PLUGIN_SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"

REQUIRED_FINDING_FIELDS = ("file", "line", "title", "description")
OPTIONAL_FINDING_FIELDS = (
    "function",
    "bug_class",
    "impact",
    "code",
    "data_flow",
    "reachability",
    "recommendation",
    "confidence",
    "severity",
    "found_by",
    "fp_verdict",
    "mitigations_checked",
    "severity_rationale",
    "fp_rationale",
)
REQUIRED_META_FIELDS = ("agents", "tokens", "wall_seconds", "model")
# Which token definition `tokens` carries. Recorded per cell and printed by `score`,
# because comparing an arm counted one way with an arm counted another way is not a
# comparison. See derive_cost for what each basis means.
TOKEN_BASES = ("reported_subagent_tokens", "tokens_fresh", "tokens_total")


class ResultError(Exception):
    """A result that must not be scored. Callers exit non-zero."""


def _load_findings_model() -> Any:
    """The plugin's own definition of the reported set. Not re-implemented here.

    Two definitions of "reported" would drift, and the arm that c-review is being
    measured against would be graded on a different set from the one its users see.
    """
    if str(PLUGIN_SCRIPTS) not in sys.path:
        sys.path.insert(0, str(PLUGIN_SCRIPTS))
    try:
        import findings_model  # noqa: PLC0415 - deliberately late, path-dependent
    except ImportError as exc:  # pragma: no cover - a broken checkout, not a code path
        raise ResultError(
            f"cannot import findings_model from {PLUGIN_SCRIPTS}: {exc}. The harness will not "
            f"guess what c-review counts as reported."
        ) from exc
    return findings_model


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def wait_until_settled(path: Path, settle_seconds: float, timeout: float) -> str:
    """Return the digest once it has held still, or raise.

    Nothing about this is a substitute for the completion marker: a file can be
    momentarily quiescent mid-write. It is the second lock on the same door.
    """
    if settle_seconds <= 0:
        raise ResultError(
            "settle_seconds must be positive; a zero-second settle check checks nothing"
        )
    deadline = time.monotonic() + timeout
    if not path.is_file():
        raise ResultError(f"result artifact does not exist: {path}")
    previous = _digest(path)
    while True:
        time.sleep(settle_seconds)
        current = _digest(path)
        if current == previous:
            return current
        if time.monotonic() > deadline:
            raise ResultError(
                f"{path} is still changing after {timeout:.0f}s. It is being written; scoring a "
                f"partial artifact is how three wrong numbers were published last time."
            )
        previous = current


def load_meta(path: Path, settle_seconds: float, timeout: float) -> dict[str, Any]:
    wait_until_settled(path, settle_seconds, timeout)
    try:
        meta = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ResultError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(meta, dict):
        raise ResultError(f"{path}: expected a JSON object")
    if meta.get("complete") is not True:
        raise ResultError(
            f'{path} does not say "complete": true. Write the meta file only after the arm has '
            f"returned — this is the completion marker, and without it the result may be partial."
        )
    missing = [field for field in REQUIRED_META_FIELDS if field not in meta]
    if missing:
        raise ResultError(f"{path} is missing required cost field(s): {', '.join(missing)}")
    basis = meta.setdefault("token_basis", TOKEN_BASES[0])
    if basis not in TOKEN_BASES:
        raise ResultError(
            f"{path}: token_basis {basis!r} is not one of {TOKEN_BASES}. Every cell in a run "
            f"must count tokens the same way or the comparison is meaningless."
        )
    for field in ("agents", "tokens"):
        try:
            value = int(meta[field])
        except (TypeError, ValueError) as exc:
            raise ResultError(f"{path}: {field} must be an integer, got {meta[field]!r}") from exc
        if value <= 0:
            raise ResultError(
                f"{path}: {field} is {value}. An arm that reports no {field} cannot be compared "
                f"with one that does; record the real number or do not collect the arm."
            )
    return meta


def _looks_like_c_review(doc: dict[str, Any]) -> bool:
    return isinstance(doc.get("run"), dict) and isinstance(doc.get("stats"), dict)


def normalise_c_review(doc: dict[str, Any]) -> dict[str, Any]:
    model = _load_findings_model()
    reported_ids = {str(f.get("id")) for f in model.reported_findings(doc)}
    findings = []
    for finding in doc["findings"]:
        entry = {
            key: finding.get(key)
            for key in ("id", *REQUIRED_FINDING_FIELDS, *OPTIONAL_FINDING_FIELDS)
            if key in finding
        }
        entry["id"] = str(finding.get("id") or f"F-{len(findings) + 1}")
        entry["reported"] = entry["id"] in reported_ids
        entry["merged_into"] = finding.get("merged_into")
        findings.append(entry)
    externals = doc.get("run", {}).get("hunter_external_sources") or []
    consulted = any(bool(e.get("consulted")) for e in externals if isinstance(e, dict))
    detail = "; ".join(
        f"{e.get('group')}: {e.get('detail')}"
        for e in externals
        if isinstance(e, dict) and e.get("consulted")
    )
    return {
        "findings": findings,
        "external_sources_consulted": consulted,
        "external_sources_detail": detail or "none",
        "native_stats": doc.get("stats", {}),
        "groups_attempted": doc.get("run", {}).get("groups_attempted", []),
        "groups_failed": doc.get("run", {}).get("groups_failed", []),
    }


def normalise_generic(doc: dict[str, Any]) -> dict[str, Any]:
    findings = []
    for index, finding in enumerate(doc["findings"], 1):
        if not isinstance(finding, dict):
            raise ResultError(
                f"findings[{index - 1}] is {type(finding).__name__}, expected an object"
            )
        entry = dict(finding)
        entry["id"] = str(finding.get("id") or f"F-{index}")
        entry["reported"] = bool(finding.get("reported", True))
        findings.append(entry)
    return {
        "findings": findings,
        "external_sources_consulted": bool(doc.get("external_sources_consulted", False)),
        "external_sources_detail": str(doc.get("external_sources_detail", "none")),
    }


def validate_findings(findings: list[dict[str, Any]]) -> None:
    problems: list[str] = []
    seen: set[str] = set()
    for finding in findings:
        fid = str(finding.get("id"))
        if fid in seen:
            problems.append(f"duplicate finding id {fid!r}")
        seen.add(fid)
        for field in REQUIRED_FINDING_FIELDS:
            if not str(finding.get(field, "")).strip():
                problems.append(f"{fid}: missing required field {field!r}")
        try:
            line = int(finding.get("line", 0))
        except (TypeError, ValueError):
            problems.append(f"{fid}: line is not an integer ({finding.get('line')!r})")
            continue
        if line < 1:
            problems.append(f"{fid}: line {line} is not a source line")
    if problems:
        raise ResultError(
            "the result does not match the schema the grader reads:\n  "
            + "\n  ".join(problems[:20])
            + "\nFix the arm's output rather than the grader: an unexpected shape is not "
            "something to infer meaning from."
        )


def derive_cost(transcripts: list[Path]) -> dict[str, Any]:
    """Token counts read out of the transcripts, with the definition made explicit.

    There is no single "tokens" number, and pretending otherwise is how two arms end
    up compared on different scales. A transcript distinguishes:

    - `tokens_fresh` = input + output + cache **creation**: what this run had to
      produce or ingest for the first time.
    - `tokens_cache_read` = context re-read from cache. Real spend, usually the
      largest term, and it grows with how often an agent re-reads the same files.
    - `tokens_total` = the two together.

    The platform separately reports a `subagent_tokens` figure per agent, which
    matches neither exactly. Whichever basis a run uses, **every cell in that run must
    use the same one**, and `meta.token_basis` records which. The previous evaluation's
    published figures are in the same range as the platform's `subagent_tokens`, so
    that is the default basis for comparability with them.

    The driver still writes `meta.json` by hand, because the completion marker has to
    be a deliberate act. This exists so the number it writes is a measured one.
    """
    files: list[Path] = []
    for path in transcripts:
        if path.is_dir():
            files += sorted(path.rglob("*.jsonl")) + sorted(path.rglob("*.output"))
        elif path.is_file():
            files.append(path)
    if not files:
        raise ResultError(f"no transcripts found in {[str(p) for p in transcripts]}")

    totals = {
        "input_tokens": 0,
        "output_tokens": 0,
        "cache_creation_input_tokens": 0,
        "cache_read_input_tokens": 0,
    }
    records = 0
    with_usage = 0
    agent_ids: set[str] = set()
    session_ids: set[str] = set()
    for file in files:
        for line in file.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            records += 1
            if isinstance(record.get("agentId"), str):
                agent_ids.add(record["agentId"])
            for key in ("sessionId", "session_id"):
                if isinstance(record.get(key), str):
                    session_ids.add(record[key])
            usage = (record.get("message") or {}).get("usage")
            if isinstance(usage, dict):
                with_usage += 1
                for key in totals:
                    try:
                        totals[key] += int(usage.get(key) or 0)
                    except (TypeError, ValueError):
                        continue
    if with_usage == 0:
        raise ResultError(
            f"parsed {records} record(s) from {len(files)} transcript(s) and found no usage "
            f"block in any of them, so the cost was not measured. Do not fall back to an "
            f"estimate: fix the transcript path."
        )
    fresh = totals["input_tokens"] + totals["output_tokens"] + totals["cache_creation_input_tokens"]
    cache_read = totals["cache_read_input_tokens"]
    if fresh + cache_read <= 0:
        raise ResultError("the transcripts report zero tokens, which is not a measurement")
    return {
        "tokens_fresh": fresh,
        "tokens_cache_read": cache_read,
        "tokens_total": fresh + cache_read,
        "breakdown": totals,
        "distinct_ids": len(agent_ids) or len(session_ids),
        "records_with_usage": with_usage,
        "transcripts": [str(f) for f in files],
    }


def load_plan(run_dir: Path) -> dict[str, Any]:
    path = Path(run_dir) / "plan.json"
    if not path.is_file():
        raise ResultError(
            f"no plan at {path}. Run `bench.py plan` first: the plan records which corpus variant "
            f"each arm reviews and which corpora passed the integrity gate."
        )
    return json.loads(path.read_text(encoding="utf-8"))


def collect(
    run_dir: Path,
    arm: str,
    corpus: str,
    result_path: Path,
    meta_path: Path,
    transcripts: list[Path],
    variant: str = "bench",
    settle_seconds: float = 2.0,
    timeout: float = 120.0,
) -> dict[str, Any]:
    """Normalise one cell of the run matrix into `run_dir/collected/`.

    The cell is keyed on all three of arm, corpus **and variant**. Matching on the
    first two was a real defect: with a control cell in the plan, a result from the
    bug-free tree was collected as a bench result, and would have been reported as
    recall rather than as false positives.
    """
    plan = load_plan(run_dir)
    cells = [
        c
        for c in plan["cells"]
        if c["arm"] == arm and c["corpus"] == corpus and c["variant"] == variant
    ]
    if not cells:
        raise ResultError(
            f"the plan has no cell for arm {arm!r} on corpus {corpus!r} "
            f"variant {variant!r}; it has "
            + ", ".join(f"{c['arm']}/{c['corpus']}/{c['variant']}" for c in plan["cells"])
        )
    if len(cells) > 1:
        raise ResultError(
            f"the plan has {len(cells)} cells for {arm}/{corpus}/{variant}, so this result "
            f"cannot be attributed to one of them"
        )
    cell = cells[0]

    meta = load_meta(Path(meta_path), settle_seconds, timeout)
    digest = wait_until_settled(Path(result_path), settle_seconds, timeout)
    try:
        doc = json.loads(Path(result_path).read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ResultError(
            f"{result_path} is not valid JSON: {exc}. If an agent wrote it, it was probably "
            f"truncated; re-run the write rather than hand-repairing it."
        ) from exc
    if not isinstance(doc, dict) or not isinstance(doc.get("findings"), list):
        raise ResultError(
            f"{result_path}: expected an object with a 'findings' list. An empty list is a valid "
            f"clean run; a missing key means this is not an arm result."
        )

    normalised = normalise_c_review(doc) if _looks_like_c_review(doc) else normalise_generic(doc)
    validate_findings(normalised["findings"])

    collected = {
        "arm": arm,
        "corpus": corpus,
        "variant": cell["variant"],
        "shape": "c-review" if _looks_like_c_review(doc) else "generic",
        "source_path": str(Path(result_path).resolve()),
        "source_sha256": digest,
        "collected_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "meta": meta,
        "transcripts": [str(Path(t).resolve()) for t in transcripts],
        **normalised,
    }
    out_dir = Path(run_dir) / "collected"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{arm}__{corpus}__{variant}.json").write_text(
        json.dumps(collected, indent=2) + "\n", encoding="utf-8"
    )
    return collected
