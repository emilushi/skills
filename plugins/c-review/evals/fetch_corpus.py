#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Fetch and prepare the ground-truth corpus for a c-review eval run.

Needs network. Clones the repo named in the ground-truth file at its pinned tag,
checks that every ground-truth file is present, prints where each ground-truth
function actually lives so anchor drift is visible, and (by default) scrubs the
version markers so a reviewer cannot read the answer off the version number.

The scrub is blinding, not tampering: it edits only the version macros and the
per-file version banner, which have no bearing on any of the seven defects.

Usage:
    uv run fetch_corpus.py --dest ./corpus
    uv run fetch_corpus.py --dest ./corpus --no-scrub    # keep version markers
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_GROUND_TRUTH = HERE / "ground_truth" / "libexpat-R_2_4_3.json"

# Version markers to neutralise. Each is (glob, pattern, replacement).
SCRUB_RULES = [
    ("**/*.h", re.compile(r"^(#define\s+XML_MICRO_VERSION\s+)\d+$", re.M), r"\g<1>0"),
    ("**/*.h", re.compile(r"^(#define\s+XML_MINOR_VERSION\s+)\d+$", re.M), r"\g<1>0"),
    ("**/*.c", re.compile(r"^\s*/\*\s*\d+\.\d+\.\d+\s*\*/\s*$", re.M), ""),
    ("**/*.h", re.compile(r"^\s*/\*\s*\d+\.\d+\.\d+\s*\*/\s*$", re.M), ""),
]


def die(message: str) -> None:
    print(f"fetch_corpus: {message}", file=sys.stderr)
    raise SystemExit(1)


def run(cmd: list[str], cwd: Path | None = None) -> str:
    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        die(
            f"`{' '.join(cmd)}` failed with exit {result.returncode}.\n"
            f"{result.stderr.strip()}\n"
            f"This step needs network access to clone the corpus; there is no offline fallback."
        )
    return result.stdout


def clone(repo: str, tag: str, dest: Path) -> None:
    if dest.exists():
        if not (dest / ".git").is_dir():
            die(f"{dest} exists and is not a git clone; remove it or pick another --dest")
        head = run(["git", "-C", str(dest), "describe", "--tags", "--exact-match"]).strip()
        if head != tag:
            die(f"{dest} is checked out at {head!r}, not {tag!r}; remove it or pick another --dest")
        print(f"reusing existing clone at {dest} ({tag})")
        return
    if shutil.which("git") is None:
        die("git is not on PATH")
    print(f"cloning {repo} at {tag} into {dest} ...")
    dest.parent.mkdir(parents=True, exist_ok=True)
    run(["git", "clone", "--quiet", "--depth", "1", "--branch", tag, repo, str(dest)])


def scrub(root: Path) -> int:
    edits = 0
    for glob, pattern, replacement in SCRUB_RULES:
        for path in sorted(root.glob(glob)):
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            new, count = pattern.subn(replacement, text)
            if count:
                path.write_text(new, encoding="utf-8")
                edits += count
    return edits


def check_ground_truth(root: Path, gt: dict) -> None:
    items = gt.get("items", [])
    if not items:
        die("ground truth has zero items; there is nothing to prepare a corpus for")

    missing = []
    print("\nground-truth anchor check (function name -> line found in this tree):")
    for item in items:
        target = root / item["file"]
        if not target.is_file():
            missing.append(item["file"])
            print(f"  {item['cve']:<20} {item['file']}  MISSING")
            continue
        lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
        found = []
        for name in item.get("functions", []):
            if name.startswith("("):
                continue
            for n, line in enumerate(lines, 1):
                if re.search(r"\b" + re.escape(name) + r"\b", line):
                    found.append(f"{name}@{n}")
                    break
        anchors = ", ".join(str(x) for x in item.get("lines", []))
        names = ", ".join(found) or "no function-name match"
        print(f"  {item['cve']:<20} anchors [{anchors}] -> {names}")

    if missing:
        die(
            "ground-truth file(s) absent from the fetched tree: "
            + ", ".join(missing)
            + ". The corpus and the ground truth disagree; fix one before grading anything."
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ground-truth", type=Path, default=DEFAULT_GROUND_TRUTH)
    parser.add_argument("--dest", type=Path, required=True, help="where to place the clone")
    parser.add_argument("--no-scrub", action="store_true", help="keep the version markers")
    parsed = parser.parse_args(argv)

    if not parsed.ground_truth.is_file():
        die(f"ground truth not found: {parsed.ground_truth}")
    gt = json.loads(parsed.ground_truth.read_text(encoding="utf-8"))
    corpus = gt.get("corpus", {})
    repo, tag = corpus.get("repo"), corpus.get("tag")
    if not repo or not tag:
        die(f"{parsed.ground_truth} has no corpus.repo / corpus.tag")

    dest = parsed.dest.resolve()
    clone(repo, tag, dest)

    if not parsed.no_scrub:
        edits = scrub(dest)
        print(f"scrubbed {edits} version marker(s)")

    check_ground_truth(dest, gt)

    scope = corpus.get("scope_subpath", ".")
    model = corpus.get("threat_model", "REMOTE")
    controls = corpus.get("attacker_controls", "")
    print(
        "\ncorpus ready.\n"
        f"  repo root:    {dest}\n"
        f"  review scope: {scope}\n"
        f"  threat model: {model} — {controls}\n"
        "\nRun c-review from the repo root with that scope, then grade findings.json\n"
        "with grade.py. Do not tell the reviewer that bugs exist, where they are,\n"
        "or which project this is."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
