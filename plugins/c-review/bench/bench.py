#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""c-review benchmark harness: one entry point for every step of a measurement.

    uv run bench.py corpora                     # what exists, and how big
    uv run bench.py verify --corpus sigil        # the integrity gate; run this first
    uv run bench.py plan --tier standard         # cost estimate + one packet per arm
    uv run bench.py partition --corpus sigil -n 13
    uv run bench.py collect --run RUN --arm bare --corpus sigil --result r.json --meta m.json
    uv run bench.py score --run RUN              # anti-cheat, grade, cost, report

The order is not advisory. `plan` refuses a corpus with no verification stamp,
`collect` refuses a result that is still being written, and `score` refuses to
compare an arm whose transcript shows it used an oracle.

Exit codes are the interface: 0 means the step did what it says, 2 means it
inspected nothing or found a disqualifying problem, 3 means the input was unusable.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from lib import corpus as corpus_mod  # noqa: E402
from lib import deidentify as deid_mod  # noqa: E402
from lib import plan as plan_mod  # noqa: E402
from lib import recipe as recipe_mod  # noqa: E402
from lib import report as report_mod  # noqa: E402
from lib import result as result_mod  # noqa: E402
from lib import verify as verify_mod  # noqa: E402

CORPORA = HERE / "corpora"
DEFAULT_WORK = Path.home() / ".cache" / "c-review-bench" / "work"


def _recipes() -> dict[str, Path]:
    found = {p.parent.name: p for p in sorted(CORPORA.glob("*/recipe.json"))}
    if not found:
        raise SystemExit("bench: no corpora found under corpora/*/recipe.json")
    return found


def _recipe(name: str) -> dict:
    found = _recipes()
    if name not in found:
        raise SystemExit(f"bench: no corpus {name!r}; have {', '.join(sorted(found))}")
    return recipe_mod.load(found[name])


def cmd_corpora(args: argparse.Namespace) -> int:
    del args
    rows = []
    for name, path in _recipes().items():
        recipe = recipe_mod.load(path)
        counts = recipe_mod.counts(recipe)
        rows.append(
            f"  {name:<12} {recipe['tier']:<7} {counts['bugs']:>3} bugs  "
            f"{counts['decoys']:>3} decoys  "
            f"{'/'.join(str(counts['by_difficulty'][d]) for d in recipe_mod.DIFFICULTIES)} E/M/H  "
            f"{len(counts['by_class'])} classes  base={recipe['base']['kind']}"
        )
    print("corpora:")
    print("\n".join(rows))
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    recipe = _recipe(args.corpus)
    workdir = Path(args.workdir or DEFAULT_WORK / args.corpus)
    print(f"corpus integrity gate: {args.corpus} ({recipe['tier']}) -> {workdir}")
    try:
        stamp = verify_mod.gate(
            recipe, workdir, allow_network=not args.offline, build_timeout=args.timeout
        )
    except (
        verify_mod.VerifyError,
        corpus_mod.CorpusError,
        recipe_mod.RecipeError,
        deid_mod.DeidError,
    ) as exc:
        print(f"bench: {exc}", file=sys.stderr)
        return 3
    for check in stamp["_checks"]:
        print(check.line())
    counts = stamp["counts"]
    print(
        f"\n  {counts['bugs']} bug(s) across {len(counts['by_class'])} class(es), "
        f"{counts['decoys']} decoy(s), {stamp['lines_of_code']} lines emitted"
    )
    if stamp["verified"]:
        print(f"\n✓ verified — stamp at {workdir / 'verified.json'}")
        return 0
    print(
        "\n✗ NOT VERIFIED — no arm may run against this corpus until every check passes",
        file=sys.stderr,
    )
    return 2


def cmd_partition(args: argparse.Namespace) -> int:
    workdir = Path(args.workdir or DEFAULT_WORK / args.corpus)
    tree = workdir / corpus_mod.BENCH
    if not tree.is_dir():
        print(f"bench: no built tree at {tree}; run verify first", file=sys.stderr)
        return 3
    groups = plan_mod.partition(tree, args.n)
    for index, group in enumerate(groups, 1):
        print(f"  region {index}: " + ", ".join(f"{p}:{a}-{b}" for p, a, b in group))
    return 0


def cmd_plan(args: argparse.Namespace) -> int:
    try:
        plan = plan_mod.build_plan(
            tier=args.tier,
            recipes={name: recipe_mod.load(path) for name, path in _recipes().items()},
            workroot=Path(args.workdir) if args.workdir else DEFAULT_WORK,
            run_dir=Path(args.out),
            fanout_n=args.fanout_n,
            arms=args.arm or None,
            corpora=args.corpus or None,
            allow_missing=args.allow_missing_corpora,
            packet_dir=HERE / "arms",
        )
    except plan_mod.PlanError as exc:
        print(f"bench: {exc}", file=sys.stderr)
        return 3
    print(plan_mod.format_plan(plan))
    return 0


def cmd_collect(args: argparse.Namespace) -> int:
    try:
        collected = result_mod.collect(
            run_dir=Path(args.run),
            arm=args.arm,
            corpus=args.corpus,
            result_path=Path(args.result),
            meta_path=Path(args.meta),
            variant=args.variant,
            transcripts=[Path(t) for t in args.transcript or ()],
            settle_seconds=args.settle,
            timeout=args.wait,
        )
    except result_mod.ResultError as exc:
        print(f"bench: {exc}", file=sys.stderr)
        return 3
    print(
        f"collected {args.arm} on {args.corpus} [{args.variant}]: "
        f"{len(collected['findings'])} finding(s), "
        f"{collected['meta']['agents']} agent(s), {collected['meta']['tokens']} token(s), "
        f"{len(collected['transcripts'])} transcript(s)"
    )
    return 0


def cmd_cost(args: argparse.Namespace) -> int:
    try:
        cost = result_mod.derive_cost([Path(t) for t in args.transcript])
    except result_mod.ResultError as exc:
        print(f"bench: {exc}", file=sys.stderr)
        return 2
    print(
        f"measured from {len(cost['transcripts'])} transcript(s), "
        f"{cost['records_with_usage']} record(s) carrying usage:"
    )
    print(f"  tokens_fresh      (input + output + cache creation): {cost['tokens_fresh']:>12,}")
    print(
        f"  tokens_cache_read (context re-read from cache):      {cost['tokens_cache_read']:>12,}"
    )
    print(f"  tokens_total                                         {cost['tokens_total']:>12,}")
    for key, value in cost["breakdown"].items():
        print(f"    {key:<34} {value:>12,}")
    print(f"  distinct ids seen (a hint, not the agent count): {cost['distinct_ids']}")
    print(
        "\nPut one of these in meta.tokens and name it in meta.token_basis, or use the "
        "platform's reported subagent_tokens with the default basis. Do not mix bases "
        "across cells in one run."
    )
    return 0


def cmd_score(args: argparse.Namespace) -> int:
    try:
        scored = report_mod.score_run(
            Path(args.run), workroot=Path(args.workdir) if args.workdir else DEFAULT_WORK
        )
    except (report_mod.ReportError, result_mod.ResultError) as exc:
        print(f"bench: {exc}", file=sys.stderr)
        return 3
    text = report_mod.format_report(scored)
    print(text)
    out = Path(args.run) / "score.json"
    out.write_text(json.dumps(scored, indent=2) + "\n", encoding="utf-8")
    (Path(args.run) / "REPORT.md").write_text(text + "\n", encoding="utf-8")
    print(f"\nwrote {out} and {Path(args.run) / 'REPORT.md'}")
    return 2 if scored["invalid_arms"] else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("corpora", help="list corpora with bug and decoy counts").set_defaults(
        func=cmd_corpora
    )

    p = sub.add_parser("verify", help="the corpus integrity gate")
    p.add_argument("--corpus", required=True)
    p.add_argument("--workdir", default=None, help="where to build (default: the cache)")
    p.add_argument("--offline", action="store_true", help="refuse to fetch; use the cache only")
    p.add_argument("--timeout", type=int, default=900)
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("partition", help="deterministic file/region split for the fanout arm")
    p.add_argument("--corpus", required=True)
    p.add_argument("-n", type=int, required=True)
    p.add_argument("--workdir", default=None)
    p.set_defaults(func=cmd_partition)

    p = sub.add_parser("plan", help="print the cost estimate and write one packet per arm")
    p.add_argument("--tier", required=True, choices=sorted(plan_mod.TIERS))
    p.add_argument("--out", required=True, help="run directory to create")
    p.add_argument("--workdir", default=None)
    p.add_argument("--fanout-n", type=int, default=None)
    p.add_argument("--arm", action="append", help="restrict to these arms")
    p.add_argument("--corpus", action="append", help="restrict to these corpora")
    p.add_argument(
        "--allow-missing-corpora",
        action="store_true",
        help="plan a tier even though no corpus exists for one of its sizes; the plan and the "
        "report both record that the run was reduced",
    )
    p.set_defaults(func=cmd_plan)

    p = sub.add_parser("collect", help="normalise and schema-check one arm's result")
    p.add_argument("--run", required=True)
    p.add_argument("--arm", required=True)
    p.add_argument("--corpus", required=True)
    p.add_argument("--result", required=True)
    p.add_argument("--meta", required=True)
    p.add_argument(
        "--variant",
        default="bench",
        choices=["bench", "control"],
        help="which tree this result reviewed; 'control' is the bug-free corpus",
    )
    p.add_argument("--transcript", action="append")
    p.add_argument(
        "--settle", type=float, default=2.0, help="seconds the artifact must be unchanged"
    )
    p.add_argument("--wait", type=float, default=120.0, help="how long to wait for it to settle")
    p.set_defaults(func=cmd_collect)

    p = sub.add_parser("cost", help="measure tokens and agents from transcripts")
    p.add_argument("--transcript", action="append", required=True)
    p.set_defaults(func=cmd_cost)

    p = sub.add_parser("score", help="anti-cheat, grade, cost, and the comparison table")
    p.add_argument("--run", required=True)
    p.add_argument("--workdir", default=None)
    p.set_defaults(func=cmd_score)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
