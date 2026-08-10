#!/usr/bin/env python3
"""The whole workflow run section, executed under node against the real file.

Why this file exists. Every other workflow test slices `c-review.js` with `str.index` and
asserts on the TEXT of a function, which leaves one recurring blind spot: *the function is
tested, the call site is not*. Testing `ASSIGNMENT_ID` in isolation leaves
`if (malformedIds.length)` replaceable with `if (false)`; testing `tier1` and
`autoMergeNearby` directly leaves their call sites replaceable with `new Map()` and `0`;
`EVIDENCE_RULE` can be emptied to `''`, `died(label)` reverted to `() => null`, and
`--expect ID=COUNT` — the only cross-check between what the workflow received through the
schema and what is on disk — reduced to `ID=0`, with the whole suite green.

So this runs the module. `agent`, `parallel`, `phase` and `log` are the four globals the
workflow runtime injects; here they are stubs that script each agent's return by label and
record every prompt, every option object and every log line. The assertions are on what the
run actually emitted — the assemble command string above all, because that command is the
whole contract between this workflow and `assemble_findings.py`.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

WORKFLOW = Path(__file__).resolve().parents[1] / "workflows" / "c-review.js"

# Not `skipif`. A suite of silent skips exits 0 — the zero-item pass AGENTS.md forbids.
if shutil.which("node") is None:  # pragma: no cover - environment guard
    import os

    if os.environ.get("C_REVIEW_ALLOW_NO_NODE") == "1":
        pytestmark = pytest.mark.skip(reason="C_REVIEW_ALLOW_NO_NODE=1")
    else:
        pytest.fail(
            "node is not installed, so the workflow contract tests would all skip and this "
            "suite would pass having checked nothing. Install node, or set "
            "C_REVIEW_ALLOW_NO_NODE=1 to accept the gap deliberately.",
            pytrace=False,
        )

HARNESS = r"""
const fs = require('fs')
const spec = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'))
// `export` is the only thing in the file that a Function body cannot hold. Nothing else is
// rewritten: the point is to run the shipped source, not a copy of it.
const body = fs.readFileSync(process.argv[3], 'utf8').replace('export const meta', 'const meta')
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor

const calls = []
const logs = []
const phases = []
async function agent(prompt, opts) {
  calls.push({
    label: opts.label,
    prompt: prompt,
    agentType: opts.agentType === undefined ? null : opts.agentType,
    phase: opts.phase,
  })
  if (!(opts.label in spec.agents)) throw new Error('unscripted agent label: ' + opts.label)
  const scripted = spec.agents[opts.label]
  if (scripted && scripted.__reject) throw new Error(scripted.__reject)
  return scripted
}
const parallel = (thunks) => Promise.all(thunks.map((t) => t()))
const log = (m) => logs.push(String(m))
const phase = (p) => phases.push(String(p))

const fn = new AsyncFunction('args', 'agent', 'parallel', 'phase', 'log', body)
fn(spec.args, agent, parallel, phase, log).then(
  (result) => process.stdout.write(JSON.stringify({ ok: true, result, calls, logs, phases })),
  (err) =>
    process.stdout.write(
      JSON.stringify({ ok: false, error: String(err && err.message), calls, logs, phases })
    )
)
"""

ARGS = {
    "outputDir": "/run",
    "pluginRoot": "/plugin",
    "threatModel": "REMOTE",
    "severityFilter": "all",
}

DETECT = {
    "units_ok": True,
    "units_summary": "3 files, 4 units",
    "assignment_ids": ["unit-01", "unit-02"],
    "is_cpp": False,
    "is_posix": True,
    "is_windows": False,
    "purpose": "a codec",
    "platform_evidence": "src/a.c:1",
    "entry_points": ["src/a.c:10"],
    "trust_boundaries": ["network"],
    "existing_hardening": ["fuzz target"],
    "state_structs": ["cfg"],
    "class_evidence": [
        {"bug_class": "buffer-overflow", "has_candidates": True, "citation": "src/a.c:5"}
    ],
}


def finding(**overrides):
    base = {
        "bug_class": "buffer-overflow",
        "title": "Missing bounds check",
        "file": "src/a.c",
        "line": 10,
        "function": "fa",
        "unit_id": "src/a.c:1-40",
        "confidence": "High",
        "description": "len is unbounded",
        "code": "memcpy(d, s, len);",
        "data_flow": "recv -> memcpy",
        "reachability": "recv -> fa",
        "impact": "heap overflow",
        "mitigations_checked": "none",
        "recommendation": "bound len",
    }
    base.update(overrides)
    return base


def review(findings, **overrides):
    base = {"findings": findings, "ledger": [], "part_written": True, "notes": ""}
    base.update(overrides)
    return base


ASSEMBLED = {
    "ok": True,
    "artifacts_written": True,
    "reported": 2,
    "raw_findings": 4,
    "checks_required": 8,
    "checks_completed": 8,
    "checks_satisfied": 8,
    "unrecognised_parts": 0,
}


def run(tmp_path, agents=None, args=None, detect=None):
    """Execute the real workflow with scripted agent returns.

    `None` for a label is an agent that returned nothing; `{"__reject": "msg"}` is one whose
    dispatch rejected, which is the path `died(label)` exists for.
    """
    scripted = {
        "detect": DETECT if detect is None else detect,
        "review:unit-01": review([finding()]),
        "review:unit-02": review([finding(file="src/b.c", line=100, function="fc")]),
        "sweep:classes": review([]),
        "dedup": {"merges": []},
        "assemble": dict(ASSEMBLED),
    }
    scripted.update(agents or {})
    spec = tmp_path / "spec.json"
    spec.write_text(
        json.dumps({"args": {**ARGS, **(args or {})}, "agents": scripted}), encoding="utf-8"
    )
    harness = tmp_path / "harness.cjs"
    harness.write_text(HARNESS, encoding="utf-8")
    out = subprocess.run(
        ["node", str(harness), str(spec), str(WORKFLOW)],
        capture_output=True,
        text=True,
        check=True,
    )
    assert out.stdout, out.stderr
    return json.loads(out.stdout)


def assemble_command(got):
    """The command string the assemble agent was told to run, exactly."""
    prompts = [c["prompt"] for c in got["calls"] if c["label"] == "assemble"]
    assert prompts, "the assemble agent was never dispatched"
    return " ".join(prompts[0].split())


# ------------------------------------------------------------ the happy path


def test_a_scripted_run_reaches_assemble_and_reports_a_measured_gate(tmp_path):
    got = run(tmp_path)
    assert got["ok"], got.get("error")
    assert got["phases"] == ["Detect", "Review", "Sweep", "Dedup", "Assemble"]
    assert got["result"]["gateAccepted"] is True
    assert got["result"]["artifactError"] is None
    assert got["result"]["stats"]["raw_findings"] == 2
    assert got["result"]["agentFailures"] == []


def test_every_producing_agent_is_dispatched_through_the_worker_agent_type(tmp_path):
    """The tool scope is the only control that closes the two documented bypasses, and it
    lives in `agents/c-review-worker.md`. Asserted on the option object the run actually
    passed rather than on the text of `producingOpts`."""
    # Colliding findings, so the dedup agent is actually dispatched and can be checked.
    got = run(tmp_path, _colliding())
    scoped = {c["label"]: c["agentType"] for c in got["calls"]}
    assert scoped["review:unit-01"] == "c-review:c-review-worker"
    assert scoped["review:unit-02"] == "c-review:c-review-worker"
    assert scoped["sweep:classes"] == "c-review:c-review-worker"
    assert scoped["dedup"] == "c-review:c-review-worker"
    # The two agents that exist to run a command are trusted, not controlled.
    assert scoped["detect"] is None
    assert scoped["assemble"] is None


def test_every_producing_prompt_carries_the_evidence_rule(tmp_path):
    """`EVIDENCE_RULE` is interpolated by reference, so emptying it to `''` leaves the whole
    suite green while "the most important instruction here" vanishes from every prompt."""
    got = run(tmp_path)
    producing = [
        c
        for c in got["calls"]
        if c["agentType"] == "c-review:c-review-worker" and c["label"] != "dedup"
    ]
    assert len(producing) >= 3
    for call in producing:
        assert "EVIDENCE RULE" in call["prompt"], call["label"]
        assert "cite the path:line" in call["prompt"], call["label"]
        assert "Recalled knowledge" in call["prompt"], call["label"]


# ------------------------------------------------------------ the assemble command


def test_expect_carries_the_count_the_workflow_received_through_the_schema(tmp_path):
    """`--expect ID=COUNT` is the only cross-check between the findings the workflow was
    handed through the schema and the findings that reached disk. Nothing else fails when
    the count becomes `+ '=' + 0`, and a reviewer can then summarise twelve findings down to
    three."""
    got = run(
        tmp_path,
        {
            "review:unit-01": review([finding(), finding(line=16, function="fb")]),
            "review:unit-02": review([finding(file="src/b.c", line=100, function="fc")]),
        },
    )
    cmd = assemble_command(got)
    assert "--expect 'review-unit-01=2'" in cmd, cmd
    assert "--expect 'review-unit-02=1'" in cmd, cmd
    assert "--expect 'sweep-classes=0'" in cmd, cmd


def test_a_part_whose_agent_returned_nothing_is_still_allowlisted(tmp_path):
    """`--expect` is an ALLOWLIST as well as an assertion.

    Push it after `if (!entry.result) continue` and a worker that wrote
    `parts/review-unit-02.json` and then had its structured answer rejected gets no
    `--expect` entry at all — so its complete, honest part file is discarded as a ghost and
    its findings reach no artifact. The stem goes in without a count (there is none to
    assert) and the matching `--agent-failure` keeps a genuinely missing file from being
    fatal.
    """
    got = run(tmp_path, {"review:unit-02": None})
    cmd = assemble_command(got)
    assert "--expect 'review-unit-02'" in cmd, cmd
    assert "--expect 'review-unit-02=" not in cmd, cmd
    assert "--agent-failure 'review-unit-02: returned nothing'" in cmd, cmd
    assert got["result"]["agentFailures"] == ["review-unit-02: returned nothing"]


def test_expect_complete_names_only_the_parts_whose_findings_were_whole(tmp_path):
    """`--expect-complete` is what lets the assembler tell a STALE part file from a thin
    one. Reducing the guard to `if (findings.length)` certifies a part whose return was
    already missing a required field, which then reads as an honest thin file."""
    got = run(
        tmp_path,
        {
            "review:unit-01": review([finding()]),
            "review:unit-02": review([finding(file="src/b.c", line=100, description="")]),
        },
    )
    cmd = assemble_command(got)
    assert "--expect-complete 'review-unit-01'" in cmd, cmd
    assert "--expect-complete 'review-unit-02'" not in cmd, cmd


def test_the_sweep_that_did_not_write_its_part_file_is_a_failed_group(tmp_path):
    """Keying `sweepDied` on `!e.result` alone lets a sweep that returned findings with
    `part_written: false` contribute nothing to any artifact and still leave
    `groupsFailed: []`. `recordClasses` already treats that return as silent."""
    got = run(tmp_path, {"sweep:classes": review([finding()], part_written=False)})
    assert got["result"]["groupsFailed"], got["result"]["groupsFailed"]
    assert set(got["result"]["groupsFailed"]) <= set(got["result"]["groupsAttempted"])
    assert "--groups-failed ''" not in assemble_command(got)


# ------------------------------------------------------------ the input guards


@pytest.mark.parametrize(
    ("ids", "because"),
    [
        (["unit-01'; echo PWNED; #"], "a shell escape"),
        (["unit=01"], "an `=` that mis-splits --expect ID=COUNT"),
        (["../../etc/passwd"], "a path escape out of parts/"),
        (["unit-01", "unit-01"], "a duplicate part path"),
        ([], "no assignment ids at all"),
    ],
)
def test_a_bad_assignment_id_set_stops_the_run_before_any_agent_is_paid_for(ids, because, tmp_path):
    """Testing `ASSIGNMENT_ID` as a regex in isolation does not assert the workflow APPLIES
    it: `if (malformedIds.length)` can be `if (false)` with the whole suite green, and the id
    then reaches a shell word, an `--expect` operand and a part-file path."""
    got = run(tmp_path, detect=dict(DETECT, assignment_ids=ids))
    assert got["ok"] is False, because
    assert "c-review:" in got["error"]
    assert [c["label"] for c in got["calls"]] == ["detect"], got["calls"]


def test_a_detect_agent_that_says_it_wrote_no_unit_list_stops_the_run(tmp_path):
    got = run(tmp_path, detect=dict(DETECT, units_ok=False, units_summary="no source files"))
    assert got["ok"] is False
    assert "no source files" in got["error"]


def test_a_detect_dispatch_that_rejects_names_the_reason(tmp_path):
    """`died(label)` returning a bare `() => null` loses the ONE rejection that means the
    tool scope is broken: `agent({agentType})` throws `agent type '…' not found` when
    `agents/c-review-worker.md` is renamed or dropped by a packaging step, and the observable
    result is N "returned nothing" warnings with the cause named nowhere."""
    got = run(tmp_path, {"detect": {"__reject": "agent type 'c-review:x' not found"}})
    assert got["ok"] is False
    assert any("agent type 'c-review:x' not found" in line for line in got["logs"]), got["logs"]


def test_a_review_dispatch_that_rejects_neither_kills_the_run_nor_loses_its_reason(tmp_path):
    got = run(tmp_path, {"review:unit-02": {"__reject": "context window exceeded"}})
    assert got["ok"] is True
    assert any("context window exceeded" in line for line in got["logs"]), got["logs"]
    assert got["result"]["agentFailures"] == ["review-unit-02: returned nothing"]


# ------------------------------------------------------------ the agents' returns


@pytest.mark.parametrize(
    "key",
    [
        "entry_points",
        "trust_boundaries",
        "existing_hardening",
        "state_structs",
        "assignment_ids",
        "class_evidence",
    ],
)
def test_a_schema_violating_detect_list_does_not_take_the_module_down(key, tmp_path):
    """`x || []` accepts any truthy non-iterable, so `entry_points: {a: 1}` throws
    `.map is not a function` out of top-level module code. The detect agent's return is
    model output like any other and gets the same hardening the review agents' returns do."""
    got = run(tmp_path, detect=dict(DETECT, **{key: {"a": 1}}))
    # `assignment_ids` empties to nothing, which is a NAMED refusal, not a TypeError.
    assert "is not a function" not in str(got.get("error")), got.get("error")
    assert "not iterable" not in str(got.get("error")), got.get("error")
    if key == "assignment_ids":
        assert got["ok"] is False and "assignment ids" in got["error"]
    else:
        assert got["ok"] is True, got.get("error")


def _colliding(**agents):
    """Two collision buckets: src/a.c 10/16 and src/b.c 100/106.

    Different functions and different bug classes, so neither tier 1 nor the nearby rule
    merges them and the dedup agent is actually dispatched with two buckets.
    """
    base = {
        "review:unit-01": review(
            [
                finding(line=10, function="fa", bug_class="buffer-overflow"),
                finding(line=16, function="fb", bug_class="integer-overflow"),
            ]
        ),
        "review:unit-02": review(
            [
                finding(file="src/b.c", line=100, function="fc", bug_class="buffer-overflow"),
                finding(file="src/b.c", line=106, function="fd", bug_class="integer-overflow"),
            ]
        ),
    }
    base.update(agents)
    return base


@pytest.mark.parametrize("duplicates", [{"a": 1}, 7, "review-unit-01#1", True])
def test_a_non_array_duplicates_list_does_not_discard_the_whole_run(duplicates, tmp_path):
    """The last `x || []` in the file, at the worst possible point: top-level module code
    after `await agent(dedup)`, i.e. after every review agent, both sweeps and the dedup
    agent have been paid for. `duplicates: {a: 1}` throws `object is not iterable` there,
    the assemble phase never runs, and the whole run is discarded."""
    got = run(
        tmp_path,
        _colliding(dedup={"merges": [{"primary": "review-unit-01#0", "duplicates": duplicates}]}),
    )
    assert got["ok"] is True, got.get("error")
    assert any(c["label"] == "assemble" for c in got["calls"])
    # A non-array is not a merge, so nothing is merged on the strength of one.
    assert got["result"]["stats"]["merged"] == 0


def test_a_merge_over_two_findings_the_agent_was_never_shown_is_rejected(tmp_path):
    """`bucketOf` keys are `<partId>#<index>` and so are guessable, and
    `assemble_findings.apply_agent_merges` applies the identical rule to the part file — so
    a hallucinated cross-bucket merge is accepted by both sides and a real finding
    disappears from REPORT.md with nothing flagged. Asserting only that `bucketOf` is
    POPULATED leaves the guard replaceable with `if (false)`."""
    got = run(
        tmp_path,
        _colliding(
            dedup={
                "merges": [
                    {"primary": "review-unit-01#0", "duplicates": ["review-unit-02#0"]},
                ]
            }
        ),
    )
    assert got["ok"] is True, got.get("error")
    assert any("rejected cross-bucket merge" in line for line in got["logs"]), got["logs"]
    assert got["result"]["stats"]["merged"] == 0
    assert got["result"]["stats"]["primaries"] == 4


def test_a_merge_inside_one_bucket_is_applied_and_counted(tmp_path):
    """The other half: the guard must not reject what the agent WAS shown, or the whole
    phase is dead code that no `if (false)` mutation could distinguish."""
    got = run(
        tmp_path,
        _colliding(
            dedup={
                "merges": [
                    {"primary": "review-unit-01#0", "duplicates": ["review-unit-01#1"]},
                ]
            }
        ),
    )
    assert got["ok"] is True, got.get("error")
    assert not any("rejected cross-bucket merge" in line for line in got["logs"])
    assert got["result"]["stats"]["merged"] == 1
    assert got["result"]["stats"]["primaries"] == 3


def test_the_deterministic_merges_run_before_the_agent_does(tmp_path):
    """`tier1` and `autoMergeNearby` are tested directly; this is what covers their CALL
    SITES. Replacing those with `new Map()` and `0` otherwise leaves the whole suite green
    while the deterministic half of dedup is off and every pair goes to an agent instead."""
    # Same (file, line, bug_class) and DIFFERENT functions, so only tier 1 can merge this
    # pair — `autoMergeNearby` needs one function and would otherwise mask the mutation.
    got = run(
        tmp_path,
        {
            "review:unit-01": review(
                [finding(line=10, function="fa"), finding(line=10, function="fb")]
            ),
            "review:unit-02": review([finding(file="src/b.c", line=100, function="fc")]),
        },
    )
    assert got["ok"] is True, got.get("error")
    assert got["result"]["stats"]["merged"] == 1
    assert got["result"]["stats"]["auto_merged"] == 0
    assert got["result"]["stats"]["primaries"] == 2
    # Deterministically, with no agent: the pair never reaches a prompt, which is the whole
    # point of running tier 1 before `collisionBuckets`.
    assert not any(c["label"] == "dedup" for c in got["calls"])


def test_nearby_findings_in_one_function_are_merged_without_an_agent(tmp_path):
    got = run(
        tmp_path,
        {
            "review:unit-01": review(
                [finding(line=10, function="fa"), finding(line=12, function="fa")]
            ),
            "review:unit-02": review([finding(file="src/b.c", line=100, function="fc")]),
        },
    )
    assert got["result"]["stats"]["auto_merged"] == 1
    assert got["result"]["stats"]["merged"] == 1


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
