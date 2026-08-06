#!/usr/bin/env python3
"""Build a SYNTHETIC stream capture so the regrade path can be verified offline.

The regrade assertions must themselves be tested before a real capture exists,
otherwise the first live run is debugging both the workflow and the harness at
once. This writes a capture in the documented stream-json shape describing eval
case 2: the payload is blocked two validation layers above the apparent sink, so
the correct outcome is NOT_EXPLOITABLE with no PoC written.

`run.meta.json` records `synthetic: true`. test_regrade.py asserts on that field
so a synthetic fixture can never be mistaken for a recorded live run.

Regenerate:
    uv run --no-project python plugins/concept-prover/tests/fixtures/make_synthetic_capture.py
"""

from __future__ import annotations

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent

VERIFY_ID = "toolu_verify_01"
REVIEW_ID = "toolu_review_01"

VERIFY_RESULT = {
    "status": "NOT_EXPLOITABLE",
    "reason": "blocked at layer-1 (search.py:20), layer-2 (search.py:27)",
    "layers": [
        {
            "layer": "layer-1",
            "location": "search.py:20",
            "verdict": "BLOCKS",
            "evidence": "ALLOWED_TERM = re.compile(r'\\A[A-Za-z0-9 _-]{1,64}\\Z') rejects quotes",
        },
        {
            "layer": "layer-2",
            "location": "search.py:27",
            "verdict": "BLOCKS",
            "evidence": "_dispatch_search rejects any of \"';\\\\-- before run_query is reached",
        },
    ],
    "recovery": {
        "recoveryExists": False,
        "effectiveImpact": "none; the payload never reaches the sink",
        "evidence": "no try/except around run_query",
    },
    "threat": {
        "inScope": "YES",
        "byDesign": False,
        "byDesignIndicators": 0,
        "evidence": "search module is the declared scope",
    },
}


def assistant_tool_use(tool_id: str, name: str, tool_input: dict) -> dict:
    return {
        "type": "assistant",
        "message": {
            "role": "assistant",
            "content": [{"type": "tool_use", "id": tool_id, "name": name, "input": tool_input}],
        },
    }


def tool_result(tool_id: str, payload: dict) -> dict:
    return {
        "type": "user",
        "message": {
            "role": "user",
            "content": [
                {
                    "type": "tool_result",
                    "tool_use_id": tool_id,
                    "content": [{"type": "text", "text": json.dumps(payload)}],
                }
            ],
        },
    }


def subagent_text(parent: str, text: str) -> dict:
    return {
        "type": "assistant",
        "parent_tool_use_id": parent,
        "message": {"role": "assistant", "content": [{"type": "text", "text": text}]},
    }


def assistant_text(text: str) -> dict:
    return {
        "type": "assistant",
        "message": {"role": "assistant", "content": [{"type": "text", "text": text}]},
    }


def build_events() -> list[dict]:
    return [
        {"type": "system", "subtype": "init", "tools": ["Workflow", "Read", "Grep"]},
        assistant_text(
            "Phase 1 intake: search.py:35 builds SQL by concatenation. Entry point is "
            "handle_search. Enumerating validation layers before dispatching."
        ),
        assistant_tool_use(
            VERIFY_ID,
            "Workflow",
            {
                "name": "concept-prover:verify-attack-path",
                "args": {
                    "baseDir": "plugins/concept-prover/skills/concept-prover",
                    "finding": {"summary": "SQL injection in search", "sink": "search.py:35"},
                    "entryPoint": {"location": "search.py:16", "payload": "' UNION SELECT 1--"},
                    "layers": [
                        {"name": "layer-1", "location": "search.py:20"},
                        {"name": "layer-2", "location": "search.py:27"},
                    ],
                    "scope": "search module",
                },
            },
        ),
        subagent_text(
            VERIFY_ID,
            "Layer 1 at search.py:20 applies ALLOWED_TERM, an anchored allowlist of "
            "[A-Za-z0-9 _-]{1,64}. The payload contains a single quote, so it is rejected. "
            "Verdict: BLOCKS.",
        ),
        subagent_text(
            VERIFY_ID,
            "Layer 2 at search.py:27 rejects any of \"';\\-- independently of layer 1. "
            "Verdict: BLOCKS.",
        ),
        tool_result(VERIFY_ID, {"status": "async_launched", "result": VERIFY_RESULT}),
        assistant_text(
            "verify-attack-path returned NOT_EXPLOITABLE. The payload is blocked at "
            "search.py:20 and again at search.py:27, so run_query is only ever reached with "
            "[A-Za-z0-9 _-] input. No PoC will be written.\n\n"
            "⛔ CHECKPOINT FAILED: [Phase 2.2 - Validation Layer Enumeration]\n"
            "Reason: payload blocked at search.py:20 and search.py:27\n"
            "Status: BLOCKED"
        ),
        {
            "type": "result",
            "subtype": "success",
            "is_error": False,
            "num_turns": 4,
            "total_cost_usd": 0.42,
        },
    ]


def main() -> None:
    stream = HERE / "run.stream.jsonl"
    meta = HERE / "run.meta.json"

    # Never clobber a recorded run with a synthetic one. A real capture cost
    # money and found bugs a hand-written fixture cannot.
    if meta.exists():
        existing = json.loads(meta.read_text())
        if existing.get("synthetic") is False:
            raise SystemExit(
                f"refusing to overwrite: {meta} records a REAL run "
                f"(cli {existing.get('cli_version')!r}, cost "
                f"${existing.get('cost_usd')}). Move it aside first if you really "
                f"mean to replace it with a synthetic fixture."
            )
    with stream.open("w") as fh:
        for ev in build_events():
            fh.write(json.dumps(ev) + "\n")
    meta.write_text(
        json.dumps(
            {
                "cli_version": "synthetic",
                "model": "synthetic",
                "effort": "synthetic",
                "exit_status": 0,
                "runs": 0,
                "passed": None,
                "synthetic": True,
                "note": (
                    "SYNTHETIC fixture. Proves the regrade assertions fire; proves nothing "
                    "about the workflow. Replace by running tests/capture-run.sh."
                ),
            },
            indent=2,
        )
        + "\n"
    )
    print(f"wrote {stream} and {meta}")


if __name__ == "__main__":
    main()
