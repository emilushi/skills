"""Detect an arm that used an oracle, and invalidate it rather than annotate it.

Three reviewers in the previous evaluation looked the answer up. One diffed against
upstream and reported the corpus as byte-identical to a named release; four of five
of that run's ground-truth hits came from it. Prompt text forbidding it did not
work, which is why the corpora are now ours and privately injected — but a defence
you cannot measure is a defence you do not have, so this scans what the arms
actually did.

**The distinction that matters.** The string `WebFetch` appears in almost every
transcript as a *tool definition*: the harness tells the model which tools exist,
and the arm packet itself says not to use them. A substring grep therefore flags
every arm, including the honest ones, and an anti-cheat check that always fires is
one that gets switched off. So nothing here greps raw text. Transcripts are parsed
as JSON and only `{"type": "tool_use"}` content blocks count as use. Definitions are
counted too — separately, and reported — because a run in which zero tools were
defined and zero invoked is a transcript this scanner failed to understand, and that
must fail loudly rather than pass quietly.

Two severities:

- **violation** — disqualifying, and the arm's numbers are excluded from the
  comparison: an oracle tool invoked, a network binary run, the harness's own
  answer key read, or external sources declared by the arm itself.
- **advisory** — worth a human's eye, never disqualifying on its own: an oracle
  hostname or a CVE id mentioned in text, a `git` subcommand that reads nothing
  outside the tree.

Precision is bought with structure, not with cleverness: a Bash command is split on
shell separators and only the *first token* of each segment is matched against the
network-binary list, so `grep -rn curl .` and a file called `wget-notes.txt` do not
fire.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

# Tool names that reach outside the machine. Anything MCP-shaped that looks like a
# fetch, a search or a browser is treated the same way: this is a benchmark, and a
# tool that can read the internet can read a project's advisories.
ORACLE_TOOLS = {"webfetch", "websearch"}
ORACLE_MCP_HINTS = (
    "web_search",
    "web_fetch",
    "websearch",
    "webfetch",
    "browser",
    "search_exa",
    "fetch_url",
)

NETWORK_BINARIES = {
    "curl",
    "wget",
    "nc",
    "ncat",
    "netcat",
    "telnet",
    "ssh",
    "scp",
    "sftp",
    "rsync",
    "ftp",
    "lynx",
    "links",
    "w3m",
    "http",
    "httpie",
    "aria2c",
    "youtube-dl",
    "svn",
    "hg",
    "cvs",
    "brew",
    "apt",
    "apt-get",
    "yum",
    "dnf",
    "pacman",
}
# Subcommands that reach a remote, or that read a history the corpus does not have.
GIT_REMOTE_SUBCOMMANDS = {"clone", "fetch", "pull", "remote", "ls-remote", "archive", "submodule"}
GIT_HISTORY_SUBCOMMANDS = {
    "log",
    "show",
    "diff",
    "blame",
    "checkout",
    "describe",
    "tag",
    "shortlog",
}
GH_SUBCOMMANDS = {"pr", "api", "repo", "issue", "release", "search", "gist", "browse"}
PACKAGE_FETCH = {
    ("pip", "download"),
    ("pip", "install"),
    ("npm", "view"),
    ("npm", "install"),
    ("uv", "pip"),
}

ORACLE_HOSTS = (
    "raw.githubusercontent.com",
    "github.com",
    "codeload.github.com",
    "gitlab.com",
    "bitbucket.org",
    "sourceforge.net",
    "savannah.gnu.org",
    "nvd.nist.gov",
    "cve.mitre.org",
    "cve.org",
    "cvedetails.com",
    "openwall.com",
    "seclists.org",
    "bugzilla",
    "sourceware.org",
    "googlesource.com",
    "kernel.org",
    "pypi.org",
    "npmjs.com",
    "crates.io",
    "debian.org",
    "ubuntu.com",
    "redhat.com",
)

# Paths that hold the answer key. The corpus tree never contains any of these, so a
# read is either a wrong turn or a look at the answers; either way the number is not
# a measurement.
# Anchored deliberately tightly. A first version matched `[-/]private/`, intending the
# harness's `<variant>-private/` directory, and matched macOS's `/private/tmp/...` — which
# is where the corpus itself lives. Every legitimate read of the code under review was
# reported as a violation, and the first real arm run scored INVALID for doing its job.
# An over-triggering integrity check is worse than none: it gets switched off.
ANSWER_KEY_PATTERNS = (
    re.compile(r"ground_truth\.json"),
    re.compile(r"verified\.json"),
    re.compile(r"maps\.json"),
    re.compile(r"recipe\.json"),
    # `bench-private/`, `control-private/`: the answer-key directory convention. The
    # trailing slash and the `-` prefix are both required, so `/private/tmp` is not it.
    re.compile(r"[A-Za-z0-9_.]+-private/"),
    # The harness's own source, not a corpus directory that happens to be called tests/.
    re.compile(r"c-review/bench/(?:lib|corpora|arms|tests|judge_bench)/"),
    re.compile(r"c-review/bench/(?:README\.md|bench\.py)"),
    re.compile(r"\bC-REVIEW-EVALUATION\.md\b"),
)

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{3,7}\b", re.IGNORECASE)
SPLIT_RE = re.compile(r"(?:\|\||&&|[;|\n&])")
ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


class AntiCheatError(Exception):
    """The scan could not inspect anything. Callers exit non-zero."""


def _content_blocks(record: Any) -> list[dict[str, Any]]:
    """Every content block in one transcript record, whatever shape it arrived in."""
    blocks: list[dict[str, Any]] = []
    if not isinstance(record, dict):
        return blocks
    for holder in (record, record.get("message")):
        if not isinstance(holder, dict):
            continue
        content = holder.get("content")
        if isinstance(content, list):
            blocks += [b for b in content if isinstance(b, dict)]
    return blocks


def _defined_tools(record: Any) -> list[str]:
    """Tool *names offered* to the model, which are never evidence of use."""
    if not isinstance(record, dict):
        return []
    names: list[str] = []
    for key in ("tools", "availableTools", "allowed_tools", "allowedTools"):
        value = record.get(key)
        if isinstance(value, list):
            names += [str(v.get("name") if isinstance(v, dict) else v) for v in value]
    return names


def _segments(command: str) -> list[list[str]]:
    out: list[list[str]] = []
    for chunk in SPLIT_RE.split(command):
        tokens = [t for t in chunk.strip().split() if t]
        while tokens and (
            ASSIGN_RE.match(tokens[0]) or tokens[0] in {"sudo", "env", "time", "nohup", "exec"}
        ):
            tokens = tokens[1:]
        if tokens:
            out.append(tokens)
    return out


def _classify_bash(command: str) -> list[tuple[str, str]]:
    """(severity, why) for one Bash command, matching only on command position."""
    found: list[tuple[str, str]] = []
    for tokens in _segments(command):
        binary = Path(tokens[0].strip("'\"")).name
        sub = tokens[1] if len(tokens) > 1 else ""
        if binary in NETWORK_BINARIES:
            found.append(("violation", f"ran network binary `{binary}`"))
        elif binary == "git" and sub in GIT_REMOTE_SUBCOMMANDS:
            found.append(("violation", f"ran `git {sub}`"))
        elif binary == "git" and sub in GIT_HISTORY_SUBCOMMANDS:
            found.append(
                ("advisory", f"ran `git {sub}`; the corpus tree has no history of its own")
            )
        elif binary == "gh" and sub in GH_SUBCOMMANDS:
            found.append(("violation", f"ran `gh {sub}`"))
        elif (binary, sub) in PACKAGE_FETCH:
            found.append(("violation", f"ran `{binary} {sub}`"))
    return found


def _classify_tool(name: str, payload: str) -> list[tuple[str, str]]:
    lowered = name.lower()
    found: list[tuple[str, str]] = []
    if lowered in ORACLE_TOOLS or any(hint in lowered for hint in ORACLE_MCP_HINTS):
        found.append(("violation", f"invoked oracle tool `{name}`"))
    for pattern in ANSWER_KEY_PATTERNS:
        match = pattern.search(payload)
        if match:
            found.append(
                ("violation", f"`{name}` touched the harness answer key ({match.group(0)})")
            )
            break
    if lowered not in ORACLE_TOOLS:
        for host in ORACLE_HOSTS:
            if host in payload.lower():
                found.append(("advisory", f"`{name}` input mentions {host}"))
                break
    return found


def scan_transcripts(paths: list[Path]) -> dict[str, Any]:
    """Parse every transcript and classify every tool invocation in it."""
    files: list[Path] = []
    for path in paths:
        if path.is_dir():
            files += sorted(path.rglob("*.jsonl"))
        elif path.is_file():
            files.append(path)
    if not files:
        raise AntiCheatError(
            f"no transcripts found in {[str(p) for p in paths]}. The anti-cheat gate cannot "
            f"clear an arm it never inspected; point --transcript at the session JSONL."
        )

    violations: list[dict[str, Any]] = []
    advisories: list[dict[str, Any]] = []
    invocations = 0
    definitions = 0
    parsed = 0
    unparsed = 0
    cve_mentions: set[str] = set()

    for file in files:
        for number, raw in enumerate(
            file.read_text(encoding="utf-8", errors="replace").splitlines(), 1
        ):
            raw = raw.strip()
            if not raw:
                continue
            try:
                record = json.loads(raw)
            except json.JSONDecodeError:
                unparsed += 1
                continue
            parsed += 1
            definitions += len(_defined_tools(record))
            for block in _content_blocks(record):
                if block.get("type") == "text":
                    cve_mentions |= {m.upper() for m in CVE_RE.findall(str(block.get("text", "")))}
                    continue
                if block.get("type") != "tool_use":
                    continue
                invocations += 1
                name = str(block.get("name", "?"))
                payload = json.dumps(block.get("input", {}), ensure_ascii=False)
                hits = _classify_tool(name, payload)
                if name.lower() == "bash":
                    hits += _classify_bash(str((block.get("input") or {}).get("command", "")))
                for severity, why in hits:
                    entry = {
                        "transcript": str(file),
                        "line": number,
                        "tool": name,
                        "why": why,
                        "input": payload[:400],
                    }
                    (violations if severity == "violation" else advisories).append(entry)

    if parsed == 0:
        raise AntiCheatError(
            f"parsed zero JSON records from {len(files)} transcript file(s) "
            f"({unparsed} unparseable "
            f"line(s)). The scan inspected nothing, which is not the same as finding nothing."
        )
    if invocations == 0:
        raise AntiCheatError(
            f"found zero tool invocations across {len(files)} transcript file(s) but "
            f"{definitions} tool definition(s). Either the wrong file was passed or the format "
            f"changed; an arm that called no tools cannot have reviewed any code."
        )

    return {
        "transcripts": [str(f) for f in files],
        "records_parsed": parsed,
        "records_unparseable": unparsed,
        "tool_definitions_seen": definitions,
        "invocations_seen": invocations,
        "violations": violations,
        "advisories": advisories,
        "cve_mentioned_in_text": sorted(cve_mentions),
    }


def assess(scan: dict[str, Any], declared: dict[str, Any] | None = None) -> dict[str, Any]:
    """Fold the transcript scan and the arm's own declaration into one verdict."""
    violations = list(scan["violations"])
    if declared and declared.get("external_sources_consulted"):
        violations.append(
            {
                "transcript": "(self-declared)",
                "line": 0,
                "tool": "declaration",
                "why": "the arm declared it consulted sources outside the corpus",
                "input": str(declared.get("external_sources_detail", ""))[:400],
            }
        )
    verdict = "INVALID" if violations else "VALID"
    return {**scan, "violations": violations, "verdict": verdict}


def format_assessment(assessment: dict[str, Any]) -> str:
    lines = [
        f"anti-cheat: {assessment['verdict']} — {assessment['invocations_seen']} "
        f"tool invocation(s) "
        f"inspected across {len(assessment['transcripts'])} transcript(s); "
        f"{assessment['tool_definitions_seen']} tool definition(s) seen and not counted as use",
    ]
    for violation in assessment["violations"]:
        lines.append(
            f"  VIOLATION {violation['why']} "
            f"({Path(violation['transcript']).name}:{violation['line']})"
        )
        lines.append(f"    {violation['input'][:200]}")
    for advisory in assessment["advisories"][:10]:
        lines.append(
            f"  advisory  {advisory['why']} "
            f"({Path(advisory['transcript']).name}:{advisory['line']})"
        )
    if assessment["cve_mentioned_in_text"]:
        lines.append(
            "  advisory  CVE id(s) mentioned in prose: "
            + ", ".join(assessment["cve_mentioned_in_text"][:6])
            + " — every bug in these corpora is ours, so no CVE can describe one"
        )
    return "\n".join(lines)
