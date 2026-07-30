---
name: sarif-parsing
description: >-
  Parses and processes SARIF files from static analysis tools like CodeQL, Semgrep, or other
  scanners. Triggers on "parse sarif", "read scan results", "aggregate findings", "deduplicate
  alerts", or "process sarif output". Handles filtering, deduplication, format conversion, and
  CI/CD integration of SARIF data. Does NOT run scans — use the Semgrep or CodeQL skills for that.
allowed-tools: Bash Read Glob Grep
---

# SARIF Parsing

SARIF 2.1.0 is a published OASIS standard and its shape is unsurprising: `runs[]`, each with
a `tool.driver` and `results[]`, each result carrying a `ruleId`, a `level`, and
`locations[].physicalLocation` with an `artifactLocation.uri` and a `region.startLine`.
Read a file and confirm the shape rather than working from memory of the spec.

What follows is the part that is **not** obvious from the schema: the judgment calls that
decide whether a pipeline built on SARIF is trustworthy.

## Use the shipped helpers

[`resources/sarif_helpers.py`]({baseDir}/resources/sarif_helpers.py) already implements the
tedious parts — `load_sarif`, `extract_findings`, `normalize_path`, `compute_fingerprint`,
`deduplicate`, `diff_findings`, `group_by_*`, `count_by_*`, `to_csv_rows`, `summary`. Import
it rather than rewriting them:

```python
from sarif_helpers import extract_findings, deduplicate, summary

findings = deduplicate(extract_findings(load_sarif("results.sarif")))
print(summary(findings))
```

For one-off questions, jq is faster than writing a script. 40+ ready queries are in
[`resources/jq-queries.md`]({baseDir}/resources/jq-queries.md):

```bash
jq '[.runs[].results[]] | length' results.sarif                   # total findings
jq '[.runs[].results[].ruleId] | unique' results.sarif            # rules that fired
```

Reach for `sarif-tools` (`pip install sarif-tools`) when you want `sarif diff`, `sarif csv`,
or `sarif html` without writing code.

## Zero findings is ambiguous — resolve it before reporting

This is the single most consequential thing about SARIF. **An empty `results[]` is
indistinguishable from a scan that never ran.** Both are valid SARIF, both parse, both count
zero. "Validated successfully, 0 findings" has shipped as a clean bill of health for scans
that analysed nothing.

Before reporting a clean result, confirm the scan actually happened:

```bash
jq '[.runs[] | .tool.driver.name] | unique' results.sarif       # did a tool identify itself?
jq '[.runs[].artifacts // [] | length] | add' results.sarif     # were any files analysed?
jq '.runs[].invocations[]?.executionSuccessful' results.sarif   # did the tool report success?
```

Zero artifacts, or `executionSuccessful: false`, means the scan is broken, not the code. The
same logic applies to any script you write over SARIF: if it counts, filters, or matches,
make it exit non-zero when the count is zero, and say which of the two cases you are in.

## Choosing a fingerprint — the trade-off that matters

Tools report different paths for the same file (`/home/runner/work/repo/src/a.py` in CI,
`/Users/you/repo/src/a.py` locally), so path-based matching fails across environments. That
is why fingerprints hash content rather than location. But the right key depends entirely on
what you are comparing:

| Comparing | Key on | Because |
|---|---|---|
| Two runs in **different environments** (baseline vs PR, local vs CI) | rule + **basename** + snippet | Absolute path prefixes differ and would produce all-new findings |
| Multiple rulesets over the **same checkout** (merging scanner output) | rule + **full path** + line | `src/a/util.py` and `src/b/util.py` are different files; basename would silently merge them |

Getting this backwards is quiet and expensive: too-loose a key drops real findings, too-tight
a key reports every finding as new after a reformat. `compute_fingerprint()` in the helpers
implements the first; the Semgrep skill's `merge_sarif.py` implements the second, and its
test suite pins that distinction.

Prefer a tool's own `partialFingerprints` when present — it is more stable than anything you
can reconstruct — and fall back to a computed key only when absent.

## Other things that bite

- **Line numbers move.** Any fingerprint including `startLine` breaks on reformatting. Include
  the normalized source line instead where you can.
- **Almost every field is optional.** `locations` can be absent, `level` can be missing (SARIF
  defaults to `warning`), `region` can lack `startLine`. Access defensively — `safe_get()` and
  `extract_location()` in the helpers do this.
- **`level` vs `rank` vs tool-specific severity.** SARIF's `level` has four values
  (`error`/`warning`/`note`/`none`). Semgrep's `ERROR`/`WARNING`/`INFO` and CodeQL's
  `security-severity` score live in `properties`. Merging tools means normalizing severity
  explicitly — do not assume `level` alone is comparable across tools.
- **100MB+ files.** Stream with `ijson` (`ijson.items(f, "runs.item.results.item")`) rather
  than `json.load`.

## CI/CD

```yaml
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

Gating a build on findings needs the ambiguity check above first — otherwise a broken scan
becomes a green build:

```bash
jq -e '[.runs[].artifacts // [] | length] | add > 0' results.sarif \
  || { echo "scan analysed no files — failing rather than reporting clean"; exit 1; }
HIGH=$(jq '[.runs[].results[] | select(.level == "error")] | length' results.sarif)
[ "$HIGH" -eq 0 ] || { echo "$HIGH high-severity findings"; exit 1; }
```

## Reference

- [OASIS SARIF 2.1.0 Specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
- [GitHub SARIF support](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning) — the subset GitHub actually ingests
- [SARIF Validator](https://sarifweb.azurewebsites.net/)
- [sarif-tools](https://github.com/microsoft/sarif-tools)
