# Data Extension YAML Format

YAML format for CodeQL data extension files. Used by the create-data-extensions workflow to model project-specific sources, sinks, and flow summaries.

## Structure

All extension files follow this structure:

```yaml
extensions:
  - addsTo:
      pack: codeql/<language>-all  # Target library pack
      extensible: <model-type>      # sourceModel, sinkModel, summaryModel, neutralModel
    data:
      - [<columns>]
```

## Source Models

Columns: `[package, type, subtypes, name, signature, ext, output, kind, provenance]`

| Column | Description | Example |
|--------|-------------|---------|
| package | Module/package path | `myapp.auth` |
| type | Class or module name | `AuthManager` |
| subtypes | Include subclasses | `True` (Java: capitalized) / `true` (Python/JS/Go) |
| name | Method name | `get_token` |
| signature | Method signature (optional) | `""` (Python/JS), `"(String,int)"` (Java) |
| ext | Extension (optional) | `""` |
| output | What is tainted | `ReturnValue`, `Parameter[0]` (Java) / `Argument[0]` (Python/JS/Go) |
| kind | Source category | `remote`, `local`, `file`, `environment`, `database` |
| provenance | How model was created | `manual` |

**Java-specific format differences:**
- **subtypes**: Use `True` / `False` (capitalized, Python-style), not `true` / `false`
- **output for parameters**: Use `Parameter[N]` (not `Argument[N]`) to mark method parameters as sources
- **signature**: Required for disambiguation — use Java type syntax: `"(String)"`, `"(String,int)"`
- **Parameter ranges**: Use `Parameter[0..2]` to mark multiple consecutive parameters

Example (Python):

```yaml
# $OUTPUT_DIR/extensions/sources.yml
extensions:
  - addsTo:
      pack: codeql/python-all
      extensible: sourceModel
    data:
      - ["myapp.http", "Request", true, "get_param", "", "", "ReturnValue", "remote", "manual"]
      - ["myapp.http", "Request", true, "get_header", "", "", "ReturnValue", "remote", "manual"]
```

Example (Java — note `True`, `Parameter[N]`, and signature):

```yaml
# $OUTPUT_DIR/extensions/sources.yml
extensions:
  - addsTo:
      pack: codeql/java-all
      extensible: sourceModel
    data:
      - ["com.myapp.controller", "ApiController", True, "search", "(String)", "", "Parameter[0]", "remote", "manual"]
      - ["com.myapp.service", "FileService", True, "upload", "(String,String)", "", "Parameter[0..1]", "remote", "manual"]
```

## Sink Models

Columns: `[package, type, subtypes, name, signature, ext, input, kind, provenance]`

Note: column 7 is `input` (which argument receives tainted data), not `output`.

| Kind | Vulnerability |
|------|---------------|
| `sql-injection` | SQL injection |
| `command-injection` | Command injection |
| `path-injection` | Path traversal |
| `xss` | Cross-site scripting |
| `code-injection` | Code injection |
| `ssrf` | Server-side request forgery |
| `unsafe-deserialization` | Insecure deserialization |

Example (Python):

```yaml
# $OUTPUT_DIR/extensions/sinks.yml
extensions:
  - addsTo:
      pack: codeql/python-all
      extensible: sinkModel
    data:
      - ["myapp.db", "Connection", true, "raw_query", "", "", "Argument[0]", "sql-injection", "manual"]
      - ["myapp.shell", "Runner", false, "execute", "", "", "Argument[0]", "command-injection", "manual"]
```

Example (Java — note `True` and `Argument[N]` for sink input):

```yaml
extensions:
  - addsTo:
      pack: codeql/java-all
      extensible: sinkModel
    data:
      - ["com.myapp.db", "QueryRunner", True, "execute", "(String)", "", "Argument[0]", "sql-injection", "manual"]
```

## Summary Models

Columns: `[package, type, subtypes, name, signature, ext, input, output, kind, provenance]`

| Kind | Description |
|------|-------------|
| `taint` | Data flows through, still tainted |
| `value` | Data flows through, exact value preserved |

Example:

```yaml
# $OUTPUT_DIR/extensions/summaries.yml
extensions:
  # Pass-through: taint propagates
  - addsTo:
      pack: codeql/python-all
      extensible: summaryModel
    data:
      - ["myapp.cache", "Cache", true, "get", "", "", "Argument[0]", "ReturnValue", "taint", "manual"]
      - ["myapp.utils", "JSON", false, "parse", "", "", "Argument[0]", "ReturnValue", "taint", "manual"]

```

## Neutral Models

Columns: `[package, type, name, signature, kind, provenance]` (6 columns, NOT the 10-column `summaryModel` format).

Use `neutralModel` to explicitly block taint propagation through known-safe functions.

Example:

```yaml
  - addsTo:
      pack: codeql/python-all
      extensible: neutralModel
    data:
      - ["myapp.security", "Sanitizer", "escape_html", "", "summary", "manual"]
```

**`neutralModel` vs no model:** If a function has no model at all, CodeQL may still infer flow through it. Use `neutralModel` to explicitly block taint propagation through known-safe functions.

## C/C++

C/C++ differs from every other language in three ways that all fail silently. Read this section
before writing a single `cpp` row.

**Source of truth is `.packinfo`, not the `.qll` files.** Every downloaded pack carries a
`.packinfo` at its root whose `extensible_predicate_metadata` block names each extensible
predicate with its exact columns and types. It answers "what can I model in this language, and
with which columns" for any pack, and unlike a hand-copied column list it cannot drift from the
implementation:

```bash
PACK=$(ls -d ~/.codeql/packages/codeql/cpp-all/*/ 2>/dev/null | sort -V | tail -1)
[ -n "$PACK" ] || { echo "ERROR: cpp-all not downloaded" >&2; exit 1; }

python3 -c '
import json, sys
meta = json.load(open(sys.argv[1]))["extensible_predicate_metadata"]["extensible_predicates"]
if not meta:
    sys.exit("ERROR: no extensible predicates in .packinfo — wrong pack or wrong key")
for e in meta:
    print(e["name"], "(" + ", ".join(p["name"] for p in e["parameters"]) + ")")
' "$PACK/.packinfo"
```

Swap `cpp-all` for `java-all`, `go-all`, or any other language pack to get the same answer —
it is how you confirm the allocation predicates really are C/C++-only.

### 1. Column 1 is `namespace`, not `package`

Use `""` for global C functions, and the C++ namespace — `::`-separated — for namespaced code.
The `type` column holds the class and is `""` for free functions. When `type` is `""`, `subtypes`
**must** be `False`.

Real `sourceModel` rows from `codeql/cpp-all`, showing both shapes:

```yaml
# global C function: namespace "", type "", subtypes False
- ["", "", False, "getc", "", "", "ReturnValue", "remote", "manual"]
# namespaced class method: subtypes True to also match subclasses
- ["Azure::Core::Http", "RawResponse", True, "GetBody", "", "", "ReturnValue[*]", "remote", "manual"]
```

Namespaced free functions take the namespace in column 1 and leave `type` blank — the shipped
models carry `std` and `bsl` variants of the `libc` entry points this way.

C/C++ writes `True`/`False` capitalized, as Java does. `signature` must be stripped of template
names — write `(const vector &)`, not `(const vector<T> &)`.

### 2. Indirection: the star is not optional

For pointers and buffers the taint is in the pointed-to memory, not the pointer value.
`Argument[*N]` selects the first indirection; `ReturnValue[*]` the same for a returned buffer.
Omitting the star produces a row that validates, loads, and matches nothing.

| Syntax | Selects |
|--------|---------|
| `Argument[0]` | The argument value itself (a scalar, or the pointer as a number) |
| `Argument[*0]` | The memory the argument points at — what you almost always want for `char *` |
| `Argument[-1]` | The qualifier, `*this` |
| `Argument[*0..1]` | First indirection of arguments 0 and 1 |
| `ReturnValue` / `ReturnValue[*]` | Returned value / returned buffer contents |
| `Argument[*@0]` | One or more indirections (`@` = an arbitrary but fixed count) |

### 3. Extensible predicates unique to C/C++

`allocationFunctionModel` and `deallocationFunctionModel` exist for no other language. They are
how custom allocators get taught to the use-after-free, double-free, and memory-leak queries.

```yaml
# $OUTPUT_DIR/extensions/allocations.yml
extensions:
  # [namespace, type, subtypes, name, sizeArg, multArg, reallocPtrArg, requiresDealloc]
  # sizeArg/multArg/reallocPtrArg are argument indices written as strings; "" if not applicable.
  - addsTo:
      pack: codeql/cpp-all
      extensible: allocationFunctionModel
    data:
      - ["", "", False, "kmem_alloc", "0", "", "", True]
      - ["", "", False, "g_malloc", "0", "", "", True]
      - ["", "", False, "alloca", "0", "", "", False]   # requiresDealloc False — no matching free

  # [namespace, type, subtypes, name, freedArg]
  - addsTo:
      pack: codeql/cpp-all
      extensible: deallocationFunctionModel
    data:
      - ["", "", False, "kmem_free", "0"]
      - ["", "", False, "pool_put", "1"]                # freed pointer is argument 1, not 0
```

C/C++ also has `barrierModel` (columns as `sourceModel`) and `barrierGuardModel`
(`namespace, type, subtypes, name, signature, ext, input, acceptingValue, kind, provenance`,
where `acceptingValue` is `"true"` or `"false"`) for modelling bounds and validity checks.

### 4. The kind vocabulary is much smaller than the shared list

**A kind that validates is not a kind that works.** Kind validation is shared across all
languages via `codeql/mad`, so `command-injection`, `path-injection`, `xss` and friends are
accepted on a `cpp` row and then consumed by nothing. In `codeql/cpp-all`:

- `sourceNode` consumes **`remote`** and **`local`** only
- `sinkNode` consumes **`remote-sink`** only
- `sql-injection` appears in shipped models and is consumed by the C/C++ SQL injection query
- `summaryModel` uses **`taint`** and **`value`**, as elsewhere

Before relying on any other kind, confirm something consumes it. Two things make this easy to get
wrong. `codeql resolve qlpacks` does **not** enumerate the downloaded package cache, so read the
cache directly. And the consumers are split across two packs: the library pack `cpp-all` defines
`remote-sink`, but every other kind is consumed by a query in `cpp-queries`. **Scanning `cpp-all`
alone returns `remote-sink` and nothing else, which would condemn a perfectly good
`sql-injection` model as dead.**

```bash
CPP_ALL=$(ls -d ~/.codeql/packages/codeql/cpp-all/*/ 2>/dev/null | sort -V | tail -1)
CPP_QUERIES=$(ls -d ~/.codeql/packages/codeql/cpp-queries/*/ 2>/dev/null | sort -V | tail -1)
for p in "$CPP_ALL" "$CPP_QUERIES"; do
  [ -n "$p" ] || {
    echo "ERROR: need both packs; run 'codeql pack download codeql/cpp-all codeql/cpp-queries'" >&2
    exit 1
  }
done

KINDS=$(grep -rhoE 'sinkNode\([^,]+, *"[a-z0-9-]+"' "$CPP_ALL" "$CPP_QUERIES" \
  | grep -oE '"[a-z0-9-]+"' | tr -d '"' | sort -u)

# Both of these are known-consumed: remote-sink by cpp-all's RemoteFlowFromCsvSink, and
# sql-injection by cpp-queries' Security/CWE/CWE-089/SqlTainted.ql. If either is missing,
# the scan has regressed — not your model.
for known in remote-sink sql-injection; do
  echo "$KINDS" | grep -qx "$known" || {
    echo "ERROR: '$known' missing from results — the scan is broken, not your model" >&2
    exit 1
  }
done

echo "$KINDS"
```

The guard is the point. A short list from a broken scan looks exactly like "your kind is not
consumed", and silently wrong advice here costs you a working model. If a kind survives that
check and still is not in the output, it really is dead weight — pick a consumed kind, or write a
custom query instead.

## Language-Specific Notes

**Python:** Use dotted module paths for `package` (e.g., `myapp.db`).

**JavaScript:** `package` is often `""` for project-local code. Use the import path for npm packages.

**Go:** Use full import paths (e.g., `myapp/internal/db`). `type` is often `""` for package-level functions.

**Java:** Use fully qualified package names (e.g., `com.myapp.db`).

**C/C++:** See the [C/C++ section](#cc) above — column 1 is `namespace`, not `package`, and pointer arguments need an indirection star.

## Deploying Extensions

**Known limitation:** `--additional-packs` and `--model-packs` flags do not work with pre-compiled query packs (bundled CodeQL distributions that cache `java-all` inside `.codeql/libraries/`). Extensions placed in a standalone model pack directory will be resolved by `codeql resolve qlpacks` but silently ignored during `codeql database analyze`.

**Workaround — copy extensions into the library pack's `ext/` directory:**

> **Warning:** Files copied into the `ext/` directory live inside CodeQL's managed pack cache. They will be **lost** when packs are updated via `codeql pack download` or version upgrades. After any pack update, re-run this deployment step to restore the extensions.

The lookup is the same for every language — only the pack name changes. `$CODEQL_LANG` is
resolved in Step 2a of the create-data-extensions workflow (`java`, `cpp`, `python`, `go`, …).

```bash
# Find the <lang>-all ext directory used by the query pack
LANG_ALL_EXT=$(find "$(codeql resolve qlpacks 2>/dev/null | grep "${CODEQL_LANG}-queries" | awk '{print $NF}' | tr -d '()')" \
  -path "*/.codeql/libraries/codeql/${CODEQL_LANG}-all/*/ext" -type d 2>/dev/null | head -1)

if [ -n "$LANG_ALL_EXT" ]; then
  PROJECT_NAME=$(basename "$(pwd)")
  for kind in sources sinks summaries allocations; do
    src="$OUTPUT_DIR/extensions/${kind}.yml"
    [ -f "$src" ] && cp "$src" "$LANG_ALL_EXT/${PROJECT_NAME}.${kind}.model.yml"
  done

  # Verify deployment — confirm files landed correctly
  DEPLOYED=$(ls "$LANG_ALL_EXT/${PROJECT_NAME}".*.model.yml 2>/dev/null | wc -l)
  if [ "$DEPLOYED" -gt 0 ]; then
    echo "Extensions deployed to $LANG_ALL_EXT ($DEPLOYED files):"
    ls -la "$LANG_ALL_EXT/${PROJECT_NAME}".*.model.yml
  else
    echo "ERROR: Files were copied but verification failed. Check path: $LANG_ALL_EXT"
  fi
else
  echo "WARNING: Could not find ${CODEQL_LANG}-all ext directory. Extensions may not load."
  echo "Attempted path lookup from: codeql resolve qlpacks | grep ${CODEQL_LANG}-queries"
  echo "Run 'codeql resolve qlpacks' manually to debug."
fi
```

`allocations.yml` only exists for C/C++; the loop skips it everywhere else.

**Alternative (if query packs are NOT pre-compiled):** Use `--additional-packs=./codeql-extensions` with a proper model pack `qlpack.yml`:

```yaml
# $OUTPUT_DIR/extensions/qlpack.yml
name: custom/<project>-extensions
version: 0.0.1
library: true
extensionTargets:
  codeql/<lang>-all: "*"
dataExtensions:
  - sources.yml
  - sinks.yml
  - summaries.yml
  - allocations.yml   # C/C++ only — omit for other languages
```
