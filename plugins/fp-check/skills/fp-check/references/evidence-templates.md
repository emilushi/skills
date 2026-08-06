# Evidence Templates

Two templates, both still reached. This file used to carry four; the two that went
were a pseudocode-PoC skeleton and a devil's-advocate write-up form, and both
belonged to a pipeline that no longer exists. Stage 3 builds and executes real
PoCs rather than sketching them, and the adversarial pass returns a schema-checked
object rather than filling in a form. A template nothing consumes is not neutral —
it is an invitation to produce the artefact it describes instead of the one the
stage actually wants.

## Algebraic bounds proof

Handed to the deep-route `math-bounds` agent, and the thing fp-check's Gate 5 is
graded on. The form is a chain of substitutions ending in a verdict, not prose
about the bounds being "probably fine".

```
Claim: operation X is vulnerable to [overflow | underflow | bounds violation]
Given: [every validation condition on the path, each with its file:line]
Given: [every constant, with its definition site]

  1. [first validated relation]
  2. [constant]
  3. [derived inequality]
  ...
  N. Therefore: [the vulnerable condition is reachable | impossible]  (Q.E.D.)
```

Worked example, and the shape of a **BLOCKS** verdict:

```
Given: validation at packet.c:98 ensures (input_size >= MIN_SIZE)
Given: MIN_SIZE = 16      (packet.h:12)
Given: header_size = 8    (packet.h:13)
Prove: (input_size - header_size) cannot underflow

  1. input_size >= MIN_SIZE            (validation, packet.c:98)
  2. MIN_SIZE = 16                     (constant)
  3. header_size = 8                   (constant)
  4. input_size >= 16                  (substitute 2 into 1)
  5. input_size - 8 >= 16 - 8          (subtract 3 from both sides)
  6. input_size - header_size >= 8     (simplify)
  7. Therefore: underflow impossible   (Q.E.D.)
```

Two rules that decide whether the proof is worth anything:

- **Cite where each `Given` comes from.** A premise with no `file:line` is an
  assumption, and a proof built on an assumed constraint proves nothing about the
  code. The most common failure is asserting a validation that is not on the path
  the attacker takes.
- **A missing premise is not a licence to conclude either way.** If the range of
  an input cannot be established, that is `UNCERTAIN`, not "unbounded, therefore
  vulnerable". Inventing an unbounded input is how a bounds finding gets reported
  against code that validates upstream.

If the finding is not arithmetic, return `UNCERTAIN` and say so. Manufacturing
algebra for a logic bug produces a confident-looking proof of nothing.

## Data flow

Handed to no agent by name — the layer agents are each given one layer and asked
for the code — but this is the form the *orchestrator* should use to enumerate
`layers[]` before dispatching, and getting it wrong is the single most consequential
dispatch error: Stage 1 spends one agent per entry in that list, and a layer left
out is a layer nothing inspects.

```
Source: [entry point, file:line] — trust level: [untrusted | trusted]
Path:   Source → check1[file:line] → transform[file:line] → sink[file:line]
Layers to dispatch, in path order:
  - name: [what the check is called]
    location: [file:line of the check itself, not of the sink]
    checks: [the condition it enforces]
```

`location` is the check's own line. Pointing it at the sink gives the layer agent
the wrong code to read and it will report `UNCERTAIN` — correctly, since it was
shown something that validates nothing.

**If nothing validates the path, say so as one explicit layer.** An empty list is
rejected before any agent runs: a forgotten field and a deliberate "nothing guards
this" are the same value, and the second is a claim that deserves checking.
