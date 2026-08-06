# Recovery Mechanisms

Lookup table for Stage 1d (recovery) and Stage 3 challenge 2. **Many "crash"
findings are error responses.** Answer one question: at the panic/exception site,
does anything in the call stack catch it, and what impact actually survives?

Do not assume recovery is absent because you did not find it. A process-crash
claim needs positive evidence that nothing recovers.

---

## Summary table

The fastest path to an answer. Everything below this table is elaboration.

| Runtime / framework | Default behavior on panic or uncaught exception | Surviving impact | How to confirm |
|---|---|---|---|
| Go `net/http` | **Per-connection `recover()` in `conn.serve`** | That one connection is closed. **No status is written** — not a 500 | Handler panic does not stop the server; the client sees a dropped connection |
| Go Gin | Recovery middleware, included in `gin.Default()` | 500 | Check whether `gin.New()` was used instead |
| Go, general | No recovery unless `defer`/`recover` | Process crash | `grep -rn 'defer func' \| grep -A3 recover` |
| Rust, general | No recovery unless `catch_unwind` | Process crash | `grep -rn catch_unwind` |
| Rust Actix-web | **No default panic recovery** | Worker thread dies | Check for panic middleware |
| Node.js Express | Depends on an error-handling middleware being registered | Varies | Look for `app.use((err, req, res, next) =>` |
| Node.js, general | Uncaught exception terminates unless a handler exists | Process exit | `grep -rn uncaughtException` |
| Python Flask | Built-in error handler | 500 | Default behavior |
| Python Django | Middleware catches exceptions | 500 | Default behavior |
| Java Spring Boot | `@ExceptionHandler` / `@ControllerAdvice` | 500 | Check for a global advice class |
| C# / ASP.NET | Exception filter pipeline | 500 | Built-in middleware |
| WebAssembly | Trapped at the VM boundary | Call fails, host survives | Cannot escape the VM |
| Docker container | Container exits, restart policy applies | Restart, brief unavailability | `docker inspect` restart policy |
| Subprocess | Child exits, parent observes | Isolated failure | Parent's `subprocess` handling |

---

## The two facts that most often flip a Critical to a Low

**Go's `net/http` recovers per connection.** A panic inside an HTTP handler is
caught by the deferred `recover()` in `conn.serve`, which logs the stack and
**closes that connection**. A finding written up as "remote attacker crashes the
server" is, in almost every `net/http` service, one dropped connection while the
server keeps accepting and answering everything else.

Be precise about what the client sees: `conn.serve` writes **no HTTP status**.
Saying it "returns a 500" is a plausible-sounding error, and an eval grader in
this plugin's own history demanded it — scoring six correct answers as failures
before anyone re-read the grader. Flask and Django *do* return a 500; `net/http`
does not.

**`recover()` does not cross goroutine boundaries.** The inverse of the above,
and the reason the same codebase can contain both a Low and a Critical. A panic
inside `go func() { ... }()` with no `recover()` *in that goroutine* takes down
the process, no matter what the enclosing handler does.

---

## Patterns that are usually false positives

- **"Panic in a Go HTTP handler crashes the server."** `net/http` catches it.
  Request error, not server crash.
- **"An exception in a Flask view crashes the server."** Flask's error handler
  catches it. 500, not a crash.
- **"A Rust panic always crashes."** Only without `catch_unwind`. Check.

## Patterns that are usually real crashes

- **Go panic in an unrecovered goroutine** — `recover()` does not reach it.
- **Rust panic with no `catch_unwind`** on the path — unwinds and aborts.
- **Node.js uncaught exception with no `uncaughtException` handler.**
- **Panic in `init()` or startup** — recovery is not installed yet.
- **C/C++ segfault** — a signal, not an exception; nothing catches it by default.

---

## Verification checklist before claiming "process crash"

- [ ] Panic location identified (file:line)
- [ ] Execution path traced from entry point to the panic
- [ ] Call stack searched for recovery code
- [ ] Framework defaults checked against the table above
- [ ] Confirmed not inside a handler that the framework recovers
- [ ] Process isolation considered (container, subprocess, worker)
- [ ] Goroutine boundaries checked, if Go
- [ ] Crash actually observed in a dev environment

**If any of these is uncertain, mark NEEDS_VERIFICATION and do not claim a
process crash.** Downgrade to the impact you can evidence.

---

## When the runtime is not in the table

1. Identify the runtime and the web framework, including version.
2. Search for the recovery primitive by name — `recover`, `catch_unwind`,
   `uncaughtException`, `errorhandler`, `ControllerAdvice`. Search for the
   primitive, not for generic `try`/`except`, which matches everything and
   tells you nothing.
3. Read the framework's request-dispatch path: recovery, when it exists, is
   almost always installed there rather than in application code.
4. Confirm empirically. Trigger the condition in a dev environment and observe
   whether the process is still serving afterwards.

Add a row to the table when you resolve a runtime it does not cover.
