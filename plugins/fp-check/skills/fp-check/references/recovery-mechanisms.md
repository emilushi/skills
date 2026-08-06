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
| Python, general | Uncaught exception unwinds to the interpreter and exits | Process exit | The absence of `try` is not the question — find the outermost frame |
| Python `asyncio` | **A task that raises dies alone.** The loop keeps running and logs "Task exception was never retrieved" — often only at GC | One task lost, silently | `grep -n 'create_task\|ensure_future'` and check who awaits the result |
| Python `threading` | An exception in a thread kills that thread only | One thread lost | `threading.excepthook`, and whether the thread was doing the only copy of the work |
| Java Spring Boot | `@ExceptionHandler` / `@ControllerAdvice` | 500 | Check for a global advice class |
| Java, general | Uncaught exception kills the thread, not the JVM | One thread lost | `Thread.setDefaultUncaughtExceptionHandler` |
| C# / ASP.NET | Exception filter pipeline | 500 | Built-in middleware |
| Ruby on Rails | `show_exceptions` middleware | 500 | Default in production; raises in development |
| PHP-FPM | Fatal error ends that request; the pool worker is reused or respawned | 500, pool survives | `max_children`, and whether the fatal leaks state |
| Erlang / Elixir | **Supervisor restarts the process by design** | Restart, state lost | The supervision tree, and the restart strategy and intensity |
| Rust `tokio` | A panicking task is captured in its `JoinHandle`; the runtime survives | One task lost | Whether anything inspects the `JoinError` |
| Go, `errgroup` / `WaitGroup` | Neither recovers — a panic in a member goroutine still takes the process | Process crash | `recover()` inside each goroutine, not around the group |
| WebAssembly | Trapped at the VM boundary | Call fails, host survives | Cannot escape the VM |
| Docker container | Container exits, restart policy applies | Restart, brief unavailability | `docker inspect` restart policy |
| Kubernetes pod | `restartPolicy: Always` by default, with exponential backoff | Restart; **`CrashLoopBackOff` if repeatable** | The liveness probe, and whether a crash loop is itself the DoS |
| systemd unit | `Restart=` decides, and defaults to `no` | Depends entirely on the unit file | `systemctl cat`, and `StartLimitBurst` |
| Subprocess | Child exits, parent observes | Isolated failure | Parent's `subprocess` handling |
| Serverless (Lambda etc.) | The invocation fails; the platform retries per its own policy | One invocation, possibly retried | Whether a retry re-triggers the bug, and whether the effect is idempotent |

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
- **Panic in `init()` or startup** — recovery is not installed yet. And this is
  the case where a restart policy makes things *worse*, not better: a crash in
  startup restarts into the same crash, which is a `CrashLoopBackOff` and an
  outage rather than a blip.
- **C/C++ segfault** — a signal, not an exception; nothing catches it by default.

## The third answer: recovered, and still a finding

The question is not binary. Recovery can exist and the impact survive anyway, and
these are the shapes that get written up as "recovered, therefore Low" when they
are not:

- **The restart is the denial of service.** A crash that is cheap to trigger and
  restarts in 100ms is a Low; the same crash under a Kubernetes backoff, reachable
  by an unauthenticated request, is an availability finding — the pod spends its
  life in `CrashLoopBackOff`. Ask how fast the attacker can re-trigger it relative
  to the restart, not just whether a restart happens.
- **State does not come back.** Erlang supervisors and container restarts both
  restore the *process*, not what it was holding: in-flight requests, unflushed
  buffers, an incomplete multi-step write. A recovered crash mid-transaction can
  leave inconsistency that outlives the recovery.
- **The recovery swallows the evidence.** A framework handler that turns every
  exception into a 500 also turns a detectable attack into ordinary error-rate
  noise. That does not raise severity by itself, but it belongs in the report,
  because it is why nobody noticed.
- **One lost task is not one lost request.** An `asyncio` task or a `tokio` task
  that dies alone is contained — unless it was the only thing draining a queue,
  renewing a lease, or expiring sessions. Check what the task was *for* before
  calling its loss contained.

Record the impact that survives, not the fact that something caught it.

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
