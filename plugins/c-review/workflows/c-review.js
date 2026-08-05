export const meta = {
  name: 'c-review',
  description: 'C/C++ security review: platform detection, parallel bug-class hunters, dedup, FP/severity judgement, SARIF',
  whenToUse: 'Auditing a C or C++ codebase for memory corruption, integer overflow, races, or platform-specific vulnerabilities',
  phases: [
    { title: 'Detect', detail: 'language, platform and codebase context from actual API usage' },
    { title: 'Hunt', detail: 'one agent per bug-class group, in parallel' },
    { title: 'Dedup', detail: 'merge same-construct duplicates (only runs when candidates collide)' },
    { title: 'Judge', detail: 'false-positive verdict and severity, in batches that share a source file' },
    { title: 'Persist', detail: 'write findings.json, REPORT.md and REPORT.sarif' },
  ],
}

// --------------------------------------------------------------------- inputs

const REQUIRED_ARGS = ['outputDir', 'pluginRoot', 'threatModel', 'severityFilter']

if (!args || typeof args !== 'object') {
  throw new Error(
    'c-review: no args. The skill must pass {outputDir, pluginRoot, threatModel, severityFilter, findingScopeRoot, contextRoots, workerModel}.'
  )
}
for (const key of REQUIRED_ARGS) {
  if (!args[key]) throw new Error('c-review: args.' + key + ' is required')
}

const OUTPUT_DIR = String(args.outputDir)
const PLUGIN_ROOT = String(args.pluginRoot)
const THREAT_MODEL = String(args.threatModel).toUpperCase()
const SEVERITY_FILTER = String(args.severityFilter).toLowerCase()
const SCOPE = String(args.findingScopeRoot || '.')
const CONTEXT_ROOTS = String(args.contextRoots || '.')
const WORKER_MODEL =
  args.workerModel && String(args.workerModel) !== 'inherit' ? String(args.workerModel) : null

if (!['REMOTE', 'LOCAL_UNPRIVILEGED', 'BOTH'].includes(THREAT_MODEL)) {
  throw new Error('c-review: threatModel must be REMOTE, LOCAL_UNPRIVILEGED or BOTH')
}
if (!['all', 'medium', 'high'].includes(SEVERITY_FILTER)) {
  throw new Error('c-review: severityFilter must be all, medium or high')
}

// Judge cost is dominated by agent COUNT, not by how much any one agent says: a
// measured run held per-agent tokens flat while agent count went 14 -> 34, and the
// single largest contributor was one judge agent per finding. Batched judging puts
// findings that share a source file in front of one agent, which reads that file
// once and has more context per verdict, not less. 'per-finding' reproduces the
// one-agent-per-candidate behaviour so the two can be measured against each other.
const JUDGE_MODE = String(args.judgeMode || 'batched').toLowerCase()
if (!['batched', 'per-finding'].includes(JUDGE_MODE)) {
  throw new Error("c-review: judgeMode must be 'batched' or 'per-finding'")
}
const JUDGE_BATCH_MAX =
  Number.isFinite(args.judgeBatchSize) && args.judgeBatchSize >= 1 ? Math.floor(args.judgeBatchSize) : 5

// Cap on findings handed to one dedup agent. Dedup batches whole buckets, so this
// is a soft cap: a single bucket larger than the cap still goes to one agent rather
// than being split, because splitting a bucket would hide a duplicate pair.
const DEDUP_BATCH_MAX = 12

// EVAL-ONLY HOOK. `injectFindings` appends synthetic findings to the hunter output
// before dedup and judging, so a judge benchmark can be scored without paying for a
// hunter fan-out (resume a cached run and inject seeded false positives). It has no
// place in a real audit: anything injected here is reported as if a hunter had found
// it. See bench/judge_bench/ for the corpus of seeded findings this exists to carry.
if (args.injectFindings !== undefined && !Array.isArray(args.injectFindings)) {
  throw new Error('c-review: injectFindings must be an array of finding objects (eval-only hook)')
}
const INJECT_FINDINGS = Array.isArray(args.injectFindings) ? args.injectFindings : []

function workerOpts(extra) {
  const opts = Object.assign({}, extra)
  if (WORKER_MODEL) opts.model = WORKER_MODEL
  return opts
}

// ------------------------------------------------------------------- catalog
//
// One entry per bug class. `brief` carries the part a strong model does NOT
// already have: the surprising library semantics, the specific invariant, and
// what makes a sighting a false positive. Generic restatement ("check bounds
// before memcpy") is deliberately absent — it costs tokens and anchors the
// search on a checklist instead of on the code.
//
// `posix` gates a class on the codebase actually using POSIX APIs; `skipRemote`
// drops classes an off-box attacker cannot reach.

const CLASSES = {
  'buffer-overflow': {
    prefix: 'BOF',
    title: 'Out-of-bounds write',
    brief:
      'Spatial safety at any write: index arithmetic, loop bounds, size computations that reach a fixed or heap buffer. The high-yield shape is a size that is computed correctly for one buffer and used against another, or a bound that is re-derived rather than reused. Not a finding when the index is provably constrained at every caller; say where.',
  },
  'memcpy-size': {
    prefix: 'MEMCPYSZ',
    title: 'Bad size argument to a memory primitive',
    brief:
      'The third argument to memcpy/memmove/memset/bcopy. Signed subtraction that can go negative then converts to a huge size_t; a syscall return used without an error check; unsigned subtraction that wraps. sizeof on a pointer rather than the pointee is the classic silent one.',
  },
  'overlapping-buffers': {
    prefix: 'OVERLAP',
    title: 'Overlapping source and destination',
    brief:
      'memcpy, strcpy, sprintf and the str*cat family are undefined when the regions overlap; only memmove is defined. Aliasing usually arrives through two pointers into the same allocation (buf and buf+k), not through a literally identical argument.',
  },
  'flexible-array': {
    prefix: 'FLEX',
    title: 'Flexible-array / struct-hack sizing',
    brief:
      'A trailing data[0] or data[1] member sized with sizeof(struct) rather than offsetof(struct, data) allocates one element too few or too many. The [1] form is the dangerous one: sizeof already counts the element, so the arithmetic silently disagrees with the C99 data[] form other code assumes.',
  },

  'strlen-strcpy': {
    prefix: 'STRLENCPY',
    title: 'strlen-derived allocation off by the NUL',
    brief:
      'malloc(strlen(s)) followed by strcpy writes one byte past the allocation. Same for a VLA sized strlen(s). Only a bug when the destination is later used as a C string — a raw byte copy of exactly strlen bytes is fine.',
  },
  'strncpy-termination': {
    prefix: 'STRNCPY',
    title: 'strncpy leaves the destination unterminated',
    brief:
      'strncpy does not NUL-terminate when the source is at least n bytes; it also zero-fills the whole destination when the source is shorter, which is a performance trap but not a safety one. Look for the missing buf[n-1] = 0, and for that assignment being present on only one branch.',
  },
  'strncat-misuse': {
    prefix: 'STRNCAT',
    title: 'strncat size argument means remaining space',
    brief:
      'strncat third argument is how many bytes to append, not the destination size, and it always writes one more byte for the NUL. sizeof(dst) is therefore wrong by strlen(dst)+1. This one is almost always a real overflow when it appears.',
  },
  'string-issues': {
    prefix: 'STR',
    title: 'Encoding, locale and multibyte handling',
    brief:
      'Byte length confused with character length across a conversion boundary; locale-dependent case folding used for a security comparison (Turkish dotless i is the standing example); missing UTF-8/UTF-16 validation where downstream code assumes well-formed input; surrogate-pair and overlong-encoding handling. Encoding-invariant violations are a real vulnerability class in parsers, not a cosmetic issue.',
  },

  'format-string': {
    prefix: 'FMT',
    title: 'Format-string control',
    brief:
      'A non-literal format argument anywhere in the printf/syslog family, %n as a write primitive, and argument/specifier type mismatches. Also variadic wrappers that forward to v*printf without __attribute__((format)), which turns off every compiler check at every call site.',
  },
  'snprintf-retval': {
    prefix: 'SNPRINTF',
    title: 'snprintf return value is the would-have-been length',
    brief:
      'snprintf returns the length the output WOULD have had, which can exceed the buffer size; it is not the number of bytes written. So buf[n] = 0 with n from the return can write out of bounds, ptr += snprintf(...) can run the pointer past the end, and remaining = size - snprintf(...) can go negative. asprintf returns -1 and leaves the pointer indeterminate on failure.',
  },
  'scanf-uninit': {
    prefix: 'SCANFUNINIT',
    title: 'scanf family leaves targets uninitialized',
    brief:
      'On a partial or failed match the *scanf family leaves later targets untouched, so an uninitialized local is read as if parsed. The return value is the number of items assigned; ignoring it is what makes this exploitable. %s with no field width is a separate unbounded write.',
  },
  'banned-functions': {
    prefix: 'BAN',
    title: 'Banned or deprecated API with attacker-reachable data',
    brief:
      'gets, strcpy, strcat, sprintf, vsprintf, tmpnam, tempnam, mktemp, strtok, alloca, putenv, rand for security purposes. Report one of these as a vulnerability only when you can trace attacker-influenced data or an attacker-influenced size to it; state the source and the sink. A call whose inputs are provably bounded internal constants is a hardening observation, not a vulnerability — you may still report it, but say so plainly in the impact so the judge can rate it accordingly. Check for a project-local macro or wrapper that shadows the libc name before concluding anything.',
  },
  'unsafe-stdlib': {
    prefix: 'UNSAFESTD',
    title: 'Discouraged stdlib usage',
    brief:
      'Width-less %s conversions, stpcpy, alloca under an attacker-influenced size, putenv ownership (it stores the caller pointer rather than copying), atoi and friends with no error channel. Same evidence bar as banned-functions: name the data that reaches it.',
  },

  'uninitialized-data': {
    prefix: 'UNINIT',
    title: 'Use or disclosure of uninitialized memory',
    brief:
      'Locals read on a path that skips their assignment, structs serialized with padding bytes intact, arrays partially filled then used at full length. The disclosure half matters as much as the use half: struct padding and tail bytes leaked over a socket or into a file are an information leak even when nothing misbehaves.',
  },
  'null-deref': {
    prefix: 'NULL',
    title: 'Null pointer dereference',
    brief:
      'Unchecked allocation returns and unchecked lookup failures. The subtle variant is a check placed after a dereference: the compiler is entitled to delete the check because the earlier dereference already proved the pointer non-null, so the guard you can see is not the guard that runs.',
  },
  'use-after-free': {
    prefix: 'UAF',
    title: 'Use after free, double free, dangling pointer',
    brief:
      'A pointer that survives its allocation: freed on an error path and used by the caller, freed twice through two owners, or invalidated by a realloc whose old value some other variable still holds. Realloc aliasing is the one most often missed — every copy of the old pointer is dangling after a successful realloc.',
  },
  'memory-leak': {
    prefix: 'LEAK',
    title: 'Memory and resource leak',
    brief:
      'Leaks matter here when the leaking path is attacker-repeatable — an error branch reachable from untrusted input is a remote memory-exhaustion primitive. A leak only reachable once at startup is not. File descriptors, sockets and locks count as resources.',
  },

  'integer-overflow': {
    prefix: 'INT',
    title: 'Integer overflow, truncation and signedness',
    brief:
      'Size and length arithmetic is the payload: n * sizeof(T) with no overflow check, a + b compared against a bound after the addition already wrapped, a 64-bit length truncated into an int, a signed value that goes negative and then converts to a huge size_t. Signed overflow is undefined, so a post-hoc check like if (a + b < a) may be deleted by the compiler — that is a bug even where the wrap would have been benign. Growth patterns that double a size, or add a header to a body length, are where this reaches memory corruption.',
  },
  'operator-precedence': {
    prefix: 'PREC',
    title: 'Operator precedence and associativity',
    brief:
      'Shift binds looser than addition; bitwise and/or bind looser than comparison; the ternary binds looser than assignment. The security-relevant shapes are a mask test written without parentheses and a size expression whose intended grouping differs from the parsed one.',
  },
  'oob-comparison': {
    prefix: 'OOBCMP',
    title: 'Comparison reads past the shorter buffer',
    brief:
      'memcmp/strncmp/bcmp with a length taken from the longer operand, and the three-iterator std::equal, which reads from the second range without knowing its end. Also: memcmp is not constant-time, so using it on a secret is a separate timing problem worth noting.',
  },
  'null-zero': {
    prefix: 'NULLZERO',
    title: 'Integer 0 passed where a null pointer is required',
    posix: true,
    brief:
      'In a variadic call the compiler cannot convert 0 to a null pointer, so execl(path, arg, 0) passes an int where a char* terminator is required. On LP64 that is 32 bits of zero followed by whatever is next in the register or on the stack. Only variadic (and K&R) contexts are affected; 0 in a prototyped pointer parameter is fine.',
  },

  'type-confusion': {
    prefix: 'TYPE',
    title: 'Type confusion and unsafe casts',
    brief:
      'A buffer cast to a struct larger than the allocation is the memory-corrupting form — look for numbered or "extended" struct variants where the choice of variant comes from the data. Also: union members read under the wrong tag, void* callback payloads cast back to the wrong type, and C++ downcasts done with static_cast where the dynamic type is attacker-influenced.',
  },
  'undefined-behavior': {
    prefix: 'UB',
    title: 'Undefined behavior the optimizer can weaponize',
    brief:
      'Shifts by a negative amount or by at least the promoted width; misaligned loads via a cast; strict-aliasing violations that are not char*, memcpy or a union; unsequenced modification of the same object. What makes these security bugs rather than pedantry is that the optimizer is allowed to assume they never happen and delete the surrounding check.',
  },
  'compiler-bugs': {
    prefix: 'COMP',
    title: 'Checks and scrubbing the optimizer removes',
    brief:
      'memset of a secret before the object dies is dead-store-eliminated unless explicit_bzero, memset_s, SecureZeroMemory or a volatile access is used. Security checks inside assert() vanish under NDEBUG. A null check placed after a dereference is removable. Constant-time code written in C is not constant-time after optimization.',
  },

  'error-handling': {
    prefix: 'ERR',
    title: 'Unchecked or mis-compared return values',
    brief:
      'Ignoring the return of an allocation, an open, a crypto verify, or a write. Comparing against the wrong success convention — a function that returns 1 on success tested with != 0, or -1 on error tested with != 1. A failure that is logged but not propagated leaves the caller acting on invalid state.',
  },
  'negative-retval': {
    prefix: 'NEGRET',
    title: 'Negative return used as a size or index',
    posix: true,
    brief:
      'read/write/recv/send/snprintf return negative on error. Assigned into a size_t, -1 becomes SIZE_MAX; the follow-on comparison n == -1 against an unsigned type is then never true, so the check reads as present but never fires. That silent-dead-check shape is the one to hunt.',
  },
  'errno-handling': {
    prefix: 'ERRNO',
    title: 'errno protocol violations',
    posix: true,
    brief:
      'errno is only meaningful after a call that failed, and functions that can legitimately return a sentinel (strtol returning 0 or LONG_MAX, getpwnam returning NULL) require errno = 0 before the call to distinguish error from data. errno is also clobbered by intervening library calls, including the logging call in the error branch itself.',
  },
  'eintr-handling': {
    prefix: 'EINTR',
    title: 'EINTR handling',
    posix: true,
    brief:
      'Blocking syscalls must be retried on EINTR unless SA_RESTART covers every installed handler. close() is the exception: on Linux the descriptor is already released when close returns EINTR, so retrying it can close an unrelated descriptor a different thread just opened. A retry loop that restarts a partial read from the beginning is also wrong.',
  },

  'open-issues': {
    prefix: 'FILEOP',
    title: 'Unsafe file open and path resolution',
    posix: true,
    brief:
      'access() then open() is a symlink race whenever the directory is attacker-writable, and access() answers for the real uid, not the effective one. O_NOFOLLOW only refuses a symlink as the final component — every directory in the path is still followed; openat2 with RESOLVE_NO_SYMLINKS or component-by-component openat is the real fix. Missing O_CLOEXEC leaks descriptors across exec.',
  },
  'filesystem-issues': {
    prefix: 'FS',
    title: 'Symlink, temp file and path-normalization issues',
    brief:
      'Predictable temp names (tmpnam/tempnam/mktemp, or a PID-derived name) in a shared directory; a path prefix check that a "..", a symlink, a trailing slash, or a case-insensitive filesystem can defeat; Unicode normalization applied after the check rather than before. A prefix test that compares strings rather than resolved paths is the recurring bug.',
  },
  'socket-disconnect': {
    prefix: 'SOCKDISCON',
    title: 'connect() with AF_UNSPEC dissolves an existing association',
    posix: true,
    brief:
      'Calling connect() with sa_family set to AF_UNSPEC disconnects an already-connected socket, after which it can be reconnected elsewhere. If any part of a sockaddr reaching connect() is attacker-influenced, the association a sandbox or a peer identity relies on can be dropped; this has been used for sandbox escapes.',
  },
  'half-closed-socket': {
    prefix: 'HALFCLOSE',
    title: 'Half-closed socket state',
    posix: true,
    brief:
      'shutdown(fd, SHUT_WR) leaves the socket readable and shutdown(fd, SHUT_RD) leaves it writable. A state machine that treats "peer closed" as "connection over" will keep processing data that arrives in the half-closed window, or will free per-connection state that a subsequent read still touches. Also: a peer that half-closes rather than closing can hold a connection slot open indefinitely.',
  },

  'race-condition': {
    prefix: 'RACE',
    title: 'TOCTOU and unsynchronized shared state',
    brief:
      'Check-then-act on anything another actor can change between the two steps: a filesystem path, a shared counter, a cached pointer. Double-fetch is the memory version — reading an attacker-writable location twice and assuming the two reads agree, so the validated value is not the used value. Also lock scope that ends before the compound operation does.',
  },
  'thread-safety': {
    prefix: 'THREAD',
    title: 'Non-reentrant library calls in threaded code',
    posix: true,
    brief:
      'gethostbyname, inet_ntoa, strtok, strerror, localtime, gmtime, ctime, asctime, getpwnam, getgrnam and readdir return pointers to static storage that the next call from any thread overwrites. The bug is not the call, it is the window between the call and the consumption of the result. Only relevant if the process actually creates threads.',
  },
  'signal-handler': {
    prefix: 'SIGNAL',
    title: 'Async-signal-unsafe handler',
    posix: true,
    brief:
      'A handler may call only async-signal-safe functions. malloc/free reentered from a handler corrupts the allocator; stdio reentered from a handler corrupts its lock and buffers; longjmp out of a handler leaves everything indeterminate. A handler must also save and restore errno. The safe shapes are: set a volatile sig_atomic_t flag, or write() one byte to a self-pipe.',
  },
  'spinlock-init': {
    prefix: 'SPINLOCK',
    title: 'Lock primitive used before initialization',
    posix: true,
    brief:
      'pthread_spinlock_t has no static initializer, so a spinlock reached on a path that skipped pthread_spin_init — or whose init return was ignored — is used uninitialized. Same shape for a mutex whose pthread_mutex_init failed and was not checked.',
  },

  'access-control': {
    prefix: 'ACCESS',
    title: 'Missing or misplaced authorization',
    brief:
      'An operation that changes state or returns data on behalf of a principal, with no check that the principal is entitled to it — or a check performed on a different value than the one used. Includes capability and descriptor leaks across a privilege boundary.',
  },
  'privilege-drop': {
    prefix: 'PRIVDROP',
    title: 'Incomplete or unchecked privilege drop',
    posix: true,
    skipRemote: true,
    brief:
      'setuid() from a non-root effective uid can fail while returning a value nobody checks, leaving the process privileged. seteuid() alone leaves the saved-set-uid, so privileges can be regained; setresuid(uid,uid,uid) is the complete form. Groups must be dropped before the user, and setgroups() must be called to clear the supplementary set. Verify the drop by reading back the ids.',
  },
  envvar: {
    prefix: 'ENVVAR',
    title: 'Environment variable trust',
    posix: true,
    skipRemote: true,
    brief:
      'Under LOCAL_UNPRIVILEGED the environment is attacker data. Relevant shapes: a privileged process trusting a variable for a path or a library location; a secret placed in the environment where any process that can read /proc/<pid>/environ sees it; setenv leaving the previous value reachable; a child inheriting an environment that was never sanitized.',
  },
  'time-issues': {
    prefix: 'TIME',
    title: 'Clock and time-arithmetic assumptions',
    brief:
      'Wall-clock time used to measure a duration (an expiry or a rate limit that the clock stepping backwards defeats); 32-bit time_t overflow; comparisons that assume 86400-second days across a DST or leap-second boundary. Only report where the wrong answer has a security consequence.',
  },
  dos: {
    prefix: 'DOS',
    title: 'Attacker-controlled resource consumption',
    brief:
      'Unbounded allocation, unbounded recursion, and superlinear algorithms driven by input size. Recursion depth is the highest-yield one in parsers: look for a depth counter that exists but is never compared against a limit, a limit that only counts one of several recursive paths, or an amplification guard that a linear chain slips under. Hash-table collision floods and regex backtracking belong here too.',
  },

  'exploit-mitigations': {
    prefix: 'MITIGATION',
    title: 'Missing or silently misspelled hardening flags',
    brief:
      'Read the actual build files. The interesting failure is not an absent flag but a misspelled one — _FORTIFY_SORUCE, -fstack-protector-stong, _GLIBCXX_ASSERTONS — because a typo in a -D or a -f flag is accepted silently and the mitigation is simply off while the build looks hardened. Also check that the flag reaches the target, not only a sample or test build.',
  },
  'printf-attr': {
    prefix: 'PRINTFATTR',
    title: 'Variadic logging wrapper without a format attribute',
    posix: true,
    brief:
      'A function that forwards a caller-supplied format to v*printf and lacks __attribute__((format(printf, m, n))) disables format checking at every one of its call sites, so an argument-count or type mismatch reaches the formatter unnoticed. This is worth reporting even with no current mismatch: it is the check that would catch the next one.',
  },
  'va-start-end': {
    prefix: 'VAARG',
    title: 'va_list lifecycle',
    brief:
      'Every va_start and every va_copy needs a matching va_end before the function returns, including on early-error paths. Reusing a va_list after it has been consumed by one v*printf call is undefined — a second consumer needs va_copy.',
  },
  'regex-issues': {
    prefix: 'REGEX',
    title: 'Regex denial of service and matching bypasses',
    brief:
      'Backtracking blowup from nested or overlapping quantifiers on attacker input. Bypasses: an unanchored pattern used as if it were a whole-string test, and POSIX regexec matching per line unless REG_NEWLINE semantics are considered, so an embedded newline can hide the rest of the input from a check.',
  },
  'inet-aton': {
    prefix: 'INETATON',
    title: 'inet_aton and inet_addr accept trailing garbage',
    posix: true,
    brief:
      'In glibc, inet_aton succeeds if the string STARTS WITH a valid address — inet_aton("1.1.1.1 anything", &a) returns 1. It also accepts octal (a leading zero changes the value) and short dotted forms such as "10.1" as a two-part address. So a validated-looking string may carry an injected payload, and the same text may resolve differently in another parser. inet_pton is strict. The bug appears when the ORIGINAL string is used after validation rather than the parsed binary address.',
  },
  qsort: {
    prefix: 'QSORT',
    title: 'Non-transitive comparator drives qsort out of bounds',
    posix: true,
    brief:
      'glibc qsort trusted its comparator to be a valid ordering; an inconsistent one walks the merge past the array (CVE-2023-6246 family, Qualys 2024). Inconsistency sources: subtracting ints, which overflows; comparing only a prefix or one field of a record; floating point where NaN makes every comparison false; and a multi-key comparator that returns 0 for distinct records. The safe form is (a > b) - (a < b).',
  },

  'logic-flaw': {
    prefix: 'LOGIC',
    title: 'Security logic, protocol and state-machine flaws',
    brief:
      'Everything memory-safety taxonomies do not name. Namespace or delimiter injection, where a separator character the format reserves is accepted inside a value and re-emitted so the two parse differently on the way back. Protocol state machines that accept a message in a state that skips authentication or size negotiation. Deserialization that lets input choose a type or a size. Off-by-one in an index-to-identity mapping. Validation applied to a normalized copy while the raw value is what is used downstream. An encoding or well-formedness invariant enforced at some call sites of a shared macro or helper but not all, so one path admits input the others reject. These are found by reading what a value is allowed to be and then asking what the code does with a value that is one step outside that.',
  },

  'crypto-misuse': {
    prefix: 'CRYPTO',
    title: 'Cryptographic misuse',
    brief:
      'Correct primitives assembled wrongly. A nonce or IV reused across two messages under one key, or derived from a counter that resets when the process does. One key serving two purposes, or a long-term key used where an ephemeral one belongs. Secrets, MACs or tags compared with memcmp or strcmp, which returns early and leaks position. Ciphertext decrypted before its tag is checked, or a tag never checked. ECB, or any unauthenticated mode where the plaintext is attacker-influenced. Keys or salts from rand/srand, time, a PID, or a hardcoded constant instead of a CSPRNG. A KDF with no salt or a trivial iteration count. Padding or signature verification whose failure path returns the same value as success. Judge the construction against what the primitive requires of its caller, not against whether the primitive itself is sound.',
  },

  'smart-pointer': {
    prefix: 'SPTR',
    title: 'C++ smart pointer ownership',
    brief:
      'Two independent shared_ptr control blocks built from one raw pointer (double free); a raw pointer or reference handed out of a unique_ptr and outliving it; shared_ptr cycles; weak_ptr::lock() result used without checking.',
  },
  'move-semantics': {
    prefix: 'MOVE',
    title: 'Use of a moved-from object',
    brief:
      'A moved-from object is valid but unspecified. The security-relevant shape is a buffer or key moved out and then read as if it still held the data, and a std::move inside a loop that moves the same object on every iteration.',
  },
  'lambda-capture': {
    prefix: 'LAMBDA',
    title: 'Lambda capture outliving its referent',
    brief:
      'A lambda stored in a callback, a thread, or a coroutine that captured a local by reference, or captured this, and now outlives it. [=] on a member function captures this by value, not the members — a common surprise.',
  },
  'iterator-invalidation': {
    prefix: 'ITER',
    title: 'Iterator, pointer or reference invalidated by a container mutation',
    brief:
      'Any vector or string growth invalidates every iterator, pointer and reference into it, including one held across a function call that appends. Erasing inside a loop without taking the returned iterator. unordered_ containers invalidate iterators on rehash but keep references valid — the asymmetry causes real bugs.',
  },

  'init-order': {
    prefix: 'INIT',
    title: 'Static initialization order',
    brief:
      'A namespace-scope object in one translation unit whose constructor reads one defined in another has no defined order. Member initializers run in declaration order, not in the order they are written in the list. The observable failure is a security check reading a not-yet-initialized table.',
  },
  'virtual-function': {
    prefix: 'VIRT',
    title: 'Virtual dispatch hazards',
    brief:
      'A virtual call in a constructor or destructor dispatches to the class being constructed, not the derived override, so a derived-class invariant check silently does not run. Deleting through a base pointer without a virtual destructor. Object slicing on assignment to a base value.',
  },
  'exception-safety': {
    prefix: 'EXCEPT',
    title: 'Exception paths that leak or leave partial state',
    brief:
      'A resource acquired between a try and the RAII wrapper that would release it; a destructor that can throw (terminate during unwind); a noexcept function whose callee throws. The security shape is a lock or a privilege left held, or a half-updated invariant observed after the handler.',
  },

  createprocess: {
    prefix: 'CREATEPROC',
    title: 'Windows process creation',
    brief:
      'An unquoted lpApplicationName/lpCommandLine path with spaces lets C:\\Program.exe run instead of the intended target. bInheritHandles = TRUE hands every inheritable handle to the child. Also: creating a process with a token or a working directory the caller does not control.',
  },
  'cross-process': {
    prefix: 'CROSSPROC',
    title: 'Cross-process memory and handle access',
    brief:
      'OpenProcess/ReadProcessMemory/WriteProcessMemory against a PID that can be recycled or a handle obtained without verifying the target identity. Duplicating a handle into a lower-privileged process with more access than intended.',
  },
  'token-privilege': {
    prefix: 'TOKPRIV',
    title: 'Token and impersonation handling',
    brief:
      'Impersonation that is not reverted on every path, including error paths. ImpersonateNamedPipeClient without first checking the client is who is expected. Privileges enabled and left enabled. A SECURITY_DESCRIPTOR with a NULL DACL, which grants everyone full control (it is not the same as an empty DACL, which grants no one).',
  },
  'service-security': {
    prefix: 'WINSVC',
    title: 'Windows service configuration',
    brief:
      'A service binary or its directory writable by non-admins; a service whose ACL allows SERVICE_CHANGE_CONFIG to a non-admin (the binary path can then be rewritten); an unquoted ImagePath with spaces.',
  },

  'dll-planting': {
    prefix: 'DLLPLANT',
    title: 'DLL search-order hijacking',
    brief:
      'LoadLibrary with a bare name, or an implicit import of a DLL not present in System32, resolves through a search order that includes the application directory and (without SetDefaultDllDirectories) the current directory. Use a fully qualified path or LOAD_LIBRARY_SEARCH_SYSTEM32.',
  },
  'windows-path': {
    prefix: 'WINPATH',
    title: 'Windows path parsing',
    brief:
      'Path checks defeated by 8.3 short names, alternate data streams, a trailing dot or space that the filesystem strips, the \\\\?\\ prefix that skips normalization, device names such as CON and NUL, and UNC paths reaching a check written for local paths. Case-insensitivity plus Unicode folding defeats string prefix tests.',
  },
  'installer-race': {
    prefix: 'INSTRACE',
    title: 'Installer and updater filesystem race',
    brief:
      'A privileged installer writing to or executing from a directory a normal user can write, or extracting to a temp directory before setting its ACL. The window between create and ACL-set is the bug.',
  },

  'named-pipe': {
    prefix: 'NAMEDPIPE',
    title: 'Named pipe security',
    brief:
      'A server that does not create the pipe with FILE_FLAG_FIRST_PIPE_INSTANCE can be squatted by a client that created the name first. A server that impersonates a client without validating it, or a client that connects without SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, can be impersonated by a malicious server.',
  },
  'windows-crypto': {
    prefix: 'WINCRYPTO',
    title: 'Windows cryptography API misuse',
    brief:
      'Deprecated CryptoAPI with weak algorithms; a static or zero IV; RSA without OAEP; a key derived from a password without a KDF; CryptGenRandom replaced by rand. Also CryptProtectData used for data that crosses a trust boundary it does not protect.',
  },
  'windows-alloc': {
    prefix: 'WINALLOC',
    title: 'Windows allocator misuse',
    brief:
      'Mixing allocator families (HeapAlloc freed with free, LocalAlloc freed with HeapFree, CoTaskMemAlloc freed with delete). Size arithmetic before HeapAlloc that can overflow. HEAP_ZERO_MEMORY assumed but not passed.',
  },
}

const GROUPS = [
  { id: 'memory-bounds', title: 'Memory bounds', classes: ['buffer-overflow', 'memcpy-size', 'overlapping-buffers', 'flexible-array'] },
  { id: 'string-handling', title: 'String handling', classes: ['strlen-strcpy', 'strncpy-termination', 'strncat-misuse', 'string-issues'] },
  { id: 'format-and-input-apis', title: 'Format and input APIs', classes: ['format-string', 'snprintf-retval', 'scanf-uninit', 'banned-functions', 'unsafe-stdlib'] },
  { id: 'object-lifecycle', title: 'Object lifecycle', classes: ['uninitialized-data', 'null-deref', 'use-after-free', 'memory-leak'] },
  { id: 'integer-safety', title: 'Integer overflow and bounds arithmetic', classes: ['integer-overflow', 'oob-comparison'] },
  { id: 'conversion-and-ub', title: 'Conversions, precedence and undefined behavior', classes: ['operator-precedence', 'null-zero', 'type-confusion', 'undefined-behavior', 'compiler-bugs'] },
  { id: 'syscall-returns', title: 'Return values and errno', classes: ['error-handling', 'negative-retval', 'errno-handling', 'eintr-handling'] },
  { id: 'files-and-sockets', title: 'Files and sockets', classes: ['open-issues', 'filesystem-issues', 'socket-disconnect', 'half-closed-socket'] },
  { id: 'concurrency', title: 'Concurrency', classes: ['race-condition', 'thread-safety', 'signal-handler', 'spinlock-init'] },
  { id: 'ambient-and-dos', title: 'Ambient state and DoS', classes: ['access-control', 'privilege-drop', 'envvar', 'time-issues', 'dos'] },
  { id: 'build-hardening', title: 'Build and declaration hygiene', classes: ['exploit-mitigations', 'printf-attr'] },
  { id: 'library-api-misuse', title: 'Library API contract misuse', classes: ['qsort', 'inet-aton', 'regex-issues', 'va-start-end'] },
  { id: 'logic-and-protocol', title: 'Logic, protocol and crypto', classes: ['logic-flaw', 'crypto-misuse'] },
  { id: 'cpp-lifetime', title: 'C++ lifetime', gate: 'is_cpp', classes: ['smart-pointer', 'move-semantics', 'lambda-capture', 'iterator-invalidation'] },
  { id: 'cpp-classes', title: 'C++ class semantics', gate: 'is_cpp', classes: ['init-order', 'virtual-function', 'exception-safety'] },
  { id: 'windows-process', title: 'Windows processes', gate: 'is_windows', classes: ['createprocess', 'cross-process', 'token-privilege', 'service-security'] },
  { id: 'windows-fs-path', title: 'Windows filesystem and paths', gate: 'is_windows', classes: ['dll-planting', 'windows-path', 'installer-race'] },
  { id: 'windows-ipc-crypto', title: 'Windows IPC and crypto', gate: 'is_windows', classes: ['named-pipe', 'windows-crypto', 'windows-alloc'] },
]

// -------------------------------------------------------------------- schemas

const DETECT_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['is_cpp', 'is_posix', 'is_windows', 'platform_evidence', 'purpose', 'entry_points', 'trust_boundaries', 'existing_hardening'],
  properties: {
    is_cpp: { type: 'boolean', description: 'C++ translation units are compiled, not merely C headers guarded by extern "C"' },
    is_posix: { type: 'boolean', description: 'the code actually calls POSIX APIs on the build path being audited' },
    is_windows: { type: 'boolean', description: 'the code actually calls Win32 APIs on the build path being audited' },
    platform_evidence: { type: 'string', description: 'one line per flag set true, each citing a path:line that shows real API usage' },
    purpose: { type: 'string' },
    entry_points: { type: 'array', items: { type: 'string' }, description: 'where untrusted data enters, as path:line plus one phrase' },
    trust_boundaries: { type: 'array', items: { type: 'string' } },
    existing_hardening: { type: 'array', items: { type: 'string' }, description: 'fuzzers, sanitizers, assertions, privilege separation actually present in the tree' },
  },
}

const FINDING_PROPERTIES = {
  bug_class: { type: 'string', description: 'one of the class ids listed in the prompt, or the closest one if the bug is outside them' },
  title: { type: 'string' },
  file: { type: 'string', description: 'repo-relative path, no markdown link, no absolute path' },
  line: { type: 'integer', minimum: 1 },
  function: { type: 'string', description: 'the single enclosing function, or (file-level)' },
  confidence: { type: 'string', enum: ['High', 'Medium', 'Low'] },
  description: { type: 'string', description: 'the broken invariant and what the attacker controls' },
  code: { type: 'string', description: 'the real snippet, copied not paraphrased' },
  data_flow: { type: 'string', description: 'source, sink and what validation exists between them; N/A for a file-level finding' },
  reachability: { type: 'string', description: 'call chain from an entry point, or the honest limit of what you traced' },
  impact: { type: 'string' },
  mitigations_checked: { type: 'string', description: 'each mitigation you looked for, with the path:line where you found it or the statement that it is absent' },
  recommendation: { type: 'string' },
  outside_assigned_classes: { type: 'boolean', description: 'true when this bug is not one of your assigned classes' },
}

const HUNT_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['findings', 'coverage', 'external_sources_consulted', 'external_sources_detail'],
  properties: {
    external_sources_consulted: {
      type: 'boolean',
      description:
        'true if you read anything outside this repository while working — upstream sources, a git history, a changelog, an advisory, a CVE record, a search result. Declaring it is expected and carries no penalty; it exists so benchmark runs can be scored honestly.',
    },
    external_sources_detail: {
      type: 'string',
      description: 'what you consulted and why, or the single word "none"',
    },
    findings: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['bug_class', 'title', 'file', 'line', 'function', 'confidence', 'description', 'code', 'impact', 'recommendation'],
        properties: FINDING_PROPERTIES,
      },
    },
    coverage: {
      type: 'array',
      description: 'one entry per assigned class. Self-reported and not verified by anything downstream, so write what is true.',
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['bug_class', 'outcome', 'population', 'evidence'],
        properties: {
          bug_class: { type: 'string' },
          outcome: {
            type: 'string',
            enum: ['reported', 'nothing-survived-review', 'no-candidates-in-scope', 'not-searched'],
            description:
              'reported means you filed at least one finding for this class. It does not mean the class is closed: a finding closes a finding, not a population.',
          },
          population: { type: 'string', description: 'the concrete set you enumerated and its size, e.g. "31 memcpy/memmove call sites across 6 files"' },
          evidence: { type: 'string', description: 'for anything other than not-searched: the path:line citations you actually opened, or the concrete reason the population is empty. An outcome with no citable evidence should be reported as not-searched. When the outcome is reported AND the population is countable, the evidence must account for the whole population — say what you found at the members you did not file, not only at the one you did.' },
        },
      },
    },
    notes: { type: 'string', description: 'anything a human should know: truncated coverage, files you could not read, areas that need a person' },
  },
}

const DEDUP_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['merges'],
  properties: {
    merges: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['primary', 'duplicates', 'rationale'],
        properties: {
          primary: { type: 'string' },
          duplicates: { type: 'array', items: { type: 'string' } },
          rationale: { type: 'string', description: 'one phrase naming the single shared source construct' },
        },
      },
    },
  },
}

const VERDICT_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['fp_verdict', 'fp_rationale'],
  properties: {
    fp_verdict: { type: 'string', enum: ['TRUE_POSITIVE', 'LIKELY_TP', 'LIKELY_FP', 'FALSE_POSITIVE', 'OUT_OF_SCOPE'] },
    fp_rationale: { type: 'string', description: 'cite the path:line that decided it' },
    severity: { type: 'string', enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'], description: 'survivors only' },
    attack_vector: { type: 'string', enum: ['Remote', 'Local', 'Both'] },
    exploitability: { type: 'string', enum: ['Reliable', 'Difficult', 'Theoretical'] },
    severity_rationale: { type: 'string' },
  },
}

// One entry per candidate in the batch. `id` is what maps a verdict back onto the
// finding it belongs to; a batch that returns fewer entries than it was given leaves
// the missing ones unjudged and labelled, never silently dropped.
const BATCH_VERDICT_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['verdicts'],
  properties: {
    verdicts: {
      type: 'array',
      description: 'exactly one entry for every candidate id you were given, in any order',
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['id', 'fp_verdict', 'fp_rationale'],
        properties: Object.assign(
          { id: { type: 'string', description: 'the candidate id this verdict belongs to' } },
          VERDICT_SCHEMA.properties
        ),
      },
    },
  },
}

const PERSIST_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['ok'],
  properties: {
    ok: { type: 'boolean' },
    findings_json: { type: 'string' },
    report_md: { type: 'string' },
    report_sarif: { type: 'string' },
    error: { type: 'string' },
  },
}

// -------------------------------------------------------------------- prompts

const EVIDENCE_RULE = [
  'EVIDENCE RULE — the most important instruction here.',
  '',
  'Every negative conclusion you reach rests on the code in front of you. You may not clear a',
  'candidate, and you may not conclude that a bug class is absent, on the basis of what you recall',
  'about this project: its identity, its version, its release history, or its published',
  'vulnerabilities. Recalled knowledge that "the fix for this is already upstream" is not evidence,',
  'and asserting it has previously caused this pipeline to suppress real, present bugs that a plain',
  'reading of the file would have found.',
  '',
  'If you claim a guard, a bounds check, a cast, or any other mitigation exists, cite the path:line',
  'where it is written, so a reader can open that line and see it. If you cannot cite it, it is not',
  'there. Nothing outside this repository substitutes for that citation: an upstream diff, a',
  'changelog or an advisory may tell you where to look, but only the code in front of you can clear',
  'a candidate.',
].join('\n')

const EXTERNAL_SOURCE_DECLARATION = [
  'DECLARE EXTERNAL SOURCES.',
  '',
  'Set external_sources_consulted true if you read anything outside this repository while working —',
  'an upstream release or tarball, a git history, a changelog, an advisory, a CVE record, a search',
  'result, a vendored copy elsewhere on the machine. Otherwise set it false. Put what you used in',
  'external_sources_detail, or the single word "none".',
  '',
  'Declaring true costs you nothing. Nothing is dropped, downgraded or re-reviewed because of it,',
  'and in a real audit comparing against upstream is legitimate and often the fastest route to a',
  'bug. The flag exists for one reason: this pipeline is also measured against corpora whose bugs',
  'are already public, and a run where a reviewer read the answer off an upstream fix measures',
  'diffing rather than review, so the score has to know which findings came from where. The only',
  'thing that does damage is an undeclared consultation.',
].join('\n')

const ESCAPE_HATCH = [
  'REPORT WHAT YOU FIND.',
  '',
  'The classes below are where to start, not a fence. If you find a security bug of any kind while',
  'reading — an authorization gap, a protocol state-machine error, an injection through a reserved',
  'delimiter, a deserialization flaw, a broken encoding invariant, a nonce reuse, a path traversal —',
  'report it and set outside_assigned_classes to true. No one else is guaranteed to be looking for it.',
].join('\n')

function contextBlock(detect) {
  return [
    '<codebase>',
    'Purpose: ' + detect.purpose,
    'Language/platform: is_cpp=' + detect.is_cpp + ', is_posix=' + detect.is_posix + ', is_windows=' + detect.is_windows,
    'Platform evidence: ' + detect.platform_evidence,
    'Entry points for untrusted data:',
    (detect.entry_points || []).map((e) => '  - ' + e).join('\n'),
    'Trust boundaries:',
    (detect.trust_boundaries || []).map((e) => '  - ' + e).join('\n'),
    'Existing hardening:',
    (detect.existing_hardening || []).map((e) => '  - ' + e).join('\n'),
    '</codebase>',
  ].join('\n')
}

function scopeBlock() {
  return [
    '<scope>',
    'Finding scope root: ' + SCOPE + '  (a finding must live inside this subtree)',
    'Context roots: ' + CONTEXT_ROOTS + '  (read these freely to establish callers, build flags and reachability; do not file findings here)',
    'Threat model: ' + THREAT_MODEL,
    '</scope>',
  ].join('\n')
}

function detectPrompt() {
  return [
    'You are opening a C/C++ codebase for a security review. Establish two things and return them',
    'structured. Read the build system and a representative sample of sources; do not guess.',
    '',
    '1. Which platform and language surfaces the audited code ACTUALLY uses.',
    '',
    '   Decide on real API usage, not on a single include. A portable library commonly carries a',
    '   compatibility header that includes <windows.h> so that one typedef resolves; that is not a',
    '   Windows codebase and gating Windows work on it wastes a large fraction of a review. Set',
    '   is_windows only if the code calls Win32 APIs — processes, handles, registry, services, named',
    '   pipes, CryptoAPI, Win32 file or path functions. Set is_posix only if the code calls POSIX',
    '   APIs — sockets, fork/exec, signals, pthreads, file descriptors, uid/gid. A library that only',
    '   uses ISO C is neither, and that is a valid answer. Both may be true when the tree really does',
    '   contain both back ends. Set is_cpp only if C++ translation units are compiled; a C library',
    '   with a C++ test harness or an extern "C" guard is not C++.',
    '',
    '   For every flag you set true, cite a path:line showing the actual API call that justifies it.',
    '',
    '2. The context a reviewer needs: what the code is for, where untrusted data enters (with',
    '   path:line), what the trust boundaries are, and what hardening already exists in the tree',
    '   (fuzz targets, sanitizer configuration, assertions, privilege separation).',
    '',
    scopeBlock(),
  ].join('\n')
}

function huntPrompt(group, classIds, detect) {
  const classText = classIds
    .map((id) => {
      const c = CLASSES[id]
      return '### ' + id + ' — ' + c.title + '\n' + c.brief
    })
    .join('\n\n')

  return [
    'You are a bug hunter in a C/C++ security review. Your group is "' + group.title + '".',
    '',
    EVIDENCE_RULE,
    '',
    EXTERNAL_SOURCE_DECLARATION,
    '',
    ESCAPE_HATCH,
    '',
    '## Your classes',
    '',
    classText,
    '',
    '## How to work',
    '',
    'Read code. Decide for yourself how to find the sites that matter — enumerate a population, follow',
    'the data, or read the files that handle input end to end, whichever fits this codebase. For each',
    'candidate, establish what an attacker controls, what reaches the site, and what stands between',
    'the two. Depth over breadth: a small number of findings you can defend with citations is worth',
    'more than a long list of pattern matches.',
    '',
    'Report every bug you confirm, with a severity-relevant impact statement. Do not filter by your',
    'own guess at severity — a separate judge assigns severity, and anything you drop here is lost.',
    'Do not stop at the first finding in a file.',
    '',
    'One finding per distinct site. file must be repo-relative and line must be the vulnerable line.',
    'function is the single enclosing function, or the literal (file-level) for a build or',
    'configuration finding.',
    '',
    'The coverage array is an audit note for a human, not a gate: nothing downstream validates it and',
    'nothing rejects your work for what it says. Write what actually happened. If you did not search a',
    'class, say not-searched.',
    '',
    'Filing a finding closes that finding, not the class it belongs to. When you mark a class reported',
    'and its population is countable — the recursive call sites, the size computations, the call sites',
    'of one macro — the evidence has to account for the whole population you declared, including the',
    'members you looked at and did not file. Writing reported over an uncountable population ("all',
    'constructs reachable from untrusted input") on the strength of one instance is how a second bug in',
    'the same class goes unlooked-at.',
    '',
    scopeBlock(),
    '',
    contextBlock(detect),
  ].join('\n')
}

function dedupPrompt(bucket) {
  return [
    'Two or more findings from independent reviewers landed on the same function. Decide which, if',
    'any, describe the SAME source construct and should be merged.',
    '',
    'Merge only when the findings point at one call expression, one statement, or one small block —',
    'the same sink token, normally within about five lines. Different constructs in one function are',
    'different bugs even when the impact overlaps, and even when one bug class is arguably a more',
    'general name for the other. Two findings that would be fixed by the same edit are related, not',
    'duplicate; leave them separate.',
    '',
    'Merging across bug classes is allowed here, and only here, when the disagreement is about what to',
    'call one defect. You must be able to say in one phrase why both labels name the same bug.',
    '',
    'When in doubt, do not merge. A wrongly merged pair silently drops a real bug; a wrongly separate',
    'pair costs one extra paragraph in the report.',
    '',
    'Findings in this bucket (JSON):',
    JSON.stringify(bucket, null, 2),
    '',
    'Return the merge groups you are confident in. primary is the id that survives; prefer the higher',
    'confidence, then the lexicographically smallest id. Return an empty merges array if none apply.',
  ].join('\n')
}

// Several collisions in one file go to one agent. The buckets stay separate in the
// prompt and a merge that crosses two of them is discarded in code, so batching
// cannot merge findings in different functions — it only saves the agent that would
// otherwise re-read the same file for each bucket.
function dedupBatchPrompt(bucketGroup) {
  return [
    'Independent reviewers landed on the same function in ' + bucketGroup.length + ' places in one',
    'file. Decide, within each group separately, which findings describe the SAME source construct',
    'and should be merged.',
    '',
    'Merge only when the findings point at one call expression, one statement, or one small block —',
    'the same sink token, normally within about five lines. Different constructs in one function are',
    'different bugs even when the impact overlaps, and even when one bug class is arguably a more',
    'general name for the other. Two findings that would be fixed by the same edit are related, not',
    'duplicate; leave them separate.',
    '',
    'Merging across bug classes is allowed here, and only here, when the disagreement is about what to',
    'call one defect. You must be able to say in one phrase why both labels name the same bug.',
    '',
    'Never merge across two groups. They are in different functions, so they are different bugs by',
    'construction, and any such merge is discarded.',
    '',
    'When in doubt, do not merge. A wrongly merged pair silently drops a real bug; a wrongly separate',
    'pair costs one extra paragraph in the report.',
    '',
    'Groups (JSON, one array per colliding function):',
    JSON.stringify(bucketGroup, null, 2),
    '',
    'Return every merge group you are confident in, across all groups, in one merges array. primary is',
    'the id that survives; prefer the higher confidence, then the lexicographically smallest id.',
    'Return an empty merges array if none apply.',
  ].join('\n')
}

const SEVERITY_TABLES = [
  '### REMOTE',
  '',
  '- CRITICAL — remote code execution, authentication bypass, remotely reachable memory corruption with reliable exploitation',
  '- HIGH — reliable remote denial of service, disclosure of sensitive data, SSRF into internal services',
  '- MEDIUM — difficult remote denial of service, limited information disclosure, bugs needing unusual network conditions',
  '- LOW — theoretical issues, defense-in-depth gaps, remotely reachable issues with negligible impact',
  '',
  '### LOCAL_UNPRIVILEGED',
  '',
  '- CRITICAL — privilege escalation to root, sandbox or container escape',
  '- HIGH — access to other users data, arbitrary file read or write as a privileged user',
  '- MEDIUM — local denial of service, system data disclosure, limited privilege-boundary crossing',
  '- LOW — a privilege-boundary crossing with minimal impact',
  '',
  '### BOTH',
  '',
  'Score remote-triggerable bugs against the remote table and local-only bugs against the local table.',
  'If a bug is triggerable either way, take the higher severity.',
  '',
  '### Adjustments',
  '',
  '- A mitigation that is present and effective at this site: reduce one level. A mitigation that is a known bypass target (ASLR, canaries): no change.',
  '- Requires winning a race, or requires a non-default configuration: reduce one level.',
  '- Affects authentication or cryptography, or sits on a widely reachable entry point: raise one level.',
].join('\n')

// Shared by the single-candidate judge and the batched judge so the two cannot drift
// apart on what a verdict means. Spliced in as one array element, so lifting it out of
// judgePrompt did not change a character of the text that prompt produces.
const JUDGE_RULES = [
  '## Verdict',
  '',
  '- TRUE_POSITIVE — a real, reachable vulnerability under this threat model',
  '- LIKELY_TP — a real bug whose reachability you could not fully establish but which is plausible',
  '- LIKELY_FP — the pattern is there but the defined attacker cannot reach it',
  '- FALSE_POSITIVE — not a bug; the reporter misread the code',
  '- OUT_OF_SCOPE — a real bug requiring attacker capabilities this threat model excludes',
  '',
  'Under REMOTE, a bug only triggerable through local configuration, CLI arguments, environment or',
  'an existing shell is OUT_OF_SCOPE. Under LOCAL_UNPRIVILEGED, a bug that crosses no privilege',
  'boundary is LIKELY_FP, and one requiring root is OUT_OF_SCOPE.',
  '',
  'A finding whose impact is hardening rather than exploitation — a banned API with no',
  'attacker-controlled data reaching it, a missing compiler flag, a missing format attribute — is',
  'yours to judge like any other. If it is a real gap that a reader should act on, TRUE_POSITIVE at',
  'LOW is right. If the pattern is unreachable, or the guard the reporter says is missing is',
  'actually present, reject it. You are not required to accept it.',
  '',
  'Between LIKELY_TP and LIKELY_FP, prefer LIKELY_TP: a wrong rejection is invisible and a wrong',
  'acceptance is one paragraph a reader can dismiss.',
  '',
  'Cite the path:line that decided the verdict in fp_rationale.',
  '',
  '## Severity — survivors only (TRUE_POSITIVE and LIKELY_TP)',
  '',
  'Leave severity, attack_vector, exploitability and severity_rationale unset for every other',
  'verdict. Severity is relative to the threat model, not absolute.',
  '',
  SEVERITY_TABLES,
].join('\n')

function judgePrompt(finding, detect, mergedGroup) {
  const alsoKnown =
    mergedGroup && mergedGroup.length
      ? '\nThis candidate absorbed other reports of the same construct. Read all of them; they are the same defect described from different angles, so they get one verdict. If the bug is real under ANY of the framings, it survives — name the framing that carries it.\n\nAbsorbed reports (JSON):\n' +
        JSON.stringify(mergedGroup, null, 2) +
        '\n'
      : ''

  return [
    'You are a senior security auditor deciding whether one candidate finding is real and, if so, how',
    'bad it is. Open the code yourself. The reporter may have misread it, and the reporter may also',
    'have understated it.',
    '',
    EVIDENCE_RULE,
    '',
    JUDGE_RULES,
    '',
    scopeBlock(),
    '',
    contextBlock(detect),
    '',
    'Candidate (JSON):',
    JSON.stringify(finding, null, 2),
    alsoKnown,
  ].join('\n')
}

// One agent, several candidates from the same file. The candidates are independent
// verdicts, not a set to rank against each other — the shared context is the file
// they all sit in, which this agent opens once instead of N times.
function judgeBatchPrompt(batch, detect, absorbedBy) {
  const candidates = batch.map((f) => {
    const absorbed = absorbedBy.get(f.id) || []
    return absorbed.length ? Object.assign({}, f, { absorbed_reports: absorbed }) : f
  })

  return [
    'You are a senior security auditor deciding whether each of ' + batch.length + ' candidate findings',
    'is real and, if so, how bad it is. They were grouped because they sit in the same file, so you can',
    'read it once. Open the code yourself. A reporter may have misread it, and a reporter may also have',
    'understated it.',
    '',
    'Judge each candidate on its own merits. They are not competing and they are not a ranking: an',
    'earlier rejection is no reason to reject the next one, and an earlier acceptance is no reason to',
    'accept it. Return one verdict per candidate id — all of them, including any you find trivial.',
    'A candidate you leave out is reported to the user as unjudged, which is worse than a verdict you',
    'were unsure about.',
    '',
    'Some candidates carry absorbed_reports: other reports of the same construct, absorbed during',
    'deduplication. They are the same defect described from different angles, so they get one verdict.',
    'If the bug is real under ANY of the framings, it survives — name the framing that carries it.',
    '',
    EVIDENCE_RULE,
    '',
    JUDGE_RULES,
    '',
    scopeBlock(),
    '',
    contextBlock(detect),
    '',
    'Candidates (JSON):',
    JSON.stringify(candidates, null, 2),
  ].join('\n')
}

function persistPrompt(payload) {
  const jsonPath = OUTPUT_DIR + '/findings.json'
  const sarifGen = PLUGIN_ROOT + '/scripts/generate_sarif.py'
  const reportGen = PLUGIN_ROOT + '/scripts/render_report.py'
  return [
    'Mechanical step. Persist a JSON document and run two generators. Do not analyse the content.',
    '',
    'Step 1 — write the JSON below verbatim to ' + jsonPath + ' using a Bash heredoc with a quoted',
    'delimiter, exactly:',
    '',
    '  cat > ' + JSON.stringify(jsonPath) + " <<'C_REVIEW_JSON_EOF'",
    '  ...the document...',
    '  C_REVIEW_JSON_EOF',
    '',
    'Use Bash, not the Write tool — the harness blocks the Write tool for findings and report',
    'filenames in a subagent. The quoted delimiter keeps the shell from expanding anything inside.',
    '',
    'Step 2 — run both generators:',
    '',
    '  uv run ' + JSON.stringify(sarifGen) + ' --findings ' + JSON.stringify(jsonPath) + ' --output-dir ' + JSON.stringify(OUTPUT_DIR),
    '  uv run ' + JSON.stringify(reportGen) + ' --findings ' + JSON.stringify(jsonPath) + ' --output-dir ' + JSON.stringify(OUTPUT_DIR),
    '',
    'Both exit non-zero and print the reason if the JSON is malformed or truncated. If either fails,',
    'return ok=false with the error text; do not hand-write the outputs.',
    '',
    'The document:',
    '',
    JSON.stringify(payload, null, 2),
  ].join('\n')
}

// ---------------------------------------------------------------- plain logic

function selectGroups(detect) {
  const selected = []
  for (const group of GROUPS) {
    if (group.gate === 'is_cpp' && !detect.is_cpp) continue
    if (group.gate === 'is_windows' && !detect.is_windows) continue
    const classIds = group.classes.filter((id) => {
      const c = CLASSES[id]
      if (c.posix && !detect.is_posix) return false
      if (c.skipRemote && THREAT_MODEL === 'REMOTE') return false
      return true
    })
    if (classIds.length) selected.push({ group: group, classIds: classIds })
  }
  return selected
}

function normalizePath(p) {
  let s = String(p == null ? '' : p).replace(/\\/g, '/').trim()
  const link = s.match(/^\[([^\]]+)\]\([^)]*\)$/)
  if (link) s = link[1]
  while (s.startsWith('./')) s = s.slice(2)
  while (s.indexOf('//') !== -1) s = s.replace('//', '/')
  return s
}

function pad3(n) {
  const s = String(n)
  return s.length >= 3 ? s : '000'.slice(s.length) + s
}

const CONFIDENCE_RANK = { High: 3, Medium: 2, Low: 1 }

function normalizeFinding(raw, groupId) {
  const bugClass = CLASSES[raw.bug_class] ? raw.bug_class : 'logic-flaw'
  return {
    bug_class: bugClass,
    reported_bug_class: String(raw.bug_class || ''),
    title: String(raw.title || 'untitled'),
    file: normalizePath(raw.file),
    line: Number.isFinite(raw.line) && raw.line > 0 ? Math.floor(raw.line) : 1,
    function: String(raw.function || '(file-level)').trim(),
    confidence: CONFIDENCE_RANK[raw.confidence] ? raw.confidence : 'Medium',
    description: String(raw.description || ''),
    code: String(raw.code || ''),
    data_flow: String(raw.data_flow || ''),
    reachability: String(raw.reachability || ''),
    impact: String(raw.impact || ''),
    mitigations_checked: String(raw.mitigations_checked || ''),
    recommendation: String(raw.recommendation || ''),
    outside_assigned_classes: raw.outside_assigned_classes === true,
    found_by: groupId,
  }
}

// Deterministic ids: sort by (file, line, bug_class, title) so the same input
// always produces the same id. Nothing here may depend on wall-clock time or
// randomness — the workflow engine replays this on resume.
function assignIds(findings) {
  const sorted = findings.slice().sort((a, b) => {
    const ka = a.file + '\u0000' + pad3(a.line) + '\u0000' + a.bug_class + '\u0000' + a.title
    const kb = b.file + '\u0000' + pad3(b.line) + '\u0000' + b.bug_class + '\u0000' + b.title
    return ka < kb ? -1 : ka > kb ? 1 : 0
  })
  const counters = {}
  for (const f of sorted) {
    const prefix = CLASSES[f.bug_class].prefix
    counters[prefix] = (counters[prefix] || 0) + 1
    f.id = prefix + '-' + pad3(counters[prefix])
  }
  return sorted
}

function pickPrimary(a, b) {
  const ra = CONFIDENCE_RANK[a.confidence] || 2
  const rb = CONFIDENCE_RANK[b.confidence] || 2
  if (ra !== rb) return ra > rb ? a : b
  return a.id <= b.id ? a : b
}

// Tier 1: identical (file, line, bug_class) is a duplicate by construction.
function tier1(findings) {
  const buckets = new Map()
  for (const f of findings) {
    const key = f.file + ':' + f.line + ':' + f.bug_class
    if (!buckets.has(key)) buckets.set(key, [])
    buckets.get(key).push(f)
  }
  const mergedInto = new Map()
  for (const members of buckets.values()) {
    if (members.length < 2) continue
    let primary = members[0]
    for (const m of members.slice(1)) primary = pickPrimary(primary, m)
    for (const m of members) if (m.id !== primary.id) mergedInto.set(m.id, primary.id)
  }
  return mergedInto
}

const NO_FUNCTION = new Set(['', '-', 'none', 'n/a', 'na', 'file-level', '(file-level)', 'filelevel', 'file level'])

function sameFunctionBuckets(findings, mergedInto) {
  const buckets = new Map()
  for (const f of findings) {
    if (mergedInto.has(f.id)) continue
    const fn = f.function.toLowerCase().replace(/[()]/g, '').replace(/[-_\s]+/g, ' ').trim()
    if (NO_FUNCTION.has(fn)) continue
    const key = f.file + '::' + fn
    if (!buckets.has(key)) buckets.set(key, [])
    buckets.get(key).push(f)
  }
  return [...buckets.values()].filter((b) => b.length > 1)
}

// Batch by source file, then split a file that has too many findings for one agent.
// The file is the unit of shared context: one agent opens it once and judges every
// candidate in it, which is why this is cheaper AND better informed than one agent
// per finding. Splitting is balanced rather than greedy (12 findings at a cap of 5
// gives 4+4+4, not 5+5+2) so no agent in the split carries an outlier share.
//
// `items` arrives sorted by file, so a batch is a contiguous run of one file's
// candidates rather than an arbitrary sample of them.
function batchByFile(items, maxPerBatch) {
  const order = []
  const byFile = new Map()
  for (const f of items) {
    if (!byFile.has(f.file)) {
      byFile.set(f.file, [])
      order.push(f.file)
    }
    byFile.get(f.file).push(f)
  }
  const batches = []
  for (const file of order) {
    const members = byFile.get(file)
    const parts = Math.ceil(members.length / maxPerBatch)
    const per = Math.ceil(members.length / parts)
    for (let i = 0; i < members.length; i += per) batches.push(members.slice(i, i + per))
  }
  return batches
}

// Same idea for dedup, but the atom is a whole bucket: a bucket split across two
// agents would hide the duplicate pair that put it there. A bucket bigger than the
// cap therefore goes to one agent on its own.
function batchBuckets(buckets, maxFindings) {
  const order = []
  const byFile = new Map()
  for (const bucket of buckets) {
    const file = bucket[0].file
    if (!byFile.has(file)) {
      byFile.set(file, [])
      order.push(file)
    }
    byFile.get(file).push(bucket)
  }
  const batches = []
  for (const file of order) {
    let current = []
    let size = 0
    for (const bucket of byFile.get(file)) {
      if (current.length && size + bucket.length > maxFindings) {
        batches.push(current)
        current = []
        size = 0
      }
      current.push(bucket)
      size += bucket.length
    }
    if (current.length) batches.push(current)
  }
  return batches
}

function severityRank(s) {
  return { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 }[String(s || '').toUpperCase()] || 0
}

function passesFilter(severity) {
  const min = { all: 1, medium: 2, high: 3 }[SEVERITY_FILTER]
  return severityRank(severity) >= min
}

// ---------------------------------------------------------------------- run

phase('Detect')
const detect = await agent(detectPrompt(), workerOpts({ label: 'detect', phase: 'Detect', schema: DETECT_SCHEMA }))
if (!detect) {
  throw new Error('c-review: detection agent returned nothing; cannot select bug-class groups')
}
log(
  'platform: is_cpp=' + detect.is_cpp + ' is_posix=' + detect.is_posix + ' is_windows=' + detect.is_windows
)

const selected = selectGroups(detect)
if (!selected.length) {
  throw new Error('c-review: no bug-class group applies to this codebase')
}
log(selected.length + ' hunter groups over ' + selected.reduce((n, s) => n + s.classIds.length, 0) + ' bug classes')

// Barrier is deliberate here: dedup needs every finding before judging starts,
// and judging a duplicate twice costs more than the idle time this barrier buys.
phase('Hunt')
const huntResults = await parallel(
  selected.map((sel) => () =>
    agent(
      huntPrompt(sel.group, sel.classIds, detect),
      workerOpts({ label: 'hunt:' + sel.group.id, phase: 'Hunt', schema: HUNT_SCHEMA })
    ).then((r) => ({ groupId: sel.group.id, result: r }))
  )
)

const rawFindings = []
const coverage = []
const hunterNotes = []
const failedGroups = []
const externalSources = []
for (let i = 0; i < huntResults.length; i++) {
  const entry = huntResults[i]
  if (!entry || !entry.result) {
    failedGroups.push(selected[i].group.id)
    continue
  }
  for (const f of entry.result.findings || []) rawFindings.push(normalizeFinding(f, entry.groupId))
  for (const c of entry.result.coverage || []) coverage.push(Object.assign({ group: entry.groupId }, c))
  if (entry.result.notes) hunterNotes.push(entry.groupId + ': ' + entry.result.notes)
  externalSources.push({
    group: entry.groupId,
    consulted: entry.result.external_sources_consulted === true,
    detail: String(entry.result.external_sources_detail || ''),
  })
}
if (failedGroups.length) {
  log('WARNING: ' + failedGroups.length + ' hunter group(s) returned nothing: ' + failedGroups.join(', '))
}

// Declared, not policed. Consulting upstream is legitimate in a real audit and
// nothing here penalises it; the record exists so an eval run scored against a
// public corpus can tell which findings came from reading and which from diffing.
// findings carry found_by, so the declaration resolves per finding.
const declaredExternal = externalSources.filter((e) => e.consulted).map((e) => e.group)
if (declaredExternal.length) {
  log('external sources declared by: ' + declaredExternal.join(', ') + ' (recorded, not penalised)')
}

// EVAL-ONLY. See the injectFindings comment at the top of the file.
for (const raw of INJECT_FINDINGS) {
  const injected = normalizeFinding(raw, String(raw.found_by || 'injected'))
  injected.injected = true
  if (raw.bench_id) injected.bench_id = String(raw.bench_id)
  rawFindings.push(injected)
}
if (INJECT_FINDINGS.length) {
  log(
    'EVAL HOOK: ' + INJECT_FINDINGS.length + ' synthetic finding(s) injected before dedup/judge. ' +
      'This run is a benchmark, not an audit.'
  )
}

const findings = assignIds(rawFindings)
const byId = new Map(findings.map((f) => [f.id, f]))
log(findings.length + ' raw findings from ' + (selected.length - failedGroups.length) + ' groups')

phase('Dedup')
const mergedInto = tier1(findings)
const buckets = sameFunctionBuckets(findings, mergedInto)
// bucketOf is what keeps batching honest: a merge whose members are not all from
// the same bucket is discarded, so one agent holding several buckets can never
// merge two findings in different functions.
const bucketOf = new Map()
for (let b = 0; b < buckets.length; b++) {
  for (const f of buckets[b]) bucketOf.set(f.id, b)
}
let dedupAgents = 0
if (buckets.length) {
  const dedupBatches = batchBuckets(buckets, DEDUP_BATCH_MAX)
  dedupAgents = dedupBatches.length
  log(buckets.length + ' same-function collision(s) in ' + dedupBatches.length + ' dedup agent(s)')
  const dedupResults = await parallel(
    dedupBatches.map((group, i) => () =>
      group.length === 1
        ? agent(
            dedupPrompt(group[0]),
            workerOpts({ label: 'dedup:' + group[0][0].file + '#' + i, phase: 'Dedup', schema: DEDUP_SCHEMA })
          )
        : agent(
            dedupBatchPrompt(group),
            workerOpts({ label: 'dedup:' + group[0][0].file + '#' + i + '+' + group.length, phase: 'Dedup', schema: DEDUP_SCHEMA })
          )
    )
  )
  for (const res of dedupResults) {
    if (!res) continue
    for (const merge of res.merges || []) {
      if (!byId.has(merge.primary) || mergedInto.has(merge.primary)) continue
      for (const dup of merge.duplicates || []) {
        if (dup === merge.primary || !byId.has(dup) || mergedInto.has(dup)) continue
        if (bucketOf.get(dup) !== bucketOf.get(merge.primary)) {
          log('rejected cross-function merge ' + dup + ' -> ' + merge.primary)
          continue
        }
        mergedInto.set(dup, merge.primary)
      }
    }
  }
} else {
  log('no same-function collisions; dedup judgement skipped')
}

const primaries = findings.filter((f) => !mergedInto.has(f.id))
const absorbedBy = new Map()
for (const [dup, primary] of mergedInto) {
  if (!absorbedBy.has(primary)) absorbedBy.set(primary, [])
  absorbedBy.get(primary).push(byId.get(dup))
}
log(primaries.length + ' primaries after dedup (' + mergedInto.size + ' merged)')

phase('Judge')
const judgeBatches = JUDGE_MODE === 'batched' ? batchByFile(primaries, JUDGE_BATCH_MAX) : primaries.map((f) => [f])
log(
  'judge mode ' + JUDGE_MODE + ': ' + primaries.length + ' candidate(s) in ' + judgeBatches.length + ' agent(s)'
)

// A one-candidate batch always takes the single-candidate prompt, in either mode:
// it is the same work, and it keeps the cheaper, longer-standing prompt on the path
// where batching buys nothing.
const verdictLists = await parallel(
  judgeBatches.map((batch) => () => {
    if (batch.length === 1) {
      const f = batch[0]
      return agent(
        judgePrompt(f, detect, absorbedBy.get(f.id) || []),
        workerOpts({ label: 'judge:' + f.id, phase: 'Judge', schema: VERDICT_SCHEMA, effort: 'high' })
      ).then((v) => (v ? [{ id: f.id, verdict: v }] : []))
    }
    const wanted = new Set(batch.map((f) => f.id))
    return agent(
      judgeBatchPrompt(batch, detect, absorbedBy),
      workerOpts({
        label: 'judge:' + batch[0].id + '+' + (batch.length - 1),
        phase: 'Judge',
        schema: BATCH_VERDICT_SCHEMA,
        effort: 'high',
      })
    ).then((res) => {
      if (!res) return []
      const out = []
      const seen = new Set()
      for (const v of res.verdicts || []) {
        // Ignore a verdict for a candidate this agent was not given, and keep the
        // first verdict for an id it answered twice.
        if (!v || !wanted.has(v.id) || seen.has(v.id)) continue
        seen.add(v.id)
        out.push({ id: v.id, verdict: v })
      }
      return out
    })
  })
)

const verdictById = new Map()
for (const list of verdictLists) {
  if (!list) continue
  for (const entry of list) if (entry && entry.verdict) verdictById.set(entry.id, entry.verdict)
}

// Driven by primaries, not by what came back, so a batch that answered for four of
// its five candidates leaves the fifth labelled unjudged instead of dropping it.
const unjudged = []
for (const f of primaries) {
  const verdict = verdictById.get(f.id)
  if (!verdict) {
    unjudged.push(f.id)
    f.fp_verdict = 'LIKELY_TP'
    f.fp_rationale = 'JUDGE DID NOT RUN — verdict and severity are unvalidated'
    f.severity = 'MEDIUM'
    f.severity_validated = false
    continue
  }
  f.fp_verdict = verdict.fp_verdict
  f.fp_rationale = verdict.fp_rationale
  f.severity_validated = true
  const survivor = f.fp_verdict === 'TRUE_POSITIVE' || f.fp_verdict === 'LIKELY_TP'
  if (survivor) {
    f.severity = verdict.severity || 'MEDIUM'
    f.attack_vector = verdict.attack_vector || ''
    f.exploitability = verdict.exploitability || ''
    f.severity_rationale = verdict.severity_rationale || ''
    if (!verdict.severity) f.severity_validated = false
  }
}
if (unjudged.length) {
  log('WARNING: ' + unjudged.length + ' finding(s) reached no judge and are reported unvalidated: ' + unjudged.join(', '))
}

for (const [dup, primary] of mergedInto) {
  byId.get(dup).merged_into = primary
}
for (const [primary, dups] of absorbedBy) {
  byId.get(primary).also_known_as = dups.map((d) => d.id)
}

const survivors = primaries.filter(
  (f) => f.fp_verdict === 'TRUE_POSITIVE' || f.fp_verdict === 'LIKELY_TP'
)
// An unvalidated severity is a guess, so filtering on it would silently drop a
// finding no judge ever saw. Those are always reported and labelled instead.
const reported = survivors.filter((f) => f.severity_validated === false || passesFilter(f.severity))

const verdictCounts = {}
for (const f of primaries) verdictCounts[f.fp_verdict] = (verdictCounts[f.fp_verdict] || 0) + 1
const severityCounts = {}
for (const f of reported) severityCounts[f.severity] = (severityCounts[f.severity] || 0) + 1

const payload = {
  run: {
    threat_model: THREAT_MODEL,
    severity_filter: SEVERITY_FILTER,
    finding_scope_root: SCOPE,
    context_roots: CONTEXT_ROOTS,
    worker_model: WORKER_MODEL || 'inherit',
    judge_mode: JUDGE_MODE,
    judge_batch_size: JUDGE_BATCH_MAX,
    output_dir: OUTPUT_DIR,
    is_cpp: detect.is_cpp,
    is_posix: detect.is_posix,
    is_windows: detect.is_windows,
    platform_evidence: detect.platform_evidence,
    purpose: detect.purpose,
    entry_points: detect.entry_points || [],
    trust_boundaries: detect.trust_boundaries || [],
    existing_hardening: detect.existing_hardening || [],
    groups_attempted: selected.map((s) => s.group.id),
    groups_failed: failedGroups,
    unjudged_findings: unjudged,
    hunter_notes: hunterNotes,
    hunter_external_sources: externalSources,
    injected_findings: INJECT_FINDINGS.length,
  },
  stats: {
    raw_findings: findings.length,
    merged: mergedInto.size,
    primaries: primaries.length,
    survivors: survivors.length,
    reported: reported.length,
    dedup_agents: dedupAgents,
    judge_agents: judgeBatches.length,
    verdict_counts: verdictCounts,
    severity_counts: severityCounts,
  },
  findings: findings,
  coverage: coverage,
}

phase('Persist')
const persisted = await agent(
  persistPrompt(payload),
  workerOpts({ label: 'persist', phase: 'Persist', schema: PERSIST_SCHEMA, effort: 'low' })
)
if (!persisted || !persisted.ok) {
  log('WARNING: artifacts were not written: ' + ((persisted && persisted.error) || 'persist agent returned nothing'))
}

return {
  outputDir: OUTPUT_DIR,
  artifactsWritten: !!(persisted && persisted.ok),
  artifactError: persisted && persisted.ok ? null : (persisted && persisted.error) || 'persist agent returned nothing',
  findingsJson: OUTPUT_DIR + '/findings.json',
  reportMd: OUTPUT_DIR + '/REPORT.md',
  reportSarif: OUTPUT_DIR + '/REPORT.sarif',
  stats: payload.stats,
  groupsAttempted: payload.run.groups_attempted,
  groupsFailed: failedGroups,
  unjudged: unjudged,
  hunterNotes: hunterNotes,
  reportedFindings: reported.map((f) => ({
    id: f.id,
    severity: f.severity,
    severity_validated: f.severity_validated,
    bug_class: f.bug_class,
    title: f.title,
    location: f.file + ':' + f.line,
    function: f.function,
  })),
}
