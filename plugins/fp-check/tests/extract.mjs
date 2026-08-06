import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

export const WORKFLOWS = join(dirname(fileURLToPath(import.meta.url)), '..', 'workflows')

/**
 * Pull a named top-level function out of a workflow script and evaluate it in
 * isolation.
 *
 * Workflow scripts have no module system, so pure helpers are defined inline in
 * the script and cannot be imported. Extracting them from the source text is the
 * only way to unit-test the deterministic logic without a model.
 *
 * Relies on the function's closing brace sitting at column 0, which is true for
 * every top-level declaration in these scripts.
 *
 * Throws if the function is absent — a missing function must fail loudly, never
 * silently skip, or the suite would report success having tested nothing.
 */
export function loadFn(scriptPath, name) {
  return loadFns(scriptPath, name)[name]
}

/**
 * Pull SEVERAL named functions out of a script and evaluate them in one scope,
 * so a helper that calls a sibling works.
 *
 * `loadFn` evaluates one function alone, which makes any call to a sibling a
 * ReferenceError. The workaround was to inline the sibling's logic at both call
 * sites — and duplicated logic in a gate is exactly the drift this suite exists
 * to catch, so the harness gives way instead of the code.
 *
 * Returns an object keyed by name. Order does not matter: function declarations
 * are hoisted within the scope.
 *
 * @param {string} scriptPath
 * @param {...string} names
 * @returns {Record<string, Function>}
 */
export function loadFns(scriptPath, ...names) {
  const sources = names.map((name) => extractFn(scriptPath, name))
  const body = `${sources.join('\n')}\nreturn { ${names.join(', ')} }`
  return new Function(body)()
}

function extractFn(scriptPath, name) {
  const src = readFileSync(scriptPath, 'utf8')
  const re = new RegExp(`^function\\s+${name}\\s*\\([\\s\\S]*?\\n\\}`, 'gm')

  const candidates = []
  for (const m of src.matchAll(re)) {
    // A `^function` at column 0 cannot sit inside a LINE comment — `// function`
    // does not match — but it can sit inside a BLOCK comment, and `.match()`
    // returns the earliest hit. So a commented-out copy of a helper shadowed the
    // real definition and the unit tests graded the comment: breaking
    // confidenceBand to `return {label:'HIGH'}` while leaving a correct copy in a
    // `/* ... */` above it kept all 32 assertions in review.test.mjs green.
    const before = src.slice(0, m.index)
    const opens = (before.match(/\/\*/g) || []).length
    const closes = (before.match(/\*\//g) || []).length
    if (opens > closes) continue
    candidates.push(m[0])
  }

  if (candidates.length === 0) throw new Error(`function ${name} not found in ${scriptPath}`)
  // Ambiguity is a hard stop rather than a first-wins guess: two live definitions
  // means the tests and the workflow may not be grading the same one.
  if (candidates.length > 1) {
    throw new Error(
      `function ${name} is defined ${candidates.length} times in ${scriptPath}; ` +
        `refusing to guess which definition the tests should grade`,
    )
  }
  // The SOURCE TEXT, not an evaluated function: loadFns needs to place several
  // of these in one scope so a helper can call a sibling.
  return candidates[0]
}

export const script = (file) => join(WORKFLOWS, file)

/**
 * Run a whole workflow script against fake agents and return what it returned.
 *
 * `loadFn` tests each pure helper in isolation, which leaves the wiring
 * untested: a review found that disabling twelve separate call sites — the
 * `gate.status !== 'PROCEED'` halt, the `isAcceptableBuild` gate, the severity
 * cap, the band check — changed no test at all. Every one of those helpers was
 * covered; none was covered *where it is used*, so the assertions were
 * decorative. This closes that by executing the real script body.
 *
 * The body is wrapped in an async function exactly as `test_script_parses`
 * wraps it for `node --check`, which is what makes top-level `await` and
 * `return` legal. `agent` is served from `agentResponses`, keyed by the call's
 * `label` (falling back to positional order), so a test scripts what each stage
 * answers and asserts on the status that comes back.
 *
 * @param {string} file      workflow filename, e.g. 'review-poc.js'
 * @param {object} opts
 * @param {object} opts.args        the `args` global the script destructures
 * @param {object} opts.agents      label -> response (or a function of the prompt)
 * @param {Array}  [opts.sequence]  responses by call order, when labels collide
 * @returns {Promise<{result: any, calls: Array, logs: string[], phases: string[]}>}
 */
export async function runScript(file, { args, agents = {}, sequence = null }) {
  const src = readFileSync(script(file), 'utf8')
  const body = src.replace(/^export const meta = \{[\s\S]*?\n\}\n/, '')
  if (body === src) throw new Error(`${file}: could not strip the meta block`)

  const calls = []
  const logs = []
  const phases = []

  const agent = async (prompt, opts = {}) => {
    const label = opts.label || `call-${calls.length}`
    calls.push({ label, prompt, opts })
    if (sequence) return sequence[calls.length - 1]
    const canned = Object.prototype.hasOwnProperty.call(agents, label)
      ? agents[label]
      : agents[label.split(':')[0]]
    return typeof canned === 'function' ? canned(prompt) : canned
  }
  // Mirrors the real contract: a thunk that throws resolves to null rather than
  // rejecting the whole call, so `.filter(Boolean)` is what removes it.
  const parallel = async (thunks) =>
    Promise.all(thunks.map((t) => Promise.resolve().then(t).catch(() => null)))
  const pipeline = async (items, ...stages) => {
    const out = []
    for (const [i, item] of items.entries()) {
      let value = item
      for (const stage of stages) value = await stage(value, item, i)
      out.push(value)
    }
    return out
  }

  const fn = new Function(
    'args', 'agent', 'parallel', 'pipeline', 'log', 'phase', 'budget', 'workflow',
    `return (async () => {\n${body}\n})()`,
  )
  const result = await fn(
    args,
    agent,
    parallel,
    pipeline,
    (m) => logs.push(String(m)),
    (p) => phases.push(String(p)),
    { total: null, spent: () => 0, remaining: () => Infinity },
    async () => {
      throw new Error('nested workflow() is not supported in tests')
    },
  )
  return { result, calls, logs, phases }
}
