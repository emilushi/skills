# Every target here mirrors a CI job. If `make check` passes and CI does not, that is a
# bug in this file — fix it here rather than working around it, or the local signal stops
# being trustworthy and everyone goes back to pushing and waiting.
#
# CI jobs covered: Lint (pre-commit: ruff, shellcheck, shfmt), Shell (bats),
# Python tests, Workflow tests, and Validate plugins and skills.
#
# RUFF_VERSION must match the ruff-pre-commit rev in .pre-commit-config.yaml. The
# validator self-test asserts that; bump both together.
RUFF_VERSION := 0.14.13

.DEFAULT_GOAL := check
.NOTPARALLEL:
.PHONY: check self-test lint shell bats shell-suites python-tests workflow-tests validate fix help

## check: most of what CI runs (this is the one you want)
check: self-test lint shell bats python-tests workflow-tests validate
	@echo ""
	@echo "✓ check passed — most of CI, but not the loadability checks, the"
	@echo "  version-increment check, or the non-ruff pre-commit hooks."

## self-test: prove the validators still detect what they exist to detect
# Runs before validate, deliberately. A checker that has silently stopped matching
# reports a clean repo forever; that failure mode has shipped here more than once.
self-test:
	@echo "→ validator self-test"
	@uv run --no-project python3 .github/scripts/validate_plugin_metadata.py --self-test

## lint: ruff check + format, pinned to the version CI uses
lint:
	@echo "→ ruff check"
	@uvx ruff@$(RUFF_VERSION) check --output-format=concise
	@echo "→ ruff format --check"
	@uvx ruff@$(RUFF_VERSION) format --check

## shell: shellcheck + shfmt over every shell script
# plugins/ AND .github/scripts/ — globbing only plugins/ left the repo's own scripts
# unchecked locally, which is where they are most likely to be edited.
shell:
	@echo "→ shellcheck"
	@find plugins .github/scripts -name '*.sh' -type f \
		-exec shellcheck --severity=warning -x {} +
	@echo "→ shfmt"
	@find plugins .github/scripts -name '*.sh' -type f -exec shfmt -i 2 -ci -d {} +

## bats: run plugin bats suites
# Fails when the glob matches nothing: this repo has bats suites, so finding none means
# the discovery broke, not that the shell code is clean.
bats:
	@echo "→ bats"
	@files=$$(find plugins -name '*.bats' -type f); \
	if [ -z "$$files" ]; then \
		echo "  ✗ no .bats files found — discovery is broken (this repo ships bats suites)"; \
		exit 1; \
	fi; \
	echo "$$files" | xargs bats

## shell-suites: run plugin shell regression suites (CI only, see note)
# Deliberately NOT in `check`. zeroize-audit's suite pipes a script to `python3 -`,
# which the modern-python plugin's shim intercepts and rejects, so this target fails
# on any machine with that plugin installed — for reasons that have nothing to do
# with the code under test. CI has no shims and runs it there. See the tracking
# issue: #207.
#
# find, not a glob: `**` needs globstar and degrades to `*` without it, so a suite
# one directory deeper would stop running with no signal.
shell-suites:
	@echo "→ shell regression suites"
	@suites=$$(find plugins -type f -path '*/tests/*' -name 'run_*.sh'); \
	if [ -z "$$suites" ]; then \
		echo "  ✗ no shell regression suites found — discovery is broken"; \
		exit 1; \
	fi; \
	for s in $$suites; do echo "  → $$s"; bash "$$s" || exit 1; done

## python-tests: run plugin Python test files
# pytest, not `python3 <file>` in a loop: a file with no `if __name__ == "__main__"`
# block exits 0 under the loop having run nothing, which reads as a pass.
# --import-mode=importlib is required — c-review and rust-review both ship
# scripts/test_split.py, and the default import mode collides on the basename.
#
# pyyaml and jsonschema are not optional extras. fp-check's suite imports `yaml`
# at module scope to read its eval cases and `jsonschema` to validate the schemas
# its workflow scripts declare; with `--with pytest` alone those files error
# during collection rather than failing informatively, and a collection error in
# one directory is easy to read as "nothing to run here". Keep this list in step
# with the CI job's pip install.
python-tests:
	@echo "→ python tests"
	@dirs=$$(find plugins -type f \( -name 'test_*.py' -o -name '*_test.py' \) \
		-exec dirname {} \; | sort -u); \
	if [ -z "$$dirs" ]; then \
		echo "  ✗ no Python test files found — discovery is broken"; \
		exit 1; \
	fi; \
	failed=0; ran=0; \
	for d in $$dirs; do \
		echo "  → $$d"; \
		( cd "$$d" && uv run --no-project --with pytest --with pyyaml --with jsonschema \
			python3 -m pytest -q --import-mode=importlib . ) || failed=1; \
		ran=$$((ran + 1)); \
	done; \
	echo "  ran $$ran test director(ies)"; \
	exit $$failed

## workflow-tests: logic tests for dynamic-workflow plugins, plus the missing-tests guard
##
## Free: no model, no API key. `python-tests` above already runs the contract
## layer (a plugin's `tests/test_*.py`), so this target exists for the two things
## it cannot do: run `node --test` over the `*.test.mjs` logic/wiring layer, and
## fail a plugin that ships `workflows/` with no tests at all.
##
## Both halves must assert that they asserted something. pytest does so on its
## own (exit 5, "no tests collected"); `node --test` does NOT — it exits 0 on a
## file containing no test() calls and, worse, reports that file as ONE PASSING
## TEST named after its path. So a plain "test count > 0" check is satisfied by
## five empty files reporting five passes. The TAP reporter is parsed instead:
## any file that surfaces as its own top-level entry ran nothing and fails by name.
##
## `set -e` is load-bearing. The recipe is ONE shell invocation with `;` between
## stages, so make reports the status of the LAST command; without it a failing
## node stage followed by a passing one exits 0.

# Plugins that ship workflows/ without logic tests. This is recorded DEBT, not an
# exemption: whatever tests they do have still run, only the missing-category
# check is downgraded to a warning. A plugin NOT named here that ships
# workflows/ with no *.test.mjs fails the build, which is the point.
#
# All four were merged before this target existed and have no tests/ directory at
# all. Removing a name from this list is how that debt gets paid.
WORKFLOW_TESTS_DEBT := audit-context-building insecure-defaults spec-to-code-compliance variant-analysis

workflow-tests:
	@echo "→ workflow logic tests"
	@set -e; \
	dirs=$$(find plugins -mindepth 2 -maxdepth 2 -type d -name workflows); \
	if [ -z "$$dirs" ]; then \
		echo "✗ no plugins/*/workflows/ directory found, so this target — whose entire" >&2; \
		echo "  purpose is running their tests — would have reported success having run" >&2; \
		echo "  none. -mindepth/-maxdepth 2 is load-bearing and fragile: several plugins" >&2; \
		echo "  use the unrelated skills/<skill>/workflows/ convention, and dynamic-workflow" >&2; \
		echo "  placement is early-access surface. If it has moved, fix the find above." >&2; \
		exit 1; \
	fi; \
	ran=0; \
	for d in $$dirs; do \
		plugin=$$(dirname $$d); \
		name=$$(basename $$plugin); \
		mjs=$$(find $$plugin/tests -maxdepth 1 -name '*.test.mjs' 2>/dev/null || true); \
		known_debt=0; \
		for known in $(WORKFLOW_TESTS_DEBT); do \
			if [ "$$name" = "$$known" ]; then known_debt=1; fi; \
		done; \
		if [ -z "$$mjs" ]; then \
			if [ "$$known_debt" -eq 1 ]; then \
				echo "  ⚠ $$plugin: ships workflows/ with no logic tests (known debt, see WORKFLOW_TESTS_DEBT)"; \
			else \
				echo "✗ $$plugin ships workflows/ but has no *.test.mjs logic tests" >&2; \
				echo "  A schema-and-shape contract test cannot tell you whether a gate's" >&2; \
				echo "  answer is ever read. Add tests/ or add the plugin to" >&2; \
				echo "  WORKFLOW_TESTS_DEBT with a reason." >&2; \
				exit 1; \
			fi; \
			continue; \
		fi; \
		echo "  $$plugin: node --test $$(echo $$mjs | wc -w | tr -d ' ') file(s)"; \
		tap=$$(mktemp); \
		if ! node --test --test-reporter=tap $$mjs >"$$tap" 2>&1; then \
			sed 's/^/    /' "$$tap" >&2; rm -f "$$tap"; \
			echo "✗ $$plugin: node --test failed" >&2; exit 1; \
		fi; \
		total=$$(sed -n 's/^# tests \([0-9][0-9]*\)$$/\1/p' "$$tap" | tail -1); \
		names=$$(sed -n 's/^ok [0-9][0-9]* - //p' "$$tap"); \
		bare=""; \
		for f in $$mjs; do \
			if printf '%s\n' "$$names" | grep -Fxq "$$f"; then bare="$$bare $$f"; fi; \
		done; \
		if [ -n "$$bare" ]; then \
			rm -f "$$tap"; \
			echo "✗ $$plugin: these files declared no test():$$bare" >&2; \
			echo "  node reports such a file as one passing test named after itself and" >&2; \
			echo "  exits 0, so the suite would go green having asserted nothing." >&2; \
			exit 1; \
		fi; \
		case "$$total" in \
			'' | *[!0-9]*) \
				rm -f "$$tap"; \
				echo "✗ $$plugin: no '# tests N' line in node's TAP output, so the test" >&2; \
				echo "  count could not be read and a zero-assertion run would pass." >&2; \
				echo "  node's reporter format has changed; fix the parse in the Makefile." >&2; \
				exit 1;; \
		esac; \
		if [ "$$total" -eq 0 ]; then \
			rm -f "$$tap"; \
			echo "✗ $$plugin: node --test ran 0 tests" >&2; exit 1; \
		fi; \
		rm -f "$$tap"; \
		echo "    $$total test(s) passed"; \
		ran=$$((ran + 1)); \
	done; \
	if [ "$$ran" -eq 0 ]; then \
		echo "⚠ every plugin shipping workflows/ is on WORKFLOW_TESTS_DEBT, so no logic"; \
		echo "  test ran. That is the recorded state, not a discovery failure."; \
	fi

## validate: plugin metadata, structure, and cross-references
# Scans every plugin. CI scopes to the plugins a PR touches, so local is a strict
# superset and cannot pass where CI fails. Do not narrow it to match: the
# zero-reference guard only arms on a full scan.
validate:
	@echo "→ validate plugin metadata"
	@uv run --no-project python3 .github/scripts/validate_plugin_metadata.py

## fix: apply the formatting CI would otherwise reject
fix:
	@uvx ruff@$(RUFF_VERSION) check --fix || true
	@uvx ruff@$(RUFF_VERSION) format
	@find plugins -name '*.sh' -type f -exec shfmt -i 2 -ci -w {} +

## help: list targets
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## /  /'
