# PythonBPF Test Suite

## Quick start

```bash
# Activate the venv and install test deps (once)
source .venv/bin/activate
uv pip install -e ".[test]"

# Run the full suite (IR + LLC levels, no sudo required)
make test

# Run with coverage report
make test-cov
```

## Test levels

Tests are split into three levels, each in a separate file:

| Level | File | What it checks | Needs sudo? |
|---|---|---|---|
| 1 — IR generation | `test_ir_generation.py` | `compile_to_ir()` completes without exception or `logging.ERROR` | No |
| 2 — LLC compilation | `test_llc_compilation.py` | Level 1 + `llc` produces a non-empty `.o` file | No |
| 3 — Kernel verifier | `test_verifier.py` | `bpftool prog load -d` exits 0 | Yes |

Levels 1 and 2 run together with `make test`. Level 3 is opt-in:

```bash
make test-verifier   # requires bpftool and sudo
```

## Running a single test

Tests are parametrized by file path. Use `-k` to filter:

```bash
# By file name
pytest tests/ -v -k "and.py" -m "not verifier"

# By category
pytest tests/ -v -k "conditionals" -m "not verifier"

# One specific level only
pytest tests/test_ir_generation.py -v -k "hash_map.py"
```

## Coverage report

```bash
make test-cov
```

- **Terminal**: shows per-file coverage with missing lines after the test run.
- **HTML**: written to `htmlcov/index.html` — open in a browser for line-by-line detail.

```bash
xdg-open htmlcov/index.html
```

`htmlcov/` and `.coverage` are excluded from git (listed in `.gitignore` if not already).

## Expected failures (`test_config.toml`)

Known-broken tests are declared in `tests/test_config.toml`:

```toml
[xfail]
"failing_tests/my_test.py" = {reason = "...", level = "ir"}
```

- `level = "ir"` — fails during IR generation.
- `level = "llc"` — IR generates fine but `llc` rejects it.
- `level = "verifier"` — IR and `llc` both succeed, but the kernel verifier rejects the object.

A failure at one level implies failure at every later one, so the declared level marks
that level **and all later ones** xfail. An `"ir"` entry is xfail at all three levels; a
`"verifier"` entry is xfail at level 3 only and must still pass levels 1 and 2.

Every test file runs at every level, including the ones declared here — level 3 does not
skip declared failures, it reports them as expected ones.

All xfails use `strict = True`: if a test starts **passing** it shows up as **XPASS** and is treated as a test failure. This is intentional — it means the bug was fixed and the test should be promoted to `passing_tests/`.

## Adding a new test

1. Create a `.py` file in `tests/passing_tests/<category>/` with the usual `@bpf` decorators and a `compile()` call at the bottom.
2. Run `make test` — the file is discovered and tested automatically at all levels.
3. If the test is expected to fail, add it to `tests/test_config.toml` instead of `passing_tests/`.

## Kernel selftest equivalents

`tests/kernel_selftest_equivalent/` contains PythonBPF versions of important
kernel BPF selftests from `bpf-next/tools/testing/selftests/bpf`. Each file names
its upstream original in a header comment.

The directory holds two kinds of test, and both are useful:

- **Ports that pass.** A program PythonBPF can already express. These widen the
  range of program types under test — `raw_tp`, `perf_event`,
  `tracepoint/sched/*` and others that nothing else exercises.
- **Roadmap tests that fail.** A program describing a feature PythonBPF should
  grow next. These must be listed as **strict** expected failures in
  `tests/test_config.toml` until the feature lands, at which point they turn up
  as XPASS and should be promoted.

### What a passing port proves — and does not

A kernel selftest is two halves: the BPF program under `progs/`, and a userspace
driver under `prog_tests/` that loads it through a skeleton, triggers it and
asserts on the result. **Only the BPF half is ported**, because this framework
compiles and verifies programs but never runs them.

So a passing test here says PythonBPF emits a loadable, verifiable object for
that program type and feature mix. It does not say the program behaves the way
the kernel's version does. Treat it as a compiler assertion, not a semantic one.

### `WORKAROUND(globals)`

The selftest corpus overwhelmingly reports results through global variables: the
program writes a global and the driver reads it back. PythonBPF has no global
variable support, so each becomes a one-entry `HashMap` keyed by index, tagged in
a comment naming the variable it replaces:

```bash
grep -rn "WORKAROUND(globals)" tests/kernel_selftest_equivalent/
```

This is deliberate scaffolding, not the intended shape — the tag exists so the
sweep is mechanical once real globals land. It is not a cosmetic substitution
either: it changes what a future userspace driver would read.

Anything importing from `vmlinux` belongs in `vmlinux/`, which is registered in
`VMLINUX_TEST_DIRS_PASSING` so it is skipped rather than failed where no
`vmlinux.py` has been generated.

## Directory structure

```
tests/
├── README.md                  ← you are here
├── conftest.py                ← pytest config: discovery, xfail/skip injection, fixtures
├── test_config.toml           ← expected-failure list
├── test_ir_generation.py      ← Level 1
├── test_llc_compilation.py    ← Level 2
├── test_verifier.py           ← Level 3 (opt-in, sudo)
├── framework/
│   ├── bpf_test_case.py       ← BpfTestCase dataclass
│   ├── collector.py           ← discovers test files, reads test_config.toml
│   ├── compiler.py            ← wrappers around compile_to_ir() + _run_llc()
│   └── verifier.py            ← bpftool subprocess wrapper
├── passing_tests/             ← programs that should compile and verify cleanly
├── failing_tests/             ← programs with known issues (declared in test_config.toml)
└── kernel_selftest_equivalent/ ← ports of kernel selftests + feature roadmap tests
```
