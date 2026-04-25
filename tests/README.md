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

- `level = "ir"` — fails during IR generation; both IR and LLC tests are marked xfail.
- `level = "llc"` — IR generates fine but `llc` rejects it; only the LLC test is marked xfail.

All xfails use `strict = True`: if a test starts **passing** it shows up as **XPASS** and is treated as a test failure. This is intentional — it means the bug was fixed and the test should be promoted to `passing_tests/`.

## Adding a new test

1. Create a `.py` file in `tests/passing_tests/<category>/` with the usual `@bpf` decorators and a `compile()` call at the bottom.
2. Run `make test` — the file is discovered and tested automatically at all levels.
3. If the test is expected to fail, add it to `tests/test_config.toml` instead of `passing_tests/`.

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
└── failing_tests/             ← programs with known issues (declared in test_config.toml)
```
