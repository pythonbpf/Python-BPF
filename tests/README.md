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

### Globals

The selftest corpus overwhelmingly reports results through global variables: the
program writes a global and the driver reads it back. Ports keep that shape with
`@bpfglobal` scalars, so a future userspace driver reads the same `.bss`/`.data`
values the kernel's driver does. Anything a global cannot yet hold (arrays,
structs, strings) is a roadmap test, not a workaround.

The one substitution still in use is `WORKAROUND(atomics)`: upstream counters
incremented with `__sync_fetch_and_add` are plain `x += 1` here, tagged on the
line so the sweep is mechanical once atomics land. `PORTING-NOTES.md` in that
directory records every port, its rewrite if any, and why the rest of the
corpus is out of reach; `tools/selftest-audit.py` regenerates that scoring.

Anything importing from `vmlinux` belongs in `vmlinux/`, which is registered in
`VMLINUX_TEST_DIRS_PASSING` so it is skipped rather than failed where no
`vmlinux.py` has been generated.

## Property-based tests (`tests/property/`)

The integer rules in `docs/user-guide/integers.md` are tested with
[Hypothesis](https://hypothesis.readthedocs.io): instead of hand-picked cases,
programs are generated, and each one is compiled two ways and run.

* **The oracle is clang.** Every generated program is printed twice, as
  PythonBPF and as the equivalent C. clang compiles the C (`-O0 -fwrapv`) to a
  native object; PythonBPF's IR is retargeted to the host. Both are JIT-run
  in a worker process (a miscompile can trap or abort inside LLVM, which must
  not take pytest down with it) and must return the same value.
* **A model keeps undefined behaviour out.** `cints.py` implements C's
  promotions, usual arithmetic conversions and operators. Programs where C
  would be undefined (division by zero, `MIN / -1`, shift counts out of
  range) are discarded before anything runs. The model is also checked
  against clang on every example, so a disagreement is reported as a model
  bug, never blamed on PythonBPF.

| File | Property |
|---|---|
| `test_int_expressions.py` | Random straight-line programs over every ctypes integer type and `c_bool`: `+ - * / // % << >> & \| ^`, comparisons as values, unary `-`, `not`, constructor casts, typed and untyped temporaries, nested. The worked examples of `integers.md` are pinned with `@example`. |
| `test_int_operators.py` | Every binary operator, parametrized by the left operand's type, with the right type and both values drawn (edge values first). Random trees rarely reach a negative dividend under a signed `%` and return it undisturbed; this property always does. |
| `test_int_conversions.py` | Every conversion site, parametrized by the destination type: constructor call, declaration, reassignment, untyped local, global store, `return`, global initialiser, and each augmented assignment. The converted value is read back through an expression whose result depends on its sign and width, not just returned, so a value stored with the right bits but the wrong type is caught too. |
| `test_known_gaps.py` | Each known divergence's smallest program, as a strict xfail. |

### Known gaps

`known_gaps.py` lists the divergences from C the suite has found and not yet
had fixed. Each has a predicate, so the properties step around it and keep
finding *new* bugs, and a pinned program that `test_known_gaps.py` runs as a
strict xfail. A fix makes that test XPASS, failing the run until the gap is
deleted, at which point the properties cover that ground again. The
operator and conversion properties step around a gap by drawing only what
avoids it (not by filtering, which Hypothesis rightly complains about), with
a comment naming the gap.

### Running

```bash
pytest tests/property                              # dev profile: 100 examples
HYPOTHESIS_PROFILE=thorough pytest tests/property  # 3000 examples, for bug hunting
```

CI uses the `ci` profile (100 examples, derandomized, so a failure always
reproduces): about two and a half minutes on a 16-core machine. The
operator and conversion properties are parametrized by type, so every type
is tested on every run, and run a sixteenth of the profile's count per
parameter. Profiles are registered in `conftest.py`. A failure prints both programs and the model's value;
Hypothesis shrinks it to the smallest program that still fails.

### Plan

1. **Integers and conversions** (done): the three properties above. A
   mutation check (deliberately breaking `>>`, `%`, `/`, the usual arithmetic
   conversions, integer promotion, sign extension and `c_bool` conversion in
   the compiler) is caught every time, each shrunk to a program of two or
   three lines.
2. **Fix the known gaps**, each on its own branch; its strict xfail flips to
   XPASS and the gap is deleted.
3. **Widen the sites**: struct field stores and vmlinux field reads; map keys
   and values, which needs helper calls stubbed with host functions in the
   JIT; `range()` loops with random bounds, steps and types against CPython.
4. **Robustness**: every generated program in the supported subset must
   also pass `llc` for BPF, and a program outside the subset must be rejected
   with a deliberate error, never an internal `KeyError` or `TypeError`.

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
│   ├── host_jit.py            ← run a helper-free program's IR on the host
│   └── verifier.py            ← bpftool subprocess wrapper
├── property/                  ← Hypothesis property tests (integers, conversions)
│   ├── cints.py               ← reference model of C's integer rules
│   ├── programs.py            ← generated programs, printed as PythonBPF and C
│   ├── harness.py             ← compile both, JIT-run in a worker, compare
│   └── known_gaps.py          ← divergences found and not yet fixed
├── passing_tests/             ← programs that should compile and verify cleanly
├── failing_tests/             ← programs with known issues (declared in test_config.toml)
└── kernel_selftest_equivalent/ ← ports of kernel selftests + feature roadmap tests
```
