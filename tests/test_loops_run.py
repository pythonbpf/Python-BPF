"""
Loops: what they compute.

Levels 1 and 2 only prove the passing_tests/loops cases compile. A loop that
compiles can still run the wrong number of times, or forever, so this test
JIT-compiles each helper-free case on the host and checks the value it returns
against what CPython returns for the same function body. Every expected value
below was checked that way.
"""

import subprocess
from pathlib import Path

import pytest

from tests.framework.compiler import run_ir_generation
from tests.framework.host_jit import run_in_subprocess

LOOPS_DIR = Path(__file__).parent / "passing_tests" / "loops"

# file -> return value of hello(ctx) under CPython
CASES = {
    "for_break.py": 5,
    "for_continue.py": 25,
    "for_range_start_stop_step.py": 20,
    "for_range_sum.py": 10,
    "loop_else.py": 104,
    "nested_for.py": 9,
    "range_negative_step.py": 22,
    "rebind_loop_var.py": 10,
    "while_basic.py": 10,
    "while_true_break.py": 10,
    "pass_body.py": 3,
    "while_true_return_i32.py": 6,
    "range_step_overflow_signed.py": 22,
    "range_step_overflow_unsigned.py": 1,
    "range_u32_stop_negative_start.py": 4,
    "reuse_loop_var_signedness.py": 303,
    "loop_var_shared.py": 60,
}

# file -> why it returns something else today (strict: a fix shows as XPASS)
XFAIL = {
    # Every local gets one slot typed by its first binding, so the second
    # loop's `i` is unsigned and `i < 0` never holds. Not a loop bug:
    # `x = n_u64; x = -3` does the same, so the fix is general (one variable
    # per web of reaching definitions), not anything loop-specific.
    "reuse_loop_var_signedness.py": "one slot per name, typed by its first binding",
}


@pytest.mark.parametrize(
    "name",
    [
        pytest.param(name, marks=pytest.mark.xfail(reason=XFAIL[name], strict=True))
        if name in XFAIL
        else name
        for name in CASES
    ],
)
def test_loop_result(name, tmp_path):
    expected = CASES[name]
    ll_path = tmp_path / name.replace(".py", ".ll")
    run_ir_generation(LOOPS_DIR / name, ll_path)
    try:
        got = run_in_subprocess(ll_path, "hello", timeout=10)
    except subprocess.TimeoutExpired:
        pytest.fail(f"{name}: did not terminate (expected to return {expected})")
    except subprocess.CalledProcessError as e:
        pytest.fail(f"{name}: could not run on the host:\n{e.stderr.strip()}")
    assert got == expected, f"{name}: returned {got}, CPython returns {expected}"
