"""
Each known gap's smallest program, as a strict xfail: when a fix lands it
XPASSes and fails the run, as a reminder to delete the gap from
tests/property/known_gaps.py so the properties cover that ground again.
"""

import pytest

from tests.property.cints import C_BOOL, C_INT64, convert
from tests.property.harness import CLANG, check_against_clang
from tests.property.known_gaps import GAPS
from tests.property.programs import Program

pytestmark = pytest.mark.skipif(CLANG is None, reason="clang is not installed")


@pytest.mark.parametrize(
    "gap",
    [
        pytest.param(
            g,
            id=g.name,
            marks=pytest.mark.xfail(
                strict=True, raises=AssertionError, reason=g.reason
            ),
        )
        for g in GAPS
    ],
)
def test_known_gap_still_diverges(gap):
    assert gap.hits(gap.example), "the pinned program must hit its own gap"
    check_against_clang(gap.example.program(), gap.example.expected)


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason="shift-result-type, in augmented assignment: `x >>= a` with x a "
    "c_int32 and a a c_uint32 shifts logically in u32; C shifts x's own int",
)
def test_known_gap_augassign_shift():
    program = Program(
        ["a0 = c_uint32(1)", "x = c_int32(-2147483648)", "x >>= a0", "return x"],
        ["unsigned int a0 = 1;", "int x = -2147483648;", "x >>= a0;", "return x;"],
    )
    check_against_clang(program, lambda: convert(-(2**31) >> 1, C_INT64))


GLOBAL_INIT_REASON = (
    "global-initialiser: a @bpfglobal initialiser that is not a bare constant "
    "(c_int64(-5) is not: -5 is a UnaryOp) is emitted as 0, and a constant is "
    "not converted to the type, so c_bool(2) keeps the low bit, 0, where C "
    "gives 1 (pythonbpf/globals_pass.py, _emit_global). "
    "test_int_conversions' global_init site steps around both."
)


@pytest.mark.xfail(strict=True, raises=AssertionError, reason=GLOBAL_INIT_REASON)
@pytest.mark.parametrize(
    "ty, literal", [(C_INT64, -5), (C_BOOL, 2)], ids=["negative", "c_bool"]
)
def test_known_gap_global_initialiser(ty, literal):
    program = Program(["return g"], ["return g;"], globals=[("g", ty, literal)])
    check_against_clang(program, lambda: convert(convert(literal, ty), C_INT64))
