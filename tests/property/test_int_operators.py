"""
Every binary operator on every pair of operand types: PythonBPF computes what
clang computes.

test_int_expressions finds bugs in how operations combine, but random trees
rarely put, say, a negative dividend under a signed `%` and then return the
result undisturbed (about 3 programs in 600 did). This property is the
enumerated complement: `a0 op a1` for each operator, left type and right type,
with Hypothesis choosing the operand values, the edge values of each type
first. Shift counts are drawn in range, since an out-of-range count is
undefined in C.
"""

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from tests.property.cints import (
    ALL_TYPES,
    ARITH_OPS,
    COMPARE_OPS,
    DIV_OPS,
    SHIFT_OPS,
    promote,
)
from tests.property.harness import CLANG, check_against_clang
from tests.property.known_gaps import gap_of
from tests.property.programs import Bin, ExpressionProgram, Var, values_of

pytestmark = pytest.mark.skipif(CLANG is None, reason="clang is not installed")

TYPES = st.sampled_from(ALL_TYPES)


# Parametrized over the left operand's type as well as the operator, so every
# type gets examples on every run (153 parameters, a sixteenth of the
# profile's examples each).
@pytest.mark.parametrize("left_ty", ALL_TYPES, ids=lambda t: t.name)
@pytest.mark.parametrize("op", ARITH_OPS + DIV_OPS + SHIFT_OPS + COMPARE_OPS)
@settings(max_examples=max(5, settings.default.max_examples // 16))
@given(right_ty=TYPES, data=st.data())
def test_binary_operator_matches_clang(op, left_ty, right_ty, data):
    left = data.draw(values_of(left_ty), label="left")
    if op in SHIFT_OPS:
        count = st.integers(0, min(promote(left_ty).bits - 1, right_ty.max))
        right = data.draw(count, label="right")
    else:
        right = data.draw(values_of(right_ty), label="right")
    program = ExpressionProgram(
        [("a0", left_ty, left), ("a1", right_ty, right)],
        [],
        Bin(op, Var("a0", left_ty), Var("a1", right_ty)),
    )
    assume(gap_of(program) is None)
    check_against_clang(program.program(), program.expected)
