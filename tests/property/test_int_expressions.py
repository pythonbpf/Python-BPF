"""
Integer expressions: PythonBPF computes what clang computes.

Random straight-line programs over every ctypes integer type (and c_bool):
arithmetic, division and remainder, shifts, comparisons used as values, unary
minus, `not`, constructor casts and untyped temporaries, nested. Each one is
printed as PythonBPF and as C, both are run on the host, and the results must
be equal. The rules being exercised are docs/user-guide/integers.md; clang is
their specification.
"""

import pytest
from hypothesis import assume, example, given

from tests.property.cints import (
    C_INT8,
    C_INT32,
    C_INT64,
    C_UINT8,
    C_UINT16,
    C_UINT32,
    C_UINT64,
)
from tests.property.harness import CLANG, check_against_clang
from tests.property.known_gaps import gap_of
from tests.property.programs import (
    Bin,
    Cast,
    ExpressionProgram,
    Lit,
    Neg,
    Var,
    expression_programs,
)

pytestmark = pytest.mark.skipif(CLANG is None, reason="clang is not installed")


def _p(inputs, result, temps=()):
    return ExpressionProgram(list(inputs), list(temps), result)


def _v(name, ty):
    return Var(name, ty)


# The worked examples in integers.md, pinned so they always run.
DOC_EXAMPLES = [
    # u32 * u32 wraps at 32 bits before any widening
    _p(
        [("a0", C_UINT32, 0x80000000), ("a1", C_UINT32, 2)],
        Bin("*", _v("a0", C_UINT32), _v("a1", C_UINT32)),
    ),
    # mixed signs go unsigned: 10u / -2 is 10 / 0xfffffffe
    _p(
        [("a0", C_UINT32, 10), ("a1", C_INT32, -2)],
        Bin("/", _v("a0", C_UINT32), _v("a1", C_INT32)),
    ),
    # c_uint64(10) > c_int64(-1) is an unsigned compare: false
    _p(
        [("a0", C_UINT64, 10), ("a1", C_INT64, -1)],
        Bin(">", _v("a0", C_UINT64), _v("a1", C_INT64)),
    ),
    # the literal -2 is an int, so count / -2 is a u32 division
    _p([("a0", C_UINT32, 10)], Bin("/", _v("a0", C_UINT32), Neg(Lit(2)))),
    # narrow operands promote to int: s8 * u16 is a signed 32-bit product
    _p(
        [("a0", C_INT8, -3), ("a1", C_UINT16, 65535)],
        Bin("*", _v("a0", C_INT8), _v("a1", C_UINT16)),
    ),
    # a constructor-typed temporary keeps its width: c_uint8(300) is 44
    _p(
        [("a0", C_INT32, 300)],
        Bin("+", _v("t0", C_UINT8), Lit(0)),
        temps=[("t0", C_UINT8, Cast(C_UINT8, _v("a0", C_INT32)))],
    ),
]


def _pin(*programs):
    def wrap(fn):
        for program in reversed(programs):
            fn = example(program)(fn)
        return fn

    return wrap


@_pin(*DOC_EXAMPLES)
@given(expression_programs())
def test_integer_expression_matches_clang(program):
    assume(gap_of(program) is None)
    check_against_clang(program.program(), program.expected)
