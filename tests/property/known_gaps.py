"""
Known divergences from C that the property tests step around.

Each gap has a predicate that recognises a generated program hitting it, so
the properties keep looking for *new* bugs instead of re-finding this one, and
a pinned program that test_known_gaps.py runs as a strict xfail. When a fix
lands, that test XPASSes and fails the run: delete the gap here then, and the
properties start generating those programs again.
"""

from dataclasses import dataclass
from typing import Callable

from tests.property.cints import (
    C_INT8,
    C_INT32,
    C_INT64,
    C_UINT8,
    C_UINT32,
    C_UINT64,
    COMPARE_OPS,
    SHIFT_OPS,
    common_type,
    promote,
    untyped_local_type,
)
from tests.property.programs import Bin, ExpressionProgram, Lit, Neg, Not, Var


def walk(expr):
    yield expr
    for child in ("operand", "left", "right"):
        if hasattr(expr, child):
            yield from walk(getattr(expr, child))


def nodes(program: ExpressionProgram):
    for _, _, expr in program.temps:
        yield from walk(expr)
    yield from walk(program.result)


@dataclass(frozen=True)
class Gap:
    name: str
    reason: str
    hits: Callable[[ExpressionProgram], bool]
    # The smallest program showing it, run by test_known_gaps.py as a strict xfail
    example: ExpressionProgram


GAPS: list[Gap] = [
    Gap(
        "negated-literal-rank",
        "`-2147483648` folds to a literal ranked by its negated value (int); "
        "C ranks -x by x, and 2147483648 is a long long "
        "(pythonbpf/expr/expr_pass.py, the USub constant fold)",
        lambda p: any(
            isinstance(n, Neg)
            and isinstance(n.operand, Lit)
            and n.operand.value == 2**31
            for n in nodes(p)
        ),
        # C: a 64-bit signed compare, 1. PythonBPF: an unsigned 32-bit one, 0.
        ExpressionProgram(
            [("a0", C_UINT32, 1)], [], Bin("<", Neg(Lit(2**31)), Var("a0", C_UINT32))
        ),
    ),
    Gap(
        "untyped-local-unary-or-compare",
        '`t = -x`, `t = not x` and `t = a < b` fail with "Undefined variable '
        't": the allocation pass has no case for a UnaryOp or Compare '
        "right-hand side, so the local never gets a slot "
        "(pythonbpf/allocation_pass.py, _allocate_for_value)",
        lambda p: any(
            isinstance(e, (Neg, Not)) or (isinstance(e, Bin) and e.op in COMPARE_OPS)
            for _, _, e in p.temps
        ),
        ExpressionProgram(
            [("a0", C_INT32, 3)],
            [("t0", C_INT64, Neg(Var("a0", C_INT32)))],
            Var("t0", C_INT64),
        ),
    ),
    Gap(
        "shift-result-type",
        "a shift is typed by the usual arithmetic conversions of both operands; "
        "C types it by the promoted left operand alone, so `int << s64` must "
        "wrap at 32 bits and `s64 >> u64` must be arithmetic "
        "(pythonbpf/expr/expr_pass.py _handle_binary_op_impl, "
        "type_inference.py infer_int_type, and for `<<=`/`>>=` "
        "functions/functions_pass.py's augmented assignment)",
        lambda p: any(
            isinstance(n, Bin)
            and n.op in SHIFT_OPS
            and promote(n.left.ty) != common_type(n.left.ty, n.right.ty)
            for n in nodes(p)
        ),
        # C: -8 >> 1 in s64, -4. PythonBPF: a logical shift in u64.
        ExpressionProgram(
            [("a0", C_INT64, -8), ("a1", C_UINT64, 1)],
            [],
            Bin(">>", Var("a0", C_INT64), Var("a1", C_UINT64)),
        ),
    ),
    Gap(
        "untyped-copy-keeps-narrow-type",
        "`t = a` gives t a's own type, so a c_bool/c_uint8/c_uint16 copy stays "
        "narrow and promotes to int; integers.md says an undeclared local is "
        "always 64 bits with the expression's sign (unsigned here). Code or "
        "doc: a decision (pythonbpf/allocation_pass.py, _allocate_for_name)",
        lambda p: any(isinstance(e, Var) and e.ty.bits < 32 for _, _, e in p.temps),
        # C, by integers.md: -128 + (u64)1 is a u64, so 0 < it holds. PythonBPF:
        # t1 stays a u8, the sum is the int -127, and the compare is false.
        ExpressionProgram(
            [("a0", C_INT8, -128), ("a1", C_UINT8, 1)],
            [("t1", untyped_local_type(C_UINT8), Var("a1", C_UINT8))],
            Bin(
                "<",
                Lit(0),
                Bin("+", Var("a0", C_INT8), Var("t1", untyped_local_type(C_UINT8))),
            ),
        ),
    ),
]


def gap_of(program: ExpressionProgram) -> "Gap | None":
    return next((g for g in GAPS if g.hits(program)), None)
