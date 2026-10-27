"""
Integer conversions at every place PythonBPF converts: PythonBPF computes what
clang computes.

A value of one type is converted to another at each site where integers.md
says a conversion happens (constructor calls, typed and untyped locals,
globals, `return`, augmented assignment). Random expressions reach these sites
only by accident; here every (source type, destination type, site) triple is
tested, with Hypothesis choosing the values, the edge values of each type
first.
"""

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from tests.property.cints import (
    ALL_TYPES,
    ARITH_OPS,
    C_INT64,
    DIV_OPS,
    SHIFT_OPS,
    binary,
    common_type,
    convert,
    promote,
    untyped_local_type,
)
from tests.property.harness import CLANG, check_against_clang
from tests.property.programs import (
    INT64_MAX,
    INT64_MIN,
    Program,
    as_literal,
    input_decl,
    literal_source,
    values_of,
)

pytestmark = pytest.mark.skipif(CLANG is None, reason="clang is not installed")

TYPES = st.sampled_from(ALL_TYPES)


def _site_program(site, src, dst, value, other):
    """(Program, model) for converting `a0`, a `src` holding `value`, to `dst`
    at `site`. `other` is a second value, used where a site needs one."""
    decl_py, decl_c = input_decl("a0", src, value)
    as_i64 = lambda v: convert(v, C_INT64)  # noqa: E731 (prog returns c_int64)

    if site == "constructor":
        return Program(
            [decl_py, f"return {dst.name}(a0)"],
            [decl_c, f"return ({dst.c_name})a0;"],
        ), lambda: as_i64(convert(value, dst))
    if site == "declare":
        return Program(
            [decl_py, f"x = {dst.name}(a0)", "return x"],
            [decl_c, f"{dst.c_name} x = a0;", "return x;"],
        ), lambda: as_i64(convert(value, dst))
    if site == "reassign":
        return Program(
            [decl_py, f"x = {dst.name}(0)", "x = a0", "return x"],
            [decl_c, f"{dst.c_name} x = 0;", "x = a0;", "return x;"],
        ), lambda: as_i64(convert(value, dst))
    if site == "untyped_local":
        # dst plays no part: an undeclared local is 64 bits with a0's sign
        local = untyped_local_type(src)
        return Program(
            [decl_py, "x = a0", "return x"],
            [decl_c, f"{local.c_name} x = a0;", "return x;"],
        ), lambda: as_i64(convert(value, local))
    if site == "global_store":
        return Program(
            [decl_py, "global out", "out = a0", "return out"],
            [decl_c, "out = a0;", "return out;"],
            globals=[("out", dst, 0)],
        ), lambda: as_i64(convert(value, dst))
    if site == "return":
        return Program([decl_py, "return a0"], [decl_c, "return a0;"], ret=dst), (
            lambda: convert(value, dst)
        )
    if site == "global_init":
        # `value` is used as the initialiser literal itself
        lit = as_literal(value, src)
        return Program(
            ["return g"], ["return g;"], globals=[("g", dst, lit)]
        ), lambda: as_i64(convert(lit, dst))
    if site.startswith("augassign"):
        op = site.split(" ")[1]
        init = as_literal(other, dst)
        return Program(
            [
                decl_py,
                f"x = {dst.name}({literal_source(init)})",
                f"x {op}= a0",
                "return x",
            ],
            [
                decl_c,
                f"{dst.c_name} x = {literal_source(init)};",
                f"x {'/' if op == '//' else op}= a0;",
                "return x;",
            ],
        ), lambda: as_i64(convert(binary(op, convert(init, dst), dst, value, src), dst))
    raise ValueError(site)


SITES = [
    "constructor",
    "declare",
    "reassign",
    "untyped_local",
    "global_store",
    "return",
    pytest.param(
        "global_init",
        marks=pytest.mark.xfail(
            strict=True,
            raises=AssertionError,
            reason="a @bpfglobal initialiser that is not a bare constant (as "
            "c_int64(-5) is not: -5 is a UnaryOp) is emitted as 0, and a "
            "constant is not converted to the type (c_bool(2) keeps the low "
            "bit, 0, where C gives 1) (pythonbpf/globals_pass.py, _emit_global)",
        ),
    ),
] + [f"augassign {op}" for op in ARITH_OPS + DIV_OPS + SHIFT_OPS]


# A quarter of the profile's examples per site: there are 18 sites, and each
# example is cheap to state but costs a clang run (~40 ms).
@pytest.mark.parametrize("site", SITES)
@settings(max_examples=max(10, settings.default.max_examples // 4))
@given(src=TYPES, dst=TYPES, data=st.data())
def test_conversion_matches_clang(site, src, dst, data):
    value = data.draw(values_of(src), label="value")
    other = data.draw(values_of(dst), label="other")
    if site == "global_init":
        value = data.draw(st.integers(INT64_MIN, INT64_MAX), label="initialiser")
    if site in ("augassign <<", "augassign >>"):
        # known gap shift-result-type: `x >>= a` is typed by both operands
        # (test_known_gaps.py pins this case)
        assume(promote(dst) == common_type(dst, src))
    program, expected = _site_program(site, src, dst, value, other)
    check_against_clang(program, expected)
