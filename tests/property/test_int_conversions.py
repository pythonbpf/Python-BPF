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
from hypothesis import given, settings
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
    Bin,
    Cast,
    Lit,
    Program,
    Var,
    as_literal,
    input_decl,
    literal_source,
    values_of,
)

pytestmark = pytest.mark.skipif(CLANG is None, reason="clang is not installed")


# How the converted value is read back. `return x` alone shows the value but
# not the type it was stored as, and a later use depends on that type: these
# read it through an operation whose result changes with its sign and width.
PROBES = {
    "value": lambda x: x,
    # -1 in x's type (promoted), halved: 0 if signed, and u32 and u64 differ
    "sign_and_width": lambda x: Bin("/", Bin("-", Bin("*", x, Lit(0)), Lit(1)), Lit(2)),
    # INT_MAX + 1 wraps if x's type promotes to a 32-bit int, not if 64-bit
    "int_overflow": lambda x: Bin(
        "+", Bin("+", Bin("*", x, Lit(0)), Lit(2**31 - 1)), Lit(1)
    ),
}


def _site_program(site, src, dst, value, other, probe):
    """(Program, model) for converting `a0`, a `src` holding `value`, to `dst`
    at `site`, then returning probe(the converted value). `other` is a second
    value, used where a site needs one."""
    decl_py, decl_c = input_decl("a0", src, value)

    def read_back(name, ty, stored, py, c, globals=()):
        """Finish a program whose statements stored `stored` into `name`."""
        expr = probe(Var(name, ty))
        program = Program(
            py + [f"return {expr.py()}"],
            c + [f"return {expr.c()};"],
            globals=list(globals),
        )
        return program, lambda: convert(expr.eval({name: stored()}), C_INT64)

    if site == "constructor":
        expr = probe(Cast(dst, Var("a0", src)))
        return Program(
            [decl_py, f"return {expr.py()}"], [decl_c, f"return {expr.c()};"]
        ), lambda: convert(expr.eval({"a0": value}), C_INT64)
    if site == "declare":
        return read_back(
            "x",
            dst,
            lambda: convert(value, dst),
            [decl_py, f"x = {dst.name}(a0)"],
            [decl_c, f"{dst.c_name} x = a0;"],
        )
    if site == "reassign":
        return read_back(
            "x",
            dst,
            lambda: convert(value, dst),
            [decl_py, f"x = {dst.name}(0)", "x = a0"],
            [decl_c, f"{dst.c_name} x = 0;", "x = a0;"],
        )
    if site == "untyped_local":
        # dst plays no part: an undeclared local is 64 bits with a0's sign
        local = untyped_local_type(src)
        return read_back(
            "x",
            local,
            lambda: convert(value, local),
            [decl_py, "x = a0"],
            [decl_c, f"{local.c_name} x = a0;"],
        )
    if site == "global_store":
        return read_back(
            "out",
            dst,
            lambda: convert(value, dst),
            [decl_py, "global out", "out = a0"],
            [decl_c, "out = a0;"],
            globals=[("out", dst, 0)],
        )
    if site == "return":
        # Read through the function's own return type, so no probe.
        return Program([decl_py, "return a0"], [decl_c, "return a0;"], ret=dst), (
            lambda: convert(value, dst)
        )
    if site == "global_init":
        # `value` is used as the initialiser literal itself
        lit = as_literal(value, src)
        return read_back("g", dst, lambda: convert(lit, dst), [], [], [("g", dst, lit)])
    if site.startswith("augassign"):
        op = site.split(" ")[1]
        init = as_literal(other, dst)
        return read_back(
            "x",
            dst,
            lambda: convert(binary(op, convert(init, dst), dst, value, src), dst),
            [decl_py, f"x = {dst.name}({literal_source(init)})", f"x {op}= a0"],
            [
                decl_c,
                f"{dst.c_name} x = {literal_source(init)};",
                f"x {'/' if op == '//' else op}= a0;",
            ],
        )
    raise ValueError(site)


SITES = [
    "constructor",
    "declare",
    "reassign",
    "untyped_local",
    "global_store",
    "return",
    "global_init",
] + [f"augassign {op}" for op in ARITH_OPS + DIV_OPS + SHIFT_OPS]


# Parametrized over the destination type as well as the site, so every type
# gets examples on every run: drawn at random, a type-specific rule (such as
# c_bool's `!= 0`) went untested in some runs. 162 parameters, so a
# sixteenth of the profile's examples each.
@pytest.mark.parametrize("dst", ALL_TYPES, ids=lambda t: t.name)
@pytest.mark.parametrize("site", SITES)
@settings(max_examples=max(5, settings.default.max_examples // 16))
@given(data=st.data())
def test_conversion_matches_clang(site, dst, data):
    # Known gaps are stepped around by drawing only what avoids them, not by
    # filtering (test_known_gaps.py pins each one):
    sources = ALL_TYPES
    if site in ("augassign <<", "augassign >>"):
        # shift-result-type: `x >>= a` is typed by both operands, so only a
        # source that leaves the type at x's own promoted type
        sources = [t for t in ALL_TYPES if common_type(dst, t) == promote(dst)]
    if site == "untyped_local":
        # untyped-copy-keeps-source-type: `x = a0` keeps a0's type, which is
        # right only for a 64-bit a0 (and dst plays no part here)
        sources = [t for t in ALL_TYPES if untyped_local_type(t) == t]
    if site == "global_init" and dst.is_bool:
        pytest.skip("known gap global-initialiser: c_bool(2) keeps its low bit")
    src = data.draw(st.sampled_from(sources), label="src")

    if site in ("augassign <<", "augassign >>"):
        # a count out of range is undefined in C
        top = min(promote(dst).bits - 1, src.max)
        value = data.draw(st.integers(0, top), label="count")
    elif site == "global_init":
        # global-initialiser: a negative initialiser is emitted as 0. `value`
        # is the initialiser literal itself, out-of-range ones included.
        value = data.draw(st.integers(0, INT64_MAX), label="initialiser")
    else:
        value = data.draw(values_of(src), label="value")
    other = data.draw(values_of(dst), label="other")
    # global_init's gap is the value itself, which the type probes multiply
    # away (global_store reads a global's type through them)
    probes = ["value"] if site == "global_init" else sorted(PROBES)
    probe = data.draw(st.sampled_from(probes), label="probe")
    program, expected = _site_program(site, src, dst, value, other, PROBES[probe])
    check_against_clang(program, expected)
