"""
Generated integer programs, printed twice: as PythonBPF source and as the C
program clang compiles for the same computation.

A program is straight-line: input locals declared with a constructor and a
literal, optional temporaries, and a returned expression. Inputs are locals,
not literals, so neither compiler sees a constant expression; clang at -O0
and PythonBPF both load them from the stack.

What is not generated, and why (bugs PythonBPF has are generated, and stepped
around by tests/property/known_gaps.py instead):
  * `~x`: PythonBPF does not support unary invert (a clean error).
  * `and` / `or`: not C's integer operators, and not an integer question.
  * Literal initialisers of @bpfglobal variables other than 0, outside
    test_int_conversions' strict-xfail site: a negative one is silently
    emitted as 0 (pythonbpf/globals_pass.py).
"""

from dataclasses import dataclass, field

from hypothesis import strategies as st

from tests.property.cints import (
    ALL_TYPES,
    ARITH_OPS,
    C_INT32,
    C_INT64,
    COMPARE_OPS,
    DIV_OPS,
    SHIFT_OPS,
    IntType,
    binary,
    binary_type,
    convert,
    literal_type,
    logical_not,
    negate,
    promote,
    untyped_local_type,
)

INT64_MIN = -(1 << 63)
INT64_MAX = (1 << 63) - 1


def literal_source(value: int) -> str:
    """A decimal literal for `value` in [INT64_MIN, INT64_MAX], valid in both
    languages and of a 64-bit-or-narrower signed type in C. Hex is never
    used: C gives a hex literal that does not fit `int` an unsigned type."""
    if value >= 0:
        return str(value)
    if value == INT64_MIN:
        return "(-9223372036854775807 - 1)"
    return f"(-{-value})"


def as_literal(value: int, ty: IntType) -> int:
    """A literal that converts to `value` in `ty` (a u64 above INT64_MAX is
    written as the negative number with the same bits)."""
    return value - (1 << 64) if value > INT64_MAX else value


# ── expressions ─────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Var:
    name: str
    ty: IntType

    def py(self) -> str:
        return self.name

    def c(self) -> str:
        return self.name

    def eval(self, env: dict) -> int:
        return env[self.name]


@dataclass(frozen=True)
class Lit:
    value: int  # non-negative; a negative constant is Neg(Lit(n)), as in both languages

    @property
    def ty(self) -> IntType:
        return literal_type(self.value)

    def py(self) -> str:
        return str(self.value)

    def c(self) -> str:
        return str(self.value)

    def eval(self, env: dict) -> int:
        return self.value


@dataclass(frozen=True)
class Neg:
    operand: object

    @property
    def ty(self) -> IntType:
        return promote(self.operand.ty)

    def py(self) -> str:
        return f"(-{self.operand.py()})"

    def c(self) -> str:
        return f"(-{self.operand.c()})"

    def eval(self, env: dict) -> int:
        return negate(self.operand.eval(env), self.operand.ty)


@dataclass(frozen=True)
class Not:
    operand: object

    @property
    def ty(self) -> IntType:
        return C_INT32  # C's `!` is an int

    def py(self) -> str:
        return f"(not {self.operand.py()})"

    def c(self) -> str:
        return f"(!{self.operand.c()})"

    def eval(self, env: dict) -> int:
        return logical_not(self.operand.eval(env))


@dataclass(frozen=True)
class Cast:
    ty: IntType
    operand: object

    def py(self) -> str:
        return f"{self.ty.name}({self.operand.py()})"

    def c(self) -> str:
        return f"(({self.ty.c_name})({self.operand.c()}))"

    def eval(self, env: dict) -> int:
        return convert(self.operand.eval(env), self.ty)


@dataclass(frozen=True)
class Bin:
    op: str
    left: object
    right: object

    @property
    def ty(self) -> IntType:
        return binary_type(self.op, self.left.ty, self.right.ty)

    def py(self) -> str:
        return f"({self.left.py()} {self.op} {self.right.py()})"

    def c(self) -> str:
        op = "/" if self.op == "//" else self.op  # both are C's truncating `/`
        return f"({self.left.c()} {op} {self.right.c()})"

    def eval(self, env: dict) -> int:
        return binary(
            self.op,
            self.left.eval(env),
            self.left.ty,
            self.right.eval(env),
            self.right.ty,
        )


# ── programs ────────────────────────────────────────────────────────────────

PY_HEADER = """\
from pythonbpf import bpf, section, bpfglobal, compile
from ctypes import (
    c_void_p,
    c_bool,
    c_int8,
    c_int16,
    c_int32,
    c_int64,
    c_uint8,
    c_uint16,
    c_uint32,
    c_uint64,
)
"""

PY_FOOTER = """

@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
"""


@dataclass
class Program:
    """One program in both languages. `globals` are (name, type, initial
    literal); `py_body` and `c_body` are the statements of `prog`, in order."""

    py_body: list[str]
    c_body: list[str]
    ret: IntType = C_INT64
    globals: list[tuple[str, IntType, int]] = field(default_factory=list)

    def py_source(self) -> str:
        parts = [PY_HEADER]
        for name, ty, init in self.globals:
            parts.append(
                f"\n@bpf\n@bpfglobal\ndef {name}() -> {ty.name}:\n"
                f"    return {ty.name}({literal_source(init)})\n"
            )
        body = "".join(f"    {line}\n" for line in self.py_body)
        parts.append(
            '\n@bpf\n@section("tracepoint/syscalls/sys_enter_getpid")\n'
            f"def prog(ctx: c_void_p) -> {self.ret.name}:\n{body}"
        )
        parts.append(PY_FOOTER)
        return "".join(parts)

    def c_source(self) -> str:
        lines = [
            f"{ty.c_name} {name} = {literal_source(init)};"
            for name, ty, init in self.globals
        ]
        lines.append(f"{self.ret.c_name} prog(void *ctx)\n{{")
        lines += [f"    {line}" for line in self.c_body]
        lines.append("}")
        return "\n".join(lines) + "\n"


def input_decl(name: str, ty: IntType, value: int) -> tuple[str, str]:
    """`name = c_T(lit)` and `T name = lit;` for an input holding `value`."""
    lit = literal_source(as_literal(value, ty))
    return f"{name} = {ty.name}({lit})", f"{ty.c_name} {name} = {lit};"


@dataclass
class ExpressionProgram:
    """Inputs, temporaries and a returned expression; `program()` prints it
    and `expected()` is the model's value (raising UndefinedBehaviour)."""

    inputs: list[tuple[str, IntType, int]]
    temps: list[tuple[str, IntType, object]]  # name, declared type, expression
    result: object

    def program(self) -> Program:
        py, c = [], []
        for name, ty, value in self.inputs:
            p, q = input_decl(name, ty, value)
            py.append(p)
            c.append(q)
        for name, ty, expr in self.temps:
            py.append(f"{name} = {expr.py()}")
            c.append(f"{ty.c_name} {name} = {expr.c()};")
        py.append(f"return {self.result.py()}")
        c.append(f"return {self.result.c()};")
        return Program(py, c)

    def expected(self) -> int:
        env = {name: value for name, _, value in self.inputs}
        for name, ty, expr in self.temps:
            env[name] = convert(expr.eval(env), ty)
        return convert(self.result.eval(env), C_INT64)


# ── strategies ──────────────────────────────────────────────────────────────


def edge_values(ty: IntType) -> list[int]:
    """The values where integer bugs live: zero, ±1, the type's limits, and
    the limits of every narrower type."""
    candidates = {0, 1, -1, 2, ty.min, ty.max, ty.min + 1, ty.max - 1}
    for k in (7, 8, 15, 16, 31, 32, 63):
        candidates |= {1 << k, (1 << k) - 1, -(1 << k), -(1 << k) + 1}
    return sorted(v for v in candidates if ty.min <= v <= ty.max)


def values_of(ty: IntType) -> st.SearchStrategy[int]:
    return st.one_of(st.sampled_from(edge_values(ty)), st.integers(ty.min, ty.max))


LITERALS = st.one_of(
    st.sampled_from(
        [0, 1, 2, 3, 7, 8, 31, 32, 63, 64, 127, 128, 255, 256, 32767, 32768, 65535]
        + [65536, 2**31 - 1, 2**31, 2**32 - 1, 2**32, 2**63 - 1]
    ),
    st.integers(0, INT64_MAX),
)


@st.composite
def expressions(draw, leaves: list[Var], depth: int):
    if depth == 0 or draw(st.integers(0, 3)) == 0:
        # Mostly inputs: a literal is non-negative and often small, so a
        # tree of literals rarely reaches a sign-sensitive case.
        if leaves and draw(st.integers(0, 3)) > 0:
            return draw(st.sampled_from(leaves))
        return Lit(draw(LITERALS))

    sub = expressions(leaves, depth - 1)
    kind = draw(
        st.sampled_from(
            ["arith", "arith", "div", "shift", "compare", "neg", "not", "cast"]
        )
    )
    if kind == "neg":
        return Neg(draw(sub))
    if kind == "not":
        return Not(draw(sub))
    if kind == "cast":
        return Cast(draw(st.sampled_from(ALL_TYPES)), draw(sub))
    if kind == "shift":
        left, right = draw(sub), draw(sub)
        # Mask the count into range so the shift is defined; the mask is a
        # literal, so `right & mask` is never negative.
        mask = Lit(promote(left.ty).bits - 1)
        return Bin(draw(st.sampled_from(SHIFT_OPS)), left, Bin("&", right, mask))
    op = draw(
        st.sampled_from(
            {"arith": ARITH_OPS, "div": DIV_OPS, "compare": COMPARE_OPS}[kind]
        )
    )
    return Bin(op, draw(sub), draw(sub))


@st.composite
def expression_programs(
    draw, max_inputs: int = 4, max_temps: int = 2, max_depth: int = 4
):
    inputs = []
    for i in range(draw(st.integers(1, max_inputs))):
        ty = draw(st.sampled_from(ALL_TYPES))
        inputs.append((f"a{i}", ty, draw(values_of(ty))))
    leaves = [Var(name, ty) for name, ty, _ in inputs]

    temps = []
    for i in range(draw(st.integers(0, max_temps))):
        expr = draw(expressions(leaves, draw(st.integers(1, 3))))
        # A constructor call declares the local with that type; anything else
        # is an undeclared local: 64 bits, with the expression's sign.
        ty = expr.ty if isinstance(expr, Cast) else untyped_local_type(expr.ty)
        temps.append((f"t{i}", ty, expr))
        leaves.append(Var(f"t{i}", ty))

    result = draw(expressions(leaves, draw(st.integers(0, max_depth))))
    return ExpressionProgram(inputs, temps, result)
