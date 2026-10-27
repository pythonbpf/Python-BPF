"""
A reference model of C's integer rules, as docs/user-guide/integers.md states
them for PythonBPF.

clang is the specification; this model is not. It exists for two reasons:

* To keep undefined behaviour out of the generated programs. Division by zero,
  INT_MIN / -1 and out-of-range shift counts are undefined in C (and the first
  two trap on the host), so a program that would hit them is discarded before
  anything is compiled. Signed overflow is left in: the C reference is built
  with -fwrapv, which defines it as wrapping, as BPF does.
* To give a third opinion when PythonBPF and clang disagree. If the model
  disagrees with clang, the model is wrong; the property tests report that
  separately from a compiler bug.

Values are plain Python ints holding the value as the type reads it (so a
c_int8 holding 0xff is -1), and every operation returns (value, type).
"""

from dataclasses import dataclass


class UndefinedBehaviour(Exception):
    """The C program would be undefined here, so the example is discarded."""


@dataclass(frozen=True)
class IntType:
    name: str  # the ctypes name, as written in PythonBPF source
    c_name: str  # the C type, as written in the reference program
    bits: int
    signed: bool

    @property
    def is_bool(self) -> bool:
        return self.name == "c_bool"

    @property
    def min(self) -> int:
        return -(1 << (self.bits - 1)) if self.signed else 0

    @property
    def max(self) -> int:
        if self.is_bool:
            return 1
        return (1 << (self.bits - 1)) - 1 if self.signed else (1 << self.bits) - 1

    def __repr__(self) -> str:
        return self.name


C_INT8 = IntType("c_int8", "signed char", 8, True)
C_INT16 = IntType("c_int16", "short", 16, True)
C_INT32 = IntType("c_int32", "int", 32, True)
C_INT64 = IntType("c_int64", "long long", 64, True)
C_UINT8 = IntType("c_uint8", "unsigned char", 8, False)
C_UINT16 = IntType("c_uint16", "unsigned short", 16, False)
C_UINT32 = IntType("c_uint32", "unsigned int", 32, False)
C_UINT64 = IntType("c_uint64", "unsigned long long", 64, False)
C_BOOL = IntType("c_bool", "_Bool", 8, False)

INTEGER_TYPES = [
    C_INT8,
    C_INT16,
    C_INT32,
    C_INT64,
    C_UINT8,
    C_UINT16,
    C_UINT32,
    C_UINT64,
]
ALL_TYPES = INTEGER_TYPES + [C_BOOL]


def convert(value: int, ty: IntType) -> int:
    """C's conversion of `value` to `ty`: _Bool is `value != 0`; otherwise the
    low `bits` bits, read with ty's sign (truncation, or reinterpretation at
    the same width; widening is the identity on the value)."""
    if ty.is_bool:
        return int(value != 0)
    value &= (1 << ty.bits) - 1
    if ty.signed and value >> (ty.bits - 1):
        value -= 1 << ty.bits
    return value


def literal_type(value: int) -> IntType:
    """A non-negative decimal literal is an `int` if it fits, else 64-bit
    signed (C's `long`/`long long`, the same on BPF and LP64 hosts)."""
    assert 0 <= value <= C_INT64.max, value
    return C_INT32 if value <= C_INT32.max else C_INT64


def promote(ty: IntType) -> IntType:
    """Integer promotion: anything narrower than int (and _Bool) becomes int."""
    return C_INT32 if ty.bits < 32 else ty


def common_type(a: IntType, b: IntType) -> IntType:
    """C's usual arithmetic conversions, as integers.md lists them."""
    a, b = promote(a), promote(b)
    if a.signed == b.signed:
        return a if a.bits >= b.bits else b
    unsigned, signed = (a, b) if not a.signed else (b, a)
    return unsigned if unsigned.bits >= signed.bits else signed


def untyped_local_type(ty: IntType) -> IntType:
    """An undeclared local is a 64-bit slot with the sign of its expression."""
    return C_INT64 if ty.signed else C_UINT64


ARITH_OPS = ["+", "-", "*", "&", "|", "^"]
DIV_OPS = ["/", "//", "%"]
SHIFT_OPS = ["<<", ">>"]
COMPARE_OPS = ["<", "<=", ">", ">=", "==", "!="]


def binary_type(op: str, a: IntType, b: IntType) -> IntType:
    if op in SHIFT_OPS:
        return promote(a)  # a shift has the type of its promoted left operand
    if op in COMPARE_OPS:
        return C_INT32
    return common_type(a, b)


def _trunc_div(a: int, b: int) -> int:
    q = abs(a) // abs(b)
    return q if (a < 0) == (b < 0) else -q


def binary(op: str, a: int, a_ty: IntType, b: int, b_ty: IntType) -> int:
    """Value of `a op b` in C, given each operand's value and type."""
    if op in SHIFT_OPS:
        ty = promote(a_ty)
        if not 0 <= b < ty.bits:
            raise UndefinedBehaviour(f"shift count {b} for a {ty.bits}-bit value")
        a = convert(a, ty)
        # Python's >> on a negative int is arithmetic, as C's is on a signed
        # type; an unsigned value is never negative, so it shifts in zeros.
        return convert(a << b if op == "<<" else a >> b, ty)

    ty = common_type(a_ty, b_ty)
    a, b = convert(a, ty), convert(b, ty)
    if op in COMPARE_OPS:
        return int(
            {
                "<": a < b,
                "<=": a <= b,
                ">": a > b,
                ">=": a >= b,
                "==": a == b,
                "!=": a != b,
            }[op]
        )
    if op in DIV_OPS:
        if b == 0:
            raise UndefinedBehaviour("division by zero")
        if ty.signed and a == ty.min and b == -1:
            raise UndefinedBehaviour(f"{ty.name} minimum divided by -1")
        q = _trunc_div(a, b)
        return convert(q if op != "%" else a - q * b, ty)
    return convert(
        {
            "+": a + b,
            "-": a - b,
            "*": a * b,
            "&": a & b,
            "|": a | b,
            "^": a ^ b,
        }[op],
        ty,
    )


def negate(a: int, a_ty: IntType) -> int:
    ty = promote(a_ty)
    return convert(-convert(a, ty), ty)


def logical_not(a: int) -> int:
    return int(a == 0)
