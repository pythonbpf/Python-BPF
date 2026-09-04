"""Every Python operator PythonBPF understands, and the IR it maps to.

This is the single registry. Binary operators map to IRBuilder method names,
comparisons map to icmp predicates, and the unary/boolean operators are listed
here even though their lowering is structural (they need convert_to_bool or
short-circuit control flow, so they live in expr_pass): if an operator is not
in this file, the compiler does not support it. Add new operators here first.
"""

import ast

from pythonbpf.type_deducer import IntTy, signedness

# ast.BinOp.op class -> llvmlite IRBuilder method name.
# Shared by binary-op evaluation and augmented assignment.
BINOP_METHODS = {
    ast.Add: "add",
    ast.Sub: "sub",
    ast.Mult: "mul",
    ast.Div: "sdiv",
    ast.Mod: "srem",
    ast.LShift: "shl",
    ast.RShift: "lshr",
    ast.BitOr: "or_",
    ast.BitXor: "xor",
    ast.BitAnd: "and_",
    ast.FloorDiv: "udiv",
}

# ast.Compare op class -> icmp predicate string.
COMPARISON_OPS = {
    ast.Eq: "==",
    ast.NotEq: "!=",
    ast.Lt: "<",
    ast.LtE: "<=",
    ast.Gt: ">",
    ast.GtE: ">=",
    ast.Is: "==",
    ast.IsNot: "!=",
}

# Lowered structurally in expr_pass (need convert_to_bool / control flow).
UNARY_OPS = (ast.Not, ast.USub)
BOOL_OPS = (ast.And, ast.Or)


def apply_binop(builder, op, left, right):
    """Emit the LLVM instruction for a Python binary operator."""
    method = BINOP_METHODS.get(type(op))
    if method is None:
        raise SyntaxError(f"Unsupported binary operation: {type(op).__name__}")
    return getattr(builder, method)(left, right)


def comparison_predicate(op):
    """icmp predicate for a Python comparison operator, or None if unsupported."""
    return COMPARISON_OPS.get(type(op))


def usual_arithmetic_conversions(left, right) -> IntTy:
    """The type a C binary operation on `left` and `right` is performed in.

    Integer promotion first: anything narrower than int becomes a signed 32-bit
    int (int can represent every value of the narrower type, signed or not).
    Then, if the signs agree, the wider type wins; if they differ, the unsigned
    operand wins at equal or greater width, otherwise the signed one -- because
    it can then represent every value of the unsigned one.
    """

    def promote(ty):
        if ty.width < 32:
            return IntTy(32, True)
        return IntTy(ty.width, signedness(ty))

    left, right = promote(left), promote(right)
    if left.signed == right.signed:
        return IntTy(max(left.width, right.width), left.signed)
    unsigned, signed = (left, right) if not left.signed else (right, left)
    if unsigned.width >= signed.width:
        return IntTy(unsigned.width, False)
    return IntTy(signed.width, True)
