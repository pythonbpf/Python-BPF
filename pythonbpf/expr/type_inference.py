"""Static integer typing of an expression, for the allocation pass.

The allocation pass runs before code generation and must size and type a slot
for `x = <expr>` without evaluating <expr>. Undeclared locals are always 64-bit
(declare with a ctypes constructor for a narrower type); what this decides is
their sign, by walking the expression with the same usual-arithmetic-conversion
rule the code generator applies.
"""

import ast
import ctypes

from llvmlite import ir

from pythonbpf.type_deducer import (
    IntTy,
    ctypes_to_ir,
    is_ctypes,
    is_signed_ctype,
    signedness,
)
from .operators import usual_arithmetic_conversions
from .vmlinux_registry import VmlinuxHandlerRegistry


def _as_intty(ty):
    if isinstance(ty, ir.IntType):
        return IntTy(ty.width, signedness(ty))
    return None


def infer_int_type(expr, local_sym_tab, compilation_context):
    """Best static integer type of `expr`, or None when it cannot be determined."""
    if isinstance(expr, ast.Constant) and isinstance(expr.value, (int, bool)):
        v = int(expr.value)
        return IntTy(32, True) if -(1 << 31) <= v < (1 << 31) else IntTy(64, True)

    if isinstance(expr, ast.Name):
        if expr.id in local_sym_tab:
            return _as_intty(local_sym_tab[expr.id].ir_type)
        if expr.id in compilation_context.bpf_globals:
            return _as_intty(compilation_context.bpf_globals[expr.id].ir_type)
        if VmlinuxHandlerRegistry.handle_name(expr.id) is not None:
            return IntTy(64, True)  # enum constants are emitted as i64
        return None

    if isinstance(expr, ast.BinOp):
        left = infer_int_type(expr.left, local_sym_tab, compilation_context)
        right = infer_int_type(expr.right, local_sym_tab, compilation_context)
        if left is None or right is None:
            return None
        return usual_arithmetic_conversions(left, right)

    if isinstance(expr, ast.UnaryOp):
        inner = infer_int_type(expr.operand, local_sym_tab, compilation_context)
        return None if inner is None else usual_arithmetic_conversions(inner, inner)

    if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Name):
        from pythonbpf.helper import HelperHandlerRegistry  # avoid an import cycle

        name = expr.func.id
        if is_ctypes(name):
            return _as_intty(ctypes_to_ir(name))
        if HelperHandlerRegistry.has_handler(name):
            return _as_intty(HelperHandlerRegistry.get_return_type(name))
        return None

    if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute):
        # map.lookup(k) used as a value: the map's declared value type
        map_name = getattr(expr.func.value, "id", None)
        sym = compilation_context.map_sym_tab.get(map_name)
        value = (sym.params or {}).get("value") if sym else None
        return (
            _as_intty(ctypes_to_ir(value))
            if isinstance(value, str) and is_ctypes(value)
            else None
        )

    if isinstance(expr, ast.Attribute) and isinstance(expr.value, ast.Name):
        base = local_sym_tab.get(expr.value.id)
        if base is None:
            return None
        meta = base.metadata
        if meta in compilation_context.structs_sym_tab:
            return _as_intty(
                compilation_context.structs_sym_tab[meta].field_type(expr.attr)
            )
        if getattr(meta, "__module__", None) == "vmlinux":
            try:
                _, field = VmlinuxHandlerRegistry.get_field_type(
                    meta.__name__, expr.attr
                )
                cname = field.type.__name__
                if is_ctypes(cname):
                    return IntTy(ctypes.sizeof(field.type) * 8, is_signed_ctype(cname))
            except Exception:
                return None
        return None

    return None
