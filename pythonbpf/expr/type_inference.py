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
    PktPtrTy,
    IntTy,
    ctypes_to_ir,
    is_ctypes,
    is_signed_ctype,
    signedness,
)
from .operators import usual_arithmetic_conversions
from .vmlinux_registry import VmlinuxHandlerRegistry
from .packet_pointer import packet_type


def _as_intty(ty):
    if isinstance(ty, PktPtrTy):
        return ty
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
        enum = VmlinuxHandlerRegistry.handle_name(expr.id)
        if enum is not None:
            return _as_intty(enum[1])
        return None

    if isinstance(expr, ast.BinOp):
        left = infer_int_type(expr.left, local_sym_tab, compilation_context)
        right = infer_int_type(expr.right, local_sym_tab, compilation_context)
        if isinstance(left, PktPtrTy) and isinstance(right, PktPtrTy):
            return IntTy(64, False)  # pointer - pointer: a length
        if isinstance(left, PktPtrTy) or isinstance(right, PktPtrTy):
            return left if isinstance(left, PktPtrTy) else right
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

    if (
        isinstance(expr, ast.Call)
        and isinstance(expr.func, ast.Attribute)
        and expr.func.attr == "lookup"
    ):
        # m.lookup(...) used as a value has the type the map declares for its
        # values, whatever the key argument looks like. The declaration is a
        # ctypes name for a scalar map and a struct name otherwise, which is
        # not an integer, so None.
        map_name = getattr(expr.func.value, "id", None)
        sym = compilation_context.map_sym_tab.get(map_name)
        value_ctype = (sym.params or {}).get("value") if sym else None
        if isinstance(value_ctype, str) and is_ctypes(value_ctype):
            return _as_intty(ctypes_to_ir(value_ctype))
        return None

    if isinstance(expr, ast.Attribute) and isinstance(expr.value, ast.Name):
        pkt_ty = packet_type(expr, local_sym_tab)
        if pkt_ty is not None:
            return pkt_ty
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
