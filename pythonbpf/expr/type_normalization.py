import logging
import ast
from llvmlite import ir
from .ir_ops import deref_to_depth

logger = logging.getLogger(__name__)

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


def get_base_type_and_depth(ir_type):
    """Get the base type for pointer types."""
    cur_type = ir_type
    depth = 0
    while isinstance(cur_type, ir.PointerType):
        depth += 1
        cur_type = cur_type.pointee
    return cur_type, depth


def _normalize_types(func, builder, lhs, rhs):
    """Normalize types for comparison."""

    logger.info(f"Normalizing types: {lhs.type} vs {rhs.type}")
    if isinstance(lhs.type, ir.IntType) and isinstance(rhs.type, ir.IntType):
        if lhs.type.width < rhs.type.width:
            lhs = builder.sext(lhs, rhs.type)
        else:
            rhs = builder.sext(rhs, lhs.type)
        return lhs, rhs
    elif not isinstance(lhs.type, ir.PointerType) and not isinstance(
        rhs.type, ir.PointerType
    ):
        logger.error(f"Type mismatch: {lhs.type} vs {rhs.type}")
        return None, None
    else:
        lhs_base, lhs_depth = get_base_type_and_depth(lhs.type)
        rhs_base, rhs_depth = get_base_type_and_depth(rhs.type)
        if lhs_base == rhs_base:
            if lhs_depth < rhs_depth:
                rhs = deref_to_depth(func, builder, rhs, rhs_depth - lhs_depth)
            elif rhs_depth < lhs_depth:
                lhs = deref_to_depth(func, builder, lhs, lhs_depth - rhs_depth)
            return _normalize_types(func, builder, lhs, rhs)


def convert_to_bool(builder, val):
    """Convert a value to boolean."""
    if val.type == ir.IntType(1):
        return val
    if isinstance(val.type, ir.PointerType):
        zero = ir.Constant(val.type, None)
    else:
        zero = ir.Constant(val.type, 0)
    return builder.icmp_signed("!=", val, zero)


def handle_comparator(func, builder, op, lhs, rhs):
    """Handle comparison operations."""

    if lhs.type != rhs.type:
        lhs, rhs = _normalize_types(func, builder, lhs, rhs)

    if lhs is None or rhs is None:
        return None

    if type(op) not in COMPARISON_OPS:
        logger.error(f"Unsupported comparison operator: {type(op)}")
        return None

    predicate = COMPARISON_OPS[type(op)]
    result = builder.icmp_signed(predicate, lhs, rhs)
    logger.debug(f"Comparison result: {result}")
    return result, ir.IntType(1)
