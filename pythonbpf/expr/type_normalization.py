import logging
from llvmlite import ir
from .ir_ops import deref_to_depth
from pythonbpf.type_deducer import signedness
from .operators import COMPARISON_OPS

logger = logging.getLogger(__name__)


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
            lhs = convert(builder, lhs, lhs.type, rhs.type)
        else:
            rhs = convert(builder, rhs, rhs.type, lhs.type)
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


def convert(builder, val, from_ty, to_ty):
    """Convert an integer value between types the way C does.

    Widening is driven by the *source* sign (zext for unsigned, sext for
    signed) so the mathematical value is preserved; narrowing truncates; equal
    width is a reinterpretation and emits nothing. `from_ty` and `to_ty` are
    descriptors (see type_deducer.IntTy); the physical width comes from the
    value itself, which may already be wider than its descriptor says.
    """
    if not (isinstance(to_ty, ir.IntType) and isinstance(val.type, ir.IntType)):
        return val
    if val.type.width > to_ty.width:
        return builder.trunc(val, to_ty)
    if val.type.width < to_ty.width:
        ext = builder.zext if not signedness(from_ty) else builder.sext
        return ext(val, to_ty)
    return val


def _fold_int_constant(val, ty, width):
    """A literal re-expressed at the working width holding type ty's value:
    wrap to ty's width, take the representative ty's sign implies."""
    v = val.constant % (1 << ty.width)
    if signedness(ty) and v >= 1 << (ty.width - 1):
        v -= 1 << ty.width
    return ir.Constant(ir.IntType(width), v)


def to_promoted(builder, val, from_ty, to_ty, width=64):
    """Bring an operand to the promoted type of its operation, C-style.

    First convert it to to_ty per its *own* sign (that is C's conversion of an
    operand to the common type), then widen to the working width per to_ty's
    sign so the i64 register holds exactly a to_ty value. Literals are folded.
    """
    if isinstance(val, ir.Constant) and isinstance(val.constant, int):
        return _fold_int_constant(val, to_ty, width)
    val = convert(builder, val, from_ty, ir.IntType(to_ty.width))
    return canonicalise(builder, val, to_ty, width)


def canonicalise(builder, val, ty, width=64):
    """Bring `val` to the working width holding exactly the value of type `ty`:
    truncate to ty's width if the register is wider (so the operation wraps at
    ty's width, as C does), then extend per ty's sign."""
    if not isinstance(val.type, ir.IntType):
        return val
    if isinstance(val, ir.Constant) and isinstance(val.constant, int):
        return _fold_int_constant(val, ty, width)
    if val.type.width > ty.width:
        val = builder.trunc(val, ir.IntType(ty.width))
    if val.type.width < width:
        ext = builder.zext if not signedness(ty) else builder.sext
        val = ext(val, ir.IntType(width))
    return val


def convert_to_bool(builder, val):
    """Convert a value to boolean."""
    if val.type == ir.IntType(1):
        return val
    if isinstance(val.type, ir.PointerType):
        zero = ir.Constant(val.type, None)
    else:
        zero = ir.Constant(val.type, 0)
    return builder.icmp_signed("!=", val, zero)


def handle_comparator(func, builder, op, lhs, rhs, signed=True):
    """Handle comparison operations, signed or unsigned per the compared type."""

    if lhs.type != rhs.type:
        lhs, rhs = _normalize_types(func, builder, lhs, rhs)

    if lhs is None or rhs is None:
        return None

    if type(op) not in COMPARISON_OPS:
        logger.error(f"Unsupported comparison operator: {type(op)}")
        return None

    predicate = COMPARISON_OPS[type(op)]
    icmp = builder.icmp_signed if signed else builder.icmp_unsigned
    result = icmp(predicate, lhs, rhs)
    logger.debug(f"Comparison result: {result}")
    return result, ir.IntType(1)
