from llvmlite import ir
import logging

logger = logging.getLogger(__name__)


def _get_base_type_and_depth(ir_type):
    """Get the base type for pointer types."""
    cur_type = ir_type
    depth = 0
    while isinstance(cur_type, ir.PointerType):
        depth += 1
        cur_type = cur_type.pointee
    return cur_type, depth


def _deref_to_depth(func, builder, val, target_depth):
    """Dereference a pointer to a certain depth."""

    cur_val = val
    cur_type = val.type

    for depth in range(target_depth):
        if not isinstance(val.type, ir.PointerType):
            logger.error("Cannot dereference further, non-pointer type")
            return None

        # dereference with null check
        pointee_type = cur_type.pointee
        null_check_block = builder.block
        not_null_block = func.append_basic_block(name=f"deref_not_null_{depth}")
        merge_block = func.append_basic_block(name=f"deref_merge_{depth}")

        null_ptr = ir.Constant(cur_type, None)
        is_not_null = builder.icmp_signed("!=", cur_val, null_ptr)
        logger.debug(f"Inserted null check for pointer at depth {depth}")

        builder.cbranch(is_not_null, not_null_block, merge_block)

        builder.position_at_end(not_null_block)
        dereferenced_val = builder.load(cur_val)
        logger.debug(f"Dereferenced to depth {depth - 1}, type: {pointee_type}")
        builder.branch(merge_block)

        builder.position_at_end(merge_block)
        phi = builder.phi(pointee_type, name=f"deref_result_{depth}")

        zero_value = (
            ir.Constant(pointee_type, 0)
            if isinstance(pointee_type, ir.IntType)
            else ir.Constant(pointee_type, None)
        )
        phi.add_incoming(zero_value, null_check_block)

        phi.add_incoming(dereferenced_val, not_null_block)

        # Continue with phi result
        cur_val = phi
        cur_type = pointee_type
    return cur_val


def normalize_types(func, builder, lhs, rhs):
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
        lhs_base, lhs_depth = _get_base_type_and_depth(lhs.type)
        rhs_base, rhs_depth = _get_base_type_and_depth(rhs.type)
        if lhs_base == rhs_base:
            if lhs_depth < rhs_depth:
                rhs = _deref_to_depth(func, builder, rhs, rhs_depth - lhs_depth)
            elif rhs_depth < lhs_depth:
                lhs = _deref_to_depth(func, builder, lhs, lhs_depth - rhs_depth)
            return normalize_types(func, builder, lhs, rhs)
