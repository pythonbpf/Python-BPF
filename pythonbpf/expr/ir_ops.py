import logging
from llvmlite import ir

logger = logging.getLogger(__name__)


def deref_to_depth(func, builder, val, target_depth):
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
