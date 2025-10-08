from llvmlite import ir
import logging
import ast

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


def _get_base_type_and_depth(ir_type):
    """
    Get the base type and pointer depth for an LLVM IR type.
    
    Args:
        ir_type: The LLVM IR type to analyze
    
    Returns:
        A tuple of (base_type, depth) where depth is the number of pointer levels
    """
    cur_type = ir_type
    depth = 0
    while isinstance(cur_type, ir.PointerType):
        depth += 1
        cur_type = cur_type.pointee
    return cur_type, depth


def _deref_to_depth(func, builder, val, target_depth):
    """
    Dereference a pointer to a certain depth with null checks.
    
    Args:
        func: The LLVM IR function being built
        builder: LLVM IR builder
        val: The pointer value to dereference
        target_depth: Number of levels to dereference
    
    Returns:
        The dereferenced value, or None if dereferencing fails
    """

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


def _normalize_types(func, builder, lhs, rhs):
    """
    Normalize types for comparison by casting or dereferencing as needed.
    
    Args:
        func: The LLVM IR function being built
        builder: LLVM IR builder
        lhs: Left-hand side value
        rhs: Right-hand side value
    
    Returns:
        A tuple of (normalized_lhs, normalized_rhs) or (None, None) on error
    """

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
            return _normalize_types(func, builder, lhs, rhs)


def convert_to_bool(builder, val):
    """
    Convert an LLVM IR value to a boolean (i1) type.
    
    Args:
        builder: LLVM IR builder
        val: The value to convert
    
    Returns:
        An i1 boolean value
    """
    if val.type == ir.IntType(1):
        return val
    if isinstance(val.type, ir.PointerType):
        zero = ir.Constant(val.type, None)
    else:
        zero = ir.Constant(val.type, 0)
    return builder.icmp_signed("!=", val, zero)


def handle_comparator(func, builder, op, lhs, rhs):
    """
    Handle comparison operations between two values.
    
    Args:
        func: The LLVM IR function being built
        builder: LLVM IR builder
        op: The AST comparison operator node
        lhs: Left-hand side value
        rhs: Right-hand side value
    
    Returns:
        A tuple of (result, ir.IntType(1)) or None on error
    """

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
