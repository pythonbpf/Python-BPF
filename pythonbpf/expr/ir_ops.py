import ast
import logging
from llvmlite import ir

logger = logging.getLogger(__name__)


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


def apply_binop(builder, op, left, right):
    """Emit the LLVM instruction for a Python binary operator.

    Shared by binary-op evaluation and augmented assignment so the operator
    table exists exactly once.
    """
    method = BINOP_METHODS.get(type(op))
    if method is None:
        raise SyntaxError("Unsupported binary operation")
    return getattr(builder, method)(left, right)


def deref_to_depth(func, builder, val, target_depth):
    """Dereference a pointer to a certain depth."""

    cur_val = val
    cur_type = val.type

    for depth in range(target_depth):
        if not isinstance(cur_type, ir.PointerType):
            logger.error("Cannot dereference further, non-pointer type")
            return None

        # dereference with null check
        pointee_type = cur_type.pointee

        def load_op(builder, ptr):
            return builder.load(ptr)

        cur_val = _null_checked_operation(
            func, builder, cur_val, load_op, pointee_type, f"deref_{depth}"
        )
        cur_type = pointee_type
        logger.debug(f"Dereferenced to depth {depth}, type: {pointee_type}")
    return cur_val


def _null_checked_operation(func, builder, ptr, operation, result_type, name_prefix):
    """
    Generic null-checked operation on a pointer.
    """
    curr_block = builder.block
    not_null_block = func.append_basic_block(name=f"{name_prefix}_not_null")
    merge_block = func.append_basic_block(name=f"{name_prefix}_merge")

    null_ptr = ir.Constant(ptr.type, None)
    is_not_null = builder.icmp_signed("!=", ptr, null_ptr)
    builder.cbranch(is_not_null, not_null_block, merge_block)

    builder.position_at_end(not_null_block)
    result = operation(builder, ptr)
    not_null_after = builder.block
    builder.branch(merge_block)

    builder.position_at_end(merge_block)
    phi = builder.phi(result_type, name=f"{name_prefix}_result")

    if isinstance(result_type, ir.IntType):
        null_val = ir.Constant(result_type, 0)
    elif isinstance(result_type, ir.PointerType):
        null_val = ir.Constant(result_type, None)
    else:
        null_val = ir.Constant(result_type, ir.Undefined)

    phi.add_incoming(null_val, curr_block)
    phi.add_incoming(result, not_null_after)

    return phi


def access_struct_field(
    builder, var_ptr, var_type, var_metadata, field_name, structs_sym_tab, func=None
):
    """
    Access a struct field - automatically returns value or pointer based on field type.
    """
    metadata = (
        structs_sym_tab.get(var_metadata)
        if isinstance(var_metadata, str)
        else var_metadata
    )
    if not metadata or field_name not in metadata.fields:
        raise ValueError(f"Field '{field_name}' not found in struct")

    field_type = metadata.field_type(field_name)
    is_ptr_to_struct = isinstance(var_type, ir.PointerType) and isinstance(
        var_metadata, str
    )

    # Get struct pointer
    struct_ptr = builder.load(var_ptr) if is_ptr_to_struct else var_ptr

    should_load = not isinstance(field_type, ir.ArrayType)

    def field_access_op(builder, ptr):
        typed_ptr = builder.bitcast(ptr, metadata.ir_type.as_pointer())
        field_ptr = metadata.gep(builder, typed_ptr, field_name)
        return builder.load(field_ptr) if should_load else field_ptr

    # Handle null check for pointer-to-struct
    if is_ptr_to_struct:
        if func is None:
            raise ValueError("func required for null-safe struct pointer access")

        if should_load:
            result_type = field_type
        else:
            result_type = field_type.as_pointer()

        result = _null_checked_operation(
            func,
            builder,
            struct_ptr,
            field_access_op,
            result_type,
            f"field_{field_name}",
        )
        return result, field_type

    field_ptr = metadata.gep(builder, struct_ptr, field_name)
    result = builder.load(field_ptr) if should_load else field_ptr
    return result, field_type
