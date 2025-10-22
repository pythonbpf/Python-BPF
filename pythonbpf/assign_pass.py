import ast
import logging
from llvmlite import ir
from pythonbpf.expr import eval_expr
from pythonbpf.helper import emit_probe_read_kernel_str_call

logger = logging.getLogger(__name__)


def handle_struct_field_assignment(
    func, module, builder, target, rval, local_sym_tab, map_sym_tab, structs_sym_tab
):
    """Handle struct field assignment (obj.field = value)."""

    var_name = target.value.id
    field_name = target.attr

    if var_name not in local_sym_tab:
        logger.error(f"Variable '{var_name}' not found in symbol table")
        return

    struct_type = local_sym_tab[var_name].metadata
    struct_info = structs_sym_tab[struct_type]

    if field_name not in struct_info.fields:
        logger.error(f"Field '{field_name}' not found in struct '{struct_type}'")
        return

    # Get field pointer and evaluate value
    field_ptr = struct_info.gep(builder, local_sym_tab[var_name].var, field_name)
    field_type = struct_info.field_type(field_name)
    val_result = eval_expr(
        func, module, builder, rval, local_sym_tab, map_sym_tab, structs_sym_tab
    )

    if val_result is None:
        logger.error(f"Failed to evaluate value for {var_name}.{field_name}")
        return

    val, val_type = val_result

    # Special case: i8* string to [N x i8] char array
    if _is_char_array(field_type) and _is_i8_ptr(val_type):
        _copy_string_to_char_array(
            func,
            module,
            builder,
            val,
            field_ptr,
            field_type,
            local_sym_tab,
            map_sym_tab,
            structs_sym_tab,
        )
        logger.info(f"Copied string to char array {var_name}.{field_name}")
        return

    # Regular assignment
    builder.store(val, field_ptr)
    logger.info(f"Assigned to struct field {var_name}.{field_name}")


def _copy_string_to_char_array(
    func,
    module,
    builder,
    src_ptr,
    dst_ptr,
    array_type,
    local_sym_tab,
    map_sym_tab,
    struct_sym_tab,
):
    """Copy string (i8*) to char array ([N x i8]) using bpf_probe_read_kernel_str"""

    array_size = array_type.count

    # Get pointer to first element: [N x i8]* -> i8*
    dst_i8_ptr = builder.gep(
        dst_ptr,
        [ir.Constant(ir.IntType(32), 0), ir.Constant(ir.IntType(32), 0)],
        inbounds=True,
    )

    # Use the shared emitter function
    emit_probe_read_kernel_str_call(builder, dst_i8_ptr, array_size, src_ptr)


def _is_char_array(ir_type):
    """Check if type is [N x i8]."""
    return (
        isinstance(ir_type, ir.ArrayType)
        and isinstance(ir_type.element, ir.IntType)
        and ir_type.element.width == 8
    )


def _is_i8_ptr(ir_type):
    """Check if type is i8*."""
    return (
        isinstance(ir_type, ir.PointerType)
        and isinstance(ir_type.pointee, ir.IntType)
        and ir_type.pointee.width == 8
    )


def handle_variable_assignment(
    func, module, builder, var_name, rval, local_sym_tab, map_sym_tab, structs_sym_tab
):
    """Handle single named variable assignment."""

    if var_name not in local_sym_tab:
        logger.error(f"Variable {var_name} not declared.")
        return False

    var_ptr = local_sym_tab[var_name].var
    var_type = local_sym_tab[var_name].ir_type

    # NOTE: Special case for struct initialization
    if isinstance(rval, ast.Call) and isinstance(rval.func, ast.Name):
        struct_name = rval.func.id
        if struct_name in structs_sym_tab and len(rval.args) == 0:
            struct_info = structs_sym_tab[struct_name]
            ir_struct = struct_info.ir_type

            builder.store(ir.Constant(ir_struct, None), var_ptr)
            logger.info(f"Initialized struct {struct_name} for variable {var_name}")
            return True

    # Special case: struct field char array -> pointer
    # Handle this before eval_expr to get the pointer, not the value
    if isinstance(rval, ast.Attribute) and isinstance(rval.value, ast.Name):
        converted_val = _try_convert_char_array_to_ptr(
            rval, var_type, builder, local_sym_tab, structs_sym_tab
        )
        if converted_val is not None:
            builder.store(converted_val, var_ptr)
            logger.info(f"Assigned char array pointer to {var_name}")
            return True

    val_result = eval_expr(
        func, module, builder, rval, local_sym_tab, map_sym_tab, structs_sym_tab
    )
    if val_result is None:
        logger.error(f"Failed to evaluate value for {var_name}")
        return False

    val, val_type = val_result
    logger.info(f"Evaluated value for {var_name}: {val} of type {val_type}, {var_type}")
    if val_type != var_type:
        if isinstance(val_type, ir.IntType) and isinstance(var_type, ir.IntType):
            # Allow implicit int widening
            if val_type.width < var_type.width:
                val = builder.sext(val, var_type)
                logger.info(f"Implicitly widened int for variable {var_name}")
            elif val_type.width > var_type.width:
                val = builder.trunc(val, var_type)
                logger.info(f"Implicitly truncated int for variable {var_name}")
        elif isinstance(val_type, ir.IntType) and isinstance(var_type, ir.PointerType):
            # NOTE: This is assignment to a PTR_TO_MAP_VALUE_OR_NULL
            logger.info(
                f"Creating temporary variable for pointer assignment to {var_name}"
            )
            var_ptr_tmp = local_sym_tab[f"{var_name}_tmp"].var
            builder.store(val, var_ptr_tmp)
            val = var_ptr_tmp
        else:
            logger.error(
                f"Type mismatch for variable {var_name}: {val_type} vs {var_type}"
            )
            return False

    builder.store(val, var_ptr)
    logger.info(f"Assigned value to variable {var_name}")
    return True


def _try_convert_char_array_to_ptr(
    rval, var_type, builder, local_sym_tab, structs_sym_tab
):
    """Try to convert char array field to i8* pointer"""
    # Only convert if target is i8*
    if not (
        isinstance(var_type, ir.PointerType)
        and isinstance(var_type.pointee, ir.IntType)
        and var_type.pointee.width == 8
    ):
        return None

    struct_var = rval.value.id
    field_name = rval.attr

    # Validate struct
    if struct_var not in local_sym_tab:
        return None

    struct_type = local_sym_tab[struct_var].metadata
    if not struct_type or struct_type not in structs_sym_tab:
        return None

    struct_info = structs_sym_tab[struct_type]
    if field_name not in struct_info.fields:
        return None

    field_type = struct_info.field_type(field_name)

    # Check if it's a char array
    if not (
        isinstance(field_type, ir.ArrayType)
        and isinstance(field_type.element, ir.IntType)
        and field_type.element.width == 8
    ):
        return None

    # Get pointer to struct field
    struct_ptr = local_sym_tab[struct_var].var
    field_ptr = struct_info.gep(builder, struct_ptr, field_name)

    # GEP to first element: [N x i8]* -> i8*
    return builder.gep(
        field_ptr,
        [ir.Constant(ir.IntType(32), 0), ir.Constant(ir.IntType(32), 0)],
        inbounds=True,
    )
