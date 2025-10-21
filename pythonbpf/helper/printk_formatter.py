import ast
import logging

from llvmlite import ir
from pythonbpf.expr import eval_expr, get_base_type_and_depth, deref_to_depth
from pythonbpf.expr.vmlinux_registry import VmlinuxHandlerRegistry

logger = logging.getLogger(__name__)


def simple_string_print(string_value, module, builder, func):
    """Prepare arguments for bpf_printk from a simple string value"""
    fmt_str = string_value + "\n\0"
    fmt_ptr = _create_format_string_global(fmt_str, func, module, builder)

    args = [fmt_ptr, ir.Constant(ir.IntType(32), len(fmt_str))]
    return args


def handle_fstring_print(
    joined_str,
    module,
    builder,
    func,
    local_sym_tab=None,
    struct_sym_tab=None,
):
    """Handle f-string formatting for bpf_printk emitter."""
    fmt_parts = []
    exprs = []

    for value in joined_str.values:
        logger.debug(f"Processing f-string value: {ast.dump(value)}")

        if isinstance(value, ast.Constant):
            _process_constant_in_fstring(value, fmt_parts, exprs)
        elif isinstance(value, ast.FormattedValue):
            _process_fval(
                value,
                fmt_parts,
                exprs,
                local_sym_tab,
                struct_sym_tab,
            )
        else:
            raise NotImplementedError(f"Unsupported f-string value type: {type(value)}")

    fmt_str = "".join(fmt_parts)
    args = simple_string_print(fmt_str, module, builder, func)

    # NOTE: Process expressions (limited to 3 due to BPF constraints)
    if len(exprs) > 3:
        logger.warning("bpf_printk supports up to 3 args, extra args will be ignored.")

    for expr in exprs[:3]:
        arg_value = _prepare_expr_args(
            expr,
            func,
            module,
            builder,
            local_sym_tab,
            struct_sym_tab,
        )
        args.append(arg_value)

    return args


# ============================================================================
# Internal Helpers
# ============================================================================


def _process_constant_in_fstring(cst, fmt_parts, exprs):
    """Process constant values in f-string."""
    if isinstance(cst.value, str):
        fmt_parts.append(cst.value)
    elif isinstance(cst.value, int):
        fmt_parts.append("%lld")
        exprs.append(ir.Constant(ir.IntType(64), cst.value))
    else:
        raise NotImplementedError(
            f"Unsupported constant type in f-string: {type(cst.value)}"
        )


def _process_fval(fval, fmt_parts, exprs, local_sym_tab, struct_sym_tab):
    """Process formatted values in f-string."""
    logger.debug(f"Processing formatted value: {ast.dump(fval)}")

    if isinstance(fval.value, ast.Name):
        _process_name_in_fval(fval.value, fmt_parts, exprs, local_sym_tab)
    elif isinstance(fval.value, ast.Attribute):
        _process_attr_in_fval(
            fval.value,
            fmt_parts,
            exprs,
            local_sym_tab,
            struct_sym_tab,
        )
    else:
        raise NotImplementedError(
            f"Unsupported formatted value in f-string: {type(fval.value)}"
        )


def _process_name_in_fval(name_node, fmt_parts, exprs, local_sym_tab):
    """Process name nodes in formatted values."""
    if local_sym_tab and name_node.id in local_sym_tab:
        _, var_type, tmp = local_sym_tab[name_node.id]
        _populate_fval(var_type, name_node, fmt_parts, exprs)
    else:
        # Try to resolve through vmlinux registry if not in local symbol table
        result = VmlinuxHandlerRegistry.handle_name(name_node.id)
        if result:
            val, var_type = result
            _populate_fval(var_type, name_node, fmt_parts, exprs)
        else:
            raise ValueError(
                f"Variable '{name_node.id}' not found in symbol table or vmlinux"
            )


def _process_attr_in_fval(attr_node, fmt_parts, exprs, local_sym_tab, struct_sym_tab):
    """Process attribute nodes in formatted values."""
    if (
        isinstance(attr_node.value, ast.Name)
        and local_sym_tab
        and attr_node.value.id in local_sym_tab
    ):
        var_name = attr_node.value.id
        field_name = attr_node.attr

        var_type = local_sym_tab[var_name].metadata
        if var_type not in struct_sym_tab:
            raise ValueError(
                f"Struct '{var_type}' for '{var_name}' not in symbol table"
            )

        struct_info = struct_sym_tab[var_type]
        if field_name not in struct_info.fields:
            raise ValueError(f"Field '{field_name}' not found in struct '{var_type}'")

        field_type = struct_info.field_type(field_name)
        _populate_fval(field_type, attr_node, fmt_parts, exprs)
    else:
        raise NotImplementedError(
            "Only simple attribute on local vars is supported in f-strings."
        )


def _populate_fval(ftype, node, fmt_parts, exprs):
    """Populate format parts and expressions based on field type."""
    if isinstance(ftype, ir.IntType):
        # TODO: We print as signed integers only for now
        if ftype.width == 64:
            fmt_parts.append("%lld")
            exprs.append(node)
        elif ftype.width == 32:
            fmt_parts.append("%d")
            exprs.append(node)
        else:
            raise NotImplementedError(
                f"Unsupported integer width in f-string: {ftype.width}"
            )
    elif isinstance(ftype, ir.PointerType):
        target, depth = get_base_type_and_depth(ftype)
        if isinstance(target, ir.IntType):
            if target.width == 64:
                fmt_parts.append("%lld")
                exprs.append(node)
            elif target.width == 32:
                fmt_parts.append("%d")
                exprs.append(node)
            elif target.width == 8 and depth == 1:
                # NOTE: Assume i8* is a string
                fmt_parts.append("%s")
                exprs.append(node)
            else:
                raise NotImplementedError(
                    f"Unsupported pointer target type in f-string: {target}"
                )
        else:
            raise NotImplementedError(
                f"Unsupported pointer target type in f-string: {target}"
            )
    elif isinstance(ftype, ir.ArrayType):
        if isinstance(ftype.element, ir.IntType) and ftype.element.width == 8:
            # Char array
            fmt_parts.append("%s")
            exprs.append(node)
        else:
            raise NotImplementedError(
                f"Unsupported array element type in f-string: {ftype.element}"
            )
    else:
        raise NotImplementedError(f"Unsupported field type in f-string: {ftype}")


def _create_format_string_global(fmt_str, func, module, builder):
    """Create a global variable for the format string."""
    fmt_name = f"{func.name}____fmt{func._fmt_counter}"
    func._fmt_counter += 1

    fmt_gvar = ir.GlobalVariable(
        module, ir.ArrayType(ir.IntType(8), len(fmt_str)), name=fmt_name
    )
    fmt_gvar.global_constant = True
    fmt_gvar.initializer = ir.Constant(
        ir.ArrayType(ir.IntType(8), len(fmt_str)), bytearray(fmt_str.encode("utf8"))
    )
    fmt_gvar.linkage = "internal"
    fmt_gvar.align = 1

    return builder.bitcast(fmt_gvar, ir.PointerType())


def _prepare_expr_args(expr, func, module, builder, local_sym_tab, struct_sym_tab):
    """Evaluate and prepare an expression to use as an arg for bpf_printk."""

    # Special case: struct field char array needs pointer to first element
    char_array_ptr = _get_struct_char_array_ptr(
        expr, builder, local_sym_tab, struct_sym_tab
    )
    if char_array_ptr:
        return char_array_ptr

    # Regular expression evaluation
    val, _ = eval_expr(func, module, builder, expr, local_sym_tab, None, struct_sym_tab)

    if not val:
        logger.warning("Failed to evaluate expression for bpf_printk, defaulting to 0")
        return ir.Constant(ir.IntType(64), 0)

    # Convert value to bpf_printk compatible type
    if isinstance(val.type, ir.PointerType):
        return _handle_pointer_arg(val, func, builder)
    elif isinstance(val.type, ir.IntType):
        return _handle_int_arg(val, builder)
    else:
        logger.warning(f"Unsupported type {val.type} in bpf_printk, defaulting to 0")
        return ir.Constant(ir.IntType(64), 0)


def _get_struct_char_array_ptr(expr, builder, local_sym_tab, struct_sym_tab):
    """Get pointer to first element of char array in struct field, or None."""
    if not (isinstance(expr, ast.Attribute) and isinstance(expr.value, ast.Name)):
        return None

    var_name = expr.value.id
    field_name = expr.attr

    # Check if it's a valid struct field
    if not (
        local_sym_tab
        and var_name in local_sym_tab
        and struct_sym_tab
        and local_sym_tab[var_name].metadata in struct_sym_tab
    ):
        return None

    struct_type = local_sym_tab[var_name].metadata
    struct_info = struct_sym_tab[struct_type]

    if field_name not in struct_info.fields:
        return None

    field_type = struct_info.field_type(field_name)

    # Check if it's a char array
    is_char_array = (
        isinstance(field_type, ir.ArrayType)
        and isinstance(field_type.element, ir.IntType)
        and field_type.element.width == 8
    )

    if not is_char_array:
        return None

    # Get field pointer and GEP to first element: [N x i8]* -> i8*
    struct_ptr = local_sym_tab[var_name].var
    field_ptr = struct_info.gep(builder, struct_ptr, field_name)

    return builder.gep(
        field_ptr,
        [ir.Constant(ir.IntType(32), 0), ir.Constant(ir.IntType(32), 0)],
        inbounds=True,
    )


def _handle_pointer_arg(val, func, builder):
    """Convert pointer type for bpf_printk."""
    target, depth = get_base_type_and_depth(val.type)

    if not isinstance(target, ir.IntType):
        logger.warning("Only int pointers supported in bpf_printk, defaulting to 0")
        return ir.Constant(ir.IntType(64), 0)

    # i8* is string - use as-is
    if target.width == 8 and depth == 1:
        return val

    # Integer pointers: dereference and sign-extend to i64
    if target.width >= 32:
        val = deref_to_depth(func, builder, val, depth)
        return builder.sext(val, ir.IntType(64))

    logger.warning("Unsupported pointer width in bpf_printk, defaulting to 0")
    return ir.Constant(ir.IntType(64), 0)


def _handle_int_arg(val, builder):
    """Convert integer type for bpf_printk (sign-extend to i64)."""
    if val.type.width < 64:
        return builder.sext(val, ir.IntType(64))
    return val
