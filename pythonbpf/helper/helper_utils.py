import ast
import logging

from llvmlite import ir
from pythonbpf.expr import (
    eval_expr,
    get_base_type_and_depth,
    deref_to_depth,
    get_operand_value,
)

logger = logging.getLogger(__name__)


class ScratchPoolManager:
    """Manage the temporary helper variables in local_sym_tab"""

    def __init__(self):
        self._counter = 0

    @property
    def counter(self):
        return self._counter

    def reset(self):
        self._counter = 0
        logger.debug("Scratch pool counter reset to 0")

    def get_next_temp(self, local_sym_tab):
        temp_name = f"__helper_temp_{self._counter}"
        self._counter += 1

        if temp_name not in local_sym_tab:
            raise ValueError(
                f"Scratch pool exhausted or inadequate: {temp_name}. "
                f"Current counter: {self._counter}"
            )

        return local_sym_tab[temp_name].var, temp_name


_temp_pool_manager = ScratchPoolManager()  # Singleton instance


def reset_scratch_pool():
    """Reset the scratch pool counter"""
    _temp_pool_manager.reset()


def get_var_ptr_from_name(var_name, local_sym_tab):
    """Get a pointer to a variable from the symbol table."""
    if local_sym_tab and var_name in local_sym_tab:
        return local_sym_tab[var_name].var
    raise ValueError(f"Variable '{var_name}' not found in local symbol table")


def create_int_constant_ptr(value, builder, local_sym_tab, int_width=64):
    """Create a pointer to an integer constant."""

    # Default to 64-bit integer
    ptr, temp_name = _temp_pool_manager.get_next_temp(local_sym_tab)
    logger.info(f"Using temp variable '{temp_name}' for int constant {value}")
    const_val = ir.Constant(ir.IntType(int_width), value)
    builder.store(const_val, ptr)
    return ptr


def get_or_create_ptr_from_arg(
    func, module, arg, builder, local_sym_tab, map_sym_tab, struct_sym_tab=None
):
    """Extract or create pointer from the call arguments."""

    if isinstance(arg, ast.Name):
        ptr = get_var_ptr_from_name(arg.id, local_sym_tab)
    elif isinstance(arg, ast.Constant) and isinstance(arg.value, int):
        ptr = create_int_constant_ptr(arg.value, builder, local_sym_tab)
    else:
        # Evaluate the expression and store the result in a temp variable
        val = get_operand_value(
            func, module, arg, builder, local_sym_tab, map_sym_tab, struct_sym_tab
        )
        if val is None:
            raise ValueError("Failed to evaluate expression for helper arg.")

        # NOTE: We assume the result is an int64 for now
        # if isinstance(arg, ast.Attribute):
        # return val
        ptr, temp_name = _temp_pool_manager.get_next_temp(local_sym_tab)
        logger.info(f"Using temp variable '{temp_name}' for expression result")
        builder.store(val, ptr)

    return ptr


def get_flags_val(arg, builder, local_sym_tab):
    """Extract or create flags value from the call arguments."""
    if not arg:
        return 0

    if isinstance(arg, ast.Name):
        if local_sym_tab and arg.id in local_sym_tab:
            flags_ptr = local_sym_tab[arg.id].var
            return builder.load(flags_ptr)
        else:
            raise ValueError(f"Variable '{arg.id}' not found in local symbol table")
    elif isinstance(arg, ast.Constant) and isinstance(arg.value, int):
        return arg.value

    raise NotImplementedError(
        "Only var names or int consts are supported as map helpers flags."
    )


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
    val, _ = eval_expr(
        func,
        module,
        builder,
        expr,
        local_sym_tab,
        None,
        struct_sym_tab,
    )

    if val:
        if isinstance(val.type, ir.PointerType):
            target, depth = get_base_type_and_depth(val.type)
            if isinstance(target, ir.IntType):
                if target.width >= 32:
                    val = deref_to_depth(func, builder, val, depth)
                    val = builder.sext(val, ir.IntType(64))
                elif target.width == 8 and depth == 1:
                    # NOTE: i8* is string, no need to deref
                    pass

            else:
                logger.warning(
                    "Only int and ptr supported in bpf_printk args. Others default to 0."
                )
                val = ir.Constant(ir.IntType(64), 0)
        elif isinstance(val.type, ir.IntType):
            if val.type.width < 64:
                val = builder.sext(val, ir.IntType(64))
        else:
            logger.warning(
                "Only int and ptr supported in bpf_printk args. Others default to 0."
            )
            val = ir.Constant(ir.IntType(64), 0)
        return val
    else:
        logger.warning(
            "Failed to evaluate expression for bpf_printk argument. "
            "It will be converted to 0."
        )
        return ir.Constant(ir.IntType(64), 0)


def get_data_ptr_and_size(data_arg, local_sym_tab, struct_sym_tab):
    """Extract data pointer and size information for perf event output."""
    if isinstance(data_arg, ast.Name):
        data_name = data_arg.id
        if local_sym_tab and data_name in local_sym_tab:
            data_ptr = local_sym_tab[data_name].var
        else:
            raise ValueError(
                f"Data variable {data_name} not found in local symbol table."
            )

        # Check if data_name is a struct
        data_type = local_sym_tab[data_name].metadata
        if data_type in struct_sym_tab:
            struct_info = struct_sym_tab[data_type]
            size_val = ir.Constant(ir.IntType(64), struct_info.size)
            return data_ptr, size_val
        else:
            raise ValueError(f"Struct {data_type} for {data_name} not in symbol table.")
    else:
        raise NotImplementedError(
            "Only simple object names are supported as data in perf event output."
        )
