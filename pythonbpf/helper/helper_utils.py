"""
Utility functions for BPF helper function handling.

This module provides utility functions for processing BPF helper function
calls, including argument handling, string formatting for bpf_printk,
and a registry for helper function handlers.
"""

import ast
import logging
from collections.abc import Callable

from llvmlite import ir
from pythonbpf.expr import eval_expr

logger = logging.getLogger(__name__)


class HelperHandlerRegistry:
    """Registry for BPF helpers"""

    _handlers: dict[str, Callable] = {}

    @classmethod
    def register(cls, helper_name):
        """Decorator to register a handler function for a helper"""

        def decorator(func):
            cls._handlers[helper_name] = func
            return func

        return decorator

    @classmethod
    def get_handler(cls, helper_name):
        """Get the handler function for a helper"""
        return cls._handlers.get(helper_name)

    @classmethod
    def has_handler(cls, helper_name):
        """Check if a handler function is registered for a helper"""
        return helper_name in cls._handlers


def get_var_ptr_from_name(var_name, local_sym_tab):
    """
    Get a pointer to a variable from the symbol table.
    
    Args:
        var_name: Name of the variable to look up
        local_sym_tab: Local symbol table
    
    Returns:
        Pointer to the variable
    
    Raises:
        ValueError: If the variable is not found
    """
    if local_sym_tab and var_name in local_sym_tab:
        return local_sym_tab[var_name].var
    raise ValueError(f"Variable '{var_name}' not found in local symbol table")


def create_int_constant_ptr(value, builder, int_width=64):
    """
    Create a pointer to an integer constant.
    
    Args:
        value: The integer value
        builder: LLVM IR builder
        int_width: Width of the integer in bits (default: 64)
    
    Returns:
        Pointer to the allocated integer constant
    """
    # Default to 64-bit integer
    int_type = ir.IntType(int_width)
    ptr = builder.alloca(int_type)
    ptr.align = int_type.width // 8
    builder.store(ir.Constant(int_type, value), ptr)
    return ptr


def get_or_create_ptr_from_arg(arg, builder, local_sym_tab):
    """
    Extract or create pointer from call arguments.
    
    Args:
        arg: The AST argument node
        builder: LLVM IR builder
        local_sym_tab: Local symbol table
    
    Returns:
        Pointer to the argument value
    
    Raises:
        NotImplementedError: If the argument type is not supported
    """

    if isinstance(arg, ast.Name):
        ptr = get_var_ptr_from_name(arg.id, local_sym_tab)
    elif isinstance(arg, ast.Constant) and isinstance(arg.value, int):
        ptr = create_int_constant_ptr(arg.value, builder)
    else:
        raise NotImplementedError(
            "Only simple variable names are supported as args in map helpers."
        )
    return ptr


def get_flags_val(arg, builder, local_sym_tab):
    """
    Extract or create flags value from call arguments.
    
    Args:
        arg: The AST argument node for flags
        builder: LLVM IR builder
        local_sym_tab: Local symbol table
    
    Returns:
        Integer flags value or LLVM IR value
    
    Raises:
        ValueError: If a variable is not found in symbol table
        NotImplementedError: If the argument type is not supported
    """
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
    """
    Prepare arguments for bpf_printk from a simple string value.
    
    Args:
        string_value: The string to print
        module: LLVM IR module
        builder: LLVM IR builder
        func: The LLVM IR function being built
    
    Returns:
        List of arguments for bpf_printk
    """
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
    """
    Handle f-string formatting for bpf_printk emitter.
    
    Args:
        joined_str: AST JoinedStr node representing the f-string
        module: LLVM IR module
        builder: LLVM IR builder
        func: The LLVM IR function being built
        local_sym_tab: Local symbol table
        struct_sym_tab: Struct symbol table
    
    Returns:
        List of arguments for bpf_printk
    
    Raises:
        NotImplementedError: If f-string contains unsupported value types
    """
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
    elif ftype == ir.PointerType(ir.IntType(8)):
        # NOTE: We assume i8* is a string
        fmt_parts.append("%s")
        exprs.append(node)
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
            val = builder.ptrtoint(val, ir.IntType(64))
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
