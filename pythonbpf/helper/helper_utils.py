import ast
import logging

from llvmlite import ir
from pythonbpf.expr import (
    get_operand_value,
    eval_expr,
)

logger = logging.getLogger(__name__)


class ScratchPoolManager:
    """Manage the temporary helper variables in local_sym_tab"""

    def __init__(self):
        self._counters = {}

    @property
    def counter(self):
        return sum(self._counters.values())

    def reset(self):
        self._counters.clear()
        logger.debug("Scratch pool counter reset to 0")

    def _get_type_name(self, ir_type):
        if isinstance(ir_type, ir.PointerType):
            return "ptr"
        elif isinstance(ir_type, ir.IntType):
            return f"i{ir_type.width}"
        elif isinstance(ir_type, ir.ArrayType):
            return f"[{ir_type.count}x{self._get_type_name(ir_type.element)}]"
        else:
            return str(ir_type).replace(" ", "")

    def get_next_temp(self, local_sym_tab, expected_type=None):
        # Default to i64 if no expected type provided
        type_name = self._get_type_name(expected_type) if expected_type else "i64"
        if type_name not in self._counters:
            self._counters[type_name] = 0

        counter = self._counters[type_name]
        temp_name = f"__helper_temp_{type_name}_{counter}"
        self._counters[type_name] += 1

        if temp_name not in local_sym_tab:
            raise ValueError(
                f"Scratch pool exhausted or inadequate: {temp_name}. "
                f"Type: {type_name} Counter: {counter}"
            )

        logger.debug(f"Using {temp_name} for type {type_name}")
        return local_sym_tab[temp_name].var, temp_name


_temp_pool_manager = ScratchPoolManager()  # Singleton instance


def reset_scratch_pool():
    """Reset the scratch pool counter"""
    _temp_pool_manager.reset()


# ============================================================================
# Argument Preparation
# ============================================================================


def get_var_ptr_from_name(var_name, local_sym_tab):
    """Get a pointer to a variable from the symbol table."""
    if local_sym_tab and var_name in local_sym_tab:
        return local_sym_tab[var_name].var
    raise ValueError(f"Variable '{var_name}' not found in local symbol table")


def create_int_constant_ptr(value, builder, local_sym_tab, int_width=64):
    """Create a pointer to an integer constant."""

    int_type = ir.IntType(int_width)
    ptr, temp_name = _temp_pool_manager.get_next_temp(local_sym_tab, int_type)
    logger.info(f"Using temp variable '{temp_name}' for int constant {value}")
    const_val = ir.Constant(int_type, value)
    builder.store(const_val, ptr)
    return ptr


def get_or_create_ptr_from_arg(
    func,
    module,
    arg,
    builder,
    local_sym_tab,
    map_sym_tab,
    struct_sym_tab=None,
    expected_type=None,
):
    """Extract or create pointer from the call arguments."""

    logger.info(f"Getting pointer from arg: {ast.dump(arg)}")
    if isinstance(arg, ast.Name):
        # Stack space is already allocated
        ptr = get_var_ptr_from_name(arg.id, local_sym_tab)
    elif isinstance(arg, ast.Constant) and isinstance(arg.value, int):
        int_width = 64  # Default to i64
        if expected_type and isinstance(expected_type, ir.IntType):
            int_width = expected_type.width
        ptr = create_int_constant_ptr(arg.value, builder, local_sym_tab, int_width)
    elif isinstance(arg, ast.Attribute):
        # A struct field
        struct_name = arg.value.id
        field_name = arg.attr

        if not local_sym_tab or struct_name not in local_sym_tab:
            raise ValueError(f"Struct '{struct_name}' not found")

        struct_type = local_sym_tab[struct_name].metadata
        if not struct_sym_tab or struct_type not in struct_sym_tab:
            raise ValueError(f"Struct type '{struct_type}' not found")

        struct_info = struct_sym_tab[struct_type]
        if field_name not in struct_info.fields:
            raise ValueError(
                f"Field '{field_name}' not found in struct '{struct_name}'"
            )

        field_type = struct_info.field_type(field_name)
        struct_ptr = local_sym_tab[struct_name].var

        # Special handling for char arrays
        if (
            isinstance(field_type, ir.ArrayType)
            and isinstance(field_type.element, ir.IntType)
            and field_type.element.width == 8
        ):
            ptr, sz = get_char_array_ptr_and_size(
                arg, builder, local_sym_tab, struct_sym_tab
            )
            if not ptr:
                raise ValueError("Failed to get char array pointer from struct field")
        else:
            ptr = struct_info.gep(builder, struct_ptr, field_name)

    else:
        # NOTE: For any integer expression reaching this branch, it is probably a struct field or a binop
        # Evaluate the expression and store the result in a temp variable
        val = get_operand_value(
            func, module, arg, builder, local_sym_tab, map_sym_tab, struct_sym_tab
        )
        if val is None:
            raise ValueError("Failed to evaluate expression for helper arg.")

        ptr, temp_name = _temp_pool_manager.get_next_temp(local_sym_tab, expected_type)
        logger.info(f"Using temp variable '{temp_name}' for expression result")
        if (
            isinstance(val.type, ir.IntType)
            and expected_type
            and val.type.width > expected_type.width
        ):
            val = builder.trunc(val, expected_type)
        builder.store(val, ptr)

    # NOTE: For char arrays, also return size
    if sz:
        return ptr, sz

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


def get_buffer_ptr_and_size(buf_arg, builder, local_sym_tab, struct_sym_tab):
    """Extract buffer pointer and size from either a struct field or variable."""

    # Case 1: Struct field (obj.field)
    if isinstance(buf_arg, ast.Attribute):
        if not isinstance(buf_arg.value, ast.Name):
            raise ValueError(
                "Only simple struct field access supported (e.g., obj.field)"
            )

        struct_name = buf_arg.value.id
        field_name = buf_arg.attr

        # Lookup struct
        if not local_sym_tab or struct_name not in local_sym_tab:
            raise ValueError(f"Struct '{struct_name}' not found")

        struct_type = local_sym_tab[struct_name].metadata
        if not struct_sym_tab or struct_type not in struct_sym_tab:
            raise ValueError(f"Struct type '{struct_type}' not found")

        struct_info = struct_sym_tab[struct_type]

        # Get field pointer and type
        struct_ptr = local_sym_tab[struct_name].var
        field_ptr = struct_info.gep(builder, struct_ptr, field_name)
        field_type = struct_info.field_type(field_name)

        if not isinstance(field_type, ir.ArrayType):
            raise ValueError(f"Field '{field_name}' must be an array type")

        return field_ptr, field_type.count

    # Case 2: Variable name
    elif isinstance(buf_arg, ast.Name):
        var_name = buf_arg.id

        if not local_sym_tab or var_name not in local_sym_tab:
            raise ValueError(f"Variable '{var_name}' not found")

        var_ptr = local_sym_tab[var_name].var
        var_type = local_sym_tab[var_name].ir_type

        if not isinstance(var_type, ir.ArrayType):
            raise ValueError(f"Variable '{var_name}' must be an array type")

        return var_ptr, var_type.count

    else:
        raise ValueError(
            "comm expects either a struct field (obj.field) or variable name"
        )


def get_char_array_ptr_and_size(buf_arg, builder, local_sym_tab, struct_sym_tab):
    """Get pointer to char array and its size."""

    # Struct field: obj.field
    if isinstance(buf_arg, ast.Attribute) and isinstance(buf_arg.value, ast.Name):
        var_name = buf_arg.value.id
        field_name = buf_arg.attr

        if not (local_sym_tab and var_name in local_sym_tab):
            raise ValueError(f"Variable '{var_name}' not found")

        struct_type = local_sym_tab[var_name].metadata
        if not (struct_sym_tab and struct_type in struct_sym_tab):
            raise ValueError(f"Struct type '{struct_type}' not found")

        struct_info = struct_sym_tab[struct_type]
        if field_name not in struct_info.fields:
            raise ValueError(f"Field '{field_name}' not found")

        field_type = struct_info.field_type(field_name)
        if not _is_char_array(field_type):
            raise ValueError("Expected char array field")

        struct_ptr = local_sym_tab[var_name].var
        field_ptr = struct_info.gep(builder, struct_ptr, field_name)

        # GEP to first element: [N x i8]* -> i8*
        buf_ptr = builder.gep(
            field_ptr,
            [ir.Constant(ir.IntType(32), 0), ir.Constant(ir.IntType(32), 0)],
            inbounds=True,
        )
        return buf_ptr, field_type.count

    elif isinstance(buf_arg, ast.Name):
        # NOTE: We shouldn't be doing this as we can't get size info
        var_name = buf_arg.id
        if not (local_sym_tab and var_name in local_sym_tab):
            raise ValueError(f"Variable '{var_name}' not found")

        var_ptr = local_sym_tab[var_name].var
        var_type = local_sym_tab[var_name].ir_type

        if not isinstance(var_type, ir.PointerType) or not isinstance(
            var_type.pointee, ir.IntType(8)
        ):
            raise ValueError("Expected str ptr variable")

        return var_ptr, 256  # Size unknown for str ptr, using 256 as default

    else:
        raise ValueError("Expected struct field or variable name")


def _is_char_array(ir_type):
    """Check if IR type is [N x i8]."""
    return (
        isinstance(ir_type, ir.ArrayType)
        and isinstance(ir_type.element, ir.IntType)
        and ir_type.element.width == 8
    )


def get_ptr_from_arg(
    arg, func, module, builder, local_sym_tab, map_sym_tab, struct_sym_tab
):
    """Evaluate argument and return pointer value"""

    result = eval_expr(
        func, module, builder, arg, local_sym_tab, map_sym_tab, struct_sym_tab
    )

    if not result:
        raise ValueError("Failed to evaluate argument")

    val, val_type = result

    if not isinstance(val_type, ir.PointerType):
        raise ValueError(f"Expected pointer type, got {val_type}")

    return val, val_type


def get_int_value_from_arg(
    arg, func, module, builder, local_sym_tab, map_sym_tab, struct_sym_tab
):
    """Evaluate argument and return integer value"""

    result = eval_expr(
        func, module, builder, arg, local_sym_tab, map_sym_tab, struct_sym_tab
    )

    if not result:
        raise ValueError("Failed to evaluate argument")

    val, val_type = result

    if not isinstance(val_type, ir.IntType):
        raise ValueError(f"Expected integer type, got {val_type}")

    return val
