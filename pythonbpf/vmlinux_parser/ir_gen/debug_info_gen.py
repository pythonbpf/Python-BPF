from pythonbpf.debuginfo import DebugInfoGenerator, dwarf_constants as dc
from ..dependency_node import DependencyNode
import ctypes
import logging
from typing import List, Any, Tuple

logger = logging.getLogger(__name__)


def debug_info_generation(
    struct: DependencyNode,
    llvm_module,
    generated_debug_info: List[Tuple[DependencyNode, Any]],
) -> Any:
    """
    Generate DWARF debug information for a struct defined in a DependencyNode.

    Args:
        struct: The dependency node containing struct information
        llvm_module: The LLVM module to add debug info to
        generated_debug_info: List of tuples (struct, debug_info) to track generated debug info

    Returns:
        The generated global variable debug info
    """
    # Set up debug info generator
    generator = DebugInfoGenerator(llvm_module)

    # Check if debug info for this struct has already been generated
    for existing_struct, debug_info in generated_debug_info:
        if existing_struct.name == struct.name:
            return debug_info

    # Process all fields and create members for the struct
    members = []
    for field_name, field in struct.fields.items():
        # Get appropriate debug type for this field
        field_type = _get_field_debug_type(
            field_name, field, generator, struct, generated_debug_info
        )
        # Create struct member with proper offset
        member = generator.create_struct_member_vmlinux(
            field_name, field_type, field.offset * 8
        )
        members.append(member)

    if struct.name.startswith("struct_"):
        struct_name = struct.name.removeprefix("struct_")
    else:
        raise ValueError("Unions are not supported in the current version")
    # Create struct type with all members
    struct_type = generator.create_struct_type_with_name(
        struct_name, members, struct.__sizeof__() * 8, is_distinct=True
    )

    return struct_type


def _get_field_debug_type(
    field_name: str,
    field,
    generator: DebugInfoGenerator,
    parent_struct: DependencyNode,
    generated_debug_info: List[Tuple[DependencyNode, Any]],
) -> tuple[Any, int]:
    """
    Determine the appropriate debug type for a field based on its Python/ctypes type.

    Args:
        field_name: Name of the field
        field: Field object containing type information
        generator: DebugInfoGenerator instance
        parent_struct: The parent struct containing this field
        generated_debug_info: List of already generated debug info

    Returns:
        The debug info type for this field
    """
    # Handle complex types (arrays, pointers)
    if field.ctype_complex_type is not None:
        if issubclass(field.ctype_complex_type, ctypes.Array):
            # Handle array types
            element_type, base_type_size = _get_basic_debug_type(
                field.containing_type, generator
            )
            return generator.create_array_type_vmlinux(
                (element_type, base_type_size * field.type_size), field.type_size
            ), field.type_size * base_type_size
        elif issubclass(field.ctype_complex_type, ctypes._Pointer):
            # Handle pointer types
            pointee_type, _ = _get_basic_debug_type(field.containing_type, generator)
            return generator.create_pointer_type(pointee_type), 64

    # Handle other vmlinux types (nested structs)
    if field.type.__module__ == "vmlinux":
        # If it's a struct from vmlinux, check if we've already generated debug info for it
        struct_name = field.type.__name__

        # Look for existing debug info in the list
        for existing_struct, debug_info in generated_debug_info:
            if existing_struct.name == struct_name:
                # Use existing debug info
                return debug_info, existing_struct.__sizeof__()

        # If not found, create a forward declaration
        # This will be completed when the actual struct is processed
        logger.warning("Forward declaration in struct created")
        forward_type = generator.create_struct_type([], 0, is_distinct=True)
        return forward_type, 0

    # Handle basic C types
    return _get_basic_debug_type(field.type, generator)


def _get_basic_debug_type(ctype, generator: DebugInfoGenerator) -> Any:
    """
    Map a ctypes type to a DWARF debug type.

    Args:
        ctype: A ctypes type or Python type
        generator: DebugInfoGenerator instance

    Returns:
        The corresponding debug type
    """
    # Map ctypes to debug info types
    if ctype == ctypes.c_char or ctype == ctypes.c_byte:
        return generator.get_basic_type("char", 8, dc.DW_ATE_signed_char), 8
    elif ctype == ctypes.c_ubyte or ctype == ctypes.c_uint8:
        return generator.get_basic_type("unsigned char", 8, dc.DW_ATE_unsigned_char), 8
    elif ctype == ctypes.c_short or ctype == ctypes.c_int16:
        return generator.get_basic_type("short", 16, dc.DW_ATE_signed), 16
    elif ctype == ctypes.c_ushort or ctype == ctypes.c_uint16:
        return generator.get_basic_type("unsigned short", 16, dc.DW_ATE_unsigned), 16
    elif ctype == ctypes.c_int or ctype == ctypes.c_int32:
        return generator.get_basic_type("int", 32, dc.DW_ATE_signed), 32
    elif ctype == ctypes.c_uint or ctype == ctypes.c_uint32:
        return generator.get_basic_type("unsigned int", 32, dc.DW_ATE_unsigned), 32
    elif ctype == ctypes.c_long:
        return generator.get_basic_type("long", 64, dc.DW_ATE_signed), 64
    elif ctype == ctypes.c_ulong:
        return generator.get_basic_type("unsigned long", 64, dc.DW_ATE_unsigned), 64
    elif ctype == ctypes.c_longlong or ctype == ctypes.c_int64:
        return generator.get_basic_type("long long", 64, dc.DW_ATE_signed), 64
    elif ctype == ctypes.c_ulonglong or ctype == ctypes.c_uint64:
        return generator.get_basic_type(
            "unsigned long long", 64, dc.DW_ATE_unsigned
        ), 64
    elif ctype == ctypes.c_float:
        return generator.get_basic_type("float", 32, dc.DW_ATE_float), 32
    elif ctype == ctypes.c_double:
        return generator.get_basic_type("double", 64, dc.DW_ATE_float), 64
    elif ctype == ctypes.c_bool:
        return generator.get_basic_type("bool", 8, dc.DW_ATE_boolean), 8
    elif ctype == ctypes.c_char_p:
        char_type = generator.get_basic_type("char", 8, dc.DW_ATE_signed_char), 8
        return generator.create_pointer_type(char_type)
    elif ctype == ctypes.c_void_p:
        return generator.create_pointer_type(None), 64
    else:
        return generator.get_uint64_type(), 64
