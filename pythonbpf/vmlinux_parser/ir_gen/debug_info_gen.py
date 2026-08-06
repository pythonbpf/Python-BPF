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
        The generated global variable debug info, or None for unsupported types
    """
    # Set up debug info generator
    generator = DebugInfoGenerator(llvm_module)

    # Check if debug info for this struct has already been generated
    for existing_struct, debug_info in generated_debug_info:
        if existing_struct.name == struct.name:
            return debug_info

    # Check if this is a union (not supported yet)
    if not struct.name.startswith("struct_"):
        logger.warning(f"Skipping debug info generation for union: {struct.name}")
        # Create a minimal forward declaration for unions
        union_type = generator.create_struct_type(
            [], struct.__sizeof__() * 8, is_distinct=True
        )
        return union_type

    # Process all fields and create members for the struct
    members = []

    # Members lifted out of an anonymous member are not members of this struct in
    # DWARF terms; they belong to the anonymous member's own type. Emitting them
    # here would both duplicate offsets and shift every later member's index.
    sorted_fields = sorted(
        (item for item in struct.fields.items() if item[1].access_path is None),
        key=lambda item: item[1].offset,
    )

    anonymous_names = set(getattr(struct.ctype_struct, "_anonymous_", None) or ())

    for field_name, field in sorted_fields:
        try:
            if field_name in anonymous_names:
                # An anonymous member has to reach BTF unnamed and with its own
                # members, or a `$...:<n>:<m>` access string cannot be resolved
                # against it at load time.
                anonymous_member = _anonymous_member_debug_info(
                    field, generator, generated_debug_info
                )
                if anonymous_member is not None:
                    members.append(anonymous_member)
                    continue
                logger.warning(
                    f"Could not describe anonymous member {struct.name}.{field_name}, "
                    "falling back to an opaque member"
                )

            # Get appropriate debug type for this field
            field_type = _get_field_debug_type(
                field_name, field, generator, struct, generated_debug_info
            )

            # Ensure field_type is a tuple
            if not isinstance(field_type, tuple) or len(field_type) != 2:
                logger.error(f"Invalid field_type for {field_name}: {field_type}")
                continue

            # Create struct member with proper offset
            member = generator.create_struct_member_vmlinux(
                field_name, field_type, field.offset * 8
            )
            members.append(member)
        except Exception as e:
            logger.error(f"Failed to process field {field_name} in {struct.name}: {e}")
            continue

    struct_name = struct.name.removeprefix("struct_")
    # Create struct type with all members
    struct_type = generator.create_struct_type_with_name(
        struct_name, members, struct.__sizeof__() * 8, is_distinct=True
    )

    return struct_type


def _lookup_generated_debug_info(
    type_name: str, generated_debug_info: List[Tuple[DependencyNode, Any]]
):
    """Find already generated debug info for a vmlinux type by name."""
    for existing_struct, debug_info in generated_debug_info:
        if existing_struct.name == type_name:
            return debug_info, existing_struct.__sizeof__() * 8
    return None


def _anonymous_member_debug_info(
    field,
    generator: DebugInfoGenerator,
    generated_debug_info: List[Tuple[DependencyNode, Any]],
):
    """
    Describe an anonymous struct/union member the way a C compiler would.

    The member itself is emitted WITHOUT a name, so it lands in BTF as `(anon)`,
    and its type is a real composite carrying its own members in declaration
    order. Both matter: libbpf walks a CO-RE access string by member index into
    the local type and then matches by name in the target type, so an opaque or
    named stand-in makes any access through the anonymous member unresolvable.

    Returns None if the member cannot be described faithfully, in which case the
    caller keeps the previous behaviour.
    """
    anonymous_type = field.type
    declared = getattr(anonymous_type, "_fields_", None)
    if not declared or not isinstance(anonymous_type, type):
        return None

    inner_members = []
    for declared_member in declared:
        if len(declared_member) != 2:
            # Bitfield members need BTF bitfield encoding we do not emit yet.
            return None
        member_name, member_type = declared_member
        try:
            member_offset_bits = getattr(anonymous_type, member_name).offset * 8
        except AttributeError:
            return None

        if getattr(member_type, "__module__", None) == "vmlinux":
            member_type_name = getattr(member_type, "__name__", None)
            member_debug_type = (
                _lookup_generated_debug_info(member_type_name, generated_debug_info)
                if member_type_name
                else None
            )
            if member_debug_type is None:
                # Keep the member so the indices stay right, but leave its type
                # opaque, exactly as nested structs are handled elsewhere.
                member_debug_type = (
                    generator.create_struct_type([], 0, is_distinct=True),
                    0,
                )
        else:
            member_debug_type = _get_basic_debug_type(member_type, generator)
        if not isinstance(member_debug_type, tuple) or len(member_debug_type) != 2:
            return None

        inner_members.append(
            generator.create_struct_member_vmlinux(
                member_name, member_debug_type, member_offset_bits
            )
        )

    size_bits = ctypes.sizeof(anonymous_type) * 8
    if issubclass(anonymous_type, ctypes.Union):
        composite = generator.create_union_type(
            inner_members, size_bits, is_distinct=True
        )
    else:
        composite = generator.create_struct_type(
            inner_members, size_bits, is_distinct=True
        )

    return generator.create_struct_member_vmlinux(
        "", (composite, size_bits), field.offset * 8
    )


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
        A tuple of (debug_type, size_in_bits)
    """
    # Handle complex types (arrays, pointers, function pointers)
    if field.ctype_complex_type is not None:
        # Handle function pointer types (CFUNCTYPE)
        if callable(field.ctype_complex_type):
            # Function pointers are represented as void pointers
            logger.warning(
                f"Field {field_name} is a function pointer, using void pointer"
            )
            void_ptr = generator.create_pointer_type(None, 64)
            return void_ptr, 64
        elif issubclass(field.ctype_complex_type, ctypes.Array):
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
                return debug_info, existing_struct.__sizeof__() * 8

        # If not found, create a forward declaration
        # This will be completed when the actual struct is processed
        logger.info(
            f"Forward declaration created for {struct_name} in {parent_struct.name}"
        )
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
