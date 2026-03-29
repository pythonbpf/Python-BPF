import logging
from llvmlite import ir
from pythonbpf.debuginfo import DebugInfoGenerator
from .map_types import BPFMapType

logger: logging.Logger = logging.getLogger(__name__)


def create_map_debug_info(compilation_context, map_global, map_name, map_params):
    """Generate debug info metadata for BPF maps HASH and PERF_EVENT_ARRAY"""
    generator = DebugInfoGenerator(compilation_context.module)
    structs_sym_tab = compilation_context.structs_sym_tab
    logger.info(f"Creating debug info for map {map_name} with params {map_params}")
    uint_type = generator.get_uint32_type()
    array_type = generator.create_array_type(
        uint_type, map_params.get("type", BPFMapType.UNSPEC).value
    )
    type_ptr = generator.create_pointer_type(array_type, 64)
    key_ptr = generator.create_pointer_type(
        array_type
        if "key_size" in map_params
        else _get_key_val_dbg_type(map_params.get("key"), generator, structs_sym_tab),
        64,
    )
    value_ptr = generator.create_pointer_type(
        array_type
        if "value_size" in map_params
        else _get_key_val_dbg_type(map_params.get("value"), generator, structs_sym_tab),
        64,
    )

    elements_arr = []

    # Create struct members
    # scope field does not appear for some reason
    cnt = 0
    for elem in map_params:
        if elem == "max_entries":
            continue
        if elem == "type":
            ptr = type_ptr
        elif "key" in elem:
            ptr = key_ptr
        else:
            ptr = value_ptr
        # TODO: the best way to do this is not 64, but get the size each time. this will not work for structs.
        member = generator.create_struct_member(elem, ptr, cnt * 64)
        elements_arr.append(member)
        cnt += 1

    if "max_entries" in map_params:
        max_entries_array = generator.create_array_type(
            uint_type, map_params["max_entries"]
        )
        max_entries_ptr = generator.create_pointer_type(max_entries_array, 64)
        max_entries_member = generator.create_struct_member(
            "max_entries", max_entries_ptr, cnt * 64
        )
        elements_arr.append(max_entries_member)

    # Create the struct type
    struct_type = generator.create_struct_type(
        elements_arr, 64 * len(elements_arr), is_distinct=True
    )

    # Create global variable debug info
    global_var = generator.create_global_var_debug_info(
        map_name, struct_type, is_local=False
    )

    # Attach debug info to the global variable
    map_global.set_metadata("dbg", global_var)

    return global_var


# TODO: This should not be exposed outside of the module.
# Ideally we should expose a single create_map_debug_info function that handles all map types.
# We can probably use a registry pattern to register different map types and their debug info generators.
# map_params["type"] will be used to determine which generator to use.
def create_ringbuf_debug_info(compilation_context, map_global, map_name, map_params):
    """Generate debug information metadata for BPF RINGBUF map"""
    generator = DebugInfoGenerator(compilation_context.module)

    int_type = generator.get_int32_type()

    type_array = generator.create_array_type(
        int_type, map_params.get("type", BPFMapType.RINGBUF).value
    )
    type_ptr = generator.create_pointer_type(type_array, 64)
    type_member = generator.create_struct_member("type", type_ptr, 0)

    max_entries_array = generator.create_array_type(int_type, map_params["max_entries"])
    max_entries_ptr = generator.create_pointer_type(max_entries_array, 64)
    max_entries_member = generator.create_struct_member(
        "max_entries", max_entries_ptr, 64
    )

    elements_arr = [type_member, max_entries_member]

    struct_type = generator.create_struct_type(elements_arr, 128, is_distinct=True)

    global_var = generator.create_global_var_debug_info(
        map_name, struct_type, is_local=False
    )
    map_global.set_metadata("dbg", global_var)
    return global_var


def _get_key_val_dbg_type(name, generator, structs_sym_tab):
    """Get the debug type for key/value based on type object"""

    if not name:
        logger.warn("No name provided for key/value type, defaulting to uint64")
        return generator.get_uint64_type()

    type_obj = structs_sym_tab.get(name)
    if type_obj:
        logger.info(f"Found struct named {name}, generating debug type")
        return _get_struct_debug_type(type_obj, generator, structs_sym_tab)

    # Fallback to basic types
    logger.info(f"No struct named {name}, falling back to basic type")

    # NOTE: Only handling int and long for now
    if name in ["c_int32", "c_uint32"]:
        return generator.get_uint32_type()

    # Default fallback for now
    return generator.get_uint64_type()


def _get_struct_debug_type(struct_obj, generator, structs_sym_tab):
    """Recursively create debug type for struct"""
    elements_arr = []
    for fld in struct_obj.fields.keys():
        fld_type = struct_obj.field_type(fld)
        if isinstance(fld_type, ir.IntType):
            if fld_type.width == 32:
                fld_dbg_type = generator.get_uint32_type()
            else:
                # NOTE: Assuming 64-bit for all other int types
                fld_dbg_type = generator.get_uint64_type()
        elif isinstance(fld_type, ir.ArrayType):
            # NOTE: Array types have u8 elements only for now
            # Debug info generation should fail for other types
            elem_type = fld_type.element
            if isinstance(elem_type, ir.IntType) and elem_type.width == 8:
                char_type = generator.get_uint8_type()
                fld_dbg_type = generator.create_array_type(char_type, fld_type.count)
            else:
                logger.warning(
                    f"Array element type {str(elem_type)} not supported for debug info, skipping"
                )
                continue
        else:
            # NOTE: Only handling int and char arrays for now
            logger.warning(
                f"Field type {str(fld_type)} not supported for debug info, skipping"
            )
            continue

        member = generator.create_struct_member(
            fld, fld_dbg_type, struct_obj.field_size(fld)
        )
        elements_arr.append(member)
    struct_type = generator.create_struct_type(
        elements_arr, struct_obj.size * 8, is_distinct=True
    )
    return struct_type
