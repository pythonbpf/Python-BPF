from pythonbpf.debuginfo import DebugInfoGenerator
from .map_types import BPFMapType


def create_map_debug_info(module, map_global, map_name, map_params):
    """Generate debug info metadata for BPF maps HASH and PERF_EVENT_ARRAY"""
    generator = DebugInfoGenerator(module)

    uint_type = generator.get_uint32_type()
    ulong_type = generator.get_uint64_type()
    array_type = generator.create_array_type(
        uint_type, map_params.get("type", BPFMapType.UNSPEC).value
    )
    type_ptr = generator.create_pointer_type(array_type, 64)
    key_ptr = generator.create_pointer_type(
        array_type if "key_size" in map_params else ulong_type, 64
    )
    value_ptr = generator.create_pointer_type(
        array_type if "value_size" in map_params else ulong_type, 64
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


def create_ringbuf_debug_info(module, map_global, map_name, map_params):
    """Generate debug information metadata for BPF RINGBUF map"""
    generator = DebugInfoGenerator(module)

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
