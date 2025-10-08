import ast
from logging import Logger
from llvmlite import ir
from enum import Enum
from .maps_utils import MapProcessorRegistry
from pythonbpf.debuginfo import DebugInfoGenerator
import logging

logger: Logger = logging.getLogger(__name__)


def maps_proc(tree, module, chunks):
    """Process all functions decorated with @map to find BPF maps"""
    map_sym_tab = {}
    for func_node in chunks:
        if is_map(func_node):
            logger.info(f"Found BPF map: {func_node.name}")
            map_sym_tab[func_node.name] = process_bpf_map(func_node, module)
    return map_sym_tab


def is_map(func_node):
    return any(
        isinstance(decorator, ast.Name) and decorator.id == "map"
        for decorator in func_node.decorator_list
    )


class BPFMapType(Enum):
    UNSPEC = 0
    HASH = 1
    ARRAY = 2
    PROG_ARRAY = 3
    PERF_EVENT_ARRAY = 4
    PERCPU_HASH = 5
    PERCPU_ARRAY = 6
    STACK_TRACE = 7
    CGROUP_ARRAY = 8
    LRU_HASH = 9
    LRU_PERCPU_HASH = 10
    LPM_TRIE = 11
    ARRAY_OF_MAPS = 12
    HASH_OF_MAPS = 13
    DEVMAP = 14
    SOCKMAP = 15
    CPUMAP = 16
    XSKMAP = 17
    SOCKHASH = 18
    CGROUP_STORAGE_DEPRECATED = 19
    CGROUP_STORAGE = 19
    REUSEPORT_SOCKARRAY = 20
    PERCPU_CGROUP_STORAGE_DEPRECATED = 21
    PERCPU_CGROUP_STORAGE = 21
    QUEUE = 22
    STACK = 23
    SK_STORAGE = 24
    DEVMAP_HASH = 25
    STRUCT_OPS = 26
    RINGBUF = 27
    INODE_STORAGE = 28
    TASK_STORAGE = 29
    BLOOM_FILTER = 30
    USER_RINGBUF = 31
    CGRP_STORAGE = 32


def create_bpf_map(module, map_name, map_params):
    """Create a BPF map in the module with given parameters and debug info"""

    # Create the anonymous struct type for BPF map
    map_struct_type = ir.LiteralStructType(
        [ir.PointerType() for _ in range(len(map_params))]
    )

    # Create the global variable
    map_global = ir.GlobalVariable(module, map_struct_type, name=map_name)
    map_global.linkage = "dso_local"
    map_global.global_constant = False
    map_global.initializer = ir.Constant(map_struct_type, None)
    map_global.section = ".maps"
    map_global.align = 8

    logger.info(f"Created BPF map: {map_name} with params {map_params}")
    return map_global


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


@MapProcessorRegistry.register("RingBuf")
def process_ringbuf_map(map_name, rval, module):
    """Process a BPF_RINGBUF map declaration"""
    logger.info(f"Processing Ringbuf: {map_name}")
    map_params = {"type": BPFMapType.RINGBUF}

    # Parse max_entries if present
    if len(rval.args) >= 1 and isinstance(rval.args[0], ast.Constant):
        const_val = rval.args[0].value
        if isinstance(const_val, int):
            map_params["max_entries"] = const_val

    for keyword in rval.keywords:
        if keyword.arg == "max_entries" and isinstance(keyword.value, ast.Constant):
            const_val = keyword.value.value
            if isinstance(const_val, int):
                map_params["max_entries"] = const_val

    logger.info(f"Ringbuf map parameters: {map_params}")

    map_global = create_bpf_map(module, map_name, map_params)
    create_ringbuf_debug_info(module, map_global, map_name, map_params)
    return map_global


@MapProcessorRegistry.register("HashMap")
def process_hash_map(map_name, rval, module):
    """Process a BPF_HASH map declaration"""
    logger.info(f"Processing HashMap: {map_name}")
    map_params = {"type": BPFMapType.HASH}

    # Assuming order: key_type, value_type, max_entries
    if len(rval.args) >= 1 and isinstance(rval.args[0], ast.Name):
        map_params["key"] = rval.args[0].id
    if len(rval.args) >= 2 and isinstance(rval.args[1], ast.Name):
        map_params["value"] = rval.args[1].id
    if len(rval.args) >= 3 and isinstance(rval.args[2], ast.Constant):
        const_val = rval.args[2].value
        if isinstance(const_val, (int, str)):  # safe check
            map_params["max_entries"] = const_val

    for keyword in rval.keywords:
        if keyword.arg == "key" and isinstance(keyword.value, ast.Name):
            map_params["key"] = keyword.value.id
        elif keyword.arg == "value" and isinstance(keyword.value, ast.Name):
            map_params["value"] = keyword.value.id
        elif keyword.arg == "max_entries" and isinstance(keyword.value, ast.Constant):
            const_val = keyword.value.value
            if isinstance(const_val, (int, str)):
                map_params["max_entries"] = const_val

    logger.info(f"Map parameters: {map_params}")
    map_global = create_bpf_map(module, map_name, map_params)
    # Generate debug info for BTF
    create_map_debug_info(module, map_global, map_name, map_params)
    return map_global


@MapProcessorRegistry.register("PerfEventArray")
def process_perf_event_map(map_name, rval, module):
    """Process a BPF_PERF_EVENT_ARRAY map declaration"""
    logger.info(f"Processing PerfEventArray: {map_name}")
    map_params = {"type": BPFMapType.PERF_EVENT_ARRAY}

    if len(rval.args) >= 1 and isinstance(rval.args[0], ast.Name):
        map_params["key_size"] = rval.args[0].id
    if len(rval.args) >= 2 and isinstance(rval.args[1], ast.Name):
        map_params["value_size"] = rval.args[1].id

    for keyword in rval.keywords:
        if keyword.arg == "key_size" and isinstance(keyword.value, ast.Name):
            map_params["key_size"] = keyword.value.id
        elif keyword.arg == "value_size" and isinstance(keyword.value, ast.Name):
            map_params["value_size"] = keyword.value.id

    logger.info(f"Map parameters: {map_params}")
    map_global = create_bpf_map(module, map_name, map_params)
    # Generate debug info for BTF
    create_map_debug_info(module, map_global, map_name, map_params)
    return map_global


def process_bpf_map(func_node, module):
    """Process a BPF map (a function decorated with @map)"""
    map_name = func_node.name
    logger.info(f"Processing BPF map: {map_name}")

    # For now, assume single return statement
    return_stmt = None
    for stmt in func_node.body:
        if isinstance(stmt, ast.Return):
            return_stmt = stmt
            break
    if return_stmt is None:
        raise ValueError("BPF map must have a return statement")

    rval = return_stmt.value

    if isinstance(rval, ast.Call) and isinstance(rval.func, ast.Name):
        handler = MapProcessorRegistry.get_processor(rval.func.id)
        if handler:
            return handler(map_name, rval, module)
        else:
            logger.warning(f"Unknown map type {rval.func.id}, defaulting to HashMap")
            return process_hash_map(map_name, rval, module)
    else:
        raise ValueError("Function under @map must return a map")
