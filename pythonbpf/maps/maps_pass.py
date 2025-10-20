import ast
import logging
from logging import Logger
from llvmlite import ir

from .maps_utils import MapProcessorRegistry
from .map_types import BPFMapType
from .map_debug_info import create_map_debug_info, create_ringbuf_debug_info
from pythonbpf.expr.vmlinux_registry import VmlinuxHandlerRegistry


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


def _parse_map_params(rval, expected_args=None):
    """Parse map parameters from call arguments and keywords."""

    params = {}
    handler = VmlinuxHandlerRegistry.get_handler()
    # Parse positional arguments
    if expected_args:
        for i, arg_name in enumerate(expected_args):
            if i < len(rval.args):
                arg = rval.args[i]
                if isinstance(arg, ast.Name):
                    params[arg_name] = arg.id
                elif isinstance(arg, ast.Constant):
                    params[arg_name] = arg.value

    # Parse keyword arguments (override positional)
    for keyword in rval.keywords:
        if isinstance(keyword.value, ast.Name):
            name = keyword.value.id
            if handler and handler.is_vmlinux_enum(name):
                result = handler.get_vmlinux_enum_value(name)
                params[keyword.arg] = result if result is not None else name
            else:
                params[keyword.arg] = name
        elif isinstance(keyword.value, ast.Constant):
            params[keyword.arg] = keyword.value.value

    return params


@MapProcessorRegistry.register("RingBuf")
def process_ringbuf_map(map_name, rval, module):
    """Process a BPF_RINGBUF map declaration"""
    logger.info(f"Processing Ringbuf: {map_name}")
    map_params = _parse_map_params(rval, expected_args=["max_entries"])
    map_params["type"] = BPFMapType.RINGBUF

    logger.info(f"Ringbuf map parameters: {map_params}")

    map_global = create_bpf_map(module, map_name, map_params)
    create_ringbuf_debug_info(module, map_global, map_name, map_params)
    return map_global


@MapProcessorRegistry.register("HashMap")
def process_hash_map(map_name, rval, module):
    """Process a BPF_HASH map declaration"""
    logger.info(f"Processing HashMap: {map_name}")
    map_params = _parse_map_params(rval, expected_args=["key", "value", "max_entries"])
    map_params["type"] = BPFMapType.HASH

    logger.info(f"Map parameters: {map_params}")
    map_global = create_bpf_map(module, map_name, map_params)
    # Generate debug info for BTF
    create_map_debug_info(module, map_global, map_name, map_params)
    return map_global


@MapProcessorRegistry.register("PerfEventArray")
def process_perf_event_map(map_name, rval, module):
    """Process a BPF_PERF_EVENT_ARRAY map declaration"""
    logger.info(f"Processing PerfEventArray: {map_name}")
    map_params = _parse_map_params(rval, expected_args=["key_size", "value_size"])
    map_params["type"] = BPFMapType.PERF_EVENT_ARRAY

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
