import ast
from llvmlite import ir
from enum import Enum

from .helper_registry import HelperHandlerRegistry
from .helper_utils import (
    get_or_create_ptr_from_arg,
    get_flags_val,
    get_data_ptr_and_size,
    get_buffer_ptr_and_size,
    get_char_array_ptr_and_size,
    get_ptr_from_arg,
)
from .printk_formatter import simple_string_print, handle_fstring_print

from logging import Logger
import logging

logger: Logger = logging.getLogger(__name__)


class BPFHelperID(Enum):
    BPF_MAP_LOOKUP_ELEM = 1
    BPF_MAP_UPDATE_ELEM = 2
    BPF_MAP_DELETE_ELEM = 3
    BPF_KTIME_GET_NS = 5
    BPF_PRINTK = 6
    BPF_GET_CURRENT_PID_TGID = 14
    BPF_GET_CURRENT_COMM = 16
    BPF_PERF_EVENT_OUTPUT = 25
    BPF_PROBE_READ_KERNEL_STR = 115


@HelperHandlerRegistry.register("ktime")
def bpf_ktime_get_ns_emitter(
    call,
    map_ptr,
    module,
    builder,
    func,
    local_sym_tab=None,
    struct_sym_tab=None,
    map_sym_tab=None,
):
    """
    Emit LLVM IR for bpf_ktime_get_ns helper function call.
    """
    # func is an arg to just have a uniform signature with other emitters
    helper_id = ir.Constant(ir.IntType(64), BPFHelperID.BPF_KTIME_GET_NS.value)
    fn_type = ir.FunctionType(ir.IntType(64), [], var_arg=False)
    fn_ptr_type = ir.PointerType(fn_type)
    fn_ptr = builder.inttoptr(helper_id, fn_ptr_type)
    result = builder.call(fn_ptr, [], tail=False)
    return result, ir.IntType(64)


@HelperHandlerRegistry.register("lookup")
def bpf_map_lookup_elem_emitter(
    call,
    map_ptr,
    module,
    builder,
    func,
    local_sym_tab=None,
    struct_sym_tab=None,
    map_sym_tab=None,
):
    """
    Emit LLVM IR for bpf_map_lookup_elem helper function call.
    """
    if not call.args or len(call.args) != 1:
        raise ValueError(
            f"Map lookup expects exactly one argument (key), got {len(call.args)}"
        )
    key_ptr = get_or_create_ptr_from_arg(
        func, module, call.args[0], builder, local_sym_tab, map_sym_tab, struct_sym_tab
    )
    map_void_ptr = builder.bitcast(map_ptr, ir.PointerType())

    # TODO: I have changed the return type to i64*, as we are
    # allocating space for that type in allocate_mem. This is
    # temporary, and we will honour other widths later. But this
    # allows us to have cool binary ops on the returned value.
    fn_type = ir.FunctionType(
        ir.PointerType(ir.IntType(64)),  # Return type: void*
        [ir.PointerType(), ir.PointerType()],  # Args: (void*, void*)
        var_arg=False,
    )
    fn_ptr_type = ir.PointerType(fn_type)

    fn_addr = ir.Constant(ir.IntType(64), BPFHelperID.BPF_MAP_LOOKUP_ELEM.value)
    fn_ptr = builder.inttoptr(fn_addr, fn_ptr_type)

    result = builder.call(fn_ptr, [map_void_ptr, key_ptr], tail=False)

    return result, ir.PointerType()


@HelperHandlerRegistry.register("print")
def bpf_printk_emitter(
    call,
    map_ptr,
    module,
    builder,
    func,
    local_sym_tab=None,
    struct_sym_tab=None,
    map_sym_tab=None,
):
    """Emit LLVM IR for bpf_printk helper function call."""
    if not hasattr(func, "_fmt_counter"):
        func._fmt_counter = 0

    if not call.args:
        raise ValueError("bpf_printk expects at least one argument (format string)")

    args = []
    if isinstance(call.args[0], ast.JoinedStr):
        args = handle_fstring_print(
            call.args[0],
            module,
            builder,
            func,
            local_sym_tab,
            struct_sym_tab,
        )
    elif isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str):
        # TODO: We are only supporting single arguments for now.
        # In case of multiple args, the first one will be taken.
        args = simple_string_print(call.args[0].value, module, builder, func)
    else:
        raise NotImplementedError(
            "Only simple strings or f-strings are supported in bpf_printk."
        )

    fn_type = ir.FunctionType(
        ir.IntType(64), [ir.PointerType(), ir.IntType(32)], var_arg=True
    )
    fn_ptr_type = ir.PointerType(fn_type)
    fn_addr = ir.Constant(ir.IntType(64), BPFHelperID.BPF_PRINTK.value)
    fn_ptr = builder.inttoptr(fn_addr, fn_ptr_type)

    builder.call(fn_ptr, args, tail=True)
    return True


@HelperHandlerRegistry.register("update")
def bpf_map_update_elem_emitter(
    call,
    map_ptr,
    module,
    builder,
    func,
    local_sym_tab=None,
    struct_sym_tab=None,
    map_sym_tab=None,
):
    """
    Emit LLVM IR for bpf_map_update_elem helper function call.
    Expected call signature: map.update(key, value, flags=0)
    """
    if not call.args or len(call.args) < 2 or len(call.args) > 3:
        raise ValueError(
            f"Map update expects 2 or 3 args (key, value, flags), got {len(call.args)}"
        )

    key_arg = call.args[0]
    value_arg = call.args[1]
    flags_arg = call.args[2] if len(call.args) > 2 else None

    key_ptr = get_or_create_ptr_from_arg(
        func, module, key_arg, builder, local_sym_tab, map_sym_tab, struct_sym_tab
    )
    value_ptr = get_or_create_ptr_from_arg(
        func, module, value_arg, builder, local_sym_tab, map_sym_tab, struct_sym_tab
    )
    flags_val = get_flags_val(flags_arg, builder, local_sym_tab)

    map_void_ptr = builder.bitcast(map_ptr, ir.PointerType())
    fn_type = ir.FunctionType(
        ir.IntType(64),
        [ir.PointerType(), ir.PointerType(), ir.PointerType(), ir.IntType(64)],
        var_arg=False,
    )
    fn_ptr_type = ir.PointerType(fn_type)

    fn_addr = ir.Constant(ir.IntType(64), BPFHelperID.BPF_MAP_UPDATE_ELEM.value)
    fn_ptr = builder.inttoptr(fn_addr, fn_ptr_type)

    if isinstance(flags_val, int):
        flags_const = ir.Constant(ir.IntType(64), flags_val)
    else:
        flags_const = flags_val

    result = builder.call(
        fn_ptr, [map_void_ptr, key_ptr, value_ptr, flags_const], tail=False
    )

    return result, None


@HelperHandlerRegistry.register("delete")
def bpf_map_delete_elem_emitter(
    call,
    map_ptr,
    module,
    builder,
    func,
    local_sym_tab=None,
    struct_sym_tab=None,
    map_sym_tab=None,
):
    """
    Emit LLVM IR for bpf_map_delete_elem helper function call.
    Expected call signature: map.delete(key)
    """
    if not call.args or len(call.args) != 1:
        raise ValueError(
            f"Map delete expects exactly one argument (key), got {len(call.args)}"
        )
    key_ptr = get_or_create_ptr_from_arg(
        func, module, call.args[0], builder, local_sym_tab, map_sym_tab, struct_sym_tab
    )
    map_void_ptr = builder.bitcast(map_ptr, ir.PointerType())

    # Define function type for bpf_map_delete_elem
    fn_type = ir.FunctionType(
        ir.IntType(64),  # Return type: int64 (status code)
        [ir.PointerType(), ir.PointerType()],  # Args: (void*, void*)
        var_arg=False,
    )
    fn_ptr_type = ir.PointerType(fn_type)

    fn_addr = ir.Constant(ir.IntType(64), BPFHelperID.BPF_MAP_DELETE_ELEM.value)
    fn_ptr = builder.inttoptr(fn_addr, fn_ptr_type)

    result = builder.call(fn_ptr, [map_void_ptr, key_ptr], tail=False)

    return result, None


@HelperHandlerRegistry.register("comm")
def bpf_get_current_comm_emitter(
    call,
    map_ptr,
    module,
    builder,
    func,
    local_sym_tab=None,
    struct_sym_tab=None,
    map_sym_tab=None,
):
    """
    Emit LLVM IR for bpf_get_current_comm helper function call.

    Accepts: comm(dataobj.field) or comm(my_buffer)
    """
    if not call.args or len(call.args) != 1:
        raise ValueError(
            f"comm expects exactly one argument (buffer), got {len(call.args)}"
        )

    buf_arg = call.args[0]

    # Extract buffer pointer and size
    buf_ptr, buf_size = get_buffer_ptr_and_size(
        buf_arg, builder, local_sym_tab, struct_sym_tab
    )

    # Validate it's a char array
    if not isinstance(
        buf_ptr.type.pointee, ir.ArrayType
    ) or buf_ptr.type.pointee.element != ir.IntType(8):
        raise ValueError(
            f"comm expects a char array buffer, got {buf_ptr.type.pointee}"
        )

    # Cast to void* and call helper
    buf_void_ptr = builder.bitcast(buf_ptr, ir.PointerType())

    fn_type = ir.FunctionType(
        ir.IntType(64),
        [ir.PointerType(), ir.IntType(32)],
        var_arg=False,
    )
    fn_ptr = builder.inttoptr(
        ir.Constant(ir.IntType(64), BPFHelperID.BPF_GET_CURRENT_COMM.value),
        ir.PointerType(fn_type),
    )

    result = builder.call(
        fn_ptr, [buf_void_ptr, ir.Constant(ir.IntType(32), buf_size)], tail=False
    )

    logger.info(f"Emitted bpf_get_current_comm with {buf_size} byte buffer")
    return result, None


@HelperHandlerRegistry.register("pid")
def bpf_get_current_pid_tgid_emitter(
    call,
    map_ptr,
    module,
    builder,
    func,
    local_sym_tab=None,
    struct_sym_tab=None,
    map_sym_tab=None,
):
    """
    Emit LLVM IR for bpf_get_current_pid_tgid helper function call.
    """
    # func is an arg to just have a uniform signature with other emitters
    helper_id = ir.Constant(ir.IntType(64), BPFHelperID.BPF_GET_CURRENT_PID_TGID.value)
    fn_type = ir.FunctionType(ir.IntType(64), [], var_arg=False)
    fn_ptr_type = ir.PointerType(fn_type)
    fn_ptr = builder.inttoptr(helper_id, fn_ptr_type)
    result = builder.call(fn_ptr, [], tail=False)

    # Extract the lower 32 bits (PID) using bitwise AND with 0xFFFFFFFF
    mask = ir.Constant(ir.IntType(64), 0xFFFFFFFF)
    pid = builder.and_(result, mask)
    return pid, ir.IntType(64)


@HelperHandlerRegistry.register("output")
def bpf_perf_event_output_handler(
    call,
    map_ptr,
    module,
    builder,
    func,
    local_sym_tab=None,
    struct_sym_tab=None,
    map_sym_tab=None,
):
    if len(call.args) != 1:
        raise ValueError(
            f"Perf event output expects exactly one argument, got {len(call.args)}"
        )
    data_arg = call.args[0]
    ctx_ptr = func.args[0]  # First argument to the function is ctx

    data_ptr, size_val = get_data_ptr_and_size(data_arg, local_sym_tab, struct_sym_tab)

    # BPF_F_CURRENT_CPU is -1 in 32 bit
    flags_val = ir.Constant(ir.IntType(64), 0xFFFFFFFF)

    map_void_ptr = builder.bitcast(map_ptr, ir.PointerType())
    data_void_ptr = builder.bitcast(data_ptr, ir.PointerType())
    fn_type = ir.FunctionType(
        ir.IntType(64),
        [
            ir.PointerType(ir.IntType(8)),
            ir.PointerType(),
            ir.IntType(64),
            ir.PointerType(),
            ir.IntType(64),
        ],
        var_arg=False,
    )
    fn_ptr_type = ir.PointerType(fn_type)

    # helper id
    fn_addr = ir.Constant(ir.IntType(64), BPFHelperID.BPF_PERF_EVENT_OUTPUT.value)
    fn_ptr = builder.inttoptr(fn_addr, fn_ptr_type)

    result = builder.call(
        fn_ptr, [ctx_ptr, map_void_ptr, flags_val, data_void_ptr, size_val], tail=False
    )
    return result, None


def emit_probe_read_kernel_str_call(builder, dst_ptr, dst_size, src_ptr):
    """Emit LLVM IR call to bpf_probe_read_kernel_str"""

    fn_type = ir.FunctionType(
        ir.IntType(64),
        [ir.PointerType(), ir.IntType(32), ir.PointerType()],
        var_arg=False,
    )
    fn_ptr = builder.inttoptr(
        ir.Constant(ir.IntType(64), BPFHelperID.BPF_PROBE_READ_KERNEL_STR.value),
        ir.PointerType(fn_type),
    )

    result = builder.call(
        fn_ptr,
        [
            builder.bitcast(dst_ptr, ir.PointerType()),
            ir.Constant(ir.IntType(32), dst_size),
            builder.bitcast(src_ptr, ir.PointerType()),
        ],
        tail=False,
    )

    logger.info(f"Emitted bpf_probe_read_kernel_str (size={dst_size})")
    return result


@HelperHandlerRegistry.register("probe_read_str")
def bpf_probe_read_kernel_str_emitter(
    call,
    map_ptr,
    module,
    builder,
    func,
    local_sym_tab=None,
    struct_sym_tab=None,
    map_sym_tab=None,
):
    """Emit LLVM IR for bpf_probe_read_kernel_str helper."""

    if len(call.args) != 2:
        raise ValueError(
            f"probe_read_str expects 2 args (dst, src), got {len(call.args)}"
        )

    # Get destination buffer (char array -> i8*)
    dst_ptr, dst_size = get_char_array_ptr_and_size(
        call.args[0], builder, local_sym_tab, struct_sym_tab
    )

    # Get source pointer (evaluate expression)
    src_ptr, src_type = get_ptr_from_arg(
        call.args[1], func, module, builder, local_sym_tab, map_sym_tab, struct_sym_tab
    )

    # Emit the helper call
    result = emit_probe_read_kernel_str_call(builder, dst_ptr, dst_size, src_ptr)

    logger.info(f"Emitted bpf_probe_read_kernel_str (size={dst_size})")
    return result, ir.IntType(64)


def handle_helper_call(
    call,
    module,
    builder,
    func,
    local_sym_tab=None,
    map_sym_tab=None,
    struct_sym_tab=None,
):
    """Process a BPF helper function call and emit the appropriate LLVM IR."""

    # Helper function to get map pointer and invoke handler
    def invoke_helper(method_name, map_ptr=None):
        handler = HelperHandlerRegistry.get_handler(method_name)
        if not handler:
            raise NotImplementedError(
                f"Helper function '{method_name}' is not implemented."
            )
        return handler(
            call,
            map_ptr,
            module,
            builder,
            func,
            local_sym_tab,
            struct_sym_tab,
            map_sym_tab,
        )

    # Handle direct function calls (e.g., print(), ktime())
    if isinstance(call.func, ast.Name):
        return invoke_helper(call.func.id)

    # Handle method calls (e.g., map.lookup(), map.update())
    elif isinstance(call.func, ast.Attribute):
        method_name = call.func.attr
        value = call.func.value
        logger.info(f"Handling method call: {ast.dump(call.func)}")
        # Get map pointer from different styles of map access
        if isinstance(value, ast.Call) and isinstance(value.func, ast.Name):
            # Func style: my_map().lookup(key)
            map_name = value.func.id
        elif isinstance(value, ast.Name):
            # Direct style: my_map.lookup(key)
            map_name = value.id
        else:
            raise NotImplementedError(
                f"Unsupported map access pattern: {ast.dump(value)}"
            )

        # Verify map exists and get pointer
        if not map_sym_tab or map_name not in map_sym_tab:
            raise ValueError(f"Map '{map_name}' not found in symbol table")

        return invoke_helper(method_name, map_sym_tab[map_name])

    return None
