from .helper_registry import HelperHandlerRegistry

from .bpf_helper_handler import (
    handle_helper_call,
    emit_probe_read_kernel_str_call,
    emit_probe_read_kernel_call,
)
from .helpers import (
    ktime,
    pid,
    deref,
    comm,
    probe_read_str,
    random,
    probe_read,
    smp_processor_id,
    uid,
    skb_store_bytes,
    get_current_cgroup_id,
    get_stack,
    XDP_DROP,
    XDP_PASS,
)


# Register the helper handler with expr module
def _register_helper_handler():
    """Register helper call handler with the expression evaluator"""
    from pythonbpf.expr.expr_pass import CallHandlerRegistry

    def helper_call_handler(call, compilation_context, builder, func, local_sym_tab):
        """Check if call is a helper and handle it"""
        import ast

        # Check for direct helper calls (e.g., ktime(), print())
        if isinstance(call.func, ast.Name):
            if HelperHandlerRegistry.has_handler(call.func.id):
                return handle_helper_call(
                    call,
                    compilation_context,
                    builder,
                    func,
                    local_sym_tab,
                )

        # Check for method calls (e.g., map.lookup())
        elif isinstance(call.func, ast.Attribute):
            method_name = call.func.attr
            map_sym_tab = compilation_context.map_sym_tab

            # Handle: my_map.lookup(key)
            if isinstance(call.func.value, ast.Name):
                obj_name = call.func.value.id
                if map_sym_tab and obj_name in map_sym_tab:
                    if HelperHandlerRegistry.has_handler(method_name):
                        return handle_helper_call(
                            call,
                            compilation_context,
                            builder,
                            func,
                            local_sym_tab,
                        )

        return None

    CallHandlerRegistry.set_handler(helper_call_handler)


# Register on module import
_register_helper_handler()

__all__ = [
    "HelperHandlerRegistry",
    "handle_helper_call",
    "emit_probe_read_kernel_str_call",
    "emit_probe_read_kernel_call",
    "get_current_cgroup_id",
    "ktime",
    "pid",
    "deref",
    "comm",
    "probe_read_str",
    "random",
    "probe_read",
    "smp_processor_id",
    "uid",
    "skb_store_bytes",
    "get_stack",
    "XDP_DROP",
    "XDP_PASS",
]
