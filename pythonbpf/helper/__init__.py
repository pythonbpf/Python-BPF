from .helper_registry import HelperHandlerRegistry
from .helper_utils import reset_scratch_pool
from .bpf_helper_handler import handle_helper_call, emit_probe_read_kernel_str_call
from .helpers import ktime, pid, deref, comm, probe_read_str, XDP_DROP, XDP_PASS


# Register the helper handler with expr module
def _register_helper_handler():
    """Register helper call handler with the expression evaluator"""
    from pythonbpf.expr.expr_pass import CallHandlerRegistry

    def helper_call_handler(
        call, module, builder, func, local_sym_tab, map_sym_tab, structs_sym_tab
    ):
        """Check if call is a helper and handle it"""
        import ast

        # Check for direct helper calls (e.g., ktime(), print())
        if isinstance(call.func, ast.Name):
            if HelperHandlerRegistry.has_handler(call.func.id):
                return handle_helper_call(
                    call,
                    module,
                    builder,
                    func,
                    local_sym_tab,
                    map_sym_tab,
                    structs_sym_tab,
                )

        # Check for method calls (e.g., map.lookup())
        elif isinstance(call.func, ast.Attribute):
            method_name = call.func.attr

            # Handle: my_map.lookup(key)
            if isinstance(call.func.value, ast.Name):
                obj_name = call.func.value.id
                if map_sym_tab and obj_name in map_sym_tab:
                    if HelperHandlerRegistry.has_handler(method_name):
                        return handle_helper_call(
                            call,
                            module,
                            builder,
                            func,
                            local_sym_tab,
                            map_sym_tab,
                            structs_sym_tab,
                        )

        return None

    CallHandlerRegistry.set_handler(helper_call_handler)


# Register on module import
_register_helper_handler()

__all__ = [
    "HelperHandlerRegistry",
    "reset_scratch_pool",
    "handle_helper_call",
    "emit_probe_read_kernel_str_call",
    "ktime",
    "pid",
    "deref",
    "comm",
    "probe_read_str",
    "XDP_DROP",
    "XDP_PASS",
]
