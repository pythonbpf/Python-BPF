import ast

import llvmlite.ir as ir
import logging
from pythonbpf.debuginfo import DebugInfoGenerator
from pythonbpf.expr import VmlinuxHandlerRegistry
import ctypes

logger = logging.getLogger(__name__)


def generate_function_debug_info(
    func_node: ast.FunctionDef, module: ir.Module, func: ir.Function
):
    generator = DebugInfoGenerator(module)
    leading_argument = func_node.args.args[0]
    leading_argument_name = leading_argument.arg
    annotation = leading_argument.annotation
    if func_node.returns is None:
        # TODO: should check if this logic is consistent with function return type handling elsewhere
        return_type = ctypes.c_int64()
    elif hasattr(func_node.returns, "id"):
        return_type = func_node.returns.id
        if return_type == "c_int32":
            return_type = generator.get_int32_type()
        elif return_type == "c_int64":
            return_type = generator.get_int64_type()
        elif return_type == "c_uint32":
            return_type = generator.get_uint32_type()
        elif return_type == "c_uint64":
            return_type = generator.get_uint64_type()
        else:
            logger.warning(
                "Return type should be int32, int64, uint32 or uint64 only. Falling back to int64"
            )
            return_type = generator.get_int64_type()
    else:
        return_type = ctypes.c_int64()
    # context processing
    if annotation is None:
        logger.warning("Type of context of function not found.")
        return
    if hasattr(annotation, "id"):
        ctype_name = annotation.id
        if ctype_name == "c_void_p":
            return
        elif ctype_name.startswith("ctypes"):
            raise SyntaxError(
                "The first argument should always be a pointer to a struct or a void pointer"
            )
        context_debug_info = VmlinuxHandlerRegistry.get_struct_debug_info(annotation.id)
        pointer_to_context_debug_info = generator.create_pointer_type(
            context_debug_info, 64
        )
        subroutine_type = generator.create_subroutine_type(
            return_type, pointer_to_context_debug_info
        )
        context_local_variable = generator.create_local_variable_debug_info(
            leading_argument_name, 1, pointer_to_context_debug_info
        )
        retained_nodes = [context_local_variable]
        subprogram_debug_info = generator.create_subprogram(
            func_node.name, subroutine_type, retained_nodes
        )
        generator.add_scope_to_local_variable(
            context_local_variable, subprogram_debug_info
        )
        func.set_metadata("dbg", subprogram_debug_info)

    else:
        logger.error(f"Invalid annotation type for argument '{leading_argument_name}'")
