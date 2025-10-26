import ast

import llvmlite.ir as ir

from pythonbpf.debuginfo import DebugInfoGenerator
from pythonbpf.expr import VmlinuxHandlerRegistry


def generate_function_debug_info(
    func_node: ast.FunctionDef, module: ir.Module, func: ir.Function
):
    generator = DebugInfoGenerator(module)
    leading_argument = func_node.args.args[0]
    leading_argument_name = leading_argument.arg
    # TODO: add ctypes handling as well here
    print(leading_argument.arg, leading_argument.annotation.id)
    context_debug_info = VmlinuxHandlerRegistry.get_struct_debug_info(
        name=leading_argument.annotation.id
    )
    print(context_debug_info)
    pass
