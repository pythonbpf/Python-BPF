import ast

import llvmlite.ir as ir


def generate_function_debug_info(
    func_node: ast.FunctionDef, module: ir.Module, func: ir.Function
):
    pass
