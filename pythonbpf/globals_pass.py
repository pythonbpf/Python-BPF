from llvmlite import ir
import ast

from llvmlite import ir
import ast
from logging import Logger
import logging
from .type_deducer import ctypes_to_ir

logger: Logger = logging.getLogger(__name__)


def emit_global(module: ir.Module, node, name):
    print("global", node.returns.id)
    ty = ctypes_to_ir(node.returns.id)

    gvar = ir.GlobalVariable(module, ty, name=name)
    gvar.initializer = ir.Constant(ty, initial_value)
    gvar.align = 8
    gvar.linkage = "dso_local"
    gvar.global_constant = False
    return gvar


def globals_processing(tree, module):
    """Process stuff decorated with @bpf and @bpfglobal except license and return the section name"""
    global_sym_tab = []

    for node in tree.body:
        # Skip non-assignment and non-function nodes
        if not (isinstance(node, (ast.FunctionDef, ast.AnnAssign, ast.Assign))):
            continue

        # Get the name based on node type
        if isinstance(node, ast.FunctionDef):
            name = node.name
        else:
            continue

        # Check for duplicate names
        if name in global_sym_tab:
            raise SyntaxError(f"ERROR: Global name '{name}' previously defined")
        else:
            global_sym_tab.append(name)

        # Process decorated functions
        if isinstance(node, ast.FunctionDef) and node.name != "LICENSE":
            # Check decorators
            decorators = [
                dec.id for dec in node.decorator_list if isinstance(dec, ast.Name)
            ]

            if "bpf" in decorators and "bpfglobal" in decorators:
                if (
                        len(node.body) == 1
                        and isinstance(node.body[0], ast.Return)
                        and node.body[0].value is not None
                        and isinstance(node.body[0].value, (ast.Constant, ast.Name))
                ):
                    emit_global(module, node, name)
                    return node.name
                else:
                    logger.info(f"Invalid global expression for '{node.name}'")
                    return None

    return None

def emit_llvm_compiler_used(module: ir.Module, names: list[str]):
    """
    Emit the @llvm.compiler.used global given a list of function/global names.
    """
    ptr_ty = ir.PointerType()
    used_array_ty = ir.ArrayType(ptr_ty, len(names))

    elems = []
    for name in names:
        # Reuse existing globals (like LICENSE), don't redeclare
        if name in module.globals:
            g = module.get_global(name)
        else:
            g = ir.GlobalValue(module, ptr_ty, name)
        elems.append(g.bitcast(ptr_ty))

    gv = ir.GlobalVariable(module, used_array_ty, "llvm.compiler.used")
    gv.linkage = "appending"
    gv.initializer = ir.Constant(used_array_ty, elems)  # type: ignore
    gv.section = "llvm.metadata"


def globals_list_creation(tree, module: ir.Module):
    collected = ["LICENSE"]

    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            for dec in node.decorator_list:
                if (
                        isinstance(dec, ast.Call)
                        and isinstance(dec.func, ast.Name)
                        and dec.func.id == "section"
                        and len(dec.args) == 1
                        and isinstance(dec.args[0], ast.Constant)
                        and isinstance(dec.args[0].value, str)
                ):
                    collected.append(node.name)

                # NOTE: all globals other than
                # elif isinstance(dec, ast.Name) and dec.id == "bpfglobal":
                #     collected.append(node.name)

                elif isinstance(dec, ast.Name) and dec.id == "map":
                    collected.append(node.name)

    emit_llvm_compiler_used(module, collected)
