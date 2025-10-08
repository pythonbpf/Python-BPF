from llvmlite import ir
import ast

from logging import Logger
import logging
from .type_deducer import ctypes_to_ir

logger: Logger = logging.getLogger(__name__)

# TODO: this is going to be a huge fuck of a headache in the future.
global_sym_tab = []


def populate_global_symbol_table(tree, module: ir.Module):
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
                    global_sym_tab.append(node)
                elif isinstance(dec, ast.Name) and dec.id == "bpfglobal":
                    global_sym_tab.append(node)

                elif isinstance(dec, ast.Name) and dec.id == "map":
                    global_sym_tab.append(node)
    return False


def emit_global(module: ir.Module, node, name):
    logger.info(f"global identifier {name} processing")
    # deduce LLVM type from the annotated return
    if not isinstance(node.returns, ast.Name):
        raise ValueError(f"Unsupported return annotation {ast.dump(node.returns)}")
    ty = ctypes_to_ir(node.returns.id)

    # extract the return expression
    # TODO: turn this return extractor into a generic function I can use everywhere.
    ret_stmt = node.body[0]
    if not isinstance(ret_stmt, ast.Return) or ret_stmt.value is None:
        raise ValueError(f"Global '{name}' has no valid return")

    init_val = ret_stmt.value

    # simple constant like "return 0"
    if isinstance(init_val, ast.Constant):
        llvm_init = ir.Constant(ty, init_val.value)

    # variable reference like "return SOME_CONST"
    elif isinstance(init_val, ast.Name):
        # need symbol resolution here, stub as 0 for now
        raise ValueError(f"Name reference {init_val.id} not yet supported")

    # constructor call like "return c_int64(0)" or dataclass(...)
    elif isinstance(init_val, ast.Call):
        if len(init_val.args) >= 1 and isinstance(init_val.args[0], ast.Constant):
            llvm_init = ir.Constant(ty, init_val.args[0].value)
        else:
            logger.info("Defaulting to zero as no constant argument found")
            llvm_init = ir.Constant(ty, 0)
    else:
        raise ValueError(f"Unsupported return expr {ast.dump(init_val)}")

    gvar = ir.GlobalVariable(module, ty, name=name)
    gvar.initializer = llvm_init
    gvar.align = 8
    gvar.linkage = "dso_local"
    gvar.global_constant = False
    return gvar


def globals_processing(tree, module):
    """Process stuff decorated with @bpf and @bpfglobal except license and return the section name"""
    globals_sym_tab = []

    for node in tree.body:
        # Skip non-assignment and non-function nodes
        if not (isinstance(node, ast.FunctionDef)):
            continue

        # Get the name based on node type
        if isinstance(node, ast.FunctionDef):
            name = node.name
        else:
            continue

        # Check for duplicate names
        if name in globals_sym_tab:
            raise SyntaxError(f"ERROR: Global name '{name}' previously defined")
        else:
            globals_sym_tab.append(name)

        if isinstance(node, ast.FunctionDef) and node.name != "LICENSE":
            decorators = [
                dec.id for dec in node.decorator_list if isinstance(dec, ast.Name)
            ]
            if "bpf" in decorators and "bpfglobal" in decorators:
                if (
                    len(node.body) == 1
                    and isinstance(node.body[0], ast.Return)
                    and node.body[0].value is not None
                    and isinstance(
                        node.body[0].value, (ast.Constant, ast.Name, ast.Call)
                    )
                ):
                    emit_global(module, node, name)
                else:
                    raise SyntaxError(f"ERROR: Invalid syntax for {name} global")

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
