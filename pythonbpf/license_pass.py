from llvmlite import ir
import ast
from logging import Logger
import logging

logger: Logger = logging.getLogger(__name__)


def emit_license(module: ir.Module, license_str: str):
    license_bytes = license_str.encode("utf8") + b"\x00"
    elems = [ir.Constant(ir.IntType(8), b) for b in license_bytes]
    ty = ir.ArrayType(ir.IntType(8), len(elems))

    gvar = ir.GlobalVariable(module, ty, name="LICENSE")

    gvar.initializer = ir.Constant(ty, elems)  # type: ignore

    gvar.align = 1  # type: ignore
    gvar.linkage = "dso_local"  # type: ignore
    gvar.global_constant = False
    gvar.section = "license"  # type: ignore

    return gvar


def license_processing(tree, compilation_context):
    """Process the LICENSE function decorated with @bpf and @bpfglobal and return the section name"""
    count = 0
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == "LICENSE":
            # check decorators
            decorators = [
                dec.id for dec in node.decorator_list if isinstance(dec, ast.Name)
            ]
            if "bpf" in decorators and "bpfglobal" in decorators:
                if count == 0:
                    count += 1
                    # check function body has a return string
                    if (
                        len(node.body) == 1
                        and isinstance(node.body[0], ast.Return)
                        and isinstance(node.body[0].value, ast.Constant)
                        and isinstance(node.body[0].value.value, str)
                    ):
                        emit_license(
                            compilation_context.module, node.body[0].value.value
                        )
                        return "LICENSE"
                    else:
                        raise SyntaxError(
                            "ERROR: LICENSE() must return a string literal"
                        )
                else:
                    raise SyntaxError("ERROR: Multiple LICENSE globals defined")
    return None
