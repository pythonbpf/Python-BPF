from llvmlite import ir
import ast

from logging import Logger
import logging
from .type_deducer import ctypes_to_ir, is_signed_ctype
from .symbols import BpfGlobalSymbol
from .debuginfo import DebugInfoGenerator
from .expr import VmlinuxHandlerRegistry
from .debuginfo import dwarf_constants as dc

logger: Logger = logging.getLogger(__name__)

_C_NAME_BY_WIDTH = {8: "char", 16: "short", 32: "int", 64: "long long"}


def populate_global_symbol_table(tree, compilation_context):
    """
    compilation_context: CompilationContext
    """
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
                    compilation_context.global_sym_tab.append(node)
                elif isinstance(dec, ast.Name) and dec.id == "bpfglobal":
                    compilation_context.global_sym_tab.append(node)

                elif isinstance(dec, ast.Name) and dec.id == "map":
                    compilation_context.global_sym_tab.append(node)
    return False


def _emit_global(module: ir.Module, node, name):
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
    # Natural alignment, matching what clang emits for the same declaration
    # (align 4 for i32, align 8 for i64). llc derives the BTF DATASEC layout
    # from these symbols, so the alignment should mirror the C reference in
    # tests/c-form/global_vars.bpf.c.
    gvar.align = ty.width // 8 if isinstance(ty, ir.IntType) else 8
    gvar.linkage = "dso_local"
    gvar.global_constant = False
    return gvar


def _emit_global_debug_info(compilation_context, gvar, name, ctype_name):
    """Attach DIGlobalVariableExpression metadata to a BPF global.

    llc's BPF backend manufactures the BTF VAR and DATASEC ('.bss'/'.data')
    entries from exactly this metadata (see tests/c-form/global_vars.bpf.c);
    without it, libbpf still creates the section maps but neither bpftool nor a
    future skeleton can tell which variable lives at which offset.
    """
    generator = DebugInfoGenerator(compilation_context.module)
    width = gvar.value_type.width
    signed = is_signed_ctype(ctype_name)
    base = _C_NAME_BY_WIDTH[width]
    if width == 8:
        encoding = dc.DW_ATE_signed_char if signed else dc.DW_ATE_unsigned_char
    else:
        encoding = dc.DW_ATE_signed if signed else dc.DW_ATE_unsigned
    cname = base if signed else f"unsigned {base}"
    di_type = generator.get_basic_type(cname, width, encoding)
    dv = generator.create_global_var_debug_info(name, di_type, is_local=False)
    gvar.set_metadata("dbg", dv)


def globals_processing(tree, compilation_context):
    """Process stuff decorated with @bpf and @bpfglobal except license and return the section name"""
    # Local tracking for duplicate checking if needed, or we can iterate context
    # But for now, we process specific nodes

    current_globals = []

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
        if name in current_globals:
            raise SyntaxError(f"ERROR: Global name '{name}' previously defined")
        else:
            current_globals.append(name)

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
                    gvar = _emit_global(compilation_context.module, node, name)
                    if VmlinuxHandlerRegistry.handle_name(name) is not None:
                        # C rejects this outright ("redefinition as different
                        # kind of symbol"); Python's rebinding semantics let
                        # the global win, and resolution order (local, then
                        # global, then vmlinux) applies it consistently. Warn
                        # so the shadowing is at least never silent.
                        logger.warning(
                            f"@bpfglobal '{name}' shadows a vmlinux enum "
                            f"constant of the same name; reads of '{name}' "
                            f"will use the global"
                        )
                    if isinstance(gvar.value_type, ir.IntType):
                        compilation_context.bpf_globals[name] = BpfGlobalSymbol(
                            var=gvar,
                            ir_type=gvar.value_type,
                            ctype_name=node.returns.id,
                        )
                        _emit_global_debug_info(
                            compilation_context, gvar, name, node.returns.id
                        )
                    else:
                        raise NotImplementedError(
                            f"Global '{name}': only integer scalar globals are "
                            f"supported so far; '{node.returns.id}' globals are "
                            f"planned for a later milestone"
                        )
                else:
                    raise SyntaxError(f"ERROR: Invalid syntax for {name} global")

    return None


def _emit_llvm_compiler_used(module: ir.Module, names: list[str]):
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


def globals_list_creation(tree, compilation_context):
    collected = ["LICENSE"]
    module = compilation_context.module

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

    _emit_llvm_compiler_used(module, collected)
