import ast
from llvmlite import ir
from .license_pass import license_processing
from .functions import func_proc
from .maps import maps_proc
from .structs import structs_proc
from .vmlinux_parser import vmlinux_proc
from pythonbpf.vmlinux_parser.vmlinux_exports_handler import VmlinuxHandler
from .expr import VmlinuxHandlerRegistry
from .globals_pass import (
    globals_list_creation,
    globals_processing,
    populate_global_symbol_table,
)
from .debuginfo import DW_LANG_C11, DwarfBehaviorEnum, DebugInfoGenerator
import os
import subprocess
import inspect
from pathlib import Path
from pylibbpf import BpfObject
import tempfile
from logging import Logger
import logging
import re

logger: Logger = logging.getLogger(__name__)

VERSION = "v0.1.6"


def finalize_module(original_str):
    """After all IR generation is complete, we monkey patch btf_ama attribute"""

    # Create a string with applied transformation of btf_ama attribute addition to BTF struct field accesses.
    pattern = r'(@"llvm\.[^"]+:[^"]*" = external global i64, !llvm\.preserve\.access\.index ![0-9]+)'
    replacement = r'\1 "btf_ama"'
    return re.sub(pattern, replacement, original_str)


def find_bpf_chunks(tree):
    """Find all functions decorated with @bpf in the AST."""
    bpf_functions = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) or isinstance(node, ast.ClassDef):
            for decorator in node.decorator_list:
                if isinstance(decorator, ast.Name) and decorator.id == "bpf":
                    bpf_functions.append(node)
                    break
    return bpf_functions


def processor(source_code, filename, module):
    tree = ast.parse(source_code, filename)
    logger.debug(ast.dump(tree, indent=4))

    bpf_chunks = find_bpf_chunks(tree)
    for func_node in bpf_chunks:
        logger.info(f"Found BPF function/struct: {func_node.name}")

    vmlinux_symtab = vmlinux_proc(tree, module)
    if vmlinux_symtab:
        handler = VmlinuxHandler.initialize(vmlinux_symtab)
        VmlinuxHandlerRegistry.set_handler(handler)

    populate_global_symbol_table(tree, module)
    license_processing(tree, module)
    globals_processing(tree, module)
    structs_sym_tab = structs_proc(tree, module, bpf_chunks)
    map_sym_tab = maps_proc(tree, module, bpf_chunks)
    func_proc(tree, module, bpf_chunks, map_sym_tab, structs_sym_tab)

    globals_list_creation(tree, module)
    return structs_sym_tab, map_sym_tab


def compile_to_ir(filename: str, output: str, loglevel=logging.INFO):
    logging.basicConfig(
        level=loglevel, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )
    with open(filename) as f:
        source = f.read()

    module = ir.Module(name=filename)
    module.data_layout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
    module.triple = "bpf"

    if not hasattr(module, "_debug_compile_unit"):
        debug_generator = DebugInfoGenerator(module)
        debug_generator.generate_file_metadata(filename, os.path.dirname(filename))
        debug_generator.generate_debug_cu(
            DW_LANG_C11,
            f"PythonBPF {VERSION}",
            True,  # TODO: This is probably not true
            # TODO: add a global field here that keeps track of all the globals. Works without it, but I think it might
            # be required for kprobes.
            True,
        )

    structs_sym_tab, maps_sym_tab = processor(source, filename, module)

    wchar_size = module.add_metadata(
        [
            DwarfBehaviorEnum.ERROR_IF_MISMATCH,
            "wchar_size",
            ir.Constant(ir.IntType(32), 4),
        ]
    )
    frame_pointer = module.add_metadata(
        [
            DwarfBehaviorEnum.OVERRIDE_USE_LARGEST,
            "frame-pointer",
            ir.Constant(ir.IntType(32), 2),
        ]
    )
    # Add Debug Info Version (3 = DWARF v3, which LLVM expects)
    debug_info_version = module.add_metadata(
        [
            DwarfBehaviorEnum.WARNING_IF_MISMATCH,
            "Debug Info Version",
            ir.Constant(ir.IntType(32), 3),
        ]
    )

    # Add explicit DWARF version 5
    dwarf_version = module.add_metadata(
        [
            DwarfBehaviorEnum.OVERRIDE_USE_LARGEST,
            "Dwarf Version",
            ir.Constant(ir.IntType(32), 5),
        ]
    )

    module.add_named_metadata("llvm.module.flags", wchar_size)
    module.add_named_metadata("llvm.module.flags", frame_pointer)
    module.add_named_metadata("llvm.module.flags", debug_info_version)
    module.add_named_metadata("llvm.module.flags", dwarf_version)

    module.add_named_metadata("llvm.ident", [f"PythonBPF {VERSION}"])

    module_string = finalize_module(str(module))

    logger.info(f"IR written to {output}")
    with open(output, "w") as f:
        f.write(f'source_filename = "{filename}"\n')
        f.write(module_string)
        f.write("\n")

    return output, structs_sym_tab, maps_sym_tab


def _run_llc(ll_file, obj_file):
    """Compile LLVM IR to BPF object file using llc."""

    logger.info(f"Compiling IR to object: {ll_file} -> {obj_file}")
    result = subprocess.run(
        [
            "llc",
            "-march=bpf",
            "-filetype=obj",
            "-O2",
            str(ll_file),
            "-o",
            str(obj_file),
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    if result.returncode == 0:
        logger.info(f"Object file written to {obj_file}")
        return True
    else:
        logger.error(f"llc compilation failed: {result.stderr}")
        return False


def compile(loglevel=logging.WARNING) -> bool:
    # Look one level up the stack to the caller of this function
    caller_frame = inspect.stack()[1]
    caller_file = Path(caller_frame.filename).resolve()

    ll_file = Path("/tmp") / caller_file.with_suffix(".ll").name
    o_file = caller_file.with_suffix(".o")

    _, structs_sym_tab, maps_sym_tab = compile_to_ir(
        str(caller_file), str(ll_file), loglevel=loglevel
    )

    if not _run_llc(ll_file, o_file):
        logger.error("Compilation to object file failed.")
        return False

    logger.info(f"Object written to {o_file}")
    return True


def BPF(loglevel=logging.WARNING) -> BpfObject:
    caller_frame = inspect.stack()[1]
    src = inspect.getsource(caller_frame.frame)
    with tempfile.NamedTemporaryFile(
        mode="w+", delete=True, suffix=".py"
    ) as f, tempfile.NamedTemporaryFile(
        mode="w+", delete=True, suffix=".ll"
    ) as inter, tempfile.NamedTemporaryFile(
        mode="w+", delete=False, suffix=".o"
    ) as obj_file:
        f.write(src)
        f.flush()
        source = f.name
        _, structs_sym_tab, maps_sym_tab = compile_to_ir(
            source, str(inter.name), loglevel=loglevel
        )
        _run_llc(str(inter.name), str(obj_file.name))

        return BpfObject(str(obj_file.name), structs=structs_sym_tab)
