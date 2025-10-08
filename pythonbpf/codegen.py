"""
Code generation module for PythonBPF.

This module handles the conversion of Python BPF programs to LLVM IR and
object files. It provides the main compilation pipeline from Python AST
to BPF bytecode.
"""

import ast
from llvmlite import ir
from .license_pass import license_processing
from .functions import func_proc
from .maps import maps_proc
from .structs import structs_proc
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
from pylibbpf import BpfProgram
import tempfile
from logging import Logger
import logging

logger: Logger = logging.getLogger(__name__)

VERSION = "v0.1.4"


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
    """
    Process Python source code and convert BPF-decorated functions to LLVM IR.
    
    Args:
        source_code: The Python source code to process
        filename: The name of the source file
        module: The LLVM IR module to populate
    """
    tree = ast.parse(source_code, filename)
    logger.debug(ast.dump(tree, indent=4))

    bpf_chunks = find_bpf_chunks(tree)
    for func_node in bpf_chunks:
        logger.info(f"Found BPF function/struct: {func_node.name}")

    populate_global_symbol_table(tree, module)
    license_processing(tree, module)
    globals_processing(tree, module)

    structs_sym_tab = structs_proc(tree, module, bpf_chunks)
    map_sym_tab = maps_proc(tree, module, bpf_chunks)
    func_proc(tree, module, bpf_chunks, map_sym_tab, structs_sym_tab)

    globals_list_creation(tree, module)


def compile_to_ir(filename: str, output: str, loglevel=logging.INFO):
    """
    Compile a Python BPF program to LLVM IR.
    
    Args:
        filename: Path to the Python source file containing BPF programs
        output: Path where the LLVM IR (.ll) file will be written
        loglevel: Logging level for compilation messages
    
    Returns:
        Path to the generated LLVM IR file
    """
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

    processor(source, filename, module)

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

    logger.info(f"IR written to {output}")
    with open(output, "w") as f:
        f.write(f'source_filename = "{filename}"\n')
        f.write(str(module))
        f.write("\n")

    return output


def compile(loglevel=logging.INFO) -> bool:
    """
    Compile the calling Python BPF program to an object file.
    
    This function should be called from a Python file containing BPF programs.
    It will compile the calling file to LLVM IR and then to a BPF object file.
    
    Args:
        loglevel: Logging level for compilation messages
    
    Returns:
        True if compilation succeeded, False otherwise
    """
    # Look one level up the stack to the caller of this function
    caller_frame = inspect.stack()[1]
    caller_file = Path(caller_frame.filename).resolve()

    ll_file = Path("/tmp") / caller_file.with_suffix(".ll").name
    o_file = caller_file.with_suffix(".o")

    success = True
    success = (
        compile_to_ir(str(caller_file), str(ll_file), loglevel=loglevel) and success
    )

    success = bool(
        subprocess.run(
            [
                "llc",
                "-march=bpf",
                "-filetype=obj",
                "-O2",
                str(ll_file),
                "-o",
                str(o_file),
            ],
            check=True,
        )
        and success
    )

    logger.info(f"Object written to {o_file}")
    return success


def BPF(loglevel=logging.INFO) -> BpfProgram:
    """
    Compile the calling Python BPF program and return a BpfProgram object.
    
    This function compiles the calling file's BPF programs to an object file
    and loads it into a BpfProgram object for immediate use.
    
    Args:
        loglevel: Logging level for compilation messages
    
    Returns:
        A BpfProgram object that can be used to load and attach BPF programs
    """
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
        compile_to_ir(source, str(inter.name), loglevel=loglevel)
        subprocess.run(
            [
                "llc",
                "-march=bpf",
                "-filetype=obj",
                "-O2",
                str(inter.name),
                "-o",
                str(obj_file.name),
            ],
            check=True,
        )

        return BpfProgram(str(obj_file.name))
