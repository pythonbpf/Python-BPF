import ast
from llvmlite import ir
from .context import CompilationContext
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
import shutil
import subprocess
import inspect
from pathlib import Path
from pylibbpf import BpfObject
import tempfile
from logging import Logger
import logging
import re

logger: Logger = logging.getLogger(__name__)

VERSION = "v0.2.0"


def finalize_module(original_str):
    """After all IR generation is complete, we monkey patch btf_ama attribute"""

    # Create a string with applied transformation of btf_ama attribute addition to BTF struct field accesses.
    pattern = r'(@"llvm\.[^"]+:[^"]*" = external global i64, !llvm\.preserve\.access\.index ![0-9]+)'
    replacement = r'\1 "btf_ama"'
    return re.sub(pattern, replacement, original_str)


def bpf_passthrough_gen(module):
    i32_ty = ir.IntType(32)
    ptr_ty = ir.PointerType(ir.IntType(8))
    fnty = ir.FunctionType(ptr_ty, [i32_ty, ptr_ty])

    # Declare the intrinsic
    passthrough = ir.Function(module, fnty, "llvm.bpf.passthrough.p0.p0")

    # Set function attributes
    # TODO: the ones commented are supposed to be there but cannot be added due to llvmlite limitations at the moment
    # passthrough.attributes.add("nofree")
    # passthrough.attributes.add("nosync")
    passthrough.attributes.add("nounwind")
    # passthrough.attributes.add("memory(none)")

    return passthrough


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


def processor(source_code, filename, compilation_context):
    tree = ast.parse(source_code, filename)
    logger.debug(ast.dump(tree, indent=4))
    module = compilation_context.module

    bpf_chunks = find_bpf_chunks(tree)
    for func_node in bpf_chunks:
        logger.info(f"Found BPF function/struct: {func_node.name}")

    bpf_passthrough_gen(module)

    vmlinux_symtab = vmlinux_proc(tree, module)
    if vmlinux_symtab:
        handler = VmlinuxHandler.initialize(vmlinux_symtab)
        VmlinuxHandlerRegistry.set_handler(handler)
        compilation_context.vmlinux_handler = handler

    populate_global_symbol_table(tree, compilation_context)
    license_processing(tree, compilation_context)
    globals_processing(tree, compilation_context)
    structs_sym_tab = structs_proc(tree, compilation_context, bpf_chunks)

    map_sym_tab = maps_proc(tree, compilation_context, bpf_chunks)

    func_proc(tree, compilation_context, bpf_chunks)

    globals_list_creation(tree, compilation_context)
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

    compilation_context = CompilationContext(module)

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

    structs_sym_tab, maps_sym_tab = processor(source, filename, compilation_context)

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

    module_string: str = finalize_module(str(module))

    logger.info(f"IR written to {output}")
    with open(output, "w") as f:
        f.write(f'source_filename = "{filename}"\n')
        f.write(module_string)
        f.write("\n")

    return output, structs_sym_tab, maps_sym_tab


MIN_OPT_VERSION = 15
_OPT_VERSIONED_RE = re.compile(r"opt-(\d+)")


def _find_opt():
    """Locate an LLVM opt binary.

    Prefers a plain ``opt`` on PATH. Otherwise falls back to the newest
    versioned ``opt-N`` (N >= MIN_OPT_VERSION) that distros such as
    Debian/Ubuntu install, e.g. ``opt-18``. Returns None if none is found.
    """
    opt = shutil.which("opt")
    if opt:
        return opt

    best_version, best_path = -1, None
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        try:
            entries = os.listdir(directory or ".")
        except OSError:
            continue
        for entry in entries:
            match = _OPT_VERSIONED_RE.fullmatch(entry)
            if not match:
                continue
            version = int(match.group(1))
            if version < MIN_OPT_VERSION or version <= best_version:
                continue
            path = shutil.which(entry, path=directory or ".")
            if path:
                best_version, best_path = version, path
    return best_path


def _run_opt(ll_file):
    """Run the O2 pipeline over the IR and return it as bitcode, or None if
    no opt binary is available."""

    opt = _find_opt()
    if opt is None:
        logger.warning(
            f"No LLVM 'opt' (or 'opt-N', N >= {MIN_OPT_VERSION}) found on PATH; "
            "skipping IR optimization."
        )
        return None

    logger.info(f"Optimizing IR with {opt} -O2: {ll_file}")
    result = subprocess.run(
        [opt, "-O2", str(ll_file), "-o", "-"],
        check=True,
        capture_output=True,
    )
    return result.stdout


def _run_llc(ll_file, obj_file):
    """Optimize LLVM IR with opt (when available) and compile it to a BPF
    object file using llc."""

    bitcode = _run_opt(ll_file)

    logger.info(f"Compiling IR to object: {ll_file} -> {obj_file}")
    result = subprocess.run(
        [
            "llc",
            "-march=bpf",
            "-filetype=obj",
            "-O2",
            "-" if bitcode is not None else str(ll_file),
            "-o",
            str(obj_file),
        ],
        input=bitcode,
        check=True,
        capture_output=True,
    )

    if result.returncode == 0:
        logger.info(f"Object file written to {obj_file}")
        return True
    else:
        logger.error(f"llc compilation failed: {result.stderr.decode()}")
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
    with (
        tempfile.NamedTemporaryFile(mode="w+", delete=True, suffix=".py") as f,
        tempfile.NamedTemporaryFile(mode="w+", delete=True, suffix=".ll") as inter,
        tempfile.NamedTemporaryFile(mode="w+", delete=False, suffix=".o") as obj_file,
    ):
        f.write(src)
        f.flush()
        source = f.name
        _, structs_sym_tab, maps_sym_tab = compile_to_ir(
            source, str(inter.name), loglevel=loglevel
        )
        _run_llc(str(inter.name), str(obj_file.name))

        return BpfObject(str(obj_file.name), structs=structs_sym_tab)
