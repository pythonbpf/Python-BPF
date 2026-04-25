import logging
from pathlib import Path

from pythonbpf.codegen import compile_to_ir, _run_llc


def run_ir_generation(test_path: Path, output_ll: Path):
    """Run compile_to_ir on a BPF test file.

    Returns the (output, structs_sym_tab, maps_sym_tab) tuple from compile_to_ir.
    Raises on exception. Any logging.ERROR records captured by pytest caplog
    indicate a compile failure even when no exception is raised.
    """
    return compile_to_ir(str(test_path), str(output_ll), loglevel=logging.WARNING)


def run_llc(ll_path: Path, obj_path: Path) -> bool:
    """Compile a .ll file to a BPF .o using llc.

    Raises subprocess.CalledProcessError on failure (llc uses check=True).
    Returns True on success.
    """
    return _run_llc(str(ll_path), str(obj_path))
