"""
PythonBPF - A Python frontend for eBPF programs.

This package provides decorators and compilation tools to write BPF programs
in Python syntax and compile them to eBPF bytecode that can run in the kernel.
"""

from .decorators import bpf, map, section, bpfglobal, struct
from .codegen import compile_to_ir, compile, BPF

__all__ = [
    "bpf",
    "map",
    "section",
    "bpfglobal",
    "struct",
    "compile_to_ir",
    "compile",
    "BPF",
]
