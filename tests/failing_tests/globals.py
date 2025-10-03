import logging

from pythonbpf import compile, bpf, section, bpfglobal, compile_to_ir
from ctypes import c_void_p, c_int64

@bpf
@bpfglobal
def somevalue() -> c_int64:
    return c_int64(0)

@bpf
@section("sometag1")
def sometag(ctx: c_void_p) -> c_int64:
    return c_int64(0)

@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile_to_ir("globals.py", "globals.ll", loglevel=logging.INFO)
compile()
