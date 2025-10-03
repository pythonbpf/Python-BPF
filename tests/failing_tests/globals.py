import logging

from pythonbpf import compile, bpf, section, bpfglobal, compile_to_ir
from ctypes import c_void_p, c_int64, c_int32

@bpf
@bpfglobal
def somevalue() -> c_int32:
    return c_int32(0)

@bpf
@bpfglobal
def somevalue2() -> c_int64:
    return c_int64(0)

@bpf
@bpfglobal
def somevalue1() -> c_int32:
    return c_int32(0)

@bpf
@section("tracepoint/syscalls/sys_enter_execve")
def sometag(ctx: c_void_p) -> c_int64:
    print("test")
    return c_int64(1)

@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile_to_ir("globals.py", "globals.ll", loglevel=logging.INFO)
compile()
