import logging

from pythonbpf import compile, bpf, section, bpfglobal, compile_to_ir
from ctypes import c_void_p, c_int64

# This should not pass as somevalue is not declared at all.
@bpf
@section("tracepoint/syscalls/sys_enter_execve")
def sometag(ctx: c_void_p) -> c_int64:
    print("test")
    print(f"{somevalue}")
    return c_int64(1)

@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile_to_ir("globals.py", "globals.ll", loglevel=logging.INFO)
compile()
