from pythonbpf import bpf, struct, section, bpfglobal, compile
from ctypes import c_void_p, c_int64, c_uint64

# Negative test: `dat` is a struct value, and a struct has no truth value
# (C rejects `if (s)`; Python would call any object true). It is a compile
# error that says to test one of the struct's fields instead. A *pointer* to
# a struct, such as a map lookup result, is a valid condition (non-null).


@bpf
@struct
class data_t:
    pid: c_uint64
    ts: c_uint64


@bpf
@section("tracepoint/syscalls/sys_enter_execve")
def hello_world(ctx: c_void_p) -> c_int64:
    dat = data_t()
    if dat:
        print("Hello, World!")
    else:
        print("Goodbye, World!")
    return


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
