from pythonbpf import bpf, struct, section, bpfglobal, compile
from ctypes import c_void_p, c_int64, c_uint64

# NOTE: Decided against fixing this
# as one workaround is to just check any field of the struct
# in the if statement. Ugly but works.
# Might fix in future.


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
