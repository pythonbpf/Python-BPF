# A struct value has no integer to reach by dereferencing, so returning one
# from an integer function is a type error, raised by convert() with both
# types named rather than left for llc to reject with an IR line number.
from pythonbpf import bpf, struct, section, bpfglobal, compile
from ctypes import c_void_p, c_int64, c_uint64


@bpf
@struct
class task_info:
    pid: c_uint64


@bpf
@section("tracepoint/raw_syscalls/sys_enter")
def prog(ctx: c_void_p) -> c_int64:
    t = task_info()
    t.pid = 1
    return t


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
