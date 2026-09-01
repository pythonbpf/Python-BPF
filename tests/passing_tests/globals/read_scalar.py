# A @bpfglobal read in a condition and in a print. Reads need no marker;
# they compile to a plain `load i64, ptr @expected_pid`.
from pythonbpf import bpf, section, bpfglobal, compile
from pythonbpf.helper import pid
from ctypes import c_void_p, c_int64, c_uint64


@bpf
@bpfglobal
def expected_pid() -> c_uint64:
    return c_uint64(0)


@bpf
@section("tracepoint/syscalls/sys_enter_nanosleep")
def trace(ctx: c_void_p) -> c_int64:
    if expected_pid == pid():
        print(f"matched {expected_pid}")
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
