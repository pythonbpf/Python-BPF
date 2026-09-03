# Only integer scalar globals are supported in milestone 1; anything else must
# be a clear NotImplementedError, not a half-emitted symbol.
from pythonbpf import bpf, section, bpfglobal, compile
from ctypes import c_void_p, c_int64, c_double


@bpf
@bpfglobal
def ratio() -> c_double:
    return c_double(0.5)


@bpf
@section("tracepoint/raw_syscalls/sys_enter")
def prog(ctx: c_void_p) -> c_int64:
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
