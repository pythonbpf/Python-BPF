# Writing a global's name without `global` must be a loud compile error, not a
# silently-created shadowing local (real Python) or a silent global store.
from pythonbpf import bpf, section, bpfglobal, compile
from ctypes import c_void_p, c_int64, c_uint64


@bpf
@bpfglobal
def counter() -> c_uint64:
    return c_uint64(0)


@bpf
@section("tracepoint/raw_syscalls/sys_enter")
def prog(ctx: c_void_p) -> c_int64:
    counter = 1  # noqa: F841 -- missing `global counter` on purpose
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
