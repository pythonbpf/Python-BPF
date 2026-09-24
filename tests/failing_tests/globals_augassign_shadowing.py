# `counter += 1` without `global counter` binds `counter` as a local and reads
# it in the same statement, which is UnboundLocalError in Python. Plain
# assignment shadows the global instead (see passing_tests/globals/shadowing.py);
# this shape cannot, because it reads before it binds.
from pythonbpf import bpf, section, bpfglobal, compile
from ctypes import c_void_p, c_int64, c_uint64


@bpf
@bpfglobal
def counter() -> c_uint64:
    return c_uint64(0)


@bpf
@section("tracepoint/raw_syscalls/sys_enter")
def prog(ctx: c_void_p) -> c_int64:
    counter += 1  # noqa: F823, F841 -- missing `global counter` on purpose; this is
    # the UnboundLocalError shape, and the compiler must reject it just as loudly
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
