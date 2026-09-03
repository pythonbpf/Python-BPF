# `counter += 1` without `global counter` must be the same loud error as plain
# assignment. Before direct lowering this slipped past the allocation pass
# (which only walks Assign) and failed later with a misleading message.
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
