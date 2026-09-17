# Reading a global needs no declaration, in every shape a read can take --
# including `x = a_global`, which resolves through the allocation pass rather
# than the expression evaluator and so needs the globals table there too.
from pythonbpf import bpf, section, bpfglobal, compile
from ctypes import c_void_p, c_int64, c_uint64


@bpf
@bpfglobal
def threshold() -> c_uint64:
    return c_uint64(42)


@bpf
@section("tracepoint/raw_syscalls/sys_enter")
def prog(ctx: c_void_p) -> c_int64:
    limit = threshold
    doubled = threshold * 2
    if threshold > 10:
        print(f"limit {limit} doubled {doubled}")
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
