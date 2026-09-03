# A local named after an XDP action must shadow the helper constant table,
# in return position too. clang agrees: a local legally shadows an enum
# constant, and the local's value is what returns (tests/c-form reference).
# Before the fix this returned the hardcoded 2 while XDP_PASS held 55.
from pythonbpf import bpf, section, bpfglobal, compile
from ctypes import c_void_p, c_int64


@bpf
@section("tracepoint/raw_syscalls/sys_enter")
def prog(ctx: c_void_p) -> c_int64:
    XDP_PASS = 55
    return XDP_PASS


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
