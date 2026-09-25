# A local named after an XDP action is just a local: it shadows the vmlinux
# enum constant of that name (when vmlinux is imported) exactly as a local
# shadows an enum constant in C, and its value is what returns. This once
# went through a special-cased return path that ignored the local and
# returned the hardcoded 2 while XDP_PASS held 55; that path is gone, and
# return resolves names like every other expression.
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
