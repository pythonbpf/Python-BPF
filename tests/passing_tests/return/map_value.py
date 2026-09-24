# `return` is a consumer of a value like any other: a pointer to one is
# dereferenced (null-checked) to reach it, so returning a map lookup result
# works the way `p + 0` already did. C shape: `if (p) return *p; return 0;`
from pythonbpf import bpf, map, section, bpfglobal, compile
from pythonbpf.maps import HashMap
from ctypes import c_void_p, c_int64, c_uint32, c_uint64


@bpf
@map
def m() -> HashMap:
    return HashMap(key=c_uint32, value=c_uint64, max_entries=4)


@bpf
@section("tracepoint/raw_syscalls/sys_enter")
def prog(ctx: c_void_p) -> c_int64:
    k = c_uint32(1)
    p = m.lookup(k)
    if p:
        return p
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
