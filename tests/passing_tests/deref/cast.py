# A ctypes cast of a map-lookup pointer is a cast of its value, as p + 0 is.
from pythonbpf import bpf, map, struct, section, bpfglobal, compile
from pythonbpf.maps import HashMap
from ctypes import c_void_p, c_int64, c_uint32, c_uint64


@bpf
@map
def m() -> HashMap:
    return HashMap(key=c_uint32, value=c_uint64, max_entries=4)


@bpf
@struct
class rec:
    val: c_uint64


@bpf
@section("tracepoint/raw_syscalls/sys_enter")
def prog(ctx: c_void_p) -> c_int64:
    k = c_uint32(1)
    p = m.lookup(k)
    q = m.lookup(k)  # noqa: F841
    if p:
        y = c_int64(p)  # noqa: F841
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
