# A map-lookup local dereferenced to its value carries the map's declared
# value type: on a c_uint64 map, p >> 63 is a logical shift.
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
        top = p >> 63  # lshr: 0 or 1, never -1
        return c_int64(top)
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
