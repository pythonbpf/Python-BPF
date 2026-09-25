# Assignment to a field of a struct map value writes through the lookup
# pointer into the map, null-checked: `stats.count += 1` updates the entry in
# place, with no update() call. Also a sub-64-bit field and a plain store.
from pythonbpf import bpf, map, section, bpfglobal, compile, struct
from pythonbpf.maps import HashMap
from ctypes import c_void_p, c_int64, c_uint64, c_uint32


@bpf
@struct
class stats_t:
    count: c_uint64
    flags: c_uint32


@bpf
@map
def stats() -> HashMap:
    return HashMap(key=c_uint32, value=stats_t, max_entries=16)


@bpf
@section("tracepoint/raw_syscalls/sys_enter")
def prog(ctx: c_void_p) -> c_int64:
    k = c_uint32(0)
    s = stats.lookup(k)
    if s:
        s.count += 1
        s.flags = 3
        s.flags <<= 1
        return s.count
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
