# A map lookup result passed straight to map.update(): the helper gets the
# pointer the local holds (the map value), as bpf_map_update_elem(&m, &k, prev, 0)
# would in C, not the address of the local's slot.

from pythonbpf import bpf, map, section, bpfglobal, compile
from pythonbpf.maps import HashMap
from ctypes import c_void_p, c_int64


@bpf
@map
def count() -> HashMap:
    return HashMap(key=c_int64, value=c_int64, max_entries=2)


@bpf
@section("tracepoint/syscalls/sys_enter_getpid")
def copy(ctx: c_void_p) -> c_int64:
    prev = count.lookup(0)
    if prev:
        count.update(1, prev)
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
