# A comparison with a map value compares what the map holds, on either side:
# `head == body.lookup(1)` with both sides map lookups used to compare the two
# entries' addresses.
from ctypes import c_int64, c_uint64, c_void_p
from pythonbpf import bpf, map, section, bpfglobal, compile
from pythonbpf.maps import HashMap


@bpf
@map
def body() -> HashMap:
    return HashMap(key=c_uint64, value=c_uint64, max_entries=10)


@bpf
@section("tracepoint/syscalls/sys_enter_getppid")
def prog(ctx: c_void_p) -> c_int64:
    head = body.lookup(0)
    if head == body.lookup(1):
        return c_int64(1)
    k = 3
    if body.lookup(2) == body.lookup(k):
        return c_int64(2)
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
