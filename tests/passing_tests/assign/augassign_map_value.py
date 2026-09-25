# Augmented assignment to a map-lookup local: `v += 1` is `v = v + 1`. It reads
# the value through the pointer (null-checked) and rebinds v to the result; the
# map itself is not written.
from pythonbpf import bpf, map, section, bpfglobal, compile
from pythonbpf.maps import HashMap
from ctypes import c_void_p, c_int64, c_uint64


@bpf
@map
def m() -> HashMap:
    return HashMap(key=c_int64, value=c_uint64, max_entries=4)


@bpf
@section("tracepoint/raw_syscalls/sys_enter")
def prog(ctx: c_void_p) -> c_int64:
    v = m.lookup(0)
    if v:
        v += 1
        v >>= 1  # c_uint64 value: a logical shift
        return v
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
