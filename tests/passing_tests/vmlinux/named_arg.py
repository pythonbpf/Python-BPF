from pythonbpf import bpf, map, section, bpfglobal, compile
from vmlinux import XDP_PASS
from pythonbpf.maps import HashMap

from ctypes import c_void_p, c_int64

# `prev` starts as a map lookup result (a pointer) and is rebound to
# `prev + 1`, which lives in a temporary that `prev` then points at. The update
# must store the incremented value: the helper gets the pointer the local
# holds, not the address of the local's own slot (that used to store a kernel
# stack address into the map).


@bpf
@map
def count() -> HashMap:
    return HashMap(key=c_int64, value=c_int64, max_entries=1)


@bpf
@section("xdp")
def hello_world(ctx: c_void_p) -> c_int64:
    prev = count.lookup(0)
    if prev:
        prev = prev + 1
        count.update(0, prev)
        return XDP_PASS
    else:
        count.update(0, 1)

    return XDP_PASS


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
