from pythonbpf import bpf, map, section, bpfglobal, compile
from vmlinux import XDP_PASS
from pythonbpf.maps import HashMap

from ctypes import c_void_p, c_int64

# An expression (`prev + 1`) passed straight to map.update(): it is evaluated
# into a scratch slot and the helper gets that slot's address. This was once
# refused for want of a slot allocated up front, and now works.


@bpf
@map
def count() -> HashMap:
    return HashMap(key=c_int64, value=c_int64, max_entries=1)


@bpf
@section("xdp")
def hello_world(ctx: c_void_p) -> c_int64:
    prev = count.lookup(0)
    if prev:
        count.update(0, prev + 1)
        return XDP_PASS
    else:
        count.update(0, 1)

    return XDP_PASS


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
