from pythonbpf import bpf, map, section, bpfglobal, compile
from pythonbpf.helper import XDP_PASS
from pythonbpf.maps import HashMap

from ctypes import c_void_p, c_int64

# NOTE: This example exposes the problems with our typing system.
# We can't do steps on line 25 and 27.
# prev is of type i64**. For prev + 1, we deref it down to i64
# To assign it back to prev, we need to go back to i64**.
# We cannot allocate space for the intermediate type now.
# We probably need to track the ref/deref chain for each variable.

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
