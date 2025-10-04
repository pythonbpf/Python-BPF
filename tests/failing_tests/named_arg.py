from pythonbpf import bpf, map, section, bpfglobal, compile
from pythonbpf.helper import XDP_PASS
from pythonbpf.maps import HashMap

from ctypes import c_void_p, c_int64

# NOTE: This example exposes the problems with our typing system.
# We assign every variable the type i64* by default.
# lookup() return type is ptr, which can't be loaded.
# So we can't do steps on line 25 and 27.
# To counter this, we should allocate vars by speculating their type.
# And in the assign pass, we should have something like a
# recursive_dereferencer() that dereferences a ptr until it hits a non-ptr type.
# And a recursive_wrapper() that does the opposite.

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
