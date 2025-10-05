from pythonbpf import bpf, map, section, bpfglobal, compile
from pythonbpf.helper import XDP_PASS
from pythonbpf.maps import HashMap

from ctypes import c_void_p, c_int64

# NOTE: I have decided to not fix this example for now.
# The issue is in line 31, where we are passing an expression.
# The update helper expects a pointer type. But the problem is
# that we must allocate the space for said pointer in the first
# basic block. As that usage is in a different basic block, we
# are unable to cast the expression to a pointer type. (as we never
# allocated space for it).
# Shall we change our space allocation logic? That allows users to
# spam the same helper with the same args, and still run out of
# stack space. So we consider this usage invalid for now.
# Might fix it later.


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
