# Counts packets in a one-entry map and lets every packet through. It used to
# be an xfail, but the only thing failing was the old `count().lookup(...)`
# spelling of a map call; `count.lookup(...)` is the current one.

from pythonbpf import bpf, map, section, bpfglobal, compile
from pythonbpf.maps import HashMap
from vmlinux import XDP_PASS
from vmlinux import struct_xdp_md
from ctypes import c_int64


@bpf
@map
def count() -> HashMap:
    return HashMap(key=c_int64, value=c_int64, max_entries=1)


@bpf
@section("xdp")
def hello_world(ctx: struct_xdp_md) -> c_int64:
    key = 0
    one = 1
    prev = count.lookup(key)
    if prev:
        prevval = prev + 1
        print(f"count: {prevval}")
        count.update(key, prevval)
        return XDP_PASS
    else:
        count.update(key, one)

    return XDP_PASS


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
