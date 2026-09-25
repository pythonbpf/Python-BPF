# Adapted from bpf-next/tools/testing/selftests/bpf/progs/test_map_ops.c
# and bpf-next/tools/testing/selftests/bpf/progs/bpf_iter_bpf_array_map.c.

from ctypes import c_int32, c_uint64, c_void_p

from pythonbpf import bpf, bpfglobal, compile, map, section
from pythonbpf.maps import ArrayMap


@bpf
@map
def counters() -> ArrayMap:
    return ArrayMap(key=c_int32, value=c_uint64, max_entries=8)


@bpf
@section("tracepoint/syscalls/sys_enter_getpid")
def array_map_lookup_update(ctx: c_void_p) -> c_int32:
    counters.update(0, 1)

    current = counters.lookup(0)
    if current:
        next_value = current + 1
        counters.update(0, next_value)

    return c_int32(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
