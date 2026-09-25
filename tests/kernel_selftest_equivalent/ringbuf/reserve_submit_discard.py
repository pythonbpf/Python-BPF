# Adapted from bpf-next/tools/testing/selftests/bpf/progs/test_ringbuf.c.

from ctypes import c_int32, c_uint64, c_void_p

from pythonbpf import bpf, bpfglobal, compile, map, section, struct
from pythonbpf.helper import pid
from pythonbpf.maps import RingBuffer


@bpf
@struct
class sample_t:
    pid: c_uint64
    seq: c_uint64
    value: c_uint64


@bpf
@map
def events() -> RingBuffer:
    return RingBuffer(max_entries=4096)


@bpf
@section("tracepoint/syscalls/sys_enter_getpid")
def ringbuf_reserve_submit_discard(ctx: c_void_p) -> c_int32:
    first = events.reserve(24)
    if first:
        sample = sample_t(first)
        sample.pid = pid()
        sample.seq = 0
        sample.value = 7
        events.submit(first, 0)

    second = events.reserve(24)
    if second:
        events.discard(second, 0)

    return c_int32(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
