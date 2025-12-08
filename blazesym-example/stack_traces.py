# tests/passing_tests/ringbuf_advanced.py
from pythonbpf import bpf, map, section, bpfglobal, struct, compile
from pythonbpf.maps import RingBuffer
from pythonbpf.helper import ktime, pid, smp_processor_id, comm, get_stack
from ctypes import c_void_p, c_int32, c_int64
import logging


@bpf
@struct
class exec_event:
    pid: c_int64
    cpu: c_int32
    timestamp: c_int64
    comm: str(16)  # type: ignore [valid-type]
    kstack_sz: c_int64
    ustack_sz: c_int64
    kstack: str(128)  # type: ignore [valid-type]
    ustack: str(128)  # type: ignore [valid-type]


@bpf
@map
def exec_events() -> RingBuffer:
    return RingBuffer(max_entries=1048576)


@bpf
@section("perf_event")
def trace_exec_enter(ctx: c_void_p) -> c_int64:
    evt = exec_event()
    evt.pid = pid()
    evt.cpu = smp_processor_id()
    evt.timestamp = ktime()
    comm(evt.comm)
    evt.kstack_sz = get_stack(evt.kstack)
    evt.ustack_sz = get_stack(evt.ustack, 256)
    exec_events.output(evt)
    print(f"Submitted exec_event for pid: {evt.pid}, cpu: {evt.cpu}")
    return 0  # type: ignore [return-value]


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile(logging.INFO)
