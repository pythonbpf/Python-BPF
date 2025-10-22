from pythonbpf import bpf, map, section, bpfglobal, BPF, trace_fields
from pythonbpf.helper import ktime
from pythonbpf.maps import HashMap

from ctypes import c_void_p, c_int64


@bpf
@map
def last() -> HashMap:
    return HashMap(key=c_int64, value=c_int64, max_entries=1)


@bpf
@section("tracepoint/syscalls/sys_enter_sync")
def do_trace(ctx: c_void_p) -> c_int64:
    key = 0
    tsp = last.lookup(key)
    if tsp:
        delta = ktime() - tsp
        if delta < 1000000000:
            time_ms = delta // 1000000
            print(f"{time_ms}")
        last.delete(key)
    else:
        last.update(key, ktime())
    return 0  # type: ignore [return-value]


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


# Compile and load
b = BPF()
b.load()
b.attach_all()

print("Tracing for quick sync's... Ctrl-C to end")

# format output
start = 0
while True:
    try:
        task, pid, cpu, flags, ts, ms = trace_fields()
        if start == 0:
            start = ts
        ts -= start
        print(f"At time {ts} s: Multiple syncs detected, last {ms} ms ago")
    except KeyboardInterrupt:
        exit()
