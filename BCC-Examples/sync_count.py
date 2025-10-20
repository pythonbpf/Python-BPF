from pythonbpf import bpf, map, section, bpfglobal, BPF, trace_fields
from pythonbpf.helper import ktime
from pythonbpf.maps import HashMap

from ctypes import c_void_p, c_int64


@bpf
@map
def last() -> HashMap:
    return HashMap(key=c_int64, value=c_int64, max_entries=2)


@bpf
@section("tracepoint/syscalls/sys_enter_sync")
def do_trace(ctx: c_void_p) -> c_int64:
    ts_key, cnt_key = 0, 1
    tsp, cntp = last.lookup(ts_key), last.lookup(cnt_key)
    if not cntp:
        last.update(cnt_key, 0)
        cntp = last.lookup(cnt_key)
    if tsp:
        delta = ktime() - tsp
        if delta < 1000000000:
            time_ms = delta // 1000000
            print(f"{time_ms} {cntp}")
        last.delete(ts_key)
    else:
        last.update(ts_key, ktime())
    last.update(cnt_key, cntp + 1)
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
        task, pid, cpu, flags, ts, msg = trace_fields()
        if start == 0:
            start = ts
        ts -= start
        ms, cnt = msg.split()
        print(f"At time {ts} s: Multiple syncs detected, last {ms} ms ago. Count {cnt}")
    except KeyboardInterrupt:
        exit()
