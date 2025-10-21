from pythonbpf import bpf, map, struct, section, bpfglobal, BPF
from pythonbpf.helper import ktime
from pythonbpf.maps import HashMap
from pythonbpf.maps import PerfEventArray
from ctypes import c_void_p, c_int64


@bpf
@struct
class data_t:
    ts: c_int64
    ms: c_int64


@bpf
@map
def events() -> PerfEventArray:
    return PerfEventArray(key_size=c_int64, value_size=c_int64)


@bpf
@map
def last() -> HashMap:
    return HashMap(key=c_int64, value=c_int64, max_entries=1)


@bpf
@section("tracepoint/syscalls/sys_enter_sync")
def do_trace(ctx: c_void_p) -> c_int64:
    dat, dat.ts, key = data_t(), ktime(), 0
    tsp = last.lookup(key)
    if tsp:
        delta = ktime() - tsp
        if delta < 1000000000:
            dat.ms = delta // 1000000
            events.output(dat)
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


def callback(cpu, event):
    global start
    if start == 0:
        start = event.ts
    event.ts -= start
    print(
        f"At time {event.ts / 1e9} s: Multiple sync detected, Last sync: {event.ms} ms ago"
    )


perf = b["events"].open_perf_buffer(callback, struct_name="data_t")
print("Starting to poll... (Ctrl+C to stop)")
print("Try running: fork() or clone() system calls to trigger events")

try:
    while True:
        b["events"].poll(1000)
except KeyboardInterrupt:
    print("Stopping...")
