from pythonbpf import bpf, map, struct, section, bpfglobal, BPF
from pythonbpf.helper import ktime, pid, comm
from pythonbpf.maps import PerfEventArray
from ctypes import c_void_p, c_int64, c_uint64


@bpf
@struct
class data_t:
    pid: c_uint64
    ts: c_uint64
    comm: str(16)  # type: ignore [valid-type]


@bpf
@map
def events() -> PerfEventArray:
    return PerfEventArray(key_size=c_int64, value_size=c_int64)


@bpf
@section("tracepoint/syscalls/sys_enter_clone")
def hello(ctx: c_void_p) -> c_int64:
    dataobj = data_t()
    dataobj.pid, dataobj.ts = pid(), ktime()
    comm(dataobj.comm)
    events.output(dataobj)
    return 0  # type: ignore [return-value]


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


# Compile and load
b = BPF()
b.load()
b.attach_all()

start = 0


def callback(cpu, event):
    global start
    if start == 0:
        start = event.ts
    ts = (event.ts - start) / 1e9
    print(f"[CPU {cpu}] PID: {event.pid}, TS: {ts}, COMM: {event.comm.decode()}")


perf = b["events"].open_perf_buffer(callback, struct_name="data_t")
print("Starting to poll... (Ctrl+C to stop)")
print("Try running: fork() or clone() system calls to trigger events")

try:
    while True:
        b["events"].poll(1000)
except KeyboardInterrupt:
    print("Stopping...")
