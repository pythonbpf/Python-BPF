from pythonbpf import bpf, map, struct, section, bpfglobal, BPF, trace_pipe
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
    print(f"clone called at {dataobj.ts} by pid {dataobj.pid}, comm {dataobj.comm}")
    events.output(dataobj)
    return 0  # type: ignore [return-value]


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


# compile
BPF().load_and_attach()

print("Tracing clone()... Ctrl-C to end")
trace_pipe()
