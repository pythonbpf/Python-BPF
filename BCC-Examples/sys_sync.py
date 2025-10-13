from pythonbpf import bpf, section, bpfglobal, BPF, trace_pipe
from ctypes import c_void_p, c_int64


@bpf
@section("tracepoint/syscalls/sys_enter_sync")
def hello_world(ctx: c_void_p) -> c_int64:
    print("sys_sync() called")
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


BPF().load_and_attach()
print("Tracing sys_sync()... Ctrl-C to end.")
trace_pipe()
