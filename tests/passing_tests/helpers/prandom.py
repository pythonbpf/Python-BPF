from pythonbpf import bpf, bpfglobal, section, BPF, trace_pipe
from ctypes import c_void_p, c_int64
from pythonbpf.helper import random


@bpf
@section("tracepoint/syscalls/sys_enter_clone")
def hello_world(ctx: c_void_p) -> c_int64:
    r = random()
    print(f"Hello, World!, {r}")
    return 0  # type: ignore [return-value]


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


# Compile and load
b = BPF()
b.load()
b.attach_all()

trace_pipe()
