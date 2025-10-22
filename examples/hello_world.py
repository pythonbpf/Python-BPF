from pythonbpf import bpf, section, bpfglobal, BPF, trace_pipe
from ctypes import c_void_p, c_int64

# Instructions to how to run this program
# 1. Install PythonBPF: pip install pythonbpf
# 2. Run the program: sudo python examples/hello_world.py
# 4. Start up any program and watch the output


@bpf
@section("tracepoint/syscalls/sys_enter_execve")
def hello_world(ctx: c_void_p) -> c_int64:
    print("Hello, World!")
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


b = BPF()
b.load()
b.attach_all()
trace_pipe()
