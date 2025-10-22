from pythonbpf import bpf, section, bpfglobal, BPF, trace_pipe
from ctypes import c_void_p, c_int64


@bpf
@section("kretprobe/do_unlinkat")
def hello_world(ctx: c_void_p) -> c_int64:
    print("Hello, World!")
    return c_int64(0)


@bpf
@section("kprobe/do_unlinkat")
def hello_world2(ctx: c_void_p) -> c_int64:
    print("Hello, World!")
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


b = BPF()
b.load()
b.attach_all()
print("running")
trace_pipe()
