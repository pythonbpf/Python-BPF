from pythonbpf import bpf, section, bpfglobal, BPF
from ctypes import c_void_p, c_int64


@bpf
@section("kretprobe/do_unlinkat")
def hello_world(ctx: c_void_p) -> c_int64:
    print("Hello, World!")
    return c_int64(0)

@bpf
@section("kprobe/do_unlinkat")
def hello_world(ctx: c_void_p) -> c_int64:
    print("Hello, World!")
    return c_int64(0)

@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


b = BPF()
b.load_and_attach()
while True:
    print("running")
# Now cat /sys/kernel/debug/tracing/trace_pipe to see results of unlink kprobe.
