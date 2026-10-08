# No LICENSE: the program gets "GPL", with a warning. `print` lowers to
# bpf_trace_printk, which is GPL-only, so the verifier only accepts this
# program if the default license reaches the kernel.

from pythonbpf import compile, bpf, section
from ctypes import c_void_p, c_int64


@bpf
@section("tracepoint/syscalls/sys_enter_getpid")
def sometag(ctx: c_void_p) -> c_int64:
    a = 1 + 2
    print(f"{a}")
    return c_int64(0)


compile()
