# A license that is not GPL-compatible may not call GPL-only helpers: `print`
# lowers to bpf_trace_printk, so the verifier rejects this program. The
# counterpart of passing_tests/license_default.py, which proves the default
# license is GPL.

from pythonbpf import compile, bpf, bpfglobal, section
from ctypes import c_void_p, c_int64


@bpf
@section("tracepoint/syscalls/sys_enter_getpid")
def sometag(ctx: c_void_p) -> c_int64:
    print("hello")
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "Proprietary"


compile()
