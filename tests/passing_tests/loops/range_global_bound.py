# The bound is a @bpfglobal and the body calls a helper, so opt cannot fold
# the loop away: this is the case that puts a real bounded loop in front of
# the verifier. Reference: dyn_helper in tests/c-form/loops.bpf.c.
#
# The clamp is required, in C as here: userspace can write any value to a
# .data global, so without it the verifier assumes a bound up to 2**63 and
# walks iterations until it hits its 1M-instruction limit (E2BIG).
from pythonbpf import bpf, section, bpfglobal, compile
from pythonbpf.helper import random
from ctypes import c_void_p, c_int64


@bpf
@bpfglobal
def n() -> c_int64:
    return c_int64(10)


@bpf
@section("tracepoint/syscalls/sys_enter_execve")
def hello(ctx: c_void_p) -> c_int64:
    total: c_int64 = 0
    stop = n
    if stop > 64:
        stop = 64
    for i in range(stop):
        total = total + random()
    return total


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
