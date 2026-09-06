# A map lookup used as a value in `or`, not just as a nullness test.
#
# `last.lookup(0)` returns a pointer into the map (NULL when the key is
# absent), so `prev or 0` must evaluate to the *stored value* when the key
# is present and to 0 when it is not. Compiling it as a truthiness test on
# the pointer makes the counter add a 0/1 flag instead of the stored count,
# so it sticks at 1 (or 2) forever.
from pythonbpf import bpf, map, section, bpfglobal, compile
from ctypes import c_void_p, c_int64, c_uint64
from pythonbpf.maps import HashMap


@bpf
@map
def last() -> HashMap:
    return HashMap(key=c_uint64, value=c_uint64, max_entries=3)


@bpf
@section("tracepoint/syscalls/sys_enter_execve")
def hello_world(ctx: c_void_p) -> c_int64:
    prev = last.lookup(0)
    last.update(0, (prev or 0) + 1)
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
