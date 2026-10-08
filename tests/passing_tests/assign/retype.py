from pythonbpf import bpf, map, section, bpfglobal, compile
from ctypes import c_void_p, c_int64, c_uint64
from pythonbpf.maps import HashMap


# `x` is first bound to a map lookup (a pointer) and then rebound to an integer,
# as Python allows; the comparison sees the integer. This was once refused
# because stack slots are typed, and now works.


@bpf
@map
def last() -> HashMap:
    return HashMap(key=c_uint64, value=c_uint64, max_entries=3)


@bpf
@section("tracepoint/syscalls/sys_enter_execve")
def hello_world(ctx: c_void_p) -> c_int64:
    last.update(0, 1)
    x = last.lookup(0)
    x = 20
    if x == 2:
        print("Hello, World!")
    else:
        print("Goodbye, World!")
    return


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
