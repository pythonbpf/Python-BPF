from pythonbpf import bpf, map, bpfglobal, section, compile
from pythonbpf.maps import HashMap
from ctypes import c_void_p, c_int64, c_int32, c_uint64


@bpf
@map
def mymap() -> HashMap:
    return HashMap(key=c_int32, value=c_uint64, max_entries=16)


# Imagined sugar over the kernel's bpf_for_each_map_elem() callback helper:
# iterating a map's entries directly from a `for` statement.
@bpf
@section("tracepoint/syscalls/sys_enter_execve")
def hello(ctx: c_void_p) -> c_int64:
    total: c_int64 = 0
    for k, v in mymap.items():
        total = total + 1
    return total


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
