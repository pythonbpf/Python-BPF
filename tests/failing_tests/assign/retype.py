from pythonbpf import bpf, map, section, bpfglobal, compile
from ctypes import c_void_p, c_int64, c_uint64
from pythonbpf.maps import HashMap


# NOTE: This example tries to reinterpret the variable `x` to a different type.
# We do not allow this for now, as stack allocations are typed and have to be
# done in the first basic block. Allowing re-interpretation would require
# re-allocation of stack space (possibly in a new basic block), which is not
# supported in eBPF yet.
# We can allow bitcasts in cases where the width of the types is the same in
# the future. But for now, we do not allow any re-interpretation of variables.

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
