from pythonbpf import bpf, map, section, bpfglobal, compile
from ctypes import c_void_p, c_int64, c_uint64
from pythonbpf.maps import HashMap

# NOTE: Decided against fixing this
# as a workaround is assigning the result of lookup to a variable
# and then using that variable in the if statement.
# Might fix in future.


@bpf
@map
def last() -> HashMap:
    return HashMap(key=c_uint64, value=c_uint64, max_entries=3)


@bpf
@section("tracepoint/syscalls/sys_enter_execve")
def hello_world(ctx: c_void_p) -> c_int64:
    last.update(0, 1)
    if last.lookup(0) > 0:
        print("Hello, World!")
    else:
        print("Goodbye, World!")
    return


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
