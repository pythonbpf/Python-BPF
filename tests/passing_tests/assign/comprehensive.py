from pythonbpf import bpf, map, section, bpfglobal, compile, struct
from ctypes import c_void_p, c_int64, c_int32, c_uint64
from pythonbpf.maps import HashMap
from pythonbpf.helper import ktime


# NOTE: This is a comprehensive test combining struct, helper, and map features
# Please note that at line 50, though we have used an absurd expression to test
# the compiler, it is recommended to use named variables to reduce the amount of
# scratch space that needs to be allocated.

@bpf
@struct
class data_t:
    pid: c_uint64
    ts: c_uint64


@bpf
@map
def last() -> HashMap:
    return HashMap(key=c_uint64, value=c_uint64, max_entries=3)


@bpf
@section("tracepoint/syscalls/sys_enter_execve")
def hello_world(ctx: c_void_p) -> c_int64:
    dat = data_t()
    dat.pid = 123
    dat.pid = dat.pid + 1
    print(f"pid is {dat.pid}")
    tu = 9
    last.update(0, tu)
    last.update(1, -last.lookup(0))
    x = last.lookup(0)
    print(f"Map value at index 0: {x}")
    x = x + c_int32(1)
    print(f"x after adding 32-bit 1 is {x}")
    x = ktime() - 121
    print(f"ktime - 121 is {x}")
    x = last.lookup(0)
    x = x + 1
    print(f"x is {x}")
    if x == 10:
        jat = data_t()
        jat.ts = 456
        print(f"Hello, World!, ts is {jat.ts}")
        a = last.lookup(0)
        print(f"a is {a}")
        last.update(9, 9)
        last.update(0, last.lookup(last.lookup(0)) +
                    last.lookup(last.lookup(0)) + last.lookup(last.lookup(0)))
        z = last.lookup(0)
        print(f"new map val at index 0 is {z}")
    else:
        a = last.lookup(0)
        print("Goodbye, World!")
    c = last.lookup(1 - 1)
    print(f"c is {c}")
    return


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
