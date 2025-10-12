from pythonbpf import bpf, section, bpfglobal, compile, struct
from ctypes import c_void_p, c_int64, c_uint64
from pythonbpf.helper import ktime


@bpf
@struct
class data_t:
    pid: c_uint64
    ts: c_uint64


@bpf
@section("tracepoint/syscalls/sys_enter_execve")
def hello_world(ctx: c_void_p) -> c_int64:
    dat = data_t()
    dat.pid = 123
    dat.pid = dat.pid + 1
    print(f"pid is {dat.pid}")
    x = ktime() - 121
    print(f"ktime is {x}")
    x = 1
    x = x + 1
    print(f"x is {x}")
    if x == 2:
        jat = data_t()
        jat.ts = 456
        print(f"Hello, World!, ts is {jat.ts}")
    else:
        print("Goodbye, World!")
    return


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
