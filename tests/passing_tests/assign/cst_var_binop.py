from pythonbpf import bpf, section, bpfglobal, compile
from ctypes import c_void_p, c_int64


@bpf
@section("tracepoint/syscalls/sys_enter_execve")
def hello_world(ctx: c_void_p) -> c_int64:
    x = 1
    print(f"Initial x: {x}")
    a = 20
    x = a
    print(f"Updated x with a: {x}")
    x = (x + x) * 3
    if x == 2:
        print("Hello, World!")
    else:
        print(f"Goodbye, World! {x}")
    return


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
