# The canonical selftest idiom: a per-object event counter. `counter += 1`
# desugars to load/add/store on the global; the local augassign checks the
# desugaring path for stack variables too.
from pythonbpf import bpf, section, bpfglobal, compile
from ctypes import c_void_p, c_int64, c_uint64


@bpf
@bpfglobal
def counter() -> c_uint64:
    return c_uint64(0)


@bpf
@section("tracepoint/raw_syscalls/sys_enter")
def tick(ctx: c_void_p) -> c_int64:
    global counter
    counter += 1
    x = 5
    x += 2
    print(f"count {counter} x {x}")
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
