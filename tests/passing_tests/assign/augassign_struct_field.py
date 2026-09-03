# Augmented assignment to a struct field: one GEP, load, op, store. Also a
# non-add operator and a sub-64-bit field, which exercises the narrow-on-store
# path of the direct lowering.
from pythonbpf import bpf, section, bpfglobal, compile, struct
from ctypes import c_void_p, c_int64, c_uint64, c_uint32


@bpf
@struct
class data_t:
    pid: c_uint64
    hits: c_uint32


@bpf
@section("tracepoint/raw_syscalls/sys_enter")
def prog(ctx: c_void_p) -> c_int64:
    x = 5
    x -= 1
    dat = data_t()
    dat.pid = 10
    dat.pid += x
    dat.hits = 1
    dat.hits <<= 2
    print(f"pid {dat.pid} hits {dat.hits} x {x}")
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
