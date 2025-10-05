from pythonbpf import compile, bpf, section, bpfglobal
from ctypes import c_void_p, c_int64


@bpf
@section("sometag1")
def sometag(ctx: c_void_p) -> c_int64:
    return c_int64(1 - 1)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
