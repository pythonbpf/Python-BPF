import logging

from pythonbpf import compile, bpf, section, bpfglobal
from ctypes import c_void_p, c_int64


@bpf
@section("sometag1")
def sometag(ctx: c_void_p) -> c_int64:
    a = 1 - 1
    return c_int64(a)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile(loglevel=logging.INFO)
