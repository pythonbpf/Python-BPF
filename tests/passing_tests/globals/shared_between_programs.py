# The test_autoattach.c shape: two programs on different attach points writing
# flags into shared global state. Both write the same section's globals.
from pythonbpf import bpf, section, bpfglobal, compile
from ctypes import c_void_p, c_int64, c_uint64


@bpf
@bpfglobal
def prog1_called() -> c_uint64:
    return c_uint64(0)


@bpf
@bpfglobal
def prog2_called() -> c_uint64:
    return c_uint64(0)


@bpf
@section("raw_tp/sys_enter")
def prog1(ctx: c_void_p) -> c_int64:
    global prog1_called
    prog1_called = 1
    return c_int64(0)


@bpf
@section("raw_tp/sys_exit")
def prog2(ctx: c_void_p) -> c_int64:
    global prog2_called
    prog2_called = 1
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
