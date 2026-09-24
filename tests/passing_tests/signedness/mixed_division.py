# Mirrors tests/c-form/signedness.bpf.c; the IR clang emits for that file is
# the specification (see tests/test_signedness_ir.py for the ops asserted).
from pythonbpf import bpf, section, bpfglobal, compile
from ctypes import c_void_p, c_int64, c_int32, c_uint32


@bpf
@bpfglobal
def u32_ten() -> c_uint32:
    return c_uint32(10)


@bpf
@bpfglobal
def s32_neg2() -> c_int32:
    return c_int32(-2)


@bpf
@bpfglobal
def mixed_div() -> c_uint32:
    return c_uint32(0)


@bpf
@bpfglobal
def mixed_mod() -> c_uint32:
    return c_uint32(0)


@bpf
@section("tracepoint/raw_syscalls/sys_enter")
def prog(ctx: c_void_p) -> c_int64:
    global mixed_div, mixed_mod
    # u32 / s32: the usual arithmetic conversions make both u32, so this is an
    # unsigned division: 10 / 0xFFFFFFFE == 0, not -5
    mixed_div = u32_ten / s32_neg2
    mixed_mod = u32_ten % s32_neg2
    # both signed: an ordinary signed division
    a = c_int32(-7)
    b = c_int32(2)
    q = a / b
    return c_int64(q)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
