# Mirrors tests/c-form/signedness.bpf.c; the IR clang emits for that file is
# the specification (see tests/test_signedness_ir.py for the ops asserted).
from pythonbpf import bpf, section, bpfglobal, compile
from ctypes import c_void_p, c_int64, c_int32, c_uint64


@bpf
@bpfglobal
def s32_neg() -> c_int32:
    return c_int32(-1)


@bpf
@bpfglobal
def widen_signed() -> c_uint64:
    return c_uint64(0)


@bpf
@section("tracepoint/raw_syscalls/sys_enter")
def prog(ctx: c_void_p) -> c_int64:
    global widen_signed
    # u64 = s32: -1 sign-extends to 0xffffffffffffffff (sext), as in C and ctypes
    widen_signed = s32_neg
    x = c_int32(-5)
    y = c_int64(x)
    return y


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
