# Mirrors tests/c-form/signedness.bpf.c; the IR clang emits for that file is
# the specification (see tests/test_signedness_ir.py for the ops asserted).
from pythonbpf import bpf, section, bpfglobal, compile
from ctypes import c_void_p, c_int64, c_int32, c_uint32


@bpf
@bpfglobal
def u32_max() -> c_uint32:
    return c_uint32(0xFFFFFFFF)


@bpf
@bpfglobal
def s32_neg() -> c_int32:
    return c_int32(-1)


@bpf
@bpfglobal
def shr_unsigned() -> c_uint32:
    return c_uint32(0)


@bpf
@bpfglobal
def shr_signed() -> c_int32:
    return c_int32(0)


@bpf
@section("tracepoint/raw_syscalls/sys_enter")
def prog(ctx: c_void_p) -> c_int64:
    global shr_unsigned, shr_signed
    # u32 >> 4 shifts zeros in (lshr): 0x0FFFFFFF
    shr_unsigned = u32_max >> 4
    # s32 >> 4 shifts the sign in (ashr): -1 stays -1
    shr_signed = s32_neg >> 4
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
