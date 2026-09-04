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
def widen_unsigned() -> c_int64:
    return c_int64(0)


@bpf
@bpfglobal
def reinterpret() -> c_int32:
    return c_int32(0)


@bpf
@section("tracepoint/raw_syscalls/sys_enter")
def prog(ctx: c_void_p) -> c_int64:
    global widen_unsigned, reinterpret
    # s64 = u32: value-preserving, so 0xFFFFFFFF stays 4294967295 (zext, not sext)
    widen_unsigned = u32_max
    # s32 = u32: same width, the bits are reinterpreted (-1)
    reinterpret = u32_max
    # a local copied from a global takes the global's type: a c_uint32 slot
    also = u32_max
    return c_int64(also)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
