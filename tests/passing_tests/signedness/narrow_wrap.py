# Mirrors tests/c-form/signedness.bpf.c; the IR clang emits for that file is
# the specification (see tests/test_signedness_ir.py for the ops asserted).
from pythonbpf import bpf, section, bpfglobal, compile
from ctypes import c_void_p, c_int64, c_uint32, c_uint64


@bpf
@bpfglobal
def u32_half() -> c_uint32:
    return c_uint32(0x80000000)


@bpf
@bpfglobal
def u32_two() -> c_uint32:
    return c_uint32(2)


@bpf
@bpfglobal
def narrow_wrap() -> c_uint64:
    return c_uint64(0)


@bpf
@section("tracepoint/raw_syscalls/sys_enter")
def prog(ctx: c_void_p) -> c_int64:
    global narrow_wrap
    # u32 * u32 is a u32 multiplication: 0x80000000 * 2 wraps to 0 before the
    # widening to u64 (the LHS never widens the operands)
    narrow_wrap = u32_half * u32_two
    # narrowing truncates: only the low 32 bits of the u64 survive
    small = c_uint32(narrow_wrap)
    return c_int64(small)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
