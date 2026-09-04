# Mirrors tests/c-form/signedness.bpf.c; the IR clang emits for that file is
# the specification (see tests/test_signedness_ir.py for the ops asserted).
from pythonbpf import bpf, section, bpfglobal, compile
from ctypes import c_void_p, c_int64, c_uint32


@bpf
@bpfglobal
def u32_ten() -> c_uint32:
    return c_uint32(10)


@bpf
@bpfglobal
def by_literal() -> c_uint32:
    return c_uint32(0)


@bpf
@bpfglobal
def wide() -> c_int64:
    return c_int64(0)


@bpf
@section("tracepoint/raw_syscalls/sys_enter")
def prog(ctx: c_void_p) -> c_int64:
    global by_literal, wide
    # A literal has C's `int` type, so u32 / -2 promotes to u32: an unsigned
    # division by 0xFFFFFFFE (udiv), exactly as `u32_ten / -2` in C
    by_literal = u32_ten / -2
    # A literal that does not fit in int is a `long long`; the sum is 64-bit
    wide = 5000000000 + 1
    # i32-ranked literals are still 64-bit slots for an undeclared local
    small = 7 * 6
    return c_int64(small)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
