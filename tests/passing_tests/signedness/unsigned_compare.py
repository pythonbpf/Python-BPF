# Mirrors tests/c-form/signedness.bpf.c; the IR clang emits for that file is
# the specification (see tests/test_signedness_ir.py for the ops asserted).
from pythonbpf import bpf, section, bpfglobal, compile
from ctypes import c_void_p, c_int64, c_uint64


@bpf
@bpfglobal
def u64_ten() -> c_uint64:
    return c_uint64(10)


@bpf
@bpfglobal
def s64_neg() -> c_int64:
    return c_int64(-1)


@bpf
@bpfglobal
def unsigned_cmp() -> c_uint64:
    return c_uint64(0)


@bpf
@bpfglobal
def signed_cmp() -> c_uint64:
    return c_uint64(0)


@bpf
@section("tracepoint/raw_syscalls/sys_enter")
def prog(ctx: c_void_p) -> c_int64:
    global unsigned_cmp, signed_cmp
    # u64 > s64: the comparison happens in u64, so -1 is the largest value and
    # 10 > -1 is false (icmp ugt)
    if u64_ten > s64_neg:
        unsigned_cmp = 1
    # s64 > s64 stays a signed comparison (icmp sgt)
    a = c_int64(10)
    if a > s64_neg:
        signed_cmp = 1
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
