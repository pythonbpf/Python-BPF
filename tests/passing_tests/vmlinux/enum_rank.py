# An enum constant has C's `int` type, whatever the enum's underlying type is
# (clang: `XDP_PASS - k` is `sub nsw i32` + sext; a *variable* of the enum
# type would be u32). So `XDP_PASS - k` with an unsigned k is a u32 operation,
# the same rank a literal that fits in int gets.
from ctypes import c_int64, c_uint32, c_void_p
from pythonbpf import bpf, section, bpfglobal, compile
from vmlinux import XDP_PASS


@bpf
@section("tracepoint/raw_syscalls/sys_enter")
def prog(ctx: c_void_p) -> c_int64:
    k = c_uint32(3)
    d = XDP_PASS - k
    return c_int64(d)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
