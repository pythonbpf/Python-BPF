# Section placement needs no marker: a zero initializer lands the global in
# .bss, a non-zero one in .data, decided by LLVM exactly as for C. Mixed
# widths and signedness also exercise the BTF basic-type emission.
from pythonbpf import bpf, section, bpfglobal, compile
from ctypes import c_void_p, c_int64, c_uint64, c_int32


@bpf
@bpfglobal
def zeroed() -> c_uint64:
    return c_uint64(0)


@bpf
@bpfglobal
def preset() -> c_int32:
    return c_int32(42)


@bpf
@section("tracepoint/raw_syscalls/sys_enter")
def prog(ctx: c_void_p) -> c_int64:
    global zeroed
    zeroed = preset + 1
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
