# Name-resolution order under collision with vmlinux enum constants:
# local wins over global wins over vmlinux, consistently in expressions,
# f-strings, and returns.
#
# clang's take on the same collisions (tests/c-form): a local shadowing an
# enum constant is legal and wins; a file-scope variable colliding with one is
# a hard error. PythonBPF follows Python's rebinding semantics instead for the
# global case -- the @bpfglobal wins -- and logs a compile-time warning so the
# shadowing is never silent.
# XDP_ABORTED's import is load-bearing despite being "unused": it is what
# registers the enum with the compiler, so the local below has something to
# shadow. Python-level unused is the point.
from vmlinux import XDP_ABORTED, XDP_TX  # noqa: F401
from pythonbpf import bpf, section, bpfglobal, compile
from ctypes import c_void_p, c_int64, c_uint64


# Shadows the vmlinux enum constant XDP_TX (warns at compile time; reads of
# XDP_TX below resolve to this global, value 77, not the enum value 3).
@bpf
@bpfglobal
def XDP_TX() -> c_uint64:  # noqa: F811 -- the collision is the test
    return c_uint64(77)


@bpf
@section("tracepoint/raw_syscalls/sys_enter")
def prog(ctx: c_void_p) -> c_int64:
    XDP_ABORTED = 55  # noqa: F811 -- local shadows the enum (value 0)
    x = XDP_ABORTED + XDP_TX
    print(f"local {XDP_ABORTED} global {XDP_TX}")
    return c_int64(x)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
