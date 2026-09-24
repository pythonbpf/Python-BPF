# Ported from Linux tools/testing/selftests/bpf/progs/test_autoattach.c
#
# Two programs on different raw tracepoints, each recording that it ran. The
# upstream test asserts both fired after bpf_object__attach_skeleton():
#
#     bool prog1_called = false;
#     bool prog2_called = false;
#
#     SEC("raw_tp/sys_enter")
#     int prog1(const void *ctx)
#     {
#             prog1_called = true;
#             return 0;
#     }
#
#     SEC("raw_tp/sys_exit")
#     int prog2(const void *ctx)
#     {
#             prog2_called = true;
#             return 0;
#     }
#
# Both flags are @bpfglobal scalars shared by the two programs in one object.
# They are c_uint64 rather than bool because integer scalars are the only
# global type today; the driver-side check is the same either way.

from pythonbpf import bpf, section, bpfglobal, compile
from ctypes import c_void_p, c_int64, c_uint64


@bpf
@bpfglobal
def prog1_called() -> c_uint64:
    return c_uint64(0)


@bpf
@bpfglobal
def prog2_called() -> c_uint64:
    return c_uint64(0)


@bpf
@section("raw_tp/sys_enter")
def prog1(ctx: c_void_p) -> c_int64:
    global prog1_called
    prog1_called = 1
    return c_int64(0)


@bpf
@section("raw_tp/sys_exit")
def prog2(ctx: c_void_p) -> c_int64:
    global prog2_called
    prog2_called = 1
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
