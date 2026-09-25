# Ported from Linux tools/testing/selftests/bpf/progs/test_link_pinning.c
#
# Two programs, one raw_tp and one tp_btf on the same tracepoint, each
# copying a global set by userspace into a global read by userspace.
# Upstream pins the link, closes every fd, then checks the program still
# fires by bumping `in` and watching `out` follow:
#
#     int in = 0;
#     int out = 0;
#
#     SEC("raw_tp/sys_enter")
#     int raw_tp_prog(const void *ctx)
#     {
#             out = in;
#             return 0;
#     }
#
# `in` is renamed `in_val` because `in` is a Python keyword.

from pythonbpf import bpf, section, bpfglobal, compile
from ctypes import c_void_p, c_int64, c_int32


@bpf
@bpfglobal
def in_val() -> c_int32:
    return c_int32(0)


@bpf
@bpfglobal
def out() -> c_int32:
    return c_int32(0)


@bpf
@section("raw_tp/sys_enter")
def raw_tp_prog(ctx: c_void_p) -> c_int64:
    global out
    out = in_val
    return c_int64(0)


@bpf
@section("tp_btf/sys_enter")
def tp_btf_prog(ctx: c_void_p) -> c_int64:
    global out
    out = in_val
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
