# Ported from Linux tools/testing/selftests/bpf/progs/cgroup_mprog.c
#
# Four identical cgroup/getsockopt programs. Upstream attaches them in
# various orders with BPF_F_BEFORE/BPF_F_AFTER and checks the resulting
# multi-prog chain; the bodies only need to exist and return "allow".

from pythonbpf import bpf, section, bpfglobal, compile
from ctypes import c_void_p, c_int64


@bpf
@section("cgroup/getsockopt")
def getsockopt_1(ctx: c_void_p) -> c_int64:
    return c_int64(1)


@bpf
@section("cgroup/getsockopt")
def getsockopt_2(ctx: c_void_p) -> c_int64:
    return c_int64(1)


@bpf
@section("cgroup/getsockopt")
def getsockopt_3(ctx: c_void_p) -> c_int64:
    return c_int64(1)


@bpf
@section("cgroup/getsockopt")
def getsockopt_4(ctx: c_void_p) -> c_int64:
    return c_int64(1)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
