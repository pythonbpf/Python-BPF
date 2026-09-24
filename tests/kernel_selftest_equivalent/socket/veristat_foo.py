# Ported from Linux tools/testing/selftests/bpf/progs/veristat_foo.c
#
# Three empty socket filters. Upstream exists only to exercise veristat's
# program-name filters, so the bodies are irrelevant and the names are the
# test. Ported for the same reason: three programs, one section, one object.

from pythonbpf import bpf, section, bpfglobal, compile
from ctypes import c_void_p, c_int64


@bpf
@section("socket")
def foo(ctx: c_void_p) -> c_int64:
    return c_int64(0)


@bpf
@section("socket")
def bar(ctx: c_void_p) -> c_int64:
    return c_int64(0)


@bpf
@section("socket")
def buz(ctx: c_void_p) -> c_int64:
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
