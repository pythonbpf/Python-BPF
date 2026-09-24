# Ported from Linux tools/testing/selftests/bpf/progs/xdp_dummy.c
#
# Two XDP programs that pass every packet. Upstream is the fixture that a
# dozen prog_tests attach and detach to exercise XDP link plumbing; the
# second program's odd name is deliberate, it is what the kallsyms test looks
# for.

from pythonbpf import bpf, section, bpfglobal, compile
from pythonbpf.helper import XDP_PASS
from ctypes import c_void_p, c_int64


@bpf
@section("xdp")
def xdp_dummy_prog(ctx: c_void_p) -> c_int64:
    return XDP_PASS


@bpf
@section("xdp")
def __x64_sys_nop(ctx: c_void_p) -> c_int64:
    return XDP_PASS


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
