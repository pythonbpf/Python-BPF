# Ported from Linux tools/testing/selftests/bpf/progs/uprobe_multi_usdt.c
#
# The USDT flavour of the multi-uprobe counter. Upstream attaches it to a
# USDT probe in the test binary and asserts on `count` from userspace.

from pythonbpf import bpf, section, bpfglobal, compile
from ctypes import c_void_p, c_int64, c_int32


@bpf
@bpfglobal
def count() -> c_int32:
    return c_int32(0)


@bpf
@section("usdt")
def usdt0(ctx: c_void_p) -> c_int64:
    global count
    count += 1
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
