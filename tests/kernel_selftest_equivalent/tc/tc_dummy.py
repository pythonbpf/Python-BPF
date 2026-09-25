# Ported from Linux tools/testing/selftests/bpf/progs/tc_dummy.c
#
# A classifier that returns TC_ACT_OK for everything. Upstream is the fixture
# behind the tc_links and tc_opts attach-order tests.

from pythonbpf import bpf, section, bpfglobal, compile
from ctypes import c_void_p, c_int64


@bpf
@section("tc")
def entry(skb: c_void_p) -> c_int64:
    return c_int64(1)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
