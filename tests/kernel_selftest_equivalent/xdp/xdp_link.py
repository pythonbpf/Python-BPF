# Ported from Linux tools/testing/selftests/bpf/progs/test_xdp_link.c
#
# One XDP and one TC handler in the same object. Upstream attaches the XDP
# one through bpf_link and checks that legacy netlink attach of the same
# program is refused while the link exists.

from pythonbpf import bpf, section, bpfglobal, compile
from ctypes import c_void_p, c_int64


@bpf
@section("xdp")
def xdp_handler(xdp: c_void_p) -> c_int64:
    return c_int64(0)


@bpf
@section("tc")
def tc_handler(skb: c_void_p) -> c_int64:
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
