# Ported from Linux tools/testing/selftests/bpf/progs/xdp_tx.c
#
# Bounce every packet back out of the interface it arrived on. Upstream is
# the transmit side of the veth XDP tests.
#
from pythonbpf import bpf, section, bpfglobal, compile
from pythonbpf.helper import XDP_TX
from ctypes import c_void_p, c_int64


@bpf
@section("xdp")
def xdp_tx(xdp: c_void_p) -> c_int64:
    return XDP_TX  # bare, like the C: resolved by the return fast path


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
