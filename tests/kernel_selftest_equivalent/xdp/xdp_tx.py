# Ported from Linux tools/testing/selftests/bpf/progs/xdp_tx.c
#
# Bounce every packet back out of the interface it arrived on. Upstream is
# the transmit side of the veth XDP tests.
#
# XDP_TX comes from vmlinux because pythonbpf.helper exports only XDP_PASS
# and XDP_DROP; that is why this lives under vmlinux/.

from pythonbpf import bpf, section, bpfglobal, compile
from vmlinux import XDP_TX
from ctypes import c_void_p, c_int64


@bpf
@section("xdp")
def xdp_tx(xdp: c_void_p) -> c_int64:
    return c_int64(XDP_TX)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
