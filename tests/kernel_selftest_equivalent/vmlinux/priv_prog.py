# Ported from Linux tools/testing/selftests/bpf/progs/priv_prog.c
#
# An XDP program that drops everything. Upstream loads it from an
# unprivileged process to check the CAP_BPF/CAP_NET_ADMIN gating; the
# program itself is the smallest privileged-type program there is.

from pythonbpf import bpf, section, bpfglobal, compile
from vmlinux import XDP_DROP
from ctypes import c_void_p, c_int64


@bpf
@section("xdp")
def xdp_prog1(xdp: c_void_p) -> c_int64:
    return XDP_DROP


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
