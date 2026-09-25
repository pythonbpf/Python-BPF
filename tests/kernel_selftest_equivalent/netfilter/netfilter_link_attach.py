# Ported from Linux tools/testing/selftests/bpf/progs/test_netfilter_link_attach.c
#
# A netfilter program that accepts everything (NF_ACCEPT is 1). Upstream
# attaches it with every combination of protocol family, hook and priority
# and checks which the kernel rejects.

from pythonbpf import bpf, section, bpfglobal, compile
from ctypes import c_void_p, c_int64


@bpf
@section("netfilter")
def nf_link_attach_test(ctx: c_void_p) -> c_int64:
    return c_int64(1)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
