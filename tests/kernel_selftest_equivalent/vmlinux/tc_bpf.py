# Ported from Linux tools/testing/selftests/bpf/progs/test_tc_bpf.c
#
# `cls` is a dummy classifier for the TC-BPF API test. `pkt_ptr` is the one
# that matters: it derives a packet pointer from skb->data, bounds-checks it
# against skb->data_end, and is loaded without CAP_SYS_ADMIN/CAP_PERFMON to
# prove direct packet access works for a plain tcx program. Upstream:
#
#     struct iphdr *iph = (void *)(long)skb->data + sizeof(struct ethhdr);
#
#     if ((long)(iph + 1) > (long)skb->data_end)
#             return 1;
#     return 0;
#
# sizeof(struct ethhdr) + sizeof(struct iphdr) is 14 + 20 = 34.

from pythonbpf import bpf, section, bpfglobal, compile
from vmlinux import struct___sk_buff
from ctypes import c_void_p, c_int64


@bpf
@section("tc")
def cls(skb: c_void_p) -> c_int64:
    return c_int64(0)


@bpf
@section("tcx/ingress")
def pkt_ptr(skb: struct___sk_buff) -> c_int64:
    data = c_void_p(skb.data)
    data_end = c_void_p(skb.data_end)
    if data + 34 > data_end:
        return c_int64(1)
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
