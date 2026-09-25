# Ported from Linux tools/testing/selftests/bpf/progs/cgroup_skb_direct_packet_access.c
#
# A cgroup_skb program that records skb->data_end into a global. Upstream
# asserts from userspace that the value is non-zero, proving cgroup_skb
# programs get direct packet access:
#
#     __u32 data_end;
#
#     SEC("cgroup_skb/ingress")
#     int direct_packet_access(struct __sk_buff *skb)
#     {
#             data_end = skb->data_end;
#             return 1;
#     }

from pythonbpf import bpf, section, bpfglobal, compile
from vmlinux import struct___sk_buff
from ctypes import c_int64, c_uint32


@bpf
@bpfglobal
def data_end() -> c_uint32:
    return c_uint32(0)


@bpf
@section("cgroup_skb/ingress")
def direct_packet_access(skb: struct___sk_buff) -> c_int64:
    global data_end
    data_end = skb.data_end
    return c_int64(1)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
