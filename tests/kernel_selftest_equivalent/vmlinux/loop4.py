# Ported from Linux tools/testing/selftests/bpf/progs/loop4.c
#
# A verifier-scale test (prog_tests/bpf_verif_scale.c, test_verif_scale_loop4):
# a 20-iteration loop whose body branches on a context field, so the verifier
# sees 2^20 paths unless it prunes states. Upstream:
#
#     SEC("socket")
#     int combinations(volatile struct __sk_buff* skb)
#     {
#             int ret = 0, i;
#
#             __pragma_loop_no_unroll
#             for (i = 0; i < 20; i++)
#                     if (skb->len)
#                             ret |= 1 << i;
#             return ret;
#     }
#
# NOTE: this port does not test what upstream tests. `volatile` and the
# no-unroll pragma have no PythonBPF spelling, so skb->len is loaded once and
# LLVM fully unrolls the loop (97 instructions against upstream's 14): the
# verifier walks straight-line code instead of pruning states across a loop.
# Clang does the same to the C with `volatile` and the pragma removed. Revisit
# when volatile reads land.

from pythonbpf import bpf, section, bpfglobal, compile
from vmlinux import struct___sk_buff
from ctypes import c_int32


@bpf
@section("socket")
def combinations(skb: struct___sk_buff) -> c_int32:
    ret: c_int32 = 0
    for i in range(20):
        if skb.len:
            ret |= 1 << i
    return ret


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
