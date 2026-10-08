# Ported from Linux tools/testing/selftests/bpf/progs/loop5.c
#
# A verifier-scale test (prog_tests/bpf_verif_scale.c, test_verif_scale_loop5):
# `while (1)` with several exits, where whether an exit is ever reached depends
# on a context field. Upstream:
#
#     SEC("socket")
#     int while_true(volatile struct __sk_buff* skb)
#     {
#             int i = 0;
#
#             while (1) {
#                     if (skb->len)
#                             i += 3;
#                     else
#                             i += 7;
#                     if (i == 9)
#                             break;
#                     barrier();
#                     if (i == 10)
#                             break;
#                     barrier();
#                     if (i == 13)
#                             break;
#                     barrier();
#                     if (i == 14)
#                             break;
#             }
#             return i;
#     }
#
# barrier() is an empty `asm volatile("" ::: "memory")` that stops clang from
# merging the exits; PythonBPF has no compiler barrier, and LLVM merges the four
# exits into one bitmask test. The loop survives, so the verifier still has to
# prove it terminates.

from pythonbpf import bpf, section, bpfglobal, compile
from vmlinux import struct___sk_buff
from ctypes import c_int32


@bpf
@section("socket")
def while_true(skb: struct___sk_buff) -> c_int32:
    i: c_int32 = 0
    while True:
        if skb.len:
            i += 3
        else:
            i += 7
        if i == 9:
            break
        if i == 10:
            break
        if i == 13:
            break
        if i == 14:
            break
    return i


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
