# Ported from Linux tools/testing/selftests/bpf/progs/loop1.c
#
# A verifier-scale test (prog_tests/bpf_verif_scale.c, test_verif_scale_loop1):
# two nested bounded loops, the inner one bounded by the outer counter, so the
# verifier has to prove termination of ~45000 iterations. Upstream:
#
#     SEC("raw_tracepoint/kfree_skb")
#     int nested_loops(volatile struct pt_regs* ctx)
#     {
#             int i, j, sum = 0, m;
#
#             for (j = 0; j < 300; j++)
#                     for (i = 0; i < j; i++) {
#                             if (j & 1)
#                                     m = PT_REGS_RC(ctx);
#                             else
#                                     m = j;
#                             sum += i * m;
#                     }
#
#             return sum;
#     }
#
# PT_REGS_RC is ctx->ax on x86. The `volatile` on ctx, which forces a reload of
# ctx->ax on every iteration, has no PythonBPF spelling yet; without it LLVM may
# hoist the load out of the loops. Here it does not (the load sits in a branch),
# and the object keeps upstream's nested-loop shape: 20 instructions against
# clang's 21, with 64-bit loop counters where C's are 32-bit.

from pythonbpf import bpf, section, bpfglobal, compile
from vmlinux import struct_pt_regs
from ctypes import c_int32


@bpf
@section("raw_tracepoint/kfree_skb")
def nested_loops(ctx: struct_pt_regs) -> c_int32:
    total: c_int32 = 0
    m: c_int32 = 0
    for j in range(300):
        for i in range(j):
            if j & 1:
                m = ctx.ax
            else:
                m = j
            total += i * m
    return total


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
