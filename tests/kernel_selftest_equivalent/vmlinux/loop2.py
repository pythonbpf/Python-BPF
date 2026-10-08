# Ported from Linux tools/testing/selftests/bpf/progs/loop2.c
#
# A verifier-scale test (prog_tests/bpf_verif_scale.c, test_verif_scale_loop2):
# an unbounded-looking `while (true)` that only terminates through a `break`,
# with a step that depends on the context. Upstream:
#
#     SEC("raw_tracepoint/consume_skb")
#     int while_true(volatile struct pt_regs* ctx)
#     {
#             int i = 0;
#
#             while (true) {
#                     if (PT_REGS_RC(ctx) & 1)
#                             i += 3;
#                     else
#                             i += 7;
#                     if (i > 40)
#                             break;
#             }
#
#             return i;
#     }
#
# PT_REGS_RC is ctx->ax on x86.
#
# NOTE: this port does not test what upstream tests. `volatile` has no
# PythonBPF spelling yet, so ctx->ax is loaded once and LLVM sees that both
# paths end at 42 (3 * 14 and 7 * 6): the program compiles to `return 42` and
# the verifier never sees a loop. Clang does the same to the C with `volatile`
# removed. Revisit when volatile reads land.

from pythonbpf import bpf, section, bpfglobal, compile
from vmlinux import struct_pt_regs
from ctypes import c_int32


@bpf
@section("raw_tracepoint/consume_skb")
def while_true(ctx: struct_pt_regs) -> c_int32:
    i: c_int32 = 0
    while True:
        if ctx.ax & 1:
            i += 3
        else:
            i += 7
        if i > 40:
            break
    return i


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
