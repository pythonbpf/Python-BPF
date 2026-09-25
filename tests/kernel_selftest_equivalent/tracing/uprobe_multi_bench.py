# Ported from Linux tools/testing/selftests/bpf/progs/uprobe_multi_bench.c
#
# Count how many times the multi-uprobe fires. Upstream attaches it to
# thousands of uprobe_multi_func_* symbols and reads `count` back:
#
#     int count;
#
#     SEC("uprobe.multi/./uprobe_multi:uprobe_multi_func_*")
#     int uprobe_bench(struct pt_regs *ctx)
#     {
#             count++;
#             return 0;
#     }

from pythonbpf import bpf, section, bpfglobal, compile
from ctypes import c_void_p, c_int64, c_int32


@bpf
@bpfglobal
def count() -> c_int32:
    return c_int32(0)


@bpf
@section("uprobe.multi/./uprobe_multi:uprobe_multi_func_*")
def uprobe_bench(ctx: c_void_p) -> c_int64:
    global count
    count += 1
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
