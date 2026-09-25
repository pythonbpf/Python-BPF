# Ported from Linux tools/testing/selftests/bpf/progs/test_enable_stats.c
#
# A raw tracepoint program that counts its runs. Upstream enables
# BPF_STATS_RUN_TIME, triggers the program, and checks run_time_ns and
# run_cnt in bpf_prog_info alongside `count`:
#
#     __u64 count = 0;
#
#     SEC("raw_tracepoint/sys_enter")
#     int test_enable_stats(void *ctx)
#     {
#             __sync_fetch_and_add(&count, 1);
#             return 0;
#     }
#
# WORKAROUND(atomics): the upstream increment is atomic. PythonBPF has no
# atomic operations, so this is a plain read-modify-write of the global.

from pythonbpf import bpf, section, bpfglobal, compile
from ctypes import c_void_p, c_int64, c_uint64


@bpf
@bpfglobal
def count() -> c_uint64:
    return c_uint64(0)


@bpf
@section("raw_tracepoint/sys_enter")
def test_enable_stats(ctx: c_void_p) -> c_int64:
    global count
    count += 1  # WORKAROUND(atomics): __sync_fetch_and_add(&count, 1)
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
