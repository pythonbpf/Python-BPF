# Ported from Linux tools/testing/selftests/bpf/progs/test_perf_link.c
#
# A perf_event program that counts how often it runs. Upstream attaches it
# through a perf_event bpf_link and checks `run_cnt` moved:
#
#     int run_cnt = 0;
#
#     SEC("perf_event")
#     int handler(struct pt_regs *ctx)
#     {
#             __sync_fetch_and_add(&run_cnt, 1);
#             return 0;
#     }
#
# WORKAROUND(atomics): the upstream increment is atomic. PythonBPF has no
# atomic operations, so this is a plain read-modify-write of the global.
# Replace with the atomic form once atomics land; grep for WORKAROUND(atomics).

from pythonbpf import bpf, section, bpfglobal, compile
from ctypes import c_void_p, c_int64, c_int32


@bpf
@bpfglobal
def run_cnt() -> c_int32:
    return c_int32(0)


@bpf
@section("perf_event")
def handler(ctx: c_void_p) -> c_int64:
    global run_cnt
    run_cnt += 1  # WORKAROUND(atomics): __sync_fetch_and_add(&run_cnt, 1)
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
