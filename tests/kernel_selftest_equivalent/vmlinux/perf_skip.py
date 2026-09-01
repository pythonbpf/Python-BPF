# Ported from Linux tools/testing/selftests/bpf/progs/test_perf_skip.c
#
# A perf_event program that reports whether the sampled instruction pointer is
# the one userspace asked about. Upstream:
#
#     uintptr_t ip;
#
#     SEC("perf_event")
#     int handler(struct bpf_perf_event_data *data)
#     {
#             /* Skip events that have the correct ip. */
#             return ip != PT_REGS_IP(&data->regs);
#     }
#
# ROADMAP: this is a strict expected failure. `ctx.regs.ip` is two levels of
# struct field access, and PythonBPF supports only one --
# `_allocate_for_attribute` in allocation_pass.py bails out unless the
# attribute's base is a plain Name. One level works today: `ctx.sample_period`
# on this same context compiles fine.
#
# Note the failure surfaces as `SyntaxError: Undefined variable actual`, naming
# the assignment target rather than the nested access that caused it -- the
# allocation pass declines to allocate and logs at debug level, then the
# expression pass fails later on the missing symbol. Worth improving alongside
# nested access support.
#
# WORKAROUND(globals): upstream uses `uintptr_t ip` to receive the address to
# compare against. PythonBPF has no global variable support yet, so it becomes a
# one-entry HashMap keyed by 0. Replace with a real global once they land.

from pythonbpf import bpf, map, section, bpfglobal, compile
from pythonbpf.maps import HashMap
from vmlinux import struct_bpf_perf_event_data
from ctypes import c_int64, c_int32, c_uint64


# WORKAROUND(globals): stands in for `uintptr_t ip;`
@bpf
@map
def expected_ip() -> HashMap:
    return HashMap(key=c_int32, value=c_uint64, max_entries=1)


@bpf
@section("perf_event")
def handler(ctx: struct_bpf_perf_event_data) -> c_int64:
    want = expected_ip.lookup(0)
    actual = ctx.regs.ip
    if want == actual:
        return c_int64(0)
    return c_int64(1)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
