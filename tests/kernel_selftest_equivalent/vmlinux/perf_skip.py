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
# `ip` is a @bpfglobal the driver sets before attaching; the program only
# reads it, so no `global` statement is needed.
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

from pythonbpf import bpf, section, bpfglobal, compile
from vmlinux import struct_bpf_perf_event_data
from ctypes import c_int64, c_uint64


@bpf
@bpfglobal
def ip() -> c_uint64:
    return c_uint64(0)


@bpf
@section("perf_event")
def handler(ctx: struct_bpf_perf_event_data) -> c_int64:
    actual = ctx.regs.ip
    if ip == actual:
        return c_int64(0)
    return c_int64(1)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
