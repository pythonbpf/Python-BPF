# Ported from Linux tools/testing/selftests/bpf/progs/test_tracepoint.c
#
# Upstream is a bare handler on sched/sched_switch, used to prove the program
# attaches to a non-syscall tracepoint. Kept faithful: the point is the
# attachment surface, not the body.
#
# Upstream declares the tracepoint argument layout as a struct taken from
# /sys/kernel/tracing/events/sched/sched_switch/format. PythonBPF does not read
# tracepoint formats, so the context stays opaque.

from pythonbpf import bpf, section, bpfglobal, compile
from ctypes import c_void_p, c_int64


@bpf
@section("tracepoint/sched/sched_switch")
def oncpu(ctx: c_void_p) -> c_int64:
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
