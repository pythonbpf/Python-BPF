# Ported from Linux tools/testing/selftests/bpf/progs/kprobe_multi_empty.c
#
# An empty kprobe.multi program. Upstream attaches it to every function in
# the kernel's available_filter_functions list to benchmark attach time.

from pythonbpf import bpf, section, bpfglobal, compile
from ctypes import c_void_p, c_int64


@bpf
@section("kprobe.multi/")
def test_kprobe_empty(ctx: c_void_p) -> c_int64:
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
