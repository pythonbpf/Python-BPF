# Ported from Linux tools/testing/selftests/bpf/progs/test_cgroup_link.c
#
# Two cgroup_skb/egress programs, each counting its own runs. Upstream
# attaches one through a cgroup bpf_link, then swaps in the other with
# bpf_link_update() and checks the right counter moves:
#
#     int calls = 0;
#     int alt_calls = 0;
#
#     SEC("cgroup_skb/egress")
#     int egress(struct __sk_buff *skb)
#     {
#             __sync_fetch_and_add(&calls, 1);
#             return 1;
#     }
#
# WORKAROUND(atomics): the upstream increments are atomic. PythonBPF has no
# atomic operations, so these are plain read-modify-writes of the globals.

from pythonbpf import bpf, section, bpfglobal, compile
from ctypes import c_void_p, c_int64, c_int32


@bpf
@bpfglobal
def calls() -> c_int32:
    return c_int32(0)


@bpf
@bpfglobal
def alt_calls() -> c_int32:
    return c_int32(0)


@bpf
@section("cgroup_skb/egress")
def egress(skb: c_void_p) -> c_int64:
    global calls
    calls += 1  # WORKAROUND(atomics): __sync_fetch_and_add(&calls, 1)
    return c_int64(1)


@bpf
@section("cgroup_skb/egress")
def egress_alt(skb: c_void_p) -> c_int64:
    global alt_calls
    alt_calls += 1  # WORKAROUND(atomics): __sync_fetch_and_add(&alt_calls, 1)
    return c_int64(1)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
