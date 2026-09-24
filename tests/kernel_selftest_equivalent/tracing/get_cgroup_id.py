# Ported from Linux tools/testing/selftests/bpf/progs/get_cgroup_id_kern.c
#
# Upstream records the cgroup id of a process whose pid matches one the
# userspace half of the test set beforehand:
#
#     __u64 cg_id;
#     __u64 expected_pid;
#
#     SEC("tracepoint/syscalls/sys_enter_nanosleep")
#     int trace(void *ctx)
#     {
#             __u32 pid = bpf_get_current_pid_tgid();
#
#             if (expected_pid == pid)
#                     cg_id = bpf_get_current_cgroup_id();
#
#             return 0;
#     }
#
# Both file-scope variables are @bpfglobal scalars, so the userspace half reads
# `cg_id` back out of the object's .bss exactly as the kernel's driver does.

from pythonbpf import bpf, section, bpfglobal, compile
from pythonbpf.helper import pid, get_current_cgroup_id
from ctypes import c_void_p, c_int64, c_uint64


@bpf
@bpfglobal
def cg_id() -> c_uint64:
    return c_uint64(0)


@bpf
@bpfglobal
def expected_pid() -> c_uint64:
    return c_uint64(0)


@bpf
@section("tracepoint/syscalls/sys_enter_nanosleep")
def trace(ctx: c_void_p) -> c_int64:
    global cg_id
    if expected_pid == pid():
        cg_id = get_current_cgroup_id()
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
