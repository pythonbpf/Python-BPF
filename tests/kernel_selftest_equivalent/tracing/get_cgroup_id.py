# Ported from Linux tools/testing/selftests/bpf/progs/get_cgroup_id_kern.c
#
# Upstream records the cgroup id of a process whose pid matches one the
# userspace half of the test set beforehand.
#
# WORKAROUND(globals): upstream uses the file-scope variables `cg_id` and
# `expected_pid` to pass values in and out. PythonBPF has no global variable
# support yet, so each becomes a one-entry HashMap keyed by 0. Replace these
# with real globals once they land; grep for WORKAROUND(globals).

from pythonbpf import bpf, map, section, bpfglobal, compile
from pythonbpf.maps import HashMap
from pythonbpf.helper import pid, get_current_cgroup_id
from ctypes import c_void_p, c_int64, c_int32, c_uint64


# WORKAROUND(globals): stands in for `__u64 expected_pid;`
@bpf
@map
def expected_pid() -> HashMap:
    return HashMap(key=c_int32, value=c_uint64, max_entries=1)


# WORKAROUND(globals): stands in for `__u64 cg_id;`
@bpf
@map
def cg_id() -> HashMap:
    return HashMap(key=c_int32, value=c_uint64, max_entries=1)


@bpf
@section("tracepoint/syscalls/sys_enter_nanosleep")
def trace(ctx: c_void_p) -> c_int64:
    process_id = pid()
    want = expected_pid.lookup(0)
    if want == process_id:
        cg_id.update(0, get_current_cgroup_id())
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
