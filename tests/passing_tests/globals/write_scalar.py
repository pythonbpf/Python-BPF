# The get_cgroup_id_kern.c shape from the kernel selftests: read one global,
# write another, gated on a pid check. Writes require Python's own `global`
# statement and compile to `store i64 %v, ptr @cg_id`.
from pythonbpf import bpf, section, bpfglobal, compile
from pythonbpf.helper import pid, get_current_cgroup_id
from ctypes import c_void_p, c_int64, c_uint64


@bpf
@bpfglobal
def expected_pid() -> c_uint64:
    return c_uint64(0)


@bpf
@bpfglobal
def cg_id() -> c_uint64:
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
