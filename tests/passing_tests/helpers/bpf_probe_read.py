from pythonbpf import bpf, section, bpfglobal, compile, struct
from ctypes import c_void_p, c_int64, c_uint64, c_uint32
from pythonbpf.helper import probe_read


@bpf
@struct
class data_t:
    pid: c_uint32
    value: c_uint64


@bpf
@section("tracepoint/syscalls/sys_enter_execve")
def test_probe_read(ctx: c_void_p) -> c_int64:
    """Test bpf_probe_read helper function"""
    data = data_t()
    probe_read(data.value, 8, ctx)
    probe_read(data.pid, 4, ctx)
    return 0


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
