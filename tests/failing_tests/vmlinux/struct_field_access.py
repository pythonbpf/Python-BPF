import logging

from pythonbpf import bpf, section, bpfglobal, compile_to_ir
from pythonbpf import compile  # noqa: F401
from vmlinux import TASK_COMM_LEN  # noqa: F401
from vmlinux import struct_trace_event_raw_sys_enter  # noqa: F401
from ctypes import c_int64, c_int32, c_void_p  # noqa: F401


# from vmlinux import struct_uinput_device
# from vmlinux import struct_blk_integrity_iter


@bpf
@section("tracepoint/syscalls/sys_enter_execve")
def hello_world(ctx: struct_trace_event_raw_sys_enter) -> c_int32:
    b = ctx.id
    print(f"This is context field {b}")
    return c_int32(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile_to_ir("struct_field_access.py", "struct_field_access.ll", loglevel=logging.INFO)
compile()
