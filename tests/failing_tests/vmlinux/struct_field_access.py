import logging

from pythonbpf import bpf, section, bpfglobal, compile_to_ir
from pythonbpf import compile  # noqa: F401
from vmlinux import TASK_COMM_LEN  # noqa: F401
from vmlinux import struct_trace_event_raw_sys_enter  # noqa: F401
from ctypes import c_int64, c_void_p  # noqa: F401


# from vmlinux import struct_uinput_device
# from vmlinux import struct_blk_integrity_iter


@bpf
@section("tracepoint/syscalls/sys_enter_execve")
def hello_world(ctx: struct_trace_event_raw_sys_enter) -> c_int64:
    a = 2 + TASK_COMM_LEN + TASK_COMM_LEN
    b = ctx.id
    print(f"Hello, World{TASK_COMM_LEN} and {a}")
    print(f"This is context field {b}")
    return c_int64(TASK_COMM_LEN + 2)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile_to_ir("struct_field_access.py", "struct_field_access.ll", loglevel=logging.INFO)
# compile()
