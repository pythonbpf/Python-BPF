import logging

from pythonbpf import bpf, section, bpfglobal, compile_to_ir
from pythonbpf import compile  # noqa: F401
from vmlinux import TASK_COMM_LEN  # noqa: F401
from vmlinux import struct_trace_event_raw_sys_enter  # noqa: F401

# from vmlinux import struct_uinput_device
# from vmlinux import struct_blk_integrity_iter
from ctypes import c_int64


# Instructions to how to run this program
# 1. Install PythonBPF: pip install pythonbpf
# 2. Run the program: python examples/simple_struct_test.py
# 3. Run the program with sudo: sudo tools/check.sh run examples/simple_struct_test.o
# 4. Attach object file to any network device with something like ./check.sh run examples/simple_struct_test.o tailscale0
# 5. send traffic through the device and observe effects
@bpf
@section("tracepoint/syscalls/sys_enter_execve")
def hello_world(ctx: struct_trace_event_raw_sys_enter) -> c_int64:
    a = 2 + TASK_COMM_LEN + TASK_COMM_LEN
    print(f"Hello, World{TASK_COMM_LEN} and {a}")
    return c_int64(TASK_COMM_LEN)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile_to_ir("simple_struct_test.py", "simple_struct_test.ll", loglevel=logging.DEBUG)
compile()
