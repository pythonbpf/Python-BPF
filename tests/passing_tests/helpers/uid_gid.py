from pythonbpf import bpf, section, bpfglobal, compile
from ctypes import c_void_p, c_int64
from pythonbpf.helper import uid, pid


@bpf
@section("tracepoint/syscalls/sys_enter_execve")
def filter_by_user(ctx: c_void_p) -> c_int64:
    """Filter events by specific user ID"""

    current_uid = uid()

    # Only trace root user (UID 0)
    if current_uid == 0:
        process_id = pid()
        print(f"Root process {process_id} executed")

    # Or trace specific user (e.g., UID 1000)
    if current_uid == 1002:
        print("User 1002 executed something")

    return 0


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
