from pythonbpf import bpf, section, bpfglobal, compile, struct
from ctypes import c_void_p, c_int64, c_uint32, c_uint64
from pythonbpf.helper import smp_processor_id, ktime


@bpf
@struct
class cpu_event_t:
    cpu_id: c_uint32
    timestamp: c_uint64


@bpf
@section("tracepoint/syscalls/sys_enter_execve")
def trace_with_cpu(ctx: c_void_p) -> c_int64:
    """Test bpf_get_smp_processor_id helper function"""

    # Get the current CPU ID
    cpu = smp_processor_id()

    # Print it
    print(f"Running on CPU {cpu}")

    # Use it in a struct
    event = cpu_event_t()
    event.cpu_id = smp_processor_id()
    event.timestamp = ktime()

    print(f"Event on CPU {event.cpu_id} at time {event.timestamp}")

    return 0


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
