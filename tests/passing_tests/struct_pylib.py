"""
Test struct values in HashMap.

This example stores a struct in a HashMap and reads it back,
testing the new set_value_struct() functionality in pylibbpf.
"""

from pythonbpf import bpf, map, struct, section, bpfglobal, BPF
from pythonbpf.helper import ktime, smp_processor_id, pid, comm
from pythonbpf.maps import HashMap
from ctypes import c_void_p, c_int64, c_uint32, c_uint64
import time
import os


@bpf
@struct
class task_info:
    pid: c_uint64
    timestamp: c_uint64
    comm: str(16)


@bpf
@map
def cpu_tasks() -> HashMap:
    return HashMap(key=c_uint32, value=task_info, max_entries=256)


@bpf
@section("tracepoint/sched/sched_switch")
def trace_sched_switch(ctx: c_void_p) -> c_int64:
    cpu = smp_processor_id()

    # Create task info struct
    info = task_info()
    info.pid = pid()
    info.timestamp = ktime()
    comm(info.comm)

    # Store in map
    cpu_tasks.update(cpu, info)

    return 0  # type: ignore


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


# Compile and load
b = BPF()
b.load()
b.attach_all()

print("Testing HashMap with Struct Values")

cpu_map = b["cpu_tasks"]
cpu_map.set_value_struct("task_info")  # Enable struct deserialization

print("Listening for context switches.. .\n")

num_cpus = os.cpu_count() or 16

try:
    while True:
        time.sleep(1)

        print(f"--- Snapshot at {time.strftime('%H:%M:%S')} ---")

        for cpu in range(num_cpus):
            try:
                info = cpu_map.lookup(cpu)

                if info:
                    comm_str = (
                        bytes(info.comm).decode("utf-8", errors="ignore").rstrip("\x00")
                    )
                    ts_sec = info.timestamp / 1e9

                    print(
                        f"  CPU {cpu}: PID={info.pid}, comm={comm_str}, ts={ts_sec:.3f}s"
                    )
            except KeyError:
                # No data for this CPU yet
                pass

        print()

except KeyboardInterrupt:
    print("\nStopped")
