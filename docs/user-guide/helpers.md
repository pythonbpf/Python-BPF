# Helper Functions and Utilities

PythonBPF provides helper functions and utilities for BPF programs and userspace code.

```{note}
**Work in Progress:** PythonBPF is under active development. We are constantly adding support for more helpers, kfuncs, and map types. Check back for updates!
```
For comprehensive documentation on BPF helpers, see the [eBPF Helper Functions documentation on ebpf.io](https://ebpf.io/what-is-ebpf/#helper-calls).

## BPF Helper Functions

BPF helper functions are kernel-provided functions that BPF programs can call to interact with the system. PythonBPF exposes these through the `pythonbpf.helper` module.

```python
from pythonbpf.helper import pid, ktime, comm
```

### Process and Task Information

#### pid()

Get the current process ID.

> **Linux Kernel Helper:** `bpf_get_current_pid_tgid()`

```python
from pythonbpf.helper import pid

@bpf
@section("tracepoint/syscalls/sys_enter_open")
def trace_open(ctx: c_void_p) -> c_int64:
    process_id = pid()
    print(f"Process {process_id} opened a file")
    return 0
```

**Returns:** `c_int32` - The process ID of the current task

#### comm()

Get the current process command name.

> **Linux Kernel Helper:** `bpf_get_current_comm()`

**Parameters:**
* `buf` - Buffer to fill with the process command name

**Returns:** `c_int64` - 0 on success, negative on error

#### uid()

Get the current user ID.

> **Linux Kernel Helper:** `bpf_get_current_uid_gid()`

```python
from pythonbpf.helper import uid

@bpf
@section("tracepoint/syscalls/sys_enter_open")
def trace_open(ctx: c_void_p) -> c_int64:
    user_id = uid()
    if user_id == 0:
        print("Root user opened a file")
    return 0
```

**Returns:** `c_int32` - The user ID of the current task

### Time and Timing

#### ktime()

Get the current kernel time in nanoseconds since system boot.

> **Linux Kernel Helper:** `bpf_ktime_get_ns()`

```python
from pythonbpf.helper import ktime

@bpf
@section("tracepoint/syscalls/sys_enter_read")
def measure_latency(ctx: c_void_p) -> c_int64:
    start_time = ktime()
    # Store for later comparison
    return 0
```

**Returns:** `c_int64` - Current time in nanoseconds

**Use cases:**
* Measuring latency
* Timestamping events
* Rate limiting
* Timeout detection

### CPU Information

#### smp_processor_id()

Get the ID of the CPU on which the BPF program is running.

> **Linux Kernel Helper:** `bpf_get_smp_processor_id()`

```python
from pythonbpf.helper import smp_processor_id

@bpf
@section("tracepoint/sched/sched_switch")
def track_cpu(ctx: c_void_p) -> c_int64:
    cpu = smp_processor_id()
    print(f"Running on CPU {cpu}")
    return 0
```

**Returns:** `c_int32` - The current CPU ID

**Use cases:**
* Per-CPU statistics
* Load balancing analysis
* CPU affinity tracking

### Memory Operations

#### probe_read()

Safely read data from kernel memory.

> **Linux Kernel Helper:** `bpf_probe_read()`

```python
from pythonbpf.helper import probe_read

@bpf
def read_kernel_data(ctx: c_void_p) -> c_int64:
    dst = 0
    size = 8
    src = ctx  # kernel address

    result = probe_read(dst, size, src)
    if result == 0:
        print(f"Read value: {dst}")
    return 0
```

**Parameters:**
* `dst` - Destination buffer
* `size` - Number of bytes to read
* `src` - Source kernel address

**Returns:** `c_int64` - 0 on success, negative on error

**Safety:** This function performs bounds checking and prevents invalid memory access.

#### probe_read_str()

Safely read a null-terminated string from kernel memory.

> **Linux Kernel Helper:** `bpf_probe_read_str()`

**Parameters:**
* `dst` - Destination buffer (string)
* `src` - Source kernel address

**Returns:** `c_int64` - Length of string on success, negative on error

### Random Numbers

#### random()

Generate a pseudo-random 32-bit number.

> **Linux Kernel Helper:** `bpf_get_prandom_u32()`

```python
from pythonbpf.helper import random

@bpf
@section("tracepoint/syscalls/sys_enter_open")
def sample_events(ctx: c_void_p) -> c_int64:
    # Sample 1% of events
    if (random() % 100) == 0:
        print("Sampled event")
    return 0
```

**Returns:** `c_int32` - A pseudo-random number

### Network Helpers

#### skb_store_bytes()

Store bytes into a socket buffer (for network programs).

> **Linux Kernel Helper:** `bpf_skb_store_bytes()`

```python
from pythonbpf.helper import skb_store_bytes

@bpf
@section("classifier")
def modify_packet(ctx: c_void_p) -> c_int32:
    offset = 14  # Skip Ethernet header
    data = b"\x00\x01\x02\x03"
    size = len(data)

    result = skb_store_bytes(offset, data, size)
    return 0
```

**Parameters:**
* `offset` - Offset in the socket buffer
* `from_buf` - Data to write
* `size` - Number of bytes to write
* `flags` - Optional flags

**Returns:** `c_int64` - 0 on success, negative on error

## Userspace Utilities

PythonBPF provides utilities for working with BPF programs from Python userspace code.

### trace_pipe()

Read and display output from the kernel trace pipe.

```python
from pythonbpf import trace_pipe

# After loading and attaching BPF programs
trace_pipe()
```

**Description:**

The `trace_pipe()` function reads from `/sys/kernel/tracing/trace_pipe` and displays BPF program output to stdout. This is the output from `print()` statements in BPF programs.

**Usage:**

```python
from pythonbpf import bpf, section, bpfglobal, BPF, trace_pipe
from ctypes import c_void_p, c_int64

@bpf
@section("tracepoint/syscalls/sys_enter_execve")
def trace_exec(ctx: c_void_p) -> c_int64:
    print("Process started")  # This goes to trace_pipe
    return 0

@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"

b = BPF()
b.load_and_attach()
trace_pipe()  # Display BPF output
```

**Behavior:**

* Blocks until Ctrl+C is pressed
* Displays output in real-time
* Shows task name, PID, CPU, timestamp, and message
* Automatically handles trace pipe access errors

**Requirements:**

* Root or sudo access
* Accessible `/sys/kernel/tracing/trace_pipe`

### trace_fields()

Parse one line from the trace pipe into structured fields.

```python
from pythonbpf import trace_fields

# Read and parse trace output
task, pid, cpu, flags, ts, msg = trace_fields()
print(f"Task: {task}, PID: {pid}, CPU: {cpu}, Time: {ts}, Message: {msg}")
```

**Returns:** Tuple of `(task, pid, cpu, flags, timestamp, message)`

* `task` - String: Task/process name (up to 16 chars)
* `pid` - Integer: Process ID
* `cpu` - Integer: CPU number
* `flags` - Bytes: Trace flags
* `timestamp` - Float: Timestamp in seconds
* `message` - String: The actual trace message

**Description:**

The `trace_fields()` function reads one line from the trace pipe and parses it into individual fields. This is useful when you need programmatic access to trace data rather than just displaying it.

**Usage:**

```python
from pythonbpf import bpf, section, bpfglobal, BPF, trace_fields
from ctypes import c_void_p, c_int64

@bpf
@section("tracepoint/syscalls/sys_enter_execve")
def trace_exec(ctx: c_void_p) -> c_int64:
    print(f"PID:{pid()}")
    return 0

@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"

b = BPF()
b.load_and_attach()

# Process trace events
try:
    while True:
        task, pid, cpu, flags, ts, msg = trace_fields()
        print(f"[{ts:.6f}] {task}({pid}) on CPU{cpu}: {msg}")
except KeyboardInterrupt:
    print("Stopped")
```

**Error Handling:**

* Raises `ValueError` if line cannot be parsed
* Skips lines about lost events
* Blocks waiting for next line

## Helper Function Examples

### Example 1: Latency Measurement

```python
from pythonbpf import bpf, map, section, bpfglobal, BPF, trace_pipe
from pythonbpf.maps import HashMap
from pythonbpf.helper import pid, ktime
from ctypes import c_void_p, c_int64, c_uint32, c_uint64

@bpf
@map
def start_times() -> HashMap:
    return HashMap(key=c_uint32, value=c_uint64, max_entries=4096)

@bpf
@section("tracepoint/syscalls/sys_enter_read")
def read_start(ctx: c_void_p) -> c_int64:
    process_id = pid()
    start = ktime()
    start_times.update(process_id, start)
    return 0

@bpf
@section("tracepoint/syscalls/sys_exit_read")
def read_end(ctx: c_void_p) -> c_int64:
    process_id = pid()
    start = start_times.lookup(process_id)

    if start:
        latency = ktime() - start
        print(f"Read latency: {latency} ns")
        start_times.delete(process_id)

    return 0

@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"

b = BPF()
b.load_and_attach()
trace_pipe()
```

### Example 2: Process Tracking

```python
from pythonbpf import bpf, section, bpfglobal, BPF, trace_pipe
from pythonbpf.helper import pid, uid
from ctypes import c_void_p, c_int64

@bpf
@section("tracepoint/syscalls/sys_enter_execve")
def track_exec(ctx: c_void_p) -> c_int64:
    process_id = pid()
    user_id = uid()

    print(f"User {user_id} started process (PID: {process_id})")
    return 0

@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"

b = BPF()
b.load_and_attach()
trace_pipe()
```

### Example 3: CPU Load Monitoring

```python
from pythonbpf import bpf, map, section, bpfglobal, BPF
from pythonbpf.maps import HashMap
from pythonbpf.helper import smp_processor_id
from ctypes import c_void_p, c_int64, c_uint32, c_uint64

@bpf
@map
def cpu_counts() -> HashMap:
    return HashMap(key=c_uint32, value=c_uint64, max_entries=256)

@bpf
@section("tracepoint/sched/sched_switch")
def count_switches(ctx: c_void_p) -> c_int64:
    cpu = smp_processor_id()
    count = cpu_counts.lookup(cpu)

    if count:
        cpu_counts.update(cpu, count + 1)
    else:
        cpu_counts.update(cpu, 1)

    return 0

@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"

b = BPF()
b.load_and_attach()

import time
time.sleep(5)

# Read results
from pylibbpf import BpfMap
map_obj = BpfMap(b, cpu_counts)
for cpu, count in map_obj.items():
    print(f"CPU {cpu}: {count} context switches")
```

### Example 4: Event Sampling

```python
from pythonbpf import bpf, section, bpfglobal, BPF, trace_pipe
from pythonbpf.helper import random, pid
from ctypes import c_void_p, c_int64

@bpf
@section("tracepoint/syscalls/sys_enter_open")
def sample_opens(ctx: c_void_p) -> c_int64:
    # Sample 5% of events
    if (random() % 100) < 5:
        process_id = pid()
        print(f"Sampled: PID {process_id} opening file")

    return 0

@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"

b = BPF()
b.load_and_attach()
trace_pipe()
```

## Troubleshooting

### Helper Not Available

If a helper function doesn't work:
* Check your kernel version (some helpers are newer)
* Ensure your LICENSE is GPL-compatible

### Trace Pipe Access Denied

If `trace_pipe()` fails:
* Run with sudo/root
* Check `/sys/kernel/tracing/` is accessible
* Verify tracing is enabled in kernel config

## Examples

Check out these examples in the `BCC-Examples/` directory that demonstrate helper functions:

* [hello_world.py](https://github.com/pythonbpf/Python-BPF/blob/main/BCC-Examples/hello_world.py) - Basic tracing with `print()`
* [sync_timing.py](https://github.com/pythonbpf/Python-BPF/blob/main/BCC-Examples/sync_timing.py) - Using `ktime()` for timing measurements
* [hello_perf_output.py](https://github.com/pythonbpf/Python-BPF/blob/main/BCC-Examples/hello_perf_output.py) - Using `pid()`, `ktime()`, and `comm()` with perf events
* [vfsreadlat.py](https://github.com/pythonbpf/Python-BPF/blob/main/BCC-Examples/vfsreadlat.py) - Latency measurement with `ktime()` in kprobes

## Next Steps

* Explore {doc}`maps` for data storage with helpers
* Learn about {doc}`compilation` to understand helper implementation
* See {doc}`decorators` for marking BPF functions
