# Helper Functions and Utilities

PythonBPF provides helper functions and utilities for BPF programs and userspace code.

## BPF Helper Functions

BPF helper functions are kernel-provided functions that BPF programs can call to interact with the system. PythonBPF exposes these through the `pythonbpf.helper` module.

```python
from pythonbpf.helper import pid, ktime, comm
```

### Process and Task Information

#### pid()

Get the current process ID.

```python
from pythonbpf.helper import pid

@bpf
@section("tracepoint/syscalls/sys_enter_open")
def trace_open(ctx: c_void_p) -> c_int64:
    process_id = pid()
    print(f"Process {process_id} opened a file")
    return c_int64(0)
```

**Returns:** `c_int32` - The process ID of the current task

#### comm()

Get the current process command name (up to 16 characters).

```python
from pythonbpf.helper import comm

@bpf
@section("tracepoint/syscalls/sys_enter_execve")
def trace_exec(ctx: c_void_p) -> c_int64:
    process_name = comm()
    print(f"Executing: {process_name}")
    return c_int64(0)
```

**Returns:** `str(16)` - The command name of the current task

**Note:** The returned string is limited to 16 characters (TASK_COMM_LEN).

#### uid()

Get the current user ID.

```python
from pythonbpf.helper import uid

@bpf
@section("tracepoint/syscalls/sys_enter_open")
def trace_open(ctx: c_void_p) -> c_int64:
    user_id = uid()
    if user_id == 0:
        print("Root user opened a file")
    return c_int64(0)
```

**Returns:** `c_int32` - The user ID of the current task

### Time and Timing

#### ktime()

Get the current kernel time in nanoseconds since system boot.

```python
from pythonbpf.helper import ktime

@bpf
@section("tracepoint/syscalls/sys_enter_read")
def measure_latency(ctx: c_void_p) -> c_int64:
    start_time = ktime()
    # Store for later comparison
    return c_int64(0)
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

```python
from pythonbpf.helper import smp_processor_id

@bpf
@section("tracepoint/sched/sched_switch")
def track_cpu(ctx: c_void_p) -> c_int64:
    cpu = smp_processor_id()
    print(f"Running on CPU {cpu}")
    return c_int64(0)
```

**Returns:** `c_int32` - The current CPU ID

**Use cases:**
* Per-CPU statistics
* Load balancing analysis
* CPU affinity tracking

### Memory Operations

#### probe_read()

Safely read data from kernel memory.

```python
from pythonbpf.helper import probe_read

@bpf
def read_kernel_data(ctx: c_void_p) -> c_int64:
    dst = c_uint64(0)
    size = 8
    src = c_void_p(...)  # kernel address
    
    result = probe_read(dst, size, src)
    if result == 0:
        print(f"Read value: {dst}")
    return c_int64(0)
```

**Parameters:**
* `dst` - Destination buffer
* `size` - Number of bytes to read
* `src` - Source kernel address

**Returns:** `c_int64` - 0 on success, negative on error

**Safety:** This function performs bounds checking and prevents invalid memory access.

#### probe_read_str()

Safely read a null-terminated string from kernel memory.

```python
from pythonbpf.helper import probe_read_str

@bpf
def read_filename(ctx: c_void_p) -> c_int64:
    filename = str(256)
    src = c_void_p(...)  # pointer to filename in kernel
    
    result = probe_read_str(filename, src)
    if result > 0:
        print(f"Filename: {filename}")
    return c_int64(0)
```

**Parameters:**
* `dst` - Destination buffer (string)
* `src` - Source kernel address

**Returns:** `c_int64` - Length of string on success, negative on error

#### deref()

Dereference a pointer safely.

```python
from pythonbpf.helper import deref

@bpf
def access_pointer(ctx: c_void_p) -> c_int64:
    ptr = c_void_p(...)
    value = deref(ptr)
    print(f"Value at pointer: {value}")
    return c_int64(0)
```

**Parameters:**
* `ptr` - Pointer to dereference

**Returns:** The dereferenced value or 0 if null

### Random Numbers

#### random()

Generate a pseudo-random 32-bit number.

```python
from pythonbpf.helper import random

@bpf
@section("tracepoint/syscalls/sys_enter_open")
def sample_events(ctx: c_void_p) -> c_int64:
    # Sample 1% of events
    if (random() % 100) == 0:
        print("Sampled event")
    return c_int64(0)
```

**Returns:** `c_int32` - A pseudo-random number

**Use cases:**
* Event sampling
* Load shedding
* A/B testing
* Randomized algorithms

### Network Helpers

#### skb_store_bytes()

Store bytes into a socket buffer (for network programs).

```python
from pythonbpf.helper import skb_store_bytes

@bpf
@section("classifier")
def modify_packet(ctx: c_void_p) -> c_int32:
    offset = 14  # Skip Ethernet header
    data = b"\x00\x01\x02\x03"
    size = len(data)
    
    result = skb_store_bytes(offset, data, size)
    return c_int32(0)
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
    return c_int64(0)

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
    return c_int64(0)

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
    return c_int64(0)

@bpf
@section("tracepoint/syscalls/sys_exit_read")
def read_end(ctx: c_void_p) -> c_int64:
    process_id = pid()
    start = start_times.lookup(process_id)
    
    if start:
        latency = ktime() - start
        print(f"Read latency: {latency} ns")
        start_times.delete(process_id)
    
    return c_int64(0)

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
from pythonbpf.helper import pid, comm, uid
from ctypes import c_void_p, c_int64

@bpf
@section("tracepoint/syscalls/sys_enter_execve")
def track_exec(ctx: c_void_p) -> c_int64:
    process_id = pid()
    process_name = comm()
    user_id = uid()
    
    print(f"User {user_id} started {process_name} (PID: {process_id})")
    return c_int64(0)

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
        cpu_counts.update(cpu, c_uint64(1))
    
    return c_int64(0)

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
from pythonbpf.helper import random, pid, comm
from ctypes import c_void_p, c_int64

@bpf
@section("tracepoint/syscalls/sys_enter_open")
def sample_opens(ctx: c_void_p) -> c_int64:
    # Sample 5% of events
    if (random() % 100) < 5:
        process_id = pid()
        process_name = comm()
        print(f"Sampled: {process_name} ({process_id}) opening file")
    
    return c_int64(0)

@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"

b = BPF()
b.load_and_attach()
trace_pipe()
```

## Best Practices

1. **Use appropriate helpers** - Choose the right helper for your use case
2. **Handle errors** - Check return values from helpers like `probe_read()`
3. **Minimize overhead** - Helper calls have cost; use judiciously
4. **Sample when appropriate** - Use `random()` for high-frequency events
5. **Clean up resources** - Delete map entries when done

## Common Patterns

### Store-and-Compare Pattern

```python
# Store a value
key = pid()
value = ktime()
my_map.update(key, value)

# Later: compare
stored = my_map.lookup(key)
if stored:
    difference = ktime() - stored
```

### Filtering Pattern

```python
# Filter by user
user_id = uid()
if user_id == 0:  # Only root
    # Process event
    pass
```

### Sampling Pattern

```python
# Sample 1 in N events
if (random() % N) == 0:
    # Process sampled event
    pass
```

## Troubleshooting

### Helper Not Available

If a helper function doesn't work:
* Check your kernel version (some helpers are newer)
* Verify the helper is available with `bpftool feature`
* Ensure your LICENSE is GPL-compatible

### Trace Pipe Access Denied

If `trace_pipe()` fails:
* Run with sudo/root
* Check `/sys/kernel/tracing/` is accessible
* Verify tracing is enabled in kernel config

### probe_read Failures

If `probe_read()` returns errors:
* Ensure the source address is valid kernel memory
* Check that the size is reasonable
* Verify you're not reading from restricted areas

## Next Steps

* Explore {doc}`maps` for data storage with helpers
* Learn about {doc}`compilation` to understand helper implementation
* See {doc}`decorators` for marking BPF functions
