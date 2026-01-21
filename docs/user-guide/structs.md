# BPF Structs

Structs allow you to define custom data types for use in BPF programs. They provide a way to group related fields together and can be used as map values, event payloads, or local variables.

## Defining Structs

Use the `@bpf` and `@struct` decorators to define a BPF struct:

```python
from pythonbpf import bpf, struct
from ctypes import c_uint64, c_uint32

@bpf
@struct
class Event:
    timestamp: c_uint64
    pid: c_uint32
    cpu: c_uint32
```

## Field Types

Structs support various field types from Python's `ctypes` module.

### Integer Types

```python
from ctypes import (
    c_int8, c_int16, c_int32, c_int64,
    c_uint8, c_uint16, c_uint32, c_uint64
)

@bpf
@struct
class Numbers:
    small_int: c_int8      # -128 to 127
    short_int: c_int16     # -32768 to 32767
    int_val: c_int32       # -2^31 to 2^31-1
    long_int: c_int64      # -2^63 to 2^63-1
    
    byte: c_uint8          # 0 to 255
    word: c_uint16         # 0 to 65535
    dword: c_uint32        # 0 to 2^32-1
    qword: c_uint64        # 0 to 2^64-1
```

### String Types

Fixed-length strings are defined using `str(N)` where N is the size:

```python
@bpf
@struct
class ProcessInfo:
    name: str(16)      # 16-byte string
    path: str(256)     # 256-byte string
```

```{note}
Strings in BPF are fixed-length and null-terminated. The size includes the null terminator.
```

### Pointer Types

```python
from ctypes import c_void_p, c_char_p

@bpf
@struct
class Pointers:
    ptr: c_void_p      # Generic pointer
    str_ptr: c_char_p  # Character pointer
```

### Nested Structs

Structs can contain other structs as fields:

```python
@bpf
@struct
class Address:
    street: str(64)
    city: str(32)
    zip_code: c_uint32

@bpf
@struct
class Person:
    name: str(32)
    age: c_uint32
    address: Address   # Nested struct
```

## Using Structs

### As Local Variables

Create and use struct instances within BPF functions:

```python
from pythonbpf import bpf, struct, section
from pythonbpf.helper import pid, ktime, comm
from ctypes import c_void_p, c_int64, c_uint64, c_uint32

@bpf
@struct
class Event:
    timestamp: c_uint64
    pid: c_uint32
    comm: str(16)

@bpf
@section("tracepoint/syscalls/sys_enter_execve")
def capture_event(ctx: c_void_p) -> c_int64:
    # Create an instance
    event = Event()
    
    # Set fields
    event.timestamp = ktime()
    event.pid = pid()
    # Note: comm() requires a buffer parameter to fill
    # comm(event.comm)  # Fills event.comm with process name
    
    # Use the struct
    print(f"Process with PID {event.pid}")
    
    return c_int64(0)
```

### As Map Values

Use structs as values in maps for complex state storage:

```python
from pythonbpf import bpf, struct, map, section
from pythonbpf.maps import HashMap
from ctypes import c_uint32, c_uint64

@bpf
@struct
class ProcessStats:
    syscall_count: c_uint64
    total_time: c_uint64
    max_latency: c_uint64

@bpf
@map
def stats() -> HashMap:
    return HashMap(
        key=c_uint32,
        value=ProcessStats,
        max_entries=1024
    )

@bpf
@section("tracepoint/syscalls/sys_enter_read")
def track_syscalls(ctx: c_void_p) -> c_int64:
    process_id = pid()
    
    # Lookup existing stats
    s = stats.lookup(process_id)
    
    if s:
        # Update existing stats
        s.syscall_count = s.syscall_count + 1
        stats.update(process_id, s)
    else:
        # Create new stats
        new_stats = ProcessStats()
        new_stats.syscall_count = c_uint64(1)
        new_stats.total_time = c_uint64(0)
        new_stats.max_latency = c_uint64(0)
        stats.update(process_id, new_stats)
    
    return c_int64(0)
```

### With Perf Events

Send struct data to userspace using PerfEventArray:

```python
from pythonbpf import bpf, struct, map, section
from pythonbpf.maps import PerfEventArray
from pythonbpf.helper import pid, ktime, comm
from ctypes import c_void_p, c_int64, c_uint32, c_uint64

@bpf
@struct
class ProcessEvent:
    timestamp: c_uint64
    pid: c_uint32
    ppid: c_uint32
    comm: str(16)

@bpf
@map
def events() -> PerfEventArray:
    return PerfEventArray(key_size=c_uint32, value_size=c_uint32)

@bpf
@section("tracepoint/sched/sched_process_fork")
def trace_fork(ctx: c_void_p) -> c_int64:
    event = ProcessEvent()
    event.timestamp = ktime()
    event.pid = pid()
    # Note: comm() requires a buffer parameter
    # comm(event.comm)  # Fills event.comm with process name
    
    # Send to userspace
    events.output(event)
    
    return c_int64(0)
```

### With Ring Buffers

Ring buffers provide efficient event delivery:

```python
from pythonbpf import bpf, struct, map, section
from pythonbpf.maps import RingBuffer

@bpf
@struct
class FileEvent:
    timestamp: c_uint64
    pid: c_uint32
    filename: str(256)

@bpf
@map
def events() -> RingBuffer:
    return RingBuffer(max_entries=4096)

@bpf
@section("tracepoint/syscalls/sys_enter_openat")
def trace_open(ctx: c_void_p) -> c_int64:
    event = FileEvent()
    event.timestamp = ktime()
    event.pid = pid()
    # event.filename would be populated from ctx
    
    events.output(event)
    
    return c_int64(0)
```

## Field Access and Modification

### Reading Fields

Access struct fields using dot notation:

```python
event = Event()
ts = event.timestamp
process_id = event.pid
```

### Writing Fields

Assign values to fields:

```python
event = Event()
event.timestamp = ktime()
event.pid = pid()
# Note: comm() requires a buffer parameter
# comm(event.comm)  # Fills event.comm with process name
```

### String Fields

String fields have special handling:

```python
@bpf
@struct
class Message:
    text: str(64)

@bpf
def example(ctx: c_void_p) -> c_int64:
    msg = Message()
    
    # Assign string value
    msg.text = "Hello from BPF"
    
    # Use helper to get process name (requires buffer)
    # comm(msg.text)  # Fills msg.text with process name
    
    return c_int64(0)
```

## StructType Class

PythonBPF provides a `StructType` class for working with struct metadata:

```python
from pythonbpf.structs import StructType

# Define a struct
@bpf
@struct
class MyStruct:
    field1: c_uint64
    field2: c_uint32

# Access struct information (from userspace)
# This is typically used internally by the compiler
```

## Complex Examples

### Network Packet Event

```python
from pythonbpf import bpf, struct, map, section
from pythonbpf.maps import RingBuffer
from pythonbpf.helper import ktime, XDP_PASS
from ctypes import c_void_p, c_int64, c_uint8, c_uint16, c_uint32, c_uint64

@bpf
@struct
class PacketEvent:
    timestamp: c_uint64
    src_ip: c_uint32
    dst_ip: c_uint32
    src_port: c_uint16
    dst_port: c_uint16
    protocol: c_uint8
    length: c_uint16

@bpf
@map
def packets() -> RingBuffer:
    return RingBuffer(max_entries=8192)

@bpf
@section("xdp")
def capture_packets(ctx: c_void_p) -> c_int64:
    pkt = PacketEvent()
    pkt.timestamp = ktime()
    # Parse packet data from ctx...
    
    packets.output(pkt)
    
    # XDP_PASS
    return XDP_PASS
```

### Process Lifecycle Tracking

```python
@bpf
@struct
class ProcessLifecycle:
    pid: c_uint32
    ppid: c_uint32
    start_time: c_uint64
    exit_time: c_uint64
    exit_code: c_int32
    comm: str(16)

@bpf
@map
def process_info() -> HashMap:
    return HashMap(
        key=c_uint32,
        value=ProcessLifecycle,
        max_entries=4096
    )

@bpf
@section("tracepoint/sched/sched_process_fork")
def track_fork(ctx: c_void_p) -> c_int64:
    process_id = pid()
    
    info = ProcessLifecycle()
    info.pid = process_id
    info.start_time = ktime()
    # Note: comm() requires a buffer parameter
    # comm(info.comm)  # Fills info.comm with process name
    
    process_info.update(process_id, info)
    
    return c_int64(0)

@bpf
@section("tracepoint/sched/sched_process_exit")
def track_exit(ctx: c_void_p) -> c_int64:
    process_id = pid()
    
    info = process_info.lookup(process_id)
    if info:
        info.exit_time = ktime()
        process_info.update(process_id, info)
    
    return c_int64(0)
```

### Aggregated Statistics

```python
@bpf
@struct
class FileStats:
    read_count: c_uint64
    write_count: c_uint64
    total_bytes_read: c_uint64
    total_bytes_written: c_uint64
    last_access: c_uint64

@bpf
@map
def file_stats() -> HashMap:
    return HashMap(
        key=str(256),  # Filename as key
        value=FileStats,
        max_entries=1024
    )
```

## Memory Layout

Structs in BPF follow C struct layout rules:

* Fields are laid out in order
* Padding may be added for alignment
* Size is rounded up to alignment

Example:

```python
@bpf
@struct
class Aligned:
    a: c_uint8   # 1 byte
                 # 3 bytes padding
    b: c_uint32  # 4 bytes
    c: c_uint64  # 8 bytes
    # Total: 16 bytes
```

```{tip}
For optimal memory usage, order fields from largest to smallest to minimize padding.
```

## Best Practices

1. **Use descriptive field names** - Makes code self-documenting
2. **Order fields by size** - Reduces padding and memory usage
3. **Use appropriate sizes** - Don't use `c_uint64` when `c_uint32` suffices
4. **Document complex structs** - Add comments explaining field purposes
5. **Keep structs focused** - Each struct should represent one logical entity
6. **Use fixed-size strings** - Always specify string lengths explicitly

## Common Patterns

### Timestamp + Data Pattern

```python
@bpf
@struct
class TimestampedEvent:
    timestamp: c_uint64  # Always first for sorting
    # ... other fields
```

### Identification Pattern

```python
@bpf
@struct
class Identifiable:
    pid: c_uint32
    tid: c_uint32
    cpu: c_uint32
    # ... additional fields
```

### Stats Aggregation Pattern

```python
@bpf
@struct
class Statistics:
    count: c_uint64
    sum: c_uint64
    min: c_uint64
    max: c_uint64
    avg: c_uint64  # Computed in userspace
```

## Troubleshooting

### Struct Size Issues

If you encounter size-related errors:
* Check for excessive padding
* Verify field types are correct
* Consider reordering fields

### Initialization Problems

If fields aren't initialized correctly:
* Always initialize all fields explicitly
* Set default values where appropriate
* Use helper functions for dynamic values

### Type Mismatch Errors

If you get type errors:
* Ensure field types match assignments
* Check that imported types are from `ctypes`
* Verify nested struct definitions

## Reading Struct Data in Userspace

After capturing struct data, read it in Python:

```python
import ctypes
from pylibbpf import BpfMap

# Define matching Python class
class Event(ctypes.Structure):
    _fields_ = [
        ("timestamp", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("comm", ctypes.c_char * 16),
    ]

# Read from map
map_obj = BpfMap(b, stats)
for key, value_bytes in map_obj.items():
    value = Event.from_buffer_copy(value_bytes)
    print(f"PID: {value.pid}, Comm: {value.comm.decode()}")
```

## Next Steps

* Learn about {doc}`maps` for storing struct data
* Explore {doc}`helpers` for populating struct fields
* See {doc}`compilation` to understand how structs are compiled
