# BPF Maps

Maps are BPF data structures that provide storage and communication mechanisms. They allow BPF programs to:

* Store state between invocations
* Share data between multiple BPF programs
* Communicate with userspace applications

## Map Types

PythonBPF supports several map types, each optimized for different use cases.

### HashMap

Hash maps provide efficient key-value storage with O(1) lookup time.

#### Definition

```python
from pythonbpf import bpf, map
from pythonbpf.maps import HashMap
from ctypes import c_uint32, c_uint64

@bpf
@map
def my_map() -> HashMap:
    return HashMap(
        key=c_uint32,
        value=c_uint64,
        max_entries=1024
    )
```

#### Parameters

* `key` - The type of the key (must be a ctypes type)
* `value` - The type of the value (must be a ctypes type or struct)
* `max_entries` - Maximum number of entries the map can hold

#### Operations

##### lookup(key)

Look up a value by key. Returns the value if found, `None` otherwise.

```python
@bpf
@section("tracepoint/syscalls/sys_enter_open")
def trace_open(ctx: c_void_p) -> c_int64:
    key = c_uint32(1)
    value = my_map.lookup(key)
    if value:
        print(f"Found value: {value}")
    return c_int64(0)
```

##### update(key, value, flags=None)

Update or insert a key-value pair.

```python
@bpf
@section("tracepoint/syscalls/sys_enter_open")
def track_opens(ctx: c_void_p) -> c_int64:
    key = pid()
    count = my_map.lookup(key)
    if count:
        my_map.update(key, count + 1)
    else:
        my_map.update(key, c_uint64(1))
    return c_int64(0)
```

##### delete(key)

Remove an entry from the map.

```python
@bpf
def cleanup(ctx: c_void_p) -> c_int64:
    key = c_uint32(1)
    my_map.delete(key)
    return c_int64(0)
```

#### Use Cases

* Counting events per process/CPU
* Storing timestamps for latency calculations
* Caching lookup results
* Implementing rate limiters

#### Example: Process Counter

```python
from pythonbpf import bpf, map, section, bpfglobal, BPF
from pythonbpf.maps import HashMap
from pythonbpf.helper import pid
from ctypes import c_void_p, c_int64, c_uint32, c_uint64

@bpf
@map
def process_count() -> HashMap:
    return HashMap(key=c_uint32, value=c_uint64, max_entries=4096)

@bpf
@section("tracepoint/syscalls/sys_enter_clone")
def count_processes(ctx: c_void_p) -> c_int64:
    process_id = pid()
    count = process_count.lookup(process_id)
    
    if count:
        new_count = count + 1
        process_count.update(process_id, new_count)
    else:
        process_count.update(process_id, c_uint64(1))
    
    return c_int64(0)

@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"

if __name__ == "__main__":
    b = BPF()
    b.load_and_attach()
    # Access map from userspace
    from pylibbpf import BpfMap
    map_obj = BpfMap(b, process_count)
    # Read values...
```

### PerfEventArray

Perf event arrays are used to send data from BPF programs to userspace with high throughput.

#### Definition

```python
from pythonbpf.maps import PerfEventArray

@bpf
@map
def events() -> PerfEventArray:
    return PerfEventArray(
        key_size=c_uint32,
        value_size=c_uint32
    )
```

#### Parameters

* `key_size` - Type for the key (typically `c_uint32`)
* `value_size` - Type for the value (typically `c_uint32`)

#### Operations

##### output(data)

Send data to userspace. The data can be a struct or basic type.

```python
@bpf
@struct
class Event:
    pid: c_uint32
    timestamp: c_uint64

@bpf
@map
def events() -> PerfEventArray:
    return PerfEventArray(key_size=c_uint32, value_size=c_uint32)

@bpf
@section("tracepoint/syscalls/sys_enter_execve")
def send_event(ctx: c_void_p) -> c_int64:
    event = Event()
    event.pid = pid()
    event.timestamp = ktime()
    events.output(event)
    return c_int64(0)
```

#### Use Cases

* Sending detailed event data to userspace
* Real-time monitoring and alerting
* Collecting samples for analysis
* High-throughput data collection

#### Example: Event Logging

```python
from pythonbpf import bpf, map, struct, section, bpfglobal, BPF
from pythonbpf.maps import PerfEventArray
from pythonbpf.helper import pid, ktime, comm
from ctypes import c_void_p, c_int64, c_uint32, c_uint64

@bpf
@struct
class ProcessEvent:
    timestamp: c_uint64
    pid: c_uint32
    comm: str(16)

@bpf
@map
def events() -> PerfEventArray:
    return PerfEventArray(key_size=c_uint32, value_size=c_uint32)

@bpf
@section("tracepoint/syscalls/sys_enter_execve")
def log_exec(ctx: c_void_p) -> c_int64:
    event = ProcessEvent()
    event.timestamp = ktime()
    event.pid = pid()
    # Note: comm() requires a buffer parameter
    # comm(event.comm)  # Fills event.comm with process name
    events.output(event)
    return c_int64(0)

@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"
```

### RingBuffer

Ring buffers provide efficient, ordered event delivery with lower overhead than perf event arrays.

#### Definition

```python
from pythonbpf.maps import RingBuffer

@bpf
@map
def events() -> RingBuffer:
    return RingBuffer(max_entries=4096)
```

#### Parameters

* `max_entries` - Maximum size of the ring buffer in bytes (must be power of 2)

#### Operations

##### output(data, flags=0)

Send data to the ring buffer.

```python
@bpf
@section("tracepoint/syscalls/sys_enter_open")
def log_event(ctx: c_void_p) -> c_int64:
    event = Event()
    event.pid = pid()
    events.output(event)
    return c_int64(0)
```

##### reserve(size)

Reserve space in the ring buffer. Returns a pointer to the reserved space or 0 if no space available.

```python
@bpf
def reserve_space(ctx: c_void_p) -> c_int64:
    ptr = events.reserve(64)  # Reserve 64 bytes
    if ptr:
        # Use the reserved space
        events.submit(ptr)
    return c_int64(0)
```

##### submit(data, flags=0)

Submit previously reserved space.

##### discard(data, flags=0)

Discard previously reserved space without submitting.

#### Use Cases

* Modern event streaming (preferred over PerfEventArray)
* Lower overhead event delivery
* Ordered event processing
* Kernel 5.8+ systems

#### Advantages over PerfEventArray

* Lower memory overhead
* Better performance
* Simpler API
* Ordered delivery guarantees

### BPFMapType Enum

PythonBPF supports various BPF map types through the `BPFMapType` enum:

```python
from pythonbpf.maps import BPFMapType

# Common map types
BPFMapType.BPF_MAP_TYPE_HASH          # Hash map
BPFMapType.BPF_MAP_TYPE_ARRAY         # Array map
BPFMapType.BPF_MAP_TYPE_PERF_EVENT_ARRAY  # Perf event array
BPFMapType.BPF_MAP_TYPE_RINGBUF       # Ring buffer
BPFMapType.BPF_MAP_TYPE_STACK_TRACE   # Stack trace storage
BPFMapType.BPF_MAP_TYPE_LRU_HASH      # LRU hash map
```

## Using Maps with Structs

Maps can store complex data types using structs as values:

```python
from pythonbpf import bpf, map, struct, section
from pythonbpf.maps import HashMap
from ctypes import c_uint32, c_uint64

@bpf
@struct
class Stats:
    count: c_uint64
    total_time: c_uint64
    max_time: c_uint64

@bpf
@map
def process_stats() -> HashMap:
    return HashMap(
        key=c_uint32,      # PID as key
        value=Stats,        # Struct as value
        max_entries=1024
    )

@bpf
@section("tracepoint/syscalls/sys_enter_read")
def track_stats(ctx: c_void_p) -> c_int64:
    process_id = pid()
    stats = process_stats.lookup(process_id)
    
    if stats:
        stats.count = stats.count + 1
        process_stats.update(process_id, stats)
    else:
        new_stats = Stats()
        new_stats.count = c_uint64(1)
        new_stats.total_time = c_uint64(0)
        new_stats.max_time = c_uint64(0)
        process_stats.update(process_id, new_stats)
    
    return c_int64(0)
```

## Accessing Maps from Userspace

After loading a BPF program, you can access maps from Python using `pylibbpf`:

```python
from pythonbpf import BPF
from pylibbpf import BpfMap

# Load BPF program
b = BPF()
b.load_and_attach()

# Get map reference
map_obj = BpfMap(b, my_map)

# Read all key-value pairs
for key, value in map_obj.items():
    print(f"Key: {key}, Value: {value}")

# Get all keys
keys = list(map_obj.keys())

# Get all values
values = list(map_obj.values())

# Lookup specific key
value = map_obj[key]

# Update from userspace
map_obj[key] = new_value

# Delete from userspace
del map_obj[key]
```

## Best Practices

1. **Choose the right map type**
   * Use `HashMap` for key-value storage
   * Use `RingBuffer` for event streaming (kernel 5.8+)
   * Use `PerfEventArray` for older kernels

2. **Size maps appropriately**
   * Consider maximum expected entries
   * Balance memory usage vs. capacity
   * Use LRU maps for automatic eviction

3. **Handle lookup failures**
   * Always check if `lookup()` returns `None`
   * Initialize new entries properly

4. **Minimize map operations**
   * BPF has instruction limits
   * Reduce unnecessary lookups
   * Batch operations when possible

5. **Use structs for complex data**
   * More efficient than multiple lookups
   * Atomic updates of related fields
   * Better cache locality

## Common Patterns

### Counter Pattern

```python
count = my_map.lookup(key)
if count:
    my_map.update(key, count + 1)
else:
    my_map.update(key, c_uint64(1))
```

### Latency Tracking

```python
# Store start time
start = ktime()
start_map.update(key, start)

# Later: calculate latency
start_time = start_map.lookup(key)
if start_time:
    latency = ktime() - start_time
    latency_map.update(key, latency)
    start_map.delete(key)
```

### Event Sampling

```python
# Only process every Nth event
count = counter.lookup(key)
if count and (count % 100) == 0:
    events.output(data)
counter.update(key, count + 1 if count else c_uint64(1))
```

## Troubleshooting

### Map Not Found

If you get "map not found" errors:
* Ensure the map is defined with `@bpf` and `@map`
* Check that the map name matches exactly
* Verify the BPF program loaded successfully

### Map Full

If updates fail due to map being full:
* Increase `max_entries`
* Use LRU maps for automatic eviction
* Add cleanup logic to delete old entries

### Type Errors

If you get type-related errors:
* Verify key and value types match the definition
* Check that structs are properly defined
* Ensure ctypes are used correctly

## Next Steps

* Learn about {doc}`structs` for defining custom value types
* Explore {doc}`helpers` for BPF helper functions
* See {doc}`compilation` to understand how maps are compiled
