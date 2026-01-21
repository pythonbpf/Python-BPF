# Decorators

Decorators are the primary way to mark Python code for BPF compilation. PythonBPF provides five core decorators that control how your code is transformed into eBPF bytecode.

## @bpf

The `@bpf` decorator marks functions or classes for BPF compilation.

### Usage

```python
from pythonbpf import bpf

@bpf
def my_function(ctx):
    # This function will be compiled to BPF bytecode
    pass
```

### Description

Any function or class decorated with `@bpf` will be processed by the PythonBPF compiler and transformed into LLVM IR, then compiled to BPF bytecode. This is the fundamental decorator that enables BPF compilation.

### Rules

* Must be used on top-level functions or classes
* The function must have proper type hints
* Return types must be BPF-compatible
* Only BPF-compatible operations are allowed inside

### Example

```python
from pythonbpf import bpf, section
from ctypes import c_void_p, c_int64

@bpf
@section("tracepoint/syscalls/sys_enter_execve")
def trace_exec(ctx: c_void_p) -> c_int64:
    print("Process started")
    return c_int64(0)
```

## @section

The `@section(name)` decorator specifies which kernel hook to attach the BPF program to.

### Usage

```python
from pythonbpf import bpf, section

@bpf
@section("tracepoint/syscalls/sys_enter_open")
def trace_open(ctx):
    pass
```

### Section Types

#### Tracepoints

Tracepoints are stable kernel hooks defined in `/sys/kernel/tracing/events/`:

```python
# System call tracepoints
@section("tracepoint/syscalls/sys_enter_execve")
@section("tracepoint/syscalls/sys_enter_clone")
@section("tracepoint/syscalls/sys_enter_open")
@section("tracepoint/syscalls/sys_exit_read")

# Scheduler tracepoints
@section("tracepoint/sched/sched_process_fork")
@section("tracepoint/sched/sched_process_exit")
@section("tracepoint/sched/sched_switch")

# Block I/O tracepoints
@section("tracepoint/block/block_rq_insert")
@section("tracepoint/block/block_rq_complete")
```

#### Kprobes

Kprobes allow attaching to any kernel function:

```python
@section("kprobe/do_sys_open")
def trace_sys_open(ctx):
    pass

@section("kprobe/__x64_sys_write")
def trace_write(ctx):
    pass
```

#### Kretprobes

Kretprobes trigger when a kernel function returns:

```python
@section("kretprobe/do_sys_open")
def trace_open_return(ctx):
    pass
```

#### XDP (eXpress Data Path)

For network packet processing at the earliest point:

```python
from pythonbpf.helper import XDP_PASS
from ctypes import c_void_p, c_int64

@section("xdp")
def xdp_prog(ctx: c_void_p) -> c_int64:
    # XDP_PASS, XDP_DROP, XDP_ABORTED constants available from pythonbpf.helper
    return XDP_PASS
```

#### TC (Traffic Control)

For network traffic filtering:

```python
@section("classifier")
def tc_filter(ctx):
    pass
```

### Finding Tracepoints

To find available tracepoints on your system:

```bash
# List all tracepoints
ls /sys/kernel/tracing/events/

# List syscall tracepoints
ls /sys/kernel/tracing/events/syscalls/

# View tracepoint format
cat /sys/kernel/tracing/events/syscalls/sys_enter_open/format
```

## @map

The `@map` decorator marks a function as a BPF map definition.

### Usage

```python
from pythonbpf import bpf, map
from pythonbpf.maps import HashMap
from ctypes import c_uint32, c_uint64

@bpf
@map
def my_map() -> HashMap:
    return HashMap(key=c_uint32, value=c_uint64, max_entries=1024)
```

### Description

Maps are BPF data structures used to:

* Store state between BPF program invocations
* Communicate data between BPF programs
* Share data with userspace

The function must return a map type (HashMap, PerfEventArray, RingBuffer) and the return type must be annotated.

### Example

```python
from pythonbpf import bpf, map, section
from pythonbpf.maps import HashMap
from pythonbpf.helper import pid
from ctypes import c_void_p, c_int64, c_uint32, c_uint64

@bpf
@map
def process_count() -> HashMap:
    return HashMap(key=c_uint32, value=c_uint64, max_entries=4096)

@bpf
@section("tracepoint/syscalls/sys_enter_clone")
def count_clones(ctx: c_void_p) -> c_int64:
    process_id = pid()
    count = process_count.lookup(process_id)
    if count:
        process_count.update(process_id, count + 1)
    else:
        process_count.update(process_id, c_uint64(1))
    return c_int64(0)
```

See {doc}`maps` for more details on available map types.

## @struct

The `@struct` decorator marks a class as a BPF struct definition.

### Usage

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

### Description

Structs allow you to define custom data types for use in BPF programs. They can be used:

* As map values
* For perf event output
* In ring buffer submissions
* As local variables

### Field Types

Supported field types include:

* **Integer types**: `c_int8`, `c_int16`, `c_int32`, `c_int64`, `c_uint8`, `c_uint16`, `c_uint32`, `c_uint64`
* **Pointers**: `c_void_p`, `c_char_p`
* **Fixed strings**: `str(N)` where N is the size (e.g., `str(16)`)
* **Nested structs**: Other `@struct` decorated classes

### Example

```python
from pythonbpf import bpf, struct, map, section
from pythonbpf.maps import RingBuffer
from pythonbpf.helper import pid, ktime
from ctypes import c_void_p, c_int64, c_uint64, c_uint32

@bpf
@struct
class ProcessEvent:
    timestamp: c_uint64
    pid: c_uint32
    comm: str(16)

@bpf
@map
def events() -> RingBuffer:
    return RingBuffer(max_entries=4096)

@bpf
@section("tracepoint/syscalls/sys_enter_execve")
def track_processes(ctx: c_void_p) -> c_int64:
    event = ProcessEvent()
    event.timestamp = ktime()
    event.pid = pid()
    # Note: comm() requires a buffer parameter
    # comm(event.comm)  # Fills event.comm with process name
    
    events.output(event)
    return c_int64(0)
```

See {doc}`structs` for more details on working with structs.

## @bpfglobal

The `@bpfglobal` decorator marks a function as a BPF global variable definition.

### Usage

```python
from pythonbpf import bpf, bpfglobal

@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"
```

### Description

BPF global variables are values that:

* Are initialized when the program loads
* Can be read by all BPF functions
* Must be constant (cannot be modified at runtime in current implementation)

### Common Global Variables

#### LICENSE (Required)

Every BPF program must declare a license:

```python
@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"
```

Valid licenses include:
* `"GPL"` - GNU General Public License
* `"GPL v2"` - GPL version 2
* `"Dual BSD/GPL"` - Dual licensed
* `"Dual MIT/GPL"` - Dual licensed

```{warning}
Many BPF features require a GPL-compatible license. Using a non-GPL license may prevent your program from loading or accessing certain kernel features.
```

#### Custom Global Variables

You can define other global variables:

```python
@bpf
@bpfglobal
def DEBUG_MODE() -> int:
    return 1

@bpf
@bpfglobal
def MAX_EVENTS() -> int:
    return 1000
```

These can be referenced in your BPF functions, though modifying them at runtime is currently not supported.

## Combining Decorators

Decorators are often used together. The order matters:

### Correct Order

```python
@bpf              # Always first
@section("...")   # Section before other decorators
def my_function():
    pass

@bpf              # Always first
@map              # Map/struct/bpfglobal after @bpf
def my_map():
    pass

@bpf              # Always first
@struct           # Map/struct/bpfglobal after @bpf
class MyStruct:
    pass

@bpf              # Always first
@bpfglobal        # Map/struct/bpfglobal after @bpf
def LICENSE():
    return "GPL"
```

### Examples by Use Case

#### Simple Tracepoint

```python
@bpf
@section("tracepoint/syscalls/sys_enter_open")
def trace_open(ctx: c_void_p) -> c_int64:
    return c_int64(0)
```

#### Map Definition

```python
@bpf
@map
def counters() -> HashMap:
    return HashMap(key=c_uint32, value=c_uint64, max_entries=256)
```

#### Struct Definition

```python
@bpf
@struct
class Event:
    timestamp: c_uint64
    value: c_uint32
```

#### Global Variable

```python
@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"
```

## Best Practices

1. **Always use @bpf first** - It must be the outermost decorator
2. **Provide type hints** - Required for proper code generation
3. **Use descriptive names** - Makes code easier to understand and debug
4. **Keep functions simple** - BPF has restrictions on complexity
5. **Test incrementally** - Verify each component works before combining

## Common Errors

### Missing @bpf Decorator

```python
# Wrong - missing @bpf
@section("tracepoint/syscalls/sys_enter_open")
def my_func(ctx):
    pass

# Correct
@bpf
@section("tracepoint/syscalls/sys_enter_open")
def my_func(ctx):
    pass
```

### Wrong Decorator Order

```python
# Wrong - @section before @bpf
@section("tracepoint/syscalls/sys_enter_open")
@bpf
def my_func(ctx):
    pass

# Correct
@bpf
@section("tracepoint/syscalls/sys_enter_open")
def my_func(ctx):
    pass
```

### Missing Type Hints

```python
# Wrong - no type hints
@bpf
def my_func(ctx):
    pass

# Correct
@bpf
def my_func(ctx: c_void_p) -> c_int64:
    pass
```

## Next Steps

* Learn about {doc}`maps` for data storage and communication
* Explore {doc}`structs` for defining custom data types
* Understand {doc}`compilation` to see how code is transformed
* Check out {doc}`helpers` for available BPF helper functions
