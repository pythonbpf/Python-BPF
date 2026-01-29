# API Reference

This section provides detailed API documentation for all PythonBPF modules, classes, and functions.

## Module Overview

PythonBPF is organized into several modules:

* `pythonbpf` - Main module with decorators and compilation functions
* `pythonbpf.maps` - BPF map types
* `pythonbpf.helper` - BPF helper functions
* `pythonbpf.structs` - Struct type handling
* `pythonbpf.codegen` - Code generation and compilation

## Public API

The main `pythonbpf` module exports the following public API:

```python
from pythonbpf import (
    # Decorators
    bpf,
    map,
    section,
    bpfglobal,
    struct,

    # Compilation
    compile_to_ir,
    compile,
    BPF,

    # Utilities
    trace_pipe,
    trace_fields,
)
```

## Decorators

```{eval-rst}
.. automodule:: pythonbpf.decorators
   :members:
   :undoc-members:
   :show-inheritance:
```

### bpf

```python
@bpf
def my_function():
    pass
```

Decorator to mark a function or class for BPF compilation. Any function or class decorated with `@bpf` will be processed by the PythonBPF compiler.

**See also:** {doc}`../user-guide/decorators`

### map

```python
@bpf
@map
def my_map() -> HashMap:
    return HashMap(key=c_uint32, value=c_uint64, max_entries=1024)
```

Decorator to mark a function as a BPF map definition. The function must return a map type.

**See also:** {doc}`../user-guide/maps`

### section

```python
@bpf
@section("tracepoint/syscalls/sys_enter_open")
def trace_open(ctx: c_void_p) -> c_int64:
    return c_int64(0)
```

Decorator to specify which kernel hook to attach the BPF program to.

**Parameters:**
* `name` (str) - The section name (e.g., "tracepoint/...", "kprobe/...", "xdp")

**See also:** {doc}`../user-guide/decorators`

### bpfglobal

```python
@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"
```

Decorator to mark a function as a BPF global variable definition.

**See also:** {doc}`../user-guide/decorators`

### struct

```python
@bpf
@struct
class Event:
    timestamp: c_uint64
    pid: c_uint32
```

Decorator to mark a class as a BPF struct definition.

**See also:** {doc}`../user-guide/structs`

## Compilation Functions

```{eval-rst}
.. automodule:: pythonbpf.codegen
   :members: compile_to_ir, compile, BPF
   :undoc-members:
   :show-inheritance:
```

### compile_to_ir()

```python
def compile_to_ir(
    filename: str,
    output: str,
    loglevel=logging.WARNING
) -> None
```

Compile Python source to LLVM Intermediate Representation.

**Parameters:**
* `filename` (str) - Path to the Python source file
* `output` (str) - Path for the output LLVM IR file (.ll)
* `loglevel` - Logging level (default: logging.WARNING)

**See also:** {doc}`../user-guide/compilation`

### compile()

```python
def compile(
    filename: str = None,
    output: str = None,
    loglevel=logging.WARNING
) -> None
```

Compile Python source to BPF object file.

**Parameters:**
* `filename` (str, optional) - Path to the Python source file (default: calling file)
* `output` (str, optional) - Path for the output object file (default: same name with .o extension)
* `loglevel` - Logging level (default: logging.WARNING)

**See also:** {doc}`../user-guide/compilation`

### BPF

```python
class BPF:
    def __init__(
        self,
        filename: str = None,
        loglevel=logging.WARNING
    )

    def load(self) -> BpfObject
    def attach_all(self) -> None
    def load_and_attach(self) -> BpfObject
```

High-level interface to compile, load, and attach BPF programs.

**Parameters:**
* `filename` (str, optional) - Path to Python source file (default: calling file)
* `loglevel` - Logging level (default: logging.WARNING)

**Methods:**
* `load()` - Load the compiled BPF program into the kernel
* `attach_all()` - Attach all BPF programs to their hooks
* `load_and_attach()` - Convenience method that loads and attaches

**See also:** {doc}`../user-guide/compilation`

## Utilities

```{eval-rst}
.. automodule:: pythonbpf.utils
   :members:
   :undoc-members:
   :show-inheritance:
```

### trace_pipe()

```python
def trace_pipe() -> None
```

Read and display output from the kernel trace pipe.

Blocks until interrupted with Ctrl+C. Displays BPF program output from `print()` statements.

**See also:** {doc}`../user-guide/helpers`

### trace_fields()

```python
def trace_fields() -> tuple
```

Parse one line from the trace pipe into structured fields.

**Returns:** Tuple of `(task, pid, cpu, flags, timestamp, message)`
* `task` (str) - Task/process name
* `pid` (int) - Process ID
* `cpu` (int) - CPU number
* `flags` (bytes) - Trace flags
* `timestamp` (float) - Timestamp in seconds
* `message` (str) - The trace message

**See also:** {doc}`../user-guide/helpers`

## Map Types

```{eval-rst}
.. automodule:: pythonbpf.maps.maps
   :members:
   :undoc-members:
   :show-inheritance:
```

### HashMap

```python
class HashMap:
    def __init__(
        self,
        key,
        value,
        max_entries: int
    )

    def lookup(self, key)
    def update(self, key, value, flags=None)
    def delete(self, key)
```

Hash map for efficient key-value storage.

**Parameters:**
* `key` - The type of the key (ctypes type or struct)
* `value` - The type of the value (ctypes type or struct)
* `max_entries` (int) - Maximum number of entries

**Methods:**
* `lookup(key)` - Look up a value by key
* `update(key, value, flags=None)` - Update or insert a key-value pair
* `delete(key)` - Remove an entry from the map

**See also:** {doc}`../user-guide/maps`

### PerfEventArray

```python
class PerfEventArray:
    def __init__(
        self,
        key_size,
        value_size
    )

    def output(self, data)
```

Perf event array for sending data to userspace.

**Parameters:**
* `key_size` - Type for the key
* `value_size` - Type for the value

**Methods:**
* `output(data)` - Send data to userspace

**See also:** {doc}`../user-guide/maps`

### RingBuffer

```python
class RingBuffer:
    def __init__(self, max_entries: int)

    def output(self, data, flags=0)
    def reserve(self, size: int)
    def submit(self, data, flags=0)
    def discard(self, data, flags=0)
```

Ring buffer for efficient event delivery.

**Parameters:**
* `max_entries` (int) - Maximum size in bytes (must be power of 2)

**Methods:**
* `output(data, flags=0)` - Send data to the ring buffer
* `reserve(size)` - Reserve space in the buffer
* `submit(data, flags=0)` - Submit previously reserved space
* `discard(data, flags=0)` - Discard previously reserved space

**See also:** {doc}`../user-guide/maps`

## Helper Functions

```{eval-rst}
.. automodule:: pythonbpf.helper.helpers
   :members:
   :undoc-members:
   :show-inheritance:
```

### Process Information

* `pid()` - Get current process ID
* `comm(buf)` - Get current process command name (requires buffer parameter)
* `uid()` - Get current user ID

### Time

* `ktime()` - Get current kernel time in nanoseconds

### CPU

* `smp_processor_id()` - Get current CPU ID

### Memory

* `probe_read(dst, size, src)` - Safely read kernel memory
* `probe_read_str(dst, src)` - Safely read string from kernel memory
* `deref(ptr)` - Dereference a pointer

### Random

* `random()` - Get pseudo-random number

**See also:** {doc}`../user-guide/helpers`

## Type System

PythonBPF uses Python's `ctypes` module for type definitions:

### Integer Types

* `c_int8`, `c_int16`, `c_int32`, `c_int64` - Signed integers
* `c_uint8`, `c_uint16`, `c_uint32`, `c_uint64` - Unsigned integers

### Other Types

* `c_char`, `c_bool` - Characters and booleans
* `c_void_p` - Void pointers
* `str(N)` - Fixed-length strings

## Examples

### Basic Usage

```python
from pythonbpf import bpf, section, bpfglobal, BPF, trace_pipe
from ctypes import c_void_p, c_int64

@bpf
@section("tracepoint/syscalls/sys_enter_execve")
def hello(ctx: c_void_p) -> c_int64:
    print("Hello, World!")
    return 0

@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"

b = BPF()
b.load_and_attach()
trace_pipe()
```

### With Maps

```python
from pythonbpf import bpf, map, section, bpfglobal, BPF
from pythonbpf.maps import HashMap
from pythonbpf.helper import pid
from ctypes import c_void_p, c_int64, c_uint32, c_uint64

@bpf
@map
def counters() -> HashMap:
    return HashMap(key=c_uint32, value=c_uint64, max_entries=256)

@bpf
@section("tracepoint/syscalls/sys_enter_clone")
def count_clones(ctx: c_void_p) -> c_int64:
    process_id = pid()
    count = counters.lookup(process_id)

    if count:
        counters.update(process_id, count + 1)
    else:
        counters.update(process_id, 1)

    return 0

@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"

b = BPF()
b.load_and_attach()
```

### With Structs

```python
from pythonbpf import bpf, struct, map, section, bpfglobal, BPF
from pythonbpf.maps import RingBuffer
from pythonbpf.helper import pid, ktime, comm
from ctypes import c_void_p, c_int64, c_uint32, c_uint64

@bpf
@struct
class Event:
    timestamp: c_uint64
    pid: c_uint32
    comm: str(16)

@bpf
@map
def events() -> RingBuffer:
    return RingBuffer(max_entries=4096)

@bpf
@section("tracepoint/syscalls/sys_enter_execve")
def track_exec(ctx: c_void_p) -> c_int64:
    event = Event()
    event.timestamp = ktime()
    event.pid = pid()
    comm(event.comm)

    events.output(event)
    return 0

@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"

b = BPF()
b.load_and_attach()
```

## See Also

* {doc}`../user-guide/index` - Comprehensive user guide
* {doc}`../getting-started/quickstart` - Quick start tutorial
* [GitHub Repository](https://github.com/pythonbpf/Python-BPF) - Source code and examples
