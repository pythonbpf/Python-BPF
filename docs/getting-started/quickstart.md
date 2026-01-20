# Quick Start

This guide will walk you through creating your first BPF program with PythonBPF.

## Your First BPF Program

Let's create a simple "Hello World" program that prints a message every time a process is executed on your system.

### Step 1: Create the Program

Create a new file called `hello_world.py`:

```python
from pythonbpf import bpf, section, bpfglobal, BPF, trace_pipe
from ctypes import c_void_p, c_int64

@bpf
@section("tracepoint/syscalls/sys_enter_execve")
def hello_world(ctx: c_void_p) -> c_int64:
    print("Hello, World!")
    return c_int64(0)

@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"

b = BPF()
b.load()
b.attach_all()
trace_pipe()
```

### Step 2: Run the Program

Run the program with sudo (required for BPF operations):

```bash
sudo python3 hello_world.py
```

### Step 3: See it in Action

Open another terminal and run any command:

```bash
ls
echo "test"
date
```

You should see "Hello, World!" printed in the first terminal for each command executed!

Press `Ctrl+C` to stop the program.

## Understanding the Code

Let's break down what each part does:

### Imports

```python
from pythonbpf import bpf, section, bpfglobal, BPF, trace_pipe
from ctypes import c_void_p, c_int64
```

* `bpf` - Decorator to mark functions for BPF compilation
* `section` - Decorator to specify which kernel event to attach to
* `bpfglobal` - Decorator for BPF global variables
* `BPF` - Class to compile, load, and attach BPF programs
* `trace_pipe` - Utility to read kernel trace output
* `c_void_p`, `c_int64` - C types for function signatures

### The BPF Function

```python
@bpf
@section("tracepoint/syscalls/sys_enter_execve")
def hello_world(ctx: c_void_p) -> c_int64:
    print("Hello, World!")
    return c_int64(0)
```

* `@bpf` - Marks this function to be compiled to BPF bytecode
* `@section("tracepoint/syscalls/sys_enter_execve")` - Attaches to the execve syscall tracepoint (called when processes start)
* `ctx: c_void_p` - Context parameter (required for all BPF functions)
* `print()` - In BPF context, this outputs to the kernel trace buffer
* `return c_int64(0)` - BPF functions must return an integer

### License Declaration

```python
@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"
```

* The Linux kernel requires BPF programs to declare a license
* Most kernel features require GPL-compatible licenses
* This is defined as a BPF global variable

### Compilation and Execution

```python
b = BPF()
b.load()
b.attach_all()
trace_pipe()
```

* `BPF()` - Creates a BPF object and compiles the current file
* `b.load()` - Loads the compiled BPF program into the kernel
* `b.attach_all()` - Attaches all BPF programs to their specified hooks
* `trace_pipe()` - Reads and displays output from the kernel trace buffer

## Next Example: Tracking Process IDs

Let's make a more interesting program that tracks which processes are being created:

```python
from pythonbpf import bpf, section, bpfglobal, BPF, trace_pipe
from pythonbpf.helper import pid, comm
from ctypes import c_void_p, c_int64

@bpf
@section("tracepoint/syscalls/sys_enter_execve")
def track_exec(ctx: c_void_p) -> c_int64:
    process_id = pid()
    process_name = comm()
    print(f"Process {process_name} (PID: {process_id}) is starting")
    return c_int64(0)

@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"

b = BPF()
b.load()
b.attach_all()
trace_pipe()
```

This program uses BPF helper functions:

* `pid()` - Gets the current process ID
* `comm()` - Gets the current process command name

Run it with `sudo python3 track_exec.py` and watch processes being created!

## Common Patterns

### Tracepoints

Tracepoints are predefined hooks in the kernel. Common ones include:

```python
# System calls
@section("tracepoint/syscalls/sys_enter_execve")
@section("tracepoint/syscalls/sys_enter_clone")
@section("tracepoint/syscalls/sys_enter_open")

# Scheduler events
@section("tracepoint/sched/sched_process_fork")
@section("tracepoint/sched/sched_switch")
```

### Kprobes

Kprobes allow you to attach to any kernel function:

```python
@section("kprobe/do_sys_open")
def trace_open(ctx: c_void_p) -> c_int64:
    print("File is being opened")
    return c_int64(0)
```

### XDP (eXpress Data Path)

For network packet processing:

```python
from ctypes import c_uint32

@section("xdp")
def xdp_pass(ctx: c_void_p) -> c_uint32:
    # XDP_PASS = 2
    return c_uint32(2)
```

## Best Practices

1. **Always include a LICENSE** - Required by the kernel
2. **Use type hints** - Helps PythonBPF generate correct code
3. **Return the correct type** - Match the expected return type for your program type
4. **Test incrementally** - Start simple and add complexity gradually
5. **Check kernel logs** - Use `dmesg` to see BPF verifier messages if loading fails

## Common Issues

### Program Won't Load

If your BPF program fails to load:

* Check `dmesg` for verifier error messages
* Ensure your LICENSE is GPL-compatible
* Verify you're using supported BPF features
* Make sure return types match function signatures

### No Output

If you don't see output:

* Verify the tracepoint/kprobe is being triggered
* Check that you're running with sudo
* Ensure `/sys/kernel/tracing/trace_pipe` is accessible

### Compilation Errors

If compilation fails:

* Check that `llc` is installed and in your PATH
* Verify your Python syntax is correct
* Ensure all imported types are from `ctypes`

## Next Steps

Now that you understand the basics, explore:

* {doc}`../user-guide/decorators` - Learn about all available decorators
* {doc}`../user-guide/maps` - Use BPF maps for data storage and communication
* {doc}`../user-guide/structs` - Define custom data structures
* {doc}`../user-guide/helpers` - Discover all available BPF helper functions
* [Examples directory](https://github.com/pythonbpf/Python-BPF/tree/master/examples) - See more complex examples
