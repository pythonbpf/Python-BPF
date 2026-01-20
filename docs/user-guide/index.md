# User Guide

This user guide provides comprehensive documentation for all PythonBPF features. Whether you're building simple tracing tools or complex performance monitoring systems, this guide will help you master PythonBPF.

## Overview

PythonBPF transforms Python code into eBPF bytecode that runs in the Linux kernel. It provides a Pythonic interface to eBPF features through decorators, type annotations, and familiar programming patterns.

## Core Concepts

### Decorators

PythonBPF uses decorators to mark code for BPF compilation:

* `@bpf` - Mark functions and classes for BPF compilation
* `@map` - Define BPF maps for data storage
* `@struct` - Define custom data structures
* `@section(name)` - Specify attachment points
* `@bpfglobal` - Define global variables

### Compilation Pipeline

Your Python code goes through several stages:

1. **AST Parsing** - Python code is parsed into an Abstract Syntax Tree
2. **IR Generation** - The AST is transformed into LLVM IR using llvmlite
3. **BPF Compilation** - LLVM IR is compiled to BPF bytecode using `llc`
4. **Loading** - The BPF object is loaded into the kernel using libbpf
5. **Attachment** - Programs are attached to kernel hooks (tracepoints, kprobes, etc.)

## Guide Contents

```{toctree}
:maxdepth: 2

decorators
maps
structs
compilation
helpers
```

## Code Organization

When writing BPF programs with PythonBPF, we recommend:

1. **Keep BPF code in separate files** - Easier to manage and test
2. **Use type hints** - Required for proper code generation
3. **Follow naming conventions** - Use descriptive names for maps and functions
4. **Document your code** - Add comments explaining BPF-specific logic
5. **Test incrementally** - Verify each component works before adding complexity

## Type System

PythonBPF uses Python's `ctypes` module for type definitions:

* `c_int8`, `c_int16`, `c_int32`, `c_int64` - Signed integers
* `c_uint8`, `c_uint16`, `c_uint32`, `c_uint64` - Unsigned integers
* `c_char`, `c_bool` - Characters and booleans
* `c_void_p` - Void pointers
* `str(N)` - Fixed-length strings (e.g., `str(16)` for 16-byte string)

## Example Structure

A typical PythonBPF program follows this structure:

```python
from pythonbpf import bpf, map, section, bpfglobal, BPF
from pythonbpf.maps import HashMap
from ctypes import c_void_p, c_int64, c_uint32

# Define maps
@bpf
@map
def my_map() -> HashMap:
    return HashMap(key=c_uint32, value=c_uint64, max_entries=1024)

# Define BPF function
@bpf
@section("tracepoint/...")
def my_function(ctx: c_void_p) -> c_int64:
    # BPF logic here
    return c_int64(0)

# License (required)
@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"

# Compile, load, and run
if __name__ == "__main__":
    b = BPF()
    b.load_and_attach()
    # Use the program...
```

## Next Steps

Start with {doc}`decorators` to learn about all available decorators, then explore the other sections to master specific features.
