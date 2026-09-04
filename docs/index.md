# PythonBPF Documentation

Welcome to **PythonBPF** - a Python frontend for writing eBPF programs without embedding C code. PythonBPF uses [llvmlite](https://github.com/numba/llvmlite) to generate LLVM IR and compiles directly to eBPF object files that can be loaded into the Linux kernel.

```{note}
This project is under active development.
```

## What is PythonBPF?

PythonBPF is an LLVM IR generator for eBPF programs written in Python. It provides:

* **Pure Python syntax** - Write eBPF programs in Python using familiar decorators and type annotations
* **Direct compilation** - Compile to LLVM object files without relying on BCC
* **Full eBPF features** - Support for maps, helpers, global definitions, and more
* **Integration with libbpf** - Works with [pylibbpf](https://github.com/pythonbpf/pylibbpf) for object loading and execution

## Quick Example

Here's a simple "Hello World" BPF program that traces process creation:

```python
from pythonbpf import bpf, section, bpfglobal, BPF, trace_pipe
from ctypes import c_void_p, c_int64

@bpf
@section("tracepoint/syscalls/sys_enter_execve")
def hello_world(ctx: c_void_p) -> c_int64:
    print("Hello, World!")
    return 0

@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"

b = BPF()
b.load()
b.attach_all()
trace_pipe()
```

## Features

* Generate eBPF programs directly using Python syntax
* Compile to LLVM object files for kernel execution
* Built with `llvmlite` for IR generation
* Supports maps, helpers, and global definitions for BPF
* Companion project: [pylibbpf](https://github.com/pythonbpf/pylibbpf), which provides bindings for libbpf

## Table of Contents

```{toctree}
:maxdepth: 2
:caption: Getting Started

getting-started/index
getting-started/installation
getting-started/quickstart
```

```{toctree}
:maxdepth: 2
:caption: User Guide

user-guide/index
user-guide/decorators
user-guide/maps
user-guide/structs
user-guide/compilation
user-guide/helpers
user-guide/integers
```

```{toctree}
:maxdepth: 2
:caption: API Reference

api/index
```

## Links

* **GitHub Repository**: [pythonbpf/Python-BPF](https://github.com/pythonbpf/Python-BPF)
* **PyPI Package**: [pythonbpf](https://pypi.org/project/pythonbpf/)
* **Video Demo**: [YouTube](https://www.youtube.com/watch?v=eFVhLnWFxtE)

## License

PythonBPF is licensed under the Apache License 2.0.

## Indices and tables

* {ref}`genindex`
* {ref}`modindex`
* {ref}`search`
