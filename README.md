<picture>
  <source
    media="(prefers-color-scheme: light)"
    srcset="https://github.com/user-attachments/assets/f3738131-d7cb-4b5c-8699-c7010295a159"
    width="450"
    alt="Light‐mode image">
  <img
    src="https://github.com/user-attachments/assets/b175bf39-23cb-475d-a6e1-7b5c99a1ed72"
    width="450"
    alt="Dark‐mode image">
</picture>
<!-- Badges -->
<p align="center">
  <!-- PyPI -->
  <a href="https://pypi.org/project/pythonbpf/"><img src="https://img.shields.io/pypi/v/pythonbpf?color=blue" alt="PyPI version"></a>
  <!-- <a href="https://pypi.org/project/pythonbpf/"><img src="https://img.shields.io/pypi/pyversions/pythonbpf" alt="Python versions"></a> -->
  <!-- <a href="https://pypi.org/project/pythonbpf/"><img src="https://img.shields.io/pypi/dm/pythonbpf" alt="PyPI downloads"></a> -->
  <!-- <a href="https://pypi.org/project/pythonbpf/"><img src="https://img.shields.io/pypi/status/pythonbpf" alt="PyPI Status"></a> -->
  <a href="https://pepy.tech/project/pythonbpf"><img src="https://pepy.tech/badge/pythonbpf" alt="Downloads"></a>
  <!-- Build & CI -->
  <a href="https://github.com/pythonbpf/python-bpf/actions"><img src="https://github.com/pythonbpf/python-bpf/actions/workflows/python-publish.yml/badge.svg" alt="Build Status"></a>
  <!-- Meta -->
  <a href="https://github.com/pythonbpf/python-bpf/blob/main/LICENSE"><img src="https://img.shields.io/github/license/pythonbpf/python-bpf" alt="License"></a>
</p>


Python-BPF is an LLVM IR generator for eBPF programs written in Python. It uses [llvmlite](https://github.com/numba/llvmlite) to generate LLVM IR and then compiles to LLVM object files. These object files can be loaded into the kernel for execution. Python-BPF performs compilation without relying on BCC.

> **Note**: This project is under active development and not ready for production use.

---

## Overview

* Generate eBPF programs directly from Python.
* Compile to LLVM object files for kernel execution.
* Built with `llvmlite` for IR generation.
* Supports maps, helpers, and global definitions for BPF.
* Companion project: [pylibbpf](https://github.com/pythonbpf/pylibbpf), which provides the bindings required for object loading and execution.

---

## Try It Out!
Run
```bash
curl -s https://raw.githubusercontent.com/pythonbpf/Python-BPF/refs/heads/master/tools/setup.sh | sudo bash
```

## Installation

Dependencies:

* `clang`
* Python ≥ 3.8

Install via pip:

```bash
pip install pythonbpf pylibbpf
```

---

## Example Usage

```python
import time
from pythonbpf import bpf, map, section, bpfglobal, BPF
from pythonbpf.helper import pid
from pythonbpf.maps import HashMap
from pylibbpf import *
from ctypes import c_void_p, c_int64, c_uint64, c_int32
import matplotlib.pyplot as plt


# This program attaches an eBPF tracepoint to sys_enter_clone,
# counts per-PID clone syscalls, stores them in a hash map,
# and then plots the distribution as a histogram using matplotlib.
# It provides a quick view of process creation activity over 10 seconds.

@bpf
@map
def hist() -> HashMap:
    return HashMap(key=c_int32, value=c_uint64, max_entries=4096)


@bpf
@section("tracepoint/syscalls/sys_enter_clone")
def hello(ctx: c_void_p) -> c_int64:
    process_id = pid()
    one = 1
    prev = hist.lookup(process_id)
    if prev:
        previous_value = prev + 1
        print(f"count: {previous_value} with {process_id}")
        hist.update(process_id, previous_value)
        return c_int64(0)
    else:
        hist.update(process_id, one)
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


b = BPF()
b.load_and_attach()
hist = BpfMap(b, hist)
print("Recording")
time.sleep(10)

counts = list(hist.values())

plt.hist(counts, bins=20)
plt.xlabel("Clone calls per PID")
plt.ylabel("Frequency")
plt.title("Syscall clone counts")
plt.show()
```
---

## Architecture

Python-BPF provides a complete pipeline to write, compile, and load eBPF programs in Python:

1. **Python Source Code**

   * Users write BPF programs in Python using decorators like `@bpf`, `@map`, `@section`, and `@bpfglobal`.
   * Maps (hash maps), helpers (e.g., `ktime`, `deref`), and tracepoints are defined using Python constructs, preserving a syntax close to standard Python.

2. **AST Generation**

   * The Python `ast` module parses the source code into an Abstract Syntax Tree (AST).
   * Decorators and type annotations are captured to determine BPF maps, tracepoints, and global variables.

3. **LLVM IR Emission**

   * The AST is transformed into LLVM Intermediate Representation (IR) using `llvmlite`.
   * IR captures BPF maps, control flow, assignments, and calls to helper functions.
   * Debug information is emitted for easier inspection.

4. **LLVM Object File Compilation**

   * The LLVM IR (`.ll`) is compiled into a BPF target object file (`.o`) using `llc -march=bpf -O2`.
   * This produces a kernel-loadable ELF object file containing the BPF bytecode.

5. **libbpf Integration (via pylibbpf)**

   * The compiled object file can be loaded into the kernel using `pylibbpf`.
   * Maps, tracepoints, and program sections are initialized, and helper functions are resolved.
   * Programs are attached to kernel hooks (e.g., syscalls) for execution.

6. **Execution in Kernel**

   * The kernel executes the loaded eBPF program.
   * Hash maps, helpers, and global variables behave as defined in the Python source.
   * Output can be read via BPF maps, helper functions, or trace printing.

This architecture eliminates the need for embedding C code in Python, allowing full Python tooling support while generating true BPF object files ready for kernel execution.

---

## Development

1. Create a virtual environment and activate it:

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

2. Install dependencies:

   ```bash
   make install
   ```
   Then, run any example in `examples`
3. Verify an object file with the kernel verifier:

   ```bash
   ./tools/check.sh check execve2.o
   ```

5. Run an object file using `bpftool`:

   ```bash
   ./tools/check.sh run execve2.o
   ```

6. Explore LLVM IR output from clang in `examples/c-form` by running `make`.

---

## Resources

* [Video demonstration](https://youtu.be/eMyLW8iWbks)
* [Slide deck](https://docs.google.com/presentation/d/1DsWDIVrpJhM4RgOETO9VWqUtEHo3-c7XIWmNpi6sTSo/edit?usp=sharing)

---

## Authors

* [@r41k0u](https://github.com/r41k0u)
* [@varun-r-mallya](https://github.com/varun-r-mallya)

---
