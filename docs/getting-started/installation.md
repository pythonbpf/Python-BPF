# Installation

This guide will walk you through installing PythonBPF and its dependencies.

## Prerequisites

### System Requirements

PythonBPF requires:

* **Linux** - eBPF is a Linux kernel feature (kernel 4.15 or higher recommended)
* **Python 3.10+** - Python 3.10 or higher is required
* **Root/sudo access** - Loading BPF programs into the kernel requires elevated privileges

### Required System Packages

Before installing PythonBPF, you need to install the following system packages:

#### On Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y bpftool clang llvm
```

#### On Fedora/RHEL/CentOS:

```bash
sudo dnf install -y bpftool clang llvm
```

#### On Arch Linux:

```bash
sudo pacman -S bpf clang llvm
```

## Installing PythonBPF

### From PyPI (Recommended)

The easiest way to install PythonBPF is using uv or pip:

**Using uv (recommended):**
```bash
uv pip install pythonbpf pylibbpf
```

**Using pip:**
```bash
pip install pythonbpf pylibbpf
```

This will install:
* `pythonbpf` - The main package for writing and compiling BPF programs
* `pylibbpf` - Python bindings for libbpf, used to load and attach BPF programs

### Development Installation

If you want to contribute to PythonBPF or work with the latest development version:

1. Clone the repository:

```bash
git clone https://github.com/pythonbpf/Python-BPF.git
cd Python-BPF
```

2. Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

3. Install in development mode:

**Using uv (recommended):**
```bash
uv pip install -e .
uv pip install pylibbpf
```

**Using pip:**
```bash
pip install -e .
pip install pylibbpf
```

4. Install development dependencies:

```bash
make install
```

### Installing Documentation Dependencies

If you want to build the documentation locally:

**Using uv (recommended):**
```bash
uv pip install pythonbpf[docs]
# Or from the repository root:
uv pip install -e .[docs]
```

**Using pip:**
```bash
pip install pythonbpf[docs]
# Or from the repository root:
pip install -e .[docs]
```

## Generating vmlinux.py

`vmlinux.py` contains the running kernel's data structures and is analogous to `vmlinux.h` included in eBPF programs written in C. Some examples require access to it. To use these features, you need to generate a `vmlinux.py` file:

1. Install additional dependencies:

**Using uv (recommended):**
```bash
uv pip install ctypeslib2
```

**Using pip:**
```bash
pip install ctypeslib2
```

2. Generate the vmlinux.py file:

```bash
sudo tools/vmlinux-gen.py
```

3. Copy the generated file to your working directory or the examples directory as needed.

```{warning}
The `vmlinux.py` file is kernel-specific. If you upgrade your kernel, you may need to regenerate this file.
```

## Verifying Installation

To verify that PythonBPF is installed correctly, run:

```bash
python3 -c "import pythonbpf; print(pythonbpf.__all__)"
```

You should see output similar to:

```
['bpf', 'map', 'section', 'bpfglobal', 'struct', 'compile_to_ir', 'compile', 'BPF', 'trace_pipe', 'trace_fields']
```

## Troubleshooting

### Permission Errors

If you encounter permission errors when running BPF programs:

* Make sure you're running with `sudo` or as root
* Check that `/sys/kernel/tracing/` is accessible

### LLVM/Clang Not Found

If you get errors about `llc` or `clang` not being found:

* Verify they're installed: `which llc` and `which clang`
* Check your PATH environment variable includes the LLVM bin directory

### Import Errors

If Python can't find the `pythonbpf` module:

* Make sure you've activated your virtual environment
* Verify installation with `uv pip list | grep pythonbpf` or `pip list | grep pythonbpf`
* Try reinstalling: `uv pip install --force-reinstall pythonbpf` or `pip install --force-reinstall pythonbpf`

## Next Steps

Now that you have PythonBPF installed, continue to the {doc}`quickstart` guide to write your first BPF program!
