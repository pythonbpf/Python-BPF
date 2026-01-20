# Compilation

PythonBPF provides several functions and classes for compiling Python code into BPF bytecode and loading it into the kernel.

## Overview

The compilation process transforms Python code into executable BPF programs:

1. **Python Source** → AST parsing
2. **AST** → LLVM IR generation (using llvmlite)
3. **LLVM IR** → BPF bytecode (using llc)
4. **BPF Object** → Kernel loading (using libbpf)

## Compilation Functions

### compile_to_ir()

Compile Python source to LLVM Intermediate Representation.

#### Signature

```python
def compile_to_ir(filename: str, output: str, loglevel=logging.INFO)
```

#### Parameters

* `filename` - Path to the Python source file to compile
* `output` - Path where the LLVM IR file (.ll) should be written
* `loglevel` - Logging level (default: `logging.INFO`)

#### Usage

```python
from pythonbpf import compile_to_ir
import logging

# Compile to LLVM IR
compile_to_ir(
    filename="my_bpf_program.py",
    output="my_bpf_program.ll",
    loglevel=logging.DEBUG
)
```

#### Output

This function generates an `.ll` file containing LLVM IR, which is human-readable assembly-like code. This is useful for:

* Debugging compilation issues
* Understanding code generation
* Manual optimization
* Educational purposes

#### Example IR Output

```llvm
; ModuleID = 'bpf_module'
source_filename = "bpf_module"
target triple = "bpf"

define i64 @hello_world(i8* %ctx) {
entry:
  ; BPF code here
  ret i64 0
}
```

### compile()

Compile Python source to BPF object file.

#### Signature

```python
def compile(filename: str = None, output: str = None, loglevel=logging.INFO)
```

#### Parameters

* `filename` - Path to the Python source file (default: calling file)
* `output` - Path for the output object file (default: same name with `.o` extension)
* `loglevel` - Logging level (default: `logging.INFO`)

#### Usage

```python
from pythonbpf import compile
import logging

# Compile current file
compile()

# Compile specific file
compile(filename="my_program.py", output="my_program.o")

# Compile with debug logging
compile(loglevel=logging.DEBUG)
```

#### Output

This function generates a `.o` file containing BPF bytecode that can be:

* Loaded into the kernel
* Inspected with `bpftool`
* Verified with the BPF verifier
* Distributed as a compiled binary

#### Compilation Steps

The `compile()` function performs these steps:

1. Parse Python source to AST
2. Process decorators and find BPF functions
3. Generate LLVM IR
4. Write IR to temporary `.ll` file
5. Invoke `llc` to compile to BPF object
6. Write final `.o` file

### BPF Class

The `BPF` class provides a high-level interface to compile, load, and attach BPF programs.

#### Signature

```python
class BPF:
    def __init__(self, filename: str = None, loglevel=logging.INFO)
    def load(self)
    def attach_all(self)
    def load_and_attach(self)
```

#### Parameters

* `filename` - Path to Python source file (default: calling file)
* `loglevel` - Logging level (default: `logging.INFO`)

#### Methods

##### __init__()

Create a BPF object and compile the source.

```python
from pythonbpf import BPF

# Compile current file
b = BPF()

# Compile specific file
b = BPF(filename="my_program.py")
```

##### load()

Load the compiled BPF program into the kernel.

```python
b = BPF()
b.load()
```

This method:
* Loads the BPF object file into the kernel
* Creates maps
* Verifies the BPF program
* Returns a `BpfObject` instance

##### attach_all()

Attach all BPF programs to their specified hooks.

```python
b = BPF()
b.load()
b.attach_all()
```

This method:
* Attaches tracepoints
* Attaches kprobes/kretprobes
* Attaches XDP programs
* Enables all hooks

##### load_and_attach()

Convenience method that loads and attaches in one call.

```python
b = BPF()
b.load_and_attach()
```

Equivalent to:
```python
b = BPF()
b.load()
b.attach_all()
```

## Complete Example

Here's a complete example showing the compilation workflow:

```python
from pythonbpf import bpf, section, bpfglobal, BPF, trace_pipe
from ctypes import c_void_p, c_int64

@bpf
@section("tracepoint/syscalls/sys_enter_execve")
def trace_exec(ctx: c_void_p) -> c_int64:
    print("Process started")
    return c_int64(0)

@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"

if __name__ == "__main__":
    # Method 1: Simple compilation and loading
    b = BPF()
    b.load_and_attach()
    trace_pipe()
    
    # Method 2: Step-by-step
    # b = BPF()
    # b.load()
    # b.attach_all()
    # trace_pipe()
    
    # Method 3: Manual compilation
    # from pythonbpf import compile
    # compile(filename="my_program.py", output="my_program.o")
    # # Then load with pylibbpf directly
```

## Compilation Pipeline Details

### AST Parsing

The Python `ast` module parses your source code:

```python
import ast
tree = ast.parse(source_code, filename)
```

The AST is then walked to find:
* Functions decorated with `@bpf`
* Classes decorated with `@struct`
* Map definitions with `@map`
* Global variables with `@bpfglobal`

### IR Generation

PythonBPF uses `llvmlite` to generate LLVM IR:

```python
from llvmlite import ir

# Create module
module = ir.Module(name='bpf_module')
module.triple = 'bpf'

# Generate IR for each BPF function
# ...
```

Key aspects of IR generation:

* Type conversion (Python types → LLVM types)
* Function definitions
* Map declarations
* Global variable initialization
* Debug information

### BPF Compilation

The LLVM IR is compiled to BPF bytecode using `llc`:

```bash
llc -march=bpf -filetype=obj input.ll -o output.o
```

Compiler flags:
* `-march=bpf` - Target BPF architecture
* `-filetype=obj` - Generate object file
* `-O2` - Optimization level (sometimes used)

### Kernel Loading

The compiled object is loaded using `pylibbpf`:

```python
from pylibbpf import BpfObject

obj = BpfObject(path="program.o")
obj.load()
```

The kernel verifier checks:
* Memory access patterns
* Pointer usage
* Loop bounds
* Instruction count
* Helper function calls

## Debugging Compilation

### Logging

Enable debug logging to see compilation details:

```python
import logging
from pythonbpf import BPF

b = BPF(loglevel=logging.DEBUG)
```

This will show:
* AST parsing details
* IR generation steps
* Compilation commands
* Loading status

### Inspecting LLVM IR

Generate and inspect the IR file:

```python
from pythonbpf import compile_to_ir

compile_to_ir("program.py", "program.ll")
```

Then examine `program.ll` to understand the generated code.

### Using bpftool

Inspect compiled objects with `bpftool`:

```bash
# Show program info
bpftool prog show

# Dump program instructions
bpftool prog dump xlated id <ID>

# Dump program JIT code
bpftool prog dump jited id <ID>

# Show maps
bpftool map show

# Dump map contents
bpftool map dump id <ID>
```

### Verifier Errors

If the kernel verifier rejects your program:

1. Check `dmesg` for detailed error messages:
   ```bash
   sudo dmesg | tail -50
   ```

2. Common issues:
   * Unbounded loops
   * Invalid pointer arithmetic
   * Exceeding instruction limit
   * Invalid helper calls
   * License incompatibility

3. Solutions:
   * Simplify logic
   * Use bounded loops
   * Check pointer operations
   * Verify GPL license

## Compilation Options

### Optimization Levels

While PythonBPF doesn't expose optimization flags directly, you can:

1. Manually compile IR with specific flags:
   ```bash
   llc -march=bpf -O2 -filetype=obj program.ll -o program.o
   ```

2. Modify the compilation pipeline in your code

### Target Options

BPF compilation targets the BPF architecture:

* **Architecture**: `bpf`
* **Endianness**: Typically little-endian
* **Pointer size**: 64-bit

### Debug Information

PythonBPF automatically generates debug information (DWARF) for:

* Function names
* Line numbers
* Variable names
* Type information

This helps with:
* Stack traces
* Debugging with `bpftool`
* Source-level debugging

## Working with Compiled Objects

### Loading Pre-compiled Objects

You can load previously compiled objects:

```python
from pylibbpf import BpfObject

# Load object file
obj = BpfObject(path="my_program.o")
obj.load()

# Attach programs
# (specific attachment depends on program type)
```

### Distribution

Distribute compiled BPF objects:

1. Compile once:
   ```python
   from pythonbpf import compile
   compile(filename="program.py", output="program.o")
   ```

2. Ship `program.o` file

3. Load on target systems:
   ```python
   from pylibbpf import BpfObject
   obj = BpfObject(path="program.o")
   obj.load()
   ```

### Version Compatibility

BPF objects are generally compatible across kernel versions, but:

* Some features require specific kernel versions
* Helper functions may not be available on older kernels
* BTF (BPF Type Format) requirements vary

## Best Practices

1. **Keep compilation separate from runtime**
   ```python
   if __name__ == "__main__":
       b = BPF()
       b.load_and_attach()
       # Runtime code
   ```

2. **Handle compilation errors gracefully**
   ```python
   try:
       b = BPF()
       b.load()
   except Exception as e:
       print(f"Failed to load BPF program: {e}")
       exit(1)
   ```

3. **Use appropriate logging levels**
   * `DEBUG` for development
   * `INFO` for production
   * `ERROR` for critical issues

4. **Cache compiled objects**
   * Compile once, load many times
   * Store `.o` files for reuse
   * Version your compiled objects

5. **Test incrementally**
   * Compile after each change
   * Verify programs load successfully
   * Test attachment before full deployment

## Troubleshooting

### Compilation Fails

If compilation fails:
* Check Python syntax
* Verify all decorators are correct
* Ensure type hints are present
* Check for unsupported Python features

### Loading Fails

If loading fails:
* Check `dmesg` for verifier errors
* Verify LICENSE is set correctly
* Ensure helper functions are valid
* Check map definitions

### Programs Don't Attach

If attachment fails:
* Verify section names are correct
* Check that hooks exist on your kernel
* Ensure you have sufficient permissions
* Verify kernel version supports the feature

## Next Steps

* Learn about {doc}`helpers` for available BPF helper functions
* Explore {doc}`maps` for data storage
* See {doc}`decorators` for compilation markers
