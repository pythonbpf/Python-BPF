from pythonbpf import bpf, section, bpfglobal, BPF, trace_fields
from ctypes import c_void_p, c_int64


@bpf
@section("tracepoint/syscalls/sys_enter_clone")
def hello_world(ctx: c_void_p) -> c_int64:
    print("Hello, World!")
    return 0  # type: ignore [return-value]


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


# Compile and load
b = BPF()
b.load()
b.attach_all()

# header
print(f"{'TIME(s)':<18} {'COMM':<16} {'PID':<6} {'MESSAGE'}")

# format output
while True:
    try:
        (task, pid, cpu, flags, ts, msg) = trace_fields()
    except ValueError:
        continue
    except KeyboardInterrupt:
        exit()
    print(f"{ts:<18} {task:<16} {pid:<6} {msg}")
