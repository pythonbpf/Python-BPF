from pythonbpf import bpf, section, bpfglobal, BPF, trace_pipe
from pythonbpf import compile  # noqa: F401
from vmlinux import struct_pt_regs
from ctypes import c_int64, c_int32, c_void_p  # noqa: F401


@bpf
@section("kprobe/do_unlinkat")
def kprobe_execve(ctx: struct_pt_regs) -> c_int64:
    r15 = ctx.r15
    r14 = ctx.r14
    r13 = ctx.r13
    r12 = ctx.r12
    bp = ctx.bp
    bx = ctx.bx
    r11 = ctx.r11
    r10 = ctx.r10
    r9 = ctx.r9
    r8 = ctx.r8
    ax = ctx.ax
    cx = ctx.cx
    dx = ctx.dx
    si = ctx.si
    di = ctx.di
    orig_ax = ctx.orig_ax
    ip = ctx.ip
    cs = ctx.cs
    flags = ctx.flags
    sp = ctx.sp
    ss = ctx.ss

    print(f"r15={r15} r14={r14} r13={r13}")
    print(f"r12={r12} rbp={bp} rbx={bx}")
    print(f"r11={r11} r10={r10} r9={r9}")
    print(f"r8={r8} rax={ax} rcx={cx}")
    print(f"rdx={dx} rsi={si} rdi={di}")
    print(f"orig_rax={orig_ax} rip={ip} cs={cs}")
    print(f"eflags={flags} rsp={sp} ss={ss}")

    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


b = BPF()
b.load()
b.attach_all()

trace_pipe()
