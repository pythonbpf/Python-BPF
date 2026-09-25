# probe_read_kernel into a scalar reads the scalar's width, and the source may
# be an address held in a register field (C: (void *)ctx->si). bpfsnake reads
# one typed byte this way: `@key = *((int8*)arg1)`.
from ctypes import c_int8, c_int64
from pythonbpf import bpf, section, bpfglobal, compile
from pythonbpf.helper import probe_read_kernel
from vmlinux import struct_pt_regs


@bpf
@bpfglobal
def last() -> c_int64:
    return c_int64(0)


# pty_write(struct tty_struct *tty, const u8 *buf, size_t c)
@bpf
@section("kprobe/pty_write")
def prog(ctx: struct_pt_regs) -> c_int64:
    global last
    if ctx.dx == 1:
        byte = c_int8(0)
        probe_read_kernel(byte, ctx.si)
        last = byte
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
