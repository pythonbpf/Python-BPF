# Ported from Linux tools/testing/selftests/bpf/progs/connect4_dropper.c
#
# A cgroup/connect4 hook that rejects TCP connects to one port, which
# userspace writes into `port` before attaching:
#
#     int port;
#
#     SEC("cgroup/connect4")
#     int connect_v4_dropper(struct bpf_sock_addr *ctx)
#     {
#             if (ctx->type != SOCK_STREAM)
#                     return VERDICT_PROCEED;
#             if (ctx->user_port == bpf_htons(port))
#                     return VERDICT_REJECT;
#             return VERDICT_PROCEED;
#     }
#
# bpf_htons() is a byte swap, written out here as shifts on the low 16 bits;
# SOCK_STREAM is 1.

from pythonbpf import bpf, section, bpfglobal, compile
from vmlinux import struct_bpf_sock_addr
from ctypes import c_int64, c_int32

VERDICT_REJECT = 0
VERDICT_PROCEED = 1
SOCK_STREAM = 1


@bpf
@bpfglobal
def port() -> c_int32:
    return c_int32(0)


@bpf
@section("cgroup/connect4")
def connect_v4_dropper(ctx: struct_bpf_sock_addr) -> c_int64:
    if ctx.type != 1:
        return c_int64(1)
    port_be = ((port & 0xFF) << 8) | ((port >> 8) & 0xFF)
    if ctx.user_port == port_be:
        return c_int64(0)
    return c_int64(1)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
