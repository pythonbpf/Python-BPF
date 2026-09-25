"""Packet-pointer context fields.

A few context fields are declared u32 in C but are packet pointers to the
verifier: it rewrites the context load into a 64-bit pointer load. C's
integer rules (which rank them as u32) therefore produce code the verifier
rejects ("32-bit pointer arithmetic prohibited"); C programs dodge that by
casting through (void *)(long). The compiler special-cases them instead, so
users never need the cast:

- the field is used at 64 bits, as the pointer it is;
- an offset added to or subtracted from it is taken as an unsigned 16-bit
  value (truncated, then zero-extended), because the verifier only tracks a
  packet range whose offset stays within MAX_PACKET_OFF (0xffff);
- pointer - pointer (e.g. data_end - data) is an ordinary 64-bit length.

The field read gives its value a PktPtrTy descriptor (a 64-bit unsigned
IntTy tagged with the verifier's kind), and the rules key on that descriptor,
so they follow the pointer through locals (`d = ctx.data`), through
`d + 14`, and into comparisons (`ctx.data + 34 > ctx.data_end` is a 64-bit
unsigned compare). packet-end pointers take no offset at all, and nothing
narrows a packet pointer below 64 bits.
"""

import ast

from pythonbpf.type_deducer import PktPtrTy

# Context struct -> {field: packet kind}. Taken from the verifier's
# is_valid_access callbacks, restricted to the fields vmlinux declares as
# 32-bit integers.
PACKET_POINTER_FIELDS = {
    "struct_xdp_md": {"data": "pkt", "data_meta": "pkt_meta", "data_end": "pkt_end"},
    "struct___sk_buff": {
        "data": "pkt",
        "data_meta": "pkt_meta",
        "data_end": "pkt_end",
    },
}

MAX_PACKET_OFF = 0xFFFF


def packet_kind(expr, local_sym_tab) -> "str | None":
    """The packet kind of `ctx.<field>` when ctx is a context parameter of one
    of the structs above and the field is one of its packet-pointer fields;
    None otherwise. This is the only place a PktPtrTy originates: from here it
    travels as a descriptor, through locals, binop results and comparisons."""
    if not (isinstance(expr, ast.Attribute) and isinstance(expr.value, ast.Name)):
        return None
    sym = (local_sym_tab or {}).get(expr.value.id)
    if sym is None:
        return None
    meta = sym.metadata
    struct_name = meta if isinstance(meta, str) else getattr(meta, "__name__", None)
    if not isinstance(struct_name, str):
        return None
    return PACKET_POINTER_FIELDS.get(struct_name, {}).get(expr.attr)


def packet_type(expr, local_sym_tab) -> "PktPtrTy | None":
    kind = packet_kind(expr, local_sym_tab)
    return PktPtrTy(kind) if kind is not None else None
