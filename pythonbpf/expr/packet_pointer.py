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

Only direct field reads (`ctx.data`) are recognised so far; a local copied
from one (`d = ctx.data`) is an ordinary integer again. Comparisons between
packet pointers are the next site of the same rule.
"""

import ast

# Context struct -> fields the verifier treats as packet pointers. Taken from
# the verifier's is_valid_access callbacks, restricted to the fields that
# vmlinux declares as 32-bit integers.
PACKET_POINTER_FIELDS = {
    "struct_xdp_md": {"data", "data_end", "data_meta"},
    "struct___sk_buff": {"data", "data_end", "data_meta"},
}

MAX_PACKET_OFF = 0xFFFF


def is_packet_pointer(expr, local_sym_tab) -> bool:
    """True for `ctx.<field>` where ctx is a context parameter of one of the
    structs above and the field is one of its packet-pointer fields."""
    if not (isinstance(expr, ast.Attribute) and isinstance(expr.value, ast.Name)):
        return False
    sym = (local_sym_tab or {}).get(expr.value.id)
    if sym is None:
        return False
    meta = sym.metadata
    struct_name = meta if isinstance(meta, str) else getattr(meta, "__name__", None)
    if not isinstance(struct_name, str):
        return False
    return expr.attr in PACKET_POINTER_FIELDS.get(struct_name, set())
