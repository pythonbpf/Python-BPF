from llvmlite import ir


class IntTy(ir.IntType):
    """An LLVM integer type that also remembers its signedness.

    LLVM integer types are sign-agnostic by design: `i32` is just 32 bits, and
    the sign lives in the operations (sdiv/udiv, sext/zext, icmp s*/u*). The
    frontend therefore has to carry it. IntTy is a plain ir.IntType for every
    purpose LLVM cares about -- it renders as `i32`, compares and hashes equal
    to ir.IntType(32), and passes every isinstance check -- with one extra
    attribute the compiler reads when choosing between signed and unsigned
    forms of an operation.

    Invariant: the sign is read only from a *descriptor* -- a Symbol.ir_type
    or the type half of an eval_expr result -- never from `value.type`. Values
    produced by the IRBuilder (loads, arithmetic, extensions) come back with a
    plain ir.IntType, so a sign on a value's own type is lost at the first
    operation. Descriptors are constructed by the compiler; that is where the
    sign lives.
    """

    def __new__(cls, bits: int, signed: bool = True):
        # ir.IntType.__new__ memoises one instance per width in a cache shared
        # with subclasses. Going through it would (a) merge the signed and
        # unsigned flavours of a width into one object and (b) plant an IntTy
        # in the cache so that ir.IntType(32) itself started returning one.
        # Construct directly instead; equality and hashing are inherited and
        # depend only on the width, so an IntTy still compares equal to i32.
        self = object.__new__(cls)
        self.width = bits
        return self

    def __init__(self, bits: int, signed: bool = True):
        self.signed = signed

    def __getnewargs__(self):
        return self.width, self.signed

    def describe(self) -> str:
        return f"{'i' if self.signed else 'u'}{self.width}"


def signedness(ty) -> bool:
    """Sign of an integer type descriptor. Plain ir.IntType (a site that has not
    been taught to carry a sign yet) reads as signed, which is the compiler's
    historical behaviour."""
    return getattr(ty, "signed", True)


_SIGNED_CTYPES = {
    "c_int8",
    "c_int16",
    "c_int32",
    "c_int64",
    "c_int",
    "c_short",
    "c_long",
    "c_longlong",
    "c_byte",
}

_INT_CTYPE_WIDTHS = {
    "c_int8": 8,
    "c_uint8": 8,
    "c_byte": 8,
    "c_ubyte": 8,
    "c_int16": 16,
    "c_uint16": 16,
    "c_short": 16,
    "c_ushort": 16,
    "c_int32": 32,
    "c_uint32": 32,
    "c_int": 32,
    "c_uint": 32,
    "c_int64": 64,
    "c_uint64": 64,
    "c_long": 64,
    "c_ulong": 64,
    "c_longlong": 64,
    # A pointer-sized integer; treated as unsigned like uintptr_t.
    "c_void_p": 64,
}


def is_signed_ctype(ctype: str) -> bool:
    return ctype in _SIGNED_CTYPES


# TODO: THIS IS NOT SUPPOSED TO MATCH STRINGS :skull:
mapping = {
    name: IntTy(width, is_signed_ctype(name))
    for name, width in _INT_CTYPE_WIDTHS.items()
}
mapping.update(
    {
        "c_float": ir.FloatType(),
        "c_double": ir.DoubleType(),
        # Not so sure about this one
        "str": ir.PointerType(ir.IntType(8)),
    }
)


def ctypes_to_ir(ctype: str):
    if ctype in mapping:
        return mapping[ctype]
    raise NotImplementedError(f"No mapping for {ctype}")


def is_ctypes(ctype: str) -> bool:
    return ctype in mapping
