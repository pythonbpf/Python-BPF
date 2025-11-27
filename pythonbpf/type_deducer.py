from llvmlite import ir

# TODO: THIS IS NOT SUPPOSED TO MATCH STRINGS :skull:
mapping = {
    "c_int8": ir.IntType(8),
    "c_uint8": ir.IntType(8),
    "c_int16": ir.IntType(16),
    "c_uint16": ir.IntType(16),
    "c_int32": ir.IntType(32),
    "c_uint32": ir.IntType(32),
    "c_int64": ir.IntType(64),
    "c_uint64": ir.IntType(64),
    "c_float": ir.FloatType(),
    "c_double": ir.DoubleType(),
    "c_void_p": ir.IntType(64),
    "c_long": ir.IntType(64),
    "c_ulong": ir.IntType(64),
    "c_longlong": ir.IntType(64),
    "c_uint": ir.IntType(32),
    "c_int": ir.IntType(32),
    "c_ushort": ir.IntType(16),
    "c_short": ir.IntType(16),
    "c_ubyte": ir.IntType(8),
    "c_byte": ir.IntType(8),
    # Not so sure about this one
    "str": ir.PointerType(ir.IntType(8)),
}


def ctypes_to_ir(ctype: str):
    if ctype in mapping:
        return mapping[ctype]
    raise NotImplementedError(f"No mapping for {ctype}")


def is_ctypes(ctype: str) -> bool:
    return ctype in mapping
