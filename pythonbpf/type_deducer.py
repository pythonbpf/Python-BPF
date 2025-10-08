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
    # Not so sure about this one
    "str": ir.PointerType(ir.IntType(8)),
}


def ctypes_to_ir(ctype: str):
    """
    Convert a ctypes type name to its corresponding LLVM IR type.
    
    Args:
        ctype: String name of the ctypes type (e.g., 'c_int64', 'c_void_p')
    
    Returns:
        The corresponding LLVM IR type
    
    Raises:
        NotImplementedError: If the ctype is not supported
    """
    if ctype in mapping:
        return mapping[ctype]
    raise NotImplementedError(f"No mapping for {ctype}")


def is_ctypes(ctype: str) -> bool:
    """
    Check if a given type name is a supported ctypes type.
    
    Args:
        ctype: String name of the type to check
    
    Returns:
        True if the type is a supported ctypes type, False otherwise
    """
    return ctype in mapping
