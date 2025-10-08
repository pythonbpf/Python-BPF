import ctypes


def ktime():
    """
    Get the current kernel time in nanoseconds.
    
    Returns:
        A c_int64 stub value (actual implementation is in BPF runtime)
    """
    return ctypes.c_int64(0)


def pid():
    """
    Get the current process ID (PID).
    
    Returns:
        A c_int32 stub value (actual implementation is in BPF runtime)
    """
    return ctypes.c_int32(0)


def deref(ptr):
    "dereference a pointer"
    result = ctypes.cast(ptr, ctypes.POINTER(ctypes.c_void_p)).contents.value
    return result if result is not None else 0


XDP_DROP = ctypes.c_int64(1)
XDP_PASS = ctypes.c_int64(2)
