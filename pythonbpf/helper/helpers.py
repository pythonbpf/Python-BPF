import ctypes


def ktime():
    """get current ktime"""
    return ctypes.c_int64(0)


def pid():
    """get current process id"""
    return ctypes.c_int32(0)


def deref(ptr):
    """dereference a pointer"""
    result = ctypes.cast(ptr, ctypes.POINTER(ctypes.c_void_p)).contents.value
    return result if result is not None else 0


def comm(buf):
    """get current process command name"""
    return ctypes.c_int64(0)


def probe_read_str(dst, src):
    """Safely read a null-terminated string from kernel memory"""
    return ctypes.c_int64(0)


XDP_ABORTED = ctypes.c_int64(0)
XDP_DROP = ctypes.c_int64(1)
XDP_PASS = ctypes.c_int64(2)
XDP_TX = ctypes.c_int64(3)
XDP_REDIRECT = ctypes.c_int64(4)
