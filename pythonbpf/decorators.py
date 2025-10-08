"""
Decorators for marking BPF functions, maps, structs, and globals.

This module provides the core decorators used to annotate Python code
for BPF compilation.
"""


def bpf(func):
    """Decorator to mark a function for BPF compilation."""
    func._is_bpf = True
    return func


def bpfglobal(func):
    """Decorator to mark a function as a BPF global variable."""
    func._is_bpfglobal = True
    return func


def map(func):
    """Decorator to mark a function as a BPF map."""
    func._is_map = True
    return func


def struct(cls):
    """Decorator to mark a class as a BPF struct."""
    cls._is_struct = True
    return cls


def section(name: str):
    """
    Decorator to specify the ELF section name for a BPF program.
    
    Args:
        name: The section name (e.g., 'xdp', 'tracepoint/syscalls/sys_enter_execve')
    
    Returns:
        A decorator function that marks the function with the section name
    """
    def wrapper(fn):
        """Decorator that sets the section name on the function."""
        fn._section = name
        return fn

    return wrapper


# from types import SimpleNamespace

# syscalls = SimpleNamespace(
#     sys_enter_execve="syscalls:sys_enter_execve",
#     sys_exit_execve="syscalls:sys_exit_execve",
#     sys_clone="syscalls:sys_clone",
# )


# def tracepoint(name: str):
#     def wrapper(fn):
#         fn._section = f"tracepoint/{name}"
#         fn._section = name
#         return fn
#     return wrapper
