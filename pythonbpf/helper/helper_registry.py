from dataclasses import dataclass
from llvmlite import ir
from typing import Callable


@dataclass
class HelperSignature:
    """Signature of a BPF helper function"""

    arg_types: list[ir.Type]
    return_type: ir.Type
    func: Callable


class HelperHandlerRegistry:
    """Registry for BPF helpers"""

    _handlers: dict[str, HelperSignature] = {}

    @classmethod
    def register(cls, helper_name, param_types=None, return_type=None):
        """Decorator to register a handler function for a helper"""

        def decorator(func):
            helper_sig = HelperSignature(
                arg_types=param_types, return_type=return_type, func=func
            )
            cls._handlers[helper_name] = helper_sig
            return func

        return decorator

    @classmethod
    def get_handler(cls, helper_name):
        """Get the handler function for a helper"""
        handler = cls._handlers.get(helper_name)
        return handler.func if handler else None

    @classmethod
    def has_handler(cls, helper_name):
        """Check if a handler function is registered for a helper"""
        return helper_name in cls._handlers
