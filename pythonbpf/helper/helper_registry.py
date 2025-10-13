from typing import Callable


class HelperHandlerRegistry:
    """Registry for BPF helpers"""

    _handlers: dict[str, Callable] = {}

    @classmethod
    def register(cls, helper_name):
        """Decorator to register a handler function for a helper"""

        def decorator(func):
            cls._handlers[helper_name] = func
            return func

        return decorator

    @classmethod
    def get_handler(cls, helper_name):
        """Get the handler function for a helper"""
        return cls._handlers.get(helper_name)

    @classmethod
    def has_handler(cls, helper_name):
        """Check if a handler function is registered for a helper"""
        return helper_name in cls._handlers
