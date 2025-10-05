from typing import Dict


class StatementHandlerRegistry:
    """Registry for statement handlers."""

    _handlers: Dict = {}

    @classmethod
    def register(cls, stmt_type):
        """Register a handler for a specific statement type."""

        def decorator(handler):
            cls._handlers[stmt_type] = handler
            return handler

        return decorator

    @classmethod
    def get_handler(cls, stmt_type):
        """Get the handler for a specific statement type."""
        return cls._handlers.get(stmt_type, None)
