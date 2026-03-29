class CallHandlerRegistry:
    """Registry for handling different types of calls (helpers, etc.)"""

    _handler = None

    @classmethod
    def set_handler(cls, handler):
        """Set the handler for unknown calls"""
        cls._handler = handler

    @classmethod
    def handle_call(cls, call, compilation_context, builder, func, local_sym_tab):
        """Handle a call using the registered handler"""
        if cls._handler is None:
            return None
        return cls._handler(call, compilation_context, builder, func, local_sym_tab)
