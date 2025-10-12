class CallHandlerRegistry:
    """Registry for handling different types of calls (helpers, etc.)"""

    _handler = None

    @classmethod
    def set_handler(cls, handler):
        """Set the handler for unknown calls"""
        cls._handler = handler

    @classmethod
    def handle_call(
        cls, call, module, builder, func, local_sym_tab, map_sym_tab, structs_sym_tab
    ):
        """Handle a call using the registered handler"""
        if cls._handler is None:
            return None
        return cls._handler(
            call, module, builder, func, local_sym_tab, map_sym_tab, structs_sym_tab
        )
