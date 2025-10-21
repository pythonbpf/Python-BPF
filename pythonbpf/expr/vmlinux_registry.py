import ast


class VmlinuxHandlerRegistry:
    """Registry for vmlinux handler operations"""

    _handler = None

    @classmethod
    def set_handler(cls, handler):
        """Set the vmlinux handler"""
        cls._handler = handler

    @classmethod
    def get_handler(cls):
        """Get the vmlinux handler"""
        return cls._handler

    @classmethod
    def handle_name(cls, name):
        """Try to handle a name as vmlinux enum/constant"""
        if cls._handler is None:
            return None
        return cls._handler.handle_vmlinux_enum(name)

    @classmethod
    def handle_attribute(cls, expr, local_sym_tab, module, builder):
        """Try to handle an attribute access as vmlinux struct field"""
        if cls._handler is None:
            return None

        if isinstance(expr.value, ast.Name):
            var_name = expr.value.id
            field_name = expr.attr
            return cls._handler.handle_vmlinux_struct_field(
                var_name, field_name, module, builder, local_sym_tab
            )
        return None

    @classmethod
    def is_vmlinux_struct(cls, name):
        """Check if a name refers to a vmlinux struct"""
        if cls._handler is None:
            return False
        return cls._handler.is_vmlinux_struct(name)
