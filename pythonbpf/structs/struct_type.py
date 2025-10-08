from llvmlite import ir


class StructType:
    """
    Wrapper class for LLVM IR struct types with field access helpers.
    
    Attributes:
        ir_type: The LLVM IR struct type
        fields: Dictionary mapping field names to their types
        size: Total size of the struct in bytes
    """
    
    def __init__(self, ir_type, fields, size):
        """
        Initialize a StructType.
        
        Args:
            ir_type: The LLVM IR struct type
            fields: Dictionary mapping field names to their types
            size: Total size of the struct in bytes
        """
        self.ir_type = ir_type
        self.fields = fields
        self.size = size

    def field_idx(self, field_name):
        """
        Get the index of a field in the struct.
        
        Args:
            field_name: The name of the field
        
        Returns:
            The zero-based index of the field
        """
        return list(self.fields.keys()).index(field_name)

    def field_type(self, field_name):
        """
        Get the LLVM IR type of a field.
        
        Args:
            field_name: The name of the field
        
        Returns:
            The LLVM IR type of the field
        """
        return self.fields[field_name]

    def gep(self, builder, ptr, field_name):
        """
        Generate a GEP (GetElementPtr) instruction to access a struct field.
        
        Args:
            builder: LLVM IR builder
            ptr: Pointer to the struct
            field_name: Name of the field to access
        
        Returns:
            A pointer to the field
        """
        idx = self.field_idx(field_name)
        return builder.gep(
            ptr,
            [ir.Constant(ir.IntType(32), 0), ir.Constant(ir.IntType(32), idx)],
            inbounds=True,
        )

    def field_size(self, field_name):
        """
        Calculate the size of a field in bytes.
        
        Args:
            field_name: The name of the field
        
        Returns:
            The size of the field in bytes
        
        Raises:
            TypeError: If the field type is not supported
        """
        fld = self.fields[field_name]
        if isinstance(fld, ir.ArrayType):
            return fld.count * (fld.element.width // 8)
        elif isinstance(fld, ir.IntType):
            return fld.width // 8
        elif isinstance(fld, ir.PointerType):
            return 8

        raise TypeError(f"Unsupported field type: {fld}")
