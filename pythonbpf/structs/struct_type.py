from pythonbpf.type_deducer import byte_size
from llvmlite import ir


class StructType:
    def __init__(self, ir_type, fields, size):
        self.ir_type = ir_type
        self.fields = fields
        self.size = size

    def field_idx(self, field_name):
        return list(self.fields.keys()).index(field_name)

    def field_type(self, field_name):
        return self.fields[field_name]

    def gep(self, builder, ptr, field_name):
        idx = self.field_idx(field_name)
        return builder.gep(
            ptr,
            [ir.Constant(ir.IntType(32), 0), ir.Constant(ir.IntType(32), idx)],
            inbounds=True,
        )

    def field_size(self, field_name):
        fld = self.fields[field_name]
        if isinstance(fld, ir.ArrayType):
            return fld.count * byte_size(fld.element)
        elif isinstance(fld, ir.IntType):
            return byte_size(fld)
        elif isinstance(fld, ir.PointerType):
            return 8

        raise TypeError(f"Unsupported field type: {fld}")
